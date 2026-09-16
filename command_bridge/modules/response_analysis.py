"""
Response Analysis engine — static analysis of a pasted raw HTTP response.

Companion to request_analysis.py. Purely passive: it parses a captured HTTP
response (Burp / devtools / curl -i / proxy logs) and flags missing or
misconfigured security headers (HSTS, CSP, X-Frame-Options,
X-Content-Type-Options, Referrer-Policy, Permissions-Policy), CORS
misconfiguration (wildcard origin, wildcard + credentials, reflected-origin
allow-lists), server/framework version disclosure, insecure Set-Cookie
flags, verbose error/stack-trace disclosure, directory listing, leaked
secrets/keys/tokens/bulk PII, weak caching of sensitive responses, risky
advertised HTTP methods, mixed content, sensitive HTML comments and verbose
JSON error bodies — each with a suggested test, remediation and, where
useful, a ready-to-use PoC. It NEVER sends anything.

Session-level dedup: findings are fingerprinted by title, and a finding
already surfaced once this session is suppressed on later responses so that
pasting several responses from the same target doesn't keep re-flagging the
same site-wide issue over and over. ResponseAnalysisMixin.clear_identified_
findings() resets that history. Saved reports (save_response_analysis)
always include everything found in the CURRENT response regardless of the
session-level suppression, so nothing is lost from the pentest report.

Split: pure-Python ResponseModel + parse_raw_response + ResponseAnalyzer (no
Qt, unit-testable), plus ResponseAnalysisMixin which is the GUI glue.
"""
import re
import json

from command_bridge.modules.request_analysis import RISK_ORDER, RISK_COLORS


class ResponseModel:
    """Mutable representation of a raw HTTP response."""

    def __init__(self):
        self.version = "HTTP/1.1"
        self.status_code = 0
        self.status_text = ""
        self.headers = []   # list of [name, value]; duplicates preserved (e.g. Set-Cookie)
        self.body = ""

    def header_get(self, name):
        nl = name.lower()
        for n, v in self.headers:
            if n.lower() == nl:
                return v
        return None

    def header_get_all(self, name):
        nl = name.lower()
        return [v for n, v in self.headers if n.lower() == nl]

    @property
    def content_type(self):
        return (self.header_get("Content-Type") or "").lower()

    def json_body(self):
        try:
            return json.loads(self.body)
        except Exception:
            return None


def parse_raw_response(raw):
    """Parse a raw HTTP response string into a ResponseModel, or None if invalid."""
    if not raw or not raw.strip():
        return None
    raw = raw.replace("\r\n", "\n").replace("\r", "\n")
    if "\n\n" in raw:
        head, body = raw.split("\n\n", 1)
    else:
        head, body = raw, ""
    lines = head.split("\n")
    status_line = lines[0].strip()
    m = re.match(r"^(HTTP/[\d.]+)\s+(\d{3})\s*(.*)$", status_line)
    if not m:
        return None
    model = ResponseModel()
    model.version = m.group(1)
    model.status_code = int(m.group(2))
    model.status_text = m.group(3).strip()
    for line in lines[1:]:
        if ":" in line:
            n, _, v = line.partition(":")
            model.headers.append([n.strip(), v.strip()])
    model.body = body.strip("\n")
    return model


class ResponseAnalyzer:
    """Runs every detector over a parsed ResponseModel and returns findings."""

    _TECH_HEADERS = ("Server", "X-Powered-By", "X-AspNet-Version", "X-AspNetMvc-Version",
                      "X-Generator", "X-Drupal-Cache", "X-Varnish")

    _ERROR_SIGNATURES = [
        (re.compile(r"Traceback \(most recent call last\)"), "Python traceback"),
        (re.compile(r"at java\.[\w.]+\("), "Java stack trace"),
        (re.compile(r"System\.\w+Exception"), ".NET exception"),
        (re.compile(r"Microsoft OLE DB Provider"), "MSSQL/OLE DB error"),
        (re.compile(r"Warning: (mysql_|mysqli_|pg_)"), "PHP DB warning"),
        (re.compile(r"ORA-\d{5}"), "Oracle DB error"),
        (re.compile(r"SQLSTATE\[\w+\]"), "SQL error (SQLSTATE)"),
        (re.compile(r"Fatal error:.*on line \d+"), "PHP fatal error"),
        (re.compile(r"django\.core\.exceptions|django\.db\.utils"), "Django traceback"),
        (re.compile(r"org\.springframework\."), "Spring stack trace"),
        (re.compile(r"\bat [\w.$]+\([\w.]+\.\w+:\d+\)"), "generic stack frame"),
    ]

    _COMMENT_KEYWORDS = ("password", "passwd", "secret", "api_key", "apikey", "todo", "fixme",
                         "hack", "internal", "debug", "backdoor", "private key")

    _AWS_KEY_RE = re.compile(r"\b(AKIA|ASIA)[0-9A-Z]{16}\b")
    _PRIVATE_KEY_RE = re.compile(r"-----BEGIN (RSA |EC |OPENSSH |DSA |)PRIVATE KEY-----")
    _JWT_RE = re.compile(r"eyJ[A-Za-z0-9_-]{6,}\.[A-Za-z0-9_-]{6,}\.[A-Za-z0-9_-]*")
    _EMAIL_RE = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")

    def __init__(self, model):
        self.m = model

    @staticmethod
    def _finding(title, risk, evidence, suggested_test, notes="", poc="", remediation="", report=""):
        return {"title": title, "risk": risk, "evidence": evidence,
                "suggested_test": suggested_test, "notes": notes,
                "poc": poc, "remediation": remediation, "report_wording": report,
                "fingerprint": title}

    def summary(self):
        m = self.m
        return {
            "status_code": m.status_code,
            "status_text": m.status_text,
            "version": m.version,
            "content_type": m.content_type or "(none)",
            "server": m.header_get("Server") or "(not disclosed)",
            "set_cookie_count": len(m.header_get_all("Set-Cookie")),
            "body_length": len(m.body or ""),
        }

    # ── run all detectors ───────────────────────────────────────────────────
    def analyze(self):
        findings = []
        for fn in (
            self._d_missing_hsts, self._d_missing_csp, self._d_clickjacking,
            self._d_missing_xcto, self._d_missing_referrer_policy,
            self._d_missing_permissions_policy, self._d_legacy_xss_protection,
            self._d_cors_wildcard, self._d_cors_allowlist_present,
            self._d_server_tech_disclosure, self._d_insecure_cookies,
            self._d_verbose_error, self._d_directory_listing,
            self._d_sensitive_data_exposure, self._d_missing_cache_control,
            self._d_http_methods_disclosure, self._d_mixed_content,
            self._d_html_comment_leak, self._d_json_error_verbosity,
        ):
            try:
                res = fn()
                if res:
                    findings.extend(res if isinstance(res, list) else [res])
            except Exception:
                continue
        findings.sort(key=lambda f: -RISK_ORDER.get(f["risk"], 0))
        return findings

    # ── detectors ───────────────────────────────────────────────────────────
    def _d_missing_hsts(self):
        if self.m.header_get("Strict-Transport-Security"):
            return None
        return self._finding(
            "Missing Strict-Transport-Security (HSTS) Header", "Medium",
            "No Strict-Transport-Security header present.",
            "If this response was served over HTTPS, confirm HSTS is missing site-wide "
            "(check a few other pages/endpoints) — without it, users can be downgraded to "
            "plain HTTP via SSL-stripping on their first visit.",
            remediation="Add 'Strict-Transport-Security: max-age=31536000; includeSubDomains; "
                        "preload' on all HTTPS responses.",
            report="Missing HSTS header (if served over HTTPS).")

    def _d_missing_csp(self):
        if self.m.header_get("Content-Security-Policy"):
            return None
        return self._finding(
            "Missing Content-Security-Policy Header", "Medium",
            "No Content-Security-Policy header present.",
            "A CSP is the primary defence-in-depth control against XSS. Cross-check with "
            "any XSS test points flagged in the Request Analysis tab — with no CSP, "
            "successful injection is not mitigated at the browser level.",
            remediation="Add a restrictive CSP, e.g. \"default-src 'self'; script-src 'self'; "
                        "object-src 'none'; frame-ancestors 'none'\", then tighten per app needs.",
            report="Missing Content-Security-Policy header.")

    def _d_clickjacking(self):
        xfo = self.m.header_get("X-Frame-Options")
        csp = self.m.header_get("Content-Security-Policy") or ""
        if xfo or "frame-ancestors" in csp.lower():
            return None
        poc = (
            "<!DOCTYPE html>\n<html>\n<body>\n"
            "  <h1>Clickjacking PoC</h1>\n"
            "  <iframe src=\"https://TARGET_URL_HERE\" width=\"800\" height=\"600\"></iframe>\n"
            "</body>\n</html>"
        )
        return self._finding(
            "Missing Clickjacking Protection (X-Frame-Options / CSP frame-ancestors)", "Medium",
            "Neither X-Frame-Options nor a CSP frame-ancestors directive is present.",
            "Host the PoC below and confirm the target page renders inside the iframe "
            "over HTTPS — if it does, sensitive actions may be trickable via an overlaid UI.",
            poc=poc,
            remediation="Add 'X-Frame-Options: DENY' (or 'SAMEORIGIN') and/or "
                        "'Content-Security-Policy: frame-ancestors 'none'' (or 'self').",
            report="Missing clickjacking protections (X-Frame-Options / CSP frame-ancestors).")

    def _d_missing_xcto(self):
        v = self.m.header_get("X-Content-Type-Options")
        if v and v.lower().strip() == "nosniff":
            return None
        return self._finding(
            "Missing/Weak X-Content-Type-Options Header", "Low",
            f"Header value: {v or '(absent)'}",
            "Confirm the response cannot be MIME-sniffed into an executable context (e.g. "
            "a JSON/text response rendered as HTML/JS by an old/misconfigured browser).",
            remediation="Add 'X-Content-Type-Options: nosniff'.",
            report="Missing or non-'nosniff' X-Content-Type-Options header.")

    def _d_missing_referrer_policy(self):
        if self.m.header_get("Referrer-Policy"):
            return None
        return self._finding(
            "Missing Referrer-Policy Header", "Low",
            "No Referrer-Policy header present.",
            "Check whether sensitive path/query data could leak to third parties via the "
            "Referer header on outbound links or embedded resources.",
            remediation="Add 'Referrer-Policy: strict-origin-when-cross-origin' (or stricter, "
                        "e.g. 'no-referrer', depending on requirements).",
            report="Missing Referrer-Policy header.")

    def _d_missing_permissions_policy(self):
        if self.m.header_get("Permissions-Policy") or self.m.header_get("Feature-Policy"):
            return None
        return self._finding(
            "Missing Permissions-Policy Header", "Info",
            "No Permissions-Policy (or legacy Feature-Policy) header present.",
            "Low-severity hardening gap — confirm whether the app embeds third-party "
            "content that should have browser feature access restricted (camera, mic, "
            "geolocation, payment, etc.).",
            remediation="Add a 'Permissions-Policy' header restricting unused browser "
                        "features, e.g. \"geolocation=(), camera=(), microphone=(), payment=()\".",
            report="Missing Permissions-Policy header.")

    def _d_legacy_xss_protection(self):
        v = self.m.header_get("X-XSS-Protection")
        if not v or v.strip().startswith("0"):
            return None
        return self._finding(
            "Legacy X-XSS-Protection Header Present", "Info",
            f"Header value: {v}",
            "This header is deprecated and removed from modern browsers (Chrome/Edge no "
            "longer honour it) and has historically enabled filter-bypass XSS in some "
            "browsers. Rely on CSP instead.",
            remediation="Remove X-XSS-Protection (or set it to '0') and rely on a strong CSP.",
            report="Legacy X-XSS-Protection header present; recommend removing in favour of CSP.")

    def _d_cors_wildcard(self):
        acao = self.m.header_get("Access-Control-Allow-Origin")
        if acao != "*":
            return None
        acac = (self.m.header_get("Access-Control-Allow-Credentials") or "").lower()
        if acac == "true":
            return self._finding(
                "CORS Wildcard Origin WITH Credentials Allowed", "Critical",
                "Access-Control-Allow-Origin: * together with Access-Control-Allow-Credentials: true.",
                "Browsers reject this exact combination, but it usually indicates the "
                "server's CORS logic is broken elsewhere (e.g. it may reflect an arbitrary "
                "Origin instead of '*' when credentials are involved) — resend the request "
                "with 'Origin: https://attacker.example.test' and check whether the response "
                "reflects it while still allowing credentials.",
                poc=(
                    "fetch('https://TARGET_URL_HERE', {credentials: 'include'})\n"
                    "  .then(r => r.text()).then(t => document.write(t));\n"
                    "// Host on https://attacker.example.test and check the browser console\n"
                    "// for a CORS error vs a successful cross-origin credentialed read."
                ),
                remediation="Never combine a wildcard Access-Control-Allow-Origin with "
                            "Access-Control-Allow-Credentials: true. Use an explicit allow-list.",
                report="Wildcard CORS origin combined with credentials allowed — high-risk misconfiguration.")
        return self._finding(
            "CORS Wildcard Origin (Access-Control-Allow-Origin: *)", "Medium",
            "Access-Control-Allow-Origin: * — any origin can read this response "
            "(browsers won't send credentials alongside a wildcard, so this is lower risk "
            "unless the endpoint requires no auth at all to reach).",
            "Confirm this endpoint does not return sensitive/authenticated data. If it "
            "requires a cookie/Authorization header to reach at all, wildcard CORS on it "
            "is still worth flagging even though the browser blocks credentialed reads.",
            remediation="If the response contains any non-public data, replace '*' with an "
                        "explicit allow-list of trusted origins.",
            report="Wildcard CORS Access-Control-Allow-Origin header present.")

    def _d_cors_allowlist_present(self):
        acao = self.m.header_get("Access-Control-Allow-Origin")
        acac = (self.m.header_get("Access-Control-Allow-Credentials") or "").lower()
        if not acao or acao == "*":
            return None
        return self._finding(
            "CORS Origin Allow-List Present — Verify It Is Not Reflection-Based", "Info",
            f"Access-Control-Allow-Origin: {acao}"
            + (" ; Access-Control-Allow-Credentials: true" if acac == "true" else ""),
            "Resend the request with a different (attacker-controlled) Origin header and "
            "confirm the server does NOT simply reflect whatever Origin was sent back — "
            "that would be equivalent to a wildcard but with credentials allowed, which is "
            "the highest-impact CORS misconfiguration.",
            notes="Confirm before ruling this out, especially if Allow-Credentials: true is set.",
            report="CORS allow-list origin present; confirm it is a genuine allow-list, not a reflection.")

    def _d_server_tech_disclosure(self):
        hits = []
        for h in self._TECH_HEADERS:
            v = self.m.header_get(h)
            if v:
                hits.append(f"{h}: {v}")
        if not hits:
            return None
        version_like = any(re.search(r"\d+\.\d+", v) for v in hits)
        return self._finding(
            "Server/Framework Version Disclosure", "Low" if version_like else "Info",
            "; ".join(hits),
            "Cross-reference the disclosed software/version against known CVEs for that "
            "exact version.",
            remediation="Remove or generic-ise Server/X-Powered-By and similar headers at "
                        "the web server / reverse proxy layer.",
            report="Server/framework version disclosed via response headers.")

    def _d_insecure_cookies(self):
        cookies = self.m.header_get_all("Set-Cookie")
        if not cookies:
            return None
        out = []
        for c in cookies:
            name = c.split("=", 1)[0].strip()
            lc = c.lower()
            missing = []
            if "secure" not in lc:
                missing.append("Secure")
            if "httponly" not in lc:
                missing.append("HttpOnly")
            if "samesite" not in lc:
                missing.append("SameSite")
            if missing:
                out.append(self._finding(
                    f"Cookie Missing {'/'.join(missing)} Attribute: {name}",
                    "High" if ("Secure" in missing or "HttpOnly" in missing) else "Low",
                    f"Set-Cookie: {c}",
                    f"Confirm whether cookie '{name}' carries session/auth state — if so, "
                    f"missing {', '.join(missing)} increases XSS/MITM/CSRF exposure.",
                    remediation="Set Secure, HttpOnly and an explicit SameSite (Lax/Strict) "
                                "on every session/auth cookie.",
                    report=f"Cookie '{name}' missing {', '.join(missing)} attribute(s)."))
        return out

    def _d_verbose_error(self):
        body = self.m.body or ""
        hits = sorted({label for pattern, label in self._ERROR_SIGNATURES if pattern.search(body)})
        if not hits:
            return None
        return self._finding(
            "Verbose Error / Stack Trace Disclosure", "High",
            f"Signature(s) matched in response body: {', '.join(hits)}",
            "Verbose errors can disclose file paths, framework/library versions, SQL "
            "queries and internal logic. Try to trigger this consistently and confirm it "
            "is not gated behind a debug flag left on in production.",
            remediation="Disable debug/verbose error pages in production; return generic "
                        "error responses and log details server-side only.",
            report="Verbose error/stack trace disclosed in the response body.")

    def _d_directory_listing(self):
        body = self.m.body or ""
        if re.search(r"Index of /", body) or re.search(r"<title>Directory listing for", body, re.I):
            return self._finding(
                "Directory Listing Enabled", "Medium",
                "Response body matches a directory-listing page (autoindex-style output).",
                "Browse the listing for backup files, config files, source archives or "
                "other unintended disclosures.",
                remediation="Disable directory autoindexing on the web server / static file host.",
                report="Directory listing is enabled on this path.")
        return None

    def _d_sensitive_data_exposure(self):
        body = self.m.body or ""
        hits = []
        if self._AWS_KEY_RE.search(body):
            hits.append("AWS access key ID pattern")
        if self._PRIVATE_KEY_RE.search(body):
            hits.append("PEM private key block")
        jwt_matches = self._JWT_RE.findall(body)
        if jwt_matches:
            hits.append(f"JWT token(s) in body ({len(jwt_matches)})")
        emails = set(self._EMAIL_RE.findall(body))
        if len(emails) >= 5:
            hits.append(f"bulk email addresses in body ({len(emails)} unique)")
        if not hits:
            return None
        risk = "Critical" if any("private key" in h.lower() or "aws" in h.lower() for h in hits) else "High"
        return self._finding(
            "Sensitive Data Exposed in Response Body", risk,
            "; ".join(hits),
            "Confirm this data should be returned to this caller/role at all (excessive "
            "data exposure) and that secrets (keys, tokens) are not hard-coded or leaked.",
            remediation="Strip secrets from responses; apply field-level authorisation so "
                        "only necessary data is returned per role.",
            report="Sensitive data (keys/tokens/bulk PII) found in the response body.")

    def _d_missing_cache_control(self):
        cc = (self.m.header_get("Cache-Control") or "").lower()
        looks_sensitive = bool(self.m.header_get_all("Set-Cookie")) or bool(self._JWT_RE.search(self.m.body or ""))
        if not looks_sensitive:
            return None
        if "no-store" in cc or ("private" in cc and "no-cache" in cc):
            return None
        return self._finding(
            "Missing/Weak Cache-Control on Sensitive Response", "Medium",
            f"Response sets a cookie or carries a token, but Cache-Control is: {cc or '(absent)'}",
            "Confirm this response is not cached by a shared proxy/CDN or stored in "
            "browser disk cache (check on a shared machine / via browser dev tools).",
            remediation="Add 'Cache-Control: no-store' (and 'Pragma: no-cache' for legacy "
                        "clients) on any response carrying session/auth data or PII.",
            report="Sensitive-looking response lacks a strong no-store Cache-Control directive.")

    def _d_http_methods_disclosure(self):
        allow = self.m.header_get("Allow") or self.m.header_get("Access-Control-Allow-Methods")
        if not allow:
            return None
        methods = {mm.strip().upper() for mm in allow.split(",")}
        risky = methods & {"PUT", "DELETE", "TRACE", "CONNECT", "PATCH"}
        if not risky:
            return None
        return self._finding(
            "Potentially Risky HTTP Methods Advertised", "Low",
            f"Allow/Access-Control-Allow-Methods: {allow}",
            "Confirm each advertised method is actually needed and properly "
            "authenticated/authorised — TRACE in particular can enable Cross-Site "
            "Tracing (XST) if reflected back in a response.",
            remediation="Disable unused HTTP methods at the web server / framework level.",
            report="Response advertises potentially risky HTTP methods.")

    def _d_mixed_content(self):
        body = self.m.body or ""
        if "text/html" not in self.m.content_type:
            return None
        hits = re.findall(r'(?:src|href)=["\']http://[^"\']+', body)
        if not hits:
            return None
        return self._finding(
            "Possible Mixed Content (HTTP resources in HTML)", "Low",
            f"{len(hits)} http:// resource reference(s) found in HTML body, e.g. {hits[0]}",
            "If this page is served over HTTPS, browsers will block/warn on these "
            "sub-resources — confirm and update them to https:// or protocol-relative URLs.",
            remediation="Serve all sub-resources over HTTPS; consider "
                        "'Content-Security-Policy: upgrade-insecure-requests'.",
            report="Possible mixed content — HTTP resource references in an HTML response.")

    def _d_html_comment_leak(self):
        body = self.m.body or ""
        if "text/html" not in self.m.content_type:
            return None
        comments = re.findall(r"<!--(.*?)-->", body, re.S)
        hits = [c.strip()[:120] for c in comments if any(k in c.lower() for k in self._COMMENT_KEYWORDS)]
        if not hits:
            return None
        return self._finding(
            "Sensitive Keyword in HTML Comment", "Low",
            f"{len(hits)} comment(s) matched, e.g.: \"{hits[0]}\"",
            "Review the full comment text for leaked credentials, internal notes or "
            "disabled/dead functionality that may still be reachable.",
            remediation="Strip developer comments from production HTML output.",
            report="HTML comment(s) containing sensitive-looking keywords found.")

    def _d_json_error_verbosity(self):
        if "json" not in self.m.content_type:
            return None
        obj = self.m.json_body()
        if not isinstance(obj, dict):
            return None
        verbose_keys = [k for k in obj if k.lower() in
                        ("stacktrace", "stack_trace", "trace", "innerexception", "exception", "debug")]
        if not verbose_keys:
            return None
        return self._finding(
            "Verbose Error Detail in JSON Response", "Medium",
            f"JSON key(s) present: {', '.join(verbose_keys)}",
            "Confirm these fields do not leak file paths, queries or internal class/module "
            "names to end clients in production.",
            remediation="Return a generic error object to clients; log full detail server-side only.",
            report="JSON error response includes verbose stack/trace detail.")


class ResponseAnalysisMixin:
    """GUI glue for the Response Analysis tab. Passive: never sends requests.

    Session-level dedup: self._resp_identified_fingerprints (lazily created) tracks
    finding titles already surfaced this session so pasting several responses from
    the same target doesn't keep re-flagging the same site-wide issue. Saved reports
    always include every finding from the CURRENT response, regardless of dedup.
    """

    def analyse_response(self):
        raw = self.resp_input.toPlainText() if hasattr(self, "resp_input") else ""
        model = parse_raw_response(raw)
        if model is None:
            self.resp_summary.setPlainText(
                "Could not parse a response.\n\nPaste a full raw HTTP response: the status "
                "line (e.g. 'HTTP/1.1 200 OK'), the headers, then a blank line and the body. "
                "You can copy this straight from Burp (right-click a response → Copy)."
            )
            self.resp_vectors.clear()
            self.resp_output.setPlainText("")
            self.resp_detail.setText("")
            return

        analyzer = ResponseAnalyzer(model)
        all_findings = analyzer.analyze()
        summary = analyzer.summary()
        self._resp_model = model
        self._resp_all_findings = all_findings

        identified = getattr(self, "_resp_identified_fingerprints", set())
        new_findings = [f for f in all_findings if f["fingerprint"] not in identified]
        suppressed_count = len(all_findings) - len(new_findings)
        for f in new_findings:
            identified.add(f["fingerprint"])
        self._resp_identified_fingerprints = identified
        self._resp_findings = new_findings

        self.resp_summary.setPlainText(
            self._resp_format_summary(summary, new_findings, suppressed_count, len(all_findings)))

        from PyQt6.QtWidgets import QListWidgetItem
        from PyQt6.QtGui import QColor
        self.resp_vectors.clear()
        for f in new_findings:
            item = QListWidgetItem(f"[{f['risk']}]  {f['title']}")
            item.setForeground(QColor(RISK_COLORS.get(f["risk"], "#e2e8f0")))
            self.resp_vectors.addItem(item)

        if new_findings:
            self.resp_vectors.setCurrentRow(0)
        else:
            self.resp_output.setPlainText("")
            if all_findings:
                self.resp_detail.setText(
                    f"All {len(all_findings)} finding(s) in this response were already "
                    "identified earlier this session. Use 'Clear Identified Findings' "
                    "to show them again.")
            else:
                self.resp_detail.setText("No issues detected in this response.")

    def _resp_format_summary(self, s, findings, suppressed_count, total_count):
        lines = [
            "=" * 50,
            "RESPONSE ANALYSIS COMPLETE",
            "=" * 50,
            f"Status            : {s['status_code']} {s['status_text']}",
            f"HTTP Version      : {s['version']}",
            f"Content-Type      : {s['content_type']}",
            f"Server            : {s['server']}",
            f"Set-Cookie Count  : {s['set_cookie_count']}",
            f"Body Length       : {s['body_length']} bytes",
            "",
        ]
        if suppressed_count:
            lines.append(
                f"({suppressed_count} of {total_count} finding(s) already identified earlier "
                "this session and suppressed below — use 'Clear Identified Findings' to show them again.)")
            lines.append("")
        lines += ["New/Outstanding Findings:", ""]
        for f in findings:
            lines.append(f"[{f['risk']}] {f['title']}")
            lines.append(f"  Evidence: {f['evidence']}")
            lines.append(f"  Suggested Test: {f['suggested_test']}")
            if f.get("remediation"):
                lines.append(f"  Remediation: {f['remediation']}")
            lines.append("")
        if not findings:
            lines.append("(none)")
            lines.append("")
        lines.append("Note: these are suggested test points requiring manual validation")
        lines.append("against authorised systems only. No requests have been sent.")
        return "\n".join(lines)

    def _on_resp_vector_selected(self, row):
        findings = getattr(self, "_resp_findings", [])
        if row is None or row < 0 or row >= len(findings):
            return
        f = findings[row]
        detail = (f"[{f['risk']}] {f['title']}\n\n"
                  f"Why flagged: {f['evidence']}\n\n"
                  f"Suggested test: {f['suggested_test']}")
        if f.get("notes"):
            detail += f"\n\nNotes: {f['notes']}"
        if f.get("remediation"):
            detail += f"\n\nRemediation: {f['remediation']}"
        if f.get("report_wording"):
            detail += f"\n\nReport wording: {f['report_wording']}"
        self.resp_detail.setText(detail)
        self.resp_output.setPlainText(
            f.get("poc") or "(no PoC/example for this finding — see the detail panel above.)")

    def clear_response(self):
        self.resp_input.setPlainText("")
        self.resp_summary.setPlainText("")
        self.resp_output.setPlainText("")
        self.resp_detail.setText("")
        self.resp_vectors.clear()
        self._resp_findings = []

    def clear_identified_findings(self):
        """Reset the session-level 'already seen' fingerprint set so previously
        suppressed findings will surface again on the next Analyse Response."""
        self._resp_identified_fingerprints = set()
        try:
            self.flash_status("Identified findings cleared")
        except Exception:
            pass
        self.show_themed_message(
            "Cleared",
            "Cleared this session's identified-findings history. Findings already shown "
            "will surface again the next time you analyse a response.")

    def copy_original_response(self):
        self._resp_copy(self.resp_input.toPlainText(), "Original response")

    def copy_response_finding_detail(self):
        self._resp_copy(self.resp_output.toPlainText(), "Finding detail/PoC")

    def _resp_copy(self, text, label):
        if not text.strip():
            self.show_themed_message("Nothing to copy", f"{label} is empty.")
            return
        from PyQt6.QtWidgets import QApplication
        QApplication.clipboard().setText(text)
        try:
            self.flash_status(f"{label} copied")
        except Exception:
            pass

    def save_response_analysis(self):
        findings = getattr(self, "_resp_all_findings", None)
        if not findings:
            self.show_themed_message("Nothing to Save", "Analyse a response first.")
            return
        from pathlib import Path as _Path
        out = _Path(self.output_dir)
        try:
            (out / "response_analysis_summary.txt").write_text(
                self.resp_summary.toPlainText(), encoding="utf-8", errors="replace")
            payload = {
                "findings": [
                    {"title": f["title"], "risk": f["risk"], "evidence": f["evidence"],
                     "suggested_test": f["suggested_test"], "notes": f.get("notes", ""),
                     "remediation": f.get("remediation", ""), "poc": f.get("poc", "")}
                    for f in findings
                ],
            }
            (out / "response_analysis_findings.json").write_text(
                json.dumps(payload, indent=2), encoding="utf-8", errors="replace")
        except Exception as e:
            self.show_themed_message("Save Error", f"Could not write analysis files: {e}")
            return
        self.show_themed_message(
            "Saved",
            "Wrote response_analysis_summary.txt and response_analysis_findings.json "
            "to the output directory.")
        try:
            self.refresh_file_list()
        except Exception:
            pass
