"""
Web testing — security headers, JWT, CORS PoC, JS checks.
"""
import os
import re
import sys
import json
import subprocess
from pathlib import Path

from PyQt6 import QtCore, QtGui, QtWidgets
from PyQt6.QtCore import QProcess, Qt, QTimer
from PyQt6.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
    QPushButton, QLabel, QLineEdit, QTextEdit, QTabWidget, QGridLayout,
    QGroupBox, QSplitter, QScrollArea, QFileDialog, QMessageBox,
    QComboBox, QFrame, QPlainTextEdit, QProgressBar, QToolButton,
)
from command_bridge.constants import APP_TITLE, APP_VERSION, THEMES, BASE_DIR



class WebTestingMixin:
    """Mixin providing web testing — security headers, jwt, cors poc, js checks."""

    def analyze_security_headers(self):
        """Analyze security headers for the current target (ported from v2)."""
        # Get target from the Target Setup tab
        target = (self.target_input.text() or "").strip()
        if not target:
            self.show_themed_message(
                "Target required",
                "Please enter a target URL or domain.",
                QMessageBox.Icon.Warning,
            )
            return
        
        # Normalize URL similar to v2 logic
        try:
            url = target
            if not (url.startswith("http://") or url.startswith("https://")):
                url = ("http://" if ":80" in target else "https://") + target
        except Exception:
            url = target if target.startswith(("http://", "https://")) else ("https://" + target)
        
        import ssl
        from urllib import request
        
        # Ensure Console tab is visible before printing output
        try:
            self.goto_console()
        except Exception:
            pass
        
        self.console.append_ansi(f"\n==> Audit Server Response: {url}\n")
        self.console.append_ansi("\n")
        self.console.append_ansi("[i] Fetching response headers (timeout 5s)…\n")
        
        # Build request headers (include any custom headers from Target Setup)
        headers = {"User-Agent": "Evalian Penetration Test/1.0", "Accept": "*/*"}
        custom_headers = self.headers_input.toPlainText().strip()
        if custom_headers:
            for line in custom_headers.split("\n"):
                if ":" in line:
                    name, value = line.split(":", 1)
                    name = name.strip()
                    if name:
                        headers[name] = value.strip()
        
        try:
            ctx = ssl.create_default_context()
            req = request.Request(url, headers=headers, method="GET")
            # Use a shorter timeout so the UI is not blocked for too long
            with request.urlopen(req, timeout=5, context=ctx) as resp:
                # Preserve original headers list and also a lowercase dict for checks
                resp_headers_list = list(resp.getheaders())
                hdrs = {k.lower(): v for k, v in resp_headers_list}
                # Build reproducible request/response blocks for reports
                from urllib.parse import urlparse
                pu = urlparse(url)
                path_q = (pu.path or "/") + (f"?{pu.query}" if pu.query else "")
                host_hdr = pu.netloc or pu.hostname or ""
                req_lines = [
                    f"GET {path_q} HTTP/1.1",
                    f"Host: {host_hdr}",
                    "User-Agent: Evalian Penetration Test/1.0",
                    "Accept: */*",
                ]
                captured_request_text = "\n".join(req_lines)
                ver = {10: "HTTP/1.0", 11: "HTTP/1.1"}.get(getattr(resp, "version", 11), "HTTP/1.1")
                status_line = f"{ver} {getattr(resp, 'status', 0)} {getattr(resp, 'reason', '')}".rstrip()
                resp_lines = [status_line] + [f"{k}: {v}" for (k, v) in resp_headers_list]
                captured_response_text = "\n".join(resp_lines)
        except Exception as e:
            self.console.append_ansi(f"[!] Request failed: {e}\n")
            return
        
        # Processing phase (logic mirrored from v2)
        self.console.append_ansi("[i] Processing security headers…\n")
        green = "\033[1;92m"
        red = "\033[1;91m"
        yellow = "\033[1;33m"
        reset = "\033[0m"
        ticks = {True: f" {green}✅{reset}", False: f" {red}❌{reset}"}
        issues = []
        detected_lines = []
        missing_lines = []

        # Detect duplicate security headers (e.g. multiple CSP / HSTS entries).
        header_counts: dict[str, int] = {}
        for k, v in resp_headers_list:
            name = (k or "").lower()
            if not name:
                continue
            header_counts[name] = header_counts.get(name, 0) + 1

        # Only flag duplicates for headers where multiple values are typically
        # ambiguous or unsafe. We intentionally do NOT flag duplicate
        # Set-Cookie headers, as multiple cookies are expected and
        # specification-compliant.
        dup_header_map = {
            "content-security-policy": "Content-Security-Policy",
            "strict-transport-security": "Strict-Transport-Security",
            "x-frame-options": "X-Frame-Options",
            "x-content-type-options": "X-Content-Type-Options",
            "x-permitted-cross-domain-policies": "X-Permitted-Cross-Domain-Policies",
            "referrer-policy": "Referrer-Policy",
            "permissions-policy": "Permissions-Policy",
            "feature-policy": "Feature-Policy",
            "access-control-allow-origin": "Access-Control-Allow-Origin",
            "cache-control": "Cache-Control",
        }

        for lname, pretty in dup_header_map.items():
            if header_counts.get(lname, 0) > 1:
                if lname == "content-security-policy":
                    issues.append(
                        "Duplicate Content-Security-Policy headers detected; combine all directives into a single CSP header so browsers enforce one unified policy (e.g. Content-Security-Policy: upgrade-insecure-requests; frame-ancestors 'self'; report-uri /_/commcsp?disposition=enforce)."
                    )
                else:
                    issues.append(
                        f"Duplicate {pretty} headers detected; send a single consolidated {pretty} header to ensure predictable enforcement across browsers."
                    )
        
        def line(name, value, ok, count_missing=True, note: str = ""):
            val_disp = value if value is not None else "<missing>"
            name_color = green if ok else red
            suffix = f" - {note}" if note else ""
            # Color only the header name and the tick; leave value with its own inline highlights
            formatted = f"{name_color}{name}:{reset} {val_disp}{ticks[ok]}{suffix}\n"
            if value is None and count_missing:
                # Missing header: report under Missing section only
                mnote = f" - {note}" if note else ""
                missing_lines.append(f"{red}{name}: <missing> {ticks[False]}{mnote}{reset}\n")
            else:
                # Present (detected), regardless of pass/fail
                detected_lines.append(formatted)
        
        # HSTS
        hsts = hdrs.get('strict-transport-security')
        h_ok = False
        if hsts:
            low = hsts.lower()
            try:
                import re as _re
                # Accept either '=' or ':' after max-age
                m = _re.search(r"max-age\s*[:=]\s*([0-9]+)", low)
                maxage = int(m.group(1)) if m else 0
            except Exception:
                maxage = 0
            # 'preload' is optional; do not require it for HSTS to be OK
            h_ok = (maxage >= 31536000) and ("includesubdomains" in low)

            # If the header is present but fails our checks (❌ in the Detected
            # section), record *why* in the summary so every red line has a
            # corresponding explanation.
            if not h_ok:
                h_reasons = []
                if maxage < 31536000:
                    h_reasons.append("max-age is less than 31536000 (1 year);")
                if "includesubdomains" not in low:
                    h_reasons.append("includeSubDomains is missing; subdomains are not covered;")
                if h_reasons:
                    issues.append(
                        "Strict-Transport-Security misconfigured: " + " ".join(h_reasons)
                    )

            # Highlight useful tokens in HSTS value for visibility
            hsts_disp = hsts
            try:
                hsts_disp = _re.sub(r"(?i)\bincludeSubDomains\b", f"{green}includeSubDomains{reset}", hsts_disp)
                hsts_disp = _re.sub(r"(?i)\bpreload\b", f"{green}preload{reset}", hsts_disp)
            except Exception:
                hsts_disp = hsts
        else:
            issues.append("HSTS missing; enable Strict-Transport-Security with max-age>=31536000 and includeSubDomains.")
            hsts_disp = hsts
        line("Strict-Transport-Security", hsts_disp, h_ok)
        
        # CSP
        csp = hdrs.get('content-security-policy')
        csp_ok = False
        frame_anc = False
        if csp:
            low = csp.lower()
            frame_anc = ('frame-ancestors' in low)
            csp_ok = ("unsafe-inline" not in low) and ("*" not in low)
            if not csp_ok:
                if "unsafe-inline" in low:
                    issues.append("CSP contains 'unsafe-inline'; disallow inline scripts.")
                if "*" in low:
                    issues.append("CSP uses wildcard *; restrict sources.")
            # Highlight risky tokens inside CSP value for visibility
            csp_disp = csp
            try:
                import re as _re2
                # Basic direct replacements for common risky tokens — highlight in red
                for tok in ["'unsafe-inline'", "'unsafe-eval'", "data:", "http:"]:
                    if tok in csp_disp:
                        csp_disp = csp_disp.replace(tok, f"{red}{tok}{reset}")
                # Highlight frame-ancestors in green when present
                csp_disp = _re2.sub(r"(?i)\bframe-ancestors\b", f"{green}frame-ancestors{reset}", csp_disp)
                # Emphasize wildcard in red
                if "*" in csp_disp:
                    csp_disp = csp_disp.replace("*", f"{red}*{reset}")
            except Exception:
                csp_disp = csp
        else:
            issues.append("CSP missing; define a strict Content-Security-Policy.")
            csp_disp = csp
        line("Content-Security-Policy", csp_disp, csp_ok)
        
        # X-Frame-Options
        xfo = hdrs.get('x-frame-options')
        xfo_ok = False
        xfo_note = ""
        if frame_anc:
            # CSP frame-ancestors present; XFO not required
            xfo_ok = True if xfo is None or xfo.strip().upper() in ("DENY", "SAMEORIGIN") else False
            if xfo is None:
                xfo_note = "Okay, because frame-ancestors is detected in the CSP"
            if not xfo_ok:
                issues.append("X-Frame-Options value invalid; use DENY or SAMEORIGIN or rely on CSP frame-ancestors.")
        else:
            if xfo is None:
                issues.append("X-Frame-Options missing (or set frame-ancestors in CSP).")
            else:
                val = xfo.strip().upper()
                xfo_ok = val in ("DENY", "SAMEORIGIN")
                if not xfo_ok:
                    issues.append("X-Frame-Options must be DENY or SAMEORIGIN.")
        # Only include in Missing if CSP frame-ancestors is NOT present; include note when applicable
        line("X-Frame-Options", xfo, xfo_ok, count_missing=(not frame_anc), note=xfo_note)
        
        # X-Content-Type-Options
        xcto = hdrs.get('x-content-type-options')
        xcto_ok = (xcto is not None and xcto.strip().lower() == 'nosniff')
        if not xcto_ok:
            issues.append("X-Content-Type-Options missing or not 'nosniff'.")
        line("X-Content-Type-Options", xcto, xcto_ok)
        
        # X-Permitted-Cross-Domain-Policies
        xpcdp = hdrs.get('x-permitted-cross-domain-policies')
        xpcdp_ok = (xpcdp is not None and xpcdp.strip().lower() in ('none', 'master-only'))
        if not xpcdp_ok:
            issues.append("X-Permitted-Cross-Domain-Policies should be 'none' or 'master-only'.")
        line("X-Permitted-Cross-Domain-Policies", xpcdp, xpcdp_ok)
        
        # X-XSS-Protection (deprecated, should not exist)
        xxxs = hdrs.get('x-xss-protection')
        xxxs_ok = (xxxs is None)
        if not xxxs_ok:
            issues.append("X-XSS-Protection is deprecated and should be removed.")
        # Do not include X-XSS-Protection in Missing section when absent (it's deprecated)
        line("X-XSS-Protection", xxxs, xxxs_ok, count_missing=False)
        
        # Additional best practice checks
        import re as _re
        server_header = hdrs.get('server')
        x_powered = hdrs.get('x-powered-by')
        server_value = server_header or x_powered
        server_ok = True
        if server_value:
            # Heuristic: presence of version tokens like "/1.2.3" or digits with dots
            if _re.search(r"\b[A-Za-z0-9_-]+/[0-9]+(?:\.[0-9]+)*\b", server_value) or _re.search(r"\bPHP/[0-9]", server_value, _re.I):
                server_ok = False
                issues.append("Server header discloses exact version; remove or obfuscate version details.")
            line("Server", server_value, server_ok)
        
        # CORS
        aco = hdrs.get('access-control-allow-origin')
        acc = hdrs.get('access-control-allow-credentials')
        cors_ok = True
        if aco:
            if aco.strip() == '*' or '*' in aco:
                cors_ok = False
                issues.append("CORS allows all origins (*); restrict to explicit trusted origins.")
            if (acc and acc.strip().lower() == 'true') and (aco and ('*' in aco)):
                cors_ok = False
                if "credentials" not in " ".join(issues).lower():
                    issues.append("CORS allows credentials with wildcard origin; define specific origins or disable credentials.")
            line("Access-Control-Allow-Origin", aco, cors_ok)
            if acc is not None:
                # Show credentials header for visibility
                line("Access-Control-Allow-Credentials", acc, cors_ok)
        
        # Referrer-Policy (do not flag as missing; only display if present and strong)
        refp = hdrs.get('referrer-policy')
        if refp is not None:
            good_referrers = {'no-referrer', 'same-origin', 'strict-origin-when-cross-origin'}
            ref_ok = (refp.strip().lower() in good_referrers)
            line("Referrer-Policy", refp, ref_ok, count_missing=False)
        
        # Permissions-Policy (do not flag as missing; only display if present)
        perm = hdrs.get('permissions-policy') or hdrs.get('feature-policy')
        if perm is not None:
            line("Permissions-Policy", perm, True, count_missing=False)
        
        # Cache-Control (do not flag as missing; only display if present and problematic with cookies)
        cc = hdrs.get('cache-control')
        set_cookies = [v for (k, v) in resp_headers_list if k.lower() == 'set-cookie']
        if cc is not None:
            cc_ok = True
            if set_cookies:
                low = (cc or '').lower()
                if (('no-store' not in low) and ('private' not in low)) or ('public' in low):
                    cc_ok = False
                    issues.append("Cache-Control not suitable for authenticated/sensitive responses; add no-store or private.")
            line("Cache-Control", cc, cc_ok, count_missing=False)
        
        # Set-Cookie flags
        cookie_ok = True
        if set_cookies:
            for c in set_cookies:
                c_low = c.lower()
                missing = []
                if 'secure' not in c_low:
                    missing.append('Secure')
                if 'httponly' not in c_low:
                    missing.append('HttpOnly')
                if 'samesite' not in c_low:
                    missing.append('SameSite')
                if missing:
                    cookie_ok = False
                    issues.append(f"Set-Cookie missing flags: {', '.join(missing)}.")
            # Show first cookie entry for detection listing
            shown_cookie = set_cookies[0]
            line("Set-Cookie", shown_cookie, cookie_ok)
        
        # Output sections
        det_block = None
        miss_block = None
        summary_block = None
        if detected_lines:
            det_block = "\nDetected Headers:\n" + "".join(detected_lines)
            if not det_block.endswith("\n\n"):
                det_block = det_block.rstrip("\n") + "\n\n"
        if missing_lines:
            miss_block = f"\n{red}Missing security headers:{reset}\n" + "".join(missing_lines)
            if not miss_block.endswith("\n\n"):
                miss_block = miss_block.rstrip("\n") + "\n\n"
        if issues:
            summary_block = "\nSummary of Issues:\n" + "\n".join(issues) + "\n\n"
        
        # Append structured HTTP request/response blocks for reporting with clear spacing
        req_block = (
            "\n### Captured HTTP GET Request ###\n" +
            captured_request_text + "\n\n"
        )
        resp_block = (
            "\n### Captured HTTP Server Response ###\n" +
            captured_response_text + "\n\n"
        )
        
        report_para = self._generate_security_report_paragraph(issues, url)

        final_parts = []
        if det_block:
            final_parts.append(det_block)
        if miss_block:
            final_parts.append(miss_block)
        if summary_block:
            final_parts.append(summary_block)
        if report_para:
            final_parts.append(report_para)
        final_parts.append(req_block)
        final_parts.append(resp_block)

        self.console.append_ansi("".join(final_parts))

    def _generate_security_report_paragraph(self, issues: list, url: str) -> str:
        """Return a British English, past-tense penetration test report paragraph."""
        if not issues:
            para = (
                f"During the engagement, the consultant examined the HTTP response headers returned by the "
                f"target application hosted at {url}. The review indicated that all assessed security headers "
                f"were present and correctly configured in accordance with current best-practice guidance. "
                f"No remediation was required in respect of the HTTP security header configuration at the "
                f"time of testing."
            )
            return f"\n### Penetration Test Report Extract ###\n{para}\n\n"

        joined = " ".join(issues).lower()

        findings_sentences = []

        # HSTS
        if "strict-transport-security" in joined or "hsts" in joined:
            if "missing" in joined and "hsts" in joined or ("hsts missing" in joined):
                findings_sentences.append(
                    "The Strict-Transport-Security (HSTS) header was absent from the server response, "
                    "meaning the application did not instruct browsers to enforce HTTPS-only communication; "
                    "this omission rendered users susceptible to SSL-stripping and protocol-downgrade attacks."
                )
            else:
                findings_sentences.append(
                    "The Strict-Transport-Security (HSTS) header was present but misconfigured; the "
                    "max-age directive did not meet the recommended minimum of one year and/or the "
                    "includeSubDomains directive was absent, thereby leaving subdomains unprotected."
                )

        # CSP
        if "content-security-policy" in joined or "csp" in joined:
            if "csp missing" in joined or ("csp" in joined and "missing" in joined):
                findings_sentences.append(
                    "No Content Security Policy (CSP) header was observed in the server response, "
                    "leaving the application without a browser-enforced mechanism to restrict the "
                    "sources from which scripts, styles, and other resources could be loaded, thereby "
                    "increasing exposure to cross-site scripting (XSS) and data-injection attacks."
                )
            else:
                csp_details = []
                if "unsafe-inline" in joined:
                    csp_details.append("permitted inline script execution via the 'unsafe-inline' directive")
                if "wildcard" in joined or ("csp" in joined and "*" in joined):
                    csp_details.append("employed wildcard source definitions which negated the policy's protective intent")
                detail_str = "; it " + " and ".join(csp_details) if csp_details else ""
                findings_sentences.append(
                    f"A Content Security Policy header was identified{detail_str}; the policy configuration "
                    f"did not align with OWASP best-practice guidance and required tightening to afford "
                    f"meaningful protection against cross-site scripting."
                )

        # Duplicate headers
        if "duplicate" in joined:
            findings_sentences.append(
                "One or more security headers were transmitted multiple times within a single HTTP response; "
                "browser behaviour when processing duplicate headers is inconsistent and browsers may honour "
                "only one instance, potentially nullifying the intended security control."
            )

        # X-Frame-Options
        if "x-frame-options" in joined:
            if "missing" in joined and "x-frame-options" in joined:
                findings_sentences.append(
                    "The X-Frame-Options header was not present and no frame-ancestors directive was "
                    "defined within the Content Security Policy, meaning the application could be "
                    "embedded within a third-party iframe and was therefore susceptible to clickjacking attacks."
                )
            else:
                findings_sentences.append(
                    "The X-Frame-Options header was present but its value was not set to an accepted "
                    "directive (DENY or SAMEORIGIN), which reduced the effectiveness of clickjacking "
                    "protections afforded to end users."
                )

        # X-Content-Type-Options
        if "x-content-type-options" in joined:
            findings_sentences.append(
                "The X-Content-Type-Options header was either absent or not set to 'nosniff', "
                "permitting browsers to perform MIME-type sniffing on server responses; this behaviour "
                "could be exploited to cause user-agent content misinterpretation and facilitate "
                "cross-site scripting in certain contexts."
            )

        # X-Permitted-Cross-Domain-Policies
        if "x-permitted-cross-domain-policies" in joined:
            findings_sentences.append(
                "The X-Permitted-Cross-Domain-Policies header was absent or misconfigured; without "
                "an explicit 'none' or 'master-only' policy, legacy Adobe Flash and PDF plug-ins "
                "could retrieve a cross-domain policy file and access content across domain boundaries."
            )

        # Server version disclosure
        if "server header discloses" in joined or "version" in joined and "server" in joined:
            findings_sentences.append(
                "The Server response header disclosed precise software version information, providing "
                "an attacker with intelligence that could be used to identify publicly known "
                "vulnerabilities affecting the underlying web server technology."
            )

        # CORS
        if "cors" in joined:
            if "credentials" in joined and "wildcard" in joined:
                findings_sentences.append(
                    "The application was configured to return the Access-Control-Allow-Origin header "
                    "with a wildcard value in conjunction with Access-Control-Allow-Credentials: true; "
                    "this combination, whilst rejected by modern browsers, represented a misconfiguration "
                    "that should be remediated by specifying explicit trusted origins."
                )
            else:
                findings_sentences.append(
                    "The Cross-Origin Resource Sharing (CORS) configuration permitted requests from any "
                    "origin via the Access-Control-Allow-Origin: * directive; it was recommended that "
                    "this be restricted to explicitly enumerated, trusted origins to prevent "
                    "unauthorised cross-origin data access."
                )

        # Cookie flags
        if "set-cookie" in joined and "flag" in joined:
            cookie_missing = []
            if "secure" in joined and "missing flags" in joined:
                cookie_missing.append("Secure")
            if "httponly" in joined and "missing flags" in joined:
                cookie_missing.append("HttpOnly")
            if "samesite" in joined and "missing flags" in joined:
                cookie_missing.append("SameSite")
            if cookie_missing:
                flags_str = ", ".join(cookie_missing)
                findings_sentences.append(
                    f"Session cookies issued by the application were observed to be missing the "
                    f"{flags_str} attribute(s); the absence of these flags increased the risk of "
                    f"cookie theft via network interception, JavaScript access, and cross-site "
                    f"request forgery respectively."
                )
            else:
                findings_sentences.append(
                    "Session cookies were identified that lacked one or more recommended security "
                    "attributes, increasing the risk of session hijacking and cross-site request "
                    "forgery attacks."
                )

        # Cache-Control
        if "cache-control" in joined and "no-store" in joined:
            findings_sentences.append(
                "The Cache-Control header was not configured appropriately for responses containing "
                "session state or sensitive data; the absence of the no-store or private directive "
                "meant that responses could be cached by intermediate proxies, potentially exposing "
                "sensitive information to subsequent users of shared infrastructure."
            )

        # Build the full paragraph
        findings_text = " ".join(findings_sentences)
        count = len(issues)
        issue_word = "issue was" if count == 1 else "issues were"
        opening = (
            f"During the engagement, the consultant examined the HTTP response headers returned by the "
            f"target application hosted at {url}. The review identified {count} security header "
            f"{issue_word} present, as detailed below. "
        )
        closing = (
            "It was recommended that the development and infrastructure teams address the identified "
            "deficiencies in accordance with OWASP guidance and industry best practice to improve the "
            "security posture of the application and reduce exposure to client-side attack vectors."
        )
        para = opening + findings_text + " " + closing
        return f"\n### Penetration Test Report Extract ###\n{para}\n\n"

    def jwt_decode_prompt(self):
        """Prompt for a JWT, decode it locally, print to console, and save to disk."""
        from PyQt6.QtWidgets import QInputDialog
        import io

        # Ask user for the JWT string
        token, ok = QInputDialog.getText(
            self,
            "JWT Decode",
            "Paste JWT token to decode:",
        )
        if not ok or not token.strip():
            return
        token = token.strip()

        # Ensure console tab is visible
        try:
            self.goto_console()
        except Exception:
            pass

        # Decode using built-in jwt_decode.py logic, capturing output
        output_buf = io.StringIO()
        try:
            self._decode_jwt_to_buffer(token, output_buf)
            decoded_text = output_buf.getvalue()
        except Exception as e:
            decoded_text = f"[-] Failed to decode JWT: {e}\n"

        # Print to console
        self.console.append_ansi("\n=== JWT Decode ===\n")
        self.console.append_ansi(decoded_text + "\n")

        # Save to output directory
        try:
            safe_target = self.sanitize_target_for_filename(self.target) if self.target else "jwt"
            out_path = self.output_dir / f"{safe_target}_jwt_decode.txt"
            with open(out_path, "w", encoding="utf-8", errors="replace") as f:
                f.write(decoded_text + "\n")
            self.console.append_ansi(f"[i] JWT decode output saved to: {out_path}\n")
            self.refresh_file_list()
        except Exception as e:
            self.console.append_ansi(f"[i] Could not save JWT decode output: {e}\n")

    def _decode_jwt_to_buffer(self, token: str, buf) -> None:
        """Decode a JWT and write human-friendly output into `buf`.

        This is an embedded version of /home/ldawson/Desktop/jwt_decode.py so
        the functionality is part of the application and does not depend on an
        external script file.
        """
        import base64
        import json
        from datetime import datetime, timezone, timedelta

        def b64url_decode(data: str) -> bytes:
            # Decode base64url without padding.
            data = data or ""
            data += "=" * (-len(data) % 4)
            return base64.urlsafe_b64decode(data.encode())

        def format_time(ts: float) -> str:
            # Convert UNIX timestamp to human-readable date string.
            try:
                dt = datetime.fromtimestamp(ts, tz=timezone.utc)
                return dt.strftime("%Y-%m-%d %H:%M:%S UTC")
            except Exception:
                return "Invalid timestamp"

        def describe_delta(seconds: float) -> str:
            # Return human-friendly delta like '1 day', '2 hours', etc.
            delta = timedelta(seconds=abs(seconds))
            days = delta.days
            hours = delta.seconds // 3600
            minutes = (delta.seconds % 3600) // 60

            parts = []
            if days:
                parts.append(f"{days} day{'s' if days != 1 else ''}")
            if hours:
                parts.append(f"{hours} hour{'s' if hours != 1 else ''}")
            if minutes and not days:
                parts.append(f"{minutes} minute{'s' if minutes != 1 else ''}")

            if not parts:
                parts.append("seconds")

            return ", ".join(parts)

        def print_time_claim(label: str, ts: float) -> None:
            real_time = format_time(ts)
            now = datetime.now(timezone.utc).timestamp()

            if label == "Issued At":
                delta = now - ts
                desc = describe_delta(delta)
                buf.write(f"[+] {label} (iat) = {ts} ({real_time})  → {desc} ago\n")

            elif label == "Not Before":
                if now < ts:
                    delta = ts - now
                    desc = describe_delta(delta)
                    buf.write(f"[+] {label} (nbf) = {ts} ({real_time})  → valid in {desc}\n")
                else:
                    buf.write(f"[+] {label} (nbf) = {ts} ({real_time})  → already valid\n")

            elif label == "Expires At":
                if now > ts:
                    delta = now - ts
                    desc = describe_delta(delta)
                    buf.write(f"[+] {label} (exp) = {ts} ({real_time})  → expired {desc} ago\n")
                else:
                    delta = ts - now
                    desc = describe_delta(delta)
                    buf.write(f"[+] {label} (exp) = {ts} ({real_time})  → expires in {desc}\n")

        def pretty_print_dict(d: dict) -> None:
            # Print claims similar to jwt_tool but enhanced with time handling.
            for k, v in d.items():
                # Issued At (iat)
                if k == "iat":
                    print_time_claim("Issued At", v)
                    continue

                # Expires At (exp)
                elif k == "exp":
                    print_time_claim("Expires At", v)

                    # Token lifetime (only if iat exists)
                    if "iat" in d:
                        lifetime = v - d["iat"]
                        buf.write(f"      Token lifetime: {describe_delta(lifetime)}\n")
                    continue

                # Not Before (nbf)
                elif k == "nbf":
                    print_time_claim("Not Before", v)
                    continue

                # Normal claims
                prefix = "[+] " + k + " = "
                if isinstance(v, dict):
                    buf.write(f"{prefix}JSON object:\n")
                    for subk, subv in v.items():
                        buf.write(" " * 6 + f"{subk}: {subv}\n")
                else:
                    buf.write(f"{prefix}{repr(v)}\n")

        # --- Decode flow (mirrors jwt_decode.py) ---
        parts = token.split(".")
        if len(parts) != 3:
            buf.write("[-] Invalid JWT format. Expected header.payload.signature\n")
            return

        header_b64, payload_b64, signature_b64 = parts

        # Decode header
        try:
            header_json = json.loads(b64url_decode(header_b64))
        except Exception:
            header_json = {}

        # Decode payload
        try:
            payload_json = json.loads(b64url_decode(payload_b64))
        except Exception:
            payload_json = {}

        buf.write("=====================\n")
        buf.write("Decoded Token Values:\n")
        buf.write("=====================\n\n")

        buf.write("Token header values:\n")
        for k, v in header_json.items():
            buf.write(f"[+] {k} = {repr(v)}\n")
        buf.write("\n")

        buf.write("Token payload values:\n")
        pretty_print_dict(payload_json)
        buf.write("\n")

        buf.write("Token signature:\n")
        buf.write(f"[+] (base64url) = '{signature_b64}'\n")
        buf.write("\n")

    def generate_cors_poc(self):
        """Generate a browser-ready CORS PoC HTML file for the current target.

        The PoC is meant to be hosted on an attacker-controlled origin. When the
        tester opens it in a browser and clicks the button, it will attempt a
        cross-origin fetch to the target URL and display either:

        - the response status and a preview of the body (vulnerable case), or
        - a clear message that CORS blocked access to the response.
        """
        if not self.target:
            self.show_themed_message(
                "No Target",
                "Please set a target first in the Target Setup tab.",
                QMessageBox.Icon.Warning,
            )
            return

        try:
            from pathlib import Path as _Path
            import json as _json

            safe_target = self.sanitize_target_for_filename(self.target)
            out_path = _Path(self.output_dir) / f"{safe_target}_cors_poc.html"

            target_url = self.target.strip()
            # Use JSON encoding so the URL is safely embedded in JavaScript.
            js_url = _json.dumps(target_url)

            html = f"""<!doctype html>
<html>
<head>
  <meta charset="utf-8">
  <title>CORS PoC for {target_url}</title>
  <style>
    body {{ font-family: system-ui, -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif; background:#0b0e13; color:#e2e8f0; padding:20px; }}
    h1 {{ color:#ff6b6b; }}
    button {{ padding:10px 18px; font-size:14px; cursor:pointer; background:#1a202c; color:#e2e8f0; border:1px solid #4a5568; border-radius:4px; }}
    pre {{ background:#111827; padding:12px; border-radius:4px; white-space:pre-wrap; word-break:break-all; max-height:400px; overflow:auto; }}
    code {{ background:#1f2933; padding:2px 4px; border-radius:3px; }}
    #status {{ margin:12px 0; padding:8px; border-radius:4px; background:#1f2933; color:#e2e8f0; }}
  </style>
</head>
<body>
  <h1>CORS Proof-of-Concept</h1>
  <p>
    This page attempts to perform a <code>fetch</code> request from its own
    origin to the target URL:
  </p>
  <p><code>{target_url}</code></p>
  <p>
    If the response body is shown below, the browser has allowed this
    cross-origin read, which strongly indicates a CORS misconfiguration on the
    target application.
  </p>

  <div id="status">Status: Waiting for you to click "Run CORS PoC".</div>
  <button onclick="runPoC(); return false;">Run CORS PoC</button>
  <pre id="output">No response yet. After running the PoC, results will appear here.</pre>
  <noscript>
    <p style="color:#f97316; font-weight:bold;">JavaScript is disabled. Enable JavaScript to run this CORS PoC.</p>
  </noscript>

  <script>
  function setStatus(text, color) {{
    var s = document.getElementById('status');
    if (!s) return;
    s.textContent = text;
    if (color) {{ s.style.color = color; }}
  }}

  function runPoC() {{
    var url = {js_url};
    var out = document.getElementById('output');
    setStatus('Sending cross-origin request to ' + url + ' ...', '#fbbf24');
    out.textContent = 'Request: GET ' + url + '\\n\\nWaiting for response...';

    fetch(url, {{ credentials: 'include' }})
      .then(function (resp) {{
        setStatus('Received HTTP ' + resp.status + ' ' + resp.statusText + ' – attempting to read body ...', '#fbbf24');
        return resp.text().then(function (body) {{
          out.textContent = 'Status: ' + resp.status + ' ' + resp.statusText + '\\n\\n' +
                            'First 2000 chars of body (if accessible):\\n\\n' + body.slice(0, 2000);
          if (body && body.length > 0) {{
            setStatus('POTENTIAL CORS VULNERABILITY: this page was able to read the cross-origin response body.', '#4ade80');
          }} else {{
            setStatus('Response received but body was empty. This may still indicate CORS read access; verify manually.', '#f97316');
          }}
        }});
      }})
      .catch(function (err) {{
        setStatus('No readable response – browser blocked access (likely correct CORS or a network error).', '#f87171');
        if (out) {{
          out.textContent += '\\n\\nError: ' + err;
        }}
      }});
  }}
  </script>
</body>
</html>
"""

            out_path.write_text(html, encoding="utf-8", errors="replace")

            # Ensure a lightweight local HTTP server is running to serve the PoC
            self._ensure_cors_poc_server_running()
            poc_name = out_path.name
            url = f"http://127.0.0.1:{self._cors_poc_server_port}/{poc_name}"

            self.console.append_ansi(
                f"[i] Generated CORS PoC HTML at: {out_path}\\n"\
                f"[i] Serving PoC via local HTTP server at: {url}\\n"\
                "[i] Open this URL in a browser (ideally from a separate profile or host). "\
                "If the response body is displayed, the target is likely vulnerable to CORS.\\n"\
            )

            # Best-effort: open the PoC URL in the system browser
            try:
                QtGui.QDesktopServices.openUrl(QtCore.QUrl(url))
            except Exception:
                pass

            self.refresh_file_list()
        except Exception as e:
            self.show_themed_message("Error", f"Failed to generate CORS PoC: {e}", QMessageBox.Icon.Critical)

    def _ensure_cors_poc_server_running(self):
        """Start or reuse a simple local HTTP server for CORS PoCs.

        The server binds to 127.0.0.1 on a fixed port and serves files from the
        current output directory. It is stopped automatically on application
        exit via closeEvent.
        """
        try:
            # Reuse existing process if still running
            proc = getattr(self, "_cors_poc_server", None)
            if proc is not None and proc.state() == QProcess.ProcessState.Running:
                return

            port = getattr(self, "_cors_poc_server_port", 8000)
            proc = QProcess(self)
            proc.setWorkingDirectory(str(self.output_dir))
            cmd = f"python3 -m http.server {port} --bind 127.0.0.1"
            proc.start("/bin/bash", ["-c", cmd])
            self._cors_poc_server = proc
        except Exception as e:
            try:
                self.console.append_ansi(f"[i] Warning: could not start local CORS PoC web server: {e}\\n")
            except Exception:
                pass

    def search_js_library_issues(self):
        """Interactively look up known vulnerabilities for JS libraries.

        Workflow:
        - Prompt for library name (e.g. "bootstrap").
        - Prompt for location/URL where the library was found.
        - Prompt for detected version (e.g. "3.3.1").
        - Query the OSV vulnerability database for that package/version.
        - Print a concise summary to the console as "Outdated Library #N".
        - Ask whether to add another entry and loop until the user selects No.
        """
        from PyQt6.QtWidgets import QInputDialog, QMessageBox
        from urllib import request, parse
        import urllib.error
        import re

        counter = self._js_lib_counter

        # Always show results in the Console tab
        try:
            self.goto_console()
        except Exception:
            pass

        # Minimal local fallback database for popular JS libraries/versions
        # where OSV may not yet return complete data but well-known issues
        # exist (e.g. jQuery 3.4.1 XSS, Bootstrap 3.3.1 XSS).
        local_js_fallback = {
            ("npm", "jquery", "3.4.1"): {
                "Cross-Site Scripting (XSS)": {
                    "CVE-2020-11022",
                    "CVE-2020-11023",
                    "CVE-2020-23064",
                }
            },
            # Bootstrap 3.3.1 has multiple documented XSS issues in tooltip,
            # popover and collapse components (e.g. CVE-2018-14040,
            # CVE-2018-20676, CVE-2019-8331).
            ("npm", "bootstrap", "3.3.1"): {
                "Cross-Site Scripting (XSS)": {
                    "CVE-2018-14040",
                    "CVE-2018-20676",
                    "CVE-2019-8331",
                }
            },
        }

        while True:
            lib_name, ok = QInputDialog.getText(
                self,
                "JavaScript Library Name",
                "Enter the library name (e.g. bootstrap, jquery):",
            )
            if not ok or not lib_name.strip():
                break
            lib_name = lib_name.strip()

            location, ok = QInputDialog.getText(
                self,
                "Library Location",
                "Enter the URL or path where this library was found (e.g. https://example.com/js/bootstrap.min.js):",
            )
            if not ok or not location.strip():
                break
            location = location.strip()

            version, ok = QInputDialog.getText(
                self,
                "Detected Version",
                f"Enter detected version for {lib_name} (e.g. 3.3.1):",
            )
            if not ok or not version.strip():
                break
            version = version.strip()

            # Optionally choose ecosystem (default to npm for JS libraries)
            ecosystems = [
                "npm",
                "Maven",
                "PyPI",
                "Go",
                "Packagist",
                "NuGet",
                "crates.io",
            ]
            eco, ok = QInputDialog.getItem(
                self,
                "Package Ecosystem",
                "Select the package ecosystem (default: npm):",
                ecosystems,
                0,
                False,
            )
            if not ok or not eco:
                break
            ecosystem = str(eco)

            self.console.append_ansi(
                f"\n=== Searching JavaScript Library Issues ===\n"
                f"Library: {lib_name}\nVersion: {version}\nEcosystem: {ecosystem}\n"
            )

            # Build OSV query payload. For npm, normalise package name to
            # lowercase to match registry/OSV conventions.
            package_name = lib_name
            if ecosystem.lower() == "npm":
                package_name = lib_name.lower()

            payload = {
                "package": {"name": package_name, "ecosystem": ecosystem},
                "version": version,
            }
            data = json.dumps(payload).encode("utf-8")

            try:
                req = request.Request(
                    "https://api.osv.dev/v1/query",
                    data=data,
                    headers={"Content-Type": "application/json"},
                    method="POST",
                )
                with request.urlopen(req, timeout=20) as resp:
                    resp_data = resp.read()
                result = json.loads(resp_data.decode("utf-8", errors="replace"))
            except urllib.error.HTTPError as e:
                self.console.append_ansi(f"[!] OSV API returned HTTP error: {e.code} {e.reason}\n")
                break
            except Exception as e:
                self.console.append_ansi(f"[!] Failed to query vulnerability database: {e}\n")
                break

            vulns = result.get("vulns") or []

            # Print header block
            self.console.append_ansi(
                f"\nOutdated Library #{counter}: {lib_name}\n"\
                f"Location: {location}\n"\
                f"Detected Version: {version}\n"\
            )

            # Group vulnerabilities by high-level type (XSS, RCE, SQLi, DoS, etc.) and
            # collect CVE IDs from aliases/IDs.
            issues_by_type: dict[str, set[str]] = {}

            # Helper to classify a free-text description into a high-level issue type.
            def classify_issue(text: str) -> str:
                lt = text.lower()
                if "remote code execution" in lt or "arbitrary code execution" in lt or "rce" in lt:
                    return "Remote Code Execution (RCE)"
                if "sql injection" in lt or "sqli" in lt:
                    return "SQL Injection"
                if "cross-site scripting" in lt or "xss" in lt:
                    return "Cross-Site Scripting (XSS)"
                if "cross-site request forgery" in lt or "csrf" in lt:
                    return "Cross-Site Request Forgery (CSRF)"
                if "prototype pollution" in lt:
                    return "Prototype Pollution"
                if "denial of service" in lt or "dos" in lt or "resource exhaustion" in lt:
                    return "Denial of Service (DoS)"
                if "directory traversal" in lt or "path traversal" in lt or "traversal" in lt:
                    return "Path / Directory Traversal"
                if "server-side request forgery" in lt or "ssrf" in lt:
                    return "Server-Side Request Forgery (SSRF)"
                if "information disclosure" in lt or "info leak" in lt or "leakage of sensitive" in lt:
                    return "Information Disclosure"
                if "privilege escalation" in lt or "escalation of privilege" in lt:
                    return "Privilege Escalation"
                if "open redirect" in lt or "open redirection" in lt:
                    return "Open Redirect"
                if "insecure deserialization" in lt or "unsafe deserialization" in lt:
                    return "Insecure Deserialization"
                if "authentication bypass" in lt or ("bypass" in lt and "authentication" in lt):
                    return "Authentication Bypass"
                return "Other"

            # Primary source: OSV for the exact package@version
            if vulns:
                for v in vulns:
                    summary = (v.get("summary") or v.get("details") or "").strip()
                    itype = classify_issue(summary)

                    aliases = v.get("aliases") or []
                    cves = [a for a in aliases if isinstance(a, str) and a.startswith("CVE-")]
                    vid = v.get("id") or ""
                    if not cves and vid.startswith("CVE-"):
                        cves = [vid]
                    if not cves and vid:
                        cves = [vid]

                    if not cves:
                        continue
                    bucket = issues_by_type.setdefault(itype, set())
                    for c in cves:
                        if c:
                            bucket.add(c)
            else:
                # No OSV entries; fall back to our small local DB for
                # well-known JS libraries/versions.
                key = (ecosystem.lower(), lib_name.lower(), version)
                fallback = local_js_fallback.get(key)
                if fallback:
                    for itype, cves in fallback.items():
                        bucket = issues_by_type.setdefault(itype, set())
                        for c in cves:
                            if c:
                                bucket.add(c)

            # Secondary source: NVD keyword search (package + version) to
            # catch CVEs that may not yet be in OSV for this ecosystem.
            try:
                nvd_query = f"{package_name} {version}"
                nvd_url = (
                    "https://services.nvd.nist.gov/rest/json/cves/2.0?" +
                    "keywordSearch=" + parse.quote_plus(nvd_query) +
                    "&resultsPerPage=20"
                )
                with request.urlopen(nvd_url, timeout=20) as nvd_resp:
                    nvd_raw = nvd_resp.read().decode("utf-8", errors="replace")
                nvd_data = json.loads(nvd_raw)
                for item in nvd_data.get("vulnerabilities") or []:
                    cve = item.get("cve") or {}
                    cve_id = cve.get("id")
                    if not cve_id:
                        continue
                    desc = ""
                    for d in cve.get("descriptions") or []:
                        if d.get("lang") == "en":
                            desc = d.get("value") or ""
                            break
                    itype = classify_issue(desc)
                    bucket = issues_by_type.setdefault(itype, set())
                    bucket.add(cve_id)
            except Exception:
                # Treat NVD lookup as best-effort; don't fail the whole flow
                # if their API is unavailable or rate-limited.
                pass

            # Tertiary source: Snyk vulnerability DB (security.snyk.io) for npm
            # packages, scraped from the public HTML page for the
            # package/version to pick up extra CVE/SNYK identifiers.
            if ecosystem.lower() == "npm":
                try:
                    snyk_url = f"https://security.snyk.io/package/npm/{package_name}/{version}"
                    with request.urlopen(snyk_url, timeout=20) as s_resp:
                        s_html = s_resp.read().decode("utf-8", errors="replace")

                    # Extract CVE IDs and SNYK-* identifiers from the page.
                    cve_ids = set(re.findall(r"CVE-\d{4}-\d{4,7}", s_html, flags=re.IGNORECASE))
                    snyk_ids = set(re.findall(r"SNYK-[A-Z0-9-]+", s_html))
                    all_ids = sorted({*cve_ids, *snyk_ids})

                    if all_ids:
                        # We don't try to infer precise vuln types from Snyk's
                        # HTML here; just bucket them under a generic label and
                        # let the user click through to Snyk for details.
                        bucket = issues_by_type.setdefault("Other (from Snyk)", set())
                        for vid in all_ids:
                            bucket.add(vid)

                        # Also print the Snyk page URL so it's easy to open.
                        self.console.append_ansi(f"Snyk reference: {snyk_url}\n")
                except Exception:
                    # Snyk integration is best-effort; ignore errors here.
                    pass

            if not issues_by_type:
                if not vulns:
                    self.console.append_ansi("Known Issues: none found in OSV database.\n")
                else:
                    self.console.append_ansi("Known Issues: vulnerabilities found but no CVE IDs returned.\n")
            else:
                for itype, cves in issues_by_type.items():
                    sorted_cves = sorted(cves) if cves else []
                    # Header per issue type, e.g. "Known Issues: Cross-Site Scripting (XSS)"
                    self.console.append_ansi(f"Known Issues: {itype}\n")
                    # One CVE/ID per line for easy scanning/copying
                    for cve in sorted_cves:
                        self.console.append_ansi(f"{cve}\n")

            counter += 1

            # Ask whether to add another library entry
            reply = QMessageBox.question(
                self,
                "Add another outdated library?",
                "Add another outdated library entry?",
                QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
                QMessageBox.StandardButton.No,
            )
            if reply != QMessageBox.StandardButton.Yes:
                break

        self._js_lib_counter = counter

    def check_wildcard_cert(self):
        """Check whether the current target presents a wildcard TLS certificate.

        Connects to the target host on 443, reads the certificate, and inspects
        the Common Name and Subject Alternative Names for wildcard entries
        (e.g. *.example.com). Output is colour-coded by the console: a wildcard
        is shown in red ([✖]); no wildcard is shown in green ([✔]).
        """
        import ssl
        import socket
        import ipaddress
        from urllib.parse import urlparse

        if not self.target:
            self.show_themed_message(
                "No Target", "Please set a target first in the Target Setup tab.",
                QMessageBox.Icon.Warning,
            )
            return

        raw = self.target.strip()
        parsed = urlparse(raw if "://" in raw else "https://" + raw)
        host = parsed.hostname or raw
        port = parsed.port or 443

        try:
            self.goto_console()
        except Exception:
            pass

        self.console.append_ansi("\n" + "-" * 80 + "\n")
        self.console.append_ansi(f"[*] Wildcard SSL Certificate Check — {host}:{port}\n")
        self.console.append_ansi("-" * 80 + "\n")

        is_ip = False
        try:
            ipaddress.ip_address(host)
            is_ip = True
        except ValueError:
            is_ip = False

        try:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            with socket.create_connection((host, port), timeout=10) as sock:
                with ctx.wrap_socket(sock, server_hostname=None if is_ip else host) as ssock:
                    cert = ssock.getpeercert()
        except Exception as e:
            self.console.append_ansi(f"[!] Could not retrieve certificate from {host}:{port}: {e}\n")
            return

        cn = None
        for rdn in cert.get("subject", ()):
            for key, value in rdn:
                if key.lower() == "commonname":
                    cn = value
        sans = [v for (t, v) in cert.get("subjectAltName", ()) if t.lower() == "dns"]
        names = ([cn] if cn else []) + sans
        wildcards = sorted({n for n in names if isinstance(n, str) and n.startswith("*.")})

        if wildcards:
            self.console.append_ansi(f"[✖] WILDCARD CERTIFICATE IN USE: {', '.join(wildcards)}\n")
        else:
            self.console.append_ansi("[✔] No wildcard certificate detected.\n")
        if cn:
            self.console.append_ansi(f"    CN : {cn}\n")
        if sans:
            self.console.append_ansi(f"    SAN: {', '.join(sorted(set(sans)))}\n")

    def run_insecure_redirect_scan(self):
        """Test the current target for unvalidated / open redirects.

        Behaviour:
        - Uses the Target URL from the Target Setup tab.
        - Tries common redirect parameters and payloads without following
          redirects (allow_redirects=False).
        - Marks VULNERABLE if the attacker-controlled URL appears in the
          Location header of a 3xx response.
        - Prints a clear, report-ready PoC for each finding.
        """
        import urllib.parse

        try:
            import requests
        except Exception:
            self.show_themed_message(
                "Missing dependency",
                "Python 'requests' module is not available. Please install it (e.g. pip install requests) and try again.",
                QMessageBox.Icon.Warning,
            )
            return

        # Get target from Target Setup
        target = (self.target_input.text() or "").strip()
        if not target:
            self.show_themed_message(
                "Target required",
                "Please enter a target URL (e.g. https://example.com/login).",
                QMessageBox.Icon.Warning,
            )
            return

        # Normalise URL
        url = target
        if not url.startswith("http://") and not url.startswith("https://"):
            url = "https://" + url

        parsed = urllib.parse.urlparse(url)
        if not parsed.scheme or not parsed.netloc:
            self.show_themed_message(
                "Invalid URL",
                f"Could not parse target URL: {url}",
                QMessageBox.Icon.Warning,
            )
            return

        base_path = parsed.path or "/"
        base = f"{parsed.scheme}://{parsed.netloc}{base_path}"

        REDIRECT_PARAMS = [
            "url", "redirect", "next", "return", "continue", "dest", "destination",
        ]
        PAYLOADS = [
            "https://evil.example.com",
            "//evil.example.com",
            "///evil.example.com",
            "https:%2f%2fevil.example.com",
        ]
        REDIRECT_CODES = {301, 302, 303, 307, 308}
        TIMEOUT = 10

        # Build headers (reuse custom headers from Target Setup where possible)
        headers = {"User-Agent": "CommandBridge Insecure Redirect Test/1.0", "Accept": "*/*"}
        custom_headers = self.headers_input.toPlainText().strip()
        if custom_headers:
            for line in custom_headers.split("\n"):
                if ":" in line:
                    name, value = line.split(":", 1)
                    name = name.strip()
                    if name:
                        headers[name] = value.strip()

        # Show results in Console tab
        try:
            self.goto_console()
        except Exception:
            pass

        self.console.append_ansi("\n" + "=" * 60 + "\n")
        self.console.append_ansi(f"[*] Insecure Redirect test for: {url}\n")
        self.console.append_ansi("=" * 60 + "\n")

        findings = []

        for param in REDIRECT_PARAMS:
            for payload in PAYLOADS:
                query = {param: payload}
                test_url = f"{base}?{urllib.parse.urlencode(query)}"

                try:
                    resp = requests.get(
                        test_url,
                        headers=headers,
                        allow_redirects=False,
                        timeout=TIMEOUT,
                        verify=False,
                    )
                except requests.RequestException:
                    # Network issues are treated as inconclusive, skip this combo
                    continue

                status = resp.status_code
                location = resp.headers.get("Location", "") or ""

                # Normalise payload for matching (handle %2f encodings)
                norm_payload = payload.replace("%2f", "/").replace("%2F", "/")

                if status in REDIRECT_CODES and norm_payload in location:
                    findings.append({
                        "parameter": param,
                        "payload": payload,
                        "status": status,
                        "location": location,
                        "poc_url": test_url,
                    })

        if not findings:
            # Green in the console layer via EnhancedConsole formatting
            self.console.append_ansi("[✔] NOT VULNERABLE: no unvalidated redirects detected.\n")
            return

        self.console.append_ansi("[✖] VULNERABLE: unvalidated / open redirect detected!\n\n")

        for idx, f in enumerate(findings, 1):
            self.console.append_ansi(f"[Finding #{idx}]\n")
            self.console.append_ansi(f" Parameter : {f['parameter']}\n")
            self.console.append_ansi(f" Payload   : {f['payload']}\n")
            self.console.append_ansi(f" Status    : HTTP {f['status']}\n")
            self.console.append_ansi(f" Location  : {f['location']}\n")

            # Report-ready HTTP PoC
            poc_query = urllib.parse.urlencode({f["parameter"]: f["payload"]})
            poc_path = f"{base_path}?{poc_query}"
            host = parsed.netloc
            http_poc = (
                f"GET {poc_path} HTTP/1.1\n"
                f"Host: {host}\n"
                "\n"
            )

            self.console.append_ansi("\n Proof of Concept URL:\n")
            self.console.append_ansi(f"  {f['poc_url']}\n")
            self.console.append_ansi("\n Report-ready HTTP PoC:\n")
            self.console.append_ansi(http_poc)
            self.console.append_ansi("-" * 60 + "\n")
