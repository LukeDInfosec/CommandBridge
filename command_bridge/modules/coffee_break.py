"""
Coffee Break — one button, the whole active-scan chain.

The idea is Burp's active scan: press it, walk away, come back to a screen that
tells you what was found, where, and why it matters. The difference is that the
work is done by the tools already in Command Bridge rather than by one engine,
and that each stage feeds the next:

    nmap ─┐
          ├─ open ports ──────────────────► the rest of the chain knows the shape
    TLS ──┘                                  of the host before it touches HTTP
    headers ──► server/tech ──► WordPress stage runs only if WordPress is there
    SmartFuzz ──► endpoints ──► every 403 it found ──► 403 bypass stage
    params ────► parameter names ─────────► LFI traversal stage

Two rules the engine keeps to:

  * **One process at a time.** The whole application shares a single
    ``CommandRunner``/``QProcess``, so a stage that shells out only starts when
    the previous one has finished. Advancement happens in ``on_command_finished``
    the same way Auto Scan and the Externals workflow do.
  * **Nothing blocks the interface.** Stages that are Python rather than shell
    (header analysis, JavaScript, traversal, bypass) run on a worker thread and
    report back through a signal. A scan that freezes the window while it works
    is not a scan you leave running.

Findings are structured — severity, title, location, evidence, remediation —
rather than lines of console text, because the point of the screen is to be read
after the fact by somebody writing a report.
"""

from __future__ import annotations

import html
import json
import os
import re
import time
import urllib.parse
from dataclasses import dataclass, field, asdict
from pathlib import Path

from PyQt6 import QtCore
from PyQt6.QtCore import QObject, QThread, QTimer, pyqtSignal
from PyQt6.QtWidgets import QMessageBox

from command_bridge.constants import BASE_DIR

# ─────────────────────────────────────────────────────────────────────────────
#  Findings
# ─────────────────────────────────────────────────────────────────────────────

SEVERITIES = ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO")
SEV_ORDER = {name: index for index, name in enumerate(reversed(SEVERITIES))}

#: Deliberately the same words as the console's own highlighter, so a finding
#: printed to the console is coloured without any extra work.
SEV_TAG = {s: f"[{s}]" for s in SEVERITIES}


@dataclass
class CBFinding:
    """One issue, in the form somebody writing it up actually needs."""

    severity: str
    title: str
    where: str              # URL, host:port, or parameter name
    detail: str = ""        # what it means
    evidence: str = ""      # the proof, verbatim
    remediation: str = ""
    stage: str = ""
    confidence: str = "firm"   # firm | tentative
    seen_at: float = field(default_factory=time.time)

    def sort_key(self):
        return (-SEV_ORDER.get(self.severity, 0), self.title.lower())

    def as_dict(self):
        return asdict(self)


# ─────────────────────────────────────────────────────────────────────────────
#  Worker
# ─────────────────────────────────────────────────────────────────────────────

class _CBWorker(QObject):
    """Runs one Python stage off the interface thread.

    The callable is handed a ``report`` function for progress lines and returns
    a list of ``CBFinding`` plus a dict of artefacts for later stages. It must
    not touch any Qt widget — everything comes back through the signals.
    """

    progress = pyqtSignal(str)
    finished = pyqtSignal(object, object, str)   # findings, artefacts, error

    def __init__(self, func, context):
        super().__init__()
        self._func = func
        self._context = context

    def run(self):
        try:
            findings, artefacts = self._func(self._context, self.progress.emit)
            self.finished.emit(findings or [], artefacts or {}, "")
        except Exception as exc:                       # noqa: BLE001
            self.finished.emit([], {}, f"{type(exc).__name__}: {exc}")


# ─────────────────────────────────────────────────────────────────────────────
#  Probes — plain functions so they can run on a thread and be tested alone
# ─────────────────────────────────────────────────────────────────────────────

SECURITY_HEADERS = {
    "content-security-policy": (
        "MEDIUM", "Content-Security-Policy is missing",
        "Without a CSP, an injected script runs with the full privileges of the "
        "page. It is the single most effective mitigation against XSS.",
        "Set a policy that names the sources you actually use; start in "
        "report-only mode if you need to find them."),
    "strict-transport-security": (
        "MEDIUM", "Strict-Transport-Security is missing",
        "A browser that has never seen the HTTPS site will try HTTP first, "
        "which is where an attacker on the path strips the redirect.",
        "Send 'max-age=31536000; includeSubDomains' over HTTPS."),
    "x-frame-options": (
        "LOW", "No framing protection",
        "The page can be embedded in a frame on another origin, which is what "
        "clickjacking needs.",
        "Send 'X-Frame-Options: DENY' or a CSP frame-ancestors directive."),
    "x-content-type-options": (
        "LOW", "X-Content-Type-Options is missing",
        "Browsers may sniff a response's type, so an upload served as text can "
        "be executed as script.",
        "Send 'X-Content-Type-Options: nosniff'."),
    "referrer-policy": (
        "INFO", "Referrer-Policy is missing",
        "Full URLs — including anything sensitive in the path or query — are "
        "sent to third parties in the Referer header.",
        "Send 'Referrer-Policy: strict-origin-when-cross-origin'."),
    "permissions-policy": (
        "INFO", "Permissions-Policy is missing",
        "Embedded content inherits access to camera, microphone and location.",
        "Send a Permissions-Policy naming only the features the page uses."),
}

#: Headers that say more about the server than the operator meant to.
LEAKY_HEADERS = ("server", "x-powered-by", "x-aspnet-version",
                 "x-aspnetmvc-version", "x-generator", "x-drupal-cache",
                 "x-runtime", "x-version")


def _session(context):
    import requests
    session = requests.Session()
    session.verify = False
    session.headers.update({
        "User-Agent": context.get("user_agent")
                      or "Mozilla/5.0 (compatible; CommandBridge/CoffeeBreak)",
    })
    for name, value in (context.get("headers") or {}).items():
        session.headers[name] = value
    try:
        import urllib3
        urllib3.disable_warnings()
    except Exception:
        pass
    return session


def probe_headers(context, report):
    """Fetch the target once and read everything the response says."""
    session = _session(context)
    url = context["url"]
    findings, artefacts = [], {}

    report(f"requesting {url}")
    response = session.get(url, timeout=context.get("timeout", 15),
                           allow_redirects=True)
    headers = {k.lower(): v for k, v in response.headers.items()}
    artefacts["status"] = response.status_code
    artefacts["server_headers"] = dict(response.headers)
    artefacts["final_url"] = response.url
    body = response.text or ""
    artefacts["body_sample"] = body[:20000]

    report(f"{response.status_code} {response.reason} — "
           f"{len(response.content)} bytes, {len(headers)} headers")

    for header, (severity, title, detail, fix) in SECURITY_HEADERS.items():
        if header not in headers:
            findings.append(CBFinding(
                severity=severity, title=title, where=response.url,
                detail=detail, remediation=fix,
                evidence="Response headers: " + ", ".join(sorted(headers)) [:400],
                stage="headers"))

    for header in LEAKY_HEADERS:
        if header in headers and headers[header].strip():
            findings.append(CBFinding(
                severity="INFO",
                title=f"Version disclosure in {header}",
                where=response.url,
                detail="The response names the software and often its version, "
                       "which turns 'find a vulnerability' into 'look up a CVE'.",
                evidence=f"{header}: {headers[header]}",
                remediation="Suppress or flatten the header at the proxy.",
                stage="headers"))

    # Cookies are part of the response, and the flags are the whole game.
    for cookie in response.cookies:
        problems = []
        if not cookie.secure:
            problems.append("no Secure flag")
        if not cookie.has_nonstandard_attr("HttpOnly") and \
                not cookie.has_nonstandard_attr("httponly"):
            problems.append("no HttpOnly flag")
        if problems:
            findings.append(CBFinding(
                severity="LOW" if "no Secure flag" in problems else "INFO",
                title=f"Cookie {cookie.name} set without {' and '.join(problems)}",
                where=response.url,
                detail="A cookie without Secure can be sent over plain HTTP; "
                       "one without HttpOnly can be read by injected script.",
                evidence=f"Set-Cookie: {cookie.name}=…",
                remediation="Set Secure, HttpOnly and an explicit SameSite.",
                stage="headers"))

    # What the stack is, so later stages can skip what does not apply.
    tech = []
    blob = (" ".join(f"{k}: {v}" for k, v in headers.items()) + " " +
            body[:4000]).lower()
    for name, needle in (("wordpress", "wp-content"), ("wordpress", "wp-json"),
                         ("drupal", "drupal"), ("joomla", "joomla"),
                         ("iis", "microsoft-iis"), ("nginx", "nginx"),
                         ("apache", "apache"), ("tomcat", "tomcat"),
                         ("laravel", "laravel_session"),
                         ("php", "php"), ("asp.net", "asp.net")):
        if needle in blob and name not in tech:
            tech.append(name)
    artefacts["tech"] = tech
    if tech:
        report("technology: " + ", ".join(tech))
    return findings, artefacts


def probe_redirects(context, report):
    """Unvalidated redirects, without following anything."""
    session = _session(context)
    base = context["url"]
    canary = "https://cb-canary.example"
    params = ("next", "url", "redirect", "redirect_uri", "return", "returnUrl",
              "return_to", "continue", "dest", "destination", "target", "r", "u")
    payloads = (canary, "//cb-canary.example", "/\\cb-canary.example",
                "https:/\\cb-canary.example")
    findings = []
    tried = 0
    for param in params:
        for payload in payloads:
            tried += 1
            probe = f"{base}{'&' if '?' in base else '?'}" \
                    f"{param}={urllib.parse.quote(payload, safe='')}"
            try:
                response = session.get(probe, timeout=context.get("timeout", 12),
                                       allow_redirects=False)
            except Exception:
                continue
            location = response.headers.get("Location", "")
            if 300 <= response.status_code < 400 and "cb-canary.example" in location:
                findings.append(CBFinding(
                    severity="MEDIUM",
                    title=f"Open redirect via '{param}'",
                    where=probe,
                    detail="The application sends the browser to a location it "
                           "took from the query string without checking it. "
                           "Useful for phishing, and for stealing OAuth codes "
                           "when the parameter feeds a redirect_uri.",
                    evidence=f"HTTP {response.status_code}\nLocation: {location}",
                    remediation="Allow-list the destinations, or map an opaque "
                                "key to a destination server-side.",
                    stage="redirect"))
                break          # one proof per parameter is enough
    report(f"tried {tried} redirect probes")
    return findings, {"redirect_params_tested": tried}


def probe_javascript(context, report):
    """Download the page's JavaScript and read it with the existing engine."""
    session = _session(context)
    url = context["url"]
    out_dir = Path(context["output_dir"]) / "coffee_break_js"
    out_dir.mkdir(parents=True, exist_ok=True)

    response = session.get(url, timeout=context.get("timeout", 15))
    body = response.text or ""
    found = set()
    for match in re.finditer(r"""<script[^>]+src\s*=\s*["']([^"']+)["']""",
                             body, re.I):
        found.add(urllib.parse.urljoin(response.url, match.group(1)))
    for match in re.finditer(r"""["']([^"']+?\.js(?:\?[^"']*)?)["']""", body):
        candidate = urllib.parse.urljoin(response.url, match.group(1))
        if candidate.startswith(("http://", "https://")):
            found.add(candidate)

    same_site = [u for u in sorted(found)
                 if urllib.parse.urlparse(u).netloc ==
                 urllib.parse.urlparse(response.url).netloc]
    scripts = same_site or sorted(found)
    scripts = scripts[:context.get("js_cap", 40)]
    report(f"{len(found)} script URL(s) referenced, analysing {len(scripts)}")

    try:
        from command_bridge.modules.js_findings import JsScanner
    except Exception as exc:                            # noqa: BLE001
        return [], {"js_error": str(exc)}

    findings, analysed = [], 0
    for script_url in scripts:
        try:
            source = session.get(script_url,
                                 timeout=context.get("timeout", 15)).text
        except Exception:
            continue
        if not source.strip():
            continue
        analysed += 1
        (out_dir / re.sub(r"[^A-Za-z0-9_.-]+", "_", script_url)[-120:]
         ).write_text(source, errors="replace")
        try:
            scanner = JsScanner(source, script_url)
            results = scanner.scan()
        except Exception as exc:                        # noqa: BLE001
            report(f"could not analyse {script_url}: {exc}")
            continue
        for item in results:
            severity = str(getattr(item, "severity", "INFO")).upper()
            locations = getattr(item, "locations", None) or []
            first = locations[0] if locations else {}
            excerpt = ""
            if isinstance(first, dict):
                excerpt = (first.get("excerpt") or "")[:400]
                line = first.get("line")
            else:
                line = None
            findings.append(CBFinding(
                severity=severity if severity in SEVERITIES else "INFO",
                title=getattr(item, "title", "JavaScript finding"),
                where=f"{script_url}" + (f" line {line}" if line else ""),
                detail=getattr(item, "description", "") or
                       getattr(item, "category", ""),
                evidence=excerpt,
                remediation=getattr(item, "guidance", "") or "",
                stage="javascript",
                confidence=str(getattr(item, "confidence", "firm")).lower()))
    report(f"analysed {analysed} script(s)")
    return findings, {"js_urls": scripts, "js_dir": str(out_dir)}


TRAVERSAL_PAYLOADS = (
    "../../../../etc/passwd",
    "....//....//....//....//etc/passwd",
    "..%2f..%2f..%2f..%2fetc%2fpasswd",
    "%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
    "/etc/passwd",
    "../../../../windows/win.ini",
    "..\\..\\..\\..\\windows\\win.ini",
    "....\\\\....\\\\windows\\\\win.ini",
)

#: What a successful read looks like. Deliberately narrow: a page that merely
#: echoes the payload back is not a file read, and reporting it as one wastes
#: the next hour of somebody's life.
TRAVERSAL_PROOF = (
    (re.compile(r"root:[x*!]?:0:0:"), "/etc/passwd contents"),
    (re.compile(r"^\s*\[(fonts|extensions|mci extensions)\]", re.I | re.M),
     "win.ini contents"),
    (re.compile(r"daemon:[x*!]?:\d+:\d+:"), "/etc/passwd contents"),
)


def probe_traversal(context, report):
    """Strip each discovered parameter's value and try to walk out of the root.

    Only the parameter under test is changed; every other parameter keeps the
    value it was discovered with, because a URL that 404s without them proves
    nothing either way.
    """
    session = _session(context)
    targets = context.get("param_urls") or []
    if not targets:
        report("no parameterised URLs were discovered")
        return [], {}

    findings = []
    tested = 0
    seen = set()
    for raw in targets[:context.get("traversal_cap", 60)]:
        parsed = urllib.parse.urlparse(raw)
        query = urllib.parse.parse_qsl(parsed.query, keep_blank_values=True)
        if not query:
            continue
        for index, (name, _value) in enumerate(query):
            shape = (parsed.netloc, parsed.path, name)
            if shape in seen:
                continue
            seen.add(shape)
            for payload in TRAVERSAL_PAYLOADS:
                mutated = list(query)
                mutated[index] = (name, payload)      # the value is replaced
                probe = urllib.parse.urlunparse(
                    parsed._replace(query=urllib.parse.urlencode(
                        mutated, safe="/\\.%")))
                tested += 1
                try:
                    response = session.get(
                        probe, timeout=context.get("timeout", 12),
                        allow_redirects=False)
                except Exception:
                    continue
                body = response.text or ""
                for pattern, what in TRAVERSAL_PROOF:
                    if pattern.search(body):
                        findings.append(CBFinding(
                            severity="CRITICAL",
                            title=f"Path traversal via '{name}'",
                            where=probe,
                            detail="The parameter is used to build a file path "
                                   "and the application returned the contents "
                                   "of a file outside the web root.",
                            evidence=f"Proof: {what}\n"
                                     + "\n".join(body.splitlines()[:6])[:600],
                            remediation="Do not build paths from user input. "
                                        "Map an identifier to a known file, or "
                                        "resolve and confirm the path stays "
                                        "inside the intended directory.",
                            stage="traversal"))
                        break
                else:
                    continue
                break            # this parameter is proven; move to the next
    report(f"{tested} traversal request(s) across {len(seen)} parameter(s)")
    return findings, {"traversal_requests": tested,
                      "traversal_params": len(seen)}


#: Each entry is (label, how to build the request). The header tricks are the
#: ones that actually land in front of reverse proxies and WAFs.
BYPASS_TRICKS = (
    ("X-Original-URL", lambda p: ({"X-Original-URL": p}, "GET", "/")),
    ("X-Rewrite-URL", lambda p: ({"X-Rewrite-URL": p}, "GET", "/")),
    ("X-Forwarded-For 127.0.0.1", lambda p: ({"X-Forwarded-For": "127.0.0.1"}, "GET", p)),
    ("X-Forwarded-Host localhost", lambda p: ({"X-Forwarded-Host": "localhost"}, "GET", p)),
    ("X-Custom-IP-Authorization", lambda p: ({"X-Custom-IP-Authorization": "127.0.0.1"}, "GET", p)),
    ("X-Real-IP 127.0.0.1", lambda p: ({"X-Real-IP": "127.0.0.1"}, "GET", p)),
    ("Referer self", lambda p: ({"Referer": p}, "GET", p)),
    ("POST instead of GET", lambda p: ({}, "POST", p)),
    ("HEAD instead of GET", lambda p: ({}, "HEAD", p)),
    ("TRACE", lambda p: ({}, "TRACE", p)),
    ("trailing slash", lambda p: ({}, "GET", p.rstrip("/") + "/")),
    ("trailing dot", lambda p: ({}, "GET", p + ".")),
    ("double slash", lambda p: ({}, "GET", "/" + p.lstrip("/").replace("/", "//", 1))),
    ("path parameter ;", lambda p: ({}, "GET", p + ";")),
    ("%2e segment", lambda p: ({}, "GET", p.replace("/", "/%2e/", 1))),
    ("uppercase path", lambda p: ({}, "GET", p.upper())),
    ("query fragment", lambda p: ({}, "GET", p + "?")),
    ("..;/ segment", lambda p: ({}, "GET", p + "..;/")),
)


def probe_403_bypass(context, report):
    """Try the usual tricks against everything that answered 403 or 401."""
    session = _session(context)
    blocked = context.get("forbidden") or []
    if not blocked:
        report("nothing answered 401 or 403 during the chain")
        return [], {}

    findings, table = [], []
    for url in blocked[:context.get("bypass_cap", 25)]:
        parsed = urllib.parse.urlparse(url)
        origin = f"{parsed.scheme}://{parsed.netloc}"
        path = parsed.path or "/"
        try:
            baseline = session.get(url, timeout=context.get("timeout", 12),
                                   allow_redirects=False)
            base_status, base_len = baseline.status_code, len(baseline.content)
        except Exception:
            continue

        for label, build in BYPASS_TRICKS:
            headers, method, target_path = build(path)
            probe = origin + target_path if target_path.startswith("/") \
                else origin + "/" + target_path
            try:
                response = session.request(
                    method, probe, headers=headers, allow_redirects=False,
                    timeout=context.get("timeout", 12))
            except Exception:
                continue
            length = len(response.content)
            worked = (response.status_code < 400
                      and response.status_code != base_status)
            row = {"url": url, "trick": label, "method": method,
                   "status": response.status_code, "length": length,
                   "baseline": base_status, "bypassed": bool(worked)}
            table.append(row)
            if worked:
                findings.append(CBFinding(
                    severity="HIGH",
                    title=f"403 bypassed with {label}",
                    where=url,
                    detail="The access control is enforced at the edge and can "
                           "be stepped around, so whatever it was protecting is "
                           "reachable.",
                    evidence=f"{method} {probe}\n"
                             + "\n".join(f"{k}: {v}" for k, v in headers.items())
                             + f"\n→ HTTP {response.status_code} ({length} bytes); "
                               f"baseline was {base_status}",
                    remediation="Enforce authorisation in the application, not "
                                "only in the proxy, and normalise the path "
                                "before the rule is applied.",
                    stage="bypass"))
    report(f"{len(table)} attempt(s) across {len(blocked[:25])} endpoint(s); "
           f"{sum(1 for r in table if r['bypassed'])} got through")
    return findings, {"bypass_table": table}


# ─────────────────────────────────────────────────────────────────────────────
#  The mixin
# ─────────────────────────────────────────────────────────────────────────────

class CoffeeBreakMixin:
    """Sequencing, parsing and state for the Coffee Break chain."""

    # ── state ────────────────────────────────────────────────────────────
    def _cb_reset(self):
        self._cb_active = False
        self._cb_stages = []
        self._cb_index = -1
        self._cb_findings = []
        self._cb_artifacts = {"forbidden": [], "param_urls": [], "tech": []}
        self._cb_buffer = []
        self._cb_started_at = 0.0
        self._cb_thread = None
        self._cb_worker = None
        self._cb_skip_requested = False

    # ── the chain ────────────────────────────────────────────────────────
    def _cb_stage_list(self):
        """Every stage, in the order they teach the next one something.

        `shell` stages run a command through the shared runner. `python` stages
        run a probe on a worker thread. `when` gates a stage on what earlier
        stages discovered — the WordPress scan is pointless against a site with
        no WordPress in it, and saying so beats running it for ten minutes.
        """
        safe = self.sanitize_target_for_filename(self.target)
        host = self.get_scanner_target()
        out = str(self.output_dir)

        def registry(button_id, default):
            return self._substitute_web_placeholders(
                self.command_registry.get(button_id, default))

        return [
            dict(key="nmap_quick", name="Nmap — service scan", kind="shell",
                 command=registry("net_nmap_quick",
                                  "nmap -sV -sC -T4 {TARGET_HOST} "
                                  "-oN {SAFE_TARGET}_nmap_quick.txt"),
                 parser="_cb_parse_nmap"),
            dict(key="nmap_full", name="Nmap — all 65535 ports", kind="shell",
                 command=registry("net_nmap_full",
                                  "nmap -sV -sC -p- -T4 {TARGET_HOST} "
                                  "-oN {SAFE_TARGET}_nmap_full.txt"),
                 parser="_cb_parse_nmap"),
            dict(key="nmap_udp", name="Nmap — UDP top 200", kind="shell",
                 command=registry("net_nmap_udp",
                                  "nmap -sU --top-ports 200 -T4 {TARGET_HOST} "
                                  "-oN {SAFE_TARGET}_nmap_udp.txt"),
                 parser="_cb_parse_nmap"),
            dict(key="testssl", name="TLS configuration (testssl)", kind="shell",
                 command=(
                     f"if command -v testssl >/dev/null 2>&1; then "
                     f"testssl --quiet --color 0 --jsonfile "
                     f"{out}/{safe}_testssl.json {host} 2>&1; "
                     f"elif command -v testssl.sh >/dev/null 2>&1; then "
                     f"testssl.sh --quiet --color 0 --jsonfile "
                     f"{out}/{safe}_testssl.json {host} 2>&1; "
                     f"else echo '[i] testssl is not installed — skipping. "
                     f"Install: sudo apt install testssl'; fi"),
                 parser="_cb_parse_testssl"),
            dict(key="headers", name="HTTP and security headers", kind="python",
                 probe=probe_headers),
            dict(key="nikto", name="Nikto", kind="shell",
                 command=registry("net_nikto",
                                  "nikto -h '{TARGET}' -o {SAFE_TARGET}_nikto.txt 2>&1"),
                 parser="_cb_parse_nikto"),
            dict(key="nuclei", name="Nuclei templates", kind="shell",
                 command=(
                     f"if command -v nuclei >/dev/null 2>&1; then "
                     f"nuclei -u '{self.target}' -severity info,low,medium,high,critical "
                     f"-jsonl -o {out}/{safe}_nuclei.jsonl -stats -silent 2>&1; "
                     f"else echo '[i] nuclei is not installed — skipping.'; fi"),
                 parser="_cb_parse_nuclei",
                 artefact_file=f"{out}/{safe}_nuclei.jsonl"),
            dict(key="javascript", name="JavaScript retrieval and analysis",
                 kind="python", probe=probe_javascript),
            dict(key="redirect", name="Unvalidated redirects", kind="python",
                 probe=probe_redirects),
            dict(key="wordpress", name="WordPress (wpscan)", kind="shell",
                 when=lambda a: "wordpress" in (a.get("tech") or []),
                 skip_note="no WordPress detected in the response",
                 command=(
                     f"if command -v wpscan >/dev/null 2>&1; then "
                     f"wpscan --url '{self.target}' --no-banner "
                     f"--random-user-agent --enumerate vp,vt,cb,dbe "
                     f"--format cli-no-color 2>&1; "
                     f"else echo '[i] wpscan is not installed — skipping.'; fi"),
                 parser="_cb_parse_wpscan"),
            dict(key="smartfuzz", name="SmartFuzz content discovery",
                 kind="shell",
                 command=self._cb_smartfuzz_command(),
                 parser="_cb_parse_fuzz"),
            dict(key="params", name="Parameter discovery", kind="shell",
                 command=(
                     f"if command -v paramspider >/dev/null 2>&1; then "
                     f"paramspider -d {host} 2>&1 | tee {out}/{safe}_params.txt; "
                     f"else echo '[i] paramspider is not installed — the "
                     f"traversal stage will use parameters found by the crawl "
                     f"instead.'; fi"),
                 parser="_cb_parse_params",
                 artefact_file=f"{out}/{safe}_params.txt"),
            dict(key="traversal", name="Path traversal against parameters",
                 kind="python", probe=probe_traversal,
                 when=lambda a: bool(a.get("param_urls")),
                 skip_note="no parameterised URLs were discovered"),
            dict(key="bypass", name="403 bypass", kind="python",
                 probe=probe_403_bypass,
                 when=lambda a: bool(a.get("forbidden")),
                 skip_note="nothing answered 401 or 403"),
        ]

    def _cb_smartfuzz_command(self):
        """SmartFuzz, inheriting any auth the operator set on the button."""
        try:
            auth_type = getattr(self, "_smartfuzz_auth_type", None) or "none"
            auth_value = getattr(self, "_smartfuzz_auth_value", None) or ""
            command = self._build_smartfuzz_command(auth_type, auth_value)
        except Exception:
            command = f"python3 {BASE_DIR}/smartfuzz.py -u {{TARGET}} -t 2"
        return self._substitute_web_placeholders(command)

    # ── starting ─────────────────────────────────────────────────────────
    def start_coffee_break(self):
        """Run the whole chain. One button, then go and make the coffee."""
        if not getattr(self, "target", ""):
            self.show_themed_message(
                "No Target", "Set a target in the Target Setup tab first.",
                QMessageBox.Icon.Warning)
            return
        if getattr(self, "_cb_active", False):
            self.show_themed_message(
                "Already running",
                "A Coffee Break scan is already in progress. Use Stop on the "
                "Coffee Break tab to end it.", QMessageBox.Icon.Information)
            return
        if getattr(self, "_auto_scan_active", False) or \
                getattr(self, "_externals_active", False):
            self.show_themed_message(
                "Another sequence is running",
                "Auto Scan or the Externals workflow is using the runner. Let "
                "it finish first — the application runs one process at a time.",
                QMessageBox.Icon.Warning)
            return

        self._cb_reset()
        self._cb_active = True
        self._cb_started_at = time.time()
        self._cb_stages = self._cb_stage_list()
        self._cb_index = -1

        try:
            self.goto_tab("coffee")
        except Exception:
            pass
        if hasattr(self, "_cb_ui_reset"):
            self._cb_ui_reset(self._cb_stages, self.target)

        self.console.append_ansi("\n" + "=" * 80 + "\n")
        self.console.append_ansi(f"[*] Coffee Break — active scan chain against "
                                 f"{self.target}\n")
        self.console.append_ansi(f"[*] {len(self._cb_stages)} stages. Findings "
                                 f"appear on the Coffee Break tab as they land.\n")
        self.console.append_ansi("=" * 80 + "\n")
        self.set_status_state("running")
        self.update_status_bar("running", "Coffee Break")
        self._cb_advance()

    def stop_coffee_break(self):
        """Stop after the current step, and stop the current step too."""
        if not getattr(self, "_cb_active", False):
            return
        self._cb_active = False
        try:
            self.runner.stop()
        except Exception:
            pass
        self._cb_ui_call("_cb_ui_finished", "stopped")
        self.console.append_ansi("\n[!] Coffee Break stopped by the operator.\n")
        self.set_status_state("idle")

    def skip_coffee_break_stage(self):
        """Give up on the stage that is running and move to the next one."""
        if not getattr(self, "_cb_active", False):
            return
        self._cb_skip_requested = True
        try:
            self.runner.stop()
        except Exception:
            pass

    # ── sequencing ───────────────────────────────────────────────────────
    def _cb_advance(self):
        if not getattr(self, "_cb_active", False):
            return
        self._cb_index += 1
        if self._cb_index >= len(self._cb_stages):
            self._cb_complete()
            return

        stage = self._cb_stages[self._cb_index]
        gate = stage.get("when")
        if gate is not None and not gate(self._cb_artifacts):
            self._cb_ui_call("_cb_ui_stage", stage["key"], "skipped",
                             stage.get("skip_note", "not applicable"))
            self.console.append_ansi(
                f"\n[i] Skipping {stage['name']} — "
                f"{stage.get('skip_note', 'not applicable')}.\n")
            QTimer.singleShot(0, self._cb_advance)
            return

        self._cb_buffer = []
        self._cb_skip_requested = False
        self._cb_ui_call("_cb_ui_stage", stage["key"], "running", "")
        self.console.append_ansi(
            f"\n{'─' * 70}\n[*] Coffee Break {self._cb_index + 1}/"
            f"{len(self._cb_stages)}: {stage['name']}\n{'─' * 70}\n")

        if stage["kind"] == "shell":
            self.current_action_label = f"Coffee Break — {stage['name']}"
            try:
                self.start_progress_animation()
            except Exception:
                pass
            self.runner.run_command(stage["command"], str(self.output_dir))
        else:
            self._cb_start_worker(stage)

    def _cb_start_worker(self, stage):
        context = {
            "url": self._cb_target_url(),
            "output_dir": str(self.output_dir),
            "headers": self._cb_extra_headers(),
            "timeout": 15,
            **self._cb_artifacts,
        }
        self._cb_thread = QThread()
        self._cb_worker = _CBWorker(stage["probe"], context)
        self._cb_worker.moveToThread(self._cb_thread)
        self._cb_thread.started.connect(self._cb_worker.run)
        self._cb_worker.progress.connect(
            lambda line: self.console.append_ansi(f"    {line}\n"))
        self._cb_worker.finished.connect(
            lambda findings, artefacts, error:
            self._cb_worker_done(stage, findings, artefacts, error))
        self._cb_thread.start()

    def _cb_worker_done(self, stage, findings, artefacts, error):
        try:
            self._cb_thread.quit()
            self._cb_thread.wait(3000)
        except Exception:
            pass
        self._cb_thread = None
        self._cb_worker = None

        if error:
            self.console.append_ansi(f"    [!] {stage['name']} failed: {error}\n")
            self._cb_ui_call("_cb_ui_stage", stage["key"], "failed", error)
        else:
            for finding in findings:
                self._cb_record(finding)
            self._cb_artifacts.update(artefacts or {})
            self._cb_ui_call("_cb_ui_stage", stage["key"], "done",
                             f"{len(findings)} finding(s)")
        QTimer.singleShot(0, self._cb_advance)

    def _cb_on_command_finished(self, exit_code):
        """Called from OutputMixin.on_command_finished while the chain runs."""
        if not getattr(self, "_cb_active", False):
            return
        stage = self._cb_stages[self._cb_index]
        text = "".join(self._cb_buffer)
        parser = stage.get("parser")
        produced = 0
        if parser and hasattr(self, parser):
            try:
                produced = getattr(self, parser)(stage, text) or 0
            except Exception as exc:                    # noqa: BLE001
                self.console.append_ansi(
                    f"    [!] Could not read {stage['name']} output: {exc}\n")
        if self._cb_skip_requested:
            status, note = "skipped", "skipped by the operator"
        elif exit_code == 0:
            status, note = "done", f"{produced} finding(s)"
        else:
            status, note = "failed", f"exit {exit_code}"
        self._cb_ui_call("_cb_ui_stage", stage["key"], status, note)
        QTimer.singleShot(0, self._cb_advance)

    def _cb_capture_output(self, text):
        """Tee the runner's output into the current stage's buffer."""
        if getattr(self, "_cb_active", False):
            self._cb_buffer.append(text)
            if len(self._cb_buffer) > 20000:
                del self._cb_buffer[:10000]

    def _cb_complete(self):
        self._cb_active = False
        elapsed = time.time() - self._cb_started_at
        counts = {s: 0 for s in SEVERITIES}
        for finding in self._cb_findings:
            counts[finding.severity] = counts.get(finding.severity, 0) + 1
        summary = ", ".join(f"{counts[s]} {s.lower()}" for s in SEVERITIES
                            if counts.get(s))
        self.console.append_ansi("\n" + "=" * 80 + "\n")
        self.console.append_ansi(
            f"[*] Coffee Break finished in {int(elapsed // 60)}m "
            f"{int(elapsed % 60)}s — {len(self._cb_findings)} finding(s)"
            + (f": {summary}" if summary else "") + "\n")
        self.console.append_ansi("=" * 80 + "\n")
        self._cb_ui_call("_cb_ui_finished", "completed")
        try:
            self.set_status_state("idle")
            self.update_status_bar("success", "Coffee Break")
            self.progress_bar.setValue(100)
        except Exception:
            pass

    # ── helpers ──────────────────────────────────────────────────────────
    def _cb_ui_call(self, name, *args):
        handler = getattr(self, name, None)
        if handler:
            try:
                handler(*args)
            except Exception:
                pass

    def _cb_target_url(self):
        target = self.target
        if not target.startswith(("http://", "https://")):
            target = "https://" + target
        return target

    def _cb_extra_headers(self):
        headers = {}
        try:
            for line in (self.custom_headers_input.toPlainText() or "").splitlines():
                if ":" in line:
                    name, _, value = line.partition(":")
                    headers[name.strip()] = value.strip()
        except Exception:
            pass
        return headers

    def _cb_record(self, finding):
        """Keep a finding, unless it is one we already have."""
        signature = (finding.severity, finding.title, finding.where)
        if any((f.severity, f.title, f.where) == signature
               for f in self._cb_findings):
            return
        self._cb_findings.append(finding)
        self._cb_ui_call("_cb_ui_finding", finding)
        self.console.append_ansi(
            f"    {SEV_TAG.get(finding.severity, '[INFO]')} "
            f"{finding.title} — {finding.where}\n")

    def _cb_note_status(self, url, status):
        """Remember anything that answered 401/403 so the bypass stage has work."""
        if status in (401, 403):
            forbidden = self._cb_artifacts.setdefault("forbidden", [])
            if url not in forbidden:
                forbidden.append(url)

    # ── parsers ──────────────────────────────────────────────────────────
    def _cb_parse_nmap(self, stage, text):
        produced = 0
        ports = self._cb_artifacts.setdefault("open_ports", [])
        for line in text.splitlines():
            match = re.match(r"^(\d+)/(tcp|udp)\s+open\s+(\S+)(?:\s+(.*))?$",
                             line.strip())
            if not match:
                continue
            port, proto, service, version = match.groups()
            entry = f"{port}/{proto} {service}"
            if entry not in ports:
                ports.append(entry)
            banner = (version or "").strip()
            risky = {"telnet": "HIGH", "ftp": "MEDIUM", "rlogin": "HIGH",
                     "rsh": "HIGH", "vnc": "MEDIUM", "rdp": "MEDIUM",
                     "smb": "MEDIUM", "microsoft-ds": "MEDIUM",
                     "mysql": "MEDIUM", "postgresql": "MEDIUM",
                     "redis": "HIGH", "mongodb": "HIGH", "memcached": "HIGH",
                     "elasticsearch": "HIGH"}
            severity = risky.get(service.lower())
            if severity:
                self._cb_record(CBFinding(
                    severity=severity,
                    title=f"{service} reachable on {port}/{proto}",
                    where=f"{self.get_scanner_target()}:{port}",
                    detail="A service that is rarely meant to face the internet "
                           "is answering. Check whether it should be reachable "
                           "at all before testing it.",
                    evidence=line.strip(),
                    remediation="Restrict it to the networks that need it.",
                    stage=stage["key"]))
                produced += 1
        if ports:
            self.console.append_ansi(f"    open: {', '.join(ports)}\n")
        return produced

    def _cb_parse_testssl(self, stage, text):
        produced = 0
        for line in text.splitlines():
            clean = re.sub(r"\x1b\[[0-9;]*m", "", line).strip()
            severity = None
            if re.search(r"\b(CRITICAL)\b", clean):
                severity = "CRITICAL"
            elif re.search(r"\b(HIGH)\b", clean):
                severity = "HIGH"
            elif re.search(r"\b(MEDIUM)\b", clean):
                severity = "MEDIUM"
            elif re.search(r"\b(LOW)\b", clean):
                severity = "LOW"
            if not severity or len(clean) < 12:
                continue
            title = re.split(r"\s{2,}", clean)[0][:90] or clean[:90]
            self._cb_record(CBFinding(
                severity=severity, title=f"TLS: {title}",
                where=self.get_scanner_target(),
                detail="Reported by testssl against the TLS configuration.",
                evidence=clean[:400], stage=stage["key"]))
            produced += 1
        return produced

    def _cb_parse_nikto(self, stage, text):
        produced = 0
        for line in text.splitlines():
            clean = line.strip()
            if not clean.startswith("+ ") or len(clean) < 12:
                continue
            body = clean[2:]
            if body.startswith(("Target ", "Start Time", "End Time",
                                "Server:", "Root page", "No CGI", "Scan terminated",
                                "host(s) tested", "SSL Info", "Allowed HTTP")):
                continue
            severity = "LOW"
            lowered = body.lower()
            if any(w in lowered for w in ("osvdb", "cve-", "vulnerab",
                                          "traversal", "injection")):
                severity = "MEDIUM"
            if any(w in lowered for w in ("remote code", "shell", "backdoor")):
                severity = "HIGH"
            self._cb_record(CBFinding(
                severity=severity, title=body[:110],
                where=self._cb_target_url(),
                detail="Reported by Nikto. Confirm by hand before reporting — "
                       "Nikto is signature-driven and does not verify.",
                evidence=body[:500], confidence="tentative",
                stage=stage["key"]))
            produced += 1
        return produced

    def _cb_parse_nuclei(self, stage, text):
        produced = 0
        lines = []
        path = stage.get("artefact_file")
        if path and Path(path).is_file():
            lines = Path(path).read_text(errors="replace").splitlines()
        else:
            lines = [l for l in text.splitlines() if l.strip().startswith("{")]
        for line in lines:
            line = line.strip()
            if not line.startswith("{"):
                continue
            try:
                row = json.loads(line)
            except Exception:
                continue
            info = row.get("info") or {}
            severity = str(info.get("severity", "info")).upper()
            matched = row.get("matched-at") or row.get("host") or self.target
            self._cb_record(CBFinding(
                severity=severity if severity in SEVERITIES else "INFO",
                title=info.get("name") or row.get("template-id", "nuclei match"),
                where=matched,
                detail=(info.get("description") or "").strip()
                       or "Matched a nuclei template.",
                evidence=(row.get("extracted-results") and
                          ", ".join(row["extracted-results"])[:400])
                         or row.get("matcher-name", "") or line[:300],
                remediation=" ".join(info.get("remediation", "").split())[:600],
                stage=stage["key"]))
            produced += 1
        return produced

    def _cb_parse_wpscan(self, stage, text):
        produced = 0
        for match in re.finditer(r"\|\s*\[!\]\s*Title:\s*(.+)", text):
            title = match.group(1).strip()
            self._cb_record(CBFinding(
                severity="MEDIUM", title=f"WordPress: {title}"[:120],
                where=self._cb_target_url(),
                detail="Reported by wpscan against the WordPress install, its "
                       "plugins or its themes.",
                evidence=title[:400], stage=stage["key"]))
            produced += 1
        if re.search(r"User\(s\) Identified", text):
            users = re.findall(r"\|\s*\[i\]\s*(\S+)$", text, re.M)
            if users:
                self._cb_record(CBFinding(
                    severity="LOW", title="WordPress usernames enumerable",
                    where=self._cb_target_url(),
                    detail="Valid usernames make password attacks cheaper.",
                    evidence=", ".join(users[:12]), stage=stage["key"]))
                produced += 1
        return produced

    def _cb_parse_fuzz(self, stage, text):
        """Read SmartFuzz/ffuf output for endpoints, and bank the 401s and 403s."""
        produced = 0
        endpoints = self._cb_artifacts.setdefault("endpoints", [])
        base = self._cb_target_url().rstrip("/")
        for line in text.splitlines():
            clean = re.sub(r"\x1b\[[0-9;]*m", "", line).strip()
            match = (re.search(r"^(/\S*)\s+.*?\[Status:\s*(\d{3})", clean)
                     or re.search(r"^(\S+)\s+\[Status:\s*(\d{3})", clean)
                     or re.search(r"Status:\s*(\d{3}).*?(/\S+)$", clean))
            if not match:
                continue
            groups = match.groups()
            if groups[0].isdigit():
                status, path = int(groups[0]), groups[1]
            else:
                path, status = groups[0], int(groups[1])
            if not path.startswith("/"):
                path = "/" + path
            url = base + path
            if url not in endpoints:
                endpoints.append(url)
            self._cb_note_status(url, status)
            if status in (401, 403):
                produced += 1
        forbidden = self._cb_artifacts.get("forbidden") or []
        self.console.append_ansi(
            f"    {len(endpoints)} endpoint(s); {len(forbidden)} answered "
            f"401/403 and will be tried against the bypass stage\n")
        return produced

    def _cb_parse_params(self, stage, text):
        """Collect parameterised URLs for the traversal stage."""
        urls = self._cb_artifacts.setdefault("param_urls", [])
        blob = text
        path = stage.get("artefact_file")
        if path and Path(path).is_file():
            blob += "\n" + Path(path).read_text(errors="replace")
        # Anything the JavaScript stage saw counts too.
        for candidate in (self._cb_artifacts.get("endpoints") or []):
            blob += "\n" + candidate
        for match in re.finditer(r"https?://\S+\?\S+=\S*", blob):
            url = match.group(0).strip().rstrip(",;)'\"")
            if url not in urls:
                urls.append(url)
        self.console.append_ansi(
            f"    {len(urls)} parameterised URL(s) for the traversal stage\n")
        return 0

    # ── export ───────────────────────────────────────────────────────────
    def coffee_break_report(self):
        """The findings as Markdown, ready to paste into a report."""
        lines = [f"# Coffee Break — {self.target}", ""]
        elapsed = time.time() - (self._cb_started_at or time.time())
        lines.append(f"{len(self._cb_findings)} finding(s) in "
                     f"{int(elapsed // 60)}m {int(elapsed % 60)}s.")
        lines.append("")
        for severity in SEVERITIES:
            group = [f for f in self._cb_findings if f.severity == severity]
            if not group:
                continue
            lines.append(f"## {severity} ({len(group)})")
            lines.append("")
            for finding in group:
                lines.append(f"### {finding.title}")
                lines.append(f"- **Where:** {finding.where}")
                lines.append(f"- **Stage:** {finding.stage}")
                lines.append(f"- **Confidence:** {finding.confidence}")
                if finding.detail:
                    lines.append(f"\n{finding.detail}\n")
                if finding.evidence:
                    lines.append("```\n" + finding.evidence.strip() + "\n```")
                if finding.remediation:
                    lines.append(f"**Fix:** {finding.remediation}")
                lines.append("")
        table = self._cb_artifacts.get("bypass_table") or []
        if table:
            lines.append("## 403 bypass attempts")
            lines.append("")
            lines.append("| Endpoint | Technique | Method | Baseline | Result | Bypassed |")
            lines.append("|---|---|---|---|---|---|")
            for row in table:
                lines.append(
                    f"| {row['url']} | {row['trick']} | {row['method']} | "
                    f"{row['baseline']} | {row['status']} ({row['length']}B) | "
                    f"{'yes' if row['bypassed'] else 'no'} |")
            lines.append("")
        return "\n".join(lines)
