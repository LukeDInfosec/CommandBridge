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
from command_bridge.modules import cb_control, cb_evidence, cb_issues
from command_bridge.modules.cb_control import RunGate, Stopped
from command_bridge.modules.cb_evidence import Evidence
from command_bridge.modules.cb_issues import ISSUES, clean_title

# ─────────────────────────────────────────────────────────────────────────────
#  Findings
# ─────────────────────────────────────────────────────────────────────────────

#: Every stage, in order, as (key, name, why you might turn it off). The
#: options panel needs this before a target exists, so it cannot come from
#: _cb_stage_list() — that one builds real commands and needs a target.
CB_STAGE_CATALOGUE = (
    ("nmap_quick", "Nmap — service scan", "fast, almost always worth it"),
    ("nmap_full", "Nmap — all 65535 ports", "thorough and slow"),
    ("nmap_udp", "Nmap — UDP top 200", "slow, and noisy on some networks"),
    ("testssl", "TLS configuration (testssl)", "HTTPS only"),
    ("headers", "HTTP and security headers", "fast"),
    ("nikto", "Nikto", "signature-driven, needs verifying"),
    ("nuclei", "Nuclei templates", "the widest coverage here"),
    ("javascript", "JavaScript retrieval and analysis", "front-end heavy apps"),
    ("redirect", "Unvalidated redirects", "fast"),
    ("wordpress", "WordPress (wpscan)", "skipped unless WordPress is found"),
    ("smartfuzz", "SmartFuzz content discovery", "the long one"),
    ("params", "Parameter discovery", "feeds the traversal stage"),
    ("traversal", "Path traversal against parameters", "needs parameters"),
    ("bypass", "403 bypass", "needs something that answered 401/403"),
)

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
    cwe: str = ""
    references: list = field(default_factory=list)
    #: The library key. Two tools describing the same problem in their own
    #: words produce the same key, which is what lets them become one finding
    #: instead of two that a reader has to work out are the same.
    key: str = ""
    #: Which stages saw it. A finding corroborated by three tools is worth
    #: more than one seen by a single signature match, and the report should
    #: say which ones.
    sources: list = field(default_factory=list)
    #: Every other place the same issue was seen. Burp calls these instances,
    #: and keeping them on one finding is the difference between "the site is
    #: missing a CSP" and four hundred identical rows.
    instances: list = field(default_factory=list)
    #: The evidence chain. Its own object, never shared with another finding,
    #: holding the request, parameter, payload, response, detector and raw
    #: tool output that this specific finding rests on.
    proof: object = None            # cb_evidence.Evidence
    #: The verdict on whether ``proof`` supports ``key``.
    validation: object = None       # cb_evidence.Validation
    #: Where the finding sits on DETECTED → CONFIRMED.
    state: str = cb_evidence.DETECTED
    #: What the scanner itself rated it, kept apart from our own severity so
    #: the report can show both and say which is which.
    scanner_severity: str = ""
    #: One evidence object per additional sighting, parallel to ``instances``.
    instance_proof: list = field(default_factory=list)
    #: The active scanner's graded verdict, when this came from the Active
    #: Scan: the signals it rested on, the reasoning, what could still
    #: explain it away and how to settle it. Kept whole so the detail pane
    #: can show the raw detection separately from the interpretation.
    verdict: object = None          # scanner.grading.Verdict
    #: Raw numbers behind the detection — response times, lengths, statuses.
    measurements: dict = field(default_factory=dict)
    #: Who the scanner was when it saw this (§15).
    auth_context: dict = field(default_factory=dict)
    #: The HTTP method of the request that produced it.
    method: str = ""

    def __post_init__(self):
        if self.proof is None:
            self.proof = cb_evidence.Evidence()
        # A finding built the short way — severity, title, where, evidence —
        # still gets an evidence object, seeded from what it was given. That
        # way there is exactly one place the report reads proof from, and
        # older call sites keep working without being rewritten.
        if self.proof.is_empty() and self.evidence:
            self.proof.raw = self.evidence
        if not self.proof.url:
            self.proof.url = self.where
        if not self.proof.detector:
            self.proof.detector = self.stage
        self.confidence = cb_evidence.normalise_confidence(self.confidence)
        if self.validation is None:
            self.revalidate()

    # ── the evidence chain ───────────────────────────────────────────────
    def revalidate(self, detector_confirmed=False):
        """Re-run the sufficiency and consistency checks over this finding.

        Called whenever the evidence changes. The state, the confidence and
        the false-positive notes are all *derived* — none of them is set by
        hand anywhere, so none of them can drift away from what was seen.
        """
        self.validation = cb_evidence.assess(
            self.key, self.proof,
            issue_severity=self.severity,
            scanner_severity=self.scanner_severity,
            detector_confirmed=detector_confirmed,
            is_information=(self.severity == "INFO"))
        if len(self.sources) > 1:
            cb_evidence.corroborate(self.validation, self.sources)
        self.state = self.validation.state
        self.confidence = self.validation.confidence
        return self.validation

    def sort_key(self):
        return (-SEV_ORDER.get(self.severity, 0), self.title.lower())

    @property
    def count(self):
        return 1 + len(self.instances)

    def locations(self):
        return [self.where] + list(self.instances)

    def add_source(self, stage):
        """Record another tool that found the same thing."""
        if stage and stage not in self.sources:
            self.sources.append(stage)
            return True
        return False

    def add_instance(self, where, evidence="", proof=None):
        """Record another sighting of *the same issue*. True when it was new.

        The sighting's own evidence is kept as its own object, tagged with
        its location. It used to be concatenated onto ``self.evidence``,
        which is how a finding's proof pane came to contain text belonging to
        a different observation — and, once the two were run together, there
        was no way to tell which line had come from where.
        """
        if not where or where == self.where or where in self.instances:
            return False
        self.instances.append(where)
        if proof is not None:
            self.instance_proof.append(proof.copy())
        elif evidence:
            self.instance_proof.append(
                cb_evidence.Evidence(url=where, raw=evidence,
                                     detector=self.stage))
        return True

    def all_proof(self):
        """This finding's evidence and every instance's, in order."""
        return [self.proof] + list(self.instance_proof)

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
        except Stopped:
            # Not a failure. The operator stopped the run, or closed the
            # window, while this stage was mid-flight.
            self.finished.emit([], {}, "")
        except Exception as exc:                       # noqa: BLE001
            self.finished.emit([], {}, f"{type(exc).__name__}: {exc}")


# ─────────────────────────────────────────────────────────────────────────────
#  Probes — plain functions so they can run on a thread and be tested alone
# ─────────────────────────────────────────────────────────────────────────────

#: header name → the issue in the library that its absence is. Keeping the
#: wording in one place means the header check and nuclei's own
#: missing-header template produce the same finding rather than two.
SECURITY_HEADERS = {
    "content-security-policy": "csp_missing",
    "strict-transport-security": "hsts_missing",
    "x-frame-options": "xfo_missing",
    "x-content-type-options": "nosniff_missing",
    "referrer-policy": "referrer_policy",
    "permissions-policy": "permissions_policy",
    "x-permitted-cross-domain-policies": "xpcdp_missing",
}

#: CSP directives that make the header present but ineffective. Burp reports
#: each of these separately, and they do mean different things.
def analyse_csp(policy):
    """Everything wrong with a Content-Security-Policy, as issue keys.

    A CSP that is present is not a CSP that works. These are the
    misconfigurations that leave the header in place and the hole open, and
    they are worth more attention than a missing header — because the
    operator believes they are covered.
    """
    text = " ".join(str(policy or "").split())
    if not text:
        return []

    directives = {}
    for chunk in text.split(";"):
        parts = chunk.strip().split()
        if parts:
            directives[parts[0].lower()] = [p.lower() for p in parts[1:]]

    # script-src falls back to default-src; so does object-src.
    script = directives.get("script-src") or directives.get("script-src-elem") \
        or directives.get("default-src") or []
    found = []

    if any(source in ("'unsafe-inline'", "'unsafe-eval'") for source in script):
        # A nonce or hash makes 'unsafe-inline' inert in browsers that support
        # them, but 'unsafe-eval' is never inert.
        has_nonce = any(s.startswith(("'nonce-", "'sha256-", "'sha384-",
                                      "'sha512-")) for s in script)
        if "'unsafe-eval'" in script or not has_nonce:
            found.append("csp_unsafe_script")

    wildcard = [s for s in script
                if s == "*" or s.endswith(":") and s in ("http:", "https:",
                                                         "data:", "blob:",
                                                         "filesystem:")
                or s.startswith("*.") and s.count(".") < 2]
    if wildcard:
        found.append("csp_wildcard_source")

    if "object-src" not in directives or "base-uri" not in directives:
        found.append("csp_missing_object_base")
    if "frame-ancestors" not in directives:
        found.append("csp_clickjacking")
    if "form-action" not in directives:
        found.append("csp_form_hijack")
    return found


def strip_parameter_values(url):
    """``…/search?q=Test&id=7`` → ``…/search?q=&id=``.

    Parameter ORDER is preserved rather than sorted, because the order a
    parameter appears in is occasionally what a WAF keys on and it costs
    nothing to keep. Duplicated names are kept once — ?a=1&a=2 is one
    parameter with two values, and for this list it is one thing to fuzz.
    """
    try:
        parsed = urllib.parse.urlparse(str(url).strip())
    except Exception:                                   # noqa: BLE001
        return ""
    if not parsed.query:
        return ""
    names, seen = [], set()
    for pair in parsed.query.split("&"):
        name = pair.split("=", 1)[0].strip()
        if name and name not in seen:
            seen.add(name)
            names.append(name)
    if not names:
        return ""
    return urllib.parse.urlunparse(
        parsed._replace(query="&".join(f"{n}=" for n in names), fragment=""))


def _finding_from(key, where, evidence="", stage="", proof=None, **override):
    """A CBFinding built from the library — the free-function form.

    The mixin has its own ``_cb_issue``; probes run on a worker thread with no
    access to it, so they use this.
    """
    issue = ISSUES.get(key) or ISSUES["tls_generic"]
    if proof is None:
        proof = Evidence(url=where, detector=stage, raw=evidence,
                         observed=override.pop("observed", ""))
    else:
        # Worker threads build these; a copy means the finding cannot be
        # changed from underneath by whatever produced it.
        proof = proof.copy()
        proof.url = proof.url or where
        proof.detector = proof.detector or stage
    fields = dict(severity=issue["severity"], title=issue["title"],
                  where=where, detail=issue["detail"],
                  remediation=issue["remediation"], cwe=issue["cwe"],
                  references=list(issue["references"]),
                  evidence=evidence or proof.raw,
                  stage=stage, key=key, sources=[stage] if stage else [],
                  proof=proof)
    fields.update({k: v for k, v in override.items() if v})
    return CBFinding(**fields)


def finding_from_scan(scan_finding, stage="active-scan"):
    """Turn one of the active scanner's results into a CBFinding.

    The evidence chain itself is built by
    :func:`cb_evidence.evidence_from_scan`, which the scanner's own report
    writer also uses — it has to stay free of Qt, and this module is not.
    What happens here is only the part that needs the library: the title,
    the severity, the explanation and the fix.
    """
    proof = cb_evidence.evidence_from_scan(scan_finding)
    proof.detector = stage
    finding = _finding_from(
        getattr(scan_finding, "issue", ""),
        getattr(scan_finding, "where", ""),
        stage=stage, proof=proof,
        severity=getattr(scan_finding, "severity", "") or "",
    )
    # The grading module already decided how strong this evidence is, and
    # assess_scan is the single place that reconciles that grade with the
    # evidence chain. Going through it means the detail pane, the written
    # report and the JSON cannot disagree about one finding.
    _, validation = cb_evidence.assess_scan(scan_finding)
    finding.validation = validation
    finding.state = validation.state
    finding.confidence = validation.confidence
    finding.verdict = getattr(scan_finding, "verdict", None)
    finding.measurements = dict(getattr(scan_finding, "measurements", {})
                                or {})
    finding.auth_context = dict(getattr(scan_finding, "auth_context", {})
                                or {})
    finding.method = getattr(scan_finding, "method", "") or ""
    return finding
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
    # Every probe reaches the network through here, so gating the session is
    # what makes Pause mean "stop touching the target" for the Python stages
    # too. Before this, Pause suspended the external tool and held the chain,
    # and the header/JavaScript/traversal/bypass probes carried right on
    # making requests.
    return cb_control.gate_session(session, context.get("gate"))


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

    seen_headers = "Response headers: " + ", ".join(sorted(headers))[:400]
    for header, key in SECURITY_HEADERS.items():
        if header not in headers:
            findings.append(_finding_from(key, response.url, seen_headers,
                                          "headers"))

    # A CSP that is present but permits what it exists to prevent is its own
    # finding — and a more interesting one than a missing header, because the
    # operator believes they are covered.
    policy = headers.get("content-security-policy", "")
    if policy:
        for key in analyse_csp(policy):
            findings.append(_finding_from(
                key, response.url,
                f"Content-Security-Policy: {policy[:500]}", "headers"))
    if headers.get("content-security-policy-report-only") and not policy:
        findings.append(_finding_from(
            "csp_report_only", response.url,
            "Content-Security-Policy-Report-Only: "
            + headers["content-security-policy-report-only"][:300], "headers"))

    if not any(name in headers for name in
               ("cross-origin-opener-policy", "cross-origin-embedder-policy",
                "cross-origin-resource-policy")):
        findings.append(_finding_from("coop_missing", response.url,
                                      seen_headers, "headers"))

    if response.url.startswith("http://"):
        findings.append(_finding_from(
            "cleartext_http", response.url,
            f"Final URL after redirects: {response.url}", "headers"))

    for header in LEAKY_HEADERS:
        if header in headers and headers[header].strip():
            findings.append(_finding_from(
                "version_disclosure", response.url,
                f"{header}: {headers[header]}", "headers",
                title=f"Software version disclosed in {header}"))

    # Cookies are part of the response, and the flags are the whole game.
    # Each missing cookie attribute is its own issue, because each one is a
    # different attack. Consolidation then groups them across cookies.
    raw_cookies = " ".join(v for k, v in response.headers.items()
                           if k.lower() == "set-cookie")
    host = urllib.parse.urlparse(response.url).hostname or ""
    for cookie in response.cookies:
        where = f"{response.url} — cookie '{cookie.name}'"
        proof = f"Set-Cookie: {cookie.name}=…"
        if not cookie.secure:
            findings.append(_finding_from("cookie_no_secure", where, proof,
                                          "headers"))
        if not (cookie.has_nonstandard_attr("HttpOnly")
                or cookie.has_nonstandard_attr("httponly")):
            findings.append(_finding_from("cookie_no_httponly", where, proof,
                                          "headers"))
        if "samesite" not in raw_cookies.lower():
            findings.append(_finding_from("cookie_no_samesite", where, proof,
                                          "headers"))
        domain = (cookie.domain or "").lstrip(".")
        if domain and host.endswith(domain) and domain != host:
            findings.append(_finding_from(
                "cookie_parent_domain", where,
                f"{proof}; Domain={cookie.domain} (host is {host})", "headers"))
        if re.search(r"pass(word|wd)?|pwd", cookie.name, re.I):
            findings.append(_finding_from("password_in_cookie", where, proof,
                                          "headers"))

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
                findings.append(_finding_from(
                    "open_redirect", probe, stage="redirect",
                    title=f"Open redirection via '{param}'",
                    evidence=f"HTTP {response.status_code}\n"
                             f"Location: {location}"))
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
                        findings.append(_finding_from(
                            "traversal", probe, stage="traversal",
                            title=f"Path traversal via '{name}'",
                            evidence=f"Proof: {what}\n"
                                     + "\n".join(body.splitlines()[:6])[:600]))
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
                findings.append(_finding_from(
                    "edge_bypass", url, stage="bypass",
                    title=f"Access restriction bypassed with {label}",
                    evidence=f"{method} {probe}\n"
                             + "\n".join(f"{k}: {v}" for k, v in headers.items())
                             + f"\n→ HTTP {response.status_code} ({length} bytes); "
                               f"baseline was {base_status}"))
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
        self._cb_paused = False
        self._cb_resume_pending = False
        # One gate per run, shared with whatever probe is on the worker
        # thread. Reused rather than replaced, so a stage that is already
        # blocked on the old one cannot be left holding a gate nothing will
        # ever release.
        if getattr(self, "_cb_gate", None) is None:
            self._cb_gate = RunGate()
        else:
            self._cb_gate.stop()        # release anything still waiting
            self._cb_gate = RunGate()
        self._cb_current_command = ""
        self._cb_muted = self._cb_load_muted()

    # ── muted issues ─────────────────────────────────────────────────────
    def _cb_muted_path(self):
        from pathlib import Path as _Path
        directory = _Path.home() / ".config" / "CommandBridge"
        directory.mkdir(parents=True, exist_ok=True)
        return directory / "muted_issues.json"

    def _cb_load_muted(self):
        """Issue types this operator does not report.

        Every team has a list — the one that started this was BREACH. Muting
        is per issue type and survives restarts, because having to delete the
        same finding after every scan is how a tool trains you to skim.
        """
        try:
            path = self._cb_muted_path()
            if path.is_file():
                data = json.loads(path.read_text() or "[]")
                if isinstance(data, list):
                    return set(data)
        except Exception:                               # noqa: BLE001
            pass
        return set()

    def _cb_save_muted(self, keys):
        try:
            self._cb_muted_path().write_text(json.dumps(sorted(keys), indent=2))
        except Exception as exc:                        # noqa: BLE001
            self.console.append_ansi(f"[i] could not save the muted list: "
                                     f"{exc}\n")

    def mute_issue_type(self, key, muted=True):
        """Stop reporting an issue type, now and in future scans."""
        current = set(getattr(self, "_cb_muted", None) or self._cb_load_muted())
        if muted:
            current.add(key)
        else:
            current.discard(key)
        self._cb_muted = current
        self._cb_save_muted(current)
        return current

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

        enabled = getattr(self, "_cb_enabled_stages", None)
        stages = [
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
                 command=self._cb_testssl_command(),
                 parser="_cb_parse_testssl",
                 # testssl exits non-zero when it FINDS something, and again
                 # for a handful of benign conditions. Judging the stage on
                 # its exit code marked a successful scan as failed; the
                 # stage is judged on whether a report was produced.
                 judge_by_output=True,
                 artefact_file=f"{out}/{safe}_testssl.json"),
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
        if enabled is not None:
            stages = [stage for stage in stages if stage["key"] in enabled]
        return stages

    def _cb_testssl_command(self):
        """The same invocation the application's own TLS button uses.

        Two things were wrong with the bespoke command this replaces, and the
        rest of the application already had both solved:

          * ``--jsonfile`` REFUSES TO OVERWRITE. Auto Scan calls
            _cleanup_testssl_outputs() before it runs for exactly this reason
            — its comment says "so reruns do not crash". Coffee Break never
            did, so the first scan of a target worked, wrote the JSON, and
            every scan after it died instantly on a file-exists error. That
            is why this only started failing on a target being scanned
            repeatedly.
          * it wrote only JSON. The log and text reports are what
            _summarize_testssl() reads to print its summary, so that summary
            never appeared for a Coffee Break run.

        The command is built here rather than taken from the
        externals_testssl registry entry, because that template is written in
        {LOG_FILE}/{JSON_FILE}/{HOST} placeholders that only the externals
        code substitutes — reusing it here would run testssl with those braces
        still in the arguments. This mirrors Auto Scan's invocation instead,
        which is the one already proven against a real target.
        """
        import shlex
        safe = self.sanitize_target_for_filename(self.target)
        host = self.get_scanner_target()
        out = str(self.output_dir)

        # Clear the previous run's reports first — this is the fix.
        try:
            self._cleanup_testssl_outputs(safe)
        except Exception as exc:                        # noqa: BLE001
            self.console.append_ansi(
                f"[i] could not clear the previous TLS reports: {exc}\n")

        log_path = shlex.quote(f"{out}/{safe}_testssl.log")
        json_path = shlex.quote(f"{out}/{safe}_testssl.json")
        txt_path = shlex.quote(f"{out}/{safe}_testssl.txt")
        default = (
            f"if command -v testssl >/dev/null 2>&1; then "
            f"testssl --logfile {log_path} --jsonfile {json_path} "
            f"{host} | tee {txt_path}; "
            f"elif command -v testssl.sh >/dev/null 2>&1; then "
            f"testssl.sh --logfile {log_path} --jsonfile {json_path} "
            f"{host} | tee {txt_path}; "
            f"else echo '[i] testssl is not installed — skipping the TLS "
            f"stage. Install it with: sudo apt install testssl'; fi")
        return default

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
        self.current_action_label = "Coffee Break"
        self.set_status_state("running", tool="Coffee Break")
        self.update_status_bar("running", "Coffee Break")
        self._cb_advance()

    def stop_coffee_break(self):
        """Stop after the current step, and stop the current step too."""
        if not getattr(self, "_cb_active", False):
            return
        self._cb_active = False
        # Release the probe thread first, and make sure it is released even
        # if the run was paused: a SIGSTOP'd process ignores SIGTERM until it
        # is continued, and a gate nobody resumes blocks for ever.
        try:
            self._cb_gate.stop()
        except Exception:                               # noqa: BLE001
            pass
        self._cb_paused = False
        self._cb_signal_process("SIGCONT")
        try:
            self.runner.stop()
        except Exception:
            pass
        self._cb_ui_call("_cb_ui_finished", "stopped")
        self.console.append_ansi("\n[!] Coffee Break stopped by the operator.\n")
        self.set_status_state("idle")

    def pause_coffee_break(self):
        """Suspend the run, and hold the chain until it is resumed.

        Two things have to happen or this does not work: the process that is
        running right now is stopped (SIGSTOP, so a forty-minute nmap is not
        thrown away and restarted), and the chain is prevented from starting
        the next stage. Pausing only the first leaves the sequence marching on
        as soon as the current step ends.
        """
        if not getattr(self, "_cb_active", False):
            return False
        self._cb_paused = not getattr(self, "_cb_paused", False)
        if self._cb_paused:
            # Three things, not one. The external tool is suspended, the
            # chain is held, and the gate stops the Python probes at their
            # next request — which is the part that was missing, and the
            # reason a paused scan used to keep hitting the target.
            self._cb_gate.pause()
            self._cb_signal_process("SIGSTOP")
            self.console.append_ansi(
                "\n[*] Coffee Break paused. The running step is suspended, "
                "in-flight checks are held at their next request, and nothing "
                "further will start until you resume.\n")
            try:
                self.set_status_state("paused")
                self.update_status_bar("paused", self._cb_current_command)
            except Exception:                           # noqa: BLE001
                pass
        else:
            self._cb_gate.resume()
            self._cb_signal_process("SIGCONT")
            self.console.append_ansi("\n[*] Coffee Break resumed.\n")
            self._cb_assert_running()
            if self._cb_resume_pending:
                self._cb_resume_pending = False
                QTimer.singleShot(0, self._cb_advance)
        self._cb_ui_call("_cb_ui_paused", self._cb_paused)
        return self._cb_paused

    def _cb_signal_process(self, name):
        """Stop or continue the child process, if there is one."""
        import os
        import signal
        try:
            pid = self.runner.process.processId()
            if pid:
                os.kill(pid, getattr(signal, name))
                self._process_paused = (name == "SIGSTOP")
        except Exception as exc:                        # noqa: BLE001
            self.console.append_ansi(f"[i] could not {name} the running "
                                     f"process: {exc}\n")

    def _cb_assert_running(self):
        """Put the status bar back to running.

        The shared command runner announces "idle" when each command finishes
        and schedules another "idle" three seconds later. During a chain that
        is wrong twice over — the chain has not finished, and the next stage
        has already started — so every stage boundary re-asserts the truth.
        """
        try:
            self.current_action_label = (
                f"Coffee Break — {self._cb_stage_name()}")
            self.set_status_state("running", tool=self.current_action_label)
            self.update_status_bar("running", self._cb_current_command)
        except Exception:                               # noqa: BLE001
            pass

    def _cb_stage_name(self):
        try:
            return self._cb_stages[self._cb_index]["name"]
        except Exception:                               # noqa: BLE001
            return "running"

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
        if getattr(self, "_cb_paused", False):
            # Hold here. The resume picks the chain up from exactly this
            # point rather than restarting the stage that just finished.
            self._cb_resume_pending = True
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
            self._cb_current_command = stage["command"]
            self._cb_ui_call("_cb_ui_command", stage["command"])
            self._cb_assert_running()
            try:
                self.start_progress_animation()
            except Exception:
                pass
            self.runner.run_command(stage["command"], str(self.output_dir))
        else:
            self.current_action_label = f"Coffee Break — {stage['name']}"
            self._cb_current_command = (
                f"(built in) {stage['name']} — running inside Command Bridge, "
                f"no external tool")
            self._cb_ui_call("_cb_ui_command", self._cb_current_command)
            self._cb_assert_running()
            self._cb_start_worker(stage)

    def _cb_worker_context(self):
        """What a probe is handed when it runs.

        Its own method so the wiring — in particular that the run's gate
        reaches the probe — can be checked without starting a thread.
        """
        return {
            "url": self._cb_target_url(),
            "output_dir": str(self.output_dir),
            "headers": self._cb_extra_headers(),
            "timeout": 15,
            # Pause and Stop reach the probe through this.
            "gate": self._cb_gate,
            **self._cb_artifacts,
        }

    def _cb_start_worker(self, stage):
        context = self._cb_worker_context()
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
        elif stage.get("judge_by_output") and self._cb_stage_produced(stage,
                                                                     text):
            # The tool said something went wrong; it also produced a full
            # report. testssl returns non-zero precisely BECAUSE it found
            # something, which is the opposite of a failure.
            status, note = "done", f"{produced} finding(s)"
        else:
            status, note = "failed", f"exit {exit_code}"
        self._cb_ui_call("_cb_ui_stage", stage["key"], status, note)
        if getattr(self, "_cb_active", False):
            self._cb_assert_running()
        QTimer.singleShot(0, self._cb_advance)

    def _cb_stage_produced(self, stage, text):
        """Did this stage leave a usable report behind, whatever it exited?"""
        path = stage.get("artefact_file")
        try:
            if path and Path(path).is_file() and Path(path).stat().st_size > 20:
                return True
        except Exception:                               # noqa: BLE001
            pass
        safe = self.sanitize_target_for_filename(self.target)
        for suffix in (".txt", ".log"):
            try:
                companion = Path(self.output_dir) / f"{safe}_testssl{suffix}"
                if companion.is_file() and companion.stat().st_size > 200:
                    return True
            except Exception:                           # noqa: BLE001
                continue
        return len((text or "").strip()) > 400

    def _cb_capture_output(self, text):
        """Tee the runner's output into the current stage's buffer."""
        if getattr(self, "_cb_active", False):
            self._cb_buffer.append(text)
            if len(self._cb_buffer) > 20000:
                del self._cb_buffer[:10000]

    def _cb_complete(self):
        self._cb_active = False
        self._cb_current_command = ""
        self.current_action_label = None
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
        """Keep a finding — or, if we already have this issue, another instance.

        The old behaviour was one row per sighting, which is how a scan of a
        site with two hundred pages produced two hundred rows saying the same
        thing. Burp consolidates by issue type and lists the affected locations
        underneath, and so does this now.
        """
        if finding.key and finding.key in self._cb_muted:
            return

        for existing in self._cb_findings:
            #: Same issue = same library key, whichever tool found it. Nikto
            #: calling BREACH "the Content-Encoding header is set to deflate"
            #: and testssl calling it BREACH are one finding with two sources,
            #: not two findings a human has to reconcile.
            same = (existing.key and existing.key == finding.key) or \
                   (not finding.key and
                    (existing.title, existing.stage) ==
                    (finding.title, finding.stage))
            if not same:
                continue
            # Same library key is necessary but NOT sufficient. Two findings
            # only merge when their evidence is about the same subject as
            # well — otherwise de-duplication is a second route by which one
            # finding acquires another's proof.
            if not self._cb_compatible(existing, finding):
                continue
            changed = existing.add_instance(finding.where, finding.evidence,
                                            finding.proof)
            if existing.add_source(finding.stage):
                changed = True
            # The more serious assessment of the same issue wins.
            if cb_issues.worst(existing.severity, finding.severity) != \
                    existing.severity:
                existing.severity = cb_issues.worst(existing.severity,
                                                    finding.severity)
                changed = True
            # Corroboration raises confidence, never severity, and only
            # through the validator — which will refuse if the classification
            # is in dispute.
            if changed:
                existing.revalidate()
            if changed:
                self._cb_ui_call("_cb_ui_refresh", existing)
            return

        if not finding.sources and finding.stage:
            finding.sources = [finding.stage]
        self._cb_findings.append(finding)
        self._cb_ui_call("_cb_ui_finding", finding)
        # The console line says the state as well as the severity, so a
        # CRITICAL that nothing has actually confirmed cannot be mistaken for
        # one that has.
        self.console.append_ansi(
            f"    [{finding.state}] {SEV_TAG.get(finding.severity, '[INFO]')} "
            f"{finding.title} — {finding.where}\n")
        if finding.validation and not \
                finding.validation.classification_consistent:
            self.console.append_ansi(
                f"      ⚠ CLASSIFICATION/EVIDENCE MISMATCH — "
                f"manual validation required\n")

    @staticmethod
    def _cb_compatible(existing, incoming):
        """May these two findings become one?

        Only when the evidence behind both is about the same subject. A
        genuine command injection proved by ``uid=0(root)`` and a passive
        alert carrying a CSP header share a library key in the failure mode
        this guards against; they must not share a row, because merging them
        would hand the passive alert the exploited one's proof.
        """
        first = cb_evidence.topics_in(existing.proof.evidence_text())
        second = cb_evidence.topics_in(incoming.proof.evidence_text())
        if not first or not second:
            return True                     # nothing to disagree about
        if first & second:
            return True
        # Disjoint subjects. Only merge if neither is an exploitation claim,
        # where the evidence is the whole finding.
        return existing.key not in cb_evidence.EXPLOIT_REQUIRED

    def _cb_issue(self, key, where, evidence="", stage="", proof=None,
                  **override):
        """Build a finding from the named-issue library.

        Everything the library knows — the settled title, the severity, the
        explanation, the fix, the CWE — comes from one place, so the same
        problem reads the same way whichever tool happened to spot it.
        """
        issue = ISSUES.get(key) or ISSUES["tls_generic"]
        # Every finding gets its OWN evidence object. Callers that pass one in
        # get a copy of it, so nothing upstream can still hold a reference and
        # mutate a finding's proof after the fact.
        if proof is None:
            proof = Evidence(target=getattr(self, "target", ""), url=where,
                             detector=stage, raw=evidence,
                             observed=override.pop("observed", ""))
        else:
            proof = proof.copy()
            if not proof.url:
                proof.url = where
            if not proof.detector:
                proof.detector = stage
        fields = dict(
            severity=issue["severity"], title=issue["title"],
            where=where, detail=issue["detail"],
            remediation=issue["remediation"], cwe=issue["cwe"],
            references=list(issue["references"]),
            evidence=evidence or proof.raw,
            stage=stage, key=key, sources=[stage] if stage else [],
            proof=proof)
        fields.update({k: v for k, v in override.items() if v})
        return CBFinding(**fields)

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
            name = service.lower()
            key = cb_issues.NMAP_SERVICES.get(name)
            if key:
                banner = (version or "").strip()
                self._cb_record(self._cb_issue(
                    key, f"{self.get_scanner_target()}:{port}",
                    line.strip(), stage["key"],
                    severity=cb_issues.NMAP_SEVERITY.get(name),
                    title=f"{ISSUES[key]['title']} — {service} on "
                          f"{port}/{proto}",
                    detail=ISSUES[key]["detail"]
                           + (f"\n\nBanner: {banner}" if banner else "")))
                produced += 1
        if ports:
            self.console.append_ansi(f"    open: {', '.join(ports)}\n")
        return produced

    def _cb_parse_testssl(self, stage, text):
        """Read testssl's JSON, and report named issues rather than its prose.

        testssl writes one record per check with a stable ``id``, a severity and
        a CVE. Those records are mapped onto the issue library, so a host that
        offers CBC suites produces one finding called **Lucky 13** carrying the
        suites as evidence — instead of, as before, one row per line that
        happened to contain the word MEDIUM, with the title cut at ninety
        characters somewhere in the middle of a word.

        Records testssl marks OK or INFO are what "not vulnerable" looks like;
        they are not findings and are not reported.
        """
        records = self._cb_testssl_records(stage, text)
        if not records:
            return 0

        #: key → (severity, [evidence lines], [cves])
        grouped = {}
        for record in records:
            identifier = str(record.get("id", ""))
            # Records that describe the configuration rather than fault it.
            # These were the whole of the "TLS configuration weakness" noise:
            # a list of signature algorithms and an empty CAA record, reported
            # as a weakness with the raw record as the only explanation.
            informational = bool(
                cb_issues.TESTSSL_INFORMATIONAL.match(identifier))
            if informational:
                named = cb_issues.for_testssl_informational(record)
                if not named:
                    continue
                key, issue = named, ISSUES[named]
            else:
                key, issue = cb_issues.for_testssl(record)
            if not key:
                continue
            reported = str(record.get("severity", "")).upper()
            # The library decides, not testssl. Its ratings are absolute
            # (SSLv3 is "high" wherever it appears); a report needs one
            # consistent scale, and that scale lives in cb_issues.
            severity = cb_issues.severity_for(
                key, reported if reported in SEVERITIES else "")
            line = clean_title(record.get("finding", ""), 300)
            identifier = str(record.get("id", ""))
            bucket = grouped.setdefault(key, {"severity": severity,
                                              "lines": [], "cves": []})
            bucket["severity"] = severity
            entry = f"{identifier}: {line}" if identifier else line
            if entry not in bucket["lines"]:
                bucket["lines"].append(entry)
            for cve in str(record.get("cve", "")).split():
                if cve and cve not in bucket["cves"]:
                    bucket["cves"].append(cve)

        produced = 0
        host = self.get_scanner_target()
        for key, bucket in grouped.items():
            evidence = "\n".join(bucket["lines"][:14])
            if len(bucket["lines"]) > 14:
                evidence += f"\n… and {len(bucket['lines']) - 14} more"
            detail = ISSUES[key]["detail"]
            title = None
            if key == "obsolete_protocol":
                # Name the versions. "Obsolete TLS protocol version enabled"
                # is the first thing a client asks a follow-up question about.
                pretty = {"sslv2": "SSLv2", "sslv3": "SSLv3", "tls1": "TLS 1.0",
                          "tls1_1": "TLS 1.1"}
                versions = [pretty[v] for v in
                            sorted({line.split(":")[0].strip().lower()
                                    for line in bucket["lines"]})
                            if v in pretty]
                if versions:
                    title = (f"Obsolete TLS protocol version"
                             f"{'s' if len(versions) > 1 else ''} enabled: "
                             f"{', '.join(versions)}")
            if key == "tls_generic":
                # "TLS configuration weakness — reported by testssl" tells the
                # reader nothing. Name the checks that failed and hand over
                # testssl's own wording, which at least says what it looked at.
                names = ", ".join(sorted({line.split(":")[0]
                                          for line in bucket["lines"]})[:6])
                detail = (
                    f"testssl flagged {len(bucket['lines'])} TLS check(s) on "
                    f"this host that do not map to a named attack: {names}. "
                    f"The specific wording of each is in the evidence below. "
                    f"These are usually cipher-suite or protocol preferences "
                    f"rather than a single exploitable flaw — read the "
                    f"evidence and decide whether the configuration meets the "
                    f"standard this engagement is being measured against.")
            finding = self._cb_issue(key, host, evidence, stage["key"],
                                     severity=bucket["severity"],
                                     detail=detail, title=title)
            for cve in bucket["cves"]:
                if cve not in finding.references:
                    finding.references.append(cve)
            self._cb_record(finding)
            produced += 1
        self.console.append_ansi(
            f"    {len(records)} TLS check(s) read; {produced} issue(s) worth "
            f"reporting\n")
        return produced

    def _cb_testssl_records(self, stage, text):
        """testssl's JSON if it wrote any, otherwise its console output.

        The text fallback rebuilds records of the same shape so that everything
        downstream — the library lookup, the grouping — does not need to know
        which of the two it is reading.
        """
        safe = self.sanitize_target_for_filename(self.target)
        path = stage.get("artefact_file") or \
            str(Path(self.output_dir) / f"{safe}_testssl.json")
        if path and Path(path).is_file():
            try:
                blob = json.loads(Path(path).read_text(errors="replace"))
            except Exception:
                blob = None
            if isinstance(blob, dict):
                blob = blob.get("scanResult") or blob.get("findings") or []
                if blob and isinstance(blob[0], dict) and "findings" not in blob[0]:
                    pass
            if isinstance(blob, list) and blob:
                flat = []
                for item in blob:
                    if not isinstance(item, dict):
                        continue
                    if "id" in item:
                        flat.append(item)
                        continue
                    # testssl --jsonfile-pretty nests by section.
                    for value in item.values():
                        if isinstance(value, list):
                            flat.extend(v for v in value
                                        if isinstance(v, dict) and "id" in v)
                if flat:
                    return flat

        records = []
        for line in text.splitlines():
            clean = re.sub(r"\x1b\[[0-9;]*m", "", line).strip()
            if len(clean) < 12:
                continue
            severity = next((s for s in ("CRITICAL", "HIGH", "MEDIUM", "LOW")
                             if re.search(rf"\b{s}\b", clean)), None)
            if not severity:
                continue
            parts = re.split(r"\s{2,}", clean, maxsplit=1)
            records.append({"id": parts[0].strip(),
                            "severity": severity,
                            "finding": (parts[1] if len(parts) > 1
                                        else clean).strip(),
                            "cve": " ".join(re.findall(r"CVE-\d{4}-\d+", clean))})
        return records

    def _cb_parse_nikto(self, stage, text):
        """Nikto's '+' lines, with the scan's own bookkeeping thrown away.

        Three rules, in order:

          1. A statement about the scan is not a finding. "1 host(s) tested",
             "8299 requests: 0 errors", "Failed to check for updates: 403" —
             none of these say anything about the target, and reporting them
             at Low teaches the reader that Low means nothing.
          2. If the library recognises what Nikto is describing, the finding
             takes the library's name, severity, explanation and CWE. That is
             what merges Nikto's "the Content-Encoding header is set to
             deflate" with testssl's BREACH into one entry.
          3. Anything left is INFORMATIONAL unless it names a weakness.
             Nikto rates everything the same; a report cannot.
        """
        produced = 0
        observations = []
        for line in text.splitlines():
            clean = line.strip()
            if not clean.startswith("+ ") or len(clean) < 12:
                continue
            body = clean[2:].strip()

            if cb_issues.is_statement(body):
                continue                      # the scan talking about itself

            key, issue = cb_issues.for_text(body)
            if key == "robots_disclosure" and \
                    not self._cb_robots_worth_reporting():
                continue
            if key:
                if issue["severity"] != "INFO":
                    produced += 1
                self._cb_record(self._cb_issue(
                    key, self._cb_where_for(key, body), body[:500],
                    stage["key"], confidence="tentative",
                    detail=issue["detail"] + f"\n\nNikto reported: {body}\n\n"
                           "Nikto matches signatures and does not confirm "
                           "what it finds; verify before this goes in a "
                           "report."))
                continue

            if cb_issues.is_observation(body):
                if len(observations) < 60 and body not in observations:
                    observations.append(body)
                continue

            # Unrecognised, and not obviously an observation. Report it, but
            # at the severity its wording justifies rather than a flat Low.
            lowered = body.lower()
            if any(word in lowered for word in
                   ("remote code", "shell", "backdoor", "command execution")):
                severity = "HIGH"
            elif any(word in lowered for word in
                     ("osvdb", "cve-", "vulnerab", "exploit", "injection",
                      "traversal", "disclosure", "bypass", "overflow")):
                severity = "MEDIUM"
            elif any(word in lowered for word in
                     ("outdated", "insecure", "missing", "weak", "default",
                      "exposed", "enabled", "unprotected")):
                severity = "LOW"
            else:
                severity = "INFO"

            self._cb_record(CBFinding(
                severity=severity, title=clean_title(body),
                where=self._cb_target_url(),
                detail="Reported by Nikto.\n\n" + body + "\n\nNikto is "
                       "signature-driven and does not verify what it matches; "
                       "confirm this by hand before reporting it.",
                evidence=body[:500], confidence="tentative",
                stage=stage["key"], sources=[stage["key"]]))
            if severity != "INFO":
                produced += 1

        if observations:
            self._cb_record(self._cb_issue(
                "scan_information", self._cb_target_url(),
                "\n".join(observations), stage["key"],
                title="Server inventory observed by Nikto",
                confidence="tentative"))
        return produced

    def _cb_robots_worth_reporting(self):
        """Is there anything in robots.txt worth a line in a report?

        A 200 on robots.txt is not a finding. An empty file is not a finding.
        The finding — such as it is — is the file naming paths the operator
        wanted kept out of a search index, which is a shortlist of where to
        look. So fetch it and check, rather than trusting a scanner that only
        confirmed the file exists.
        """
        cached = self._cb_artifacts.get("robots_checked")
        if cached is not None:
            return cached
        worth, entries = False, []
        try:
            import requests
            response = requests.get(
                self._cb_target_url().rstrip("/") + "/robots.txt",
                timeout=12, verify=False,
                headers={"User-Agent": "CommandBridge"})
            if response.status_code == 200 and \
                    "html" not in (response.headers.get("Content-Type") or ""):
                for line in (response.text or "").splitlines():
                    line = line.strip()
                    if re.match(r"^(dis)?allow\s*:\s*\S", line, re.I) and \
                            not re.match(r"^disallow\s*:\s*/\s*$", line, re.I):
                        entries.append(line)
                worth = bool(entries)
        except Exception:                               # noqa: BLE001
            pass
        self._cb_artifacts["robots_checked"] = worth
        self._cb_artifacts["robots_entries"] = entries
        return worth

    def _cb_where_for(self, key, body):
        """The URL a finding belongs to, pulled out of the tool's own line.

        A login panel finding that says "somewhere on the target" is half a
        finding. Nikto prints the path it found; this puts it in the finding's
        location so the reader can click it.
        """
        base = self._cb_target_url().rstrip("/")
        match = re.search(r"(/[A-Za-z0-9_\-./%]{1,120})", body or "")
        if match and key in ("login_panel_exposed", "admin_exposed",
                             "directory_listing", "backup_file",
                             "vcs_exposed", "env_file_exposed",
                             "info_page_exposed", "source_code_disclosure",
                             "config_disclosed", "api_spec_exposed"):
            return base + match.group(1)
        return self._cb_target_url()

    @staticmethod
    def _cb_nuclei_observation(template, name, matched, extracted, matcher):
        """§14 — why nuclei raised this, said in terms of what it saw.

        Built only from things nuclei actually reported. If it reported
        nothing but a template id, that is what this says; it does not
        describe an interaction that was never observed.
        """
        if not template and not name:
            return ""
        sentence = (f"nuclei template '{template or name}' matched at "
                    f"{matched}.")
        if matcher:
            sentence += f" Matcher: {matcher}."
        if extracted:
            sentence += (" It extracted: "
                         + ", ".join(str(x) for x in extracted)[:300] + ".")
        else:
            sentence += (" The template's own match is the whole of the "
                         "evidence; no request, parameter or payload was "
                         "recorded.")
        return sentence

    def _cb_parse_nuclei(self, stage, text):
        produced = 0
        lines = []
        path = stage.get("artefact_file")
        if path and Path(path).is_file():
            lines = Path(path).read_text(errors="replace").splitlines()
        else:
            lines = [l for l in text.splitlines() if l.strip().startswith("{")]
        fingerprints = []
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
            template = row.get("template-id", "")
            name = info.get("name") or template or "nuclei match"
            description = " ".join((info.get("description") or "").split())

            # Name it BEFORE deciding it is noise. The previous order folded
            # anything nuclei rated info with no remediation into the
            # fingerprint bucket — and nuclei rates its entire exposed-panels
            # library exactly that way, so a publicly reachable Umbraco or
            # phpMyAdmin login page vanished into "Technology fingerprint".
            # An unnamed template can be inventory; a named issue never is.
            # Classification comes from the template's identity alone. The
            # description is metadata about the class of issue, written for a
            # human — feeding it in here is what turned weak-csp-detect into
            # a CRITICAL CWE-78.
            key, issue = cb_issues.for_nuclei(template, name)

            if not key and cb_issues.is_fingerprint(template):
                entry = f"{name} — {matched}"
                if entry not in fingerprints:
                    fingerprints.append(entry)
                continue

            references = [r for r in (info.get("reference") or []) if r][:6] \
                if isinstance(info.get("reference"), list) else []
            extracted = [str(x) for x in (row.get("extracted-results") or [])]
            evidence = (", ".join(extracted)[:400]
                        or row.get("matcher-name", "") or line[:300])
            if template:
                evidence = f"nuclei template: {template}\n{evidence}"

            # §11 — everything nuclei told us, kept with the result it came
            # from. The description lives here as template metadata and is
            # never fed back into classification.
            proof = Evidence(
                target=self.target,
                url=matched,
                method=str(row.get("type", "")).upper()
                       if str(row.get("type", "")).lower() in ("get", "post")
                       else "",
                detector="nuclei",
                template_id=template,
                template_name=name,
                template_author=", ".join(info.get("author") or [])
                                if isinstance(info.get("author"), list)
                                else str(info.get("author") or ""),
                template_severity=severity,
                template_tags=[t for t in (info.get("tags") or [])]
                              if isinstance(info.get("tags"), list) else [],
                template_path=str(row.get("template-path", "")
                                  or row.get("template", "")),
                matcher=str(row.get("matcher-name", "")),
                extracted=extracted,
                request=str(row.get("request", "") or ""),
                response=str(row.get("response", "") or "")[:2000],
                raw=line[:1200],
                observed=self._cb_nuclei_observation(
                    template, name, matched, extracted,
                    row.get("matcher-name", "")),
            )

            if key == "robots_disclosure" and \
                    not self._cb_robots_worth_reporting():
                continue
            if key:
                if key == "robots_disclosure":
                    evidence = "\n".join(
                        self._cb_artifacts.get("robots_entries") or []) \
                        or evidence
                finding = self._cb_issue(
                    key, matched, evidence, stage["key"], proof=proof,
                    severity=cb_issues.severity_for(
                        key, severity if severity in SEVERITIES else ""),
                    scanner_severity=severity,
                    detail=issue["detail"] + (f"\n\nnuclei: {name}"
                                              if name else ""))
                for reference in references:
                    if reference not in finding.references:
                        finding.references.append(reference)
                self._cb_record(finding)
            else:
                self._cb_record(CBFinding(
                    severity=severity if severity in SEVERITIES else "INFO",
                    title=clean_title(name),
                    where=matched,
                    detail=(description or "Matched a nuclei template.")
                           + (f"\n\nTemplate: {template}" if template else ""),
                    evidence=evidence,
                    remediation=" ".join(
                        info.get("remediation", "").split())[:600],
                    references=references,
                    # nuclei's own CWE, kept as the SCANNER's claim. It is
                    # presented as metadata on an unclassified detection, not
                    # as this tool's confirmed classification.
                    cwe=self._cb_cwe_from(info),
                    scanner_severity=severity,
                    proof=proof,
                    stage=stage["key"]))
            produced += 1

        if fingerprints:
            self._cb_record(CBFinding(
                severity="INFO",
                title="Technology fingerprint",
                where=self._cb_target_url(),
                detail="Everything nuclei recognised about the stack, in one "
                       "entry rather than one row each. Useful for choosing "
                       "what to test next; not a finding in itself.",
                evidence="\n".join(fingerprints[:60]),
                stage=stage["key"]))
        return produced

    @staticmethod
    def _cb_cwe_from(info):
        """nuclei's classification block, when the template carries one."""
        classification = info.get("classification") or {}
        cwe = classification.get("cwe-id") or ""
        if isinstance(cwe, list):
            cwe = ", ".join(str(c) for c in cwe[:3])
        return str(cwe).upper()

    def _cb_parse_wpscan(self, stage, text):
        produced = 0
        for match in re.finditer(r"\|\s*\[!\]\s*Title:\s*(.+)", text):
            title = match.group(1).strip()
            key, issue = cb_issues.for_text(title)
            if key:
                self._cb_record(self._cb_issue(
                    key, self._cb_target_url(), title[:400], stage["key"],
                    title=clean_title(f"WordPress: {ISSUES[key]['title']}"),
                    detail=issue["detail"] + f"\n\nwpscan reported: {title}"))
            else:
                self._cb_record(CBFinding(
                    severity="MEDIUM", title=clean_title(f"WordPress: {title}"),
                    where=self._cb_target_url(),
                    detail="Reported by wpscan against the WordPress install, "
                           "its plugins or its themes.",
                    evidence=title[:400], stage=stage["key"]))
            produced += 1
        if re.search(r"User\(s\) Identified", text):
            users = re.findall(r"\|\s*\[i\]\s*(\S+)$", text, re.M)
            if users:
                self._cb_record(self._cb_issue(
                    "user_enumeration", self._cb_target_url(),
                    ", ".join(users[:12]), stage["key"],
                    title="WordPress usernames enumerable"))
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
        """Collect parameterised URLs, and write the stripped list to a file.

        Two outputs from one pass. The traversal stage wants the URLs with
        their discovered values intact — a request that 404s without them
        proves nothing. A person wants them with the values removed, because
        that is the form you feed to ffuf, sqlmap or Burp Intruder:

            https://example.com/search?q=Test   →   https://example.com/search?q=
            https://example.com/item?id=7&s=a   →   https://example.com/item?id=&s=

        One line per distinct parameter shape, so a paginated site does not
        produce four hundred lines that differ only by an id.
        """
        urls = self._cb_artifacts.setdefault("param_urls", [])
        blob = text
        path = stage.get("artefact_file")
        if path and Path(path).is_file():
            blob += "\n" + Path(path).read_text(errors="replace")
        # Anything the JavaScript stage or the crawl saw counts too.
        for candidate in (self._cb_artifacts.get("endpoints") or []):
            blob += "\n" + candidate
        for match in re.finditer(r"https?://\S+\?\S+=\S*", blob):
            url = match.group(0).strip().rstrip(",;)'\"")
            if url not in urls:
                urls.append(url)

        written = self._cb_write_parameter_file(urls)
        self.console.append_ansi(
            f"    {len(urls)} parameterised URL(s) for the traversal stage\n")
        if written:
            self.console.append_ansi(f"    parameters written to {written}\n")
        return 0

    def _cb_write_parameter_file(self, urls):
        """Write 'Discovered Parameters.txt' — the URLs with values stripped."""
        stripped = []
        for url in urls:
            bare = strip_parameter_values(url)
            if bare and bare not in stripped:
                stripped.append(bare)
        if not stripped:
            return ""
        path = Path(self.output_dir) / "Discovered Parameters.txt"
        try:
            path.write_text("\n".join(sorted(stripped)) + "\n",
                            encoding="utf-8")
        except Exception as exc:                        # noqa: BLE001
            self.console.append_ansi(
                f"    [!] could not write the parameter list: {exc}\n")
            return ""
        self._cb_artifacts["parameter_file"] = str(path)
        self._cb_artifacts["stripped_params"] = stripped
        return str(path)

    # ── export ───────────────────────────────────────────────────────────
    @staticmethod
    def _cb_evidence_block(finding):
        """The observed-evidence part of a report entry.

        Kept strictly apart from the generic description and the remediation
        advice, because a reader has to be able to tell what was seen from
        what a library says about this kind of issue in general.
        """
        proof = finding.proof or cb_evidence.Evidence()
        validation = finding.validation or cb_evidence.Validation()
        lines = ["", "**Why this was detected:**",
                 "", (validation.rationale
                      or "Detection rationale unavailable."), ""]

        lines.append("**Observed evidence:**")
        lines.append("")
        lines.append("```")
        lines += cb_evidence.evidence_checklist(finding.key, proof)
        lines.append("```")

        section = cb_evidence.poc_section(finding.key, proof)
        lines += ["", "**Proof of concept:**", ""]
        if proof.poc() or len(section) > 1:
            lines += ["```"] + section + ["```"]
        else:
            lines += section

        burp = proof.burp_request()
        if burp:
            lines += ["", "**Replay in Burp:**", "", "```", burp, "```"]

        lines += ["", "**Validation:**", "",
                  f"- Evidence sufficient: "
                  f"{'Yes' if validation.evidence_sufficient else 'No'}",
                  f"- Classification consistent: "
                  f"{'Yes' if validation.classification_consistent else 'No'}"]
        for conflict in validation.conflicts:
            lines.append(f"- ⚠ {conflict}")
        if validation.false_positive_indicators:
            lines += ["", "**Potential false-positive indicators:**", ""]
            lines += [f"- {item}"
                      for item in validation.false_positive_indicators]

        raw = proof.raw_detection()
        if raw.strip() != "RAW DETECTION":
            lines += ["", "**Raw detection (what the tool actually said):**",
                      "", "```", raw, "```"]
        for extra in finding.instance_proof[:10]:
            extra_raw = extra.raw_detection()
            if extra_raw.strip() != "RAW DETECTION":
                lines += ["", f"_Instance at {extra.url}:_",
                          "", "```", extra_raw, "```"]
        if validation.action:
            lines += ["", f"**Next step:** {validation.action}"]
        return lines

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
                if finding.instances:
                    lines.append(f"- **Also at:** {len(finding.instances)} "
                                 f"other location(s)")
                    for extra in finding.instances[:25]:
                        lines.append(f"    - {extra}")
                    if len(finding.instances) > 25:
                        lines.append(f"    - … and "
                                     f"{len(finding.instances) - 25} more")
                lines.append(f"- **Status:** {finding.state}")
                lines.append(f"- **Stage:** {finding.stage}")
                lines.append(f"- **Confidence:** {finding.confidence}")
                lines.append(f"- **Severity (tool-assessed):** "
                             f"{finding.severity}")
                if finding.scanner_severity:
                    lines.append(f"- **Severity (scanner-reported):** "
                                 f"{finding.scanner_severity}")
                if finding.cwe:
                    lines.append(f"- **Classification:** {finding.cwe}")
                if finding.references:
                    lines.append("- **References:** "
                                 + ", ".join(str(r) for r in finding.references))
                lines += self._cb_evidence_block(finding)
                if finding.detail:
                    lines.append("\n**What this class of issue means "
                                 "(generic description):**\n")
                    lines.append(finding.detail + "\n")
                if finding.remediation:
                    lines.append(f"**Recommended remediation:** "
                                 f"{finding.remediation}")
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
