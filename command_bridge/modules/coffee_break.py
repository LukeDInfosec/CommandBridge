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
from command_bridge.modules import detector_registry, risk, verification
from command_bridge.modules import cipher_properties, csp_analysis, explanations
from command_bridge.modules import classification
from command_bridge.modules import port_risk, version_catalog, finding_groups
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


def _bytes_in(lines):
    """The body size out of a verifier evidence line, or 0."""
    for line in lines or []:
        match = re.search(r"(\d+)\s+bytes", str(line))
        if match:
            return int(match.group(1))
    return 0


def _version_in(lines):
    """The version a verifier read, or ""."""
    for line in lines or []:
        match = re.search(r"version\s+([0-9]+(?:\.[0-9]+){0,3})\b",
                          str(line), re.I)
        if match:
            return match.group(1)
    return ""


def _state_for(status):
    """A registry status → the finding-state vocabulary already in use.

    Two scales exist for good reasons: cb_evidence.STATES describes how
    far a finding has travelled, and the registry's statuses describe
    what a reader should do about it. Mapping rather than replacing keeps
    the existing table, colouring and report grouping working.
    """
    return {
        detector_registry.CONFIRMED: cb_evidence.VALIDATED,
        detector_registry.POTENTIAL: cb_evidence.POTENTIAL,
        detector_registry.INCONCLUSIVE: cb_evidence.INCONCLUSIVE,
        detector_registry.INFORMATIONAL: cb_evidence.DETECTED,
    }.get(str(status or "").upper(), cb_evidence.DETECTED)


def _same_location(first, second):
    """Are these the same URL, ignoring a trailing slash on the root?

    A finding reported at ``https://example.com`` and one reported at
    ``https://example.com/`` are the same place. Treating them as two
    produced an "also seen at" entry that was the same page again, and
    made a pair of findings look like coverage of two locations.
    """
    def normal(value):
        value = str(value or "").strip()
        return value[:-1] if value.endswith("/") and value.count("/") == 3 \
            else value
    return bool(first) and normal(first) == normal(second)


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
    #: A subdivision of the key, when one key covers several findings
    #: that must stay apart. SSLv3 and TLS 1.0 are both
    #: ``obsolete_protocol``, and merging them on that basis is what
    #: produced a single MEDIUM row reading "SSLv3, TLS 1.0" — the HIGH
    #: fact averaged into the LOW one. Two findings with different
    #: variants never merge; an empty variant behaves as before.
    variant: str = ""
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
        # https://host and https://host/ are the same location. Without
        # this, two tools reporting the same issue on the same page look
        # like one finding "also seen at" a second URL that is the first
        # URL with a slash on the end.
        if _same_location(where, self.where) or \
                any(_same_location(where, seen) for seen in self.instances):
            return False
        if not where:
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
    # x-frame-options is deliberately NOT here. Framing is assessed from
    # both headers together — see the framing block in probe_headers —
    # rather than reported as one more missing header, which produced two
    # findings for one weakness on any host that had neither.
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
    # frame-ancestors is NOT judged here any more. A missing directive
    # is only a finding once X-Frame-Options has also been looked at,
    # and that needs the response — see the framing block in
    # probe_headers, which assesses both together.
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


def _header_exchange(response, limit=40):
    """The request and the response head, verbatim, as a tester reads them.

    A header finding is about what the server sent, so the evidence should
    be what the server sent — not a summary of it, and not a list of the
    header names with the values thrown away.
    """
    try:
        request = getattr(response, "request", None)
        method = getattr(request, "method", "GET")
        url = getattr(request, "url", response.url)
        parsed = urllib.parse.urlparse(str(url))
        path = parsed.path or "/"
        if parsed.query:
            path += "?" + parsed.query
        lines = [f"{method} {path} HTTP/1.1", f"Host: {parsed.netloc}"]
        for name, value in (getattr(request, "headers", {}) or {}).items():
            if name.lower() in ("host",):
                continue
            lines.append(f"{name}: {value}")
        lines.append("")
        lines.append("")
        reason = getattr(response, "reason", "") or ""
        lines.append(f"HTTP/1.1 {response.status_code} {reason}".rstrip())
        for name, value in list(response.headers.items())[:limit]:
            lines.append(f"{name}: {value}")
        return "\n".join(lines)
    except Exception:                                   # noqa: BLE001
        return "Response headers: " + ", ".join(
            sorted(k.lower() for k in response.headers))[:400]


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

    # The exchange itself, written the way a tester reads one. A list of
    # header *names* ("Response headers: content-length, content-type,
    # date, server") was what this used to show, and it answered none of the
    # questions a reader of a header finding has: what was sent, what came
    # back, and what the headers actually said. The request and the full
    # response head go in verbatim instead.
    seen_headers = _header_exchange(response)
    for header, key in SECURITY_HEADERS.items():
        if header not in headers:
            findings.append(_finding_from(key, response.url, seen_headers,
                                          "headers"))

    # HSTS that is present but short-lived is a different finding from HSTS
    # that is absent, and a much smaller one: the protection works, the
    # window is just narrow.
    hsts = headers.get("strict-transport-security", "")
    if hsts:
        age = re.search(r"max-age\s*=\s*(\d+)", hsts, re.I)
        if age and int(age.group(1)) < 31536000:
            days = int(age.group(1)) // 86400
            findings.append(_finding_from(
                "hsts_short_max_age", response.url,
                f"Strict-Transport-Security: {hsts[:200]}\n\n"
                f"max-age is {age.group(1)} seconds (about {days} days). "
                f"One year (31536000) is what the preload list and most "
                f"baselines ask for.", "headers"))

    # A CSP that is present but permits what it exists to prevent is its own
    # finding — and a more interesting one than a missing header, because the
    # operator believes they are covered.
    policy = headers.get("content-security-policy", "")
    if policy:
        for key in analyse_csp(policy):
            findings.append(_finding_from(
                key, response.url,
                f"Content-Security-Policy: {policy[:500]}", "headers"))

    # ── framing, assessed once from everything that governs it ──────────
    #
    # frame-ancestors, X-Frame-Options and the Report-Only policy
    # together. default-src is not a fallback for frame-ancestors and
    # frame-src is a different directive, so a policy can be long,
    # strict-looking and still place no restriction on framing — which
    # is why this is parsed rather than pattern-matched.
    framing = csp_analysis.assess_framing(headers=headers)
    if framing.vulnerable:
        explanation = explanations.explain(
            "cross_site_framing", policy=framing, url=response.url)
        finding = _finding_from(
            "cross_site_framing", response.url,
            explanation.text() if explanation else seen_headers, "headers")
        finding.summary = explanation.text() if explanation else ""
        finding.status_label = "Confirmed"
        finding.impact_if_real = "MEDIUM"
        if explanation:
            finding.explanation = explanation.as_dict()
        finding.framing = framing.as_dict()
        findings.append(finding)
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


#: Words that mean a header is absent rather than merely mentioned.
_HEADER_ABSENT = re.compile(
    r"\b(missing|not (?:defined|present|set|sent)|absent|no\s+\w*\s*header)",
    re.I)


#: Path or wording → what the panel actually is. "Administrative login
#: panel publicly reachable" is true but makes the reader go and look;
#: naming the product says what it is, what the default accounts are and
#: which wordlist to point at it.
_PANEL_PRODUCTS = (
    ("wordpress", ("wp-login", "wp-admin", "wordpress")),
    ("Joomla", ("/administrator", "joomla")),
    ("Drupal", ("/user/login", "drupal")),
    ("phpMyAdmin", ("phpmyadmin", "/pma", "/pma2")),
    ("Tomcat Manager", ("/manager/html", "tomcat")),
    ("Jenkins", ("/jenkins", "jenkins")),
    ("cPanel", ("cpanel", ":2083")),
    ("Webmin", ("webmin", ":10000")),
    ("Magento", ("/admin_", "magento")),
)


def _panel_title(key, body):
    """A product-specific title for a login-panel finding, or ""."""
    if key not in ("login_panel_exposed", "admin_exposed"):
        return ""
    text = (body or "").lower()
    for product, needles in _PANEL_PRODUCTS:
        if any(needle in text for needle in needles):
            name = "WordPress" if product == "wordpress" else product
            return f"Publicly accessible {name} login panel"
    return ""


def _header_issue_from_nikto(body):
    """Map Nikto's missing-header sentences onto the library.

    Nikto writes these two ways round —

        + /: Suggested security header missing: referrer-policy
        + /: The X-Content-Type-Options header is not defined.

    — so rather than guess at the grammar, look for a header the library
    knows and a word that means it is absent. The library already rates
    referrer-policy and permissions-policy as Informational; without this
    join the generic fallback below read the word "missing" and called them
    Low, so the same finding came out at two different severities depending
    on which tool happened to notice it.
    """
    text = (body or "").lower()
    if not _HEADER_ABSENT.search(text):
        return "", None
    # Longest name first: x-content-type-options must win over any shorter
    # name that is a substring of it.
    for name in sorted(SECURITY_HEADERS, key=len, reverse=True):
        if name in text:
            key = SECURITY_HEADERS[name]
            return key, cb_issues.ISSUES.get(key)
    return "", None


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
        # --color 0 is not cosmetic. testssl decides on colour from the
        # TERM variable, not from whether its output is a terminal, so
        # under this application's QProcess it emits ANSI escapes and
        # writes them into --logfile and through tee into the .txt as
        # well. The saved reports came out as walls of ESC[1m, which is
        # what a tester opens when they want to paste a finding into a
        # report. The JSON was fine; the two human-readable files were
        # not. Asking for no colour at the source fixes all three
        # outputs, and _strip_ansi below catches any that still arrive.
        default = (
            f"if command -v testssl >/dev/null 2>&1; then "
            f"testssl --color 0 --logfile {log_path} --jsonfile {json_path} "
            f"{host} | tee {txt_path}; "
            f"elif command -v testssl.sh >/dev/null 2>&1; then "
            f"testssl.sh --color 0 --logfile {log_path} --jsonfile {json_path} "
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

        # Before anything is overwritten, say whether a previous run's
        # findings are sitting on disk for this target.
        self._cb_report_previous_run()

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
        # The console batches writes now; make sure the summary is
        # actually on screen rather than sitting in the buffer.
        try:
            self.console.flush()
        except Exception:                                   # noqa: BLE001
            pass
        self._cb_ui_call("_cb_ui_finished", "completed")
        # Synchronous, not debounced: the run is over and there may be no
        # further event loop turn in which a pending timer would fire.
        self._cb_autosave()
        if getattr(self, "_cb_findings", None):
            md_path, json_path = self._cb_autosave_paths()
            self.console.append_ansi(
                f"[*] Findings saved to:\n      {md_path}\n"
                f"      {json_path}\n")
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
        """The operator's custom headers, for Coffee Break's own requests.

        This read ``self.custom_headers_input``, which does not exist —
        the widget is ``headers_input``. Every call raised
        AttributeError into the bare ``except`` below and returned {},
        so Coffee Break made every request unauthenticated no matter
        what was in the box. Same root cause as the API tab's version of
        this bug: the header was collected and then quietly discarded.
        """
        from command_bridge.modules import header_injection
        try:
            text = self.headers_input.toPlainText()
        except Exception:                                   # noqa: BLE001
            return {}
        return dict(header_injection.parse(text))

    # ── not losing a run ─────────────────────────────────────────────────
    #
    # Reported after a run froze partway through a directory-fuzzing
    # stage: the application had to be killed, and forty-five minutes of
    # findings went with it, because the report was only ever written
    # when somebody clicked Export and chose a filename. Findings lived
    # in self._cb_findings and nowhere else.
    #
    # The freeze itself is fixed in widgets/console.py, but a crash, a
    # closed lid or a power cut would have cost the same, so the run is
    # now written to disk as it goes. The Markdown is the same text the
    # Export button produces, so it is immediately usable in a report.

    #: Rebuilding the whole report on every merged instance would be
    #: wasteful during a fuzzing stage that produces hundreds of
    #: sightings a second, so saves are debounced.
    _CB_AUTOSAVE_MS = 2000

    def _cb_autosave_paths(self):
        safe = self.sanitize_target_for_filename(self.target or "target")
        base = Path(self.output_dir)
        return (base / f"{safe}_coffee_break_findings.md",
                base / f"{safe}_coffee_break_findings.json")

    def _cb_schedule_autosave(self):
        timer = getattr(self, "_cb_autosave_timer", None)
        if timer is None:
            try:
                from PyQt6.QtWidgets import QApplication
                if QApplication.instance() is None:
                    # No event loop to run a timer, so nothing would ever
                    # fire it. Save now instead of warning and losing it.
                    self._cb_autosave()
                    return
                timer = QTimer(self) if isinstance(self, QObject) else QTimer()
                timer.setSingleShot(True)
                timer.setInterval(self._CB_AUTOSAVE_MS)
                timer.timeout.connect(self._cb_autosave)
            except Exception:                               # noqa: BLE001
                # No Qt event loop (a test harness, a headless run). Save
                # straight away rather than not at all — correctness of
                # the saved file matters more than the debounce.
                self._cb_autosave()
                return
            self._cb_autosave_timer = timer
        if not timer.isActive():
            timer.start()

    def _cb_autosave(self):
        """Write the run to disk. Never raises into the scan.

        Written to a temporary file and moved into place, so a kill
        halfway through a write leaves the previous good copy rather
        than a truncated one.
        """
        if not getattr(self, "_cb_findings", None):
            return
        md_path, json_path = self._cb_autosave_paths()
        try:
            report = self.coffee_break_report()
        except Exception:                                   # noqa: BLE001
            return
        for path, payload in ((md_path, report),
                              (json_path, self._cb_findings_json())):
            if payload is None:
                continue
            try:
                tmp = path.with_suffix(path.suffix + ".tmp")
                tmp.write_text(payload, encoding="utf-8", errors="replace")
                os.replace(tmp, path)
            except Exception as exc:                        # noqa: BLE001
                if not getattr(self, "_cb_autosave_warned", False):
                    self._cb_autosave_warned = True
                    try:
                        self.console.append_ansi(
                            f"    [!] could not autosave findings to "
                            f"{path.name}: {exc}\n")
                    except Exception:                       # noqa: BLE001
                        pass

    def _cb_findings_json(self):
        """The findings as JSON — the machine-readable half of the save."""
        rows = []
        for finding in self._cb_findings:
            try:
                rows.append({
                    "severity": finding.severity,
                    "title": finding.title,
                    "where": finding.where,
                    "state": finding.state,
                    "confidence": finding.confidence,
                    "stage": finding.stage,
                    "sources": list(finding.sources or []),
                    "key": finding.key,
                    "cwe": finding.cwe,
                    "scanner_severity": finding.scanner_severity,
                    # Provenance, so a corrected classification can be
                    # audited against what the scanner actually said.
                    "status": getattr(finding, "status_label", ""),
                    "detected_by": getattr(
                        getattr(finding, "proof", None), "detector", ""),
                    "template_id": getattr(
                        getattr(finding, "proof", None), "template_id", ""),
                    "template_name": getattr(
                        getattr(finding, "proof", None), "template_name", ""),
                    "detail": finding.detail,
                    "evidence": finding.evidence,
                    "remediation": finding.remediation,
                    "instances": list(finding.instances or []),
                    "references": list(finding.references or []),
                    "seen_at": finding.seen_at,
                })
            except Exception:                               # noqa: BLE001
                continue
        try:
            return json.dumps({
                "target": self.target,
                "started_at": getattr(self, "_cb_started_at", None),
                "saved_at": time.time(),
                "complete": not getattr(self, "_cb_active", False),
                "findings": rows,
            }, indent=2, default=str)
        except Exception:                                   # noqa: BLE001
            return None

    def _cb_report_previous_run(self):
        """Say so, at startup, if a previous run's findings are on disk.

        The findings table is not repopulated — that would mean rebuilding
        every evidence object from JSON, and a half-restored evidence
        chain is worse than none, because the whole point of this tool is
        that a finding carries its proof. What it does instead is make
        sure nobody re-runs a 45-minute scan without being told the
        results are already saved.
        """
        try:
            md_path, _ = self._cb_autosave_paths()
            if not md_path.is_file() or md_path.stat().st_size < 40:
                return
            age = time.time() - md_path.stat().st_mtime
            when = (f"{int(age // 3600)}h {int(age % 3600 // 60)}m ago"
                    if age >= 3600 else f"{int(age // 60)}m ago")
            self.console.append_ansi(
                f"[i] Findings from an earlier Coffee Break run on this "
                f"target were saved {when}:\n      {md_path}\n"
                f"    Starting a new run overwrites that file — copy it "
                f"first if you still need it.\n")
        except Exception:                                   # noqa: BLE001
            pass

    #: A header cannot be both absent and misconfigured. The left-hand
    #: key claims a header is MISSING; every key on the right is only ever
    #: produced by PARSING that header's value, so it is first-hand
    #: evidence that the header is there.
    #:
    #: Reported from an engagement: a target produced "CSP allows
    #: clickjacking", "CSP does not restrict object-src or base-uri",
    #: "CSP allows form hijacking" AND "Content-Security-Policy is
    #: missing" — four findings, the last contradicting the first three.
    #: probe_headers cannot do that on its own (it reports csp_missing
    #: only when the header is absent), so the "missing" one comes from a
    #: signature tool looking at a different response, or at the same one
    #: through a cache. Whichever it is, first-hand parsing of the header
    #: wins over a signature saying it is not there.
    _PRESENCE_CONFLICTS = {
        "csp_missing": ("csp_unsafe_script", "csp_clickjacking",
                        "csp_form_hijack", "csp_wildcard_source",
                        "csp_missing_object_base", "csp_report_only"),
        "hsts_missing": ("hsts_short_max_age",),
    }

    def _cb_presence_conflict(self, finding):
        """Does this finding contradict one we already have? ``(drop, why)``.

        Works in both directions, because the order the stages run in is
        not the order the evidence arrives in: a "missing" finding from
        nuclei can land before the header probe has parsed the header, or
        after it.
        """
        held = {existing.key for existing in self._cb_findings if existing.key}

        # Incoming says the header is missing, but we have parsed it.
        proofs = self._PRESENCE_CONFLICTS.get(finding.key)
        if proofs and held.intersection(proofs):
            witness = sorted(held.intersection(proofs))[0]
            return True, (f"the header was read and analysed by the header "
                          f"stage ({witness}), so it is present")

        # Incoming is a parse of the header; drop any held "missing".
        for missing_key, proofs in self._PRESENCE_CONFLICTS.items():
            if finding.key in proofs and missing_key in held:
                stale = [f for f in self._cb_findings if f.key == missing_key]
                self._cb_drop_quietly(stale)
                try:
                    self.console.append_ansi(
                        f"[i] dropped '{ISSUES[missing_key]['title']}' — the "
                        f"header was found and parsed, so it is not "
                        f"missing\n")
                except Exception:                           # noqa: BLE001
                    pass
        return False, ""

    def _cb_drop_quietly(self, findings):
        """Remove findings from the list and from the table.

        Prefers the UI's own _cb_drop, which also refreshes the filter,
        the tally and the detail pane — removing the finding from
        _cb_findings alone would leave its row on screen. Falls back to
        the list when the UI half is not present (a headless run).
        """
        findings = [f for f in (findings or [])]
        if not findings:
            return
        dropper = getattr(self, "_cb_drop", None)
        if callable(dropper):
            dropper(findings)
            return
        doomed = {id(f) for f in findings}
        self._cb_findings = [f for f in self._cb_findings
                             if id(f) not in doomed]

    # ── the validation pipeline ──────────────────────────────────────────
    #
    # A detector hit goes through the same six stages whichever scanner
    # raised it, and each stage is allowed to know only what the one
    # before it established:
    #
    #   1 raw detection     the scanner's line, kept verbatim
    #   2 normalisation     detector_registry.classify_* → Detection
    #   3 classification    the registry entry's own semantics
    #   4 evidence          what the detector did and did not show
    #   5 verification      verification.Verifier, when safe
    #   6 final rating      risk.assess — impact capped by confirmation
    #
    # Reporting is stage 7 and lives in cb_evidence.summary_html.

    def _cb_verifier(self):
        """The verifier for this run, built once.

        Uses the scan's own session factory, so verification requests
        carry the operator's custom headers and proxy setting and are
        subject to the same timeouts as everything else.
        """
        existing = getattr(self, "_cb_verifier_instance", None)
        if existing is not None:
            return existing

        def session_for(url):
            return _session({"url": url, "headers": self._cb_extra_headers()})

        verifier = verification.Verifier(
            session_for,
            report=lambda line: self.console.append_ansi(f"      {line}\n"),
            in_scope=self._cb_in_scope)
        self._cb_verifier_instance = verifier
        return verifier

    def _cb_in_scope(self, url):
        """Is this URL part of what we were asked to scan?

        Verification only ever re-requests a path a scanner already
        reported on the target, so this is a guard against a malformed
        path escaping to another host rather than a scope engine.
        """
        try:
            target_host = urllib.parse.urlparse(
                self._cb_target_url()).netloc.lower()
            candidate = urllib.parse.urlparse(url).netloc.lower()
        except Exception:                                   # noqa: BLE001
            return False
        return bool(candidate) and candidate == target_host

    def _cb_explanation_context(self, detection, outcome, detector):
        """What the explanation rules need, from what was established.

        One place, so a rule is never handed a value nobody read. Each
        entry below comes from the detection or from the verifier's own
        outcome — never from the detector's metadata, which is what a
        rule must not be allowed to describe as evidence.
        """
        verification = outcome.as_dict() if outcome is not None else {}
        confirmed = (outcome is not None
                     and outcome.status == detector_registry.CONFIRMED)
        catch_all = "catch-all" in ((outcome.reason if outcome else "") or "")
        extracted = [str(x) for x in (detection.extracted or ()) if x]
        name = detection.detector_name or ""

        if detector.observation == classification.HEADER_VALUE:
            value = ""
            for line in (outcome.evidence if outcome else []):
                prefix = f"{detector.header}:"
                if detector.header and str(line).strip().startswith(prefix):
                    value = str(line).split(":", 1)[1].strip()
                    break
            return {"header_name": detector.header,
                    "header_value": value or (extracted[0] if extracted
                                              else ""),
                    "present": bool(value or extracted),
                    "url": detection.url}

        if name == "shell_history":
            return {"path": detection.path or detection.url,
                    "http_status": verification.get("http_status") or 0,
                    "content_type": verification.get("content_type") or "",
                    "body_bytes": _bytes_in(
                        outcome.evidence if outcome else []),
                    "confirmed": confirmed, "catch_all": catch_all}

        if detector.issue_key in ("component_admin_exposed",
                                  "component_known_vulnerable"):
            return {"name": detector.component or detector.name,
                    "version": _version_in(
                        outcome.evidence if outcome else []),
                    "path": detection.path or detection.url,
                    "cves": detector.cves,
                    "reachable": (outcome is not None and outcome.status
                                  != detector_registry.INCONCLUSIVE)}

        if detector.issue_key == "sri_missing":
            return {"scripts": extracted, "url": detection.url}
        return {}

    def _cb_explain_detection(self, detection, outcome, issue_key):
        """The explanation rule for a verified detection, or None.

        Each rule is handed only what was actually established — the
        status code, the content type, the body size, the version that
        was read — so a rule cannot describe evidence that does not
        exist.
        """
        verification = outcome.as_dict()
        confirmed = outcome.status == detector_registry.CONFIRMED
        catch_all = "catch-all" in (outcome.reason or "")
        detector = detection.detector

        if detection.detector_name == "shell_history":
            return explanations.explain(
                "shell_history_exposed",
                path=detection.path or detection.url,
                http_status=verification.get("http_status") or 0,
                content_type=verification.get("content_type") or "",
                body_bytes=_bytes_in(outcome.evidence),
                confirmed=confirmed, catch_all=catch_all)

        if issue_key in ("component_admin_exposed",
                         "component_known_vulnerable"):
            return explanations.explain(
                issue_key, name=detector.component or detector.name,
                version=_version_in(outcome.evidence),
                path=detection.path or detection.url,
                cves=detector.cves,
                reachable=outcome.status != detector_registry.INCONCLUSIVE)

        if issue_key == "sri_missing":
            return explanations.explain(
                "sri_missing", scripts=detection.extracted,
                url=detection.url)
        return None

    def _cb_record_detection(self, detection, stage, raw="",
                             scanner_severity="", template_tags=(),
                             template_author=""):
        """Stages 4-6, then record. Returns 1 if reported, else 0."""
        detector = detection.detector
        detection.scanner_severity = (scanner_severity
                                      or detection.scanner_severity)

        outcome = self._cb_verifier().run(detection)
        detection.status = outcome.status

        # The decision engine. Stages 2-8 in one place, the same for
        # every scanner — see modules/classification.py. Its stage 3 is
        # the general rule that replaced a table of special cases: a
        # class needing a demonstrated behaviour cannot be carried by an
        # observation that is only a header value, a cipher, a path or a
        # banner, whatever the detector is named or tagged.
        decision = classification.decide(
            detection, outcome, issue_library=cb_issues.ISSUES,
            verified=outcome.verified,
            explanation_context=self._cb_explanation_context(
                detection, outcome, detector))

        issue_key = decision.issue_key
        library = cb_issues.ISSUES.get(issue_key, {}) if issue_key else {}
        reported, impact, note = (decision.severity, decision.impact_if_real,
                                  "; ".join(decision.notes))
        if decision.mismatch:
            self.console.append_ansi(
                f"    [i] {detection.scanner} '{detector.name}' was not "
                f"reported as {detector.issue_key}: {decision.mismatch}\n")

        # A confirmed file exposure is a different issue from the
        # signature that led to it, and the library has an entry for it.
        if outcome.status == detector_registry.CONFIRMED and \
                detection.detector_name == "shell_history":
            issue_key = "shell_history_exposed"
            library = cb_issues.ISSUES[issue_key]
            reported, impact, note = risk.assess(
                library["severity"], outcome.status,
                vuln_class=issue_key, verified=True)

        title = decision.title or library.get("title") or detector.name
        if detector.name and not decision.mismatch and \
                outcome.status != detector_registry.CONFIRMED:
            title = detector.name

        explanation = (decision.explanation
                       or self._cb_explain_detection(detection, outcome,
                                                     issue_key))

        evidence_lines = list(outcome.evidence)
        if detection.extracted:
            evidence_lines.append(
                "extracted by the scanner: "
                + ", ".join(str(x) for x in detection.extracted)[:300])
        if note:
            evidence_lines.append(note)

        proof = Evidence(
            target=self.target,
            url=detection.url or self._cb_target_url(),
            detector=detection.scanner,
            template_id=detection.detector_id,
            template_name=detector.name,
            template_severity=detection.scanner_severity,
            template_tags=list(template_tags or []),
            template_author=template_author,
            extracted=list(detection.extracted),
            raw=raw or detection.raw,
            observed=outcome.summary,
        )

        finding = CBFinding(
            severity=reported,
            title=title,
            where=detection.url or self._cb_target_url(),
            detail=library.get("detail", "") or detector.notes,
            evidence="\n".join(evidence_lines) or outcome.summary,
            remediation=library.get("remediation", ""),
            stage=stage.get("key", detection.scanner),
            sources=[stage.get("key", detection.scanner)],
            confidence=("firm" if outcome.status ==
                        detector_registry.CONFIRMED else "tentative"),
            cwe=detector.cwe or library.get("cwe", ""),
            references=list(detector.cves) + list(
                library.get("references", [])),
            key=issue_key,
            proof=proof,
            scanner_severity=detection.scanner_severity,
        )
        # The four fields the Findings section shows, settled here rather
        # than reconstructed by the renderer.
        finding.summary = (explanation.text() if explanation
                           else (decision.summary or outcome.summary))
        if explanation:
            finding.explanation = explanation.as_dict()
        finding.impact_if_real = impact
        finding.verification = outcome.as_dict()
        finding.detection = detection.as_dict()
        finding.decision = decision.as_dict()
        finding.status_label = decision.status_label
        # ONE source of truth for the status. These two lines used to sit
        # here in this order, so the engine's verdict was computed and
        # then overwritten by the raw verification status — which meant
        # the table could say "Inconclusive" while the exported JSON said
        # POTENTIAL for the same finding. The decision is what both read.
        finding.state = _state_for(decision.status)
        finding.confidence = ("firm" if decision.status ==
                              detector_registry.CONFIRMED else "tentative")

        self._cb_record(finding)
        return 1 if reported != "INFO" else 0

    def _cb_record(self, finding):
        """Keep a finding — or, if we already have this issue, another instance.

        The old behaviour was one row per sighting, which is how a scan of a
        site with two hundred pages produced two hundred rows saying the same
        thing. Burp consolidates by issue type and lists the affected locations
        underneath, and so does this now.
        """
        if finding.key and finding.key in self._cb_muted:
            return

        # Identification is identification, whichever header or template
        # noticed it. "Software identified in response headers:
        # server: cloudflare" and "Cloudflare detected via cf-ray
        # header" are one fact reported twice — the second row tells the
        # reader nothing the first did not.
        if self._cb_already_identified(finding):
            return

        if finding.key:
            drop, why = self._cb_presence_conflict(finding)
            if drop:
                try:
                    self.console.append_ansi(
                        f"[i] not reported — '{finding.title}' contradicts "
                        f"evidence already held: {why}\n")
                except Exception:                           # noqa: BLE001
                    pass
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
            if getattr(existing, "variant", "") != \
                    getattr(finding, "variant", ""):
                # Same key, different thing. SSLv3 is not TLS 1.0.
                same = False
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
                self._cb_schedule_autosave()
            return

        if not finding.sources and finding.stage:
            finding.sources = [finding.stage]
        self._cb_findings.append(finding)
        self._cb_ui_call("_cb_ui_finding", finding)
        self._cb_schedule_autosave()
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

    #: Keys that say "this host runs X" and nothing more. Several tools
    #: notice the same X by different means, and each used to produce
    #: its own row.
    _IDENTIFICATION_KEYS = frozenset({
        "software_disclosed", "infrastructure_disclosed",
        "version_disclosure", "technology_detected",
    })

    def _cb_already_identified(self, finding):
        """Is this product already reported as identified?

        Merges the duplicate into the finding that is already there,
        keeping its evidence as another instance, so nothing is lost —
        the second ROW is what goes, not the second observation.
        """
        if finding.key not in self._IDENTIFICATION_KEYS:
            return False
        text = " ".join([str(finding.title or ""),
                         str(finding.evidence or ""),
                         str(getattr(finding, "summary", "") or "")])
        products = set(cb_issues.infrastructure_in(text))
        if not products:
            return False
        for existing in self._cb_findings:
            if existing.key not in self._IDENTIFICATION_KEYS:
                continue
            seen = set(cb_issues.infrastructure_in(
                " ".join([str(existing.title or ""),
                          str(existing.evidence or ""),
                          str(getattr(existing, "summary", "") or "")])))
            if products & seen:
                existing.add_instance(finding.where, finding.evidence,
                                      finding.proof)
                # Keep the second observation visible even when the two
                # share a URL, because what differs is HOW it was seen —
                # a Server header and a cf-ray header are two sightings
                # of one fact, and dropping the wording loses the second
                # tool's contribution.
                if finding.evidence and \
                        finding.evidence not in (existing.evidence or ""):
                    existing.evidence = ((existing.evidence or "")
                                         + "\n" + finding.evidence).strip()
                for source in (finding.sources or []):
                    if source not in existing.sources:
                        existing.sources.append(source)
                return True
        # A DIFFERENT product is a different finding. These share an
        # issue key, so without a variant the ordinary same-key merge
        # would fold nginx into cloudflare.
        finding.variant = finding.variant or sorted(products)[0]
        return False

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
        """Every open port judged the way a tester judges it.

        This stage used to report only the services named in a short
        hand-written table, so the ordinary case — SSH on 22 with a
        version banner, FTP on 21, an admin console on 8080 — produced
        nothing at all. A chain of standard checks that runs the checks
        and reports nothing is worse than no chain, because the tester
        assumes it looked.

        modules/port_risk.py holds the judgement: which services are
        dangerous to expose and why, which are dangerous wherever they
        run, and what changes when the host is internet-facing.
        """
        produced = 0
        ports = self._cb_artifacts.setdefault("open_ports", [])
        public = self._cb_host_is_public(text)
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
            produced += self._cb_report_port(
                stage, line.strip(), port, proto, service, banner, public)
        if ports:
            self.console.append_ansi(f"    open: {', '.join(ports)}\n")
        produced += self._cb_nmap_inventory(stage, text, ports)
        return produced

    def _cb_host_is_public(self, text):
        """Is the scanned host reachable from the internet?

        True, False, or None when it cannot be decided — which is a
        real answer, and findings built on it say which assumption they
        made rather than quietly picking the flattering one.
        """
        # nmap prints the address it actually scanned, which is better
        # than resolving the name again here.
        for pattern in (r"Nmap scan report for \S+ \(([0-9a-fA-F.:]+)\)",
                        r"Nmap scan report for ([0-9a-fA-F.:]+)\s*$"):
            found = re.search(pattern, text or "", re.M)
            if found:
                verdict = port_risk.is_public_address(found.group(1))
                if verdict is not None:
                    return verdict
        # Failing that, whatever the target resolves to.
        try:
            import socket
            host = self.get_scanner_target()
            return port_risk.is_public_address(
                socket.gethostbyname(host)) if host else None
        except Exception:                                   # noqa: BLE001
            return None

    def _cb_report_port(self, stage, line, port, proto, service, banner,
                        public):
        """One open port: what it is, and what the version banner says."""
        produced = 0
        host = self.get_scanner_target()
        where = f"{host}:{port}"
        verdict = port_risk.assess(port, proto, service, banner, public)

        # A rating that rests on nmap guessing from the port number is
        # confirmed before it is stated. "Jenkins reachable from the
        # internet on 8080" at CRITICAL, from nothing but an open 8080,
        # is a finding that has to be withdrawn in front of a client.
        confirmation = None
        if port_risk.needs_confirmation(verdict):
            confirmation = self._cb_confirm_service(host, port, verdict)

        evidence = line
        if banner:
            evidence += f"\n\nVersion reported by the service: {banner}"
        if confirmation and confirmation.get("evidence"):
            evidence += "\n\n" + confirmation["evidence"]

        summary = [verdict.why]
        if banner:
            summary.append(
                f"nmap read a version from this service: {banner}. That is "
                f"reported separately as a version disclosure, and whether "
                f"the version is current is answered from the local version "
                f"catalogue — never guessed.")
        else:
            summary.append(
                "No version was returned by this service, so nothing here "
                "says which software or release it is running.")
        summary.extend(verdict.notes)
        if verdict.fix:
            summary.append(f"Recommended: {verdict.fix}")
        summary.append(
            "This finding is about EXPOSURE — the service answered on "
            "this port. It makes no claim about a vulnerability in the "
            "service itself.")

        severity = verdict.severity
        status = "Confirmed"
        title = verdict.title
        if confirmation is not None and not confirmation["confirmed"]:
            # The port is open — that much nmap established. WHAT is
            # listening on it is not, so the finding says so, is capped,
            # and names the check that would settle it.
            severity = port_risk.cap_unconfirmed(severity)
            status = "Potential"
            title = (f"Service on {port}/{proto} reported by nmap as "
                     f"{verdict.entry.name} — not confirmed")
            summary.insert(1, (
                f"THIS IDENTIFICATION IS NOT CONFIRMED. nmap named the "
                f"service from the port, and {confirmation['why']} So the "
                f"open port is established and the software on it is not. "
                f"Rated at {severity} rather than "
                f"{verdict.severity} for that reason.\n\n"
                f"To settle it: request the port directly and look at what "
                f"answers — a login page, a product name in the body or a "
                f"product header. If it is what nmap said, this is a "
                f"{verdict.severity} finding."))
        elif confirmation is not None:
            summary.insert(1, f"Confirmed by request: {confirmation['why']}")

        finding = self._cb_issue(
            verdict.issue_key, where, evidence, stage["key"],
            severity=severity, title=title,
            variant=f"{port}/{proto}")
        finding.summary = "\n\n".join(part for part in summary if part)
        finding.status_label = status
        finding.impact_if_real = verdict.severity
        self._cb_record(finding)
        produced += 1

        if verdict.has_version:
            produced += self._cb_report_version(stage, where, port, proto,
                                                service, banner)
        return produced

    #: What confirms each product, in the response to one GET. Matched
    #: case-insensitively against the status line, the headers and the
    #: first part of the body.
    _SERVICE_SIGNATURES = {
        "Jenkins": ("jenkins", "x-jenkins", "hudson"),
        "Management or admin interface": (
            "webmin", "portainer", "grafana", "kibana", "prometheus",
            "rabbitmq", "activemq", "glassfish", "weblogic", "vault",
            "nessus", "login", "sign in", "dashboard", "console"),
        "Docker API": ("docker", "api version", "\"apiversion\""),
        "Kubernetes API server": ("kubernetes", "forbidden", "apiversion"),
        "Kubelet API": ("kubelet", "node", "pods"),
        "Message broker": ("rabbitmq", "activemq", "mqtt", "kafka"),
        "IPMI / BMC": ("ipmi", "bmc", "idrac", "ilo", "supermicro"),
    }

    def _cb_confirm_service(self, host, port, verdict):
        """Ask the port what it is, once.

        Returns ``{"confirmed": bool, "why": str, "evidence": str}``.
        One request per scheme, no payload, nothing written — the same
        thing a tester does by hand before putting a service in a
        report.
        """
        name = verdict.entry.name if verdict.entry else ""
        signatures = self._SERVICE_SIGNATURES.get(name, ())
        attempts = []
        for scheme in ("https", "http"):
            url = f"{scheme}://{host}:{port}/"
            try:
                session = _session({"url": url,
                                    "headers": self._cb_extra_headers()})
                response = session.get(url, timeout=8, allow_redirects=False,
                                       verify=False)
            except Exception as exc:                        # noqa: BLE001
                attempts.append(f"{scheme}: no response ({exc.__class__.__name__})")
                continue
            body = (response.text or "")[:4000]
            haystack = " ".join([
                str(response.status_code),
                " ".join(f"{k}: {v}" for k, v in response.headers.items()),
                body]).lower()
            hit = next((token for token in signatures
                        if token in haystack), "")
            title = ""
            found = re.search(r"<title[^>]*>(.{0,120}?)</title>", body,
                              re.I | re.S)
            if found:
                title = " ".join(found.group(1).split())
            evidence = (f"Confirmation request: GET {url}\n"
                        f"  HTTP {response.status_code}"
                        + (f"\n  Title: {title}" if title else "")
                        + (f"\n  Server: {response.headers.get('Server')}"
                           if response.headers.get("Server") else ""))
            if hit:
                return {"confirmed": True,
                        "why": (f"GET {url} returned HTTP "
                                f"{response.status_code} and the response "
                                f"names it ('{hit}')"
                                + (f"; page title: {title}" if title else "")),
                        "evidence": evidence}
            attempts.append(
                f"{scheme}: HTTP {response.status_code}"
                + (f", title '{title}'" if title else "")
                + ", nothing identifying it")
        return {
            "confirmed": False,
            "why": ("a direct request did not find anything identifying it ("
                    + "; ".join(attempts) + ")." if attempts
                    else "no confirmation request could be made."),
            "evidence": ("Confirmation attempted:\n  "
                         + "\n  ".join(attempts) if attempts else ""),
        }

    def _cb_report_version(self, stage, where, port, proto, service, banner):
        """The version banner as its own finding, plus a catalogue check.

        Asked for explicitly: if SSH answers with "OpenSSH 8.9p1" the
        tool must say so, whether or not the release is old, because
        that string is what a CVE search starts from. Whether it IS old
        is a separate question, answered only from the local catalogue —
        and when the catalogue has nothing, the finding says that rather
        than repeating a scanner's idea of "current".
        """
        product, version = port_risk.product_in_banner(banner)
        verdict, detail, severity = "", "", "LOW"
        if product and version:
            try:
                verdict, detail = version_catalog.assess(product, version)
            except Exception:                               # noqa: BLE001
                verdict, detail = "unknown", ""
            if verdict == "outdated":
                severity = "MEDIUM"

        title = f"Service version disclosed — {service} on {port}/{proto}"
        if product and version:
            # Spelled as a person writes it: "OpenSSH 8.9p1", not
            # "openssh 8.9p1", which reads as a tool's internal key.
            title += f": {cb_issues.infrastructure_name(product)} {version}"

        parts = [
            f"The service on {port}/{proto} returns its software and "
            f"version before authentication:\n\n  {banner}",
        ]
        if verdict == "outdated":
            parts.append(f"The local version catalogue says this release is "
                         f"behind the current one. {detail}")
        elif verdict == "current":
            parts.append(f"The local version catalogue says this release is "
                         f"current. {detail}")
        elif product:
            parts.append(
                "The local version catalogue has nothing recorded for this "
                "product, so this finding does not say whether the release "
                "is current. Press 'Update version data' on the Target tab "
                "to fetch it. This tool does not repeat another scanner's "
                "idea of what the current version is.")
        else:
            parts.append(
                "This banner names software the version catalogue does not "
                "track, so no currency check was attempted. The string "
                "above is still what a CVE search starts from.")
        if product and version:
            try:
                links = version_catalog.links_for(product, version)
                if links:
                    parts.append("Where to check what this version is "
                                 "vulnerable to:\n"
                                 + "\n".join(f"  {url}" for url in
                                             list(links)[:4]))
            except Exception:                               # noqa: BLE001
                pass

        key = "outdated_software" if verdict == "outdated" \
            else "service_version_disclosed"
        finding = self._cb_issue(
            key, where, f"{banner}", stage["key"],
            severity=severity, title=title,
            variant=f"version-{port}/{proto}")
        finding.summary = "\n\n".join(parts)
        finding.status_label = "Confirmed"
        finding.impact_if_real = severity
        self._cb_record(finding)
        return 1

    def _cb_nmap_inventory(self, stage, text, ports):
        """The two findings a tester writes from an nmap table by hand.

        Neither comes from a single line, which is why neither existed:
        the parser looked at one line at a time and reported only the
        services the library names individually.

          * **Port count.** No single open port is a finding, but a host
            with eight of them is one. A tester flags that; the tool
            said nothing.
          * **What the software IS.** The version column named nginx,
            and the finding list did not mention it anywhere, because
            nginx is not in NMAP_SERVICES — it is not a risky service,
            it is the infrastructure. Recorded as an observation, not
            as a weakness.
        """
        produced = 0
        host = self.get_scanner_target()

        if len(ports) > cb_issues.EXCESSIVE_PORT_THRESHOLD:
            listing = "\n".join(f"  {entry}" for entry in ports)
            finding = self._cb_issue(
                "excessive_ports", host,
                f"{len(ports)} open ports were found on {host}:\n{listing}",
                stage["key"],
                title=(f"Potentially excessive open ports — "
                       f"{len(ports)} reachable on {host}"))
            finding.summary = (
                f"nmap found {len(ports)} listening services on {host}, "
                f"above the {cb_issues.EXCESSIVE_PORT_THRESHOLD} this "
                f"report treats as ordinary for one host.\n\n"
                f"Open ports:\n{listing}\n\n"
                f"This is a statement about the host's exposure, not about "
                f"any one service: each port is counted because it answered, "
                f"and whether a given service belongs here is a question for "
                f"whoever owns the host. Services that are risky in "
                f"themselves are reported separately above.")
            finding.status_label = "Confirmed"
            finding.impact_if_real = finding.severity
            self._cb_record(finding)
            produced += 1

        # Products named in the version column, gathered across the
        # whole table so one finding lists the stack.
        seen = {}
        for line in text.splitlines():
            match = re.match(
                r"^(\d+)/(tcp|udp)\s+open\s+(\S+)(?:\s+(.*))?$", line.strip())
            if not match:
                continue
            port, proto, _service, version = match.groups()
            for product in cb_issues.infrastructure_in(version or ""):
                seen.setdefault(product, []).append(
                    f"{port}/{proto}: {(version or '').strip()}")
        if seen:
            lines = []
            for product in sorted(seen):
                for entry in seen[product]:
                    lines.append(f"  {entry}")
            names = ", ".join(sorted(cb_issues.infrastructure_name(p)
                                     for p in seen))
            finding = self._cb_issue(
                "infrastructure_disclosed", host,
                "\n".join(lines), stage["key"],
                title=f"Underlying infrastructure identified: {names}")
            finding.summary = (
                f"The service banners on {host} name the software behind "
                f"it: {names}.\n\nAs reported by nmap:\n"
                + "\n".join(lines)
                + "\n\nThis is an observation, not a weakness — it is "
                  "recorded because it is what a reader needs to know the "
                  "stack, and what a CVE search starts from. Whether any "
                  "named version is out of date is a separate question this "
                  "finding does not answer.")
            finding.status_label = "Confirmed"
            finding.impact_if_real = finding.severity
            self._cb_record(finding)
            produced += 1
        return produced

    #: Every ANSI escape, not just the colour ones. testssl emits cursor
    #: moves and erase-line sequences during its progress display too,
    #: and a report with ESC[2K in it is no more readable than one with
    #: ESC[1m. ``\x1b\[[0-9;]*m`` — the pattern used elsewhere in this
    #: file — matches only the colour subset and leaves the rest.
    _ANSI = re.compile(r"\x1b(?:\[[0-9;?]*[ -/]*[@-~]|\][^\x07\x1b]*(?:\x07|\x1b\\)|[@-Z\\-_])")

    @classmethod
    def strip_ansi(cls, text):
        return cls._ANSI.sub("", text or "")

    def _cb_clean_testssl_reports(self, safe):
        """Rewrite the saved .log and .txt without escape sequences.

        ``--color 0`` on the command is the real fix, but it only helps
        the run that has it: a tester on an older testssl, or one who
        has edited the command by hand, still gets escape codes. These
        two files are the ones a human opens, so they are cleaned after
        the stage regardless of how the command was built. The JSON is
        left alone — it never had colour in it, and rewriting a file the
        parser depends on to fix a problem it does not have is how you
        acquire a new one.
        """
        for suffix in (".log", ".txt"):
            path = Path(self.output_dir) / f"{safe}_testssl{suffix}"
            try:
                if not path.is_file():
                    continue
                raw = path.read_text(errors="replace")
                clean = self.strip_ansi(raw)
                if clean != raw:
                    path.write_text(clean)
            except Exception as exc:                        # noqa: BLE001
                try:
                    self.console.append_ansi(
                        f"[i] could not clean {path.name}: {exc}\n")
                except Exception:                           # noqa: BLE001
                    pass

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
        try:
            self._cb_clean_testssl_reports(
                self.sanitize_target_for_filename(self.target))
        except Exception:                                   # noqa: BLE001
            pass

        records = self._cb_testssl_records(stage, text)
        # Read the cipher inventory out FIRST, so the findings built
        # below have the suites to work from, and clear the cache that
        # may have been filled before it was available.
        inventory = self._cb_testssl_cipher_inventory(records)
        if inventory:
            self._cb_testssl_inventory = inventory
            self._cb_tls_cache = {}
            self.console.append_ansi(
                f"    testssl enumerated "
                f"{sum(len(v) for v in inventory.values())} cipher suite(s) "
                f"across {len(inventory)} protocol version(s)\n")
        if not records:
            # Never silent. A TLS stage that ran and reported nothing is
            # either a clean host or a parser that read nothing, and the
            # operator is entitled to know which — the alternative is
            # finding SSLv3 by hand afterwards and wondering why the
            # tool missed it.
            artefact = stage.get("artefact_file") or ""
            ran = bool((text or "").strip())
            # The suites may still be available from the SSL/TLS
            # Analysis, in which case the cipher findings stand on their
            # own and this stage is not a dead loss.
            recovered = self._cb_tls_cipher_findings(stage)
            if recovered:
                self.console.append_ansi(
                    f"    testssl produced no readable checks, but "
                    f"{recovered} cipher issue(s) were established from "
                    f"the suites this host negotiated\n")
                return recovered
            if "not installed" in (text or ""):
                pass                      # the stage already said so
            elif not ran:
                self.console.append_ansi(
                    "[!] the TLS stage produced no output at all — no TLS "
                    "findings were assessed for this host.\n")
            else:
                self.console.append_ansi(
                    f"[!] testssl ran but no TLS checks could be read from "
                    f"its output, so NO TLS findings were assessed. This is "
                    f"not the same as a clean result.\n"
                    f"    JSON report: {artefact or 'none written'}"
                    f"{'' if artefact and Path(artefact).is_file() else ' (missing)'}\n"
                    f"    Run the SSL/TLS Analysis button in the Web tab "
                    f"against this host before concluding its TLS "
                    f"configuration is sound.\n")
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
            # One finding per obsolete protocol version, not one merged
            # row for all of them. SSLv3 and TLS 1.0 are not the same
            # finding and are not the same severity; merging them rated
            # SSLv3 at the library's MEDIUM and buried the version that
            # mattered inside a comma-separated title.
            bucket_key = key
            version = ""
            if key == "obsolete_protocol":
                version = cb_issues.obsolete_protocol_version(identifier)
                if version:
                    bucket_key = f"{key}::{version}"
                    severity = cb_issues.OBSOLETE_PROTOCOL_SEVERITY.get(
                        version, severity)

            bucket = grouped.setdefault(bucket_key,
                                        {"severity": severity, "lines": [],
                                         "cves": [], "key": key,
                                         "version": version})
            # The WORST of the records in the bucket, not the last one
            # read. This line used to be a plain assignment, so for
            # tls_generic — the one key that takes the tool's own rating
            # — whichever record happened to come last set the severity
            # of the whole group. That is how a bucket holding a
            # certificate date, an empty header list and a letter grade
            # came out CRITICAL.
            bucket["severity"] = cb_issues.worst(bucket["severity"],
                                                 severity)
            if key == "tls_generic":
                # A check that maps to no named attack cannot carry a
                # High or Critical rating on its own. It has no attack,
                # no CVE and no demonstrated impact — only testssl's
                # wording, which is in the evidence for the reader to
                # judge. Capped here rather than in the library because
                # tls_generic is deliberately tool-rated.
                bucket["severity"] = {"CRITICAL": "MEDIUM",
                                      "HIGH": "MEDIUM"}.get(
                    bucket["severity"], bucket["severity"])
            entry = f"{identifier}: {line}" if identifier else line
            if entry not in bucket["lines"]:
                bucket["lines"].append(entry)
            for cve in str(record.get("cve", "")).split():
                if cve and cve not in bucket["cves"]:
                    bucket["cves"].append(cve)

        produced = 0
        host = self.get_scanner_target()
        for bucket_key, bucket in grouped.items():
            key = bucket.get("key") or bucket_key
            evidence = "\n".join(bucket["lines"][:14])
            if len(bucket["lines"]) > 14:
                evidence += f"\n… and {len(bucket['lines']) - 14} more"

            # A CBC finding whose whole proof is testssl's sentence
            # ("LUCKY13: potentially vulnerable, uses obsolete TLS CBC
            # ciphers") cannot be written up: the report has to name the
            # suites. testssl only puts per-suite detail in its JSON when
            # run with --show-each or the cipher-enumeration flags, which
            # this invocation does not use, so that detail was never
            # available to attach however the parser was written.
            #
            # So ask the server. One handshake per CBC suite, nothing
            # sent after it, and only a suite that was NEGOTIATED is
            # listed — see modules/cbc_suites.py.
            # An explanation first — what this check found, which
            # property makes it a weakness, the exact suites, and what
            # the evidence does not establish — then the structured
            # listing, then the scanner's own line. See
            # modules/explanations.py.
            explanation = self._cb_explain_tls(key)
            listing = "" if explanation else self._cb_tls_evidence(key)
            if explanation:
                evidence = (explanation.text()
                            + "\n\nAs reported by the scanner:\n"
                            + evidence)
            elif listing:
                evidence = (listing + "\n\nAs reported by the scanner:\n"
                            + evidence)
            detail = ISSUES[key]["detail"]
            title = None
            if key == "obsolete_protocol":
                # Name the version in the title. "Obsolete TLS protocol
                # version enabled" is the first thing anyone asks a
                # follow-up question about, and a HIGH row that does not
                # say SSLv3 is a HIGH row that has to be investigated by
                # hand — which is exactly what happened.
                pretty = cb_issues.OBSOLETE_PROTOCOL_NAMES
                version = bucket.get("version") or ""
                if version in pretty:
                    broken = version in ("sslv2", "sslv3")
                    title = (f"{pretty[version]} enabled"
                             + (" — broken protocol" if broken
                                else " — deprecated protocol"))
                else:
                    versions = [pretty[v] for v in
                                sorted({line.split(":")[0].strip().lower()
                                        for line in bucket["lines"]})
                                if v in pretty]
                    if versions:
                        title = (f"Obsolete TLS protocol version"
                                 f"{'s' if len(versions) > 1 else ''} "
                                 f"enabled: {', '.join(versions)}")
            if key == "tls_generic":
                # The title has to name them too. "TLS configuration
                # weakness" at the top of a finding, with three raw
                # record lines under it, is a row a tester has to
                # investigate by hand to learn what it is about.
                named = sorted({line.split(":")[0].strip()
                                for line in bucket["lines"] if line})[:3]
                if named:
                    extra = len({line.split(":")[0] for line in
                                 bucket["lines"]}) - len(named)
                    title = ("Unclassified TLS configuration checks: "
                             + ", ".join(named)
                             + (f" (+{extra} more)" if extra > 0 else ""))
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
                                     detail=detail, title=title,
                                     variant=bucket.get("version") or "")
            for cve in bucket["cves"]:
                if cve not in finding.references:
                    finding.references.append(cve)

            # What is confirmed and what is not, kept apart.
            #
            # Lucky 13, BEAST, Sweet32 and ROBOT are all named ATTACKS
            # whose precondition is a cipher or protocol being offered.
            # The precondition is what has been established — the suites
            # above are the evidence for it — and the attack itself has
            # not been attempted: no timing measurements were taken and
            # no padding oracle was exercised. Reporting these as
            # "Confirmed" claims the second from evidence for the first.
            #
            # The suites are preserved either way, which is the point:
            # the status changes, the evidence does not.
            listing_present = bool(listing)
            if explanation:
                # The rule already states the limitation in its own
                # terms; repeating the generic one underneath reads as
                # two different qualifications of the same thing.
                finding.explanation = explanation.as_dict()
            if key in self._TLS_PRECONDITION_ONLY:
                finding.status_label = "Potential"
                finding.state = cb_evidence.POTENTIAL
                finding.confidence = "tentative"
                finding.impact_if_real = bucket["severity"]
                # The rule already states the limitation in its own
                # terms, so the generic sentence below is only used when
                # there is no rule for this check. Appending both put
                # two near-identical qualifications under one finding.
                if explanation:
                    finding.summary = explanation.text()
                else:
                    finding.summary = (
                        ((listing + "\n\n") if listing_present else "")
                        + "The configuration this attack needs is present "
                          "and confirmed. The attack itself was not "
                          "attempted — no timing measurements were taken — "
                          "so whether this host is exploitable is "
                          "unestablished.")
            else:
                finding.status_label = "Confirmed"
                finding.impact_if_real = bucket["severity"]
                finding.summary = (explanation.text() if explanation
                                   else (listing or evidence))

            self._cb_record(finding)
            produced += 1

        # Whatever testssl did or did not emit a record for, the suites
        # the host negotiated are their own evidence. This fills the
        # gaps — a run whose JSON held only the rating section used to
        # produce no Sweet32, BEAST or CBC finding at all — and never
        # touches a key already reported above.
        from_ciphers = self._cb_tls_cipher_findings(stage)
        produced += from_ciphers

        self.console.append_ansi(
            f"    {len(records)} TLS check(s) read; {produced} issue(s) worth "
            f"reporting"
            + (f" ({from_ciphers} from the negotiated cipher suites)"
               if from_ciphers else "") + "\n")
        return produced

    # ── TLS evidence: reuse the SSL/TLS Analysis, do not re-scan ─────────
    #
    # The suites, their key sizes and the protocol versions were already
    # being discovered by modules/ssl_cipher_check.py — the standalone
    # SSL/TLS Analysis button — and then printed to a terminal and
    # discarded. That is why a Lucky 13 finding on the Findings screen
    # could only ever carry testssl's one-line sentence: the structured
    # data existed in the application and never reached the finding.
    #
    # So that module now writes its results as JSON as well as text, and
    # this reads them. In order of preference:
    #
    #   1. the JSON artefact from an SSL/TLS Analysis already run for
    #      this target — no second scan, which is the point
    #   2. that module run once, in-process, if sslyze is importable
    #   3. a direct handshake enumeration (modules/cbc_suites.py), which
    #      needs no sslyze but only knows about CBC suites
    #
    # Everything is cached per run and keyed by host and port, so
    # repeated scans cannot mix one target's ciphers into another's
    # finding.

    #: registry of library key → the vulnerability name ssl_cipher_check
    #: uses, so every TLS finding gets its own structured evidence rather
    #: than only Lucky 13.
    #: Findings named after an ATTACK whose precondition is a cipher or
    #: protocol being offered. The precondition is confirmed; the attack
    #: is not, and the two must not be reported as one.
    _TLS_PRECONDITION_ONLY = frozenset({
        "lucky13", "beast", "sweet32", "robot", "crime", "breach",
        "logjam", "freak", "drown", "poodle",
    })

    _TLS_EVIDENCE_FOR = {
        "lucky13": "Lucky13",
        "sweet32": "Sweet32",
        "rc4": "RC4",
        "robot": "ROBOT (static RSA)",
        "freak": "EXPORT / FREAK",
        "null_cipher": "NULL encryption",
        "anonymous_cipher": "Anonymous (no server auth)",
        "weak_cipher": "",            # handled as "every weak suite"
    }

    def _cb_tls_host_port(self):
        parsed = urllib.parse.urlparse(self._cb_target_url())
        return (self.get_scanner_target(), parsed.port or 443)

    def _cb_tls_structured(self):
        """The SSL/TLS Analysis results as structure, or {}.

        Cached, and the cache key includes the host and port so a second
        target in the same session cannot inherit the first's ciphers.
        """
        host, port = self._cb_tls_host_port()
        cache = getattr(self, "_cb_tls_cache", None)
        if cache is None:
            cache = self._cb_tls_cache = {}
        if (host, port) in cache:
            return cache[(host, port)]

        # testssl's own cipher inventory comes BEFORE sslyze and the
        # handshake fallback: it is already in hand, it cost no extra
        # traffic, and it is the enumeration of the host that was
        # actually scanned. It also removes the dependency that made the
        # cipher and protocol findings fail silently when no SSL/TLS
        # Analysis had been run for the host.
        data = self._cb_tls_from_artefact(host, port) or \
            self._cb_tls_from_testssl(host, port) or \
            self._cb_tls_from_sslyze(host, port) or \
            self._cb_tls_from_handshakes(host, port)
        cache[(host, port)] = data or {}
        return cache[(host, port)]

    #: testssl's per-suite inventory records. The id carries the
    #: protocol and the hex code; the finding carries the suite itself:
    #:
    #:   cipher-tls1_2_xc009: TLSv1.2 xc009 ECDHE-ECDSA-AES128-SHA
    #:                        ECDH 253 AES 128
    #:                        TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA
    #:
    #: These were being reported AS A FINDING — twelve of them under one
    #: "TLS configuration weakness" at MEDIUM, with no statement of what
    #: was wrong. They are an inventory: the list of what the host
    #: offers. Which is exactly the data the cipher findings need, so
    #: they are read into the suite enumeration instead of thrown at the
    #: reader.
    _TESTSSL_CIPHER_RECORD = re.compile(r"^cipher[-_](?P<proto>[a-z0-9_]+)_x",
                                        re.I)

    def _cb_testssl_cipher_inventory(self, records):
        """``{protocol: [{"name", "bits"}]}`` from testssl's cipher records."""
        inventory = {}
        for record in records or []:
            identifier = str(record.get("id", "") or "")
            if not self._TESTSSL_CIPHER_RECORD.match(identifier):
                continue
            text = str(record.get("finding", "") or "")
            tokens = text.split()
            if not tokens:
                continue
            # The IANA name is the token that looks like one. testssl
            # prints it last, but reading it by SHAPE rather than by
            # position survives a column being absent.
            iana = next((t for t in reversed(tokens)
                         if t.startswith(("TLS_", "SSL_"))), "")
            if not iana:
                continue
            protocol = tokens[0] if tokens[0].upper().startswith(
                ("TLS", "SSL")) else ""
            if not protocol:
                protocol = str(record.get("protocol", "")
                               or identifier.split("_x")[0].split("-")[-1])
            # The symmetric key size is the last bare integer before the
            # IANA name — "AES 128" — not the curve size that precedes
            # it ("ECDH 253").
            bits = 0
            for token in tokens[:tokens.index(iana)]:
                if token.isdigit():
                    bits = int(token)
            inventory.setdefault(protocol, [])
            if all(entry["name"] != iana for entry in inventory[protocol]):
                inventory[protocol].append({"name": iana, "bits": bits})
        return inventory

    def _cb_tls_from_testssl(self, host, port):
        """The suite enumeration testssl already produced, if it did."""
        inventory = getattr(self, "_cb_testssl_inventory", None) or {}
        if not inventory:
            return {}
        deprecated = {}
        for protocol in inventory:
            if cb_issues.protocol_token(protocol):
                deprecated[protocol] = {}
        return {
            "tool": "testssl",
            "host": host,
            "port": port,
            "protocols": inventory,
            "deprecated_protocols": deprecated,
            "suite_count": sum(len(v) for v in inventory.values()),
        }

    def _cb_tls_from_artefact(self, host, port):
        """An SSL/TLS Analysis already run for this target."""
        safe = self.sanitize_target_for_filename(self.target)
        path = Path(self.output_dir) / f"{safe}_ssl_ciphers.json"
        try:
            if not path.is_file():
                return {}
            data = json.loads(path.read_text(errors="replace"))
        except Exception as exc:                            # noqa: BLE001
            self.console.append_ansi(
                f"    [i] could not read {path.name}: {exc}\n")
            return {}
        if not isinstance(data, dict) or not data.get("protocols"):
            return {}
        # Belt and braces against mixing targets: the file says which
        # host it was produced for, and a mismatch is not usable evidence
        # however convenient it would be.
        if str(data.get("host", "")).lower() not in ("", host.lower()):
            self.console.append_ansi(
                f"    [i] {path.name} was produced for "
                f"{data.get('host')}, not {host} — not using it\n")
            return {}
        self.console.append_ansi(
            f"    reusing the SSL/TLS Analysis results for {host}:{port} "
            f"({data.get('suite_count', 0)} cipher suites)\n")
        return data

    def _cb_tls_from_sslyze(self, host, port):
        """Run the standalone module's own scan once, in-process.

        Only while a Coffee Break run is actually in progress. Parsing a
        saved report is not a reason to open connections to a host: the
        parser is called when re-reading artefacts, from tests, and from
        the report writer, and a full cipher enumeration fired from any
        of those is exactly the unnecessary duplicate scan this reuse
        was meant to avoid. Outside a live run the cheaper fallbacks
        apply, or the finding keeps the scanner's own line.
        """
        if not getattr(self, "_cb_active", False):
            return {}
        try:
            from command_bridge.modules import ssl_cipher_check as scc
        except Exception:                                   # noqa: BLE001
            return {}
        try:
            import sslyze                                   # noqa: F401
        except Exception:                                   # noqa: BLE001
            return {}
        try:
            self.console.append_ansi(
                f"    running the SSL/TLS cipher analysis for "
                f"{host}:{port}\n")
            result = scc.scan_full(host, port)
            if result is None:
                return {}
            accepted = scc.get_accepted_ciphers(result)
            flat = scc.all_ciphers_flat(accepted)
            data = scc.structured_result(host, port, accepted, flat)
            # Leave the artefact behind so the next stage, and the
            # standalone button, do not repeat the work.
            safe = self.sanitize_target_for_filename(self.target)
            scc.write_structured(
                str(Path(self.output_dir) / f"{safe}_ssl_ciphers.json"),
                host, port, accepted, flat)
            return data
        except Exception as exc:                            # noqa: BLE001
            self.console.append_ansi(
                f"    [i] the cipher analysis did not complete: {exc}\n")
            return {}

    def _cb_tls_from_handshakes(self, host, port):
        """Last resort: ask the server directly, one CBC suite at a time.

        Gated the same way and for the same reason — it opens one
        connection per suite, which is not something a parser should do
        when nobody asked for a scan.

        Needs no sslyze. Only knows about CBC suites, so it populates
        Lucky 13 and nothing else — which is better than a finding with
        no evidence in it, and is reported as the narrower source it is.
        """
        if not getattr(self, "_cb_active", False):
            return {}
        try:
            from command_bridge.modules import cbc_suites
            suites = cbc_suites.offered(host, port)
        except Exception:                                   # noqa: BLE001
            return {}
        if not suites:
            return {}
        self.console.append_ansi(
            f"    sslyze is not available — enumerated {len(suites)} CBC "
            f"suite(s) by handshake instead\n")
        return {
            "tool": "cbc_suites",
            "host": host,
            "port": port,
            "protocols": {},
            "deprecated_protocols": {},
            "suite_count": len(suites),
            "vulnerabilities": {
                "Lucky13": {
                    "name": "Lucky13",
                    "description": "Timing side-channel on CBC-mode HMAC "
                                   "padding — CVE-2013-0169",
                    "suites": [{"name": name, "bits": bits}
                               for name, bits, _ in suites],
                },
            },
        }

    def _cb_tls_suites(self):
        """Every accepted suite, parsed into its properties.

        One list for the whole run, from the structured SSL/TLS Analysis
        results. The per-check findings then select from it by the
        property each check is about — which is how a Lucky 13 finding
        lists CBC suites rather than every suite the scan returned.
        """
        data = self._cb_tls_structured()
        if not data:
            return []
        rows, seen = [], set()
        for suites in (data.get("protocols") or {}).values():
            for suite in suites:
                name = suite.get("name") if isinstance(suite, dict) else suite
                if name and name not in seen:
                    seen.add(name)
                    rows.append(suite)
        if not rows:
            # The handshake fallback records suites only under the
            # vulnerability it enumerated them for.
            for entry in (data.get("vulnerabilities") or {}).values():
                for suite in entry.get("suites") or []:
                    name = suite.get("name")
                    if name and name not in seen:
                        seen.add(name)
                        rows.append(suite)
        return cipher_properties.parse_all(rows)

    #: Which cipher weakness establishes which named issue, and which
    #: suites a finding for it must list. Driven by the PROPERTIES of
    #: the suites the host actually negotiated, parsed from their names
    #: — not by searching testssl's prose.
    _CIPHER_ISSUES = (
        ("sweet32", (cipher_properties.TRIPLE_DES, cipher_properties.DES),
         "64-bit block cipher suites"),
        ("lucky13", (cipher_properties.CBC_MODE,),
         "CBC-mode cipher suites"),
        ("rc4", (cipher_properties.RC4,), "RC4 cipher suites"),
        ("weak_cipher", (cipher_properties.NULL_CIPHER,
                         cipher_properties.EXPORT_GRADE,
                         cipher_properties.ANONYMOUS,
                         cipher_properties.SMALL_KEY), "weak cipher suites"),
    )

    def _cb_tls_protocol_findings(self, stage, data, host, where):
        """Obsolete protocol findings from the versions actually accepted.

        The enumeration already knows which versions the host
        negotiated; it was only ever being used for the explanation
        text. So a host offering TLS 1.0 and 1.1 with no corresponding
        testssl record produced no finding — the same dependency that
        hid Sweet32 and BEAST.

        One finding per version, rated by version, and never a duplicate
        of one the testssl records already produced.
        """
        if not data:
            return 0

        labels = list((data.get("deprecated_protocols") or {}).keys()) + \
            list((data.get("protocols") or {}).keys())
        offered = {}
        for label in labels:
            token = cb_issues.protocol_token(label)
            if token:
                offered.setdefault(token, label)
        if not offered:
            return 0

        reported = {getattr(f, "variant", "") for f in self._cb_findings
                    if f.key == "obsolete_protocol"}
        produced = 0
        for token, label in sorted(offered.items()):
            if token in reported:
                continue
            pretty = cb_issues.OBSOLETE_PROTOCOL_NAMES.get(token, label)
            broken = token in ("sslv2", "sslv3")
            suites = (data.get("protocols") or {}).get(label) or []
            names = [s.get("name") if isinstance(s, dict) else str(s)
                     for s in suites]
            evidence = (
                f"{pretty} was negotiated by {where}."
                + (f"\n\nSuites accepted over {pretty}:\n"
                   + "\n".join(f"  {n}" for n in names if n)
                   if names else ""))
            finding = self._cb_issue(
                "obsolete_protocol", host, evidence,
                stage.get("key", "testssl"),
                severity=cb_issues.OBSOLETE_PROTOCOL_SEVERITY.get(
                    token, "MEDIUM"),
                title=(f"{pretty} enabled — "
                       + ("broken protocol" if broken
                          else "deprecated protocol")),
                variant=token)
            explanation = explanations.explain(
                "obsolete_protocol", versions=[pretty], host=where,
                suites_by_version={pretty: names})
            finding.summary = (explanation.text() if explanation
                               else evidence)
            if explanation:
                finding.explanation = explanation.as_dict()
            # The version being offered IS the finding — it was
            # negotiated, not inferred.
            finding.status_label = "Confirmed"
            finding.impact_if_real = finding.severity
            self._cb_record(finding)
            produced += 1
        return produced

    def _cb_tls_cipher_findings(self, stage):
        """Findings from the suites the host offered, with the suites listed.

        Why this exists. The cipher findings used to depend entirely on
        testssl emitting its own SWEET32 / BEAST / LUCKY13 records. On a
        run whose JSON held only the rating section, those records were
        absent — so a host offering 3DES and CBC suites produced no
        Sweet32 finding, no BEAST finding and no CBC finding, and the
        report said nothing about any of them.

        The suites themselves are the better evidence anyway: they are
        what goes in the write-up. So each weakness is established from
        the parsed properties of the suites that were actually
        negotiated, and the finding carries them one per line, ready to
        paste.

        Nothing here overrides a finding testssl already produced — a
        key already reported is left alone, so this adds, never replaces.
        """
        host, port = self._cb_tls_host_port()
        where = f"{host}:{port}"
        data = self._cb_tls_structured()
        produced = 0

        # Protocol versions first, and from the same source as the
        # suites. These had the same dependency the cipher findings had:
        # no testssl SSLv3/TLS1 record meant no finding, whatever the
        # host actually negotiated — so a host offering TLS 1.0 and 1.1
        # was reported as having neither.
        produced += self._cb_tls_protocol_findings(stage, data, host, where)

        suites = self._cb_tls_suites()
        if not suites:
            return produced

        already = {f.key for f in self._cb_findings if f.key}

        for key, weaknesses, label in self._CIPHER_ISSUES:
            if key in already:
                continue
            affected = []
            for weakness in weaknesses:
                for suite in cipher_properties.with_weakness(suites, weakness):
                    if suite not in affected:
                        affected.append(suite)
            if not affected:
                continue
            listing = cipher_properties.listing(affected)
            explanation = explanations.explain(key, suites=affected,
                                               host=where)
            evidence = (
                f"{len(affected)} {label} were negotiated by "
                f"{where}:\n{listing}")
            finding = self._cb_issue(
                key, host, evidence, stage.get("key", "testssl"),
                severity=cb_issues.severity_for(key))
            finding.summary = (explanation.text() if explanation
                               else evidence)
            if explanation:
                finding.explanation = explanation.as_dict()
            # The precondition is established — these suites were
            # negotiated. The attack was not attempted.
            if key in self._TLS_PRECONDITION_ONLY:
                finding.status_label = "Potential"
                finding.state = cb_evidence.POTENTIAL
                finding.confidence = "tentative"
            else:
                finding.status_label = "Confirmed"
            finding.impact_if_real = finding.severity
            self._cb_record(finding)
            produced += 1

        # BEAST needs a CBC suite AND TLS 1.0, so it is decided here
        # rather than from a weakness alone.
        if "beast" not in {f.key for f in self._cb_findings if f.key}:
            cbc = cipher_properties.with_weakness(
                suites, cipher_properties.CBC_MODE)
            protocols = {str(p).lower().replace(".", "").replace(" ", "")
                         for p in (data.get("protocols") or {})}
            tls10 = any(p in ("tls10", "tlsv10", "tls1", "tlsv1")
                        for p in protocols)
            if cbc and tls10:
                listing = cipher_properties.listing(cbc)
                explanation = explanations.explain("beast", suites=cbc,
                                                   host=where)
                finding = self._cb_issue(
                    "beast", host,
                    f"TLS 1.0 is offered and {len(cbc)} CBC-mode suites "
                    f"were negotiated by {where}:\n{listing}",
                    stage.get("key", "testssl"),
                    severity=cb_issues.severity_for("beast"))
                finding.summary = (explanation.text() if explanation
                                   else finding.evidence)
                if explanation:
                    finding.explanation = explanation.as_dict()
                finding.status_label = "Potential"
                finding.state = cb_evidence.POTENTIAL
                finding.confidence = "tentative"
                finding.impact_if_real = finding.severity
                self._cb_record(finding)
                produced += 1

        return produced

    def _cb_explain_tls(self, key):
        """The explanation rule for one TLS check, or None.

        Driven by the suites the check's own property selects. Nothing is
        derived from searching every suite name for a substring.
        """
        suites = self._cb_tls_suites()
        host, port = self._cb_tls_host_port()
        where = f"{host}:{port}"
        data = self._cb_tls_structured()

        if key == "obsolete_protocol":
            versions = sorted((data.get("deprecated_protocols") or {}).keys())
            return explanations.explain(
                key, versions=versions, host=where,
                suites_by_version=data.get("protocols") or {})
        if not suites:
            return None
        return explanations.explain(key, suites=suites, host=where)

    def _cb_tls_evidence(self, key):
        """Structured evidence for one TLS finding, or "".

        Returns the suite names and key sizes, one per line, exactly as
        the SSL/TLS Analysis reports them — which is what a report needs
        and what a generic description cannot provide.
        """
        data = self._cb_tls_structured()
        if not data:
            return ""
        host, port = self._cb_tls_host_port()
        name = self._TLS_EVIDENCE_FOR.get(key)

        if key == "obsolete_protocol":
            rows = data.get("deprecated_protocols") or {}
            if not rows:
                return ""
            lines = [f"Deprecated protocol versions accepted by "
                     f"{host}:{port}:"]
            for version, detail in sorted(rows.items()):
                lines.append(f"  {version}  —  {detail.get('reason', '')}")
                suites = (data.get("protocols") or {}).get(version) or []
                for suite in suites[:8]:
                    lines.append(f"      {suite['name']}  "
                                 f"{suite.get('bits') or ''}".rstrip())
            return "\n".join(lines)

        if name:
            entry = (data.get("vulnerabilities") or {}).get(name)
            if not entry or not entry.get("suites"):
                return ""
            suites = entry["suites"]
            width = max(len(s["name"]) for s in suites)
            lines = [f"{len(suites)} cipher suite(s) accepted by "
                     f"{host}:{port} match this:"]
            for suite in suites:
                bits = suite.get("bits")
                lines.append(f"  {suite['name'].ljust(width)}"
                             + (f"  {bits}" if bits else ""))
            return "\n".join(lines)

        if key == "weak_cipher":
            protocols = data.get("protocols") or {}
            if not protocols:
                return ""
            lines = [f"Cipher suites accepted by {host}:{port}:"]
            for version in ("SSL 2.0", "SSL 3.0", "TLS 1.0", "TLS 1.1",
                            "TLS 1.2", "TLS 1.3"):
                suites = protocols.get(version) or []
                if not suites:
                    continue
                lines.append(f"  {version}")
                for suite in suites[:12]:
                    bits = suite.get("bits")
                    lines.append(f"      {suite['name']}"
                                 + (f"  {bits}" if bits else ""))
                if len(suites) > 12:
                    lines.append(f"      … and {len(suites) - 12} more")
            return "\n".join(lines)
        return ""

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

        return self._cb_testssl_from_console(text)

    #: Verdicts in testssl's console output that mean "this is a problem".
    #: Matched case-insensitively against the right-hand side of a line.
    _TESTSSL_BAD = (
        "vulnerable", "not ok", "offered (deprecated)", "insecure",
        "weak", "uses 64 bit block ciphers", "no fs", "expired",
        "self signed", "self-signed", "mismatch", "untrusted",
    )
    #: And the ones that mean the opposite, checked FIRST — "not
    #: vulnerable (OK)" contains "vulnerable".
    _TESTSSL_GOOD = (
        "(ok)", "not offered", "not vulnerable", "no rc4", "ok --",
        "not susceptible", "none", "no (ok)",
    )

    def _cb_testssl_from_console(self, text):
        """Rebuild records from testssl's console output.

        This is the fallback for a run that wrote no JSON — testssl not
        having the --jsonfile support, a permissions problem on the
        output directory, or an interrupted scan.

        It used to look for the words HIGH / MEDIUM / LOW in each line,
        and that was wrong in a way that lost real findings silently:
        testssl prints severity words into its JSON and its logfile, NOT
        into the console output the operator sees. So a host offering
        SSLv3 printed "SSLv3   offered (NOT ok)", no severity word
        anywhere, no record built, no finding reported — while the same
        host run through the standalone testssl button showed it plainly.

        What testssl does print is a check name and a verdict. That is
        what this reads. Severity is not taken from the line at all; it
        comes from the issue library, which is where the house scoring
        policy lives.
        """
        records = []
        seen = set()
        for line in (text or "").splitlines():
            clean = re.sub(r"\x1b\[[0-9;]*m", "", line).strip()
            if len(clean) < 8 or clean.startswith(("#", "Start ", "Done ")):
                continue
            parts = re.split(r"\s{2,}", clean, maxsplit=1)
            if len(parts) < 2:
                continue
            name, verdict = parts[0].strip(), parts[1].strip()
            lowered = verdict.lower()
            if any(good in lowered for good in self._TESTSSL_GOOD):
                continue
            if not any(bad in lowered for bad in self._TESTSSL_BAD):
                continue
            # "BEAST (CVE-2011-3389)" → "BEAST"; "POODLE, SSL" → "POODLE_SSL";
            # "TLS 1" → "TLS1". The identifiers the library matches on are
            # testssl's JSON ids, so the console names are normalised to them.
            cves = re.findall(r"CVE-\d{4}-\d+", clean)
            identifier = re.sub(r"\s*\(.*?\)\s*", "", name).strip()
            identifier = identifier.replace(", ", "_").replace(" ", "")
            if not identifier:
                continue
            marker = (identifier.lower(), lowered[:60])
            if marker in seen:
                continue
            seen.add(marker)
            records.append({"id": identifier,
                            # Left empty on purpose: the library rates it.
                            "severity": "",
                            "finding": verdict,
                            "cve": " ".join(cves)})
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

            # Same order as nuclei, same reason. Nikto's plugin id and
            # the path it names identify the check; its sentence is an
            # explanation written for a human. "[007303] /JAMonAdmin.jsp:
            # … Versions 2.7 and earlier contain XSS vulnerabilities" was
            # matching the reflected-XSS pattern, so an admin interface
            # became a HIGH CWE-79 with no parameter, payload or
            # reflection anywhere in it.
            detection = detector_registry.classify_nikto(
                body, url=self._cb_target_url())
            if detection is not None:
                if detection.path:
                    detection.url = self._cb_target_url().rstrip("/") + \
                        detection.path
                produced += self._cb_record_detection(
                    detection, stage, raw=clean)
                continue

            key, issue = cb_issues.for_text(body)
            if not key:
                key, issue = _header_issue_from_nikto(body)
            override_title = _panel_title(key, body)

            # Nikto matches signatures; it does not re-check that the thing
            # it matched is still there. It reported a WordPress login
            # panel at /wordpress/wp-admin/wp-login.php on a target that
            # returns 404 for it, and the finding went into the report with
            # a URL that leads to a 404 page — which is worse than no
            # finding, because the first thing anybody does is click it.
            #
            # So any finding that names a path gets that path re-requested
            # before it is reported. One HEAD or GET per finding, against a
            # target already being scanned.
            located = self._cb_where_for(key, body)
            alive, note = self._cb_endpoint_alive(located)
            if alive is False:
                self._cb_log_dropped(located, note, body)
                continue
            reachable_note = (f"\n\nVerified: {note}" if note else "")
            if key == "robots_disclosure" and \
                    not self._cb_robots_worth_reporting():
                continue
            if key:
                if issue["severity"] != "INFO":
                    produced += 1
                evidence = body[:500]
                extra_summary = ""
                if key == "robots_disclosure":
                    # "contains 27 entries which should be manually
                    # viewed" is the scanner telling the operator to go
                    # and look. The entries were already fetched to
                    # decide whether this was worth reporting at all —
                    # so put them IN the finding, which is the manual
                    # viewing done.
                    entries = self._cb_artifacts.get("robots_entries") or []
                    if entries:
                        listing = "\n".join(f"  {line}" for line in entries)
                        evidence = (f"robots.txt on this host lists "
                                    f"{len(entries)} path rule(s):\n"
                                    f"{listing}")
                        extra_summary = (
                            f"The file names {len(entries)} path rule(s). "
                            f"Each one is somewhere the operator asked "
                            f"search engines not to index, which makes the "
                            f"list a shortlist of places to look — it is "
                            f"not an access control.\n\n{listing}")
                finding = self._cb_issue(
                    key, located, evidence,
                    stage["key"], confidence="tentative",
                    **({"title": override_title} if override_title else {}),
                    detail=issue["detail"]
                           + (f"\n\nNikto reported: {body}" if not extra_summary
                              else "")
                           + "\n\nNikto matches signatures and does not "
                             "confirm what it finds; verify it independently."
                           + reachable_note)
                if extra_summary:
                    finding.summary = extra_summary
                self._cb_record(finding)
                continue

            if cb_issues.is_observation(body):
                if len(observations) < 60 and body not in observations:
                    observations.append(body)
                continue

            # Unrecognised, and not obviously an observation. Report it, but
            # at the severity its wording justifies rather than a flat Low.
            lowered = body.lower()
            # A sensitive file that was RE-REQUESTED and came back with
            # plausible contents is graded on that fact, not on the
            # adjectives in Nikto's sentence. Tightening the keyword
            # ladder below (correctly) stopped "the shell history was
            # retrieved" matching the word "shell", and dropped a
            # genuinely readable .bash_history to INFO — a credential
            # disclosure rated beneath a missing header.
            if alive is True and self._cb_sensitive_path(located):
                severity = "HIGH"
                self._cb_record(CBFinding(
                    severity=severity,
                    title=(cb_issues.nikto_title(body)
                           or clean_title(body)),
                    where=located,
                    detail="Reported by Nikto, and re-requested by Command "
                           "Bridge: the path answered and the response did "
                           "not look like the application's own error or "
                           "catch-all page.\n\n" + body +
                           "\n\nThis is a sensitive path. Read the response "
                           "yourself before reporting it — what matters is "
                           "what the file contains.",
                    evidence=body[:500], confidence="tentative",
                    stage=stage["key"], sources=[stage["key"]]))
                produced += 1
                continue

            # "shell" on its own caught "the shell history was retrieved"
            # and graded a file-disclosure signature as HIGH alongside
            # remote code execution. The phrases below mean shell ACCESS.
            if any(phrase in lowered for phrase in
                   ("remote code", "web shell", "reverse shell",
                    "shell upload", "command execution", "backdoor",
                    "command injection", "arbitrary code")):
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
                severity=severity,
                # Nikto's line is a sentence of explanation, not a title.
                # Truncated into a title column it read "[002756]
                # /.sh_history: …", which names neither the problem nor
                # the file. nikto_title names both, and falls back to
                # clean_title when the line is not in Nikto's path form.
                title=cb_issues.nikto_title(body) or clean_title(body),
                # `located`, not the bare target. This hardcoded the host,
                # which meant an unrecognised finding about a specific path
                # pointed the reader at the home page — and the path that
                # was actually re-requested above never reached the report.
                where=located,
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

    #: Statuses that mean "this really is here". A 401 or 403 counts: a
    #: protected admin panel is still an admin panel, and arguably a better
    #: finding than an open one.
    _ALIVE = (200, 201, 202, 204, 301, 302, 303, 307, 308, 401, 403, 405)

    def _cb_endpoint_alive(self, url):
        """Re-request a path a tool claims exists. ``(alive, note)``.

        ``alive`` is None when the question does not apply or could not be
        answered — the finding is reported either way then, because a
        network blip is not evidence of absence.

        A soft 404 is caught too: plenty of applications answer 200 with a
        "not found" page, and a signature scanner counts that as a hit.
        """
        if not url or not url.startswith(("http://", "https://")):
            return None, ""
        parsed = urllib.parse.urlparse(url)
        if not parsed.path or parsed.path == "/":
            return None, ""
        try:
            session = _session({"url": url})
            response = session.get(url, timeout=10, allow_redirects=False)
        except Exception:                               # noqa: BLE001
            return None, ""
        if response.status_code not in self._ALIVE:
            return False, f"HTTP {response.status_code}"

        # ── the catch-all test ──────────────────────────────────────────
        #
        # The wording test below was the only soft-404 detection here, and
        # it is not enough. Reported from an engagement: Nikto claimed
        # /.bash_history had been retrieved; the host is a single-page
        # application behind a cache that answers 200 with the app shell
        # for EVERY path. The shell says nothing about 404 — it is a
        # <title>, some script tags and an empty root div — so the page
        # never admits it is not there and the finding sailed through as
        # "Observed directly".
        #
        # Asking the page whether it exists is the wrong question. The
        # right one is whether this response differs from one for a path
        # that cannot possibly exist.
        control = self._cb_catch_all_signature(url)
        if control:
            if self._cb_same_as_control(response, control):
                return False, ("HTTP %d, but this host answers the same way "
                               "for a path that cannot exist — it serves a "
                               "catch-all, so the match proves nothing"
                               % response.status_code)

        # Does the body match what the signature claims was retrieved?
        plausible, why = self._cb_file_contents_plausible(
            url, response.text or "", response.headers.get("Content-Type"))
        if not plausible:
            return False, f"HTTP {response.status_code}, but {why}"

        body = (response.text or "")[:4000].lower()
        if response.status_code == 200 and any(
                phrase in body for phrase in
                ("404", "not found", "nothing at", "page cannot be found",
                 "does not exist", "no such page")):
            # Only call it a soft 404 when the page says so AND has
            # nothing else going on; a login form that mentions "not
            # found" in a cookie banner is still a login form.
            if len(body.strip()) < 3000 and "<form" not in body:
                return False, f"HTTP 200 but the page says it is not there"
        return True, f"re-requested, HTTP {response.status_code}"

    #: Content types that a file-disclosure finding cannot be true of. A
    #: shell history, a private key or a .env served as text/html with a
    #: <title> in it is the application's own page, not the file.
    _NOT_A_FILE_MARKERS = ("<!doctype html", "<html", "<title", "<app-root",
                           "<div id=\"root\"", "<div id='root'")

    #: Paths whose mere readability is the finding. Matched against the
    #: path that was actually verified, which is why this is evidence
    #: rather than another keyword list: it only applies once the request
    #: has been made and the response did not look like a catch-all.
    _SENSITIVE_PATHS = (
        ".bash_history", ".zsh_history", ".sh_history", ".env",
        ".git/config", ".git/head", ".svn/entries", ".hg/",
        "id_rsa", "id_dsa", "id_ecdsa", "id_ed25519", ".ssh/authorized_keys",
        ".htpasswd", ".netrc", ".pgpass", ".my.cnf", ".npmrc", ".pypirc",
        "wp-config.php", "web.config", "settings.py", "credentials",
        ".aws/credentials", ".docker/config.json", "database.yml",
        ".dockercfg", "secrets.yml", ".pem", ".key", ".keystore",
        ".sql", ".sqlite", ".dump", ".bak", ".old", ".swp",
    )

    def _cb_sensitive_path(self, url):
        """Is this a path whose readability is itself the problem?"""
        try:
            path = urllib.parse.urlparse(url or "").path.lower()
        except Exception:                               # noqa: BLE001
            return False
        if not path or path == "/":
            return False
        return any(marker in path for marker in self._SENSITIVE_PATHS)

    def _cb_catch_all_signature(self, url):
        """How this host answers a path that cannot exist.

        One extra request per host, cached, not per finding. Returns None
        when the control request fails — an unanswerable question must
        not become evidence either way.
        """
        parsed = urllib.parse.urlparse(url)
        host_key = (parsed.scheme, parsed.netloc)
        cache = getattr(self, "_cb_catch_all_cache", None)
        if cache is None:
            cache = self._cb_catch_all_cache = {}
        if host_key in cache:
            return cache[host_key]

        probe = (f"{parsed.scheme}://{parsed.netloc}/"
                 f"cb-does-not-exist-{int(time.time())}-zqx/nope.txt")
        signature = None
        try:
            session = _session({"url": probe})
            response = session.get(probe, timeout=10, allow_redirects=False)
            signature = {
                "status": response.status_code,
                "type": (response.headers.get("Content-Type") or "")
                        .split(";")[0].strip().lower(),
                "length": len(response.content or b""),
                "body": (response.text or "")[:2000],
            }
            if signature["status"] in (404, 410):
                # A host that answers 404 properly has no catch-all, so
                # there is nothing to compare against later.
                signature = None
        except Exception:                               # noqa: BLE001
            signature = None
        cache[host_key] = signature
        return signature

    @staticmethod
    def _cb_same_as_control(response, control):
        """Is this response indistinguishable from the catch-all's?"""
        if response.status_code != control["status"]:
            return False
        kind = (response.headers.get("Content-Type") or "") \
            .split(";")[0].strip().lower()
        if kind != control["type"]:
            return False
        here, there = len(response.content or b""), control["length"]
        if max(here, there) == 0:
            return True
        # A templated shell differs only by whatever the path put in it,
        # so allow a few per cent rather than demanding equality.
        if abs(here - there) / max(here, there) > 0.05:
            return False
        return True

    def _cb_file_contents_plausible(self, url, body, content_type):
        """Could this response really be the file the signature claims?

        Nikto's wording for these is "the shell history was retrieved",
        "the file was retrieved" — a claim about content, which can be
        checked against the content. An HTML document is not a
        .bash_history, a .env or a private key, whatever the status code.
        """
        path = urllib.parse.urlparse(url).path.lower()
        looks_like_a_file = any(
            path.endswith(ext) or part in path for ext, part in
            ((".bash_history", ".bash_history"), (".env", ".env"),
             (".git/config", ".git"), (".ssh/id_rsa", "id_rsa"),
             (".htpasswd", ".htpasswd"), (".npmrc", ".npmrc"),
             (".sql", ".sql"), (".bak", ".bak"), (".log", ".log"),
             (".pem", ".pem"), (".key", ".key"), (".config", ".config")))
        if not looks_like_a_file:
            return True, ""
        kind = (content_type or "").split(";")[0].strip().lower()
        lowered = (body or "")[:3000].lower()
        if kind.startswith("text/html") or any(
                marker in lowered for marker in self._NOT_A_FILE_MARKERS):
            return False, (f"the response is {kind or 'HTML'} containing an "
                           f"HTML document, which is the application's own "
                           f"page rather than the file the signature claims "
                           f"was retrieved")
        return True, ""

    def _cb_log_dropped(self, url, note, body):
        """Say what was dropped and why, rather than silently binning it."""
        try:
            self.console.append_ansi(
                f"[i] not reported — {url} returned {note or 'nothing'} "
                f"when re-requested, so the signature that matched it is "
                f"stale: {body[:120]}\n")
        except Exception:                               # noqa: BLE001
            pass

    def _cb_where_for(self, key, body):
        """The URL a finding belongs to, pulled out of the tool's own line.

        A login panel finding that says "somewhere on the target" is half a
        finding. Nikto prints the path it found; this puts it in the finding's
        location so the reader can click it.
        """
        base = self._cb_target_url().rstrip("/")
        match = re.search(r"(/[A-Za-z0-9_\-./%]{1,120})", body or "")
        if not match:
            return self._cb_target_url()

        # The fixed key list below misses the case this was reported
        # for: Nikto said /.bash_history had been retrieved, that issue
        # matches no library key, so the finding's location fell back to
        # the bare host — and _cb_endpoint_alive declines to check a URL
        # whose path is "/", so NO verification ran at all and a
        # signature match was reported as observed.
        #
        # Deliberately NOT broadened to every line that mentions a
        # slash. Nikto's inventory lines mention paths too ("/test.php:
        # This might be interesting."), and pinning those to a path puts
        # them through the aliveness gate, which drops them instead of
        # collecting them as the low-value observations they are. What
        # gets pinned is a recognised path-based issue, or a path whose
        # readability is itself the finding.
        candidate = match.group(1)
        if key in ("login_panel_exposed", "admin_exposed",
                   "directory_listing", "backup_file",
                   "vcs_exposed", "env_file_exposed",
                   "info_page_exposed", "source_code_disclosure",
                   "config_disclosed", "api_spec_exposed"):
            return base + candidate
        if self._cb_sensitive_path(base + candidate):
            return base + candidate
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
            tags = [str(x) for x in (info.get("tags") or [])] \
                if isinstance(info.get("tags"), list) else []

            # The detector registry decides first, because it keys on the
            # template's IDENTITY — the one thing nuclei reports that is
            # actually about what was tested. modules/detector_registry.py
            # carries the history; missing-sri has an entry there because
            # its NAME contains "Subresou(rce)" and it was being published
            # as a CRITICAL OS command injection.
            detection = detector_registry.classify_nuclei(
                template, name, tags=tags, severity=severity,
                url=matched,
                extracted=[str(x) for x in
                           (row.get("extracted-results") or [])])
            if detection is not None:
                produced += self._cb_record_detection(
                        detection, stage, raw=line[:1200],
                    scanner_severity=severity,
                    template_tags=tags,
                    template_author=", ".join(info.get("author") or [])
                    if isinstance(info.get("author"), list)
                    else str(info.get("author") or ""))
                continue

            key, issue = cb_issues.for_nuclei(template, name)

            # A template that does not test for an exploit cannot carry an
            # exploit class, whatever its wording matched. The backstop
            # for templates the registry does not name.
            if key and key in risk.NEEDS_DEMONSTRATION and \
                    not detector_registry.exploit_class_admissible(
                        tags, severity):
                self.console.append_ansi(
                    f"    [i] '{name}' matched the wording for "
                    f"{cb_issues.ISSUES.get(key, {}).get('title', key)}, "
                    f"but template '{template}' (severity {severity}, tags "
                    f"{', '.join(tags) or 'none'}) does not test for one — "
                    f"keeping nuclei's own description instead\n")
                key, issue = None, None

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
