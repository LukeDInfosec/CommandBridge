"""
The evidence chain: what was actually seen, and what we are allowed to say
about it.

A scanner alert is not a vulnerability. It is one tool's opinion, and the job
of this module is to keep that opinion attached to the thing that produced it
so a human can check the working. Everything here answers one of three
questions:

  * **What did we observe?**      :class:`Evidence` — the request, the
    parameter, the payload, the response, the detector, the template, the raw
    line the tool printed. Captured once, copied on every hand-off, never
    shared between findings.
  * **Does it support the claim?** :func:`assess` — per-classification minimum
    evidence, and a topic check that catches a Content-Security-Policy header
    being offered as proof of command execution.
  * **What may we print?**        :class:`Validation` — a state, a confidence,
    the reasons for both, and a proof-of-concept that is rendered *from the
    evidence* or not rendered at all.

The rule that shapes the whole file: nothing in a report may exist that
cannot be traced back to an observation. Where there is no observation, the
report says so in as many words. It never fills the gap in.
"""

from __future__ import annotations

import copy
import itertools
import re
import time
from dataclasses import dataclass, field, asdict


# ─────────────────────────────────────────────────────────────────────────────
#  States and confidence
# ─────────────────────────────────────────────────────────────────────────────
#
# A finding moves along this scale as evidence accumulates. It starts at the
# left. Nothing puts it at the right except evidence.

DETECTED = "DETECTED"                # a tool said something; nothing checked
POTENTIAL = "POTENTIAL"              # plausible, not proven
VALIDATED = "VALIDATED"              # our own checks reproduced it
CONFIRMED = "CONFIRMED"              # exploited, or otherwise beyond argument
INCONCLUSIVE = "INCONCLUSIVE"        # evidence is missing or contradictory
FALSE_POSITIVE = "FALSE_POSITIVE"    # judged wrong, by us or by a human

STATES = (DETECTED, POTENTIAL, VALIDATED, CONFIRMED,
          INCONCLUSIVE, FALSE_POSITIVE)

#: The states a reader should act on differently. Used by the report to
#: group, and by the UI to colour.
OPEN_STATES = (CONFIRMED, VALIDATED, POTENTIAL, DETECTED, INCONCLUSIVE)

INFORMATIONAL = "informational"      # not a vulnerability claim at all
POTENTIAL_C = "potential"            # a claim with nothing behind it yet
LOW = "low"
MEDIUM = "medium"
HIGH = "high"
CONFIRMED_C = "confirmed"

CONFIDENCE = (INFORMATIONAL, POTENTIAL_C, LOW, MEDIUM, HIGH, CONFIRMED_C)
CONFIDENCE_ORDER = {name: index for index, name in enumerate(CONFIDENCE)}

#: The old two-value scale, so findings written by older code still render.
LEGACY_CONFIDENCE = {"tentative": POTENTIAL_C, "firm": MEDIUM,
                     "confirmed": CONFIRMED_C}


def normalise_confidence(value):
    """Accept either scale and return one of :data:`CONFIDENCE`."""
    text = str(value or "").strip().lower()
    if text in CONFIDENCE_ORDER:
        return text
    return LEGACY_CONFIDENCE.get(text, POTENTIAL_C)


_COUNTER = itertools.count(1)


def correlation_id(prefix="cb"):
    """A short id that follows one observation through the pipeline."""
    return f"{prefix}-{int(time.time() * 1000) % 10_000_000}-{next(_COUNTER)}"


# ─────────────────────────────────────────────────────────────────────────────
#  Evidence
# ─────────────────────────────────────────────────────────────────────────────

#: Where a parameter lived. Reporting "the id parameter" without saying it was
#: a cookie wastes the reader's time when they try to reproduce it.
QUERY, BODY, JSON, XML, HEADER, COOKIE, PATH, MULTIPART = (
    "query", "body", "json", "xml", "header", "cookie", "path", "multipart")


@dataclass
class Evidence:
    """Everything observed about one detection, in one place.

    Every field is optional because tools differ in what they report, and a
    missing field is itself information — it is what makes a finding
    inconclusive rather than confirmed. Nothing here is ever inferred: a
    populated field means the value was seen.
    """

    # ── where ────────────────────────────────────────────────────────────
    target: str = ""
    url: str = ""
    endpoint: str = ""
    method: str = ""

    # ── the input that was tested ────────────────────────────────────────
    parameter: str = ""
    location: str = ""            # one of QUERY/BODY/JSON/... above
    original_value: str = ""
    payload: str = ""

    # ── the exchange ─────────────────────────────────────────────────────
    request: str = ""
    response: str = ""
    status_code: object = None
    response_headers: dict = field(default_factory=dict)
    body_excerpt: str = ""
    redirect: str = ""
    timing_ms: object = None

    # ── the comparison that made it mean something ───────────────────────
    baseline_request: str = ""
    baseline_response: str = ""
    comparison: str = ""          # what differed, in words
    oob_interaction: str = ""     # DNS/HTTP callback, if any

    # ── who said so ──────────────────────────────────────────────────────
    detector: str = ""            # nuclei | nikto | testssl | active-scan | …
    template_id: str = ""
    template_name: str = ""
    template_author: str = ""
    template_severity: str = ""   # the scanner's own rating, kept as metadata
    template_tags: list = field(default_factory=list)
    template_path: str = ""
    matcher: str = ""
    extracted: list = field(default_factory=list)
    raw: str = ""                 # the tool's own line, verbatim

    # ── what we actually saw ─────────────────────────────────────────────
    #: A human sentence describing the observation. This is the only place a
    #: finding's "why" may come from; it is never generated from the issue
    #: library.
    observed: str = ""

    timestamp: float = field(default_factory=time.time)
    correlation_id: str = field(default_factory=correlation_id)

    # ── copying ──────────────────────────────────────────────────────────
    def copy(self):
        """A deep copy.

        Findings hand evidence to each other during de-duplication. Handing
        over a reference is how one finding ends up displaying another's
        proof, so nothing in this codebase passes the original.
        """
        clone = copy.deepcopy(self)
        return clone

    # ── what is present ──────────────────────────────────────────────────
    def has_injection_point(self):
        return bool(self.parameter or self.location)

    def has_payload(self):
        return bool(self.payload)

    def has_exchange(self):
        return bool(self.request or self.response or self.body_excerpt
                    or self.status_code is not None)

    def has_differential(self):
        return bool(self.comparison
                    or (self.baseline_response and self.response))

    def has_oob(self):
        return bool(self.oob_interaction)

    def has_timing(self):
        return self.timing_ms is not None

    def is_empty(self):
        return not any((self.raw, self.observed, self.response,
                        self.body_excerpt, self.extracted, self.matcher))

    def evidence_text(self):
        """Everything observed, as one blob, for topic matching."""
        parts = [self.observed, self.matcher, self.body_excerpt,
                 self.response, self.raw, self.comparison,
                 " ".join(str(item) for item in self.extracted)]
        parts += [f"{name}: {value}"
                  for name, value in (self.response_headers or {}).items()]
        return "\n".join(part for part in parts if part)

    def summary(self):
        """A short line naming the detector and what it matched on."""
        bits = []
        if self.detector:
            bits.append(self.detector)
        if self.template_id:
            bits.append(f"template: {self.template_id}")
        elif self.template_name:
            bits.append(self.template_name)
        if self.url:
            bits.append(self.url)
        return " · ".join(bits)

    def as_dict(self):
        return asdict(self)

    # ── rendering ────────────────────────────────────────────────────────
    def raw_detection(self):
        """§19 — exactly what the tool reported, before we interpreted it."""
        lines = ["RAW DETECTION"]
        lines.append(f"  Scanner:   {self.detector or 'unknown'}")
        if self.template_id:
            lines.append(f"  Template:  {self.template_id}")
        if self.template_name and self.template_name != self.template_id:
            lines.append(f"  Name:      {self.template_name}")
        if self.template_severity:
            lines.append(f"  Scanner severity: {self.template_severity}")
        if self.template_tags:
            lines.append(f"  Tags:      {', '.join(self.template_tags)}")
        if self.template_author:
            lines.append(f"  Author:    {self.template_author}")
        if self.template_path:
            lines.append(f"  Path:      {self.template_path}")
        if self.url:
            lines.append(f"  Matched:   {self.url}")
        if self.matcher:
            lines.append(f"  Matcher:   {self.matcher}")
        if self.extracted:
            lines.append("  Extracted: "
                         + ", ".join(str(x) for x in self.extracted)[:400])
        if self.raw:
            lines.append("  Raw:")
            lines += [f"    {line}" for line in self.raw.splitlines()[:12]]
        return "\n".join(lines)

    def poc(self):
        """§3 — a proof of concept, or nothing.

        Returns ``""`` when the pieces were not captured. The caller prints
        "PoC unavailable" in that case; neither of us invents a request.
        """
        if not (self.has_injection_point() and self.has_payload()):
            return ""
        lines = ["Proof of Concept", ""]
        lines.append("Endpoint:")
        lines.append(f"  {self.url or self.endpoint or self.target}")
        if self.method:
            lines += ["", "Method:", f"  {self.method}"]
        lines += ["", "Parameter:",
                  f"  {self.parameter or '(unnamed)'}"
                  + (f"  [{self.location}]" if self.location else "")]
        if self.original_value:
            lines += ["", "Original value:", f"  {self.original_value}"]
        lines += ["", "Test input:", f"  {self.payload}"]
        if self.request:
            lines += ["", "Request:"] + _indent(self.request)
        if self.response:
            lines += ["", "Response:"] + _indent(self.response)
        elif self.body_excerpt:
            lines += ["", "Response excerpt:"] + _indent(self.body_excerpt)
        if self.observed:
            lines += ["", "Observation:", f"  {self.observed}"]
        elif self.comparison:
            lines += ["", "Observation:", f"  {self.comparison}"]
        return "\n".join(lines)

    def burp_request(self):
        """§16 — the request in a form that pastes into Burp Repeater."""
        if self.request:
            return self.request.strip()
        return ""


def _indent(text, width=2):
    return [" " * width + line for line in str(text).strip().splitlines()[:40]]


# ─────────────────────────────────────────────────────────────────────────────
#  What a piece of evidence is *about*
# ─────────────────────────────────────────────────────────────────────────────
#
# This is the check that the reported failure needed. A Content-Security-Policy
# header is evidence about a Content-Security-Policy. It is not evidence about
# a shell, whatever an unrelated template's prose happens to say, and whatever
# CWE a database hangs off it.
#
# Topics are deliberately coarse. The question being asked is not "which issue
# is this" — the library already answered that — it is "could the thing we are
# looking at possibly be proof of the thing we are claiming".

EVIDENCE_TOPICS = (
    ("csp", r"content-security-policy|(default|script|object|style|img|"
            r"frame|base|form)-(src|uri|action|ancestors)|unsafe-inline|"
            r"unsafe-eval|\bnonce-|\bcsp\b"),
    ("shell", r"\buid=\d+|\bgid=\d+\(|root:x:0:0|/bin/(ba)?sh\b|"
              r"\bwhoami\b|nt authority\\\\system|volume serial number|"
              r"directory of c:\\\\|command (execution|output)|"
              r";\s*(id|whoami|sleep|ping)\b|\$\(.*\)|`id`"),
    ("sql", r"sql syntax|mysql_fetch|ora-\d{5}|sqlstate|unclosed quotation|"
            r"psql:|sqlite3?\.|pg_query|odbc driver|syntax error at or near|"
            r"you have an error in your sql"),
    ("xss", r"<script|onerror\s*=|onload\s*=|javascript:|alert\(|"
            r"reflected (in|into) (the )?(response|html)|"
            r"executed in (a|the) browser"),
    ("tls", r"\bciphers?\b|tls ?1\.[0-3]|sslv[23]|\bcbc\b|\brc4\b|"
            r"certificate|handshake|x509|\bhsts\b|"
            r"strict-transport-security"),
    ("header", r"x-frame-options|x-content-type-options|referrer-policy|"
               r"permissions-policy|x-permitted-cross-domain-policies|"
               r"cross-origin-opener|access-control-allow-origin"),
    ("cookie", r"set-cookie|httponly|samesite|secure flag|session cookie"),
    ("path", r"\.\./|root:x:0:0|boot\.ini|win\.ini|/etc/passwd|"
             r"directory traversal|path traversal"),
    ("panel", r"login (page|panel|form)|/umbraco|/wp-(login|admin)|"
              r"phpmyadmin|/administrator|sign ?in|admin (panel|console)"),
    ("disclosure", r"\.git/|\.env\b|BEGIN [A-Z ]*PRIVATE KEY|AKIA[0-9A-Z]{16}|"
                   r"index of /|phpinfo|stack ?trace|server-status"),
    ("service", r"\d+/tcp\s+open|\bbanner\b|ssh-\d|smtp|ftp server"),
    ("timing", r"delay(ed)? by|response time|took \d+(\.\d+)?\s*(ms|s)\b|"
               r"time-based"),
    ("oob", r"\boob\b|out.of.band|dns (callback|interaction|lookup)|"
            r"interactsh|collaborator|burpcollaborator"),
)

_COMPILED_TOPICS = [(name, re.compile(pattern, re.I))
                    for name, pattern in EVIDENCE_TOPICS]


def topics_in(text):
    """Which subjects a piece of evidence could possibly be about."""
    blob = str(text or "")
    if not blob.strip():
        return set()
    return {name for name, pattern in _COMPILED_TOPICS if pattern.search(blob)}


#: The subject each classification is a claim about. A finding whose evidence
#: shares none of these topics is a finding whose evidence is about something
#: else — which is exactly the failure this module exists to catch.
#:
#: Keys absent from this table make no topical claim (version disclosure can
#: be proved by almost anything), and are not topic-checked.
CLASSIFICATION_TOPICS = {
    # injection and execution
    "command_injection": {"shell", "timing", "oob"},
    "code_injection": {"shell", "timing", "oob"},
    "ssti": {"shell", "timing", "oob"},
    "deserialization": {"shell", "timing", "oob"},
    "sqli": {"sql", "timing", "oob"},
    "ldap_injection": {"sql", "timing", "oob"},
    "xpath_injection": {"sql", "timing", "oob"},
    "ssi_injection": {"shell", "timing", "oob"},
    "xss_reflected": {"xss"},
    "xss_stored": {"xss"},
    "xss_dom": {"xss"},
    "traversal": {"path", "disclosure"},
    "file_inclusion": {"path", "disclosure", "shell"},
    "ssrf": {"oob", "timing", "disclosure"},
    "xxe": {"oob", "path", "disclosure"},
    # configuration, where the header *is* the evidence
    "csp_missing": {"csp", "header"},
    "csp_unsafe_script": {"csp"},
    "csp_clickjacking": {"csp", "header"},
    "csp_form_hijack": {"csp"},
    "csp_report_only": {"csp"},
    "csp_wildcard_source": {"csp"},
    "csp_missing_object_base": {"csp"},
    "hsts_missing": {"header", "tls"},
    "xfo_missing": {"header", "csp"},
    "nosniff_missing": {"header"},
    "referrer_policy": {"header"},
    "permissions_policy": {"header"},
    "xpcdp_missing": {"header"},
    "coop_missing": {"header"},
    "cors_arbitrary_origin": {"header"},
    "cors_null_origin": {"header"},
    "cors_subdomains": {"header"},
    "cors_insecure_origin": {"header"},
    "cookie_no_secure": {"cookie", "header"},
    "cookie_no_httponly": {"cookie", "header"},
    "cookie_no_samesite": {"cookie", "header"},
    "login_panel_exposed": {"panel"},
    "admin_exposed": {"panel"},
    "directory_listing": {"disclosure"},
    "vcs_exposed": {"disclosure"},
    "env_file_exposed": {"disclosure"},
    "private_key_disclosed": {"disclosure"},
    "info_page_exposed": {"disclosure"},
    "exposed_datastore": {"service"},
    "cleartext_service": {"service"},
    "remote_access_exposed": {"service"},
}

#: Classifications that assert an attacker *did something* rather than that a
#: setting is wrong. These cannot be established by a signature, a header or a
#: banner — they need an input, a payload and an observed consequence. This is
#: the rule that stops any passive detection ever being printed as a confirmed
#: CWE-78.
EXPLOIT_REQUIRED = {
    "command_injection", "code_injection", "ssti", "deserialization",
    "sqli", "ldap_injection", "xpath_injection", "ssi_injection",
    "xss_reflected", "xss_stored", "xss_dom", "traversal", "file_inclusion",
    "ssrf", "xxe", "crlf_injection", "host_header_injection",
    "request_smuggling", "cache_poisoning", "open_redirect",
    "prototype_pollution", "file_upload", "access_control",
}

#: What each family of exploit needs before we will say it happened.
#: ``differential`` means a before/after that a reader can check; ``oob`` is
#: accepted in its place, because a DNS callback from the target is proof on
#: its own.
EVIDENCE_REQUIREMENTS = {
    "default": ("injection_point", "payload", "observation"),
    "sqli": ("injection_point", "payload", "observation"),
    "command_injection": ("injection_point", "payload", "observation"),
    "xss_reflected": ("injection_point", "payload", "observation"),
    "ssrf": ("injection_point", "payload", "oob_or_differential"),
    "xxe": ("injection_point", "payload", "oob_or_differential"),
}


def requirements_for(key):
    return EVIDENCE_REQUIREMENTS.get(key, EVIDENCE_REQUIREMENTS["default"])


# ─────────────────────────────────────────────────────────────────────────────
#  Validation
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class Validation:
    """The verdict on one finding's evidence, and the reasons for it."""

    state: str = DETECTED
    confidence: str = POTENTIAL_C
    evidence_sufficient: bool = False
    classification_consistent: bool = True
    #: The pieces the classification needed and did not get.
    missing: list = field(default_factory=list)
    #: Sentences describing a contradiction between claim and evidence.
    conflicts: list = field(default_factory=list)
    #: §15 — why this might be wrong.
    false_positive_indicators: list = field(default_factory=list)
    #: §14 — why the tool raised it at all, from the evidence itself.
    rationale: str = ""
    #: What a human should do next.
    action: str = ""

    @property
    def needs_manual_validation(self):
        return self.state in (POTENTIAL, DETECTED, INCONCLUSIVE)

    def as_dict(self):
        return asdict(self)


#: Names for the things a claim can be missing, in the words the report uses.
_MISSING_LABEL = {
    "injection_point": "no injection point (parameter/location) was identified",
    "payload": "no test payload was recorded",
    "observation": "no observed consequence was captured "
                   "(no response, body excerpt or comparison)",
    "oob_or_differential": "no out-of-band interaction and no "
                           "baseline/comparison pair were captured",
}


def _satisfied(requirement, evidence):
    if requirement == "injection_point":
        return evidence.has_injection_point()
    if requirement == "payload":
        return evidence.has_payload()
    if requirement == "observation":
        return (evidence.has_exchange() or evidence.has_differential()
                or evidence.has_oob() or bool(evidence.observed))
    if requirement == "oob_or_differential":
        return evidence.has_oob() or evidence.has_differential()
    return True


def rationale_for(evidence):
    """§14 — why this finding exists, in terms of what was seen."""
    if evidence.observed:
        return evidence.observed
    if evidence.comparison:
        return evidence.comparison
    if evidence.matcher and evidence.template_id:
        return (f"{evidence.detector or 'A scanner'} template "
                f"'{evidence.template_id}' matched '{evidence.matcher}' "
                f"at {evidence.url or 'the target'}.")
    if evidence.template_id:
        return (f"{evidence.detector or 'A scanner'} template "
                f"'{evidence.template_id}' matched at "
                f"{evidence.url or 'the target'}. The template's own match "
                f"is the whole of the evidence.")
    if evidence.extracted:
        return (f"{evidence.detector or 'A scanner'} extracted "
                f"{', '.join(str(x) for x in evidence.extracted)[:200]} "
                f"from {evidence.url or 'the target'}.")
    if evidence.raw:
        return (f"{evidence.detector or 'A scanner'} reported: "
                f"{evidence.raw.splitlines()[0][:200]}")
    return ""


def assess(key, evidence, *, issue_severity="", scanner_severity="",
           detector_confirmed=False, is_information=False):
    """Decide what may be said about a classification given its evidence.

    ``detector_confirmed`` is set by our own active checks, which do not
    guess: when one of those reports something it has already reproduced the
    behaviour, and the evidence it carries shows it.

    Returns a :class:`Validation`. It never raises, and never upgrades a
    finding on the strength of a tool's own opinion.
    """
    evidence = evidence or Evidence()
    validation = Validation()
    validation.rationale = rationale_for(evidence) or ""

    # ── 1. is the evidence even about this subject? ──────────────────────
    expected = CLASSIFICATION_TOPICS.get(key)
    seen = topics_in(evidence.evidence_text())
    if expected and seen and not (seen & expected):
        validation.classification_consistent = False
        validation.conflicts.append(
            f"Classification conflict detected. The detector reported "
            f"evidence associated with {', '.join(sorted(seen))}, while the "
            f"current vulnerability classification is '{key}', which is a "
            f"claim about {', '.join(sorted(expected))}. "
            f"Manual validation required.")
        validation.false_positive_indicators.append(
            f"Detector evidence relates to {', '.join(sorted(seen))} rather "
            f"than to {', '.join(sorted(expected))}.")

    # ── 2. information is not a vulnerability claim ──────────────────────
    if is_information:
        validation.state = DETECTED
        validation.confidence = INFORMATIONAL
        validation.evidence_sufficient = True
        validation.action = "Informational. No validation required."
        return validation

    # ── 3. does it meet the minimum for this classification? ─────────────
    needs_exploit = key in EXPLOIT_REQUIRED
    if needs_exploit:
        for requirement in requirements_for(key):
            if not _satisfied(requirement, evidence):
                validation.missing.append(requirement)
        validation.evidence_sufficient = not validation.missing
    else:
        # A configuration finding is proved by the observation itself: the
        # header either carries unsafe-inline or it does not.
        validation.evidence_sufficient = not evidence.is_empty()
        if evidence.is_empty():
            validation.missing.append("observation")

    for requirement in validation.missing:
        validation.false_positive_indicators.append(
            _MISSING_LABEL.get(requirement, requirement).capitalize() + ".")

    if not validation.rationale:
        validation.rationale = ""
        validation.false_positive_indicators.append(
            "Detection rationale unavailable — the detector did not say why "
            "it raised this.")

    # ── 4. the verdict ───────────────────────────────────────────────────
    if not validation.classification_consistent:
        validation.state = INCONCLUSIVE
        validation.confidence = POTENTIAL_C
        validation.action = ("Manual validation required — the evidence does "
                             "not match the classification.")
        return validation

    if detector_confirmed and validation.evidence_sufficient:
        validation.state = CONFIRMED
        validation.confidence = CONFIRMED_C
        validation.action = "Reproduced by the tool. Re-check before writing up."
        return validation

    if needs_exploit:
        if validation.evidence_sufficient:
            validation.state = VALIDATED
            validation.confidence = HIGH
            validation.action = ("Evidence captured. Replay the PoC to "
                                 "confirm before reporting.")
        else:
            validation.state = POTENTIAL
            validation.confidence = POTENTIAL_C
            validation.action = "MANUAL VALIDATION REQUIRED"
        return validation

    # Configuration and disclosure findings: what the tool saw is the finding.
    if validation.evidence_sufficient:
        validation.state = VALIDATED
        validation.confidence = HIGH if evidence.has_exchange() else MEDIUM
        validation.action = "Observed directly. Spot-check the evidence."
    else:
        validation.state = INCONCLUSIVE
        validation.confidence = POTENTIAL_C
        validation.action = "MANUAL VALIDATION REQUIRED"
    return validation


def corroborate(validation, sources):
    """Raise confidence — never severity — when tools agree.

    Two scanners matching the same thing is better evidence for the same
    problem, not a worse problem. And it is not evidence at all when the
    classification is already in dispute.
    """
    if not validation.classification_consistent or len(sources) < 2:
        return validation
    if validation.state in (POTENTIAL, DETECTED) and \
            validation.evidence_sufficient:
        validation.state = VALIDATED
    index = CONFIDENCE_ORDER.get(validation.confidence, 1)
    if validation.confidence != INFORMATIONAL and validation.evidence_sufficient:
        validation.confidence = CONFIDENCE[min(index + 1,
                                               CONFIDENCE_ORDER[HIGH])]
    return validation


# ─────────────────────────────────────────────────────────────────────────────
#  Rendering
# ─────────────────────────────────────────────────────────────────────────────

_TICK, _CROSS, _WARN = "✓", "✗", "⚠"


def evidence_checklist(key, evidence):
    """The §12 block: what we have, and what we do not, spelled out."""
    lines = []
    if key in EXPLOIT_REQUIRED:
        lines.append(f"  Injection point: "
                     + (f"{evidence.parameter or '(unnamed)'}"
                        + (f" [{evidence.location}]" if evidence.location else "")
                        if evidence.has_injection_point() else "NOT IDENTIFIED"))
        lines.append(f"  Payload: "
                     + (evidence.payload if evidence.has_payload()
                        else "NOT CAPTURED"))
        lines.append(f"  Exploitation evidence: "
                     + (evidence.comparison or evidence.oob_interaction
                        or evidence.observed or "NOT OBSERVED"))
    else:
        # A configuration finding's evidence IS the thing that was observed,
        # so show it rather than listing what an exploit would have needed.
        seen = (evidence.extracted and
                ", ".join(str(x) for x in evidence.extracted)[:400]) \
            or evidence.matcher or evidence.body_excerpt[:400] \
            or evidence.raw.splitlines()[0][:400] if evidence.raw else ""
        lines.append(f"  Observed: {seen or 'NOT CAPTURED'}")
    lines.append("  Response evidence: "
                 + ("captured" if evidence.has_exchange() else "NOT CAPTURED"))
    if evidence.has_timing():
        lines.append(f"  Response timing: {evidence.timing_ms} ms")
    if evidence.has_oob():
        lines.append(f"  Out-of-band: {evidence.oob_interaction}")
    return lines


def poc_section(key, evidence):
    """The proof-of-concept lines, or an honest statement that there are none.

    A reproduction step is only ever rendered from captured evidence. Where
    there is nothing to render, this says so; it does not compose a plausible
    request out of the issue library.
    """
    poc = evidence.poc()
    if poc:
        return poc.splitlines()
    if key not in EXPLOIT_REQUIRED and not evidence.is_empty():
        # Nothing was exploited because nothing needed to be: the observation
        # itself is the finding. Say how to see it again.
        where = evidence.url or evidence.target
        return ["Reproduction",
                "",
                f"  Request {where} and inspect the response.",
                f"  Observed: "
                + (", ".join(str(x) for x in evidence.extracted)[:400]
                   or evidence.matcher or evidence.observed
                   or evidence.raw.splitlines()[0][:200]),
                "",
                "  No payload was sent — this is a configuration "
                "observation, not an exploit."]
    return ["PoC unavailable — insufficient evidence was captured."]


def render(title, severity, key, evidence, validation, *,
           scanner_severity="", detail="", remediation="", cwe=""):
    """A finding, in the form §12 and §19 ask for.

    Observed evidence, the generic description of the issue and the
    remediation advice are three separate sections and are never run
    together, because a reader has to be able to tell which is which.
    """
    lines = [f"[{validation.state}] {title}"]
    lines.append(f"Severity (tool-assessed): {severity}")
    if scanner_severity:
        lines.append(f"Severity (scanner-reported): {scanner_severity}")
    lines.append(f"Confidence: {validation.confidence}")
    if evidence.detector:
        lines.append(f"Detector: {evidence.detector}")
    if evidence.template_id:
        lines.append(f"Template: {evidence.template_id}")
    lines.append(f"Target: {evidence.url or evidence.target}")
    if cwe:
        lines.append(f"Classification: {key} / {cwe}")

    lines += ["", "Evidence:"] + evidence_checklist(key, evidence)

    lines += ["", "Why this was detected:"]
    lines.append("  " + (validation.rationale
                         or "Detection rationale unavailable."))

    lines += ["", "Classification validation:"]
    lines.append(f"  {_TICK if validation.evidence_sufficient else _CROSS} "
                 f"Evidence sufficient: "
                 f"{'Yes' if validation.evidence_sufficient else 'No'}")
    lines.append(f"  {_TICK if validation.classification_consistent else _WARN} "
                 f"Classification consistent: "
                 f"{'Yes' if validation.classification_consistent else 'No'}")
    for conflict in validation.conflicts:
        lines.append(f"  {_WARN} {conflict}")

    if validation.false_positive_indicators:
        lines += ["", "Potential false-positive indicators:"]
        lines += [f"  - {item}"
                  for item in validation.false_positive_indicators]

    lines += [""] + poc_section(key, evidence)

    lines += ["", evidence.raw_detection()]

    if detail:
        lines += ["", "Generic vulnerability description:"]
        lines += [f"  {line}" for line in str(detail).splitlines()]
    if remediation:
        lines += ["", "Recommended remediation:"]
        lines += [f"  {line}" for line in str(remediation).splitlines()]

    lines += ["", f"Status: {validation.action or validation.state}"]
    return "\n".join(lines)
