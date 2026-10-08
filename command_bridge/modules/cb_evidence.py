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
import urllib.parse
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


#: Only the characters that genuinely break a URL. Everything else is left
#: alone deliberately: this string exists to be read, pasted into a browser
#: and recognised, and `..%2F..%2Fetc%2Fpasswd` is none of those things. The
#: fully percent-encoded form is still printed in the proof-of-concept block
#: for anyone who wants to replay it exactly as the scanner sent it.
_URL_BREAKERS = {
    "&": "%26", "#": "%23", " ": "%20", "+": "%2B",
    "\n": "%0A", "\r": "%0D", "\t": "%09", "%": "%25",
}


def _url_safe(value):
    text = str(value or "")
    # % first, or the replacements below get double-encoded.
    text = text.replace("%", "%25")
    for char, code in _URL_BREAKERS.items():
        if char == "%":
            continue
        text = text.replace(char, code)
    return text


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
    #: The same request as a raw HTTP/1.1 message — request line, Host, every
    #: header including the session cookies, a blank line, the body. This is
    #: what pastes into Burp Repeater and comes back with the same response,
    #: which is the difference between a proof of concept and a description
    #: of one.
    raw_request: str = ""
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
    def attack_url(self):
        """The one line a tester actually wants: the URL, with the payload in.

        Everything else in a finding is supporting material. What gets
        clicked, pasted into a browser or dropped into a ticket is a single
        URL with the payload already in the right parameter — and that was
        the one thing the report never printed. It gave the endpoint on one
        line, the parameter on another and the payload on a third, and left
        the reader to reassemble them by hand, every time, for every
        finding.

        Returns "" when there is nothing honest to build: a finding with no
        payload, a POST body (where a URL would be a lie about how it was
        sent), or an injection point that is not in the query string.
        """
        if not self.payload:
            return ""
        base = self.url or self.endpoint or self.target
        if not base or not str(base).startswith(("http://", "https://")):
            return ""
        location = (self.location or "").lower()
        # A header, cookie or body parameter cannot be expressed as a URL,
        # and pretending otherwise sends someone to a page that works fine
        # and makes them distrust the finding.
        if location and not any(word in location for word in
                                ("query", "url", "path", "get")):
            return ""
        name = (self.parameter or "").strip()
        # Parameter labels arrive as "query parameter 'id'" or "query 'id'".
        match = re.search(r"'([^']+)'", name)
        if match:
            name = match.group(1)
        name = name.split()[-1] if name else ""
        if not name:
            return ""
        parsed = urllib.parse.urlparse(str(base))
        pairs = urllib.parse.parse_qsl(parsed.query, keep_blank_values=True)
        found = False
        rebuilt = []
        for key, value in pairs:
            if key == name:
                rebuilt.append((key, self.payload))
                found = True
            else:
                rebuilt.append((key, value))
        if not found:
            rebuilt.append((name, self.payload))
        query = "&".join(f"{key}={_url_safe(value)}"
                         for key, value in rebuilt)
        return urllib.parse.urlunparse(parsed._replace(query=query,
                                                       fragment=""))

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
            # Some classes are not proved by sending anything — access
            # control is proved by replaying one request as two identities.
            # Those have a reproduction, just not a payload-shaped one.
            return self._differential_poc()
        # No title line: every caller prints its own heading, and two of them
        # were printing "Proof of concept" immediately above this one's.
        lines = ["Endpoint:"]
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

    def _differential_poc(self):
        """A reproduction for findings proved by comparison, not by payload.

        Returns ``""`` unless there really is a before/after to show, so a
        finding with nothing behind it still says the PoC is unavailable.
        """
        if not self.has_differential():
            return ""
        lines = ["Endpoint:", f"  {self.url or self.endpoint or self.target}"]
        if self.method:
            lines += ["", "Method:", f"  {self.method}"]
        lines += ["", "How to reproduce:",
                  "  Send the same request as each identity below and compare "
                  "what comes back.", ""]
        if self.request:
            lines += ["Request:"] + _indent(self.request)
        if self.response:
            lines += ["", "Response:"] + _indent(self.response)
        if self.comparison:
            lines += ["", "Comparison:"] + _indent(self.comparison)
        if self.observed:
            lines += ["", "Observation:", f"  {self.observed}"]
        return "\n".join(lines)

    def burp_request(self):
        """§16 — the request in a form that pastes into Burp Repeater.

        Returns the raw HTTP message when one was captured, and otherwise
        nothing. The human-readable ``request`` summary is deliberately not
        offered as a substitute: "GET http://host/path?id=1" is not a request
        Burp will accept, and handing it to somebody under a button marked
        "Copy Burp Request" wastes their time twice — once pasting it and
        once working out why it did not work.
        """
        if not self.raw_request:
            return ""
        # Leading whitespace goes; trailing does not. The blank line at the
        # end is what terminates the header block, and stripping it produces
        # a request that looks right and that Repeater will not send.
        raw = self.raw_request.lstrip()
        return raw if "\r\n\r\n" in raw else raw.rstrip("\r\n") + "\r\n\r\n"

    def has_burp_request(self):
        return bool(self.raw_request and self.raw_request.strip())


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
    # Access control is not proved by sending a payload. It is proved by
    # sending the SAME request as two different identities and showing that
    # one got something it should not have. Demanding a payload here was
    # marking genuine, fully evidenced findings as unproven.
    "access_control": ("observation", "differential"),
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
    """What this finding actually has. Not a list of what it is missing.

    This used to print "Payload: NOT CAPTURED / Exploitation evidence: NOT
    OBSERVED / Injection point: NOT IDENTIFIED" on every finding that was
    never going to have those — a signature match from Nikto, a missing
    header — which is three lines of nothing on most of the report. The
    absences still matter, but they belong in the one place that explains
    why the finding is not confirmed, not repeated as a table of blanks
    beside every entry.
    """
    lines = []
    if key in EXPLOIT_REQUIRED:
        # The line a tester actually uses, first and on its own.
        attack = evidence.attack_url()
        if attack:
            lines.append(f"  Vulnerable URL: {attack}")
        if evidence.has_injection_point():
            lines.append(f"  Injection point: {evidence.parameter or '(unnamed)'}"
                         + (f" [{evidence.location}]"
                            if evidence.location else ""))
        if evidence.has_payload():
            lines.append(f"  Payload: {evidence.payload}")
        proof = (evidence.comparison or evidence.oob_interaction
                 or evidence.observed)
        if proof:
            lines.append(f"  Exploitation evidence: {proof}")
        if not lines:
            lines.append("  Nothing was captured for this finding — it rests "
                         "on the detecting tool's signature alone.")
            return lines
    else:
        # A configuration finding's evidence IS the thing that was observed,
        # so show it rather than listing what an exploit would have needed.
        seen = (evidence.extracted and
                ", ".join(str(x) for x in evidence.extracted)[:400]) \
            or evidence.matcher or evidence.body_excerpt[:400] \
            or evidence.raw.splitlines()[0][:400] if evidence.raw else ""
        if seen:
            lines.append(f"  Observed: {seen}")
        else:
            lines.append("  Nothing was captured beyond the detecting "
                         "tool's own statement.")
            return lines
    if evidence.has_timing():
        lines.append(f"  Response timing: {evidence.timing_ms} ms")
    if evidence.has_oob():
        lines.append(f"  Out-of-band: {evidence.oob_interaction}")
    return lines


#: One colour per severity, picked to read on every theme in the app rather
#: than to match any single one. Lives here because both findings screens
#: draw from it and they must not drift apart.
SEV_COLOURS = {
    "CRITICAL": "#ff3b5c",
    "HIGH": "#ff6b4a",
    "MEDIUM": "#f6b73c",
    # Low is green and Info is blue, not the other way round. Blue reads as
    # "a note"; green reads as "nothing to do here". A Low is something you
    # may choose to live with, which is the green end of the scale — and
    # putting Low in the same blue as an informational note made the two
    # indistinguishable at a glance, which is the one thing a severity
    # colour exists to prevent.
    "LOW": "#3fb950",
    "INFO": "#4f8cff",
}

#: One colour per state, on the same principle.
STATE_COLOURS = {
    CONFIRMED: "#3fb950",
    VALIDATED: "#58a6ff",
    POTENTIAL: "#d29922",
    DETECTED: "#8b9bb4",
    INCONCLUSIVE: "#d29922",
    FALSE_POSITIVE: "#6e7681",
}


#: Confidence gets its own palette, deliberately unlike the severity one. A
#: confirmed low and a potential critical must not be able to look alike.
CONFIDENCE_COLOURS = {
    CONFIRMED_C: "#3fb950",
    HIGH: "#58a6ff",
    MEDIUM: "#58a6ff",
    "likely": "#58a6ff",
    POTENTIAL_C: "#d29922",
    "inconclusive": "#8b9bb4",
    INFORMATIONAL: "#8b9bb4",
}

#: Human names for the scanner's evidence grades, so this module can label a
#: raw signal without importing the scanner (which is a heavier dependency
#: than a lookup table deserves). Falls back to the grade itself.
try:                                    # pragma: no cover - import guard
    from command_bridge.modules.scanner.grading import GRADE_NAMES
except Exception:                       # pragma: no cover
    GRADE_NAMES = {}


def severity_label(severity, confidence):
    """"Potentially Critical" rather than a bare CRITICAL or a quiet demotion.

    A critical issue that has not been proved is still potentially critical.
    Saying so keeps both facts in one phrase instead of letting the severity
    imply a certainty the evidence does not support.
    """
    severity = (severity or "INFO").upper()
    if confidence in (CONFIRMED_C, INFORMATIONAL):
        return severity
    if confidence == "inconclusive":
        return f"{severity} if real"
    return f"Potentially {severity.capitalize()}"


def _esc(text):
    """HTML-escape, the way both tabs need it."""
    return (str(text or "").replace("&", "&amp;").replace("<", "&lt;")
            .replace(">", "&gt;"))


def detail_html(finding):
    """One finding, rendered for a detail pane.

    Both findings screens call this. Coffee Break and the Active Scan reach
    their findings by completely different routes — one reads other people's
    tools, the other exploits things itself — but what a reader needs from a
    finding is the same either way: what state it is in, why it was raised,
    what was actually observed, how to reproduce it, and what might make it
    wrong. Writing that twice is how the two screens drift apart, which is
    what this exists to prevent.

    ``finding`` is a CBFinding, or anything with the same shape.
    """
    severity = getattr(finding, "severity", "INFO")
    colour = SEV_COLOURS.get(severity, "#8b9bb4")
    state = getattr(finding, "state", "")
    validation = getattr(finding, "validation", None)
    proof = getattr(finding, "proof", None) or Evidence()
    stage = getattr(finding, "stage", "")

    html = [f"<h3 style='margin:0 0 4px 0'>"
            f"{_esc(getattr(finding, 'title', ''))}</h3>"]
    if state:
        html.append(f"<div style='color:{STATE_COLOURS.get(state, '#8b9bb4')};"
                    f"font-weight:700'>[{_esc(state)}]</div>")
    # §18 — severity answers "how bad if real", confidence answers "how well
    # do we know it". They are printed as two separate statements, and the
    # combined label spells out the relationship instead of hiding it.
    confidence = getattr(finding, "confidence", "") or ""
    html.append(
        f"<div style='color:{colour};font-weight:600'>{_esc(severity)}"
        f" <span style='color:palette(mid);font-weight:400'>"
        f"(impact if real)</span>"
        f" &nbsp;·&nbsp; <span style='color:"
        f"{CONFIDENCE_COLOURS.get(confidence, '#8b9bb4')};font-weight:600'>"
        f"{_esc(confidence)}</span>"
        f" <span style='color:palette(mid);font-weight:400'>"
        f"(evidence) · {_esc(stage)}</span></div>")
    if confidence and confidence not in (CONFIRMED_C, INFORMATIONAL):
        html.append(f"<div style='color:palette(mid)'>Reads as: "
                    f"<b>{_esc(severity_label(severity, confidence))}</b>"
                    f"</div>")

    verdict = getattr(finding, "verdict", None)
    auth = getattr(finding, "auth_context", {}) or {}
    if auth:
        # §15 — the same bug on a public page and behind an admin login are
        # two different reports, so every finding says which it was.
        html.append(
            f"<p><b>Authentication context:</b> "
            f"{_esc(auth.get('label', 'unknown'))}"
            + (f" as <code>{_esc(auth.get('identity'))}</code>"
               if auth.get("identity") else "")
            + (f", via {_esc(auth.get('method'))}"
               if auth.get("method") and auth.get("method") != "none" else "")
            + "</p>")
    if getattr(verdict, "detection_method", ""):
        html.append(f"<p><b>Detected by:</b> "
                    f"{_esc(verdict.detection_method)}</p>")
    # The attack URL goes first, before anything else, because it is the
    # only line most readers need. Everything underneath is the argument
    # for it. Reassembling endpoint + parameter + payload by hand, for
    # every finding, was work the report was making the reader do.
    attack = proof.attack_url()
    if attack:
        html.append(
            "<p style='margin:10px 0 2px 0'><b>Vulnerable URL</b> "
            "<span style='color:palette(mid);font-weight:400'>"
            "&mdash; paste this into a browser</span></p>"
            "<pre style='white-space:pre-wrap;margin:0 0 10px 0;"
            "padding:8px 10px;border-left:3px solid #ff3b5c;"
            "background:rgba(255,59,92,0.08);color:#ff6b7f;"
            "font-weight:600'>" + _esc(attack) + "</pre>")
        html.append(f"<p><b>Vulnerable parameter:</b> "
                    f"<code>{_esc(proof.parameter or '(unnamed)')}</code>"
                    + (f" [{_esc(proof.location)}]"
                       if proof.location else "") + "</p>")
        html.append(f"<p><b>Endpoint:</b> "
                    f"<code>{_esc(getattr(finding, 'where', ''))}</code></p>")
    else:
        html.append(f"<p><b>Where:</b> "
                    f"<code>{_esc(getattr(finding, 'where', ''))}</code></p>")
        if proof.parameter:
            html.append(
                f"<p><b>Parameter:</b> <code>{_esc(proof.parameter)}</code>"
                + (f" [{_esc(proof.location)}]" if proof.location else "")
                + "</p>")

    scanner_severity = getattr(finding, "scanner_severity", "")
    if scanner_severity and scanner_severity != severity:
        html.append(
            f"<p><b>Severity:</b> {_esc(severity)} (tool-assessed) "
            f"&nbsp;·&nbsp; {_esc(scanner_severity)} (reported by "
            f"{_esc(stage)}). The scanner's rating is kept as metadata; it "
            f"does not set ours.</p>")

    if validation is not None:
        if not validation.classification_consistent:
            html.append(
                "<p style='color:#d29922'><b>⚠ Classification / evidence "
                "mismatch.</b> "
                + "<br>".join(_esc(c) for c in validation.conflicts) + "</p>")
        # §17 — raw detection on its own first: exactly what was measured
        # or matched, with nothing wrapped around it. The interpretation
        # comes after, clearly labelled as interpretation.
        signals = list(getattr(verdict, "signals", None)
                       or getattr(finding, "signals", []) or [])
        measurements = getattr(finding, "measurements", {}) or {}
        if signals or measurements:
            rows = []
            for signal in signals:
                numbers = ""
                if signal.measurements:
                    numbers = " <code>" + _esc(", ".join(
                        f"{k}={signal.measurements[k]}"
                        for k in sorted(signal.measurements))) + "</code>"
                rows.append(
                    f"<li><b>{_esc(GRADE_NAMES.get(signal.grade, signal.grade))}"
                    f"</b>"
                    + (" (reproduced)" if signal.reproduced else "")
                    + f": {_esc(signal.detail)}{numbers}</li>")
            for key in sorted(measurements):
                rows.append(f"<li><b>{_esc(key)}</b>: "
                            f"{_esc(str(measurements[key]))}</li>")
            html.append("<p><b>Raw detection</b> — what was actually "
                        "observed</p><ul>" + "".join(rows) + "</ul>")
        html.append("<p><b>Interpreted finding</b><br>"
                    + _esc(validation.rationale
                           or "Detection rationale unavailable.") + "</p>")
        checklist = evidence_checklist(getattr(finding, "key", ""), proof)
        if checklist:
            html.append("<p><b>Observed evidence</b></p>"
                        "<pre style='white-space:pre-wrap'>"
                        + _esc("\n".join(checklist)) + "</pre>")
        html.append("<p><b>Proof of concept</b></p>"
                    "<pre style='white-space:pre-wrap'>"
                    + _esc("\n".join(poc_section(
                        getattr(finding, "key", ""), proof))) + "</pre>")
        burp = proof.burp_request()
        if burp:
            html.append(
                "<p><b>Replay in Burp</b> — the complete request, exactly as "
                "it was sent. Use the <b>Copy Burp Request</b> button below, "
                "or select the block and paste it into Repeater.</p>"
                "<pre style='white-space:pre-wrap;border-left:3px solid "
                f"#3d7eff;padding-left:8px'>{_esc(burp)}</pre>")
        if validation.false_positive_indicators:
            html.append("<p><b>What could explain this without the "
                        "vulnerability</b></p><ul>"
                        + "".join(f"<li>{_esc(i)}</li>"
                                  for i in
                                  validation.false_positive_indicators)
                        + "</ul>")
        if confidence not in (CONFIRMED_C, INFORMATIONAL):
            html.append(
                f"<p style='border-left:3px solid #d29922;padding-left:8px'>"
                f"<b>Not proved.</b> "
                f"{_esc(getattr(verdict, 'verification', '') or validation.action or 'Manual validation required.')}"
                f"</p>")
        elif validation.action:
            html.append(f"<p><b>Next step:</b> {_esc(validation.action)}</p>")

    # Outdated-software findings get the one thing they were missing: what
    # the current release actually is, and somewhere to read about what
    # this version is vulnerable to. The figure comes from the operator's
    # own catalogue (Target tab -> Update Version Data), never from the
    # scanner's built-in idea of "current", which is as old as its database.
    key_name = getattr(finding, "key", "")
    if key_name in ("outdated_software", "version_disclosure",
                    "js_library_outdated"):
        try:
            from command_bridge.modules import version_catalog
            haystack = " ".join(str(x) for x in (
                getattr(finding, "title", ""), proof.raw, proof.observed,
                proof.matcher, getattr(finding, "where", "")))
            product, version = version_catalog.identify(haystack)
            if product:
                verdict, detail = version_catalog.assess(product, version)
                colour = {"outdated": "#ff6b4a", "current": "#3fb950"}.get(
                    verdict, "#8b9bb4")
                html.append(
                    f"<p><b>Version check</b> "
                    f"<span style='color:{colour};font-weight:600'>"
                    f"{_esc(product)} {_esc(version)} \u2014 "
                    f"{_esc(verdict)}</span><br>{_esc(detail)}</p>")
                references = version_catalog.links_for(product, version)
                if references:
                    html.append("<p><b>Look it up</b></p><ul>" + "".join(
                        f'<li><a href="{_esc(url)}">{_esc(label)}</a></li>'
                        for label, url in references) + "</ul>")
        except Exception:                               # noqa: BLE001
            pass

    sources = [s for s in (getattr(finding, "sources", []) or [stage]) if s]
    if len(sources) > 1:
        html.append(
            f"<p><b>Detected by {len(sources)} tools:</b> "
            f"{_esc(', '.join(sources))} — independent agreement, which is "
            f"why this is worth more than a single signature match.</p>")

    instances = list(getattr(finding, "instances", []) or [])
    if instances:
        shown = "".join(f"<li><code>{_esc(u)}</code></li>"
                        for u in instances[:30])
        more = (f"<li>… and {len(instances) - 30} more</li>"
                if len(instances) > 30 else "")
        html.append(f"<p><b>Also affects {len(instances)} other "
                    f"location(s)</b></p><ul>{shown}{more}</ul>")

    detail = getattr(finding, "detail", "")
    if detail:
        html.append("".join(f"<p>{_esc(para)}</p>"
                            for para in str(detail).split("\n\n")))

    raw = proof.raw_detection()
    if raw.strip() != "RAW DETECTION":
        html.append("<p><b>Raw detection</b> — exactly what the tool "
                    "reported, before interpretation</p>"
                    f"<pre style='white-space:pre-wrap'>{_esc(raw)}</pre>")
    elif getattr(finding, "evidence", ""):
        html.append("<p><b>Evidence</b></p><pre style='white-space:pre-wrap'>"
                    f"{_esc(finding.evidence)}</pre>")

    if getattr(finding, "remediation", ""):
        html.append(f"<p><b>Recommended remediation:</b> "
                    f"{_esc(finding.remediation)}</p>")
    if getattr(finding, "cwe", ""):
        html.append(f"<p><b>Classification:</b> {_esc(finding.cwe)}</p>")
    references = list(getattr(finding, "references", []) or [])
    if references:
        html.append("<p><b>References:</b> "
                    + ", ".join(_esc(r) for r in references[:8]) + "</p>")
    return "".join(html)


def burp_request_for(finding):
    """The raw HTTP request behind a finding, for the clipboard.

    Takes a CBFinding or anything with a ``proof``. Returns "" when there is
    nothing to copy, which is the UI's cue to disable the button rather than
    put an empty clipboard in front of somebody about to paste.
    """
    proof = getattr(finding, "proof", None)
    if proof is None:
        return ""
    return proof.burp_request()


def evidence_from_scan(scan_finding):
    """The evidence chain behind one of the active scanner's results.

    The scanner does not guess: by the time it emits a result it has put a
    payload into a named insertion point and watched what came back. This
    lifts that chain — parameter, payload, request, response, and the
    oracle's own words for what it saw — into the same shape Coffee Break
    uses, so the report, the detail pane and the validator can all read it
    without caring which tool produced it.

    Kept here rather than beside CBFinding because the scanner's own report
    writer needs it and must stay free of Qt.
    """
    items = list(getattr(scan_finding, "evidence", []) or [])
    # The step that demonstrates the issue, not simply the first one recorded.
    # A boolean SQL injection proves itself with a true/false pair and the
    # control is sometimes listed first; leading a PoC with the request that
    # did *not* do anything is actively misleading.
    lead = next((item for item in items if getattr(item, "decisive", False)),
                items[0] if items else None)
    # The payload named in the PoC must be the one in the request the PoC
    # shows. Taking the first payload recorded anywhere in the chain reads
    # fine until the lead step is a different request from the first — then
    # the report prints one payload above a request containing another, and
    # whoever tries to reproduce it gets a different result.
    payload = (getattr(lead, "payload", "") if lead else "") or next(
        (getattr(item, "payload", "") for item in items
         if getattr(item, "payload", "")), "")
    proof = Evidence(
        url=getattr(scan_finding, "where", ""),
        parameter=getattr(scan_finding, "point", ""),
        detector="active-scan",
        payload=payload or payload_from_label(getattr(lead, "label", "")),
        request=getattr(lead, "request", "") if lead else "",
        # Prefer the decisive step's wire form; fall back to any step that
        # captured one, so a finding whose lead step never got a response
        # still offers something that can be replayed.
        raw_request=(getattr(lead, "raw_request", "") if lead else "")
                    or next((getattr(item, "raw_request", "") for item in items
                             if getattr(item, "raw_request", "")), ""),
        response=getattr(lead, "response", "") if lead else "",
        # Every step, in order, including the one chosen as the lead. A
        # multi-request proof is only a proof if the reader can see all of it.
        comparison="\n\n".join(item.render() for item in items)
                   if len(items) > 1 else "",
        observed=getattr(scan_finding, "detail_extra", "")
                 or (getattr(lead, "note", "") if lead else ""),
        raw=scan_finding.evidence_text()
            if hasattr(scan_finding, "evidence_text") else "",
    )
    return proof


def payload_from_label(label):
    """Last resort: pull the payload out of a label that happens to name one.

    The checks record the payload as a field. This only catches a label of
    the form "Payload: …" from anything that has not been updated to, and it
    is deliberately not relied upon — recovering a payload by parsing
    human-written prose is guesswork that fails silently, which is exactly
    how confirmed findings came to be printed with "Payload: NOT CAPTURED".
    """
    match = re.search(r"payload[: ]+(.+)$", str(label or ""), re.I)
    return match.group(1).strip() if match else ""


#: The scanner's graded confidence → what this module may say about it.
#: A graded verdict is the scanner's own account of how strong its evidence
#: was, so it governs in both directions: it can confirm a finding, and it
#: can hold one down. Nothing here can lift a finding above the grade its
#: evidence earned.
_GRADED = {
    "confirmed": (CONFIRMED, CONFIRMED_C,
                  "Reproduced by the tool on decisive evidence. Re-check "
                  "before writing up."),
    "likely": (VALIDATED, HIGH,
               "Corroborating evidence captured, nothing decisive. Confirm "
               "manually before reporting."),
    "potential": (POTENTIAL, POTENTIAL_C, "MANUAL VALIDATION REQUIRED"),
    "inconclusive": (INCONCLUSIVE, POTENTIAL_C, "MANUAL VALIDATION REQUIRED"),
}


def assess_scan(scan_finding):
    """``(evidence, validation)`` for one active-scan result.

    The active checks no longer declare their own confidence: each attaches
    graded signals and the grading module derives a verdict from them. This
    reads that verdict rather than second-guessing it, and carries its
    reasoning — why, what could still explain it away, and how to check —
    into the validation so the report can show all three.
    """
    proof = evidence_from_scan(scan_finding)
    graded = str(getattr(scan_finding, "confidence", "") or "").lower()
    verdict = getattr(scan_finding, "verdict", None)

    validation = assess(
        getattr(scan_finding, "issue", ""), proof,
        detector_confirmed=graded == "confirmed")

    if graded in _GRADED and validation.classification_consistent:
        state, confidence, action = _GRADED[graded]
        if graded == "confirmed" and not validation.evidence_sufficient:
            # The grade says the behaviour was proved, but the evidence
            # chain is missing a piece the write-up needs. Keep the lower of
            # the two: say what is there, not what it would have been.
            pass
        else:
            validation.state = state
            validation.confidence = confidence
            validation.action = action

    if verdict is not None:
        if getattr(verdict, "rationale", ""):
            validation.rationale = verdict.rationale
        for limitation in getattr(verdict, "limitations", ()) or ():
            if limitation not in validation.false_positive_indicators:
                validation.false_positive_indicators.append(limitation)
        if getattr(verdict, "verification", "") and \
                validation.state != CONFIRMED:
            validation.action = verdict.verification
    return proof, validation


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

    lines += ["", "Proof of concept:"] + poc_section(key, evidence)

    lines += ["", evidence.raw_detection()]

    if detail:
        lines += ["", "Generic vulnerability description:"]
        lines += [f"  {line}" for line in str(detail).splitlines()]
    if remediation:
        lines += ["", "Recommended remediation:"]
        lines += [f"  {line}" for line in str(remediation).splitlines()]

    lines += ["", f"Status: {validation.action or validation.state}"]
    return "\n".join(lines)
