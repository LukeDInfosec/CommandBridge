"""
The decision engine: one path from "a scanner said something" to "this
is the finding", used by every scanner.

Until now each scanner's parser made these decisions itself, and the
rules were fixed where each bug was found — in the nuclei parser, then
the Nikto parser, then the testssl parser. The same fault kept arriving
through whichever route had not been patched yet:

    weak-csp-detect       CSP header     → CRITICAL OS command injection
    missing-sri           script URL     → CRITICAL OS command injection
    JAMonAdmin.jsp        a Java page    → HIGH reflected XSS
    xss-deprecated-header "1; mode=block" → reflected XSS

The last one is why this module exists rather than another entry in a
table. It defeats both earlier guards: the registry had no entry for it,
and the tag-based backstop passed it because the template is TAGGED
``xss``. A tag says what subject a template is about. It does not say
whether the template tested for an exploit, and ``xss-deprecated-header``
tests for a header.

So the general rule is not about names, tags or severities. It is about
what was OBSERVED:

    A vulnerability class that requires a demonstrated behaviour cannot
    be carried by an observation that is only a header value, a cipher
    suite, a path, or a component banner.

``1; mode=block`` is a header value. No arrangement of template metadata
makes it evidence of script execution. That rule needs no entry per
detector, and it is checked for every finding from every scanner.

Eight stages, each allowed to know only what the one before established:

    1 identify the detector        which check ran
    2 identify the observation     what it actually produced
    3 consistency                  can that observation support the class?
    4 verification                 cheap, safe, reusing what we have
    5 confirmation                 confirmed / potential / inconclusive
    6 risk                         impact, capped by confirmation
    7 explanation                  why this was raised, from the evidence
    8 display                      report, qualify, or keep as context

No LLM anywhere in it. Every decision is a function of structured
evidence, so every decision is testable and the same input gives the
same answer twice.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from command_bridge.modules import detector_registry as registry
from command_bridge.modules import explanations, risk

# ── stage 2: what kind of thing was observed ────────────────────────────
#
# This is the axis the engine turns on, so the vocabulary is small and
# each member is something a scanner can actually hand over.

HEADER_VALUE = "header_value"        # a response header and its value
RESPONSE_BODY = "response_body"      # content returned for a path
PATH_EXISTS = "path_exists"          # a path answered
COMPONENT = "component"             # a product or version banner
CIPHER_CONFIG = "cipher_config"      # suites, protocols, certificates
EXTRACTED_URL = "extracted_url"      # a URL read out of a page
PARAMETER_ECHO = "parameter_echo"    # input appearing in a response
DEMONSTRATED = "demonstrated"        # a payload and its observed effect
UNKNOWN_OBSERVATION = "unknown"

#: Classes whose impact exists only once a behaviour has been shown.
#: Each lists the observation kinds that COULD support it. Anything else
#: is a classification mismatch, however the detector is labelled.
BEHAVIOURAL_CLASSES = {
    "command_injection": {DEMONSTRATED},
    "sqli": {DEMONSTRATED, PARAMETER_ECHO},
    "potential_sqli": {DEMONSTRATED, PARAMETER_ECHO},
    "xss_reflected": {DEMONSTRATED, PARAMETER_ECHO},
    "xss_stored": {DEMONSTRATED, PARAMETER_ECHO},
    "xss_dom": {DEMONSTRATED, PARAMETER_ECHO},
    "ssrf": {DEMONSTRATED},
    "xxe": {DEMONSTRATED},
    "ssti": {DEMONSTRATED, PARAMETER_ECHO},
    "lfi": {DEMONSTRATED, RESPONSE_BODY},
    "rfi": {DEMONSTRATED},
    "traversal": {DEMONSTRATED, RESPONSE_BODY},
    "deserialization": {DEMONSTRATED},
    "auth_bypass": {DEMONSTRATED},
    "idor": {DEMONSTRATED},
    "code_injection": {DEMONSTRATED},
    "file_upload": {DEMONSTRATED},
}

#: What an observation of each kind can legitimately be a finding ABOUT,
#: when the detector's own class has been rejected. The fallback is
#: deliberately dull: a header observation becomes a header finding.
FALLBACK_CLASS = {
    HEADER_VALUE: ("security_header_observation",
                   "Security header observation"),
    RESPONSE_BODY: ("content_observation", "Response content observation"),
    PATH_EXISTS: ("path_observation", "Reachable path"),
    COMPONENT: ("component_admin_exposed", "Component identified"),
    CIPHER_CONFIG: ("weak_cipher", "TLS configuration observation"),
    EXTRACTED_URL: ("content_observation", "Response content observation"),
    UNKNOWN_OBSERVATION: ("scan_information", "Scanner observation"),
}


@dataclass
class Observation:
    """Stage 2 — what the detector actually produced."""

    kind: str = UNKNOWN_OBSERVATION
    header_name: str = ""
    header_value: str = ""
    path: str = ""
    url: str = ""
    body: str = ""
    content_type: str = ""
    http_status: int = 0
    component: str = ""
    version: str = ""
    parameter: str = ""
    payload: str = ""
    reflected: bool = False
    executed: bool = False
    extracted: tuple = ()
    suites: tuple = ()
    raw: str = ""

    def as_dict(self):
        return {k: (list(v) if isinstance(v, tuple) else v)
                for k, v in self.__dict__.items()}


@dataclass
class Decision:
    """What the engine concluded, and why — the whole audit trail."""

    issue_key: str = ""
    title: str = ""
    category: str = ""
    status: str = registry.INCONCLUSIVE
    status_label: str = "Inconclusive"
    severity: str = "INFO"
    impact_if_real: str = "INFO"
    scanner_severity: str = ""
    explanation: object = None          # explanations.Explanation or None
    summary: str = ""
    evidence: list = field(default_factory=list)
    mismatch: str = ""                  # why the detector's class was rejected
    verification: dict = field(default_factory=dict)
    observation: dict = field(default_factory=dict)
    detector_id: str = ""
    scanner: str = ""
    display: str = "report"             # report | context | suppress
    notes: list = field(default_factory=list)

    def as_dict(self):
        out = dict(self.__dict__)
        out["explanation"] = (self.explanation.as_dict()
                              if self.explanation is not None else None)
        return out


# ── stage 2 ─────────────────────────────────────────────────────────────

def observe(detection, outcome=None):
    """Work out what kind of observation this detection rests on.

    Read from the detector's declared evidence type where it has one,
    and otherwise inferred from what is actually present. The inference
    is the part that matters for unknown detectors: a detection whose
    only content is one short header-shaped string is a header
    observation whatever its template is called.
    """
    detector = getattr(detection, "detector", None)
    declared = getattr(detector, "observation", "") if detector else ""
    extracted = tuple(str(x) for x in (getattr(detection, "extracted", ())
                                       or ()) if x)
    verification = outcome.as_dict() if outcome is not None else {}

    observation = Observation(
        url=getattr(detection, "url", "") or "",
        path=getattr(detection, "path", "") or "",
        extracted=extracted,
        raw=getattr(detection, "raw", "") or "",
        http_status=verification.get("http_status") or 0,
        content_type=verification.get("content_type") or "",
    )

    if declared:
        observation.kind = declared
    elif observation.http_status and observation.content_type:
        observation.kind = RESPONSE_BODY
    elif extracted and all(_header_shaped(value) for value in extracted):
        observation.kind = HEADER_VALUE
    elif extracted and any(_url_shaped(value) for value in extracted):
        observation.kind = EXTRACTED_URL
    elif observation.path:
        observation.kind = PATH_EXISTS
    else:
        observation.kind = UNKNOWN_OBSERVATION

    if observation.kind == HEADER_VALUE:
        observation.header_name = getattr(detector, "header", "") or ""
        observation.header_value = extracted[0] if extracted else ""
    return observation


def _header_shaped(value):
    """Does this look like a header VALUE rather than a payload or URL?

    Short, no scheme, no angle brackets, no quotes. ``1; mode=block``
    passes; ``<script>alert(1)</script>`` and a URL do not. Being wrong
    in the cautious direction here means an observation is treated as
    something that could support more, not less.
    """
    text = str(value or "").strip()
    if not text or len(text) > 200:
        return False
    if any(token in text.lower() for token in
           ("http://", "https://", "<", ">", "javascript:", "'", '"')):
        return False
    return True


def _url_shaped(value):
    return str(value or "").strip().lower().startswith(("http://", "https://",
                                                        "//"))


# ── stage 3 ─────────────────────────────────────────────────────────────

def consistent(issue_key, observation):
    """Can this observation support this vulnerability class?

    ``(ok, why_not)``. The single rule that generalises every
    misclassification in this project's history.
    """
    required = BEHAVIOURAL_CLASSES.get(str(issue_key or ""))
    if not required:
        return True, ""
    if observation.kind in required:
        return True, ""
    if observation.executed or (observation.payload and observation.reflected):
        return True, ""

    what = {
        HEADER_VALUE: (f"the only evidence is a response header"
                       + (f" ({observation.header_name})"
                          if observation.header_name else "")
                       + (f" with the value {observation.header_value!r}"
                          if observation.header_value else "")),
        RESPONSE_BODY: "the only evidence is the content of a response",
        PATH_EXISTS: "the only evidence is that a path answered",
        COMPONENT: "the only evidence is a product or version banner",
        CIPHER_CONFIG: "the only evidence is the TLS configuration",
        EXTRACTED_URL: "the only evidence is a URL read out of the page",
        UNKNOWN_OBSERVATION: "no vulnerability-specific evidence was "
                             "recorded",
    }.get(observation.kind, "the evidence is of the wrong kind")

    return False, (f"{what}, which cannot establish {issue_key} — that "
                   f"needs an injection point, a payload and an observed "
                   f"effect")


# ── the engine ──────────────────────────────────────────────────────────

def decide(detection, outcome, *, issue_library, verified=False,
           explanation_context=None):
    """Stages 2-8 for one detection. Always returns a Decision.

    ``issue_library`` is cb_issues.ISSUES, passed in rather than
    imported so this module stays testable on its own and has no opinion
    about where the library lives.
    """
    detector = detection.detector
    observation = observe(detection, outcome)
    decision = Decision(
        scanner=getattr(detection, "scanner", "") or "",
        detector_id=getattr(detection, "detector_id", "") or "",
        scanner_severity=getattr(detection, "scanner_severity", "") or "",
        observation=observation.as_dict(),
        verification=outcome.as_dict() if outcome is not None else {},
    )

    issue_key = detector.issue_key or ""
    title = detector.name or ""
    category = detector.vuln_class or ""

    # ── stage 3: reject a class the observation cannot support ──────────
    ok, why_not = consistent(issue_key, observation)
    if not ok:
        decision.mismatch = why_not
        fallback_key, fallback_title = FALLBACK_CLASS.get(
            observation.kind, FALLBACK_CLASS[UNKNOWN_OBSERVATION])
        decision.notes.append(
            f"the detector's class ({issue_key}) was not used: {why_not}")
        issue_key = detector.fallback_key or fallback_key
        title = detector.fallback_name or fallback_title
        category = "observation"

    library = issue_library.get(issue_key, {}) if issue_key else {}
    decision.issue_key = issue_key
    decision.title = library.get("title") or title or "Scanner observation"
    decision.category = category

    # ── stage 5: confirmation ───────────────────────────────────────────
    status = (outcome.status if outcome is not None
              else registry.INCONCLUSIVE)
    if decision.mismatch:
        # The observation itself may be perfectly well established; it
        # is the CLASS that was wrong. A header that was read is a
        # confirmed header, reported as what it is.
        if observation.kind in (HEADER_VALUE, RESPONSE_BODY, COMPONENT,
                                CIPHER_CONFIG) and (
                observation.extracted or observation.http_status):
            status = registry.CONFIRMED if \
                detector.observation_is_self_evident else registry.POTENTIAL
    # A self-evident observation has no middle ground. Either the thing
    # was read back — a header and its value, say — and the observation
    # is settled, or it was not and we are repeating what the scanner
    # claimed. "Potential" sits between those and belongs to neither: on
    # a header it reads as a potential VULNERABILITY, which is the exact
    # conflation this detector exists to stop. So it collapses to
    # Inconclusive unless a check actually ran and established it.
    if (detector.observation_is_self_evident
            and status == registry.POTENTIAL
            and not (outcome is not None and outcome.verified
                     and outcome.status == registry.CONFIRMED)):
        status = registry.INCONCLUSIVE
        decision.notes.append(
            "the observation was not independently read back, so it is "
            "reported as inconclusive rather than potential — what is "
            "uncertain is the observation, not an exploit")

    decision.status = status
    decision.status_label = risk.status_label(status)

    # ── stage 6: risk ───────────────────────────────────────────────────
    impact = library.get("severity") or detector.severity_if_confirmed
    if decision.mismatch:
        # Never inherit the impact of the class that was rejected.
        impact = detector.severity_unconfirmed or "INFO"
    severity, impact_if_real, note = risk.assess(
        impact, status, vuln_class=issue_key,
        scanner_severity=decision.scanner_severity, verified=verified)
    decision.severity = severity
    decision.impact_if_real = impact_if_real
    if note:
        decision.notes.append(note)

    # ── stage 7: explanation ────────────────────────────────────────────
    context = dict(explanation_context or {})
    decision.explanation = explanations.explain(issue_key, **context) \
        if context else None
    if decision.explanation is None and detector.explain_as:
        decision.explanation = explanations.explain(detector.explain_as,
                                                    **context)
    decision.summary = (decision.explanation.text()
                        if decision.explanation is not None
                        else (outcome.summary if outcome is not None else ""))

    decision.evidence = list(outcome.evidence) if outcome is not None else []
    if observation.extracted:
        decision.evidence.append(
            "extracted by the scanner: "
            + ", ".join(observation.extracted)[:300])
    if decision.mismatch:
        decision.evidence.append(f"classification note: {why_not}")

    # ── stage 8: display ────────────────────────────────────────────────
    #
    # Nothing is deleted. A rejected class becomes the observation it
    # really is, and an observation with nothing behind it becomes
    # context rather than a row claiming a vulnerability.
    if decision.severity == "INFO" and status in (
            registry.INFORMATIONAL, registry.INCONCLUSIVE) and \
            not observation.executed:
        decision.display = "context"
    return decision
