"""
Severity is impact. Confirmation is confidence. They are not the same
number, and the reported rating has to come from both.

The failure this corrects: a nuclei template rated INFO by nuclei
matched, a classification mapping associated it with command injection,
command injection's library severity is CRITICAL, and the finding was
published as CRITICAL. Nothing in that chain asked what had been
demonstrated.

Three inputs, three separate jobs:

  SCANNER SEVERITY      metadata, kept for traceability, never the answer
  IMPACT IF REAL        what this class of problem is worth when it holds
  CONFIRMATION          what the evidence actually establishes

The reported rating is the impact, capped by the confirmation. A
CRITICAL class that nothing has confirmed is not reported as CRITICAL;
it is reported at what the evidence carries, with the impact stated
beside it so the ceiling is visible rather than hidden.
"""

from __future__ import annotations

from command_bridge.modules import detector_registry as registry

ORDER = ("INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL")
RANK = {name: index for index, name in enumerate(ORDER)}

#: How far a rating may rise on each confirmation status. This is the
#: whole mechanism: a signature match cannot be reported at the impact
#: of a proven exploit, whatever the class.
#:
#: CONFIRMED     — the behaviour was observed; the class's impact stands.
#: POTENTIAL     — real evidence, short of demonstrating the behaviour.
#: INCONCLUSIVE  — a detection that verification did not support.
#: INFORMATIONAL — an observation; nothing is claimed.
CEILING = {
    registry.CONFIRMED: "CRITICAL",
    registry.POTENTIAL: "MEDIUM",
    registry.INCONCLUSIVE: "LOW",
    registry.INFORMATIONAL: "INFO",
}

#: A class whose impact only exists once it is demonstrated. For these,
#: an unconfirmed finding is not "a smaller version of the same thing" —
#: there may be no vulnerability at all, so the floor is lower.
NEEDS_DEMONSTRATION = frozenset({
    "command_injection", "sqli", "xss_reflected", "xss_stored", "xss_dom",
    "ssrf", "xxe", "ssti", "deserialization", "lfi", "rfi", "traversal",
    "auth_bypass", "idor", "code_injection", "file_upload",
})


def normalise(severity, default="INFO"):
    value = str(severity or "").strip().upper()
    if value in ("INFORMATIONAL", "INFORMATION", "NONE", "UNKNOWN", ""):
        return default if value == "" else "INFO"
    return value if value in RANK else default


def cap(severity, ceiling):
    """``severity``, but no higher than ``ceiling``."""
    severity, ceiling = normalise(severity), normalise(ceiling, "CRITICAL")
    return severity if RANK[severity] <= RANK[ceiling] else ceiling


def assess(issue_severity, status, *, vuln_class="", scanner_severity="",
           verified=False):
    """``(reported, impact, note)`` for one finding.

    ``reported`` is what goes in the Risk Rating column. ``impact`` is
    what the class is worth if it holds, kept so the finding can say
    "Medium — High if confirmed" rather than quietly losing the stakes.
    ``note`` explains the cap in one line, or is "" when none applied.
    """
    impact = normalise(issue_severity, "MEDIUM")
    status = str(status or registry.INCONCLUSIVE).upper()
    ceiling = CEILING.get(status, "LOW")

    # A class that only exists once demonstrated drops an extra step when
    # nothing demonstrated it. An unproven "SQL injection" is not a
    # medium SQL injection; it is a lead.
    if (vuln_class in NEEDS_DEMONSTRATION
            and status in (registry.POTENTIAL, registry.INCONCLUSIVE)):
        ceiling = "LOW" if status == registry.POTENTIAL else "INFO"

    reported = cap(impact, ceiling)
    note = ""
    if RANK[reported] < RANK[impact]:
        if status == registry.CONFIRMED:
            note = ""
        elif verified:
            note = (f"{impact} if confirmed — verification ran and did not "
                    f"establish it, so it is reported at {reported}.")
        else:
            note = (f"{impact} if confirmed — nothing has demonstrated it "
                    f"yet, so it is reported at {reported}.")
    return reported, impact, note


def label(reported, status):
    """The Risk Rating cell: "High", or "Low (High if confirmed)"."""
    pretty = {"INFO": "Informational"}.get(reported,
                                           reported.capitalize())
    return pretty if status == registry.CONFIRMED else pretty


def status_label(status):
    """The Confirmation Status cell, in the application's vocabulary."""
    return {
        registry.CONFIRMED: "Confirmed",
        registry.POTENTIAL: "Potential",
        registry.INCONCLUSIVE: "Inconclusive",
        registry.INFORMATIONAL: "Informational",
    }.get(str(status or "").upper(), "Inconclusive")
