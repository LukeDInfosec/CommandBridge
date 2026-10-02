#!/usr/bin/env python3
"""What counts as proof, per vulnerability class.

This exists because of one finding:

    SQL Injection  [CONFIRMED]  CRITICAL
    Parameter: header 'X-Original-URL'
    Normal response: 3.43s   5s payload: 4.59s   10s payload: 8.58s

Nothing in that is proof of SQL injection. The application's own baseline was
three and a half seconds, the "five second" payload added 1.16s, and the whole
observation is equally consistent with a slow server, a lock, a cold cache, a
proxy, or a neighbour's backup job. Presenting it as a confirmed critical is
worse than missing it, because a tester who checks two of those and finds
nothing stops reading the rest of the report.

The old logic was a single line — ``if timing: confidence = "confirmed"`` —
and it was wrong in a way that a tweak cannot fix, because the mistake is
structural: the checks were deciding their own confidence, each with its own
ad-hoc rule, and nothing in the system knew the difference between *seeing
something interesting* and *proving something*.

So confidence is no longer something a check sets. A check reports the KIND of
evidence it obtained, and this module derives the confidence from it, using a
policy written per vulnerability class. The question behind every entry in
that policy is the one a tester asks:

    What would convince an experienced pentester that this is real?

For SQL injection, that is a database error naming the engine, a reproducible
boolean differential, or data that could only have come from the database. A
stopwatch is not on the list.

Severity and confidence are kept apart. A potentially critical finding with
low confidence is an honest and useful thing to report; "CONFIRMED CRITICAL"
on a stopwatch reading is not.
"""

from __future__ import annotations

# ─────────────────────────────────────────────────────────────────────────────
#  Grades of evidence
# ─────────────────────────────────────────────────────────────────────────────
#
# Ordered by how hard they are to explain away. The ordering is the whole
# argument: anything above DIFFERENTIAL cannot plausibly be produced by an
# application behaving normally, and anything at TIMING or below routinely is.

OAST = "oast"                    # the target contacted infrastructure we own
EXECUTION = "execution"          # a unique marker we generated came back
DATA = "data"                    # data that could only come from the backend
ERROR = "error"                  # an engine-specific error signature
DIFFERENTIAL = "differential"    # a reproduced, controlled behavioural split
EXECUTABLE_CONTEXT = "executable_context"   # reflection where it would run
OBSERVATION = "observation"      # a direct, unambiguous protocol observation
TIMING = "timing"                # the response took longer
REFLECTION = "reflection"        # the input came back, somewhere
ACCEPTED = "accepted"            # the payload was not rejected

#: Human names, for the report.
GRADE_NAMES = {
    OAST: "out-of-band interaction",
    EXECUTION: "server-side execution marker",
    DATA: "backend-derived data",
    ERROR: "engine-specific error signature",
    DIFFERENTIAL: "reproduced behavioural differential",
    EXECUTABLE_CONTEXT: "reflection in an executable context",
    OBSERVATION: "direct protocol observation",
    TIMING: "response-time anomaly",
    REFLECTION: "input reflected in the response",
    ACCEPTED: "payload accepted without visible effect",
}

#: What each grade is worth on its own, before the per-class policy is applied.
STRENGTH = {
    OAST: 100, EXECUTION: 100, DATA: 100,
    ERROR: 70, DIFFERENTIAL: 70, EXECUTABLE_CONTEXT: 55, OBSERVATION: 80,
    TIMING: 25, REFLECTION: 15, ACCEPTED: 0,
}

# ─────────────────────────────────────────────────────────────────────────────
#  Confidence
# ─────────────────────────────────────────────────────────────────────────────

CONFIRMED = "confirmed"
LIKELY = "likely"
POTENTIAL = "potential"
INCONCLUSIVE = "inconclusive"

CONFIDENCE_ORDER = (INCONCLUSIVE, POTENTIAL, LIKELY, CONFIRMED)

CONFIDENCE_BLURB = {
    CONFIRMED: ("Reproducible, vulnerability-specific evidence was obtained. "
                "A tester can replay the request below and see the same "
                "thing."),
    LIKELY: ("More than one test points the same way, but the scanner did not "
             "obtain a single piece of evidence that rules out normal "
             "application behaviour. Verify before reporting."),
    POTENTIAL: ("Something behaved unusually. This is a lead, not a finding. "
                "It is recorded so it can be looked at by hand, and it should "
                "not go in a report in this state."),
    INCONCLUSIVE: ("The scanner could not tell this apart from the "
                   "application working normally."),
}


# ─────────────────────────────────────────────────────────────────────────────
#  Per-class policy
# ─────────────────────────────────────────────────────────────────────────────
#
# ``decisive``   any one of these confirms the class on its own.
# ``supporting`` two or more of these together make it Likely; one alone is
#                Potential.
# ``never``      these can never raise confidence above Potential, whatever
#                else is present alongside them. Timing is in this list for
#                every class that has it, which is the point of the file.
# ``verify``     what the tester should do by hand when it is not confirmed.

POLICY = {
    "sqli": {
        "decisive": (ERROR, DATA, DIFFERENTIAL, OAST),
        "supporting": (TIMING,),
        "never": (TIMING, REFLECTION, ACCEPTED),
        "verify": ("Replay the request with sqlmap, or by hand with a "
                   "condition that returns a value you can read — "
                   "a database error, a version string, or a page that "
                   "changes for 1=1 and not for 1=2. A delay on its own is "
                   "not reportable."),
    },
    "command_injection": {
        "decisive": (EXECUTION, OAST, DATA),
        "supporting": (ERROR, TIMING),
        "never": (TIMING, REFLECTION, ACCEPTED),
        "verify": ("Re-send the proven request with a command whose output "
                   "you can see — `id`, `whoami`, `uname -a`. If nothing "
                   "comes back in the response, use an out-of-band callback. "
                   "A delay alone proves nothing."),
    },
    "ssti": {
        "decisive": (EXECUTION, DATA, OAST),
        "supporting": (ERROR,),
        "never": (REFLECTION, TIMING, ACCEPTED),
        "verify": ("Send an arithmetic expression in the template syntax the "
                   "engine uses and check the ANSWER comes back rather than "
                   "the expression. Reflection of `{{7*191}}` is not SSTI; "
                   "`1337` coming back is."),
    },
    "code_injection": {
        "decisive": (EXECUTION, DATA, OAST),
        "supporting": (ERROR,),
        "never": (REFLECTION, TIMING, ACCEPTED),
        "verify": ("Confirm the expression is evaluated rather than echoed, "
                   "with a second, different expression."),
    },
    "xss_reflected": {
        "decisive": (EXECUTION,),
        "supporting": (EXECUTABLE_CONTEXT, REFLECTION),
        "never": (REFLECTION, TIMING, ACCEPTED),
        "verify": ("Open the URL in a browser and confirm "
                   "`alert(document.domain)` actually fires. Reflection in an "
                   "executable context is a strong lead; execution is the "
                   "finding."),
    },
    "xss_stored": {
        "decisive": (EXECUTION,),
        "supporting": (EXECUTABLE_CONTEXT, REFLECTION),
        "never": (REFLECTION, TIMING, ACCEPTED),
        "verify": ("View the page that renders the stored value in a browser "
                   "and confirm the payload executes."),
    },
    "traversal": {
        "decisive": (DATA,),
        "supporting": (ERROR, DIFFERENTIAL),
        "never": (REFLECTION, TIMING, ACCEPTED),
        "verify": ("Confirm the response contains the contents of a file "
                   "outside the web root, not merely a different error."),
    },
    "file_inclusion": {
        "decisive": (DATA, EXECUTION),
        "supporting": (ERROR,),
        "never": (REFLECTION, TIMING, ACCEPTED),
        "verify": ("Confirm the included file's contents or its execution, "
                   "not just a changed response."),
    },
    "open_redirect": {
        "decisive": (OBSERVATION,),
        "supporting": (REFLECTION,),
        "never": (TIMING, ACCEPTED),
        "verify": ("Follow the redirect in a browser and confirm it leaves "
                   "the application's own origin."),
    },
    "access_control": {
        "decisive": (DIFFERENTIAL,),
        "supporting": (OBSERVATION,),
        "never": (TIMING, REFLECTION, ACCEPTED),
        "verify": ("Replay the request as each identity side by side and "
                   "confirm the unauthorised one really receives the "
                   "protected content rather than a shared page."),
    },
    # The three policies below are declared but have no detector behind them
    # yet. The Active Scan does not test for SSRF, XXE or unsafe
    # deserialization at all, so it will never raise one of these — the
    # entries exist so that a finding imported from another tool is graded by
    # the same rules, and so that nothing can be reported as confirmed on an
    # accepted URL, an accepted XML document or a deserializer exception.
    # Said plainly rather than left to be inferred from an empty report.
    "ssrf": {
        "decisive": (OAST, DATA),
        "supporting": (ERROR, TIMING, DIFFERENTIAL),
        "never": (TIMING, REFLECTION, ACCEPTED),
        "verify": ("Point the parameter at a collaborator host you control "
                   "and confirm an inbound request arrives from the target's "
                   "infrastructure. A URL being accepted is not SSRF."),
    },
    "xxe": {
        "decisive": (OAST, DATA),
        "supporting": (ERROR,),
        "never": (TIMING, REFLECTION, ACCEPTED),
        "verify": ("Confirm an external entity is actually resolved — either "
                   "a local file's contents in the response or an outbound "
                   "request to a host you control. XML being accepted is not "
                   "XXE."),
    },
    "deserialization": {
        "decisive": (OAST, EXECUTION, DATA),
        "supporting": (ERROR, TIMING),
        "never": (TIMING, REFLECTION, ACCEPTED, ERROR),
        "verify": ("An exception from a deserializer is not proof the data "
                   "was deserialized in an exploitable way. Confirm with a "
                   "controlled gadget that produces an out-of-band callback."),
    },
}

#: Classes with no entry fall back to this: something decisive, or it is a
#: lead. Erring towards under-claiming is deliberate.
DEFAULT_POLICY = {
    "decisive": (OAST, EXECUTION, DATA, OBSERVATION),
    "supporting": (ERROR, DIFFERENTIAL, EXECUTABLE_CONTEXT),
    "never": (TIMING, REFLECTION, ACCEPTED),
    "verify": "Reproduce the request by hand and confirm what the scanner saw.",
}


def policy_for(issue):
    return POLICY.get(issue, DEFAULT_POLICY)


# ─────────────────────────────────────────────────────────────────────────────
#  One piece of evidence
# ─────────────────────────────────────────────────────────────────────────────

class Signal:
    """One thing the scanner observed, and what kind of thing it is.

    ``detail`` is the sentence that goes in the report. ``measurements`` holds
    the raw numbers behind it, kept separately so the raw-detection block can
    show exactly what was measured without the interpretation wrapped around
    it.
    """

    __slots__ = ("grade", "detail", "measurements", "reproduced")

    def __init__(self, grade, detail, measurements=None, reproduced=False):
        self.grade = grade
        self.detail = detail
        self.measurements = dict(measurements or {})
        #: Whether the observation was seen more than once. A differential
        #: that happened once is a coincidence; one that repeats is evidence.
        self.reproduced = bool(reproduced)

    def __repr__(self):                                 # pragma: no cover
        return f"<Signal {self.grade} {self.detail[:40]!r}>"

    def as_dict(self):
        return {"grade": self.grade, "name": GRADE_NAMES.get(self.grade, ""),
                "detail": self.detail, "measurements": self.measurements,
                "reproduced": self.reproduced}


# ─────────────────────────────────────────────────────────────────────────────
#  The verdict
# ─────────────────────────────────────────────────────────────────────────────

class Verdict:
    """Confidence, and the reasoning that produced it."""

    def __init__(self, issue, confidence, signals, rationale, limitations,
                 verification):
        self.issue = issue
        self.confidence = confidence
        self.signals = list(signals)
        self.rationale = rationale
        self.limitations = list(limitations)
        self.verification = verification

    @property
    def grades(self):
        return [s.grade for s in self.signals]

    @property
    def detection_method(self):
        if not self.signals:
            return "none"
        return ", ".join(dict.fromkeys(
            GRADE_NAMES.get(s.grade, s.grade) for s in self.signals))

    def as_dict(self):
        return {"confidence": self.confidence,
                "rationale": self.rationale,
                "limitations": self.limitations,
                "verification": self.verification,
                "detection_method": self.detection_method,
                "signals": [s.as_dict() for s in self.signals]}


def grade(issue, signals):
    """Derive the confidence for one finding from the evidence behind it.

    The rules, in order:

      1. A decisive signal for this class confirms it — but a *differential*
         only counts as decisive when it was actually reproduced, because a
         single pair of responses that differ is how a page with a timestamp
         in it looks.
      2. Anything in the class's ``never`` list is capped at Potential, no
         matter how many of them there are. Three stopwatch readings are one
         stopwatch reading.
      3. Two or more independent supporting signals make it Likely.
      4. One supporting signal is Potential.
      5. Nothing usable is Inconclusive.
    """
    rules = policy_for(issue)
    signals = [s for s in signals if s is not None]
    present = {s.grade for s in signals}
    limitations = []

    if not signals:
        return Verdict(issue, INCONCLUSIVE, signals,
                       "No evidence was captured for this finding.",
                       ["Nothing was recorded that could be assessed."],
                       rules["verify"])

    decisive = [s for s in signals if s.grade in rules["decisive"]]
    # A differential has to have been reproduced to be decisive. One
    # observation of a difference is not a controlled experiment.
    unreproduced = [s for s in decisive
                    if s.grade == DIFFERENTIAL and not s.reproduced]
    decisive = [s for s in decisive if s not in unreproduced]
    for item in unreproduced:
        limitations.append(
            "The behavioural difference was seen once and not re-tested, so "
            "it could be the page varying by itself.")

    weak_only = present and present <= set(rules["never"])

    if decisive:
        names = ", ".join(dict.fromkeys(GRADE_NAMES.get(s.grade, s.grade)
                                        for s in decisive))
        rationale = (f"Confirmed by {names}. "
                     + " ".join(s.detail for s in decisive))
        if weak_only:                       # cannot happen, but be explicit
            rationale += " "
        for signal in signals:
            if signal.grade in rules["never"]:
                limitations.append(
                    f"A {GRADE_NAMES.get(signal.grade, signal.grade)} was also "
                    f"observed; on its own it would not have been enough and "
                    f"it is not what this finding rests on.")
        return Verdict(issue, CONFIRMED, signals, rationale, limitations,
                       rules["verify"])

    if weak_only:
        names = ", ".join(dict.fromkeys(GRADE_NAMES.get(s.grade, s.grade)
                                        for s in signals))
        limitations.append(
            f"The only evidence is {names}, which an application that is "
            f"slow, loaded, locked or behind a proxy can produce without any "
            f"vulnerability being present.")
        return Verdict(
            issue, POTENTIAL, signals,
            f"Observed {names}, and nothing that distinguishes it from the "
            f"application behaving normally. "
            + " ".join(s.detail for s in signals),
            limitations, rules["verify"])

    supporting = [s for s in signals if s.grade in rules["supporting"]
                  and s.grade not in rules["never"]]
    distinct = {s.grade for s in supporting}
    if len(distinct) >= 2:
        return Verdict(
            issue, LIKELY, signals,
            "Two independent tests point the same way: "
            + " ".join(s.detail for s in supporting),
            limitations + ["No single piece of evidence rules out normal "
                           "application behaviour on its own."],
            rules["verify"])

    if supporting:
        return Verdict(
            issue, POTENTIAL, signals,
            " ".join(s.detail for s in supporting),
            limitations + ["Only one indicator was obtained."],
            rules["verify"])

    names = ", ".join(dict.fromkeys(GRADE_NAMES.get(s.grade, s.grade)
                                    for s in signals))
    return Verdict(
        issue, POTENTIAL, signals,
        f"Observed {names}. " + " ".join(s.detail for s in signals),
        limitations + [f"{names} is not specific to this vulnerability."],
        rules["verify"])


# ─────────────────────────────────────────────────────────────────────────────
#  Severity, kept separate from confidence
# ─────────────────────────────────────────────────────────────────────────────

def severity_label(severity, confidence):
    """How to print the severity next to a confidence.

    A critical vulnerability that has not been proved is still potentially
    critical, and saying so is more useful than either silently downgrading it
    or printing CRITICAL beside a stopwatch reading. The two stay separate and
    the wording makes the relationship explicit.
    """
    severity = (severity or "INFO").upper()
    if confidence == CONFIRMED:
        return severity
    if confidence == INCONCLUSIVE:
        return f"{severity} if real"
    return f"Potentially {severity.capitalize()}"


# ─────────────────────────────────────────────────────────────────────────────
#  Authentication context
# ─────────────────────────────────────────────────────────────────────────────

def auth_context(ctx):
    """How the scan was authenticated when a finding was made.

    Recorded on every finding, because the same bug means different things
    depending on who can reach it. SQL injection on a public search box and
    the same injection behind an administrator login are not the same report,
    and a reader who cannot tell which one they are looking at cannot triage
    it.
    """
    auth = getattr(ctx, "auth", None)
    config = getattr(auth, "config", None)
    outcome = getattr(auth, "outcome", None)
    if config is None or getattr(config, "strategy", "none") == "none":
        return {"authenticated": False, "method": "none",
                "state": "unauthenticated", "identity": "", "label":
                "Unauthenticated"}
    state = getattr(outcome, "state", "unknown")
    method = getattr(outcome, "method", "") or getattr(config, "strategy", "")
    authenticated = bool(getattr(auth, "logged_in", False)) and \
        state in ("ok", "unverified")
    label = "Authenticated" if authenticated else "Unauthenticated"
    if state == "unverified":
        label = "Authenticated (never verified)"
    elif state == "lost":
        label = "Session lost during the scan"
    return {
        "authenticated": authenticated,
        "method": method,
        "state": state,
        "identity": getattr(config, "name", ""),
        "verification_url": getattr(config, "check_url", ""),
        "label": label,
    }
