"""
What sqlmap actually concluded.

This exists because of a false positive that is worth describing in full,
since the shape of it recurs.

sqlmap was run against an endpoint. It tested every technique it has and
ended with:

    [WARNING] (custom) POST parameter '#1*' does not seem to be injectable
    [CRITICAL] all tested parameters do not appear to be injectable.

Command Bridge printed:

    [+] SQL INJECTION FOUND — DBMS: Unknown — PARAMETER: #1* — CRITICAL

Two separate mistakes produced that, and neither was subtle once found:

  1. The old line scanner flagged a finding on any line containing the
     substring "stacked queries". sqlmap prints

         [INFO] testing 'Microsoft SQL Server/Sybase stacked queries (comment)'

     while *announcing a test it is about to run*. Every sqlmap run that got
     as far as the stacked-queries phase — which is to say nearly all of
     them — was therefore reported as a confirmed critical SQL injection.

  2. "[CRITICAL]" was read as a vulnerability severity. In sqlmap it is a
     log level, and the single most common line it appears on is the one
     saying nothing was injectable.

So the tool was reading sqlmap's *narration* and inferring a verdict from
it. The fix is the same principle the Active Scan was rebuilt on: do not
infer a conclusion from prose when the tool states its conclusion outright.

sqlmap's verdict is explicit and machine-readable. On success it prints a
block that cannot be mistaken for anything else:

    sqlmap identified the following injection point(s) with a total of 71 HTTP(s) requests:
    ---
    Parameter: id (GET)
        Type: boolean-based blind
        Title: AND boolean-based blind - WHERE or HAVING clause
        Payload: id=1 AND 4821=4821
    ---
    [INFO] the back-end DBMS is MySQL

On failure it says so, equally plainly. This module reads those, and
nothing else. A line that merely mentions a technique is narration and is
ignored, however alarming the words in it are.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

#: sqlmap's own statements that it found nothing. These are authoritative and
#: they *clear* any earlier suspicion: a run that ends on one of these found
#: nothing, whatever was printed while it was working.
NEGATIVE = (
    re.compile(r"all tested parameters (?:do not|don't) appear to be injectable",
               re.I),
    re.compile(r"all parameters appear to be not injectable", re.I),
    re.compile(r"does ?n[o']t seem to be injectable", re.I),
    re.compile(r"does not appear to be injectable", re.I),
    re.compile(r"might not be injectable", re.I),
    re.compile(r"unable to retrieve page content", re.I),
    re.compile(r"no parameter\(s\) found for testing", re.I),
)

#: The only line that means sqlmap confirmed something.
IDENTIFIED = re.compile(
    r"sqlmap identified the following injection point\(s\)", re.I)

#: The verdict block's own fields. "Parameter:" at the start of a line, inside
#: the --- delimited block, is structure; the same word in a sentence is not.
BLOCK_PARAM = re.compile(r"^\s*Parameter:\s*(.+?)\s*$")
BLOCK_TYPE = re.compile(r"^\s*Type:\s*(.+?)\s*$")
BLOCK_TITLE = re.compile(r"^\s*Title:\s*(.+?)\s*$")
BLOCK_PAYLOAD = re.compile(r"^\s*Payload:\s*(.+?)\s*$")

#: sqlmap states the DBMS only once it has established one.
DBMS = re.compile(r"back-end DBMS\s*(?:is\s*|:\s*)['\"]?([^'\"\n]+)", re.I)

#: Resuming a previous session still counts: the injection was confirmed, just
#: not during this run. Say so rather than hiding it.
RESUMED = re.compile(
    r"resumed|sqlmap resumed the following injection point\(s\) from stored session",
    re.I)

#: A line that is sqlmap narrating what it is about to do. Never evidence.
#: This is the rule that kills the original bug: "testing 'Oracle stacked
#: queries …'" is an announcement, not a result, and so is every other line
#: of this shape.
NARRATION = re.compile(
    r"^\s*(?:\[\d{2}:\d{2}:\d{2}\]\s*)?\[(?:INFO|DEBUG|PAYLOAD|TRAFFIC OUT|"
    r"TRAFFIC IN)\]\s*(?:testing|checking|searching|confirming|processing|"
    r"heuristic|trying|loading|fetched|flushing|parsing|using|resuming)",
    re.I)

#: Techniques whose confirmation genuinely raises the impact, read from the
#: verdict block's own Type/Title fields — never from a line that merely names
#: the technique while testing for it.
STACKED = re.compile(r"stacked quer", re.I)
FILE_ACCESS = re.compile(r"into (?:out|dump)file|file (?:read|write)|"
                         r"LOAD_FILE|xp_cmdshell|OS command", re.I)


@dataclass
class Injection:
    """One injection point sqlmap confirmed, with the proof it gave."""

    parameter: str = ""
    technique: str = ""
    title: str = ""
    payload: str = ""

    def summary(self):
        bits = [self.parameter or "(unnamed)"]
        if self.technique:
            bits.append(self.technique)
        return " — ".join(bits)


@dataclass
class Verdict:
    """What sqlmap concluded, and what it showed for it."""

    #: True only when sqlmap printed its injection-point block.
    confirmed: bool = False
    #: True when sqlmap explicitly said nothing was injectable.
    refuted: bool = False
    #: The confirmed injection points, in the order sqlmap listed them.
    injections: list = field(default_factory=list)
    dbms: str = ""
    #: Confirmed from the verdict block's own Type field, never from narration.
    stacked: bool = False
    file_access: bool = False
    #: True when the result came from a stored session rather than this run.
    resumed: bool = False
    #: How many separate sqlmap runs were seen in the output.
    runs: int = 0

    @property
    def severity(self):
        """CRITICAL only when a technique that earns it was confirmed.

        sqlmap's own ``[CRITICAL]`` log level is not consulted: it is a
        logging severity, and the line it appears on most often is the one
        reporting that nothing was injectable.
        """
        if not self.confirmed:
            return ""
        if self.stacked or self.file_access:
            return "CRITICAL"
        return "HIGH"

    @property
    def parameters(self):
        seen = []
        for item in self.injections:
            if item.parameter and item.parameter not in seen:
                seen.append(item.parameter)
        return seen

    def banner(self):
        """The one line to print when the run finishes, or "" for silence.

        Silence is the right output for a run that found nothing. The old
        code had no way to say that, which is half of why it over-claimed.
        """
        if not self.confirmed:
            return ""
        where = ", ".join(self.parameters) or "unnamed parameter"
        techniques = ", ".join(dict.fromkeys(
            i.technique for i in self.injections if i.technique))
        parts = [f"[+] SQL INJECTION CONFIRMED BY SQLMAP — PARAMETER: {where}"]
        if techniques:
            parts.append(f"TECHNIQUE: {techniques}")
        parts.append(f"DBMS: {self.dbms or 'not established'}")
        parts.append(self.severity)
        line = " — ".join(parts)
        if self.resumed:
            line += "  (resumed from a stored session, not re-tested this run)"
        return line

    def explain(self):
        """Why this verdict, in the words a tester needs. Never empty."""
        if self.confirmed:
            lines = ["sqlmap printed its injection-point block, which is the "
                     "only thing treated as confirmation."]
            for item in self.injections:
                lines.append(f"  Parameter: {item.parameter}")
                if item.title:
                    lines.append(f"    Title:   {item.title}")
                if item.payload:
                    lines.append(f"    Payload: {item.payload}")
            lines.append("Replay the payload above by hand before reporting "
                         "it.")
            return lines
        if self.refuted:
            return ["sqlmap tested the parameters and stated that none of "
                    "them appear to be injectable. Nothing is reported.",
                    "Lines naming techniques during the run ('testing "
                    "… stacked queries') are sqlmap announcing a test, "
                    "not a result."]
        return ["sqlmap did not state a verdict — the run may have been "
                "interrupted, or it could not reach the target. Nothing is "
                "reported; check the output above for the reason."]


def parse(output: str) -> Verdict:
    """Read sqlmap's output and return what it actually concluded.

    Handles an output file holding several runs appended together, which is
    the normal case when the same button is pressed more than once: the last
    run's verdict is the one that stands, so an earlier failed attempt cannot
    leak into a later result or the other way round.
    """
    verdict = Verdict()
    lines = (output or "").splitlines()

    # Split into runs. sqlmap announces each start, and an appended output
    # file otherwise reads as one long contradictory run.
    starts = [i for i, line in enumerate(lines)
              if re.search(r"starting @|parsing HTTP request from|"
                           r"^\s*___\s*$", line)]
    if starts:
        bounds = list(zip(starts, starts[1:] + [len(lines)]))
        # Output that begins mid-run — a log opened after the banner scrolled
        # past, or a chunk pasted in — still has to be read, not dropped.
        if starts[0] > 0:
            bounds.insert(0, (0, starts[0]))
    else:
        bounds = [(0, len(lines))]
    verdict.runs = len(bounds)

    for start, end in bounds:
        chunk = lines[start:end]
        result = _parse_run(chunk)
        # A confirmed run wins outright; otherwise the newest statement holds.
        if result.confirmed:
            result.runs = verdict.runs
            verdict = result
            verdict.runs = len(bounds)
        elif not verdict.confirmed:
            verdict.refuted = result.refuted
            verdict.dbms = result.dbms or verdict.dbms
    return verdict


def _parse_run(lines) -> Verdict:
    verdict = Verdict()
    in_block = False
    current = None

    for line in lines:
        if IDENTIFIED.search(line) or RESUMED.search(line):
            verdict.confirmed = True
            verdict.refuted = False
            in_block = True
            if RESUMED.search(line) and not IDENTIFIED.search(line):
                verdict.resumed = True
            continue

        # The DBMS is only stated once sqlmap has established one, so it is
        # worth recording wherever it appears — but on its own it is not a
        # finding. A fingerprint is not an injection.
        found = DBMS.search(line)
        if found:
            verdict.dbms = found.group(1).strip().rstrip(".")

        if NARRATION.search(line):
            # sqlmap saying what it is about to try. Never evidence — this
            # is the line that used to produce the false positive.
            continue

        for pattern in NEGATIVE:
            if pattern.search(line):
                if not verdict.confirmed:
                    verdict.refuted = True
                break

        if not in_block:
            continue

        match = BLOCK_PARAM.match(line)
        if match:
            current = Injection(parameter=match.group(1))
            verdict.injections.append(current)
            continue
        if current is None:
            continue
        match = BLOCK_TYPE.match(line)
        if match:
            current.technique = match.group(1)
            if STACKED.search(current.technique):
                verdict.stacked = True
            continue
        match = BLOCK_TITLE.match(line)
        if match:
            current.title = match.group(1)
            if STACKED.search(current.title):
                verdict.stacked = True
            if FILE_ACCESS.search(current.title):
                verdict.file_access = True
            continue
        match = BLOCK_PAYLOAD.match(line)
        if match:
            current.payload = match.group(1)
            if FILE_ACCESS.search(current.payload):
                verdict.file_access = True
            continue

    if verdict.confirmed and not verdict.injections:
        # It said it identified something but we could not read the block —
        # a truncated log, or a format change. Do not invent the detail.
        verdict.injections.append(Injection(parameter="(see sqlmap output)"))
    return verdict


def highlight_colour(line: str, verdict_so_far: Verdict) -> str:
    """The colour for one streamed line, or "" to leave it alone.

    Only the verdict block is coloured. Narration stays plain however
    dramatic its wording, because colouring a line that says "testing
    'stacked queries'" is what made the old output read as a finding even
    before the summary printed.
    """
    if NARRATION.search(line):
        return ""
    if IDENTIFIED.search(line) or RESUMED.search(line):
        return "#22c55e"
    for pattern in NEGATIVE:
        if pattern.search(line):
            return "#94a3b8"
    if verdict_so_far.confirmed and (BLOCK_PARAM.match(line)
                                     or BLOCK_TYPE.match(line)
                                     or BLOCK_TITLE.match(line)
                                     or BLOCK_PAYLOAD.match(line)):
        return "#22c55e"
    return ""
