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

  3. **Timing** — for the blind case where nothing about the response changes.
     Only accepted when the delay scales with the number in the payload, which
     is what separates an injection from a slow endpoint.

Payloads are appended to the real value rather than replacing it, because a
query that finds no row cannot demonstrate a difference between true and
false.
"""

from __future__ import annotations

from command_bridge.modules.scanner.model import Evidence, ScanFinding, \
    response_summary
from command_bridge.modules.scanner import oracles

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

        if not (boolean or error or timing):
            return findings

        evidence, notes = [], []
        confidence = "tentative"

        if boolean:
            confidence = "confirmed"
            notes.append("The application evaluated a condition supplied in "
                         "this parameter: the true form returned the original "
                         "page and the false form did not.")
            for result in boolean[:2]:
                evidence.append(Evidence(
                    label="Condition true — page returned as normal",
                    request=result["true_request"].describe(),
                    response=response_summary(result["true_response"], 400)))
                evidence.append(Evidence(
                    label="Condition false — page changed",
                    request=result["false_request"].describe(),
                    response=response_summary(result["false_response"], 400),
                    note=f"similarity between the two responses: "
                         f"{result['pair_similarity']}"))

        if timing:
            confidence = "confirmed"
            notes.append(
                f"The response time tracked the delay requested in the "
                f"payload: {timing['short_delay']}s produced "
                f"{timing['short_time']}s and {timing['long_delay']}s produced "
                f"{timing['long_time']}s, against a normal response time of "
                f"{timing['baseline_median']}s.")
            evidence.append(Evidence(
                label=f"Delay {timing['short_delay']}s → "
                      f"{timing['short_time']}s",
                request=timing["short_request"].describe()))
            evidence.append(Evidence(
                label=f"Delay {timing['long_delay']}s → {timing['long_time']}s",
                request=timing["long_request"].describe(),
                note=f"This endpoint never took longer than "
                     f"{timing['baseline_ceiling']}s when left alone."))

        if error:
            engine, excerpt, request, response = error
            notes.append(f"The {engine} parser reported a syntax error when "
                         f"the value was modified.")
            evidence.append(Evidence(
                label=f"{engine} error",
                request=request.describe(),
                response=response_summary(response, 300),
                note=excerpt))
            if confidence == "tentative":
                confidence = "firm"

        findings.append(ScanFinding(
            issue=self.issue,
            where=point.request.url,
            point=point.label(),
            evidence=evidence,
            confidence=confidence,
            detail_extra=" ".join(notes)))
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
                return engine, excerpt, request, response
        return None

    def _timing(self, ctx, point, baseline):
        timing = oracles.Timing(ctx.auth, baseline, ctx.profile.delay_seconds)
        for _engine, template in TIME_TEMPLATES:
            result = timing.test(point, template, mode="append")
            if result:
                return result
        return None
