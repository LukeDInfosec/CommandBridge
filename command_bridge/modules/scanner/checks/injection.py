"""
Command injection, server-side template injection and code evaluation.

These three are grouped because they share one confirmation idea: make the
server compute something it could only compute by *executing* what was sent,
and look for the answer in the response. Nothing harmful is run — the proof is
arithmetic.

  * **Template injection** sends ``${7*191}`` and its relatives and looks for
    1337 in the response. Each engine has its own syntax, and the syntax that
    works identifies the engine, which is worth knowing: Jinja2 and Freemarker
    are a short step from code execution, Smarty and Twig are further.

  * **Code evaluation** does the same for a language's own expression syntax.

  * **Command injection** tries arithmetic through the shell where it can, and
    otherwise falls back to a timed sleep — again only accepted when the delay
    scales with the number in the payload.

The echo-based proofs are strong: no error handler, cache or WAF produces the
number 1337 in response to ``${7*191}`` by accident. The timed proof is
weaker, so it is confirmed twice before it is reported.
"""

from __future__ import annotations

import re

from command_bridge.modules.scanner.model import Evidence, ScanFinding, \
    response_summary
from command_bridge.modules.scanner import oracles

#: 7 * 191 = 1337, which does not appear on a normal page the way 49 does.
CANARY_RESULT = "1337"

TEMPLATE_PAYLOADS = (
    ("Jinja2 / Twig", "{{7*191}}"),
    ("Jinja2 (statement)", "{{'7'*1}}{{7*191}}"),
    ("Freemarker", "${7*191}"),
    ("Velocity", "#set($x=7*191)$x"),
    ("ERB / Ruby", "<%= 7*191 %>"),
    ("Smarty", "{7*191}"),
    ("Handlebars-style", "{{#with 7}}{{/with}}{{7*191}}"),
    ("Angular / Vue", "{{constructor.constructor('return 7*191')()}}"),
)

CODE_PAYLOADS = (
    ("PHP", ";print(7*191);"),
    ("PHP", "');print(7*191);//"),
    ("Python", "'+str(7*191)+'"),
    ("Ruby", "#{7*191}"),
    ("JavaScript", "';return 7*191;//"),
)

#: Separators that get a second command run. The command itself is the
#: harmless arithmetic below.
COMMAND_SEPARATORS = (";", "|", "||", "&&", "\n", "`{cmd}`", "$({cmd})")
COMMAND_ECHO = "expr 7 \\* 191"
COMMAND_TIME = "sleep {d}"
WINDOWS_TIME = "ping -n {d} 127.0.0.1"


class TemplateInjectionCheck:
    key = "ssti"
    name = "Server-side template injection"
    issue = "ssti"

    def applies(self, point, profile):
        return True

    def run(self, ctx, point, baseline):
        for engine, payload in TEMPLATE_PAYLOADS:
            request = point.build(payload, mode="replace")
            response = ctx.auth.send(request)
            if response is None:
                continue
            body = response.text or ""
            if CANARY_RESULT not in body:
                continue
            # The payload must not simply be echoed back: a page that reflects
            # {{7*191}} verbatim has not evaluated anything.
            if payload in body:
                continue
            confirm = point.build(payload.replace("7*191", "6*191"),
                                  mode="replace")
            second = ctx.auth.send(confirm)
            if second is None or "1146" not in (second.text or ""):
                continue
            return [ScanFinding(
                issue=self.issue,
                where=point.request.url,
                point=point.label(),
                confidence="confirmed",
                detail_extra=f"The template engine evaluated an expression "
                             f"supplied in this parameter. The syntax that "
                             f"worked points to {engine}. Two different "
                             f"expressions were evaluated correctly, so this "
                             f"is not a reflection.",
                evidence=[
                    Evidence(label=f"{payload} evaluated to {CANARY_RESULT}",
                             request=request.describe(),
                             response=response_summary(response, 300)),
                    Evidence(label="A second expression, to rule out a "
                                   "coincidence",
                             request=confirm.describe(),
                             response=response_summary(second, 300),
                             note="6*191 = 1146")])]
        return []


class CodeInjectionCheck:
    key = "code"
    name = "Server-side code injection"
    issue = "code_injection"

    def applies(self, point, profile):
        return True

    def run(self, ctx, point, baseline):
        for language, payload in CODE_PAYLOADS:
            for mode in ("append", "replace"):
                request = point.build(payload, mode)
                response = ctx.auth.send(request)
                if response is None:
                    continue
                body = response.text or ""
                if CANARY_RESULT in body and payload not in body:
                    return [ScanFinding(
                        issue=self.issue,
                        where=point.request.url,
                        point=point.label(),
                        confidence="confirmed",
                        detail_extra=f"An expression supplied in this "
                                     f"parameter was evaluated by the "
                                     f"application. The syntax suggests "
                                     f"{language}.",
                        evidence=[Evidence(
                            label=f"{payload} evaluated to {CANARY_RESULT}",
                            request=request.describe(),
                            response=response_summary(response, 300))])]
        return []


class CommandInjectionCheck:
    key = "cmdi"
    name = "OS command injection"
    issue = "command_injection"

    def applies(self, point, profile):
        return True

    def run(self, ctx, point, baseline):
        echoed = self._echo(ctx, point)
        if echoed:
            return [echoed]
        if ctx.profile.timing_checks:
            timed = self._timed(ctx, point, baseline)
            if timed:
                return [timed]
        return []

    def _echo(self, ctx, point):
        """Run harmless arithmetic through the shell and look for the answer."""
        for separator in COMMAND_SEPARATORS:
            payload = (separator.format(cmd=COMMAND_ECHO)
                       if "{cmd}" in separator
                       else f"{separator} {COMMAND_ECHO}")
            for mode in ("append", "replace"):
                request = point.build(payload, mode)
                response = ctx.auth.send(request)
                if response is None:
                    continue
                body = response.text or ""
                if CANARY_RESULT not in body or payload in body:
                    continue
                shell_error = oracles.COMMAND_ERRORS.search(body)
                return ScanFinding(
                    issue=self.issue,
                    where=point.request.url,
                    point=point.label(),
                    confidence="confirmed",
                    detail_extra="A second command supplied in this parameter "
                                 "was executed by the shell: its output "
                                 f"({CANARY_RESULT}) appears in the response. "
                                 "The command used was arithmetic and did "
                                 "nothing to the host."
                                 + (" The response also contains shell error "
                                    "output." if shell_error else ""),
                    evidence=[Evidence(
                        label=f"Injected with '{separator}'",
                        request=request.describe(),
                        response=response_summary(response, 400),
                        note=f"`{COMMAND_ECHO}` printed {CANARY_RESULT}")])
        return None

    def _timed(self, ctx, point, baseline):
        timing = oracles.Timing(ctx.auth, baseline, ctx.profile.delay_seconds)
        for separator in (";", "|", "&&", "`{cmd}`", "$({cmd})"):
            for command in (COMMAND_TIME, WINDOWS_TIME):
                template = (separator.format(cmd=command)
                            if "{cmd}" in separator
                            else f"{separator} {command}")
                for mode in ("append", "replace"):
                    result = timing.test(point, template, mode)
                    if not result:
                        continue
                    return ScanFinding(
                        issue=self.issue,
                        where=point.request.url,
                        point=point.label(),
                        confidence="confirmed",
                        detail_extra=(
                            f"A sleep command supplied in this parameter was "
                            f"executed: asking for {result['short_delay']}s "
                            f"took {result['short_time']}s and asking for "
                            f"{result['long_delay']}s took "
                            f"{result['long_time']}s, against a normal "
                            f"response time of {result['baseline_median']}s. "
                            f"The response itself is unchanged, so this would "
                            f"not be visible to anybody reading the page."),
                        evidence=[
                            Evidence(label=f"{result['short_delay']}s "
                                           f"requested → "
                                           f"{result['short_time']}s",
                                     request=result["short_request"].describe()),
                            Evidence(label=f"{result['long_delay']}s "
                                           f"requested → "
                                           f"{result['long_time']}s",
                                     request=result["long_request"].describe(),
                                     note=f"Normal responses never exceeded "
                                          f"{result['baseline_ceiling']}s.")])
        return None
