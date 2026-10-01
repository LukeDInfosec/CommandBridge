#!/usr/bin/env python3
"""The active scanner, proved against an application with known bugs.

The last section is the one that matters. It runs a complete authenticated
scan against ``vulnerable_app.py`` — which contains seven planted
vulnerabilities and, beside each, a correct implementation of the same feature
— and asserts both halves:

    every planted bug is found     …and nothing is reported on the safe twins

A scanner that only proves the first half is a scanner that reports the safe
endpoints too, and one that only proves the second half is a scanner that
reports nothing. Both assertions are here, and the false-positive half has
caught more mistakes during this build than the other one.
"""

import json
import tempfile
import threading
import re
import sys
import time
import urllib.parse
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from command_bridge.modules.scanner import (                # noqa: E402
    AuthConfig, Authenticator, Profile, Request, ScanEngine, ScanFinding,
    build_scope, insertion_points)
from command_bridge.modules.scanner import oracles, report   # noqa: E402
from command_bridge.modules import cb_evidence                # noqa: E402
from command_bridge.modules.scanner.crawl import Scope, _plausible  # noqa: E402
from command_bridge.modules.scanner.model import json_points, json_set  # noqa: E402
from tests.vulnerable_app import start                      # noqa: E402

PASS = FAIL = 0


def check(label, got, want=True):
    global PASS, FAIL
    if got == want:
        PASS += 1
        print(f"  \033[32m✓\033[0m {label}")
    else:
        FAIL += 1
        print(f"  \033[31m✗\033[0m {label}  (got {got!r}, wanted {want!r})")


class FakeResponse:
    def __init__(self, text="", status=200, headers=None, url=""):
        self.text = text
        self.status_code = status
        self.reason = "OK"
        self.headers = headers or {}
        self.content = text.encode()
        self.url = url


class FakeAuth:
    """Answers from a table, so the oracles can be tested without a server."""

    def __init__(self, answers, delays=None):
        self.answers = answers
        self.delays = delays or {}
        self.sent = []

    def send(self, request, allow_redirects=False, timeout=None):
        self.sent.append(request.url)
        for needle, response in self.answers.items():
            if needle in request.url:
                delay = self.delays.get(needle, 0)
                if delay:
                    time.sleep(delay)
                return response
        return FakeResponse("default page body, unchanged")


def main():
    print("\n\033[1mRequests and insertion points\033[0m")
    request = Request("GET", "https://app.example/user/42/orders?id=7&sort=name")
    check("the query is parsed", dict(request.query), {"id": "7",
                                                       "sort": "name"})
    check("numeric path segments collapse into one shape",
          request.shape(),
          Request("GET", "https://app.example/user/99/orders?id=1&sort=x"
                  ).shape())
    check("a different parameter set is a different shape",
          request.shape() ==
          Request("GET", "https://app.example/user/1/orders?id=1").shape(),
          False)

    points = insertion_points(request)
    check("one point per query parameter", len(points), 2)
    built = points[0].build("PAYLOAD", "replace")
    check("replacing puts the payload in", dict(built.query)["id"], "PAYLOAD")
    check("and leaves the others alone", dict(built.query)["sort"], "name")
    built = points[0].build("PAYLOAD", "append")
    check("appending keeps the original value",
          dict(built.query)["id"], "7PAYLOAD")
    check("the original request is untouched", dict(request.query)["id"], "7")

    body = Request("POST", "https://app.example/save",
                   data=[("name", "x"), ("name", "y")])
    check("same-named body parameters are separate points",
          len(insertion_points(body)), 2)
    check("and only the targeted one changes",
          insertion_points(body)[1].build("Z", "replace").data,
          [("name", "x"), ("name", "Z")])

    api = Request("POST", "https://app.example/api",
                  json_body={"user": {"id": 5, "tags": ["a", "b"]}})
    check("nested JSON scalars are found",
          sorted(p for p, _ in json_points(api.json_body)),
          ["user.id", "user.tags[0]", "user.tags[1]"])
    check("and can be replaced in place",
          json_set(api.json_body, "user.tags[1]", "Z")["user"]["tags"],
          ["a", "Z"])
    check("a JSON point rebuilds the whole body",
          [p for p in insertion_points(api)
           if p.name == "user.id"][0].build("Z", "replace").json_body,
          {"user": {"id": "Z", "tags": ["a", "b"]}})

    header_points = insertion_points(
        Request("GET", "https://app.example/", headers={"Cookie": "sid=abc"}),
        include_headers=True)
    check("cookies are insertion points",
          any(p.kind == "cookie" and p.name == "sid" for p in header_points))
    cookie_point = [p for p in header_points if p.kind == "cookie"][0]
    check("and rebuild the header",
          cookie_point.build("Z", "replace").headers["Cookie"], "sid=Z")

    path_points = insertion_points(
        Request("GET", "https://app.example/orders/42/view"),
        include_path=True)
    check("numeric path segments are insertion points", len(path_points), 1)
    check("and rebuild the path",
          path_points[0].build("Z", "replace").path, "/orders/Z/view")

    print("\n\033[1mScope is a hard boundary\033[0m")
    scope = Scope(["https://app.example/shop"])
    check("the target host is allowed",
          scope.allows("https://app.example/shop/item"))
    check("another host is not", scope.allows("https://evil.example/"), False)
    check("a subdomain is not, by default",
          scope.allows("https://cdn.app.example/x"), False)
    check("unless asked for",
          Scope(["https://app.example/"], allow_subdomains=True
                ).allows("https://cdn.app.example/x"))
    check("an excluded pattern is refused",
          Scope(["https://app.example/"], exclude=[r"/admin"]
                ).allows("https://app.example/admin/users"), False)
    check("javascript: and data: are not URLs to fetch",
          scope.allows("javascript:alert(1)"), False)

    print("\n\033[1mForm values that get past validation\033[0m")
    check("an email field gets an email", "@" in _plausible("email", "text"))
    check("a quantity gets a number", _plausible("qty", "text"), "1")
    check("a date gets a date", _plausible("start", "date"), "2026-01-01")

    print("\n\033[1mComparing responses\033[0m")
    check("a page is identical to itself",
          oracles.similarity("<p>hello</p>", "<p>hello</p>"), 1.0)
    check("a CSRF token changing does not make it a different page",
          oracles.similarity(
              '<input name="csrf" value="aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa">ok',
              '<input name="csrf" value="bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb">ok'
          ) > 0.99)
    check("nor does a timestamp",
          oracles.similarity("Generated 2026-01-01 10:00:00 — report",
                             "Generated 2026-02-09 22:31:14 — report") > 0.99)
    check("a real difference still shows",
          oracles.similarity("<p>Item: Blue widget</p>",
                             "<p>No such item.</p>") < 0.8)

    print("\n\033[1mThe baseline sets its own threshold\033[0m")
    # The bug this test exists for: with a fixed 0.95 threshold, a page whose
    # navigation and footer dominate its content is 96% identical to the same
    # page with the content missing — so no blind injection could ever be
    # confirmed on a real application.
    chrome = "<nav>" + " ".join(f"<a href='/p{i}'>Link {i}</a>"
                                for i in range(40)) + "</nav>"
    with_row = FakeResponse(chrome + "<p>Item: Blue widget</p>")
    without_row = FakeResponse(chrome + "<p>No such item.</p>")
    baseline = oracles.Baseline([with_row, with_row, with_row], [0.1, 0.1, 0.1])
    check("a static page is judged against itself",
          baseline.strict_threshold, 0.999)
    check("the same page matches", baseline.matches(with_row))
    check("chrome-heavy pages are still over 95% alike",
          oracles.similarity(with_row.text, without_row.text) > 0.95)
    check("but the missing row is correctly not a match",
          baseline.matches(without_row), False)

    wobbly = [FakeResponse(f"<p>Random: {n}</p>{chrome}")
              for n in (111111111, 222222222, 333333333)]
    check("a page that changes on its own is still stable once normalised",
          oracles.Baseline(wobbly, [0.1] * 3).stable)

    print("\n\033[1mThe differential oracle\033[0m")
    auth = FakeAuth({"1%20AND%201%3D1": with_row, "1+AND+1%3D1": with_row,
                     "1%20AND%201%3D2": without_row, "1+AND+1%3D2": without_row})
    point = insertion_points(Request("GET", "https://app/item?id=1"))[0]
    differential = oracles.Differential(auth, baseline)
    result = differential.test(point, " AND 1=1", " AND 1=2")
    check("true matches the baseline and false does not", result["confirmed"])

    flat = FakeAuth({})
    check("a parameter that changes nothing is not reported",
          bool(oracles.Differential(flat, baseline).test(
              point, " AND 1=1", " AND 1=2")["confirmed"]), False)

    unstable = oracles.Baseline(
        [FakeResponse("a" * 50 + "x"), FakeResponse("b" * 50 + "y"),
         FakeResponse("c" * 50 + "z")], [0.1] * 3)
    check("an endpoint that is not stable gives no verdict at all",
          oracles.Differential(auth, unstable).test(
              point, " AND 1=1", " AND 1=2"), None)
    check("one agreeing pair is not enough to confirm",
          oracles.Differential(auth, baseline).confirm(
              point, [(" AND 1=1", " AND 1=2")]), [])
    check("two are",
          len(oracles.Differential(auth, baseline).confirm(
              point, [(" AND 1=1", " AND 1=2"), (" AND 1=1", " AND 1=2")])), 2)

    print("\n\033[1mThe timing oracle only believes proportion\033[0m")
    quick = oracles.Baseline([FakeResponse("ok")] * 3, [0.05, 0.06, 0.05])
    sleepy = FakeAuth({"sleep": FakeResponse("ok")},
                      delays={"2": 0.0})

    class ProportionalAuth:
        """Sleeps for exactly as long as the payload asks."""
        def send(self, request, allow_redirects=False, timeout=None):
            match = re.search(r"sleep\+?(\d+)", request.url)
            if match:
                time.sleep(int(match.group(1)))
            return FakeResponse("ok")

    result = oracles.Timing(ProportionalAuth(), quick, base_delay=1).test(
        point, "; sleep {d}")
    check("a delay that scales with the payload is confirmed",
          bool(result and result["confirmed"]))

    class AlwaysSlowAuth:
        """A slow endpoint, which is not the same thing at all: it takes the
        same time whatever the payload asks for."""
        def send(self, request, allow_redirects=False, timeout=None):
            time.sleep(1.4)
            return FakeResponse("ok")

    check("an endpoint that is simply slow is not",
          oracles.Timing(AlwaysSlowAuth(), quick, base_delay=1).test(
              point, "; sleep {d}"), None)

    print("\n\033[1mError signatures and reflection contexts\033[0m")
    check("a MySQL error is recognised",
          oracles.database_error(
              "You have an error in your SQL syntax near ... MySQL server "
              "version")[0], "MySQL")
    check("a SQLite error is recognised",
          oracles.database_error('near "1\'": syntax error')[0], "SQLite")
    check("ordinary prose is not an error",
          oracles.database_error("We could not find that order.")[0], None)

    check("a reflection in an attribute is identified",
          oracles.reflection_contexts('<input value="CANARY">',
                                      "CANARY")[0]["kind"],
          "attribute-double")
    check("a reflection in a script block is identified",
          oracles.reflection_contexts('<script>var a="CANARY";</script>',
                                      "CANARY")[0]["kind"], "script")
    check("a reflection in the body is identified",
          oracles.reflection_contexts("<p>CANARY</p>", "CANARY")[0]["kind"],
          "html")
    check("a reflection in a textarea is identified",
          oracles.reflection_contexts("<textarea>CANARY</textarea>",
                                      "CANARY")[0]["kind"], "raw-text")

    # ── the real thing ───────────────────────────────────────────────────
    server, base = start()
    try:
        print("\n\033[1mAuthentication\033[0m")
        config = AuthConfig(
            "form", login_url=base + "/login", username="alice",
            password="wonderland", check_url=base + "/dashboard",
            logged_in_signature="Sign out", name="alice")
        auth = Authenticator(config)
        check("the form login works", auth.login())
        check("the field names were read off the form itself",
              "Signed in as alice" in
              auth.send(Request("GET", base + "/dashboard")).text)
        check("wrong credentials do not report success",
              Authenticator(AuthConfig(
                  "form", login_url=base + "/login", username="alice",
                  password="wrong", check_url=base + "/dashboard",
                  logged_in_signature="Sign out")).login(), False)

        check("a logged-out response is recognised",
              auth.looks_logged_in(FakeResponse("Please log in to continue")),
              False)
        check("and so is a password field",
              auth.looks_logged_in(
                  FakeResponse('<input type="password" name="p">')), False)

        # Kill the session behind the scanner's back; it should notice and
        # recover without being told.
        from tests import vulnerable_app
        vulnerable_app.SESSIONS.clear()
        before = auth._relogins
        recovered = auth.send(Request("GET", base + "/dashboard"))
        check("a session killed mid-scan is noticed and re-established",
              recovered is not None and "Signed in as alice" in recovered.text)
        check("and it took exactly one re-login", auth._relogins - before, 1)

        check("the logout link is refused outright",
              auth.send(Request("GET", base + "/logout")), None)

        print("\n\033[1mA full authenticated scan\033[0m")
        second = AuthConfig(
            "form", login_url=base + "/login", username="bob",
            password="builder", check_url=base + "/dashboard",
            logged_in_signature="Sign out", name="bob")
        profile = Profile.standard()
        profile.use_browser = False       # the browser path is tested below
        profile.delay_seconds = 2
        profile.rate = 80
        started = time.time()
        # Capture the live progress detail so it can be asserted against the
        # scan that actually produced it.
        progress_detail, progress_counts = [], []

        def record_progress(phase, done, total, detail=None):
            progress_counts.append((done, total))
            if detail:
                progress_detail.append(detail)

        engine = ScanEngine(base, auth=config, second_auth=second,
                            profile=profile, scope=build_scope(base),
                            on_progress=record_progress)
        result = engine.run()
        elapsed = time.time() - started

        found = {(f.issue, urllib.parse.urlparse(f.where).path)
                 for f in result.findings}
        print(f"      ({len(result.findings)} findings in {elapsed:.0f}s "
              f"across {result.points_tested} insertion points)")

        check("it knew it was authenticated", result.authenticated)
        for issue, path in (
                ("sqli", "/item"),
                ("command_injection", "/ping"),
                ("ssti", "/render"),
                ("traversal", "/download"),
                ("open_redirect", "/go"),
                ("xss_reflected", "/search"),
                ("xss_reflected", "/profile"),
                ("xss_stored", "/comments"),
                ("access_control", "/admin"),
                ("access_control", "/account")):
            check(f"{issue} found at {path}", (issue, path) in found)

        confidences = {f.issue: f.confidence for f in result.findings}
        check("the SQL injection was confirmed, not guessed",
              confidences.get("sqli"), "confirmed")
        check("so was the command injection",
              confidences.get("command_injection"), "confirmed")
        check("and the access control failure",
              confidences.get("access_control"), "confirmed")

        print("\n\033[1mAn unauthenticated scan does not invent access "
              "control failures\033[0m")
        # The report that prompted this said "requested with no session
        # cookie at all and returned the same content as it does for a
        # logged-in user (responses 100% identical)" — on an engagement that
        # had no login. Of course they were identical: both requests were the
        # same anonymous request. Every page looked like broken access
        # control, and none of them were.
        anon_profile = Profile.standard()
        anon_profile.use_browser = False
        anon_profile.rate = 80
        anon_profile.checks = ("access",)
        anon_engine = ScanEngine(base, auth=AuthConfig("none"),
                                 profile=anon_profile, scope=build_scope(base))
        anon_result = anon_engine.run()
        check("no access control findings without a session",
              [f.issue for f in anon_result.findings
               if f.issue == "access_control"], [])
        check("and the report says why rather than staying silent",
              any("Access control was not tested" in note
                  for note in anon_result.notes))
        check("it still says it was unauthenticated",
              anon_result.authenticated, False)

        from command_bridge.modules.scanner.checks.access import \
            AccessControlCheck

        class Unauthenticated:
            config = AuthConfig("none")
            logged_in = True

        class LoggedIn:
            config = AuthConfig("form", name="alice")
            logged_in = True

        class Lapsed:
            config = AuthConfig("form", name="alice")
            logged_in = False

        class Ctx:
            def __init__(self, auth):
                self.auth = auth

        check("the check knows an anonymous session is not authenticated",
              AccessControlCheck.authenticated(Ctx(Unauthenticated())), False)
        check("and that a lapsed one is not either",
              AccessControlCheck.authenticated(Ctx(Lapsed())), False)
        check("but a live login is",
              AccessControlCheck.authenticated(Ctx(LoggedIn())), True)

        print("\n\033[1mAnd nothing on the endpoints that are correct\033[0m")
        safe_paths = ("/clean", "/item_safe", "/profile_safe", "/go_safe",
                      "/download_safe", "/jitter", "/wobble", "/about")
        for path in safe_paths:
            reported = [f.issue for f in result.findings
                        if urllib.parse.urlparse(f.where).path == path]
            check(f"nothing reported on {path}", reported, [])

        check("the logout link was never followed",
              any("logout" in url for url in result.skipped_destructive))

        print("\n\033[1mEvery finding carries its proof\033[0m")
        check("all of them have evidence",
              [f.issue for f in result.findings if not f.evidence], [])
        check("all of them name the parameter",
              [f.issue for f in result.findings if not f.point], [])
        check("all of them explain how it was confirmed",
              [f.issue for f in result.findings if not f.detail_extra], [])
        sqli = [f for f in result.findings if f.issue == "sqli"][0]
        text = sqli.evidence_text()
        check("the SQL evidence shows the true request, readably",
              "AND 1=1" in text)
        check("and the false one", "AND 1=2" in text)
        traversal = [f for f in result.findings if f.issue == "traversal"][0]
        check("the traversal evidence carries the file that came back",
              "root:x:0:0" in traversal.evidence_text())

        print("\n\033[1mThe report\033[0m")
        rendered = report.as_html(result)
        check("the HTML report names the target", base in rendered)
        check("it carries the severity of each finding",
              "CRITICAL" in rendered or "HIGH" in rendered)
        check("it says what was skipped", "not followed" in rendered)
        check("it is a complete document",
              rendered.strip().startswith("<!doctype html>")
              and rendered.strip().endswith("</html>"))
        markdown = report.as_markdown(result)
        check("the Markdown report has a heading per finding",
              markdown.count("\n## ") >= len(result.findings))
        payload = json.loads(report.as_json(result))
        check("the JSON report round-trips every finding",
              len(payload["findings"]), len(result.findings))
        check("and records the coverage honestly",
              payload["coverage"]["insertion_points"], result.points_tested)
        check("and whether it was authenticated", payload["authenticated"])

        print("\n\033[1mXSS is confirmed in a real browser\033[0m")
        try:
            from playwright.sync_api import sync_playwright   # noqa: F401
            browser_available = True
        except Exception:                                     # noqa: BLE001
            browser_available = False
        if not browser_available:
            print("      (skipped — Playwright is not installed)")
        else:
            from command_bridge.modules.scanner.checks.xss import XssCheck

            class Ctx:
                def __init__(self, auth, profile):
                    self.auth, self.profile = auth, profile

                def plant(self, *args):
                    pass

            browser_profile = Profile.standard()
            browser_profile.use_browser = True
            for path, expect in (("/search?q=test", "confirmed"),
                                 ("/profile?nick=alice", "confirmed"),
                                 ("/clean?q=safe", None)):
                request = Request("GET", base + path)
                point = insertion_points(request)[0]
                baseline = oracles.take_baseline(auth, request, 2)
                found = XssCheck().run(Ctx(auth, browser_profile), point,
                                       baseline)
                got = found[0].confidence if found else None
                check(f"{path} → {expect or 'nothing'}", got, expect)
            confirmed = XssCheck().run(
                Ctx(auth, browser_profile),
                insertion_points(Request("GET", base + "/search?q=test"))[0],
                oracles.take_baseline(auth, Request("GET",
                                                    base + "/search?q=test"), 2))
            check("the evidence says the script actually ran",
                  "executed" in confirmed[0].detail_extra)

        # ─────────────────────────────────────────────────────────────────
        #  Pause, and closing while a scan is live
        # ─────────────────────────────────────────────────────────────────
        #
        # Pausing has to mean the scanner stops sending, not that the
        # progress bar stops moving. Every request goes through the pacer, so
        # that is where the run is held; these prove it holds, that a paused
        # scan can still be stopped without being resumed first, and that a
        # real run stops promptly when told to.

        # ─────────────────────────────────────────────────────────────────
        #  Every real finding must be replayable
        # ─────────────────────────────────────────────────────────────────
        #
        # These run against the findings the engine ACTUALLY produced above,
        # not a hand-written fixture. That distinction is the whole point:
        # the evidence layer was first tested with a fake ScanFinding whose
        # label happened to match the regex that recovered the payload, so
        # the tests passed while every genuine confirmed finding came out as
        # "POTENTIAL — Payload: NOT CAPTURED" with no PoC. A fixture tests
        # the assumption; this tests the data.
        # ─────────────────────────────────────────────────────────────────
        #  Authentication: the verdict must match reality
        # ─────────────────────────────────────────────────────────────────
        #
        # The reported bug: correct credentials, a reachable verification
        # URL, and the scan still said "Unauthenticated". Three causes, each
        # pinned below.
        print("\n\033[1mAuthentication is judged on evidence\033[0m")

        profile_page = (
            '<h1>My profile</h1><p>Welcome alice</p>'
            '<h2>Change password</h2><form method="post">'
            '<input type="password" name="new_password">'
            '<input type="password" name="confirm">'
            '<button>Update</button></form>'
            '<a href="/logout">Sign out</a>')
        login_page = ('<form method="post" action="/login">'
                      '<input name="username">'
                      '<input type="password" name="password">'
                      '<button>Sign in</button></form>')

        bare = Authenticator(AuthConfig("none"))
        # CAUSE 1 — an account/profile page offers "change password", and a
        # password input was being read as proof of a login page. That is
        # the page people give as the verification URL.
        check("a change-password form is NOT a logged-out page",
              bare.judge(FakeResponse(profile_page))[0])
        check("but a real login form is",
              bare.judge(FakeResponse(login_page))[0], False)
        check("and it says why",
              "login form" in bare.judge(FakeResponse(login_page))[1])
        check("'please log in' is still recognised",
              bare.judge(FakeResponse("<p>Please log in to continue</p>"))[0],
              False)
        check("so is a 401", bare.judge(FakeResponse("ok", 401))[0], False)

        # CAUSE 2 — an unfollowed redirect to the login page. Once requests
        # has followed it the status is 200 and the clue is gone, so the
        # check now looks before following.
        redirecting = FakeResponse("", 302)
        redirecting.headers = {"Location": "/login?next=/account"}
        check("a redirect towards login is caught before it is followed",
              bare.judge(redirecting)[0], False)

        # CAUSE 3 — with no check_url, verification used to fall back to the
        # LOGIN page, which can only ever answer "not logged in".
        live = AuthConfig("form", login_url=base + "/login",
                          username="alice", password="wonderland",
                          check_url=base + "/dashboard", name="alice")
        worked = Authenticator(live)
        check("a correct form login is confirmed", worked.login())
        check("the outcome state is 'ok'", worked.outcome.state, "ok")
        check("the method is named for the tester",
              worked.outcome.method, "Username/Password")
        check("the indicator text is the one asked for",
              worked.outcome.summary(), "Authentication Successful")
        steps = "\n".join(worked.outcome.lines)
        for expected in ("Authentication method:", "Login URL:",
                         "Login response:", "Session established",
                         "Verification URL:", "Verification:"):
            check(f"the log records '{expected.rstrip(':')}'",
                  expected in steps)
        check("and NEVER the password",
              "wonderland" not in steps and "wonderland" not in
              str(worked.outcome.as_dict()))

        unverifiable = Authenticator(AuthConfig(
            "form", login_url=base + "/login", username="alice",
            password="wonderland", name="alice"))
        check("no verification URL is 'unverified', not 'successful'",
              unverifiable.login() and unverifiable.outcome.state,
              "unverified")
        check("and says so plainly",
              unverifiable.outcome.summary(), "Authentication Unverified")

        rejected = Authenticator(AuthConfig(
            "form", login_url=base + "/login", username="alice",
            password="nonsense", check_url=base + "/dashboard", name="x"))
        check("wrong credentials fail", rejected.login(), False)
        check("the indicator says Failed",
              rejected.outcome.summary(), "Authentication Failed")
        check("and the reason is useful, not just 'unauthenticated'",
              len(rejected.outcome.reason) > 20)

        unreachable = Authenticator(AuthConfig(
            "static", cookies={"sid": "nope"},
            check_url="http://127.0.0.1:9/nothing", name="x"))
        check("an unreachable verification URL fails", unreachable.login(),
              False)
        check("and says it could not be reached",
              "could not be reached" in unreachable.outcome.reason)

        # Cookie authentication must keep working, and reach the same states.
        cookie_auth = Authenticator(AuthConfig(
            "static", cookies=dict(worked.session.cookies),
            check_url=base + "/dashboard", name="pasted"))
        check("pasted cookies still authenticate", cookie_auth.login())
        check("with the same 'ok' state", cookie_auth.outcome.state, "ok")
        check("and are named as the method used",
              cookie_auth.outcome.method, "Pasted cookies/headers")
        empty_static = Authenticator(AuthConfig("static", name="x"))
        check("static mode with nothing pasted fails",
              empty_static.login(), False)

        print("\n\033[1mReal findings carry a replayable PoC\033[0m")
        confirmed_real = [f for f in result.findings
                          if f.confidence == "confirmed"]
        check("the scan confirmed several findings to check",
              len(confirmed_real) >= 5)

        missing_poc, not_confirmed, no_payload = [], [], []
        for finding in confirmed_real:
            proof, validation = cb_evidence.assess_scan(finding)
            # Access control is proved by replaying one request as two
            # identities, so it has a reproduction but no payload.
            if not proof.payload and finding.issue != "access_control":
                no_payload.append(finding.issue)
            if not proof.poc():
                missing_poc.append(finding.issue)
            if validation.state != cb_evidence.CONFIRMED:
                not_confirmed.append((finding.issue, validation.state))
        check("every confirmed finding names the payload it sent",
              no_payload, [])
        check("every confirmed finding renders a PoC", missing_poc, [])
        check("and reaches CONFIRMED, not POTENTIAL", not_confirmed, [])

        by_issue = {f.issue: f for f in result.findings}
        sqli_proof, sqli_validation = cb_evidence.assess_scan(by_issue["sqli"])
        check("the SQL injection PoC names the parameter",
              "id" in sqli_proof.parameter)
        check("it shows a condition that was injected",
              "AND" in sqli_proof.payload.upper())
        check("it carries a request that can be pasted into Burp",
              sqli_proof.burp_request().startswith("GET "))
        check("the request actually contains the payload",
              "AND" in urllib.parse.unquote_plus(sqli_proof.request).upper())
        check("it shows the response that came back",
              "HTTP 200" in sqli_proof.response)
        check("the lead evidence is the TRUE case, not the control",
              "true" in sqli_proof.request.lower()
              or "1 AND 1=1" in urllib.parse.unquote_plus(sqli_proof.request)
              or "5=5" in urllib.parse.unquote_plus(sqli_proof.request))
        check("both halves of the pair are kept for the reader",
              "Condition false" in sqli_proof.comparison)
        check("and the explanation says what was observed",
              "evaluated a condition" in sqli_proof.observed)

        poc = sqli_proof.poc()
        for part in ("Endpoint:", "Parameter:", "Test input:", "Request:",
                     "Response:", "Observation:"):
            check(f"the PoC has a '{part.rstrip(':')}' section", part in poc)

        # ─────────────────────────────────────────────────────────────────
        #  Progress, and the discovered-parameter list
        # ─────────────────────────────────────────────────────────────────
        print("\n\033[1mProgress reports the real operation\033[0m")
        check("the scan reported live detail", len(progress_detail) > 0)
        check("every entry names the URL being tested",
              all(d.get("url") for d in progress_detail))
        check("every entry names the parameter",
              all(d.get("parameter") for d in progress_detail))
        check("every entry names the check running",
              all(d.get("check") for d in progress_detail))
        reported_checks = {d["check"] for d in progress_detail}
        check("several different checks were reported, not one label",
              len(reported_checks) >= 3)
        check("the names are the ones a tester uses",
              "SQL injection" in reported_checks)
        # The detail must come from the scan, not be invented: every URL
        # reported must be one the crawl actually found.
        crawled = set(result.discovered_parameters or {})
        check("every reported URL was really discovered",
              {d["url"] for d in progress_detail} <= crawled)
        check("progress never exceeds the total",
              all(0 <= d_done <= d_total
                  for d_done, d_total in progress_counts))
        check("and the running item is counted from one, not zero",
              all(d_done >= 1 for d_done, _ in progress_counts
                  if _ > 1))

        print("\n\033[1mThe discovered-parameter file\033[0m")
        out_dir = Path(tempfile.mkdtemp())
        written = engine.write_parameter_file(out_dir)
        check("it is written where the other output goes",
              Path(written).parent, out_dir)
        check("under the name asked for", Path(written).name,
              "Active_Scan_Discovered_Parameters.txt")
        check("and the result records the path", result.parameter_file,
              written)
        body = Path(written).read_text()
        lines = [l for l in body.splitlines()
                 if l and not l.startswith("#")]
        check("it lists the parameterised URLs", len(lines) >= 5)
        check("every line carries a method and a URL",
              all(l.split()[0] in ("GET", "POST", "PUT", "PATCH")
                  for l in lines))
        check("parameter names are preserved", "[id]" in body)
        check("so are example values", "item?id=1" in body)
        check("body parameters are marked as such", "body:" in body)
        check("there are no duplicates",
              len(lines), len(set(lines)))
        urls = [l.split()[1] for l in lines]
        check("entries are in a stable order", urls, sorted(urls))
        check("nothing the scan never saw is in it",
              all(url in crawled for url in urls))
        check("a URL with no parameters is left out",
              not any(u.rstrip('/').endswith(base.rstrip('/')) for u in urls))

        empty = ScanEngine(base, auth=AuthConfig("none"),
                           profile=Profile.safe(), scope=build_scope(base))
        check("a scan that found nothing writes no misleading file",
              empty.write_parameter_file(out_dir), "")

        print("\n\033[1mPause and stop\033[0m")
        paused_profile = Profile.standard()
        paused_profile.use_browser = False
        paused_profile.rate = 60
        engine = ScanEngine(base, auth=AuthConfig("none"),
                            profile=paused_profile, scope=build_scope(base))
        check("a new engine is not paused", engine.paused, False)
        check("and not stopped", engine.stopped(), False)
        check("pausing reports paused", engine.pause(), True)
        check("the engine agrees", engine.paused)
        check("the pacer is held by the same gate",
              engine.pacer.gate is engine.gate)
        check("a held gate answers 'no, do not send' rather than waiting "
              "for ever", engine.gate.wait(timeout=0.2), False)
        check("resuming clears it", engine.resume() and not engine.paused)
        check("toggle pauses", engine.toggle_pause(), True)
        check("and toggles back", engine.toggle_pause(), False)

        # Stop while paused: the worker must be released, not left waiting on
        # a resume that is never coming. This is what makes closing the
        # window safe after somebody has pressed Pause.
        engine.pause()
        released = {"done": False}

        def blocked():
            # The pacer raises Stopped rather than returning, which is how a
            # worker mid-request unwinds instead of sending.
            try:
                engine.pacer.wait()
            except Exception:                           # noqa: BLE001
                pass
            released["done"] = True

        waiter = threading.Thread(target=blocked, daemon=True)
        waiter.start()
        time.sleep(0.3)
        check("a worker blocks while the scan is paused",
              released["done"], False)
        engine.stop()
        waiter.join(timeout=5)
        check("stopping while paused releases it", waiter.is_alive(), False)
        check("the engine is stopped", engine.stopped())
        check("and its gate is too", engine.gate.stopped)

        # And the same thing against a live run: a scan told to stop must
        # stop, promptly, without an exception reaching the caller.
        live_profile = Profile.standard()
        live_profile.use_browser = False
        live_profile.rate = 40
        live = ScanEngine(base, auth=AuthConfig("none"),
                          profile=live_profile, scope=build_scope(base))
        outcome = {}

        def run_it():
            try:
                outcome["result"] = live.run()
            except Exception as exc:                    # noqa: BLE001
                outcome["error"] = exc

        runner = threading.Thread(target=run_it, daemon=True)
        runner.start()
        time.sleep(2.0)
        sent_before = live.result.requests_seen
        live.stop()
        stopped_at = time.time()
        runner.join(timeout=30)
        check("a running scan stops when told to", runner.is_alive(), False)
        check("and does so promptly", time.time() - stopped_at < 25)
        check("with no exception escaping run()", "error" not in outcome,
              True)
        check("it still returns a result", "result" in outcome)
        del sent_before

        # ─────────────────────────────────────────────────────────────────
        print("\n\033[1mCommand injection is proved by output, not by "
              "waiting\033[0m")

        cmdi = [f for f in result.findings
                if f.issue == "command_injection"]
        check("the planted command injection is found", bool(cmdi))
        if cmdi:
            finding = cmdi[0]
            labels = [e.label for e in finding.evidence]
            text = finding.detail_extra + " ".join(
                (e.label or "") + (e.note or "") for e in finding.evidence)

            check("execution is established before anything else",
                  "Shell execution proved" in labels[0])
            check("real commands were run, not just arithmetic",
                  any("`id`" in label for label in labels))
            check("including whoami",
                  any("`whoami`" in label for label in labels))
            check("and uname",
                  any("`uname -a`" in label for label in labels))
            check("and /etc/passwd",
                  any("cat /etc/passwd" in label for label in labels))
            check("the output of id is in the evidence",
                  "uid=0(root)" in text)
            check("the passwd file is identified by its first line",
                  "root:x:0:0:" in text)
            check("the finding does not rest on a delay",
                  "took" not in finding.detail_extra
                  or "TIME-BASED" not in finding.detail_extra)
            check("it says the commands were read-only",
                  "read-only" in finding.detail_extra)

            proof, validation = cb_evidence.assess_scan(finding)
            check("it is CONFIRMED", validation.state, cb_evidence.CONFIRMED)
            check("the PoC leads with a request that returns output",
                  "id" in proof.burp_request()
                  or "passwd" in proof.burp_request())
            check("and the payload shown matches that request",
                  proof.payload in urllib.parse.unquote_plus(
                      proof.burp_request()))

        print("\n\033[1mEvery finding can be pasted into Burp\033[0m")
        # Asserted against the findings the engine really produced. A fixture
        # here would only prove that the fixture was written to match.
        missing = []
        for finding in result.findings:
            proof, _ = cb_evidence.assess_scan(finding)
            raw = proof.burp_request()
            if not raw:
                missing.append(finding.issue)
                continue
            first = raw.splitlines()[0] if raw.splitlines() else ""
            if not first.endswith(" HTTP/1.1"):
                missing.append(f"{finding.issue}: no request line")
            elif not re.search(r"(?mi)^Host: \S+", raw):
                missing.append(f"{finding.issue}: no Host header")
            elif "\r\n\r\n" not in raw:
                missing.append(f"{finding.issue}: headers not terminated")
            elif not re.search(r"(?mi)^Cookie: \S+", raw) \
                    and finding.point != "no session":
                # Everything else was found as a logged-in user, so the
                # session cookie has to be in the block or the tester pastes
                # it and gets the login page. Forced browsing is the one
                # exception and is excluded deliberately: its whole point is
                # that the request carried no cookie, so a block with one in
                # it would not reproduce the finding.
                missing.append(f"{finding.issue}: no session cookie")
        check("all of them carry a raw HTTP request", missing, [])

        print("\n\033[1mThe second account's role decides the finding\033[0m")
        for role, expect in (("same", "HORIZONTAL"), ("lower", "VERTICAL")):
            second.role = role
            access_profile = Profile.standard()
            access_profile.use_browser = False
            access_profile.rate = 80
            access_profile.checks = ("access",)
            role_engine = ScanEngine(base, auth=config, second_auth=second,
                                     profile=access_profile,
                                     scope=build_scope(base))
            role_result = role_engine.run()
            paths = {urllib.parse.urlparse(f.where).path
                     for f in role_result.findings}
            cross = [f for f in role_result.findings
                     if expect in f.detail_extra]
            check(f"role '{role}' reports {expect.lower()} failures",
                  bool(cross))
            check(f"role '{role}' finds the planted /account bug",
                  "/account" in paths)
            check(f"role '{role}' finds the planted /admin bug",
                  "/admin" in paths)
            # The false-positive half, which is the half that matters: these
            # are pages both accounts are meant to see, and a check that
            # reports them reports the whole application.
            for safe in ("/dashboard", "/tools", "/profile", "/item_safe"):
                check(f"role '{role}' does not report {safe}",
                      safe not in paths)
            if role == "lower":
                admin = [f for f in role_result.findings
                         if urllib.parse.urlparse(f.where).path == "/admin"
                         and "VERTICAL" in f.detail_extra]
                check("an admin path is raised as CRITICAL",
                      bool(admin) and admin[0].severity, "CRITICAL")
        second.role = "same"

    finally:
        server.shutdown()

    print(f"\n{PASS} passed, {FAIL} failed")
    return 1 if FAIL else 0


if __name__ == "__main__":
    sys.exit(main())
