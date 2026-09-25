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
        engine = ScanEngine(base, auth=config, second_auth=second,
                            profile=profile, scope=build_scope(base))
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

    finally:
        server.shutdown()

    print(f"\n{PASS} passed, {FAIL} failed")
    return 1 if FAIL else 0


if __name__ == "__main__":
    sys.exit(main())
