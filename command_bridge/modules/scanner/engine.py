"""
The engine: profiles, orchestration, and the rules that keep a live scan safe.

The order of work matters and is not arbitrary:

    log in ─► confirm we are logged in ─► crawl ─► build insertion points
           ─► baseline every request ─► run the parameter checks
           ─► sweep for stored payloads ─► replay for access control

Baselining before attacking is what makes the differential oracles possible,
and the access-control pass runs last because it needs the full set of
authenticated requests the crawl discovered.

Three safety rules are enforced here rather than left to the checks:

  * **Scope** is checked on every request, not just during the crawl.
  * **Destructive verbs** are refused by profile. Standard will submit a form
    but will not issue DELETE, and skips anything whose URL or link text reads
    like it removes something.
  * **Pace** is limited, because a scanner that opens sixty connections to a
    client's production application is an outage with a report attached.

Findings are named from the same ``cb_issues`` library the Coffee Break screen
uses, so an issue reads identically whichever part of Command Bridge found it.
"""

from __future__ import annotations

import threading
import time
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field

from command_bridge.modules import cb_issues
from command_bridge.modules.cb_control import RunGate, Stopped
from command_bridge.modules.scanner import oracles
from command_bridge.modules.scanner.crawl import Crawler, Scope
from command_bridge.modules.scanner.model import (
    Request, ScanFinding, insertion_points)
from command_bridge.modules.scanner.session import AuthConfig, Authenticator

#: The name the discovered-parameter list is written under. One place, so
#: the engine, the interface and the report cannot disagree about it.
PARAMETER_FILENAME = "Active_Scan_Discovered_Parameters.txt"
from command_bridge.modules.scanner.checks.access import (
    AccessControlCheck, anonymous_identity)
from command_bridge.modules.scanner.checks.files import (
    OpenRedirectCheck, TraversalCheck)
from command_bridge.modules.scanner.checks.injection import (
    CodeInjectionCheck, CommandInjectionCheck, TemplateInjectionCheck)
from command_bridge.modules.scanner.checks.sqli import SqlInjectionCheck
from command_bridge.modules.scanner.checks.xss import StoredXssCheck, XssCheck


# ─────────────────────────────────────────────────────────────────────────────
#  Profiles
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class Profile:
    """How hard to push, and what is off limits."""

    name: str = "standard"
    #: Verbs the scanner will send. DELETE and PATCH are absent from every
    #: profile but 'full' for the obvious reason.
    methods: tuple = ("GET", "POST")
    max_depth: int = 4
    max_pages: int = 400
    max_points: int = 1500
    threads: int = 6
    #: Requests per second, across all threads.
    rate: float = 12.0
    timing_checks: bool = True
    #: Report command injection that rests on a delay and nothing else.
    #: Off by default: on a slow application these are mostly the application
    #: being slow, and a report full of them costs more to validate than it
    #: is worth. Execution-proved command injection is always reported.
    report_timing_only: bool = False
    delay_seconds: int = 5
    use_browser: bool = True
    browser_crawl: bool = False
    max_browser_pages: int = 25
    max_scripts: int = 30
    max_js_endpoints: int = 60
    test_headers: bool = False
    test_path_segments: bool = True
    baseline_samples: int = 3
    checks: tuple = ("sqli", "cmdi", "ssti", "code", "xss", "traversal",
                     "redirect", "access")

    @classmethod
    def safe(cls):
        """Read-only. Nothing is submitted, nothing is created."""
        return cls(name="safe", methods=("GET",), max_pages=250,
                   timing_checks=True, delay_seconds=4, threads=4, rate=6.0,
                   test_path_segments=True,
                   checks=("sqli", "traversal", "redirect", "xss", "access"))

    @classmethod
    def standard(cls):
        """The default: forms are submitted, nothing is deleted."""
        return cls(name="standard")

    @classmethod
    def full(cls):
        """Everything. For staging, with the client's agreement in writing."""
        return cls(name="full", methods=("GET", "POST", "PUT", "PATCH"),
                   max_depth=6, max_pages=1200, max_points=6000, threads=10,
                   rate=25.0, test_headers=True, browser_crawl=True,
                   max_browser_pages=60)


PROFILES = {"safe": Profile.safe, "standard": Profile.standard,
            "full": Profile.full}


class Pacer:
    """A shared speed limit, so threads do not add up to a denial of service.

    It is also where the run's pause lives. Every request the scanner makes
    passes through ``Session._send_once``, which calls this — so holding it
    here holds the whole scanner, thread pool and all, without any check
    having to know that pausing exists.
    """

    def __init__(self, rate, gate=None):
        self.interval = 1.0 / rate if rate > 0 else 0.0
        self._lock = threading.Lock()
        self._next = 0.0
        self.gate = gate

    def wait(self):
        if self.gate is not None and not self.gate.wait():
            # Stopped, not merely paused. Unwind rather than send.
            raise Stopped("the scan was stopped")
        if not self.interval:
            return
        with self._lock:
            now = time.time()
            if self._next <= now:
                self._next = now + self.interval
                return
            delay = self._next - now
            self._next += self.interval
        time.sleep(delay)


# ─────────────────────────────────────────────────────────────────────────────
#  The engine
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class ScanResult:
    target: str = ""
    started: float = 0.0
    finished: float = 0.0
    findings: list = field(default_factory=list)
    requests_seen: int = 0
    points_tested: int = 0
    pages_crawled: int = 0
    http_sent: int = 0
    relogins: int = 0
    skipped_destructive: list = field(default_factory=list)
    authenticated: bool = False
    #: The full authentication story — method, every step, and the reason it
    #: ended the way it did. The report and the interface both read this
    #: rather than inferring a state from which fields were filled in.
    auth_outcome: object = None
    #: Every parameterised request the crawl found, as
    #: ``{url: [parameter names]}``. Written out at the end of the scan for
    #: the tester to work through by hand.
    discovered_parameters: dict = field(default_factory=dict)
    parameter_file: str = ""
    profile: str = ""
    notes: list = field(default_factory=list)

    @property
    def duration(self):
        return (self.finished or time.time()) - self.started


class ScanEngine:
    """One scan of one target."""

    def __init__(self, target, auth=None, second_auth=None, profile=None,
                 scope=None, on_log=None, on_progress=None, on_finding=None,
                 on_auth=None):
        self.target = target if target.startswith(("http://", "https://")) \
            else "https://" + target
        self.profile = profile or Profile.standard()
        self.auth_config = auth or AuthConfig("none")
        self.second_auth_config = second_auth
        self.on_log = on_log or (lambda line: None)
        self.on_progress = on_progress or (lambda *a, **k: None)
        #: Live progress state, shared across the worker threads. The
        #: interface reads what is ACTUALLY running rather than a number
        #: with no context: which URL, which parameter, which check.
        self._progress_lock = threading.Lock()
        self._done = 0
        self._total = 1
        self.on_finding = on_finding or (lambda finding: None)
        #: Called once with the AuthOutcome as soon as the login attempt
        #: resolves, so the interface can show the real state before the
        #: crawl rather than only at the end of the scan.
        self.on_auth = on_auth or (lambda outcome: None)
        self._stop = threading.Event()
        #: Pause/stop for this run. The engine's own stop flag stays as it
        #: was so nothing that reads it has to change; the gate is what
        #: reaches the threads that are already mid-request.
        self.gate = RunGate()
        self.pacer = Pacer(self.profile.rate, self.gate)
        self.scope = scope or Scope([self.target])
        self.result = ScanResult(target=self.target,
                                 profile=self.profile.name)
        self._seen = set()
        self._lock = threading.Lock()
        self.planted = {}

    def stop(self):
        self._stop.set()
        # Wakes any worker blocked on a pause, so a paused scan can still be
        # stopped — and so closing the window does not wait on a resume that
        # is never coming.
        self.gate.stop()

    def stopped(self):
        return self._stop.is_set()

    # ── pause ────────────────────────────────────────────────────────────
    def pause(self):
        """Hold every worker at its next request. Reversible."""
        return self.gate.pause()

    def resume(self):
        return self.gate.resume()

    def toggle_pause(self):
        """Returns True when the scan is now paused."""
        return self.gate.toggle()

    @property
    def paused(self):
        return self.gate.paused

    # ── the run ──────────────────────────────────────────────────────────
    def run(self):
        self.result.started = time.time()
        self.on_log(f"[scan] {self.target} — {self.profile.name} profile, "
                    f"{self.profile.threads} workers, "
                    f"{self.profile.rate:.0f} req/s ceiling")

        auth = self._identity(self.auth_config)
        if not auth.login():
            self.result.notes.append(
                "The scan could not confirm a logged-in session. Everything "
                "below was found as an unauthenticated user, which is a "
                "fraction of the application.")
            self.on_log("[scan] WARNING: not authenticated — see the report")
        self.result.auth_outcome = getattr(auth, "outcome", None)
        self.auth = auth
        # One source of truth. `authenticated` is derived from the outcome
        # rather than tracked separately, so the report line and the
        # interface's indicator cannot disagree — they are the same fact read
        # twice. They did disagree, and a green light above a report that
        # says UNAUTHENTICATED destroys trust in both.
        self.result.authenticated = self.authenticated_now()
        # The indicator follows the session for the whole run, not just the
        # first second of it. A session that dies forty minutes in is
        # something the operator needs to see while it is happening.
        auth.on_state_change = self._auth_changed
        try:
            self.on_auth(self.result.auth_outcome)
        except Exception:                               # noqa: BLE001
            pass

        second = None
        if self.second_auth_config:
            second = self._identity(self.second_auth_config)
            if not second.login():
                self.on_log("[scan] the second identity could not log in; "
                            "the IDOR comparison will be skipped")
                second = None

        context = _Context(auth, self.profile, self.on_log, self)

        # 1 ── crawl
        self.on_progress("Crawling", 0, 1)
        crawler = Crawler(auth, self.scope, self.profile, self.on_log)
        requests = crawler.crawl(self._seeds(auth), self.stopped)
        if self.profile.browser_crawl and not self.stopped():
            try:
                requests = crawler.crawl_with_browser(
                    [self.target] + [r.url for r in requests[:8]
                                     if r.method == "GET"], self.stopped)
            except Exception as exc:                    # noqa: BLE001
                self.on_log(f"[crawl] browser pass unavailable: {exc}")
        self.result.pages_crawled = crawler.pages_fetched
        self.result.requests_seen = len(requests)
        self.result.skipped_destructive = crawler.skipped_destructive[:50]
        self.on_progress("Crawling", 1, 1)

        if not requests:
            self.on_log("[scan] nothing was reachable — check the target, the "
                        "scope and the credentials")
            self.result.finished = time.time()
            return self.result

        # 2 ── parameter checks
        points = []
        for request in requests:
            points.extend(insertion_points(
                request,
                include_headers=self.profile.test_headers,
                include_path=self.profile.test_path_segments))
        points = points[:self.profile.max_points]
        self.result.points_tested = len(points)
        self.result.discovered_parameters = self._collect_parameters(
            requests, points)
        self.on_log(f"[scan] {len(points)} insertion point(s) across "
                    f"{len(requests)} request(s)")

        checks = self._checks()
        total = max(1, len(points))
        with self._progress_lock:
            self._done, self._total = 0, total
        done = 0
        if points:
            with ThreadPoolExecutor(max_workers=self.profile.threads) as pool:
                futures = {pool.submit(self._test_point, context, point,
                                       checks): point for point in points}
                for future in as_completed(futures):
                    done += 1
                    with self._progress_lock:
                        self._done = done
                    self.on_progress("Testing parameters", done, total)
                    try:
                        for finding in future.result() or []:
                            self._record(finding)
                    except Stopped:
                        # Every worker still in flight raises this once the
                        # run is stopped. It is the stop working, not a
                        # failure, and it must not fill the log.
                        pass
                    except Exception as exc:            # noqa: BLE001
                        self.on_log(f"[scan] a check failed: {exc}")
                    if self.stopped():
                        break

        # 3 ── stored payloads
        if "xss" in self.profile.checks and self.planted and not self.stopped():
            self.on_progress("Looking for stored payloads", 0, 1)
            sweep = StoredXssCheck(self.planted)
            for finding in sweep.sweep(context, requests):
                self._record(finding)
            self.on_progress("Looking for stored payloads", 1, 1)

        # 4 ── access control
        if "access" in self.profile.checks and not self.stopped() \
                and not self.result.authenticated:
            self.result.notes.append(
                "Access control was not tested. Both halves of that check are "
                "comparisons against a logged-in session — what an anonymous "
                "user can reach that a logged-in one can, and what one user "
                "can reach that another cannot — and this scan had no "
                "authenticated session. It was skipped rather than reported "
                "against itself.")
            self.on_log("[scan] access control skipped — no authenticated "
                        "session to compare against")
        elif "access" in self.profile.checks and not self.stopped():
            anonymous = anonymous_identity(auth)
            anonymous.pace = self.pacer.wait
            access = AccessControlCheck(
                anonymous, second,
                # What the second account is relative to the first decides
                # whether a shared response is an IDOR or a privilege
                # escalation. The operator declares it; the scanner does not
                # guess, because guessing it wrong mislabels every finding
                # this check produces.
                role=getattr(self.second_auth_config, "role", "same")
                if self.second_auth_config else "same")
            total = max(1, len(requests))
            for index, request in enumerate(requests, 1):
                if self.stopped():
                    break
                self.on_progress("Checking access control", index, total)
                try:
                    for finding in access.run(context, request):
                        self._record(finding)
                except Exception as exc:                # noqa: BLE001
                    self.on_log(f"[scan] access check failed: {exc}")

        self.result.http_sent = getattr(auth, "sent", 0) + (
            getattr(second, "sent", 0) if second else 0)
        self.result.relogins = auth._relogins
        self.result.finished = time.time()
        self.on_log(f"[scan] finished in {int(self.result.duration)}s — "
                    f"{len(self.result.findings)} confirmed finding(s)")
        return self.result

    def _seeds(self, auth):
        """Where to start walking.

        The target on its own is usually the login page, whose only link is
        the login form — so an authenticated scan that seeds from it alone
        crawls one page and reports nothing. The page the login redirected to,
        and the session check URL, are where the application actually starts.
        """
        seeds = [self.target]
        for candidate in (self.auth_config.check_url,):
            if candidate and self.scope.allows(candidate):
                seeds.append(candidate)
        try:
            landing = auth.send(Request("GET", self.target),
                                allow_redirects=True)
            if landing is not None and self.scope.allows(str(landing.url)):
                seeds.append(str(landing.url))
        except Exception:                               # noqa: BLE001
            pass
        ordered, seen = [], set()
        for seed in seeds:
            if seed not in seen:
                seen.add(seed)
                ordered.append(seed)
        return ordered

    # ── pieces ───────────────────────────────────────────────────────────
    def authenticated_now(self):
        """Whether the scan currently has a session it has actually proved.

        Read from the outcome, which is the same object the interface shows,
        so the two can never drift. "unverified" counts as authenticated —
        the session exists and the scan is using it — but the outcome keeps
        the distinction so the report can say it was never confirmed.
        """
        if self.auth_config.strategy == "none":
            return False
        outcome = getattr(getattr(self, "auth", None), "outcome", None)
        return bool(outcome and outcome.state in ("ok", "unverified"))

    def _auth_changed(self, outcome):
        self.result.auth_outcome = outcome
        self.result.authenticated = self.authenticated_now()
        try:
            self.on_auth(outcome)
        except Exception:                               # noqa: BLE001
            pass

    def _identity(self, config):
        auth = Authenticator(config, report=self.on_log)
        auth.pace = self.pacer.wait
        auth.scope = self.scope
        return auth

    def _checks(self):
        wanted = set(self.profile.checks)
        # Ordered by how much a finding in each would matter, because a
        # parameter that is both traversable and reflective should be
        # reported as the traversal first.
        available = [
            ("sqli", SqlInjectionCheck()),
            ("cmdi", CommandInjectionCheck()),
            ("code", CodeInjectionCheck()),
            ("ssti", TemplateInjectionCheck()),
            ("traversal", TraversalCheck()),
            ("xss", XssCheck()),
            ("redirect", OpenRedirectCheck()),
        ]
        return [check for key, check in available if key in wanted]

    def _collect_parameters(self, requests, points):
        """What the crawl actually found that takes input.

        Built from the requests and insertion points the scan really used, so
        the file cannot contain a URL the scanner never saw. Values are kept
        — an example value is most of what makes a parameter worth testing by
        hand — and identical entries collapse.
        """
        found = {}
        for request in requests:
            names = [name for name, _ in request.query]
            if request.data:
                names += [f"body:{name}" for name, _ in request.data]
            if not names:
                continue
            entry = found.setdefault(request.url, {
                "method": request.method, "names": [], "source": "crawl"})
            for name in names:
                if name not in entry["names"]:
                    entry["names"].append(name)
        for point in points:
            url = point.request.url
            entry = found.setdefault(url, {
                "method": point.request.method, "names": [],
                "source": "tested"})
            entry["source"] = "tested"
            tag = point.name if point.kind == "query" \
                else f"{point.kind}:{point.name}"
            if tag not in entry["names"]:
                entry["names"].append(tag)
        return found

    def write_parameter_file(self, directory, filename=PARAMETER_FILENAME):
        """Write the discovered parameters where the tester can use them.

        Returns the path, or "" when there was nothing to write or the
        directory could not be used. A scan that finds nothing should not
        leave an empty file implying it did.
        """
        rows = self.result.discovered_parameters or {}
        if not rows or not directory:
            return ""
        lines = [
            "# Parameters discovered by the Active Scan",
            f"# Target:  {self.result.target}",
            f"# Scanned: {time.strftime('%Y-%m-%d %H:%M:%S')}",
            f"# {len(rows)} parameterised URL(s). Everything here was "
            f"actually reached by the crawl.",
            "",
        ]
        tested = sorted(u for u, r in rows.items() if r["source"] == "tested")
        seen_only = sorted(u for u, r in rows.items()
                           if r["source"] != "tested")
        if tested:
            lines += ["# --- tested by the scanner ---", ""]
            lines += [f"{rows[url]['method']} {url}"
                      f"    [{', '.join(rows[url]['names'])}]"
                      for url in tested]
        if seen_only:
            lines += ["", "# --- found but not tested (over the point "
                          "limit, or out of profile) ---", ""]
            lines += [f"{rows[url]['method']} {url}"
                      f"    [{', '.join(rows[url]['names'])}]"
                      for url in seen_only]
        try:
            path = Path(directory) / filename
            path.write_text("\n".join(lines) + "\n", encoding="utf-8")
        except Exception as exc:                        # noqa: BLE001
            self.on_log(f"[scan] could not write the parameter list: {exc}")
            return ""
        self.result.parameter_file = str(path)
        self.on_log(f"[scan] discovered parameters written to {path}")
        return str(path)

    def _announce_check(self, point, check):
        """Tell the interface exactly what is being tested right now."""
        with self._progress_lock:
            done, total = self._done, self._total
        # `done` counts what has FINISHED. The thing being announced is the
        # one running now, so the tester sees "27 of 268" while the 27th is
        # being tested rather than while it is already over.
        current = min(done + 1, total)
        try:
            self.on_progress(
                "Testing parameters", current, total,
                detail={
                    "url": point.request.url,
                    "method": point.request.method,
                    "parameter": point.name,
                    "location": point.kind,
                    "point": point.label(),
                    "check": check.name,
                    "check_key": check.key,
                })
        except TypeError:
            # An older callback that does not take a detail. Keep the scan
            # running rather than failing over a progress line.
            self.on_progress("Testing parameters", current, total)
        except Exception:                               # noqa: BLE001
            pass

    def _test_point(self, context, point, checks):
        if self.stopped():
            return []
        # Block here while paused, so a pause takes hold even between the
        # scheduling of a point and its first request.
        if not self.gate.wait():
            return []
        baseline = oracles.take_baseline(
            context.auth, point.request, self.profile.baseline_samples)
        if baseline is None:
            return []
        findings = []
        for check in checks:
            if self.stopped():
                break
            if not check.applies(point, self.profile):
                continue
            # Announce the check as it STARTS. Reporting it after the point
            # finishes would show the tester what the scanner has already
            # stopped doing.
            self._announce_check(point, check)
            try:
                found = check.run(context, point, baseline) or []
            except Exception as exc:                    # noqa: BLE001
                self.on_log(f"[{check.key}] {point.name}: {exc}")
                continue
            findings.extend(found)
            # Stop early only for a confirmed critical: at that point the
            # parameter is as bad as it can be and more payloads would only
            # describe the same hole. Anything less and the remaining checks
            # still run — an earlier version stopped on the first hit of any
            # kind, which is how a parameter that was both reflective and
            # traversable got reported as the lesser of the two.
            if any(f.confidence == "confirmed"
                   and (f.severity
                        or cb_issues.ISSUES.get(f.issue, {}).get("severity"))
                   == "CRITICAL" for f in found):
                break
        return findings

    def _record(self, finding):
        """Keep it once, and tell whoever is watching."""
        signature = (finding.issue, finding.where.split("?")[0], finding.point)
        with self._lock:
            if signature in self._seen:
                return
            self._seen.add(signature)
            self.result.findings.append(finding)
        issue = cb_issues.ISSUES.get(finding.issue, {})
        severity = finding.severity or issue.get("severity", "MEDIUM")
        self.on_log(f"    [{severity}] {issue.get('title', finding.issue)} — "
                    f"{finding.point} at {finding.where}")
        self.on_finding(finding)

    # ── for the checks ───────────────────────────────────────────────────
    def plant(self, canary, request, label):
        with self._lock:
            self.planted[canary] = (request, label)


class _Context:
    """What a check is handed: the session, the profile, and a way to talk."""

    def __init__(self, auth, profile, report, engine):
        self.auth = auth
        self.profile = profile
        self.report = report
        self.engine = engine

    def plant(self, canary, request, label):
        self.engine.plant(canary, request, label)


def build_scope(target, include=(), exclude=(), allow_subdomains=False):
    return Scope([target], include=include, exclude=exclude,
                 allow_subdomains=allow_subdomains)
