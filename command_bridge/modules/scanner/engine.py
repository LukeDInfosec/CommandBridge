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
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field

from command_bridge.modules import cb_issues
from command_bridge.modules.scanner import oracles
from command_bridge.modules.scanner.crawl import Crawler, Scope
from command_bridge.modules.scanner.model import (
    Request, ScanFinding, insertion_points)
from command_bridge.modules.scanner.session import AuthConfig, Authenticator
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
    """A shared speed limit, so threads do not add up to a denial of service."""

    def __init__(self, rate):
        self.interval = 1.0 / rate if rate > 0 else 0.0
        self._lock = threading.Lock()
        self._next = 0.0

    def wait(self):
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
    profile: str = ""
    notes: list = field(default_factory=list)

    @property
    def duration(self):
        return (self.finished or time.time()) - self.started


class ScanEngine:
    """One scan of one target."""

    def __init__(self, target, auth=None, second_auth=None, profile=None,
                 scope=None, on_log=None, on_progress=None, on_finding=None):
        self.target = target if target.startswith(("http://", "https://")) \
            else "https://" + target
        self.profile = profile or Profile.standard()
        self.auth_config = auth or AuthConfig("none")
        self.second_auth_config = second_auth
        self.on_log = on_log or (lambda line: None)
        self.on_progress = on_progress or (lambda phase, done, total: None)
        self.on_finding = on_finding or (lambda finding: None)
        self._stop = threading.Event()
        self.pacer = Pacer(self.profile.rate)
        self.scope = scope or Scope([self.target])
        self.result = ScanResult(target=self.target,
                                 profile=self.profile.name)
        self._seen = set()
        self._lock = threading.Lock()
        self.planted = {}

    def stop(self):
        self._stop.set()

    def stopped(self):
        return self._stop.is_set()

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
        self.result.authenticated = auth.logged_in and \
            self.auth_config.strategy != "none"

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
        self.on_log(f"[scan] {len(points)} insertion point(s) across "
                    f"{len(requests)} request(s)")

        checks = self._checks()
        total = max(1, len(points))
        done = 0
        if points:
            with ThreadPoolExecutor(max_workers=self.profile.threads) as pool:
                futures = {pool.submit(self._test_point, context, point,
                                       checks): point for point in points}
                for future in as_completed(futures):
                    done += 1
                    self.on_progress("Testing parameters", done, total)
                    try:
                        for finding in future.result() or []:
                            self._record(finding)
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
        if "access" in self.profile.checks and not self.stopped():
            anonymous = anonymous_identity(auth)
            anonymous.pace = self.pacer.wait
            access = AccessControlCheck(anonymous, second)
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

    def _test_point(self, context, point, checks):
        if self.stopped():
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
