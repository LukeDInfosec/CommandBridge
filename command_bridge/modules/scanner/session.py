"""
Staying logged in.

The failure that makes authenticated scanning worthless is silent: the session
expires twenty minutes into a two-hour scan, every subsequent request gets the
login page, every check sees the same benign response, and the report says the
application is clean. It is not clean. It was never tested.

So this module does two things. It logs in — four ways, because real
applications differ — and then it keeps checking that it is still logged in,
and logs in again when it is not. Every check in the scanner goes through
``Authenticator.send``, so none of them can accidentally test a logout page.

The four strategies:

  ``form``     POST credentials to the login endpoint, carrying any CSRF token
               found on the login form first. Fast, no browser, and correct for
               most server-rendered applications.
  ``browser``  Drive headless Chromium through the real login form and harvest
               the cookies it ends up with. The answer for SSO, for anything
               that computes a token in JavaScript, and for multi-step logins.
  ``static``   Cookies and headers captured by hand. Always works, expires
               without warning — the detector below is what makes it usable.
  ``bearer``   Mint a token from an OAuth token endpoint (client credentials or
               refresh) and re-mint it when it expires. For APIs and SPAs.
"""

from __future__ import annotations

import json
import re
import threading
import time
import urllib.parse


#: Signs that what came back is a login page rather than the application.
#: Deliberately conservative: a false "we are logged out" costs a re-login,
#: a false "we are logged in" costs the whole scan.
#: URLs where a login page is the *correct* response. Without this the
#: scanner treats every visit to /login as a lapsed session and re-logs in
#: forever, which is both wrong and loud.
PUBLIC_BY_NATURE = re.compile(
    r"/(login|log-in|signin|sign-in|logout|sign-out|register|signup|"
    r"password|forgot|reset)(/|$|\?)", re.I)

#: Prose that only appears when the application is telling you to log in.
#: Strong evidence: an application does not say this to a logged-in user.
LOGGED_OUT_PROSE = re.compile(
    r"\b(please (log|sign) ?in|session (has )?expired|"
    r"your session has timed out|you must be logged ?in|"
    r"authentication required|not authori[sz]ed|access denied|"
    r"invalid (username|password|credentials)|login failed)\b", re.I)

#: A password field on its own means nothing. Every account page, profile
#: page and settings page in the world offers "change your password" — and
#: those are exactly the pages a tester supplies as the verification URL.
#: Treating a password input as proof of being logged out is what made a
#: perfectly good session report as unauthenticated.
#:
#: What actually indicates a login form is a password field sitting beside a
#: username or email field in the same form. A change-password form has a
#: password field (often two) and no username.
LOGIN_FORM_SHAPE = re.compile(
    r"<form[^>]*>(?:(?!</form>).)*?"
    r"<input[^>]+(?:name|id)\s*=\s*[\"']?[^\"'>]*"
    r"(?:user|email|login|account)[^\"'>]*[\"']?[^>]*>"
    r"(?:(?!</form>).)*?"
    r"<input[^>]+type\s*=\s*[\"']?password[\"']?"
    r"|"
    # …or the same two the other way round.
    r"<form[^>]*>(?:(?!</form>).)*?"
    r"<input[^>]+type\s*=\s*[\"']?password[\"']?"
    r"(?:(?!</form>).)*?"
    r"<input[^>]+(?:name|id)\s*=\s*[\"']?[^\"'>]*"
    r"(?:user|email|login|account)[^\"'>]*[\"']?",
    re.I | re.S)

#: Things only a logged-in page shows. Weighed against the above.
LOGGED_IN_SIGNS = (
    re.compile(r"\b(log ?out|sign ?out)\b", re.I),
    re.compile(r"href=[\"'][^\"']*(logout|signout|sign-out|log-out)", re.I),
    re.compile(r"\b(my (account|profile|dashboard)|welcome back)\b", re.I),
)

#: Kept so anything importing it still works; the detection no longer
#: depends on it.
LOGGED_OUT_SIGNS = (LOGGED_OUT_PROSE,)


#: What to call each strategy when talking to a human.
METHOD_NAMES = {
    "none": "None",
    "form": "Username/Password",
    "browser": "Username/Password (browser)",
    "static": "Pasted cookies/headers",
    "bearer": "Bearer token",
}


class AuthOutcome:
    """What happened when we tried to log in, step by step.

    The scan is only worth running if the session is real, so when it is not
    the person running it needs to know which step failed — not merely that
    the result was "unauthenticated". Nothing here ever holds a password.
    """

    def __init__(self, method=""):
        self.method = method
        self.ok = False
        #: Whether a verification URL actually proved it. Without one the
        #: scan still runs with whatever session the login produced, but
        #: saying "Authentication Successful" would be a claim nothing
        #: checked — so this gets its own state rather than being rounded up.
        self.verified = False
        self.reason = ""
        self.lines = []
        self.finished = False
        self.was_lost = False

    def step(self, line):
        """Record one step. Returns the line, so callers can log it too."""
        self.lines.append(f"[AUTH] {line}")
        return line

    def finish(self, ok, reason, verified=True):
        self.ok = bool(ok)
        self.verified = bool(ok and verified)
        self.reason = reason
        self.finished = True
        self.was_lost = False
        return self

    def lost(self, reason):
        """The session worked and has stopped working.

        A distinct state rather than a flip back to failed, because the two
        mean different things to whoever is reading the report: a login that
        never worked is a configuration problem, and a session that died
        forty minutes in is a timeout or a concurrent-login policy, and the
        findings up to that point are still real.
        """
        self.ok = False
        self.verified = False
        self.was_lost = True
        self.reason = reason
        self.finished = True
        return self

    @property
    def state(self):
        if not self.finished:
            return "checking"
        if getattr(self, "was_lost", False):
            return "lost"
        if not self.ok:
            return "failed"
        return "ok" if self.verified else "unverified"

    def summary(self):
        return {"checking": "Checking authentication…",
                "ok": "Authentication Successful",
                "unverified": "Authentication Unverified",
                "lost": "Session Lost During Scan",
                "failed": "Authentication Failed"}[self.state]

    def as_dict(self):
        return {"method": self.method, "ok": self.ok,
                "verified": self.verified, "reason": self.reason,
                "state": self.state, "lines": list(self.lines)}


class AuthConfig:
    """Everything needed to become, and stay, a logged-in user."""

    def __init__(self, strategy="none", **options):
        self.strategy = strategy            # none|form|browser|static|bearer
        self.login_url = options.get("login_url", "")
        self.username = options.get("username", "")
        self.password = options.get("password", "")
        self.username_field = options.get("username_field", "")
        self.password_field = options.get("password_field", "")
        self.extra_fields = options.get("extra_fields") or {}
        #: A URL that requires authentication, and a string that is only in
        #: its response when we are logged in. Together these are the
        #: heartbeat; without them nothing else here can be trusted.
        self.check_url = options.get("check_url", "")
        self.logged_in_signature = options.get("logged_in_signature", "")
        self.cookies = options.get("cookies") or {}
        self.headers = options.get("headers") or {}
        self.token_url = options.get("token_url", "")
        self.token_payload = options.get("token_payload") or {}
        self.token_field = options.get("token_field", "access_token")
        #: Anything matching is never requested — the logout link being the
        #: one that ends an authenticated scan early every single time.
        self.avoid = list(options.get("avoid") or
                          ["logout", "signout", "sign-out", "log-out",
                           "/exit", "deactivate", "delete-account"])
        self.name = options.get("name", "user")
        #: For a second identity: what it is *relative to the first* — 'same'
        #: (peer, so a shared record is an IDOR), 'lower' (so a shared record
        #: is a privilege escalation) or 'higher' (the first account is the
        #: unprivileged one and the test runs in the other direction).
        self.role = options.get("role", "same")

    def as_dict(self):
        data = dict(self.__dict__)
        if data.get("password"):
            data["password"] = "********"
        return data


class Authenticator:
    """One logged-in identity, and the machinery that keeps it that way."""

    def __init__(self, config, verify=False, timeout=20, user_agent=None,
                 proxies=None, report=None):
        import requests
        self.config = config
        self.report = report or (lambda line: None)
        self.session = requests.Session()
        self.session.verify = verify
        self.session.proxies = proxies or {}
        self.session.headers["User-Agent"] = (
            user_agent or "Mozilla/5.0 (compatible; CommandBridge Scanner)")
        self.timeout = timeout
        self._lock = threading.Lock()
        self._token = ""
        self._token_expires = 0.0
        self._relogins = 0
        self._last_check = 0.0
        self.logged_in = False
        #: Set by the engine: a speed limit shared across every worker, and
        #: the scope. Both are enforced here rather than in the checks, so a
        #: check cannot exceed either by forgetting to ask.
        self.pace = None
        self.scope = None
        self.sent = 0
        self._consecutive_lapses = 0
        self._gave_up = False
        self._login_doubt = ""
        self.outcome = AuthOutcome(method=METHOD_NAMES.get(config.strategy,
                                                           config.strategy))
        #: Called with the outcome whenever the authentication state changes.
        #: The interface uses it to keep its indicator honest *during* a run
        #: rather than only at the start — a session that dies in the middle
        #: of a two-hour scan is something the operator needs to see while it
        #: is happening, not inferred afterwards from an empty report.
        self.on_state_change = None
        try:
            import urllib3
            urllib3.disable_warnings()
        except Exception:
            pass

    # ── logging in ───────────────────────────────────────────────────────
    def login(self):
        """Establish the session. Returns True when it looks authenticated.

        Every step is reported, so that when it fails the person running the
        scan can see which one failed rather than only that something did.
        No credential material is ever logged.
        """
        strategy = self.config.strategy
        self.outcome = AuthOutcome(method=METHOD_NAMES.get(strategy, strategy))
        step = self.outcome.step

        if strategy == "none":
            self.logged_in = True
            self.outcome.finish(True, "no authentication was requested")
            return True

        step(f"Authentication method: {self.outcome.method}")
        with self._lock:
            try:
                if strategy == "static":
                    self._apply_static()
                    step(f"Applied {len(self.config.cookies or {})} cookie(s) "
                         f"and {len(self.config.headers or {})} header(s)")
                    if not (self.config.cookies or self.config.headers):
                        self.logged_in = False
                        self.outcome.finish(
                            False, "no cookies or headers were supplied")
                        self._announce()
                        return False
                elif strategy == "form":
                    if not self.config.login_url:
                        self.logged_in = False
                        self.outcome.finish(False, "no login URL was given")
                        self._announce()
                        return False
                    if not self._login_form():
                        self.logged_in = False
                        self._announce()
                        return False
                elif strategy == "browser":
                    step(f"Login URL: {self.config.login_url}")
                    self._login_browser()
                    step("Browser login finished; cookies harvested")
                elif strategy == "bearer":
                    step(f"Token endpoint: {self.config.token_url}")
                    self._mint_token()
                    step("Access token obtained" if self._token
                         else "No access token was returned")
                else:
                    raise ValueError(f"unknown auth strategy: {strategy}")
            except Exception as exc:                    # noqa: BLE001
                self.logged_in = False
                self.outcome.finish(
                    False, f"the login attempt raised "
                           f"{type(exc).__name__}: {exc}")
                self._announce()
                return False

        if self.session.cookies or \
                self.session.headers.get("Authorization"):
            names = ", ".join(sorted(c.name for c in self.session.cookies)[:6])
            step(f"Session established ({names or 'bearer token'})")
        else:
            step("No session cookie or token was set by the login")

        # The verification URL is the actual test. A 200 from the login
        # endpoint proves nothing: applications return 200 with "invalid
        # credentials" on the same page all the time.
        if self.config.check_url:
            step(f"Verification URL: {self.config.check_url}")
        ok, reason = self.check_session()
        self._last_check = time.time()
        step(("Verification: " if ok else "Verification indicates an "
              "unauthenticated session: ") + reason)
        self.logged_in = ok
        if not ok and self._login_doubt:
            # The verification failed and the login response already told us
            # why. "the signature was not in the response" is true and
            # useless; "the application replied 'Invalid username or
            # password'" is the thing to act on.
            reason = f"{self._login_doubt}, and {reason}"
        elif ok and self._login_doubt:
            # Worth recording: the login response looked like a failure and
            # the verification URL disagreed. Whoever reads this later should
            # know the verdict came from the check, not from the POST.
            reason = (f"{reason} (the login response itself looked "
                      f"unsuccessful — {self._login_doubt} — but the "
                      f"verification URL confirms the session)")
        self.outcome.finish(ok, reason,
                            verified=bool(self.config.check_url))
        if not ok:
            # Nothing is gained by re-logging in during the scan with
            # credentials that have just been refused. Without this the run
            # log fills with "session lapsed — logging back in (attempt 7)"
            # long after the scanner has announced it is continuing
            # unauthenticated.
            self._gave_up = True
        self._announce()
        return self.logged_in

    def _announce(self):
        for line in self.outcome.lines:
            self.report(line)
        verdict = {"ok": "AUTHENTICATION CONFIRMED",
                   "unverified": "AUTHENTICATION UNVERIFIED — "
                                 "no verification URL was given, so the "
                                 "session was never actually tested",
                   "failed": f"AUTHENTICATION FAILED — {self.outcome.reason}",
                   "checking": "authentication still in progress"}
        self.report(f"[auth] {self.config.name}: "
                    f"{verdict[self.outcome.state]}")
        self._publish()

    def _publish(self):
        """Tell whoever is watching what the state is now.

        The interface's indicator and the report's "authenticated" line must
        never be able to disagree, and the only way to guarantee that is for
        both to read the same object and for every change to it to be
        published. A green light beside a report that says UNAUTHENTICATED is
        worse than either one being wrong on its own, because it means
        neither can be trusted.
        """
        if self.on_state_change:
            try:
                self.on_state_change(self.outcome)
            except Exception:                           # noqa: BLE001
                pass

    def session_lost(self, reason):
        """The session was established and has since stopped working.

        Only meaningful if it ever worked. A login that was refused at the
        start stays "failed", with the reason it was refused — relabelling it
        "session lost" would replace the one piece of information the
        operator needs ("the credentials were rejected") with a vaguer one.
        """
        if self.outcome.state in ("lost", "failed"):
            return
        self.outcome.lost(reason)
        self.logged_in = False
        self.report(f"[auth] {self.config.name}: SESSION LOST — {reason}")
        self._publish()

    def _apply_static(self):
        for name, value in (self.config.cookies or {}).items():
            self.session.cookies.set(name, value)
        self.session.headers.update(self.config.headers or {})

    def _login_form(self):
        """POST the credentials, carrying any hidden fields from the form.

        The hidden fields matter more than they look: a CSRF token on the
        login form is the usual reason a hand-rolled form login silently
        fails, and a failed login that is not noticed produces an empty scan.
        """
        step = self.outcome.step
        self._apply_static()
        fields = dict(self.config.extra_fields)
        username_field = self.config.username_field or "username"
        password_field = self.config.password_field or "password"
        action = self.config.login_url
        hidden_fields = {}

        step(f"Login URL: {self.config.login_url}")
        try:
            page = self.session.get(self.config.login_url,
                                    timeout=self.timeout)
            step(f"Login page: HTTP {page.status_code}")
            hidden, guessed, form_action = _read_login_form(page.text,
                                                            page.url)
            hidden_fields = hidden
            fields.update(hidden)
            if not self.config.username_field and guessed[0]:
                username_field = guessed[0]
            if not self.config.password_field and guessed[1]:
                password_field = guessed[1]
            if form_action:
                action = form_action
        except Exception as exc:                        # noqa: BLE001
            self.report(f"[auth] could not read the login form: {exc}")

        fields[username_field] = self.config.username
        fields[password_field] = self.config.password
        step(f"Submitting credentials to {action} "
             f"(fields: {username_field}/{password_field}"
             + (f", {len(hidden_fields)} hidden" if hidden_fields else "")
             + ")")
        try:
            response = self.session.post(action, data=fields,
                                         timeout=self.timeout,
                                         allow_redirects=True)
        except Exception as exc:                        # noqa: BLE001
            self.outcome.finish(
                False, f"the login request failed: "
                       f"{type(exc).__name__}: {exc}")
            return False
        step(f"Login response: HTTP {response.status_code} "
             f"at {str(response.url)}")

        # What the login response looks like is a *signal*, not the verdict.
        #
        # This is the ordering that was wrong before, and it is worth being
        # explicit about because it is the whole design. A 200 from the login
        # endpoint proves nothing — applications re-serve the login page with
        # an error on the same status code. So the previous version refused
        # the login whenever the response came back at the same URL carrying
        # something login-shaped, and returned False immediately.
        #
        # The problem is that it returned False *before the verification URL
        # was ever requested*. A guess was overruling the only piece of real
        # evidence available, and on an application whose home page carries a
        # login widget beside its content — or which simply renders the
        # dashboard at the same path — a completely successful login was
        # reported as refused credentials.
        #
        # So: record what was seen, and let check_session() decide. The
        # heuristic only has the final word when there is no verification URL
        # to consult, which is the one case where a guess is better than
        # nothing.
        self._login_doubt = ""
        rejected = LOGGED_OUT_PROSE.search(response.text or "")
        landed_back = (str(response.url).split("?")[0].rstrip("/") ==
                       self.config.login_url.split("?")[0].rstrip("/"))
        if rejected:
            self._login_doubt = (f"the application replied "
                                 f"{rejected.group(0).strip()!r}")
        elif landed_back and LOGIN_FORM_SHAPE.search(response.text or ""):
            self._login_doubt = ("the login request returned a page carrying "
                                 "a login form again")
        if self._login_doubt:
            step(f"The login response looks unsuccessful: {self._login_doubt}"
                 + (". The verification URL decides."
                    if self.config.check_url else
                    ". There is no verification URL, so this is the only "
                    "evidence available."))
            if not self.config.check_url:
                self.outcome.finish(
                    False,
                    f"{self._login_doubt}, and with no verification URL set "
                    f"there is nothing that can confirm otherwise. Set a "
                    f"session check URL and a string that only appears when "
                    f"logged in, and the scan will be able to tell.")
                return False
        return True

    def _login_browser(self):
        """Log in with a real browser, then take the cookies it earned."""
        self._apply_static()
        from playwright.sync_api import sync_playwright

        with sync_playwright() as playwright:
            browser = playwright.chromium.launch(args=["--no-sandbox"])
            context = browser.new_context(ignore_https_errors=True)
            page = context.new_page()
            page.goto(self.config.login_url, wait_until="domcontentloaded")
            user_selector = (self.config.username_field
                             or "input[type=email], input[name*=user i], "
                                "input[name*=email i], input[type=text]")
            page.fill(user_selector, self.config.username)
            page.fill(self.config.password_field or "input[type=password]",
                      self.config.password)
            try:
                page.click("button[type=submit], input[type=submit], "
                           "button:has-text('Log in'), button:has-text('Sign in')")
            except Exception:                           # noqa: BLE001
                page.keyboard.press("Enter")
            page.wait_for_load_state("networkidle", timeout=20000)
            for cookie in context.cookies():
                self.session.cookies.set(cookie["name"], cookie["value"],
                                         domain=cookie.get("domain"))
            # Tokens kept in web storage rather than a cookie.
            try:
                stored = page.evaluate(
                    "() => JSON.stringify(Object.assign({}, localStorage))")
                for key, value in json.loads(stored or "{}").items():
                    if re.search(r"token|jwt|auth", key, re.I) and \
                            isinstance(value, str) and len(value) > 20:
                        self.session.headers["Authorization"] = \
                            value if value.lower().startswith("bearer ") \
                            else f"Bearer {value}"
                        break
            except Exception:                           # noqa: BLE001
                pass
            browser.close()

    def _mint_token(self):
        self._apply_static()
        response = self.session.post(
            self.config.token_url, data=self.config.token_payload,
            timeout=self.timeout)
        body = {}
        try:
            body = response.json()
        except Exception:                               # noqa: BLE001
            pass
        token = body.get(self.config.token_field, "")
        if not token:
            self.report("[auth] the token endpoint returned no token")
            return
        self._token = token
        self._token_expires = time.time() + float(body.get("expires_in", 3000))
        self.session.headers["Authorization"] = f"Bearer {token}"

    # ── staying logged in ────────────────────────────────────────────────
    def verify_session(self, force=False):
        """Is this session still authenticated?

        Cheap, and rate-limited to once every fifteen seconds unless forced,
        because it runs between checks and should not double the scan's
        traffic.
        """
        if self.config.strategy == "none":
            return True
        if not force and time.time() - self._last_check < 15:
            return self.logged_in
        self._last_check = time.time()
        ok, _reason = self.check_session()
        return ok

    def check_session(self):
        """``(logged_in, reason)`` from one request to the verification URL.

        Never falls back to the login URL. It used to, and checking the login
        page for signs of being logged in can only ever answer "no" — which
        is why a correct username and password with no verification URL came
        out as unauthenticated.
        """
        url = (self.config.check_url or "").strip()
        if not url:
            return True, ("no verification URL was given, so the session "
                          "could not be confirmed either way")
        try:
            # Unfollowed first, so a 302 to the login page is visible as a
            # 302 rather than as a 200 on a page that happens to look fine.
            response = self.session.get(url, timeout=self.timeout,
                                        allow_redirects=False)
            if 300 <= response.status_code < 400:
                verdict, reason = self.judge(response)
                if not verdict:
                    return False, reason
                response = self.session.get(url, timeout=self.timeout,
                                            allow_redirects=True)
        except Exception as exc:                        # noqa: BLE001
            return False, (f"the verification URL could not be reached: "
                           f"{type(exc).__name__}: {exc}")
        verdict, reason = self.judge(response)
        return verdict, f"HTTP {response.status_code} — {reason}"

    def looks_logged_in(self, response):
        """Is this response one the application gives a logged-in user?"""
        return self.judge(response)[0]

    def judge(self, response):
        """``(logged_in, reason)`` — the verdict and why, for the log.

        Evidence in order of how much it proves. The order matters: a
        password field used to be treated as proof of a login page, which is
        wrong on every account, profile and settings page in existence — the
        very pages people give as the verification URL.
        """
        body = response.text or ""
        final_url = str(getattr(response, "url", "") or "")

        # 1. An explicit signature settles it. Nothing else is consulted.
        if self.config.logged_in_signature:
            if self.config.logged_in_signature in body:
                return True, "the session signature was present"
            return False, (f"the session signature "
                           f"{self.config.logged_in_signature!r} was not in "
                           f"the response")

        # 2. The server refusing outright.
        if response.status_code in (401, 403):
            return False, f"the server answered HTTP {response.status_code}"

        # 3. A redirect towards a login page, seen before it is followed.
        location = response.headers.get("Location", "")
        if 300 <= response.status_code < 400 and location:
            if PUBLIC_BY_NATURE.search(location) or \
                    re.search(r"log ?in|sign ?in|auth|sso", location, re.I):
                return False, (f"the response redirected to {location}, "
                               f"which is a login page")

        # 4. Redirects already followed, and we ended up at a login page.
        #    This is the case the old code could not see at all: once
        #    requests has followed the redirect, the status is 200 and the
        #    only remaining clue is the URL we actually landed on.
        if final_url:
            if self.config.login_url and \
                    final_url.split("?")[0].rstrip("/") == \
                    self.config.login_url.split("?")[0].rstrip("/"):
                return False, "the request ended up back on the login page"
            if PUBLIC_BY_NATURE.search(final_url) and \
                    not PUBLIC_BY_NATURE.search(self.config.check_url or ""):
                return False, (f"the request ended up at {final_url}, which "
                               f"is a sign-in or registration page")

        # 5. The application saying so in words.
        prose = LOGGED_OUT_PROSE.search(body)
        if prose:
            return False, (f"the response said "
                           f"{prose.group(0).strip()!r}")

        # 6. A login-shaped form: a password field beside a username field.
        #    A change-password form has no username field and does not match.
        if LOGIN_FORM_SHAPE.search(body):
            return False, "the response contains a login form"

        # 7. Positive signs, for the log rather than the verdict.
        for sign in LOGGED_IN_SIGNS:
            if sign.search(body):
                return True, "the response carries a signed-in marker"
        return True, "nothing in the response indicates a logged-out session"

    def send(self, request, allow_redirects=False, timeout=None):
        """Send a Request, re-authenticating if the session has lapsed.

        This is the only way the checks talk to the target, which is what
        makes the guarantee hold: no check can be testing a logged-out
        application without the engine knowing.
        """
        response = self._send_once(request, allow_redirects, timeout)
        if self.config.strategy == "none" or response is None:
            return response
        # Once we have given up, stay given up.
        #
        # This guard was missing and the effect was visible in the log as
        # "session lapsed — logging back in (attempt 4) … (attempt 7)" after
        # the scanner had already announced it was continuing unauthenticated.
        # The cause is three lines below: any response that happens to look
        # logged in resets the lapse counter, so the "three strikes" test kept
        # being re-armed and the scan spent itself on login requests it had
        # already decided were pointless.
        if self._gave_up:
            return response
        if self.looks_logged_in(response):
            self._consecutive_lapses = 0
            return response
        if PUBLIC_BY_NATURE.search(request.url) or \
                request.url.rstrip("/") == (self.config.login_url or "").rstrip("/"):
            return response          # a login page here is the right answer
        # A response that looks logged out is not proof that we are. A public
        # landing page, a 403 on something genuinely forbidden, an error page
        # with a login form in the header — all of them look like this. The
        # session check is the only thing that actually knows, so ask it
        # before spending a login on a guess.
        if self.verify_session(force=True):
            return response
        if self._consecutive_lapses >= 3:
            # Something is wrong that logging in again will not fix. Say so
            # once and let the engine's report carry it, rather than spending
            # the scan on login requests.
            self._gave_up = True
            self.session_lost(
                "the session would not stay established after three "
                "re-logins. Everything from this point on was requested as "
                "an anonymous user.")
            self.report("[auth] the session will not stay established — "
                        "continuing unauthenticated, and the report will "
                        "say so")
            return response
        # One re-login, then one retry. If it is still logged out the session
        # is genuinely broken and the engine needs to hear about it.
        with self._lock:
            self._relogins += 1
            self._consecutive_lapses += 1
            self.report(f"[auth] session lapsed — logging {self.config.name} "
                        f"back in (attempt {self._relogins})")
            try:
                if self.config.strategy == "form":
                    self._login_form()
                elif self.config.strategy == "browser":
                    self._login_browser()
                elif self.config.strategy == "bearer":
                    self._mint_token()
                else:
                    self._apply_static()
            except Exception as exc:                    # noqa: BLE001
                self.report(f"[auth] re-login failed: {exc}")
                self.logged_in = False
                return response
        retried = self._send_once(request, allow_redirects, timeout)
        # `logged_in` is read by the access-control check to decide whether
        # there is a real session to compare an anonymous one against, so it
        # must mean "the verification URL says we are logged in" and nothing
        # weaker. It used to be set from whether one arbitrary response looked
        # logged-in, and that is how an entirely unauthenticated scan came to
        # report broken access control on every page it had crawled —
        # including jQuery. Both halves of that comparison were anonymous, so
        # of course they matched, and the check believed it was comparing a
        # privileged session against an anonymous one.
        ok, reason = self.check_session()
        self.logged_in = ok
        if not ok:
            self._consecutive_lapses += 1
        else:
            self._consecutive_lapses = 0
            if self.outcome.state in ("failed", "lost"):
                self.outcome.finish(True, f"re-established mid-scan: {reason}",
                                    verified=bool(self.config.check_url))
                self.report(f"[auth] {self.config.name}: session re-established")
                self._publish()
        return retried if retried is not None else response

    def _send_once(self, request, allow_redirects, timeout):
        if self.scope is not None and not self.scope.allows(request.url):
            return None
        if self.forbidden(request.url):
            return None
        if self.pace is not None:
            self.pace()
        self.sent += 1
        if self.config.strategy == "bearer" and self._token_expires and \
                time.time() > self._token_expires - 30:
            with self._lock:
                self._mint_token()
        kwargs = dict(headers=request.headers or None,
                      allow_redirects=allow_redirects,
                      timeout=timeout or self.timeout)
        if request.json_body is not None:
            kwargs["json"] = request.json_body
        elif request.data is not None:
            kwargs["data"] = request.data
        try:
            return self.session.request(request.method, request.url, **kwargs)
        except Exception:                               # noqa: BLE001
            return None

    def forbidden(self, url):
        """True for anything that would end the session or the client's day."""
        lowered = url.lower()
        return any(word in lowered for word in self.config.avoid)


def _read_login_form(html, base_url):
    """Every field the browser would send, the field names, and the action.

    "Every field the browser would send" is the part that was wrong, and it
    cost a real engagement. The first version read ``<input>`` elements only,
    and inside those it skipped anything of type ``submit``. That drops three
    things an application may well require:

      * **the submit control's own name and value.** A great many server-side
        frameworks branch on it — ASP.NET MVC in particular, where a
        controller reads ``Command=Login`` to tell a login POST from any
        other POST to the same URL. Without it the controller does not treat
        the request as a login at all, re-renders the page, and the scanner
        reports "the credentials were refused" against perfectly good
        credentials;
      * **``<button name=… value=…>``**, which is the modern spelling of
        exactly that and was not being looked at at all;
      * **``<select>`` and ``<textarea>``**, which carry their own defaults
        and are occasionally mandatory (a tenant or region picker beside the
        login box).

    Only the *first* submit control is sent, because a browser sends the one
    that was clicked and never more than one — a form with "Log in" and
    "Forgot password" buttons must not have both.
    """
    hidden, username_field, password_field, action = {}, "", "", ""
    try:
        from bs4 import BeautifulSoup
        soup = BeautifulSoup(html or "", "html.parser")
        form = None
        for candidate in soup.find_all("form"):
            if candidate.find("input", {"type": "password"}):
                form = candidate
                break
        if form is None:
            return hidden, ("", ""), ""
        if form.get("action"):
            action = urllib.parse.urljoin(base_url, form["action"])

        submit_sent = False
        for field in form.find_all(["input", "button", "select", "textarea"]):
            tag = field.name.lower()
            name = field.get("name")

            if tag == "button":
                kind = (field.get("type") or "submit").lower()
                if kind == "submit" and name and not submit_sent:
                    hidden[name] = field.get("value", "")
                    submit_sent = True
                continue

            if tag == "select":
                if not name:
                    continue
                chosen = field.find("option", selected=True) or \
                    field.find("option")
                if chosen is not None:
                    hidden[name] = chosen.get("value",
                                              chosen.get_text(strip=True))
                continue

            if tag == "textarea":
                if name:
                    hidden[name] = field.get_text()
                continue

            kind = (field.get("type") or "text").lower()
            if kind in ("submit", "image"):
                # The clicked button. A browser sends exactly one.
                if name and not submit_sent:
                    hidden[name] = field.get("value", "")
                    submit_sent = True
                continue
            if not name:
                continue
            if kind == "hidden":
                hidden[name] = field.get("value", "")
            elif kind == "password" and not password_field:
                password_field = name
            elif kind in ("checkbox", "radio"):
                # Only a ticked box is submitted. "Remember me" left alone.
                if field.has_attr("checked"):
                    hidden[name] = field.get("value", "on")
            elif kind in ("text", "email", "tel", "number", ""):
                if not username_field:
                    username_field = name
    except Exception:                                   # noqa: BLE001
        pass
    return hidden, (username_field, password_field), action
