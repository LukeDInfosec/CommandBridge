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

LOGGED_OUT_SIGNS = (
    re.compile(r"<input[^>]+type=[\"']password[\"']", re.I),
    re.compile(r"\b(please (log|sign) ?in|session (has )?expired|"
               r"your session has timed out|you must be logged in|"
               r"authentication required)\b", re.I),
)


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
        self.role = options.get("role", "")      # 'low' / 'high' for IDOR work

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
        try:
            import urllib3
            urllib3.disable_warnings()
        except Exception:
            pass

    # ── logging in ───────────────────────────────────────────────────────
    def login(self):
        """Establish the session. Returns True when it looks authenticated."""
        strategy = self.config.strategy
        with self._lock:
            if strategy == "none":
                self.logged_in = True
                return True
            if strategy == "static":
                self._apply_static()
            elif strategy == "form":
                self._login_form()
            elif strategy == "browser":
                self._login_browser()
            elif strategy == "bearer":
                self._mint_token()
            else:
                raise ValueError(f"unknown auth strategy: {strategy}")
        self.logged_in = self.verify_session(force=True)
        self.report(f"[auth] {self.config.name}: "
                    + ("logged in" if self.logged_in
                       else "could NOT confirm a logged-in session"))
        return self.logged_in

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
        self._apply_static()
        fields = dict(self.config.extra_fields)
        username_field = self.config.username_field or "username"
        password_field = self.config.password_field or "password"
        action = self.config.login_url

        try:
            page = self.session.get(self.config.login_url,
                                    timeout=self.timeout)
            hidden, guessed, form_action = _read_login_form(page.text,
                                                            page.url)
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
        self.session.post(action, data=fields, timeout=self.timeout,
                          allow_redirects=True)

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
        url = self.config.check_url or self.config.login_url
        if not url:
            return True
        try:
            response = self.session.get(url, timeout=self.timeout,
                                        allow_redirects=True)
        except Exception:                               # noqa: BLE001
            return self.logged_in
        return self.looks_logged_in(response)

    def looks_logged_in(self, response):
        """The signature first; the heuristics only when there is none."""
        body = response.text or ""
        if self.config.logged_in_signature:
            return self.config.logged_in_signature in body
        if response.status_code in (401, 403):
            return False
        location = response.headers.get("Location", "")
        if 300 <= response.status_code < 400 and \
                re.search(r"log ?in|sign ?in|auth", location, re.I):
            return False
        return not any(sign.search(body) for sign in LOGGED_OUT_SIGNS)

    def send(self, request, allow_redirects=False, timeout=None):
        """Send a Request, re-authenticating if the session has lapsed.

        This is the only way the checks talk to the target, which is what
        makes the guarantee hold: no check can be testing a logged-out
        application without the engine knowing.
        """
        response = self._send_once(request, allow_redirects, timeout)
        if self.config.strategy == "none" or response is None:
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
            if not self._gave_up:
                self._gave_up = True
                self.report("[auth] the session will not stay established — "
                            "continuing unauthenticated, and the report will "
                            "say so")
                self.logged_in = False
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
        self.logged_in = retried is not None and self.looks_logged_in(retried)
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
    """Hidden fields, field names and the action URL of the login form."""
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
        for field in form.find_all("input"):
            kind = (field.get("type") or "text").lower()
            name = field.get("name")
            if not name:
                continue
            if kind == "hidden":
                hidden[name] = field.get("value", "")
            elif kind == "password" and not password_field:
                password_field = name
            elif kind in ("text", "email") and not username_field:
                username_field = name
    except Exception:                                   # noqa: BLE001
        pass
    return hidden, (username_field, password_field), action
