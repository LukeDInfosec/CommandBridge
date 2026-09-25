"""
Finding the attack surface.

A scanner is only as good as the requests it knows about. Everything the crawl
misses is untested, and the report will not say so — which is why this walks
forms and JavaScript-declared endpoints as well as links, and why it can drive
a real browser when the application is a single-page app that has no links in
its HTML at all.

Three rules it keeps to:

  * **Scope is a hard boundary.** Nothing outside it is requested, ever. A
    scanner that wanders onto a third-party host during a client engagement is
    a serious problem, not an inconvenience.
  * **Shapes, not URLs.** /user/1 … /user/9000 is one thing to test. Without
    this a paginated table turns a two-hour scan into a two-day one.
  * **Nothing destructive while crawling.** Logout links, delete actions and
    anything the profile forbids are recorded as discovered and never
    followed.
"""

from __future__ import annotations

import json
import re
import urllib.parse
from collections import deque

from command_bridge.modules.scanner.model import Request

#: Extensions with no attack surface worth the request.
BORING = re.compile(
    r"\.(png|jpe?g|gif|svg|ico|webp|bmp|woff2?|ttf|eot|otf|mp[34]|avi|mov|"
    r"zip|gz|tar|rar|7z|pdf|docx?|xlsx?|pptx?|css|map)(\?|$)", re.I)

#: Link text and URLs that end a session or destroy something.
DESTRUCTIVE = re.compile(
    r"log ?out|sign ?out|/exit\b|delete|remove|destroy|drop|purge|deactivate|"
    r"cancel.?(account|subscription)|reset.?(all|database)|wipe|terminate",
    re.I)

#: Endpoints declared in JavaScript rather than linked in HTML. Crude by
#: design — a wrong guess costs one request, a missed endpoint costs a finding.
JS_ENDPOINT = re.compile(
    r"""["'`](/(?:api|v\d|rest|graphql|ajax)[A-Za-z0-9_\-/.{}]*)["'`]""")
JS_FETCH = re.compile(
    r"""(?:fetch|axios\.\w+|\.open)\(\s*["'`]([^"'`]+)["'`]""")


class Scope:
    """What may be touched, decided once and enforced everywhere."""

    def __init__(self, seeds, include=(), exclude=(), allow_subdomains=False):
        self.hosts = set()
        self.prefixes = []
        for seed in seeds:
            parsed = urllib.parse.urlparse(seed)
            if parsed.netloc:
                self.hosts.add(parsed.netloc.lower())
                self.prefixes.append(
                    f"{parsed.scheme}://{parsed.netloc.lower()}"
                    + (parsed.path.rsplit("/", 1)[0] if "." in
                       parsed.path.rsplit("/", 1)[-1] else parsed.path))
        self.include = [re.compile(p, re.I) for p in include]
        self.exclude = [re.compile(p, re.I) for p in exclude]
        self.allow_subdomains = allow_subdomains

    def host_ok(self, host):
        host = (host or "").lower()
        if host in self.hosts:
            return True
        if self.allow_subdomains:
            bare = host.split(":")[0]
            return any(bare.endswith("." + h.split(":")[0]) for h in self.hosts)
        return False

    def allows(self, url):
        parsed = urllib.parse.urlparse(url)
        if parsed.scheme not in ("http", "https"):
            return False
        if not self.host_ok(parsed.netloc):
            return False
        if any(pattern.search(url) for pattern in self.exclude):
            return False
        if self.include:
            return any(pattern.search(url) for pattern in self.include)
        return True


class Crawler:
    """Walks the application and returns the requests worth attacking."""

    def __init__(self, auth, scope, profile, report=None):
        self.auth = auth
        self.scope = scope
        self.profile = profile
        self.report = report or (lambda line: None)
        self.requests = {}          # shape → Request
        self.seen_urls = set()
        self.skipped_destructive = []
        self.pages_fetched = 0

    # ── the walk ─────────────────────────────────────────────────────────
    def crawl(self, seeds, should_stop=None):
        queue = deque((url, 0) for url in seeds)
        while queue:
            if should_stop and should_stop():
                break
            url, depth = queue.popleft()
            if depth > self.profile.max_depth:
                continue
            if url in self.seen_urls or not self.scope.allows(url):
                continue
            if BORING.search(url):
                continue
            if self._is_destructive(url):
                self.skipped_destructive.append(url)
                continue
            self.seen_urls.add(url)
            if self.pages_fetched >= self.profile.max_pages:
                self.report(f"[crawl] page limit ({self.profile.max_pages}) "
                            f"reached")
                break

            request = Request("GET", url, source="crawl")
            response = self.auth.send(request, allow_redirects=True)
            if response is None:
                continue
            self.pages_fetched += 1
            self._remember(request)

            content_type = response.headers.get("Content-Type", "")
            body = response.text or ""
            final_url = str(response.url)

            if "html" in content_type.lower():
                for link in self._links(body, final_url):
                    if link not in self.seen_urls:
                        queue.append((link, depth + 1))
                for form_request in self._forms(body, final_url):
                    self._remember(form_request)
                    if form_request.method == "GET":
                        queue.append((form_request.url, depth + 1))
                for script in self._scripts(body, final_url):
                    queue.append((script, depth + 1))
            elif "javascript" in content_type.lower():
                for endpoint in self._js_endpoints(body, final_url):
                    if endpoint not in self.seen_urls:
                        queue.append((endpoint, depth + 1))
            elif "json" in content_type.lower():
                request.json_body = None            # it is a response, not one
        self.report(f"[crawl] {self.pages_fetched} page(s) fetched, "
                    f"{len(self.requests)} distinct request shape(s)")
        return list(self.requests.values())

    def crawl_with_browser(self, seeds, should_stop=None):
        """Render each seed and collect the requests the page actually makes.

        For a single-page application the HTML contains no links at all; the
        attack surface only exists once the JavaScript has run. This produces
        real requests — including the XHR bodies — rather than guesses.
        """
        from playwright.sync_api import sync_playwright
        captured = []
        with sync_playwright() as playwright:
            browser = playwright.chromium.launch(args=["--no-sandbox"])
            context = browser.new_context(ignore_https_errors=True)
            for cookie in self.auth.session.cookies:
                try:
                    context.add_cookies([{
                        "name": cookie.name, "value": cookie.value,
                        "domain": cookie.domain or
                                  urllib.parse.urlparse(seeds[0]).hostname,
                        "path": cookie.path or "/"}])
                except Exception:                       # noqa: BLE001
                    pass
            page = context.new_page()

            def record(route):
                request = route.request
                if self.scope.allows(request.url) and \
                        not BORING.search(request.url):
                    captured.append((request.method, request.url,
                                     request.post_data,
                                     request.headers.get("content-type", "")))
                route.continue_()

            page.route("**/*", record)
            for seed in seeds[:self.profile.max_browser_pages]:
                if should_stop and should_stop():
                    break
                try:
                    page.goto(seed, wait_until="networkidle", timeout=25000)
                    page.wait_for_timeout(800)
                except Exception:                       # noqa: BLE001
                    continue
            browser.close()

        for method, url, body, content_type in captured:
            if self._is_destructive(url):
                self.skipped_destructive.append(url)
                continue
            request = Request(method.upper(), url, source="browser")
            if body:
                if "json" in content_type.lower():
                    try:
                        request.json_body = json.loads(body)
                    except Exception:                   # noqa: BLE001
                        pass
                else:
                    request.data = urllib.parse.parse_qsl(
                        body, keep_blank_values=True)
            self._remember(request)
        self.report(f"[crawl] browser pass captured {len(captured)} "
                    f"request(s)")
        return list(self.requests.values())

    # ── extraction ───────────────────────────────────────────────────────
    def _links(self, html, base_url):
        found = []
        try:
            from bs4 import BeautifulSoup
            soup = BeautifulSoup(html, "html.parser")
            for tag, attribute in (("a", "href"), ("area", "href"),
                                   ("iframe", "src"), ("link", "href")):
                for element in soup.find_all(tag):
                    value = element.get(attribute)
                    if not value or value.startswith(
                            ("#", "javascript:", "mailto:", "tel:", "data:")):
                        continue
                    url = urllib.parse.urljoin(base_url, value)
                    url, _, _ = url.partition("#")
                    if self._is_destructive(url) or \
                            DESTRUCTIVE.search(element.get_text(" ")[:80]):
                        self.skipped_destructive.append(url)
                        continue
                    if self.scope.allows(url):
                        found.append(url)
        except Exception:                               # noqa: BLE001
            pass
        return found

    def _scripts(self, html, base_url):
        found = []
        for match in re.finditer(
                r"""<script[^>]+src\s*=\s*["']([^"']+)["']""", html, re.I):
            url = urllib.parse.urljoin(base_url, match.group(1))
            if self.scope.allows(url):
                found.append(url)
        return found[:self.profile.max_scripts]

    def _js_endpoints(self, source, base_url):
        found = set()
        for pattern in (JS_ENDPOINT, JS_FETCH):
            for match in pattern.finditer(source):
                candidate = match.group(1)
                if "{" in candidate or "${" in candidate:
                    continue
                url = urllib.parse.urljoin(base_url, candidate)
                if self.scope.allows(url) and not BORING.search(url):
                    found.add(url)
        return sorted(found)[:self.profile.max_js_endpoints]

    def _forms(self, html, base_url):
        """Every form, filled with plausible values.

        Empty submissions mostly bounce off validation, and a request that
        never reaches the application logic cannot be tested. The guesses are
        based on the field's own name and type, which is enough to get past
        most front-door validation.
        """
        built = []
        try:
            from bs4 import BeautifulSoup
            soup = BeautifulSoup(html, "html.parser")
        except Exception:                               # noqa: BLE001
            return built

        for form in soup.find_all("form"):
            method = (form.get("method") or "GET").upper()
            action = urllib.parse.urljoin(base_url, form.get("action") or "")
            if not self.scope.allows(action):
                continue
            if self._is_destructive(action) or \
                    DESTRUCTIVE.search(form.get_text(" ")[:120]):
                self.skipped_destructive.append(action)
                continue
            if method not in self.profile.methods:
                continue
            # A login form is the session's own; submitting it with junk logs
            # us out of the scan.
            if form.find("input", {"type": "password"}):
                continue

            fields = []
            for element in form.find_all(["input", "textarea", "select"]):
                name = element.get("name")
                if not name:
                    continue
                if element.name == "select":
                    option = element.find("option")
                    fields.append((name, (option.get("value")
                                          if option else "") or "1"))
                    continue
                kind = (element.get("type") or "text").lower()
                if kind in ("submit", "button", "image", "reset", "file"):
                    continue
                value = element.get("value")
                fields.append((name, value if value not in (None, "")
                               else _plausible(name, kind)))
            if not fields:
                continue

            if method == "GET":
                request = Request("GET", action, source="form")
                built.append(request.with_query(fields))
            else:
                built.append(Request(method, action, data=fields,
                                     source="form"))
        return built

    # ── bookkeeping ──────────────────────────────────────────────────────
    def _remember(self, request):
        shape = request.shape()
        if shape not in self.requests:
            self.requests[shape] = request

    def _is_destructive(self, url):
        return bool(DESTRUCTIVE.search(url)) or self.auth.forbidden(url)


def _plausible(name, kind):
    """A value the application will probably accept."""
    lowered = (name or "").lower()
    if kind == "email" or "email" in lowered:
        return "scanner@example.com"
    if kind == "number" or any(w in lowered for w in
                               ("id", "qty", "quantity", "amount", "num",
                                "page", "count")):
        return "1"
    if kind == "date" or "date" in lowered:
        return "2026-01-01"
    if kind == "url" or "url" in lowered or "link" in lowered:
        return "https://example.com/"
    if kind == "tel" or "phone" in lowered:
        return "01234567890"
    if kind == "checkbox" or kind == "radio":
        return "on"
    if "search" in lowered or "query" in lowered or lowered in ("q", "s"):
        return "test"
    return "CommandBridge"
