"""
Cross-site scripting, confirmed by execution.

Most scanners report XSS when their payload comes back in the response. That
is reflection, not execution, and it is where the false positives come from: a
page that echoes ``<script>alert(1)</script>`` inside a textarea, or with a
Content-Security-Policy that stops it dead, or HTML-encoded by a template
engine one layer down, is not vulnerable.

So this check works in three steps:

  1. Send a harmless canary and find **where** it lands — inside an attribute,
     inside a script block, in the page body — and **which characters survive**
     the journey. If nothing dangerous survives, stop here; there is nothing
     to report and nothing more to send.
  2. Choose a payload that fits that context. Breaking out of a
     double-quoted attribute needs a quote; inside a script block it needs
     none at all.
  3. Load the result in headless Chromium and see whether the script *runs*.
     The page is given a marker function to call; if the marker is called, it
     executed. That is the whole test, and it accounts for the CSP, the
     encoding and the browser's own filters, because it is a browser.

When no browser is available the check still reports, at lower confidence,
saying plainly that execution was inferred from the context rather than
observed.
"""

from __future__ import annotations

import re
import urllib.parse

from command_bridge.modules.scanner.model import Evidence, ScanFinding, \
    response_summary
from command_bridge.modules.scanner import oracles

CANARY = "cbx9r4t"
#: The characters that decide whether a reflection can become execution.
DANGEROUS = ("<", ">", "\"", "'", "(", ")", "/", "=", "`")

MARKER = "__cb_xss_fired"

#: One payload per context. ``MARK`` is replaced with the call that proves
#: execution, so the same payloads work with and without a browser.
BY_CONTEXT = {
    "html": ['<img src=x onerror="MARK">',
             '<svg onload="MARK">',
             '<script>MARK</script>'],
    "attribute-double": ['" onmouseover="MARK" x="',
                         '"><img src=x onerror="MARK">',
                         '" autofocus onfocus="MARK" x="'],
    "attribute-single": ["' onmouseover='MARK' x='",
                         "'><img src=x onerror='MARK'>",
                         "' autofocus onfocus='MARK' x='"],
    "attribute-bare": [' onmouseover=MARK ',
                       '><img src=x onerror=MARK>'],
    "script": ["';MARK;//", '";MARK;//', "-MARK-", "</script><img src=x "
                                                   "onerror=MARK>"],
    "raw-text": ['</textarea><img src=x onerror="MARK">',
                 '</title><img src=x onerror="MARK">',
                 '</style><img src=x onerror="MARK">'],
    "comment": ['--><img src=x onerror="MARK">'],
}

#: What the browser is asked to call. Kept trivial so a CSP that allows
#: inline handlers at all will allow it.
BROWSER_MARK = f"window.{MARKER}=1"
#: What is looked for when there is no browser: an alert is only used as a
#: textual marker in that case, never executed by the scanner.
TEXT_MARK = f"window.{MARKER}=1"


class XssCheck:
    key = "xss"
    name = "Cross-site scripting"
    issue = "xss_reflected"

    def applies(self, point, profile):
        return True

    def run(self, ctx, point, baseline):
        # Step 1 — is it reflected at all, and what survived?
        # The canary is unique per insertion point so that if it turns up on
        # a different page later, the stored-XSS sweep knows exactly which
        # request put it there.
        tag = "%04x" % (abs(hash((point.request.shape(), point.kind,
                                  point.name))) % 0xFFFF)
        canary = CANARY + tag
        # The canary goes in front of the characters and nowhere else. An
        # earlier version bracketed them with a second canary, which meant the
        # markup immediately after that trailing canary — the closing </p> of
        # a perfectly escaped page — counted as a surviving '<'.
        probe_value = f"{canary}{''.join(DANGEROUS)}"
        probe = point.build(probe_value, mode="replace")
        try:
            ctx.plant(canary, probe, point.label())
        except Exception:                               # noqa: BLE001
            pass
        response = ctx.auth.send(probe)
        if response is None:
            return []
        body = response.text or ""
        if canary not in body:
            return []
        # Reflection into something that is not a document cannot become
        # script. A canary echoed into a JSON error or a text/plain download
        # is not cross-site scripting, and reporting it as such is how a
        # scanner loses the reader's trust.
        content_type = (response.headers.get("Content-Type") or "").lower()
        if content_type and not any(kind in content_type for kind in
                                    ("html", "xhtml", "xml")):
            return []

        contexts = oracles.reflection_contexts(body, canary)
        if not contexts:
            return []
        # The probe was canary + every dangerous character + canary, so a
        # character survived if and only if it still follows the canary. The
        # earlier version also looked at the surrounding page, which meant the
        # closing </p> after an escaped reflection counted as a surviving '<'
        # — and every properly escaped page was reported as vulnerable.
        intact = [c for c in DANGEROUS if f"{canary}{c}" in body]
        if not any(c in intact for c in ("<", "\"", "'", "`")):
            # Everything that matters was encoded. Reflection without any of
            # these is not exploitable and is not worth a line in a report.
            return []

        findings = []
        for context in contexts[:3]:
            finding = self._try_context(ctx, point, context, response, canary)
            if finding:
                findings.append(finding)
                break
        return findings

    def _try_context(self, ctx, point, context, first_response, canary):
        for template in BY_CONTEXT.get(context["kind"], BY_CONTEXT["html"]):
            payload = template.replace("MARK", BROWSER_MARK)
            request = point.build(payload, mode="replace")
            response = ctx.auth.send(request)
            if response is None:
                continue
            body = response.text or ""
            # The payload has to survive intact — if the template engine
            # encoded the angle brackets there is nothing to execute.
            if payload not in body and payload.replace('"', "&quot;") in body:
                continue
            if MARKER not in body:
                continue

            executed, how = self._executes(ctx, request, response, body)
            if executed is False:
                continue

            confidence = "confirmed" if executed else "firm"
            return ScanFinding(
                issue=self._issue_for(point),
                where=point.request.url,
                point=point.label(),
                confidence=confidence,
                detail_extra=(
                    f"Input to this parameter is reflected into the page in a "
                    f"{context['kind']} context, and the characters needed to "
                    f"break out of it are not encoded. " + how),
                evidence=[
                    Evidence(label="Where the input lands",
                             request=point.build(canary, "replace").describe(),
                             note=context["excerpt"]),
                    Evidence(label="Payload for that context",
                             request=request.describe(),
                             response=response_summary(response, 400))])
        return None

    def _executes(self, ctx, request, response, body):
        """Load it in a browser and see whether the script actually runs."""
        if not ctx.profile.use_browser:
            return None, ("Execution was inferred from the reflection context "
                          "rather than observed, because the scan ran without "
                          "a browser. Confirm by hand before reporting it.")
        try:
            from playwright.sync_api import sync_playwright
        except Exception:                               # noqa: BLE001
            return None, ("Execution could not be observed — Playwright is "
                          "not installed — so this is based on the reflection "
                          "context alone.")

        try:
            with sync_playwright() as playwright:
                browser = playwright.chromium.launch(args=["--no-sandbox"])
                context = browser.new_context(ignore_https_errors=True)
                for cookie in ctx.auth.session.cookies:
                    try:
                        context.add_cookies([{
                            "name": cookie.name, "value": cookie.value,
                            "domain": cookie.domain or
                                      urllib.parse.urlparse(request.url).hostname,
                            "path": cookie.path or "/"}])
                    except Exception:                   # noqa: BLE001
                        pass
                page = context.new_page()
                if request.method == "GET":
                    page.goto(request.url, wait_until="domcontentloaded",
                              timeout=20000)
                else:
                    # Render the response body against the right origin, so
                    # the CSP and the document's own origin still apply.
                    page.goto(request.url.split("?")[0],
                              wait_until="domcontentloaded", timeout=20000)
                    page.set_content(body, wait_until="domcontentloaded")
                page.wait_for_timeout(700)
                try:
                    page.mouse.move(5, 5)
                    page.mouse.move(400, 300)           # trigger onmouseover
                    page.wait_for_timeout(300)
                except Exception:                       # noqa: BLE001
                    pass
                fired = bool(page.evaluate(f"() => !!window.{MARKER}"))
                browser.close()
        except Exception as exc:                        # noqa: BLE001
            return None, (f"Execution could not be observed ({exc}); this is "
                          f"based on the reflection context alone.")

        if fired:
            return True, ("The payload was loaded in a real browser and the "
                          "injected script executed — the Content-Security-"
                          "Policy and the page's own encoding did not stop "
                          "it.")
        return False, ""

    @staticmethod
    def _issue_for(point):
        return "xss_reflected"


class StoredXssCheck:
    """Did anything we submitted earlier come back somewhere else?

    Stored XSS is a different shape of problem: the payload goes into one
    request and appears in another, often on a page the submitting user never
    sees. This runs at the end of the scan, after the forms have been
    submitted, and looks for the scanner's own canaries anywhere in the
    application.
    """

    key = "xss_stored"
    name = "Stored cross-site scripting"
    issue = "xss_stored"

    def __init__(self, planted):
        #: canary → (request that planted it, the insertion point's label)
        self.planted = planted

    def sweep(self, ctx, requests):
        findings = []
        for request in requests:
            if request.method != "GET":
                continue
            response = ctx.auth.send(request, allow_redirects=True)
            if response is None:
                continue
            body = response.text or ""
            for canary, (origin, label) in self.planted.items():
                if canary not in body:
                    continue
                contexts = oracles.reflection_contexts(body, canary)
                if not contexts:
                    continue
                if not re.search(re.escape(canary) + r"[^&]*[<\"']", body):
                    continue
                findings.append(ScanFinding(
                    issue=self.issue,
                    where=request.url,
                    point=label,
                    confidence="firm",
                    detail_extra=(
                        "Input submitted to one page is stored and rendered "
                        "on another, in a context where the characters needed "
                        "for script injection are not encoded. Stored XSS "
                        "runs for every user who views the page, without any "
                        "link being clicked."),
                    evidence=[
                        Evidence(label="Submitted here",
                                 request=origin.describe()),
                        Evidence(label="Rendered here",
                                 request=request.describe(),
                                 response=response_summary(response, 400),
                                 note=contexts[0]["excerpt"])]))
                break
        return findings
