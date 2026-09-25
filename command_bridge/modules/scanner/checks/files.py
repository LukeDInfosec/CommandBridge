"""
Path traversal, file inclusion and open redirection.

All three are confirmed by content, never by a status code. A parameter is
only reported as traversable when the response actually contains a file the
web root does not hold — /etc/passwd's field structure, win.ini's section
headers, or the opening line of a PHP source file. A page that echoes the
payload back, or 500s, proves nothing and is not reported.
"""

from __future__ import annotations

import re
import urllib.parse

from command_bridge.modules.scanner.model import Evidence, ScanFinding, \
    response_summary

TRAVERSAL_PAYLOADS = (
    "../../../../etc/passwd",
    "../../../../../../etc/passwd",
    "....//....//....//....//etc/passwd",
    "..%2f..%2f..%2f..%2fetc%2fpasswd",
    "%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
    "..%252f..%252f..%252fetc%252fpasswd",
    "/etc/passwd",
    "/etc/passwd%00",
    "../../../../windows/win.ini",
    "..\\..\\..\\..\\windows\\win.ini",
    "..%5c..%5c..%5cwindows%5cwin.ini",
)

#: What a successful read looks like. Narrow on purpose: an application that
#: merely echoes the payload has not read anything, and reporting that as a
#: file read wastes somebody's afternoon.
PROOF = (
    (re.compile(r"root:[x*!]?:0:0:"), "the structure of /etc/passwd"),
    (re.compile(r"daemon:[x*!]?:\d+:\d+:"), "the structure of /etc/passwd"),
    (re.compile(r"^\s*\[(fonts|extensions|mci extensions)\]", re.I | re.M),
     "the section headers of win.ini"),
)

LFI_PAYLOADS = (
    "php://filter/convert.base64-encode/resource=index",
    "php://filter/convert.base64-encode/resource=config",
    "/proc/self/environ",
)

REDIRECT_CANARY = "cb-redirect-canary.example"
REDIRECT_PAYLOADS = (
    f"https://{REDIRECT_CANARY}/",
    f"//{REDIRECT_CANARY}/",
    f"/\\{REDIRECT_CANARY}/",
    f"https:/\\{REDIRECT_CANARY}/",
    f"https://{REDIRECT_CANARY}%2f%2e%2e",
    f"http://example.com@{REDIRECT_CANARY}/",
)


class TraversalCheck:
    key = "traversal"
    name = "Path traversal"
    issue = "traversal"

    def applies(self, point, profile):
        #: A parameter that never held anything file-shaped is still worth one
        #: pass, but the file-shaped ones go first and get the full payload
        #: set. Names are a hint, not a filter.
        return True

    def run(self, ctx, point, baseline):
        for payload in TRAVERSAL_PAYLOADS:
            request = point.build(payload, mode="replace")
            response = ctx.auth.send(request)
            if response is None:
                continue
            body = response.text or ""
            for pattern, what in PROOF:
                if not pattern.search(body):
                    continue
                return [ScanFinding(
                    issue=self.issue,
                    where=point.request.url,
                    point=point.label(),
                    confidence="confirmed",
                    detail_extra=(
                        f"The parameter is used to build a file path. The "
                        f"response contains {what}, so a file outside the web "
                        f"root was read and returned."),
                    evidence=[Evidence(
                        label=f"Payload: {payload}",
                        request=request.describe(),
                        response=response_summary(response, 500),
                        note="\n".join(body.splitlines()[:6])[:400])])]

        for payload in LFI_PAYLOADS:
            request = point.build(payload, mode="replace")
            response = ctx.auth.send(request)
            if response is None:
                continue
            body = (response.text or "").strip()
            # A base64 PHP source file starts with the encoding of "<?php".
            if body.startswith(("PD9waHA", "PHNjcmlwdA")) or \
                    re.search(r"\bPATH=/", body):
                return [ScanFinding(
                    issue="file_inclusion",
                    where=point.request.url,
                    point=point.label(),
                    confidence="confirmed",
                    detail_extra=(
                        "The parameter selects a file that the application "
                        "reads. A PHP stream wrapper returned the source of "
                        "another file, which is one step from code execution "
                        "on this platform."),
                    evidence=[Evidence(
                        label=f"Payload: {payload}",
                        request=request.describe(),
                        response=response_summary(response, 400))])]
        return []


class OpenRedirectCheck:
    key = "redirect"
    name = "Open redirection"
    issue = "open_redirect"

    #: Only parameters that plausibly carry a destination. Firing redirect
    #: payloads at every parameter on every page is a lot of traffic for a
    #: medium-severity finding.
    LIKELY = re.compile(
        r"^(next|url|redirect|redirect_uri|redirect_url|return|returnurl|"
        r"return_to|continue|dest|destination|target|goto|forward|to|out|"
        r"view|link|r|u)$", re.I)

    def applies(self, point, profile):
        return bool(self.LIKELY.match(point.name or ""))

    def run(self, ctx, point, baseline):
        for payload in REDIRECT_PAYLOADS:
            request = point.build(payload, mode="replace")
            response = ctx.auth.send(request, allow_redirects=False)
            if response is None:
                continue
            location = response.headers.get("Location", "")
            if not (300 <= response.status_code < 400):
                # A meta refresh or a JavaScript assignment counts too.
                body = response.text or ""
                if not re.search(
                        r"(http-equiv=[\"']?refresh[^>]*"
                        + re.escape(REDIRECT_CANARY) + r"|location\s*=\s*"
                        r"[\"'][^\"']*" + re.escape(REDIRECT_CANARY) + ")",
                        body, re.I):
                    continue
                proof = "a meta refresh or a JavaScript assignment"
            else:
                host = urllib.parse.urlparse(
                    location if "//" in location
                    else "//" + location.lstrip("/\\")).netloc
                if REDIRECT_CANARY not in host:
                    continue
                proof = f"Location: {location}"
            return [ScanFinding(
                issue=self.issue,
                where=point.request.url,
                point=point.label(),
                confidence="confirmed",
                detail_extra=(
                    "The destination is taken from the request and used "
                    "without being checked against an allow-list. The "
                    "response sent the browser to a host chosen by the "
                    "request."),
                evidence=[Evidence(
                    label=f"Payload: {payload}",
                    request=request.describe(),
                    response=response_summary(response, 200),
                    note=proof)])]
        return []
