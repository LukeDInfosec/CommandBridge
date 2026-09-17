#!/usr/bin/env python3
"""Parse a pasted HTTP request into something replayable.

Testers copy requests out of two places: a proxy (Burp / ZAP → "Copy to
file", giving a raw request) and browser DevTools (→ "Copy as cURL"). Both
land on the clipboard constantly during an engagement, so both are accepted
here rather than making anyone reformat by hand.

Everything downstream — the rate-limit tester, and anything else that needs
to replay a real authenticated request — works off ParsedRequest, so the
parsing rules live in exactly one place.

Raw form::

    POST /Service.svc HTTP/1.1
    Host: api.example.co.uk
    Content-Type: application/soap+xml; charset=utf-8
    Authorization: Bearer eyJ...

    <soap:Envelope>...</soap:Envelope>

curl form::

    curl 'https://api.example.co.uk/Service.svc' \\
      -H 'Content-Type: application/soap+xml' \\
      --data-raw '<soap:Envelope>...</soap:Envelope>'
"""

from __future__ import annotations

import shlex
import urllib.parse
from dataclasses import dataclass, field

#: Hop-by-hop and length headers that must not be replayed verbatim: the
#: HTTP client recomputes them, and sending a stale Content-Length is a
#: reliable way to get a 400 that looks like the target rejecting you.
SKIP_HEADERS = {"content-length", "connection", "keep-alive", "transfer-encoding",
                "upgrade", "proxy-connection", "te", "trailer"}

METHODS = {"GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS", "TRACE", "CONNECT"}


@dataclass
class ParsedRequest:
    method: str = "GET"
    url: str = ""
    headers: dict = field(default_factory=dict)
    body: bytes | None = None

    def summary(self) -> str:
        parts = [f"{self.method} {self.url}"]
        if self.headers:
            parts.append(f"{len(self.headers)} header(s)")
        if self.body:
            parts.append(f"{len(self.body)} byte body")
        return "  |  ".join(parts)

    def header(self, name: str, default=None):
        for key, value in self.headers.items():
            if key.lower() == name.lower():
                return value
        return default


class RequestParseError(ValueError):
    """The pasted text could not be understood as a request."""


def _clean_headers(pairs) -> dict:
    headers = {}
    for name, value in pairs:
        if name.lower() in SKIP_HEADERS:
            continue
        headers[name] = value
    return headers


def parse_curl(text: str) -> ParsedRequest:
    """Parse a `curl` command line, as copied from browser DevTools."""
    # DevTools wraps long commands with backslash-newline; shlex needs it flat.
    flat = text.replace("\\\n", " ").replace("^\n", " ").replace("`\n", " ")
    try:
        tokens = shlex.split(flat)
    except ValueError as exc:
        raise RequestParseError(f"could not split the curl command: {exc}") from exc

    if not tokens or tokens[0] != "curl":
        raise RequestParseError("does not start with 'curl'")

    url = ""
    method = ""
    headers = []
    body = None

    i = 1
    while i < len(tokens):
        token = tokens[i]
        if token in ("-X", "--request") and i + 1 < len(tokens):
            method = tokens[i + 1].upper()
            i += 2
        elif token in ("-H", "--header") and i + 1 < len(tokens):
            raw = tokens[i + 1]
            if ":" in raw:
                name, value = raw.split(":", 1)
                headers.append((name.strip(), value.strip()))
            i += 2
        elif token in ("-b", "--cookie") and i + 1 < len(tokens):
            headers.append(("Cookie", tokens[i + 1]))
            i += 2
        elif token in ("-A", "--user-agent") and i + 1 < len(tokens):
            headers.append(("User-Agent", tokens[i + 1]))
            i += 2
        elif token in ("-d", "--data", "--data-raw", "--data-binary",
                       "--data-ascii", "--data-urlencode") and i + 1 < len(tokens):
            body = tokens[i + 1].encode("utf-8")
            i += 2
        elif token in ("--url",) and i + 1 < len(tokens):
            url = tokens[i + 1]
            i += 2
        elif token.startswith("-"):
            # Flags that take no argument (-s, -k, --compressed, ...) or ones
            # not relevant to replaying the request.
            i += 1
        else:
            if not url:
                url = token
            i += 1

    if not url:
        raise RequestParseError("no URL found in the curl command")
    if not method:
        method = "POST" if body is not None else "GET"

    return ParsedRequest(method=method, url=url, headers=_clean_headers(headers), body=body)


def parse_raw_http(text: str, base_url: str = "") -> ParsedRequest:
    """Parse a raw HTTP request as copied from a proxy.

    A raw request carries only a path, so the scheme and host come from the
    Host header, falling back to `base_url` (the app's target) when the paste
    has no Host — which happens with HTTP/2 captures.
    """
    normalised = text.replace("\r\n", "\n").strip("\n")
    if not normalised.strip():
        raise RequestParseError("the request is empty")

    head, _, body_text = normalised.partition("\n\n")
    lines = [line for line in head.split("\n") if line.strip()]
    if not lines:
        raise RequestParseError("no request line found")

    request_line = lines[0].split()
    if len(request_line) < 2 or request_line[0].upper() not in METHODS:
        raise RequestParseError(
            f"first line is not an HTTP request line: {lines[0][:60]!r}"
        )
    method = request_line[0].upper()
    path = request_line[1]

    header_pairs = []
    for line in lines[1:]:
        if ":" not in line:
            continue
        name, value = line.split(":", 1)
        header_pairs.append((name.strip(), value.strip()))

    host = ""
    scheme = "https"
    for name, value in header_pairs:
        if name.lower() == ":authority" or name.lower() == "host":
            host = value.strip()
    if base_url:
        parsed_base = urllib.parse.urlparse(
            base_url if "://" in base_url else "https://" + base_url
        )
        if parsed_base.scheme:
            scheme = parsed_base.scheme
        if not host:
            host = parsed_base.netloc

    if path.startswith("http://") or path.startswith("https://"):
        url = path
    elif host:
        url = f"{scheme}://{host}{path if path.startswith('/') else '/' + path}"
    else:
        raise RequestParseError(
            "no Host header and no target set — add a Host header to the request"
        )

    body = body_text.encode("utf-8") if body_text.strip() else None
    if body is None and method in ("POST", "PUT", "PATCH"):
        body = b""  # an intentionally empty body, not "no body"

    return ParsedRequest(method=method, url=url,
                         headers=_clean_headers(header_pairs), body=body)


def parse_any(text: str, base_url: str = "") -> ParsedRequest:
    """Work out which form was pasted and parse it.

    A bare URL on its own is accepted too, so the simplest case still works
    without the user having to construct a request.
    """
    stripped = (text or "").strip()
    if not stripped:
        raise RequestParseError("nothing was pasted")

    if stripped.lstrip().startswith("curl"):
        return parse_curl(stripped)

    first = stripped.split("\n", 1)[0].split()
    if first and first[0].upper() in METHODS and len(first) >= 2:
        return parse_raw_http(stripped, base_url)

    if "\n" not in stripped and "://" in stripped:
        return ParsedRequest(method="GET", url=stripped)

    raise RequestParseError(
        "unrecognised format — paste either a raw HTTP request "
        "(METHOD /path, headers, blank line, body) or a curl command"
    )
