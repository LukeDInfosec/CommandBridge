"""
What the scanner passes around.

Three ideas carry the whole engine:

  * a **Request** is one thing the application will accept — method, URL,
    headers, body — captured during the crawl and replayable afterwards;
  * an **InsertionPoint** is one place inside that request where data can be
    put. A request with ``?id=7&sort=name`` and a Cookie has three of them,
    and each is tested independently, because a parameter that is safe in one
    position is frequently not in another;
  * an **Evidence** is the request and response pair that proved something.
    A finding without one is an opinion.

Everything is plain data with no network and no Qt, so the checks can be
tested by calling them.
"""

from __future__ import annotations

import copy
import json
import re
import time
import urllib.parse
from dataclasses import dataclass, field


# ─────────────────────────────────────────────────────────────────────────────
#  Requests
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class Request:
    """One replayable request."""

    method: str = "GET"
    url: str = ""
    headers: dict = field(default_factory=dict)
    #: form-encoded body as a list of (name, value) pairs, preserving order
    #: and duplicates, or None
    data: list = None
    #: parsed JSON body, or None
    json_body: object = None
    #: where it was found, for the report
    source: str = ""

    # ── views ────────────────────────────────────────────────────────────
    @property
    def parsed(self):
        return urllib.parse.urlparse(self.url)

    @property
    def query(self):
        return urllib.parse.parse_qsl(self.parsed.query, keep_blank_values=True)

    @property
    def host(self):
        return self.parsed.netloc.lower()

    @property
    def path(self):
        return self.parsed.path or "/"

    def with_query(self, pairs):
        clone = self.copy()
        clone.url = urllib.parse.urlunparse(
            self.parsed._replace(query=urllib.parse.urlencode(pairs)))
        return clone

    def copy(self):
        return Request(method=self.method, url=self.url,
                       headers=dict(self.headers),
                       data=list(self.data) if self.data is not None else None,
                       json_body=copy.deepcopy(self.json_body),
                       source=self.source)

    # ── identity ─────────────────────────────────────────────────────────
    def shape(self):
        """What makes this request *different* from another one.

        Numeric and hash-like path segments collapse, so /user/1, /user/2 and
        /user/9931 are one shape and get tested once rather than nine thousand
        times. Parameter names matter; their values do not.
        """
        segments = []
        for segment in self.path.split("/"):
            if not segment:
                continue
            if segment.isdigit():
                segments.append("{n}")
            elif re.fullmatch(r"[0-9a-f]{8,}", segment, re.I):
                segments.append("{id}")
            elif re.fullmatch(r"[0-9a-f-]{32,}", segment, re.I):
                segments.append("{uuid}")
            else:
                segments.append(segment)
        names = sorted(name for name, _ in self.query)
        if self.data:
            names += sorted("body:" + name for name, _ in self.data)
        if self.json_body is not None:
            names += sorted("json:" + p for p, _ in json_points(self.json_body))
        return f"{self.method} {self.host}/{'/'.join(segments)}?{','.join(names)}"

    def describe(self):
        text = f"{self.method} {self.url}"
        # A payload in a URL is percent-encoded, which is correct on the wire
        # and unreadable in a report. Show the decoded form underneath when it
        # differs, so the person reading the evidence can see the payload.
        decoded = urllib.parse.unquote_plus(self.url)
        if decoded != self.url:
            text += f"\n  (decoded: {decoded})"
        if self.data:
            text += "\n\n" + urllib.parse.urlencode(self.data)
        elif self.json_body is not None:
            text += "\n\n" + json.dumps(self.json_body)[:600]
        return text


# ─────────────────────────────────────────────────────────────────────────────
#  The request as it went out on the wire
# ─────────────────────────────────────────────────────────────────────────────
#
# `describe()` above is for a human reading a report. This is for a tool. Burp
# Repeater, ZAP and curl all accept a raw HTTP/1.1 message, and a tester who
# can select one block and paste it has reproduced the finding in about four
# seconds. Reconstructing it from the pieces is where this usually goes wrong —
# the session cookie gets left off, the Content-Length disagrees with the body,
# the payload gets double-encoded — so the preferred source is the
# PreparedRequest that `requests` actually sent, which carries the session's
# cookies and headers already merged in.

#: Headers requests/urllib3 add for transport and which Burp will set itself.
#: Leaving them in produces a request that is subtly wrong when replayed.
_TRANSPORT_HEADERS = ("content-length", "transfer-encoding", "connection",
                      "proxy-connection", "host")


def origin_form(url):
    """The request-target: path and query only, as it appears on the wire."""
    parts = urllib.parse.urlparse(url)
    target = parts.path or "/"
    if parts.query:
        target += "?" + parts.query
    return target


def raw_http(prepared, body_limit=8000):
    """A ``requests`` PreparedRequest rendered as a raw HTTP/1.1 message.

    This is the authoritative version: it is literally what went to the
    server, session cookies and all, so what the tester pastes into Repeater
    is the request that produced the finding rather than an approximation of
    it.
    """
    if prepared is None:
        return ""
    host = urllib.parse.urlparse(prepared.url).netloc
    lines = [f"{prepared.method} {origin_form(prepared.url)} HTTP/1.1",
             f"Host: {host}"]
    for name, value in (prepared.headers or {}).items():
        if name.lower() in _TRANSPORT_HEADERS:
            continue
        lines.append(f"{name}: {value}")
    body = prepared.body
    if isinstance(body, bytes):
        body = body.decode("utf-8", "replace")
    if body:
        # Content-Length is recomputed rather than copied: an edited body in
        # Repeater needs a correct length, and a stale one is the single most
        # common reason a pasted request comes back 400.
        lines.append(f"Content-Length: {len(body.encode('utf-8', 'replace'))}")
        lines.append("")
        lines.append(body[:body_limit])
    else:
        # A request with no body still ends with the blank line that closes
        # the header block. Without it Repeater shows the last header as
        # unterminated and some servers hold the connection open.
        lines.append("")
        lines.append("")
    return "\r\n".join(lines)


def raw_http_from_request(request, auth=None, body_limit=8000):
    """The same thing, built from a model Request when no response exists.

    Used for the handful of steps that record a request they never got an
    answer to. Cookies and default headers are read off the live session so
    the block is still complete and still replayable.
    """
    if request is None:
        return ""
    headers = {}
    session = getattr(auth, "session", None)
    if session is not None:
        for name, value in (session.headers or {}).items():
            if value is not None and name.lower() not in _TRANSPORT_HEADERS:
                headers[name] = value
    headers.update(request.headers or {})
    jar = []
    if session is not None:
        jar = [f"{c.name}={c.value}" for c in session.cookies]
    if jar:
        existing = headers.get("Cookie", "")
        headers["Cookie"] = "; ".join(
            ([existing] if existing else []) + jar)

    body = ""
    if request.json_body is not None:
        body = json.dumps(request.json_body)
        headers.setdefault("Content-Type", "application/json")
    elif request.data is not None:
        body = urllib.parse.urlencode(request.data)
        headers.setdefault("Content-Type",
                           "application/x-www-form-urlencoded")

    host = urllib.parse.urlparse(request.url).netloc
    lines = [f"{request.method} {origin_form(request.url)} HTTP/1.1",
             f"Host: {host}"]
    lines += [f"{name}: {value}" for name, value in headers.items()
              if name.lower() not in _TRANSPORT_HEADERS]
    if body:
        lines.append(f"Content-Length: {len(body.encode('utf-8', 'replace'))}")
        lines.append("")
        lines.append(body[:body_limit])
    else:
        # A request with no body still ends with the blank line that closes
        # the header block. Without it Repeater shows the last header as
        # unterminated and some servers hold the connection open.
        lines.append("")
        lines.append("")
    return "\r\n".join(lines)


def wire(request, response=None, auth=None):
    """The best raw request available for this exchange.

    Prefers what was actually sent; falls back to a reconstruction. Never
    returns a half-built request: if there is nothing to render it returns
    "" and the caller says the PoC is unavailable rather than inventing one.
    """
    prepared = getattr(response, "request", None) if response is not None \
        else None
    if prepared is not None:
        return raw_http(prepared)
    return raw_http_from_request(request, auth)


def json_points(node, prefix=""):
    """Every scalar inside a JSON document, as (dotted path, value)."""
    found = []
    if isinstance(node, dict):
        for key, value in node.items():
            found.extend(json_points(value, f"{prefix}.{key}" if prefix else key))
    elif isinstance(node, list):
        for index, value in enumerate(node):
            found.extend(json_points(value, f"{prefix}[{index}]"))
    elif isinstance(node, (str, int, float)) and not isinstance(node, bool):
        found.append((prefix, node))
    return found


def json_set(node, path, value):
    """Return a copy of the document with one scalar replaced."""
    clone = copy.deepcopy(node)
    tokens = re.findall(r"[^.\[\]]+|\[\d+\]", path)
    cursor = clone
    for token in tokens[:-1]:
        if token.startswith("["):
            cursor = cursor[int(token[1:-1])]
        else:
            cursor = cursor[token]
    last = tokens[-1]
    if last.startswith("["):
        cursor[int(last[1:-1])] = value
    else:
        cursor[last] = value
    return clone


# ─────────────────────────────────────────────────────────────────────────────
#  Insertion points
# ─────────────────────────────────────────────────────────────────────────────

QUERY, BODY, JSON, COOKIE, HEADER, PATH = (
    "query", "body", "json", "cookie", "header", "path")

#: Headers worth testing. Testing every header wastes the scan; these are the
#: ones applications actually read and route on.
TESTABLE_HEADERS = ("User-Agent", "Referer", "X-Forwarded-For",
                    "X-Forwarded-Host", "X-Original-URL")


@dataclass
class InsertionPoint:
    """One place in one request where a payload can go."""

    request: Request
    kind: str              # QUERY | BODY | JSON | COOKIE | HEADER | PATH
    name: str
    value: str = ""
    index: int = 0         # which of several same-named parameters

    def label(self):
        return f"{self.kind} parameter '{self.name}'" if self.kind in (
            QUERY, BODY, JSON) else f"{self.kind} '{self.name}'"

    def build(self, payload, mode="replace"):
        """A copy of the request with this point set to ``payload``.

        ``mode`` is 'replace' (the value is thrown away — right for traversal
        and for anything where the original value would break the payload) or
        'append' (payload added to the original — right for SQL where the
        query needs the real value to find a row first).
        """
        value = payload if mode == "replace" else f"{self.value}{payload}"
        request = self.request.copy()

        if self.kind == QUERY:
            pairs = list(request.query)
            pairs[self.index] = (self.name, value)
            return request.with_query(pairs)

        if self.kind == BODY:
            pairs = list(request.data or [])
            pairs[self.index] = (self.name, value)
            request.data = pairs
            return request

        if self.kind == JSON:
            # Keep the original type where we can: an API that validates
            # types rejects a string where it wanted a number, and a
            # rejection is not a negative result.
            request.json_body = json_set(request.json_body, self.name, value)
            return request

        if self.kind == COOKIE:
            jar = dict(_split_cookies(request.headers.get("Cookie", "")))
            jar[self.name] = value
            request.headers["Cookie"] = "; ".join(
                f"{k}={v}" for k, v in jar.items())
            return request

        if self.kind == HEADER:
            request.headers[self.name] = value
            return request

        if self.kind == PATH:
            segments = request.path.split("/")
            segments[self.index] = urllib.parse.quote(str(value), safe="")
            request.url = urllib.parse.urlunparse(
                request.parsed._replace(path="/".join(segments)))
            return request

        raise ValueError(f"unknown insertion point kind: {self.kind}")


def _split_cookies(header):
    for chunk in (header or "").split(";"):
        if "=" in chunk:
            name, _, value = chunk.partition("=")
            yield name.strip(), value.strip()


def insertion_points(request, include_headers=False, include_path=False):
    """Every place in a request worth attacking."""
    points = []
    for index, (name, value) in enumerate(request.query):
        points.append(InsertionPoint(request, QUERY, name, value, index))
    for index, (name, value) in enumerate(request.data or []):
        points.append(InsertionPoint(request, BODY, name, value, index))
    if request.json_body is not None:
        for path, value in json_points(request.json_body):
            points.append(InsertionPoint(request, JSON, path, str(value)))
    if include_headers:
        for name in TESTABLE_HEADERS:
            points.append(InsertionPoint(
                request, HEADER, name, request.headers.get(name, "")))
        for name, value in _split_cookies(request.headers.get("Cookie", "")):
            points.append(InsertionPoint(request, COOKIE, name, value))
    if include_path:
        segments = request.path.split("/")
        for index, segment in enumerate(segments):
            # Only segments that look like data, not like routes.
            if segment and (segment.isdigit()
                            or re.fullmatch(r"[0-9a-f-]{8,}", segment, re.I)):
                points.append(InsertionPoint(request, PATH, f"segment {index}",
                                             segment, index))
    return points


# ─────────────────────────────────────────────────────────────────────────────
#  Results
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class Evidence:
    """The pair that proved it, in the form a client will ask to see."""

    label: str = ""
    request: str = ""
    response: str = ""
    note: str = ""
    #: The exact input that was sent, when this step sent one. Recorded as a
    #: field rather than left to be read back out of the label or the URL: a
    #: proof of concept has to name the payload, and recovering it by parsing
    #: a human-written label is guesswork that silently fails.
    payload: str = ""
    #: True for the step that demonstrates the issue. A boolean SQL injection
    #: proves itself with a pair of requests, and the one worth putting at the
    #: top of a PoC is the one that came back *true*, not the control.
    decisive: bool = False
    #: The same request as a raw HTTP/1.1 message, ready to paste into Burp
    #: Repeater. Stored rather than derived at display time because by then
    #: the live session — and its cookies — is gone.
    raw_request: str = ""

    def render(self):
        parts = [f"── {self.label} " + "─" * max(0, 60 - len(self.label))]
        if self.request:
            parts.append(self.request.strip())
        if self.response:
            parts.append("→\n" + self.response.strip())
        if self.note:
            parts.append(self.note.strip())
        return "\n".join(parts)


@dataclass
class ScanFinding:
    """A confirmed issue.

    ``issue`` is a key into the cb_issues library, so the name, severity,
    explanation, fix and CWE come from the same place as Coffee Break's.
    """

    issue: str
    where: str
    point: str = ""                 # which parameter
    evidence: list = field(default_factory=list)   # [Evidence]
    confidence: str = "confirmed"   # confirmed | firm | tentative
    severity: str = ""              # only to override the library
    detail_extra: str = ""
    found_at: float = field(default_factory=time.time)

    def evidence_text(self):
        return "\n\n".join(item.render() for item in self.evidence)


def step(label, request, response=None, *, auth=None, payload="",
         decisive=False, note="", body_limit=400):
    """One evidence step, with its wire form captured at the same moment.

    Every check builds its evidence through this so that no finding can be
    recorded without the raw request that produced it. That is what makes
    "Copy Burp Request" always work rather than working for whichever checks
    happened to remember.
    """
    return Evidence(
        label=label,
        payload=payload,
        decisive=decisive,
        note=note,
        request=request.describe() if request is not None else "",
        raw_request=wire(request, response, auth),
        response=response_summary(response, body_limit)
        if response is not None else "")


def response_summary(response, body_limit=700):
    """A response rendered the way it should appear in a report."""
    head = f"HTTP {response.status_code} {response.reason}"
    interesting = ("content-type", "content-length", "location", "set-cookie",
                   "server", "x-powered-by")
    for name in interesting:
        if name in response.headers:
            head += f"\n{name.title()}: {response.headers[name][:200]}"
    body = (response.text or "")[:body_limit]
    return head + ("\n\n" + body if body.strip() else "")
