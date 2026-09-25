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
