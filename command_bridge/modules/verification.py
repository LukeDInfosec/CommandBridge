"""
Go and check, rather than telling the operator to check.

A finding that ends "confirm this by hand before reporting it" has moved
work onto the reader. Where the check is a safe one — a GET of a path the
scanner already requested, reading what comes back — the application can
do it and say what it saw.

What counts as safe here is narrow and deliberate:

  * GET only, and only of a path a scanner has already reported.
  * One control request per host, to a path that cannot exist, so a
    response can be compared against the host's own catch-all.
  * Nothing is written, nothing is deleted, no OS command is run, no
    payload is sent, and no out-of-band callback is used.

That last restriction is the reason verification is PER CLASS and not a
single routine. A GET proves a file came back. It proves nothing at all
about command injection, SQL injection or XSS, and a generic request
dressed up as confirmation of those would be the same failure this
module exists to correct — a claim outrunning its evidence.

So a detector either names a verification procedure that genuinely
settles its question, or it names none and the finding stays
unconfirmed. An inconclusive result is a result; it is recorded as one.
"""

from __future__ import annotations

import time
import urllib.parse
from dataclasses import dataclass, field

from command_bridge.modules import detector_registry as registry

#: Statuses that mean the path is really served. 401 and 403 included: a
#: protected admin interface is still a reachable admin interface.
REACHABLE = (200, 201, 202, 204, 301, 302, 303, 307, 308, 401, 403, 405)


@dataclass
class Outcome:
    """What verification established. Never more than that."""

    status: str                      # registry.CONFIRMED / POTENTIAL / …
    summary: str = ""                # one line, for "What was found"
    evidence: list = field(default_factory=list)
    http_status: int = 0
    content_type: str = ""
    verified: bool = False           # did a check actually run?
    reason: str = ""                 # why not, when it did not

    def as_dict(self):
        return {
            "status": self.status,
            "summary": self.summary,
            "evidence": list(self.evidence),
            "http_status": self.http_status,
            "content_type": self.content_type,
            "verified": self.verified,
            "reason": self.reason,
        }


class Verifier:
    """Runs the registry's verification procedures against one target.

    ``session_for`` is injected rather than imported so this module has
    no opinion about how requests are made — Coffee Break passes its own
    session factory, which already carries the operator's custom headers,
    the proxy setting and the scan's timeouts.
    """

    def __init__(self, session_for, report=None, in_scope=None):
        self._session_for = session_for
        self._say = report or (lambda line: None)
        self._in_scope = in_scope or (lambda url: True)
        self._catch_all = {}
        self._fetches = 0

    # ── the one request shape this module makes ─────────────────────────

    def _get(self, url, timeout=10):
        """A single GET. Returns the response, or None."""
        if not url or not url.startswith(("http://", "https://")):
            return None
        if not self._in_scope(url):
            self._say(f"not verified — {url} is outside the scan's scope")
            return None
        try:
            session = self._session_for(url)
            self._fetches += 1
            return session.get(url, timeout=timeout, allow_redirects=False)
        except Exception as exc:                            # noqa: BLE001
            self._say(f"could not verify {url}: {exc}")
            return None

    def _catch_all_signature(self, url):
        """How this host answers a path that cannot exist.

        One request per host, cached. None when the host answers 404
        properly — there is then no catch-all to compare against, and
        saying so is different from failing to ask.
        """
        parsed = urllib.parse.urlparse(url)
        host_key = (parsed.scheme, parsed.netloc)
        if host_key in self._catch_all:
            return self._catch_all[host_key]

        probe = (f"{parsed.scheme}://{parsed.netloc}/"
                 f"cb-verify-{int(time.time())}-zzq/none.txt")
        signature = None
        response = self._get(probe)
        if response is not None and response.status_code not in (404, 410):
            signature = {
                "status": response.status_code,
                "type": _kind(response),
                "length": len(response.content or b""),
            }
        self._catch_all[host_key] = signature
        return signature

    @staticmethod
    def _matches_catch_all(response, signature):
        if not signature:
            return False
        if response.status_code != signature["status"]:
            return False
        if _kind(response) != signature["type"]:
            return False
        here, there = len(response.content or b""), signature["length"]
        if max(here, there) == 0:
            return True
        return abs(here - there) / max(here, there) <= 0.05

    # ── the procedures a registry entry can name ────────────────────────

    def run(self, detection):
        """Verify a ``Detection``. Always returns an Outcome."""
        procedure = getattr(detection.detector, "verify", "") or ""
        handler = getattr(self, f"_verify_{procedure}", None)
        if not procedure or handler is None:
            return Outcome(
                status=_floor(detection),
                summary=_signature_summary(detection),
                verified=False,
                reason=("no safe automated check settles this one — "
                        "confirming it means "
                        + (detection.detector.confirm_requires
                           or "manual testing")),
            )
        try:
            return handler(detection)
        except Exception as exc:                            # noqa: BLE001
            return Outcome(status=_floor(detection),
                           summary=_signature_summary(detection),
                           verified=False,
                           reason=f"the check could not be completed: {exc}")

    def _verify_file_contents(self, detection):
        """Did the file actually come back?

        The question a "/.bash_history was retrieved" signature raises,
        and the one it does not answer. Three things have to hold: the
        path answers, the answer is not the host's catch-all, and the
        body is in the file's own format.
        """
        url = detection.url or ""
        response = self._get(url)
        if response is None:
            return Outcome(status=_floor(detection),
                           summary=_signature_summary(detection),
                           verified=False,
                           reason="the path could not be re-requested")

        kind = _kind(response)
        if response.status_code not in REACHABLE:
            return Outcome(
                status=registry.INCONCLUSIVE, verified=True,
                http_status=response.status_code, content_type=kind,
                summary=(f"{detection.path or url} returned HTTP "
                         f"{response.status_code} when re-requested, so the "
                         f"signature is stale."),
                evidence=[f"GET {url} → HTTP {response.status_code}"],
                reason="the path does not answer")

        if self._matches_catch_all(response, self._catch_all_signature(url)):
            return Outcome(
                status=registry.INCONCLUSIVE, verified=True,
                http_status=response.status_code, content_type=kind,
                summary=(f"{detection.path or url} returned HTTP "
                         f"{response.status_code}, but this host serves a "
                         f"catch-all: it answers identically for a path "
                         f"that cannot exist, so nothing was retrieved."),
                evidence=[f"GET {url} → HTTP {response.status_code} "
                          f"({kind}, {len(response.content or b'')} bytes)",
                          "the same response is returned for a random "
                          "non-existent path — the host serves a catch-all"],
                reason="the host serves a catch-all page")

        verdict, why = registry.looks_like_file(detection.detector_name,
                                                response.text or "")
        body_size = len(response.content or b"")
        evidence = [f"GET {url} → HTTP {response.status_code} "
                    f"({kind}, {body_size} bytes)"]

        if verdict is True:
            evidence.append(why)
            sample = _sample(response.text)
            if sample:
                evidence.append("first lines of the response:\n" + sample)
            return Outcome(
                status=registry.CONFIRMED, verified=True,
                http_status=response.status_code, content_type=kind,
                summary=(f"{detection.path or url} is readable and returned "
                         f"{body_size} bytes in the file's own format."),
                evidence=evidence)

        if verdict is False:
            evidence.append(why)
            return Outcome(
                status=registry.INCONCLUSIVE, verified=True,
                http_status=response.status_code, content_type=kind,
                summary=(f"{detection.path or url} answered HTTP "
                         f"{response.status_code}, but {why}."),
                evidence=evidence, reason=why)

        return Outcome(
            status=_ceiling(detection), verified=True,
            http_status=response.status_code, content_type=kind,
            summary=(f"{detection.path or url} answered HTTP "
                     f"{response.status_code} ({kind}, {body_size} bytes); "
                     f"the contents were not recognised either way."),
            evidence=evidence,
            reason="no content signature exists for this file type")

    def _verify_component_version(self, detection):
        """Is the component there, and can its version be established?

        Answers what the detector actually raised — a component is
        reachable — and explicitly declines to answer the question its
        wording invites, which is whether a historical CVE applies. That
        needs the version, and when the version cannot be read, the
        finding says so rather than borrowing the CVE's severity.
        """
        url = detection.url or ""
        response = self._get(url)
        if response is None:
            return Outcome(status=_floor(detection),
                           summary=_signature_summary(detection),
                           verified=False,
                           reason="the interface could not be re-requested")

        kind = _kind(response)
        evidence = [f"GET {url} → HTTP {response.status_code} ({kind})"]
        if response.status_code not in REACHABLE:
            return Outcome(
                status=registry.INCONCLUSIVE, verified=True,
                http_status=response.status_code, content_type=kind,
                summary=(f"{detection.path or url} returned HTTP "
                         f"{response.status_code}; the interface is not "
                         f"reachable."),
                evidence=evidence, reason="the path does not answer")

        if self._matches_catch_all(response, self._catch_all_signature(url)):
            return Outcome(
                status=registry.INCONCLUSIVE, verified=True,
                http_status=response.status_code, content_type=kind,
                summary=(f"{detection.path or url} answered HTTP "
                         f"{response.status_code}, but this host serves a "
                         f"catch-all: it answers identically for a path "
                         f"that cannot exist."),
                evidence=evidence + ["the host serves a catch-all page"],
                reason="the host serves a catch-all page")

        version, where = _version_in(response, detection)
        if version:
            evidence.append(f"version {version} read from {where}")
            return Outcome(
                status=registry.CONFIRMED, verified=True,
                http_status=response.status_code, content_type=kind,
                summary=(f"The interface at {detection.path or url} is "
                         f"reachable and reports version {version}."),
                evidence=evidence)

        evidence.append("no version string was found in the response")
        return Outcome(
            status=registry.POTENTIAL, verified=True,
            http_status=response.status_code, content_type=kind,
            summary=(f"The interface at {detection.path or url} is reachable "
                     f"(HTTP {response.status_code}), but no version could "
                     f"be read, so whether any known issue applies is "
                     f"unestablished."),
            evidence=evidence,
            reason="the version could not be determined from the response")

    def _verify_header_absent(self, detection):
        """Is the header really not there?"""
        url = detection.url or ""
        response = self._get(url)
        if response is None:
            return Outcome(status=_floor(detection),
                           summary=_signature_summary(detection),
                           verified=False,
                           reason="the response could not be re-requested")
        header = _header_for(detection)
        if not header:
            return Outcome(status=_ceiling(detection), verified=False,
                           summary=_signature_summary(detection),
                           reason="no header name is recorded for this check")
        present = header.lower() in {k.lower() for k in response.headers}
        if present:
            return Outcome(
                status=registry.INCONCLUSIVE, verified=True,
                http_status=response.status_code,
                summary=(f"{header} IS present on {url}, so the detection "
                         f"does not hold."),
                evidence=[f"{header}: "
                          f"{response.headers.get(header, '')[:200]}"],
                reason="the header is present")
        return Outcome(
            status=registry.CONFIRMED, verified=True,
            http_status=response.status_code,
            summary=f"{header} is absent from the response for {url}.",
            evidence=[f"GET {url} → HTTP {response.status_code}",
                      f"{header} not present in the response headers"])

    @property
    def requests_made(self):
        return self._fetches


# ── helpers ─────────────────────────────────────────────────────────────

def _kind(response):
    return (response.headers.get("Content-Type") or "") \
        .split(";")[0].strip().lower()


def _floor(detection):
    """Where a finding sits when nothing could be verified."""
    if detection.detector.evidence_kind == registry.SIGNATURE:
        return registry.INCONCLUSIVE
    return _ceiling(detection)


def _ceiling(detection):
    return detection.detector.ceiling


def _signature_summary(detection):
    """"What was found" when no verification procedure applied.

    Uses whatever the detector actually extracted. A finding whose
    summary reads "reported by nuclei at <url>" has told the reader
    nothing they could act on; the extracted values are the observation.
    """
    detector = detection.detector
    where = detection.path or detection.url or "the target"
    extracted = [str(x) for x in (detection.extracted or []) if x]

    if extracted:
        shown = ", ".join(extracted[:4])
        if len(extracted) > 4:
            shown += f", and {len(extracted) - 4} more"
        if detector.evidence_kind == registry.OBSERVED:
            return f"{where}: {shown}"
        return (f"{detection.scanner or 'A scanner'} matched at {where}: "
                f"{shown}. Nothing was read back to confirm it.")

    if detector.evidence_kind == registry.SIGNATURE:
        return (f"{detection.scanner or 'A scanner'} matched a signature for "
                f"this at {where}. Nothing was read back to confirm it.")
    return (f"{detection.scanner or 'A scanner'} observed this at {where}; "
            f"it reported no further detail.")


def _sample(text, lines=4, width=100):
    """A few lines of a response, for the evidence record.

    Short on purpose. The point is to show that the content is what it
    claims to be, not to copy somebody's secrets into a report file.
    """
    out = []
    for line in str(text or "").splitlines():
        line = line.rstrip()
        if not line:
            continue
        out.append(line[:width] + ("…" if len(line) > width else ""))
        if len(out) >= lines:
            break
    return "\n".join(f"    {line}" for line in out)


#: Where a product's version tends to appear, by detector.
_VERSION_PATTERNS = {
    "jamon_admin": (
        r"JAMon[\s/_-]*(?:version)?[\s:v]*([0-9]+(?:\.[0-9]+){1,3})",
        r"jamon[-_]([0-9]+(?:\.[0-9]+){1,3})\.jar",
    ),
}

_GENERIC_VERSION = (
    r"\bversion[\s:]*([0-9]+(?:\.[0-9]+){1,3})\b",
)


def _version_in(response, detection):
    """``(version, where)`` read out of the response, or ``("", "")``."""
    import re
    body = (response.text or "")[:20000]
    patterns = _VERSION_PATTERNS.get(detection.detector_name, ())
    for pattern in patterns:
        match = re.search(pattern, body, re.I)
        if match:
            return match.group(1), "the response body"
    for name in ("X-Powered-By", "Server", "X-Generator"):
        value = response.headers.get(name, "")
        for pattern in patterns + _GENERIC_VERSION:
            match = re.search(pattern, value, re.I)
            if match:
                return match.group(1), f"the {name} header"
    return "", ""


def _header_for(detection):
    """The header a 'missing header' detector is about."""
    mapping = {
        "csp_missing": "Content-Security-Policy",
        "hsts_missing": "Strict-Transport-Security",
        "xfo_missing": "X-Frame-Options",
        "nosniff_missing": "X-Content-Type-Options",
        "referrer_policy": "Referrer-Policy",
        "permissions_policy": "Permissions-Policy",
    }
    return mapping.get(detection.detector.issue_key, "")
