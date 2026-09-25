"""
Access control — the reason to run an authenticated scan at all.

Everything else in this scanner could, in principle, be found without logging
in. This cannot. Broken access control is a *comparison*: what one user can
reach that another cannot, and what the application will hand to somebody who
simply asks.

Three tests, all of them differential:

  **Forced browsing.** Every authenticated request is replayed with no session
  at all. If it still returns the same content, authentication is decorative —
  the page checks nothing, it merely fails to be linked from anywhere a logged
  out user visits.

  **Horizontal escalation (IDOR).** Requests that identify an object by
  number or by id are replayed as a *second* logged-in user. If that user gets
  the first user's data, the application is checking that you are logged in
  but not that the record is yours. This needs two sessions and cannot be done
  with one.

  **Vertical escalation.** Requests found only while logged in as the
  high-privilege user are replayed as the low-privilege one.

The comparison is the careful part. An application that returns "access
denied" with HTTP 200 defeats a status-code check, so the test is whether the
*content* matches what the authorised user saw — and whether the response
contains the identifying value that makes it that user's record rather than a
generic page.
"""

from __future__ import annotations

import re
import urllib.parse

from command_bridge.modules.scanner.model import Evidence, ScanFinding, \
    response_summary
from command_bridge.modules.scanner import oracles

#: Pages that are meant to be reachable without logging in.
PUBLIC = re.compile(
    r"/(login|signin|register|signup|logout|about|contact|terms|privacy|"
    r"robots\.txt|favicon|health|status|static|assets|public)(/|$|\?)", re.I)

#: Parameters that name an object rather than describing one.
OBJECT_PARAM = re.compile(
    r"^(id|uid|user|user_?id|account|account_?id|customer|customer_?id|"
    r"order|order_?id|invoice|invoice_?id|doc|document|file|record|"
    r"profile|member|ref|no|num|number|key|pid|oid|gid)$", re.I)


class AccessControlCheck:
    """Request-level rather than parameter-level: it replays whole requests."""

    key = "access"
    name = "Broken access control"

    def __init__(self, unauthenticated, second_identity=None):
        #: An Authenticator with strategy 'none' — the anonymous attacker.
        self.unauthenticated = unauthenticated
        #: A second logged-in Authenticator, when one was configured.
        self.second = second_identity

    # ── the pass over every request ──────────────────────────────────────
    def run(self, ctx, request):
        if request.method not in ("GET", "POST"):
            return []
        if PUBLIC.search(request.url):
            return []

        authorised = ctx.auth.send(request, allow_redirects=False)
        if authorised is None or authorised.status_code >= 400:
            return []
        if len((authorised.text or "").strip()) < 40:
            return []

        findings = []
        forced = self._forced_browsing(ctx, request, authorised)
        if forced:
            findings.append(forced)
        if self.second is not None:
            sideways = self._other_user(ctx, request, authorised)
            if sideways:
                findings.append(sideways)
        return findings

    # ── unauthenticated replay ───────────────────────────────────────────
    def _forced_browsing(self, ctx, request, authorised):
        anonymous = self.unauthenticated.send(request, allow_redirects=False)
        if anonymous is None:
            return None
        if anonymous.status_code in (301, 302, 303, 307, 308):
            return None                     # redirected to login: correct
        if anonymous.status_code in (401, 403):
            return None                     # refused: correct
        if anonymous.status_code != authorised.status_code:
            return None

        likeness = oracles.similarity(authorised.text, anonymous.text)
        if likeness < 0.9:
            return None
        # A login page served with HTTP 200 looks nothing like the real page,
        # which the similarity test already catches — but check anyway,
        # because an application that renders a shell around a login form can
        # score high.
        if any(sign.search(anonymous.text or "")
               for sign in __import__(
                   "command_bridge.modules.scanner.session", fromlist=["x"]
               ).LOGGED_OUT_SIGNS):
            return None

        return ScanFinding(
            issue="access_control",
            where=request.url,
            point="no session",
            confidence="confirmed",
            detail_extra=(
                f"This page was requested with no session cookie at all and "
                f"returned the same content as it does for a logged-in user "
                f"(responses {int(likeness * 100)}% identical). The "
                f"authentication in front of it is not being enforced here."),
            evidence=[
                Evidence(label="As the logged-in user",
                         request=request.describe(),
                         response=response_summary(authorised, 350)),
                Evidence(label="With no session",
                         request=request.describe(),
                         response=response_summary(anonymous, 350),
                         note="No cookies, no Authorization header.")])

    # ── replay as somebody else ──────────────────────────────────────────
    def _other_user(self, ctx, request, authorised):
        """The IDOR test: does user B get user A's record?

        Only run against requests that identify an object, and only reported
        when B's response both matches A's *and* contains something that
        identifies A. Without that second condition a shared page — a
        dashboard both users can see — reads as a finding.
        """
        identifiers = self._object_params(request)
        if not identifiers:
            return None

        other = self.second.send(request, allow_redirects=False)
        if other is None or other.status_code >= 400:
            return None
        likeness = oracles.similarity(authorised.text, other.text)
        if likeness < 0.95:
            return None

        # The identifying value is now mandatory. Two users seeing the same
        # page is not an access control failure — a shared dashboard looks
        # exactly like that. It is only a finding when the second user's
        # response contains something that belongs to the first, and if
        # nothing in the page identifies the owner then the scanner cannot
        # honestly claim one. That trade loses the occasional real IDOR whose
        # record has no visible owner; it also removes an entire category of
        # confident nonsense from the report.
        marker = self._owner_marker(authorised.text, ctx.auth.config)
        if not marker or marker not in (other.text or ""):
            return None

        return ScanFinding(
            issue="access_control",
            where=request.url,
            point=", ".join(identifiers),
            confidence="confirmed",
            severity="HIGH",
            detail_extra=(
                f"The request identifies a record by "
                f"{', '.join(identifiers)}. Replaying it as a different "
                f"logged-in user ({self.second.config.name}) returned the "
                f"same record"
                + (f", including '{marker}', which belongs to "
                   f"{ctx.auth.config.name}" if marker else "")
                + ". The application checks that you are logged in but not "
                  "that the record is yours."),
            evidence=[
                Evidence(label=f"As {ctx.auth.config.name}",
                         request=request.describe(),
                         response=response_summary(authorised, 350)),
                Evidence(label=f"As {self.second.config.name}",
                         request=request.describe(),
                         response=response_summary(other, 350),
                         note=f"responses {int(likeness * 100)}% identical")])

    # ── helpers ──────────────────────────────────────────────────────────
    @staticmethod
    def _object_params(request):
        found = []
        for name, value in request.query:
            if OBJECT_PARAM.match(name) and value:
                found.append(f"query '{name}'")
        for name, value in (request.data or []):
            if OBJECT_PARAM.match(name) and value:
                found.append(f"body '{name}'")
        for index, segment in enumerate(request.path.split("/")):
            if segment.isdigit() or re.fullmatch(r"[0-9a-f-]{16,}", segment,
                                                 re.I):
                found.append(f"path segment {index}")
        return found

    @staticmethod
    def _owner_marker(body, config):
        """Something in the page that identifies whose record it is."""
        for candidate in (config.username, config.name):
            if candidate and len(candidate) > 3 and candidate in (body or ""):
                return candidate
        match = re.search(r"[\w.+-]+@[\w-]+\.[\w.]+", body or "")
        return match.group(0) if match else ""


def anonymous_identity(template):
    """An Authenticator with no credentials, for the forced-browsing pass."""
    from command_bridge.modules.scanner.session import AuthConfig, \
        Authenticator
    config = AuthConfig("none", name="anonymous")
    config.avoid = list(template.config.avoid)
    auth = Authenticator(config, verify=template.session.verify,
                         timeout=template.timeout,
                         user_agent=template.session.headers.get("User-Agent"),
                         proxies=template.session.proxies)
    auth.logged_in = True
    return auth
