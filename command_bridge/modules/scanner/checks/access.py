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
  number or by id are replayed as a *second* logged-in user of the same
  privilege level. If that user gets the first user's data, the application is
  checking that you are logged in but not that the record is yours.

  **Vertical escalation.** The same replay, between two users at *different*
  privilege levels. If the lower-privileged account gets the same response as
  the higher-privileged one, the application is checking that you are logged
  in but not what you are allowed to do.

Which of the last two is being run depends entirely on what the second account
is, and the scanner cannot work that out for itself — "user B saw user A's
page" means a data leak between peers if they are peers and a privilege
escalation if they are not. So the operator declares it, in the Active Scan
form, and the finding is titled, scored and explained accordingly. Declaring
it wrong is the main way these results come out wrong, which is why the form
explains what to put where rather than leaving it to a tooltip.

The comparison is the careful part. An application that returns "access
denied" with HTTP 200 defeats a status-code check, so the test is whether the
*content* matches what the authorised user saw — and, for the horizontal
case, whether the response contains the identifying value that makes it that
user's record rather than a generic page.
"""

from __future__ import annotations

import re
import urllib.parse

from command_bridge.modules.scanner.model import Evidence, Request, \
    ScanFinding, response_summary, step
from command_bridge.modules.scanner import oracles
from command_bridge.modules.scanner import grading

#: Pages that are meant to be reachable without logging in.
PUBLIC = re.compile(
    r"/(login|signin|register|signup|logout|about|contact|terms|privacy|"
    r"robots\.txt|favicon|health|status|static|assets|public)(/|$|\?)", re.I)

#: Files the browser fetches to render the page. jQuery is *meant* to be
#: readable without a session; so are the stylesheets, the fonts and the logo.
#: Reporting them as broken access control is noise of the worst kind,
#: because there are hundreds of them and they crowd out the one finding that
#: matters. A static asset is never an access-control finding, whatever the
#: comparison says.
STATIC_ASSET = re.compile(
    r"\.(?:js|mjs|cjs|jsx|ts|css|scss|less|map|png|jpe?g|gif|svg|webp|avif|"
    r"ico|bmp|tiff?|woff2?|ttf|otf|eot|mp4|webm|ogg|mp3|wav|flac|avi|mov|"
    r"pdf|zip|gz|tgz|bz2|xz|7z|rar|txt|xml|json|csv|wasm|manifest|"
    r"appcache)(?:$|\?|#)", re.I)

#: Directories that hold them, for applications that serve assets without an
#: extension (a bundler hash route, a CDN-style path).
ASSET_PATH = re.compile(
    r"/(?:scripts?|js|javascript|css|styles?|fonts?|images?|img|media|"
    r"content|dist|build|bundles?|_next/static|__webpack|vendor|lib|libs|"
    r"node_modules|wp-includes|wp-content/(?:themes|plugins))/", re.I)


def is_static_asset(url):
    return bool(STATIC_ASSET.search(url or "") or ASSET_PATH.search(url or ""))

_ATTRIBUTES = re.compile(r"""=\s*(?:"[^"]*"|'[^']*')""")
_SCRIPTS = re.compile(r"<(script|style)\b.*?</\1>", re.I | re.S)
_COMMENTS = re.compile(r"<!--.*?-->", re.S)


def visible_text(html):
    """The page with its markup values removed, leaving what a reader sees.

    Deliberately crude — this is not a parser and does not need to be. It
    exists so that a username sitting in ``value="…"`` is not mistaken for a
    username the application printed on the page.
    """
    stripped = _COMMENTS.sub(" ", _SCRIPTS.sub(" ", html or ""))
    return _ATTRIBUTES.sub("= ", stripped)


#: An application refusing in prose while returning HTTP 200. Every one of
#: these is a page the challenger did *not* get, however similar it scores.
DENIED = re.compile(
    r"\b(access denied|permission denied|not authori[sz]ed|unauthori[sz]ed|"
    r"forbidden|you (do not|don't) have (the )?(permission|access|rights)|"
    r"insufficient (privileges|permissions)|admin(istrator)?s only|"
    r"restricted area|not allowed to (view|access))\b", re.I)

#: Paths that only a privileged account should be able to reach. Used to
#: prioritise and to score: a lower-privileged user reaching /admin/users is a
#: different conversation from one reaching /dashboard.
PRIVILEGED_PATH = re.compile(
    r"/(admin|administrator|administration|manage|management|console|"
    r"backoffice|back-office|internal|staff|operator|supervisor|root|"
    r"superuser|sysadmin|settings/users|users/\d+/roles?|privileges?|"
    r"permissions?|audit|billing|invoices?|reports?/all|export|"
    r"impersonate|masquerade)(/|$|\?)", re.I)

#: What the second account is, relative to the first.
SAME, LOWER, HIGHER = "same", "lower", "higher"

ROLE_LABELS = {
    SAME: "the same privilege level",
    LOWER: "a lower privilege level",
    HIGHER: "a higher privilege level",
}

#: Parameters that name an object rather than describing one.
OBJECT_PARAM = re.compile(
    r"^(id|uid|user|user_?id|account|account_?id|customer|customer_?id|"
    r"order|order_?id|invoice|invoice_?id|doc|document|file|record|"
    r"profile|member|ref|no|num|number|key|pid|oid|gid)$", re.I)


class AccessControlCheck:
    """Request-level rather than parameter-level: it replays whole requests."""

    key = "access"
    name = "Broken access control"

    def __init__(self, unauthenticated, second_identity=None, role=SAME):
        #: An Authenticator with strategy 'none' — the anonymous attacker.
        self.unauthenticated = unauthenticated
        #: A second logged-in Authenticator, when one was configured.
        self.second = second_identity
        #: What that second account is, relative to the one the scan crawls
        #: as. Declared by the operator; see the module docstring for why it
        #: cannot be inferred.
        self.role = (role or SAME).lower()
        if self.role not in (SAME, LOWER, HIGHER):
            self.role = SAME

    @staticmethod
    def authenticated(ctx):
        """Is there a real logged-in session to compare an anonymous one to?

        Both halves of this check are comparisons — what a logged-in user can
        reach that an anonymous one cannot, and what one user can reach that
        another cannot. Neither question exists without a session, so the
        check does not run rather than answering it wrongly.
        """
        config = getattr(ctx.auth, "config", None)
        if not (config and config.strategy != "none"):
            return False
        if not getattr(ctx.auth, "logged_in", False):
            return False
        # `logged_in` on its own is not enough. A session that was established
        # and has since died leaves the flag set in some code paths, and this
        # check is the one that pays for it: with both halves of the
        # comparison anonymous, every page matches every page and the whole
        # crawl is reported as broken access control. So the outcome has to
        # agree, and the outcome only says "ok" when a verification URL
        # actually confirmed it.
        outcome = getattr(ctx.auth, "outcome", None)
        if outcome is not None and outcome.state not in ("ok", "unverified"):
            return False
        return True

    # ── the pass over every request ──────────────────────────────────────
    def run(self, ctx, request):
        if request.method not in ("GET", "POST"):
            return []
        if PUBLIC.search(request.url):
            return []
        if is_static_asset(request.url):
            # jQuery, the stylesheet and the logo are served to everybody on
            # purpose. They are not access-control findings, and there are
            # enough of them to bury the one that is.
            return []
        if not self.authenticated(ctx):
            # Without a logged-in session there is nothing to compare against.
            # The "authorised" request and the anonymous one are the same
            # request, so every page comes back 100% identical and every page
            # looks like broken access control. On an unauthenticated
            # engagement that is not a finding, it is the definition of the
            # engagement — and a report full of them is worse than useless.
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
            sideways = self._cross_identity(ctx, request, authorised)
            if sideways:
                findings.append(sideways)
        return findings

    # ── which session holds the privilege ────────────────────────────────
    def _roles(self, ctx):
        """``(privileged, challenger)`` for the declared configuration.

        The scan crawls as the primary account, so the primary is the one
        whose responses are known to be legitimate. When the operator says
        the *second* account is the higher-privileged one, the direction of
        the test reverses: the privileged response has to come from the
        second session, and the primary becomes the account that should not
        be able to see it. Replaying a low user's own pages as an admin
        proves nothing, and getting this backwards is how a scanner reports
        "privilege escalation" on every page an administrator can legitimately
        read.
        """
        if self.role == HIGHER:
            return self.second, ctx.auth
        return ctx.auth, self.second

    # ── unauthenticated replay ───────────────────────────────────────────
    def _forced_browsing(self, ctx, request, authorised):
        anonymous = self.unauthenticated.send(request, allow_redirects=False)
        if anonymous is None:
            return None
        # Re-confirm the session right now. A session that lapsed earlier in
        # the scan would make the "authorised" response anonymous too, and
        # every remaining page would be reported.
        if not ctx.auth.verify_session(force=True):
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

        # The part this check was missing, and it is the same mistake the
        # static-asset filter was added to fix, one level up.
        #
        # "An anonymous request returned the same page as a logged-in one"
        # describes every public page ever served: a home page, a catalogue,
        # a search form, a login page. Reported as broken access control it
        # produces a finding for most of the application, and the first
        # scan of a shop front came back with eight of them — /products,
        # /search, /wp-login.php — none of which are meant to need a
        # session in the first place.
        #
        # So something has to establish that this page was *supposed* to be
        # protected. The same two things the vertical check accepts:
        #
        #   * the path says so (/admin, /manage, /billing), or
        #   * the page carries the logged-in account's own data, which a
        #     public page does not — if an anonymous request gets a page
        #     with alice's name and address on it, authentication is not
        #     being enforced, whatever the URL looks like.
        #
        # A protected page at an unremarkable URL showing no owner is missed.
        # That is the deliberate trade, and it is the right way round: a
        # missed finding costs one endpoint, and "broken access control on
        # /search" costs the reader's trust in the whole report.
        privileged_path = bool(PRIVILEGED_PATH.search(request.url))
        marker = self._owner_marker(authorised.text, ctx.auth.config)
        leaked = self._leaked(marker, request, anonymous,
                              self.unauthenticated)
        if not (privileged_path or leaked):
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

        repeated, again = self._repeats(
            self.unauthenticated, request, authorised, 0.9)

        finding = ScanFinding(
            issue="access_control",
            where=request.url,
            point="no session",
            method=request.method,
            auth_context=grading.auth_context(ctx),
            detail_extra=(
                f"This page was requested with no session cookie at all and "
                f"returned the same content as it does for a logged-in user "
                f"(responses {int(likeness * 100)}% identical). The "
                f"authentication in front of it is not being enforced here."),
            evidence=[
                step("As the logged-in user", request, authorised,
                     auth=ctx.auth, body_limit=350),
                step("With no session", request, anonymous,
                     auth=self.unauthenticated, decisive=True, body_limit=350,
                     note="No cookies, no Authorization header.")])
        finding.add(grading.Signal(
            grading.DIFFERENTIAL,
            f"With no session cookie the page returned the same content as "
            f"it does for a logged-in user ({int(likeness * 100)}% "
            f"identical)" + (f", and a second serial request repeated it "
                             f"({int(again * 100)}%)." if repeated
                             else ", but a second serial request did not "
                                  "repeat it."),
            {"similarity": round(likeness, 4),
             "repeat_similarity": round(again, 4),
             "authorised_status": authorised.status_code,
             "anonymous_status": anonymous.status_code},
            reproduced=repeated))
        finding.add(grading.Signal(
            grading.OBSERVATION,
            (f"The anonymous response still contains '{marker}', which "
             f"belongs to {ctx.auth.config.name} — so this is not a public "
             f"page being served to everyone."
             if leaked else
             "The URL is an administrative or otherwise privileged path, so "
             "it is not a page an anonymous visitor is meant to reach.")
            + " The response was not a redirect to a login page, a 401, a "
              "403, or a login form rendered with HTTP 200.",
            {"status": anonymous.status_code,
             "privileged_path": privileged_path,
             "owner_marker": marker if leaked else ""}))
        return finding.settle()

    # ── replay as somebody else ──────────────────────────────────────────
    def _cross_identity(self, ctx, request, authorised):
        """Replay one identity's request as the other, and judge the result.

        Two different questions share this machinery, and which one is being
        asked is decided by the role the operator declared:

        *Same level* — horizontal. "Does user B get user A's record?" Only
        meaningful on a request that identifies an object, and only a finding
        when B's response contains something that belongs to A. Without that
        second condition a shared dashboard reads as an IDOR.

        *Different level* — vertical. "Does the lower-privileged account get
        the higher-privileged one's page?" Here the object identifier is not
        required and the owner marker is not required either: the finding is
        that the page came back at all. What stands in for them is that the
        page is one the lower account should not be able to reach, so the
        content must match and the response must not be a refusal dressed up
        as an HTTP 200.
        """
        privileged, challenger = self._roles(ctx)
        if privileged is None or challenger is None:
            return None

        # When the second account is the privileged one, the baseline passed
        # in came from the wrong session. Fetch the real one.
        if self.role == HIGHER:
            authorised = privileged.send(request, allow_redirects=False)
            if authorised is None or authorised.status_code >= 400:
                return None
            if len((authorised.text or "").strip()) < 40:
                return None

        if self.role == SAME:
            return self._horizontal(ctx, request, authorised,
                                    privileged, challenger)
        # A second account proves whatever it proves, whatever level it is.
        # An admin and a standard user are still two accounts, so if the
        # standard one can read the admin's record by changing an identifier
        # that is an IDOR and belongs in the report — it is simply not the
        # headline the operator asked for. Vertical is tried first because
        # that is what they declared; horizontal catches the rest.
        return (self._vertical(ctx, request, authorised,
                               privileged, challenger)
                or self._horizontal(ctx, request, authorised,
                                    privileged, challenger))

    def _horizontal(self, ctx, request, authorised, privileged, challenger):
        # The IDOR test always runs in the crawl's direction, whatever the
        # declared role. These URLs were discovered while logged in as the
        # first account, so they name the first account's records, and the
        # question is whether the second account can read them. Running it
        # the other way round asks whether the first account can read records
        # it already owns, which is not a question.
        privileged, challenger = ctx.auth, self.second
        if self.role == HIGHER:
            authorised = privileged.send(request, allow_redirects=False)
            if authorised is None or authorised.status_code >= 400:
                return None
        identifiers = self._object_params(request)
        if not identifiers:
            return None

        other = challenger.send(request, allow_redirects=False)
        if not self._got_the_same_page(authorised, other, 0.95):
            return None

        # The identifying value is mandatory for the horizontal case. Two
        # peers seeing the same page is not an access control failure — a
        # shared dashboard looks exactly like that. It is only a finding when
        # the second user's response contains something that belongs to the
        # first, and if nothing in the page identifies the owner then the
        # scanner cannot honestly claim one. That trade loses the occasional
        # real IDOR whose record has no visible owner; it also removes an
        # entire category of confident nonsense from the report.
        marker = self._owner_marker(authorised.text, privileged.config)
        # Same two exclusions as the vertical case: a reflected query value
        # and a shared user listing both put the first account's name in the
        # second account's response without anything having leaked.
        if not self._leaked(marker, request, other, challenger):
            return None

        likeness = oracles.similarity(authorised.text, other.text)
        repeated, again = self._repeats(challenger, request, authorised, 0.95)
        finding = ScanFinding(
            issue="access_control",
            where=request.url,
            point=", ".join(identifiers),
            method=request.method,
            auth_context=grading.auth_context(ctx),
            severity="HIGH",
            detail_extra=(
                f"HORIZONTAL ACCESS CONTROL FAILURE (IDOR). The request "
                f"identifies a record by {', '.join(identifiers)}. Replaying "
                f"it as {challenger.config.name} — declared as "
                f"{ROLE_LABELS[self.role]} relative to "
                f"{privileged.config.name} — returned "
                f"the same record, including '{marker}', which belongs to "
                f"{privileged.config.name}. The application checks that you "
                f"are logged in but not that the record is yours. Any user "
                f"can read any other user's data by changing the identifier."),
            evidence=self._pair(request, authorised, other,
                                privileged, challenger, likeness))
        finding.add(grading.Signal(
            grading.DIFFERENTIAL,
            f"Replayed as {challenger.config.name}, the request returned the "
            f"same record ({int(likeness * 100)}% identical)"
            + (f" and a second serial replay returned it again "
               f"({int(again * 100)}%)." if repeated
               else ", but a second serial replay did not return it again."),
            {"similarity": round(likeness, 4),
             "repeat_similarity": round(again, 4),
             "identifiers": list(identifiers)},
            reproduced=repeated))
        finding.add(grading.Signal(
            grading.OBSERVATION,
            f"The challenger's response contains '{marker}', which belongs "
            f"to {privileged.config.name}.",
            {"owner_marker": marker}))
        return finding.settle()

    def _vertical(self, ctx, request, authorised, privileged, challenger):
        """The privilege-escalation case: does the lower account get in?"""
        other = challenger.send(request, allow_redirects=False)
        if not self._got_the_same_page(authorised, other, 0.90):
            return None

        privileged_path = bool(PRIVILEGED_PATH.search(request.url))
        identifiers = self._object_params(request)

        # The hard part of the vertical test, and the one that decides whether
        # this check is usable. Most of an application is pages both accounts
        # are *meant* to see: a dashboard, a profile, a settings screen. Those
        # come back 99% identical between any two users — they differ by a
        # name in the corner — so "the lower account got the same page" on its
        # own reports the entire application and the tester throws the report
        # away.
        #
        # Something has to establish that this page was restricted. Two things
        # can:
        #
        #   * the path itself says so (/admin, /manage, /users/4/roles), or
        #   * the lower account's response still contains the *privileged
        #     account's* own data — their username or email — which means it
        #     is not being served its own version of a shared page, it is
        #     being served somebody else's.
        #
        # Neither is perfect. A restricted page at an unremarkable URL that
        # shows no owner is missed, and that is the deliberate trade: a missed
        # finding costs one endpoint, and a report full of "privilege
        # escalation on /dashboard" costs the whole check.
        marker = self._owner_marker(authorised.text, privileged.config)
        leaked = self._leaked(marker, request, other, challenger)
        if not (privileged_path or leaked):
            return None

        likeness = oracles.similarity(authorised.text, other.text)
        severity = "CRITICAL" if privileged_path else "HIGH"
        where = ("an administrative or otherwise privileged path"
                 if privileged_path else "a page reached as the privileged "
                                         "account")
        marker = marker if leaked else ""
        repeated, again = self._repeats(challenger, request, authorised, 0.90)
        finding = ScanFinding(
            issue="access_control",
            where=request.url,
            point=", ".join(identifiers) or "whole request",
            method=request.method,
            auth_context=grading.auth_context(ctx),
            severity=severity,
            detail_extra=(
                f"VERTICAL ACCESS CONTROL FAILURE (PRIVILEGE ESCALATION). "
                f"This request was made successfully as "
                f"{privileged.config.name}, and replaying it as "
                f"{challenger.config.name} — declared as "
                f"{ROLE_LABELS[LOWER]} — returned the same content "
                f"({int(likeness * 100)}% identical). The URL is {where}. "
                + (f"The lower-privileged account's response still contains "
                   f"'{marker}', which belongs to "
                   f"{privileged.config.name}. " if marker else "")
                + "The application enforces authentication but not "
                  "authorisation on this endpoint: being logged in as any "
                  "account is enough to reach it."),
            evidence=self._pair(request, authorised, other,
                                privileged, challenger, likeness))
        finding.add(grading.Signal(
            grading.DIFFERENTIAL,
            f"The request succeeded as {privileged.config.name} and, "
            f"replayed as {challenger.config.name}, returned the same "
            f"content ({int(likeness * 100)}% identical)"
            + (f"; a second serial replay returned it again "
               f"({int(again * 100)}%)." if repeated
               else ", but a second serial replay did not return it again."),
            {"similarity": round(likeness, 4),
             "repeat_similarity": round(again, 4),
             "privileged_path": privileged_path},
            reproduced=repeated))
        finding.add(grading.Signal(
            grading.OBSERVATION,
            (f"The lower-privileged account's response contains '{marker}', "
             f"which belongs to {privileged.config.name}." if marker
             else "The URL is an administrative or otherwise privileged "
                  "path, so it is not a page both accounts are meant to "
                  "share."),
            {"owner_marker": marker, "privileged_path": privileged_path}))
        return finding.settle()

    # ── shared judging ───────────────────────────────────────────────────
    @staticmethod
    def _leaked(marker, request, other, challenger):
        """Is the privileged account's identifier really *leaking* here?

        Finding their username in the lower account's response is suggestive
        and, taken literally, wrong twice over:

          * **Reflection.** ``/profile?nick=alice`` echoes whatever is in the
            query string. Every account that requests that URL gets "alice"
            back, because every account asked for it. Nothing leaked.
          * **Shared listings.** A page that prints "All users: alice, bob"
            contains alice's name for everyone, by design. The giveaway is
            that it contains the challenger's name too — a page that leaks
            one user's private data to another does not also contain the
            reader's own name beside it.

        Both of these put real findings and nonsense in the same bucket, and
        the nonsense is far more common, so both are excluded.
        """
        if not marker:
            return False
        # Only text the reader actually sees counts. A form that repopulates
        # itself, a placeholder, or a hardcoded example value —
        # <input name="nick" value="alice"> — puts a username in the markup
        # of a page that belongs to nobody, and three of this check's four
        # false positives during development were exactly that. Attribute
        # values, scripts and styles are stripped before the marker is
        # looked for; private data appears in the body of a page, not in the
        # default value of a search box.
        body = visible_text(other.text or "")
        if marker not in body:
            return False
        # Reflection: the value came from the request we sent.
        haystack = request.url + urllib.parse.urlencode(request.data or [])
        if marker in urllib.parse.unquote_plus(haystack):
            return False
        # A shared listing: the reader's own identifier is on the page too.
        #
        # This used to veto on the challenger's name appearing anywhere in
        # the visible text, which is far too strong. Almost every
        # application puts the logged-in user's name in its own furniture —
        # "Signed in as bob", a nav bar, a greeting — so the test fired on
        # every page and suppressed the real IDORs along with the listings.
        # It was found by scanning a target whose order page genuinely does
        # leak one customer's record to another: the finding was correct,
        # the evidence was there, and this line threw it away because the
        # word "bob" was in the header.
        #
        # So the comparison is made against the page's *content* rather than
        # the whole of it. Anything that also appears on the challenger's
        # own ordinary page is site furniture and is removed first; a shared
        # listing still names both accounts in what is left, and a leaked
        # record no longer does.
        content = _without_chrome(body, challenger)
        if marker not in content:
            return False
        for own in (getattr(challenger.config, "username", ""),
                    getattr(challenger.config, "name", "")):
            if own and len(own) >= 3 and own in content:
                return False
        return True

    @staticmethod
    def _repeats(sender, request, authorised, threshold):
        """Ask the same question a second time, on its own.

        A differential seen once can be a cache, a race, or a server that
        truncated under the load of a concurrent scan. One serial replay is
        what separates a behavioural difference from a coincidence, and the
        grading module will not confirm a differential that did not repeat.
        """
        again = sender.send(request, allow_redirects=False)
        if again is None or again.status_code >= 400:
            return False, 0.0
        if again.status_code in (301, 302, 303, 307, 308):
            return False, 0.0
        likeness = oracles.similarity(authorised.text, again.text)
        return likeness >= threshold, likeness

    @staticmethod
    def _got_the_same_page(authorised, other, threshold):
        """Did the challenger actually get the page, rather than a refusal?"""
        if other is None or other.status_code >= 400:
            return False
        if other.status_code in (301, 302, 303, 307, 308):
            return False                # redirected away: correct behaviour
        if other.status_code != authorised.status_code:
            return False
        body = other.text or ""
        if len(body.strip()) < 40:
            return False
        # An application that refuses with HTTP 200 defeats the status check.
        if DENIED.search(body):
            return False
        from command_bridge.modules.scanner import session as _session
        if any(sign.search(body) for sign in _session.LOGGED_OUT_SIGNS):
            return False
        return oracles.similarity(authorised.text, body) >= threshold

    def _pair(self, request, authorised, other, privileged, challenger,
              likeness):
        return [
            step(f"As {privileged.config.name} (the authorised account)",
                 request, authorised, auth=privileged, body_limit=350),
            step(f"As {challenger.config.name} "
                 f"({ROLE_LABELS[self.role]})",
                 request, other, auth=challenger, decisive=True,
                 body_limit=350,
                 note=f"Identical request, different session. Responses "
                      f"{int(likeness * 100)}% identical.")]

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
        """Something in the page that identifies *this account* as the owner.

        The email fallback is restricted to addresses that plainly belong to
        the account. Taking the first email on the page was wrong in a way
        that mattered: on a page showing somebody else's record it returned
        *their* address as proof that the record belonged to ours, which
        inverts the one thing this function exists to establish.
        """
        for candidate in (config.username, config.name):
            if candidate and len(candidate) >= 3 and candidate in (body or ""):
                return candidate
        username = (config.username or "").lower()
        if len(username) >= 3:
            for match in re.finditer(r"[\w.+-]+@[\w-]+\.[\w.]+", body or ""):
                local = match.group(0).split("@", 1)[0].lower()
                if username in local or local in username:
                    return match.group(0)
        return ""


def _without_chrome(body, challenger):
    """``body`` with the challenger's own site furniture removed.

    The furniture is established empirically rather than guessed at: fetch a
    page the challenger is plainly entitled to — their session-check URL —
    and treat every line of visible text on it as chrome. A navigation bar
    saying "Signed in as bob" appears on both pages and drops out; the body
    of somebody else's record does not appear on it and stays.

    Cached on the Authenticator, so this costs one request per identity per
    scan rather than one per finding.
    """
    lines = [line.strip() for line in (body or "").splitlines()
             if line.strip()]
    chrome = getattr(challenger, "_chrome_lines", None)
    if chrome is None:
        chrome = set()
        check_url = getattr(challenger.config, "check_url", "")
        if check_url:
            try:
                own = challenger.send(Request("GET", check_url),
                                      allow_redirects=True)
                if own is not None and own.text:
                    chrome = {line.strip() for line
                              in visible_text(own.text).splitlines()
                              if line.strip()}
            except Exception:                                 # noqa: BLE001
                chrome = set()
        try:
            challenger._chrome_lines = chrome
        except Exception:                                     # noqa: BLE001
            pass
    if not chrome:
        return "\n".join(lines)
    return "\n".join(line for line in lines if line not in chrome)


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
