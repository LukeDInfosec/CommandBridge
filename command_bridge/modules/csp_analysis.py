"""
Can this page be framed by another site? Read from the policy, not from
the fact that a policy exists.

The finding this replaces printed a whole Content-Security-Policy header
under the title "CSP allows clickjacking" and left the reader to work
out which part of it was the problem. On the header that prompted this —

    base-uri 'self'; connect-src 'self' https://…; default-src 'self';
    font-src 'self' https://fonts.gstatic.com; …

— nothing in what was shown explains the finding, and two of the things
a reader might reach for are wrong:

  * ``default-src`` is NOT a fallback for ``frame-ancestors``. The
    fallback chain covers fetch directives; ``frame-ancestors`` is a
    navigation directive and falls back to nothing. A policy with
    ``default-src 'self'`` and no ``frame-ancestors`` places no
    restriction at all on who may embed the page.
  * ``frame-src`` is not ``frame-ancestors``. ``frame-src`` governs what
    this page may load INTO a frame; ``frame-ancestors`` governs who may
    embed THIS page. They point in opposite directions.

A long header, third-party origins in ``font-src``, or an unrestricted
``connect-src`` are not framing problems and must not produce this
finding. ``connect-src`` governs where script may send requests.

Terminology: the organisation this is written for calls the issue
**Cross-Site Framing**. "Clickjacking" names one way of abusing it —
overlaying a decoy on a framed page — and the finding is about the
framing itself, whether or not that particular abuse follows.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

#: Directives that do not fall back to default-src. frame-ancestors is
#: the one that matters here, and listing the others makes the rule
#: visible rather than implicit in a comment.
NO_FALLBACK = frozenset({
    "frame-ancestors", "base-uri", "form-action", "report-uri",
    "report-to", "sandbox", "upgrade-insecure-requests",
    "block-all-mixed-content", "navigate-to", "require-trusted-types-for",
    "trusted-types",
})

# ── what the framing policy comes out as ────────────────────────────────

NO_RESTRICTION = "no_restriction"        # nothing restricts framing
SELF_ONLY = "self_only"                  # 'self' — same origin only
NONE = "none"                            # 'none' — nobody
SPECIFIC_ORIGINS = "specific_origins"    # a named allow-list
WILDCARD = "wildcard"                    # * or a scheme-wide source
UNKNOWN = "unknown"                      # no response was inspected


@dataclass
class FramingPolicy:
    """The effective answer to "who may embed this page?"."""

    verdict: str = UNKNOWN
    csp_present: bool = False
    csp_value: str = ""
    report_only_value: str = ""
    frame_ancestors: tuple = ()           # the sources, as written
    frame_ancestors_present: bool = False
    xfo_value: str = ""
    xfo_present: bool = False
    xfo_effective: bool = False
    permitted_origins: tuple = ()
    notes: list = field(default_factory=list)
    inspected: bool = False               # was a real response read?

    @property
    def restricted(self):
        """Is framing actually restricted by something?"""
        return self.verdict in (SELF_ONLY, NONE) or self.xfo_effective

    @property
    def vulnerable(self):
        """Is this a Cross-Site Framing finding?"""
        if not self.inspected:
            return False
        if self.xfo_effective:
            return False
        return self.verdict in (NO_RESTRICTION, WILDCARD)

    def as_dict(self):
        return {"verdict": self.verdict, "csp_present": self.csp_present,
                "frame_ancestors": list(self.frame_ancestors),
                "frame_ancestors_present": self.frame_ancestors_present,
                "xfo": self.xfo_value, "xfo_effective": self.xfo_effective,
                "permitted_origins": list(self.permitted_origins),
                "inspected": self.inspected, "notes": list(self.notes)}


def directives(policy):
    """A CSP string → ``{name: [sources]}``, names lowercased.

    Source values keep their original case, because an origin is
    case-sensitive in the part that matters and a report that lowercases
    somebody's hostname is quietly altering the evidence. Keywords are
    compared case-insensitively where they are compared.
    """
    out = {}
    for chunk in str(policy or "").split(";"):
        parts = chunk.strip().split()
        if not parts:
            continue
        name = parts[0].lower()
        if name not in out:              # first occurrence wins, per spec
            out[name] = parts[1:]
    return out


def _xfo_is_effective(value):
    """Does this X-Frame-Options value actually restrict framing?

    DENY and SAMEORIGIN do. ALLOW-FROM is obsolete and ignored by every
    current browser, so a page relying on it is not protected — saying
    otherwise would be inventing a protection the reader does not have.
    """
    token = str(value or "").strip().upper()
    if not token:
        return False, ""
    if token in ("DENY", "SAMEORIGIN"):
        return True, ""
    if token.startswith("ALLOW-FROM"):
        return False, ("X-Frame-Options is set to ALLOW-FROM, which is "
                       "obsolete and ignored by current browsers, so it "
                       "provides no protection")
    return False, (f"X-Frame-Options has an unrecognised value "
                   f"({token[:40]!r}), which browsers ignore")


def assess_framing(headers=None, csp=None, report_only=None, xfo=None,
                   inspected=None):
    """Work out the effective framing policy.

    ``headers`` is a response's header mapping when one was read; the
    individual arguments are for callers that already hold the values.
    ``inspected`` says whether a real response was examined — a finding
    must not claim "X-Frame-Options is not present" unless something
    actually looked.
    """
    policy = FramingPolicy()

    if headers is not None:
        lowered = {str(k).lower(): str(v) for k, v in dict(headers).items()}
        csp = csp if csp is not None else \
            lowered.get("content-security-policy", "")
        report_only = report_only if report_only is not None else \
            lowered.get("content-security-policy-report-only", "")
        xfo = xfo if xfo is not None else lowered.get("x-frame-options", "")
        policy.inspected = True if inspected is None else bool(inspected)
    else:
        policy.inspected = bool(inspected)

    policy.csp_value = str(csp or "")
    policy.report_only_value = str(report_only or "")
    policy.xfo_value = str(xfo or "")
    policy.csp_present = bool(policy.csp_value.strip())
    policy.xfo_present = bool(policy.xfo_value.strip())

    policy.xfo_effective, xfo_note = _xfo_is_effective(policy.xfo_value)
    if xfo_note:
        policy.notes.append(xfo_note)

    parsed = directives(policy.csp_value)
    sources = parsed.get("frame-ancestors")
    policy.frame_ancestors_present = sources is not None
    policy.frame_ancestors = tuple(sources or ())

    if sources is None:
        policy.verdict = NO_RESTRICTION
        if policy.csp_present:
            # Name the two directives a reader is most likely to think
            # cover this, and say why they do not.
            if "default-src" in parsed:
                policy.notes.append(
                    "the policy sets default-src, which is not a fallback "
                    "for frame-ancestors — frame-ancestors is a navigation "
                    "directive and falls back to nothing")
            if "frame-src" in parsed:
                policy.notes.append(
                    "the policy sets frame-src, which controls what this "
                    "page may load into a frame, not who may embed this "
                    "page")
        if policy.report_only_value and \
                "frame-ancestors" in directives(policy.report_only_value):
            policy.notes.append(
                "frame-ancestors appears only in the Report-Only policy, "
                "which is not enforced")
    else:
        lowered_sources = [s.lower() for s in sources]
        if not sources:
            # "frame-ancestors;" with no source list is equivalent to
            # 'none' per the grammar.
            policy.verdict = NONE
            policy.notes.append("frame-ancestors is present with an empty "
                                "source list, which means 'none'")
        elif any(s in ("*", "http:", "https:", "data:", "blob:")
                 for s in lowered_sources):
            policy.verdict = WILDCARD
            policy.permitted_origins = tuple(sources)
        elif "'none'" in lowered_sources:
            policy.verdict = NONE
        elif all(s in ("'self'",) for s in lowered_sources):
            policy.verdict = SELF_ONLY
        else:
            policy.verdict = SPECIFIC_ORIGINS
            policy.permitted_origins = tuple(
                s for s in sources if s.lower() != "'self'")
            if any(s.startswith("*.") for s in lowered_sources):
                policy.notes.append(
                    "one of the permitted sources is a wildcard subdomain, "
                    "so any host under that domain may embed the page")
    return policy


def explain_framing(policy, url=""):
    """``(summary, evidence_lines, limitation)`` for a framing finding.

    Deterministic: every sentence below is selected by a value read out
    of the policy above, and none of it is generic prose about framing.
    """
    where = f" on {url}" if url else ""
    evidence = []

    if policy.frame_ancestors_present:
        evidence.append("frame-ancestors: "
                        + (" ".join(policy.frame_ancestors) or "(empty)"))
    else:
        evidence.append("frame-ancestors: not present"
                        if policy.csp_present
                        else "Content-Security-Policy: not present")
    if policy.xfo_present:
        evidence.append(f"X-Frame-Options: {policy.xfo_value}")
    elif policy.inspected:
        evidence.append("X-Frame-Options: not present")
    if policy.csp_present:
        evidence.append("Content-Security-Policy: " + policy.csp_value)
    if policy.report_only_value:
        evidence.append("Content-Security-Policy-Report-Only: "
                        + policy.report_only_value)
    evidence.extend(policy.notes)

    if not policy.inspected:
        return ("No response was examined, so the framing policy could not "
                "be established.", evidence,
                "Nothing here is evidence either way.")

    if policy.verdict == NO_RESTRICTION:
        if policy.csp_present:
            summary = (f"The enforced Content-Security-Policy{where} sets no "
                       f"frame-ancestors directive, so it places no "
                       f"restriction on which origins may embed the page.")
        else:
            summary = (f"No Content-Security-Policy was returned{where}, so "
                       f"nothing in the policy restricts framing.")
        if policy.xfo_effective:
            summary += (" X-Frame-Options does restrict it, so the page is "
                        "not framable by another origin.")
        elif policy.xfo_present:
            summary += " The X-Frame-Options header present does not "\
                       "restrict it either."
        else:
            summary += " No X-Frame-Options header was returned either."
        limitation = ("This is the observed configuration. Whether a given "
                      "browser frames the page also depends on the page's "
                      "own script and any framebusting it performs, which "
                      "was not tested.")
        return summary, evidence, limitation

    if policy.verdict == WILDCARD:
        return ((f"frame-ancestors{where} permits "
                 f"{' '.join(policy.frame_ancestors)}, which allows any "
                 f"origin to embed the page."), evidence,
                "The directive is present, so this is a permissive value "
                "rather than a missing protection.")

    if policy.verdict == NONE:
        return ("frame-ancestors is set to 'none', so no origin may embed "
                "the page.", evidence, "")

    if policy.verdict == SELF_ONLY:
        return ("frame-ancestors is set to 'self', so only the page's own "
                "origin may embed it.", evidence, "")

    if policy.verdict == SPECIFIC_ORIGINS:
        allowed = ", ".join(policy.permitted_origins) or "the listed origins"
        return ((f"frame-ancestors restricts embedding to an allow-list: "
                 f"{allowed}. Framing is restricted, but those origins can "
                 f"embed the page, so the finding depends on whether they "
                 f"are trusted."), evidence,
                "Whether this is acceptable is a judgement about the listed "
                "origins, not something the scan can settle.")

    return ("The framing policy could not be determined from what was "
            "observed.", evidence, "")
