"""
Related findings, gathered under one row — presentation only.

A scan of one host routinely produces four TLS findings, three CSP
findings and half a dozen missing headers. Each is a real, separately
evidenced finding and none should be merged or dropped; the list is
simply long enough that the interesting rows are hard to find in it.

So this module decides, for a list of findings, which belong together
and what a parent row should say about them. It is a PRESENTATION layer
and it is deliberately incapable of doing anything else:

  * it returns references to the findings it was given, never copies,
  * it never writes to a finding,
  * every finding goes into exactly one group, so a total is a total,
  * a parent's severity is reported as a DISTRIBUTION, never collapsed
    into one rating that would imply the group is as bad as its worst
    child or as mild as its mildest.

That last point is the one worth guarding. A parent row headed
"CRITICAL" over three informational observations is a lie in the
direction people act on, and a parent headed "INFORMATIONAL" over a
confirmed exposure is a lie in the direction people ignore.

Grouping by ISSUE KEY, not by title text. The keys come from the
validated finding, so a group cannot be formed by two findings that
merely share a word — which is the same discipline the classification
engine applies, for the same reason.
"""

from __future__ import annotations

from dataclasses import dataclass, field

SEVERITY_ORDER = ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO")
SEVERITY_RANK = {name: index for index, name
                 in enumerate(reversed(SEVERITY_ORDER))}

STATUS_ORDER = ("Confirmed", "Potential", "Inconclusive", "Informational")


@dataclass(frozen=True)
class Category:
    """One group: what it is called, and what belongs in it."""

    key: str
    title: str
    #: Issue keys that belong here. Exact matches only.
    keys: frozenset = frozenset()
    #: Issue-key prefixes, for families that share one.
    prefixes: tuple = ()
    #: Stages whose findings belong here when the issue key is unknown.
    #: A fallback, so an unrecognised TLS finding still lands with the
    #: TLS ones rather than alone at the bottom of the list.
    stages: frozenset = frozenset()
    #: Smallest number of findings worth a parent row. Below it they are
    #: shown as ordinary rows — a parent over one child is a row that
    #: costs a click and says nothing.
    minimum: int = 2
    order: int = 50


#: The categories, in display order. Adding one is adding an entry: the
#: UI reads this list and nothing else, so a new group needs no UI work.
#:
#: CSP comes before the general header category ON PURPOSE. Both could
#: claim a CSP finding, assignment is first-match, and a CSP finding
#: belongs under CSP — which is also why nothing is ever placed twice.
CATEGORIES = (
    Category(
        key="tls",
        title="TLS/SSL",
        keys=frozenset({
            "lucky13", "beast", "sweet32", "robot", "poodle", "freak",
            "logjam", "drown", "crime", "breach", "rc4", "heartbleed",
            "ccs", "ticketbleed", "renegotiation", "fallback",
            "weak_cipher", "obsolete_protocol", "null_cipher",
            "anonymous_cipher", "cert_expired", "cert_expiring",
            "cert_untrusted", "cert_hostname", "cert_weak_signature",
            "cert_weak_key", "cert_self_signed", "tls_config",
            "hsts_missing", "hsts_short_max_age", "cleartext_http",
        }),
        prefixes=("cert_", "tls_"),
        stages=frozenset({"testssl", "tls"}),
        order=10,
    ),
    Category(
        key="csp",
        title="Content-Security-Policy",
        keys=frozenset({
            "csp_missing", "csp_unsafe_script", "csp_clickjacking",
            "csp_form_hijack", "csp_report_only", "csp_wildcard_source",
            "csp_missing_object_base", "cross_site_framing",
        }),
        prefixes=("csp_",),
        order=20,
    ),
    Category(
        key="headers",
        title="HTTP Security Headers",
        keys=frozenset({
            "nosniff_missing", "referrer_policy", "permissions_policy",
            "xpcdp_missing", "coop_missing", "xfo_missing",
            "xss_protection_deprecated", "security_header_observation",
            "cookie_no_httponly", "cookie_no_secure", "cookie_no_samesite",
            "cors_arbitrary_origin", "cors_credentials_wildcard",
        }),
        prefixes=("cookie_", "cors_"),
        order=30,
    ),
    Category(
        key="disclosure",
        title="Web Server and Information Disclosure",
        keys=frozenset({
            "version_disclosure", "directory_listing", "backup_file",
            "vcs_exposed", "env_file_exposed", "info_page_exposed",
            "source_code_disclosure", "config_disclosed",
            "shell_history_exposed", "private_key_exposed",
            "api_spec_exposed", "robots_disclosure", "email_disclosure",
            "verbose_error", "stack_trace", "path_disclosure",
            "cloud_key_disclosed", "db_connection_string",
            "content_observation", "path_observation",
        }),
        order=40,
    ),
    # Below here are categories that exist so related findings group
    # when a scan produces several. They are NOT a way of folding
    # unrelated vulnerabilities together: each lists specific keys.
    Category(
        key="injection",
        title="Injection",
        keys=frozenset({
            "command_injection", "sqli", "potential_sqli", "ssti",
            "code_injection", "ldap_injection", "crlf_injection",
            "nosql_injection", "xxe",
        }),
        order=50,
    ),
    Category(
        key="xss",
        title="Cross-Site Scripting",
        keys=frozenset({"xss_reflected", "xss_stored", "xss_dom"}),
        order=60,
    ),
    Category(
        key="access",
        title="Access Control",
        keys=frozenset({
            "broken_access_control", "idor", "auth_bypass",
            "forced_browsing", "privilege_escalation",
        }),
        order=70,
    ),
    Category(
        key="components",
        title="Components and Services",
        keys=frozenset({
            "component_admin_exposed", "component_known_vulnerable",
            "outdated_software", "known_cve", "login_panel_exposed",
            "admin_exposed", "sri_missing", "dangerous_method",
        }),
        order=80,
    ),
)

_BY_KEY = {}
for _category in CATEGORIES:
    for _key in _category.keys:
        _BY_KEY.setdefault(_key, _category)


@dataclass
class Group:
    """A parent row and the findings under it."""

    category: Category
    findings: list = field(default_factory=list)
    #: True when this is a real parent row; False when the category had
    #: too few findings and they are shown as ordinary rows.
    grouped: bool = True

    @property
    def key(self):
        return self.category.key

    @property
    def title(self):
        return f"{self.category.title} — Several Issues Detected"

    @property
    def count(self):
        return len(self.findings)

    def severity_counts(self):
        """``{"MEDIUM": 2, "LOW": 1}`` — only what is present."""
        counts = {}
        for finding in self.findings:
            name = str(getattr(finding, "severity", "INFO") or "INFO").upper()
            counts[name] = counts.get(name, 0) + 1
        return counts

    def status_counts(self):
        counts = {}
        for finding in self.findings:
            label = str(getattr(finding, "status_label", "") or "") or \
                _status_from_state(getattr(finding, "state", ""))
            counts[label] = counts.get(label, 0) + 1
        return counts

    @property
    def worst_severity(self):
        """The highest severity present — for the indicator, not a verdict."""
        present = [s for s in SEVERITY_ORDER if s in self.severity_counts()]
        return present[0] if present else "INFO"

    @property
    def informational_only(self):
        """True when nothing in the group claims a vulnerability."""
        return set(self.severity_counts()) <= {"INFO"}

    def summary(self):
        """The parent row's second line.

        ``4 findings · 2 Medium · 1 Low · 1 Informational``

        A distribution, never a single rating. The severities appear in
        order of seriousness so the eye finds the worst first, and the
        statuses follow because "3 findings · 2 Confirmed" answers a
        different question from the severities.
        """
        parts = [f"{self.count} finding" + ("s" if self.count != 1 else "")]
        counts = self.severity_counts()
        for name in SEVERITY_ORDER:
            if name in counts:
                parts.append(f"{counts[name]} {_pretty_severity(name)}")
        statuses = self.status_counts()
        for name in STATUS_ORDER:
            if statuses.get(name):
                parts.append(f"{statuses[name]} {name}")
        line = " · ".join(parts)
        if self.informational_only:
            # Said explicitly, because a row of counts beside a group
            # title reads as a list of problems.
            line += " · no vulnerability claimed"
        return line

    def accessible_name(self):
        """What a screen reader should say for the parent row."""
        return (f"{self.category.title}, {self.count} findings. "
                f"{self.summary()}")


def _pretty_severity(name):
    return {"INFO": "Informational"}.get(name, name.capitalize())


def _status_from_state(state):
    return {
        "CONFIRMED": "Confirmed", "VALIDATED": "Confirmed",
        "POTENTIAL": "Potential", "DETECTED": "Potential",
        "INCONCLUSIVE": "Inconclusive",
    }.get(str(state or "").upper(), "Inconclusive")


def category_for(finding):
    """Which category this finding belongs to, or None.

    By issue key first, then by key prefix, then by the stage that
    produced it. Title text is never consulted: two findings that share
    a word are not thereby related, and a group formed that way would be
    the same mistake the classifier was built to stop.
    """
    key = str(getattr(finding, "key", "") or "")
    if key and key in _BY_KEY:
        return _BY_KEY[key]
    if key:
        for category in sorted(CATEGORIES, key=lambda c: c.order):
            if any(key.startswith(prefix) for prefix in category.prefixes):
                return category
    stage = str(getattr(finding, "stage", "") or "").lower()
    if stage:
        for category in sorted(CATEGORIES, key=lambda c: c.order):
            if stage in category.stages:
                return category
    return None


def organise(findings, minimum_override=None):
    """``(groups, loose)`` — findings arranged for display.

    ``groups`` are the categories that reached their minimum, in display
    order. ``loose`` are the findings that belong to no category, or to
    one with too few members to be worth a parent row.

    Every finding appears exactly once across the two, so a count of
    everything shown equals the number of findings passed in. The tests
    assert that, because a presentation layer that loses or duplicates a
    finding is worse than no grouping at all.
    """
    buckets = {}
    loose = []
    for finding in findings or []:
        category = category_for(finding)
        if category is None:
            loose.append(finding)
            continue
        buckets.setdefault(category.key, []).append(finding)

    groups = []
    for category in sorted(CATEGORIES, key=lambda c: c.order):
        members = buckets.get(category.key) or []
        if not members:
            continue
        minimum = (category.minimum if minimum_override is None
                   else minimum_override)
        if len(members) < minimum:
            # One TLS finding is a TLS finding, not a group of one.
            loose.extend(members)
            continue
        groups.append(Group(category=category, findings=members))

    return groups, loose


def total_shown(groups, loose):
    """Every finding across groups and loose rows, counted once."""
    return sum(group.count for group in groups) + len(loose)
