"""
What does this specific check actually check?

The registry exists because classifying a finding by looking for words in
a scanner's sentence does not work, and keeps not working in the same
way. The history in PROJECT_REFERENCE is one bug of this shape after
another:

  * ``weak-csp-detect``'s description ends "…which can lead to arbitrary
    code execution", so a CSP header was published as a CRITICAL CWE-78
    OS command injection with the header as its proof.
  * ``rce\\b`` has no leading word boundary, so "Missing Subresou(rce)
    Integrity" — nuclei severity INFO, CWE-353 — became the same
    CRITICAL command injection. So did any finding mentioning a source
    or a resource.
  * Nikto's JAMon line mentions "XSS vulnerabilities" while identifying
    an admin interface, so a component fingerprint became a HIGH
    reflected XSS with no parameter, no payload and no reflection.
  * sqlmap's "testing 'stacked queries'" announcement became a confirmed
    SQL injection.

Each was fixed where it was found. The disease is the same every time: a
check's IDENTITY was inferred from prose written about it.

So this module keys on identity. A scanner names the check it ran —
nuclei gives a template id, Nikto a plugin id, testssl a check id — and
that identifier says what was tested far more reliably than any sentence
can. An entry records what the check establishes, what it does NOT
establish, what evidence would be needed to go further, and how to go
and get that evidence safely.

Three things an entry deliberately separates, because conflating them is
what produced the reports above:

  WHAT THE DETECTOR FOUND      a component, a header, a path, a cipher
  WHAT THAT WOULD MEAN         the vulnerability class, if established
  WHETHER IT IS ESTABLISHED    the evidence actually in hand

A known-vulnerable component, a component fingerprint and a confirmed
exploitable vulnerability are three findings, not one.

Unknown detectors are NOT forced through here. ``classify`` returns None
and the caller keeps its existing behaviour, so the registry is additive:
it constrains the checks it knows about and leaves the rest alone.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

# ── statuses ────────────────────────────────────────────────────────────
#
# The vocabulary the rest of the application already uses, named here so
# a registry entry can state its own ceiling.

CONFIRMED = "CONFIRMED"
POTENTIAL = "POTENTIAL"
INCONCLUSIVE = "INCONCLUSIVE"
INFORMATIONAL = "INFORMATIONAL"

#: What a detector's own output can establish on its own, before any
#: verification this application performs.
#:
#: SIGNATURE — the tool matched a pattern. It did not test behaviour.
#: OBSERVED  — the tool read something directly out of a response.
#: PROVEN    — the tool demonstrated the behaviour (sent a payload and
#:             saw its effect).
SIGNATURE = "signature"
OBSERVED = "observed"
PROVEN = "proven"


@dataclass(frozen=True)
class Detector:
    """One scanner check, and what it is and is not evidence of."""

    #: The finding's name. Concise, and about the thing that was found —
    #: never the scanner's sentence about it.
    name: str

    #: The library key this maps onto, or "" to keep the detector's own
    #: name. A key here OVERRIDES keyword classification; that is the
    #: whole point of an entry existing.
    issue_key: str = ""

    #: What class of problem this is, in the application's own terms.
    vuln_class: str = "misconfiguration"

    #: The PRODUCT, where the detector identifies one. Separate from
    #: ``name``, which is the finding's title: an explanation that says
    #: "<title> is reachable at <path>" reads as "JAMon administrative
    #: interface is reachable is reachable at …" when the two are the
    #: same string.
    component: str = ""

    #: Severity if the finding is established. NOT the severity it is
    #: reported at when it is not — see ceiling.
    severity_if_confirmed: str = "MEDIUM"

    #: Severity when the detector's own evidence is all there is.
    severity_unconfirmed: str = "INFO"

    #: The best status this detector's own output can justify. A
    #: signature match cannot reach CONFIRMED however alarming its
    #: wording; only verification can move it.
    ceiling: str = POTENTIAL

    #: What the detector's output amounts to.
    evidence_kind: str = SIGNATURE

    cwe: str = ""

    #: CVEs are CONTEXT — "this product has had this bug" — and never
    #: proof that this host is affected.
    cves: tuple = ()

    #: What would have to be observed to call this confirmed. Written
    #: for a reader, and checked by the verifier below.
    confirm_requires: str = ""

    #: Name of a safe verification procedure in ``verification.py``, or
    #: "" when nothing can be checked without exploiting something.
    verify: str = ""

    #: Where the evidence may legitimately come from. A detector whose
    #: evidence arrives from somewhere else is a bug, not a finding.
    evidence_sources: tuple = ()

    notes: str = ""


# ── nuclei, by template id ──────────────────────────────────────────────
#
# Keys are matched exactly, then as a prefix. nuclei's template ids are
# stable and are the best identity signal any of these scanners gives.

NUCLEI = {
    "missing-sri": Detector(
        name="Subresource Integrity missing on external script",
        issue_key="sri_missing",
        vuln_class="misconfiguration",
        severity_if_confirmed="LOW",
        severity_unconfirmed="INFO",
        ceiling=INFORMATIONAL,
        evidence_kind=OBSERVED,
        cwe="CWE-353",
        confirm_requires="The response's script tags, showing an external "
                         "src with no integrity attribute.",
        evidence_sources=("response body",),
        notes="This template reads script tags out of the HTML. It does "
              "not test execution, injection or a shell. It was being "
              "classified as OS command injection because its NAME "
              "contains 'Subresou(rce)'.",
    ),
    "weak-csp-detect": Detector(
        name="Content-Security-Policy is permissive",
        issue_key="csp_unsafe_script",
        vuln_class="misconfiguration",
        severity_if_confirmed="MEDIUM",
        severity_unconfirmed="LOW",
        ceiling=POTENTIAL,
        evidence_kind=OBSERVED,
        cwe="CWE-693",
        confirm_requires="The policy itself, and the directive that "
                         "permits what the header exists to prevent.",
        evidence_sources=("response headers",),
        notes="Its description mentions arbitrary code execution. That "
              "is prose about what a weak CSP can allow, not evidence "
              "of code execution here.",
    ),
    "missing-csp": Detector(
        name="Content-Security-Policy is missing",
        issue_key="csp_missing",
        vuln_class="misconfiguration",
        severity_if_confirmed="LOW",
        severity_unconfirmed="LOW",
        ceiling=CONFIRMED,
        evidence_kind=OBSERVED,
        cwe="CWE-693",
        confirm_requires="The response headers, without the header in them.",
        verify="header_absent",
        evidence_sources=("response headers",),
    ),
    # tech-detect and waf-detect deliberately have NO entries here.
    # cb_issues.is_fingerprint already folds them into the single
    # "Technology fingerprint" inventory finding, and giving them
    # registry entries pulled each one out into a finding of its own —
    # which is how a scan of one host produced a row saying "Technology
    # identified" beside the inventory it was supposed to be part of.
}

#: nuclei tag sets that mean "this template reports a configuration or an
#: observation", used when the template id is not in the table above.
#: A template tagged only this way must never acquire an exploit class.
NUCLEI_NON_EXPLOIT_TAGS = frozenset({
    "misconfig", "misconfiguration", "compliance", "tech", "detect",
    "fingerprint", "exposure", "disclosure", "sri", "ssl", "tls",
    "headers", "dns", "network", "osint", "panel", "login",
})

#: Tags that genuinely mark a template as testing for an exploit.
NUCLEI_EXPLOIT_TAGS = frozenset({
    "rce", "sqli", "xss", "ssrf", "lfi", "rfi", "xxe", "ssti", "redirect",
    "traversal", "injection", "deserialization", "auth-bypass", "takeover",
})


# ── Nikto, by plugin id and by path ─────────────────────────────────────
#
# Nikto prints a numeric id in brackets — "[002743] /.bash_history: …" —
# which identifies the check far better than its sentence. Where the id
# is absent or unknown, the path is matched instead.

NIKTO_IDS = {
    "002743": "shell_history",
    "002756": "shell_history",
    "007303": "jamon_admin",
}

#: path fragment → detector name, matched case-insensitively, longest
#: first. Used when Nikto gives no id this table knows.
NIKTO_PATHS = (
    (".bash_history", "shell_history"),
    (".sh_history", "shell_history"),
    (".zsh_history", "shell_history"),
    ("jamonadmin.jsp", "jamon_admin"),
    (".env", "env_file"),
    ("id_rsa", "private_key"),
    (".git/config", "git_exposed"),
    (".htpasswd", "htpasswd"),
    ("phpinfo.php", "phpinfo"),
    ("server-status", "server_status"),
)

NIKTO = {
    "shell_history": Detector(
        name="Shell history file is readable",
        issue_key="shell_history_exposed",
        vuln_class="sensitive data exposure",
        severity_if_confirmed="HIGH",
        severity_unconfirmed="LOW",
        ceiling=POTENTIAL,
        evidence_kind=SIGNATURE,
        cwe="CWE-200",
        confirm_requires="A response body that actually looks like shell "
                         "history — command lines, not an HTML document — "
                         "and that differs from what the host returns for "
                         "a path that cannot exist.",
        verify="file_contents",
        evidence_sources=("response body", "response headers"),
        notes="Nikto matches on the request succeeding. On a host that "
              "answers 200 with an application shell for every path, "
              "that match means nothing. HIGH only once the content is "
              "read and it is really a history file.",
    ),
    "jamon_admin": Detector(
        name="JAMon administrative interface is reachable",
        # The product name only. Saying "not a JavaScript package" here
        # puts the words into the finding, which is the opposite of the
        # point — the finding should simply be accurate about what JAMon
        # is. The distinction is recorded in notes, below.
        component="JAMon (Java Application Monitor)",
        issue_key="component_admin_exposed",
        vuln_class="component identification",
        severity_if_confirmed="MEDIUM",
        severity_unconfirmed="LOW",
        ceiling=POTENTIAL,
        evidence_kind=SIGNATURE,
        cwe="CWE-284",
        cves=("CVE-2013-6235",),
        confirm_requires="A response from the interface itself, and where "
                         "possible the JAMon version, to establish whether "
                         "the referenced CVE applies at all.",
        verify="component_version",
        evidence_sources=("response body", "response headers"),
        notes="Nikto's line says 'Versions 2.7 and earlier contain XSS "
              "vulnerabilities'. That sentence was matching the reflected-"
              "XSS keyword pattern, so a Java admin interface was reported "
              "as HIGH reflected XSS CWE-79 with no parameter, no payload "
              "and no reflection. JAMon is a Java component, not a "
              "JavaScript package, and a historical CVE in a product is "
              "not evidence about this host. Reflected XSS needs an "
              "input reflected into an unsafe context.",
    ),
    "env_file": Detector(
        name="Environment file is readable",
        issue_key="env_file_exposed",
        vuln_class="sensitive data exposure",
        severity_if_confirmed="HIGH",
        severity_unconfirmed="LOW",
        ceiling=POTENTIAL,
        evidence_kind=SIGNATURE,
        cwe="CWE-200",
        confirm_requires="A body containing KEY=value lines rather than an "
                         "HTML document.",
        verify="file_contents",
        evidence_sources=("response body",),
    ),
    "private_key": Detector(
        name="Private key file is readable",
        issue_key="private_key_exposed",
        vuln_class="sensitive data exposure",
        severity_if_confirmed="CRITICAL",
        severity_unconfirmed="LOW",
        ceiling=POTENTIAL,
        evidence_kind=SIGNATURE,
        cwe="CWE-200",
        confirm_requires="A body containing a PEM private key header.",
        verify="file_contents",
        evidence_sources=("response body",),
    ),
    "git_exposed": Detector(
        name="Git repository is exposed",
        issue_key="vcs_exposed",
        vuln_class="sensitive data exposure",
        severity_if_confirmed="HIGH",
        severity_unconfirmed="LOW",
        ceiling=POTENTIAL,
        evidence_kind=SIGNATURE,
        cwe="CWE-200",
        confirm_requires="A body containing git config or index structure.",
        verify="file_contents",
        evidence_sources=("response body",),
    ),
    "htpasswd": Detector(
        name="Password file is readable",
        issue_key="backup_file",
        vuln_class="sensitive data exposure",
        severity_if_confirmed="HIGH",
        severity_unconfirmed="LOW",
        ceiling=POTENTIAL,
        evidence_kind=SIGNATURE,
        cwe="CWE-200",
        confirm_requires="A body containing user:hash lines.",
        verify="file_contents",
        evidence_sources=("response body",),
    ),
    "phpinfo": Detector(
        name="PHP configuration page is exposed",
        issue_key="info_page_exposed",
        vuln_class="information disclosure",
        severity_if_confirmed="MEDIUM",
        severity_unconfirmed="LOW",
        ceiling=POTENTIAL,
        evidence_kind=SIGNATURE,
        cwe="CWE-200",
        confirm_requires="A body containing phpinfo()'s own output.",
        verify="file_contents",
        evidence_sources=("response body",),
    ),
    "server_status": Detector(
        name="Server status page is exposed",
        issue_key="info_page_exposed",
        vuln_class="information disclosure",
        severity_if_confirmed="MEDIUM",
        severity_unconfirmed="LOW",
        ceiling=POTENTIAL,
        evidence_kind=SIGNATURE,
        cwe="CWE-200",
        confirm_requires="A body containing the server status table.",
        verify="file_contents",
        evidence_sources=("response body",),
    ),
}

#: Content a response must contain for a "file is readable" finding to be
#: confirmed, by detector name. Checked against the body the verifier
#: fetches — this is what separates "the path answered" from "the file
#: came back".
FILE_SIGNATURES = {
    "shell_history": (
        re.compile(r"^\s*(?:cd|ls|sudo|ssh|scp|git|vi|vim|nano|cat|curl|"
                   r"wget|mysql|psql|docker|npm|python3?|export|rm|cp|mv|"
                   r"chmod|chown|systemctl|service|apt|yum|history|exit)"
                   r"\b", re.I | re.M),
    ),
    "env_file": (
        re.compile(r"^\s*[A-Z][A-Z0-9_]{2,}\s*=", re.M),
    ),
    "private_key": (
        re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----"),
    ),
    "git_exposed": (
        re.compile(r"\[core\]|\[remote\s|repositoryformatversion", re.I),
    ),
    "htpasswd": (
        re.compile(r"^[A-Za-z0-9_.-]+:\$?[A-Za-z0-9$./]{10,}", re.M),
    ),
    "phpinfo": (
        re.compile(r"phpinfo\(\)|PHP Version\s*</|allow_url_fopen", re.I),
    ),
    "server_status": (
        re.compile(r"Apache Server Status|Total accesses:|"
                   r"<th>Srv</th>", re.I),
    ),
}

#: An HTML document is not any of the files above, whatever the status
#: code. This is how an application's catch-all page stops being mistaken
#: for a retrieved file.
NOT_A_FILE = re.compile(
    r"<!doctype\s+html|<html[\s>]|<head[\s>]|<title[\s>]|<app-root|"
    r"<div\s+id=[\"']root[\"']", re.I)


@dataclass
class Detection:
    """A classified detector hit, before verification."""

    detector: Detector
    detector_name: str              # the registry key, for the verifier
    scanner: str = ""
    detector_id: str = ""           # template id or Nikto plugin id
    scanner_severity: str = ""
    url: str = ""
    path: str = ""
    raw: str = ""
    extracted: tuple = ()
    status: str = ""                # filled in by verification
    evidence_lines: list = field(default_factory=list)

    @property
    def name(self):
        return self.detector.name

    def as_dict(self):
        return {
            "scanner": self.scanner,
            "detector_id": self.detector_id,
            "detector": self.detector_name,
            "name": self.detector.name,
            "vuln_class": self.detector.vuln_class,
            "issue_key": self.detector.issue_key,
            "cwe": self.detector.cwe,
            "cves": list(self.detector.cves),
            "scanner_severity": self.scanner_severity,
            "url": self.url,
            "path": self.path,
            "status": self.status,
            "evidence": list(self.evidence_lines),
        }


def _nikto_detector_name(line, plugin_id=""):
    """Which Nikto check is this? ``""`` when the registry has no entry."""
    if plugin_id and plugin_id in NIKTO_IDS:
        return NIKTO_IDS[plugin_id]
    lowered = str(line or "").lower()
    for fragment, detector_name in sorted(
            NIKTO_PATHS, key=lambda row: -len(row[0])):
        if fragment in lowered:
            return detector_name
    return ""


def classify_nikto(line, url="", path=""):
    """A Nikto line → ``Detection``, or None when unknown.

    Returning None rather than guessing is deliberate. The caller's
    existing handling is not replaced by this module, only overridden
    where the registry actually knows the check.
    """
    text = str(line or "").strip()
    id_match = re.match(r"^\[(\d+)\]\s*", text)
    plugin_id = id_match.group(1) if id_match else ""
    body = text[id_match.end():] if id_match else text

    detector_name = _nikto_detector_name(body, plugin_id)
    if not detector_name or detector_name not in NIKTO:
        return None

    path_match = re.match(r"^(/[^\s:]*)", body)
    return Detection(
        detector=NIKTO[detector_name],
        detector_name=detector_name,
        scanner="nikto",
        detector_id=plugin_id,
        url=url,
        path=path or (path_match.group(1) if path_match else ""),
        raw=text,
    )


def classify_nuclei(template_id, name="", tags=(), severity="",
                    url="", extracted=()):
    """A nuclei match → ``Detection``, or None when unknown.

    Two layers. An exact or prefix hit in :data:`NUCLEI` is a decision
    made in advance about that specific template. Failing that, the
    template's TAGS are used to decide whether it is even the kind of
    check that could justify an exploit class — which is what stops the
    next ``rce``-inside-a-word from promoting an INFO misconfiguration to
    CRITICAL.
    """
    identifier = str(template_id or "").strip()
    lowered = identifier.lower()

    entry = NUCLEI.get(lowered)
    if entry is None:
        for key, candidate in NUCLEI.items():
            if lowered.startswith(key):
                entry = candidate
                break

    if entry is not None:
        return Detection(
            detector=entry, detector_name=lowered, scanner="nuclei",
            detector_id=identifier, scanner_severity=str(severity).upper(),
            url=url, extracted=tuple(extracted or ()),
        )

    # Not a template the registry names. Decide only whether an exploit
    # class is admissible, and leave the naming to the caller.
    tag_set = {str(t).strip().lower() for t in (tags or []) if t}
    if tag_set and not tag_set.intersection(NUCLEI_EXPLOIT_TAGS):
        if tag_set.intersection(NUCLEI_NON_EXPLOIT_TAGS):
            return Detection(
                detector=Detector(
                    name=str(name or identifier or "nuclei match"),
                    vuln_class="misconfiguration",
                    severity_if_confirmed="LOW",
                    severity_unconfirmed="INFO",
                    ceiling=INFORMATIONAL,
                    evidence_kind=OBSERVED,
                    notes="Classified from the template's tags: it is a "
                          "configuration or detection template, so it "
                          "cannot carry an exploit class however its name "
                          "or description reads.",
                ),
                detector_name="", scanner="nuclei", detector_id=identifier,
                scanner_severity=str(severity).upper(), url=url,
                extracted=tuple(extracted or ()),
            )
    return None


def exploit_class_admissible(tags=(), severity=""):
    """May a finding from this nuclei template carry an exploit class?

    An INFO or LOW template with no exploit tag has not tested for an
    exploit. This is the guard that would have stopped both the
    weak-csp-detect and the missing-sri reports.
    """
    tag_set = {str(t).strip().lower() for t in (tags or []) if t}
    if tag_set.intersection(NUCLEI_EXPLOIT_TAGS):
        return True
    if str(severity).upper() in ("INFO", "LOW", "UNKNOWN", ""):
        return False
    return True


def looks_like_file(detector_name, body):
    """Does this body match what the named file should contain?

    ``(verdict, why)`` with verdict True, False or None — None meaning
    the registry has no signature for this detector and the question
    cannot be answered, which must not be read as either answer.
    """
    patterns = FILE_SIGNATURES.get(detector_name)
    if not patterns:
        return None, ""
    text = str(body or "")
    if not text.strip():
        return False, "the response body is empty"
    if NOT_A_FILE.search(text[:4000]):
        return False, ("the response is an HTML document, which is the "
                       "application's own page rather than the file")
    for pattern in patterns:
        if pattern.search(text):
            return True, "the response body matches the file's own format"
    return False, ("the response body does not match the format this file "
                   "has")
