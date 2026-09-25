"""
Named issues — the difference between a scanner and a report.

Burp's scanner does not hand you the line its check printed. It hands you an
*issue definition*: a settled name, a severity, a paragraph on what the problem
actually is, a paragraph on how to fix it, and a CWE. The raw output of the
check becomes the evidence underneath it.

That is what this module is. ``ISSUES`` is the library; ``for_testssl`` maps
one of testssl's JSON records onto an entry in it. The effect on the Coffee
Break screen is the one Luke asked for: a host offering CBC ciphers produces a
finding called **Lucky 13**, not a truncated copy of testssl's own sentence,
and the list of CBC ciphers it printed becomes the proof underneath.

Anything testssl reports that has no entry here still comes through — it just
comes through as a generic TLS finding, with its own text intact rather than
chopped at ninety characters.
"""

from __future__ import annotations

import re

# ─────────────────────────────────────────────────────────────────────────────
#  The library
# ─────────────────────────────────────────────────────────────────────────────
#
# Each entry: severity, title, detail, remediation, cwe, references.
# Severity is the one the issue carries in general; a scanner that is more
# certain than usual can raise it, but the default is here so that two runs of
# the same finding never disagree with each other.

def _issue(severity, title, detail, remediation, cwe="", references=()):
    return {"severity": severity, "title": title, "detail": detail,
            "remediation": remediation, "cwe": cwe,
            "references": list(references)}


ISSUES = {
    # ── TLS: the named attacks ───────────────────────────────────────────
    "lucky13": _issue(
        "MEDIUM", "Lucky 13 (CBC ciphers supported)",
        "The server negotiates CBC-mode cipher suites. The way TLS composes "
        "MAC-then-encrypt with CBC padding leaks, through the time taken to "
        "reject a record, whether the padding was well formed. Given enough "
        "captured records an attacker on the path can recover plaintext a byte "
        "at a time — session cookies being the usual target. The listed suites "
        "are the ones this host actually agreed to.",
        "Prefer AEAD suites (AES-GCM, ChaCha20-Poly1305) and remove the CBC "
        "suites from the server's cipher list. On TLS 1.3 this is automatic; "
        "on TLS 1.2 it means an explicit cipher string.",
        "CWE-203", ("CVE-2013-0169", "https://www.isg.rhul.ac.uk/tls/")),
    "beast": _issue(
        "LOW", "BEAST (CBC ciphers over TLS 1.0)",
        "TLS 1.0 uses a predictable CBC initialisation vector, which lets an "
        "attacker who can inject chosen plaintext into the same connection "
        "recover earlier blocks. Every modern browser has client-side "
        "mitigations, which is why this is low rather than high, but the "
        "protocol version that makes it possible should not be on.",
        "Disable TLS 1.0 and 1.1 entirely.",
        "CWE-326", ("CVE-2011-3389",)),
    "poodle": _issue(
        "HIGH", "POODLE (SSLv3 CBC padding oracle)",
        "SSLv3's CBC padding is not covered by the MAC, so a man in the middle "
        "who can force a downgrade to SSLv3 can decrypt a byte at a time.",
        "Disable SSLv3. There is no configuration that makes it safe.",
        "CWE-310", ("CVE-2014-3566",)),
    "sweet32": _issue(
        "MEDIUM", "Sweet32 (64-bit block ciphers)",
        "3DES and Blowfish use a 64-bit block, so a birthday collision becomes "
        "likely after roughly 32GB on one connection — enough to recover "
        "repeated plaintext such as a session cookie from a long-lived "
        "connection.",
        "Remove 3DES and any other 64-bit block cipher from the cipher list.",
        "CWE-327", ("CVE-2016-2183",)),
    "robot": _issue(
        "HIGH", "ROBOT (RSA PKCS#1 v1.5 padding oracle)",
        "The server's different responses to malformed RSA padding form an "
        "oracle. With enough queries an attacker can decrypt a recorded session "
        "or forge a signature with the server's private key, without ever "
        "holding the key.",
        "Disable RSA key-exchange cipher suites; use ECDHE throughout. Patch "
        "the TLS stack.",
        "CWE-203", ("CVE-2017-13099", "https://robotattack.org/")),
    "heartbleed": _issue(
        "CRITICAL", "Heartbleed (memory disclosure in the TLS heartbeat)",
        "The server returns up to 64KB of its own process memory for each "
        "malformed heartbeat request. That memory routinely contains session "
        "tokens, credentials and the server's private key. There is no trace "
        "of it in any log.",
        "Update OpenSSL, then reissue and revoke the certificate and invalidate "
        "every session — assume the key has been taken.",
        "CWE-119", ("CVE-2014-0160",)),
    "ccs": _issue(
        "HIGH", "CCS injection",
        "The server accepts a ChangeCipherSpec message early in the handshake, "
        "which lets a man in the middle force both sides onto keying material "
        "they know, and so read and modify the session.",
        "Update OpenSSL to a patched release.",
        "CWE-310", ("CVE-2014-0224",)),
    "ticketbleed": _issue(
        "HIGH", "Ticketbleed (session-ticket memory disclosure)",
        "The F5 TLS stack returns uninitialised memory alongside the session "
        "ID, leaking up to 31 bytes per handshake from another connection.",
        "Apply the F5 fix, or disable session tickets.",
        "CWE-200", ("CVE-2016-9244",)),
    "drown": _issue(
        "CRITICAL", "DROWN (SSLv2 cross-protocol attack)",
        "A server that still speaks SSLv2 anywhere on the same key lets an "
        "attacker decrypt recorded TLS sessions, even sessions made by clients "
        "that never used SSLv2.",
        "Disable SSLv2 on every service sharing the key, and reissue the "
        "certificate.",
        "CWE-310", ("CVE-2016-0800",)),
    "freak": _issue(
        "HIGH", "FREAK (export-grade RSA)",
        "The server offers export cipher suites, so a man in the middle can "
        "force a 512-bit RSA key exchange and factor it in hours.",
        "Remove all EXPORT cipher suites.",
        "CWE-310", ("CVE-2015-0204",)),
    "logjam": _issue(
        "MEDIUM", "Logjam (weak or common Diffie-Hellman parameters)",
        "The server's DH group is either export grade or one of the well-known "
        "primes that have been precomputed. Either way the key exchange can be "
        "broken and the session read.",
        "Use a unique 2048-bit-or-larger DH group, or prefer ECDHE.",
        "CWE-310", ("CVE-2015-4000", "https://weakdh.org/")),
    "crime": _issue(
        "MEDIUM", "CRIME (TLS-level compression enabled)",
        "Compression before encryption means the ciphertext length reveals how "
        "much the injected data matched the secret, which recovers session "
        "cookies byte by byte.",
        "Disable TLS compression.",
        "CWE-310", ("CVE-2012-4929",)),
    "breach": _issue(
        "LOW", "BREACH (HTTP compression with reflected input)",
        "HTTP-level compression of a response that contains both a secret (a "
        "CSRF token) and attacker-controlled input leaks the secret through the "
        "response length.",
        "Mask per-response secrets, separate secrets from reflected input, or "
        "disable compression on responses containing tokens.",
        "CWE-310", ("CVE-2013-3587",)),
    "rc4": _issue(
        "MEDIUM", "RC4 cipher suites supported",
        "RC4's keystream is measurably biased. A cookie sent across enough "
        "sessions can be recovered from those biases alone.",
        "Remove every RC4 suite from the cipher list.",
        "CWE-327", ("RFC 7465",)),
    "renegotiation": _issue(
        "MEDIUM", "Insecure or client-initiated TLS renegotiation",
        "Renegotiation without RFC 5746 binding lets an attacker prepend chosen "
        "plaintext to the victim's request; client-initiated renegotiation is "
        "in any case a cheap way to exhaust the server's CPU.",
        "Require secure renegotiation and refuse client-initiated "
        "renegotiation.",
        "CWE-310", ("CVE-2009-3555",)),
    "fallback": _issue(
        "LOW", "No downgrade protection (TLS_FALLBACK_SCSV missing)",
        "Without the fallback signalling suite, an attacker who interrupts the "
        "handshake can make each side think the other only speaks an older "
        "protocol version.",
        "Enable TLS_FALLBACK_SCSV in the TLS stack.",
        "CWE-757", ("RFC 7507",)),

    # ── TLS: protocol versions and certificates ──────────────────────────
    "obsolete_protocol": _issue(
        "MEDIUM", "Obsolete TLS protocol version enabled",
        "The host still negotiates a protocol version that is deprecated and "
        "carries known attacks. Browsers have already removed support, so this "
        "is usually serving nothing but an attacker's downgrade.",
        "Offer TLS 1.2 and 1.3 only.",
        "CWE-326", ("RFC 8996",)),
    "cert_expired": _issue(
        "HIGH", "Certificate expired or not yet valid",
        "Every client sees an interstitial warning, and the ones that do not — "
        "mobile apps, API clients — typically fail closed or, worse, are "
        "configured to ignore certificate errors entirely.",
        "Renew the certificate and automate the renewal.",
        "CWE-298"),
    "cert_untrusted": _issue(
        "MEDIUM", "Certificate chain is not trusted",
        "The chain is self-signed, incomplete, or signed by an authority the "
        "client does not trust. Users are trained by it to click through the "
        "warning that would otherwise stop a real attack.",
        "Serve the full chain from a publicly trusted authority.",
        "CWE-295"),
    "cert_hostname": _issue(
        "MEDIUM", "Certificate does not match the hostname",
        "The common name and subject alternative names do not cover the name "
        "the client asked for, so the certificate cannot authenticate this "
        "host.",
        "Reissue with the correct names, or serve the right certificate for "
        "this virtual host.",
        "CWE-297"),
    "cert_weak_signature": _issue(
        "MEDIUM", "Weak certificate signature algorithm",
        "The certificate is signed with an algorithm (MD5, SHA-1) for which "
        "collisions are practical, so a forged certificate is possible.",
        "Reissue with SHA-256 or better.",
        "CWE-327"),
    "cert_weak_key": _issue(
        "MEDIUM", "Weak certificate key size",
        "The key is below the size now considered sound, which shortens the "
        "work needed to recover it.",
        "Reissue with a 2048-bit RSA key or a 256-bit elliptic curve key.",
        "CWE-326"),
    "weak_cipher": _issue(
        "MEDIUM", "Weak cipher suites offered",
        "The server accepts suites with no encryption, export-grade key sizes, "
        "or broken primitives. Any of them can be forced by an attacker who "
        "controls the handshake.",
        "Set an explicit modern cipher list and remove NULL, anonymous, "
        "export and 3DES suites.",
        "CWE-327"),
    "tls_generic": _issue(
        "LOW", "TLS configuration weakness",
        "Reported by testssl against the TLS configuration.",
        "Review against the server's TLS hardening guide.",
        "CWE-326"),
}


# ─────────────────────────────────────────────────────────────────────────────
#  testssl → issue
# ─────────────────────────────────────────────────────────────────────────────
#
# Matched in order, first hit wins. testssl's ids are stable enough to key on;
# where a family shares a prefix (BEAST_CBC_TLS1, cipherlist_3DES_IDEA) the
# pattern covers the family rather than naming every member.

_TESTSSL_IDS = (
    # testssl reports the CBC suites under their own ids as well as under
    # LUCKY13; they are the same issue and belong on the same finding.
    (r"^(LUCKY13|cbc)", "lucky13"),
    (r"^BEAST", "beast"),
    (r"^POODLE", "poodle"),
    (r"^SWEET32", "sweet32"),
    (r"^ROBOT", "robot"),
    (r"^heartbleed", "heartbleed"),
    (r"^CCS", "ccs"),
    (r"^ticketbleed", "ticketbleed"),
    (r"^DROWN", "drown"),
    (r"^FREAK", "freak"),
    (r"^LOGJAM", "logjam"),
    (r"^CRIME", "crime"),
    (r"^BREACH", "breach"),
    (r"^RC4", "rc4"),
    (r"^(secure_renego|secure_client_renego|renego)", "renegotiation"),
    (r"^fallback_SCSV", "fallback"),
    (r"^(SSLv2|SSLv3|TLS1$|TLS1_1)", "obsolete_protocol"),
    (r"^cert_expiration", "cert_expired"),
    (r"^cert_(chain_of_trust|trust|caIssuers)", "cert_untrusted"),
    (r"^cert_(commonName|subjectAltName|hostname)", "cert_hostname"),
    (r"^cert_signatureAlgorithm", "cert_weak_signature"),
    (r"^cert_keySize", "cert_weak_key"),
    (r"^(cipherlist_|cipher_negotiated|std_)", "weak_cipher"),
)

#: What the finding text says, when the id is not enough. testssl reuses a
#: generic id for several checks in older releases.
_TESTSSL_TEXT = (
    (r"\blucky\s*13\b|CBC ciphers", "lucky13"),
    (r"\bBEAST\b", "beast"),
    (r"\bPOODLE\b", "poodle"),
    (r"\bSWEET32\b|64 bit block", "sweet32"),
    (r"\bROBOT\b", "robot"),
    (r"\bheartbleed\b", "heartbleed"),
    (r"\bDROWN\b", "drown"),
    (r"\bFREAK\b", "freak"),
    (r"\bLOGJAM\b|common prime", "logjam"),
    (r"\bRC4\b", "rc4"),
    (r"\bexport\b|\bNULL cipher|\banon\b|\b3DES\b", "weak_cipher"),
    (r"expired|not yet valid", "cert_expired"),
    (r"self.signed|chain of trust|untrusted", "cert_untrusted"),
    (r"SHA1 with|MD5 with|signature algorithm", "cert_weak_signature"),
)

#: testssl's own severities. OK and INFO mean "we looked, it was fine" — the
#: single biggest source of the noise on the findings screen was treating
#: those as things to report.
TESTSSL_BENIGN = {"OK", "INFO", "DEBUG", "WARN", "FATAL"}

_NOT_VULNERABLE = re.compile(
    r"not vulnerable|no (?:CBC|RC4|weak|export)|not offered|"
    r"not supported|isn't vulnerable|downgrade attack protection", re.I)


def for_testssl(record):
    """Map one testssl JSON record onto a library entry.

    Returns ``(key, issue)`` or ``(None, None)`` when the record is telling us
    the host is *fine* — which is most of them, and none of which belongs on a
    findings screen.
    """
    severity = str(record.get("severity", "")).upper()
    identifier = str(record.get("id", ""))
    finding = str(record.get("finding", ""))

    if severity in TESTSSL_BENIGN:
        return None, None
    if _NOT_VULNERABLE.search(finding):
        return None, None

    for pattern, key in _TESTSSL_IDS:
        # Case-insensitively: testssl's own ids are consistent, but the
        # console fallback reconstructs an id from the printed label, which
        # is capitalised however the section header was.
        if re.search(pattern, identifier, re.I):
            return key, ISSUES[key]
    for pattern, key in _TESTSSL_TEXT:
        if re.search(pattern, finding, re.I):
            return key, ISSUES[key]
    return "tls_generic", ISSUES["tls_generic"]


def worst(*severities):
    """The most serious of the severities given, ignoring anything unknown."""
    order = ("INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL")
    best = 0
    for severity in severities:
        if severity and str(severity).upper() in order:
            best = max(best, order.index(str(severity).upper()))
    return order[best]


# ─────────────────────────────────────────────────────────────────────────────
#  Noise
# ─────────────────────────────────────────────────────────────────────────────
#
# A scanner that prints everything is a scanner nobody reads. Burp keeps this
# material too, but it keeps it as *information*, collapsed, and out of the way
# of the things that need acting on. These are the checks whose output is
# inventory rather than a finding.

#: nuclei template ids (and id prefixes) that describe what the stack is, not
#: what is wrong with it. They are folded into one "Technology fingerprint"
#: entry instead of one row each.
NUCLEI_FINGERPRINT = (
    "tech-detect", "waf-detect", "favicon-detect", "fingerprinthub",
    "ssl-dns-names", "ssl-issuer", "tls-version", "http-missing-security-headers",
    "options-method", "robots-txt", "sitemap", "dns-", "wappalyzer",
    "metatag-cms", "caa-fingerprint", "mx-fingerprint", "txt-fingerprint",
    "nameserver-fingerprint", "ptr-fingerprint", "cname-fingerprint",
    "http-trace", "cookies-without", "security-txt", "openapi", "swagger-api",
    "wordpress-detect", "php-detect", "nginx-version", "apache-detect",
    "iis-version", "server-version", "git-config", "url-analyse",
)

#: Nikto's line prefixes that are inventory, a banner, or the scan's own
#: bookkeeping. Nikto prints a lot of these and every one of them used to
#: become a row.
NIKTO_NOISE = (
    "target ", "start time", "end time", "server:", "root page", "no cgi",
    "scan terminated", "host(s) tested", "ssl info", "allowed http",
    "retrieved x-powered-by", "retrieved access-control", "uncommon header",
    "the anti-clickjacking", "the x-content-type-options",
    "the x-xss-protection", "no cgi directories", "multiple index files",
    "web server returns", "cookie ", "retrieved via header",
    "reports it is", "appears to be outdated",     # handled as its own issue
)


def clean_title(text, limit=118):
    """A title that reads like a title.

    Strips ANSI, collapses whitespace, drops testssl's trailing parentheticals,
    and — this is the part that was wrong before — cuts on a word boundary with
    an ellipsis rather than mid-word at a fixed offset. The full text is always
    kept as the finding's detail, so nothing is lost by shortening it here.
    """
    text = re.sub(r"\x1b\[[0-9;]*m", "", str(text or ""))
    text = re.sub(r"\s+", " ", text).strip(" \t-—:;.")
    if len(text) <= limit:
        return text
    cut = text[:limit].rsplit(" ", 1)[0].rstrip(",;:-")
    return (cut or text[:limit]) + "…"


def is_fingerprint(template_id):
    """True when a nuclei template is describing the stack rather than a bug."""
    lowered = str(template_id or "").lower()
    return any(lowered.startswith(n) or n in lowered
               for n in NUCLEI_FINGERPRINT)


def is_nikto_noise(line):
    lowered = str(line or "").strip().lower()
    return any(lowered.startswith(n) for n in NIKTO_NOISE)
