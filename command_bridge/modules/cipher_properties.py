"""
What is actually wrong with a cipher suite — read off the suite itself.

A "weak cipher suites offered" finding that lists every suite the server
negotiated has told the reader nothing. On the host that prompted this,
twelve suites were listed under one heading: five CBC, three static-RSA,
and four — AES-GCM and ChaCha20-Poly1305, including the TLS 1.3 ones —
that are the suites you would ask for if you were fixing it. A reader
cannot tell which of the twelve the finding is about.

So a suite is parsed, not pattern-matched. An IANA name states its own
construction:

    TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256
        │    │     │        │   │   │
        │    │     │        │   │   └── MAC / PRF hash
        │    │     │        │   └────── mode: CBC, GCM, CCM, POLY1305
        │    │     │        └────────── bulk cipher and key size
        │    │     └─────────────────── authentication
        │    └───────────────────────── key exchange
        └────────────────────────────── TLS 1.2 and earlier naming

TLS 1.3 renamed everything: TLS_AES_128_GCM_SHA256 has no key-exchange
or authentication component because 1.3 fixed both, and any 1.3 suite is
AEAD by construction. Reading a 1.3 name with 1.2 rules is how a scanner
ends up calling TLS_AES_256_GCM_SHA384 weak.

What this module will NOT say:

  * that a suite is weak because its key is 128-bit. AES-128 is not a
    finding, and saying so next to a real one makes both easier to
    dismiss.
  * that a suite is weak because it was returned by a check that fired
    for a different suite in the same list.
  * that CBC is broken. CBC with MAC-then-encrypt has a history of
    padding-oracle and timing problems, which is a reason to move off
    it and is not the same claim.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

# ── what a weakness is, and why ─────────────────────────────────────────
#
# Each reason is a short sentence a reader can act on, and each is about
# a property this module can actually establish from the suite name.

CBC_MODE = "cbc_mode"
STATIC_RSA = "static_rsa"
NO_FORWARD_SECRECY = "no_forward_secrecy"
ANONYMOUS = "anonymous_kx"
NULL_CIPHER = "null_cipher"
EXPORT_GRADE = "export_grade"
RC4 = "rc4"
TRIPLE_DES = "triple_des"
DES = "single_des"
WEAK_MAC = "weak_mac"
SMALL_KEY = "small_key"

REASONS = {
    CBC_MODE: "CBC mode with MAC-then-encrypt — the construction behind "
              "the padding-oracle and timing issues (BEAST, Lucky 13)",
    STATIC_RSA: "static RSA key exchange — no forward secrecy, so a future "
                "compromise of the server key decrypts past traffic",
    NO_FORWARD_SECRECY: "no forward secrecy",
    ANONYMOUS: "anonymous key exchange — the server is not authenticated, "
               "so the connection can be man-in-the-middled outright",
    NULL_CIPHER: "no encryption at all",
    EXPORT_GRADE: "export-grade key sizes, breakable by design",
    RC4: "RC4, which has practical plaintext-recovery biases (RFC 7465 "
         "prohibits it)",
    TRIPLE_DES: "3DES with a 64-bit block — practical birthday-bound "
                "collisions on long-lived connections (Sweet32)",
    DES: "single DES, a 56-bit key",
    WEAK_MAC: "MD5 as the MAC",
    SMALL_KEY: "a symmetric key under 128 bits",
}

#: Reasons serious enough that the suite should not be offered at all,
#: separated from reasons that are a modernisation argument. A reader
#: fixing a TLS configuration treats these differently, and so should a
#: report.
SEVERE = frozenset({NULL_CIPHER, EXPORT_GRADE, ANONYMOUS, RC4, DES,
                    WEAK_MAC, SMALL_KEY})

#: TLS 1.3 suite names, which carry no key exchange or authentication.
_TLS13 = {
    "TLS_AES_128_GCM_SHA256": ("AES", 128, "GCM", "SHA256"),
    "TLS_AES_256_GCM_SHA384": ("AES", 256, "GCM", "SHA384"),
    "TLS_CHACHA20_POLY1305_SHA256": ("CHACHA20", 256, "POLY1305", "SHA256"),
    "TLS_AES_128_CCM_SHA256": ("AES", 128, "CCM", "SHA256"),
    "TLS_AES_128_CCM_8_SHA256": ("AES", 128, "CCM", "SHA256"),
}

_KEY_SIZES = {
    "AES_256": 256, "AES_128": 128, "CAMELLIA_256": 256,
    "CAMELLIA_128": 128, "ARIA_256": 256, "ARIA_128": 128,
    "CHACHA20": 256, "3DES_EDE": 112, "DES_EDE3": 112, "DES": 56,
    "DES40": 40, "RC4_128": 128, "RC4_40": 40, "RC2_CBC_40": 40,
    "SEED": 128, "IDEA": 128, "NULL": 0,
}


@dataclass
class Suite:
    """One cipher suite, as its own name describes it."""

    name: str
    bits: int = 0
    tls13: bool = False
    key_exchange: str = ""          # ECDHE, DHE, RSA, ECDH, DH, PSK, …
    authentication: str = ""        # RSA, ECDSA, DSS, anon, …
    cipher: str = ""                # AES, CHACHA20, 3DES, RC4, NULL, …
    mode: str = ""                  # CBC, GCM, CCM, POLY1305, STREAM
    mac: str = ""                   # SHA, SHA256, SHA384, MD5, AEAD
    aead: bool = False
    forward_secrecy: bool = False
    weaknesses: tuple = ()
    parsed: bool = True

    @property
    def is_weak(self):
        return bool(self.weaknesses)

    @property
    def is_severe(self):
        return bool(set(self.weaknesses) & SEVERE)

    def reasons(self):
        return [REASONS[w] for w in self.weaknesses if w in REASONS]

    def describe(self):
        """``"TLS_… — 256-bit AES, CBC mode, ECDHE (forward secrecy)"``."""
        bits = f"{self.bits}-bit {self.cipher}" if self.bits else self.cipher
        parts = [p for p in (bits, f"{self.mode} mode" if self.mode and
                             self.mode != "STREAM" else "") if p]
        if self.tls13:
            parts.append("TLS 1.3, AEAD")
        elif self.key_exchange:
            fs = " (forward secrecy)" if self.forward_secrecy else \
                 " (no forward secrecy)"
            parts.append(f"{self.key_exchange}{fs}")
        return f"{self.name} — " + ", ".join(parts) if parts else self.name

    def as_dict(self):
        return {"name": self.name, "bits": self.bits, "tls13": self.tls13,
                "key_exchange": self.key_exchange, "cipher": self.cipher,
                "mode": self.mode, "mac": self.mac, "aead": self.aead,
                "forward_secrecy": self.forward_secrecy,
                "weaknesses": list(self.weaknesses)}


def parse(name, bits=0):
    """An IANA cipher suite name → :class:`Suite`.

    ``bits`` is the key size a scanner reported, used in preference to
    the one inferred from the name — the scanner measured it.

    A name this does not understand comes back with ``parsed=False`` and
    NO weaknesses. An unrecognised suite is not evidence of anything,
    and guessing from fragments of its name is the mistake this module
    exists to avoid.
    """
    raw = str(name or "").strip().upper().replace("-", "_")
    if not raw:
        return Suite(name=str(name or ""), parsed=False)

    if raw in _TLS13:
        cipher, inferred, mode, mac = _TLS13[raw]
        return Suite(name=str(name), bits=bits or inferred, tls13=True,
                     cipher=cipher, mode=mode, mac=mac, aead=True,
                     forward_secrecy=True,     # 1.3 is ephemeral-only
                     key_exchange="ECDHE/DHE", authentication="certificate",
                     weaknesses=())

    if not raw.startswith("TLS_") or "_WITH_" not in raw:
        return Suite(name=str(name), bits=bits, parsed=False)

    head, _, tail = raw[4:].partition("_WITH_")
    suite = Suite(name=str(name), bits=bits)

    # ── key exchange and authentication ─────────────────────────────────
    if head.startswith("ECDHE_"):
        suite.key_exchange, suite.authentication = "ECDHE", head[6:]
        suite.forward_secrecy = True
    elif head.startswith("DHE_"):
        suite.key_exchange, suite.authentication = "DHE", head[4:]
        suite.forward_secrecy = True
    elif head.startswith("ECDH_"):
        suite.key_exchange, suite.authentication = "ECDH", head[5:]
    elif head.startswith("DH_"):
        suite.key_exchange, suite.authentication = "DH", head[3:]
    elif head == "RSA":
        suite.key_exchange, suite.authentication = "RSA", "RSA"
    else:
        suite.key_exchange = head.split("_")[0]
        suite.authentication = "_".join(head.split("_")[1:])

    if "ANON" in head:
        suite.authentication = "anon"
        suite.forward_secrecy = False

    # ── bulk cipher, mode and MAC ───────────────────────────────────────
    if tail.endswith("_POLY1305_SHA256") or "CHACHA20" in tail:
        suite.cipher, suite.mode, suite.mac = "CHACHA20", "POLY1305", "AEAD"
        suite.aead = True
        suite.bits = bits or 256
    else:
        match = re.match(
            r"(?P<cipher>NULL|AES_256|AES_128|CAMELLIA_256|CAMELLIA_128|"
            r"ARIA_256|ARIA_128|3DES_EDE|DES_EDE3|DES40|DES|RC4_128|RC4_40|"
            r"RC2_CBC_40|SEED|IDEA)"
            r"(?:_(?P<mode>CBC|GCM|CCM|CCM_8))?"
            r"(?:_(?P<mac>SHA384|SHA256|SHA|MD5|NULL))?$", tail)
        if match is None:
            suite.parsed = False
            return suite
        cipher_token = match.group("cipher")
        suite.mode = match.group("mode") or ""
        suite.mac = match.group("mac") or ""
        suite.bits = bits or _KEY_SIZES.get(cipher_token, 0)
        suite.cipher = cipher_token.replace("_256", "").replace("_128", "") \
            .replace("_40", "").replace("_CBC", "")
        if suite.mode in ("GCM", "CCM", "CCM_8"):
            suite.aead = True
            suite.mac = "AEAD"
        elif not suite.mode and cipher_token.startswith("RC4"):
            suite.mode = "STREAM"

    # ── weaknesses, each from a property established above ──────────────
    found = []
    if suite.cipher == "NULL" or suite.mac == "NULL":
        found.append(NULL_CIPHER)
    if "EXPORT" in raw or "_EXP" in raw or cipher_token_is_export(raw):
        found.append(EXPORT_GRADE)
    if suite.authentication == "anon":
        found.append(ANONYMOUS)
    if suite.cipher == "RC4":
        found.append(RC4)
    # The cipher token for 3DES comes through as "3DES_EDE" or
    # "DES_EDE3" depending on the naming, and matching only the short
    # forms left 3DES reported as "a symmetric key under 128 bits" with
    # no mention of Sweet32 — true, but not the reason anybody cares.
    if suite.cipher.replace("_", "").startswith(("3DESEDE", "DESEDE3")):
        found.append(TRIPLE_DES)
    elif suite.cipher == "DES":
        found.append(DES)
    if suite.mac == "MD5":
        found.append(WEAK_MAC)
    if suite.mode == "CBC":
        found.append(CBC_MODE)
    if suite.key_exchange == "RSA":
        found.append(STATIC_RSA)
    elif suite.key_exchange in ("ECDH", "DH") and not suite.forward_secrecy:
        found.append(NO_FORWARD_SECRECY)
    if 0 < suite.bits < 128 and TRIPLE_DES not in found:
        found.append(SMALL_KEY)

    suite.weaknesses = tuple(dict.fromkeys(found))
    return suite


def cipher_token_is_export(raw):
    return bool(re.search(r"_EXPORT|_EXP_|DES40|RC4_40|RC2_CBC_40", raw))


def parse_all(rows):
    """``[{"name":…, "bits":…}, …]`` or ``[(name, bits), …]`` → Suites."""
    out = []
    for row in rows or []:
        if isinstance(row, dict):
            out.append(parse(row.get("name"), row.get("bits") or 0))
        elif isinstance(row, (tuple, list)) and row:
            out.append(parse(row[0], row[1] if len(row) > 1 else 0))
        else:
            out.append(parse(row))
    return out


@dataclass
class Grouping:
    """Suites sorted into what is wrong with them, and what is not."""

    by_weakness: dict = field(default_factory=dict)   # reason key → [Suite]
    acceptable: list = field(default_factory=list)
    unparsed: list = field(default_factory=list)

    @property
    def problematic(self):
        seen, out = set(), []
        for suites in self.by_weakness.values():
            for suite in suites:
                if suite.name not in seen:
                    seen.add(suite.name)
                    out.append(suite)
        return out


def group(suites):
    """Sort suites by the weakness each one actually has.

    The point of the grouping is that a reader can see which suites a
    finding is about. A suite with no weakness this module can establish
    goes in ``acceptable`` — not in a list headed "weak ciphers".
    """
    grouping = Grouping()
    for suite in suites:
        if not suite.parsed:
            grouping.unparsed.append(suite)
            continue
        if not suite.weaknesses:
            grouping.acceptable.append(suite)
            continue
        for weakness in suite.weaknesses:
            grouping.by_weakness.setdefault(weakness, []).append(suite)
    return grouping


def with_weakness(suites, weakness):
    """Only the suites that actually have this weakness.

    This is what a per-check finding is built from. A Lucky 13 finding
    lists the suites whose MODE is CBC — established by parsing each
    name — rather than every suite whose name contains the letters CBC,
    and rather than every suite the scan happened to return.
    """
    return [s for s in suites if weakness in s.weaknesses]


def listing(suites, note_bits=True, indent="  "):
    """Suites one per line, aligned, with what each one is.

    Plain text with real newlines, so selecting it out of the findings
    pane and pasting it into a report gives what is on screen.
    """
    suites = [s for s in suites if s]
    if not suites:
        return ""
    ordered = sorted(suites, key=lambda s: (-(s.bits or 0), s.name))
    width = max(len(s.name) for s in ordered)
    lines = []
    for suite in ordered:
        if note_bits and suite.bits:
            detail = f"{suite.bits}-bit {suite.cipher}" if suite.cipher \
                else f"{suite.bits}-bit"
            lines.append(f"{indent}{suite.name.ljust(width)}  {detail}")
        else:
            lines.append(f"{indent}{suite.name}")
    return "\n".join(lines)
