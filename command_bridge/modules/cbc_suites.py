"""Which CBC cipher suites does this host actually agree to?

A Lucky 13 finding whose entire proof is testssl's own sentence —

    LUCKY13: potentially vulnerable, uses obsolete TLS CBC ciphers

— is not a finding anybody can write up. The question a report has to
answer is *which* suites, and testssl only puts the per-suite detail in
its JSON when it is run with ``--show-each`` or the cipher-enumeration
flags, which the Coffee Break invocation does not use. The data was
therefore never available to attach, however the parser was written.

So this asks the server directly: offer it one CBC suite at a time and
see which handshakes complete. That is the same question testssl asks,
it needs no extra flags, and what comes back is what the host agreed to
rather than what a signature guessed.

Deliberately narrow:

  * One TCP connection per suite, against a host already being scanned.
  * No data is sent after the handshake, and the socket is closed
    immediately. Nothing is read, written or authenticated.
  * A suite is only reported when the handshake SUCCEEDS. A refused or
    timed-out suite is not evidence of anything either way, and is
    silently skipped rather than recorded as absent.
"""

from __future__ import annotations

import socket
import ssl

#: OpenSSL's name for each CBC suite, with the IANA name a report wants
#: and the symmetric key size. OpenSSL prints its own short names
#: ("ECDHE-RSA-AES256-SHA"); every TLS reference, scanner report and
#: remediation ticket uses the IANA ones, so the translation lives here
#: rather than leaving the reader to do it.
SUITES = (
    # (OpenSSL name, IANA name, bits)
    ("ECDHE-RSA-AES256-SHA",       "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA", 256),
    ("ECDHE-ECDSA-AES256-SHA",     "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA", 256),
    ("ECDHE-RSA-AES256-SHA384",    "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384", 256),
    ("ECDHE-ECDSA-AES256-SHA384",  "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384", 256),
    ("AES256-SHA",                 "TLS_RSA_WITH_AES_256_CBC_SHA", 256),
    ("AES256-SHA256",              "TLS_RSA_WITH_AES_256_CBC_SHA256", 256),
    ("DHE-RSA-AES256-SHA",         "TLS_DHE_RSA_WITH_AES_256_CBC_SHA", 256),
    ("DHE-RSA-AES256-SHA256",      "TLS_DHE_RSA_WITH_AES_256_CBC_SHA256", 256),
    ("CAMELLIA256-SHA",            "TLS_RSA_WITH_CAMELLIA_256_CBC_SHA", 256),

    ("ECDHE-RSA-AES128-SHA",       "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA", 128),
    ("ECDHE-ECDSA-AES128-SHA",     "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA", 128),
    ("ECDHE-RSA-AES128-SHA256",    "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256", 128),
    ("ECDHE-ECDSA-AES128-SHA256",  "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256", 128),
    ("AES128-SHA",                 "TLS_RSA_WITH_AES_128_CBC_SHA", 128),
    ("AES128-SHA256",              "TLS_RSA_WITH_AES_128_CBC_SHA256", 128),
    ("DHE-RSA-AES128-SHA",         "TLS_DHE_RSA_WITH_AES_128_CBC_SHA", 128),
    ("DHE-RSA-AES128-SHA256",      "TLS_DHE_RSA_WITH_AES_128_CBC_SHA256", 128),
    ("CAMELLIA128-SHA",            "TLS_RSA_WITH_CAMELLIA_128_CBC_SHA", 128),

    ("ECDHE-RSA-DES-CBC3-SHA",     "TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA", 112),
    ("DES-CBC3-SHA",               "TLS_RSA_WITH_3DES_EDE_CBC_SHA", 112),
    ("EDH-RSA-DES-CBC3-SHA",       "TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA", 112),
    ("DES-CBC-SHA",                "TLS_RSA_WITH_DES_CBC_SHA", 56),
    ("EXP-DES-CBC-SHA",            "TLS_RSA_EXPORT_WITH_DES40_CBC_SHA", 40),
)

#: IANA name by OpenSSL name, for naming whatever the handshake actually
#: settled on rather than what was asked for.
_IANA = {openssl: iana for openssl, iana, _ in SUITES}


def _context(openssl_name):
    """A client context that will offer exactly one suite.

    ``@SECLEVEL=0`` is required: OpenSSL 3 refuses SHA-1 and 3DES suites
    at the default security level, so without it the older suites — the
    ones most worth reporting — cannot even be offered, and the host
    would look clean because the CLIENT declined, not the server.
    """
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    # TLS 1.3 has no CBC suites at all, and leaving it enabled lets the
    # handshake succeed on a 1.3 suite and report a false positive.
    try:
        context.maximum_version = ssl.TLSVersion.TLSv1_2
    except Exception:                                   # noqa: BLE001
        pass
    for attempt in (f"{openssl_name}:@SECLEVEL=0", openssl_name):
        try:
            context.set_ciphers(attempt)
            return context
        except ssl.SSLError:
            continue
    return None


def offered(host, port=443, timeout=4, report=None):
    """``[(iana_name, bits, openssl_name), ...]`` the host agreed to.

    Ordered strongest first, which is how a cipher list is read.
    """
    say = report or (lambda line: None)
    found, seen = [], set()
    for openssl_name, iana_name, bits in SUITES:
        context = _context(openssl_name)
        if context is None:
            continue                    # this client cannot offer it
        try:
            with socket.create_connection((host, port), timeout=timeout) as raw:
                with context.wrap_socket(raw, server_hostname=host) as tls:
                    negotiated = tls.cipher()
        except Exception:                               # noqa: BLE001
            continue                    # refused, filtered, or no such suite
        if not negotiated:
            continue
        # Report what was NEGOTIATED. A server may pick something other
        # than what was offered, and the finding must name the suite that
        # was actually agreed, not the one we asked for.
        actual = negotiated[0]
        name = _IANA.get(actual, actual)
        if name in seen:
            continue
        seen.add(name)
        found.append((name, negotiated[2] or bits, actual))
        say(f"CBC suite accepted: {name} ({negotiated[2] or bits} bit)")
    found.sort(key=lambda row: (-row[1], row[0]))
    return found


def as_evidence(suites, host=""):
    """The suite list as the proof block under a Lucky 13 finding.

    One per line, aligned, no markup — so that selecting it and pasting
    it into a report gives the same thing that is on screen.
    """
    if not suites:
        return ""
    width = max(len(name) for name, _, _ in suites)
    lines = [f"{len(suites)} CBC cipher suite(s) accepted"
             + (f" by {host}" if host else "") + ":"]
    for name, bits, _ in suites:
        lines.append(f"  {name.ljust(width)}  {bits}")
    return "\n".join(lines)
