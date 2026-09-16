#!/usr/bin/env python3
"""
ssl_cipher_check.py  —  SSL/TLS Full Vulnerability Scanner

Comprehensive SSL/TLS assessment using sslyze covering:
  • Deprecated protocol versions (SSL 2.0/3.0, TLS 1.0/1.1)
  • Protocol exploits: Heartbleed, CRIME, CCS Injection, ROBOT, DROWN
  • Cipher vulnerabilities: Lucky13, Sweet32, BEAST, RC4, NULL, EXPORT, Anonymous
  • Session security: renegotiation, resumption, TLS 1.3 0-RTT
  • Certificate: expiry, trust chain, key size, self-signed
  • Elliptic curves: weak curve detection
  • HTTP headers: HSTS, BREACH, clickjacking, CSP
  • LOGJAM: DHE cipher flagging with manual verification guide

Usage:  python3 ssl_cipher_check.py <host>[:<port>]
"""

import re
import sys
import ssl
import datetime
import urllib.request

# ── ANSI colours ──────────────────────────────────────────────────────────────
RED    = "\033[91m"
YELLOW = "\033[93m"
GREEN  = "\033[92m"
CYAN   = "\033[96m"
BOLD   = "\033[1m"
DIM    = "\033[2m"
RESET  = "\033[0m"

# ── Cipher-level vulnerability definitions ────────────────────────────────────
VULNS = [
    (
        "Sweet32",
        "Birthday attack on 64-bit block ciphers (3DES/DES) — CVE-2016-2183",
        re.compile(r"3DES|DES_EDE|_DES_CBC|IDEA", re.I),
    ),
    (
        "Lucky13",
        "Timing side-channel on CBC-mode HMAC padding — CVE-2013-0169",
        re.compile(r"_CBC_", re.I),
    ),
    (
        "ROBOT (static RSA)",
        "RSA PKCS#1 v1.5 key exchange — no forward secrecy, Bleichenbacher oracle candidate",
        re.compile(r"^TLS_RSA_WITH_", re.I),
    ),
    (
        "RC4",
        "RC4 stream cipher is statistically broken — RFC 7465",
        re.compile(r"RC4", re.I),
    ),
    (
        "NULL encryption",
        "No encryption — data transmitted in plaintext",
        re.compile(r"_NULL_|WITH_NULL", re.I),
    ),
    (
        "EXPORT / FREAK",
        "Export-grade ciphers susceptible to FREAK downgrade — CVE-2015-0204",
        re.compile(r"EXPORT|_EXP_", re.I),
    ),
    (
        "Anonymous (no server auth)",
        "No server authentication — trivially man-in-the-middled",
        re.compile(r"_anon_|ADH_|_ADH\b|DH_anon|ECDH_anon", re.I),
    ),
]

DEPRECATED_VERSIONS = {
    "SSL 2.0": ("CRITICAL", "Severely broken + DROWN (CVE-2016-0800) — disable immediately"),
    "SSL 3.0": ("CRITICAL", "POODLE (CVE-2014-3566) — disable immediately"),
    "TLS 1.0": ("HIGH",     "BEAST risk + deprecated by RFC 8996"),
    "TLS 1.1": ("MEDIUM",   "Deprecated by RFC 8996, no AEAD cipher support"),
}

VERSION_COMMANDS = [
    ("SSL 2.0", "SSL_2_0_CIPHER_SUITES", "ssl_2_0_cipher_suites"),
    ("SSL 3.0", "SSL_3_0_CIPHER_SUITES", "ssl_3_0_cipher_suites"),
    ("TLS 1.0", "TLS_1_0_CIPHER_SUITES", "tls_1_0_cipher_suites"),
    ("TLS 1.1", "TLS_1_1_CIPHER_SUITES", "tls_1_1_cipher_suites"),
    ("TLS 1.2", "TLS_1_2_CIPHER_SUITES", "tls_1_2_cipher_suites"),
    ("TLS 1.3", "TLS_1_3_CIPHER_SUITES", "tls_1_3_cipher_suites"),
]

# Weak / deprecated elliptic curves
WEAK_CURVES = {
    "sect163k1", "sect163r1", "sect163r2", "sect193r1", "sect193r2",
    "sect233k1", "sect233r1", "sect239k1", "sect283k1", "sect283r1",
    "secp112r1", "secp112r2", "secp128r1", "secp128r2", "secp160k1",
    "secp160r1", "secp160r2", "secp192k1", "prime192v1",
    "brainpoolP160r1", "brainpoolP160t1", "brainpoolP192r1", "brainpoolP192t1",
    "brainpoolP224r1", "brainpoolP224t1",
}


# ── Helpers ───────────────────────────────────────────────────────────────────

def section(title):
    print(f"\n{BOLD}{'─' * 62}{RESET}")
    print(f"{BOLD}{title}{RESET}")
    print(f"{BOLD}{'─' * 62}{RESET}\n")


def flag(severity, label, detail=""):
    col = RED if severity in ("CRITICAL", "HIGH") else YELLOW if severity == "MEDIUM" else DIM
    detail_str = f"\n          {DIM}{detail}{RESET}" if detail else ""
    print(f"  {col}{BOLD}[{severity}]{RESET}  {label}{detail_str}")


def ok(label):
    print(f"  {GREEN}[OK]{RESET}  {label}")


def print_vuln_block(vuln_name, description, matches):
    print(f"{BOLD}{RED}Vulnerable — {vuln_name}{RESET}")
    print(f"{DIM}  {description}{RESET}")
    for cipher, key_size in sorted(matches.items(), key=lambda x: (-(x[1] or 0), x[0])):
        bits = f"  {key_size}" if key_size else ""
        print(f"  {cipher}{YELLOW}{bits}{RESET}")
    print()


# ── Scan functions ────────────────────────────────────────────────────────────

def scan_full(host, port):
    """Queue all sslyze scan commands and return the raw scan_result object."""
    try:
        from sslyze import Scanner, ServerNetworkLocation, ScanCommand, ServerScanRequest
    except ImportError:
        print(f"{RED}[!] sslyze not installed. Run: pip3 install sslyze{RESET}")
        sys.exit(1)

    cipher_cmds = {getattr(ScanCommand, cmd) for _, cmd, _ in VERSION_COMMANDS}
    extra_cmds = {
        ScanCommand.HEARTBLEED,
        ScanCommand.TLS_COMPRESSION,
        ScanCommand.OPENSSL_CCS_INJECTION,
        ScanCommand.SESSION_RENEGOTIATION,
        ScanCommand.ROBOT,
        ScanCommand.CERTIFICATE_INFO,
        ScanCommand.TLS_1_3_EARLY_DATA,
        ScanCommand.ELLIPTIC_CURVES,
        ScanCommand.SESSION_RESUMPTION,
    }

    request = ServerScanRequest(
        server_location=ServerNetworkLocation(host, port),
        scan_commands=cipher_cmds | extra_cmds,
    )
    scanner = Scanner()
    scanner.queue_scans([request])
    results = list(scanner.get_results())
    if not results or results[0].scan_result is None:
        print(f"{RED}[!] Scan failed — could not connect to {host}:{port}{RESET}")
        sys.exit(1)
    return results[0].scan_result


def get_accepted_ciphers(scan_result):
    """Extract {version_label: [(name, key_size)]} from scan result."""
    accepted = {}
    for label, _, attr in VERSION_COMMANDS:
        attempt = getattr(scan_result, attr)
        if attempt.status.name == "COMPLETED" and attempt.result is not None:
            ciphers = [
                (c.cipher_suite.name, c.cipher_suite.key_size)
                for c in attempt.result.accepted_cipher_suites
            ]
            if ciphers:
                accepted[label] = ciphers
    return accepted


def all_ciphers_flat(accepted):
    """Deduplicated {cipher_name: key_size} across all TLS versions."""
    seen = {}
    for ciphers in accepted.values():
        for name, key_size in ciphers:
            if name not in seen:
                seen[name] = key_size
    return seen


def check_http_security(host, port):
    """Fetch HTTPS headers; return dict with HSTS, BREACH, and other security header findings."""
    findings = {}
    url = f"https://{host}:{port}/"
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    try:
        req = urllib.request.Request(url, headers={"Accept-Encoding": "gzip, deflate, br"})
        with urllib.request.urlopen(req, context=ctx, timeout=10) as resp:
            headers = {k.lower(): v for k, v in resp.getheaders()}
            hsts = headers.get("strict-transport-security", "")
            findings["hsts_present"] = bool(hsts)
            findings["hsts_value"] = hsts
            if hsts:
                m = re.search(r"max-age\s*=\s*(\d+)", hsts, re.I)
                findings["hsts_max_age"] = int(m.group(1)) if m else 0
                findings["hsts_include_subdomains"] = "includesubdomains" in hsts.lower()
                findings["hsts_preload"] = "preload" in hsts.lower()
            enc = headers.get("content-encoding", "")
            findings["breach_risk"] = bool(re.search(r"gzip|deflate|br", enc, re.I))
            findings["content_encoding"] = enc
            findings["x_frame_options"] = headers.get("x-frame-options", "")
            findings["x_content_type"] = headers.get("x-content-type-options", "")
            findings["csp"] = headers.get("content-security-policy", "")
    except Exception as e:
        findings["http_error"] = str(e)
    return findings


# ── Main ──────────────────────────────────────────────────────────────────────

def main():
    if len(sys.argv) < 2:
        print(f"Usage: {sys.argv[0]} <host>[:<port>]")
        sys.exit(1)

    target = sys.argv[1].strip()
    target = re.sub(r"^https?://", "", target, flags=re.I).split("/")[0]

    if ":" in target and not target.startswith("["):
        host, port_str = target.rsplit(":", 1)
        try:
            port = int(port_str)
        except ValueError:
            host, port = target, 443
    else:
        host, port = target, 443

    title = f"  SSL/TLS Full Vulnerability Report — {host}:{port}  "
    bar   = "═" * len(title)
    print(f"\n{BOLD}{CYAN}╔{bar}╗")
    print(f"║{title}║")
    print(f"╚{bar}╝{RESET}\n")
    print(f"[*] Scanning {BOLD}{host}:{port}{RESET} — running all checks …\n")

    scan_result = scan_full(host, port)
    accepted    = get_accepted_ciphers(scan_result)
    flat        = all_ciphers_flat(accepted)
    any_finding = False

    # ── 1. Deprecated / Insecure Protocol Versions ───────────────────────────
    section("1. Deprecated / Insecure Protocol Versions")
    found_dep = [v for v in ("SSL 2.0", "SSL 3.0", "TLS 1.0", "TLS 1.1") if v in accepted]
    if found_dep:
        any_finding = True
        for ver in found_dep:
            severity, reason = DEPRECATED_VERSIONS[ver]
            flag(severity, ver, reason)
        if "SSL 2.0" in accepted:
            flag("CRITICAL", "DROWN (CVE-2016-0800)",
                 "SSLv2 on any server sharing this RSA key allows cross-protocol decryption of TLS sessions")
    else:
        ok("No deprecated protocol versions accepted (TLS 1.2+ only)")

    # ── 2. Heartbleed ─────────────────────────────────────────────────────────
    section("2. Heartbleed")
    try:
        hb = scan_result.heartbleed
        if hb.status.name == "COMPLETED" and hb.result is not None:
            if hb.result.is_vulnerable_to_heartbleed:
                any_finding = True
                flag("CRITICAL", "HEARTBLEED (CVE-2014-0160)",
                     "OpenSSL heap memory disclosure — private keys, passwords, cookies all exposed. Patch immediately.")
            else:
                ok("Not vulnerable to Heartbleed")
        else:
            print(f"  {YELLOW}[?]{RESET}  Heartbleed check did not complete")
    except Exception as e:
        print(f"  {YELLOW}[?]{RESET}  Heartbleed check error: {e}")

    # ── 3. CRIME (TLS Compression) ────────────────────────────────────────────
    section("3. CRIME — TLS Compression (CVE-2012-4929)")
    try:
        comp = scan_result.tls_compression
        if comp.status.name == "COMPLETED" and comp.result is not None:
            if comp.result.supports_compression:
                any_finding = True
                flag("HIGH", "CRIME — TLS-level compression enabled",
                     "Allows session token extraction via chosen-plaintext attack against compressed TLS stream")
            else:
                ok("TLS compression disabled — not vulnerable to CRIME")
        else:
            print(f"  {YELLOW}[?]{RESET}  CRIME check did not complete")
    except Exception as e:
        print(f"  {YELLOW}[?]{RESET}  CRIME check error: {e}")

    # ── 4. OpenSSL CCS Injection ──────────────────────────────────────────────
    section("4. OpenSSL CCS Injection (CVE-2014-0224)")
    try:
        ccs = scan_result.openssl_ccs_injection
        if ccs.status.name == "COMPLETED" and ccs.result is not None:
            if ccs.result.is_vulnerable_to_ccs_injection:
                any_finding = True
                flag("HIGH", "CCS Injection — vulnerable",
                     "Early ChangeCipherSpec allows MitM to force weak keying material, enabling full session decryption")
            else:
                ok("Not vulnerable to OpenSSL CCS Injection")
        else:
            print(f"  {YELLOW}[?]{RESET}  CCS Injection check did not complete")
    except Exception as e:
        print(f"  {YELLOW}[?]{RESET}  CCS Injection check error: {e}")

    # ── 5. ROBOT (Active Oracle Test) ─────────────────────────────────────────
    section("5. ROBOT — RSA Decryption Oracle (CVE-2017-13099)")
    try:
        robot = scan_result.robot
        if robot.status.name == "COMPLETED" and robot.result is not None:
            name = robot.result.robot_result.name if hasattr(robot.result.robot_result, "name") else str(robot.result.robot_result)
            if "VULNERABLE_STRONG" in name:
                any_finding = True
                flag("CRITICAL", "ROBOT — Strong Bleichenbacher Oracle",
                     "Attacker can perform RSA private-key operations to decrypt any recorded TLS session")
            elif "VULNERABLE_WEAK" in name:
                any_finding = True
                flag("HIGH", "ROBOT — Weak Bleichenbacher Oracle",
                     "Exploitable with many queries — recorded sessions can be decrypted offline")
            elif "UNKNOWN" in name:
                flag("MEDIUM", "ROBOT — Inconclusive", "Oracle behavior uncertain — manual retest recommended")
            else:
                ok(f"Not vulnerable to ROBOT ({name})")
        else:
            print(f"  {YELLOW}[?]{RESET}  ROBOT check did not complete")
    except Exception as e:
        print(f"  {YELLOW}[?]{RESET}  ROBOT check error: {e}")

    # ── 6. Session Renegotiation ──────────────────────────────────────────────
    section("6. Session Renegotiation")
    try:
        reneg = scan_result.session_renegotiation
        if reneg.status.name == "COMPLETED" and reneg.result is not None:
            r = reneg.result
            if r.accepts_client_renegotiation:
                any_finding = True
                flag("MEDIUM", "Insecure client-initiated renegotiation accepted",
                     "Client can trigger costly renegotiations — DoS vector; also prerequisite for CVE-2009-3555")
            else:
                ok("Client-initiated renegotiation rejected")
            if not r.supports_secure_renegotiation:
                any_finding = True
                flag("HIGH", "Secure renegotiation (RFC 5746) NOT supported",
                     "CVE-2009-3555 — allows plaintext injection into TLS sessions")
            else:
                ok("Secure renegotiation (RFC 5746) supported")
        else:
            print(f"  {YELLOW}[?]{RESET}  Session renegotiation check did not complete")
    except Exception as e:
        print(f"  {YELLOW}[?]{RESET}  Session renegotiation check error: {e}")

    # ── 7. TLS 1.3 Early Data (0-RTT Replay) ─────────────────────────────────
    section("7. TLS 1.3 Early Data (0-RTT Replay)")
    if "TLS 1.3" not in accepted:
        print(f"  {DIM}[—]  TLS 1.3 not supported — 0-RTT not applicable{RESET}")
    else:
        try:
            early = scan_result.tls_1_3_early_data
            if early.status.name == "COMPLETED" and early.result is not None:
                if early.result.supports_early_data:
                    any_finding = True
                    flag("MEDIUM", "TLS 1.3 0-RTT Early Data enabled",
                         "Replay attacks possible against early-data requests — non-idempotent endpoints (POST, payments) must explicitly reject early data")
                else:
                    ok("TLS 1.3 0-RTT Early Data disabled")
            else:
                print(f"  {YELLOW}[?]{RESET}  0-RTT check did not complete")
        except Exception as e:
            print(f"  {YELLOW}[?]{RESET}  0-RTT check error: {e}")

    # ── 8. Elliptic Curves ────────────────────────────────────────────────────
    section("8. Elliptic Curves")
    try:
        ec = scan_result.elliptic_curves
        if ec.status.name == "COMPLETED" and ec.result is not None:
            supported = {c.name for c in ec.result.supported_elliptic_curves} if ec.result.supported_elliptic_curves else set()
            weak      = supported & WEAK_CURVES
            safe      = supported - weak
            if weak:
                any_finding = True
                flag("HIGH", "Weak elliptic curves supported")
                for curve in sorted(weak):
                    print(f"    {RED}{curve}{RESET}")
                print()
            else:
                ok(f"No weak elliptic curves ({len(supported)} curves, all safe)")
            if safe:
                print(f"  {CYAN}Supported safe curves:{RESET}")
                for c in sorted(safe):
                    print(f"    {c}")
        else:
            print(f"  {YELLOW}[?]{RESET}  Elliptic curves check did not complete")
    except Exception as e:
        print(f"  {YELLOW}[?]{RESET}  Elliptic curves check error: {e}")

    # ── 9. Session Resumption ─────────────────────────────────────────────────
    section("9. Session Resumption")
    try:
        resum = scan_result.session_resumption
        if resum.status.name == "COMPLETED" and resum.result is not None:
            r = resum.result
            if hasattr(r, "session_id_resumption_result"):
                sid = r.session_id_resumption_result
                sid_name = sid.name if hasattr(sid, "name") else str(sid)
                if "FULLY_SUPPORTED" in sid_name:
                    print(f"  {CYAN}[INFO]{RESET}  Session ID resumption: supported")
                else:
                    print(f"  {DIM}[—]   Session ID resumption: {sid_name}{RESET}")
            if hasattr(r, "tls_ticket_resumption_result"):
                tkt = r.tls_ticket_resumption_result
                tkt_name = tkt.name if hasattr(tkt, "name") else str(tkt)
                if "FULLY_SUPPORTED" in tkt_name:
                    print(f"  {CYAN}[INFO]{RESET}  TLS session tickets: supported")
                    print(f"  {DIM}        Ensure ticket rotation policy enforced — long-lived tickets undermine forward secrecy{RESET}")
                else:
                    print(f"  {DIM}[—]   TLS session tickets: {tkt_name}{RESET}")
        else:
            print(f"  {YELLOW}[?]{RESET}  Session resumption check did not complete")
    except Exception as e:
        print(f"  {YELLOW}[?]{RESET}  Session resumption check error: {e}")

    # ── 10. Certificate Information ───────────────────────────────────────────
    section("10. Certificate Information")
    try:
        cert_info = scan_result.certificate_info
        if cert_info.status.name == "COMPLETED" and cert_info.result is not None:
            for deploy in cert_info.result.certificate_deployments:
                chain = deploy.received_certificate_chain
                if not chain:
                    flag("HIGH", "Empty certificate chain received")
                    continue

                leaf = chain[0]
                subject = leaf.subject.rfc4514_string()
                issuer  = leaf.issuer.rfc4514_string()

                try:
                    not_after = leaf.not_valid_after_utc
                except AttributeError:
                    not_after = leaf.not_valid_after.replace(tzinfo=datetime.timezone.utc)

                now       = datetime.datetime.now(datetime.timezone.utc)
                days_left = (not_after - now).days

                print(f"  {CYAN}Subject:{RESET}  {subject}")
                print(f"  {CYAN}Issuer: {RESET}  {issuer}")
                print(f"  {CYAN}Expires:{RESET}  {not_after.strftime('%Y-%m-%d')}  ({days_left} days remaining)")

                if days_left < 0:
                    any_finding = True
                    flag("CRITICAL", f"Certificate EXPIRED {abs(days_left)} days ago")
                elif days_left < 14:
                    any_finding = True
                    flag("HIGH", f"Certificate expires in {days_left} days — renew immediately")
                elif days_left < 30:
                    any_finding = True
                    flag("MEDIUM", f"Certificate expires in {days_left} days")
                else:
                    ok(f"Certificate valid for {days_left} more days")

                # Key size check
                try:
                    pub_key  = leaf.public_key()
                    key_size = pub_key.key_size
                    key_type = type(pub_key).__name__.replace("PublicKey", "").replace("_", "")
                    print(f"  {CYAN}Key:{RESET}      {key_type} {key_size}-bit")
                    if "RSA" in key_type.upper() and key_size < 2048:
                        any_finding = True
                        flag("HIGH", f"Weak RSA key ({key_size}-bit) — minimum 2048-bit required (NIST SP 800-131A)")
                    elif "RSA" in key_type.upper() and key_size < 3072:
                        flag("LOW", f"RSA {key_size}-bit — 3072-bit or ECDSA P-256+ recommended for post-2030")
                    else:
                        ok(f"Key size acceptable ({key_size}-bit)")
                except Exception:
                    pass

                # Self-signed
                if leaf.subject == leaf.issuer:
                    any_finding = True
                    flag("HIGH", "Self-signed certificate — not trusted by browsers/OS")

                # Trust chain
                trusted = deploy.verified_certificate_chain
                if trusted is None:
                    any_finding = True
                    flag("HIGH", "Certificate chain NOT trusted by built-in CA stores")
                else:
                    ok(f"Trust chain verified ({len(trusted)} certificate(s))")

                print()
        else:
            print(f"  {YELLOW}[?]{RESET}  Certificate info check did not complete")
    except Exception as e:
        print(f"  {YELLOW}[?]{RESET}  Certificate check error: {e}")

    # ── 11. Cipher Suite Vulnerabilities ──────────────────────────────────────
    section("11. Cipher Suite Vulnerabilities")

    # BEAST — TLS 1.0 + CBC
    beast_matches = {}
    if "TLS 1.0" in accepted:
        for name, key_size in accepted["TLS 1.0"]:
            if re.search(r"_CBC_", name, re.I):
                beast_matches[name] = key_size

    cipher_finding = False
    for vuln_name, description, pattern in VULNS:
        matches = {name: ks for name, ks in flat.items() if pattern.search(name)}
        if matches:
            any_finding = True
            cipher_finding = True
            print_vuln_block(vuln_name, description, matches)

    if beast_matches:
        any_finding = True
        cipher_finding = True
        print_vuln_block("BEAST", "TLS 1.0 supported with CBC ciphers — CVE-2011-3389", beast_matches)

    # LOGJAM — DHE (non-ECDHE) ciphers present
    dhe_ciphers = {name: ks for name, ks in flat.items()
                   if re.search(r"\bDHE_|\bDH_", name, re.I) and not re.search(r"ECDHE|ECDH", name, re.I)}
    if dhe_ciphers:
        cipher_finding = True
        print(f"{BOLD}{YELLOW}Potential LOGJAM Risk — DHE Ciphers Present (CVE-2015-4000){RESET}")
        print(f"{DIM}  Weak DH parameters (<=1024-bit) allow offline passive decryption by nation-state adversaries{RESET}")
        print(f"{DIM}  Verify DH param size manually:{RESET}")
        print(f"{DIM}    openssl s_client -connect {host}:{port} -cipher 'EDH' 2>&1 | grep 'Server Temp Key'{RESET}")
        print(f"{DIM}  Safe if 'Server Temp Key: DH, 2048 bits' or higher — flag if <=1024-bit{RESET}")
        for cipher in sorted(dhe_ciphers):
            print(f"  {YELLOW}{cipher}{RESET}")
        print()

    if not cipher_finding:
        ok("No cipher suite vulnerabilities detected")

    # ── 12. HTTP Security Headers (HSTS / BREACH) ─────────────────────────────
    section("12. HTTP Security Headers")
    print(f"  [*] Fetching HTTPS headers from {host}:{port} …")
    http = check_http_security(host, port)

    if "http_error" in http:
        print(f"  {YELLOW}[?]{RESET}  Could not retrieve HTTP headers: {http['http_error']}")
    else:
        # HSTS
        if http.get("hsts_present"):
            max_age = http.get("hsts_max_age", 0)
            if max_age < 31536000:
                any_finding = True
                flag("MEDIUM", f"HSTS max-age too short ({max_age}s) — recommended ≥ 31536000 (1 year)")
            else:
                ok(f"HSTS present (max-age={max_age})")
            if not http.get("hsts_include_subdomains"):
                flag("LOW", "HSTS missing includeSubDomains — subdomains can be downgraded")
            if not http.get("hsts_preload"):
                print(f"  {DIM}[—]  HSTS preload not set (optional — submit to hstspreload.org for full protection){RESET}")
        else:
            any_finding = True
            flag("HIGH", "HSTS not set — HTTP Strict-Transport-Security header missing",
                 "Allows protocol downgrade / SSL stripping attacks")

        # BREACH
        if http.get("breach_risk"):
            any_finding = True
            flag("MEDIUM", f"BREACH — HTTP compression enabled (Content-Encoding: {http['content_encoding']})",
                 "CVE-2013-3587 — compressing secrets in HTTPS responses leaks them via chosen-plaintext. Disable gzip for authenticated responses.")
        else:
            ok("No HTTP-level compression on this response (not vulnerable to BREACH)")

        # Other headers (low severity / informational)
        if not http.get("x_frame_options") and not http.get("csp"):
            flag("LOW", "X-Frame-Options not set — Clickjacking risk")
        if not http.get("x_content_type"):
            flag("LOW", "X-Content-Type-Options: nosniff not set — MIME sniffing risk")
        if not http.get("csp"):
            flag("LOW", "Content-Security-Policy not set")

    # ── 13. All Accepted Cipher Suites ────────────────────────────────────────
    section("13. All Accepted Cipher Suites")
    if not accepted:
        print(f"  {YELLOW}[!]{RESET}  No accepted cipher suites found on port {port}")
    else:
        for ver in ("TLS 1.3", "TLS 1.2", "TLS 1.1", "TLS 1.0", "SSL 3.0", "SSL 2.0"):
            if ver not in accepted:
                continue
            dep  = ver in DEPRECATED_VERSIONS
            vcol = RED if dep else CYAN
            tag  = f"  {DIM}(deprecated){RESET}" if dep else ""
            print(f"\n  {vcol}{BOLD}{ver}{RESET}{tag}")
            for cipher, key_size in sorted(accepted[ver], key=lambda x: (-(x[1] or 0), x[0])):
                bits = f"  {key_size}" if key_size else ""
                print(f"    {cipher}{YELLOW}{bits}{RESET}")

    # ── Summary ───────────────────────────────────────────────────────────────
    print(f"\n{BOLD}{'═' * 62}{RESET}")
    if any_finding:
        print(f"{BOLD}{RED}  Findings detected — review sections above{RESET}")
    else:
        print(f"{BOLD}{GREEN}  No SSL/TLS vulnerabilities detected{RESET}")
    print(f"{BOLD}{'═' * 62}{RESET}\n")


if __name__ == "__main__":
    main()
