"""
Why was this raised, and which part of the evidence says so?

The Findings section was cut back to four fields because the long
version was mostly boilerplate that stayed the same whatever had been
observed — and on a finding whose classification was wrong, all of it
was wrong together. Cutting it left the opposite problem: a reader could
see the raw scanner line and the verdict, and not the step between them.

So each finding class gets a RULE rather than a paragraph. A rule takes
the structured evidence and returns four things:

    summary      one or two sentences: what was found and why it matters
    reason       which property makes the observation a weakness
    evidence     the exact values that support it
    limitation   what the evidence does NOT establish

Every sentence a rule produces is selected by a value it read. None of
them is generic prose about the vulnerability class, which is the
difference between an explanation and a description — a description of
reflected XSS is identical whether or not anything was reflected.

A class with no rule falls back to whatever the verifier recorded, which
is already evidence-based. Nothing here invents a header, a suite, a
version, a payload or a response.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from command_bridge.modules import cipher_properties as ciphers
from command_bridge.modules import csp_analysis


@dataclass
class Explanation:
    """What a reader needs between the scanner's line and the verdict."""

    summary: str = ""
    reason: str = ""
    evidence: list = field(default_factory=list)
    limitation: str = ""

    def text(self):
        """The whole thing as plain text, for "What was found"."""
        parts = []
        if self.summary:
            parts.append(self.summary.strip())
        if self.reason and self.reason.strip() not in (self.summary or ""):
            parts.append(self.reason.strip())
        if self.evidence:
            parts.append("\n".join(str(line) for line in self.evidence
                                   if str(line).strip()))
        if self.limitation:
            parts.append(self.limitation.strip())
        return "\n\n".join(p for p in parts if p)

    def as_dict(self):
        return {"summary": self.summary, "reason": self.reason,
                "evidence": list(self.evidence),
                "limitation": self.limitation}


# ── TLS ─────────────────────────────────────────────────────────────────
#
# Each of these is driven by the suites the relevant check matched, not
# by a search for a substring across everything the scan returned.

def _cbc_attack(name, concern, suites, host="", tested=False):
    """Shared shape for Lucky 13, BEAST and the other CBC attacks."""
    matched = ciphers.with_weakness(suites, ciphers.CBC_MODE)
    if not matched:
        return None
    where = f" on {host}" if host else ""
    explanation = Explanation(
        summary=(f"The server{where} offers {len(matched)} CBC-mode cipher "
                 f"suite(s). {concern}"),
        reason=("CBC suites in TLS compose MAC-then-encrypt, and the padding "
                "check leaks through the time taken to reject a record. "
                "AEAD suites (AES-GCM, ChaCha20-Poly1305) do not have this "
                "construction."),
        evidence=[f"CBC-mode suites accepted{where}:",
                  ciphers.listing(matched)],
    )
    acceptable = [s for s in suites if not s.weaknesses]
    if acceptable:
        explanation.evidence.append(
            f"\nAlso offered, and not part of this finding — "
            f"{len(acceptable)} AEAD suite(s):")
        explanation.evidence.append(ciphers.listing(acceptable))
    explanation.limitation = (
        f"Cipher support is confirmed. {name} itself was not attempted — no "
        f"timing measurements were taken — so whether this host is "
        f"practically exploitable is unestablished."
        if not tested else
        f"{name} was tested directly; see the measurements in the technical "
        f"detail.")
    return explanation


def lucky13(suites, host="", tested=False, **_):
    return _cbc_attack(
        "Lucky 13",
        "Lucky 13 concerns a timing side channel in CBC-mode TLS record "
        "processing.", suites, host, tested)


def beast(suites, host="", tested=False, **_):
    return _cbc_attack(
        "BEAST",
        "BEAST concerns the predictable CBC initialisation vector in "
        "TLS 1.0.", suites, host, tested)


def sweet32(suites, host="", **_):
    matched = ciphers.with_weakness(suites, ciphers.TRIPLE_DES) + \
        ciphers.with_weakness(suites, ciphers.DES)
    if not matched:
        return None
    where = f" on {host}" if host else ""
    return Explanation(
        summary=(f"The server{where} offers {len(matched)} suite(s) built on "
                 f"a 64-bit block cipher."),
        reason=("A 64-bit block reaches the birthday bound after about 32 GB "
                "on one connection, at which point a collision leaks "
                "plaintext. Modern suites use 128-bit blocks."),
        evidence=[f"64-bit block suites accepted{where}:",
                  ciphers.listing(matched)],
        limitation=("Cipher support is confirmed. Exploiting it needs a "
                    "very long-lived connection carrying attacker-"
                    "influenced data, which was not attempted."))


def static_rsa(suites, host="", **_):
    matched = ciphers.with_weakness(suites, ciphers.STATIC_RSA)
    if not matched:
        return None
    where = f" on {host}" if host else ""
    forward = [s for s in suites if s.forward_secrecy]
    explanation = Explanation(
        summary=(f"The server{where} offers {len(matched)} suite(s) using "
                 f"static RSA key exchange."),
        reason=("The client encrypts the premaster secret to the server's "
                "long-term RSA key, so anyone who later obtains that key can "
                "decrypt recorded sessions. ECDHE and DHE derive a fresh key "
                "per session and do not have this property."),
        evidence=[f"Static RSA key exchange{where}:",
                  ciphers.listing(matched)],
        limitation=("This is a property of the configuration. It becomes an "
                    "exposure only if the server's private key is "
                    "compromised, now or in future."))
    if forward:
        explanation.evidence.append(
            f"\n{len(forward)} suite(s) offered WITH forward secrecy, for "
            f"comparison:")
        explanation.evidence.append(ciphers.listing(forward[:6]))
    return explanation


def weak_ciphers(suites, host="", **_):
    """The general weak-cipher finding, grouped by what is wrong.

    The failure this replaces listed twelve suites under one heading,
    including every AES-GCM and TLS 1.3 suite the server offered. A
    reader could not tell which of the twelve the finding was about.
    """
    grouping = ciphers.group(suites)
    if not grouping.by_weakness:
        return None
    where = f" on {host}" if host else ""
    severe = [w for w in grouping.by_weakness if w in ciphers.SEVERE]

    headline = (f"{len(grouping.problematic)} of the {len(suites)} cipher "
                f"suite(s) offered{where} have a property worth acting on; "
                f"the rest do not and are listed separately.")
    if severe:
        headline += (" Some should not be offered at all, rather than being "
                     "a modernisation argument.")

    evidence = ["Problematic suites identified:"]
    order = sorted(grouping.by_weakness,
                   key=lambda w: (w not in ciphers.SEVERE, w))
    for weakness in order:
        matched = grouping.by_weakness[weakness]
        evidence.append(f"\n  {ciphers.REASONS.get(weakness, weakness)}")
        evidence.append(ciphers.listing(matched, indent="    "))
    if grouping.acceptable:
        evidence.append(
            f"\nOther suites observed — authenticated encryption, no "
            f"weakness identified, NOT part of this finding "
            f"({len(grouping.acceptable)}):")
        evidence.append(ciphers.listing(grouping.acceptable, indent="    "))
    if grouping.unparsed:
        evidence.append(
            "\nSuite names that could not be parsed, so nothing is claimed "
            "about them:")
        evidence.append(ciphers.listing(grouping.unparsed, note_bits=False,
                                        indent="    "))
    return Explanation(
        summary=headline,
        reason="",
        evidence=evidence,
        limitation=("Each group above is included for the property named "
                    "against it. A 128-bit key is not itself a weakness and "
                    "is not why any suite is listed."))


def obsolete_protocol(versions=(), host="", suites_by_version=None, **_):
    """Name the versions, and say what each one means."""
    if not versions:
        return None
    why = {
        "SSL 2.0": "broken in its key exchange and vulnerable to DROWN",
        "SSL 3.0": "vulnerable to POODLE; its CBC padding is not covered by "
                   "the MAC",
        "TLS 1.0": "deprecated by RFC 8996; its CBC IV is predictable "
                   "(BEAST) and it cannot negotiate AEAD",
        "TLS 1.1": "deprecated by RFC 8996 and supports no AEAD suites",
    }
    where = f" on {host}" if host else ""
    evidence = []
    for version in versions:
        evidence.append(f"  {version} — accepted; "
                        f"{why.get(version, 'deprecated')}")
        for suite in (suites_by_version or {}).get(version, [])[:6]:
            name = suite.get("name") if isinstance(suite, dict) else suite
            evidence.append(f"      {name}")
    return Explanation(
        summary=(f"The server{where} accepts {', '.join(versions)}, which "
                 f"{'are' if len(versions) > 1 else 'is'} deprecated."),
        reason=("A client that supports only a deprecated version can still "
                "connect, and a man in the middle can try to steer a modern "
                "client down to it."),
        evidence=["Protocol versions accepted:"] + evidence,
        limitation=("Protocol support is confirmed by the handshake. Whether "
                    "any client actually negotiates it depends on the "
                    "clients in use."))


def certificate_expiry(not_after=None, scanned_at=None, not_before=None,
                       host="", subject="", **_):
    """Interpret notAfter against the scan date, not in isolation.

    A certificate expiry date on its own is not a finding, and printing
    one under a heading about weak TLS configuration is how an unrelated
    date ended up as evidence for a cipher problem.
    """
    import datetime
    if not_after is None:
        return None
    try:
        expiry = (not_after if isinstance(not_after, datetime.datetime)
                  else datetime.datetime.fromisoformat(str(not_after)))
    except Exception:                                       # noqa: BLE001
        return Explanation(
            summary="The certificate's expiry date could not be parsed.",
            evidence=[f"notAfter (as reported): {not_after}"],
            limitation="No conclusion is drawn from an unparsed date.")
    now = scanned_at or datetime.datetime.now(tz=expiry.tzinfo)
    if isinstance(now, (int, float)):
        now = datetime.datetime.fromtimestamp(now, tz=expiry.tzinfo)
    days = (expiry - now).days

    evidence = [f"  notAfter:  {expiry.date().isoformat()}",
                f"  scan date: {now.date().isoformat()}"]
    if not_before is not None:
        evidence.insert(0, f"  notBefore: {not_before}")
    if subject:
        evidence.insert(0, f"  subject:   {subject}")

    where = f" for {host}" if host else ""
    if days < 0:
        return Explanation(
            summary=(f"The certificate{where} expired {abs(days)} day(s) "
                     f"before this scan."),
            reason=("Clients will refuse the connection or warn the user; an "
                    "expired certificate also stops being a useful identity "
                    "check."),
            evidence=["Certificate validity:"] + evidence,
            limitation="")
    if days <= 30:
        return Explanation(
            summary=(f"The certificate{where} expires in {days} day(s)."),
            reason="It is valid now; this is a renewal deadline.",
            evidence=["Certificate validity:"] + evidence,
            limitation="Not a vulnerability — a date to act on.")
    return None          # valid and not close to expiry: not a finding


# ── everything else ─────────────────────────────────────────────────────

def cross_site_framing(policy=None, url="", **_):
    if policy is None:
        return None
    summary, evidence, limitation = csp_analysis.explain_framing(policy, url)
    return Explanation(
        summary=summary,
        reason=("A page another site can embed can be overlaid or framed "
                "invisibly, so a user's click or keystroke lands somewhere "
                "they did not intend."),
        evidence=["Observed:"] + [f"  {line}" for line in evidence],
        limitation=limitation)


def shell_history(path="", http_status=0, content_type="", body_bytes=0,
                  confirmed=False, catch_all=False, **_):
    where = path or "the path"
    if confirmed:
        return Explanation(
            summary=(f"{where} is readable over HTTP and returned content in "
                     f"the file's own format."),
            reason=("Shell history routinely records credentials passed on "
                    "the command line, internal hostnames, database "
                    "connection strings and the shape of the deployment."),
            evidence=[f"  GET {where} → HTTP {http_status} "
                      f"({content_type}, {body_bytes} bytes)",
                      "  the body matches shell command history, not an "
                      "HTML document"],
            limitation=("What it exposes depends on what is in it — read the "
                        "file before reporting its contents."))
    if catch_all:
        return Explanation(
            summary=(f"A scanner matched a shell history signature at "
                     f"{where}, but the file was not retrieved."),
            reason=("This host serves a catch-all: it answers identically "
                    "for a path that cannot exist, so a 200 response does "
                    "not mean the file is there."),
            evidence=[f"  GET {where} → HTTP {http_status} "
                      f"({content_type}, {body_bytes} bytes)",
                      "  the same response is returned for a random "
                      "non-existent path"],
            limitation=("Nothing here shows an exposure. It is kept as a "
                        "lead for manual checking, not as a finding to "
                        "report."))
    return Explanation(
        summary=f"A scanner matched a shell history signature at {where}.",
        reason=("If the file is readable it tends to contain credentials and "
                "internal detail."),
        evidence=[f"  reported path: {where}"],
        limitation=("The response was not read, so whether the file is "
                    "actually exposed is unestablished."))


def sri_missing(scripts=(), url="", **_):
    listed = [str(s) for s in (scripts or []) if s]
    return Explanation(
        summary=("The page loads a script or stylesheet from another origin "
                 "with no integrity attribute."),
        reason=("Without an integrity hash the browser cannot tell whether "
                "the file it received is the file the author intended, so a "
                "compromise of that origin runs with this page's "
                "privileges."),
        evidence=(["External resource(s) with no integrity attribute:"]
                  + [f"  {s}" for s in listed[:8]]) if listed else
                 [f"  observed on {url}" if url else ""],
        limitation=("This is a property of the markup. It becomes an "
                    "exposure only if the third-party origin is "
                    "compromised."))


def component(name="", version="", path="", cves=(), reachable=True, **_):
    cve_list = [str(c) for c in (cves or []) if c]
    if version:
        summary = (f"{name or 'The component'} is reachable at "
                   f"{path or 'the target'} and reports version {version}.")
        limitation = (f"The version is established. Whether "
                      f"{', '.join(cve_list)} applies depends on that "
                      f"version and the configuration, and no exploitation "
                      f"was attempted."
                      if cve_list else
                      "The component and version are established; no "
                      "vulnerability was tested.")
    else:
        summary = (f"{name or 'The component'} is reachable at "
                   f"{path or 'the target'}, but no version could be read "
                   f"from the response.")
        limitation = (f"Without a version, whether "
                      f"{', '.join(cve_list)} applies is unestablished."
                      if cve_list else
                      "Without a version nothing can be said about known "
                      "issues in it.")
    evidence = [f"  path: {path}" if path else "",
                f"  version: {version}" if version else
                "  version: not determined from the response"]
    if cve_list:
        evidence.append(f"  referenced by the detector: "
                        f"{', '.join(cve_list)} (context, not a result)")
    return Explanation(
        summary=summary,
        reason=("An administrative or monitoring interface reachable without "
                "authentication widens the attack surface and often exposes "
                "internal detail."),
        evidence=[line for line in evidence if line],
        limitation=limitation)


def reflected_xss(parameter="", payload="", context="", reflected=False,
                  executed=False, url="", **_):
    if executed:
        return Explanation(
            summary=(f"Input in {parameter or 'a parameter'} is reflected "
                     f"into the page and executed by a browser."),
            reason="Script supplied in the request runs in the origin.",
            evidence=[f"  parameter: {parameter}", f"  payload: {payload}",
                      f"  context: {context or 'HTML'}",
                      "  a browser was driven to the URL and the script "
                      "ran"],
            limitation="")
    if reflected:
        return Explanation(
            summary=(f"Input in {parameter or 'a parameter'} is reflected "
                     f"into the response"
                     + (f" in {context} context." if context else ".")),
            reason=("Reflection into an unsafe context is the precondition "
                    "for script injection."),
            evidence=[f"  parameter: {parameter}", f"  payload: {payload}",
                      f"  context: {context or 'not determined'}"],
            limitation=("Reflection is confirmed; script execution was not "
                        "demonstrated, so exploitability depends on the "
                        "context and any encoding applied."))
    return Explanation(
        summary=("A scanner reported cross-site scripting, but no reflected "
                 "input was recorded."),
        reason="",
        evidence=[f"  reported at: {url}" if url else ""],
        limitation=("Without a parameter, a payload and a reflection, this "
                    "does not establish XSS."))


def sql_injection(parameter="", payload="", differential=False,
                  database_error="", timing=False, **_):
    evidence = [f"  parameter: {parameter}" if parameter else "",
                f"  payload: {payload}" if payload else ""]
    if database_error:
        evidence.append(f"  database error returned: {database_error[:200]}")
    if differential:
        evidence.append("  the true and false cases produced different "
                        "responses")
    if timing:
        evidence.append("  response time tracked the injected delay")

    if differential or database_error:
        return Explanation(
            summary=(f"Input in {parameter or 'a parameter'} reaches a SQL "
                     f"query."),
            reason=("The response changes with the logical value of the "
                    "injected condition, which a server error alone would "
                    "not do."
                    if differential else
                    "The database's own error text is returned, which places "
                    "the input inside a query."),
            evidence=[line for line in evidence if line],
            limitation=("Data was not extracted and no destructive statement "
                        "was run."))
    return Explanation(
        summary="A scanner reported SQL injection.",
        evidence=[line for line in evidence if line],
        limitation=("No differential, database error or timing evidence was "
                    "recorded, so this does not establish injection — a "
                    "generic server error is not enough."))


def command_injection(parameter="", payload="", command_output="",
                      timing=False, oob=False, **_):
    evidence = [f"  parameter: {parameter}" if parameter else "",
                f"  payload: {payload}" if payload else ""]
    if command_output:
        evidence.append(f"  command output in the response: "
                        f"{command_output[:200]}")
    if timing:
        evidence.append("  an injected delay changed the response time")
    if oob:
        evidence.append("  an out-of-band interaction was observed")

    if command_output or timing or oob:
        return Explanation(
            summary=(f"Input in {parameter or 'a parameter'} reaches a shell."),
            reason=("The response contains output that only running the "
                    "injected command produces."
                    if command_output else
                    "The injected command's side effect was observed."),
            evidence=[line for line in evidence if line],
            limitation=("Confirmed to the extent of the command that was "
                        "run; no further commands were executed."))
    return Explanation(
        summary="A scanner reported command injection.",
        evidence=[line for line in evidence if line],
        limitation=("No command output, timing change or out-of-band "
                    "interaction was recorded. Nothing here shows input "
                    "reaching a shell."))


#: issue key → rule. A key with no entry keeps whatever the verifier
#: recorded, which is already evidence-based.
RULES = {
    "lucky13": lucky13,
    "beast": beast,
    "sweet32": sweet32,
    "robot": static_rsa,
    "weak_cipher": weak_ciphers,
    "obsolete_protocol": obsolete_protocol,
    "cert_expired": certificate_expiry,
    "cert_expiring": certificate_expiry,
    "cross_site_framing": cross_site_framing,
    "csp_clickjacking": cross_site_framing,
    "xfo_missing": cross_site_framing,
    "shell_history_exposed": shell_history,
    "sri_missing": sri_missing,
    "component_admin_exposed": component,
    "component_known_vulnerable": component,
    "xss_reflected": reflected_xss,
    "sqli": sql_injection,
    "potential_sqli": sql_injection,
    "command_injection": command_injection,
}


def explain(key, **context):
    """The rule for ``key``, or None when there is no rule or no evidence."""
    rule = RULES.get(str(key or ""))
    if rule is None:
        return None
    try:
        return rule(**context)
    except TypeError:
        # A caller that does not have what this rule needs gets nothing
        # rather than a half-filled explanation.
        return None
    except Exception:                                       # noqa: BLE001
        return None
