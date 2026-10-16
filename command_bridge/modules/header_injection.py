"""
Custom headers, applied to the tool that is actually being run.

The Target tab has a Custom Headers box. Before this module, exactly one
line in core/commands.py consumed it:

    headers_str = self.get_headers_string()
    if headers_str and 'curl' in cmd:
        cmd = cmd.replace('curl', f'curl {headers_str}')

Three things are wrong with that, and all three were reported from the
field as "my bearer token is being ignored":

  1. ONLY CURL. Every other tool got nothing. graphw00f, graphql-cop,
     ffuf, arjun, nuclei and sqlmap all accept custom headers and all of
     them were being run anonymously. Against an API that requires a
     bearer token that is not a degraded scan, it is a scan of a 401 page
     — and the tools dutifully report that they found no GraphQL engine,
     no introspection and no parameters, which reads exactly like a clean
     result.

  2. THE SUBSTRING. ``'curl' in cmd`` and ``cmd.replace('curl', ...)``
     match the four letters anywhere — in a filename, in an echo string,
     in a URL. A command that merely mentions curl got headers spliced
     into the middle of a word.

  3. SILENTLY. Nothing anywhere said "you set a header and it was not
     used". A tester had no way to tell the difference between a header
     that was applied and one that was dropped.

What this does instead: a table of the tools whose header syntax is
known, keyed by the executable name, each with its own flag and its own
value format — because they genuinely differ. graphql-cop takes a JSON
object, arjun takes one newline-separated string, graphw00f takes a
single header and silently keeps only the last one. Writing them all as
``-H 'Name: Value'`` would produce commands that run and do nothing,
which is the failure mode this module exists to end.

A tool NOT in the table is left alone and reported, so an unapplied
header is visible instead of assumed.

Nothing here interpolates a header value into a shell string unquoted:
every value goes through shlex.quote. A bearer token is a credential, so
it is also never written to the console — the report names the header,
never its value.
"""

from __future__ import annotations

import json
import re
import shlex

#: Headers that belong to the transport and must never be forwarded from
#: the operator's box to a target: they describe THIS connection, and
#: setting them by hand produces malformed requests or silent truncation.
NEVER_FORWARD = {
    "content-length", "transfer-encoding", "connection", "proxy-connection",
    "upgrade", "te", "trailer", "expect",
}

#: Headers whose value is a credential. Named in reports, never printed.
SECRET = {"authorization", "cookie", "proxy-authorization", "x-api-key",
          "x-auth-token", "api-key", "x-csrf-token", "x-amz-security-token"}


def parse(text):
    """``"Authorization: Bearer ey..."`` lines -> ``[(name, value), ...]``.

    Tolerant of what people actually paste: a trailing colon with no
    value is dropped, leading/trailing whitespace goes, blank lines and
    ``#`` comments are skipped, and a value containing a colon (every
    bearer token, every URL) is kept whole because only the FIRST colon
    separates the name.
    """
    out = []
    for line in (text or "").splitlines():
        line = line.strip()
        if not line or line.startswith("#") or ":" not in line:
            continue
        name, _, value = line.partition(":")
        name, value = name.strip(), value.strip()
        if not name or not value:
            continue
        if name.lower() in NEVER_FORWARD:
            continue
        out.append((name, value))
    return out


def describe(headers):
    """``"Authorization (hidden), X-Tenant: acme"`` — safe for the console."""
    parts = []
    for name, value in headers:
        if name.lower() in SECRET:
            parts.append(f"{name} (value hidden)")
        else:
            parts.append(f"{name}: {value}")
    return ", ".join(parts)


# ── per-tool header syntax ───────────────────────────────────────────────
#
# Each builder takes [(name, value)] and returns the arguments to splice in
# directly after the executable, already shell-quoted.

def _repeated_h(headers):
    """``-H 'Name: Value'`` once per header. curl, ffuf, nuclei, sqlmap."""
    return " ".join(f"-H {shlex.quote(f'{n}: {v}')}" for n, v in headers)


def _graphql_cop(headers):
    """graphql-cop takes a JSON OBJECT, repeatable.

        -H '{"Authorization": "Bearer ey..."}'

    Passing it ``-H 'Authorization: Bearer ey...'`` does not error. It
    fails to parse and the request goes out unauthenticated, which is
    how this went unnoticed.
    """
    return " ".join(
        f"-H {shlex.quote(json.dumps({n: v}))}" for n, v in headers)


def _graphw00f(headers):
    """graphw00f's -H is a plain optparse option, so it is NOT repeatable:
    the last one wins and the others vanish. Where several headers are
    set, prefer the one that carries the credential and say so."""
    chosen = None
    for name, value in headers:
        if name.lower() in SECRET:
            chosen = (name, value)
            break
    chosen = chosen or headers[0]
    return f"-H {shlex.quote(f'{chosen[0]}: {chosen[1]}')}"


def _arjun(headers):
    """arjun takes ONE --headers string, newline-separated for several."""
    blob = "\n".join(f"{n}: {v}" for n, v in headers)
    return f"--headers {shlex.quote(blob)}"


def _nikto(headers):
    """nikto repeats -H for extra headers."""
    return " ".join(f"-H {shlex.quote(f'{n}: {v}')}" for n, v in headers)


#: executable name -> (builder, how many headers it really honours)
TOOLS = {
    "curl":        (_repeated_h, None),
    "ffuf":        (_repeated_h, None),
    "nuclei":      (_repeated_h, None),
    "sqlmap":      (_repeated_h, None),
    "httpx":       (_repeated_h, None),
    "httpx-toolkit": (_repeated_h, None),
    "dalfox":      (_repeated_h, None),
    "gobuster":    (_repeated_h, None),
    "feroxbuster": (_repeated_h, None),
    "katana":      (_repeated_h, None),
    "wfuzz":       (_repeated_h, None),
    "nikto":       (_nikto, None),
    "graphql-cop": (_graphql_cop, None),
    "graphql-cop.py": (_graphql_cop, None),
    "graphw00f":   (_graphw00f, 1),
    "arjun":       (_arjun, None),
}

#: Tools that take no headers because they do not speak HTTP at that
#: layer. Listing them keeps them out of the "could not apply" report,
#: which would otherwise cry wolf on every TLS and port scan.
NO_HTTP = {"nmap", "testssl", "testssl.sh", "openssl", "sslscan", "sslyze",
           "dig", "whois", "host", "nslookup", "masscan", "amass",
           "subfinder", "assetfinder", "theharvester", "dnsrecon", "gau",
           "waybackurls", "echo", "cat", "grep", "sed", "awk", "python3",
           "tee", "sort", "uniq", "head", "tail", "jq"}

#: Shell syntax that sits in command position without being a command.
#: Without this, every ``if``/``for``/``done`` in a multi-step template
#: would be reported as a tool whose headers could not be applied.
SHELL_WORDS = {
    "if", "then", "elif", "else", "fi", "for", "in", "do", "done", "while",
    "until", "case", "esac", "function", "return", "exit", "break",
    "continue", "local", "export", "set", "unset", "shift", "read", "eval",
    "exec", "source", "trap", "wait", "true", "false", "test", "command",
    "printf", "sleep", "mkdir", "rm", "mv", "cp", "touch", "chmod", "ls",
    "wc", "cut", "tr", "xargs", "find", "basename", "dirname", "date",
    "env", "which", "time", "nohup", "sudo", "bash", "sh", "python",
}

#: Where a command can start: the beginning, or after a shell separator.
#: This is what replaces ``'curl' in cmd`` — the executable has to be in
#: command position, not merely present in the text somewhere.
_START = r"(?:^|(?<=[;|&\n(])|(?<=\$\()|(?<=&&)|(?<=\|\|))"


def _names_already_set(segment, tool):
    """Which header NAMES this invocation already sets by hand.

    Per name, not per flag. The first version of this asked only whether
    a ``-H`` appeared anywhere in the invocation, and the GraphQL
    introspection command sets ``-H 'Content-Type: application/json'`` —
    so the one command most likely to need a bearer token was the one
    guaranteed not to get it. Declining to overwrite ``Content-Type`` is
    right; declining to add ``Authorization`` because ``Content-Type``
    was there is the bug being fixed.
    """
    if tool == "arjun":
        blob = " ".join(re.findall(r"--headers[= ]\s*('[^']*'|\"[^\"]*\"|\S+)",
                                   segment))
    else:
        blob = " ".join(re.findall(
            r"(?:-H|--header)[= ]\s*('[^']*'|\"[^\"]*\"|\S+)", segment))
    found = set()
    for name in re.findall(r"([A-Za-z0-9_-]+)\s*:", blob):
        found.add(name.lower())
    # graphql-cop's JSON form: {"Authorization": "..."}
    for name in re.findall(r'\{\s*\\?"([A-Za-z0-9_-]+)\\?"', blob):
        found.add(name.lower())
    return found


def apply(cmd, headers):
    """Splice the headers into every tool invocation that accepts them.

    Returns ``(new_cmd, applied, skipped)`` — ``applied`` and ``skipped``
    being sorted lists of executable names, for the console note. The
    command is returned unchanged when there are no headers, so the
    normal no-header path costs one boolean test.
    """
    if not headers or not cmd:
        return cmd, [], []

    applied, skipped = set(), set()

    def splice(match):
        tool = match.group("tool")
        base = tool.rsplit("/", 1)[-1]
        entry = TOOLS.get(base)
        if entry is None:
            # A variable assignment, a flag, a shell keyword or a tool
            # that does not speak HTTP is not a missed opportunity.
            # A variable assignment, a flag, a file descriptor from a
            # redirection like ``2>&1``, a shell keyword, or a tool that
            # does not speak HTTP — none of these is a missed header.
            if ("=" not in tool and not tool.startswith("-")
                    and not tool.isdigit()
                    and base not in SHELL_WORDS and base not in NO_HTTP):
                skipped.add(base)
            return match.group(0)

        # Only look at this invocation, not the whole line: a pipeline
        # can hold several tools and they must be judged separately.
        tail = cmd[match.end():]
        segment = re.split(r"[;|\n]", tail, 1)[0]
        already = _names_already_set(segment, base)
        mine = [(n, v) for n, v in headers if n.lower() not in already]
        if not mine:
            return match.group(0)

        builder, limit = entry
        use = mine[:limit] if limit else mine
        if limit and len(mine) > limit:
            skipped.add(f"{base} (accepts only {limit}, "
                        f"{len(mine) - limit} not sent)")
        args = builder(use)
        applied.add(base)
        return f"{match.group(0)} {args}"

    # Every executable in command position, known or not. Matching ANY
    # executable rather than only the known ones is what lets this report
    # a tool it could not help with, instead of staying quiet about it.
    pattern = re.compile(_START + r"[ \t]*(?P<tool>[\w./-]+)(?=[ \t])")
    new_cmd = pattern.sub(splice, cmd)
    return new_cmd, sorted(applied), sorted(skipped)
