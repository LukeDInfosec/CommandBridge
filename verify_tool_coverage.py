#!/usr/bin/env python3
"""Check that every external tool the buttons call is handled by the installer.

The failure this exists to prevent: a button runs `dotdotpwn ...`, dotdotpwn is
not in install_tools.sh, "Check Installed Tools" reports a clean bill of health,
and the button still prints "not installed". Nothing in the code linked the two,
so this re-derives the link from source every time it runs.

What counts as a command
────────────────────────
Only three shapes, so UI labels and prose can never be mistaken for shell:

  1. the third element of a ``(label, button_id, command)`` tuple — the button
     definition shape used throughout the tab modules;
  2. any string containing a ``{TARGET}`` / ``{SAFE_TARGET}`` / ``{TARGET_HOST}``
     / ``{CB_DIR}`` placeholder — those only ever appear in command templates;
  3. any string containing a ``command -v <tool>`` guard.

Deliberately no hardcoded list of known tool names: a list like that goes stale
the moment a new button is added, which is the exact class of bug this checks
for.

Usage:
    python3 verify_tool_coverage.py          # exits 1 if anything is uncovered
    python3 verify_tool_coverage.py -v       # also list every tool and its uses
"""

from __future__ import annotations

import ast
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent
PKG = ROOT / "command_bridge"
INSTALLER = PKG / "modules" / "install_tools.sh"

# Shell builtins, coreutils and interpreters: present on any box, never
# something the installer needs to fetch.
BUILTINS = set(
    """
    if then else elif fi for while until do done case esac function return in
    echo printf cat grep egrep fgrep sed awk cut sort uniq head tail tr wc tee
    xargs find ls mkdir rmdir rm mv cp ln touch chmod chown stat test true false
    export local read eval exec set unset shift source alias type hash ulimit
    trap wait jobs bg fg disown pushd popd dirs cd pwd exit break continue
    getopts declare typeset readonly mapfile readarray let time command builtin
    bash sh zsh python python3 pip pip3 pipx perl ruby php node npm npx go cargo
    curl wget jq base64 openssl date sleep timeout nohup env printenv
    dirname basename realpath readlink mktemp seq paste join comm diff rev
    split nl fold column expand unexpand tsort shuf tac yes stdbuf sudo
    apt apt-get snap brew git tar unzip zip gzip gunzip file strings xxd
    md5sum sha1sum sha256sum host dig nslookup whois ping traceroute tracepath
    nc ncat socat ss netstat ip route arp lsof ps kill pkill pgrep
    df du free uname id whoami hostname uptime tty stty xdg-open
    """.split()
)

PLACEHOLDERS = ("{TARGET}", "{TARGET_HOST}", "{SAFE_TARGET}", "{CB_DIR}")

# Tools the app calls deliberately as an optional first choice, with an
# installed alternative behind them. tplmap is unmaintained, Python 2 era and
# in no repository — the SSTI button prefers it only if the user already has a
# working copy, and otherwise falls through to sstimap, which IS installed.
OPTIONAL = {"tplmap"}

_GUARD_RE = re.compile(r"command -v ([A-Za-z0-9_.+-]+)")
_PREFIX_RE = re.compile(r"^(?:sudo\s+|stdbuf(?:\s+-\S+)*\s+|time\s+)+")
# A real invocation: a binary name at the head of a segment, followed by
# end-of-segment, a flag/path/quote/variable/placeholder, or — for the
# subcommand-style tools (`gobuster dir -u ...`, `gf xss`, `dalfox url ...`) —
# a bare word, provided the segment as a whole still reads like shell.
_INVOCATION_RE = re.compile(
    r"^([A-Za-z][A-Za-z0-9_.+-]*)(?:\s+(?=[-'\"/${])|\s+[a-z][a-z0-9_-]*\b|\s*$)"
)


def _split_segments(text: str) -> list[str]:
    """Split a command on shell separators, ignoring quoted text.

    Quote-awareness matters: ``grep -Ei 'asp|php|jsp'`` is one invocation of
    grep, not four commands, and ``echo '[!] tool not installed'`` is one echo
    rather than a tool called "installed".
    """
    segments: list[str] = []
    current: list[str] = []
    quote: str | None = None
    i = 0
    while i < len(text):
        ch = text[i]
        if quote:
            current.append(ch)
            if ch == quote and (i == 0 or text[i - 1] != "\\"):
                quote = None
            i += 1
            continue
        if ch in "'\"":
            quote = ch
            current.append(ch)
            i += 1
            continue
        two = text[i:i + 2]
        if two in ("&&", "||") or two == "$(":
            segments.append("".join(current))
            current = []
            i += 2
            continue
        if ch in "|;\n`":
            segments.append("".join(current))
            current = []
            i += 1
            continue
        current.append(ch)
        i += 1
    segments.append("".join(current))
    return segments


def _static_value(node: ast.AST) -> str | None:
    """Best-effort literal value of a string expression."""
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    if isinstance(node, ast.JoinedStr):
        parts = []
        for value in node.values:
            if isinstance(value, ast.Constant) and isinstance(value.value, str):
                parts.append(value.value)
            else:
                parts.append("VAL")  # stand-in for an interpolated value
        return "".join(parts)
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
        left, right = _static_value(node.left), _static_value(node.right)
        if left is not None and right is not None:
            return left + right
    return None


def _docstring_ids(tree: ast.AST) -> set[int]:
    """Node ids of module/class/function docstrings.

    Docstrings in this codebase happily quote placeholders while explaining
    what a function does ("resolves {CB_DIR} and streams…"), so they have to be
    excluded or the prose gets parsed as shell.
    """
    ids: set[int] = set()
    for node in ast.walk(tree):
        if isinstance(node, (ast.Module, ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            body = getattr(node, "body", [])
            if (body and isinstance(body[0], ast.Expr)
                    and isinstance(body[0].value, ast.Constant)
                    and isinstance(body[0].value.value, str)):
                ids.add(id(body[0].value))
    return ids


def _is_shell_like(text: str) -> bool:
    """A command has a verb and an argument, not just a word."""
    if " " not in text:
        return False
    return bool(re.search(r"\s-{1,2}[A-Za-z]|[/{]|\s'|\s\"", text))


def _command_strings(tree: ast.AST) -> list[str]:
    out: list[str] = []
    docstrings = _docstring_ids(tree)

    # Shape 1: (label, button_id, command) button definitions. Tuples of three
    # plain words ("isAdmin", "role", "authorised") share that shape, so the
    # third element also has to read as shell.
    for node in ast.walk(tree):
        if isinstance(node, (ast.Tuple, ast.List)) and len(getattr(node, "elts", [])) == 3:
            values = [_static_value(e) for e in node.elts]
            if (values[1] and values[2]
                    and re.fullmatch(r"[a-z][a-z0-9_]*", values[1])
                    and _is_shell_like(values[2])):
                out.append(values[2])

    # Shapes 2 and 3: placeholder templates and command -v guards.
    for node in ast.walk(tree):
        if isinstance(node, (ast.Constant, ast.JoinedStr, ast.BinOp)):
            if id(node) in docstrings:
                continue
            text = _static_value(node)
            if not text:
                continue
            if any(p in text for p in PLACEHOLDERS) or "command -v " in text:
                out.append(text)
    return out


def tools_used() -> dict[str, set[str]]:
    """Map each external binary the app invokes -> the files that invoke it."""
    used: dict[str, set[str]] = {}
    for path in sorted(PKG.rglob("*.py")):
        if "__pycache__" in path.parts:
            continue
        try:
            tree = ast.parse(path.read_text(encoding="utf-8"))
        except SyntaxError:
            continue
        rel = str(path.relative_to(ROOT))
        for text in _command_strings(tree):
            for name in _GUARD_RE.findall(text):
                if name not in BUILTINS:
                    used.setdefault(name, set()).add(rel)
            for segment in _split_segments(text):
                segment = _PREFIX_RE.sub("", segment.strip())
                match = _INVOCATION_RE.match(segment)
                if not match:
                    continue
                name = match.group(1)
                if name in BUILTINS or name.isupper():
                    continue
                used.setdefault(name, set()).add(rel)
    return used


def tools_installed() -> set[str]:
    """Binaries install_tools.sh checks and can install."""
    names: set[str] = set()
    for line in INSTALLER.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if line.startswith("handle_tool"):
            parts = line.split()
            if len(parts) >= 3:
                names.add(parts[2].strip('"'))
    return names


def main() -> int:
    verbose = "-v" in sys.argv
    used = tools_used()
    installed = tools_installed()
    missing = {name: files for name, files in used.items()
               if name not in installed and name not in OPTIONAL}

    print(f"external tools invoked by the app : {len(used)}")
    print(f"tools handled by install_tools.sh : {len(installed)}")
    print()

    if missing:
        print("NOT COVERED BY THE INSTALLER:")
        for name in sorted(missing):
            where = ", ".join(sorted(missing[name])[:3])
            print(f"  {name:16s} used in {where}")
        print()
        print("Add a _i_<tool> installer and a handle_tool line to")
        print(f"  {INSTALLER.relative_to(ROOT)}")
        return 1

    print("Every tool the buttons call is handled by install_tools.sh.")
    if verbose:
        print()
        for name in sorted(used):
            print(f"  {name:16s} {', '.join(sorted(used[name])[:3])}")
    unused = installed - set(used)
    if unused:
        print()
        print("Installed but not called by any button (harmless, kept for manual use):")
        print("  " + ", ".join(sorted(unused)))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
