#!/usr/bin/env python3
"""
Does every method the code calls on the window actually exist?

    python3 verify_startup.py

Run it after updating, before launching. It exits 0 when the window
class can satisfy every call the package makes on ``self``, and 1 with
a list when it cannot.

WHY THIS EXISTS

CommandBridgeV5 is composed from twenty-six mixins. Nothing checks that
a method called in one mixin is defined in another — Python only finds
out when the line runs, which for a tab builder means the moment you
click that tab, and for __init__ means the application never opens at
all.

Two releases in a row shipped exactly that. window.py called
self.report_command_overrides() and cards.py called
self.register_default_command(); neither existed, and the tracebacks
arrived on the user's machine. A test suite can miss this when the tree
it runs in is not identical to the tree that ships — a stub, a stale
file, a mixin that was never copied across. This script does not care
about any of that. It reads the tree it is standing in.

WHAT IT CANNOT TELL YOU

That a method does the right thing — only that it is there. An
attribute set at runtime (self.foo = ... in some other method) counts
as existing, which is correct, and a name reached only through getattr
is not checked, which is also correct: those are already guarded.
"""

from __future__ import annotations

import ast
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent
PACKAGE = ROOT / "command_bridge"


def window_classes(tree):
    """The classes in this file whose ``self`` IS the window.

    Not every ``self`` in the package is CommandBridgeV5. widgets/
    console.py subclasses QTextEdit, and a table cell subclasses
    QTableWidgetItem; their self.textCursor() and self.data() are Qt
    methods on a different object entirely. Checking those against the
    window's methods produces nothing but noise — the first version of
    this script reported seven such lines and zero real ones, which
    would have taught anyone running it to ignore the output.

    The window is composed of mixins, so that is the test: a class
    named ``*Mixin``, or CommandBridgeV5 itself.
    """
    out = []
    for node in ast.walk(tree):
        if isinstance(node, ast.ClassDef):
            if node.name.endswith("Mixin") or node.name == "CommandBridgeV5":
                out.append(node)
    return out


def called_attributes(path):
    """Every ``self.NAME(...)`` in a window class, as ``{name: line}``."""
    try:
        tree = ast.parse(path.read_text(encoding="utf-8", errors="replace"))
    except SyntaxError as exc:
        print(f"  ! {path.relative_to(ROOT)} does not parse: {exc}")
        return {}
    found = {}
    for klass in window_classes(tree):
        for node in ast.walk(klass):
            # A call, not a plain attribute read: reading self.target
            # is not a claim that a method exists.
            if not isinstance(node, ast.Call):
                continue
            func = node.func
            if not isinstance(func, ast.Attribute):
                continue
            if not (isinstance(func.value, ast.Name)
                    and func.value.id == "self"):
                continue
            found.setdefault(func.attr, node.lineno)
    return found


def assigned_attributes(path):
    """Every ``self.NAME = ...`` and ``def NAME`` in a file.

    An attribute assigned anywhere in the package exists at runtime
    even though no mixin declares it, so collecting these keeps the
    report free of false alarms about things like self.command_registry.
    """
    try:
        tree = ast.parse(path.read_text(encoding="utf-8", errors="replace"))
    except SyntaxError:
        return set()
    names = set()
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            names.add(node.name)
        elif isinstance(node, ast.Attribute) and isinstance(node.ctx, ast.Store):
            if isinstance(node.value, ast.Name) and node.value.id == "self":
                names.add(node.attr)
    return names


def guarded(path, name):
    """Is this name only ever reached through getattr/hasattr?

    A guarded call is a deliberate "this may not be here", so it is not
    a defect. Checked by looking for the name as a STRING anywhere in
    the file, which is how both getattr and hasattr take it.
    """
    source = path.read_text(encoding="utf-8", errors="replace")
    return f'"{name}"' in source or f"'{name}'" in source


def main():
    if not PACKAGE.is_dir():
        print(f"No command_bridge package next to {Path(__file__).name} — "
              f"run this from the repository root.")
        return 2

    files = sorted(PACKAGE.rglob("*.py"))
    print(f"Reading {len(files)} files under {PACKAGE.name}/")

    defined = set()
    for path in files:
        defined |= assigned_attributes(path)

    # Anything Qt itself provides. CommandBridgeV5 is a QMainWindow, so
    # self.show(), self.close(), self.setWindowTitle() and several
    # hundred more are real without appearing anywhere in this tree.
    try:
        from PyQt6.QtWidgets import QMainWindow
        defined |= set(dir(QMainWindow))
    except Exception as exc:                                # noqa: BLE001
        print(f"  ! PyQt6 is not importable here ({exc}).")
        print("    Qt's own methods cannot be recognised, so expect "
              "false alarms below.")

    missing = []
    for path in files:
        for name, line in called_attributes(path).items():
            if name in defined or name.startswith("__"):
                continue
            if guarded(path, name):
                continue
            missing.append((path.relative_to(ROOT), line, name))

    if not missing:
        print(f"\n\033[32mOK\033[0m — every method called on the window is "
              f"defined somewhere in the tree.")
        return 0

    print(f"\n\033[31m{len(missing)} call"
          f"{'' if len(missing) == 1 else 's'} to a method that is not "
          f"defined anywhere:\033[0m\n")
    for path, line, name in sorted(missing):
        print(f"  {path}:{line}")
        print(f"      self.{name}(...)")
    print("\nEach of these raises AttributeError the moment it runs. If the "
          "call is optional, guard it:\n"
          '    fn = getattr(self, "name", None)\n'
          "    if callable(fn): fn()\n"
          "Otherwise the file that defines it is missing from this tree.")
    return 1


if __name__ == "__main__":
    sys.exit(main())
