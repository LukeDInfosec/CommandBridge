"""
Self-update — pull the latest Command Bridge from its git remote and restart.

Why this exists
───────────────
Before this, shipping a fix meant: zip the tree, upload it somewhere, download
it on the laptop, extract it, copy it to the Kali box, relaunch. Every
one-line fix cost that whole loop. With the install directory as a git clone,
the box updates itself: fetch, show what changed, fast-forward, relaunch.

What is safe across an update
─────────────────────────────
Everything the user customises lives in ~/.config/CommandBridge (edited
command templates, theme choice, output directory, collapsed-section state,
rail preference) — outside the repo, so a pull never touches it. The repo
holds only code and the installer script.

Design notes
────────────
* Every git call runs on a worker thread. `git fetch` talks to the network and
  can block for many seconds; doing that on the GUI thread freezes the window
  and, on a slow link, gets the app killed as unresponsive.
* Nothing here ever runs `git reset --hard`, `git clean` or a force-pull
  without the user explicitly choosing it in a dialog that names what will be
  lost. An update button that silently destroys local edits is worse than no
  update button.
* Only fast-forward pulls. If the local branch has diverged (someone committed
  on the box), the update stops and says so rather than opening a merge the
  user cannot resolve from a GUI.
"""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

from PyQt6 import QtCore, QtWidgets
from PyQt6.QtCore import QThread, pyqtSignal
from PyQt6.QtWidgets import QMessageBox

from command_bridge.constants import BASE_DIR

#: git calls that touch the network get a generous timeout; local ones are
#: near-instant and a hang there means something is badly wrong.
NETWORK_TIMEOUT = 60
LOCAL_TIMEOUT = 15


def _run_git(args: list[str], timeout: int = LOCAL_TIMEOUT) -> tuple[int, str]:
    """Run a git command inside the install directory.

    Returns (exit_code, combined_output). Never raises: a missing git binary
    or a timeout comes back as a non-zero code with a readable message, which
    is what every caller here wants to show the user anyway.
    """
    env = dict(os.environ)
    # Stop git from trying to pop a GUI/terminal password prompt from under a
    # Qt app — an un-authenticated private remote would otherwise hang the
    # worker thread until the timeout instead of failing cleanly.
    env.setdefault("GIT_TERMINAL_PROMPT", "0")
    env.setdefault("GIT_ASKPASS", "echo")
    try:
        proc = subprocess.run(
            ["git", "-C", str(BASE_DIR), *args],
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            timeout=timeout,
            env=env,
        )
        return proc.returncode, proc.stdout.decode("utf-8", errors="replace").strip()
    except FileNotFoundError:
        return 127, "git is not installed (sudo apt install -y git)"
    except subprocess.TimeoutExpired:
        return 124, f"git {' '.join(args)} timed out after {timeout}s"
    except Exception as exc:  # pragma: no cover - defensive
        return 1, f"{type(exc).__name__}: {exc}"


def _redact(text: str) -> str:
    """Strip any token embedded in a remote URL before showing it.

    A remote stored as https://<token>@github.com/... will otherwise leak the
    token into an error dialog, and from there into a screenshot in a report.
    """
    import re

    return re.sub(r"://[^/@\s]+@", "://***@", text)


class _GitWorker(QThread):
    """Runs a sequence of git commands off the GUI thread."""

    finished_ok = pyqtSignal(dict)
    failed = pyqtSignal(str)

    def __init__(self, job: str, parent=None):
        super().__init__(parent)
        self.job = job

    def run(self):
        try:
            if self.job == "check":
                self._check()
            elif self.job == "pull":
                self._pull()
        except Exception as exc:  # pragma: no cover - defensive
            self.failed.emit(f"{type(exc).__name__}: {exc}")

    # ── jobs ──────────────────────────────────────────────────────────────
    def _check(self):
        code, branch = _run_git(["rev-parse", "--abbrev-ref", "HEAD"])
        if code != 0:
            self.failed.emit(_redact(branch))
            return

        code, out = _run_git(["fetch", "--prune", "origin"], NETWORK_TIMEOUT)
        if code != 0:
            self.failed.emit(_redact(out) or "git fetch failed")
            return

        # The upstream ref: whatever this branch tracks, falling back to
        # origin/<branch> for a clone made before tracking was set.
        code, upstream = _run_git(["rev-parse", "--abbrev-ref", "--symbolic-full-name", "@{u}"])
        if code != 0:
            upstream = f"origin/{branch}"

        _, local_sha = _run_git(["rev-parse", "HEAD"])
        code, remote_sha = _run_git(["rev-parse", upstream])
        if code != 0:
            self.failed.emit(
                f"Could not find the remote branch '{upstream}'.\n\n{_redact(remote_sha)}"
            )
            return

        _, behind_ahead = _run_git(["rev-list", "--left-right", "--count", f"{upstream}...HEAD"])
        behind, ahead = 0, 0
        parts = behind_ahead.split()
        if len(parts) == 2:
            behind, ahead = int(parts[0]), int(parts[1])

        _, log = _run_git(["log", "--oneline", "--no-decorate", "-20", f"HEAD..{upstream}"])
        _, dirty = _run_git(["status", "--porcelain", "--untracked-files=no"])

        self.finished_ok.emit({
            "branch": branch,
            "upstream": upstream,
            "local_sha": local_sha[:8],
            "remote_sha": remote_sha[:8],
            "behind": behind,
            "ahead": ahead,
            "log": log,
            "dirty": [line for line in dirty.splitlines() if line.strip()],
        })

    def _pull(self):
        code, out = _run_git(["merge", "--ff-only", "@{u}"], NETWORK_TIMEOUT)
        if code != 0:
            self.failed.emit(_redact(out) or "fast-forward merge failed")
            return
        _, sha = _run_git(["rev-parse", "--short", "HEAD"])
        self.finished_ok.emit({"sha": sha, "output": out})


class UpdaterMixin:
    """Mixin providing the Check for Updates button and its machinery."""

    # ── state helpers ─────────────────────────────────────────────────────
    def is_git_install(self) -> bool:
        """True when the install directory is a working git clone."""
        return (Path(BASE_DIR) / ".git").exists()

    def installed_revision(self) -> str:
        """Short description of what is currently installed, for the UI."""
        if not self.is_git_install():
            return "not a git install"
        code, sha = _run_git(["rev-parse", "--short", "HEAD"])
        if code != 0:
            return "unknown revision"
        code, when = _run_git(["log", "-1", "--format=%cd", "--date=format:%d %b %Y %H:%M"])
        code2, dirty = _run_git(["status", "--porcelain", "--untracked-files=no"])
        suffix = " (locally modified)" if code2 == 0 and dirty.strip() else ""
        return f"{sha} · {when}{suffix}" if code == 0 else f"{sha}{suffix}"

    def refresh_update_label(self):
        """Update the revision caption under the Update button, if present."""
        label = getattr(self, "_update_revision_label", None)
        if label is not None:
            label.setText(f"Installed revision: {self.installed_revision()}")

    # ── the button ────────────────────────────────────────────────────────
    def check_for_updates(self, silent: bool = False):
        """Fetch from the remote and offer to fast-forward if there is anything new.

        `silent` suppresses the "you are up to date" and error dialogs — used
        for the optional check on startup, where an offline box should not be
        greeted with a modal.
        """
        if not self.is_git_install():
            if not silent:
                self._show_not_a_clone_help()
            return

        button = getattr(self, "_update_button", None)
        if button is not None:
            button.setEnabled(False)
            button.setText("Checking…")

        worker = _GitWorker("check", self)
        worker.finished_ok.connect(lambda info: self._on_check_done(info, silent))
        worker.failed.connect(lambda msg: self._on_check_failed(msg, silent))
        worker.finished.connect(lambda: self._reset_update_button())
        self._update_worker = worker  # keep a reference alive
        worker.start()

    def _reset_update_button(self):
        button = getattr(self, "_update_button", None)
        if button is not None:
            button.setEnabled(True)
            button.setText("Check for Updates")
        self.refresh_update_label()

    def _on_check_failed(self, message: str, silent: bool):
        if silent:
            return
        box = QMessageBox(self)
        box.setIcon(QMessageBox.Icon.Warning)
        box.setWindowTitle("Update check failed")
        box.setText("Could not reach the update remote.")
        box.setInformativeText(
            "The most common causes are no network, or the box not having "
            "credentials for a private repository."
        )
        box.setDetailedText(message)
        self.apply_theme_to_dialog(box)
        box.exec()

    def _on_check_done(self, info: dict, silent: bool):
        if info["ahead"] and not info["behind"]:
            if not silent:
                self._info_dialog(
                    "Local commits not on the remote",
                    f"This copy is {info['ahead']} commit(s) ahead of "
                    f"{info['upstream']} and has nothing to pull.",
                    "Nothing to update. If those commits were not deliberate, "
                    "they will block future updates until they are pushed or "
                    "discarded.",
                )
            return

        if info["behind"] == 0:
            if not silent:
                self._info_dialog(
                    "Up to date",
                    "Command Bridge is up to date.",
                    f"Installed revision {info['local_sha']} on branch "
                    f"{info['branch']}.",
                )
            return

        if info["ahead"]:
            self._info_dialog(
                "Branch has diverged",
                f"This copy has {info['ahead']} local commit(s) that are not on "
                f"{info['upstream']}, and {info['behind']} update(s) are waiting.",
                "Updating would need a merge, which this button deliberately "
                "will not do for you. Resolve it from a terminal:\n\n"
                f"    cd {BASE_DIR}\n"
                "    git log --oneline @{u}..HEAD    # see your local commits\n"
                "    git pull --rebase               # replay them on top",
                icon=QMessageBox.Icon.Warning,
            )
            return

        self._offer_update(info)

    def _offer_update(self, info: dict):
        count = info["behind"]
        box = QMessageBox(self)
        box.setIcon(QMessageBox.Icon.Information)
        box.setWindowTitle("Update available")
        box.setText(f"{count} update{'s' if count != 1 else ''} available.")

        detail = info["log"] or "(no commit messages)"
        if info["dirty"]:
            files = "\n".join(f"    {line}" for line in info["dirty"][:20])
            box.setInformativeText(
                f"{info['local_sha']} → {info['remote_sha']}\n\n"
                "⚠ This copy has local modifications to tracked files. They "
                "would be overwritten, so the update is blocked until you deal "
                "with them.\n\n"
                "Your saved commands, theme and settings are NOT affected — "
                "those live in ~/.config/CommandBridge, outside the repo."
            )
            box.setDetailedText(f"Locally modified:\n{files}\n\nIncoming:\n{detail}")
            discard = box.addButton("Discard local changes and update",
                                    QMessageBox.ButtonRole.DestructiveRole)
            box.addButton("Cancel", QMessageBox.ButtonRole.RejectRole)
            box.setDefaultButton(discard)
            self.apply_theme_to_dialog(box)
            box.exec()
            if box.clickedButton() is discard:
                code, out = _run_git(["stash", "push", "--message",
                                      "command-bridge: auto-stashed before update"])
                if code != 0:
                    self._info_dialog("Could not set local changes aside",
                                      "The update was stopped.", _redact(out),
                                      icon=QMessageBox.Icon.Critical)
                    return
                self._start_pull(stashed=True)
            return

        box.setInformativeText(
            f"{info['local_sha']} → {info['remote_sha']} on {info['branch']}.\n\n"
            "Command Bridge will restart once the update is applied. Any scan "
            "still running will be stopped.\n\n"
            "Your saved commands, theme and output directory are untouched — "
            "they live in ~/.config/CommandBridge, outside the repo."
        )
        box.setDetailedText(detail)
        update = box.addButton("Update and restart", QMessageBox.ButtonRole.AcceptRole)
        box.addButton("Not now", QMessageBox.ButtonRole.RejectRole)
        box.setDefaultButton(update)
        self.apply_theme_to_dialog(box)
        box.exec()
        if box.clickedButton() is update:
            self._start_pull()

    def _start_pull(self, stashed: bool = False):
        button = getattr(self, "_update_button", None)
        if button is not None:
            button.setEnabled(False)
            button.setText("Updating…")
        worker = _GitWorker("pull", self)
        worker.finished_ok.connect(lambda res: self._on_pull_done(res, stashed))
        worker.failed.connect(lambda msg: self._on_pull_failed(msg, stashed))
        worker.finished.connect(lambda: self._reset_update_button())
        self._update_worker = worker
        worker.start()

    def _on_pull_failed(self, message: str, stashed: bool):
        extra = ""
        if stashed:
            extra = ("\n\nYour local changes were stashed before the attempt and "
                     "are still there — restore them with:\n    git stash pop")
        self._info_dialog("Update failed", "The update could not be applied.",
                          _redact(message) + extra, icon=QMessageBox.Icon.Critical)

    def _on_pull_done(self, result: dict, stashed: bool):
        note = ""
        if stashed:
            note = ("\n\nYour previous local changes are in the git stash "
                    "(git stash list) if you need them back.")
        self._info_dialog(
            "Update applied",
            f"Updated to {result.get('sha', 'the latest revision')}.",
            "Command Bridge will now restart." + note,
        )
        self.restart_application()

    # ── restart ───────────────────────────────────────────────────────────
    def restart_application(self):
        """Relaunch the app in place so the new code is loaded.

        Any running scan is stopped first: the QProcess is a child of this
        process and would otherwise be orphaned by the exec, leaving an
        invisible nmap or ffuf running against the target.
        """
        try:
            stop = getattr(self, "stop_current_process", None)
            if callable(stop):
                stop()
        except Exception:
            pass

        entry = Path(BASE_DIR) / "command_bridge_v5.py"
        try:
            QtWidgets.QApplication.processEvents()
            # os.execv replaces this process, so nothing after it runs. The
            # window does not need closing — the process simply becomes the
            # new one, which keeps the taskbar entry and desktop launcher
            # pointing at the same thing.
            os.execv(sys.executable, [sys.executable, str(entry)])
        except Exception as exc:
            self._info_dialog(
                "Restart failed",
                "The update was applied but the app could not restart itself.",
                f"Close and reopen Command Bridge to load the new version.\n\n{exc}",
                icon=QMessageBox.Icon.Warning,
            )

    # ── helpers ───────────────────────────────────────────────────────────
    def _info_dialog(self, title: str, text: str, detail: str = "",
                     icon=QMessageBox.Icon.Information):
        box = QMessageBox(self)
        box.setIcon(icon)
        box.setWindowTitle(title)
        box.setText(text)
        if detail:
            box.setInformativeText(detail)
        self.apply_theme_to_dialog(box)
        box.exec()

    def _show_not_a_clone_help(self):
        """Explain the one-time step that turns this folder into a git install."""
        code, _ = _run_git(["--version"])
        git_note = "" if code == 0 else "\n\nFirst: sudo apt install -y git"
        self._info_dialog(
            "Not a git install",
            "This copy of Command Bridge was extracted from a zip, so there is "
            "nothing to update from.",
            "To switch to self-updating, clone the repository once and run from "
            "the clone:\n\n"
            "    cd ~/Desktop/Luke_Software\n"
            "    git clone <repo-url> CommandBridge\n"
            "    cd CommandBridge && python3 command_bridge_v5.py\n\n"
            "Your saved commands and settings live in ~/.config/CommandBridge "
            "and will carry straight over." + git_note,
            icon=QMessageBox.Icon.Warning,
        )
