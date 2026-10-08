"""
Target Setup tab creator.
"""
import os
import re
import sys
import json
import subprocess
from pathlib import Path

from PyQt6 import QtCore, QtGui, QtWidgets
from PyQt6.QtCore import QProcess, Qt, QTimer
from PyQt6.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
    QPushButton, QLabel, QLineEdit, QTextEdit, QTabWidget, QGridLayout,
    QGroupBox, QSplitter, QScrollArea, QFileDialog, QMessageBox,
    QComboBox, QFrame, QPlainTextEdit, QProgressBar, QToolButton,
)
from command_bridge.constants import APP_TITLE, APP_VERSION, THEMES, BASE_DIR



class TargetTabMixin:
    """Mixin providing target setup tab creator."""

    def create_target_tab(self):
        """Create target configuration tab"""
        widget = QWidget()
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QFrame.Shape.NoFrame)
        scroll.setWidget(widget)
        layout = QVBoxLayout(widget)
        layout.setContentsMargins(25, 25, 25, 25)
        layout.setSpacing(20)
        
        # Target input group
        target_group = self.create_card("Primary Target")
        target_layout = QVBoxLayout()
        
        target_label = QLabel("Target URL or Domain:")
        target_label.setObjectName("fieldLabel")
        target_layout.addWidget(target_label)
        
        self.target_input = QLineEdit()
        self.target_input.setPlaceholderText("example.com or https://example.com")
        self.target_input.setMinimumHeight(42)
        self.target_input.textChanged.connect(self.on_target_changed)
        self.target_input.textChanged.connect(self.save_target_preference)
        target_layout.addWidget(self.target_input)
        
        target_group.layout().addLayout(target_layout)
        layout.addWidget(target_group)

        # Output directory group — placed directly beneath the primary target
        # since "where results are saved" is the next thing to check before
        # running anything, not an afterthought below headers.
        output_group = self.create_card("Output Directory")
        output_layout = QVBoxLayout()

        output_label = QLabel("Save Results To:")
        output_label.setObjectName("fieldLabel")
        output_layout.addWidget(output_label)

        dir_row = QHBoxLayout()
        self.output_input = QLineEdit(str(self.output_dir))
        self.output_input.setReadOnly(True)
        self.output_input.setMinimumHeight(42)
        dir_row.addWidget(self.output_input)

        browse_btn = QPushButton("Browse...")
        browse_btn.setObjectName("primaryButton")
        browse_btn.clicked.connect(self.browse_output_dir)
        browse_btn.setFixedWidth(120)
        dir_row.addWidget(browse_btn)

        output_layout.addLayout(dir_row)
        output_group.layout().addLayout(output_layout)
        layout.addWidget(output_group)

        # Custom Headers group
        headers_group = self.create_card("Custom Headers")
        headers_layout = QVBoxLayout()

        headers_label = QLabel("Custom HTTP Headers:")
        headers_label.setObjectName("fieldLabel")
        headers_layout.addWidget(headers_label)

        self.headers_input = QPlainTextEdit()
        self.headers_input.setPlaceholderText("Authorization: Bearer token\nUser-Agent: Custom Agent\nX-Custom-Header: value")
        self.headers_input.setMaximumHeight(100)
        self.headers_input.textChanged.connect(self.save_headers_preference)
        headers_layout.addWidget(self.headers_input)

        headers_group.layout().addLayout(headers_layout)
        layout.addWidget(headers_group)

        # Environment / Tool Setup group — checks and (best-effort) repairs
        # the external tools every button in this app shells out to. Kali
        # boxes commonly end up with pipx-installed tools whose venv shims
        # point at a python interpreter that no longer exists (a system
        # Python upgrade breaks every pipx tool at once — droopescan, uro,
        # graphql-cop, etc. all fail with "bad interpreter: No such file or
        # directory"), and Go-based recon tools (gau, gf, Gxss, kxss, dalfox,
        # ...) are simply never installed on a fresh box. Both show up as a
        # wall of "command not found" errors the first time someone runs the
        # XSS Pipeline / Dalfox / droopescan buttons.
        tools_group = self.create_card("🧰 Environment / Tool Setup")
        tools_layout = QVBoxLayout()

        tools_desc = QLabel(
            "Check or repair the external command-line tools this software calls "
            "(nmap, ffuf, gobuster, sqlmap, nuclei, dalfox, the gau/gf/uro/Gxss/kxss "
            "XSS-hunting chain, and more). Repair also fixes pipx tools broken by a "
            "system Python upgrade (\"bad interpreter\" errors)."
        )
        tools_desc.setWordWrap(True)
        tools_desc.setObjectName("autoDesc")
        tools_layout.addWidget(tools_desc)

        tools_btn_row = QHBoxLayout()

        check_tools_btn = QPushButton("🔍 Check Installed Tools")
        check_tools_btn.setObjectName("secondaryButton")
        check_tools_btn.setMinimumHeight(38)
        check_tools_btn.setCursor(QtGui.QCursor(QtCore.Qt.CursorShape.PointingHandCursor))
        check_tools_btn.setToolTip(
            "Scans PATH for every external tool this app's buttons use and reports "
            "OK / MISSING / BROKEN (installed but fails to run — e.g. a pipx shim "
            "pointing at a deleted interpreter) for each. Makes no changes."
        )
        check_tools_btn.clicked.connect(self.run_check_tools)
        tools_btn_row.addWidget(check_tools_btn)

        install_tools_btn = QPushButton("🛠️ Install / Repair Missing Tools")
        install_tools_btn.setObjectName("primaryButton")
        install_tools_btn.setMinimumHeight(38)
        install_tools_btn.setCursor(QtGui.QCursor(QtCore.Qt.CursorShape.PointingHandCursor))
        install_tools_btn.setToolTip(
            "Best-effort install/repair for every missing or broken tool: apt for "
            "packaged tools, 'pipx install --force' for Python tools (this rebuilds "
            "a broken pipx venv), and 'go install' + a copy into ~/.local/bin for "
            "Go-based recon tools (gau, Gxss, kxss, ...), including fetching gf's "
            "XSS/SQLi pattern files. Requires sudo for apt packages and may prompt "
            "for your password in a terminal the first time. Safe to re-run any time."
        )
        install_tools_btn.clicked.connect(self.run_install_tools)
        tools_btn_row.addWidget(install_tools_btn)

        # Version data. Deliberately a button and not something that happens
        # during a scan: it is the only part of the application that sends
        # anything to a third party, so pressing it is a decision. It
        # carries no target data — only the names of well-known products.
        self.versions_btn = QPushButton("\U0001F4E6 Update Version Data")
        self.versions_btn.setObjectName("secondaryButton")
        self.versions_btn.setMinimumHeight(38)
        self.versions_btn.setCursor(
            QtGui.QCursor(QtCore.Qt.CursorShape.PointingHandCursor))
        self.versions_btn.setToolTip(
            "Fetches the current release of PHP, Apache, nginx, OpenSSL, "
            "WordPress, Tomcat, jQuery and about thirty other common "
            "products from endoflife.date, and checks that every reference "
            "link the reports use still resolves.\n\n"
            "Why a button: this is the only outbound request Command Bridge "
            "makes that is not to your target. It sends product names only "
            "\u2014 nothing about the engagement \u2014 and it happens when "
            "you press this and at no other time.\n\n"
            "The result is cached in ~/.config/CommandBridge and used "
            "offline, so 'outdated software' findings cite a figure you "
            "fetched on a date you chose, rather than whatever was true "
            "when Nikto's database was built.")
        self.versions_btn.clicked.connect(self.run_update_versions)
        tools_btn_row.addWidget(self.versions_btn)

        tools_layout.addLayout(tools_btn_row)
        self.versions_age = QLabel("")
        self.versions_age.setObjectName("autoDesc")
        self.versions_age.setWordWrap(True)
        tools_layout.addWidget(self.versions_age)
        self._refresh_version_age()
        tools_group.layout().addLayout(tools_layout)
        layout.addWidget(tools_group)

        # Software Updates — pulls the latest code from the git remote this
        # copy was cloned from and restarts in place, so a fix never has to
        # travel by zip file again. Everything the user has customised lives
        # in ~/.config/CommandBridge, outside the repo, and survives updates.
        update_group = self.create_card("Software Updates")
        update_layout = QVBoxLayout()

        update_desc = QLabel(
            "Fetch the latest version of Command Bridge, show what changed and "
            "restart. Your saved commands, theme and output directory are kept."
        )
        update_desc.setWordWrap(True)
        update_desc.setObjectName("autoDesc")
        update_layout.addWidget(update_desc)

        self._update_revision_label = QLabel("Installed revision: checking…")
        self._update_revision_label.setObjectName("cardHint")
        update_layout.addWidget(self._update_revision_label)

        update_btn_row = QHBoxLayout()
        self._update_button = QPushButton("Check for Updates")
        self._update_button.setObjectName("primaryButton")
        self._update_button.setMinimumHeight(38)
        self._update_button.setCursor(QtGui.QCursor(QtCore.Qt.CursorShape.PointingHandCursor))
        self._update_button.setToolTip(
            "Runs 'git fetch' against the remote this copy was cloned from, "
            "lists the incoming commits and — if you confirm — fast-forwards "
            "and restarts. Only ever fast-forwards: if this box has local "
            "commits or edits, it stops and tells you rather than overwriting "
            "them."
        )
        self._update_button.clicked.connect(self.check_for_updates)
        update_btn_row.addWidget(self._update_button)
        update_btn_row.addStretch()

        update_layout.addLayout(update_btn_row)
        update_group.layout().addLayout(update_layout)
        layout.addWidget(update_group)

        # Fill in the revision caption once the window is up; reading it needs
        # a couple of git calls and there is no reason to make startup wait.
        QtCore.QTimer.singleShot(0, self.refresh_update_label)

        layout.addStretch()

        return scroll

    # ── version catalogue ────────────────────────────────────────────────
    def _refresh_version_age(self):
        """Say how old the cached version data is, in plain words."""
        try:
            from command_bridge.modules import version_catalog
            data = version_catalog.load()
            age = version_catalog.age_days(data)
            count = len(data.get("products") or {})
        except Exception:                               # noqa: BLE001
            return
        if not count or age is None:
            self.versions_age.setText(
                "No version data yet \u2014 'outdated software' findings "
                "will link you to NVD and Snyk but will not state a current "
                "release.")
            return
        if age < 1:
            when = "today"
        elif age < 2:
            when = "yesterday"
        else:
            when = f"{int(age)} days ago"
        stale = "  \u2014 worth refreshing" if age > 60 else ""
        self.versions_age.setText(
            f"{count} products, last updated {when}.{stale}")

    def run_update_versions(self):
        """Fetch current versions and verify the reference links.

        Runs on a worker thread: it is a few dozen HTTPS requests and the
        window must not freeze while they happen. Progress goes to the
        console, because this is the one place the application talks to
        somebody other than the target and the operator should see it.
        """
        from PyQt6.QtCore import QThread, QObject, pyqtSignal
        from command_bridge.modules import version_catalog

        if getattr(self, "_versions_thread", None) is not None:
            self.console.append_ansi("[i] A version refresh is already "
                                     "running.\n")
            return

        self.goto_tab("console")
        self.console.append_ansi(
            "\n[i] Updating version data. This contacts endoflife.date and "
            "the reference sites; no target information is sent.\n")
        self.versions_btn.setEnabled(False)

        class _Worker(QObject):
            line = pyqtSignal(str)
            done = pyqtSignal(object, str)

            def run(self):
                try:
                    summary = version_catalog.refresh(
                        report=lambda text: self.line.emit(text))
                    self.done.emit(summary, "")
                except Exception as exc:                # noqa: BLE001
                    self.done.emit(None, f"{type(exc).__name__}: {exc}")

        self._versions_thread = QThread()
        self._versions_worker = _Worker()
        self._versions_worker.moveToThread(self._versions_thread)
        self._versions_thread.started.connect(self._versions_worker.run)
        self._versions_worker.line.connect(
            lambda text: self.console.append_ansi(text + "\n"))
        self._versions_worker.done.connect(self._on_versions_done)
        self._versions_thread.start()

    def _on_versions_done(self, summary, error):
        try:
            self._versions_thread.quit()
            self._versions_thread.wait(3000)
        except Exception:                               # noqa: BLE001
            pass
        self._versions_thread = None
        self._versions_worker = None
        self.versions_btn.setEnabled(True)

        if error:
            self.console.append_ansi(
                f"[!] Version refresh failed: {error}\n"
                f"    Findings will still link to NVD and Snyk; they just "
                f"will not state a current release.\n")
            return
        dead = [k for k, v in (summary.get("links") or {}).items()
                if not v.get("ok")]
        self.console.append_ansi(
            f"[+] Version data updated: {len(summary['updated'])} product(s) "
            f"refreshed, {len(summary['failed'])} failed, "
            f"{summary['count']} in the catalogue.\n")
        if summary["failed"]:
            for product, why in summary["failed"][:8]:
                self.console.append_ansi(f"    - {product}: {why}\n")
        if dead:
            self.console.append_ansi(
                f"[!] {len(dead)} reference link(s) did not resolve and have "
                f"been recorded as dead:\n")
            for url in dead[:8]:
                self.console.append_ansi(f"    - {url}\n")
        else:
            self.console.append_ansi(
                "    Every reference link resolved.\n")
        self._refresh_version_age()
