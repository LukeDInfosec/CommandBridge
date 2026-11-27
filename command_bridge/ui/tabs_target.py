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

        layout.addStretch()

        return scroll

    # ── version catalogue ────────────────────────────────────────────────
    # ── Traffic transparency ─────────────────────────────────────────
    #
    # The question a client asks is "what does your tool talk to?", and
    # the answer should not be a paragraph in a README. Two controls,
    # both off until the operator turns them on:
    #
    #   * a proxy, which sends this application's own HTTP and every
    #     tool it launches through Burp / ZAP / mitmproxy, and
    #   * a log, which records every outbound request this application
    #     makes, to a JSONL file that can be read offline.
    #
    # See modules/egress.py for what is recorded and what deliberately
    # is not.
    def _create_tools_card(self):
        """Build the tools_group card (own Settings tab)."""
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
        return tools_group

    def _create_uat_card(self):
        """Build the uat_group card (own Settings tab)."""
        # UAT — a known-vulnerable target to test changes against.
        uat_group = self.create_card("UAT \u2014 test against a known target")
        uat_layout = QVBoxLayout()
        uat_desc = QLabel(
            "Start OWASP Juice Shop on a free loopback port and point the "
            "scanner at it. Juice Shop's vulnerabilities are catalogued and "
            "written up by other people, so it is the one target where "
            "'did my change break a check?' has an answer that does not "
            "come from me."
        )
        uat_desc.setObjectName("autoDesc")
        uat_desc.setWordWrap(True)
        uat_layout.addWidget(uat_desc)

        uat_row = QHBoxLayout()
        self.uat_start_btn = QPushButton("\U0001F9EA Start Juice Shop (UAT)")
        self.uat_start_btn.setObjectName("primaryButton")
        self.uat_start_btn.setMinimumHeight(38)
        self.uat_start_btn.setCursor(
            QtGui.QCursor(QtCore.Qt.CursorShape.PointingHandCursor))
        self.uat_start_btn.setToolTip(
            "Pulls the bkimminich/juice-shop image from Docker Hub and runs "
            "it on 127.0.0.1 on a port nothing else is using, then opens it "
            "and sets it as the target.\n\n"
            "This downloads and runs third-party code, which is why it is a "
            "button and not something that happens on its own. It binds to "
            "loopback only and there is no option to change that: a "
            "deliberately vulnerable application on a routable address is "
            "an incident, not a test target.\n\n"
            "First run takes a few minutes for the image.")
        self.uat_start_btn.clicked.connect(self.run_start_uat)
        uat_row.addWidget(self.uat_start_btn)

        self.uat_stop_btn = QPushButton("\u23F9 Stop and remove")
        self.uat_stop_btn.setObjectName("secondaryButton")
        self.uat_stop_btn.setMinimumHeight(38)
        self.uat_stop_btn.setEnabled(False)
        self.uat_stop_btn.setCursor(
            QtGui.QCursor(QtCore.Qt.CursorShape.PointingHandCursor))
        self.uat_stop_btn.clicked.connect(self.run_stop_uat)
        uat_row.addWidget(self.uat_stop_btn)

        self.uat_coverage_btn = QPushButton("\U0001F4CB What it should find")
        self.uat_coverage_btn.setObjectName("secondaryButton")
        self.uat_coverage_btn.setMinimumHeight(38)
        self.uat_coverage_btn.setCursor(
            QtGui.QCursor(QtCore.Qt.CursorShape.PointingHandCursor))
        self.uat_coverage_btn.setToolTip(
            "Prints Juice Shop's 16 vulnerability categories and, against "
            "each, whether this scanner can prove it, partly covers it, or "
            "does not test for it at all. Read the scan against that rather "
            "than against hope.")
        self.uat_coverage_btn.clicked.connect(self.show_uat_coverage)
        uat_row.addWidget(self.uat_coverage_btn)
        uat_layout.addLayout(uat_row)

        self.uat_status = QLabel("")
        self.uat_status.setObjectName("autoDesc")
        self.uat_status.setWordWrap(True)
        uat_layout.addWidget(self.uat_status)
        uat_group.layout().addLayout(uat_layout)
        return uat_group

    # ── Settings tabs (relocated from the old Target tab) ────────────────
    def _settings_scroll(self, card):
        """Wrap a single settings card in a scrollable tab page."""
        from PyQt6.QtWidgets import QWidget, QScrollArea, QVBoxLayout, QFrame
        widget = QWidget()
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QFrame.Shape.NoFrame)
        scroll.setWidget(widget)
        layout = QVBoxLayout(widget)
        layout.setContentsMargins(25, 25, 25, 25)
        layout.setSpacing(20)
        layout.addWidget(card)
        layout.addStretch()
        return scroll

    def create_transparency_tab(self):
        """Settings → Traffic Transparency (proxy and egress log)."""
        return self._settings_scroll(self._create_egress_card())

    def create_tools_tab(self):
        """Settings → Environment / Tool Setup."""
        return self._settings_scroll(self._create_tools_card())

    def create_uat_tab(self):
        """Settings → UAT (test against a known target)."""
        return self._settings_scroll(self._create_uat_card())

    def _create_egress_card(self):
        from command_bridge.modules import egress

        group = self.create_card("Traffic Transparency (Proxy and Egress Log)")
        box = QVBoxLayout()

        description = QLabel(
            "Route this application's own requests — and every tool it "
            "runs — through a proxy you control, and keep a record of "
            "every outbound request it makes. Both are off until you "
            "switch them on.")
        description.setWordWrap(True)
        description.setObjectName("cardDescription")
        box.addWidget(description)

        proxy_row = QHBoxLayout()
        proxy_label = QLabel("Proxy:")
        proxy_label.setObjectName("fieldLabel")
        proxy_row.addWidget(proxy_label)
        self.egress_proxy_input = QLineEdit()
        self.egress_proxy_input.setPlaceholderText("127.0.0.1:8080")
        self.egress_proxy_input.setText(self._load_egress_proxy())
        proxy_row.addWidget(self.egress_proxy_input)
        self.egress_proxy_toggle = QtWidgets.QCheckBox(
            "Send all traffic through this proxy")
        self.egress_proxy_toggle.toggled.connect(self._apply_egress_settings)
        proxy_row.addWidget(self.egress_proxy_toggle)
        box.addLayout(proxy_row)
        self.egress_proxy_input.textChanged.connect(
            self._apply_egress_settings)

        self.egress_tls_toggle = QtWidgets.QCheckBox(
            "Accept the proxy's TLS certificate (needed for HTTPS "
            "interception unless its CA is already trusted)")
        self.egress_tls_toggle.toggled.connect(self._apply_egress_settings)
        box.addWidget(self.egress_tls_toggle)

        log_row = QHBoxLayout()
        self.egress_log_toggle = QtWidgets.QCheckBox(
            "Log every outbound request to a file")
        self.egress_log_toggle.toggled.connect(self._apply_egress_settings)
        log_row.addWidget(self.egress_log_toggle)
        self.egress_log_path = QLabel("no log file yet")
        self.egress_log_path.setObjectName("fieldLabel")
        self.egress_log_path.setWordWrap(True)
        log_row.addWidget(self.egress_log_path, 1)
        box.addLayout(log_row)

        button_row = QHBoxLayout()
        hosts_btn = QPushButton("Show every host contacted")
        hosts_btn.clicked.connect(self.show_egress_summary)
        button_row.addWidget(hosts_btn)
        folder_btn = QPushButton("Open the log file")
        folder_btn.clicked.connect(self.open_egress_log)
        button_row.addWidget(folder_btn)
        button_row.addStretch()
        box.addLayout(button_row)

        self.egress_status = QLabel(
            "Not proxying. Nothing logged yet this session.")
        self.egress_status.setObjectName("fieldLabel")
        self.egress_status.setWordWrap(True)
        box.addWidget(self.egress_status)

        self._egress_timer = QTimer(self)
        self._egress_timer.setInterval(2000)
        self._egress_timer.timeout.connect(self._refresh_egress_status)
        self._egress_timer.start()

        group.layout().addLayout(box)
        return group

    #: Where the proxy address is remembered between sessions. Beside
    #: the other preferences, and it holds an address, nothing else:
    #: the proxy's own credentials are not stored.
    _EGRESS_PREF = Path.home() / ".config" / "CommandBridge" / "egress_proxy.txt"

    def _load_egress_proxy(self):
        try:
            if self._EGRESS_PREF.is_file():
                saved = self._EGRESS_PREF.read_text().strip()
                if saved:
                    return saved
        except Exception:                                   # noqa: BLE001
            pass
        return "127.0.0.1:8080"

    def _save_egress_proxy(self, value):
        try:
            self._EGRESS_PREF.parent.mkdir(parents=True, exist_ok=True)
            self._EGRESS_PREF.write_text(str(value or "").strip())
        except Exception:                                   # noqa: BLE001
            pass

    def _apply_egress_settings(self):
        from command_bridge.modules import egress

        proxy = self.egress_proxy_input.text().strip()
        enabled = self.egress_proxy_toggle.isChecked()
        logging_on = self.egress_log_toggle.isChecked()

        if enabled and not proxy:
            self.egress_proxy_toggle.setChecked(False)
            self.egress_status.setText(
                "Enter a proxy address first, for example 127.0.0.1:8080.")
            return

        path = egress.STATE.log_path
        if logging_on and path is None:
            path = egress.default_log_path(
                getattr(self, "output_dir", None)
                or self.output_input.text().strip() or None)

        egress.STATE.configure(
            proxy_url=proxy, proxy_enabled=enabled, log_enabled=logging_on,
            log_path=str(path) if path else None,
            verify_tls=not self.egress_tls_toggle.isChecked())
        try:
            # Child processes started after this point inherit it; the
            # runner also sets it per command.
            egress.apply_to_environment()
        except Exception:                                   # noqa: BLE001
            pass
        self._save_egress_proxy(proxy)

        self.egress_log_path.setText(str(path) if path and logging_on
                                     else "no log file yet")
        if logging_on and path:
            egress.STATE.record_command(
                "--- egress logging enabled by the operator ---",
                component="command_bridge")
        self._refresh_egress_status()
        if enabled:
            self.console.append_ansi(
                f"[i] All traffic from Command Bridge is now routed through "
                f"{egress.normalise_proxy(proxy)} — its own requests and "
                f"every tool it launches.\n")
        if logging_on and path:
            self.console.append_ansi(
                f"[i] Outbound requests are being recorded to {path}\n")

    def _refresh_egress_status(self):
        from command_bridge.modules import egress

        # The scope follows the target, so the log can say whether a
        # host was one the engagement is about.
        try:
            target = getattr(self, "target", "") or ""
            host = egress.host_of(target) or target.strip()
            if host:
                egress.STATE.set_scope([host])
        except Exception:                                   # noqa: BLE001
            pass

        _lines, unexpected, total = egress.STATE.summary()
        state = (f"Proxying through {egress.STATE.proxy_url}"
                 if egress.STATE.active else "Not proxying")
        logged = (f"recording to {egress.STATE.log_path}"
                  if egress.STATE.log_enabled and egress.STATE.log_path
                  else "not recording")
        warning = ""
        if unexpected:
            warning = (f"  —  {unexpected} request(s) to host(s) that are "
                       f"neither in scope nor expected. Press 'Show every "
                       f"host contacted'.")
        self.egress_status.setText(
            f"{state}; {logged}. {total} request(s) from this application "
            f"so far.{warning}")

    def show_egress_summary(self):
        """Every host this application has contacted, and why."""
        from command_bridge.modules import egress

        lines, unexpected, total = egress.STATE.summary()
        if not lines:
            body = ("This application has made no outbound requests yet "
                    "this session.\n\nNote that tools it launches (nmap, "
                    "nuclei, testssl and the rest) make their own "
                    "requests, which do not pass through this process. "
                    "Those are visible in the proxy.")
        else:
            body = ("Requests  Host  —  why\n\n" + "\n".join(lines)
                    + f"\n\n{total} request(s) in total.")
            if unexpected:
                body += (f"\n\n{unexpected} of them went to a host that is "
                         f"neither in the engagement's scope nor one this "
                         f"application has a documented reason to contact. "
                         f"That is worth investigating — the log file has "
                         f"each one with a timestamp.")
            else:
                body += ("\n\nEvery host above is either the engagement's "
                         "own target or a documented one (certificate "
                         "transparency, tool downloads, CVE lookups).")
        dialog = QMessageBox(self)
        dialog.setWindowTitle("Hosts contacted by Command Bridge")
        dialog.setText(body)
        dialog.setIcon(QMessageBox.Icon.Warning if unexpected
                       else QMessageBox.Icon.Information)
        dialog.exec()

    def open_egress_log(self):
        from command_bridge.modules import egress

        path = egress.STATE.log_path
        if not path or not Path(str(path)).is_file():
            QMessageBox.information(
                self, "No log yet",
                "No egress log has been written yet. Tick 'Log every "
                "outbound request to a file' and run something.")
            return
        try:
            QtGui.QDesktopServices.openUrl(
                QtCore.QUrl.fromLocalFile(str(path)))
        except Exception as exc:                            # noqa: BLE001
            QMessageBox.information(self, "Could not open the log",
                                    f"The log is at:\n{path}\n\n{exc}")

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

    # ── UAT mode ─────────────────────────────────────────────────────────
    def show_uat_coverage(self):
        from command_bridge.modules import uat
        self.goto_tab("console")
        self.console.append_ansi("\n" + uat.coverage_report() + "\n")

    def run_start_uat(self):
        """Start Juice Shop on a free loopback port, on a worker thread."""
        from PyQt6.QtCore import QThread, QObject, pyqtSignal
        from command_bridge.modules import uat

        if getattr(self, "_uat_thread", None) is not None:
            self.console.append_ansi("[i] UAT is already starting.\n")
            return

        engine, note = uat.runtime()
        if engine is None:
            self.goto_tab("console")
            self.console.append_ansi(f"[!] Cannot start UAT: {note}\n")
            self.uat_status.setText(note)
            return

        self.goto_tab("console")
        self.console.append_ansi("\n" + uat.coverage_report() + "\n\n")
        self.uat_start_btn.setEnabled(False)
        self.uat_status.setText("Starting \u2014 the first run pulls a "
                                "400 MB image.")

        class _Worker(QObject):
            line = pyqtSignal(str)
            done = pyqtSignal(object, str)

            def run(self):
                url, why = uat.start(report=lambda t: self.line.emit(t))
                self.done.emit(url, why)

        self._uat_thread = QThread()
        self._uat_worker = _Worker()
        self._uat_worker.moveToThread(self._uat_thread)
        self._uat_thread.started.connect(self._uat_worker.run)
        self._uat_worker.line.connect(
            lambda t: self.console.append_ansi(t + "\n"))
        self._uat_worker.done.connect(self._on_uat_started)
        self._uat_thread.start()

    def _on_uat_started(self, url, why):
        import webbrowser
        try:
            self._uat_thread.quit()
            self._uat_thread.wait(3000)
        except Exception:                               # noqa: BLE001
            pass
        self._uat_thread = None
        self._uat_worker = None
        self.uat_start_btn.setEnabled(True)

        if not url:
            self.console.append_ansi(f"[!] UAT did not start: {why}\n")
            self.uat_status.setText(why)
            return
        self.uat_stop_btn.setEnabled(True)
        self.uat_status.setText(
            f"Running at {url} \u2014 set as the target. Stop it when you "
            f"are done; it is deliberately vulnerable.")
        # setText fires textChanged, which is wired to on_target_changed
        # and save_target_preference — so the target, the header chip and
        # the saved preference all follow from this one line.
        #
        # This used to call a self.set_target() that does not exist. It
        # did not crash only because the AttributeError landed in the
        # except below and the fallback set self.target directly, which
        # left the header chip showing the previous target. A bare
        # except that makes a missing method look like a working one is
        # how the next person loses an afternoon.
        self.target_input.setText(url)
        self.console.append_ansi(
            f"[+] {why}\n    Target set to {url}. Opening it in a "
            f"browser.\n")
        try:
            webbrowser.open(url)
        except Exception:                               # noqa: BLE001
            self.console.append_ansi("    (could not open a browser — "
                                     "open the URL yourself)\n")

    def run_stop_uat(self):
        from command_bridge.modules import uat
        self.goto_tab("console")
        if uat.stop(report=lambda t: self.console.append_ansi(t + "\n")):
            self.uat_status.setText("Stopped and removed.")
            self.uat_stop_btn.setEnabled(False)
        else:
            self.uat_status.setText("Could not stop it \u2014 see the "
                                    "console.")
