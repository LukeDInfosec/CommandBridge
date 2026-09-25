"""
Active Scan tab — the scanner's front end.

The screen is arranged the way the work is: what to scan, who to scan as, how
hard to push, and then what it found. The authentication card is given the
most room because it is the part that decides whether the scan is worth
running at all, and the card tells you plainly whether the session was
established rather than making you infer it from an empty report.

The engine itself runs on a worker thread and never touches a widget; it
reports back through signals, so a two-hour scan does not freeze the window
and Stop actually stops.
"""

from __future__ import annotations

import time
import urllib.parse

from PyQt6 import QtGui
from PyQt6.QtCore import Qt, QObject, QThread, QTimer, pyqtSignal
from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QGridLayout, QLabel, QPushButton,
    QFrame, QScrollArea, QProgressBar, QTableWidget, QTableWidgetItem,
    QSplitter, QTextEdit, QHeaderView, QAbstractItemView, QComboBox,
    QLineEdit, QCheckBox, QFileDialog, QMessageBox, QSizePolicy, QGroupBox,
)

from command_bridge.modules import cb_issues

SEV_COLOURS = {
    "CRITICAL": "#ff3b5c", "HIGH": "#ff6b4a", "MEDIUM": "#f6b73c",
    "LOW": "#4f8cff", "INFO": "#8b9bb4",
}
SEV_RANK = {name: index for index, name in
            enumerate(("INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"))}


class _SeverityItem(QTableWidgetItem):
    """Sorts by how much it matters, not alphabetically."""

    def __lt__(self, other):
        mine = self.data(Qt.ItemDataRole.UserRole)
        theirs = other.data(Qt.ItemDataRole.UserRole)
        if mine is None or theirs is None:
            return super().__lt__(other)
        return mine < theirs


class _ScanWorker(QObject):
    """Runs one scan off the interface thread."""

    log = pyqtSignal(str)
    progress = pyqtSignal(str, int, int)
    finding = pyqtSignal(object)
    finished = pyqtSignal(object, str)

    def __init__(self, engine):
        super().__init__()
        self.engine = engine

    def run(self):
        try:
            self.engine.on_log = self.log.emit
            self.engine.on_progress = self.progress.emit
            self.engine.on_finding = self.finding.emit
            result = self.engine.run()
            self.finished.emit(result, "")
        except Exception as exc:                        # noqa: BLE001
            import traceback
            self.finished.emit(None, traceback.format_exc()
                               if not str(exc) else f"{type(exc).__name__}: "
                                                    f"{exc}")


class ActiveScanTabMixin:
    """Builds the tab and owns the widgets the engine reports into."""

    # ── construction ─────────────────────────────────────────────────────
    def create_active_scan_tab(self):
        widget = QWidget()
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QFrame.Shape.NoFrame)
        scroll.setWidget(widget)

        layout = QVBoxLayout(widget)
        layout.setContentsMargins(25, 25, 25, 25)
        layout.setSpacing(18)
        layout.addWidget(self._as_build_header())
        layout.addWidget(self._as_build_auth())
        layout.addWidget(self._as_build_options())
        layout.addWidget(self._as_build_findings(), 1)

        self._as_thread = None
        self._as_worker = None
        self._as_engine = None
        self._as_result = None
        self._as_findings = []
        self._as_started = 0.0
        self._as_timer = QTimer(self)
        self._as_timer.setInterval(1000)
        self._as_timer.timeout.connect(self._as_tick)
        return scroll

    def _as_build_header(self):
        card = self.create_card("🎯 Active Scan")
        box = QVBoxLayout()
        box.setSpacing(10)

        blurb = QLabel(
            "Crawls the application as a logged-in user, finds every place "
            "data can be put, attacks each one, and reports only what it "
            "could prove. Every finding carries the request and response that "
            "confirmed it.")
        blurb.setWordWrap(True)
        blurb.setStyleSheet("color: palette(mid); font-size: 12px;")
        box.addWidget(blurb)

        row = QHBoxLayout()
        row.setSpacing(10)
        self.as_start_btn = QPushButton("Start Active Scan")
        self.as_start_btn.setObjectName("primaryButton")
        self.as_start_btn.setMinimumHeight(42)
        self.as_start_btn.setCursor(
            QtGui.QCursor(Qt.CursorShape.PointingHandCursor))
        self.as_start_btn.clicked.connect(self.start_active_scan)
        row.addWidget(self.as_start_btn)

        self.as_stop_btn = QPushButton("Stop")
        self.as_stop_btn.setObjectName("secondaryButton")
        self.as_stop_btn.setMinimumHeight(42)
        self.as_stop_btn.setEnabled(False)
        self.as_stop_btn.clicked.connect(self.stop_active_scan)
        row.addWidget(self.as_stop_btn)
        row.addStretch()

        self.as_export_btn = QPushButton("Save report")
        self.as_export_btn.setObjectName("secondaryButton")
        self.as_export_btn.setMinimumHeight(42)
        self.as_export_btn.clicked.connect(self._as_export)
        row.addWidget(self.as_export_btn)
        box.addLayout(row)

        self.as_progress = QProgressBar()
        self.as_progress.setRange(0, 100)
        self.as_progress.setTextVisible(True)
        self.as_progress.setFormat("idle")
        self.as_progress.setMinimumHeight(22)
        box.addWidget(self.as_progress)

        status = QHBoxLayout()
        self.as_phase = QLabel("Set a target and press Start.")
        self.as_phase.setStyleSheet("font-weight: 600;")
        status.addWidget(self.as_phase)
        status.addStretch()
        self.as_elapsed = QLabel("")
        self.as_elapsed.setStyleSheet("color: palette(mid);")
        status.addWidget(self.as_elapsed)
        box.addLayout(status)

        self.as_tally = QLabel("")
        self.as_tally.setStyleSheet("font-size: 12px;")
        box.addWidget(self.as_tally)

        card.layout().addLayout(box)
        return card

    def _as_build_auth(self):
        card = self.create_card("Authentication")
        self._init_collapsible_groupbox(card, "as_auth_card")
        box = QVBoxLayout()
        box.setSpacing(10)

        note = QLabel(
            "An unauthenticated scan reaches the login page and very little "
            "else. The session check below is what stops a scan continuing "
            "quietly after the session expires — set it to a page that only "
            "works when logged in, and a string that only appears on it.")
        note.setWordWrap(True)
        note.setStyleSheet("color: palette(mid); font-size: 11.5px;")
        box.addWidget(note)

        grid = QGridLayout()
        grid.setHorizontalSpacing(12)
        grid.setVerticalSpacing(8)

        self.as_auth_mode = QComboBox()
        for label, value in (("None — scan as an anonymous user", "none"),
                             ("Form login (username and password)", "form"),
                             ("Browser login (headless Chromium)", "browser"),
                             ("Cookies / headers I paste in", "static"),
                             ("Bearer token from an OAuth endpoint", "bearer")):
            self.as_auth_mode.addItem(label, value)
        self.as_auth_mode.currentIndexChanged.connect(self._as_auth_mode)
        grid.addWidget(QLabel("Method"), 0, 0)
        grid.addWidget(self.as_auth_mode, 0, 1, 1, 3)

        self.as_login_url = QLineEdit()
        self.as_login_url.setPlaceholderText("https://app.example/login")
        grid.addWidget(QLabel("Login URL"), 1, 0)
        grid.addWidget(self.as_login_url, 1, 1, 1, 3)

        self.as_username = QLineEdit()
        self.as_username.setPlaceholderText("username")
        self.as_password = QLineEdit()
        self.as_password.setPlaceholderText("password")
        self.as_password.setEchoMode(QLineEdit.EchoMode.Password)
        grid.addWidget(QLabel("User"), 2, 0)
        grid.addWidget(self.as_username, 2, 1)
        grid.addWidget(QLabel("Password"), 2, 2)
        grid.addWidget(self.as_password, 2, 3)

        self.as_check_url = QLineEdit()
        self.as_check_url.setPlaceholderText(
            "https://app.example/account — a page that needs a session")
        self.as_signature = QLineEdit()
        self.as_signature.setPlaceholderText("Sign out")
        grid.addWidget(QLabel("Session check"), 3, 0)
        grid.addWidget(self.as_check_url, 3, 1)
        grid.addWidget(QLabel("Looks for"), 3, 2)
        grid.addWidget(self.as_signature, 3, 3)

        self.as_cookies = QLineEdit()
        self.as_cookies.setPlaceholderText(
            "sid=abc123; other=value    (for the paste-in method)")
        grid.addWidget(QLabel("Cookies"), 4, 0)
        grid.addWidget(self.as_cookies, 4, 1, 1, 3)

        self.as_headers = QLineEdit()
        self.as_headers.setPlaceholderText(
            "Authorization: Bearer …    (one per comma)")
        grid.addWidget(QLabel("Headers"), 5, 0)
        grid.addWidget(self.as_headers, 5, 1, 1, 3)
        box.addLayout(grid)

        self.as_second_user = QCheckBox(
            "I have a second account — test for IDOR and privilege escalation")
        self.as_second_user.setToolTip(
            "Replays one user's requests as the other. This is the check that "
            "cannot be done without two logins, and it is usually where the "
            "worst findings are.")
        self.as_second_user.stateChanged.connect(self._as_second_toggle)
        box.addWidget(self.as_second_user)

        second = QGridLayout()
        second.setHorizontalSpacing(12)
        self.as_username2 = QLineEdit()
        self.as_username2.setPlaceholderText("second username")
        self.as_password2 = QLineEdit()
        self.as_password2.setPlaceholderText("second password")
        self.as_password2.setEchoMode(QLineEdit.EchoMode.Password)
        second.addWidget(QLabel("Second user"), 0, 0)
        second.addWidget(self.as_username2, 0, 1)
        second.addWidget(QLabel("Password"), 0, 2)
        second.addWidget(self.as_password2, 0, 3)
        self._as_second_widgets = [self.as_username2, self.as_password2]
        for widget in self._as_second_widgets:
            widget.setEnabled(False)
        box.addLayout(second)

        card.layout().addLayout(box)
        self._as_auth_mode()
        return card

    def _as_build_options(self):
        card = self.create_card("Scope and aggression")
        self._init_collapsible_groupbox(card, "as_options_card")
        grid = QGridLayout()
        grid.setHorizontalSpacing(12)
        grid.setVerticalSpacing(8)

        self.as_profile = QComboBox()
        for label, value in (
                ("Safe — read-only, no forms submitted", "safe"),
                ("Standard — submits forms, nothing destructive", "standard"),
                ("Full — everything, for staging only", "full")):
            self.as_profile.addItem(label, value)
        self.as_profile.setCurrentIndex(1)
        grid.addWidget(QLabel("Profile"), 0, 0)
        grid.addWidget(self.as_profile, 0, 1, 1, 3)

        self.as_exclude = QLineEdit()
        self.as_exclude.setPlaceholderText(
            "/billing, /admin/delete — patterns never to touch")
        grid.addWidget(QLabel("Never touch"), 1, 0)
        grid.addWidget(self.as_exclude, 1, 1, 1, 3)

        self.as_subdomains = QCheckBox("Include subdomains")
        self.as_browser = QCheckBox("Confirm XSS in a real browser")
        self.as_browser.setChecked(True)
        self.as_browser_crawl = QCheckBox("Render pages while crawling (SPAs)")
        grid.addWidget(self.as_subdomains, 2, 0, 1, 2)
        grid.addWidget(self.as_browser, 2, 2, 1, 2)
        grid.addWidget(self.as_browser_crawl, 3, 0, 1, 2)

        card.layout().addLayout(grid)
        return card

    def _as_build_findings(self):
        card = self.create_card("Findings")
        box = QVBoxLayout()
        box.setSpacing(8)

        controls = QHBoxLayout()
        controls.addWidget(QLabel("Show"))
        self.as_filter = QComboBox()
        self.as_filter.addItem("Everything", "")
        for severity in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"):
            self.as_filter.addItem(severity.title() + "+", severity)
        self.as_filter.currentIndexChanged.connect(self._as_apply_filter)
        controls.addWidget(self.as_filter)
        controls.addStretch()
        self.as_count = QLabel("")
        self.as_count.setStyleSheet("color: palette(mid); font-size: 12px;")
        controls.addWidget(self.as_count)
        box.addLayout(controls)

        splitter = QSplitter(Qt.Orientation.Vertical)
        self.as_table = QTableWidget(0, 5)
        self.as_table.setHorizontalHeaderLabels(
            ["Severity", "Finding", "Where", "Parameter", "Confidence"])
        self.as_table.verticalHeader().setVisible(False)
        self.as_table.setSelectionBehavior(
            QAbstractItemView.SelectionBehavior.SelectRows)
        self.as_table.setSelectionMode(
            QAbstractItemView.SelectionMode.SingleSelection)
        self.as_table.setEditTriggers(
            QAbstractItemView.EditTrigger.NoEditTriggers)
        self.as_table.setAlternatingRowColors(False)
        self.as_table.setSortingEnabled(True)
        self.as_table.sortByColumn(0, Qt.SortOrder.DescendingOrder)
        header = self.as_table.horizontalHeader()
        header.setSectionResizeMode(0, QHeaderView.ResizeMode.Fixed)
        self.as_table.setColumnWidth(0, 108)
        header.setSectionResizeMode(1, QHeaderView.ResizeMode.Stretch)
        header.setSectionResizeMode(2, QHeaderView.ResizeMode.Stretch)
        header.setSectionResizeMode(3, QHeaderView.ResizeMode.ResizeToContents)
        header.setSectionResizeMode(4, QHeaderView.ResizeMode.Fixed)
        self.as_table.setColumnWidth(4, 104)
        self.as_table.itemSelectionChanged.connect(self._as_show_detail)
        self.as_table.setMinimumHeight(260)
        splitter.addWidget(self.as_table)

        self.as_detail = QTextEdit()
        self.as_detail.setReadOnly(True)
        self.as_detail.setMinimumHeight(200)
        self.as_detail.setPlaceholderText(
            "Select a finding to see the evidence that confirmed it.")
        splitter.addWidget(self.as_detail)
        splitter.setStretchFactor(0, 3)
        splitter.setStretchFactor(1, 2)
        box.addWidget(splitter)

        card.layout().addLayout(box)
        card.setSizePolicy(QSizePolicy.Policy.Expanding,
                           QSizePolicy.Policy.Expanding)
        return card

    # ── interaction ──────────────────────────────────────────────────────
    def _as_auth_mode(self):
        mode = self.as_auth_mode.currentData()
        credentials = mode in ("form", "browser")
        for widget in (self.as_login_url, self.as_username, self.as_password):
            widget.setEnabled(credentials)
        self.as_cookies.setEnabled(mode == "static")
        self.as_headers.setEnabled(mode in ("static", "bearer"))
        for widget in (self.as_check_url, self.as_signature):
            widget.setEnabled(mode != "none")
        self.as_second_user.setEnabled(credentials)

    def _as_second_toggle(self):
        for widget in self._as_second_widgets:
            widget.setEnabled(self.as_second_user.isChecked())

    # ── running ──────────────────────────────────────────────────────────
    def start_active_scan(self):
        from command_bridge.modules.scanner import (
            AuthConfig, Profile, PROFILES, ScanEngine, build_scope)

        if not getattr(self, "target", ""):
            self.show_themed_message(
                "No Target", "Set a target in the Target Setup tab first.",
                QMessageBox.Icon.Warning)
            return
        if self._as_thread is not None:
            self.show_themed_message(
                "Already running", "A scan is already in progress.",
                QMessageBox.Icon.Information)
            return

        mode = self.as_auth_mode.currentData()
        if mode != "none" and not self.as_check_url.text().strip():
            answer = QMessageBox.question(
                self, "No session check",
                "Without a session check the scan cannot tell whether it is "
                "still logged in, and a session that expires halfway through "
                "will produce a report that looks clean.\n\nStart anyway?",
                QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
                QMessageBox.StandardButton.No)
            if answer != QMessageBox.StandardButton.Yes:
                return

        auth = AuthConfig(
            mode,
            login_url=self.as_login_url.text().strip(),
            username=self.as_username.text().strip(),
            password=self.as_password.text(),
            check_url=self.as_check_url.text().strip(),
            logged_in_signature=self.as_signature.text().strip(),
            cookies=_parse_cookies(self.as_cookies.text()),
            headers=_parse_headers(self.as_headers.text()),
            name=self.as_username.text().strip() or "user")

        second = None
        if self.as_second_user.isChecked() and \
                self.as_username2.text().strip():
            second = AuthConfig(
                mode,
                login_url=self.as_login_url.text().strip(),
                username=self.as_username2.text().strip(),
                password=self.as_password2.text(),
                check_url=self.as_check_url.text().strip(),
                logged_in_signature=self.as_signature.text().strip(),
                name=self.as_username2.text().strip() or "second user")

        profile = PROFILES[self.as_profile.currentData()]()
        profile.use_browser = self.as_browser.isChecked()
        profile.browser_crawl = self.as_browser_crawl.isChecked()

        target = self.target
        if not target.startswith(("http://", "https://")):
            target = "https://" + target
        exclude = [part.strip() for part in self.as_exclude.text().split(",")
                   if part.strip()]
        scope = build_scope(target, exclude=exclude,
                            allow_subdomains=self.as_subdomains.isChecked())

        self._as_reset(target, profile.name)
        self._as_engine = ScanEngine(target, auth=auth, second_auth=second,
                                     profile=profile, scope=scope)

        self._as_thread = QThread()
        self._as_worker = _ScanWorker(self._as_engine)
        self._as_worker.moveToThread(self._as_thread)
        self._as_thread.started.connect(self._as_worker.run)
        self._as_worker.log.connect(self._as_log)
        self._as_worker.progress.connect(self._as_on_progress)
        self._as_worker.finding.connect(self._as_on_finding)
        self._as_worker.finished.connect(self._as_on_finished)
        self._as_thread.start()

    def stop_active_scan(self):
        if self._as_engine is not None:
            self._as_engine.stop()
            self._as_log("[scan] stopping after the current step…")

    def _as_reset(self, target, profile_name):
        self.as_table.setRowCount(0)
        self.as_detail.clear()
        self._as_findings = []
        self._as_result = None
        self._as_started = time.time()
        self.as_progress.setValue(0)
        self.as_progress.setFormat("starting…")
        self.as_phase.setText(f"Scanning {target} — {profile_name} profile")
        self.as_tally.setText("")
        self.as_count.setText("")
        self.as_start_btn.setEnabled(False)
        self.as_stop_btn.setEnabled(True)
        self._as_timer.start()
        try:
            self.goto_tab("scan")
        except Exception:                               # noqa: BLE001
            pass
        self.console.append_ansi("\n" + "=" * 80 + "\n")
        self.console.append_ansi(f"[*] Active scan — {target}\n")
        self.console.append_ansi("=" * 80 + "\n")
        try:
            self.set_status_state("running")
            self.update_status_bar("running", "Active Scan")
        except Exception:                               # noqa: BLE001
            pass

    # ── signals from the worker ──────────────────────────────────────────
    def _as_log(self, line):
        self.console.append_ansi(line + "\n")

    def _as_on_progress(self, phase, done, total):
        self.as_phase.setText(phase)
        if total:
            self.as_progress.setValue(int(done / total * 100))
            self.as_progress.setFormat(f"{phase} — {done} of {total}")

    def _as_on_finding(self, finding):
        self._as_findings.append(finding)
        self._as_add_row(finding)
        self._as_update_tally()

    def _as_on_finished(self, result, error):
        self._as_timer.stop()
        self.as_start_btn.setEnabled(True)
        self.as_stop_btn.setEnabled(False)
        if self._as_thread is not None:
            self._as_thread.quit()
            self._as_thread.wait(3000)
        self._as_thread = None
        self._as_worker = None
        self._as_result = result

        if error:
            self.as_progress.setFormat("failed")
            self.as_phase.setText("The scan stopped with an error.")
            self.show_themed_message("Scan failed", error,
                                     QMessageBox.Icon.Warning)
            return

        self.as_progress.setValue(100)
        self.as_progress.setFormat("finished")
        minutes, seconds = divmod(int(result.duration), 60)
        summary = (f"{len(result.findings)} confirmed finding(s) in "
                   f"{minutes}m {seconds:02d}s — {result.points_tested} "
                   f"parameter(s) across {result.requests_seen} request(s)")
        if not result.authenticated:
            summary += " — NOT authenticated"
        self.as_phase.setText(summary)
        try:
            self.set_status_state("idle")
            self.update_status_bar("success", "Active Scan")
        except Exception:                               # noqa: BLE001
            pass

    def _as_tick(self):
        if not self._as_started:
            return
        elapsed = int(time.time() - self._as_started)
        self.as_elapsed.setText(f"running for {elapsed // 60}m "
                                f"{elapsed % 60:02d}s")

    # ── the table ────────────────────────────────────────────────────────
    def _as_severity(self, finding):
        issue = cb_issues.ISSUES.get(finding.issue, {})
        return finding.severity or issue.get("severity", "MEDIUM")

    def _as_add_row(self, finding):
        severity = self._as_severity(finding)
        wanted = self.as_filter.currentData()
        if wanted and SEV_RANK.get(severity, 0) < SEV_RANK.get(wanted, 0):
            self._as_update_count()
            return

        issue = cb_issues.ISSUES.get(finding.issue, {})
        self.as_table.setSortingEnabled(False)
        row = self.as_table.rowCount()
        self.as_table.insertRow(row)

        cell = _SeverityItem(severity)
        cell.setData(Qt.ItemDataRole.UserRole, SEV_RANK.get(severity, 0))
        cell.setForeground(QtGui.QColor(SEV_COLOURS.get(severity, "#8b9bb4")))
        font = cell.font()
        font.setBold(True)
        cell.setFont(font)
        cell.setTextAlignment(Qt.AlignmentFlag.AlignCenter)

        title = QTableWidgetItem(issue.get("title", finding.issue))
        title.setToolTip(issue.get("title", finding.issue))
        where = QTableWidgetItem(finding.where)
        where.setToolTip(finding.where)
        confidence = QTableWidgetItem(finding.confidence)
        confidence.setTextAlignment(Qt.AlignmentFlag.AlignCenter)

        index = self._as_findings.index(finding)
        for column, item in enumerate([cell, title, where,
                                       QTableWidgetItem(finding.point),
                                       confidence]):
            item.setData(Qt.ItemDataRole.UserRole + 1, index)
            self.as_table.setItem(row, column, item)
        self.as_table.setSortingEnabled(True)
        self._as_update_count()

    def _as_apply_filter(self):
        findings = list(self._as_findings)
        self.as_table.setRowCount(0)
        for finding in findings:
            self._as_add_row(finding)

    def _as_update_count(self):
        shown, total = self.as_table.rowCount(), len(self._as_findings)
        self.as_count.setText(f"{shown} of {total} shown"
                              if shown != total else f"{total} finding(s)")

    def _as_update_tally(self):
        counts = {}
        for finding in self._as_findings:
            severity = self._as_severity(finding)
            counts[severity] = counts.get(severity, 0) + 1
        parts = [f"<span style='color:{SEV_COLOURS[s]};font-weight:600'>"
                 f"{counts[s]} {s.lower()}</span>"
                 for s in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO")
                 if counts.get(s)]
        self.as_tally.setText(" &nbsp;·&nbsp; ".join(parts))

    def _as_show_detail(self):
        items = self.as_table.selectedItems()
        if not items:
            return
        index = items[0].data(Qt.ItemDataRole.UserRole + 1)
        if index is None or index >= len(self._as_findings):
            return
        finding = self._as_findings[index]
        issue = cb_issues.ISSUES.get(finding.issue, {})
        severity = self._as_severity(finding)
        colour = SEV_COLOURS.get(severity, "#8b9bb4")
        html = [
            f"<h3 style='margin:0 0 4px 0'>"
            f"{_esc(issue.get('title', finding.issue))}</h3>",
            f"<div style='color:{colour};font-weight:600'>{severity}"
            f" &nbsp;·&nbsp; <span style='color:palette(mid);font-weight:400'>"
            f"{_esc(finding.confidence)}"
            + (f" · {issue['cwe']}" if issue.get("cwe") else "")
            + "</span></div>",
            f"<p><b>Where:</b> <code>{_esc(finding.where)}</code><br>"
            f"<b>Parameter:</b> {_esc(finding.point)}</p>",
        ]
        if issue.get("detail"):
            html.append(f"<p>{_esc(issue['detail'])}</p>")
        if finding.detail_extra:
            html.append(f"<p><b>How it was confirmed.</b> "
                        f"{_esc(finding.detail_extra)}</p>")
        if finding.evidence:
            html.append("<p><b>Evidence</b></p><pre style='white-space:pre-wrap'>"
                        f"{_esc(finding.evidence_text())}</pre>")
        if issue.get("remediation"):
            html.append(f"<p><b>Fix:</b> {_esc(issue['remediation'])}</p>")
        self.as_detail.setHtml("".join(html))

    # ── export ───────────────────────────────────────────────────────────
    def _as_export(self):
        from command_bridge.modules.scanner import report as scan_report
        if self._as_result is None:
            self.show_themed_message(
                "Nothing to save", "Run a scan first.",
                QMessageBox.Icon.Information)
            return
        directory = QFileDialog.getExistingDirectory(
            self, "Where should the report go?", str(self.output_dir))
        if not directory:
            return
        host = urllib.parse.urlparse(self._as_result.target).netloc or "scan"
        stem = f"active_scan_{host.replace(':', '_')}"
        try:
            written = scan_report.write_all(self._as_result, directory, stem)
        except Exception as exc:                        # noqa: BLE001
            self.show_themed_message("Could not save", str(exc),
                                     QMessageBox.Icon.Warning)
            return
        self.console.append_ansi(
            "\n[✓] Report written:\n" +
            "".join(f"    {path}\n" for path in written.values()))
        self.show_themed_message(
            "Report saved",
            "HTML, Markdown and JSON written to:\n" + directory)


def _parse_cookies(text):
    jar = {}
    for chunk in (text or "").split(";"):
        if "=" in chunk:
            name, _, value = chunk.partition("=")
            jar[name.strip()] = value.strip()
    return jar


def _parse_headers(text):
    headers = {}
    for chunk in (text or "").split(","):
        if ":" in chunk:
            name, _, value = chunk.partition(":")
            headers[name.strip()] = value.strip()
    return headers


def _esc(text):
    return (str(text).replace("&", "&amp;").replace("<", "&lt;")
            .replace(">", "&gt;"))
