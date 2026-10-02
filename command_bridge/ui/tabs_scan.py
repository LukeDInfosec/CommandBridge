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

from PyQt6 import QtCore, QtGui
from PyQt6.QtCore import Qt, QObject, QThread, QTimer, pyqtSignal
from PyQt6.QtGui import QGuiApplication
from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QGridLayout, QLabel, QPushButton,
    QFrame, QScrollArea, QProgressBar, QTableWidget, QTableWidgetItem,
    QSplitter, QTextEdit, QHeaderView, QAbstractItemView, QComboBox,
    QLineEdit, QCheckBox, QFileDialog, QMessageBox, QSizePolicy, QGroupBox,
)

from command_bridge.modules import cb_evidence, cb_issues
from command_bridge.modules.scanner.engine import PARAMETER_FILENAME
from command_bridge.modules.coffee_break import finding_from_scan

#: Shared with Coffee Break so the two findings screens cannot drift apart.
SEV_COLOURS = cb_evidence.SEV_COLOURS
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
    #: phase, done, total, detail — the detail says which URL, which
    #: parameter and which check, so the tester sees the actual operation
    #: rather than a bare number.
    progress = pyqtSignal(str, int, int, object)
    finding = pyqtSignal(object)
    auth = pyqtSignal(object)
    finished = pyqtSignal(object, str)

    def __init__(self, engine):
        super().__init__()
        self.engine = engine

    def run(self):
        try:
            self.engine.on_log = self.log.emit
            self.engine.on_progress = (
                lambda phase, done, total, detail=None:
                self.progress.emit(phase, done, total, detail))
            self.engine.on_finding = self.finding.emit
            self.engine.on_auth = self.auth.emit
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
        self._as_paused = False
        #: ScanFinding id → the shared CBFinding built from it.
        self._as_shared_cache = {}
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

        # Same control set as Coffee Break, in the same order.
        self.as_pause_btn = QPushButton("Pause")
        self.as_pause_btn.setObjectName("secondaryButton")
        self.as_pause_btn.setMinimumHeight(42)
        self.as_pause_btn.setEnabled(False)
        self.as_pause_btn.setToolTip(
            "Hold every worker at its next request. Nothing further is sent "
            "to the target until you resume, and the scan picks up where it "
            "left off.")
        self.as_pause_btn.clicked.connect(self.pause_active_scan)
        row.addWidget(self.as_pause_btn)

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

        # The authentication indicator sits beside Save report, because the
        # question "was this scan actually logged in?" decides whether the
        # report means anything. It shows the state the SCAN is using, taken
        # from the authenticator's own verdict — not from whether the
        # username box has text in it.
        self.as_auth_light = QLabel("")
        self.as_auth_light.setObjectName("authIndicator")
        self.as_auth_light.setMinimumHeight(42)
        self.as_auth_light.setTextInteractionFlags(
            Qt.TextInteractionFlag.TextSelectableByMouse)
        row.addWidget(self.as_auth_light)
        self._as_set_auth_state(None)
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

        # What is being tested right now: the URL, the parameter and the
        # check. Filled from the engine's live state.
        self.as_detail_line = QLabel("")
        self.as_detail_line.setTextFormat(Qt.TextFormat.RichText)
        self.as_detail_line.setWordWrap(True)
        self.as_detail_line.setStyleSheet(
            "font-size: 11.5px; font-family: ui-monospace, Menlo, Consolas, "
            "monospace;")
        self.as_detail_line.setMinimumHeight(32)
        box.addWidget(self.as_detail_line)

        # Where the discovered-parameter list ended up.
        self.as_param_file = QLabel("")
        self.as_param_file.setTextFormat(Qt.TextFormat.RichText)
        self.as_param_file.setStyleSheet(
            "color: palette(mid); font-size: 11.5px;")
        self.as_param_file.setTextInteractionFlags(
            Qt.TextInteractionFlag.TextBrowserInteraction)
        self.as_param_file.setOpenExternalLinks(False)
        self.as_param_file.linkActivated.connect(self._as_open_param_file)
        box.addWidget(self.as_param_file)

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

        # Which test this is depends entirely on what the second account is,
        # and the scanner cannot work it out: the same observation — account
        # B saw account A's page — is a data leak between peers and a
        # privilege escalation between levels. So it is declared here, and
        # the explanation sits underneath rather than in a tooltip, because
        # getting it wrong mislabels every finding the check produces.
        self.as_second_role = QComboBox()
        for label, value in (
                ("Same level as the first account — tests for IDOR",
                 "same"),
                ("Lower privilege than the first — tests for privilege "
                 "escalation", "lower"),
                ("Higher privilege than the first — tests the first account "
                 "for escalation", "higher")):
            self.as_second_role.addItem(label, value)
        self.as_second_role.currentIndexChanged.connect(self._as_role_help)
        second.addWidget(QLabel("Second account is"), 1, 0)
        second.addWidget(self.as_second_role, 1, 1, 1, 3)

        self._as_second_widgets = [self.as_username2, self.as_password2,
                                   self.as_second_role]
        for widget in self._as_second_widgets:
            widget.setEnabled(False)
        box.addLayout(second)

        self.as_role_help = QLabel("")
        self.as_role_help.setWordWrap(True)
        self.as_role_help.setTextFormat(Qt.TextFormat.RichText)
        self.as_role_help.setStyleSheet(
            "color: palette(mid); padding: 6px 2px 2px 2px;")
        box.addWidget(self.as_role_help)
        self._as_role_help()

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

        self.as_timing_only = QCheckBox(
            "Report time-based-only command injection")
        self.as_timing_only.setToolTip(
            "Off by default. Command injection is proved by running `id`, "
            "`whoami`, `uname -a` and `cat /etc/passwd` and finding the "
            "output in the response — that is always reported and is what "
            "makes a usable screenshot.\n\n"
            "This switch is about the other case: a payload asking the "
            "server to sleep, where the delay scaled but no command output "
            "came back. On an application that is slow, or slow in "
            "proportion to the work a request asks for, that pattern occurs "
            "without any injection, so these are reported as POTENTIAL and "
            "need validating by hand.")
        grid.addWidget(self.as_timing_only, 3, 2, 1, 2)

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

        # Side by side, exactly as Coffee Break lays it out: the list is an
        # index, the evidence gets the height of the card. Stacked, the pane
        # showing the PoC was a few lines tall on a laptop.
        splitter = QSplitter(Qt.Orientation.Horizontal)
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
        # Where, parameter and confidence all appear in the detail pane, so
        # in a narrow left-hand column they cost width and earn nothing.
        for column in (2, 3, 4):
            self.as_table.setColumnHidden(column, True)
        self.as_table.itemSelectionChanged.connect(self._as_show_detail)
        self.as_table.setMinimumHeight(260)
        self.as_table.setMinimumWidth(260)
        splitter.addWidget(self.as_table)

        self.as_detail = QTextEdit()
        self.as_detail.setReadOnly(True)
        self.as_detail.setMinimumHeight(360)
        self.as_detail.setMinimumWidth(320)
        self.as_detail.setPlaceholderText(
            "Select a finding to see the evidence that confirmed it.")

        # The detail pane and its one action, kept together so the button is
        # beside what it copies rather than in a toolbar at the top of the
        # tab where it reads as applying to the whole scan.
        right = QWidget()
        right_box = QVBoxLayout(right)
        right_box.setContentsMargins(0, 0, 0, 0)
        right_box.setSpacing(6)
        right_box.addWidget(self.as_detail)
        self.as_burp_btn = QPushButton("Copy Burp Request")
        self.as_burp_btn.setObjectName("secondaryButton")
        self.as_burp_btn.setToolTip(
            "Copies the complete request — request line, Host, every header "
            "including the session cookies, and the body — as raw HTTP/1.1. "
            "Paste straight into Burp Repeater.")
        self.as_burp_btn.setEnabled(False)
        self.as_burp_btn.clicked.connect(self._as_copy_burp)
        right_box.addWidget(self.as_burp_btn,
                            alignment=Qt.AlignmentFlag.AlignLeft)
        splitter.addWidget(right)
        splitter.setStretchFactor(0, 0)
        splitter.setStretchFactor(1, 1)
        splitter.setSizes([340, 860])
        splitter.setChildrenCollapsible(False)
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
        self._as_role_help()

    #: What each role means, what to put in the boxes, and what the scanner
    #: will do with it. Written out in full because "second account" on its
    #: own leaves the tester guessing which way round to enter the two logins,
    #: and the two orders produce different findings.
    _ROLE_HELP = {
        "same": (
            "<b>Horizontal — Insecure Direct Object Reference (IDOR).</b> "
            "Both accounts are ordinary users of equal standing: two "
            "customers, two staff members on the same team. Put either one "
            "above and the other here.<br><br>"
            "The scanner crawls as the first account, then replays every "
            "request that names a record — <code>?id=</code>, "
            "<code>/invoice/4471</code>, <code>account_id</code> — as the "
            "second. It reports only when the second account gets the same "
            "record <i>and</i> that response still contains something "
            "belonging to the first (their username or email address), so a "
            "dashboard both users are meant to see is not reported."),
        "lower": (
            "<b>Vertical — privilege escalation.</b> The account above is "
            "the privileged one (admin, manager, support); the account here "
            "is the restricted one (standard user, read-only, customer). "
            "<b>Enter the admin above and the low-privileged user here.</b>"
            "<br><br>"
            "The scanner crawls as the privileged account — so it reaches "
            "the administrative pages — then replays each of those requests "
            "as the restricted account. Anything the restricted account gets "
            "back unchanged is a broken access control: authentication is "
            "enforced, authorisation is not. Hits on administrative paths "
            "(<code>/admin</code>, <code>/manage</code>, "
            "<code>/users/…/roles</code>, <code>/billing</code>) are raised "
            "as CRITICAL; the rest as HIGH."),
        "higher": (
            "<b>Vertical — privilege escalation, reversed.</b> Use this when "
            "the account above is "
            "the restricted one and the account here is the admin. The "
            "scanner swaps the direction automatically: the privileged "
            "response is taken from <i>this</i> account and replayed as the "
            "first one.<br><br>"
            "Prefer the option above where you can — the scan crawls as the "
            "first account, so entering the admin first discovers more "
            "privileged endpoints to test. Use this one when the first "
            "account is fixed for another reason."),
    }

    def _as_role_help(self):
        if not self.as_second_user.isChecked():
            self.as_role_help.setText(
                "<i>Tick the box above to test for IDOR and privilege "
                "escalation. These need two logins and cannot be done with "
                "one; they are also where the worst findings usually "
                "are.</i>")
            return
        self.as_role_help.setText(
            self._ROLE_HELP.get(self.as_second_role.currentData(), ""))

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
                role=self.as_second_role.currentData(),
                name=self.as_username2.text().strip() or "second user")

        profile = PROFILES[self.as_profile.currentData()]()
        profile.use_browser = self.as_browser.isChecked()
        profile.browser_crawl = self.as_browser_crawl.isChecked()
        profile.report_timing_only = self.as_timing_only.isChecked()

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
        self._as_worker.auth.connect(self._as_show_auth_outcome)
        self._as_worker.finished.connect(self._as_on_finished)
        self._as_thread.start()

    def stop_active_scan(self):
        if self._as_engine is not None:
            # stop() also releases a pause, so a paused scan can be stopped
            # without being resumed first.
            self._as_engine.stop()
            self._as_paused = False
            self.as_pause_btn.setText("Pause")
            self._as_log("[scan] stopping after the current step…")

    # ── discovered parameters ────────────────────────────────────────────
    def _as_write_parameter_file(self, result):
        """Drop the discovered-parameter list beside the other scan output.

        Written by the engine, which is the only thing that knows what the
        crawl actually reached, so the file cannot contain a URL the scan
        never saw.
        """
        engine = self._as_engine
        if engine is None or result is None:
            return ""
        try:
            path = engine.write_parameter_file(self.output_dir)
        except Exception as exc:                        # noqa: BLE001
            self._as_log(f"[scan] could not write the parameter list: {exc}")
            return ""
        if not path:
            self.as_param_file.setText(
                "<i>No parameterised URLs were discovered.</i>")
            return ""
        count = len(getattr(result, "discovered_parameters", {}) or {})
        self.as_param_file.setText(
            f"Discovered Parameters: "
            f"<a href='open'>{_esc(PARAMETER_FILENAME)}</a> "
            f"— {count} parameterised URL(s)")
        self.as_param_file.setToolTip(path)
        return path

    def _as_open_param_file(self, _link=""):
        """Open the parameter list with whatever the desktop uses for .txt."""
        path = self.as_param_file.toolTip()
        if not path:
            return
        try:
            QtGui.QDesktopServices.openUrl(
                QtCore.QUrl.fromLocalFile(str(path)))
        except Exception:                               # noqa: BLE001
            self.show_themed_message(
                "Discovered parameters",
                f"The list is at:\n\n{path}",
                QMessageBox.Icon.Information)

    # ── authentication indicator ─────────────────────────────────────────
    #: state → (text, background, foreground). One place, so the colours and
    #: the words cannot drift apart.
    _AUTH_STYLES = {
        None:          ("Auth: not configured", "transparent", "#8b9bb4"),
        "none":        ("Unauthenticated scan", "transparent", "#8b9bb4"),
        "checking":    ("Checking authentication…", "#3a2f10", "#f6b73c"),
        "ok":          ("Authentication Successful", "#102a16", "#3fb950"),
        "unverified":  ("Authentication Unverified", "#3a2f10", "#f6b73c"),
        "lost":        ("Session Lost During Scan", "#2e1115", "#ff3b5c"),
        "failed":      ("Authentication Failed", "#2e1115", "#ff3b5c"),
    }

    def _as_set_auth_state(self, state, reason="", method=""):
        """Show the authentication state the scan is actually using.

        ``state`` is one of the keys above, or None before anything has been
        attempted. The reason goes in the tooltip rather than the label, so a
        long explanation cannot push the buttons around.
        """
        text, background, colour = self._AUTH_STYLES.get(
            state, self._AUTH_STYLES[None])
        self.as_auth_light.setText(f"  ●  {text}  ")
        self.as_auth_light.setStyleSheet(
            f"background-color: {background}; color: {colour}; "
            f"border: 1px solid {colour}; border-radius: 8px; "
            f"font-weight: 600; padding: 0 10px;")
        tip = []
        if method:
            tip.append(f"Method: {method}")
        if reason:
            tip.append(reason)
        if state in (None, "none"):
            tip.append("Choose a login method above to scan as a logged-in "
                       "user.")
        self.as_auth_light.setToolTip("\n".join(tip))
        self._as_auth_state = state

    def _as_show_auth_outcome(self, outcome):
        """Reflect an Authenticator's verdict, whatever produced it."""
        if outcome is None:
            return
        self._as_set_auth_state(outcome.state, outcome.reason,
                                getattr(outcome, "method", ""))

    def pause_active_scan(self):
        """Hold the scan where it is, or let it go again.

        Every request the scanner makes passes through the pacer, so this
        holds the whole thread pool — crawl, parameter testing, stored-payload
        sweep and all. Nothing further reaches the target until it is
        resumed, and the scan continues from the same point rather than
        starting the phase again.
        """
        if self._as_engine is None or self._as_thread is None:
            return False
        self._as_paused = self._as_engine.toggle_pause()
        self.as_pause_btn.setText("Resume" if self._as_paused else "Pause")
        if self._as_paused:
            self._as_log("[scan] paused — nothing further will be sent to "
                         "the target until you resume.")
            self.as_progress.setFormat("paused")
            try:
                self.set_status_state("paused")
            except Exception:                           # noqa: BLE001
                pass
        else:
            self._as_log("[scan] resumed.")
            try:
                self.set_status_state("running", tool="Active Scan")
            except Exception:                           # noqa: BLE001
                pass
        return self._as_paused

    def _as_reset(self, target, profile_name):
        self.as_table.setRowCount(0)
        self.as_detail.clear()
        self._as_findings = []
        self._as_shared_cache = {}
        self._as_result = None
        self._as_started = time.time()
        self.as_progress.setValue(0)
        self.as_progress.setFormat("starting…")
        self.as_phase.setText(f"Scanning {target} — {profile_name} profile")
        self.as_tally.setText("")
        self.as_count.setText("")
        self.as_start_btn.setEnabled(False)
        self.as_stop_btn.setEnabled(True)
        self.as_pause_btn.setEnabled(True)
        self.as_pause_btn.setText("Pause")
        self._as_paused = False
        self.as_detail_line.setText("")
        self.as_param_file.setText("")
        mode = self.as_auth_mode.currentData()
        self._as_set_auth_state("none" if mode == "none" else "checking")
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

    def _as_on_progress(self, phase, done, total, detail=None):
        """Show what the scan is doing, from the scan's own state."""
        if total:
            self.as_progress.setValue(int(done / total * 100))
            self.as_progress.setFormat(f"{phase} — {done} of {total}")
        headline = f"{phase} {done} of {total}" if total else phase

        if not detail:
            self.as_phase.setText(headline)
            self.as_detail_line.setText("")
            return
        url = str(detail.get("url", ""))
        # The query string is where the parameter lives, so keep it; trim
        # only when it would push the rest of the line off the card.
        if len(url) > 110:
            url = url[:107] + "…"
        parameter = detail.get("point") or detail.get("parameter") or ""
        check = detail.get("check", "")
        self.as_phase.setText(headline)
        self.as_detail_line.setText(
            f"<span style='color:palette(mid)'>Target:</span> "
            f"<code>{_esc(url)}</code>"
            + (f" &nbsp;<span style='color:palette(mid)'>Parameter:</span> "
               f"<b>{_esc(parameter)}</b>" if parameter else "")
            + (f"<br><span style='color:palette(mid)'>Testing:</span> "
               f"<b>{_esc(check)}</b>" if check else ""))

    def _as_on_finding(self, finding):
        self._as_findings.append(finding)
        self._as_add_row(finding)
        self._as_update_tally()

    def _as_on_finished(self, result, error):
        self._as_timer.stop()
        self.as_start_btn.setEnabled(True)
        self.as_stop_btn.setEnabled(False)
        self.as_pause_btn.setEnabled(False)
        self.as_pause_btn.setText("Pause")
        self._as_paused = False
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

        self.as_detail_line.setText("")
        # The outcome from the run itself, in case the scan finished before
        # the live signal was processed.
        self._as_show_auth_outcome(getattr(result, "auth_outcome", None))
        self._as_write_parameter_file(result)
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

        shared = self._as_shared(finding)
        name = issue.get("title", finding.issue)
        title = QTableWidgetItem(name)
        state = getattr(shared, "state", "")
        title.setToolTip(f"[{state}] {name}" if state else name)
        # Same convention as Coffee Break: anything a human still has to
        # confirm is italic, so it cannot be mistaken at a glance for
        # something the scanner actually reproduced.
        validation = getattr(shared, "validation", None)
        if validation is not None and validation.needs_manual_validation:
            unsettled = QtGui.QFont(title.font())
            unsettled.setItalic(True)
            title.setFont(unsettled)
        where = QTableWidgetItem(finding.where)
        where.setToolTip(finding.where)
        # Severity and confidence are two separate columns and neither is
        # allowed to colour the other (§18). The severity cell's tooltip
        # carries the phrase that spells the relationship out.
        graded = getattr(shared, "confidence", "") or finding.confidence
        cell.setToolTip(
            f"{cb_evidence.severity_label(severity, graded)} — "
            f"{severity} impact if real, evidence graded {graded}.")
        confidence = QTableWidgetItem(graded)
        confidence.setForeground(QtGui.QColor(
            cb_evidence.CONFIDENCE_COLOURS.get(graded, "#8b9bb4")))
        verdict = getattr(shared, "verdict", None)
        confidence.setToolTip(
            (f"Detected by {verdict.detection_method}.\n"
             if getattr(verdict, "detection_method", "") else "")
            + (getattr(verdict, "rationale", "") or "")
            + (f"\n\nTo confirm: {verdict.verification}"
               if getattr(verdict, "verification", "")
               and graded != "confirmed" else ""))
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
        # Rendered by the same function Coffee Break uses, from the same
        # evidence objects, so a finding reads identically whichever tool
        # produced it — state, rationale, observed evidence, PoC, Burp
        # request, false-positive indicators, raw detection and all.
        shared = self._as_shared(finding)
        self.as_detail.setHtml(cb_evidence.detail_html(shared))
        self._as_burp = cb_evidence.burp_request_for(shared)
        self.as_burp_btn.setEnabled(bool(self._as_burp))
        self.as_burp_btn.setText(
            "Copy Burp Request" if self._as_burp
            else "No request captured for this finding")

    def _as_copy_burp(self):
        if not getattr(self, "_as_burp", ""):
            return
        QGuiApplication.clipboard().setText(self._as_burp)
        # Confirm in the button itself rather than a dialog: a dialog here
        # costs a click on something the tester is about to do thirty times.
        self.as_burp_btn.setText("Copied — paste into Repeater")
        QTimer.singleShot(
            2000, lambda: self.as_burp_btn.setText("Copy Burp Request"))

    def _as_shared(self, finding):
        """The shared finding object for one of the scanner's results.

        Built once and cached: the conversion carries the parameter, the
        payload, the request, the response and the oracle's own note into an
        evidence chain, and re-running the validator on every selection would
        be wasted work.
        """
        cached = self._as_shared_cache.get(id(finding))
        if cached is None:
            cached = finding_from_scan(finding)
            self._as_shared_cache[id(finding)] = cached
        return cached

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
