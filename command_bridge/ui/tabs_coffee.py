"""
Coffee Break tab — the screen you come back to.

Three regions, top to bottom:

  * the run header — target, elapsed, overall progress, and the transport
    buttons, so you can tell at a glance whether it is still working;
  * the stage list — every step with its state and what it produced, because
    "no findings" means something quite different when a step was skipped for
    want of a tool;
  * the findings, as a sortable table with a detail pane underneath. Clicking a
    row shows what it means, where it was, the evidence, and the fix, which is
    the order somebody writing it up needs them in.

The table is deliberately not the console. Console output scrolls away; a
finding has to still be there an hour later, sorted by how much it matters.
"""

from PyQt6 import QtCore, QtGui, QtWidgets
from PyQt6.QtCore import Qt, QTimer
from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QPushButton, QFrame,
    QScrollArea, QProgressBar, QTableWidget, QTableWidgetItem, QSplitter,
    QTextEdit, QHeaderView, QAbstractItemView, QComboBox, QFileDialog,
    QMessageBox, QSizePolicy, QMenu, QApplication, QCheckBox, QGridLayout,
)

from command_bridge.modules import cb_evidence
from command_bridge.modules.coffee_break import SEVERITIES, SEV_ORDER

#: One colour per severity, picked to read on every theme in the app rather
#: than to match any single one.
SEV_COLOURS = {
    "CRITICAL": "#ff3b5c",
    "HIGH": "#ff6b4a",
    "MEDIUM": "#f6b73c",
    "LOW": "#4f8cff",
    "INFO": "#8b9bb4",
}

#: The checklist marks. A tick for done, an arrow for the one in flight, an
#: empty circle for what is still to come — the point of the list is that you
#: can tell those three apart from across the room.
STAGE_MARK = {
    "pending": ("○", "#6b7688"),
    "running": ("▶", "#4f8cff"),
    "done": ("✓", "#2dd4a7"),
    "skipped": ("⊘", "#8b9bb4"),
    "failed": ("✕", "#ff5f6d"),
}
FINISHED = ("done", "skipped", "failed")


class _SeverityItem(QTableWidgetItem):
    """A cell that sorts by severity rather than alphabetically.

    Qt sorts on the display string unless the item says otherwise, which put
    MEDIUM above CRITICAL — precisely upside down for a table whose whole job
    is to show you the worst thing first.
    """

    def __lt__(self, other):
        mine = self.data(Qt.ItemDataRole.UserRole)
        theirs = other.data(Qt.ItemDataRole.UserRole)
        if mine is None or theirs is None:
            return super().__lt__(other)
        return mine < theirs


class CoffeeBreakTabMixin:
    """Builds the tab and owns every widget the engine reports into."""

    def create_coffee_break_tab(self):
        widget = QWidget()
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QFrame.Shape.NoFrame)
        scroll.setWidget(widget)

        layout = QVBoxLayout(widget)
        layout.setContentsMargins(25, 25, 25, 25)
        layout.setSpacing(18)

        layout.addWidget(self._cb_build_header())
        layout.addWidget(self._cb_build_options())
        layout.addWidget(self._cb_build_stages())
        layout.addWidget(self._cb_build_findings(), 1)

        self._cb_elapsed_timer = QTimer(self)
        self._cb_elapsed_timer.setInterval(1000)
        self._cb_elapsed_timer.timeout.connect(self._cb_tick)

        self._cb_rows = []
        self._cb_stage_rows = {}
        self._cb_stage_status = {}
        self._cb_ui_finding_list = []
        return scroll

    # ── header ───────────────────────────────────────────────────────────
    def _cb_build_header(self):
        card = self.create_card("☕ Coffee Break")
        box = QVBoxLayout()
        box.setSpacing(10)

        self.cb_subtitle = QLabel(
            "Every active check in the application, in an order where each step "
            "teaches the next one something. Press it, walk away.")
        self.cb_subtitle.setWordWrap(True)
        self.cb_subtitle.setStyleSheet("color: palette(mid); font-size: 12px;")
        box.addWidget(self.cb_subtitle)

        row = QHBoxLayout()
        row.setSpacing(10)
        self.cb_start_btn = QPushButton("Start Coffee Break")
        self.cb_start_btn.setObjectName("primaryButton")
        self.cb_start_btn.setMinimumHeight(42)
        self.cb_start_btn.setCursor(
            QtGui.QCursor(Qt.CursorShape.PointingHandCursor))
        self.cb_start_btn.clicked.connect(self.start_coffee_break)
        row.addWidget(self.cb_start_btn)

        self.cb_pause_btn = QPushButton("Pause")
        self.cb_pause_btn.setObjectName("secondaryButton")
        self.cb_pause_btn.setMinimumHeight(42)
        self.cb_pause_btn.setEnabled(False)
        self.cb_pause_btn.setToolTip(
            "Suspends the step that is running and holds the chain. The "
            "running tool is stopped rather than killed, so a long scan is "
            "not thrown away — leave the house, come back, press Resume.")
        self.cb_pause_btn.clicked.connect(self._cb_toggle_pause)
        row.addWidget(self.cb_pause_btn)

        self.cb_skip_btn = QPushButton("Skip this step")
        self.cb_skip_btn.setObjectName("secondaryButton")
        self.cb_skip_btn.setMinimumHeight(42)
        self.cb_skip_btn.clicked.connect(self.skip_coffee_break_stage)
        self.cb_skip_btn.setEnabled(False)
        row.addWidget(self.cb_skip_btn)

        self.cb_stop_btn = QPushButton("Stop")
        self.cb_stop_btn.setObjectName("secondaryButton")
        self.cb_stop_btn.setMinimumHeight(42)
        self.cb_stop_btn.clicked.connect(self.stop_coffee_break)
        self.cb_stop_btn.setEnabled(False)
        row.addWidget(self.cb_stop_btn)

        row.addStretch()

        self.cb_export_btn = QPushButton("Export findings")
        self.cb_export_btn.setObjectName("secondaryButton")
        self.cb_export_btn.setMinimumHeight(42)
        self.cb_export_btn.clicked.connect(self._cb_export)
        row.addWidget(self.cb_export_btn)
        box.addLayout(row)

        status = QHBoxLayout()
        self.cb_target_label = QLabel("No target set")
        self.cb_target_label.setStyleSheet("font-weight: 600;")
        status.addWidget(self.cb_target_label)
        status.addStretch()
        self.cb_elapsed_label = QLabel("")
        self.cb_elapsed_label.setStyleSheet("color: palette(mid);")
        status.addWidget(self.cb_elapsed_label)
        box.addLayout(status)

        self.cb_progress = QProgressBar()
        self.cb_progress.setRange(0, 100)
        self.cb_progress.setValue(0)
        self.cb_progress.setTextVisible(True)
        self.cb_progress.setFormat("idle")
        self.cb_progress.setMinimumHeight(22)
        box.addWidget(self.cb_progress)

        # What is actually running. A progress bar that says "4 of 14" does
        # not tell you whether it is the nmap that takes forty minutes or the
        # header check that takes two seconds.
        self.cb_command = QLabel("")
        self.cb_command.setWordWrap(False)
        self.cb_command.setTextInteractionFlags(
            Qt.TextInteractionFlag.TextSelectableByMouse)
        self.cb_command.setStyleSheet(
            "color: palette(mid); font-size: 11px; "
            "font-family: ui-monospace, Menlo, Consolas, monospace;")
        self.cb_command.setMinimumHeight(16)
        box.addWidget(self.cb_command)

        self.cb_tally = QLabel("")
        self.cb_tally.setStyleSheet("font-size: 12px;")
        box.addWidget(self.cb_tally)

        card.layout().addLayout(box)
        return card

    # ── options ──────────────────────────────────────────────────────────
    def _cb_build_options(self):
        """Everything you might want to change, folded away until you do.

        Collapsed by default: on most runs you press the button and walk off,
        and a screen that opens with fourteen checkboxes in your face buries
        the thing you actually came to look at.
        """
        from command_bridge.modules.coffee_break import CB_STAGE_CATALOGUE

        card = self.create_card("Scan options")
        self._init_collapsible_groupbox(card, "cb_options_card")
        box = QVBoxLayout()
        box.setSpacing(10)

        hint = QLabel(
            "Which steps run, and what gets reported. Turning a step off "
            "removes it from the checklist below rather than skipping it "
            "silently.")
        hint.setWordWrap(True)
        hint.setStyleSheet("color: palette(mid); font-size: 11.5px;")
        box.addWidget(hint)

        grid = QGridLayout()
        grid.setHorizontalSpacing(18)
        grid.setVerticalSpacing(4)
        self.cb_stage_toggles = {}
        for position, (key, name, note) in enumerate(CB_STAGE_CATALOGUE):
            toggle = QCheckBox(name)
            toggle.setChecked(True)
            toggle.setToolTip(note)
            toggle.stateChanged.connect(self._cb_stages_chosen)
            self.cb_stage_toggles[key] = toggle
            grid.addWidget(toggle, position % 7, position // 7)
        box.addLayout(grid)

        row = QHBoxLayout()
        row.setSpacing(8)
        for label, keys in (
                ("All", [k for k, _n, _h in CB_STAGE_CATALOGUE]),
                ("None", []),
                ("Quick (skip the slow scans)",
                 [k for k, _n, _h in CB_STAGE_CATALOGUE
                  if k not in ("nmap_full", "nmap_udp", "smartfuzz")])):
            button = QPushButton(label)
            button.setObjectName("secondaryButton")
            button.setMinimumHeight(30)
            button.clicked.connect(
                lambda _checked=False, chosen=keys: self._cb_choose(chosen))
            row.addWidget(button)
        row.addStretch()
        box.addLayout(row)

        self.cb_muted_label = QLabel("")
        self.cb_muted_label.setWordWrap(True)
        self.cb_muted_label.setStyleSheet(
            "color: palette(mid); font-size: 11.5px;")
        box.addWidget(self.cb_muted_label)

        self.cb_unmute_btn = QPushButton("Report muted issue types again")
        self.cb_unmute_btn.setObjectName("secondaryButton")
        self.cb_unmute_btn.setMinimumHeight(30)
        self.cb_unmute_btn.clicked.connect(self._cb_unmute_all)
        box.addWidget(self.cb_unmute_btn)

        card.layout().addLayout(box)
        self._cb_refresh_muted()
        return card

    def _cb_choose(self, keys):
        wanted = set(keys)
        for key, toggle in self.cb_stage_toggles.items():
            toggle.blockSignals(True)
            toggle.setChecked(key in wanted)
            toggle.blockSignals(False)
        self._cb_stages_chosen()

    def _cb_stages_chosen(self):
        self._cb_enabled_stages = {
            key for key, toggle in self.cb_stage_toggles.items()
            if toggle.isChecked()}

    def _cb_refresh_muted(self):
        muted = sorted(getattr(self, "_cb_muted", None) or
                       self._cb_load_muted())
        from command_bridge.modules.cb_issues import ISSUES
        if not muted:
            self.cb_muted_label.setText(
                "No issue types are muted. Right-click a finding to stop "
                "reporting its type.")
            self.cb_unmute_btn.setVisible(False)
            return
        names = [ISSUES.get(key, {}).get("title", key) for key in muted]
        self.cb_muted_label.setText(
            "Not reported: " + " · ".join(names))
        self.cb_unmute_btn.setVisible(True)

    def _cb_unmute_all(self):
        for key in list(getattr(self, "_cb_muted", None) or
                        self._cb_load_muted()):
            self.mute_issue_type(key, False)
        self._cb_refresh_muted()
        self.console.append_ansi("\n[i] every muted issue type will be "
                                 "reported again.\n")

    # ── stage list ───────────────────────────────────────────────────────
    def _cb_build_stages(self):
        card = self.create_card("Checklist")
        self._cb_stages_card = card
        self._init_collapsible_groupbox(card, "cb_stages_card")
        outer = QVBoxLayout()
        outer.setSpacing(6)

        self.cb_stage_summary = QLabel("Not started.")
        self.cb_stage_summary.setStyleSheet(
            "color: palette(mid); font-size: 11.5px;")
        outer.addWidget(self.cb_stage_summary)

        self.cb_stage_box = QVBoxLayout()
        self.cb_stage_box.setSpacing(4)
        placeholder = QLabel("The chain has not been run yet.")
        placeholder.setStyleSheet("color: palette(mid); font-size: 12px;")
        self.cb_stage_box.addWidget(placeholder)
        outer.addLayout(self.cb_stage_box)
        card.layout().addLayout(outer)
        return card

    def _cb_clear_stage_box(self):
        while self.cb_stage_box.count():
            item = self.cb_stage_box.takeAt(0)
            child = item.widget()
            if child:
                child.deleteLater()

    # ── findings ─────────────────────────────────────────────────────────
    def _cb_build_findings(self):
        card = self.create_card("Findings")
        box = QVBoxLayout()
        box.setSpacing(8)

        controls = QHBoxLayout()
        controls.setSpacing(8)
        controls.addWidget(QLabel("Show"))
        self.cb_filter = QComboBox()
        self.cb_filter.addItem("Everything", "")
        for severity in SEVERITIES:
            # "Critical and above" is nonsense when Critical is the top of
            # the scale. "Critical+" reads as a floor, which is what it is.
            self.cb_filter.addItem(severity.title() + "+", severity)
        # Start at Low+ rather than Everything. Every scanner in the chain
        # emits informational material — what the stack is, which headers were
        # seen — and showing it by default buries the four findings that
        # actually need acting on. It is one click away, and the count on the
        # right says how much is being held back.
        self.cb_filter.setCurrentIndex(self.cb_filter.findData("LOW"))
        self.cb_filter.currentIndexChanged.connect(self._cb_apply_filter)
        controls.addWidget(self.cb_filter)
        controls.addStretch()
        self.cb_count_label = QLabel("")
        self.cb_count_label.setStyleSheet("color: palette(mid); font-size: 12px;")
        controls.addWidget(self.cb_count_label)
        box.addLayout(controls)

        # Side by side, not stacked. Stacked, the detail pane got whatever
        # vertical room the table left it — which on a laptop was a few lines,
        # and meant dragging the divider up for every single finding. Beside
        # it, the list stays a list and the detail gets the height of the
        # whole card.
        splitter = QSplitter(Qt.Orientation.Horizontal)

        self.cb_table = QTableWidget(0, 5)
        self.cb_table.setHorizontalHeaderLabels(
            ["Severity", "Finding", "Where", "Stage", "Confidence"])
        self.cb_table.verticalHeader().setVisible(False)
        self.cb_table.setSelectionBehavior(
            QAbstractItemView.SelectionBehavior.SelectRows)
        self.cb_table.setSelectionMode(
            QAbstractItemView.SelectionMode.SingleSelection)
        self.cb_table.setEditTriggers(
            QAbstractItemView.EditTrigger.NoEditTriggers)
        # Alternating row colours come from the palette, and on several of
        # the darker themes the alternate row washed the text out until it
        # could not be read. Severity already gives the eye a column to
        # track down; the stripes were costing legibility for nothing.
        self.cb_table.setAlternatingRowColors(False)
        self.cb_table.setSortingEnabled(True)
        self.cb_table.sortByColumn(0, Qt.SortOrder.DescendingOrder)
        header = self.cb_table.horizontalHeader()
        # A fixed, generous severity column. Sized to contents it hugged the
        # word so tightly that the text sat against the cell border; given room
        # and centred, the column reads as a column.
        header.setSectionResizeMode(0, QHeaderView.ResizeMode.Fixed)
        self.cb_table.setColumnWidth(0, 108)
        header.setSectionResizeMode(1, QHeaderView.ResizeMode.Stretch)
        header.setSectionResizeMode(2, QHeaderView.ResizeMode.Stretch)
        header.setSectionResizeMode(3, QHeaderView.ResizeMode.ResizeToContents)
        header.setSectionResizeMode(4, QHeaderView.ResizeMode.Fixed)
        self.cb_table.setColumnWidth(4, 104)
        # In a narrow left-hand column there is room for the severity and the
        # name, and that is all a list needs to be scanned down. Where, stage
        # and confidence are still populated — filtering, sorting and the
        # delete menu all read them — but they are shown in the detail pane
        # on the right rather than squeezed into a column two words wide.
        for column in (2, 3, 4):
            self.cb_table.setColumnHidden(column, True)
        self.cb_table.itemSelectionChanged.connect(self._cb_show_detail)
        self.cb_table.setContextMenuPolicy(
            Qt.ContextMenuPolicy.CustomContextMenu)
        self.cb_table.customContextMenuRequested.connect(self._cb_menu)
        # Delete does the same as the menu's first item. A context menu that
        # does not open leaves you with nothing; a key always works.
        remove = QtGui.QShortcut(QtGui.QKeySequence.StandardKey.Delete,
                                 self.cb_table)
        remove.setContext(Qt.ShortcutContext.WidgetShortcut)
        remove.activated.connect(self._cb_delete_selected)
        self.cb_table.setToolTip(
            "Right-click a finding to delete it, delete every finding of its "
            "type, or never report that type again. Delete removes the "
            "selected one.")
        self.cb_table.setMinimumHeight(300)
        self.cb_table.setMinimumWidth(260)
        splitter.addWidget(self.cb_table)

        self.cb_detail = QTextEdit()
        self.cb_detail.setReadOnly(True)
        # Tall enough that a finding's evidence, PoC and fix are readable
        # without touching the divider — which is the whole reason the panes
        # sit side by side.
        self.cb_detail.setMinimumHeight(360)
        self.cb_detail.setMinimumWidth(320)
        self.cb_detail.setPlaceholderText(
            "Select a finding to see what it means, the evidence, and the fix.")

        right = QWidget()
        right_box = QVBoxLayout(right)
        right_box.setContentsMargins(0, 0, 0, 0)
        right_box.setSpacing(6)
        right_box.addWidget(self.cb_detail)
        self.cb_burp_btn = QPushButton("Copy Burp Request")
        self.cb_burp_btn.setObjectName("secondaryButton")
        self.cb_burp_btn.setToolTip(
            "Copies the complete request as raw HTTP/1.1 — request line, "
            "Host, every header including session cookies, and the body. "
            "Paste straight into Burp Repeater.")
        self.cb_burp_btn.setEnabled(False)
        self.cb_burp_btn.clicked.connect(self._cb_copy_burp)
        right_box.addWidget(self.cb_burp_btn,
                            alignment=Qt.AlignmentFlag.AlignLeft)
        splitter.addWidget(right)
        # The list is a fixed-ish index; the evidence takes the rest.
        splitter.setStretchFactor(0, 0)
        splitter.setStretchFactor(1, 1)
        splitter.setSizes([340, 860])
        splitter.setChildrenCollapsible(False)

        box.addWidget(splitter)
        card.layout().addLayout(box)
        card.setSizePolicy(QSizePolicy.Policy.Expanding,
                           QSizePolicy.Policy.Expanding)
        return card

    # ── the engine calls these ───────────────────────────────────────────
    def _cb_ui_reset(self, stages, target):
        self.cb_target_label.setText(f"Target: {target}")
        self.cb_progress.setValue(0)
        self.cb_progress.setFormat("starting…")
        self.cb_tally.setText("")
        self.cb_count_label.setText("")
        self.cb_table.setRowCount(0)
        self.cb_detail.clear()
        self._cb_rows = []
        self._cb_ui_finding_list = []

        self._cb_clear_stage_box()
        self._cb_stage_rows = {}
        self._cb_stage_status = {}
        # A checklist you cannot see is not a checklist. However the card was
        # left last time, a run opens it.
        try:
            self._cb_stages_card.setChecked(True)
        except Exception:                               # noqa: BLE001
            pass
        for stage in stages:
            row = QWidget()
            line = QHBoxLayout(row)
            line.setContentsMargins(0, 2, 0, 2)
            line.setSpacing(10)
            mark = QLabel(STAGE_MARK["pending"][0])
            mark.setFixedWidth(16)
            mark.setStyleSheet(f"color: {STAGE_MARK['pending'][1]};")
            name = QLabel(stage["name"])
            note = QLabel("")
            note.setStyleSheet("color: palette(mid); font-size: 11.5px;")
            line.addWidget(mark)
            line.addWidget(name)
            line.addStretch()
            line.addWidget(note)
            self.cb_stage_box.addWidget(row)
            self._cb_stage_rows[stage["key"]] = (mark, name, note)
            self._cb_stage_status[stage["key"]] = "pending"

        total = len(stages)
        self.cb_stage_summary.setText(
            f"0 done · {total} to go" if total else "Nothing to run.")

        self.cb_start_btn.setEnabled(False)
        self.cb_skip_btn.setEnabled(True)
        self.cb_stop_btn.setEnabled(True)
        self.cb_pause_btn.setEnabled(True)
        self.cb_pause_btn.setText("Pause")
        self.cb_command.setText("")
        self._cb_elapsed_timer.start()

    def _cb_ui_stage(self, key, status, note):
        self._cb_stage_status[key] = status
        widgets = getattr(self, "_cb_stage_rows", {}).get(key)
        if widgets:
            mark, name, note_label = widgets
            glyph, colour = STAGE_MARK.get(status, STAGE_MARK["pending"])
            mark.setText(glyph)
            mark.setStyleSheet(f"color: {colour};")
            # Done steps are struck through and dimmed, the running one is
            # bold, and everything still to come is left plain. You should be
            # able to see where the scan has got to without reading a word.
            if status == "done":
                name.setStyleSheet("text-decoration: line-through; "
                                   "color: palette(mid);")
            elif status == "skipped":
                name.setStyleSheet("text-decoration: line-through; "
                                   "color: palette(mid); font-style: italic;")
            elif status == "failed":
                name.setStyleSheet(f"color: {STAGE_MARK['failed'][1]};")
            elif status == "running":
                name.setStyleSheet(
                    f"font-weight: 700; color: {STAGE_MARK['running'][1]};")
            else:
                name.setStyleSheet("")
            note_label.setText(note or "")

        total = max(1, len(getattr(self, "_cb_stages", [])) or 1)
        counts = {state: 0 for state in
                  ("pending", "running", "done", "skipped", "failed")}
        for state in self._cb_stage_status.values():
            counts[state] = counts.get(state, 0) + 1
        finished = sum(counts[state] for state in FINISHED)

        self.cb_progress.setValue(int(finished / total * 100))
        parts = [f"{counts['done']} done"]
        if counts["skipped"]:
            parts.append(f"{counts['skipped']} skipped")
        if counts["failed"]:
            parts.append(f"{counts['failed']} failed")
        outstanding = total - finished
        parts.append(f"{outstanding} to go" if outstanding else "all finished")
        self.cb_stage_summary.setText(" · ".join(parts))

        if status == "running":
            label = self._cb_stage_rows.get(key)
            self.cb_progress.setFormat(
                f"{finished + 1} of {total} — "
                f"{label[1].text() if label else key}")

    def _cb_ui_command(self, command):
        """Show the command the current stage is running."""
        text = " ".join(str(command or "").split())
        self.cb_command.setToolTip(text)
        if len(text) > 200:
            text = text[:197] + "…"
        self.cb_command.setText(text)

    def _cb_ui_paused(self, paused):
        self.cb_pause_btn.setText("Resume" if paused else "Pause")
        if paused:
            self.cb_progress.setFormat("paused")
            self.cb_elapsed_label.setText("paused")

    def _cb_toggle_pause(self):
        self.pause_coffee_break()

    def _cb_ui_finding(self, finding):
        self._cb_ui_finding_list.append(finding)
        self._cb_add_row(finding)
        self._cb_update_tally()

    def _cb_ui_finished(self, how):
        self._cb_elapsed_timer.stop()
        self.cb_start_btn.setEnabled(True)
        self.cb_skip_btn.setEnabled(False)
        self.cb_stop_btn.setEnabled(False)
        self.cb_pause_btn.setEnabled(False)
        self.cb_pause_btn.setText("Pause")
        self.cb_command.setText("")
        if how == "completed":
            self.cb_progress.setValue(100)
            self.cb_progress.setFormat("finished")
        else:
            self.cb_progress.setFormat("stopped")

    # ── table plumbing ───────────────────────────────────────────────────
    def _cb_add_row(self, finding):
        wanted = self.cb_filter.currentData()
        if wanted and SEV_ORDER.get(finding.severity, 0) < SEV_ORDER.get(wanted, 0):
            self._cb_rows.append((None, finding))
            self._cb_update_count()
            return

        self.cb_table.setSortingEnabled(False)
        row = self.cb_table.rowCount()
        self.cb_table.insertRow(row)

        severity = _SeverityItem(finding.severity)
        # Sort by how much it matters, not alphabetically: CRITICAL before LOW.
        severity.setData(Qt.ItemDataRole.UserRole,
                         SEV_ORDER.get(finding.severity, 0))
        severity.setForeground(QtGui.QColor(
            SEV_COLOURS.get(finding.severity, "#8b9bb4")))
        font = severity.font()
        font.setBold(True)
        severity.setFont(font)
        severity.setTextAlignment(Qt.AlignmentFlag.AlignCenter)

        title = QTableWidgetItem(finding.title)
        # The column can be narrower than the title on a small window, so the
        # full text is always one hover away.
        state = getattr(finding, "state", "")
        title.setToolTip(f"[{state}] {finding.title}" if state
                         else finding.title)
        # A CRITICAL nobody has validated must not look, at a glance down the
        # list, like one that has been. Italics carry that without a column
        # and without depending on a colour that some theme will wash out.
        validation = getattr(finding, "validation", None)
        if validation is not None and validation.needs_manual_validation:
            unsettled = QtGui.QFont(title.font())
            unsettled.setItalic(True)
            title.setFont(unsettled)
        where = QTableWidgetItem(_where_text(finding))
        where.setToolTip("\n".join(finding.locations()[:40]))
        confidence = QTableWidgetItem(finding.confidence)
        confidence.setTextAlignment(Qt.AlignmentFlag.AlignCenter)

        cells = [severity, title, where,
                 QTableWidgetItem(finding.stage), confidence]
        for column, item in enumerate(cells):
            item.setData(Qt.ItemDataRole.UserRole + 1, len(self._cb_rows))
            self.cb_table.setItem(row, column, item)
        self.cb_table.setSortingEnabled(True)
        self._cb_rows.append((row, finding))
        self._cb_update_count()

    def _cb_ui_refresh(self, finding):
        """Another instance of a finding already on the table."""
        index = next((i for i, f in enumerate(self._cb_ui_finding_list)
                      if f is finding), None)
        if index is None:
            return
        for row in range(self.cb_table.rowCount()):
            item = self.cb_table.item(row, 0)
            if item is None:
                continue
            if item.data(Qt.ItemDataRole.UserRole + 1) != index:
                continue
            cell = self.cb_table.item(row, 2)
            if cell is not None:
                cell.setText(_where_text(finding))
                cell.setToolTip("\n".join(finding.locations()[:40]))
            break
        self._cb_show_detail()

    def _cb_apply_filter(self):
        findings = list(self._cb_ui_finding_list)
        self.cb_table.setRowCount(0)
        self._cb_rows = []
        for finding in findings:
            self._cb_add_row(finding)
        self._cb_update_count()

    def _cb_update_count(self):
        shown = self.cb_table.rowCount()
        total = len(self._cb_ui_finding_list)
        instances = sum(getattr(f, "count", 1)
                        for f in self._cb_ui_finding_list)
        extra = ""
        if instances > total:
            extra = f" · {instances} location(s)"
        if shown != total:
            self.cb_count_label.setText(
                f"{shown} of {total} shown — {total - shown} hidden by the "
                f"filter{extra}")
        else:
            self.cb_count_label.setText(f"{total} finding(s){extra}")

    def _cb_update_tally(self):
        counts = {}
        for finding in self._cb_ui_finding_list:
            counts[finding.severity] = counts.get(finding.severity, 0) + 1
        parts = []
        for severity in SEVERITIES:
            if counts.get(severity):
                parts.append(
                    f"<span style='color:{SEV_COLOURS[severity]};"
                    f"font-weight:600'>{counts[severity]} {severity.lower()}</span>")
        self.cb_tally.setText(" &nbsp;·&nbsp; ".join(parts))

    def _cb_show_detail(self):
        items = self.cb_table.selectedItems()
        if not items:
            return
        index = items[0].data(Qt.ItemDataRole.UserRole + 1)
        finding = None
        for stored_index, (row, candidate) in enumerate(self._cb_rows):
            if stored_index == index:
                finding = candidate
                break
        if finding is None:
            return
        # The Active Scan tab renders its findings with this same
        # function. Two screens, one description of what a finding is.
        self.cb_detail.setHtml(cb_evidence.detail_html(finding))
        self._cb_burp = cb_evidence.burp_request_for(finding)
        self.cb_burp_btn.setEnabled(bool(self._cb_burp))
        self.cb_burp_btn.setText(
            "Copy Burp Request" if self._cb_burp
            else "No request captured for this finding")

    def _cb_copy_burp(self):
        if not getattr(self, "_cb_burp", ""):
            return
        QApplication.clipboard().setText(self._cb_burp)
        self.cb_burp_btn.setText("Copied — paste into Repeater")
        QTimer.singleShot(
            2000, lambda: self.cb_burp_btn.setText("Copy Burp Request"))

    # ── right-click ──────────────────────────────────────────────────────
    def _cb_finding_at(self, row):
        item = self.cb_table.item(row, 0)
        if item is None:
            return None
        index = item.data(Qt.ItemDataRole.UserRole + 1)
        findings = getattr(self, "_cb_ui_finding_list", [])
        if index is None or index >= len(findings):
            return None
        return findings[index]

    def _cb_row_at(self, position):
        """Which row was right-clicked.

        customContextMenuRequested hands back a position in the widget's own
        coordinates, while rowAt() expects the viewport's — and the two differ
        by the height of the horizontal header. That is about 25 pixels, which
        was enough to return the wrong row near the top of the table and -1 on
        the first row, so the menu never appeared at all. Map it properly,
        then fall back to whatever is selected.
        """
        table = self.cb_table
        for candidate in (table.viewport().mapFrom(table, position), position):
            index = table.indexAt(candidate)
            if index.isValid():
                return index.row()
        return table.currentRow()

    def _cb_menu(self, position):
        """Delete a finding, delete its whole type, or mute it for good.

        Every team has issues it does not report — the one that prompted this
        was BREACH. Deleting the row covers this scan; muting the type covers
        every scan after it, which is the difference between a fix and a
        chore you repeat.
        """
        row = self._cb_row_at(position)
        finding = self._cb_finding_at(row)
        if finding is None:
            return
        # Right-clicking a row selects it, so the detail pane below matches
        # what the menu is about to act on.
        if row != self.cb_table.currentRow():
            self.cb_table.selectRow(row)

        menu = QMenu(self)
        title = finding.title
        key = getattr(finding, "key", "") or ""

        delete_one = menu.addAction("Delete this finding")
        delete_kind = menu.addAction(
            f"Delete every finding of this type "
            f"({self._cb_count_of(finding)})")
        menu.addSeparator()
        mute = menu.addAction("Never report this issue type again")
        mute.setEnabled(bool(key))
        mute.setToolTip(
            "Removes it from this scan and stops it being reported in future "
            "ones. Stored in ~/.config/CommandBridge/muted_issues.json."
            if key else "This finding has no issue type to mute.")
        menu.addSeparator()
        copy_one = menu.addAction("Copy this finding")
        copy_all = menu.addAction("Copy every finding as Markdown")

        chosen = menu.exec(self.cb_table.mapToGlobal(position))
        if chosen is None:
            return

        if chosen is delete_one:
            self._cb_drop([finding])
        elif chosen is delete_kind:
            self._cb_drop(self._cb_same_type(finding))
        elif chosen is mute:
            self.mute_issue_type(key, True)
            dropped = self._cb_drop(self._cb_same_type(finding))
            self.console.append_ansi(
                f"\n[i] '{title}' muted — {dropped} finding(s) removed, and "
                f"it will not be reported in future scans. Undo by editing "
                f"~/.config/CommandBridge/muted_issues.json.\n")
        elif chosen is copy_one:
            QApplication.clipboard().setText(self._cb_as_text(finding))
            self.flash_status("finding copied")
        elif chosen is copy_all:
            QApplication.clipboard().setText(self.coffee_break_report())
            self.flash_status("report copied")

    def _cb_delete_selected(self):
        finding = self._cb_finding_at(self.cb_table.currentRow())
        if finding is not None:
            self._cb_drop([finding])

    def _cb_same_type(self, finding):
        key = getattr(finding, "key", "") or ""
        return [f for f in self._cb_ui_finding_list
                if (key and getattr(f, "key", "") == key)
                or (not key and f.title == finding.title)]

    def _cb_count_of(self, finding):
        return len(self._cb_same_type(finding))

    def _cb_drop(self, findings):
        """Remove findings from the screen and from the exported report."""
        doomed = {id(f) for f in findings}
        self._cb_ui_finding_list = [f for f in self._cb_ui_finding_list
                                    if id(f) not in doomed]
        engine_list = getattr(self, "_cb_findings", None)
        if isinstance(engine_list, list):
            self._cb_findings = [f for f in engine_list if id(f) not in doomed]
        self._cb_apply_filter()
        self._cb_update_tally()
        self.cb_detail.clear()
        return len(doomed)

    @staticmethod
    def _cb_as_text(finding):
        parts = [f"## [{getattr(finding, 'state', 'DETECTED')}] "
                 f"[{finding.severity}] {finding.title}",
                 f"Where: {finding.where}"]
        for extra in (getattr(finding, "instances", []) or [])[:20]:
            parts.append(f"  also: {extra}")
        sources = getattr(finding, "sources", []) or [finding.stage]
        parts.append(f"Detected by: {', '.join(s for s in sources if s)}")
        parts.append(f"Confidence: {finding.confidence}")
        if getattr(finding, "cwe", ""):
            parts.append(f"Classification: {finding.cwe}")
        proof = getattr(finding, "proof", None) or cb_evidence.Evidence()
        validation = getattr(finding, "validation", None)
        if validation is not None:
            parts.append("\nWhy this was detected:\n  "
                         + (validation.rationale
                            or "Detection rationale unavailable."))
            parts.append("\nObserved evidence:\n"
                         + "\n".join(cb_evidence.evidence_checklist(
                             getattr(finding, "key", ""), proof)))
            poc = proof.poc()
            parts.append("\n" + (poc if poc else
                                 "PoC unavailable — insufficient evidence "
                                 "was captured."))
            for conflict in validation.conflicts:
                parts.append("\n⚠ " + conflict)
            if validation.false_positive_indicators:
                parts.append("\nPotential false-positive indicators:\n"
                             + "\n".join(
                                 f"  - {i}"
                                 for i in
                                 validation.false_positive_indicators))
        raw = proof.raw_detection()
        if raw.strip() != "RAW DETECTION":
            parts.append("\n" + raw)
        elif finding.evidence:
            parts.append("\nEvidence:\n" + finding.evidence)
        if finding.detail:
            parts.append("\nGeneric description:\n" + finding.detail)
        if finding.remediation:
            parts.append("\nRecommended remediation: " + finding.remediation)
        return "\n".join(parts)

    # ── misc ─────────────────────────────────────────────────────────────
    def _cb_tick(self):
        started = getattr(self, "_cb_started_at", 0)
        if not started:
            return
        import time
        elapsed = int(time.time() - started)
        if getattr(self, "_cb_paused", False):
            self.cb_elapsed_label.setText("paused")
            return
        self.cb_elapsed_label.setText(
            f"running for {elapsed // 60}m {elapsed % 60:02d}s")
        # The status bar's clock belongs to the chain while one is running,
        # not to whichever step happens to be in flight.
        try:
            minutes, seconds = divmod(elapsed, 60)
            self.update_status_elapsed(f"{minutes:02d}:{seconds:02d}")
        except Exception:                               # noqa: BLE001
            pass

    def _cb_export(self):
        if not getattr(self, "_cb_findings", None):
            self.show_themed_message(
                "Nothing to export",
                "Run Coffee Break first — there are no findings yet.",
                QMessageBox.Icon.Information)
            return
        default = str(self.output_dir / "coffee_break_findings.md")
        path, _ = QFileDialog.getSaveFileName(
            self, "Save Coffee Break findings", default,
            "Markdown (*.md);;All files (*)")
        if not path:
            return
        try:
            with open(path, "w", encoding="utf-8") as handle:
                handle.write(self.coffee_break_report())
        except Exception as exc:                        # noqa: BLE001
            self.show_themed_message("Could not save", str(exc),
                                     QMessageBox.Icon.Warning)
            return
        self.console.append_ansi(f"\n[✓] Coffee Break findings written to {path}\n")


def _where_text(finding):
    """One location, or one location and a count of the rest."""
    extra = len(getattr(finding, "instances", []) or [])
    return f"{finding.where}  (+{extra} more)" if extra else finding.where


def _esc(text):
    return (str(text).replace("&", "&amp;").replace("<", "&lt;")
            .replace(">", "&gt;"))
