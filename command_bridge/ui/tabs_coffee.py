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
    QTreeWidget, QTreeWidgetItem,
    QTextEdit, QHeaderView, QAbstractItemView, QComboBox, QFileDialog,
    QMessageBox, QSizePolicy, QMenu, QApplication, QCheckBox, QGridLayout,
    QLineEdit,
)

from command_bridge.modules import cb_evidence
from command_bridge.modules import finding_groups
from command_bridge.modules.coffee_break import SEVERITIES, SEV_ORDER
from command_bridge.widgets.plain_copy import PlainCopyTextEdit

#: One colour per severity. Taken from cb_evidence rather than written out
#: again here — this file used to hold its own copy, and the copies drifted:
#: the Active Scan screen and the Coffee Break screen were painting the same
#: severity two different colours.
SEV_COLOURS = cb_evidence.SEV_COLOURS

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


class _SeverityTreeItem(QTreeWidgetItem):
    """A tree row that sorts by severity rather than alphabetically.

    The same reason _SeverityItem exists for the table, and the same bug
    if it is left out: Qt sorts on the display string, so a descending
    sort puts MEDIUM above CRITICAL — precisely upside down for a list
    whose job is to show the worst thing first. Caught by the existing
    "the worst finding sorts to the top" assertion when the widget
    changed, which is what that assertion is for.

    Group rows carry the rank of the worst severity they contain, so a
    parent sorts among the findings it is comparable to rather than
    always to the top or always to the bottom.
    """

    def __lt__(self, other):
        column = self.treeWidget().sortColumn() if self.treeWidget() else 0
        mine = self.data(column, Qt.ItemDataRole.UserRole)
        theirs = other.data(column, Qt.ItemDataRole.UserRole)
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

        # A search box, added with the grouping. Collapsed groups make a
        # finding harder to spot by eye, so there has to be a way to go
        # straight to one by name — and a group whose child matches is
        # opened automatically, otherwise searching would hide the very
        # row it found.
        self.cb_search = QLineEdit()
        self.cb_search.setPlaceholderText("Search findings…")
        self.cb_search.setClearButtonEnabled(True)
        self.cb_search.setMaximumWidth(260)
        self.cb_search.setToolTip(
            "Matches a finding's name, location, scanner or issue key. "
            "Groups open automatically to show a match.")
        self.cb_search.textChanged.connect(self._cb_apply_filter)
        controls.addWidget(self.cb_search)
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

        # A QTreeWidget, not a QTableWidget, so that related findings can
        # sit under one expandable parent row. Qt's own disclosure widget:
        # the chevron, the keyboard handling (Left/Right collapse and
        # expand, Space and Enter activate) and the expanded/collapsed
        # state a screen reader reports all come with it, so no new
        # component and no new library.
        #
        # Columns, selection behaviour and the hidden columns are exactly
        # as the table had them — a child row is still one finding, and
        # the detail pane, filter, right-click menu and delete all still
        # work off the same five fields.
        self.cb_table = QTreeWidget()
        self.cb_table.setColumnCount(5)
        self.cb_table.setHeaderLabels(
            ["Severity", "Finding", "Where", "Stage", "Confidence"])
        self.cb_table.setSelectionBehavior(
            QAbstractItemView.SelectionBehavior.SelectRows)
        self.cb_table.setSelectionMode(
            QAbstractItemView.SelectionMode.SingleSelection)
        self.cb_table.setEditTriggers(
            QAbstractItemView.EditTrigger.NoEditTriggers)
        self.cb_table.setUniformRowHeights(False)
        self.cb_table.setExpandsOnDoubleClick(False)
        self.cb_table.setAnimated(False)
        self.cb_table.setIndentation(18)
        self.cb_table.setAllColumnsShowFocus(True)
        #: group key → whether the operator has opened it. Groups start
        #: collapsed; a choice made during a scan is remembered for the
        #: rest of that scan, which is as long as it is useful. Nothing
        #: is written to disk for a transient view state.
        self._cb_expanded = {}
        self.cb_table.itemClicked.connect(self._cb_item_clicked)
        self.cb_table.itemExpanded.connect(self._cb_remember_expanded)
        self.cb_table.itemCollapsed.connect(self._cb_remember_expanded)
        # Alternating row colours come from the palette, and on several of
        # the darker themes the alternate row washed the text out until it
        # could not be read. Severity already gives the eye a column to
        # track down; the stripes were costing legibility for nothing.
        self.cb_table.setAlternatingRowColors(False)
        self.cb_table.setSortingEnabled(True)
        self.cb_table.sortByColumn(0, Qt.SortOrder.DescendingOrder)
        header = self.cb_table.header()
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

        # PlainCopyTextEdit, not QTextEdit: selecting a finding
        # and copying it out of a plain QTextEdit yields U+2029
        # and U+2028 instead of newlines, so a cipher list that
        # reads one-per-line on screen pastes into a report as a
        # single line. See widgets/plain_copy.py.
        self.cb_detail = PlainCopyTextEdit()
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
        self.cb_technical_btn = QPushButton("Technical detail")
        self.cb_technical_btn.setObjectName("secondaryButton")
        self.cb_technical_btn.setToolTip(
            "Show the full evidence chain, raw scanner output, proof of "
            "concept, false-positive indicators and remediation for this "
            "finding. The summary above is deliberately short; nothing is "
            "discarded by hiding this.")
        self.cb_technical_btn.clicked.connect(self._cb_toggle_technical)
        self.cb_burp_btn = QPushButton("Copy Burp Request")
        self.cb_burp_btn.setObjectName("secondaryButton")
        self.cb_burp_btn.setToolTip(
            "Copies the complete request as raw HTTP/1.1 — request line, "
            "Host, every header including session cookies, and the body. "
            "Paste straight into Burp Repeater.")
        self.cb_burp_btn.setEnabled(False)
        self.cb_burp_btn.clicked.connect(self._cb_copy_burp)
        detail_buttons = QHBoxLayout()
        detail_buttons.setSpacing(8)
        detail_buttons.addWidget(self.cb_technical_btn)
        detail_buttons.addWidget(self.cb_burp_btn)
        detail_buttons.addStretch()
        right_box.addLayout(detail_buttons)
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
        self.cb_table.clear()
        self.cb_detail.clear()
        self._cb_rows = []
        self._cb_ui_finding_list = []
        # A new scan starts with every group shut again.
        self._cb_expanded = {}

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

    # ── the tree ─────────────────────────────────────────────────────────
    #
    # The whole tree is rebuilt from _cb_ui_finding_list whenever it
    # changes, rather than rows being inserted one at a time. Grouping
    # depends on the whole set — a category becomes a parent only once it
    # has two members — so an incremental insert would have to promote a
    # loose row into a group mid-scan and keep the two paths in step.
    # A findings list is tens of items; rebuilding it is not worth the
    # second code path.

    def _cb_add_row(self, finding):
        """A finding arrived. It is already in the list; redraw."""
        self._cb_rebuild_tree()

    def _cb_matches_filter(self, finding):
        """Both filters: the severity floor and the search text."""
        wanted = self.cb_filter.currentData()
        if wanted and SEV_ORDER.get(finding.severity, 0) < \
                SEV_ORDER.get(wanted, 0):
            return False
        return self._cb_matches_search(finding)

    def _cb_matches_search(self, finding):
        """Does the search text match this finding?

        Across the fields a tester would search by — the name, the
        affected location, the scanner and the issue key — so searching
        "csp" finds the CSP findings and searching "testssl" finds that
        scanner's. Case-insensitive, substring.
        """
        text = ""
        box = getattr(self, "cb_search", None)
        if box is not None:
            text = box.text().strip().lower()
        if not text:
            return True
        haystack = " ".join(str(part or "").lower() for part in (
            finding.title, getattr(finding, "where", ""),
            getattr(finding, "stage", ""), getattr(finding, "key", ""),
            getattr(finding, "severity", ""),
            getattr(finding, "status_label", ""),
        ))
        return text in haystack

    def _cb_rebuild_tree(self):
        """Draw every finding, grouped, honouring the current filter.

        Child rows keep their index into _cb_ui_finding_list, so the
        detail pane, the right-click menu and delete all resolve to the
        same finding object they did before grouping existed.
        """
        selected = self._cb_selected_finding()
        self.cb_table.setSortingEnabled(False)
        self.cb_table.clear()
        self._cb_rows = []

        findings = list(self._cb_ui_finding_list)
        index_of = {id(f): i for i, f in enumerate(findings)}
        visible = [f for f in findings if self._cb_matches_filter(f)]
        groups, loose = finding_groups.organise(visible)

        to_select = None
        for group in groups:
            parent = _SeverityTreeItem(self.cb_table)
            self._cb_dress_group(parent, group)
            for finding in group.findings:
                child = _SeverityTreeItem(parent)
                self._cb_dress_finding(child, finding,
                                       index_of.get(id(finding)))
                if finding is selected:
                    to_select = child
            # Collapsed unless the operator opened this group earlier in
            # the scan — or unless a search is running, in which case
            # every surviving child is a match and hiding it behind a
            # closed group would defeat the search.
            searching = bool(getattr(self, "cb_search", None)
                             and self.cb_search.text().strip())
            parent.setExpanded(searching
                               or bool(self._cb_expanded.get(group.key)))

        for finding in loose:
            row = _SeverityTreeItem(self.cb_table)
            self._cb_dress_finding(row, finding, index_of.get(id(finding)))
            if finding is selected:
                to_select = row

        self.cb_table.setSortingEnabled(True)
        if to_select is not None:
            # Keep the operator's place across a redraw, and make sure
            # the group it lives in is open enough to see it.
            parent = to_select.parent()
            if parent is not None:
                parent.setExpanded(True)
            self.cb_table.setCurrentItem(to_select)
        self._cb_update_count()

    def _cb_dress_group(self, item, group):
        """A parent row: title, count, and the distribution underneath."""
        item.setData(0, Qt.ItemDataRole.UserRole + 2, group.key)
        # NOT first-column-spanned. Spanning draws the row from column 0
        # alone, so a title written to column 1 is simply never painted —
        # which is exactly what it did: a black row with a chevron and no
        # name on it. The parent uses the same columns as its children.
        item.setFirstColumnSpanned(False)
        item.setText(1, f"{group.title}   [{group.count} findings]")
        # Column 0 carries the worst severity present, as a child row
        # does, so the columns line up. It is an indicator, not a verdict:
        # the distribution sits in column 2 and says what is really there.
        item.setText(0, group.worst_severity)
        item.setTextAlignment(0, Qt.AlignmentFlag.AlignCenter)
        severity_font = QtGui.QFont(item.font(0))
        severity_font.setBold(True)
        item.setFont(0, severity_font)
        item.setForeground(0, QtGui.QColor(
            SEV_COLOURS.get(group.worst_severity, "#8b9bb4")))

        bold = QtGui.QFont(item.font(1))
        bold.setBold(True)
        item.setFont(1, bold)
        # The indicator shows the worst severity present; the SUMMARY
        # beside it shows the distribution, so a parent never implies
        # that every child is as bad as the worst one.
        item.setForeground(1, QtGui.QColor(
            SEV_COLOURS.get(group.worst_severity, "#8b9bb4")))
        item.setToolTip(0, f"Worst severity among {group.count} findings — "
                           f"see the distribution beside it")
        item.setToolTip(1, group.summary())
        item.setText(2, group.summary())
        # Qt reads the item's text to a screen reader; the summary says
        # the counts, and the expanded state comes from the widget.
        item.setData(1, Qt.ItemDataRole.AccessibleTextRole,
                     group.accessible_name())
        item.setData(1, Qt.ItemDataRole.AccessibleDescriptionRole,
                     "Group of related findings. Press Right to expand, "
                     "Left to collapse.")
        # Sorts among the findings it is comparable to: the rank of the
        # worst severity it contains. -1 here (its first form) parked
        # every group at one end of the list regardless of content.
        item.setData(0, Qt.ItemDataRole.UserRole,
                     SEV_ORDER.get(group.worst_severity, 0))

    def _cb_dress_finding(self, item, finding, index):
        """A child row: exactly what the table row used to be."""
        item.setData(0, Qt.ItemDataRole.UserRole + 1, index)
        item.setText(0, finding.severity)
        item.setData(0, Qt.ItemDataRole.UserRole,
                     SEV_ORDER.get(finding.severity, 0))
        item.setForeground(0, QtGui.QColor(
            SEV_COLOURS.get(finding.severity, "#8b9bb4")))
        severity_font = QtGui.QFont(item.font(0))
        severity_font.setBold(True)
        item.setFont(0, severity_font)
        item.setTextAlignment(0, Qt.AlignmentFlag.AlignCenter)

        item.setText(1, finding.title)
        state = getattr(finding, "state", "")
        item.setToolTip(1, f"[{state}] {finding.title}" if state
                        else finding.title)
        # A CRITICAL nobody has validated must not look, at a glance down
        # the list, like one that has been.
        validation = getattr(finding, "validation", None)
        if validation is not None and validation.needs_manual_validation:
            unsettled = QtGui.QFont(item.font(1))
            unsettled.setItalic(True)
            item.setFont(1, unsettled)

        item.setText(2, _where_text(finding))
        item.setToolTip(2, "\n".join(finding.locations()[:40]))
        item.setText(3, finding.stage)
        item.setText(4, finding.confidence)
        item.setTextAlignment(4, Qt.AlignmentFlag.AlignCenter)
        status = getattr(finding, "status_label", "")
        item.setData(1, Qt.ItemDataRole.AccessibleTextRole,
                     f"{finding.severity}, {finding.title}"
                     + (f", {status}" if status else ""))
        self._cb_rows.append((item, finding))

    def _cb_item_clicked(self, item, column):
        """Clicking a group header toggles it. A child is left alone.

        Required explicitly: clicking an individual finding must not
        toggle its parent. A child click selects the child and nothing
        else, which is what the detail pane reacts to.
        """
        if item is None or item.parent() is not None:
            return
        if item.data(0, Qt.ItemDataRole.UserRole + 2) is None:
            return                      # a loose finding at the top level
        item.setExpanded(not item.isExpanded())

    def _cb_remember_expanded(self, item):
        key = item.data(0, Qt.ItemDataRole.UserRole + 2) if item else None
        if key is not None:
            self._cb_expanded[key] = item.isExpanded()

    def _cb_selected_finding(self):
        """The finding the operator has selected, or None for a group."""
        items = self.cb_table.selectedItems()
        if not items:
            return None
        return self._cb_finding_for_item(items[0])

    def _cb_finding_for_item(self, item):
        if item is None:
            return None
        index = item.data(0, Qt.ItemDataRole.UserRole + 1)
        findings = getattr(self, "_cb_ui_finding_list", [])
        if index is None or not isinstance(index, int) or \
                index >= len(findings):
            return None
        return findings[index]

    def _cb_ui_refresh(self, finding):
        """Another instance of a finding already on the tree."""
        for item, candidate in self._cb_rows:
            if candidate is finding:
                item.setText(2, _where_text(finding))
                item.setToolTip(2, "\n".join(finding.locations()[:40]))
                break
        self._cb_show_detail()

    def _cb_apply_filter(self):
        self._cb_rebuild_tree()

    def _cb_update_count(self):
        """Counts over FINDINGS, never over rows.

        A parent row is not a finding, so counting rows would report one
        more than there are for every group on screen.
        """
        shown = len(self._cb_rows)
        total = len(self._cb_ui_finding_list)
        instances = sum(getattr(f, "count", 1)
                        for f in self._cb_ui_finding_list)
        extra = ""
        if instances > total:
            extra = f" · {instances} location(s)"
        groups = sum(1 for item, _ in self._cb_rows
                     if item.parent() is not None)
        grouped = f" · {groups} in groups" if groups else ""
        searching = bool(getattr(self, "cb_search", None)
                         and self.cb_search.text().strip())
        reason = "the search" if searching else "the filter"
        if shown != total:
            self.cb_count_label.setText(
                f"{shown} of {total} shown — {total - shown} hidden by "
                f"{reason}{extra}{grouped}")
        else:
            self.cb_count_label.setText(
                f"{total} finding(s){extra}{grouped}")

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
        """Draw whatever is selected: a finding, or a group's summary."""
        items = self.cb_table.selectedItems()
        if not items:
            return
        item = items[0]
        finding = self._cb_finding_for_item(item)
        if finding is None:
            # A group header. Show what the group contains rather than
            # clearing the pane, so selecting a parent is informative
            # instead of looking broken.
            key = item.data(0, Qt.ItemDataRole.UserRole + 2)
            self._cb_detail_finding = None
            self.cb_detail.setHtml(self._cb_group_html(key))
            self._cb_burp = ""
            self.cb_burp_btn.setEnabled(False)
            self.cb_burp_btn.setText("No request captured for this finding")
            return
        # The Active Scan tab renders its findings with these same
        # functions. Two screens, one description of what a finding is.
        #
        # Concise by default: name, rating, status, what was found. The
        # full technical rendering is one click away and is still what
        # "Copy this finding" produces, so nothing is lost from the
        # record by not showing it first.
        self._cb_detail_finding = finding
        self._cb_render_detail()
        self._cb_burp = cb_evidence.burp_request_for(finding)
        self.cb_burp_btn.setEnabled(bool(self._cb_burp))
        self.cb_burp_btn.setText(
            "Copy Burp Request" if self._cb_burp
            else "No request captured for this finding")

    def _cb_group_html(self, key):
        """A group header's detail pane: the distribution, and the list.

        Deliberately a summary of its CHILDREN and nothing more. A parent
        has no evidence of its own, and inventing a description for it
        would be exactly the generic prose the findings pane was cut
        down to remove.
        """
        groups, _ = finding_groups.organise(
            [f for f in self._cb_ui_finding_list
             if self._cb_matches_filter(f)])
        group = next((g for g in groups if g.key == key), None)
        if group is None:
            return ""
        rows = []
        for finding in group.findings:
            colour = SEV_COLOURS.get(finding.severity, "#8b9bb4")
            status = getattr(finding, "status_label", "") or ""
            rows.append(
                f"<tr><td style='padding:2px 12px 2px 0;color:{colour};"
                f"white-space:nowrap'>{finding.severity}</td>"
                f"<td style='padding:2px 12px 2px 0'>{finding.title}</td>"
                f"<td style='padding:2px 0;color:#8b9bb4;"
                f"white-space:nowrap'>{status}</td></tr>")
        return (
            f"<h3 style='margin:0 0 6px 0'>{group.category.title}</h3>"
            f"<p style='margin:0 0 12px 0;color:#8b9bb4'>"
            f"{group.summary()}</p>"
            f"<table cellspacing='0' cellpadding='0'>{''.join(rows)}</table>"
            f"<p style='margin:12px 0 0 0;color:#8b9bb4'>Select a finding "
            f"above for its evidence. Each one keeps its own rating, status "
            f"and raw scanner output.</p>")

    def _cb_render_detail(self):
        """Draw the selected finding at the current level of detail."""
        finding = getattr(self, "_cb_detail_finding", None)
        if finding is None:
            self.cb_detail.clear()
            return
        if getattr(self, "_cb_show_technical", False):
            self.cb_detail.setHtml(cb_evidence.detail_html(finding))
        else:
            self.cb_detail.setHtml(cb_evidence.summary_html(finding))

    def _cb_toggle_technical(self):
        self._cb_show_technical = not getattr(self, "_cb_show_technical",
                                              False)
        self.cb_technical_btn.setText(
            "Hide technical detail" if self._cb_show_technical
            else "Technical detail")
        self._cb_render_detail()

    def _cb_copy_burp(self):
        if not getattr(self, "_cb_burp", ""):
            return
        QApplication.clipboard().setText(self._cb_burp)
        self.cb_burp_btn.setText("Copied — paste into Repeater")
        QTimer.singleShot(
            2000, lambda: self.cb_burp_btn.setText("Copy Burp Request"))

    # ── right-click ──────────────────────────────────────────────────────
    def _cb_finding_at(self, item_or_row):
        """The finding for a tree item.

        Takes an item now rather than a row index. The row index it used
        to take has no meaning in a tree, where row 3 of the viewport
        may be a group header or a child of a different group.
        """
        if isinstance(item_or_row, QTreeWidgetItem):
            return self._cb_finding_for_item(item_or_row)
        return None

    def _cb_item_at(self, position):
        """Which item was right-clicked.

        customContextMenuRequested gives a position in the widget's own
        coordinates while itemAt() expects the viewport's, and the two
        differ by the height of the header — enough to return the wrong
        item near the top and nothing at all on the first row.
        """
        table = self.cb_table
        for candidate in (table.viewport().mapFrom(table, position),
                          position):
            item = table.itemAt(candidate)
            if item is not None:
                return item
        return table.currentItem()

    def _cb_menu(self, position):
        """Delete a finding, delete its whole type, or mute it for good.

        Every team has issues it does not report — the one that prompted this
        was BREACH. Deleting the row covers this scan; muting the type covers
        every scan after it, which is the difference between a fix and a
        chore you repeat.
        """
        item = self._cb_item_at(position)
        finding = self._cb_finding_at(item)
        if finding is None:
            # A group header has nothing to delete or mute — its
            # children do, individually.
            return
        # Right-clicking a row selects it, so the detail pane below
        # matches what the menu is about to act on.
        if item is not self.cb_table.currentItem():
            self.cb_table.setCurrentItem(item)

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
        finding = self._cb_finding_at(self.cb_table.currentItem())
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
