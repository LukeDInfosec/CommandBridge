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
    QMessageBox, QSizePolicy,
)

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

STAGE_MARK = {
    "pending": ("○", "#6b7688"),
    "running": ("◐", "#4f8cff"),
    "done": ("●", "#2dd4a7"),
    "skipped": ("◌", "#8b9bb4"),
    "failed": ("✕", "#ff5f6d"),
}


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
        layout.addWidget(self._cb_build_stages())
        layout.addWidget(self._cb_build_findings(), 1)

        self._cb_elapsed_timer = QTimer(self)
        self._cb_elapsed_timer.setInterval(1000)
        self._cb_elapsed_timer.timeout.connect(self._cb_tick)

        self._cb_rows = []
        self._cb_stage_rows = {}
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

        self.cb_tally = QLabel("")
        self.cb_tally.setStyleSheet("font-size: 12px;")
        box.addWidget(self.cb_tally)

        card.layout().addLayout(box)
        return card

    # ── stage list ───────────────────────────────────────────────────────
    def _cb_build_stages(self):
        card = self.create_card("Stages")
        self._init_collapsible_groupbox(card, "cb_stages_card")
        self.cb_stage_box = QVBoxLayout()
        self.cb_stage_box.setSpacing(4)
        placeholder = QLabel("The chain has not been run yet.")
        placeholder.setStyleSheet("color: palette(mid); font-size: 12px;")
        self.cb_stage_box.addWidget(placeholder)
        card.layout().addLayout(self.cb_stage_box)
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
        self.cb_filter.currentIndexChanged.connect(self._cb_apply_filter)
        controls.addWidget(self.cb_filter)
        controls.addStretch()
        self.cb_count_label = QLabel("")
        self.cb_count_label.setStyleSheet("color: palette(mid); font-size: 12px;")
        controls.addWidget(self.cb_count_label)
        box.addLayout(controls)

        splitter = QSplitter(Qt.Orientation.Vertical)

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
        header.setSectionResizeMode(0, QHeaderView.ResizeMode.ResizeToContents)
        header.setSectionResizeMode(1, QHeaderView.ResizeMode.Stretch)
        header.setSectionResizeMode(2, QHeaderView.ResizeMode.Stretch)
        header.setSectionResizeMode(3, QHeaderView.ResizeMode.ResizeToContents)
        header.setSectionResizeMode(4, QHeaderView.ResizeMode.ResizeToContents)
        self.cb_table.itemSelectionChanged.connect(self._cb_show_detail)
        self.cb_table.setMinimumHeight(300)
        splitter.addWidget(self.cb_table)

        self.cb_detail = QTextEdit()
        self.cb_detail.setReadOnly(True)
        self.cb_detail.setMinimumHeight(170)
        self.cb_detail.setPlaceholderText(
            "Select a finding to see what it means, the evidence, and the fix.")
        splitter.addWidget(self.cb_detail)
        splitter.setStretchFactor(0, 3)
        splitter.setStretchFactor(1, 2)

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

        self.cb_start_btn.setEnabled(False)
        self.cb_skip_btn.setEnabled(True)
        self.cb_stop_btn.setEnabled(True)
        self._cb_elapsed_timer.start()

    def _cb_ui_stage(self, key, status, note):
        widgets = getattr(self, "_cb_stage_rows", {}).get(key)
        if widgets:
            mark, name, note_label = widgets
            glyph, colour = STAGE_MARK.get(status, STAGE_MARK["pending"])
            mark.setText(glyph)
            mark.setStyleSheet(f"color: {colour};")
            name.setStyleSheet(
                "font-weight: 600;" if status == "running" else "")
            note_label.setText(note or "")

        total = max(1, len(getattr(self, "_cb_stages", [])) or 1)
        done = sum(1 for k, (m, _n, _o) in self._cb_stage_rows.items()
                   if m.text() in (STAGE_MARK["done"][0],
                                   STAGE_MARK["skipped"][0],
                                   STAGE_MARK["failed"][0]))
        self.cb_progress.setValue(int(done / total * 100))
        if status == "running":
            label = self._cb_stage_rows.get(key)
            self.cb_progress.setFormat(
                f"{done + 1} of {total} — {label[1].text() if label else key}")

    def _cb_ui_finding(self, finding):
        self._cb_ui_finding_list.append(finding)
        self._cb_add_row(finding)
        self._cb_update_tally()

    def _cb_ui_finished(self, how):
        self._cb_elapsed_timer.stop()
        self.cb_start_btn.setEnabled(True)
        self.cb_skip_btn.setEnabled(False)
        self.cb_stop_btn.setEnabled(False)
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

        cells = [severity,
                 QTableWidgetItem(finding.title),
                 QTableWidgetItem(finding.where),
                 QTableWidgetItem(finding.stage),
                 QTableWidgetItem(finding.confidence)]
        for column, item in enumerate(cells):
            item.setData(Qt.ItemDataRole.UserRole + 1, len(self._cb_rows))
            self.cb_table.setItem(row, column, item)
        self.cb_table.setSortingEnabled(True)
        self._cb_rows.append((row, finding))
        self._cb_update_count()

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
        self.cb_count_label.setText(
            f"{shown} of {total} shown" if shown != total else f"{total} finding(s)")

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
        colour = SEV_COLOURS.get(finding.severity, "#8b9bb4")
        html = [
            f"<h3 style='margin:0 0 4px 0'>{_esc(finding.title)}</h3>",
            f"<div style='color:{colour};font-weight:600'>{finding.severity}"
            f" &nbsp;·&nbsp; <span style='color:palette(mid);font-weight:400'>"
            f"{_esc(finding.stage)} · {_esc(finding.confidence)} confidence</span></div>",
            f"<p><b>Where:</b> <code>{_esc(finding.where)}</code></p>",
        ]
        if finding.detail:
            html.append(f"<p>{_esc(finding.detail)}</p>")
        if finding.evidence:
            html.append("<p><b>Evidence</b></p>"
                        f"<pre style='white-space:pre-wrap'>{_esc(finding.evidence)}</pre>")
        if finding.remediation:
            html.append(f"<p><b>Fix:</b> {_esc(finding.remediation)}</p>")
        self.cb_detail.setHtml("".join(html))

    # ── misc ─────────────────────────────────────────────────────────────
    def _cb_tick(self):
        started = getattr(self, "_cb_started_at", 0)
        if not started:
            return
        import time
        elapsed = int(time.time() - started)
        self.cb_elapsed_label.setText(
            f"running for {elapsed // 60}m {elapsed % 60:02d}s")

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


def _esc(text):
    return (str(text).replace("&", "&amp;").replace("<", "&lt;")
            .replace(">", "&gt;"))
