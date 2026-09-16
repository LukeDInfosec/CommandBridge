"""
Console Results tab creator.
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

from command_bridge.widgets.console import EnhancedConsole


class ConsoleTabMixin:
    """Mixin providing console results tab creator."""

    def create_console_tab(self):
        """Console tab: run controls, live status strip, output and artefacts.

        Layout is deliberately flat — a transport bar, a one-line status strip
        with a hairline progress indicator, then output on the left and the
        artefacts the run produced on the right. No nested cards, because this
        is the screen that gets watched for minutes at a time.
        """
        from PyQt6.QtWidgets import QListWidget
        from command_bridge.ui.icons import icon as _icon
        from command_bridge.constants import CONTENT_MARGIN

        widget = QWidget()
        layout = QVBoxLayout(widget)
        layout.setContentsMargins(CONTENT_MARGIN, CONTENT_MARGIN, CONTENT_MARGIN, CONTENT_MARGIN)
        layout.setSpacing(12)

        # ── Transport controls ────────────────────────────────────────────────
        toolbar = QWidget()
        toolbar.setObjectName("consoleToolbar")
        toolbar.setFixedHeight(56)
        toolbar_row = QHBoxLayout(toolbar)
        toolbar_row.setContentsMargins(12, 0, 12, 0)
        toolbar_row.setSpacing(8)

        self._console_buttons = []
        for label, icon_name, obj_name, handler in (
            ("Pause", "pause", "secondaryButton", self.pause_current_process),
            ("Skip",  "skip",  "secondaryButton", self.skip_current_task),
            ("Stop",  "stop",  "warningButton",   self.stop_current_process),
        ):
            btn = QPushButton(f"  {label}")
            btn.setObjectName(obj_name)
            btn.setFixedWidth(104)
            btn.setIconSize(QtCore.QSize(15, 15))
            btn.setCursor(QtGui.QCursor(Qt.CursorShape.PointingHandCursor))
            btn.clicked.connect(handler)
            toolbar_row.addWidget(btn)
            self._console_buttons.append((btn, icon_name, obj_name))

        toolbar_row.addStretch()

        clear_btn = QPushButton("  Clear")
        clear_btn.setObjectName("ghostButton")
        clear_btn.setFixedWidth(96)
        clear_btn.setIconSize(QtCore.QSize(15, 15))
        clear_btn.setCursor(QtGui.QCursor(Qt.CursorShape.PointingHandCursor))
        clear_btn.clicked.connect(self.clear_console)
        toolbar_row.addWidget(clear_btn)
        self._console_buttons.append((clear_btn, "trash", "ghostButton"))

        layout.addWidget(toolbar)

        # ── Live status strip ─────────────────────────────────────────────────
        status_container = QWidget()
        status_container.setObjectName("statusBarContainer")
        # Grows to fit the running command instead of truncating it.
        status_container.setMinimumHeight(58)
        status_container.setMaximumHeight(124)

        status_layout = QVBoxLayout(status_container)
        status_layout.setContentsMargins(14, 10, 14, 12)
        status_layout.setSpacing(8)

        status_row = QHBoxLayout()
        status_row.setContentsMargins(0, 0, 0, 0)
        status_row.setSpacing(10)

        self.status_info_label = QLabel("Idle")
        self.status_info_label.setObjectName("statusInfoLabel")
        # Wrap rather than elide: the whole command should be readable.
        self.status_info_label.setWordWrap(True)
        self.status_info_label.setTextInteractionFlags(
            Qt.TextInteractionFlag.TextSelectableByMouse
        )
        self.status_info_label.setSizePolicy(
            QtWidgets.QSizePolicy.Policy.Expanding, QtWidgets.QSizePolicy.Policy.Fixed
        )
        status_row.addWidget(self.status_info_label)

        self.console_elapsed_label = QLabel("00:00")
        self.console_elapsed_label.setObjectName("consolePaneTitle")
        status_row.addWidget(self.console_elapsed_label, 0, Qt.AlignmentFlag.AlignTop)

        status_layout.addLayout(status_row)

        self.progress_bar = QProgressBar()
        self.progress_bar.setObjectName("consoleProgressBar")
        self.progress_bar.setRange(0, 100)
        self.progress_bar.setValue(0)
        self.progress_bar.setTextVisible(False)
        self.progress_bar.setFixedHeight(6)
        status_layout.addWidget(self.progress_bar)

        layout.addWidget(status_container)

        # ── Output | artefacts ────────────────────────────────────────────────
        main_splitter = QSplitter(Qt.Orientation.Horizontal)

        console_container = QWidget()
        console_layout = QVBoxLayout(console_container)
        console_layout.setContentsMargins(0, 0, 0, 0)
        console_layout.setSpacing(6)

        output_caption = QLabel("OUTPUT")
        output_caption.setObjectName("consolePaneTitle")
        console_layout.addWidget(output_caption)

        self.console = EnhancedConsole()
        self.console.setMinimumHeight(360)
        console_layout.addWidget(self.console)
        main_splitter.addWidget(console_container)

        results_container = QWidget()
        results_layout = QVBoxLayout(results_container)
        results_layout.setContentsMargins(0, 0, 0, 0)
        results_layout.setSpacing(6)

        results_caption = QLabel("ARTEFACTS")
        results_caption.setObjectName("consolePaneTitle")
        results_layout.addWidget(results_caption)

        results_splitter = QSplitter(Qt.Orientation.Vertical)

        dir_widget = QWidget()
        dir_layout = QVBoxLayout(dir_widget)
        dir_layout.setContentsMargins(0, 0, 0, 0)
        dir_layout.setSpacing(8)

        self.file_list = QListWidget()
        self.file_list.setObjectName("fileList")
        self.file_list.itemClicked.connect(self.on_file_selected)
        self.file_list.itemDoubleClicked.connect(self.open_selected_file_external)
        dir_layout.addWidget(self.file_list)

        btn_row = QHBoxLayout()
        btn_row.setSpacing(8)
        for label, icon_name, obj_name, handler in (
            ("Refresh", "refresh", "ghostButton", self.refresh_file_list),
            ("Folder",  "folder",  "ghostButton", self.open_output_folder),
            ("Delete",  "trash",   "ghostButton", self.delete_selected_file),
        ):
            btn = QPushButton(f"  {label}")
            btn.setObjectName(obj_name)
            btn.setIconSize(QtCore.QSize(14, 14))
            btn.setCursor(QtGui.QCursor(Qt.CursorShape.PointingHandCursor))
            btn.clicked.connect(handler)
            btn_row.addWidget(btn)
            self._console_buttons.append(
                (btn, icon_name, "danger" if label == "Delete" else obj_name)
            )
        dir_layout.addLayout(btn_row)
        results_splitter.addWidget(dir_widget)

        preview_widget = QWidget()
        preview_layout = QVBoxLayout(preview_widget)
        preview_layout.setContentsMargins(0, 0, 0, 0)
        preview_layout.setSpacing(6)

        preview_caption = QLabel("PREVIEW")
        preview_caption.setObjectName("consolePaneTitle")
        preview_layout.addWidget(preview_caption)

        self.file_preview = QTextEdit()
        self.file_preview.setReadOnly(True)
        self.file_preview.setPlaceholderText("Select an artefact to preview it…")
        preview_layout.addWidget(self.file_preview)

        results_splitter.addWidget(preview_widget)
        results_splitter.setStretchFactor(0, 1)
        results_splitter.setStretchFactor(1, 1)

        results_layout.addWidget(results_splitter)
        main_splitter.addWidget(results_container)

        main_splitter.setStretchFactor(0, 4)
        main_splitter.setStretchFactor(1, 1)
        layout.addWidget(main_splitter, 1)

        return widget

    def set_transport_button(self, button, label: str, icon_name: str):
        """Retarget a transport button (Pause <-> Resume) with matching icon.

        Keeps the pause toggle inside the drawn icon set instead of writing an
        emoji back into a button the text sweep had already cleaned.
        """
        if button is None:
            return
        try:
            from command_bridge.ui.icons import icon as _icon
            button.setText(f"  {label}")
            button.setIcon(_icon(icon_name, self.tc("text"), 15, 1.9))
            for i, (btn, _name, role) in enumerate(getattr(self, "_console_buttons", [])):
                if btn is button:
                    self._console_buttons[i] = (btn, icon_name, role)
                    break
        except Exception:
            button.setText(label)

    def _refresh_console_theme(self):
        """Re-tint console controls and result highlighting for the palette."""
        from command_bridge.ui.icons import icon as _icon

        try:
            if hasattr(self, "console"):
                self.console.apply_theme_colors(self.theme())

            for btn, icon_name, role in getattr(self, "_console_buttons", []):
                if role == "warningButton":
                    colour = "#ffffff"
                elif role == "danger":
                    colour = self.tc("danger")
                elif role == "ghostButton":
                    colour = self.tc("text_dim")
                else:
                    colour = self.tc("text")
                btn.setIcon(_icon(icon_name, colour, 15, 1.9))
        except Exception:
            pass
