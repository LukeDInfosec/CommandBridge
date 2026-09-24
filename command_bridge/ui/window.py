"""
Main application window — CommandBridgeV5.

Inherits all functionality from mixin classes, keeping this file thin:
only __init__ and init_ui live here; everything else is in the mixins.
"""

from pathlib import Path

from PyQt6 import QtCore, QtGui, QtWidgets
from PyQt6.QtCore import Qt, QTimer
from PyQt6.QtWidgets import (
    QMainWindow, QWidget, QVBoxLayout, QHBoxLayout, QFrame, QLabel, QPushButton,
)

from command_bridge.constants import APP_TITLE, APP_VERSION

# ── Widget helpers ─────────────────────────────────────────────────────────────
from command_bridge.widgets.runner import CommandRunner

# ── UI mixins ──────────────────────────────────────────────────────────────────
from command_bridge.ui.window_controls import WindowControlsMixin
from command_bridge.ui.navigation import NavigationMixin
from command_bridge.ui.tabs_target import TargetTabMixin
from command_bridge.ui.tabs_recon import ReconTabMixin
from command_bridge.ui.tabs_web import WebTabMixin
from command_bridge.ui.tabs_api import ApiTabMixin
from command_bridge.ui.tabs_methodology import MethodologyTabMixin
from command_bridge.ui.tabs_console import ConsoleTabMixin
from command_bridge.ui.tabs_externals_ui import ExternalsTabUIMixin
from command_bridge.ui.tabs_coffee import CoffeeBreakTabMixin
from command_bridge.ui.cards import CardsMixin
from command_bridge.ui.theme import ThemeMixin

# ── Core mixins ────────────────────────────────────────────────────────────────
from command_bridge.core.preferences import PreferencesMixin
from command_bridge.core.commands import CommandsMixin
from command_bridge.core.output import OutputMixin
from command_bridge.core.status import StatusMixin
from command_bridge.core.updater import UpdaterMixin

# ── Module mixins ──────────────────────────────────────────────────────────────
from command_bridge.modules.web_testing import WebTestingMixin
from command_bridge.modules.sqlmap import SqlmapMixin
from command_bridge.modules.fuzzing import FuzzingMixin
from command_bridge.modules.auto_scan import AutoScanMixin
from command_bridge.modules.externals import ExternalsMixin
from command_bridge.modules.externals_reporting import ExternalsReportingMixin
from command_bridge.modules.network_scan import NetworkScanMixin
from command_bridge.modules.js_analysis import JsAnalysisMixin
from command_bridge.modules.coffee_break import CoffeeBreakMixin
from command_bridge.modules.file_upload_lab import FileUploadLabMixin
from command_bridge.modules.graphql_tools import GraphqlToolsMixin
from command_bridge.modules.tool_setup import ToolSetupMixin


class CommandBridgeV5(
    # Qt base
    QMainWindow,
    # UI
    WindowControlsMixin,
    NavigationMixin,
    TargetTabMixin,
    ReconTabMixin,
    WebTabMixin,
    ApiTabMixin,
    MethodologyTabMixin,
    ConsoleTabMixin,
    ExternalsTabUIMixin,
    CoffeeBreakTabMixin,
    CardsMixin,
    ThemeMixin,
    # Core
    PreferencesMixin,
    CommandsMixin,
    OutputMixin,
    StatusMixin,
    UpdaterMixin,
    # Modules
    WebTestingMixin,
    SqlmapMixin,
    FuzzingMixin,
    AutoScanMixin,
    ExternalsMixin,
    ExternalsReportingMixin,
    NetworkScanMixin,
    JsAnalysisMixin,
    CoffeeBreakMixin,
    FileUploadLabMixin,
    GraphqlToolsMixin,
    ToolSetupMixin,
):
    """Main application window — Command Bridge v5."""

    def __init__(self):
        super().__init__()
        self.target = ""

        # Default options for testssl summary parser
        self._testssl_summary_min_severity = "LOW"
        self._testssl_summary_include_notes = False

        self._js_lib_counter = 1

        # Auto Scan state
        self._auto_scan_active = False
        self._auto_scan_commands: list[str] = []
        self._auto_scan_index: int = 0
        self._auto_scan_output_dir: str | None = None

        # Coffee Break chain state (see modules/coffee_break.py)
        self._cb_reset()

        # Externals workflow state
        self._externals_active: bool = False
        self._externals_phase: str | None = None
        self._externals_context: dict = {}

        # CORS PoC local server
        self._cors_poc_server = None
        self._cors_poc_server_port: int = 8000

        # SQLMap output state
        self._sqlmap_vuln_found: bool = False
        self._sqlmap_first_vuln_highlighted: bool = False
        self._sqlmap_dbms: str | None = None
        self._sqlmap_param: str | None = None
        self._sqlmap_critical: bool = False
        self._sqlmap_buffer: str = ""

        # Fuzzing readiness tracking
        self._fuzzing_ready: set[str] = set()

        self.runner = CommandRunner()
        self.runner.output_ready.connect(self.on_command_output)
        self.runner.finished.connect(self.on_command_finished)

        self.command_registry = {}
        self.load_custom_commands()

        self.current_theme = self.load_theme_preference()
        self.output_dir = self.load_output_dir_preference()

        self.init_ui()
        self.apply_theme(self.current_theme)

        self.load_target_and_headers()
        self.load_window_geometry()

    def init_ui(self):
        """Initialise the user interface."""
        self.setWindowTitle(f"{APP_TITLE} v{APP_VERSION}")
        self.setGeometry(100, 100, 1600, 900)
        self.setMinimumSize(1200, 700)

        self.setWindowFlags(Qt.WindowType.FramelessWindowHint)
        self.setAttribute(Qt.WidgetAttribute.WA_TranslucentBackground, False)

        self.setMouseTracking(True)
        self.setAttribute(Qt.WidgetAttribute.WA_Hover, True)

        self.dragging = False
        self.drag_position = None
        self.resize_edge = None
        self.resize_start_pos = None
        self.resize_start_geometry = None
        self.current_command = ""
        self.command_start_time = None
        self.status_animation_timer = None
        self.is_resizing = False

        self.installEventFilter(self)
        # Also install globally on the QApplication: with a frameless window
        # and full-bleed child content (header bar, nav rail, tab content,
        # status bar), mouse events at the window edges land on a CHILD
        # widget first, so self.mousePressEvent/mouseMoveEvent above almost
        # never fire for a real edge click. The app-level filter in
        # WindowControlsMixin.eventFilter intercepts those before the child
        # widget sees them, which is what actually makes edge-resize work.
        app = QtWidgets.QApplication.instance()
        if app is not None:
            app.installEventFilter(self)

        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        root_layout = QVBoxLayout(central_widget)
        root_layout.setContentsMargins(0, 0, 0, 0)
        root_layout.setSpacing(0)

        # ── Unified header bar ────────────────────────────────────────────────
        root_layout.addWidget(self.create_header_bar())

        sep1 = QFrame()
        sep1.setFrameShape(QFrame.Shape.HLine)
        sep1.setObjectName("headerSeparator")
        sep1.setFixedHeight(1)
        root_layout.addWidget(sep1)

        # ── Body: nav rail + content ──────────────────────────────────────────
        body = QWidget()
        body.setObjectName("appBody")
        body_layout = QHBoxLayout(body)
        body_layout.setContentsMargins(0, 0, 0, 0)
        body_layout.setSpacing(0)

        body_layout.addWidget(self.create_nav_rail())

        rail_sep = QFrame()
        rail_sep.setFrameShape(QFrame.Shape.VLine)
        rail_sep.setObjectName("railSeparator")
        body_layout.addWidget(rail_sep)

        body_layout.addWidget(self.create_content_area(), 1)
        root_layout.addWidget(body, 1)

        # ── Bottom status bar ─────────────────────────────────────────────────
        sep2 = QFrame()
        sep2.setFrameShape(QFrame.Shape.HLine)
        sep2.setObjectName("headerSeparator")
        sep2.setFixedHeight(1)
        root_layout.addWidget(sep2)

        root_layout.addWidget(self.create_bottom_status_bar())

        # One pass over the finished widget tree strips decorative emoji from
        # every label and button, so the nine tab modules stay focused on
        # wiring commands while the UI keeps a single typographic voice.
        self.polish_ui_text()

        # Open on the first tab and show what we're pointed at.
        self._nav_activate(0, init=True)
        self.update_target_display()
        self.set_status_state("idle")

    def get_headers_string(self) -> str:
        """Return a curl-compatible string of all configured HTTP headers."""
        headers = []
        custom_headers = self.headers_input.toPlainText().strip()
        if custom_headers:
            for line in custom_headers.split('\n'):
                if line.strip() and ':' in line:
                    headers.append(f"-H '{line.strip()}'")
        return ' '.join(headers) if headers else ''
