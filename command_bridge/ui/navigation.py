"""Application shell — header bar, navigation rail, status bar, tab registry.

Structure
─────────
    ┌──────────────────────────────────────────────────────────────┐
    │ ⚡ COMMAND BRIDGE  v5 │ Section · hint     [target] [theme] ─□✕│
    ├────────┬─────────────────────────────────────────────────────┤
    │ ENGAGE │                                                     │
    │  Target│                                                     │
    │DISCOVER│                 active tab content                  │
    │  Recon │                                                     │
    │ …      │                                                     │
    │────────│                                                     │
    │Console │                                                     │
    │ Bounty │                                                     │
    ├────────┴─────────────────────────────────────────────────────┤
    │ ● READY │ nmap │ 00:42          target · output dir · theme   │
    └──────────────────────────────────────────────────────────────┘

Tab order comes from constants.TABS and nothing else. Address tabs by key
(``self.goto_tab("console")``) — never by index, so the order can change
without hunting for magic numbers.
"""

from __future__ import annotations

from PyQt6 import QtGui
from PyQt6.QtCore import (
    Qt, QVariantAnimation, QEasingCurve, QSize, QTimer, QObject, QEvent,
)
from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QPushButton, QLabel,
    QTabWidget, QFrame, QComboBox, QSizePolicy,
)

from command_bridge.constants import (
    APP_TITLE, APP_VERSION, THEMES, TABS, RAIL_SECTIONS,
    HEADER_HEIGHT, STATUSBAR_HEIGHT, RAIL_WIDTH_COMPACT, RAIL_WIDTH_EXPANDED,
)
from command_bridge.ui import icons
from command_bridge.ui.theme import rgba


# Which mixin method builds each tab.
_TAB_BUILDERS = {
    "target":    "create_target_tab",
    "recon":     "create_reconnaissance_tab",
    "externals": "create_externals_tab",
    "web":       "create_web_testing_tab",
    "api":       "create_api_testing_tab",
    "coffee":    "create_coffee_break_tab",
    "scan":      "create_active_scan_tab",
    "console":   "create_console_tab",
    "bounty":    "create_methodology_tab",
}

# Widgets are built in this order regardless of where they end up in the tab
# bar, so a tab that touches self.console while constructing can never race
# the console into existence.
_SAFE_BUILD_ORDER = [
    "target", "console", "recon", "externals", "web", "api", "scan",
    "coffee", "bounty",
]

# Header target chip: grows with the target, but never so far that it crowds
# out the theme picker and window controls sitting to its right.
TARGET_PILL_MIN_WIDTH = 200
TARGET_PILL_MAX_WIDTH = 620

# Slack added to the measured text width. Font metrics describe where the pen
# lands, not where the ink stops: an italic or a glyph with a right side
# bearing can paint a pixel or two past its own advance, and a fractional
# device pixel ratio rounds the label's usable width down. Without this the
# final character of a target loses its right-hand edge.
TARGET_PILL_TEXT_PAD = 10


class _HeaderFitWatcher(QObject):
    """Re-sizes the header target chip when the window is shown or resized.

    This has to be a standalone filter object rather than a ``showEvent`` /
    ``resizeEvent`` on the mixin: ``QMainWindow`` sits ahead of every mixin in
    the MRO, so a handler defined on one would simply never be called.
    """

    def __init__(self, window):
        super().__init__(window)
        self._window = window

    def eventFilter(self, obj, event):
        if event.type() in (QEvent.Type.Show, QEvent.Type.Resize,
                            QEvent.Type.FontChange, QEvent.Type.StyleChange):
            try:
                self._window.refit_target_pill()
            except Exception:
                pass
        return False

# Status states → (palette role, status text)
_STATUS_STATES = {
    "idle":    ("text_dim", "READY"),
    "running": ("warning",  "RUNNING"),
    "ok":      ("success",  "COMPLETE"),
    "error":   ("danger",   "FAILED"),
    "stopped": ("text_dim", "STOPPED"),
    "paused":  ("info",     "PAUSED"),
}


class NavigationMixin:
    """Header bar, navigation rail, status bar and tab addressing."""

    # ══════════════════════════════════════════════════════════════════════════
    #  TAB REGISTRY
    # ══════════════════════════════════════════════════════════════════════════

    def tab_index(self, key: str) -> int:
        """Index of a tab by key; -1 when unknown."""
        return getattr(self, "_tab_index", {}).get(key, -1)

    def goto_tab(self, key: str):
        """Switch to a tab by key and sync the rail."""
        idx = self.tab_index(key)
        if idx >= 0:
            self._nav_activate(idx)

    def goto_console(self):
        """Jump to the Console tab.

        Every 'show me the output' call site routes through here rather than a
        hard-coded index, which is what lets the tab order be rearranged.
        """
        self.goto_tab("console")

    def switch_category(self, category: str):
        """Compatibility shim: switch by display name or key."""
        aliases = {
            "Target Setup": "target", "Reconnaissance": "recon",
            "Web Testing": "web", "Access Control": "web",
            "API Testing": "api", "Methodology": "bounty",
            "Injections": "bounty", "Bug Bounty": "bounty",
            "Console": "console", "Results": "console",
            "Externals": "externals", "External Infra": "externals",
            "Coffee Break": "coffee", "Active Scan": "coffee",
        }
        self.goto_tab(aliases.get(category, category))

    # ══════════════════════════════════════════════════════════════════════════
    #  HEADER BAR
    # ══════════════════════════════════════════════════════════════════════════

    def create_header_bar(self):
        bar = QWidget()
        bar.setObjectName("headerBar")
        bar.setFixedHeight(HEADER_HEIGHT)

        layout = QHBoxLayout(bar)
        layout.setContentsMargins(14, 0, 8, 0)
        layout.setSpacing(0)

        # ── Brand ─────────────────────────────────────────────────────────────
        self._brand_mark = QLabel()
        self._brand_mark.setObjectName("brandMark")
        self._brand_mark.setFixedSize(28, 28)
        self._brand_mark.setAlignment(Qt.AlignmentFlag.AlignCenter)
        layout.addWidget(self._brand_mark)

        layout.addSpacing(10)

        brand = QLabel(APP_TITLE.upper())
        brand.setObjectName("brandName")
        layout.addWidget(brand)

        layout.addSpacing(8)

        version = QLabel(f"v{APP_VERSION}")
        version.setObjectName("versionChip")
        version.setFixedHeight(20)
        layout.addWidget(version, 0, Qt.AlignmentFlag.AlignVCenter)

        layout.addSpacing(16)
        layout.addWidget(self._vdivider(24))
        layout.addSpacing(16)

        # ── Section breadcrumb (title + hint) ──────────────────────────────────
        crumb = QWidget()
        crumb.setObjectName("headerCrumb")
        crumb_layout = QVBoxLayout(crumb)
        crumb_layout.setContentsMargins(0, 0, 0, 0)
        crumb_layout.setSpacing(1)

        self.section_title_label = QLabel(TABS[0][2])
        self.section_title_label.setObjectName("sectionTitle")
        crumb_layout.addWidget(self.section_title_label)

        self.section_hint_label = QLabel(TABS[0][3])
        self.section_hint_label.setObjectName("sectionHint")
        crumb_layout.addWidget(self.section_hint_label)

        layout.addWidget(crumb)
        # Kept for older call sites that set a breadcrumb directly.
        self.breadcrumb_label = self.section_title_label

        layout.addStretch()

        # ── Live target chip ──────────────────────────────────────────────────
        layout.addWidget(self._build_target_pill())
        layout.addSpacing(10)

        # ── Theme picker ──────────────────────────────────────────────────────
        self._theme_icon = QLabel()
        self._theme_icon.setFixedSize(16, 16)
        layout.addWidget(self._theme_icon)
        layout.addSpacing(6)

        self.theme_combo = QComboBox()
        self.theme_combo.setObjectName("themeCombo")
        self.theme_combo.addItems(list(THEMES.keys()))
        self.theme_combo.setCurrentText(self.current_theme)
        # Wide enough for the longest palette name ("Black & Orange",
        # "Gunmetal Gold") without eliding, and tall enough in the popup to
        # list every palette rather than scrolling one row at a time.
        self.theme_combo.setFixedWidth(158)
        self.theme_combo.setMaxVisibleItems(len(THEMES))
        self.theme_combo.setCursor(QtGui.QCursor(Qt.CursorShape.PointingHandCursor))
        self.theme_combo.currentTextChanged.connect(self._on_theme_selected)
        layout.addWidget(self.theme_combo)

        layout.addSpacing(14)
        layout.addWidget(self._vdivider(24))
        layout.addSpacing(6)

        # ── Window controls ───────────────────────────────────────────────────
        self._win_buttons = []
        for icon_name, obj_name, handler in (
            ("minimize", "winBtn",      self.showMinimized),
            ("maximize", "winBtn",      self.toggle_maximize),
            ("close",    "winBtnClose", self.close),
        ):
            btn = QPushButton()
            btn.setObjectName(obj_name)
            btn.setFixedSize(36, 32)
            btn.setIconSize(QSize(15, 15))
            btn.setCursor(QtGui.QCursor(Qt.CursorShape.PointingHandCursor))
            btn.clicked.connect(handler)
            layout.addWidget(btn)
            self._win_buttons.append((btn, icon_name))

        bar.mousePressEvent = self.title_bar_mouse_press
        bar.mouseMoveEvent = self.title_bar_mouse_move
        bar.mouseReleaseEvent = self.title_bar_mouse_release
        bar.mouseDoubleClickEvent = lambda e: self.toggle_maximize()

        return bar

    def _build_target_pill(self):
        """Always-visible chip showing what the app is currently pointed at."""
        pill = QPushButton()
        pill.setObjectName("targetPill")
        pill.setFixedHeight(36)
        pill.setMinimumWidth(TARGET_PILL_MIN_WIDTH)
        pill.setCursor(QtGui.QCursor(Qt.CursorShape.PointingHandCursor))
        pill.setToolTip("Current target — click to open Target Setup")
        pill.clicked.connect(lambda: self.goto_tab("target"))

        inner = QHBoxLayout(pill)
        inner.setContentsMargins(12, 0, 14, 0)
        inner.setSpacing(9)

        self._target_pill_icon = QLabel()
        self._target_pill_icon.setFixedSize(14, 14)
        self._target_pill_icon.setAttribute(Qt.WidgetAttribute.WA_TransparentForMouseEvents)
        inner.addWidget(self._target_pill_icon)

        text_col = QVBoxLayout()
        text_col.setContentsMargins(0, 0, 0, 0)
        text_col.setSpacing(0)

        label = QLabel("TARGET")
        label.setObjectName("targetPillLabel")
        label.setAttribute(Qt.WidgetAttribute.WA_TransparentForMouseEvents)
        text_col.addWidget(label)
        self._target_pill_caption = label

        self.target_pill_value = QLabel("not set")
        self.target_pill_value.setObjectName("targetPillValue")
        self.target_pill_value.setProperty("empty", "true")
        self.target_pill_value.setAttribute(Qt.WidgetAttribute.WA_TransparentForMouseEvents)
        text_col.addWidget(self.target_pill_value)

        inner.addLayout(text_col)
        self._target_pill = pill
        self._target_pill_text = "not set"

        # Show and resize both change what will fit, and the first of them
        # arrives after the stylesheet has been applied — which is the point at
        # which the chip can finally be measured in the font it will be painted
        # in rather than the application default.
        if getattr(self, "_header_fit_watcher", None) is None:
            self._header_fit_watcher = _HeaderFitWatcher(self)
            self.installEventFilter(self._header_fit_watcher)

        return pill

    def update_target_display(self, target: str = None):
        """Refresh the header chip and status bar with the active target.

        The target is shown in full — you need to be able to read exactly what
        you are pointed at without hovering for a tooltip. The chip widens to
        fit, and only a pathologically long URL (one that would push the theme
        picker and window controls off the bar) gets elided, at which point
        the whole value is still on the tooltip.
        """
        value = (target if target is not None else getattr(self, "target", "")) or ""
        value = value.strip()
        shown = value if value else "not set"

        # Kept unabbreviated: every later re-fit measures this, never whatever
        # elided form happens to be on the label at the time.
        self._target_pill_text = shown

        if hasattr(self, "target_pill_value"):
            self.target_pill_value.setText(shown)
            self.target_pill_value.setProperty("empty", "false" if value else "true")
            self.target_pill_value.style().unpolish(self.target_pill_value)
            self.target_pill_value.style().polish(self.target_pill_value)
            self._fit_target_pill(shown)

        if hasattr(self, "_target_pill"):
            self._target_pill.setToolTip(
                f"Target: {value}" if value else "No target set — click to open Target Setup"
            )
        if hasattr(self, "_status_target"):
            # The status bar has the full width of the window to play with, so
            # it always carries the untruncated value.
            self._status_target.setText(shown)

    def refit_target_pill(self):
        """Re-measure the chip against the text it is actually showing.

        Called on show, on resize and after a theme change, because all three
        move the goalposts: the stylesheet gives the value label a monospace
        font that is wider than the application default, and the chip's ceiling
        scales with the window. Sizing it once during construction — before any
        stylesheet exists — is what used to leave the last character clipped.
        """
        if getattr(self, "_target_pill", None) is None:
            return
        self._fit_target_pill(getattr(self, "_target_pill_text", "") or "not set")

    def _text_width(self, label, text: str) -> int:
        """Width of ``text`` in the font the label will really be painted in."""
        if label is None or not text:
            return 0
        try:
            # Resolve the stylesheet font first; an unpolished widget still
            # reports the application default, which is narrower than the
            # monospace face the chip ends up using.
            label.ensurePolished()
            metrics = QtGui.QFontMetrics(label.font())
            # boundingRect covers ink that spills past the advance width;
            # horizontalAdvance covers the reverse case. Take whichever is
            # larger so neither kind of glyph gets shaved.
            return max(metrics.horizontalAdvance(text),
                       metrics.boundingRect(text).right() + 1)
        except Exception:
            return 0

    def _fit_target_pill(self, text: str):
        """Size the header chip to its contents, up to a sane ceiling."""
        pill = getattr(self, "_target_pill", None)
        label = getattr(self, "target_pill_value", None)
        if pill is None or label is None:
            return

        caption = getattr(self, "_target_pill_caption", None)
        # The caption is styled separately, so it must be measured in its own
        # font rather than the value's.
        caption_width = self._text_width(caption, "TARGET")

        # icon + layout margins + spacing around the text column
        chrome = 12 + 14 + 9 + 14 + 6 + TARGET_PILL_TEXT_PAD
        needed = max(self._text_width(label, text), caption_width) + chrome

        # Scale the ceiling with the window so the chip can take more room on a
        # wide screen without ever squeezing the controls on a narrow one.
        ceiling = min(TARGET_PILL_MAX_WIDTH, max(TARGET_PILL_MIN_WIDTH, int(self.width() * 0.38)))
        width = max(TARGET_PILL_MIN_WIDTH, min(needed, ceiling))
        pill.setFixedWidth(width)

        if needed > ceiling:
            # Only now do we shorten, and from the middle so both the scheme
            # and the host stay readable.
            available = max(0, ceiling - chrome)
            try:
                label.ensurePolished()
                metrics = QtGui.QFontMetrics(label.font())
                label.setText(
                    metrics.elidedText(text, Qt.TextElideMode.ElideMiddle, available)
                )
            except Exception:
                pass
        elif label.text() != text:
            # Undo an earlier elision now that the full value fits again.
            label.setText(text)

    def _on_theme_selected(self, name: str):
        if name and name != getattr(self, "current_theme", None):
            self.apply_theme(name)

    def _vdivider(self, height: int = 22):
        div = QFrame()
        div.setObjectName("headerDivider")
        div.setFrameShape(QFrame.Shape.VLine)
        div.setFixedHeight(height)
        return div

    def _refresh_header_theme(self):
        """Repaint header icons and the brand mark for the active palette."""
        accent = self.tc("accent")
        text = self.tc("text")
        dim = self.tc("text_dim")

        if hasattr(self, "_brand_mark"):
            self._brand_mark.setPixmap(icons.icon_pixmap("bolt", accent, 17))
            self._brand_mark.setStyleSheet(
                f"background-color: {rgba(accent, 0.16)};"
                f"border: 1px solid {rgba(accent, 0.35)};"
                f"border-radius: 7px;"
            )
        if hasattr(self, "_theme_icon"):
            self._theme_icon.setPixmap(icons.icon_pixmap("droplet", dim, 14))
        if hasattr(self, "_target_pill_icon"):
            self._target_pill_icon.setPixmap(icons.icon_pixmap("target", accent, 14))

        for btn, icon_name in getattr(self, "_win_buttons", []):
            colour = "#ffffff" if icon_name == "close" else text
            btn.setIcon(icons.icon(icon_name, colour if icon_name != "close" else text, 15, 1.7))

        if hasattr(self, "theme_combo"):
            self.theme_combo.blockSignals(True)
            self.theme_combo.setCurrentText(self.current_theme)
            self.theme_combo.blockSignals(False)

        # A new stylesheet can mean a new font on the chip, so re-measure it —
        # once the style has actually been applied, not in the middle of it.
        QTimer.singleShot(0, self.refit_target_pill)

    # ══════════════════════════════════════════════════════════════════════════
    #  NAVIGATION RAIL
    # ══════════════════════════════════════════════════════════════════════════

    def create_nav_rail(self):
        rail = QWidget()
        rail.setObjectName("navRail")
        self.nav_rail = rail

        self._rail_expanded = bool(self.load_rail_preference())
        rail.setFixedWidth(RAIL_WIDTH_EXPANDED if self._rail_expanded else RAIL_WIDTH_COMPACT)

        layout = QVBoxLayout(rail)
        layout.setContentsMargins(8, 10, 8, 10)
        layout.setSpacing(2)

        self._nav_buttons = {}
        self._nav_icon_labels = {}
        self._nav_text_labels = {}
        self._nav_section_labels = []
        self._nav_compact_dividers = []

        # Collapse / expand toggle
        toggle_row = QHBoxLayout()
        toggle_row.setContentsMargins(0, 0, 0, 0)
        self._rail_toggle = QPushButton()
        self._rail_toggle.setObjectName("railToggle")
        self._rail_toggle.setFixedSize(34, 30)
        self._rail_toggle.setIconSize(QSize(17, 17))
        self._rail_toggle.setCursor(QtGui.QCursor(Qt.CursorShape.PointingHandCursor))
        self._rail_toggle.setToolTip("Collapse / expand the navigation rail")
        self._rail_toggle.clicked.connect(self.toggle_rail)
        toggle_row.addWidget(self._rail_toggle)
        toggle_row.addStretch()
        layout.addLayout(toggle_row)
        layout.addSpacing(6)

        # Workflow sections
        current_section = None
        for key, short, full, hint, icon_name, section in TABS:
            if section == "PINNED":
                continue
            if section != current_section:
                current_section = section
                caption = QLabel(section)
                caption.setObjectName("navSectionLabel")
                caption.setFixedHeight(22)
                layout.addWidget(caption)
                self._nav_section_labels.append(caption)

                divider = QFrame()
                divider.setObjectName("railSeparator")
                divider.setFixedHeight(1)
                layout.addWidget(divider)
                self._nav_compact_dividers.append(divider)

            layout.addWidget(self._create_nav_item(key, short, full, icon_name))

        layout.addStretch()

        # Pinned group — destinations rather than workflow steps
        pinned_divider = QFrame()
        pinned_divider.setObjectName("railSeparator")
        pinned_divider.setFixedHeight(1)
        layout.addWidget(pinned_divider)
        layout.addSpacing(6)

        for key, short, full, hint, icon_name, section in TABS:
            if section == "PINNED":
                layout.addWidget(self._create_nav_item(key, short, full, icon_name))

        self._apply_rail_mode()
        return rail

    def _create_nav_item(self, key: str, short: str, full: str, icon_name: str):
        btn = QPushButton()
        btn.setObjectName("navItem")
        btn.setCheckable(True)
        btn.setFixedHeight(42)
        btn.setToolTip(full)
        btn.setCursor(QtGui.QCursor(Qt.CursorShape.PointingHandCursor))
        btn.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Fixed)

        inner = QHBoxLayout(btn)
        inner.setContentsMargins(13, 0, 10, 0)
        inner.setSpacing(12)

        icon_label = QLabel()
        icon_label.setFixedSize(20, 20)
        icon_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        icon_label.setAttribute(Qt.WidgetAttribute.WA_TransparentForMouseEvents)
        inner.addWidget(icon_label)

        text_label = QLabel(short)
        text_label.setAttribute(Qt.WidgetAttribute.WA_TransparentForMouseEvents)
        inner.addWidget(text_label)
        inner.addStretch()

        btn.clicked.connect(lambda _checked, k=key: self.goto_tab(k))

        self._nav_buttons[key] = btn
        self._nav_icon_labels[key] = (icon_label, icon_name)
        self._nav_text_labels[key] = text_label
        return btn

    def toggle_rail(self):
        """Animate the rail between compact and expanded."""
        self._rail_expanded = not getattr(self, "_rail_expanded", True)
        self.save_rail_preference(self._rail_expanded)

        start = self.nav_rail.width()
        end = RAIL_WIDTH_EXPANDED if self._rail_expanded else RAIL_WIDTH_COMPACT

        if self._rail_expanded:
            self._apply_rail_mode()  # reveal labels before widening

        anim = QVariantAnimation(self)
        anim.setDuration(150)
        anim.setStartValue(start)
        anim.setEndValue(end)
        anim.setEasingCurve(QEasingCurve.Type.InOutCubic)
        anim.valueChanged.connect(lambda v: self.nav_rail.setFixedWidth(int(v)))
        if not self._rail_expanded:
            anim.finished.connect(self._apply_rail_mode)  # hide labels after
        anim.start()
        self._rail_anim = anim  # keep a reference alive

    def _apply_rail_mode(self):
        """Show or hide rail labels/captions for the current mode."""
        expanded = getattr(self, "_rail_expanded", True)

        for label in getattr(self, "_nav_text_labels", {}).values():
            label.setVisible(expanded)
        for caption in getattr(self, "_nav_section_labels", []):
            caption.setVisible(expanded)
        for divider in getattr(self, "_nav_compact_dividers", []):
            divider.setVisible(not expanded)

        for btn in getattr(self, "_nav_buttons", {}).values():
            inner = btn.layout()
            if inner is not None:
                inner.setContentsMargins(13, 0, 10, 0) if expanded else inner.setContentsMargins(0, 0, 0, 0)
                for i in range(inner.count()):
                    item = inner.itemAt(i)
                    if item.widget() is not None and isinstance(item.widget(), QLabel) \
                            and item.widget().width() == 20:
                        inner.setAlignment(item.widget(), Qt.AlignmentFlag.AlignCenter)

    def _refresh_rail_theme(self):
        """Tint rail icons and labels for the active palette and selection."""
        accent = self.tc("accent")
        text = self.tc("text")
        dim = self.tc("text_dim")

        if hasattr(self, "_rail_toggle"):
            self._rail_toggle.setIcon(icons.icon("panel_left", dim, 17, 1.8))

        for key, btn in getattr(self, "_nav_buttons", {}).items():
            active = btn.isChecked()
            icon_label, icon_name = self._nav_icon_labels[key]
            colour = accent if active else dim
            icon_label.setPixmap(icons.icon_pixmap(icon_name, colour, 19, 1.85))

            text_label = self._nav_text_labels[key]
            text_label.setStyleSheet(
                f"background: transparent; font-size: 12.5px;"
                f"font-weight: {'700' if active else '500'};"
                f"color: {accent if active else text};"
            )

    def _nav_activate(self, index: int, init: bool = False):
        """Select a tab by index and sync rail + breadcrumb."""
        keys = list(getattr(self, "_tab_index", {}).keys())
        active_key = None
        for key in keys:
            if self._tab_index[key] == index:
                active_key = key
                break

        for key, btn in getattr(self, "_nav_buttons", {}).items():
            btn.setChecked(key == active_key)
        self._refresh_rail_theme()

        meta = getattr(self, "_tab_meta", {}).get(active_key)
        if meta and hasattr(self, "section_title_label"):
            self.section_title_label.setText(meta["title"])
            self.section_hint_label.setText(meta["hint"])

        if not init and self.tab_widget.currentIndex() != index:
            self.tab_widget.setCurrentIndex(index)

    # Legacy alias (older call sites used _nav_rail_activate)
    def _nav_rail_activate(self, index, full_name=None, init=False):
        self._nav_activate(index, init=init)

    # ══════════════════════════════════════════════════════════════════════════
    #  BOTTOM STATUS BAR
    # ══════════════════════════════════════════════════════════════════════════

    def create_bottom_status_bar(self):
        bar = QWidget()
        bar.setObjectName("bottomStatusBar")
        bar.setFixedHeight(STATUSBAR_HEIGHT)

        layout = QHBoxLayout(bar)
        layout.setContentsMargins(12, 0, 12, 0)
        layout.setSpacing(10)

        self._status_dot = QLabel()
        self._status_dot.setFixedSize(9, 9)
        layout.addWidget(self._status_dot)

        self.status_label = QLabel("READY")
        self.status_label.setObjectName("statusLabel")
        layout.addWidget(self.status_label)

        layout.addWidget(self._status_sep())

        self._status_tool = QLabel("idle")
        self._status_tool.setObjectName("statusMetaStrong")
        layout.addWidget(self._status_tool)

        layout.addWidget(self._status_sep())

        self._status_elapsed = QLabel("00:00")
        self._status_elapsed.setObjectName("statusMetaStrong")
        layout.addWidget(self._status_elapsed)

        layout.addStretch()

        target_caption = QLabel("TARGET")
        target_caption.setObjectName("statusMeta")
        layout.addWidget(target_caption)

        self._status_target = QLabel("not set")
        self._status_target.setObjectName("statusMetaStrong")
        layout.addWidget(self._status_target)

        layout.addWidget(self._status_sep())

        out_caption = QLabel("OUTPUT")
        out_caption.setObjectName("statusMeta")
        layout.addWidget(out_caption)

        self._status_output = QLabel(str(getattr(self, "output_dir", "")))
        self._status_output.setObjectName("statusMetaStrong")
        self._status_output.setToolTip("Output directory")
        layout.addWidget(self._status_output)

        self.update_output_display()
        return bar

    def _status_sep(self):
        sep = QFrame()
        sep.setObjectName("statusSep")
        sep.setFrameShape(QFrame.Shape.VLine)
        sep.setFixedHeight(12)
        return sep

    def set_status_state(self, state: str, tool: str = None):
        """Set the status bar state: idle / running / ok / error / stopped."""
        role, label = _STATUS_STATES.get(state, _STATUS_STATES["idle"])
        colour = self.tc(role)

        if hasattr(self, "status_label"):
            self.status_label.setText(label)
            self.status_label.setStyleSheet(
                f"background: transparent; font-size: 11px; font-weight: 700;"
                f"letter-spacing: 0.4px; color: {colour};"
            )
        if hasattr(self, "_status_dot"):
            self._status_dot.setPixmap(icons.icon_pixmap("dot", colour, 9))
        if tool is not None and hasattr(self, "_status_tool"):
            self._status_tool.setText(tool or "idle")
        self._status_state = state

    def flash_status(self, message: str, seconds: float = 2.5):
        """Briefly show a transient message, then restore the run state.

        Used for confirmations like "PAYLOAD COPIED" that shouldn't
        permanently overwrite whether a scan is running.
        """
        if not hasattr(self, "status_label"):
            return
        self.status_label.setText(str(message).upper())
        self.status_label.setStyleSheet(
            f"background: transparent; font-size: 11px; font-weight: 700;"
            f"letter-spacing: 0.4px; color: {self.tc('accent')};"
        )
        QTimer.singleShot(
            int(seconds * 1000),
            lambda: self.set_status_state(getattr(self, "_status_state", "idle")),
        )

    def update_status_elapsed(self, text: str):
        if hasattr(self, "_status_elapsed"):
            self._status_elapsed.setText(text)

    def update_output_display(self):
        """Show a shortened output directory in the status bar."""
        if not hasattr(self, "_status_output"):
            return
        full = str(getattr(self, "output_dir", "") or "")
        parts = [p for p in full.replace("\\", "/").split("/") if p]
        short = "/".join(parts[-2:]) if len(parts) > 2 else full
        self._status_output.setText(short or "—")
        self._status_output.setToolTip(full)

    def _refresh_status_theme(self):
        self.set_status_state(getattr(self, "_status_state", "idle"))

    # ══════════════════════════════════════════════════════════════════════════
    #  CONTENT AREA
    # ══════════════════════════════════════════════════════════════════════════

    def create_content_area(self):
        """Build every tab, then insert them in the order defined by TABS."""
        self.tab_widget = QTabWidget()
        self.tab_widget.setObjectName("contentTabs")
        self.tab_widget.tabBar().hide()

        # Build first (safe order), insert second (display order).
        #
        # Each builder is guarded. A tab that raises while being constructed
        # used to take the whole window with it — the application simply did
        # not open, with the traceback going to a log the user had no reason
        # to look in. One broken tab should cost you that tab, not the
        # engagement, so the failure is caught, shown in its place, and the
        # other eight tabs still work.
        built = {}
        for key in _SAFE_BUILD_ORDER:
            builder = getattr(self, _TAB_BUILDERS[key], None)
            if builder is None:
                continue
            try:
                built[key] = builder()
            except Exception:
                import traceback
                built[key] = self._broken_tab(key, traceback.format_exc())

        self._tab_index = {}
        self._tab_meta = {}
        for key, short, full, hint, icon_name, section in TABS:
            widget = built.get(key)
            if widget is None:
                continue
            index = self.tab_widget.addTab(widget, full)
            self._tab_index[key] = index
            self._tab_meta[key] = {"title": full, "hint": hint, "short": short}

        self.tab_widget.currentChanged.connect(self._on_tab_index_changed)
        return self.tab_widget

    def _broken_tab(self, key: str, trace: str):
        """Stand-in for a tab whose builder raised, showing why.

        Deliberately built from the plainest widgets available: whatever broke
        might be the very thing this would otherwise depend on.
        """
        from PyQt6.QtWidgets import (QWidget, QVBoxLayout, QLabel, QTextEdit,
                                     QPushButton, QApplication)

        page = QWidget()
        box = QVBoxLayout(page)
        box.setContentsMargins(30, 30, 30, 30)
        box.setSpacing(12)

        title = QLabel(f"The {key} tab could not be built")
        title.setStyleSheet("font-size: 17px; font-weight: 600; color: #ff6b6b;")
        box.addWidget(title)

        blurb = QLabel(
            "The rest of the application is unaffected. This is the error, "
            "which is also in ~/.config/CommandBridge/errors.log — send it on "
            "and it can be fixed.")
        blurb.setWordWrap(True)
        blurb.setStyleSheet("color: palette(mid);")
        box.addWidget(blurb)

        detail = QTextEdit()
        detail.setReadOnly(True)
        detail.setPlainText(trace)
        detail.setStyleSheet("font-family: monospace; font-size: 12px;")
        box.addWidget(detail, 1)

        copy = QPushButton("Copy the error")
        copy.clicked.connect(
            lambda: QApplication.clipboard().setText(trace))
        box.addWidget(copy)

        # And to stderr, so a terminal launch shows it without clicking about.
        import sys
        sys.stderr.write(f"\n[Command Bridge] the {key} tab failed to "
                         f"build:\n{trace}\n")
        try:
            from pathlib import Path
            from datetime import datetime
            log = Path.home() / ".config" / "CommandBridge" / "errors.log"
            log.parent.mkdir(parents=True, exist_ok=True)
            with open(log, "a", encoding="utf-8") as handle:
                handle.write(f"\n===== {datetime.now():%Y-%m-%d %H:%M:%S} "
                             f"tab '{key}' failed to build =====\n{trace}")
        except Exception:
            pass
        return page

    def _on_tab_index_changed(self, index: int):
        self._nav_activate(index, init=True)
