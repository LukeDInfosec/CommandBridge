"""
Card helpers — create_card, collapsible sections, editable buttons.
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


# Leading decorative glyphs (emoji, dingbats, symbol pictographs) that used to
# prefix card titles, section labels and button captions. They render at a
# different size and colour on every platform and read as consumer software,
# so the chrome strips them and relies on typography + the drawn icon set
# instead. Only a LEADING run is removed — an arrow or symbol in the middle of
# a label ("Nmap → TestSSL") is meaningful and is left alone.
_LEADING_GLYPH_RE = re.compile(
    r"^(?:[\U0001F000-\U0001FAFF\U00002190-\U000021FF\U00002300-\U000023FF"
    r"\U000025A0-\U000027BF\U00002B00-\U00002BFF\U0000FE00-\U0000FE0F"
    r"\U0001F1E6-\U0001F1FF•·]️?\s*)+"
)


def strip_leading_glyphs(text: str) -> str:
    """Remove decorative leading emoji/symbols from a UI string."""
    if not text:
        return text
    cleaned = _LEADING_GLYPH_RE.sub("", text).strip()
    return cleaned or text


class CardsMixin:
    """Mixin providing card helpers — create_card, collapsible sections, editable buttons."""

    def create_card(self, title):
        """Create a styled card.

        The title renders as a small uppercase eyebrow inside the card's top
        edge (see QGroupBox#card in theme.py) rather than as a floating pill
        on the border, which is what made the old cards look like a 2015
        dashboard.

        Two details worth keeping: QGroupBox treats a lone '&' as a mnemonic
        marker (so "Fuzzing & Directory Enumeration" rendered as "Fuzzing
        Directory Enumeration" with an underlined space) — it has to be
        escaped to '&&'. And decorative leading emoji are stripped so every
        card header shares one typographic voice.
        """
        clean = strip_leading_glyphs(title or "")
        card = QGroupBox(clean.upper().replace("&", "&&") if clean else clean)
        card.setObjectName("card")
        card.setFlat(True)
        # Escaping '&' as '&&' makes Qt measure a wider title than it paints,
        # which nudged these headings right of every other card. The stylesheet
        # cancels it out per ampersand — see _ampersand_shift() in theme.py.
        card.setProperty("ampCount", clean.count("&"))

        card_layout = QVBoxLayout()
        # Top margin clears the inset title; the rest sits on the 8px grid.
        card_layout.setContentsMargins(20, 46, 20, 20)
        card_layout.setSpacing(14)
        card.setLayout(card_layout)
        return card

    def polish_ui_text(self):
        """Strip decorative leading emoji from every label and button.

        Runs once after the UI is built. Doing it as a sweep rather than
        editing every tab file keeps the nine tab modules focused on what
        they actually do — wiring commands to buttons — while still giving
        the whole app a single, consistent typographic voice.
        """
        try:
            for button in self.findChildren(QtWidgets.QAbstractButton):
                original = button.text()
                cleaned = strip_leading_glyphs(original)
                # Qt eats a lone '&' as a mnemonic marker, so "JS Recon &
                # Analysis" rendered as "JS Recon _Analysis". Escaping to
                # '&&' prints a literal ampersand.
                if "&" in cleaned and "&&" not in cleaned:
                    cleaned = cleaned.replace("&", "&&")
                if cleaned != original:
                    button.setText(cleaned)

            for label in self.findChildren(QLabel):
                original = label.text()
                if not original or "<" in original:  # leave rich text alone
                    continue
                cleaned = strip_leading_glyphs(original)
                if cleaned != original:
                    label.setText(cleaned)

            for box in self.findChildren(QGroupBox):
                original = box.title()
                cleaned = strip_leading_glyphs(original)
                if cleaned != original:
                    box.setTitle(cleaned.upper() if box.objectName() == "card" else cleaned)
        except Exception as e:
            print(f"UI text polish skipped: {e}")

    def _sections_state_path(self):
        """Return path to JSON file storing collapsible section states."""
        config_dir = Path.home() / ".config" / "CommandBridge"
        config_dir.mkdir(parents=True, exist_ok=True)
        return config_dir / "sections.json"

    def _load_sections_state(self):
        """Load persisted section expand/collapse state from disk."""
        try:
            path = self._sections_state_path()
            if path.exists():
                with open(path, "r", encoding="utf-8", errors="replace") as f:
                    data = json.load(f)
                if isinstance(data, dict):
                    return data
        except Exception as e:
            print(f"Error loading sections state: {e}")
        return {}

    def _get_section_state(self, key: str, default: bool = True) -> bool:
        """Get last-known expanded/collapsed state for a section key."""
        state = getattr(self, "_sections_state_cache", None)
        if state is None:
            state = self._load_sections_state()
            self._sections_state_cache = state
        return bool(state.get(key, default))

    def _save_section_state(self, key: str, expanded: bool):
        """Persist expanded/collapsed state for a section key."""
        try:
            path = self._sections_state_path()
            state = getattr(self, "_sections_state_cache", None)
            if state is None:
                state = self._load_sections_state()
            state[key] = bool(expanded)
            self._sections_state_cache = state
            with open(path, "w", encoding="utf-8", errors="replace") as f:
                json.dump(state, f)
        except Exception as e:
            print(f"Error saving sections state: {e}")

    def _init_collapsible_groupbox(self, groupbox: QGroupBox, state_key: str):
        """Make a QGroupBox collapsible and persist its state.

        This uses the QGroupBox's checkable feature to show/hide its child
        widgets while keeping the header visible. The last expanded/collapsed
        state is saved in sections.json.
        """
        try:
            groupbox.setCheckable(True)
            # A checkable QGroupBox reserves horizontal space for its
            # indicator *before* the title, which pushed every collapsible
            # card's heading ~20px right of the content beneath it. The
            # stylesheet compensates via this dynamic property (see
            # QGroupBox#card[collapsible="true"]::title in theme.py) so the
            # chevron sits in the card's left gutter and the title text
            # lines up on the same 20px rail as the content.
            groupbox.setProperty("collapsible", True)
        except Exception:
            return

        expanded = self._get_section_state(state_key, True)
        groupbox.setChecked(expanded)

        def on_toggled(checked: bool):
            # Show/hide all child widgets inside the groupbox
            for child in groupbox.findChildren(QWidget):
                if child is groupbox:
                    continue
                child.setVisible(checked)
            self._save_section_state(state_key, checked)

        groupbox.toggled.connect(on_toggled)
        on_toggled(expanded)

    def create_editable_button(self, name, button_id, default_cmd):
        """Create a button with right-click menu to edit command.

        The button automatically gets a hover tooltip describing what the
        underlying command does, including any obvious output files (e.g.
        {SAFE_TARGET}_nmap_quick.txt). This gives the user inline guidance
        without having to right-click or open the editor.
        """
        btn = QPushButton(strip_leading_glyphs(name))
        btn.setObjectName("secondaryButton")
        btn.setMinimumHeight(38)
        btn.setMaximumHeight(42)

        # Store the command (so we can use it in tooltips and execution)
        if button_id not in self.command_registry:
            self.command_registry[button_id] = default_cmd

        # Remember the caption so the console can report "[Quick Nmap] has
        # been completed" rather than naming whichever binary happened to come
        # first in the pipeline. See get_action_display_name() in core/status.py.
        if not hasattr(self, "button_labels"):
            self.button_labels = {}
        self.button_labels[button_id] = strip_leading_glyphs(name)
        cmd_for_tooltip = self.command_registry[button_id]

        # Attach an informative tooltip built from the command template.
        try:
            tooltip_text = self._build_tooltip_from_command(name, cmd_for_tooltip)
            if tooltip_text:
                btn.setToolTip(tooltip_text)
        except Exception:
            # Tooltip generation is best-effort; never break button creation.
            pass

        # For fuzzing tools (Dirsearch / FFUF / Feroxbuster / Gobuster),
        # left-click should *either* open the quick-select menu (if not yet
        # configured) or execute the configured command (if already
        # configured). Right-click always opens the quick-select menu to
        # reconfigure.
        if button_id in ("web_dirsearch", "web_ffuf", "web_feroxbuster", "web_gobuster"):
            btn.clicked.connect(
                lambda checked, b=btn, bid=button_id, def_cmd=default_cmd: self._on_fuzzing_button_clicked(b, bid, def_cmd)
            )
        elif button_id == "web_retrieve_js":
            # Two-stage button: run the (editable) wget command, then analyse
            # the JavaScript it pulled down. See run_retrieve_and_analyse_js().
            btn.clicked.connect(lambda checked: self.run_retrieve_and_analyse_js())
        elif button_id == "web_wpscan_full":
            # WordPress Scan (WPScan) – left-click runs the currently selected
            # profile, right-click opens a dedicated menu with quick profiles
            # (fast / normal / deep) plus a manual editor.
            btn.clicked.connect(lambda checked, bid=button_id: self.run_command_from_registry(bid))
            btn.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
            btn.customContextMenuRequested.connect(
                lambda pos, b=btn, bid=button_id, def_cmd=default_cmd: self.show_wpscan_menu(b, bid, def_cmd, pos)
            )
            return btn
        else:
            # Left-click runs the command for non-fuzzing tools
            btn.clicked.connect(lambda checked, bid=button_id: self.run_command_from_registry(bid))
        
        # Right-click opens edit dialog / quick-select menu
        btn.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        btn.setCursor(QtGui.QCursor(QtCore.Qt.CursorShape.PointingHandCursor))
        btn.customContextMenuRequested.connect(
            lambda pos, b=btn, bid=button_id, def_cmd=default_cmd: self.show_command_editor(b, bid, def_cmd)
        )
        
        return btn

    def _build_tooltip_from_command(self, label: str, cmd_template: str) -> str:
        """Generate a short hover description from a command template.

        - Shows the primary tool being run (nmap, sqlmap, wpscan, etc.).
        - Lists obvious output files (e.g. -o file, --logfile file, > file).
        - Keeps placeholders like {SAFE_TARGET} so the user sees the pattern.
        """
        import re
        import shlex

        if not cmd_template:
            return ""

        raw = cmd_template.strip()

        # Strip common wrappers so we can see the real tool name
        for prefix in ("yes |", "stdbuf -oL -eL"):
            if raw.startswith(prefix):
                raw = raw[len(prefix):].lstrip()

        # Best-effort extraction of the primary tool name
        tool = ""
        try:
            tokens = shlex.split(raw)
            if tokens:
                tool = tokens[0]
        except Exception:
            parts = raw.split()
            if parts:
                tool = parts[0]

        # If the first token is "echo" in a pipeline, try to find a better tool
        if tool == "echo":
            for candidate in [
                "nmap", "rustscan", "testssl", "sqlmap", "wpscan", "ffuf",
                "feroxbuster", "dirsearch", "gobuster", "dalfox", "subfinder",
                "amass", "httpx-toolkit", "httpx", "gau", "katana", "nuclei",
                "ghauri", "corsy", "hakrawler", "dnsx", "subzy", "uro",
                "Gxss", "kxss", "waybackurls", "urldedupe",
            ]:
                if re.search(rf"\b{candidate}\b", cmd_template):
                    tool = candidate
                    break

        # Collect obvious output files
        outputs: set[str] = set()
        patterns = [
            r"-o\s+([^\s|;]+)",
            r"-oN\s+([^\s|;]+)",
            r"--logfile\s+([^\s|;]+)",
            r"--jsonfile\s+([^\s|;]+)",
            r"--log\s+([^\s|;]+)",
            r">\s*([^\s|;]+)",
        ]
        for pat in patterns:
            for m in re.findall(pat, cmd_template):
                if isinstance(m, tuple):
                    m = m[-1]
                if m:
                    outputs.add(m)

        # Build human-friendly description
        lines = []
        if tool:
            lines.append(f"Runs: {tool} against the current target.")
        else:
            lines.append("Runs a custom command against the current target.")

        if outputs:
            lines.append("")
            lines.append("Creates/updates:")
            for out in sorted(outputs):
                lines.append(f"  • {out}")

        # Fallback: if we couldn't detect any outputs and tool name is generic,
        # still show (a trimmed) command preview so the user has context.
        if len(lines) <= 1:
            preview = cmd_template.replace("\n", " ")
            if len(preview) > 140:
                preview = preview[:137] + "..."
            lines.append(f"Command: {preview}")

        return "\n".join(lines)
