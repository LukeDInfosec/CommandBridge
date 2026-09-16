"""Theme engine — design tokens in, application stylesheet out.

The whole visual language of Command Bridge lives in this file. Widgets set an
objectName; this module decides what that objectName looks like in every
palette. Nothing here knows about pentesting, and nothing in the feature code
should know about colours.

Layout rules the stylesheet enforces:
  · 8px spacing grid, 10px corner radius on surfaces, 8px on controls
  · one accent colour per theme, used for state — never for decoration
  · hairline borders instead of shadows (Qt has no real box-shadow)
  · semantic colours (success / warning / danger) identical across themes
"""

from __future__ import annotations

import re as _re

from PyQt6 import QtGui, QtWidgets
from PyQt6.QtWidgets import QMessageBox

from command_bridge.constants import (
    THEMES, DEFAULT_THEME, FONT_STACK_UI, FONT_STACK_MONO, theme_value,
)
from command_bridge.ui import icons


# ══════════════════════════════════════════════════════════════════════════════
#  Colour helpers
# ══════════════════════════════════════════════════════════════════════════════

def rgba(hex_color: str, alpha: float) -> str:
    """Return an rgba() string for a #RRGGBB colour at `alpha` (0.0 – 1.0).

    Qt parses #RRGGBBAA as #AARRGGBB (alpha first), so an 8-digit hex whose red
    channel is 00 silently renders fully transparent. Emitting rgba() avoids
    that trap entirely.
    """
    try:
        h = str(hex_color).lstrip("#")
        r, g, b = int(h[0:2], 16), int(h[2:4], 16), int(h[4:6], 16)
        return f"rgba({r}, {g}, {b}, {max(0.0, min(1.0, alpha)):.3f})"
    except Exception:
        return str(hex_color)


def mix(color_a: str, color_b: str, weight: float) -> str:
    """Blend two hex colours; weight 0.0 = all A, 1.0 = all B."""
    try:
        a = str(color_a).lstrip("#")
        b = str(color_b).lstrip("#")
        ar, ag, ab = int(a[0:2], 16), int(a[2:4], 16), int(a[4:6], 16)
        br, bg, bb = int(b[0:2], 16), int(b[2:4], 16), int(b[4:6], 16)
        w = max(0.0, min(1.0, weight))
        return "#{:02x}{:02x}{:02x}".format(
            round(ar + (br - ar) * w),
            round(ag + (bg - ag) * w),
            round(ab + (bb - ab) * w),
        )
    except Exception:
        return color_a


def lighten(color: str, amount: float) -> str:
    return mix(color, "#ffffff", amount)


def darken(color: str, amount: float) -> str:
    return mix(color, "#000000", amount)


#: Stylesheet fragment used to calibrate the ampersand drift. It mirrors the
#: real QGroupBox#card::title rule so the probe measures the same typography.
_AMP_PROBE_QSS = """
QGroupBox#ampProbe {
    background: #ffffff; border: none; margin-top: 0px; padding: 0px;
}
QGroupBox#ampProbe::title {
    subcontrol-origin: padding; subcontrol-position: top left;
    left: 20px; top: 2px; padding: 0px; color: #000000;
    font-size: 13.5px; font-weight: 700; letter-spacing: 0.6px;
}
"""

_AMP_SHIFT_CACHE: dict = {}


def _ampersand_shift(widget) -> int:
    """Pixels a card title drifts right for each '&' it contains.

    QGroupBox titles have to escape '&' as '&&' (a lone '&' is swallowed as a
    mnemonic marker). Qt then sizes the title rect from the escaped string but
    paints the unescaped one centred inside it, so any card named "Fuzzing &
    Directory Enumeration" hung a few pixels right of its neighbours.

    The exact drift depends on the font that actually resolved and on Qt's
    internal rounding, so rather than model it this renders two offscreen
    probes — "H&&H" and "HH", same opening glyph, so only the ampersand
    differs — and measures where the ink starts in each. Cached per font,
    which means one pair of 320x40 grabs for the whole session.
    """
    try:
        key = widget.font().toString()
    except Exception:
        return 0
    if key in _AMP_SHIFT_CACHE:
        return _AMP_SHIFT_CACHE[key]

    def _first_ink(title: str):
        box = QtWidgets.QGroupBox(title)
        box.setObjectName("ampProbe")
        box.setFlat(True)
        box.setStyleSheet(_AMP_PROBE_QSS)
        box.resize(320, 40)
        image = box.grab().toImage()
        for x in range(image.width()):
            for y in range(image.height()):
                if QtGui.QColor(image.pixel(x, y)).red() < 140:
                    return x
        return None

    shift = 0
    try:
        with_amp = _first_ink("H&&H")
        without = _first_ink("HH")
        if with_amp is not None and without is not None:
            shift = max(0, min(with_amp - without, 12))
    except Exception:
        shift = 0

    _AMP_SHIFT_CACHE[key] = shift
    return shift


def _fix_alpha_hex(css: str) -> str:
    """Convert any leftover 8-digit hex colours in a stylesheet to rgba().

    Retained so hand-written snippets elsewhere in the codebase keep working;
    new code should call rgba() directly.
    """
    def _sub(m: _re.Match) -> str:
        h = m.group(0)[1:]
        r, g, b, a = int(h[0:2], 16), int(h[2:4], 16), int(h[4:6], 16), int(h[6:8], 16)
        return f"rgba({r}, {g}, {b}, {a / 255:.3f})"
    return _re.sub(r'#[0-9A-Fa-f]{8}(?![0-9A-Fa-f])', _sub, css)


# ══════════════════════════════════════════════════════════════════════════════
#  Theme mixin
# ══════════════════════════════════════════════════════════════════════════════

class ThemeMixin:
    """Applies a palette to the whole application."""

    # ── Palette access ────────────────────────────────────────────────────────

    def theme(self) -> dict:
        """Current palette dict (falls back to the default theme)."""
        name = getattr(self, "current_theme", DEFAULT_THEME)
        return THEMES.get(name, THEMES[DEFAULT_THEME])

    def tc(self, role: str, fallback: str = "#808080") -> str:
        """Theme colour for a palette role, e.g. self.tc('accent')."""
        return theme_value(self.theme(), role, fallback)

    # ── Main entry point ──────────────────────────────────────────────────────

    def apply_theme(self, theme_name: str):
        """Apply a palette to every widget in the application."""
        if theme_name not in THEMES:
            theme_name = DEFAULT_THEME

        self.current_theme = theme_name
        t = THEMES[theme_name]
        self.save_theme_preference(theme_name)
        icons.clear_cache()

        # ── Roles ─────────────────────────────────────────────────────────────
        bg            = t["bg"]
        nav_bg        = t["nav_bg"]
        panel_bg      = t["panel_bg"]
        card_bg       = t["card_bg"]
        surface       = theme_value(t, "surface")
        console_bg    = t["console_bg"]
        border        = t["border"]
        border_strong = theme_value(t, "border_strong")
        hover         = t["hover"]
        text          = t["text"]
        text_dim      = theme_value(t, "text_dim")
        heading       = theme_value(t, "heading")
        accent        = t["accent"]
        success       = t["success"]
        warning       = t["warning"]
        danger        = theme_value(t, "danger")
        is_light      = bool(t.get("is_light", False))

        # Derived
        accent_text   = "#0b0f14" if is_light is False and _is_bright(accent) else "#ffffff"
        accent_hover  = lighten(accent, 0.12) if not is_light else darken(accent, 0.08)
        accent_press  = darken(accent, 0.16)
        accent_tint   = rgba(accent, 0.14)
        accent_tint_2 = rgba(accent, 0.22)
        danger_hover  = lighten(danger, 0.10)
        scroll_handle = mix(border_strong, text, 0.12)

        # Icon assets for stylesheet-only controls (Qt can't recolour images,
        # so each palette writes its own PNGs into the user cache).
        chev_down  = icons.icon_png("chevron_down", text_dim, 12, 2.2)
        chev_down_a = icons.icon_png("chevron_down", accent, 12, 2.2)
        chev_right = icons.icon_png("chevron_right", text_dim, 12, 2.2)
        tick       = icons.icon_png("check", accent_text, 12, 2.4)

        # ── Ampersand title compensation ──────────────────────────────────────
        # A QGroupBox title needs '&' escaped to '&&' (a lone '&' is eaten as a
        # mnemonic marker). Qt then sizes the title rect from the *escaped*
        # string but paints the *unescaped* one, centred inside that rect — so
        # every card whose name contains '&' ("Fuzzing & Directory Enumeration")
        # drew its heading a few pixels right of every other card. The shift is
        # exactly half an ampersand's advance per '&', which depends on whichever
        # UI font actually resolved, so it is measured here rather than guessed.
        amp_shift = _ampersand_shift(self)
        amp_rules = "\n".join(
            f"QGroupBox#card[ampCount=\"{n}\"]::title {{ left: {20 - amp_shift * n}px; }}\n"
            f"QGroupBox#card[collapsible=\"true\"][ampCount=\"{n}\"]::title "
            f"{{ left: {4 - amp_shift * n}px; }}"
            for n in (1, 2, 3)
        )

        stylesheet = f"""
/* ══════════════════════════════════════════════════════════════════
   BASE
══════════════════════════════════════════════════════════════════ */
QWidget {{
    background-color: {bg};
    color: {text};
    font-family: {FONT_STACK_UI};
    font-size: 13px;
}}
QMainWindow, #appBody {{ background-color: {bg}; }}

QToolTip {{
    background-color: {card_bg};
    color: {text};
    border: 1px solid {border_strong};
    border-radius: 8px;
    padding: 7px 10px;
    font-size: 12px;
}}

/* ══════════════════════════════════════════════════════════════════
   HEADER BAR
══════════════════════════════════════════════════════════════════ */
#headerBar {{ background-color: {panel_bg}; }}

#brandName {{
    color: {heading};
    background: transparent;
    font-size: 14px;
    font-weight: 700;
    letter-spacing: 1.6px;
}}
#versionChip {{
    max-height: 20px;
    color: {text_dim};
    background-color: {surface};
    border: 1px solid {border};
    border-radius: 4px;
    padding: 2px 7px;
    font-size: 10px;
    font-weight: 700;
    letter-spacing: 0.6px;
}}
#headerCrumb, #headerCrumb > QWidget {{ background: transparent; }}
#sectionTitle {{
    color: {heading};
    background: transparent;
    font-size: 14px;
    font-weight: 650;
    letter-spacing: 0.2px;
}}
#sectionHint {{
    color: {text_dim};
    background: transparent;
    font-size: 11.5px;
    font-weight: 400;
}}
#headerDivider, #railDivider {{
    background-color: {border};
    border: none;
    max-width: 1px;
    min-width: 1px;
}}
#headerSeparator {{
    background-color: {border};
    border: none;
    max-height: 1px;
    min-height: 1px;
}}

/* Live target chip in the header */
#targetPill {{
    background-color: {surface};
    border: 1px solid {border};
    border-radius: 8px;
}}
#targetPill:hover {{ border-color: {accent}; background-color: {hover}; }}
#targetPillLabel {{
    color: {text_dim};
    background: transparent;
    font-size: 10px;
    font-weight: 700;
    letter-spacing: 0.8px;
}}
#targetPillValue {{
    color: {heading};
    background: transparent;
    font-family: {FONT_STACK_MONO};
    font-size: 12px;
    font-weight: 600;
}}
#targetPillValue[empty="true"] {{ color: {text_dim}; font-style: italic; }}

#themeCombo {{
    background-color: {surface};
    color: {text};
    border: 1px solid {border};
    border-radius: 8px;
    padding: 6px 10px;
    font-size: 12px;
    font-weight: 500;
    min-height: 28px;
}}
#themeCombo:hover {{ border-color: {accent}; }}

/* Window controls */
#winBtn, #winBtnClose {{
    background: transparent;
    border: none;
    border-radius: 6px;
}}
#winBtn:hover {{ background-color: {hover}; }}
#winBtnClose:hover {{ background-color: {danger}; }}

/* ══════════════════════════════════════════════════════════════════
   NAVIGATION RAIL
══════════════════════════════════════════════════════════════════ */
#navRail {{ background-color: {nav_bg}; }}

#navSectionLabel {{
    color: {text_dim};
    background: transparent;
    font-size: 10.5px;
    font-weight: 700;
    letter-spacing: 0.9px;
    /* 13px matches the nav item's own 13px inner left margin, so the
       section caption and the icons below it share one left rail. */
    padding: 0px 13px;
}}

#navItem {{
    background: transparent;
    border: none;
    border-left: 3px solid transparent;
    border-radius: 8px;
    text-align: left;
    padding: 0px;
}}
#navItem:hover {{ background-color: {hover}; }}
#navItem:checked {{
    background-color: {accent_tint};
    border-left: 3px solid {accent};
    border-top-left-radius: 0px;
    border-bottom-left-radius: 0px;
}}

#railToggle {{
    background: transparent;
    border: none;
    border-radius: 7px;
}}
#railToggle:hover {{ background-color: {hover}; }}

#railSeparator {{
    background-color: {border};
    border: none;
    max-height: 1px;
    min-height: 1px;
}}

/* ══════════════════════════════════════════════════════════════════
   BOTTOM STATUS BAR
══════════════════════════════════════════════════════════════════ */
#bottomStatusBar {{ background-color: {nav_bg}; }}
#statusLabel {{
    background: transparent;
    font-size: 11.5px;
    font-weight: 700;
    letter-spacing: 0.4px;
}}
#statusMeta {{
    background: transparent;
    color: {text_dim};
    font-size: 11.5px;
    font-weight: 500;
}}
#statusMetaStrong {{
    background: transparent;
    color: {text};
    font-family: {FONT_STACK_MONO};
    font-size: 11.5px;
    font-weight: 600;
}}
#statusSep {{
    background-color: {border};
    border: none;
    max-width: 1px;
    min-width: 1px;
}}

/* ══════════════════════════════════════════════════════════════════
   CARDS
══════════════════════════════════════════════════════════════════ */
QGroupBox#card {{
    background-color: {card_bg};
    border: 1px solid {border};
    border-radius: 10px;
    margin-top: 0px;
    padding: 0px;
    font-weight: 700;
}}
/* Title text sits on the same 20px left rail as the card's content.
   Measured: border(1) + left(20) + padding(0) = 21px, which is exactly
   where the layout's 20px content margin puts the first child widget. */
QGroupBox#card::title {{
    subcontrol-origin: padding;
    subcontrol-position: top left;
    left: 20px;
    top: 15px;
    padding: 0px;
    color: {heading};
    font-size: 13.5px;
    font-weight: 700;
    letter-spacing: 0.6px;
    background: transparent;
}}
/* Collapsible cards reserve indicator space ahead of the title
   (width + margins + 6px of Qt spacing = 16px here), so the offset is
   pulled back to 4px: chevron lands at x=5 inside the gutter and the
   title text still starts at 21px. */
QGroupBox#card[collapsible="true"]::title {{
    left: 4px;
}}
{amp_rules}
QGroupBox#card::indicator {{
    width: 10px;
    height: 10px;
    margin: 0px;
}}
QGroupBox#card::indicator:checked  {{ image: url({chev_down}); }}
QGroupBox#card::indicator:unchecked {{ image: url({chev_right}); }}
QGroupBox#card:hover::title {{ color: {accent}; }}

#cardHint {{
    color: {text_dim};
    background: transparent;
    font-size: 11.5px;
}}

/* ══════════════════════════════════════════════════════════════════
   BUTTONS
══════════════════════════════════════════════════════════════════ */
QPushButton#primaryButton {{
    background-color: {accent};
    color: {accent_text};
    border: 1px solid {accent};
    border-radius: 8px;
    padding: 9px 18px;
    font-size: 12.5px;
    font-weight: 700;
    letter-spacing: 0.2px;
    min-height: 20px;
}}
QPushButton#primaryButton:hover   {{ background-color: {accent_hover}; border-color: {accent_hover}; }}
QPushButton#primaryButton:pressed {{ background-color: {accent_press}; border-color: {accent_press}; }}
QPushButton#primaryButton:disabled {{
    background-color: {surface};
    border-color: {border};
    color: {text_dim};
}}

QPushButton#secondaryButton {{
    background-color: {surface};
    color: {text};
    border: 1px solid {border};
    border-radius: 8px;
    padding: 9px 14px;
    font-size: 12.5px;
    font-weight: 500;
    text-align: left;
    min-height: 20px;
}}
QPushButton#secondaryButton:hover {{
    background-color: {hover};
    border-color: {accent};
    color: {heading};
}}
QPushButton#secondaryButton:pressed {{ background-color: {accent_tint}; }}
QPushButton#secondaryButton:disabled {{ color: {text_dim}; border-color: {border}; }}
QPushButton#secondaryButton:focus {{ border-color: {accent}; }}

QPushButton#ghostButton {{
    background: transparent;
    color: {text_dim};
    border: 1px solid transparent;
    border-radius: 8px;
    padding: 8px 12px;
    font-size: 12.5px;
    font-weight: 500;
    min-height: 18px;
}}
QPushButton#ghostButton:hover {{ background-color: {hover}; color: {text}; }}

QPushButton#warningButton {{
    background-color: {danger};
    color: #ffffff;
    border: 1px solid {danger};
    border-radius: 8px;
    padding: 9px 14px;
    font-size: 12.5px;
    font-weight: 700;
    min-height: 20px;
}}
QPushButton#warningButton:hover   {{ background-color: {danger_hover}; border-color: {danger_hover}; }}
QPushButton#warningButton:pressed {{ background-color: {darken(danger, 0.18)}; }}

QPushButton#iconButton {{
    background-color: {surface};
    border: 1px solid {border};
    border-radius: 8px;
    padding: 6px;
}}
QPushButton#iconButton:hover {{ background-color: {hover}; border-color: {accent}; }}

/* ══════════════════════════════════════════════════════════════════
   INPUTS
══════════════════════════════════════════════════════════════════ */
QLineEdit {{
    background-color: {panel_bg};
    color: {text};
    border: 1px solid {border};
    border-radius: 8px;
    padding: 10px 13px;
    font-size: 13px;
    selection-background-color: {accent};
    selection-color: {accent_text};
    min-height: 20px;
}}
QLineEdit:hover  {{ border-color: {border_strong}; }}
QLineEdit:focus  {{ border: 1px solid {accent}; background-color: {bg}; }}
QLineEdit:read-only {{ color: {text_dim}; background-color: {surface}; }}
QLineEdit[monospace="true"] {{ font-family: {FONT_STACK_MONO}; font-size: 12.5px; }}

QTextEdit, QPlainTextEdit {{
    background-color: {console_bg};
    color: {text};
    border: 1px solid {border};
    border-radius: 10px;
    padding: 12px;
    font-family: {FONT_STACK_MONO};
    font-size: 12.5px;
    selection-background-color: {rgba(accent, 0.35)};
    selection-color: {heading};
}}
QTextEdit:focus, QPlainTextEdit:focus {{ border-color: {accent}; }}

/* ══════════════════════════════════════════════════════════════════
   LABELS
══════════════════════════════════════════════════════════════════ */
QLabel {{ color: {text}; background: transparent; }}
QLabel:disabled {{ color: {text_dim}; }}

QLabel#fieldLabel {{
    color: {text_dim};
    font-size: 11.5px;
    font-weight: 700;
    letter-spacing: 0.7px;
}}
QLabel#sectionHeader {{
    color: {heading};
    font-size: 13.5px;
    font-weight: 700;
    letter-spacing: 0.3px;
    padding: 2px 0px;
}}
QLabel#sectionDivider, QLabel#methodologySection {{
    color: {heading};
    font-size: 12.5px;
    font-weight: 700;
    letter-spacing: 0.5px;
    padding: 12px 0px 4px 0px;
    qproperty-alignment: 'AlignLeft | AlignVCenter';
}}
QLabel#autoDesc {{
    color: {text_dim};
    font-size: 12.5px;
    padding: 0px 0px 2px 0px;
}}

/* ══════════════════════════════════════════════════════════════════
   COMBOBOX
══════════════════════════════════════════════════════════════════ */
QComboBox {{
    background-color: {surface};
    color: {text};
    border: 1px solid {border};
    border-radius: 8px;
    padding: 7px 12px;
    font-size: 12.5px;
    min-height: 32px;
}}
QComboBox:hover {{ border-color: {accent}; }}
QComboBox:focus {{ border-color: {accent}; }}
QComboBox::drop-down {{ border: none; width: 26px; }}
QComboBox::down-arrow {{ image: url({chev_down}); width: 12px; height: 12px; }}
QComboBox::down-arrow:hover {{ image: url({chev_down_a}); }}
QComboBox QAbstractItemView {{
    background-color: {card_bg};
    color: {text};
    border: 1px solid {border_strong};
    border-radius: 8px;
    padding: 5px;
    selection-background-color: {accent_tint_2};
    selection-color: {heading};
    outline: none;
}}

/* ══════════════════════════════════════════════════════════════════
   SCROLLBARS
══════════════════════════════════════════════════════════════════ */
QScrollBar:vertical {{
    background: transparent; width: 10px; margin: 2px 2px 2px 0px;
}}
QScrollBar::handle:vertical {{
    background: {scroll_handle}; border-radius: 4px; min-height: 36px;
}}
QScrollBar::handle:vertical:hover {{ background: {accent}; }}
QScrollBar:horizontal {{
    background: transparent; height: 10px; margin: 0px 2px 2px 2px;
}}
QScrollBar::handle:horizontal {{
    background: {scroll_handle}; border-radius: 4px; min-width: 36px;
}}
QScrollBar::handle:horizontal:hover {{ background: {accent}; }}
QScrollBar::add-line, QScrollBar::sub-line {{ width: 0px; height: 0px; background: transparent; }}
QScrollBar::add-page, QScrollBar::sub-page {{ background: transparent; }}

QScrollArea {{ border: none; background: transparent; }}
QScrollArea > QWidget > QWidget {{ background: transparent; }}

/* ══════════════════════════════════════════════════════════════════
   SPLITTER
══════════════════════════════════════════════════════════════════ */
QSplitter::handle {{ background-color: transparent; }}
QSplitter::handle:horizontal {{ width: 9px; }}
QSplitter::handle:vertical {{ height: 9px; }}
QSplitter::handle:hover {{ background-color: {rgba(accent, 0.25)}; }}

/* ══════════════════════════════════════════════════════════════════
   CHECKBOX / RADIO
══════════════════════════════════════════════════════════════════ */
QCheckBox {{ background: transparent; color: {text}; spacing: 9px; font-size: 12.5px; }}
QCheckBox::indicator {{
    width: 17px; height: 17px;
    border: 1px solid {border_strong};
    border-radius: 5px;
    background-color: {panel_bg};
}}
QCheckBox::indicator:hover {{ border-color: {accent}; }}
QCheckBox::indicator:checked {{
    background-color: {accent};
    border-color: {accent};
    image: url({tick});
}}

/* ══════════════════════════════════════════════════════════════════
   LISTS / TREES
══════════════════════════════════════════════════════════════════ */
QListWidget, QTreeView, QListView {{
    background-color: {console_bg};
    color: {text};
    border: 1px solid {border};
    border-radius: 10px;
    padding: 5px;
    outline: none;
    font-size: 12.5px;
}}
QListWidget::item, QTreeView::item, QListView::item {{
    padding: 7px 9px;
    border-radius: 6px;
    margin: 1px 0px;
}}
QListWidget::item:hover, QTreeView::item:hover, QListView::item:hover {{
    background-color: {hover};
}}
QListWidget::item:selected, QTreeView::item:selected, QListView::item:selected {{
    background-color: {accent_tint_2};
    color: {heading};
}}
QListWidget#fileList {{ font-family: {FONT_STACK_MONO}; font-size: 12px; }}

QHeaderView::section {{
    background-color: {panel_bg};
    color: {text_dim};
    border: none;
    border-bottom: 1px solid {border};
    padding: 7px;
    font-size: 11px;
    font-weight: 700;
    letter-spacing: 0.5px;
}}

/* ══════════════════════════════════════════════════════════════════
   CONSOLE SURFACES
══════════════════════════════════════════════════════════════════ */
#consoleOutput {{
    background-color: {console_bg};
    border: 1px solid {border};
    border-radius: 10px;
}}
#consoleToolbar {{
    background: transparent;
    border: none;
}}
#statusBarContainer {{
    background-color: {panel_bg};
    border: 1px solid {border};
    border-radius: 10px;
}}
#statusInfoLabel {{
    color: {text};
    background: transparent;
    font-family: {FONT_STACK_MONO};
    font-size: 12px;
    font-weight: 500;
    padding: 0px 2px;
}}
#consolePaneTitle {{
    color: {text_dim};
    background: transparent;
    font-size: 11.5px;
    font-weight: 700;
    letter-spacing: 0.8px;
}}
QProgressBar#consoleProgressBar {{
    background-color: {surface};
    border: none;
    border-radius: 3px;
    text-align: center;
    color: transparent;
    max-height: 6px;
    min-height: 6px;
}}
QProgressBar#consoleProgressBar::chunk {{
    background-color: {accent};
    border-radius: 3px;
}}

/* ══════════════════════════════════════════════════════════════════
   INNER TAB WIDGETS
══════════════════════════════════════════════════════════════════ */
QTabWidget::pane {{ border: none; background-color: {bg}; }}
QTabBar::tab {{
    background: transparent;
    color: {text_dim};
    border: none;
    border-bottom: 2px solid transparent;
    padding: 9px 16px;
    margin-right: 4px;
    font-size: 12.5px;
    font-weight: 600;
}}
QTabBar::tab:hover {{ color: {text}; }}
QTabBar::tab:selected {{ color: {accent}; border-bottom: 2px solid {accent}; }}

/* ══════════════════════════════════════════════════════════════════
   MENUS
══════════════════════════════════════════════════════════════════ */
QMenu {{
    background-color: {card_bg};
    color: {text};
    border: 1px solid {border_strong};
    border-radius: 10px;
    padding: 6px;
    font-size: 12.5px;
}}
QMenu::item {{
    background: transparent;
    padding: 8px 20px 8px 14px;
    border-radius: 6px;
    margin: 1px 2px;
}}
QMenu::item:selected {{ background-color: {accent_tint_2}; color: {heading}; }}
QMenu::item:disabled {{
    color: {heading};
    font-size: 12px;
    font-weight: 700;
    letter-spacing: 0.4px;
    /* 16px left = the 14px item padding + the item's 2px side margin, so a
       menu section heading sits on the same rail as the entries under it. */
    padding: 10px 10px 5px 16px;
    background: transparent;
}}
QMenu::separator {{ height: 1px; background: {border}; margin: 5px 10px; }}
"""

        self.setStyleSheet(_fix_alpha_hex(stylesheet))
        self._sync_palette(t)

        # Let the chrome repaint its icons/labels in the new palette.
        for hook in ("_refresh_rail_theme", "_refresh_header_theme",
                     "_refresh_status_theme", "_refresh_console_theme"):
            fn = getattr(self, hook, None)
            if callable(fn):
                try:
                    fn()
                except Exception:
                    pass

    # ── Native palette (file dialogs, native popups) ───────────────────────────

    def _sync_palette(self, t: dict):
        """Keep non-stylesheet surfaces (native dialogs) on-theme."""
        try:
            app = QtWidgets.QApplication.instance()
            if app is None:
                return
            pal = QtGui.QPalette()
            C = QtGui.QPalette.ColorRole
            pal.setColor(C.Window, QtGui.QColor(t["bg"]))
            pal.setColor(C.WindowText, QtGui.QColor(t["text"]))
            pal.setColor(C.Base, QtGui.QColor(t["panel_bg"]))
            pal.setColor(C.AlternateBase, QtGui.QColor(t["card_bg"]))
            pal.setColor(C.Text, QtGui.QColor(t["text"]))
            pal.setColor(C.Button, QtGui.QColor(theme_value(t, "surface")))
            pal.setColor(C.ButtonText, QtGui.QColor(t["text"]))
            pal.setColor(C.Highlight, QtGui.QColor(t["accent"]))
            pal.setColor(C.HighlightedText, QtGui.QColor("#ffffff"))
            pal.setColor(C.ToolTipBase, QtGui.QColor(t["card_bg"]))
            pal.setColor(C.ToolTipText, QtGui.QColor(t["text"]))
            app.setPalette(pal)
        except Exception:
            pass

    # ── Themed popups ─────────────────────────────────────────────────────────

    def apply_theme_to_menu(self, menu):
        """QMenus inherit the app stylesheet; kept for call-site compatibility."""
        try:
            menu.setStyleSheet(self.styleSheet())
        except Exception:
            pass

    def apply_theme_to_dialog(self, dialog):
        """Apply the app stylesheet to a dialog opened outside the main window."""
        try:
            dialog.setStyleSheet(self.styleSheet() + f"""
                QDialog, QFileDialog, QMessageBox {{
                    background-color: {self.tc('bg')};
                }}
                QDialogButtonBox QPushButton {{
                    background-color: {self.tc('surface')};
                    color: {self.tc('text')};
                    border: 1px solid {self.tc('border')};
                    border-radius: 8px;
                    padding: 8px 20px;
                    font-weight: 600;
                    min-width: 92px;
                    min-height: 34px;
                }}
                QDialogButtonBox QPushButton:hover {{
                    background-color: {self.tc('hover')};
                    border-color: {self.tc('accent')};
                }}
                QDialogButtonBox QPushButton:default {{
                    background-color: {self.tc('accent')};
                    border-color: {self.tc('accent')};
                    color: #ffffff;
                    font-weight: 700;
                }}
            """)
        except Exception:
            pass

    def show_themed_message(self, title, message, icon=QMessageBox.Icon.Information):
        """Message box styled with the active palette."""
        msg_box = QMessageBox(self)
        msg_box.setWindowTitle(title)
        msg_box.setText(message)
        msg_box.setIcon(icon)
        self.apply_theme_to_dialog(msg_box)
        msg_box.exec()


def _is_bright(hex_color: str) -> bool:
    """Perceived brightness test (ITU-R BT.601) used to pick text on accent."""
    try:
        h = str(hex_color).lstrip("#")
        r, g, b = int(h[0:2], 16), int(h[2:4], 16), int(h[4:6], 16)
        return (r * 299 + g * 587 + b * 114) / 1000 > 150
    except Exception:
        return False
