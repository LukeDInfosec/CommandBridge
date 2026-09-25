"""Application-wide constants, design tokens and theme definitions.

Design system notes
───────────────────
Every colour the UI paints comes from one of the palettes in ``THEMES``.
Nothing in the widget code should hard-code a hex value; if a new colour role
is needed, add it here so all themes stay in sync.

Palette roles
─────────────
    bg            Application canvas behind everything
    nav_bg        Navigation rail / status bar chrome
    panel_bg      Header bar, input fields, inset surfaces
    card_bg       Card (QGroupBox) surface
    surface       Raised surface: buttons, combo boxes, hover fills
    console_bg    Terminal / code surfaces
    border        Hairline dividers and control outlines
    border_strong Emphasised outline (hover, focus-adjacent)
    hover         Hover fill for interactive chrome
    text          Primary body text
    text_dim      Secondary / supporting text
    heading       Card + section titles (highest contrast)
    accent        Brand / primary interactive colour
    success       Positive state (complete, safe, open)
    warning       Caution state (running, medium severity)
    danger        Negative state (failed, critical finding)
    info          Neutral informational state
    button_bg     Legacy alias used by dialog styling  (== surface)
    button_text   Legacy alias used by dialog styling  (== text)
    is_light      True for light palettes (drives contrast heuristics)
"""

from pathlib import Path

APP_TITLE = "Command Bridge"
APP_VERSION = "5.2.0"
BASE_DIR = Path(__file__).resolve().parent.parent  # Project root (Test26/)
DEFAULT_OUTPUT_DIR = Path.cwd()

# ══════════════════════════════════════════════════════════════════════════════
#  SPACING / RADIUS / TYPE SCALE
#  An 8px grid keeps every tab visually aligned without each tab file
#  inventing its own margins.
# ══════════════════════════════════════════════════════════════════════════════

SPACE_XS = 4
SPACE_SM = 8
SPACE_MD = 12
SPACE_LG = 16
SPACE_XL = 24
SPACE_2XL = 32

RADIUS_SM = 6
RADIUS_MD = 8
RADIUS_LG = 10
RADIUS_XL = 14

# Chrome dimensions
HEADER_HEIGHT = 56
STATUSBAR_HEIGHT = 28
RAIL_WIDTH_COMPACT = 78
RAIL_WIDTH_EXPANDED = 214
CONTENT_MARGIN = 24

FONT_STACK_UI = '"Inter", "SF Pro Text", "Segoe UI", "Ubuntu", "Cantarell", sans-serif'
FONT_STACK_MONO = '"JetBrains Mono", "Fira Code", "Cascadia Code", "DejaVu Sans Mono", monospace'


# ══════════════════════════════════════════════════════════════════════════════
#  TAB REGISTRY — single source of truth for tab order
#
#  Ordered along a real engagement: define scope, discover the estate, test it,
#  analyse what came back. Console and Bug Bounty are pinned to the bottom of
#  the rail: Console because it is a destination rather than a workflow step,
#  Bug Bounty because it is occasional work rather than the main event.
#
#  Fields: key, rail label, full title, header hint, icon name, rail section
#  NEVER address a tab by a hard-coded integer — use self.goto_tab("console").
# ══════════════════════════════════════════════════════════════════════════════

TABS = [
    ("target",    "Target",   "Target Setup",        "Scope, authentication and output location", "target",    "ENGAGE"),
    ("recon",     "Recon",    "Reconnaissance",      "Passive and active discovery",              "radar",     "DISCOVER"),
    ("externals", "External", "External Infra",      "Bulk hosts, ports, TLS and services",       "nodes",     "DISCOVER"),
    ("web",       "Web",      "Web Application",     "Fuzzing, injection and access control",     "globe",     "TEST"),
    ("api",       "API",      "API Testing",         "Endpoints, schemas and GraphQL",            "braces",    "TEST"),
    ("coffee",    "Coffee",   "Coffee Break",        "One button, the whole active-scan chain",   "bolt",      "TEST"),
    ("console",   "Console",  "Console & Results",   "Live output and captured artefacts",        "terminal",  "PINNED"),
    ("bounty",    "Bounty",   "Bug Bounty",          "Mass recon methodology workflows",          "flag",      "PINNED"),
]

RAIL_SECTIONS = ["ENGAGE", "DISCOVER", "TEST"]


# ══════════════════════════════════════════════════════════════════════════════
#  THEMES
#
#  Seventeen palettes, all built for long sessions in a dark room and for looking
#  credible on a client's screen. Dark neutrals with a single saturated accent;
#  semantic colours (success / warning / danger) stay consistent across themes
#  so a red finding always reads as red.
# ══════════════════════════════════════════════════════════════════════════════

THEMES = {
    # ── Neutral graphite with an indigo accent. The default. ──────────────────
    "Graphite": {
        "bg": "#0e1116", "nav_bg": "#0a0d12", "panel_bg": "#12161e",
        "card_bg": "#161b24", "surface": "#1c222d", "console_bg": "#0a0d12",
        "border": "#222836", "border_strong": "#2e3645", "hover": "#1a202b",
        "text": "#e2e7ef", "text_dim": "#949daf", "heading": "#f0f3f8",
        "accent": "#5b7cfa", "success": "#3ddc97", "warning": "#f5a524",
        "danger": "#f04d5b", "info": "#4cc3f0",
        "button_bg": "#1c222d", "button_text": "#e2e7ef", "is_light": False,
    },
    # ── Near-black with a teal accent. Highest contrast, least glare. ─────────
    "Obsidian": {
        "bg": "#08090b", "nav_bg": "#060709", "panel_bg": "#0d0f12",
        "card_bg": "#101317", "surface": "#171b21", "console_bg": "#050607",
        "border": "#1c2026", "border_strong": "#2a3039", "hover": "#14181e",
        "text": "#e4e7ea", "text_dim": "#8d949e", "heading": "#f5f7f9",
        "accent": "#00c2a8", "success": "#45d483", "warning": "#f0b429",
        "danger": "#ef4b5e", "info": "#35b7e8",
        "button_bg": "#171b21", "button_text": "#e4e7ea", "is_light": False,
    },
    # ── Deep navy with azure. Classic SOC console look. ───────────────────────
    "Midnight": {
        "bg": "#0a1020", "nav_bg": "#070c19", "panel_bg": "#0e1526",
        "card_bg": "#111a2d", "surface": "#172236", "console_bg": "#060a14",
        "border": "#1e2b42", "border_strong": "#2b3c58", "hover": "#162033",
        "text": "#dde5f2", "text_dim": "#8c9ab3", "heading": "#eef3fa",
        "accent": "#3d8bfd", "success": "#35d0a5", "warning": "#f7b955",
        "danger": "#ff5c6c", "info": "#57c7ff",
        "button_bg": "#172236", "button_text": "#dde5f2", "is_light": False,
    },
    # ── Muted arctic greys. Lower contrast, very easy on the eyes. ────────────
    "Nord Frost": {
        "bg": "#2e3440", "nav_bg": "#272c36", "panel_bg": "#333a47",
        "card_bg": "#3b4252", "surface": "#434c5e", "console_bg": "#242933",
        "border": "#434c5e", "border_strong": "#4c566a", "hover": "#414a5c",
        "text": "#e5e9f0", "text_dim": "#a7b0c0", "heading": "#eceff4",
        "accent": "#88c0d0", "success": "#a3be8c", "warning": "#ebcb8b",
        "danger": "#bf616a", "info": "#81a1c1",
        "button_bg": "#434c5e", "button_text": "#e5e9f0", "is_light": False,
    },
    # ── Graphite with a red accent. Red-team engagements. ─────────────────────
    "Crimson": {
        "bg": "#101013", "nav_bg": "#0c0c0f", "panel_bg": "#141418",
        "card_bg": "#17181d", "surface": "#1e1f26", "console_bg": "#0b0b0e",
        "border": "#26272f", "border_strong": "#33353f", "hover": "#1c1d24",
        "text": "#e6e4e6", "text_dim": "#9b979e", "heading": "#f4f2f4",
        "accent": "#e03b4b", "success": "#46c98a", "warning": "#e9a33b",
        "danger": "#ff5a5a", "info": "#6ba8e8",
        "button_bg": "#1e1f26", "button_text": "#e6e4e6", "is_light": False,
    },
    # ── Dark with a green accent. Defensive / monitoring work. ────────────────
    "Viridian": {
        "bg": "#0b1210", "nav_bg": "#080e0c", "panel_bg": "#0f1815",
        "card_bg": "#121c19", "surface": "#182420", "console_bg": "#070d0b",
        "border": "#1e2b26", "border_strong": "#2b3d36", "hover": "#16211d",
        "text": "#dfe8e3", "text_dim": "#8fa39a", "heading": "#eff5f2",
        "accent": "#2fbf71", "success": "#4ade80", "warning": "#f0b429",
        "danger": "#ef4d5e", "info": "#4aa8d8",
        "button_bg": "#182420", "button_text": "#dfe8e3", "is_light": False,
    },
    # ── Light palette for report screenshots, demos and bright rooms. ─────────
    "Daylight": {
        "bg": "#f4f6f9", "nav_bg": "#ffffff", "panel_bg": "#ffffff",
        "card_bg": "#ffffff", "surface": "#eef1f6", "console_bg": "#ffffff",
        "border": "#dde3ec", "border_strong": "#c3ccda", "hover": "#e8edf4",
        "text": "#1d2430", "text_dim": "#5d6879", "heading": "#0f1621",
        "accent": "#2563eb", "success": "#10996b", "warning": "#b45309",
        "danger": "#dc2626", "info": "#0b7fc4",
        "button_bg": "#eef1f6", "button_text": "#1d2430", "is_light": True,
    },
    # ── True black with a hot orange accent. High-contrast, OLED friendly. ────
    "Black & Orange": {
        "bg": "#000000", "nav_bg": "#000000", "panel_bg": "#080808",
        "card_bg": "#0d0d0d", "surface": "#161616", "console_bg": "#000000",
        "border": "#232323", "border_strong": "#3a3a3a", "hover": "#1b1613",
        "text": "#ececec", "text_dim": "#9a9a9a", "heading": "#ffffff",
        "accent": "#ff7a18", "success": "#3ddc97", "warning": "#ffc23d",
        "danger": "#ff4d4d", "info": "#4cc3f0",
        "button_bg": "#161616", "button_text": "#ececec", "is_light": False,
    },
    # ── Warm charcoal with amber. Softer take on black & orange. ──────────────
    "Solar Amber": {
        "bg": "#14110d", "nav_bg": "#100e0a", "panel_bg": "#191510",
        "card_bg": "#1e1913", "surface": "#272119", "console_bg": "#0d0b08",
        "border": "#2f2820", "border_strong": "#443a2c", "hover": "#241e16",
        "text": "#ece5da", "text_dim": "#a89b89", "heading": "#fbf6ef",
        "accent": "#f59f2e", "success": "#5ec98a", "warning": "#ffcc55",
        "danger": "#e8574f", "info": "#5bb4d8",
        "button_bg": "#272119", "button_text": "#ece5da", "is_light": False,
    },
    # ── Purple-black with magenta. Neon console look. ─────────────────────────
    "Cyber Neon": {
        "bg": "#0c0714", "nav_bg": "#090511", "panel_bg": "#120b1d",
        "card_bg": "#160e23", "surface": "#1f142f", "console_bg": "#07040d",
        "border": "#2a1c3d", "border_strong": "#3c2a55", "hover": "#1d1230",
        "text": "#e9e0f5", "text_dim": "#a294b8", "heading": "#f8f3ff",
        "accent": "#e044c8", "success": "#3ee6b0", "warning": "#ffc542",
        "danger": "#ff4f70", "info": "#48d7f5",
        "button_bg": "#1f142f", "button_text": "#e9e0f5", "is_light": False,
    },
    # ── Deep sea teal with cyan. Calm, long-session palette. ──────────────────
    "Deep Ocean": {
        "bg": "#06131a", "nav_bg": "#040f15", "panel_bg": "#0a1a23",
        "card_bg": "#0d2029", "surface": "#132b36", "console_bg": "#030c11",
        "border": "#173442", "border_strong": "#22485a", "hover": "#12313d",
        "text": "#dceaf0", "text_dim": "#87a3b0", "heading": "#eef7fb",
        "accent": "#21c8d6", "success": "#3fd99b", "warning": "#f2b544",
        "danger": "#f0596a", "info": "#5bc6f5",
        "button_bg": "#132b36", "button_text": "#dceaf0", "is_light": False,
    },
    # ── Charcoal with a royal violet accent. ──────────────────────────────────
    "Royal Violet": {
        "bg": "#0f0d16", "nav_bg": "#0b0a11", "panel_bg": "#15121f",
        "card_bg": "#1a1626", "surface": "#221d31", "console_bg": "#0a0810",
        "border": "#2a2440", "border_strong": "#3a3256", "hover": "#1f1a2d",
        "text": "#e5e2f0", "text_dim": "#9a94b0", "heading": "#f4f2fb",
        "accent": "#8b5cf6", "success": "#40d99a", "warning": "#f5b13c",
        "danger": "#f45a6d", "info": "#54b9f0",
        "button_bg": "#221d31", "button_text": "#e5e2f0", "is_light": False,
    },
    # ── Gunmetal with brushed gold. Understated, report-friendly. ─────────────
    "Gunmetal Gold": {
        "bg": "#121417", "nav_bg": "#0e1013", "panel_bg": "#171a1e",
        "card_bg": "#1c2025", "surface": "#242a30", "console_bg": "#0b0d10",
        "border": "#2b3138", "border_strong": "#3b434c", "hover": "#222830",
        "text": "#e6e8ea", "text_dim": "#99a0a8", "heading": "#f6f7f8",
        "accent": "#d4af5c", "success": "#4bd18c", "warning": "#e9b545",
        "danger": "#e45563", "info": "#54aee0",
        "button_bg": "#242a30", "button_text": "#e6e8ea", "is_light": False,
    },
    # ── Near-black with an ice-blue accent. Clinical and very legible. ────────
    "Carbon Ice": {
        "bg": "#0a0b0d", "nav_bg": "#070809", "panel_bg": "#0f1113",
        "card_bg": "#131619", "surface": "#1b1f24", "console_bg": "#060708",
        "border": "#232830", "border_strong": "#333a44", "hover": "#191d23",
        "text": "#e8ecf1", "text_dim": "#939ba6", "heading": "#f7f9fc",
        "accent": "#7dd3fc", "success": "#4ade80", "warning": "#fbbf24",
        "danger": "#f87171", "info": "#38bdf8",
        "button_bg": "#1b1f24", "button_text": "#e8ecf1", "is_light": False,
    },
    # ── Dark moss with a lime accent. Terminal-forward. ───────────────────────
    "Forest Night": {
        "bg": "#0d120e", "nav_bg": "#0a0e0b", "panel_bg": "#121813",
        "card_bg": "#161d17", "surface": "#1d261f", "console_bg": "#070b08",
        "border": "#233024", "border_strong": "#324333", "hover": "#1a231b",
        "text": "#e3ebe4", "text_dim": "#94a596", "heading": "#f2f7f3",
        "accent": "#a3e635", "success": "#4ade80", "warning": "#facc15",
        "danger": "#f0555f", "info": "#56b8d6",
        "button_bg": "#1d261f", "button_text": "#e3ebe4", "is_light": False,
    },
    # ── Dark plum with a rose accent. ─────────────────────────────────────────
    "Rosewood": {
        "bg": "#140e11", "nav_bg": "#100b0e", "panel_bg": "#1a1216",
        "card_bg": "#1f161a", "surface": "#291d22", "console_bg": "#0d080a",
        "border": "#33242a", "border_strong": "#46323a", "hover": "#261a1f",
        "text": "#efe3e7", "text_dim": "#ad969e", "heading": "#fbf3f6",
        "accent": "#f472a0", "success": "#4bd195", "warning": "#f0b64a",
        "danger": "#ff5b6b", "info": "#5cb3e6",
        "button_bg": "#291d22", "button_text": "#efe3e7", "is_light": False,
    },
    # ── Warm light palette. Bright rooms and client-facing screenshots. ───────
    "Sandstone": {
        "bg": "#f6f2ec", "nav_bg": "#fffdfa", "panel_bg": "#fffdfa",
        "card_bg": "#ffffff", "surface": "#efe9e0", "console_bg": "#fffdfa",
        "border": "#e3dbcf", "border_strong": "#c9bdac", "hover": "#eee6da",
        "text": "#2a241d", "text_dim": "#6b6154", "heading": "#171310",
        "accent": "#c2410c", "success": "#0f8a5f", "warning": "#a35a07",
        "danger": "#c02626", "info": "#0b6fa8",
        "button_bg": "#efe9e0", "button_text": "#2a241d", "is_light": True,
    },
}

DEFAULT_THEME = "Graphite"


def theme_value(theme: dict, key: str, fallback: str = "#808080") -> str:
    """Safely read a palette role, tolerating older/partial theme dicts."""
    value = theme.get(key)
    if value:
        return value
    # Graceful degradation for palettes missing newer roles.
    aliases = {
        "surface": "button_bg",
        "text_dim": "text",
        "border_strong": "border",
        "danger": "accent",
        "info": "accent",
        "heading": "text",
    }
    alias = aliases.get(key)
    if alias:
        return theme.get(alias, fallback)
    return fallback
