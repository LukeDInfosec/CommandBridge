"""Vector icon set drawn with QPainter.

Why not emoji or an icon font: emoji render in full colour with a different
metric on every platform (and look like a toy next to an enterprise tool),
icon fonts add a dependency and a licence, and SVG files need QtSvg plus a
recolouring step. Everything here is a path drawn on a 24x24 grid, stroked in
whatever colour the active theme asks for, cached per (name, colour, size).

Result: crisp at any DPI, instantly recoloured when the theme changes, and
zero dependencies beyond PyQt6 itself.

    pix  = icon_pixmap("target", "#5b7cfa", 22)     # QPixmap for a QLabel
    ico  = icon("close", "#e2e7ef", 16)             # QIcon for a QPushButton
    path = icon_png("chevron_down", "#949daf", 12)  # file path for QSS url()
"""

from __future__ import annotations

from pathlib import Path

from PyQt6.QtCore import QPointF, QRectF, Qt
from PyQt6.QtGui import QColor, QIcon, QPainter, QPainterPath, QPen, QPixmap

GRID = 24.0  # every path below is authored on a 24x24 canvas

_PIXMAP_CACHE: dict[tuple, QPixmap] = {}
_PNG_CACHE: dict[tuple, str] = {}


# ══════════════════════════════════════════════════════════════════════════════
#  Path builders — each returns (stroked_path, filled_path)
# ══════════════════════════════════════════════════════════════════════════════

def _line(path: QPainterPath, x1, y1, x2, y2):
    path.moveTo(x1, y1)
    path.lineTo(x2, y2)


def _poly(path: QPainterPath, points, close=False):
    path.moveTo(*points[0])
    for pt in points[1:]:
        path.lineTo(*pt)
    if close:
        path.closeSubpath()


def _rounded(path: QPainterPath, x, y, w, h, r):
    path.addRoundedRect(QRectF(x, y, w, h), r, r)


def _circle(path: QPainterPath, cx, cy, r):
    path.addEllipse(QPointF(cx, cy), r, r)


def _build(name: str) -> tuple[QPainterPath, QPainterPath]:
    """Return (stroke_path, fill_path) for an icon name on the 24x24 grid."""
    s = QPainterPath()   # stroked
    f = QPainterPath()   # filled
    f.setFillRule(Qt.FillRule.WindingFill)

    # ── Navigation ────────────────────────────────────────────────────────────
    if name == "target":
        _circle(s, 12, 12, 8)
        _circle(s, 12, 12, 3.4)
        _line(s, 12, 1.2, 12, 4.2)
        _line(s, 12, 19.8, 12, 22.8)
        _line(s, 1.2, 12, 4.2, 12)
        _line(s, 19.8, 12, 22.8, 12)
        _circle(f, 12, 12, 1.1)

    elif name in ("radar", "search"):
        _circle(s, 10.5, 10.5, 6.6)
        _line(s, 15.4, 15.4, 20.8, 20.8)
        _line(s, 7.6, 10.5, 13.4, 10.5)
        _line(s, 10.5, 7.6, 10.5, 13.4)

    elif name == "nodes":
        # Stacked hosts: reads as external infrastructure at 19px, where a
        # node-graph collapses into an unreadable triangle.
        _rounded(s, 3.4, 3.8, 17.2, 6.2, 1.8)
        _rounded(s, 3.4, 13.8, 17.2, 6.2, 1.8)
        _circle(f, 7.2, 6.9, 1.15)
        _circle(f, 7.2, 16.9, 1.15)
        _line(s, 11.0, 6.9, 16.6, 6.9)
        _line(s, 11.0, 16.9, 16.6, 16.9)

    elif name == "globe":
        _circle(s, 12, 12, 8.6)
        s.addEllipse(QRectF(12 - 3.6, 12 - 8.6, 7.2, 17.2))
        _line(s, 3.4, 12, 20.6, 12)
        _line(s, 5.0, 7.4, 19.0, 7.4)
        _line(s, 5.0, 16.6, 19.0, 16.6)

    elif name in ("code", "braces"):
        _poly(s, [(9.4, 7.6), (5.6, 12.0), (9.4, 16.4)])
        _poly(s, [(14.6, 7.6), (18.4, 12.0), (14.6, 16.4)])
        _line(s, 13.2, 5.6, 10.8, 18.4)

    elif name == "arrow_in":
        _line(s, 2.8, 12, 14.4, 12)
        _poly(s, [(10.6, 8.2), (14.4, 12.0), (10.6, 15.8)])
        _line(s, 18.6, 4.8, 18.6, 19.2)

    elif name == "arrow_out":
        _line(s, 5.4, 4.8, 5.4, 19.2)
        _line(s, 9.6, 12, 21.2, 12)
        _poly(s, [(17.4, 8.2), (21.2, 12.0), (17.4, 15.8)])

    elif name == "terminal":
        _rounded(s, 2.6, 4.2, 18.8, 15.6, 2.6)
        _poly(s, [(6.8, 9.2), (10.2, 12.4), (6.8, 15.6)])
        _line(s, 12.4, 15.8, 17.4, 15.8)

    elif name == "flag":
        _line(s, 6.2, 3.2, 6.2, 21.0)
        _poly(s, [(6.2, 4.6), (17.8, 4.6), (14.6, 8.6), (17.8, 12.6), (6.2, 12.6)], close=True)

    # ── Chrome / window controls ──────────────────────────────────────────────
    elif name == "minimize":
        _line(s, 6.5, 12, 17.5, 12)

    elif name == "maximize":
        _rounded(s, 6.5, 6.5, 11, 11, 1.8)

    elif name == "restore":
        _rounded(s, 5.2, 8.8, 10, 10, 1.6)
        _poly(s, [(8.6, 5.2), (18.8, 5.2), (18.8, 15.4)])

    elif name == "close":
        _line(s, 6.6, 6.6, 17.4, 17.4)
        _line(s, 17.4, 6.6, 6.6, 17.4)

    elif name == "chevron_down":
        _poly(s, [(5.8, 9.4), (12.0, 15.4), (18.2, 9.4)])

    elif name == "chevron_up":
        _poly(s, [(5.8, 14.6), (12.0, 8.6), (18.2, 14.6)])

    elif name == "chevron_right":
        _poly(s, [(9.4, 5.8), (15.4, 12.0), (9.4, 18.2)])

    elif name == "chevron_left":
        _poly(s, [(14.6, 5.8), (8.6, 12.0), (14.6, 18.2)])

    elif name == "panel_left":
        _rounded(s, 2.8, 5.0, 18.4, 14.0, 2.4)
        _line(s, 9.4, 5.0, 9.4, 19.0)

    elif name == "droplet":
        f.moveTo(12, 2.8)
        f.lineTo(17.9, 11.4)
        f.cubicTo(20.4, 15.5, 17.4, 20.8, 12.0, 20.8)
        f.cubicTo(6.6, 20.8, 3.6, 15.5, 6.1, 11.4)
        f.closeSubpath()

    elif name == "bolt":
        _poly(f, [(13.6, 2.2), (5.8, 13.6), (10.9, 13.6), (10.4, 21.8),
                  (18.2, 10.4), (13.1, 10.4)], close=True)

    elif name == "shield":
        _poly(s, [(12, 2.6), (20, 5.8), (20, 11.6)])
        s.moveTo(20, 11.6)
        s.cubicTo(20, 16.6, 16.4, 19.8, 12, 21.4)
        s.cubicTo(7.6, 19.8, 4, 16.6, 4, 11.6)
        s.lineTo(4, 5.8)
        s.closeSubpath()

    # ── Actions ───────────────────────────────────────────────────────────────
    elif name == "play":
        _poly(f, [(8.8, 6.0), (18.4, 12.0), (8.8, 18.0)], close=True)

    elif name == "pause":
        _rounded(f, 8.4, 6.4, 2.9, 11.2, 1.2)
        _rounded(f, 12.7, 6.4, 2.9, 11.2, 1.2)

    elif name == "stop":
        _rounded(f, 7.4, 7.4, 9.2, 9.2, 1.8)

    elif name == "skip":
        _poly(f, [(6.8, 6.2), (14.2, 12.0), (6.8, 17.8)], close=True)
        _rounded(f, 15.8, 6.2, 2.2, 11.6, 1.0)

    elif name == "refresh":
        s.arcMoveTo(QRectF(4.4, 4.4, 15.2, 15.2), 60)
        s.arcTo(QRectF(4.4, 4.4, 15.2, 15.2), 60, 285)
        _poly(s, [(13.0, 3.0), (18.0, 6.2), (14.4, 10.2)])

    elif name == "folder":
        _poly(s, [(3.2, 18.8), (3.2, 5.6), (9.2, 5.6), (11.4, 8.4),
                  (20.8, 8.4), (20.8, 18.8)], close=True)

    elif name == "trash":
        _line(s, 4.2, 6.6, 19.8, 6.6)
        _poly(s, [(6.6, 6.6), (6.6, 19.4), (17.4, 19.4), (17.4, 6.6)])
        _poly(s, [(9.6, 6.6), (9.6, 4.2), (14.4, 4.2), (14.4, 6.6)])
        _line(s, 10.2, 10.0, 10.2, 16.2)
        _line(s, 13.8, 10.0, 13.8, 16.2)

    elif name == "check":
        _poly(s, [(5.4, 12.4), (10.0, 17.0), (18.6, 7.0)])

    elif name == "warning":
        _poly(s, [(12, 3.4), (21.4, 19.6), (2.6, 19.6)], close=True)
        _line(s, 12, 9.6, 12, 14.2)
        _circle(f, 12, 17.0, 0.95)

    elif name == "dot":
        _circle(f, 12, 12, 4.4)

    elif name == "plus":
        _line(s, 12, 5.6, 12, 18.4)
        _line(s, 5.6, 12, 18.4, 12)

    return s, f


# ══════════════════════════════════════════════════════════════════════════════
#  Rendering
# ══════════════════════════════════════════════════════════════════════════════

def icon_pixmap(name: str, color: str, size: int = 22, stroke: float = 1.9) -> QPixmap:
    """Return a cached QPixmap of `name` tinted `color`, `size` px square."""
    key = (name, str(color), int(size), round(float(stroke), 2))
    cached = _PIXMAP_CACHE.get(key)
    if cached is not None:
        return cached

    dpr = 2  # render at 2x so the glyph stays sharp on HiDPI panels
    pm = QPixmap(int(size * dpr), int(size * dpr))
    pm.fill(QColor(0, 0, 0, 0))

    painter = QPainter(pm)
    try:
        painter.setRenderHint(QPainter.RenderHint.Antialiasing, True)
        scale = (size * dpr) / GRID
        painter.scale(scale, scale)

        qcolor = QColor(color)
        stroke_path, fill_path = _build(name)

        if not fill_path.isEmpty():
            painter.setPen(Qt.PenStyle.NoPen)
            painter.setBrush(qcolor)
            painter.drawPath(fill_path)

        if not stroke_path.isEmpty():
            pen = QPen(qcolor)
            pen.setWidthF(stroke)
            pen.setCapStyle(Qt.PenCapStyle.RoundCap)
            pen.setJoinStyle(Qt.PenJoinStyle.RoundJoin)
            painter.setPen(pen)
            painter.setBrush(Qt.BrushStyle.NoBrush)
            painter.drawPath(stroke_path)
    finally:
        painter.end()

    pm.setDevicePixelRatio(dpr)
    _PIXMAP_CACHE[key] = pm
    return pm


def icon(name: str, color: str, size: int = 18, stroke: float = 1.9) -> QIcon:
    """Return a QIcon of `name` tinted `color`."""
    return QIcon(icon_pixmap(name, color, size, stroke))


def _icon_cache_dir() -> Path:
    path = Path.home() / ".cache" / "CommandBridge" / "icons"
    path.mkdir(parents=True, exist_ok=True)
    return path


def icon_png(name: str, color: str, size: int = 14, stroke: float = 2.0) -> str:
    """Write `name` to a PNG and return a forward-slash path for QSS url().

    Qt stylesheets cannot recolour an image, so each theme gets its own file
    keyed by colour. Paths use as_posix() so the same stylesheet string works
    on Linux and Windows.
    """
    key = (name, str(color), int(size), round(float(stroke), 2))
    cached = _PNG_CACHE.get(key)
    if cached is not None and Path(cached).exists():
        return cached

    safe_color = str(color).lstrip("#").lower()
    out = _icon_cache_dir() / f"{name}_{safe_color}_{size}_{int(stroke * 10)}.png"
    if not out.exists():
        pm = icon_pixmap(name, color, size, stroke)
        try:
            pm.save(str(out), "PNG")
        except Exception:
            return ""
    result = out.as_posix()
    _PNG_CACHE[key] = result
    return result


def clear_cache() -> None:
    """Drop cached pixmaps (called when the theme changes)."""
    _PIXMAP_CACHE.clear()
