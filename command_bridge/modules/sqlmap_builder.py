#!/usr/bin/env python3
"""Interactive sqlmap command builder for a pasted HTTP request.

The stock "Extensive" run is deliberately exhaustive: level 5, risk 3, every
technique including time-based, every parameter, and six enumeration flags. On
a real application that is tens of thousands of requests and can take hours,
which is the wrong shape for the question you usually want answered first —
*is this parameter injectable at all?*

This module builds the command instead of hard-coding it. You pick a speed
profile, tick the enumeration you actually want, and point sqlmap at one
parameter rather than all of them. The command is shown as it is assembled and
can be hand-edited before it runs, so nothing here is a black box.

Where the time actually goes, in rough order:

  * Time-based blind (``T``) is the expensive technique: every payload costs a
    deliberate delay, so a handful of parameters becomes minutes of sleeping.
    Dropping it is the single biggest win and it is what the fast profile does.
  * ``--level`` widens *where* sqlmap injects (5 reaches Cookie, User-Agent,
    Referer and Host); ``--risk`` widens *what* it injects. Both multiply the
    request count.
  * Every parameter is tested independently, so ``-p`` on the one you care
    about divides the work by the number of parameters you skipped.
  * ``--dbms`` skips fingerprinting payloads for the other nine engines.
"""

from __future__ import annotations

import json
import re
import shlex
import urllib.parse

# ─────────────────────────────────────────────────────────────────────────────
#  Speed profiles
# ─────────────────────────────────────────────────────────────────────────────
# "techniques" uses sqlmap's own letters:
#   B boolean-blind   E error-based   U union   S stacked   T time-blind   Q inline
# T is omitted from the quick profiles because it is the slow one by design.

SPEED_PROFILES = {
    "fast": {
        "label": "Fast — confirmation only",
        "level": 1,
        "risk": 1,
        "techniques": "BEU",
        "threads": 10,
        "smart": True,
        "extra": ["--timeout=10", "--retries=1"],
        "suffix": "fast",
        "blurb": ("Boolean, error and union payloads at level 1 / risk 1, ten "
                  "threads, heuristics first. No time-based payloads, so it "
                  "will not catch a purely time-blind injection — it answers "
                  "'is this injectable' in a minute or two, not 'find me "
                  "everything'."),
    },
    "balanced": {
        "label": "Balanced — confirm and identify",
        "level": 2,
        "risk": 1,
        "techniques": "BEUS",
        "threads": 5,
        "smart": False,
        "extra": ["--retries=2"],
        "suffix": "balanced",
        "blurb": ("Adds stacked queries and a second level of injection points "
                  "at five threads. Still no time-based payloads. A reasonable "
                  "default once a fast scan has found something."),
    },
    "thorough": {
        "label": "Thorough — full detection",
        "level": 5,
        "risk": 3,
        "techniques": "BEUSTQ",
        "threads": 1,
        "smart": False,
        "extra": [],
        "suffix": "thorough",
        "blurb": ("Every technique including time-based, every injection point "
                  "including headers and cookies, most intrusive payloads, "
                  "single-threaded so the timing stays honest. This is the slow "
                  "one — hours on a large request is normal."),
    },
}

DEFAULT_PROFILE = "fast"

# ─────────────────────────────────────────────────────────────────────────────
#  Enumeration flags
# ─────────────────────────────────────────────────────────────────────────────
# (flag, label, tooltip, cheap) — "cheap" ones are a single query once an
# injection is confirmed; the others walk the database and cost real time.

ENUM_OPTIONS = [
    ("--current-db",   "Current database name",     "One query. The DB the app itself is using.", True),
    ("--current-user", "Current database user",     "One query. The account the app connects as.", True),
    ("--is-dba",       "Is the user a DBA?",        "One query. Straight to the privilege question.", True),
    ("--banner",       "DBMS banner / version",     "One query. Exact engine and version string.", True),
    ("--hostname",     "Database server hostname",  "One query. Often reveals internal naming.", True),
    ("--dbs",          "List all databases",        "Enumerates every schema on the server.", False),
    ("--tables",       "List tables",               "Every table in scope — large on a real app.", False),
    ("--columns",      "List columns",              "Every column of every table in scope. Slow.", False),
    ("--schema",       "Full schema",               "Databases, tables and columns together. Slowest structural option.", False),
    ("--count",        "Row counts per table",      "One count query per table.", False),
    ("--privileges",   "User privileges",           "Privilege grants for the current user.", True),
    ("--roles",        "User roles",                "Role membership for the current user.", True),
    ("--passwords",    "Password hashes",           "Dumps credential hashes — confirm this is in scope.", False),
]

DBMS_CHOICES = [
    ("", "Auto-detect (sqlmap fingerprints it)"),
    ("MySQL", "MySQL / MariaDB"),
    ("PostgreSQL", "PostgreSQL"),
    ("Microsoft SQL Server", "Microsoft SQL Server"),
    ("Oracle", "Oracle"),
    ("SQLite", "SQLite"),
    ("IBM DB2", "IBM DB2"),
    ("Firebird", "Firebird"),
    ("Microsoft Access", "Microsoft Access"),
]

TAMPER_PRESETS = [
    ("", "None"),
    ("space2comment,between,randomcase", "General WAF bundle"),
    ("charencode,charunicodeencode", "Character encoding"),
    ("base64encode", "Base64"),
    ("space2comment", "Space to comment"),
    ("randomcase", "Random case"),
]

_HTTP_METHODS = {"GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS", "TRACE"}

#: Headers whose values legitimately contain "*" as a wildcard rather than as
#: sqlmap's injection marker — "Accept: */*" is on every request ever sent.
_WILDCARD_HEADERS = {
    "accept", "accept-encoding", "accept-language", "accept-charset",
    "access-control-allow-origin", "access-control-allow-headers",
    "access-control-allow-methods", "access-control-request-headers",
}


def _has_injection_marker(value: str) -> bool:
    """True when "*" looks like a marked injection point, not a wildcard.

    sqlmap's marker is appended to a real value (``id=1*``,
    ``X-Forwarded-For: 127.0.0.1*``), so the character before it is part of
    that value. A bare ``*`` or one behind a slash is a wildcard.
    """
    return bool(re.search(r"[^\s/*]\*", value or ""))

#: Cookie names that are session plumbing rather than application input. They
#: are still listed — a session cookie is a perfectly good injection point —
#: but they are not pre-ticked, because testing them is rarely the first move.
_BORING_COOKIES = {
    "phpsessid", "jsessionid", "asp.net_sessionid", "aspsessionid",
    "sessionid", "session_id", "session", "csrftoken", "csrf_token",
    "xsrf-token", "_csrf", "__requestverificationtoken",
    "_ga", "_gid", "_gat", "_gcl_au", "_fbp", "_fbc", "__utma", "__utmb",
    "__utmc", "__utmz", "_hjid", "ai_user", "ai_session",
}


# ─────────────────────────────────────────────────────────────────────────────
#  Parameter extraction
# ─────────────────────────────────────────────────────────────────────────────

class Parameter:
    """One candidate injection point found in a pasted request."""

    __slots__ = ("name", "where", "value", "note")

    def __init__(self, name: str, where: str, value: str = "", note: str = ""):
        self.name = name
        self.where = where          # query | body | json | cookie | multipart
        self.value = value
        self.note = note

    @property
    def interesting(self) -> bool:
        """Whether this one is worth pre-selecting."""
        if self.where == "cookie":
            return self.name.lower() not in _BORING_COOKIES
        return True

    def describe(self) -> str:
        value = self.value
        if len(value) > 38:
            value = value[:35] + "…"
        bits = [f"{self.name}"]
        if value:
            bits.append(f"= {value}")
        label = "  ".join(bits)
        tail = self.note or self.where.upper()
        return f"{label}   [{tail}]"

    def __repr__(self):  # pragma: no cover - debugging aid
        return f"<Parameter {self.name} {self.where}>"


def _add(found, seen, name, where, value="", note=""):
    name = (name or "").strip()
    if not name:
        return
    key = (name, where)
    if key in seen:
        return
    seen.add(key)
    found.append(Parameter(name, where, (value or "").strip(), note))


def _walk_json(node, found, seen, path=""):
    """Collect JSON keys. sqlmap addresses a JSON parameter by its key name,
    so that is what is recorded; the path is kept for the description only."""
    if isinstance(node, dict):
        for key, value in node.items():
            here = f"{path}.{key}" if path else str(key)
            if isinstance(value, (dict, list)):
                _walk_json(value, found, seen, here)
            else:
                note = "JSON" if here == key else f"JSON {here}"
                _add(found, seen, str(key), "json", "" if value is None else str(value), note)
    elif isinstance(node, list):
        for index, value in enumerate(node[:8]):
            _walk_json(value, found, seen, f"{path}[{index}]")


def extract_parameters(request_text: str) -> list:
    """Find candidate injection points in a raw HTTP request.

    Covers the query string, a form-encoded or JSON body, multipart field
    names and cookies. Anything the tester has already marked with sqlmap's
    ``*`` injection marker is reported first, because that marker overrides
    every other targeting decision.
    """
    found: list = []
    seen: set = set()

    text = (request_text or "").replace("\r\n", "\n").strip("\n")
    if not text.strip():
        return found

    head, _, body = text.partition("\n\n")
    lines = [line for line in head.split("\n") if line.strip()]
    if not lines:
        return found

    # ── Request line ──────────────────────────────────────────────────────
    first = lines[0].split()
    path = ""
    if first and first[0].upper() in _HTTP_METHODS and len(first) >= 2:
        path = first[1]
    elif "?" in lines[0]:
        path = lines[0]

    if _has_injection_marker(path):
        _add(found, seen, "URI", "uri", "", "marked with *")

    query = path.partition("?")[2]
    if query:
        for pair in re.split(r"[&;]", query):
            if not pair:
                continue
            name, _, value = pair.partition("=")
            _add(found, seen, urllib.parse.unquote_plus(name), "query",
                 urllib.parse.unquote_plus(value))

    # ── Headers ───────────────────────────────────────────────────────────
    content_type = ""
    for line in lines[1:]:
        if ":" not in line:
            continue
        name, _, value = line.partition(":")
        name_l = name.strip().lower()
        value = value.strip()

        if name_l == "content-type":
            content_type = value.lower()
        elif name_l == "cookie":
            for crumb in value.split(";"):
                cname, _, cvalue = crumb.strip().partition("=")
                _add(found, seen, cname, "cookie", cvalue)
        elif (_has_injection_marker(value)
              and name_l not in _WILDCARD_HEADERS
              and name_l not in ("cookie", "content-type")):
            # An explicitly marked header, e.g. "X-Forwarded-For: 127.0.0.1*"
            _add(found, seen, name.strip(), "header", value, "header, marked with *")

    # ── Body ──────────────────────────────────────────────────────────────
    body = body.strip()
    if body:
        if "json" in content_type or body[:1] in "{[":
            try:
                _walk_json(json.loads(body), found, seen)
            except (ValueError, TypeError):
                # Malformed or templated JSON — fall back to quoted keys.
                for key in re.findall(r'"([A-Za-z_][\w.\-]*)"\s*:', body):
                    _add(found, seen, key, "json", "", "JSON (unparsed body)")
        elif "multipart/form-data" in content_type:
            # `filename="…"` also ends in name="…"; it is the uploaded file's
            # name, not a form field, so it must not become an injection point.
            for key in re.findall(r'(?<!file)name="([^"]+)"', body):
                _add(found, seen, key, "multipart", "", "multipart field")
        elif "xml" in content_type or body.lstrip().startswith("<"):
            for key in re.findall(r"<([A-Za-z_][\w.\-]*)[\s>]", body):
                _add(found, seen, key, "xml", "", "XML element")
        else:
            for pair in re.split(r"[&;]", body):
                if not pair.strip():
                    continue
                name, _, value = pair.partition("=")
                _add(found, seen, urllib.parse.unquote_plus(name), "body",
                     urllib.parse.unquote_plus(value))

    # Explicit * markers win: sqlmap ignores -p entirely when one is present,
    # so they belong at the top of the list where they will be noticed.
    marked = [p for p in found
              if _has_injection_marker(p.value) or "marked with *" in p.note]
    if marked:
        for param in marked:
            if "marked" not in param.note:
                param.note = (param.note + " · marked with *").strip(" ·")
        rest = [p for p in found if p not in marked]
        found = marked + rest

    return found


def request_is_https(request_text: str, target: str = "") -> bool:
    """Best guess at whether the saved request was made over TLS.

    A raw request copied out of a proxy carries no scheme, so sqlmap assumes
    http:// and a plain-text retry against an HTTPS-only host produces a wall
    of connection errors that look like the target refusing to talk. The
    answer comes from the target, an absolute request line, or the handful of
    headers a browser only sends over TLS.
    """
    text = (request_text or "")
    lowered = text.lower()

    if (target or "").lower().startswith("https://"):
        return True

    first = lowered.split("\n", 1)[0]
    if "https://" in first:
        return True
    if "http://" in first:
        return False

    for marker in ("upgrade-insecure-requests:", "sec-fetch-site:",
                   "strict-transport-security:", ":scheme: https"):
        if marker in lowered:
            return True
    if re.search(r"^origin:\s*https://", lowered, re.MULTILINE):
        return True
    if re.search(r"^referer:\s*https://", lowered, re.MULTILINE):
        return True
    if re.search(r"^host:\s*\S+:443\b", lowered, re.MULTILINE):
        return True
    return False


# ─────────────────────────────────────────────────────────────────────────────
#  Command assembly
# ─────────────────────────────────────────────────────────────────────────────

def _quote(value: str) -> str:
    """Shell-quote only when the value needs it, so the preview stays readable."""
    value = str(value)
    # Brace placeholders ({SAFE_TARGET} and friends) are substituted later by
    # run_command_template and are safe to leave bare; quoting them only makes
    # the preview harder to read.
    if value and re.fullmatch(r"[A-Za-z0-9_.,:/=+@%{}-]+", value):
        return value
    return shlex.quote(value)


def build_command(options: dict) -> str:
    """Assemble an sqlmap command line from the dialog's state.

    ``options`` keys: profile, level, risk, threads, techniques, smart,
    request_file, output_dir, params, skip_params, dbms, tamper, enum,
    force_ssl, flush_session, proxy, verbosity, extra.
    """
    profile_key = options.get("profile", DEFAULT_PROFILE)
    profile = SPEED_PROFILES.get(profile_key, SPEED_PROFILES[DEFAULT_PROFILE])

    parts = ["sqlmap", "-r", _quote(options.get("request_file", "sql.txt")),
             "--batch", "--random-agent"]

    level = int(options.get("level", profile["level"]))
    risk = int(options.get("risk", profile["risk"]))
    parts += [f"--level={level}", f"--risk={risk}"]

    techniques = (options.get("techniques") or profile["techniques"]).strip().upper()
    if techniques and techniques != "BEUSTQ":
        parts.append(f"--technique={techniques}")

    threads = int(options.get("threads", profile["threads"]) or 1)
    # sqlmap serialises time-based payloads anyway, and threading them makes
    # the timing unreliable rather than faster.
    if "T" in techniques and threads > 1:
        threads = 1
    if threads > 1:
        parts.append(f"--threads={threads}")

    if options.get("smart", profile["smart"]):
        parts.append("--smart")

    params = [p for p in (options.get("params") or []) if p]
    if params:
        parts.append("-p " + _quote(",".join(params)))

    skip = [p for p in (options.get("skip_params") or []) if p]
    if skip:
        parts.append("--skip=" + _quote(",".join(skip)))

    dbms = (options.get("dbms") or "").strip()
    if dbms:
        parts.append("--dbms=" + _quote(dbms))

    tamper = (options.get("tamper") or "").strip()
    if tamper:
        parts.append("--tamper=" + _quote(tamper))

    if options.get("force_ssl"):
        parts.append("--force-ssl")
    if options.get("flush_session"):
        parts.append("--flush-session")

    proxy = (options.get("proxy") or "").strip()
    if proxy:
        parts.append("--proxy=" + _quote(proxy))

    for flag in options.get("extra", []) or profile["extra"]:
        if flag and flag not in parts:
            parts.append(flag)

    for flag in options.get("enum", []) or []:
        if flag not in parts:
            parts.append(flag)

    outdir = (options.get("output_dir") or "").strip()
    if outdir:
        parts.append("--output-dir=" + _quote(outdir))

    verbosity = options.get("verbosity", 1)
    parts.append(f"-v {int(verbosity)}")

    return " ".join(parts)


def default_output_dir(profile_key: str) -> str:
    """Per-profile output directory, so runs do not overwrite one another."""
    suffix = SPEED_PROFILES.get(profile_key, {}).get("suffix", "custom")
    return "{SAFE_TARGET}_sqlmap_http_" + suffix


def estimate_shape(options: dict) -> str:
    """A plain-language read on what the current settings will cost.

    Deliberately qualitative. A real request count depends on the target's
    behaviour, and a fabricated number would be worse than no number.
    """
    techniques = (options.get("techniques") or "").upper()
    level = int(options.get("level", 1))
    risk = int(options.get("risk", 1))
    params = options.get("params") or []
    enum = options.get("enum") or []
    detected = int(options.get("detected_count", 0) or 0)

    notes = []

    if "T" in techniques:
        notes.append("time-based payloads are in play, so expect deliberate "
                     "delays on every probe — this is the slow setting")
    else:
        notes.append("no time-based payloads, so no built-in sleeping")

    if params:
        if detected > len(params):
            notes.append(f"testing {len(params)} of {detected} parameters")
        else:
            notes.append(f"testing {len(params)} parameter"
                         f"{'s' if len(params) != 1 else ''}")
    else:
        notes.append("testing every parameter in the request")

    if level >= 4:
        notes.append(f"level {level} also injects into headers and cookies")
    elif level >= 2:
        notes.append(f"level {level} widens the injection points a little")

    if risk >= 3:
        notes.append("risk 3 includes OR-based payloads, which can modify data "
                     "on a bad day — keep it off UPDATE endpoints")

    heavy = [f for f in enum if f in ("--dbs", "--tables", "--columns",
                                      "--schema", "--count", "--passwords")]
    if heavy:
        notes.append("enumeration (" + ", ".join(heavy) + ") runs only after an "
                     "injection is confirmed, and walks the database")

    return "; ".join(notes) + "."


# ─────────────────────────────────────────────────────────────────────────────
#  The dialog
# ─────────────────────────────────────────────────────────────────────────────

from PyQt6.QtCore import Qt                                     # noqa: E402
from PyQt6.QtWidgets import (                                   # noqa: E402
    QDialog, QVBoxLayout, QHBoxLayout, QGridLayout, QFormLayout,
    QLabel, QPushButton, QPlainTextEdit, QCheckBox, QRadioButton,
    QButtonGroup, QGroupBox, QComboBox, QSpinBox, QLineEdit,
    QListWidget, QListWidgetItem, QDialogButtonBox, QScrollArea,
    QWidget, QSplitter, QFrame,
)


class SqlmapBuilderDialog(QDialog):
    """Assemble an sqlmap run from a pasted request, with the command in view.

    The dialog owns no state of its own beyond the widgets: every change
    re-runs :func:`build_command`, so what is shown in the preview is exactly
    what will be executed. Taking the preview off auto-update ("Edit the
    command by hand") hands over control completely — from that point the text
    box is the source of truth and nothing overwrites it.
    """

    def __init__(self, parent=None, request_text: str = "", target: str = "",
                 remembered: dict | None = None):
        super().__init__(parent)
        self.setWindowTitle("SQLMap — build a scan")
        self.setMinimumSize(1120, 780)

        self._target = target or ""
        self._params: list = []
        self._manual = False
        self._remembered = remembered or {}

        root = QVBoxLayout(self)
        root.setContentsMargins(16, 16, 16, 12)
        root.setSpacing(12)

        splitter = QSplitter(Qt.Orientation.Horizontal)
        splitter.addWidget(self._build_request_side(request_text))
        splitter.addWidget(self._build_options_side())
        splitter.setStretchFactor(0, 4)
        splitter.setStretchFactor(1, 5)
        root.addWidget(splitter, 1)

        root.addWidget(self._build_preview_side())

        buttons = QDialogButtonBox(
            QDialogButtonBox.StandardButton.Ok | QDialogButtonBox.StandardButton.Cancel
        )
        buttons.button(QDialogButtonBox.StandardButton.Ok).setText("Run scan")
        buttons.accepted.connect(self.accept)
        buttons.rejected.connect(self.reject)
        root.addWidget(buttons)

        self._restore(self._remembered)
        if request_text.strip():
            self.detect_parameters(quiet=True)
        self._refresh()

    # ── Construction ──────────────────────────────────────────────────────

    def _build_request_side(self, request_text: str) -> QWidget:
        box = QWidget()
        layout = QVBoxLayout(box)
        layout.setContentsMargins(0, 0, 8, 0)

        heading = QLabel("1 · The request")
        heading.setObjectName("fieldLabel")
        layout.addWidget(heading)

        hint = QLabel(
            "Paste a full request from Burp or ZAP — request line, headers, a "
            "blank line, then the body. It is saved as sql.txt and passed to "
            "sqlmap with -r.\n"
            "Marking a spot with * (e.g. id=1*) overrides parameter selection "
            "entirely; sqlmap will test only there."
        )
        hint.setWordWrap(True)
        hint.setObjectName("hintLabel")
        layout.addWidget(hint)

        self.request_edit = QPlainTextEdit()
        self.request_edit.setPlaceholderText(
            "POST /search HTTP/1.1\n"
            "Host: example.co.uk\n"
            "Content-Type: application/x-www-form-urlencoded\n"
            "Cookie: session=…\n"
            "\n"
            "query=widget&category=2"
        )
        self.request_edit.setPlainText(request_text)
        layout.addWidget(self.request_edit, 1)

        row = QHBoxLayout()
        self.detect_btn = QPushButton("Detect parameters")
        self.detect_btn.setToolTip(
            "Read the query string, body, JSON keys and cookies out of the "
            "request above and list them as injection points."
        )
        self.detect_btn.clicked.connect(lambda: self.detect_parameters())
        row.addWidget(self.detect_btn)
        self.detect_status = QLabel("")
        self.detect_status.setObjectName("hintLabel")
        row.addWidget(self.detect_status, 1)
        layout.addLayout(row)

        return box

    def _build_options_side(self) -> QWidget:
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QFrame.Shape.NoFrame)

        inner = QWidget()
        layout = QVBoxLayout(inner)
        layout.setContentsMargins(8, 0, 0, 0)
        layout.setSpacing(12)

        layout.addWidget(self._group_speed())
        layout.addWidget(self._group_params())
        layout.addWidget(self._group_enum())
        layout.addWidget(self._group_hints())
        layout.addStretch()

        scroll.setWidget(inner)
        return scroll

    def _group_speed(self) -> QGroupBox:
        box = QGroupBox("2 · How hard to look")
        box.setObjectName("card")
        layout = QVBoxLayout(box)

        self.profile_group = QButtonGroup(self)
        self._profile_buttons = {}
        for key, profile in SPEED_PROFILES.items():
            radio = QRadioButton(profile["label"])
            radio.setToolTip(profile["blurb"])
            self.profile_group.addButton(radio)
            self._profile_buttons[key] = radio
            layout.addWidget(radio)
        self._profile_buttons[DEFAULT_PROFILE].setChecked(True)
        self.profile_group.buttonClicked.connect(self._on_profile_changed)

        self.profile_blurb = QLabel(SPEED_PROFILES[DEFAULT_PROFILE]["blurb"])
        self.profile_blurb.setWordWrap(True)
        self.profile_blurb.setObjectName("hintLabel")
        layout.addWidget(self.profile_blurb)

        form = QFormLayout()
        form.setContentsMargins(0, 8, 0, 0)

        self.level_spin = QSpinBox()
        self.level_spin.setRange(1, 5)
        self.level_spin.setToolTip("Where sqlmap injects. 5 reaches cookies, "
                                   "User-Agent, Referer and Host.")
        form.addRow("Level", self.level_spin)

        self.risk_spin = QSpinBox()
        self.risk_spin.setRange(1, 3)
        self.risk_spin.setToolTip("What sqlmap injects. 3 includes OR-based "
                                  "payloads that can alter data.")
        form.addRow("Risk", self.risk_spin)

        self.threads_spin = QSpinBox()
        self.threads_spin.setRange(1, 20)
        self.threads_spin.setToolTip("Concurrent requests. Forced back to 1 "
                                     "when time-based payloads are enabled.")
        form.addRow("Threads", self.threads_spin)

        self.time_check = QCheckBox("Include time-based blind payloads (slow)")
        self.time_check.setToolTip(
            "Time-based injection is found by making the database sleep, so "
            "every probe costs real seconds. Leave it off for a first pass; "
            "turn it on when a parameter looks suspicious but nothing else "
            "has confirmed it."
        )
        form.addRow("", self.time_check)

        self.smart_check = QCheckBox("Heuristics first (--smart)")
        self.smart_check.setToolTip(
            "Only test a parameter thoroughly once a quick heuristic says it "
            "looks injectable. A large saving on requests with many parameters."
        )
        form.addRow("", self.smart_check)

        layout.addLayout(form)

        for widget in (self.level_spin, self.risk_spin, self.threads_spin):
            widget.valueChanged.connect(self._refresh)
        for widget in (self.time_check, self.smart_check):
            widget.toggled.connect(self._refresh)

        return box

    def _group_params(self) -> QGroupBox:
        box = QGroupBox("3 · Which parameters")
        box.setObjectName("card")
        layout = QVBoxLayout(box)

        self.param_mode = QButtonGroup(self)
        self.mode_all = QRadioButton("Test every parameter in the request")
        self.mode_only = QRadioButton("Test only the ticked ones  (-p)")
        self.mode_skip = QRadioButton("Test everything except the ticked ones  (--skip)")
        for radio in (self.mode_all, self.mode_only, self.mode_skip):
            self.param_mode.addButton(radio)
            layout.addWidget(radio)
        self.mode_only.setChecked(True)
        self.param_mode.buttonClicked.connect(self._refresh)

        self.param_list = QListWidget()
        self.param_list.setMinimumHeight(140)
        self.param_list.setToolTip(
            "Detected injection points. Narrowing to one is the difference "
            "between a scan that finishes over a coffee and one that does not."
        )
        self.param_list.itemChanged.connect(lambda *_: self._refresh())
        layout.addWidget(self.param_list)

        row = QHBoxLayout()
        for text, handler in (("All", lambda: self._set_all_params(True)),
                              ("None", lambda: self._set_all_params(False))):
            btn = QPushButton(text)
            btn.setMaximumWidth(80)
            btn.clicked.connect(handler)
            row.addWidget(btn)
        row.addStretch()
        layout.addLayout(row)

        return box

    def _group_enum(self) -> QGroupBox:
        box = QGroupBox("4 · What to collect once something is found")
        box.setObjectName("card")
        layout = QVBoxLayout(box)

        note = QLabel(
            "None of this runs unless an injection is confirmed. The first "
            "five are a single query each; the rest walk the database."
        )
        note.setWordWrap(True)
        note.setObjectName("hintLabel")
        layout.addWidget(note)

        grid = QGridLayout()
        self.enum_checks = {}
        for index, (flag, label, tip, cheap) in enumerate(ENUM_OPTIONS):
            check = QCheckBox(label)
            check.setToolTip(f"{flag} — {tip}")
            check.toggled.connect(self._refresh)
            self.enum_checks[flag] = check
            grid.addWidget(check, index // 2, index % 2)
        layout.addLayout(grid)

        return box

    def _group_hints(self) -> QGroupBox:
        box = QGroupBox("5 · Target hints")
        box.setObjectName("card")
        form = QFormLayout(box)

        self.dbms_combo = QComboBox()
        for value, label in DBMS_CHOICES:
            self.dbms_combo.addItem(label, value)
        self.dbms_combo.setToolTip(
            "Naming the engine skips fingerprinting payloads for all the "
            "others — a real saving when you already know what it runs."
        )
        self.dbms_combo.currentIndexChanged.connect(self._refresh)
        form.addRow("Database engine", self.dbms_combo)

        self.tamper_combo = QComboBox()
        for value, label in TAMPER_PRESETS:
            self.tamper_combo.addItem(label, value)
        self.tamper_combo.setEditable(True)
        self.tamper_combo.setToolTip(
            "Payload rewriting for WAF evasion. Each script adds work, so "
            "leave it off until something is actually being blocked."
        )
        self.tamper_combo.currentTextChanged.connect(self._refresh)
        form.addRow("Tamper scripts", self.tamper_combo)

        self.ssl_check = QCheckBox("Request was sent over HTTPS  (--force-ssl)")
        self.ssl_check.setToolTip(
            "A raw request carries no scheme, so sqlmap assumes http:// and "
            "an HTTPS-only host answers with connection errors that look like "
            "the target refusing to talk."
        )
        self.ssl_check.toggled.connect(self._refresh)
        form.addRow("", self.ssl_check)

        self.flush_check = QCheckBox("Ignore earlier results for this target  (--flush-session)")
        self.flush_check.setToolTip(
            "sqlmap caches what it learned. Flush when the application has "
            "changed, or when a previous run's conclusions look wrong."
        )
        self.flush_check.toggled.connect(self._refresh)
        form.addRow("", self.flush_check)

        proxy_row = QHBoxLayout()
        self.proxy_check = QCheckBox("Through a proxy")
        self.proxy_check.toggled.connect(self._refresh)
        proxy_row.addWidget(self.proxy_check)
        self.proxy_edit = QLineEdit("http://127.0.0.1:8080")
        self.proxy_edit.textChanged.connect(self._refresh)
        proxy_row.addWidget(self.proxy_edit, 1)
        holder = QWidget()
        holder.setLayout(proxy_row)
        form.addRow("", holder)

        return box

    def _build_preview_side(self) -> QWidget:
        box = QWidget()
        layout = QVBoxLayout(box)
        layout.setContentsMargins(0, 0, 0, 0)

        self.summary = QLabel("")
        self.summary.setWordWrap(True)
        self.summary.setObjectName("hintLabel")
        layout.addWidget(self.summary)

        heading = QHBoxLayout()
        title = QLabel("Command")
        title.setObjectName("fieldLabel")
        heading.addWidget(title)
        heading.addStretch()
        self.manual_check = QCheckBox("Edit the command by hand")
        self.manual_check.setToolTip(
            "Stops the options above from rewriting the command. Anything "
            "typed here runs exactly as written."
        )
        self.manual_check.toggled.connect(self._on_manual_toggled)
        heading.addWidget(self.manual_check)
        layout.addLayout(heading)

        self.preview = QPlainTextEdit()
        self.preview.setReadOnly(True)
        self.preview.setMaximumHeight(96)
        self.preview.setObjectName("commandPreview")
        layout.addWidget(self.preview)

        return box

    # ── Behaviour ─────────────────────────────────────────────────────────

    def _on_profile_changed(self):
        profile = SPEED_PROFILES[self.selected_profile()]
        self.profile_blurb.setText(profile["blurb"])
        for widget, value in ((self.level_spin, profile["level"]),
                              (self.risk_spin, profile["risk"]),
                              (self.threads_spin, profile["threads"])):
            widget.blockSignals(True)
            widget.setValue(value)
            widget.blockSignals(False)
        for widget, value in ((self.time_check, "T" in profile["techniques"]),
                              (self.smart_check, profile["smart"])):
            widget.blockSignals(True)
            widget.setChecked(value)
            widget.blockSignals(False)
        self._refresh()

    def _on_manual_toggled(self, on: bool):
        self._manual = on
        self.preview.setReadOnly(not on)
        if not on:
            self._refresh()

    def _set_all_params(self, checked: bool):
        state = Qt.CheckState.Checked if checked else Qt.CheckState.Unchecked
        self.param_list.blockSignals(True)
        for row in range(self.param_list.count()):
            self.param_list.item(row).setCheckState(state)
        self.param_list.blockSignals(False)
        self._refresh()

    def detect_parameters(self, quiet: bool = False):
        """Re-read the request box and rebuild the parameter list."""
        text = self.request_edit.toPlainText()
        self._params = extract_parameters(text)

        self.param_list.blockSignals(True)
        self.param_list.clear()
        for param in self._params:
            item = QListWidgetItem(param.describe())
            item.setFlags(item.flags() | Qt.ItemFlag.ItemIsUserCheckable)
            item.setCheckState(Qt.CheckState.Checked if param.interesting
                               else Qt.CheckState.Unchecked)
            item.setData(Qt.ItemDataRole.UserRole, param.name)
            self.param_list.addItem(item)
        self.param_list.blockSignals(False)

        marked = any("marked with *" in (p.note or "") for p in self._params)
        if not self._params:
            message = "No parameters found — sqlmap will work it out itself."
        elif marked:
            message = (f"{len(self._params)} found. The request has a * marker, "
                       "which overrides any selection here.")
        else:
            message = f"{len(self._params)} found."
        self.detect_status.setText(message)

        if self._params and not quiet:
            self.mode_only.setChecked(True)

        # A raw paste carries no scheme; take the best guess so the first run
        # does not fail against an HTTPS-only host.
        self.ssl_check.blockSignals(True)
        self.ssl_check.setChecked(request_is_https(text, self._target))
        self.ssl_check.blockSignals(False)

        self._refresh()

    def _checked_params(self) -> list:
        names = []
        for row in range(self.param_list.count()):
            item = self.param_list.item(row)
            if item.checkState() == Qt.CheckState.Checked:
                names.append(item.data(Qt.ItemDataRole.UserRole))
        return names

    def selected_profile(self) -> str:
        for key, radio in self._profile_buttons.items():
            if radio.isChecked():
                return key
        return DEFAULT_PROFILE

    def options(self) -> dict:
        profile_key = self.selected_profile()
        profile = SPEED_PROFILES[profile_key]

        techniques = profile["techniques"]
        if self.time_check.isChecked():
            techniques = "".join(dict.fromkeys(techniques + "T"))
        else:
            techniques = techniques.replace("T", "")
        if not techniques:
            techniques = "BEU"

        chosen = self._checked_params()
        params, skip = [], []
        if self.mode_only.isChecked():
            params = chosen
        elif self.mode_skip.isChecked():
            skip = chosen

        enum = [flag for flag, check in self.enum_checks.items() if check.isChecked()]

        return {
            "profile": profile_key,
            "level": self.level_spin.value(),
            "risk": self.risk_spin.value(),
            "threads": self.threads_spin.value(),
            "techniques": techniques,
            "smart": self.smart_check.isChecked(),
            "request_file": "sql.txt",
            "output_dir": default_output_dir(profile_key),
            "params": params,
            "skip_params": skip,
            "dbms": self.dbms_combo.currentData() or "",
            "tamper": (self.tamper_combo.currentData()
                       if self.tamper_combo.currentIndex() >= 0
                       and self.tamper_combo.currentText() ==
                       self.tamper_combo.itemText(self.tamper_combo.currentIndex())
                       else self.tamper_combo.currentText()) or "",
            "enum": enum,
            "force_ssl": self.ssl_check.isChecked(),
            "flush_session": self.flush_check.isChecked(),
            "proxy": self.proxy_edit.text() if self.proxy_check.isChecked() else "",
            "verbosity": 1,
            "extra": list(profile["extra"]),
            "detected_count": len(self._params),
        }

    def _refresh(self, *_):
        if self._manual:
            return
        options = self.options()
        self.threads_spin.setEnabled(not self.time_check.isChecked())
        self.proxy_edit.setEnabled(self.proxy_check.isChecked())
        self.param_list.setEnabled(not self.mode_all.isChecked())
        self.preview.setPlainText(build_command(options))
        self.summary.setText(estimate_shape(options))

    # ── Results ───────────────────────────────────────────────────────────

    def command_text(self) -> str:
        return self.preview.toPlainText().strip()

    def request_text(self) -> str:
        return self.request_edit.toPlainText().strip()

    def remembered(self) -> dict:
        """The settings worth restoring next time (never the request itself)."""
        options = self.options()
        for key in ("params", "skip_params", "detected_count", "output_dir",
                    "request_file"):
            options.pop(key, None)
        options["param_mode"] = ("all" if self.mode_all.isChecked()
                                 else "skip" if self.mode_skip.isChecked()
                                 else "only")
        options["proxy_on"] = self.proxy_check.isChecked()
        options["proxy_url"] = self.proxy_edit.text()
        return options

    def _restore(self, saved: dict):
        if not saved:
            self._on_profile_changed()
            return
        try:
            profile = saved.get("profile", DEFAULT_PROFILE)
            if profile in self._profile_buttons:
                self._profile_buttons[profile].setChecked(True)
            self._on_profile_changed()

            for widget, key in ((self.level_spin, "level"),
                                (self.risk_spin, "risk"),
                                (self.threads_spin, "threads")):
                if key in saved:
                    widget.blockSignals(True)
                    widget.setValue(int(saved[key]))
                    widget.blockSignals(False)

            if "techniques" in saved:
                self.time_check.blockSignals(True)
                self.time_check.setChecked("T" in str(saved["techniques"]).upper())
                self.time_check.blockSignals(False)
            if "smart" in saved:
                self.smart_check.blockSignals(True)
                self.smart_check.setChecked(bool(saved["smart"]))
                self.smart_check.blockSignals(False)

            for flag in saved.get("enum", []):
                if flag in self.enum_checks:
                    self.enum_checks[flag].blockSignals(True)
                    self.enum_checks[flag].setChecked(True)
                    self.enum_checks[flag].blockSignals(False)

            dbms = saved.get("dbms", "")
            for index in range(self.dbms_combo.count()):
                if self.dbms_combo.itemData(index) == dbms:
                    self.dbms_combo.setCurrentIndex(index)
                    break

            if saved.get("tamper"):
                self.tamper_combo.setCurrentText(saved["tamper"])

            mode = saved.get("param_mode", "only")
            {"all": self.mode_all, "skip": self.mode_skip,
             "only": self.mode_only}.get(mode, self.mode_only).setChecked(True)

            self.flush_check.setChecked(bool(saved.get("flush_session")))
            self.proxy_check.setChecked(bool(saved.get("proxy_on")))
            if saved.get("proxy_url"):
                self.proxy_edit.setText(saved["proxy_url"])
        except Exception:
            # A malformed settings file must never stop the dialog opening.
            pass
