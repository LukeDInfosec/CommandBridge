"""Enhanced console widget with ANSI color support and smart output formatting."""

import re
from PyQt6 import QtGui
from PyQt6.QtCore import QMimeData
from PyQt6.QtWidgets import QTextEdit


_SPACE_RUN_RE = re.compile(r"  +")


def _keep_spacing(escaped_text: str) -> str:
    """Preserve runs of spaces inside HTML output.

    Console lines are inserted as HTML so findings can be colour-coded, but
    HTML collapses consecutive spaces — which flattens every ASCII banner
    (SmartFuzz, ffuf, wpscan) and every column-aligned result row into a
    single run-on line. Converting runs of two or more spaces to &nbsp;
    keeps the alignment while leaving single spaces breakable, so long URLs
    still wrap normally.
    """
    return _SPACE_RUN_RE.sub(lambda m: "&nbsp;" * len(m.group(0)), escaped_text)


def _blend(color_a: str, color_b: str, weight: float) -> str:
    """Blend two hex colours (weight 0.0 = all A, 1.0 = all B)."""
    try:
        a, b = color_a.lstrip("#"), color_b.lstrip("#")
        ar, ag, ab = int(a[0:2], 16), int(a[2:4], 16), int(a[4:6], 16)
        br, bg, bb = int(b[0:2], 16), int(b[2:4], 16), int(b[4:6], 16)
        w = max(0.0, min(1.0, weight))
        return "#{:02x}{:02x}{:02x}".format(
            round(ar + (br - ar) * w), round(ag + (bg - ag) * w), round(ab + (bb - ab) * w)
        )
    except Exception:
        return color_a


class EnhancedConsole(QTextEdit):
    """Console with ANSI handling, semantic result highlighting and auto-scroll.

    Highlight colours come from the active theme rather than being baked in,
    so a 200 hit reads as "good" in every palette — including the light one,
    where the old hardcoded neon green on near-black was unreadable.
    """

    # Sensible defaults so the widget is usable before a theme is applied.
    _DEFAULT_COLORS = {
        "ok": "#22c55e",        # 200 / open / safe / low severity
        "redirect": "#facc15",  # 3xx
        "client": "#f97316",    # 4xx / medium severity
        "server": "#ef4444",    # 5xx / high severity / dangerous
        "info": "#38bdf8",      # informational headers
    }

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setReadOnly(True)
        self.setObjectName("consoleOutput")
        font = QtGui.QFont()
        font.setFamilies(["JetBrains Mono", "Fira Code", "Cascadia Code", "DejaVu Sans Mono", "Monospace"])
        font.setPointSize(11)
        self.setFont(font)

        self._colors = dict(self._DEFAULT_COLORS)
        self._auto_scroll = True
        self._dirsearch_base_url: str | None = None
        sb = self.verticalScrollBar()
        sb.valueChanged.connect(self._on_scrollbar_value_changed)

    def apply_theme_colors(self, theme: dict):
        """Re-derive result highlight colours from the active palette."""
        try:
            success = theme.get("success", self._DEFAULT_COLORS["ok"])
            warning = theme.get("warning", self._DEFAULT_COLORS["redirect"])
            danger = theme.get("danger") or theme.get("accent", self._DEFAULT_COLORS["server"])
            info = theme.get("info") or theme.get("accent", self._DEFAULT_COLORS["info"])

            self._colors = {
                "ok": success,
                "redirect": warning,
                "client": _blend(warning, danger, 0.45),
                "server": danger,
                "info": info,
            }
        except Exception:
            self._colors = dict(self._DEFAULT_COLORS)

    def _status_color(self, status_code: str) -> str:
        """Map an HTTP status code onto a semantic highlight colour."""
        code = str(status_code)
        if code.startswith("2"):
            return self._colors["ok"]
        if code.startswith("3"):
            return self._colors["redirect"]
        if code.startswith("4"):
            return self._colors["client"]
        return self._colors["server"]

    def _on_scrollbar_value_changed(self, value: int):
        sb = self.verticalScrollBar()
        try:
            self._auto_scroll = (value >= sb.maximum())
        except Exception:
            self._auto_scroll = True

    #: Longest partial escape sequence worth holding back before giving up and
    #: printing it — a real one is a handful of bytes, so anything longer is
    #: not an escape and should not be buffered indefinitely.
    _MAX_ANSI_TAIL = 16

    def append_ansi(self, text):
        """Append text with ANSI colour support and carriage-return handling."""
        ansi_escape = re.compile(r'\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])')

        # Output arrives in whatever sized chunks the pipe delivers, so an
        # escape sequence can be split down the middle. Half a sequence does
        # not match the pattern above and would be printed as literal "[0m"
        # rubbish, so an unterminated tail is held back until the rest arrives.
        tail = getattr(self, '_ansi_tail', '')
        if tail:
            text = tail + text
            self._ansi_tail = ''
        partial = re.search(r'\x1B\[[0-9;]*$|\x1B$', text)
        if partial and len(text) - partial.start() <= self._MAX_ANSI_TAIL:
            self._ansi_tail = text[partial.start():]
            text = text[:partial.start()]
            if not text:
                return

        clean_text = ansi_escape.sub('', text)

        # A lone \r means "go back to the start of this line" — it is how every
        # command-line tool draws a progress counter in place. Rewriting it to
        # \n turned one updating line into hundreds of stacked ones, which
        # buried the actual findings. Progress output is never worth colouring,
        # so CR text takes the plain path.
        if '\r' in clean_text.replace('\r\n', '\n'):
            self._append_with_carriage_returns(clean_text)
        else:
            colored_text = self._apply_feroxbuster_colors(clean_text)
            cursor = self.textCursor()
            cursor.movePosition(cursor.MoveOperation.End)
            if colored_text != clean_text:
                cursor.insertHtml(colored_text)
            else:
                cursor.insertText(clean_text.replace('\r\n', '\n'))
            self.setTextCursor(cursor)

        scrollbar = self.verticalScrollBar()
        if getattr(self, "_auto_scroll", True):
            scrollbar.setValue(scrollbar.maximum())

    def _append_with_carriage_returns(self, text: str):
        """Insert text, treating each \r as a rewrite of the current line.

        Splitting on \r gives the successive states of one line: the first
        chunk is appended normally and every later chunk replaces whatever is
        currently on the last line, which is what a terminal does.
        """
        cursor = self.textCursor()
        cursor.movePosition(cursor.MoveOperation.End)

        chunks = text.replace('\r\n', '\n').split('\r')
        cursor.insertText(chunks[0])
        for chunk in chunks[1:]:
            cursor.movePosition(cursor.MoveOperation.End)
            cursor.movePosition(cursor.MoveOperation.StartOfBlock,
                                cursor.MoveMode.KeepAnchor)
            cursor.removeSelectedText()
            cursor.insertText(chunk)
        self.setTextCursor(cursor)

    def _apply_feroxbuster_colors(self, text):
        """Apply color formatting to tool output lines."""
        import html

        ferox_pattern = re.compile(
            r'^(\d{3})\s+(GET|POST|PUT|DELETE|HEAD|OPTIONS|PATCH)\s+(.+?)(https?://[^\s]+)\s*$',
            re.MULTILINE
        )
        nmap_open_pattern = re.compile(r'^(\d+/(tcp|udp))\s+open\b.*$')

        # Gobuster: /path   (Status: 200) [Size: 1234] [--> /redirect]
        gobuster_hit_pattern = re.compile(
            r'^(/\S*)\s+\(Status:\s*(\d+)\)(.*)',
        )
        # Gobuster --expanded / dirsearch --full-url: full URL then (Status: NNN)
        url_status_pattern = re.compile(
            r'^(https?://\S+)\s+\(Status:\s*(\d+)\)(.*)',
        )

        dirsearch_progress_pattern = re.compile(r'^\[[\s\=\-\>\|#]+\]\s*\d+%')
        dirsearch_target_pattern = re.compile(r'^Target:\s+(https?://\S+)', re.IGNORECASE)
        dirsearch_hit_pattern = re.compile(
            r'^\[(\d{2}:\d{2}:\d{2})\]\s+(\d{3})\s+-\s+([^\s]+)\s+-\s+(\S+)$'
        )
        dirsearch_job_pattern = re.compile(
            r'^(job:\s*\d+/\d+\s+errors:\s*\d+|errors:\s*\d+|:\s*\d+/\d+\s+errors:\s*\d+|:\s*\d+)\s*$',
            re.IGNORECASE,
        )
        summary_header_pattern = re.compile(r'^(.*?)\s+\((Low|Medium|High)\)$')
        danger_tag_pattern = re.compile(r'^\[DANGEROUS\]')
        warning_tag_pattern = re.compile(r'^\[WARNING\]')
        # ssl_cipher_check.py severity tags, e.g. "[CRITICAL]  Certificate EXPIRED..."
        severity_tag_pattern = re.compile(r'^\[(CRITICAL|HIGH|MEDIUM|LOW)\]')
        ok_tag_pattern = re.compile(r'^\[OK\]')

        tick_char = '✅'
        cross_char = '❌'
        openredir_bad_pattern = re.compile(r'^\[✖\]')
        openredir_good_pattern = re.compile(r'^\[✔\]')

        text_norm = text.replace('\r\n', '\n').replace('\r', '\n')
        lines = text_norm.split('\n')
        formatted_lines = []
        changed = False

        for line in lines:
            stripped = line.strip()

            if dirsearch_progress_pattern.match(stripped):
                changed = True
                continue

            if dirsearch_job_pattern.match(stripped):
                changed = True
                continue

            m_dir_tgt = dirsearch_target_pattern.match(stripped)
            if m_dir_tgt:
                base = m_dir_tgt.group(1).rstrip('/')
                try:
                    self._dirsearch_base_url = base
                except Exception:
                    self._dirsearch_base_url = base
                escaped = _keep_spacing(html.escape(line.expandtabs(4)))
                formatted_lines.append(
                    f'<span style="color: {self._colors["info"]}; font-weight: bold;">{escaped}</span><br>'
                )
                changed = True
                continue

            m_dir_hit = dirsearch_hit_pattern.match(stripped)
            if m_dir_hit:
                status_code = m_dir_hit.group(2)
                size = m_dir_hit.group(3)
                path = m_dir_hit.group(4)

                if status_code != '200':
                    changed = True
                    continue

                base = getattr(self, "_dirsearch_base_url", None) or ""
                if base and path.startswith("/"):
                    full_url = f"{base}{path}"
                elif base:
                    full_url = f"{base}/{path}"
                else:
                    full_url = path

                formatted_lines.append(
                    f'<span style="color: {self._colors["ok"]}; font-weight: bold;">[200 OK]</span> '
                    f'<span style="color: {self._colors["ok"]};">{html.escape(size)} — {html.escape(full_url)}</span><br>'
                )
                changed = True
                continue

            if danger_tag_pattern.search(stripped):
                escaped = _keep_spacing(html.escape(line.expandtabs(4)))
                formatted_lines.append(
                    f'<span style="color: {self._colors["server"]}; font-weight: bold;">{escaped}</span><br>'
                )
                changed = True
                continue

            if warning_tag_pattern.search(stripped):
                escaped = _keep_spacing(html.escape(line.expandtabs(4)))
                formatted_lines.append(
                    f'<span style="color: {self._colors["client"]}; font-weight: bold;">{escaped}</span><br>'
                )
                changed = True
                continue

            sev_m = severity_tag_pattern.match(stripped)
            if sev_m:
                severity = sev_m.group(1)
                sev_color = {
                    "CRITICAL": self._colors["server"],
                    "HIGH": self._colors["server"],
                    "MEDIUM": self._colors["client"],
                    "LOW": self._colors["redirect"],
                }[severity]
                escaped = _keep_spacing(html.escape(line.expandtabs(4)))
                formatted_lines.append(
                    f'<span style="color: {sev_color}; font-weight: bold;">{escaped}</span><br>'
                )
                changed = True
                continue

            if ok_tag_pattern.match(stripped):
                escaped = _keep_spacing(html.escape(line.expandtabs(4)))
                formatted_lines.append(
                    f'<span style="color: {self._colors["ok"]};">{escaped}</span><br>'
                )
                changed = True
                continue

            match = ferox_pattern.match(stripped)
            if match:
                status_code = match.group(1)
                url = match.group(4)
                c = self._status_color(status_code)
                formatted_line = (
                    f'<span style="color: {c}; font-weight: bold;">[{status_code}]</span> '
                    f'<span style="color: {c};">{html.escape(url)}</span>'
                )
                formatted_lines.append(formatted_line + '<br>')
                changed = True
                continue

            if nmap_open_pattern.match(stripped):
                escaped = _keep_spacing(html.escape(line.expandtabs(4)))
                formatted_line = (
                    f'<span style="color: {self._colors["ok"]}; font-weight: bold;">{escaped}</span>'
                )
                formatted_lines.append(formatted_line + '<br>')
                changed = True
                continue

            um = url_status_pattern.match(stripped)
            if um:
                full_url = um.group(1)
                status_code = um.group(2)
                rest_part = um.group(3)
                c = self._status_color(status_code)
                formatted_lines.append(
                    f'<span style="color: {c}; font-weight: bold;">[{status_code}]</span> '
                    f'<span style="color: {c};">{html.escape(full_url)}</span>'
                    f'<span style="color: {c}80;">{html.escape(rest_part)}</span><br>'
                )
                changed = True
                continue

            gm = gobuster_hit_pattern.match(stripped)
            if gm:
                path_part = gm.group(1)
                status_code = gm.group(2)
                rest_part = gm.group(3)
                c = self._status_color(status_code)
                esc_path = html.escape(path_part)
                esc_rest = html.escape(rest_part)
                formatted_lines.append(
                    f'<span style="color: {c}; font-weight: bold;">{esc_path}</span>'
                    f'<span style="color: {c}80;"> (Status: {status_code}){esc_rest}</span><br>'
                )
                changed = True
                continue

            sm = summary_header_pattern.match(stripped)
            if sm:
                text_part, sev = sm.groups()
                sev = sev.lower()
                if sev == 'low':
                    color = self._colors["ok"]
                elif sev == 'medium':
                    color = self._colors["client"]
                else:
                    color = self._colors["server"]
                escaped_text = html.escape(text_part)
                formatted_line = f'<span style="color: {color}; font-weight: bold;">{escaped_text} ({sev.title()})</span>'
                formatted_lines.append(formatted_line + '<br>')
                changed = True
                continue

            if tick_char in stripped or cross_char in stripped:
                if cross_char in stripped:
                    color = self._colors["client"]
                else:
                    color = self._colors["ok"]
                escaped = _keep_spacing(html.escape(line.expandtabs(4)))
                formatted_lines.append(
                    f'<span style="color: {color}; font-weight: bold;">{escaped}</span><br>'
                )
                changed = True
                continue

            if openredir_bad_pattern.match(stripped):
                escaped = _keep_spacing(html.escape(line.expandtabs(4)))
                formatted_lines.append(
                    f'<span style="color: {self._colors["server"]}; font-weight: bold;">{escaped}</span><br>'
                )
                changed = True
                continue

            if openredir_good_pattern.match(stripped):
                escaped = _keep_spacing(html.escape(line.expandtabs(4)))
                formatted_lines.append(
                    f'<span style="color: {self._colors["ok"]}; font-weight: bold;">{escaped}</span><br>'
                )
                changed = True
                continue

            if line:
                formatted_lines.append(_keep_spacing(html.escape(line.expandtabs(4))) + '<br>')
            else:
                formatted_lines.append('<br>')
            changed = True

        result = ''.join(formatted_lines)
        # Every line gets a trailing <br>, which is right when the text ends on
        # a newline. When it does not — a chunk that arrived split mid-line,
        # which QProcess does constantly — that extra break cuts a word in two
        # and the rest lands on the next line.
        if result.endswith('<br>') and not text_norm.endswith('\n'):
            result = result[:-4]
        if changed:
            return result
        return text

    def createMimeDataFromSelection(self):
        """Force copy to put ONLY plain text on the clipboard.

        Findings are colour-coded on screen via cursor.insertHtml(), which
        makes this a rich-text QTextEdit. Qt's default copy behaviour also
        puts a "text/html" flavour on the clipboard (generated by its own
        QTextDocument::toHtml() serialiser — recognisable by the leading
        space inside style="..." and self-closing "<br />" tags). Some paste
        targets render that raw HTML source as literal text instead of using
        it, which is exactly "highlight a finding, paste into Notepad, get a
        wall of <span style=...> tags" — the console never emitted those
        tags as visible text, they only ever existed in that clipboard
        flavour. Only ever offering "text/plain" (built from the same
        visible text, not the HTML) guarantees paste always matches what was
        selected on screen, in every target application.
        """
        cursor = self.textCursor()
        # QTextCursor.selectedText() uses U+2029 (paragraph separator) for
        # line breaks instead of '\n' — normalise so pasted text has real
        # newlines.
        plain = cursor.selectedText().replace(' ', '\n')
        mime = QMimeData()
        mime.setText(plain)
        return mime

    def append_html(self, html_text: str):
        """Append raw HTML to the console without ANSI stripping."""
        cursor = self.textCursor()
        cursor.movePosition(cursor.MoveOperation.End)
        cursor.insertHtml(html_text)
        self.setTextCursor(cursor)
        scrollbar = self.verticalScrollBar()
        if getattr(self, "_auto_scroll", True):
            scrollbar.setValue(scrollbar.maximum())
