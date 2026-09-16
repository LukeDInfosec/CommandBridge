"""
Status bar, progress animation, and scan completion reporting.
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



class StatusMixin:
    """Mixin providing status bar, progress animation, and scan completion reporting."""

    # Known pentesting tool binaries invoked by commands this app builds.
    # Commands are sometimes wrapped in shell setup — variable assignments,
    # calibration probes, if/then guards — before the real tool runs (e.g.
    # gobuster's soft-404 calibration probe assigns PROBE_PATH/PROBE_LEN
    # first). A naive "first whitespace-separated token" split then picks up
    # a stray fragment of that setup code instead of the tool name, and can
    # even split mid-token on an embedded space (e.g. inside "$(date +%s%N)"),
    # producing labels like "[PROBE_PATH="cb_probe_$(date] has been
    # completed." Searching for a known tool name anywhere in the command
    # avoids that.
    # Kept in step with the tools install_tools.sh handles — run
    # verify_tool_coverage.py after adding a button that calls a new tool.
    _KNOWN_SCAN_TOOLS = (
        "testssl", "sqlmap", "ghauri", "dirsearch", "gobuster", "ffuf",
        "feroxbuster", "nikto", "nuclei", "sslyze", "sslscan", "whatweb",
        "hping3", "ike-scan", "ssh-audit", "wpscan", "graphw00f", "dalfox",
        "corsy", "ssrfmap", "sstimap", "tplmap", "lfimap", "dotdotpwn",
        "subfinder", "httpx-toolkit", "httpx", "katana", "gau", "kxss",
        "Gxss", "uro", "gf", "urldedupe", "waybackurls", "subzy", "dnsx",
        "hakrawler", "wafw00f", "theHarvester", "arjun", "droopescan",
        "graphql-cop", "paramspider", "rustscan", "amass", "masscan",
        "wfuzz", "nmap", "openssl", "curl",
    )

    def _find_known_scan_tool(self, command: str):
        """Return the first known tool name found anywhere in `command`, or None."""
        if not command:
            return None
        for tool in self._KNOWN_SCAN_TOOLS:
            if re.search(rf"(?<![\w./-]){re.escape(tool)}(?![\w-])", command):
                return tool
        return None

    # Maps the caller's status vocabulary onto the status bar's states.
    _STATUS_BAR_STATES = {
        "idle": "idle", "running": "running", "success": "ok",
        "error": "error", "stopped": "stopped", "paused": "paused",
    }

    def get_display_command(self, command: str) -> str:
        """The full command as run, minus the plumbing we added around it.

        The console strip shows this untruncated — when a fuzzing run is
        thirty seconds in, "dirsearch -u 'https://…' -w /usr/share/wordlis…"
        tells you nothing about which wordlist or which flags are actually in
        play, which is exactly what you need to know.
        """
        if not command:
            return ""
        text = command.strip()
        for wrapper in ("stdbuf -oL -eL ", "yes | "):
            if text.startswith(wrapper):
                text = text[len(wrapper):].lstrip()
        return " ".join(text.split())

    def update_status_bar(self, status, command=""):
        """Reflect the current run in the console strip and the status bar."""
        full = self.get_display_command(command)
        tool = self.get_scan_name_from_command(command) if command else None

        detail = {
            "idle": "Idle",
            "running": full or "Running",
            "success": full or "Completed",
            "error": full or "Failed",
            "stopped": full or "Stopped",
            "paused": full or "Paused",
        }.get(status, full or "Idle")

        if hasattr(self, "status_info_label"):
            self.status_info_label.setText(detail)
            self.status_info_label.setToolTip(full)

        # Bottom status bar (state chip + active tool)
        if hasattr(self, "set_status_state"):
            self.set_status_state(
                self._STATUS_BAR_STATES.get(status, "idle"),
                tool=(tool if status in ("running", "paused") else "idle"),
            )

        if not hasattr(self, "progress_bar"):
            return
        if status == "success":
            self.progress_bar.setValue(100)
        elif status in ("idle", "error", "stopped"):
            self.progress_bar.setValue(0)

    def get_short_command(self, command):
        """Get shortened version of command for display"""
        if not command:
            return ""
        max_len = 80
        # Prefer a known tool name so shell setup prepended ahead of the real
        # invocation (e.g. gobuster's soft-404 calibration probe) doesn't get
        # shown/truncated instead of the actual scan (see _find_known_scan_tool).
        known = self._find_known_scan_tool(command)
        if known:
            idx = command.find(known)
            display = command[idx:]
            return display[:max_len] + "..." if len(display) > max_len else display
        # Extract the main command (first part)
        parts = command.split()
        if len(parts) > 0:
            cmd_name = parts[0].split('/')[-1]  # Get just the command name
            # Limit total display length to avoid overflow
            display = f"{cmd_name} {command[len(parts[0]):]}"
            if len(display) > max_len:
                return display[:max_len] + "..."
            return display
        return command[:80] + "..." if len(command) > 80 else command

    def get_scan_name_from_command(self, command: str) -> str:
        """Derive a simple scan name from the underlying command string."""
        if not command:
            return "Scan"
        known = self._find_known_scan_tool(command)
        if known:
            return known
        parts = command.strip().split()
        if not parts:
            return "Scan"
        primary = parts[0]
        # Skip common wrappers
        wrappers = {"echo", "cat", "stdbuf", "python3", "python", "bash", "sh"}
        if primary in wrappers and len(parts) > 1:
            primary = parts[1]
        return primary.split('/')[-1]

    def append_scan_completion_message(self, scan_name: str, success: bool = True, exit_code=None):
        """Append a colored completion message for the last scan.

        Colours come from self.theme() rather than indexing THEMES with a
        literal name. The previous version read
        ``THEMES.get(self.current_theme, THEMES["Some Theme"])`` — Python
        evaluates that default argument eagerly, so it raised KeyError on
        EVERY call once the named theme no longer existed, regardless of which
        theme was actually active. This method runs whenever a command
        finishes, and an unhandled exception inside a Qt slot aborts the
        process, so that one dead key took the whole app down every time a
        scan ended or was stopped.
        """
        theme = self.theme() if hasattr(self, "theme") else {}
        if success:
            color = theme.get("success", "#3ddc97")
            msg = f"[{scan_name}] has been completed."
        else:
            # Failures are 'danger', not 'accent' — accent is the brand colour
            # and would print a failed scan in the same blue as the UI chrome.
            color = theme.get("danger") or theme.get("accent", "#f04d5b")
            # Do not show raw exit codes in the console; use a clean failure message
            msg = f"[{scan_name}] has failed."

        html = f'<span style="color: {color}; font-weight: bold;">{msg}</span><br>'
        cursor = self.console.textCursor()
        cursor.movePosition(cursor.MoveOperation.End)
        cursor.insertHtml(html)
        sb = self.console.verticalScrollBar()
        if getattr(self.console, "_auto_scroll", True):
            sb.setValue(sb.maximum())

    def start_progress_animation(self):
        """Start animated progress bar"""
        import time
        self.command_start_time = time.time()
        self.progress_value = 0
        
        # Create timer for animation
        self.status_animation_timer = QTimer()
        self.status_animation_timer.timeout.connect(self.animate_progress)
        self.status_animation_timer.start(100)  # Update every 100ms

    def animate_progress(self):
        """Animate the progress bar with a realistic slow animation"""
        import time
        if self.command_start_time:
            elapsed = time.time() - self.command_start_time
            
            # Much slower, more realistic progress curve
            # Stays low for longer, then gradually increases
            # Formula: logarithmic growth with very slow rate
            if elapsed < 10:
                # First 10 seconds: 0-15%
                progress = int(elapsed * 1.5)
            elif elapsed < 30:
                # 10-30 seconds: 15-30%
                progress = 15 + int((elapsed - 10) * 0.75)
            elif elapsed < 60:
                # 30-60 seconds: 30-45%
                progress = 30 + int((elapsed - 30) * 0.5)
            elif elapsed < 120:
                # 1-2 minutes: 45-60%
                progress = 45 + int((elapsed - 60) * 0.25)
            elif elapsed < 300:
                # 2-5 minutes: 60-75%
                progress = 60 + int((elapsed - 120) * 0.083)
            elif elapsed < 600:
                # 5-10 minutes: 75-85%
                progress = 75 + int((elapsed - 300) * 0.033)
            else:
                # After 10 minutes: slowly approach 90% but never reach 100%
                progress = min(90, 85 + int((elapsed - 600) * 0.008))
            
            self.progress_bar.setValue(progress)

            # mm:ss reads faster than "3m 7s elapsed" when glancing at a
            # long-running scan, and it stays the same width as it counts up.
            minutes, seconds = divmod(int(elapsed), 60)
            time_str = f"{minutes:02d}:{seconds:02d}"

            if hasattr(self, "console_elapsed_label"):
                self.console_elapsed_label.setText(time_str)
            if hasattr(self, "update_status_elapsed"):
                self.update_status_elapsed(time_str)

    def stop_progress_animation(self):
        """Stop the progress animation"""
        if self.status_animation_timer:
            self.status_animation_timer.stop()
            self.status_animation_timer = None
        self.command_start_time = None
        if hasattr(self, "update_status_elapsed"):
            self.update_status_elapsed("00:00")
        if hasattr(self, "console_elapsed_label"):
            self.console_elapsed_label.setText("00:00")

    def _summarize_testssl_if_applicable(self, exit_code):
        """If the last command was a testssl run, print a concise summary when a report exists.

        testssl often returns non-zero exit codes when vulnerabilities are found or
        certain checks fail. We therefore **do not** gate the summary on exit_code;
        instead we only require that the last command contained 'testssl' and a
        report file was generated.
        """
        try:
            cmd = self.current_command or ""
            if "testssl" not in cmd:
                return

            from pathlib import Path

            # Prefer per-target report files based on SAFE_TARGET
            report_paths = []
            if self.target:
                safe_target = self.sanitize_target_for_filename(self.target)
                # Primary: human-readable text report
                report_paths.append(self.output_dir / f"{safe_target}_testssl.txt")
                # Fallback: raw log file if no .txt was generated
                report_paths.append(self.output_dir / f"{safe_target}_testssl.log")

            # Fallback: legacy ssl.txt
            report_paths.append(self.output_dir / "ssl.txt")

            for report_path in report_paths:
                try:
                    if report_path.exists() and report_path.stat().st_size > 0:
                        self._summarize_testssl(report_path)
                        return
                except Exception:
                    continue
        except Exception:
            # Let caller handle logging
            raise

    def _summarize_ffuf_if_applicable(self, exit_code: int) -> None:
        """If the last command was an ffuf run, print a concise summary of hits.

        We run ffuf in quiet mode (-s) and with -mc 200 by default, writing
        JSON results to {SAFE_TARGET}_ffuf.json. This helper parses that
        JSON file and prints one line per hit in the form:

            [200] https://example.com/sensitive

        If the JSON file is missing or unparsable, we simply skip the
        summary without failing the overall command.
        """
        try:
            cmd = self.current_command or ""
            if "ffuf" not in cmd:
                return

            if not self.target:
                return

            safe_target = self.sanitize_target_for_filename(self.target)
            report_path = self.output_dir / f"{safe_target}_ffuf.json"

            if not report_path.exists() or report_path.stat().st_size == 0:
                return

            import json as _json
            try:
                with open(report_path, "r", encoding="utf-8", errors="replace") as f:
                    data = _json.load(f)
            except Exception:
                # If we cannot parse the JSON, do not spam the console further
                return

            results = data.get("results") or []
            if not isinstance(results, list) or not results:
                self.console.append_ansi("[i] FFUF completed with no matching results.")
                return

            lines = []
            for r in results:
                try:
                    status = r.get("status")
                    url = r.get("url")
                    if not url or status is None:
                        continue
                    lines.append(f"[{status}] {url}")
                except Exception:
                    continue

            if not lines:
                self.console.append_ansi("[i] FFUF completed with no matching results.")
                return

            # Colour-code hits like Feroxbuster: 200 green (copy-pasteable URL),
            # 3xx yellow, 4xx orange, 5xx red.
            import html as _html
            self.console.append_ansi("\n[i] FFUF results (HTTP hits):\n")
            for r in results:
                try:
                    status = str(r.get("status"))
                    url = r.get("url")
                    if not url or status in ("None", ""):
                        continue
                    if status == "200":
                        c = "#22c55e"
                    elif status.startswith("3"):
                        c = "#facc15"
                    elif status.startswith("4"):
                        c = "#f97316"
                    else:
                        c = "#ef4444"
                    self.console.append_html(
                        f'<span style="color:{c};font-weight:bold;">[{_html.escape(status)}]</span> '
                        f'<span style="color:{c};">{_html.escape(url)}</span><br>'
                    )
                except Exception:
                    continue
        except Exception:
            raise

    def _summarize_sqlmap_if_applicable(self, exit_code: int) -> None:
        """Append a summary banner if the last command was sqlmap and SQLi was found."""
        try:
            cmd = self.current_command or ""
            if "sqlmap" not in cmd:
                return
            if not getattr(self, "_sqlmap_vuln_found", False):
                return

            from html import escape as _esc

            dbms = getattr(self, "_sqlmap_dbms", None) or "Unknown"
            param = getattr(self, "_sqlmap_param", None) or "Unknown"
            critical = getattr(self, "_sqlmap_critical", False)
            color = "#ef4444" if critical else "#22c55e"

            banner = f"[+] SQL INJECTION FOUND — DBMS: {dbms} — PARAMETER: {param}"
            if critical:
                banner += " — CRITICAL"

            self.console.append_html(
                "<br>" +
                f'<span style="color: {color}; font-weight: bold;">{_esc(banner)}</span><br>'
            )
        finally:
            # Always reset SQLMap state for the next command
            if hasattr(self, "_sqlmap_vuln_found"):
                self._reset_sqlmap_state()

    def _summarize_testssl(self, report_path):
        """Summarize testssl output using a robust, rule-based parser.

        - Scans raw testssl output line-by-line.
        - Detects common vulnerabilities and groups multi-line evidence.
        - Prints one block per finding, ordered by severity (High → Medium → Low)
          and then by first appearance in the output.
        - Supports --min-severity and --include-notes parser options.
        """
        from pathlib import Path
        import re

        report_path = Path(report_path)

        try:
            if not report_path.exists() or report_path.stat().st_size == 0:
                self.console.append_ansi("[i] No SSL report produced; testssl may be missing or failed.\\n")
                return
            raw_text = report_path.read_text(errors="replace")
            raw_lines = raw_text.splitlines()
        except Exception as e:
            self.console.append_ansi(f"[i] Could not read SSL report: {e}\\n")
            return

        # Strip ANSI escape sequences so our matching and summary output work on
        # clean text (avoids stray "\\x1b[1m" etc. in the console summary). We
        # also write the cleaned text back to the report file so that when you
        # open {SAFE_TARGET}_testssl.txt / .log from disk, there are no raw
        # escape codes present there either.
        ansi_escape = re.compile(r"\\x1B(?:[@-Z\\\\-_]|\\[[0-?]*[ -/]*[@-~])")
        lines = [ansi_escape.sub("", ln) for ln in raw_lines]
        try:
            clean_text = "\n".join(lines) + "\n"
            report_path.write_text(clean_text)

            # If this is the human-readable _testssl.txt report, also clean the
            # corresponding _testssl.log file (same basename, .log extension) so
            # that both artefacts are free from raw ANSI sequences.
            try:
                if report_path.name.endswith("_testssl.txt"):
                    log_path = report_path.with_suffix(".log")
                    if log_path.exists():
                        raw_log = log_path.read_text(errors="replace")
                        cleaned_log = ansi_escape.sub("", raw_log)
                        if cleaned_log != raw_log:
                            log_path.write_text(cleaned_log)
            except Exception:
                # Log cleaning is best-effort; ignore failures.
                pass
        except Exception:
            # Best-effort clean-up; summary parsing still uses the cleaned lines
            # even if we fail to overwrite the file on disk.
            pass
        n = len(lines)
        low = [ln.lower() for ln in lines]

        # Detect help/usage output or option errors to avoid false positives
        try:
            looks_like_help = any(
                ("unrecognized option" in l or "unknown option" in l or "illegal option" in l)
                for l in low
            ) or any(
                re.search(r"^\s*\"?testssl\s*\[options\]", l) for l in lines
            )
        except Exception:
            looks_like_help = False

        if looks_like_help:
            self.console.append_ansi(
                "[i] testssl output indicates an option error/help text. Skipping summary.\n"
                "    Please edit SSL flags and retry.\n"
            )
            return

        # Severity mapping
        sev_rank = {"LOW": 0, "MEDIUM": 1, "HIGH": 2}

        # Pull parser options from instance attributes (set in run_command_template)
        min_severity = getattr(self, "_testssl_summary_min_severity", "LOW").upper()
        if min_severity not in sev_rank:
            min_severity = "LOW"
        min_sev_level = sev_rank[min_severity]
        include_notes = bool(getattr(self, "_testssl_summary_include_notes", False))

        findings = {}  # key -> {name, severity(int), evidence:set(idx), first_idx}

        def is_negative(l: str) -> bool:
            """Return True if the line clearly indicates non-vulnerability."""
            negatives = [
                "not vulnerable",
                "probably not",
                "no rc4 ciphers detected",
                "not offered (ok)",
                "not offered ( ok)",
                "not offered ( o.k.)",
            ]
            return any(neg in l for neg in negatives)

        def add_finding(key: str, name: str, severity: str, idxs):
            """Register or update a finding with combined evidence.

            severity is the baseline (LOW/MEDIUM/HIGH). If any evidence line
            explicitly mentions "vulnerable" (without "not vulnerable" or
            "potentially") or "critical", the effective severity is raised
            accordingly.
            """
            if not idxs:
                return

            base = (severity or "LOW").upper()
            sev_val = sev_rank.get(base, 0)

            # Escalate severity based on explicit markers in evidence
            for idx in idxs:
                li = low[idx]
                if "critical" in li:
                    sev_val = max(sev_val, sev_rank["HIGH"])
                if (
                    "vulnerable" in li
                    and "not vulnerable" not in li
                    and "potentially" not in li
                ):
                    # At least Medium when explicitly reported as vulnerable
                    if sev_val < sev_rank["MEDIUM"]:
                        sev_val = sev_rank["MEDIUM"]

            if key in findings:
                f = findings[key]
                f["severity"] = max(f["severity"], sev_val)
                f["evidence"].update(idxs)
                f["first_idx"] = min(f["first_idx"], min(idxs))
            else:
                findings[key] = {
                    "name": name,
                    "severity": sev_val,
                    "evidence": set(idxs),
                    "first_idx": min(idxs),
                }

        # 1) Deprecated TLS 1.0 / 1.1
        dep_idxs = []
        for i, l in enumerate(low):
            if re.search(r"\btls\s*1\.0\b.*deprecated", l) or re.search(r"\btls\s*1\.1\b.*deprecated", l):
                dep_idxs.append(i)
        if dep_idxs:
            add_finding(
                "deprecated_tls",
                "Deprecated TLS 1.0 & 1.1 In Use",
                "MEDIUM",
                dep_idxs,
            )

        # 2) SWEET32 / 64-bit block ciphers (3DES)
        #
        # We want to avoid flagging generic test headings like
        # "Testing robust forward secrecy (FS) -- omitting ... 3DES, RC4" as
        # SWEET32 evidence. Instead, only treat lines that either:
        #   - explicitly mention SWEET32 and are not "not vulnerable", or
        #   - reference 3DES/DES-CBC3 in a cipher/context line (not an
        #     "omitting" or "testing" banner).
        sweet_idxs = []
        for i, l in enumerate(low):
            if "sweet32" in l:
                if not is_negative(l):
                    sweet_idxs.append(i)
                continue
            if "3des" in l or "des-cbc3" in l:
                # Skip generic info banners that only describe what is being
                # omitted from tests.
                if "omitting" in l or "testing robust forward secrecy" in l:
                    continue
                if not is_negative(l):
                    sweet_idxs.append(i)
        if sweet_idxs:
            add_finding(
                "sweet32",
                "SWEET32 / 64-bit block ciphers Detected",
                "MEDIUM",
                sweet_idxs,
            )

        # 3) Lucky13 / CBC padding oracle timing (CBC ciphers)
        lucky_base = []
        for i, l in enumerate(low):
            if "lucky13" in l or (
                "potentially" in l and "vulnerable" in l and "cbc" in l
            ):
                lucky_base.append(i)
        for i in lucky_base:
            # For Lucky13 we only care about the CBC cipher names themselves;
            # the header already explains the issue. Collect all TLS_*CBC*
            # cipher lines across the report as evidence.
            evidence = set()
            for j, lj_low in enumerate(low):
                if "tls_" in lj_low and "cbc" in lj_low:
                    evidence.add(j)

            # Default Lucky13 severity is Low unless testssl explicitly marks it
            # as vulnerable (without "potentially" or "not vulnerable").
            sev = "LOW"
            base_l = low[i]
            if "vulnerable" in base_l and "not vulnerable" not in base_l and "potentially" not in base_l:
                sev = "MEDIUM"
            add_finding("lucky13", "Lucky13 Detected", sev, evidence)
        # 4) BEAST
        beast_idxs = []
        for i, l in enumerate(low):
            if "beast" in l and not is_negative(l):
                beast_idxs.append(i)
        if beast_idxs:
            add_finding("beast", "BEAST vulnerability Detected", "MEDIUM", beast_idxs)

        # 5) DROWN / SSLv2
        # Only treat explicit DROWN vulnerability lines as findings. Avoid
        # matching generic "SSLv2" references (like advice about using the
        # same certificate elsewhere).
        drown_idxs = []
        for i, l in enumerate(low):
            if "drown" in l and not is_negative(l):
                drown_idxs.append(i)
        if drown_idxs:
            add_finding("drown", "DROWN / SSLv2 Enabled", "HIGH", drown_idxs)

        # 6) POODLE / SSLv3
        # Similar approach: only use explicit POODLE lines, not plain "SSLv3"
        # section headers.
        poodle_idxs = []
        for i, l in enumerate(low):
            if "poodle" in l and not is_negative(l):
                poodle_idxs.append(i)
        if poodle_idxs:
            add_finding("poodle", "POODLE / SSLv3 In Use", "HIGH", poodle_idxs)

        # 7) RC4 / Insecure stream cipher
        rc4_idxs = []
        rc4_token = re.compile(r"\brc4\b")
        for i, l in enumerate(low):
            if rc4_token.search(l) or "arcfour" in l:
                # Skip FS test banner lines that just mention "omitting ... RC4".
                if "omitting" in l or "testing robust forward secrecy" in l:
                    continue
                if not is_negative(l):
                    rc4_idxs.append(i)
        if rc4_idxs:
            add_finding("rc4", "RC4 Ciphers Enabled", "MEDIUM", rc4_idxs)

        # 8) Heartbleed
        hb_idxs = []
        for i, l in enumerate(low):
            if "heartbleed" in l and not is_negative(l):
                hb_idxs.append(i)
        if hb_idxs:
            add_finding("heartbleed", "Heartbleed (OpenSSL Heartbeat) Detected", "HIGH", hb_idxs)

        # 9) Insecure renegotiation
        reneg_idxs = []
        for i, l in enumerate(low):
            if "insecure renegotiation" in l or "secure renegotiation is not" in l:
                if not is_negative(l):
                    reneg_idxs.append(i)
        if reneg_idxs:
            add_finding("reneg", "Insecure Renegotiation Supported", "MEDIUM", reneg_idxs)

        # 10) Compression / CRIME
        comp_idxs = []
        for i, l in enumerate(low):
            if (("compression" in l and "enabled" in l) or "crime" in l) and not is_negative(l):
                comp_idxs.append(i)
        if comp_idxs:
            add_finding("crime", "TLS Compression Enabled", "MEDIUM", comp_idxs)

        # 11) Certificate issues (expired, weak signature, SHA1 *signatures*)
        #
        # IMPORTANT: testssl output includes SHA1 in multiple non-vulnerable
        # contexts, such as:
        #   - "TLS 1.2 sig_algs offered: ... RSA+SHA1" (supported algorithms)
        #   - "Fingerprints SHA1 <hash>" (fingerprint only)
        # These are *not* vulnerabilities. We therefore only treat SHA1 as an
        # issue when it appears in a certificate signature context, e.g.
        #   - "Signature Algorithm: sha1WithRSAEncryption"
        #   - lines mentioning both "signature" and "sha1".
        cert_idxs = []
        cert_sev = "MEDIUM"
        for i, l in enumerate(low):
            # Expired or weak signatures are always issues
            if "expired" in l or "weak signature" in l:
                cert_idxs.append(i)
                if "expired" in l:
                    cert_sev = "HIGH"
                continue

            # SHA1 only when clearly tied to *signature*, not fingerprints or
            # sig_algs offerings.
            if "sha1" in l and ("signature" in l or "sha1withrsa" in l):
                cert_idxs.append(i)
        if cert_idxs:
            add_finding("cert", "Certificate Issues", cert_sev, cert_idxs)

        # 12) Missing Forward Secrecy (no ECDHE/DHE)
        fs_idxs = []
        for i, l in enumerate(low):
            if ("forward secrecy" in l and ("no" in l or "missing" in l)) or (
                "no ecdhe" in l or "no dhe" in l
            ):
                fs_idxs.append(i)
        if fs_idxs:
            add_finding("fs", "Forward Secrecy Missing", "MEDIUM", fs_idxs)

        # Optionally collect non-vulnerable informational notes (e.g., "Heartbleed: NOT vulnerable")
        notes_lines = []
        if include_notes:
            note_markers = [
                "tls 1.0",
                "tls1.0",
                "tls 1.1",
                "tls1.1",
                "sweet32",
                "3des",
                "des-cbc3",
                "lucky13",
                "beast",
                "drown",
                "sslv2",
                "poodle",
                "sslv3",
                "rc4",
                "heartbleed",
                "renegotiation",
                "compression",
                "crime",
                "expired",
                "sha1",
                "weak signature",
                "forward secrecy",
            ]
            for i, l in enumerate(low):
                if is_negative(l) and any(m in l for m in note_markers):
                    notes_lines.append(lines[i].rstrip("\n"))

        # Apply min-severity filter
        filtered = [
            f for f in findings.values() if f["severity"] >= min_sev_level
        ]

        if not filtered:
            # No notable findings
            self.console.append_ansi("No notable testssl vulnerabilities detected.\n")
            # Optionally append notes
            if include_notes and notes_lines:
                out_lines = ["", "Informational Notes (Info)"]
                out_lines.extend(notes_lines)
                out_lines.append("")
                self.console.append_ansi("\n".join(out_lines) + "\n")
            return

        # Sort by severity (HIGH → MEDIUM → LOW) then by first occurrence
        filtered.sort(key=lambda f: (-f["severity"], f["first_idx"]))

        rank_to_name = {v: k for k, v in sev_rank.items()}

        # Build HTML output so we can color headers by severity in the console
        from html import escape as _html_escape
        html_parts = []
        # Local ANSI stripper to be absolutely sure nothing like "\x1b[1m"
        # shows up in the summary, even if a line slipped through earlier.
        ansi_escape = re.compile(r"\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])")

        for f in filtered:
            sev_name = rank_to_name.get(f["severity"], "LOW").title()
            sev_lower = sev_name.lower()
            if sev_lower == "low":
                color = "#22c55e"  # green
            elif sev_lower == "medium":
                color = "#f97316"  # orange
            else:
                color = "#ef4444"  # red

            header_text = f"{f['name']} ({sev_name})"
            html_parts.append(
                f'<span style="color: {color}; font-weight: bold;">{_html_escape(header_text)}</span><br>'
            )

            # Evidence: sorted by line number; escape HTML and keep exact text.
            # De-duplicate identical lines across IPs so we only show unique
            # evidence strings once per finding.
            seen_texts = set()
            for idx in sorted(f["evidence"]):
                raw_text = lines[idx].rstrip("\n")
                # Extra ANSI defense in case anything slipped through earlier
                text = ansi_escape.sub("", raw_text)

                # For Lucky13, only show the TLS_*CBC* cipher names, not the
                # entire table line.
                if f["name"] == "Lucky13 Detected":
                    m = re.search(r"(TLS_[A-Z0-9_]*CBC[A-Z0-9_]*)", text)
                    if m:
                        text = m.group(1)
                    else:
                        # If no match, fall back to the cleaned line.
                        text = text

                if not text or text in seen_texts:
                    continue
                seen_texts.add(text)
                html_parts.append(f"{_html_escape(text)}<br>")

            # Blank line between findings
            html_parts.append("<br>")

        # Append informational notes if requested
        if include_notes and notes_lines:
            html_parts.append(
                '<span style="font-weight: bold;">Informational Notes (Info)</span><br>'
            )
            for note in notes_lines:
                html_parts.append(f"{_html_escape(note)}<br>")
            html_parts.append("<br>")

        self.console.append_html("".join(html_parts))

    def _cleanup_ansi_in_command_outputs(self) -> None:
        """Strip ANSI escape codes from text files written by the last command.

        Many tools emit colored output even when redirected to files. This
        helper scans the last command for obvious output paths (-o/-oN,
        --logfile/--jsonfile, "| tee", and "> file") and rewrites those
        files in-place *without* ANSI escape sequences so that opening them in
        an editor shows clean, readable text.
        """
        try:
            cmd = self.current_command or ""
            if not cmd.strip():
                return

            import re as _re
            from pathlib import Path as _Path

            # Patterns to extract output filenames from the shell command
            patterns = [
                r"-o\s+([^\s|;]+)",
                r"-oN\s+([^\s|;]+)",
                r"--logfile\s+([^\s|;]+)",
                r"--jsonfile\s+([^\s|;]+)",
                r"--log\s+([^\s|;]+)",
                r"\btee\s+([^\s|;]+)",
                r">\s*([^\s|;]+)",
            ]

            candidates: set[str] = set()
            for pat in patterns:
                for m in _re.findall(pat, cmd):
                    if isinstance(m, tuple):
                        m = m[-1]
                    if not m:
                        continue
                    # Ignore known non-files
                    if m in ("/dev/null",):
                        continue
                    candidates.add(m)

            if not candidates:
                return

            ansi_escape = _re.compile(r"\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])")
            allowed_ext = {
                ".txt", ".log", ".json", ".csv", ".xml", ".html", ".htm", ".md",
            }

            base = _Path(self.output_dir)

            for name in candidates:
                p = _Path(name)
                if not p.is_absolute():
                    p = base / name
                try:
                    if not p.exists() or not p.is_file():
                        continue
                    # Only touch obviously-text formats
                    if p.suffix and p.suffix.lower() not in allowed_ext:
                        continue

                    text = p.read_text(errors="replace")
                    if "\x1b" not in text:
                        continue
                    cleaned = ansi_escape.sub("", text)
                    if cleaned != text:
                        p.write_text(cleaned)
                except Exception:
                    # Silent best-effort; do not disrupt main flow
                    continue
        except Exception:
            # Fully best-effort; if anything unexpected happens we just bail.
            return

    def _cleanup_testssl_outputs(self, safe_target: str):
        """Delete existing TestSSL/SSL output files for the current target.

        This prevents tools like testssl/sslscan from erroring when log or
        report files already exist.
        """
        try:
            from pathlib import Path
            base_dir = Path(self.output_dir)
            candidates = [
                base_dir / f"{safe_target}_testssl.log",
                base_dir / f"{safe_target}_testssl.json",
                base_dir / f"{safe_target}_testssl.txt",
                base_dir / "ssl.txt",
            ]
            removed_any = False
            for p in candidates:
                try:
                    if p.exists():
                        p.unlink()
                        removed_any = True
                except Exception:
                    continue
            if removed_any:
                self.console.append_ansi("[i] Old TestSSL/SSL output files removed for fresh run.\n")
        except Exception:
            # Best-effort cleanup; ignore failures
            pass
