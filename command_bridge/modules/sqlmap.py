"""
SQLMap integration — HTTP-request import and WPScan menu.
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



class SqlmapMixin:
    """Mixin providing sqlmap integration — http-request import and wpscan menu."""

    def handle_sqlmap_http_click(self):
        """Entry point for the SQLMap HTTP button (left-click).

        Just invokes the HTTP-request workflow with the default
        "extensive" profile and reports any errors. The actual console
        switch happens later when sqlmap is started.
        """
        try:
            self.run_sqlmap_from_http_request("extensive")
        except Exception as e:
            # Best-effort logging so the user can see what went wrong
            try:
                self.console.append_ansi(f"[!] SQLMap HTTP button error: {e}\n")
            except Exception:
                pass
            try:
                self.show_themed_message(
                    "Error",
                    f"SQLMap HTTP workflow failed: {e}",
                    QMessageBox.Icon.Critical,
                )
            except Exception:
                pass

    def run_sqlmap_from_http_request(self, profile: str = "extensive"):
        """Prompt for a full HTTP request and run sqlmap -r sql.txt with a profile.

        Workflow:
        - Ask the user to paste a full HTTP request (e.g. from Burp "Copy as HTTP")
          including method, path, headers and body.
        - Save it as sql.txt in the current output directory.
        - Run sqlmap with -r sql.txt using one of several pre-defined profiles
          (extensive, tamper/WAF, dbs-only, current user/DB only).
        """
        from PyQt6.QtWidgets import QDialog, QVBoxLayout, QLabel, QPlainTextEdit, QDialogButtonBox
        from pathlib import Path as _Path

        if not self.target:
            self.show_themed_message(
                "No Target",
                "Please set a target first in the Target Setup tab.",
                QMessageBox.Icon.Warning,
            )
            return

        # Build dialog to capture the HTTP request
        dialog = QDialog(self)
        dialog.setWindowTitle("Paste Full HTTP Request for SQLMap")
        dialog.resize(900, 600)
        self.apply_theme_to_dialog(dialog)

        layout = QVBoxLayout(dialog)
        info = QLabel(
            "Paste a full HTTP request as captured in Burp (GET or POST),\n"
            "including request line, headers, and body. sql.txt will be \n"
            "saved in the current output directory and used with sqlmap -r sql.txt."
        )
        info.setObjectName("fieldLabel")
        layout.addWidget(info)

        text_edit = QPlainTextEdit()
        text_edit.setPlaceholderText(
            "GET /vuln.php?id=1 HTTP/1.1\n"
            "Host: example.com\n"
            "User-Agent: ...\n"
            "Cookie: ...\n"
            "Accept: */*\n"
            "\n"
            "param1=value1&param2=value2"
        )
        text_edit.setMinimumHeight(450)
        layout.addWidget(text_edit)

        buttons = QDialogButtonBox(QDialogButtonBox.StandardButton.Ok | QDialogButtonBox.StandardButton.Cancel)
        buttons.accepted.connect(dialog.accept)
        buttons.rejected.connect(dialog.reject)
        layout.addWidget(buttons)

        if dialog.exec() != QDialog.DialogCode.Accepted:
            return

        request_text = text_edit.toPlainText().strip()
        if not request_text:
            self.show_themed_message("No Request", "You must paste a full HTTP request.")
            return

        # Write sql.txt into the configured output directory
        sql_path = _Path(self.output_dir) / "sql.txt"
        try:
            sql_path.write_text(request_text + "\n", encoding="utf-8", errors="replace")
            self.console.append_ansi(f"[i] Saved HTTP request to {sql_path}\n")
            self.refresh_file_list()
        except Exception as e:
            self.show_themed_message("Error", f"Could not write sql.txt: {e}", QMessageBox.Icon.Critical)
            return

        # Build profile-specific sqlmap options
        base = "sqlmap -r sql.txt --batch --random-agent"

        # NOTE: All profiles share the same saved sql.txt request; only flags
        # and output directories differ. We compute a default level/risk per
        # profile but allow the user to override these interactively.
        level = 2
        risk = 1
        extra_flags = ""
        outdir = "{SAFE_TARGET}_sqlmap_http_generic"

        # QUICK, LOW-IMPACT PROFILES (single objective)
        if profile == "quick_confirm":
            level, risk = 2, 1
            # No --smart here; run with standard detection logic so behaviour
            # matches manual terminal usage and does not skip borderline cases.
            extra_flags = ""
            outdir = "{SAFE_TARGET}_sqlmap_http_quick_confirm"
        elif profile == "quick_dbms_fingerprint":
            level, risk = 2, 1
            extra_flags = "--fingerprint"
            outdir = "{SAFE_TARGET}_sqlmap_http_quick_dbms"
        elif profile == "quick_current_db":
            level, risk = 2, 1
            extra_flags = "--current-db"
            outdir = "{SAFE_TARGET}_sqlmap_http_quick_curdb"
        elif profile == "quick_current_user":
            level, risk = 2, 1
            extra_flags = "--current-user"
            outdir = "{SAFE_TARGET}_sqlmap_http_quick_curuser"
        elif profile == "quick_is_dba":
            level, risk = 2, 1
            extra_flags = "--is-dba"
            outdir = "{SAFE_TARGET}_sqlmap_http_quick_dba"
        elif profile == "quick_db_version":
            level, risk = 2, 1
            extra_flags = "--banner"
            outdir = "{SAFE_TARGET}_sqlmap_http_quick_version"
        elif profile == "quick_hostname":
            level, risk = 2, 1
            extra_flags = "--hostname"
            outdir = "{SAFE_TARGET}_sqlmap_http_quick_host"
        elif profile == "quick_injection_type":
            level, risk = 2, 1
            extra_flags = "--flush-session"
            outdir = "{SAFE_TARGET}_sqlmap_http_quick_injtype"
        elif profile == "quick_auth_context":
            level, risk = 1, 1
            extra_flags = "--current-user"
            outdir = "{SAFE_TARGET}_sqlmap_http_quick_auth"
        elif profile == "quick_minimal_poc":
            level, risk = 1, 1
            extra_flags = "--current-db"
            outdir = "{SAFE_TARGET}_sqlmap_http_quick_poc"
        # FULLER CONTEXT / ENUMERATION PROFILES
        elif profile == "extensive":
            level, risk = 5, 3
            extra_flags = "--dbs --current-user --current-db --is-dba --hostname --banner"
            outdir = "{SAFE_TARGET}_sqlmap_http_extensive"
        elif profile == "ctx_fingerprint":
            level, risk = 3, 1
            extra_flags = "--current-user --current-db --hostname --banner --is-dba"
            outdir = "{SAFE_TARGET}_sqlmap_http_ctx"
        elif profile == "dbs_enum":
            level, risk = 3, 2
            extra_flags = "--dbs --schema --tables --columns"
            outdir = "{SAFE_TARGET}_sqlmap_http_enum"
        elif profile == "dump_all":
            level, risk = 5, 3
            extra_flags = "--dump-all --exclude-sysdbs"
            outdir = "{SAFE_TARGET}_sqlmap_http_dump"
        elif profile == "auth_passwords":
            level, risk = 3, 2
            extra_flags = "--passwords --roles --privileges --is-dba"
            outdir = "{SAFE_TARGET}_sqlmap_http_auth"
        elif profile == "priv_checks":
            level, risk = 3, 1
            extra_flags = "--roles --privileges --is-dba"
            outdir = "{SAFE_TARGET}_sqlmap_http_priv"
        elif profile == "tamper_waf":
            level, risk = 5, 3
            extra_flags = "--tamper=space2comment,between,randomcase,charencode,base64encode --dbs"
            outdir = "{SAFE_TARGET}_sqlmap_http_tamper"
        elif profile == "dbs_only":
            level, risk = 3, 2
            extra_flags = "--dbs"
            outdir = "{SAFE_TARGET}_sqlmap_http_dbs"
        elif profile == "current_info":
            level, risk = 2, 1
            extra_flags = "--current-user --current-db --is-dba"
            outdir = "{SAFE_TARGET}_sqlmap_http_info"
        else:
            # Fallback to extensive if unknown profile is passed
            level, risk = 5, 3
            extra_flags = "--dbs --current-user --current-db --is-dba --hostname --banner"
            outdir = "{SAFE_TARGET}_sqlmap_http_extensive"

        # The quick profiles exist to answer one question fast; stopping to ask
        # for a level and a risk on the way there defeats the point.
        if profile == "fast_confirm":
            from command_bridge.modules import sqlmap_builder as _builder

            fast = _builder.SPEED_PROFILES["fast"]
            template = _builder.build_command({
                "profile": "fast",
                "level": fast["level"],
                "risk": fast["risk"],
                "threads": fast["threads"],
                "techniques": fast["techniques"],
                "smart": fast["smart"],
                "request_file": "sql.txt",
                "output_dir": _builder.default_output_dir("fast"),
                "force_ssl": _builder.request_is_https(request_text, self.target),
                "extra": list(fast["extra"]),
            })
            found = _builder.extract_parameters(request_text)
            self.console.append_ansi(
                f"[i] Fast confirmation scan — {len(found)} parameter(s) in the "
                "request, no enumeration, no time-based payloads.\n"
            )
            self.run_command_template(template, label="SQLMap fast confirmation scan")
            return

        # Allow user to override level/risk interactively after choosing profile
        try:
            from PyQt6.QtWidgets import QInputDialog
            lvl, ok = QInputDialog.getInt(
                self,
                "SQLMap Level",
                "Level (1-5) – higher = deeper testing:",
                level,
                1,
                5,
                1,
            )
            if not ok:
                return
            rsk, ok = QInputDialog.getInt(
                self,
                "SQLMap Risk",
                "Risk (1-3) – higher = more intrusive payloads:",
                risk,
                1,
                3,
                1,
            )
            if not ok:
                return
            level, risk = int(lvl), int(rsk)
        except Exception:
            # If the dialog fails for any reason, fall back to profile defaults
            pass

        # Default verbosity: use -v 1 so you still see INFO/WARNING output
        # without the extra DEBUG noise. If the user has already specified a
        # custom verbosity flag in a profile ("-v"), we do not override it.
        if "-v" not in (extra_flags or ""):
            extra_flags = (extra_flags + " -v 1").strip()

        opts = f" --level={level} --risk={risk} --output-dir={outdir} " + (extra_flags or "")

        template = base + opts
        self.run_command_template(template)

    # ── Custom scan builder ───────────────────────────────────────────────

    def _sqlmap_builder_settings_path(self):
        """Where the builder's last settings live."""
        return Path.home() / ".config" / "CommandBridge" / "sqlmap_builder.json"

    def _load_sqlmap_builder_settings(self) -> dict:
        try:
            path = self._sqlmap_builder_settings_path()
            if path.exists():
                data = json.loads(path.read_text(encoding="utf-8"))
                if isinstance(data, dict):
                    return data
        except Exception:
            # Corrupt settings are not worth a dialog; fall back to defaults.
            pass
        return {}

    def _save_sqlmap_builder_settings(self, settings: dict):
        try:
            path = self._sqlmap_builder_settings_path()
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(json.dumps(settings, indent=2), encoding="utf-8")
        except Exception as e:
            self.console.append_ansi(
                f"[i] Could not save SQLMap builder settings: {e}\n"
            )

    def open_sqlmap_builder(self):
        """Open the build-your-own-scan dialog for the pasted HTTP request.

        Everything the dialog needs is on screen at once: the request, the
        options, and the command they produce. Nothing runs until the command
        in the preview is the one you want.
        """
        from command_bridge.modules.sqlmap_builder import SqlmapBuilderDialog
        from PyQt6.QtWidgets import QDialog

        if not self.target:
            self.show_themed_message(
                "No Target",
                "Please set a target first in the Target Setup tab.",
                QMessageBox.Icon.Warning,
            )
            return

        # Start from the last request that was scanned, so a second pass with
        # different options does not mean pasting it again.
        existing = ""
        try:
            sql_path = Path(self.output_dir) / "sql.txt"
            if sql_path.exists():
                existing = sql_path.read_text(encoding="utf-8", errors="replace")
        except Exception:
            existing = ""

        dialog = SqlmapBuilderDialog(
            self,
            request_text=existing,
            target=self.target,
            remembered=self._load_sqlmap_builder_settings(),
        )
        self.apply_theme_to_dialog(dialog)

        if dialog.exec() != QDialog.DialogCode.Accepted:
            return

        request_text = dialog.request_text()
        if not request_text:
            self.show_themed_message("No Request", "You must paste a full HTTP request.")
            return

        command = dialog.command_text()
        if not command:
            self.show_themed_message("No Command", "The command is empty — nothing to run.")
            return

        try:
            sql_path = Path(self.output_dir) / "sql.txt"
            sql_path.write_text(request_text + "\n", encoding="utf-8", errors="replace")
            self.console.append_ansi(f"[i] Saved HTTP request to {sql_path}\n")
            self.refresh_file_list()
        except Exception as e:
            self.show_themed_message(
                "Error", f"Could not write sql.txt: {e}", QMessageBox.Icon.Critical
            )
            return

        self._save_sqlmap_builder_settings(dialog.remembered())
        self.run_command_template(command, label="SQLMap custom scan")

    def show_sqlmap_http_menu(self, pos):
        """Right-click menu for the Extensive SQLMap (HTTP Request) button.

        Presents quick profiles for common SQL injection goals without
        switching tabs or starting sqlmap until after you've pasted the
        HTTP request and confirmed the dialog.
        """
        from PyQt6.QtWidgets import QMenu

        try:
            menu = QMenu(self)
            menu.setObjectName("contextMenuSqlmapHttp")
            self.apply_theme_to_menu(menu)

            actions: dict[object, str] = {}

            # The two entries that answer "is it injectable" without committing
            # to an exhaustive run. They sit first because they are what you
            # want on a first pass.
            hdr_build = menu.addAction("Build the scan")
            hdr_build.setEnabled(False)

            a_fast = menu.addAction("   ⚡ Fast Confirmation Scan (no enumeration)")
            a_fast.setToolTip(
                "Level 1, risk 1, boolean/error/union only, ten threads. Skips "
                "time-based payloads and every enumeration flag — it answers "
                "whether the request is injectable, nothing more."
            )
            actions[a_fast] = "fast_confirm"

            a_custom = menu.addAction("   ⚙ Custom Scan — choose the options…")
            a_custom.setToolTip(
                "Pick the depth, tick what to collect, and target one "
                "parameter instead of all of them. Shows the command it builds."
            )

            menu.addSeparator()

            # QUICK CHECKS (low-impact, time-boxed)
            hdr_quick = menu.addAction("Quick Checks (Low-Impact / Time-Boxed)")
            hdr_quick.setEnabled(False)

            a_q_confirm = menu.addAction("   ⚡ SQLi Confirmation Only")
            actions[a_q_confirm] = "quick_confirm"

            a_q_dbms = menu.addAction("   ⚡ DB Engine Fingerprint (DBMS only)")
            actions[a_q_dbms] = "quick_dbms_fingerprint"

            a_q_curdb = menu.addAction("   ⚡ Current Database Name")
            actions[a_q_curdb] = "quick_current_db"

            a_q_curuser = menu.addAction("   ⚡ Current Database User")
            actions[a_q_curuser] = "quick_current_user"

            a_q_dba = menu.addAction("   ⚡ DBA Privilege Check (Yes/No)")
            actions[a_q_dba] = "quick_is_dba"

            a_q_version = menu.addAction("   ⚡ Database Version Only")
            actions[a_q_version] = "quick_db_version"

            a_q_host = menu.addAction("   ⚡ Hostname / Server Info")
            actions[a_q_host] = "quick_hostname"

            a_q_injtype = menu.addAction("   ⚡ Injection Type Discovery Only")
            actions[a_q_injtype] = "quick_injection_type"

            a_q_auth = menu.addAction("   🕒 Auth Context Verification (current-user probe)")
            actions[a_q_auth] = "quick_auth_context"

            a_q_poc = menu.addAction("   🕒 Minimal Proof-of-Impact (DB name only)")
            actions[a_q_poc] = "quick_minimal_poc"

            menu.addSeparator()

            # 1. Basic Context & Fingerprinting
            hdr_ctx = menu.addAction("Context & Fingerprinting")
            hdr_ctx.setEnabled(False)
            a_ctx = menu.addAction("   Current user / DB / host / engine / version / is-dba")
            actions[a_ctx] = "ctx_fingerprint"

            menu.addSeparator()

            # 2. Database Enumeration
            hdr_enum = menu.addAction("Database Enumeration")
            hdr_enum.setEnabled(False)
            a_enum = menu.addAction("   Enumerate DBs, schema, tables & columns")
            actions[a_enum] = "dbs_enum"

            menu.addSeparator()

            # 3. Data Extraction (High Impact)
            hdr_dump = menu.addAction("Data Extraction (High Impact)")
            hdr_dump.setEnabled(False)
            a_dump_all = menu.addAction("   Dump ALL data (exclude system DBs)")
            actions[a_dump_all] = "dump_all"

            menu.addSeparator()

            # 4. Authentication & Password Analysis
            hdr_auth = menu.addAction("Authentication & Password Analysis")
            hdr_auth.setEnabled(False)
            a_auth = menu.addAction("   DB passwords, roles & privileges")
            actions[a_auth] = "auth_passwords"

            menu.addSeparator()

            # 5. Access & Privilege Testing
            hdr_priv = menu.addAction("Access & Privilege Testing")
            hdr_priv.setEnabled(False)
            a_priv = menu.addAction("   Roles / privileges / is-dba")
            actions[a_priv] = "priv_checks"

            menu.addSeparator()

            # WAF / tamper & legacy quick profiles
            hdr_extra = menu.addAction("WAF / Tamper & Legacy Profiles")
            hdr_extra.setEnabled(False)
            a_extensive = menu.addAction("   ⚠️ Extensive (L5/R3, DBs + context)")
            actions[a_extensive] = "extensive"
            a_tamper = menu.addAction("   ⚠️ Tamper bundle (space2comment,between,randomcase,charencode,base64encode)")
            actions[a_tamper] = "tamper_waf"
            a_dbs_only = menu.addAction("   🕒 Databases only (L3/R2, dbs)")
            actions[a_dbs_only] = "dbs_only"
            a_curr_info = menu.addAction("   🕒 Current user / DB / is-dba only")
            actions[a_curr_info] = "current_info"

            action = menu.exec(self.sqlmap_http_btn.mapToGlobal(pos))
            if action is a_custom:
                self.open_sqlmap_builder()
                return
            if action and action in actions:
                profile = actions[action]
                self.run_sqlmap_from_http_request(profile)
        except Exception as e:
            try:
                self.console.append_ansi(f"[!] SQLMap HTTP context menu error: {e}\n")
            except Exception:
                pass

    def show_wpscan_menu(self, button, button_id: str, default_cmd: str, pos) -> None:
        """Right-click menu for the WordPress Scan (WPScan) button.

        Provides quick profiles (Fast / Normal / Deep) and an option to open the
        full command editor for manual tweaks. The selected profile is stored in
        the command registry so a normal left-click immediately runs it.
        """
        from PyQt6.QtWidgets import QMenu

        try:
            menu = QMenu(self)
            menu.setObjectName("contextMenuWPScan")
            self.apply_theme_to_menu(menu)

            actions = {}

            hdr = menu.addAction("WPScan Profiles")
            hdr.setEnabled(False)

            a_fast = menu.addAction("⚡ Fast scan (themes, plugins, users)")
            actions[a_fast] = "fast"

            a_normal = menu.addAction("🔍 Normal scan (plugins, themes, users)")
            actions[a_normal] = "normal"

            a_deep = menu.addAction("🛠 Deep scan (extended enumeration)")
            actions[a_deep] = "deep"

            menu.addSeparator()
            a_edit = menu.addAction("✏ Edit underlying command…")

            chosen = menu.exec(button.mapToGlobal(pos))
            if not chosen:
                return

            # Manual edit uses the generic editor
            if chosen is a_edit:
                self.show_command_editor(button, button_id, default_cmd)
                return

            profile = actions.get(chosen)
            if not profile:
                return

            # Build profile-specific WPScan command templates. All profiles keep
            # threads at WPScan defaults; we only change enumeration breadth.
            if profile == "fast":
                cmd = (
                    "echo 'Starting FAST WPScan against {TARGET} (limited enumeration)…'; "
                    "wpscan --url {TARGET} --enumerate vp,vt,u "
                    "--plugins-detection mixed --random-user-agent --no-update "
                    "-o {SAFE_TARGET}_wpscan_fast.txt; "
                    "echo; echo '=== WPScan FAST results (from {SAFE_TARGET}_wpscan_fast.txt) ==='; "
                    "cat {SAFE_TARGET}_wpscan_fast.txt"
                )
            elif profile == "deep":
                cmd = (
                    "echo 'Starting DEEP WPScan against {TARGET} (aggressive enumeration)…'; "
                    "wpscan --url {TARGET} --enumerate vp,vt,tt,cb,dbe,u,m "
                    "--plugins-detection aggressive --random-user-agent "
                    "-o {SAFE_TARGET}_wpscan_deep.txt; "
                    "echo; echo '=== WPScan DEEP results (from {SAFE_TARGET}_wpscan_deep.txt) ==='; "
                    "cat {SAFE_TARGET}_wpscan_deep.txt"
                )
            else:  # normal
                cmd = (
                    "echo 'Starting WPScan against {TARGET} - this can take some time, please wait...'; "
                    "wpscan --url {TARGET} --enumerate vp,vt,tt,cb,dbe,u,m "
                    "--plugins-detection mixed --random-user-agent "
                    "-o {SAFE_TARGET}_wpscan.txt; "
                    "echo; echo '=== WPScan results (from {SAFE_TARGET}_wpscan.txt) ==='; "
                    "cat {SAFE_TARGET}_wpscan.txt"
                )

            self.command_registry[button_id] = cmd
            self.save_custom_commands()

            self.show_themed_message(
                "WPScan Profile Updated",
                f"WordPress Scan profile set to: {profile.title()}\n\nLeft-click the button to run this profile.",
            )
        except Exception as e:
            try:
                self.console.append_ansi(f"[!] WPScan menu error: {e}\n")
            except Exception:
                pass

    def _reset_sqlmap_state(self) -> None:
        """Reset per-command SQLMap highlighting and summary state."""
        self._sqlmap_vuln_found = False
        self._sqlmap_first_vuln_highlighted = False
        self._sqlmap_dbms = None
        self._sqlmap_param = None
        self._sqlmap_critical = False
        self._sqlmap_buffer = ""
