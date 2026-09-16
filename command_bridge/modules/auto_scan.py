"""
Auto-scan pipeline — sequential Nmap / TestSSL / Feroxbuster.
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



class AutoScanMixin:
    """Mixin providing auto-scan pipeline — sequential nmap / testssl / feroxbuster."""

    def run_auto_scan(self):
        """Run automated scan sequence: Nmap -> TestSSL -> Feroxbuster.

        This now runs each phase sequentially (Nmap quick, full, UDP, then
        TestSSL, then Feroxbuster) so that the TestSSL summary is printed to the
        console immediately after the TestSSL phase completes, before
        Feroxbuster starts.
        """
        if not self.target:
            self.show_themed_message("No Target", "Please set a target first in the Target Setup tab.", QMessageBox.Icon.Warning)
            return
        
        # Get auth mode from registry or default to 'none'
        auth_mode = self.command_registry.get('auto_scan_auth', 'none')
        
        # Build the automated scan command sequence
        import os, shlex
        safe_target = self.sanitize_target_for_filename(self.target)
        output_dir = str(self.output_dir)
        scan_target = self.get_scanner_target()

        # Precompute safely quoted output file paths to handle spaces, etc.
        nmap_quick_path = shlex.quote(os.path.join(output_dir, f"{safe_target}_nmap_quick.txt"))
        nmap_full_path = shlex.quote(os.path.join(output_dir, f"{safe_target}_nmap_full.txt"))
        nmap_udp_path = shlex.quote(os.path.join(output_dir, f"{safe_target}_nmap_udp.txt"))
        testssl_log_path = shlex.quote(os.path.join(output_dir, f"{safe_target}_testssl.log"))
        testssl_json_path = shlex.quote(os.path.join(output_dir, f"{safe_target}_testssl.json"))
        testssl_txt_path = shlex.quote(os.path.join(output_dir, f"{safe_target}_testssl.txt"))
        
        # Build Feroxbuster command with optional auth
        ferox_cmd = self._build_feroxbuster_command(self.target, auth_mode, output_dir)
        
        # Clean up any existing TestSSL outputs for this target so reruns do not crash
        try:
            self._cleanup_testssl_outputs(safe_target)
        except Exception as e:
            self.console.append_ansi(f"[i] Warning: could not clean previous SSL outputs: {e}\n")
        
        # Store each phase as its own command so we can advance step-by-step.
        self._auto_scan_commands = [
            f"nmap -sC -sV -T4 {scan_target} -oN {nmap_quick_path}",
            f"nmap -p- -T4 {scan_target} -oN {nmap_full_path}",
            f"nmap -sU -T4 --top-ports 100 {scan_target} -oN {nmap_udp_path}",
            (
                f"if command -v testssl >/dev/null 2>&1; then "
                f"testssl --logfile {testssl_log_path} "
                f"--jsonfile {testssl_json_path} {scan_target} "
                f"| tee {testssl_txt_path}; "
                f"else echo '[!] testssl not installed - skipping TLS check. "
                f"Install with: sudo apt install testssl  OR  download from https://testssl.sh'; fi"
            ),
            ferox_cmd,
        ]
        self._auto_scan_active = True
        self._auto_scan_index = 0
        self._auto_scan_output_dir = output_dir
        
        # Switch to console tab
        self.goto_console()
        self.console.append_ansi(f"\n{'='*80}\n")
        self.console.append_ansi(f"[*] Starting Automated Scan Sequence for: {self.target}\n")
        self.console.append_ansi(f"[*] Scans: Nmap Quick -> Nmap Full -> Nmap UDP -> TestSSL -> Feroxbuster\n")
        if auth_mode != 'none':
            self.console.append_ansi(f"[*] Auth Mode: {auth_mode.title()}\n")
        self.console.append_ansi(f"{'='*80}\n\n")
        
        # Mark status as running and kick off the first step
        self.set_status_state("running")
        self.update_status_bar("running", "Auto Scan")
        
        self._start_next_auto_scan_command()

    def _start_next_auto_scan_command(self):
        """Run the next command in the Auto Scan sequence, if any remain."""
        if not self._auto_scan_active:
            return
        if self._auto_scan_index >= len(self._auto_scan_commands):
            # Sequence complete
            self._auto_scan_active = False
            self._auto_scan_commands = []
            self._auto_scan_output_dir = None
            self._auto_scan_index = 0
            return

        cmd = self._auto_scan_commands[self._auto_scan_index]
        self._auto_scan_index += 1

        # Update status and log this step
        self.current_command = cmd
        self.update_status_bar("running", cmd)
        self.start_progress_animation()

        total = len(self._auto_scan_commands)
        step_no = self._auto_scan_index
        self.console.append_ansi(f"\n{'-'*80}\n")
        self.console.append_ansi(f"[*] Auto Scan Step {step_no}/{total}: {cmd}\n")
        self.console.append_ansi(f"{'-'*80}\n\n")

        # Run this phase in the configured output directory
        self.runner.run_command(cmd, self._auto_scan_output_dir or str(self.output_dir))

    def _build_feroxbuster_command(self, target, auth_mode, output_dir):
        """Build Feroxbuster command with optional authentication"""
        safe_target = self.sanitize_target_for_filename(target)

        import os, shlex
        ferox_out_path = shlex.quote(os.path.join(output_dir, f"{safe_target}_ferox_results.txt"))
        
        # Base Feroxbuster command
        base_cmd = (
            f"feroxbuster --url {target} "
            f"-w /usr/share/seclists/Discovery/Web-Content/raft-medium-words.txt "
            "-r -x php,html,asp,aspx,jsp,jsf,cfm,py,rb,pl,sh,cgi,env,ini,conf,config,yml,json,xml,"
            "properties,bak,old,orig,zip,tar,gz,7z,sql,log,txt,pdf,doc,docx -s 200,301,302 "
            f"--threads 1 --timeout 10 -o {ferox_out_path}"
        )
        
        # Add authentication if specified
        if auth_mode == 'session':
            cookies = self.command_registry.get('auto_scan_cookies', '')
            if cookies:
                base_cmd += f" -b '{cookies}'"
        elif auth_mode == 'bearer':
            token = self.command_registry.get('auto_scan_bearer', '')
            if token:
                base_cmd += f" -H 'Authorization: Bearer {token}'"
        
        return base_cmd

    def show_auto_scan_menu(self, position):
        """Show context menu for Auto Scan button"""
        from PyQt6.QtWidgets import QMenu, QInputDialog
        
        menu = QMenu(self)
        menu.setObjectName("contextMenu")
        self.apply_theme_to_menu(menu)
        
        # Add reset and auth options
        reset_action = menu.addAction("🔄 Reset to Default (No Auth)")
        menu.addSeparator()
        session_action = menu.addAction("🔐 Add Session Cookies")
        bearer_action = menu.addAction("🎫 Add Bearer Token")
        
        # Show menu
        action = menu.exec(self.auto_scan_btn.mapToGlobal(self.auto_scan_btn.rect().bottomLeft()))
        
        if action == reset_action:
            # Reset to default (no auth)
            self.command_registry['auto_scan_auth'] = 'none'
            self.command_registry.pop('auto_scan_cookies', None)
            self.command_registry.pop('auto_scan_bearer', None)
            self.save_custom_commands()
            self.show_themed_message("Auto Scan Reset", "Auto Scan reset to default (no authentication)")
        
        elif action == session_action:
            # Prompt for session cookies
            cookies, ok = QInputDialog.getText(
                self,
                "Session Cookies",
                "Enter session cookies (e.g., session_id=abc123; user_token=xyz789):",
                QtWidgets.QLineEdit.EchoMode.Normal
            )
            if ok and cookies:
                self.command_registry['auto_scan_auth'] = 'session'
                self.command_registry['auto_scan_cookies'] = cookies
                self.save_custom_commands()
                self.show_themed_message("Success", "Session cookies added to Auto Scan")
        
        elif action == bearer_action:
            # Prompt for bearer token
            token, ok = QInputDialog.getText(
                self,
                "Bearer Token",
                "Enter Bearer token:",
                QtWidgets.QLineEdit.EchoMode.Normal
            )
            if ok and token:
                self.command_registry['auto_scan_auth'] = 'bearer'
                self.command_registry['auto_scan_bearer'] = token
                self.save_custom_commands()
                self.show_themed_message("Success", "Bearer token added to Auto Scan")
