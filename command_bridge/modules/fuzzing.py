"""
Fuzzing workflows — wordlist selection and command building.
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


# ── Auth helpers ──────────────────────────────────────────────────────────────

_BEARER_PREFIX_RE = re.compile(r'^bearer\s+', re.I)
_COOKIE_PREFIX_RE = re.compile(r'^cookie\s*:\s*', re.I)
_AUTH_HEADER_PREFIX_RE = re.compile(r'^authorization\s*:\s*', re.I)


def _strip_cookie_prefix(raw: str) -> str:
    """Remove accidental 'Cookie: ' prefix from a pasted cookie string."""
    return _COOKIE_PREFIX_RE.sub("", raw).strip()


def _strip_bearer_prefix(raw: str) -> str:
    """Remove 'Bearer ' prefix (case-insensitive) from a token, then strip."""
    value = _AUTH_HEADER_PREFIX_RE.sub("", raw).strip()  # strip 'Authorization: ' too
    return _BEARER_PREFIX_RE.sub("", value).strip()


def validate_auth_input(auth_type: str, raw: str) -> tuple:
    """
    Validate raw auth input for the given auth_type.
    Returns (is_valid: bool, error_message: str).
    Empty error_message means valid.
    """
    raw = raw.strip()

    if not raw:
        return False, "Auth value cannot be empty."

    if auth_type == 'session':
        value = _strip_cookie_prefix(raw)
        if not value:
            return False, "Cookie string is empty after removing the 'Cookie:' prefix."
        if '=' not in value:
            return False, (
                "Invalid cookie format.\n\n"
                "Expected: name=value pairs separated by semicolons\n"
                "Example:  session=abc123; user=admin"
            )
        # Check for obviously broken pairs
        for pair in value.split(';'):
            pair = pair.strip()
            if pair and '=' not in pair:
                return False, (
                    f"Malformed cookie segment: '{pair}'\n\n"
                    "Each cookie must be in name=value format."
                )
        return True, ""

    elif auth_type == 'bearer':
        value = _strip_bearer_prefix(raw)
        if not value:
            return False, "Token is empty after stripping the 'Bearer ' prefix."
        if ' ' in value:
            return False, (
                "Token contains spaces — this looks invalid.\n\n"
                "Paste just the token value or 'Bearer <token>'.\n"
                "Do not paste the full HTTP header line (e.g. 'Authorization: Bearer ...')."
            )
        return True, ""

    return True, ""


def normalize_auth(auth_type: str, raw: str) -> tuple:
    """
    Normalize raw auth input to a canonical (header_name, header_value) pair.
    Returns ('', '') for auth_type 'none' or on failure.

    cookie  → ('Cookie', 'session=abc; user=admin')
    bearer  → ('Authorization', 'Bearer eyJ...')
    """
    raw = raw.strip()
    if not raw:
        return ('', '')

    if auth_type == 'session':
        value = _strip_cookie_prefix(raw)
        return ('Cookie', value)

    elif auth_type == 'bearer':
        token = _strip_bearer_prefix(raw)
        return ('Authorization', f'Bearer {token}')

    return ('', '')


def build_header_flag(header_name: str, header_value: str) -> str:
    """
    Return a shell-safe -H flag string for the given header.
    Single-quotes the entire 'Name: Value' to handle special chars.
    """
    return f"-H 'Cookie: {header_value}'" if header_name == 'Cookie' \
        else f"-H '{header_name}: {header_value}'"


def auth_flags_for_tool(tool_id: str, auth_type: str, auth_value: str) -> str:
    """
    Return the complete header flag string(s) for the given tool and auth.
    Returns "" when auth_type is 'none' or auth_value is empty/invalid.

    All tools use -H 'Name: Value'.
    Dirsearch also accepts --cookie but -H is unified and equally correct.
    Feroxbuster accepts -b for cookies but -H works for both cookies and
    bearer tokens, so -H is used for consistency.
    """
    if auth_type == 'none' or not auth_value:
        return ""

    valid, _ = validate_auth_input(auth_type, auth_value)
    if not valid:
        return ""

    header_name, header_value = normalize_auth(auth_type, auth_value)
    if not header_name:
        return ""

    return build_header_flag(header_name, header_value)


# ── Mixin ─────────────────────────────────────────────────────────────────────

class FuzzingMixin:
    """Mixin providing fuzzing workflows — wordlist selection and command building."""

    # Persisted across the session so SmartFuzz restarts inherit auth headers.
    _smartfuzz_auth_type:  str = 'none'
    _smartfuzz_auth_value: str = ''

    def _prompt_auth(self, title: str = "Authentication") -> tuple:
        """
        Show the auth-mode → auth-value dialog sequence.
        Returns (auth_type, auth_value) or (None, None) if cancelled.

        auth_type is one of: 'none', 'session', 'bearer'
        auth_value is the raw user input (will be validated + normalised downstream).
        """
        from PyQt6.QtWidgets import QInputDialog, QDialog, QVBoxLayout, QLabel, QPlainTextEdit, QDialogButtonBox

        auth_items = ["No Auth", "Cookie Auth (Session)", "JWT / Bearer Token"]
        auth_choice, ok = QInputDialog.getItem(
            self, title, "Choose authentication method:", auth_items, 0, False
        )
        if not ok:
            return None, None

        if auth_choice == "No Auth":
            return 'none', ''

        auth_type = 'session' if auth_choice == "Cookie Auth (Session)" else 'bearer'

        if auth_type == 'session':
            prompt = (
                "Paste your cookie string.\n\n"
                "Examples:\n"
                "  session=abc123\n"
                "  session=abc123; user=admin; csrf=xyz\n\n"
                "The 'Cookie: ' prefix is stripped automatically if present."
            )
        else:
            prompt = (
                "Paste your JWT or Bearer token.\n\n"
                "Examples:\n"
                "  eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...\n"
                "  Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...\n\n"
                "The 'Bearer ' prefix is normalised automatically."
            )

        # Multi-line dialog so long tokens are easy to paste
        dialog = QDialog(self)
        dialog.setWindowTitle(title)
        dialog.resize(560, 280)
        try:
            self.apply_theme_to_dialog(dialog)
        except Exception:
            pass

        layout = QVBoxLayout(dialog)
        lbl = QLabel(prompt)
        lbl.setWordWrap(True)
        lbl.setObjectName("fieldLabel")
        layout.addWidget(lbl)

        text_edit = QPlainTextEdit()
        text_edit.setPlaceholderText("Paste here…")
        text_edit.setMaximumHeight(80)
        layout.addWidget(text_edit)

        buttons = QDialogButtonBox(
            QDialogButtonBox.StandardButton.Ok | QDialogButtonBox.StandardButton.Cancel
        )
        buttons.accepted.connect(dialog.accept)
        buttons.rejected.connect(dialog.reject)
        layout.addWidget(buttons)

        if dialog.exec() != QDialog.DialogCode.Accepted:
            return None, None

        raw = text_edit.toPlainText().strip()

        # Validate immediately so the user gets a clear error before proceeding
        valid, err = validate_auth_input(auth_type, raw)
        if not valid:
            self.show_themed_message("Invalid Auth Input", err, QMessageBox.Icon.Warning)
            return None, None

        return auth_type, raw

    # ── Fuzzing button click handler ──────────────────────────────────────────

    def _on_fuzzing_button_clicked(self, button, button_id, default_cmd):
        """Left-click: run if already configured, else open quick-select menu."""
        try:
            if button_id in getattr(self, "_fuzzing_ready", set()):
                self.run_command_from_registry(button_id)
            else:
                self.show_command_editor(button, button_id, default_cmd)
        except Exception as e:
            self.console.append_ansi(f"[i] Fuzzing button handler error: {e}\n")
            self.show_command_editor(button, button_id, default_cmd)

    def show_command_editor(self, button, button_id, default_cmd):
        """Context menu for command buttons.

        Fuzzing tools (Dirsearch/FFUF/Ferox/Gobuster) get the architecture/
        wordlist picker.  The 403 Bypass button gets a small browse menu.
        Everything else opens the manual edit dialog.
        """
        from PyQt6.QtWidgets import QMenu, QDialog, QVBoxLayout, QLabel, QDialogButtonBox, QInputDialog, QFileDialog
        from pathlib import Path as _Path
        import shlex

        is_fuzzing_tool = button_id in ['web_dirsearch', 'web_ffuf', 'web_feroxbuster', 'web_gobuster']

        if is_fuzzing_tool:
            menu = QMenu(self)
            menu.setObjectName("contextMenu")
            self.apply_theme_to_menu(menu)

            edit_action = menu.addAction("✏️ Manually Modify Underlying Command")
            menu.addSeparator()

            arch_header = menu.addAction("🛠️ Server Architecture")
            arch_header.setEnabled(False)

            apache_action       = menu.addAction("   Apache")
            nginx_action        = menu.addAction("   Nginx")
            iis_action          = menu.addAction("   Microsoft IIS")
            iis_sysweb_action   = menu.addAction("   Microsoft IIS (system.web)")
            aspnet_action       = menu.addAction("   ASP.NET Application")
            aspnet_bd_action    = menu.addAction("   ASP.NET (backdoors / handlers)")
            aspnet_elmah_action = menu.addAction("   ASP.NET (ELMAH / debug endpoints)")
            tomcat_action       = menu.addAction("   Tomcat")
            laravel_action      = menu.addAction("   Laravel")
            php_arch_action     = menu.addAction("   PHP Application")
            drupal_arch_action  = menu.addAction("   Drupal")
            graphql_action      = menu.addAction("   GraphQL API")
            generic_action      = menu.addAction("   Generic Web App")
            other_action        = menu.addAction("   Other (manual path)")

            menu.addSeparator()
            cms_header = menu.addAction("📦 CMS Endpoints")
            cms_header.setEnabled(False)

            wordpress_action    = menu.addAction("   WordPress")
            laravel_cms_action  = menu.addAction("   Laravel (CMS / Routes)")
            drupal_cms_action   = menu.addAction("   Drupal (CMS)")
            joomla_action       = menu.addAction("   Joomla")
            magento_action      = menu.addAction("   Magento")
            dnn_action          = menu.addAction("   DotNetNuke (.NET CMS)")

            menu.addSeparator()
            bonus_header = menu.addAction("🎁 Bonus Wordlists")
            bonus_header.setEnabled(False)

            big_action              = menu.addAction("   big.txt")
            common_action           = menu.addAction("   common.txt")
            combined_dirs_action    = menu.addAction("   combined_directories.txt")
            combined_words_action   = menu.addAction("   combined_words.txt")
            quickhits_action        = menu.addAction("   quickhits.txt")
            php_wordlist_action     = menu.addAction("   PHP.fuzz.txt")
            dirlist_small_action    = menu.addAction("   directory-list-2.3-small.txt")
            dirlist_medium_action   = menu.addAction("   directory-list-2.3-medium.txt")
            dirlist_big_action      = menu.addAction("   directory-list-2.3-big.txt")
            raft_small_dirs_action  = menu.addAction("   raft-small-directories.txt")
            raft_medium_dirs_action = menu.addAction("   raft-medium-directories.txt")
            raft_large_dirs_action  = menu.addAction("   raft-large-directories.txt")
            raft_large_files_action = menu.addAction("   raft-large-files.txt")

            action = menu.exec(button.mapToGlobal(button.rect().bottomLeft()))

            if action == edit_action:
                self.open_command_edit_dialog(button, button_id, default_cmd)
            elif action:
                wordlist_path = self._get_wordlist_from_action(action, [
                    (apache_action,       '/usr/share/seclists/Discovery/Web-Content/Web-Servers/Apache.txt'),
                    (nginx_action,        '/usr/share/seclists/Discovery/Web-Content/Web-Servers/nginx.txt'),
                    (iis_action,          '/usr/share/seclists/Discovery/Web-Content/Web-Servers/IIS.txt'),
                    (iis_sysweb_action,   '/usr/share/seclists/Discovery/Web-Content/Web-Servers/IIS-systemweb.txt'),
                    (aspnet_action,       '/usr/share/seclists/Discovery/Web-Content/Web-Servers/IIS.txt'),
                    (aspnet_bd_action,    '/usr/share/seclists/Discovery/Web-Content/Programming-Language-Specific/ASP.NET/CommonBackdoors-ASP.fuzz.txt'),
                    (aspnet_elmah_action, '/usr/share/seclists/Discovery/Web-Content/Programming-Language-Specific/ASP.NET/ELMAH-Debugger.txt'),
                    (tomcat_action,       '/usr/share/seclists/Discovery/Web-Content/Web-Servers/Apache-Tomcat.txt'),
                    (laravel_action,      '/usr/share/seclists/Discovery/Web-Content/Programming-Language-Specific/PHP.fuzz.txt'),
                    (php_arch_action,     '/usr/share/seclists/Discovery/Web-Content/Programming-Language-Specific/PHP.fuzz.txt'),
                    (drupal_arch_action,  '/usr/share/seclists/Discovery/Web-Content/CMS/Drupal.txt'),
                    (graphql_action,      '/usr/share/seclists/Discovery/Web-Content/graphql.txt'),
                    (generic_action,      '/usr/share/seclists/Discovery/Web-Content/raft-medium-words.txt'),
                    (wordpress_action,    '/usr/share/seclists/Discovery/Web-Content/CMS/wordpress.fuzz.txt'),
                    (laravel_cms_action,  '/usr/share/seclists/Discovery/Web-Content/Programming-Language-Specific/PHP.fuzz.txt'),
                    (drupal_cms_action,   '/usr/share/seclists/Discovery/Web-Content/CMS/Drupal.txt'),
                    (joomla_action,       '/usr/share/seclists/Discovery/Web-Content/CMS/joomla-plugins.fuzz.txt'),
                    (magento_action,      '/usr/share/seclists/Discovery/Web-Content/CMS/sitemap-magento.txt'),
                    (dnn_action,          '/usr/share/seclists/Discovery/Web-Content/CMS/dotnetnuke.txt'),
                    (big_action,              '/usr/share/seclists/Discovery/Web-Content/big.txt'),
                    (common_action,           '/usr/share/seclists/Discovery/Web-Content/common.txt'),
                    (combined_dirs_action,    '/usr/share/seclists/Discovery/Web-Content/combined_directories.txt'),
                    (combined_words_action,   '/usr/share/seclists/Discovery/Web-Content/combined_words.txt'),
                    (quickhits_action,        '/usr/share/seclists/Discovery/Web-Content/quickhits.txt'),
                    (php_wordlist_action,     '/usr/share/seclists/Discovery/Web-Content/Programming-Language-Specific/PHP.fuzz.txt'),
                    (dirlist_small_action,    '/usr/share/seclists/Discovery/Web-Content/DirBuster-2007_directory-list-2.3-small.txt'),
                    (dirlist_medium_action,   '/usr/share/seclists/Discovery/Web-Content/DirBuster-2007_directory-list-2.3-medium.txt'),
                    (dirlist_big_action,      '/usr/share/seclists/Discovery/Web-Content/DirBuster-2007_directory-list-2.3-big.txt'),
                    (raft_small_dirs_action,  '/usr/share/seclists/Discovery/Web-Content/raft-small-directories.txt'),
                    (raft_medium_dirs_action, '/usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt'),
                    (raft_large_dirs_action,  '/usr/share/seclists/Discovery/Web-Content/raft-large-directories.txt'),
                    (raft_large_files_action, '/usr/share/seclists/Discovery/Web-Content/raft-large-files.txt'),
                ])

                if wordlist_path:
                    if action == other_action:
                        file_path, _ = QFileDialog.getOpenFileName(
                            self, "Select Wordlist File",
                            "/usr/share/seclists/Discovery/Web-Content",
                            "Text Files (*.txt);;All Files (*)"
                        )
                        if file_path:
                            wordlist_path = file_path
                        else:
                            return

                    self.fuzzing_workflow_direct(button, button_id, wordlist_path, action.text().strip())

        elif button_id == 'access_403_bypass':
            menu = QMenu(self)
            menu.setObjectName("contextMenu403Bypass")
            self.apply_theme_to_menu(menu)

            browse_action = menu.addAction("📂 Browse for 403 bypass script…")
            edit_action   = menu.addAction("✏️ Manually Modify Underlying Command")

            action = menu.exec(button.mapToGlobal(button.rect().bottomLeft()))

            if action == browse_action:
                current_cmd = self.command_registry.get(button_id, default_cmd)
                start_dir = str(_Path.home())
                try:
                    parts = shlex.split(current_cmd)
                    if parts and parts[0] == 'bash' and len(parts) >= 2:
                        candidate = _Path(parts[1])
                        if candidate.exists():
                            start_dir = str(candidate.parent)
                except Exception:
                    pass

                file_path, _ = QFileDialog.getOpenFileName(
                    self, "Select 403 bypass script", start_dir,
                    "Shell scripts (*.sh);;All files (*)",
                )
                if file_path:
                    new_cmd = f"bash {file_path} {{target}}"
                    self.command_registry[button_id] = new_cmd
                    self.save_custom_commands()
                    try:
                        tt = self._build_tooltip_from_command(button.text(), new_cmd)
                        if tt:
                            button.setToolTip(tt)
                    except Exception:
                        pass
                    self.show_themed_message(
                        "403 Bypass Updated",
                        f"403 bypass script set to:\n{file_path}",
                    )
            elif action == edit_action:
                self.open_command_edit_dialog(button, button_id, default_cmd)

        else:
            self.open_command_edit_dialog(button, button_id, default_cmd)

    def _get_wordlist_from_action(self, action, mapping):
        for menu_action, wordlist_path in mapping:
            if action == menu_action:
                return wordlist_path
        return None

    # ── Fuzzing workflow entry points ─────────────────────────────────────────

    def fuzzing_workflow_direct(self, button, button_id, wordlist_path, wordlist_name):
        """Configure a fuzzing tool: prompt auth → threads → build + store command."""
        from PyQt6.QtWidgets import QInputDialog

        auth_type, auth_value = self._prompt_auth("Fuzzing Authentication")
        if auth_type is None:
            return

        threads, ok = QInputDialog.getInt(
            self, "Fuzzing Threads", "Number of threads:", 10, 1, 100, 1,
        )
        if not ok:
            return

        cmd = self._build_fuzzing_command(button_id, wordlist_path, auth_type, auth_value, threads)

        self.command_registry[button_id] = cmd
        self.save_custom_commands()

        if not hasattr(self, "_fuzzing_ready"):
            self._fuzzing_ready = set()
        self._fuzzing_ready.add(button_id)

        # Log the final command so the user can verify auth headers are correct
        try:
            self.console.append_ansi(
                f"\n[i] Fuzzing command configured ({button.text()}):\n"
                f"    {cmd}\n\n"
            )
        except Exception:
            pass

        auth_label = self._auth_label(auth_type, auth_value)
        self.show_themed_message(
            "Command Updated",
            f"{button.text()} configured:\n\n"
            f"Wordlist: {wordlist_name}\n"
            f"Auth:     {auth_label}\n"
            f"Threads:  {threads}\n\n"
            "Check the console for the full command."
        )

    def fuzzing_workflow(self, button, button_id, wordlist_size=None, architecture=None):
        """Size/architecture-based fuzzing workflow (kept for backwards compat)."""
        from PyQt6.QtWidgets import QInputDialog

        auth_type, auth_value = self._prompt_auth("Fuzzing Authentication")
        if auth_type is None:
            return

        threads, ok = QInputDialog.getInt(
            self, "Fuzzing Threads", "Number of threads:", 10, 1, 100, 1,
        )
        if not ok:
            return

        if architecture:
            wordlist_path = self._get_wordlist_path(architecture, 'medium')
            size_label = "Architecture-specific"
            arch_choice = architecture
        else:
            arch_choice = "Generic Web App"
            wordlist_path = self._get_wordlist_path(arch_choice, wordlist_size)
            size_label = wordlist_size.capitalize() if wordlist_size else "Medium"

        cmd = self._build_fuzzing_command(button_id, wordlist_path, auth_type, auth_value, threads)

        self.command_registry[button_id] = cmd
        self.save_custom_commands()

        if not hasattr(self, "_fuzzing_ready"):
            self._fuzzing_ready = set()
        self._fuzzing_ready.add(button_id)

        try:
            self.console.append_ansi(
                f"\n[i] Fuzzing command configured ({button.text()}):\n"
                f"    {cmd}\n\n"
            )
        except Exception:
            pass

        auth_label = self._auth_label(auth_type, auth_value)
        self.show_themed_message(
            "Command Updated",
            f"{button.text()} configured:\n\n"
            f"Wordlist:     {size_label}\n"
            f"Architecture: {arch_choice}\n"
            f"Auth:         {auth_label}\n"
            f"Threads:      {threads}\n\n"
            "Check the console for the full command."
        )

    def run_smartfuzz_with_auth(self):
        """Run SmartFuzz — prompt for auth, persist headers across wordlist restarts."""
        if not self.target:
            self.show_themed_message(
                "No Target", "Please set a target first in the Target Setup tab.",
                QMessageBox.Icon.Warning
            )
            return

        auth_type, auth_value = self._prompt_auth("SmartFuzz Authentication")
        if auth_type is None:
            return

        # Persist so SmartFuzz can inherit them if it restarts with a different wordlist
        self._smartfuzz_auth_type  = auth_type
        self._smartfuzz_auth_value = auth_value

        cmd = self._build_smartfuzz_command(auth_type, auth_value)

        try:
            self.console.append_ansi(f"\n[i] SmartFuzz command:\n    {cmd}\n\n")
        except Exception:
            pass

        self.run_command_template(cmd)

    # Technologies whose wordlists can be overridden via the SmartFuzz menu.
    _SMARTFUZZ_TECHS = ("nginx", "apache", "iis", "tomcat",
                        "wordpress", "drupal", "joomla", "laravel")

    def _build_smartfuzz_command(self, auth_type: str, auth_value: str) -> str:
        """Build SmartFuzz command, injecting auth headers and any user-set
        per-architecture wordlist overrides (configured via right-click)."""
        cmd = f"python3 {BASE_DIR}/smartfuzz.py -u {{TARGET}} -t 2"

        initial = self.command_registry.get("smartfuzz_wl_initial")
        if initial:
            cmd += f" -w '{initial}'"

        for tech in self._SMARTFUZZ_TECHS:
            path = self.command_registry.get(f"smartfuzz_wl_{tech}")
            if path:
                cmd += f" --wl {tech}='{path}'"

        flags = auth_flags_for_tool('smartfuzz', auth_type, auth_value)
        if flags:
            cmd += f" {flags}"
        return cmd

    def show_smartfuzz_menu(self, pos):
        """Right-click menu on SmartFuzz: set per-architecture wordlists.

        Each entry opens a file picker and stores the chosen path in the command
        registry (persisted). The SmartFuzz engine then uses these paths when it
        auto-detects the matching server architecture mid-scan.
        """
        from PyQt6.QtWidgets import QMenu, QFileDialog

        menu = QMenu(self)
        menu.setObjectName("contextMenu")
        try:
            self.apply_theme_to_menu(menu)
        except Exception:
            pass

        header = menu.addAction("🧠 SmartFuzz Wordlist Overrides")
        header.setEnabled(False)

        items = [
            ("Set Initial / Generic Wordlist", "initial"),
            ("Set Nginx Wordlist", "nginx"),
            ("Set Apache Wordlist", "apache"),
            ("Set IIS Wordlist", "iis"),
            ("Set Tomcat Wordlist", "tomcat"),
            ("Set WordPress Wordlist", "wordpress"),
            ("Set Drupal Wordlist", "drupal"),
            ("Set Joomla Wordlist", "joomla"),
            ("Set Laravel Wordlist", "laravel"),
        ]
        action_tech = {}
        for label, tech in items:
            cur = self.command_registry.get(f"smartfuzz_wl_{tech}")
            a = menu.addAction(f"   {label}" + ("  ✓" if cur else ""))
            action_tech[a] = tech

        menu.addSeparator()
        show_action = menu.addAction("📋 Show Current Overrides")
        reset_action = menu.addAction("🔄 Reset All Overrides")

        btn = getattr(self, "smartfuzz_btn", None)
        global_pos = btn.mapToGlobal(pos) if btn is not None else self.mapToGlobal(pos)
        action = menu.exec(global_pos)
        if action is None:
            return

        if action in action_tech:
            tech = action_tech[action]
            start_dir = "/usr/share/seclists/Discovery/Web-Content"
            path, _ = QFileDialog.getOpenFileName(
                self, f"Select {tech} wordlist", start_dir,
                "Text Files (*.txt);;All Files (*)",
            )
            if path:
                self.command_registry[f"smartfuzz_wl_{tech}"] = path
                self.save_custom_commands()
                self.show_themed_message(
                    "SmartFuzz Wordlist Set",
                    f"{tech.capitalize()} wordlist set to:\n{path}",
                )
        elif action == reset_action:
            for _label, tech in items:
                self.command_registry.pop(f"smartfuzz_wl_{tech}", None)
            self.save_custom_commands()
            self.show_themed_message("SmartFuzz", "All wordlist overrides cleared.")
        elif action == show_action:
            lines = []
            for label, tech in items:
                v = self.command_registry.get(f"smartfuzz_wl_{tech}")
                lines.append(f"{label.replace('Set ', '')}: {v if v else '(default)'}")
            self.show_themed_message("SmartFuzz Overrides", "\n".join(lines))

    def get_smartfuzz_auth_flags(self) -> str:
        """
        Return the current SmartFuzz auth header flags so the SmartFuzz
        engine can preserve them when switching wordlists mid-scan.
        Returns "" when no auth is configured.
        """
        return auth_flags_for_tool(
            'smartfuzz',
            self._smartfuzz_auth_type,
            self._smartfuzz_auth_value,
        )

    # ── Command builder ───────────────────────────────────────────────────────

    def _build_fuzzing_command(self, button_id, wordlist_path, auth_type, auth_value, threads=None):
        """
        Build the full fuzzing command for the given tool.

        Auth is always injected via -H 'Name: Value' so the same path works
        for every header type (Cookie, Authorization, or custom).  Threads are
        clamped to [1, 100].
        """
        try:
            t = int(threads) if threads is not None else 10
        except (TypeError, ValueError):
            t = 10
        t = max(1, min(t, 100))

        h_flag = auth_flags_for_tool(button_id, auth_type, auth_value)
        h_part = f" {h_flag}" if h_flag else ""

        if button_id == 'web_dirsearch':
            # --full-url makes each hit print the complete URL so 200s can be
            # copied straight into a browser (the console highlights 200s green).
            # NOTE: an earlier version of this command added "--filter-threshold
            # 10" as a soft-404/wildcard backstop, but that flag does not exist
            # in dirsearch — the installed Kali/Debian package rejects it
            # immediately with "no such option: --filter-threshold", which
            # made every dirsearch run fail before it could send a single
            # request. dirsearch already does its own automatic wildcard/
            # soft-404 calibration internally (it samples a few nonexistent
            # paths up front and filters further hits that look like
            # duplicates of that response), so no extra flag is needed —
            # removing the invalid one restores that built-in behaviour
            # instead of crashing on startup.
            cmd = (
                f"dirsearch -u '{{TARGET}}' -w {wordlist_path}"
                f"{h_part}"
                f" -t {t} -i 200,204,301,302,307,403 -q --full-url"
                f" -o {{SAFE_TARGET}}_dirsearch.txt"
            )

        elif button_id == 'web_ffuf':
            # ffuf's own "-of json" output is a full metadata dump (duration,
            # resultfile, scraper, position, ...) — great for tooling, useless
            # to paste into a report. Write that to a "_raw.json" file, then
            # pipe it through ffuf_clean.py so the file the user actually
            # opens ({SAFE_TARGET}_ffuf.txt) is just "[STATUS] URL" lines,
            # which is also what gets printed to the console.
            #
            # -ac (auto-calibrate): ffuf's built-in fix for exactly the
            # "500 different paths, all return 200, all the same 'not
            # found' page" problem — before the real run it probes the
            # target with a few random/nonexistent paths, learns what that
            # false-positive response looks like (size/words/lines), and
            # silently filters anything matching it out of the results.
            # ffuf_clean.py additionally re-groups by response size as a
            # backstop in case -ac's calibration doesn't catch it.
            cmd = (
                f"ffuf -u '{{TARGET}}/FUZZ' -w {wordlist_path}"
                f"{h_part}"
                f" -t {t} -mc 200,204,301,302,307,401,403 -fc 404,500"
                f" -ac -s -of json -o {{SAFE_TARGET}}_ffuf_raw.json; "
                f"python3 {{CB_DIR}}/command_bridge/modules/ffuf_clean.py "
                f"{{SAFE_TARGET}}_ffuf_raw.json {{SAFE_TARGET}}_ffuf.txt"
            )

        elif button_id == 'web_feroxbuster':
            # No extra flag needed here for wildcard/soft-404 filtering:
            # feroxbuster auto-filters those responses BY DEFAULT (it's the
            # -D/--dont-filter flag that turns this off, which we deliberately
            # never pass).
            #
            # -q/--quiet: without this, feroxbuster prints its banner and a
            # live-updating progress bar (request count/rate) straight to the
            # console. Note the -s just below is feroxbuster's own
            # --status-codes filter, not a silent/quiet flag, so it does
            # nothing to stop that noise on its own. -q hides the banner and
            # progress bar while every discovered result still prints.
            cmd = (
                f"feroxbuster --url {{TARGET}} -t {t} -w {wordlist_path}"
                f"{h_part}"
                f" -x php,asp,aspx,jsp,html,txt,conf,bak,old,zip,log,sql,json,xml"
                f" -s 200,204,301,302,307,403 --timeout 10 -q"
                f" -o {{SAFE_TARGET}}_ferox_results.txt"
            )

        elif button_id == 'web_gobuster':
            # NOTE: there is no --wildcard flag in `gobuster dir` mode (that
            # was a mistaken carry-over from a different tool's flag name) —
            # passing it makes gobuster fail immediately with "Incorrect
            # Usage: flag provided but not defined: -wildcard" before a
            # single request is sent. gobuster dir instead relies on -b
            # (status code blacklist) for that job, which is already set
            # below. --expanded prints full URLs so 200s are
            # copy-pasteable, and the console highlights them green.
            #
            # Unlike ffuf, gobuster's `dir` mode has no built-in auto-
            # calibration — its only tool for a "every path returns 200
            # with the same body" server is --exclude-length/--xl, and that
            # needs a byte count supplied UP FRONT. So we calibrate it
            # ourselves: probe one virtually-guaranteed-nonexistent path
            # with curl first, and if the server answers with content (i.e.
            # it's a catch-all/soft-404 responder rather than a real 404),
            # feed that response's byte size straight into gobuster's own
            # --exclude-length so it's filtered server-request-side, not
            # left for the user to spot 500 identical hits later.
            # Built as a plain (non-f) string for the probe portion so curl's
            # own '%{size_download}' write-out syntax needs no brace-doubling
            # gymnastics against Python's f-string escaping — {TARGET} here
            # is already the literal placeholder text run_command_template()
            # substitutes later, same as everywhere else in this file.
            probe_snippet = (
                'PROBE_PATH="cb_probe_$(date +%s%N)_$$_definitely_not_real"; '
                'PROBE_LEN=$(curl -sk -m 10' + h_part + ' -o /dev/null '
                "-w '%{size_download}' "
                '"{TARGET}/$PROBE_PATH" 2>/dev/null); '
                'GB_EXCL=""; '
                'if echo "$PROBE_LEN" | grep -qE "^[0-9]+$" && [ "$PROBE_LEN" -gt 0 ]; then '
                'echo "[*] Calibration probe got a ${PROBE_LEN}-byte response for a '
                'nonexistent path -- looks like a catch-all/soft-404 responder, '
                'excluding that size via --exclude-length."; '
                'GB_EXCL="--exclude-length $PROBE_LEN"; '
                'fi; '
            )
            cmd = (
                probe_snippet +
                f"gobuster dir -u {{TARGET}} -w {wordlist_path}"
                f"{h_part}"
                f" -t {t} -b 404,500 $GB_EXCL --no-error --expanded -q"
                f" -o {{SAFE_TARGET}}_gobuster.txt"
            )

        else:
            cmd = f"ffuf -u '{{TARGET}}/FUZZ' -w {wordlist_path}{h_part} -t {t}"

        return cmd

    # ── Utilities ─────────────────────────────────────────────────────────────

    def _auth_label(self, auth_type: str, auth_value: str) -> str:
        """Human-readable auth summary for confirmation dialogs."""
        if auth_type == 'none' or not auth_value:
            return "None"
        if auth_type == 'session':
            preview = _strip_cookie_prefix(auth_value)
            if len(preview) > 40:
                preview = preview[:37] + "…"
            return f"Cookie ({preview})"
        if auth_type == 'bearer':
            token = _strip_bearer_prefix(auth_value)
            preview = token[:20] + "…" if len(token) > 20 else token
            return f"Bearer {preview}"
        return auth_type

    def _get_wordlist_path(self, architecture, size):
        arch_wordlists = {
            "Apache":        "/usr/share/seclists/Discovery/Web-Content/Web-Servers/Apache.txt",
            "Nginx":         "/usr/share/seclists/Discovery/Web-Content/Web-Servers/nginx.txt",
            "Microsoft IIS": "/usr/share/seclists/Discovery/Web-Content/Web-Servers/IIS.txt",
            "ASP.NET Application": "/usr/share/seclists/Discovery/Web-Content/Web-Servers/IIS.txt",
            "Tomcat":        "/usr/share/seclists/Discovery/Web-Content/Web-Servers/Apache-Tomcat.txt",
        }
        if architecture in arch_wordlists:
            return arch_wordlists[architecture]

        size_wordlists = {
            'small':  '/usr/share/seclists/Discovery/Web-Content/raft-small-words.txt',
            'medium': '/usr/share/seclists/Discovery/Web-Content/raft-medium-words.txt',
            'large':  '/usr/share/seclists/Discovery/Web-Content/raft-large-words.txt',
        }
        return size_wordlists.get(size, size_wordlists['medium'])

    def run_param_finder(self, mode):
        """Launch param_finder.sh in dev (historical) or live (crawl) mode."""
        script = BASE_DIR / "param_finder.sh"
        if not script.exists():
            self.show_themed_message(
                "Script Not Found",
                f"param_finder.sh not found at:\n{script}",
                QMessageBox.Icon.Warning,
            )
            return
        cmd = (
            f"bash '{script}' --mode {mode} "
            f"--target '{{TARGET}}' "
            f"--output '{{SAFE_TARGET}}_params_{mode}.txt'"
        )
        self.run_command_template(cmd)
