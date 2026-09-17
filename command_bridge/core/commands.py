"""
Command execution — template substitution and registry.
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



class CommandsMixin:
    """Mixin providing command execution — template substitution and registry."""

    def sanitize_target_for_filename(self, target):
        """Sanitize target string for filenames.

        Rules:
        - Strip protocol, path, query, fragment, auth info
        - For hostnames:
          * "example.com"        -> "example"
          * "example.co.uk"      -> "example_co" (no TLD suffix)
          * "example.example.com"-> "example_example"
        - For IPv4 addresses, keep all 4 octets
        - Replace invalid filename chars with underscores
        """
        import re

        if not target:
            return "target"

        sanitized = target.strip()

        # Remove protocol (http://, https://, ftp://, etc.)
        sanitized = re.sub(r'^[a-zA-Z]+://', '', sanitized)

        # Strip path, query, fragment
        for sep in ['/', '?', '#']:
            if sep in sanitized:
                sanitized = sanitized.split(sep, 1)[0]

        # Strip credentials if present: user:pass@host -> host
        if '@' in sanitized:
            sanitized = sanitized.split('@', 1)[1]

        sanitized = sanitized.strip()

        # Separate host and port if any
        host_part, port_part = (sanitized.split(':', 1) + [''])[:2]

        # Remove wildcard prefixes and leading dots (e.g. *.example.com)
        host_part = re.sub(r'^\*+\.', '', host_part).lstrip('.')

        if not host_part:
            host_part = 'target'

        # Special case: IPv4 address -> keep all octets
        if re.fullmatch(r"\d+(?:\.\d+){3}", host_part):
            base_parts = host_part.split('.')
        else:
            # Hostname labels
            labels = [lbl for lbl in host_part.split('.') if lbl]
            if not labels:
                labels = ['target']

            if len(labels) == 1:
                base_parts = labels
            elif len(labels) == 2:
                # example.com -> example
                base_parts = [labels[0]]
            else:
                # example.example.com -> example_example (first two labels)
                base_parts = labels[:2]

        # Replace problematic characters in each label
        safe_labels = [re.sub(r'[^A-Za-z0-9_-]', '_', lbl) for lbl in base_parts]
        base = '_'.join([lbl for lbl in safe_labels if lbl]) or 'target'

        # Append port if present and numeric
        port_clean = re.sub(r'[^0-9]', '', port_part)
        if port_clean:
            base = f"{base}_{port_clean}"

        return base

    def get_scanner_target(self):
        """Return target normalized for tools that expect host/domain, not full URL."""
        import re

        if not self.target:
            return ""

        t = self.target.strip()
        # Remove protocol
        t = re.sub(r'^[a-zA-Z]+://', '', t)
        # Strip path, query, fragment
        for sep in ['/', '?', '#']:
            if sep in t:
                t = t.split(sep, 1)[0]
        # Strip credentials
        if '@' in t:
            t = t.split('@', 1)[1]
        return t.strip()

    def run_command_template(self, cmd_template, label: str = None):
        """Run a command with template substitution.

        `label` is the human name for what is running (normally the button's
        caption); it is what the console and status bar report instead of the
        first binary in the pipeline. Passing nothing clears any previous
        label so a later run never inherits the last one's name.
        """
        self.current_action_label = label
        if not self.target:
            self.show_themed_message("No Target", "Please set a target first in the Target Setup tab.", QMessageBox.Icon.Warning)
            return
        
        # Sanitize target for use in filenames only
        safe_target = self.sanitize_target_for_filename(self.target)
            
        # If this is a TestSSL/SSL scan, proactively remove any existing
        # per-target report files so the tool does not error when logs exist.
        if "testssl" in cmd_template or "sslscan" in cmd_template:
            try:
                self._cleanup_testssl_outputs(safe_target)
            except Exception as e:
                self.console.append_ansi(f"[i] Warning: could not clean previous SSL outputs: {e}\n")
        
        # Substitute placeholders - use ORIGINAL target for command execution, sanitized only for output filenames
        cmd = cmd_template.replace("{target}", self.target)  # Legacy lowercase placeholder
        cmd = cmd.replace("{TARGET}", self.target)          # Full target (may include scheme/path)
        cmd = cmd.replace("{TARGET_URL}", self.target)
        cmd = cmd.replace("{TARGET_HOST}", self.get_scanner_target())  # Host/domain only, no scheme
        cmd = cmd.replace("{SAFE_TARGET}", safe_target)  # Use sanitized for output filenames
        cmd = cmd.replace("{CB_DIR}", str(BASE_DIR))      # Path to the Test25/ root directory
        
        # Replace output file placeholders with sanitized version
        # This handles patterns like: -o {target}_something.txt
        import re as _re
        cmd = _re.sub(r'-o\s+\{target\}_([^\s]+)', f'-o {safe_target}_\\1', cmd)
        cmd = _re.sub(r'--output-dir=\{target\}_([^\s]+)', f'--output-dir={safe_target}_\\1', cmd)
        cmd = _re.sub(r'>\s*\{target\}_([^\s]+)', f'> {safe_target}_\\1', cmd)
        
        # Ensure Paramspider's internal results directory exists inside the
        # configured output directory so we don't need to prepend "mkdir -p"
        # in the shell template. Paramspider always writes to ./results/<domain>.txt.
        if "paramspider" in cmd:
            try:
                from pathlib import Path as _Path
                (_Path(self.output_dir) / "results").mkdir(parents=True, exist_ok=True)
            except Exception as e:
                self.console.append_ansi(f"[i] Warning: could not create Paramspider results directory: {e}\n")
        
        # Post-substitution fixes:
        # - If a pipeline starts with echo <target>, ensure we didn't accidentally use the sanitized version
        for prefix in ("echo ", "echo\t", "echo\n"):
            if f"{prefix}{safe_target}" in cmd:
                cmd = cmd.replace(f"{prefix}{safe_target}", f"{prefix}{self.target}")
            if f"{prefix}https://{safe_target}" in cmd:
                cmd = cmd.replace(f"{prefix}https://{safe_target}", f"{prefix}{self.target}")
            if f"{prefix}http://{safe_target}" in cmd:
                cmd = cmd.replace(f"{prefix}http://{safe_target}", f"{prefix}{self.target}")
        
        # - Remove invalid gau flags if present in any custom template. This is
        #   now scoped to gau-only commands so that legitimate -mc flags used
        #   by tools like ffuf are preserved.
        import re as _re
        if " gau " in cmd or cmd.strip().startswith("gau "):
            cmd = _re.sub(r"\s--?mc\s*=?\s*\d+", "", cmd)

        # - For nuclei commands, ensure the -u URL argument is shell-quoted so
        #   query parameters containing '&' do not split the command into
        #   multiple statements (which causes "-o: command not found"). This
        #   also fixes any older custom nuclei templates that did not include
        #   quotes around {TARGET}.
        if "nuclei" in cmd and " -u " in cmd:
            def _quote_nuclei_url(m: "_re.Match[str]") -> str:
                prefix = m.group(1)
                url = m.group(2)
                # If already quoted, leave unchanged
                if url.startswith("'") or url.startswith('"'):
                    return m.group(0)
                return f"{prefix}'{url}'"

            cmd = _re.sub(r"(nuclei\s+[^|;]*?\s-u\s)(\S+)", _quote_nuclei_url, cmd)

        # - For ffuf commands, do the same quoting for the -u URL so '&' in the
        #   query string cannot break the shell command (which leads to "-w:
        #   command not found" when the wordlist flag is treated as a new
        #   command).
        if "ffuf" in cmd and " -u " in cmd:
            def _quote_ffuf_url(m: "_re.Match[str]") -> str:
                prefix = m.group(1)
                url = m.group(2)
                if url.startswith("'") or url.startswith('"'):
                    return m.group(0)
                return f"{prefix}'{url}'"

            cmd = _re.sub(r"(ffuf\s+[^|;]*?\s-u\s)(\S+)", _quote_ffuf_url, cmd)
        
        # Parse custom testssl summary options and strip them from the command
        # Supported flags (interpreted by the GUI, not by testssl itself):
        #   --min-severity <low|medium|high>
        #   --min-severity=<low|medium|high>
        #   --include-notes
        if "testssl" in cmd:
            # Reset to defaults for this invocation
            self._testssl_summary_min_severity = "LOW"
            self._testssl_summary_include_notes = False

            # --min-severity
            m = _re.search(r"--min-severity(?:=|\s+)(low|medium|high)", cmd, flags=_re.IGNORECASE)
            if m:
                sev = m.group(1).upper()
                if sev in ("LOW", "MEDIUM", "HIGH"):
                    self._testssl_summary_min_severity = sev
                # Strip the flag from the command so testssl doesn't see it
                cmd = _re.sub(
                    r"--min-severity(?:=|\s+)(low|medium|high)\b",
                    "",
                    cmd,
                    flags=_re.IGNORECASE,
                )

            # --include-notes
            if _re.search(r"--include-notes\b", cmd, flags=_re.IGNORECASE):
                self._testssl_summary_include_notes = True
                cmd = _re.sub(r"--include-notes\b", "", cmd, flags=_re.IGNORECASE)
        else:
            # Non-testssl commands: revert to safe defaults
            self._testssl_summary_min_severity = "LOW"
            self._testssl_summary_include_notes = False
        
        # Add custom headers if present
        headers_str = self.get_headers_string()
        if headers_str and 'curl' in cmd:
            cmd = cmd.replace('curl', f'curl {headers_str}')
        
        # Detect if this is the httpx alive check command that needs output file
        output_file = None
        if 'httpx-toolkit' in cmd and '_subdomains.txt' in cmd and ('-silent' in cmd or '-stream' in cmd):
            # This is the httpx filter command - save output to {target}_alive.txt
            output_file = str(self.output_dir / f"{safe_target}_alive.txt")
            self.console.append_ansi(f"[*] Output will be saved to: {safe_target}_alive.txt\\n")
        
        # Switch to console tab (now index 5 after restructuring)
        self.goto_console()
        self.console.append_ansi(f"\n{'='*80}\n")
        self.console.append_ansi(f"[*] Executing: {cmd}\n")
        self.console.append_ansi(f"{'='*80}\n\n")
        
        # Update status
        self.set_status_state("running")
        
        # Update status bar
        self.current_command = cmd
        self.update_status_bar("running", cmd)

        # If this is a sqlmap run, clear any previous SQLi highlighting state
        if "sqlmap" in cmd:
            self._reset_sqlmap_state()

        self.start_progress_animation()
        
        # Run command with optional output file
        self.runner.run_command(cmd, str(self.output_dir), output_file=output_file)

    def run_raw_command(self, cmd_template: str, label: str = None):
        """Run a command that needs no {TARGET}/{SAFE_TARGET} — e.g. the
        environment/tool-setup scripts, which make no sense to gate behind
        "set a target first" the way run_command_template does. Still
        resolves {CB_DIR} and streams through the same console/status bar/
        runner as every other command so the UX is identical.
        """
        self.current_action_label = label
        cmd = cmd_template.replace("{CB_DIR}", str(BASE_DIR))

        self.goto_console()

        self.console.append_ansi(f"\n{'='*80}\n")
        self.console.append_ansi(f"[*] Executing: {cmd}\n")
        self.console.append_ansi(f"{'='*80}\n\n")

        self.set_status_state("running")

        self.current_command = cmd
        self.update_status_bar("running", cmd)

        self.start_progress_animation()
        self.runner.run_command(cmd, str(self.output_dir))

    def run_command_from_registry(self, button_id):
        """Run a command from the registry"""
        # Special handling for SmartFuzz - always prompt for auth
        if button_id == 'web_smartfuzz':
            self.run_smartfuzz_with_auth()
            return

        cmd_template = self.command_registry.get(button_id)
        if cmd_template:
            # The button's own caption is the best name for what is running —
            # see get_action_display_name(). Registered by create_editable_button.
            label = getattr(self, "button_labels", {}).get(button_id)
            self.run_command_template(cmd_template, label=label)

    # ── Command persistence ──────────────────────────────────────────────
    #
    # The rule: the app ships a default for every button, and the user can
    # override any of them. Only genuine overrides are ever written to disk.
    #
    # This used to be badly broken. save_custom_commands() persisted the
    # WHOLE registry, so the first time anyone edited a single wordlist, all
    # ~97 commands were frozen to disk. load_custom_commands() then ran
    # before the UI was built and filled the registry from that file, and
    # create_editable_button()'s "if button_id not in self.command_registry"
    # meant every shipped default was skipped from then on. The effect was
    # silent and permanent: every command fix shipped in an update was
    # invisible, and the app kept running commands from whenever that file
    # was written.
    #
    # Now: saved entries are held aside until each button registers its
    # shipped default, and an entry only wins if it actually differs from the
    # default it was saved against. Entries that merely echo an old default
    # are discarded, so updates land.

    #: More saved commands than this means the file is a wholesale dump from
    #: the old build rather than deliberate edits. Nobody hand-edits twenty
    #: commands; the old save wrote all ninety-odd in one go.
    LEGACY_DUMP_THRESHOLD = 20

    def load_custom_commands(self):
        """Read saved command overrides. Does not populate the registry yet.

        Nothing is applied here because the shipped defaults are not known
        until the tabs are built — see register_default_command().
        """
        self._saved_overrides = {}
        self._migrated_overrides = []   # provenance unknown (old file format)
        self._stale_overrides = []      # user edit, but the default has since changed
        self._legacy_dump = {}          # wholesale dump from the old build
        config_dir = Path.home() / ".config" / "CommandBridge"

        # Current format: commands.json, which records the default each
        # override was made against.
        json_file = config_dir / "commands.json"
        if json_file.exists():
            try:
                with open(json_file, "r", encoding="utf-8") as f:
                    data = json.load(f)
                for button_id, entry in (data or {}).items():
                    if isinstance(entry, dict) and entry.get("command"):
                        self._saved_overrides[button_id] = {
                            "command": self.migrate_command_template(entry["command"]),
                            "base": entry.get("base"),
                        }
                return
            except Exception as e:
                print(f"Error loading commands.json: {e}")

        # Legacy format: custom_commands.txt, one "id::command" per line, with
        # no record of what the default was at the time.
        legacy = config_dir / "custom_commands.txt"
        if not legacy.exists():
            return
        try:
            entries = {}
            with open(legacy, "r", encoding="utf-8") as f:
                for line in f:
                    if "::" in line:
                        button_id, cmd = line.strip().split("::", 1)
                        entries[button_id] = self.migrate_command_template(cmd)
        except Exception as e:
            print(f"Error loading custom commands: {e}")
            return

        # The old build wrote the ENTIRE registry the moment any one command
        # was edited, so a file with dozens of entries is a wholesale dump,
        # not a set of deliberate customisations. Honouring it would keep
        # masking every shipped fix — which is the bug this is here to end.
        # So a dump is set aside rather than applied. Nothing is lost: the
        # file is preserved as a backup and every discarded command is listed
        # in the console, so a real edit can be put back deliberately.
        if len(entries) > self.LEGACY_DUMP_THRESHOLD:
            self._legacy_dump = entries
            # Retire the file now, not at the next save — otherwise it would
            # be read again on the next launch and keep re-masking defaults
            # for anyone who never edits a command again.
            try:
                legacy.rename(config_dir / "custom_commands.txt.pre-json-backup")
            except OSError as exc:
                print(f"Could not archive the legacy command file: {exc}")
            return

        # A short file is plausibly a genuine set of edits, so those are kept
        # and flagged for review instead.
        for button_id, cmd in entries.items():
            self._saved_overrides[button_id] = {"command": cmd, "base": None}

    def register_default_command(self, button_id: str, default_cmd: str):
        """Record a button's shipped default and decide what it should run.

        Called by create_editable_button() as each button is built.
        """
        if not hasattr(self, "default_commands"):
            self.default_commands = {}
        self.default_commands[button_id] = default_cmd

        override = getattr(self, "_saved_overrides", {}).get(button_id)
        if not override:
            self.command_registry[button_id] = default_cmd
            return

        saved = override["command"]
        base = override.get("base")

        if saved == default_cmd:
            # Identical to what ships — nothing to preserve.
            self.command_registry[button_id] = default_cmd
            return

        if base is None:
            # Legacy entry: can't tell an edit from a stale default. Keep it
            # (losing a real edit silently would be worse) but flag it.
            self._migrated_overrides.append(button_id)
        elif saved == base:
            # Saved copy is just the old shipped default — the update wins.
            self.command_registry[button_id] = default_cmd
            return
        elif base != default_cmd:
            # A real edit, but the shipped default has moved on since.
            self._stale_overrides.append(button_id)

        self.command_registry[button_id] = saved

    def reset_command_to_default(self, button_id: str) -> bool:
        """Drop a user override and go back to the shipped command."""
        default = getattr(self, "default_commands", {}).get(button_id)
        if default is None:
            return False
        self.command_registry[button_id] = default
        getattr(self, "_saved_overrides", {}).pop(button_id, None)
        self.save_custom_commands()
        return True

    def reset_all_commands_to_defaults(self) -> int:
        """Drop every override. Returns how many were reset."""
        defaults = getattr(self, "default_commands", {})
        changed = 0
        for button_id, default in defaults.items():
            if self.command_registry.get(button_id) != default:
                self.command_registry[button_id] = default
                changed += 1
        self._saved_overrides = {}
        self._migrated_overrides = []
        self._stale_overrides = []
        self.save_custom_commands()
        return changed

    def report_command_overrides(self):
        """Tell the user which commands are not running the shipped version.

        Runs once after the UI is built. Without this, an override that is
        really a stale default from an old version is completely invisible —
        which is exactly how a fixed command kept appearing broken.
        """
        migrated = getattr(self, "_migrated_overrides", [])
        stale = getattr(self, "_stale_overrides", [])
        dump = getattr(self, "_legacy_dump", {})
        if not migrated and not stale and not dump:
            return
        labels = getattr(self, "button_labels", {})

        def name(bid):
            return labels.get(bid, bid)

        try:
            if dump:
                defaults = getattr(self, "default_commands", {})
                differing = sorted(
                    bid for bid, cmd in dump.items()
                    if bid in defaults and cmd != defaults[bid]
                )
                self.console.append_ansi(
                    f"\n[i] {len(dump)} saved commands were found from an older "
                    "build that wrote every command to disk whenever one was "
                    "edited. That was masking shipped fixes, so they have been "
                    "set aside and the versions from this release are in use.\n"
                )
                self.console.append_ansi(
                    "    Backup: ~/.config/CommandBridge/custom_commands.txt.pre-json-backup\n"
                )
                if differing:
                    self.console.append_ansi(
                        f"    {len(differing)} of them differed from this release "
                        "— if any were deliberate edits of yours, re-apply them by "
                        "right-clicking the button:\n"
                    )
                    for bid in differing[:20]:
                        self.console.append_ansi(f"      - {name(bid)}\n")
                    if len(differing) > 20:
                        self.console.append_ansi(
                            f"      ... and {len(differing) - 20} more (see the backup file)\n"
                        )
            if migrated:
                self.console.append_ansi(
                    f"\n[i] {len(migrated)} saved command(s) differ from the versions "
                    "that ship with this release. They were saved by an older build "
                    "that could not tell an edit from a default, so they may simply "
                    "be out of date:\n"
                )
                for bid in sorted(migrated)[:25]:
                    self.console.append_ansi(f"      - {name(bid)}\n")
                if len(migrated) > 25:
                    self.console.append_ansi(f"      ... and {len(migrated) - 25} more\n")
                self.console.append_ansi(
                    "    Right-click a button -> Reset to Shipped Default to take the "
                    "updated version, or use Reset All Commands on the Target tab.\n"
                )
            if stale:
                self.console.append_ansi(
                    f"\n[i] {len(stale)} command(s) you have edited have also changed "
                    "in this release — your version is still being used:\n"
                )
                for bid in sorted(stale)[:25]:
                    self.console.append_ansi(f"      - {name(bid)}\n")
        except Exception:
            pass

    def migrate_command_template(self, cmd: str) -> str:
        """Migrate legacy/broken command templates to current format.
        - Replace {target} with {TARGET} for URL usage
        - Replace {target} with {SAFE_TARGET} in output filenames
        - Fix Nmap/TestSSL templates to use {TARGET_HOST} and proper logging flags
        - Remove invalid gau flags like --mc/-mc
        """
        try:
            import re as _re
            out = cmd
            
            # 1) Fix output file placeholders: -o {target}_xxx.txt -> -o {SAFE_TARGET}_xxx.txt
            out = _re.sub(r'-o\s+\{target\}_(\S+)', r'-o {SAFE_TARGET}_\1', out)
            out = _re.sub(r'-oN\s+\{target\}_(\S+)', r'-oN {SAFE_TARGET}_\1', out)
            out = _re.sub(r'--log\s+\{target\}_(\S+)', r'--log {SAFE_TARGET}_\1', out)
            out = _re.sub(r'--output-dir=\{target\}_(\S+)', r'--output-dir={SAFE_TARGET}_\1', out)
            out = _re.sub(r'>\s*\{target\}_(\S+)', r'> {SAFE_TARGET}_\1', out)
            
            # 2) Replace remaining {target} with {TARGET} for URL usage
            out = out.replace("{target}", "{TARGET}")
            
            # 3) Promote echo {TARGET} usages (for pipelines)
            out = out.replace("echo https://{TARGET}", "echo {TARGET}")
            out = out.replace("echo http://{TARGET}", "echo {TARGET}")
            
            # 4) Remove invalid gau flags
            out = _re.sub(r"\s--?mc\s*=?\s*\d+", "", out)

            # 5) Fix known Nmap templates to use {TARGET_HOST}
            out = out.replace(
                "nmap -sC -sV -T4 {TARGET} -oN {SAFE_TARGET}_nmap_quick.txt",
                "nmap -sC -sV -T4 {TARGET_HOST} -oN {SAFE_TARGET}_nmap_quick.txt",
            )
            out = out.replace(
                "nmap -p- -T4 {TARGET} -oN {SAFE_TARGET}_nmap_full.txt",
                "nmap -p- -T4 {TARGET_HOST} -oN {SAFE_TARGET}_nmap_full.txt",
            )
            out = out.replace(
                "nmap -sU -T4 --top-ports 100 {TARGET} -oN {SAFE_TARGET}_nmap_udp.txt",
                "nmap -sU -T4 --top-ports 100 {TARGET_HOST} -oN {SAFE_TARGET}_nmap_udp.txt",
            )

            # 6) Fix known TestSSL templates to use --logfile and {TARGET_HOST}
            out = out.replace(
                "testssl --log {SAFE_TARGET}_testssl.txt {TARGET}",
                "testssl --logfile {SAFE_TARGET}_testssl.log {TARGET_HOST}",
            )
            out = out.replace(
                "testssl --log {SAFE_TARGET}_testssl.txt {TARGET_HOST}",
                "testssl --logfile {SAFE_TARGET}_testssl.log {TARGET_HOST}",
            )

            # 7a) Legacy/broken raw `sslyze` CLI templates for the "SSL/TLS
            # Analysis" button (including the old --regular flag removed in
            # sslyze 5+, and the flag set that previously replaced it). A raw
            # sslyze CLI invocation just dumps data with no vulnerability
            # flagging at all — it will not surface BEAST, Lucky13, deprecated
            # TLS 1.0/1.1, or certificate expiry as findings, even though
            # sslyze technically retrieves that data. Migrate any such legacy
            # template wholesale to the bundled ssl_cipher_check.py script,
            # which parses the same sslyze data and prints proper
            # CRITICAL/HIGH/MEDIUM/LOW findings (this is also the button's
            # current default command in network_scan.py, so this just
            # un-shadows it for anyone with an old saved override).
            if _re.match(r"^\s*sslyze\s+\{TARGET_HOST\}(\s|$)", out):
                out = (
                    "python3 {CB_DIR}/command_bridge/modules/ssl_cipher_check.py {TARGET_HOST} "
                    "2>&1 | tee {SAFE_TARGET}_ssl_ciphers.txt"
                )

            # 7) Fix legacy Paramspider templates that used unsupported -o flag
            # and normalise them to use {TARGET_HOST} for the domain argument.
            out = out.replace(
                "paramspider -d {TARGET} -o {SAFE_TARGET}_params.txt",
                "paramspider -d {TARGET_HOST} | tee {SAFE_TARGET}_params.txt",
            )

            # 7) Fix broken Audit Server Response templates (truncated echo)
            if out.strip().startswith("curl -I {TARGET} -o {SAFE_TARGET}_headers.txt && echo"):
                out = (
                    "curl -I {TARGET} -o {SAFE_TARGET}_headers.txt && "
                    "printf \"\\n--- Full Response ---\\n\" >> {SAFE_TARGET}_headers.txt && "
                    "curl -v {TARGET} >> {SAFE_TARGET}_headers.txt 2>&1"
                )

            # 7b) Replace the legacy Swagger button command that relied on the
            # non-existent `swagger-parser` CLI with a curl-based fetch that also
            # reports clearly when the URL is not actually a spec endpoint.
            if "swagger-parser" in out:
                out = (
                    "echo '[*] Fetching OpenAPI/Swagger spec from {TARGET}'; "
                    "curl -sk '{TARGET}' -o {SAFE_TARGET}_swagger.json; "
                    "if python3 -m json.tool {SAFE_TARGET}_swagger.json >/dev/null 2>&1; then "
                    "echo '[+] Valid JSON spec saved to {SAFE_TARGET}_swagger.json'; "
                    "python3 -m json.tool {SAFE_TARGET}_swagger.json | head -120; "
                    "else echo '[!] Response is not valid JSON — the URL is likely NOT a Swagger/OpenAPI endpoint. "
                    "Try a real spec path e.g. /swagger.json /openapi.json /v2/api-docs /v3/api-docs /swagger/v1/swagger.json'; fi"
                )

            # 9) `gobuster dir` has no --wildcard flag — passing it makes
            # gobuster refuse to start at all ("flag provided but not
            # defined: -wildcard"). Strip it from any saved custom template.
            if _re.match(r"^\s*gobuster\s+dir\b", out):
                out = _re.sub(r"\s--wildcard\b", "", out)

            # 10) Legacy ffuf templates that wrote ffuf's raw "-of json" dump
            # straight to the file the user opens (full metadata: duration,
            # resultfile, scraper, position, ...) instead of a clean
            # "[STATUS] URL" list. Migrate the two known default commands
            # (Web tab FFUF, API tab API Fuzzing) to pipe through
            # ffuf_clean.py so the saved .txt is just the findings.
            if "-of json -o {SAFE_TARGET}_ffuf.json" in out and "ffuf_clean.py" not in out:
                out = out.replace(
                    "-of json -o {SAFE_TARGET}_ffuf.json",
                    "-of json -o {SAFE_TARGET}_ffuf_raw.json",
                ) + (
                    "; python3 {CB_DIR}/command_bridge/modules/ffuf_clean.py "
                    "{SAFE_TARGET}_ffuf_raw.json {SAFE_TARGET}_ffuf.txt"
                )
            if "-o {SAFE_TARGET}_api_fuzz.json" in out and "ffuf_clean.py" not in out:
                out = out.replace(
                    "-o {SAFE_TARGET}_api_fuzz.json",
                    "-of json -o {SAFE_TARGET}_api_fuzz_raw.json",
                ) + (
                    "; python3 {CB_DIR}/command_bridge/modules/ffuf_clean.py "
                    "{SAFE_TARGET}_api_fuzz_raw.json {SAFE_TARGET}_api_fuzz.txt"
                )

            # 12) Soft-404/wildcard filtering, added to the default fuzzing
            # commands after a real-world run turned up 500 identical "200"
            # hits that were all the same catch-all page. Self-heal any
            # saved custom command that predates this fix and still lacks
            # the relevant flag:
            #   - ffuf: add -ac (auto-calibrate) if missing.
            if _re.search(r"(?<![\w-])ffuf\s+-u", out) and not _re.search(r"(?<![\w-])-ac(?![\w-])", out):
                out = _re.sub(r"\bffuf(\s+-u)", r"ffuf -ac\1", out, count=1)

            #   - dirsearch: strip --filter-threshold if present, instead of
            #     adding it. This flag does NOT exist in dirsearch (confirmed
            #     against upstream source) — an earlier version of this app
            #     mistakenly added it as a soft-404 backstop, which made every
            #     dirsearch run fail immediately with "no such option:
            #     --filter-threshold" before sending a single request.
            #     dirsearch already does its own automatic wildcard/soft-404
            #     calibration with no flag needed. This direction matters: any
            #     dirsearch command saved to custom_commands.txt *before* this
            #     fix already has the broken flag baked in, and a saved
            #     command_registry entry permanently shadows the fixed
            #     default in tabs_web.py/fuzzing.py — so without this
            #     self-heal running here on load, the crash would keep coming
            #     back for anyone who had already configured Dirsearch once.
            if _re.match(r"^\s*dirsearch\b", out) and "--filter-threshold" in out:
                out = _re.sub(r"\s*--filter-threshold(?:=|\s+)\d+", "", out)

            #   - feroxbuster: add -q/--quiet if missing. Without it,
            #     feroxbuster prints its banner and a live-updating progress
            #     bar straight to the console — the -s in this command is
            #     feroxbuster's --status-codes filter, not a silent flag, so
            #     it does nothing to stop that. Same self-heal reasoning as
            #     above: a command saved before this fix would otherwise keep
            #     flooding the console forever.
            if _re.match(r"^\s*feroxbuster\b", out) and not _re.search(r"(?<![\w-])(-q|--quiet)(?![\w-])", out):
                out = _re.sub(r"\bferoxbuster(\s+--url)", r"feroxbuster -q\1", out, count=1)

            #   - gobuster: prepend the curl calibration probe (see
            #     modules/fuzzing.py web_gobuster for the full explanation)
            #     and route its result through --exclude-length, but only
            #     for a command we recognise as one of our own past default
            #     shapes — a hand-written custom gobuster command is left
            #     alone rather than risk mangling it.
            if (
                _re.match(r"^\s*gobuster\s+dir\s+-u\s+\{TARGET\}", out)
                and "PROBE_LEN" not in out
                and "-b 404,500" in out
            ):
                probe = (
                    'PROBE_PATH="cb_probe_$(date +%s%N)_$$_definitely_not_real"; '
                    "PROBE_LEN=$(curl -sk -m 10 -o /dev/null -w '%{size_download}' "
                    '"{TARGET}/$PROBE_PATH" 2>/dev/null); '
                    'GB_EXCL=""; '
                    'if echo "$PROBE_LEN" | grep -qE "^[0-9]+$" && [ "$PROBE_LEN" -gt 0 ]; then '
                    'echo "[*] Calibration probe got a ${PROBE_LEN}-byte response for a '
                    'nonexistent path -- looks like a catch-all/soft-404 responder, '
                    'excluding that size via --exclude-length."; '
                    'GB_EXCL="--exclude-length $PROBE_LEN"; '
                    'fi; '
                )
                out = probe + out.replace("-b 404,500", "-b 404,500 $GB_EXCL", 1)

            # 13) Trim duplicate spaces
            out = _re.sub(r"\s{2,}", " ", out).strip()

            return out
        except Exception:
            return cmd

    def save_custom_commands(self):
        """Persist only the commands that actually differ from the defaults.

        Writing the whole registry is what broke updates before: it turned
        every shipped command into a frozen user override the moment anything
        was edited. Each entry records the default it was made against, so a
        later release can tell "the user changed this" from "this is just an
        old default".
        """
        try:
            config_dir = Path.home() / ".config" / "CommandBridge"
            config_dir.mkdir(parents=True, exist_ok=True)
            defaults = getattr(self, "default_commands", {})

            data = {}
            for button_id, cmd in self.command_registry.items():
                default = defaults.get(button_id)
                if default is None or cmd != default:
                    data[button_id] = {"command": cmd, "base": default}

            with open(config_dir / "commands.json", "w", encoding="utf-8") as f:
                json.dump(data, f, indent=2, sort_keys=True)

            # Retire the legacy file so it can never be read back and undo
            # this. Renamed rather than deleted — it is the only copy of any
            # edit made under the old build.
            legacy = config_dir / "custom_commands.txt"
            if legacy.exists():
                legacy.rename(config_dir / "custom_commands.txt.pre-json-backup")
        except Exception as e:
            print(f"Error saving custom commands: {e}")

    def open_command_edit_dialog(self, button, button_id, default_cmd):
        """Open dialog to manually edit command"""
        from PyQt6.QtWidgets import QDialog, QVBoxLayout, QLabel, QDialogButtonBox
        
        # Create custom dialog
        dialog = QDialog(self)
        dialog.setWindowTitle(f"Edit Command: {button.text()}")
        dialog.resize(800, 400)  # Wide dialog for long commands
        
        # Apply current theme to dialog
        self.apply_theme_to_dialog(dialog)
        
        layout = QVBoxLayout(dialog)
        
        # Info label
        info = QLabel("Edit the command template below.\nUse {target} as placeholder for the target URL/domain.")
        info.setObjectName("fieldLabel")
        layout.addWidget(info)
        
        # Text editor
        current_cmd = self.command_registry.get(button_id, default_cmd)
        text_edit = QPlainTextEdit()
        text_edit.setPlainText(current_cmd)
        text_edit.setMinimumHeight(250)
        layout.addWidget(text_edit)
        
        # Buttons. "Restore Defaults" puts the shipped command back in the
        # editor rather than applying it immediately, so the change is still
        # reviewed and confirmed like any other edit.
        button_box = QDialogButtonBox(
            QDialogButtonBox.StandardButton.Ok | QDialogButtonBox.StandardButton.Cancel
        )
        shipped = getattr(self, "default_commands", {}).get(button_id, default_cmd)
        if shipped and shipped != current_cmd:
            reset_btn = button_box.addButton(
                "Reset to Shipped Default", QDialogButtonBox.ButtonRole.ResetRole
            )
            reset_btn.setToolTip(
                "Replace the text above with the command that ships with this "
                "version of Command Bridge. Useful after an update: your saved "
                "copy is kept until you press OK."
            )
            reset_btn.clicked.connect(lambda: text_edit.setPlainText(shipped))
        button_box.accepted.connect(dialog.accept)
        button_box.rejected.connect(dialog.reject)
        layout.addWidget(button_box)
        
        # Show dialog and handle result
        if dialog.exec() == QDialog.DialogCode.Accepted:
            new_cmd = text_edit.toPlainText().strip()
            if new_cmd:
                self.command_registry[button_id] = new_cmd
                self.save_custom_commands()

                # If this is one of the fuzzing buttons, treat manual editing as
                # a full configuration step so subsequent left-clicks execute
                # the command instead of re-opening the menu.
                try:
                    if button_id in ("web_dirsearch", "web_ffuf", "web_feroxbuster", "web_gobuster"):
                        if not hasattr(self, "_fuzzing_ready"):
                            self._fuzzing_ready = set()
                        self._fuzzing_ready.add(button_id)
                except Exception:
                    pass

                self.show_themed_message("Success", f"Command updated for '{button.text()}'")

    def on_target_changed(self, text):
        """Handle target input change"""
        self.target = text.strip()
        # Keep the header chip and status bar in step with the input field.
        if hasattr(self, "update_target_display"):
            self.update_target_display(self.target)
