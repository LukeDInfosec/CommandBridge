"""
Network Scanning section helpers for the Web tab.

Single source of truth for the Network Scanning tool commands (so the buttons
and the "All Network Scans" runner stay in sync) plus a sequential runner that
chains every network scan against the current target, one after another.
"""
import re as _re

from PyQt6.QtWidgets import QMessageBox

from command_bridge.constants import BASE_DIR


class NetworkScanMixin:
    """Provides the Network Scanning tool list, the Nuclei scan, and the
    'All Network Scans' sequential runner."""

    def _network_scan_tools(self):
        """Return [(label, button_id, default_command), ...] for the Network
        Scanning card. Edited commands persist in self.command_registry under
        the button_id, so the 'All' runner picks up user edits automatically."""
        return [
            ("Quick Nmap", "net_nmap_quick",
             "nmap -sV -sC -T4 {TARGET_HOST} -oN {SAFE_TARGET}_nmap_quick.txt"),
            ("Full Port Scan", "net_nmap_full",
             "nmap -sV -sC -p- -T4 {TARGET_HOST} -oN {SAFE_TARGET}_nmap_full.txt"),
            ("UDP Scan", "net_nmap_udp",
             "nmap -sU --top-ports 200 -T4 {TARGET_HOST} -oN {SAFE_TARGET}_nmap_udp.txt"),
            ("SSL/TLS Analysis", "net_sslyze",
             "python3 {CB_DIR}/command_bridge/modules/ssl_cipher_check.py {TARGET_HOST} 2>&1 | tee {SAFE_TARGET}_ssl_ciphers.txt"),
            ("Nikto Web Scan", "net_nikto",
             "nikto -h '{TARGET}' -o {SAFE_TARGET}_nikto.txt 2>&1"),
            ("Nuclei Scan", "net_nuclei",
             "if command -v nuclei >/dev/null 2>&1; then "
             "nuclei -u '{TARGET}' -severity low,medium,high,critical "
             "-stats -o {SAFE_TARGET}_nuclei.txt 2>&1; "
             "else echo '[!] nuclei is not installed (command not found). "
             "Install: go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest'; fi"),
        ]

    def _substitute_web_placeholders(self, cmd):
        """Substitute the common command placeholders without running anything.
        Mirrors the core replacements used by run_command_template."""
        safe_target = self.sanitize_target_for_filename(self.target)
        cmd = cmd.replace("{target}", self.target)
        cmd = cmd.replace("{TARGET}", self.target)
        cmd = cmd.replace("{TARGET_URL}", self.target)
        cmd = cmd.replace("{TARGET_HOST}", self.get_scanner_target())
        cmd = cmd.replace("{SAFE_TARGET}", safe_target)
        cmd = cmd.replace("{CB_DIR}", str(BASE_DIR))
        return cmd

    def run_all_network_scans(self):
        """Run every Network Scanning tool sequentially against the target.

        Reuses the Auto Scan sequential engine (self._auto_scan_*): each scan
        starts only when the previous one finishes, and output files land in the
        configured output directory just like the individual buttons."""
        if not self.target:
            self.show_themed_message(
                "No Target", "Please set a target first in the Target Setup tab.",
                QMessageBox.Icon.Warning,
            )
            return

        tools = self._network_scan_tools()
        commands = []
        for _name, btn_id, default_cmd in tools:
            template = self.command_registry.get(btn_id, default_cmd)
            commands.append(self._substitute_web_placeholders(template))

        # Hand off to the Auto Scan sequential runner.
        self._auto_scan_commands = commands
        self._auto_scan_active = True
        self._auto_scan_index = 0
        self._auto_scan_output_dir = str(self.output_dir)

        try:
            self.goto_console()
        except Exception:
            pass

        names = " → ".join(n for n, _b, _c in tools)
        self.console.append_ansi("\n" + "=" * 80 + "\n")
        self.console.append_ansi(f"[*] All Network Scans against: {self.target}\n")
        self.console.append_ansi(f"[*] Sequence: {names}\n")
        self.console.append_ansi("=" * 80 + "\n")

        self.set_status_state("running")
        self.update_status_bar("running", "All Network Scans")

        self._start_next_auto_scan_command()
