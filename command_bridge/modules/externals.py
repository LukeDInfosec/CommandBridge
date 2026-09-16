"""
Externals workflow — bulk IP testing, Nmap, TLS checks.
"""
import os
import re
import sys
import json
import subprocess
from pathlib import Path

from PyQt6 import QtCore, QtGui, QtWidgets
from PyQt6.QtCore import QProcess, Qt, QTimer, QThread, pyqtSignal, QObject
from PyQt6.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
    QPushButton, QLabel, QLineEdit, QTextEdit, QTabWidget, QGridLayout,
    QGroupBox, QSplitter, QScrollArea, QFileDialog, QMessageBox,
    QComboBox, QFrame, QPlainTextEdit, QProgressBar, QToolButton,
)
from command_bridge.constants import APP_TITLE, APP_VERSION, THEMES, BASE_DIR



class ExternalsMixin:
    """Mixin providing externals workflow — bulk ip testing, nmap, tls checks."""

    def check_self_signed_cert(self):
        """Check if the primary target is using a self-signed TLS certificate.

        Runs an openssl s_client command (configurable via right-click on the
        button) and compares the "subject=" and "issuer=" lines. If they
        match, the certificate is self-signed. Results are printed to the
        Console tab with red highlighting for self-signed certs and green when
        the issuer differs.
        """
        from PyQt6.QtWidgets import QMessageBox
        import subprocess
        import html as _html

        # Use the same host-normalisation as Nmap/TestSSL (no scheme, no path)
        host = self.get_scanner_target()
        if not host:
            self.show_themed_message(
                "No Target Host",
                "Please set a primary target (IP or hostname) in the Target Setup tab.",
                QMessageBox.Icon.Warning,
            )
            return

        # Ensure Console tab is visible
        try:
            self.goto_console()
        except Exception:
            pass

        self.console.append_ansi("\n=== Self-Signed Certificate Check ===\n")
        self.console.append_ansi(f"Target: {host}:443\n")

        # Resolve command template (user-editable via right-click on the button)
        default_cmd = "openssl s_client -connect {HOST}:443 -servername {HOST}"
        template = self.command_registry.get("externals_self_signed", default_cmd)
        final_cmd = template.replace("{HOST}", host)

        try:
            proc = subprocess.run(
                final_cmd,
                input=b"\n",
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                timeout=15,
                shell=True,
                executable="/bin/bash",
            )
            raw = proc.stdout.decode("utf-8", errors="replace")
        except subprocess.TimeoutExpired:
            self.console.append_ansi("[!] openssl s_client timed out connecting to target.\\n")
            return
        except Exception as e:
            self.console.append_ansi(f"[!] openssl s_client failed: {e}\\n")
            return

        # Extract subject= and issuer= lines (first occurrence of each)
        subject_line = ""
        issuer_line = ""
        for ln in raw.splitlines():
            lstrip = ln.strip()
            if lstrip.lower().startswith("subject=") and not subject_line:
                subject_line = lstrip
            elif lstrip.lower().startswith("issuer=") and not issuer_line:
                issuer_line = lstrip
            if subject_line and issuer_line:
                break

        if not subject_line or not issuer_line:
            msg = (
                "<span style=\"color: #f97316; font-weight: bold;\">"
                "Could not find subject=/issuer= lines in openssl output. "
                "The handshake may have failed or the output format was unexpected."
                "</span><br>"
            )
            self.console.append_html(msg)
            # Still dump the raw openssl output to the console for debugging
            self.console.append_ansi("\n[openssl raw output follows]\n" + raw + "\n")
            return

        # Pull out the values after "subject=" / "issuer=" for comparison
        subj_val = subject_line.split("=", 1)[1].strip() if "=" in subject_line else subject_line
        issu_val = issuer_line.split("=", 1)[1].strip() if "=" in issuer_line else issuer_line

        is_self_signed = bool(subj_val and issu_val and subj_val == issu_val)

        subj_esc = _html.escape(subject_line)
        issu_esc = _html.escape(issuer_line)

        if is_self_signed:
            header_color = "#ef4444"  # red
            status_label = "SELF-SIGNED certificate detected"
            subj_color = "#ef4444"
            issu_color = "#ef4444"
        else:
            header_color = "#22c55e"  # green
            status_label = "Certificate issuer differs from subject (not self-signed)"
            subj_color = "#22c55e"
            issu_color = "#22c55e"

        html_block = [
            f'<span style="color: {header_color}; font-weight: bold;">{_html.escape(status_label)}</span><br>',
            f'<span style="color: {subj_color};">{subj_esc}</span><br>',
            f'<span style="color: {issu_color};">{issu_esc}</span><br>',
            "<br>",
        ]

        self.console.append_html("".join(html_block))

    def tidy_externals_ips(self):
        """Normalise pasted Externals IP list to bare IP/CIDR values.

        Examples:
        - "127.0.0.1 - Internal IP Address" -> "127.0.0.1"
        - "127.0.0.1/29 - Range"           -> "127.0.0.1/29"

        Any line that does not start with an IPv4 address (optionally with a
        CIDR suffix) is dropped.
        """
        from PyQt6.QtWidgets import QMessageBox
        import re

        if not hasattr(self, "externals_ip_input"):
            return

        raw = self.externals_ip_input.toPlainText().splitlines()
        cleaned: list[str] = []

        # Regex: capture IPv4 or IPv4/CIDR *anywhere* in the line. This allows
        # for bullet characters or other prefixes before the address.
        ip_re = re.compile(r"([0-9]{1,3}(?:\.[0-9]{1,3}){3}(?:/[0-9]{1,2})?)")

        for line in raw:
            if not line.strip():
                continue
            # Remove any trailing description after a '-' first
            before_dash = line.split('-', 1)[0]
            m = ip_re.search(before_dash)
            if not m:
                # Fallback: search the full line (in case there was no '-')
                m = ip_re.search(line)
            if m:
                cleaned.append(m.group(1).strip())

        if not cleaned:
            self.show_themed_message(
                "No IPs Detected",
                "No valid IP addresses or CIDR ranges were found to tidy.",
                QMessageBox.Icon.Warning,
            )
            return

        self.externals_ip_input.setPlainText("\n".join(cleaned))
        # Optional console note so you can see that a tidy operation occurred
        try:
            self.console.append_ansi(
                f"\n[i] TIDY IPs normalised list to {len(cleaned)} entries (IP/CIDR only).\\n"
            )
        except Exception:
            pass

    def _normalise_externals_host_lines(self, raw: str) -> list[str]:
        """Return clean host/IP entries from pasted Externals text."""
        from urllib.parse import urlparse

        cleaned: list[str] = []
        seen: set[str] = set()
        ip_re = re.compile(r"([0-9]{1,3}(?:\.[0-9]{1,3}){3}(?:/[0-9]{1,2})?)")

        for line in raw.splitlines():
            candidate = line.strip()
            if not candidate:
                continue

            host = ""
            parsed = urlparse(candidate)
            if parsed.scheme and parsed.hostname:
                host = parsed.hostname
                if parsed.port:
                    host = f"{host}:{parsed.port}"
            else:
                before_dash = candidate.split(" - ", 1)[0].strip()
                m = ip_re.search(before_dash)
                if m:
                    host = m.group(1).strip()
                else:
                    host = before_dash.split()[0] if before_dash else ""
                    host = host.split("/", 1)[0].split("?", 1)[0].strip()

            if host.startswith("*."):
                host = host[2:]
            if host and host not in seen:
                cleaned.append(host)
                seen.add(host)

        return cleaned

    def _normalise_externals_url_lines(self, raw: str, default_scheme: str = "https") -> list[str]:
        """Return URL entries, adding https:// to bare IPs/hosts."""
        urls: list[str] = []
        seen: set[str] = set()

        for line in raw.splitlines():
            candidate = line.strip()
            if not candidate:
                continue
            if not candidate.lower().startswith(("http://", "https://")):
                candidate = f"{default_scheme}://{candidate}"
            if candidate not in seen:
                urls.append(candidate)
                seen.add(candidate)

        return urls

    def save_externals_ips_csv(self):
        """Save pasted Externals hosts as a single comma-separated output file."""
        from pathlib import Path as _Path

        if not hasattr(self, "externals_ip_input"):
            return

        hosts = self._normalise_externals_host_lines(self.externals_ip_input.toPlainText())
        if not hosts:
            self.show_themed_message(
                "No IPs Detected",
                "No valid IP addresses or hostnames were found to save.",
                QMessageBox.Icon.Warning,
            )
            return

        csv_line = ", ".join(hosts)
        out_path = _Path(self.output_dir) / "ips_comma_separated.txt"
        try:
            out_path.write_text(csv_line + "\n", encoding="utf-8", errors="replace")
        except Exception as e:
            self.show_themed_message("File Error", f"Could not write CSV IP list: {e}", QMessageBox.Icon.Critical)
            return

        try:
            self.externals_ip_input.setPlainText("\n".join(hosts))
            self.goto_console()
            self.console.append_ansi("\n[i] Saved comma-separated IP list to ips_comma_separated.txt:\n")
            self.console.append_ansi(csv_line + "\n")
            self.refresh_file_list()
        except Exception:
            pass

    # ── Bulk Web-Facing Host Check ────────────────────────────────────────────

    def run_externals_web_facing_check(self):
        """Bulk-check pasted hosts/IPs for a reachable public-facing web service.

        Built for large lists (hundreds of IPs) where a full Nmap -sV pass per
        host would be far too slow. Runs fast concurrent TCP-connect probes
        against a small set of common web ports (443, 80, 8443, 8080) for
        every host and reports which ones have at least one open, i.e. are
        potentially exposing a web page to the internet. Writes
        bulk_web_facing_hosts.txt (and a comma-separated variant) to the
        output directory.
        """
        if not hasattr(self, "externals_ip_input"):
            return

        raw = self.externals_ip_input.toPlainText().strip()
        if not raw:
            self.show_themed_message(
                "No Hosts Provided",
                "Please paste one or more IP addresses/hostnames (one per line) "
                "before running 'Check Web-Facing Hosts'.",
                QMessageBox.Icon.Warning,
            )
            return

        hosts = self._normalise_externals_host_lines(raw)
        # Drop any :port left over from URL parsing — this check tests its own port list.
        hosts = [h.split(":", 1)[0] for h in hosts]
        hosts = list(dict.fromkeys(h for h in hosts if h))  # de-dupe, keep order

        if not hosts:
            self.show_themed_message(
                "No Valid Hosts",
                "No valid IP addresses or hostnames were detected in the input.",
                QMessageBox.Icon.Warning,
            )
            return

        try:
            self.goto_console()
        except Exception:
            pass

        port_list = ", ".join(str(p) for p in _WebFacingCheckWorker.WEB_PORTS)
        self.console.append_ansi("\n" + "=" * 60 + "\n")
        self.console.append_ansi(f"  Bulk Web-Facing Host Check — {len(hosts)} host(s)\n")
        self.console.append_ansi(f"  Ports checked: {port_list}\n")
        self.console.append_ansi("=" * 60 + "\n\n")

        if hasattr(self, "externals_webcheck_btn"):
            self.externals_webcheck_btn.setEnabled(False)
            self.externals_webcheck_btn.setText("Checking…")

        self._webcheck_worker = _WebFacingCheckWorker(hosts)
        self._webcheck_thread = QThread()
        self._webcheck_worker.moveToThread(self._webcheck_thread)
        self._webcheck_thread.started.connect(self._webcheck_worker.run)
        self._webcheck_worker.progress.connect(self._on_webcheck_progress)
        self._webcheck_worker.finished.connect(self._on_webcheck_done)
        self._webcheck_worker.finished.connect(self._webcheck_thread.quit)
        self._webcheck_thread.start()

    def _on_webcheck_progress(self, msg):
        self.console.append_ansi(msg)

    def _on_webcheck_done(self, result: dict):
        if hasattr(self, "externals_webcheck_btn"):
            self.externals_webcheck_btn.setEnabled(True)
            self.externals_webcheck_btn.setText("🌐  Check Web-Facing Hosts (Bulk)")

        import html as _html

        exposed = result.get("exposed", [])   # [(host, [ports]), ...]
        closed = result.get("closed", [])     # [host, ...]
        errors = result.get("errors", [])     # [host, ...]

        self.console.append_ansi("\n" + "-" * 60 + "\n")
        if exposed:
            self.console.append_html(
                '<span style="color:#ef4444;font-weight:bold;">'
                "[EXPOSED] Hosts with a reachable web service:</span><br>"
            )
            for host, ports in exposed:
                port_str = ", ".join(str(p) for p in ports)
                self.console.append_html(
                    f'<span style="color:#ef4444;">  {_html.escape(host)}  →  '
                    f'{_html.escape(port_str)}</span><br>'
                )
        else:
            self.console.append_html(
                '<span style="color:#22c55e;font-weight:bold;">'
                "✓ No web-facing services detected on any scanned host/port."
                "</span><br>"
            )

        total = len(exposed) + len(closed) + len(errors)
        self.console.append_ansi(
            f"\n[i] Checked {total} host(s): {len(exposed)} exposed, "
            f"{len(closed)} closed, {len(errors)} unreachable/errored.\n"
        )

        try:
            out_path = Path(self.output_dir) / "bulk_web_facing_hosts.txt"
            lines = [f"{host} -> {', '.join(str(p) for p in ports)}" for host, ports in exposed]
            out_path.write_text(
                ("\n".join(lines) + "\n") if lines else "",
                encoding="utf-8", errors="replace",
            )
            if exposed:
                csv_path = Path(self.output_dir) / "bulk_web_facing_hosts_comma_separated.txt"
                csv_path.write_text(", ".join(h for h, _ in exposed) + "\n", encoding="utf-8", errors="replace")
            self.console.append_ansi("[i] Wrote results to bulk_web_facing_hosts.txt\n")
            self.refresh_file_list()
        except Exception as e:
            self.console.append_ansi(f"[i] Could not write bulk_web_facing_hosts.txt: {e}\n")

        self.console.append_ansi("=" * 60 + "\n")

    def run_externals_check_whats_up(self):
        """Check which pasted hosts are responsive and write them to up.txt.

        This performs a lightweight Nmap host discovery (nmap -sn) against the
        hosts in the Externals text box, then:
        - Prints a list of hosts considered UP and those considered DOWN.
        - Writes only the UP hosts to up.txt in the current output directory.

        Input lines can be:
        - Bare IP addresses (e.g. 192.0.2.10)
        - Hostnames (e.g. test.cloud)
        - URLs (e.g. https://test.cloud/login), in which case only the hostname
          portion is used for scanning.
        """
        from pathlib import Path
        from urllib.parse import urlparse

        raw = self.externals_ip_input.toPlainText().strip() if hasattr(self, "externals_ip_input") else ""
        if not raw:
            self.show_themed_message(
                "No Hosts Provided",
                "Please paste one or more IP addresses, hostnames, or URLs (one per line) before running 'Check What's Up'.",
                QMessageBox.Icon.Warning,
            )
            return

        lines = self._normalise_externals_host_lines(raw)

        if not lines:
            self.show_themed_message(
                "No Valid Hosts",
                "No valid IP addresses, hostnames, or URLs were detected in the input.",
                QMessageBox.Icon.Warning,
            )
            return

        base_dir = Path(self.output_dir)
        nmap_dir = base_dir / "Nmap"
        try:
            nmap_dir.mkdir(parents=True, exist_ok=True)
        except Exception as e:
            self.show_themed_message("Directory Error", f"Could not create Nmap folder: {e}", QMessageBox.Icon.Critical)
            return

        # Write ips.txt with the pasted list so nmap -iL can consume it
        ips_path = base_dir / "ips.txt"
        try:
            with open(ips_path, "w", encoding="utf-8", errors="replace") as f_ips:
                for ip in lines:
                    f_ips.write(ip + "\n")
        except Exception as e:
            self.show_themed_message("File Error", f"Could not write ips.txt: {e}", QMessageBox.Icon.Critical)
            return

        # Prepare discovery output path
        disc_rel = f"{nmap_dir.name}/externals_nmap_discovery.txt"
        disc_abs = nmap_dir / "externals_nmap_discovery.txt"

        # Initialise a dedicated check-whats-up state so _on_externals_command_finished
        # can post-process the discovery results without triggering the full
        # Externals pipeline.
        self._externals_active = True
        self._externals_check_mode = True
        self._externals_phase = "check-discovery"
        self._externals_context = {
            "ips_path": str(ips_path),
            "discovery_rel": disc_rel,
            "discovery_abs": str(disc_abs),
        }

        # Switch to Console tab
        try:
            self.goto_console()
        except Exception:
            pass

        self.console.append_ansi("\n" + "=" * 80 + "\n")
        self.console.append_ansi("[*] Running 'Check What's Up' host discovery for Externals IP list\n")
        self.console.append_ansi(f"[*] Saved {len(lines)} IPs to ips.txt in {self.output_dir}\n")
        self.console.append_ansi("=" * 80 + "\n\n")

        # Allow user to customise discovery flags via command template
        default_cmd = "nmap -sn -T4 -n -iL ips.txt -oN {DISCOVERY_OUT}"
        template = self.command_registry.get("externals_discovery", default_cmd)
        cmd = template.replace("{DISCOVERY_OUT}", disc_rel)
        self._run_externals_command(cmd, "Externals Check What's Up")

    def run_externals_workflow(self):
        """Entry point for Externals tab 'Run Externals Test' button."""
        from pathlib import Path
        from PyQt6.QtWidgets import QInputDialog

        raw = self.externals_ip_input.toPlainText().strip() if hasattr(self, "externals_ip_input") else ""
        pasted_lines = self._normalise_externals_host_lines(raw) if raw else []
        has_pasted = bool(pasted_lines)

        base_dir = Path(self.output_dir)
        up_candidate = base_dir / "up.txt"
        has_up_file = up_candidate.exists() and up_candidate.stat().st_size > 0

        # Build source options depending on what is available
        options = []
        if has_pasted:
            options.append("Use IPs from text box")
        if has_up_file:
            options.append("Use IPs from up.txt")

        if not options:
            self.show_themed_message(
                "No IPs Available",
                "Please paste one or more IP addresses, or run 'Check What's Up' to create up.txt before running the Externals test.",
                QMessageBox.Icon.Warning,
            )
            return

        # Ask the user which source to use
        choice, ok = QInputDialog.getItem(
            self,
            "Externals: Select IP Source",
            "Run Externals tests against:",
            options,
            0,
            False,
        )
        if not ok:
            return

        use_pasted = (choice == "Use IPs from text box")
        use_up_file = (choice == "Use IPs from up.txt")

        if use_pasted:
            if not has_pasted:
                self.show_themed_message(
                    "No IPs Provided",
                    "Please paste one or more IP addresses (one per line) before choosing the text box option.",
                    QMessageBox.Icon.Warning,
                )
                return
            lines = pasted_lines
            try:
                self.externals_ip_input.setPlainText("\n".join(lines))
            except Exception:
                pass
        elif use_up_file:
            # Load IPs from up.txt
            try:
                with open(up_candidate, "r", encoding="utf-8", errors="replace") as f_up:
                    lines = [ln.strip() for ln in f_up if ln.strip()]
            except Exception as e:
                self.show_themed_message("File Error", f"Could not read up.txt: {e}", QMessageBox.Icon.Critical)
                return
            if not lines:
                self.show_themed_message(
                    "Empty up.txt",
                    "up.txt does not contain any IP addresses. Run 'Check What's Up' again or paste IPs into the text box.",
                    QMessageBox.Icon.Warning,
                )
                return
        else:
            # Fallback safety net
            self.show_themed_message("Selection Error", "Unknown selection for Externals source.", QMessageBox.Icon.Critical)
            return

        base_dir = Path(self.output_dir)
        nmap_dir = base_dir / "Nmap"
        ssl_dir = base_dir / "SSL_Scan"

        # Ensure subdirectories exist
        try:
            nmap_dir.mkdir(parents=True, exist_ok=True)
            ssl_dir.mkdir(parents=True, exist_ok=True)
        except Exception as e:
            self.show_themed_message("Directory Error", f"Could not create Nmap/SSL_Scan folders: {e}", QMessageBox.Icon.Critical)
            return

        # Clean up old Externals artefacts to keep the output folder tidy
        try:
            # Remove previous ips/up lists
            for p in (base_dir / "ips.txt", base_dir / "up.txt"):
                if p.exists():
                    p.unlink()
            for name in (
                "live_hosts.txt",
                "unreachable_hosts.txt",
                "web_facing_hosts.txt",
                "potential_admin_interfaces.txt",
                "additional_external_checks.txt",
                "directory_findings.txt",
                "dangerous_services.txt",
                "open_ports_by_service.txt",
                "technology_fingerprints.txt",
                "missing_security_headers.txt",
                "externals_tls_summary.txt",
                "tls_findings.txt",
                "external_assessment_summary.txt",
                "executive_summary.txt",
                "technical_findings.txt",
                "external_findings.json",
            ):
                p = base_dir / name
                if p.exists() and p.is_file():
                    p.unlink()
            # Remove previous Externals Nmap outputs
            for p in nmap_dir.glob("externals_*"):
                if p.is_file():
                    p.unlink()
            # Remove previous Externals TestSSL outputs
            for p in ssl_dir.glob("externals_*"):
                if p.is_file():
                    p.unlink()
        except Exception:
            # Best-effort cleanup; do not block the workflow
            pass

        ips_path = base_dir / "ips.txt"
        up_path = base_dir / "up.txt"
        try:
            # ips.txt always reflects the list chosen for this Externals run
            with open(ips_path, "w", encoding="utf-8", errors="replace") as f_ips:
                for ip in lines:
                    f_ips.write(ip + "\n")

            # up.txt mirrors the chosen list here as well. If the user previously
            # ran 'Check What's Up', up.txt will have already been written with
            # the "up" hosts; in that workflow we overwrite up.txt there. For an
            # Externals run based on the text box, we maintain the earlier
            # behaviour where all hosts are treated as scan candidates.
            with open(up_path, "w", encoding="utf-8", errors="replace") as f_up:
                for ip in lines:
                    f_up.write(ip + "\n")
        except Exception as e:
            self.show_themed_message("File Error", f"Could not write ips.txt/up.txt: {e}", QMessageBox.Icon.Critical)
            return

        # Initialise Externals state machine
        self._externals_active = True
        self._externals_phase = "discovery"
        self._externals_context = {
            "ips_path": str(ips_path),
            "up_path": str(up_path),
            "nmap_dir_name": nmap_dir.name,
            "ssl_dir_name": ssl_dir.name,
            "nmap_results_path": str(nmap_dir / "externals_nmap_results.txt"),
            "nmap_results_rel": f"{nmap_dir.name}/externals_nmap_results.txt",
            "targets": list(lines),
            "live_hosts": [],
            "unreachable_hosts": [],
            "web_assets": [],
            "admin_interfaces": [],
            "findings": [],
        }

        # Switch to Console tab
        try:
            self.goto_console()
        except Exception:
            pass

        self.console.append_ansi("\n" + "=" * 80 + "\n")
        self.console.append_ansi("[*] Starting Externals workflow (host discovery + Nmap + headers + TLS)\n")
        self.console.append_ansi(f"[*] Saved {len(lines)} IPs to ips.txt and up.txt in {self.output_dir}\n")
        self.console.append_ansi("=" * 80 + "\n\n")

        # Kick off a lightweight host discovery scan (results are informational;
        # all IPs remain in up.txt for -Pn scanning).
        disc_name = f"{self._externals_context['nmap_dir_name']}/externals_nmap_discovery.txt"
        default_cmd = "nmap -sn -T4 -n -iL ips.txt -oN {DISCOVERY_OUT}"
        template = self.command_registry.get("externals_discovery", default_cmd)
        cmd = template.replace("{DISCOVERY_OUT}", disc_name)
        self._run_externals_command(cmd, "Externals Host Discovery")

    def set_externals_single_host(self):
        """Populate the IP list box from the single-host field for quick checks."""
        if not hasattr(self, "externals_single_host_input"):
            return
        host = self.externals_single_host_input.text().strip()
        if not host:
            self.show_themed_message(
                "No Host Provided",
                "Enter a single IP or hostname first.",
                QMessageBox.Icon.Warning,
            )
            return
        # Replace contents of the IP list box with this one host
        self.externals_ip_input.setPlainText(host + "\n")

    def run_externals_ike_aggressive(self):
        """Validate IKE Aggressive Mode with pre-shared key using ike-scan.

        This loop is intended to confirm Nessus findings such as
        "Internet Key Exchange (IKE) Aggressive Mode with Pre-Shared Key" by
        actively probing UDP/500 on each external host and logging the
        handshake details.
        """
        ip_list = self._externals_pick_ip_list_for_checks()
        if not ip_list:
            return

        # Use a simple while-read loop so each host's output is clearly
        # separated in externals_ike_scan.txt and in the console.
        cmd = (
            "if command -v ike-scan >/dev/null 2>&1; then "
            f"list={ip_list}; "
            "if [ ! -s \"$list\" ]; then echo 'No IPs in list for ike-scan (expected up.txt or ips.txt)'; exit 1; fi; "
            "while read ip; do "
            "echo \"===== $ip =====\" | tee -a externals_ike_scan.txt; "
            "ike-scan -M -A \"$ip\" | tee -a externals_ike_scan.txt; "
            "echo \"\" | tee -a externals_ike_scan.txt; "
            "done < \"$list\"; "
            "else echo 'Error: ike-scan is not installed (command not found).'; fi"
        )
        self._run_externals_command(cmd, "Externals IKE Aggressive Mode Check")

    def run_externals_ssh_audit(self):
        """Run ssh-audit (if installed) against each external host on up.txt/ips.txt."""
        ip_list = self._externals_pick_ip_list_for_checks()
        if not ip_list:
            return

        cmd = (
            "if command -v ssh-audit >/dev/null 2>&1; then "
            f"list={ip_list}; "
            "if [ ! -s \"$list\" ]; then echo 'No IPs in list for ssh-audit (expected up.txt or ips.txt)'; exit 1; fi; "
            "while read ip; do "
            "echo \"===== $ip =====\" | tee -a externals_ssh_audit.txt; "
            "ssh-audit -T \"$ip\" | tee -a externals_ssh_audit.txt; "
            "echo \"\" | tee -a externals_ssh_audit.txt; "
            "done < \"$list\"; "
            "else echo 'Error: ssh-audit is not installed (command not found).'; fi"
        )
        self._run_externals_command(cmd, "Externals SSH Crypto Audit")

    def run_externals_smb_validation(self):
        """Validate SMB signing/shares using Nmap SMB NSE scripts."""
        ip_list = self._externals_pick_ip_list_for_checks()
        if not ip_list:
            return
        nmap_dir = self._externals_ensure_nmap_dir()
        if nmap_dir is None:
            return

        out_path = f"Nmap/externals_smb_validation.txt"
        cmd = (
            "if command -v nmap >/dev/null 2>&1; then "
            "nmap -Pn -n -p445 --script smb2-security-mode,smb-enum-shares "
            f"-iL {ip_list} -oN {out_path}; "
            "else echo 'Error: nmap is not installed (command not found).'; fi"
        )
        self._run_externals_command(cmd, "Externals SMB Validation")

    def run_externals_rdp_encryption(self):
        """Validate RDP encryption/security level with rdp-enum-encryption."""
        ip_list = self._externals_pick_ip_list_for_checks()
        if not ip_list:
            return
        nmap_dir = self._externals_ensure_nmap_dir()
        if nmap_dir is None:
            return

        out_path = f"Nmap/externals_rdp_encryption.txt"
        cmd = (
            "if command -v nmap >/dev/null 2>&1; then "
            "nmap -Pn -n -p3389 --script rdp-enum-encryption "
            f"-iL {ip_list} -oN {out_path}; "
            "else echo 'Error: nmap is not installed (command not found).'; fi"
        )
        self._run_externals_command(cmd, "Externals RDP Encryption Check")

    def run_externals_ftp_anon(self):
        """Check for anonymous FTP access on external hosts."""
        ip_list = self._externals_pick_ip_list_for_checks()
        if not ip_list:
            return
        nmap_dir = self._externals_ensure_nmap_dir()
        if nmap_dir is None:
            return

        out_path = f"Nmap/externals_ftp_anon.txt"
        cmd = (
            "if command -v nmap >/dev/null 2>&1; then "
            "nmap -Pn -n -p21 --script ftp-anon "
            f"-iL {ip_list} -oN {out_path}; "
            "else echo 'Error: nmap is not installed (command not found).'; fi"
        )
        self._run_externals_command(cmd, "Externals FTP Anonymous Check")

    def run_externals_smtp_relay(self):
        """Check for SMTP open relay behaviour on common mail ports."""
        ip_list = self._externals_pick_ip_list_for_checks()
        if not ip_list:
            return
        nmap_dir = self._externals_ensure_nmap_dir()
        if nmap_dir is None:
            return

        out_path = f"Nmap/externals_smtp_open_relay.txt"
        cmd = (
            "if command -v nmap >/dev/null 2>&1; then "
            "nmap -Pn -n -p25,465,587 --script smtp-open-relay "
            f"-iL {ip_list} -oN {out_path}; "
            "else echo 'Error: nmap is not installed (command not found).'; fi"
        )
        self._run_externals_command(cmd, "Externals SMTP Open Relay Check")

    def run_externals_icmp_timestamp(self):
        """ICMP Timestamp Request Remote Date Disclosure via hping3.

        Runs `sudo hping3 <ip> --icmp --icmp-ts -c 1 -V` against each host in
        live_hosts.txt (falling back to up.txt / ips.txt). Prints one sample
        reply for context, then lists every affected host as a comma-separated
        line and saves it to icmp_timestamp_affected.txt.
        """
        from pathlib import Path as _Path

        base_dir = _Path(self.output_dir)
        list_name = None
        for cand in ("live_hosts.txt", "up.txt", "ips.txt"):
            p = base_dir / cand
            if p.exists() and p.stat().st_size > 0:
                list_name = cand
                break
        if not list_name:
            self.show_themed_message(
                "No Host List Available",
                "No live_hosts.txt / up.txt / ips.txt found. Run 'Check What's Up' "
                "or 'Run Externals Test' first so a host list exists.",
                QMessageBox.Icon.Warning,
            )
            return

        cmd = (
            "if command -v hping3 >/dev/null 2>&1; then "
            f"list={list_name}; "
            "if [ ! -s \"$list\" ]; then echo \"No hosts in $list\"; exit 1; fi; "
            "affected=\"\"; first=1; "
            "while read ip; do "
            "[ -z \"$ip\" ] && continue; "
            "out=$(timeout 15 sudo -n hping3 \"$ip\" --icmp --icmp-ts -c 1 -V 2>&1); "
            "if echo \"$out\" | grep -qi 'ICMP timestamp'; then "
            "if [ \"$first\" -eq 1 ]; then echo \"===== Sample ICMP timestamp reply ($ip) =====\"; echo \"$out\"; echo; first=0; fi; "
            "if [ -z \"$affected\" ]; then affected=\"$ip\"; else affected=\"$affected, $ip\"; fi; "
            "fi; "
            "done < \"$list\"; "
            "echo; echo '=== ICMP Timestamp Request Remote Date Disclosure ==='; "
            "if [ -n \"$affected\" ]; then echo 'Affected Hosts:'; echo \"$affected\"; "
            "echo \"$affected\" > icmp_timestamp_affected.txt; echo; echo '[i] Saved to icmp_timestamp_affected.txt'; "
            "else echo 'No hosts disclosed ICMP timestamps. If every host errored, ensure passwordless sudo for hping3 (the GUI cannot answer a sudo password prompt).'; fi; "
            "else echo 'Error: hping3 is not installed (command not found). Install with: sudo apt install hping3'; fi"
        )
        self._run_externals_command(cmd, "Externals ICMP Timestamp Disclosure")

    def run_externals_wildcard_certs(self):
        """Check for wildcard TLS certificates across external hosts.

        Instead of just dumping raw openssl output, this helper:
        - Reads hosts from up.txt or ips.txt (via _externals_pick_ip_list_for_checks).
        - Normalises each entry (stripping http(s) schemes, etc.).
        - Fetches the server certificate with Python's ssl module.
        - Parses CN and subjectAltName DNS entries.
        - Explicitly reports whether any wildcard names (e.g. *.example.com) are present.
        - Writes a summary file externals_wildcard_certs.txt in the output directory.
        """
        import ssl
        import socket
        import ipaddress
        from pathlib import Path as _Path
        from urllib.parse import urlparse

        ip_list = self._externals_pick_ip_list_for_checks()
        if not ip_list:
            return

        base_dir = _Path(self.output_dir)
        list_path = base_dir / ip_list

        try:
            with open(list_path, "r", encoding="utf-8", errors="replace") as f:
                hosts = [ln.strip() for ln in f if ln.strip()]
        except Exception as e:
            self.show_themed_message("File Error", f"Could not read {ip_list}: {e}", QMessageBox.Icon.Critical)
            return

        if not hosts:
            self.show_themed_message(
                "No Hosts Found",
                f"{ip_list} does not contain any IPs/hosts. Run 'Check What's Up' or 'Run Externals Test' first.",
                QMessageBox.Icon.Warning,
            )
            return

        out_path = base_dir / "externals_wildcard_certs.txt"
        out_file = None
        try:
            out_file = open(out_path, "w", encoding="utf-8", errors="replace")
        except Exception:
            out_file = None

        # Show results in Console tab
        try:
            self.goto_console()
        except Exception:
            pass

        self.console.append_ansi("\n" + "-" * 80 + "\n")
        self.console.append_ansi("[*] Externals Wildcard Certificate Check (Python-based)\n")
        self.console.append_ansi(f"[*] Using host list from: {list_path}\n")
        self.console.append_ansi("-" * 80 + "\n")

        def _log(line: str) -> None:
            self.console.append_ansi(line + "\n")
            if out_file is not None:
                try:
                    out_file.write(line + "\n")
                except Exception:
                    pass

        for raw in hosts:
            raw_host = raw.strip()
            if not raw_host:
                continue

            # Normalise entries like https://host or http://host: strip scheme.
            parsed = urlparse(raw_host)
            if parsed.scheme and parsed.hostname:
                host = parsed.hostname
            else:
                host = raw_host

            _log("")
            _log(f"===== {raw_host} =====")

            # Determine if this is an IP literal (so we don't send SNI for IPs).
            is_ip = False
            try:
                ipaddress.ip_address(host)
                is_ip = True
            except ValueError:
                is_ip = False

            try:
                ctx = ssl.create_default_context()
                with socket.create_connection((host, 443), timeout=10) as sock:
                    with ctx.wrap_socket(sock, server_hostname=None if is_ip else host) as ssock:
                        cert = ssock.getpeercert()
            except Exception as e:
                _log(f"[!] Error fetching certificate from {host}: {e}")
                continue

            # Extract CN
            cn = None
            for rdn in cert.get("subject", ()):
                for key, value in rdn:
                    if key.lower() == "commonname":
                        cn = value
                        break
                if cn:
                    break

            # Extract DNS SANs
            sans = [v for (t, v) in cert.get("subjectAltName", ()) if t.lower() == "dns"]

            names = []
            if cn:
                names.append(cn)
            names.extend(sans)

            wildcard_names = [n for n in names if isinstance(n, str) and n.startswith("*.")]

            if wildcard_names:
                # Use [✖] prefix so the EnhancedConsole colours this as high-risk.
                status = f"[✖] WILDCARD CERTIFICATE IN USE: {', '.join(sorted(set(wildcard_names)))}"
            else:
                status = "[✔] No wildcard names detected in certificate."

            _log(status)
            if cn:
                _log(f"    CN : {cn}")
            if sans:
                _log(f"    SAN: {', '.join(sorted(set(sans)))}")

        if out_file is not None:
            try:
                out_file.close()
            except Exception:
                pass

        self.console.append_ansi("\n[i] Wildcard certificate summary written to externals_wildcard_certs.txt in the output directory.\n")
        try:
            self.refresh_file_list()
        except Exception:
            pass

    def _run_externals_command(self, cmd: str, label: str) -> None:
        """Run a shell command as part of the Externals workflow."""
        # Log and update status, mirroring run_command_template behaviour but
        # without placeholder substitution.
        self.console.append_ansi(f"\n{'-'*80}\n")
        self.console.append_ansi(f"[*] {label}: {cmd}\n")
        self.console.append_ansi(f"{'-'*80}\n\n")

        self.set_status_state("running")

        self.current_command = cmd
        self.update_status_bar("running", cmd)
        self.start_progress_animation()

        # Run in the configured output directory so ips.txt/up.txt etc. resolve
        self.runner.run_command(cmd, str(self.output_dir))

    def _externals_pick_ip_list_for_checks(self) -> str | None:
        """Return the filename to use for verification checks (up.txt or ips.txt).

        Preference order:
        - up.txt if it exists and is non-empty (hosts confirmed "up").
        - ips.txt if it exists and is non-empty.
        If neither exists, show a warning and return None.
        """
        try:
            from pathlib import Path as _Path
            base_dir = _Path(self.output_dir)
            up_path = base_dir / "up.txt"
            ips_path = base_dir / "ips.txt"

            if up_path.exists() and up_path.stat().st_size > 0:
                return "up.txt"
            if ips_path.exists() and ips_path.stat().st_size > 0:
                return "ips.txt"
        except Exception:
            pass

        self.show_themed_message(
            "No IP List Available",
            "Run 'Check What's Up' or 'Run Externals Test' first so up.txt or ips.txt exists in the output directory.",
            QMessageBox.Icon.Warning,
        )
        return None

    def _externals_ensure_nmap_dir(self):
        """Ensure the Nmap subdirectory exists for Externals checks."""
        from pathlib import Path as _Path
        base_dir = _Path(self.output_dir)
        nmap_dir = base_dir / "Nmap"
        try:
            nmap_dir.mkdir(parents=True, exist_ok=True)
        except Exception as e:
            self.show_themed_message("Directory Error", f"Could not create Nmap folder: {e}", QMessageBox.Icon.Critical)
            return None
        return nmap_dir

    def _externals_add_finding(self, severity: str, title: str, target: str = "", detail: str = "", evidence: str = "") -> None:
        """Append a normalised finding to the active Externals context."""
        ctx = getattr(self, "_externals_context", {}) or {}
        findings = ctx.setdefault("findings", [])
        sev = (severity or "INFO").upper()
        if sev == "INFORMATIONAL":
            sev = "INFO"
        finding = {
            "severity": sev,
            "title": title,
            "target": target,
            "detail": detail,
            "evidence": evidence,
        }
        # Avoid exact duplicates from repeated phases.
        key = (finding["severity"], finding["title"], finding["target"], finding["detail"], finding["evidence"])
        for existing in findings:
            existing_key = (
                existing.get("severity"),
                existing.get("title"),
                existing.get("target"),
                existing.get("detail"),
                existing.get("evidence"),
            )
            if existing_key == key:
                return
        findings.append(finding)
        self._externals_context = ctx

    def _externals_parse_discovery_results(self) -> tuple[list[str], list[str]]:
        """Parse host discovery output and write live/unreachable host files."""
        from pathlib import Path as _Path
        import re as _re

        ctx = getattr(self, "_externals_context", {}) or {}
        base_dir = _Path(self.output_dir)
        ips_path = _Path(ctx.get("ips_path", base_dir / "ips.txt"))
        disc_path = base_dir / "Nmap" / "externals_nmap_discovery.txt"

        source_hosts = []
        if ips_path.exists():
            source_hosts = [ln.strip() for ln in ips_path.read_text(encoding="utf-8", errors="replace").splitlines() if ln.strip()]

        live: set[str] = set()
        if disc_path.exists():
            host_pattern = _re.compile(r"^Nmap scan report for\s+(.+)$")
            up_pattern = _re.compile(r"Host is up", _re.IGNORECASE)
            current_host = None
            for line in disc_path.read_text(encoding="utf-8", errors="replace").splitlines():
                m_h = host_pattern.match(line)
                if m_h:
                    host_str = m_h.group(1).strip()
                    m_ip = _re.search(r"([0-9]{1,3}(?:\.[0-9]{1,3}){3})", host_str)
                    current_host = m_ip.group(1) if m_ip else host_str
                    continue
                if current_host and up_pattern.search(line):
                    live.add(current_host)

        # If host discovery found nothing, keep the workflow useful for public
        # targets that block ping by treating the submitted list as scanable.
        if not live:
            live = set(source_hosts)

        unreachable = []
        for host in source_hosts:
            if "/" in host:
                continue
            if host not in live:
                unreachable.append(host)

        live_list = sorted(live)
        unreachable_list = sorted(set(unreachable))

        (base_dir / "live_hosts.txt").write_text("\n".join(live_list) + ("\n" if live_list else ""), encoding="utf-8", errors="replace")
        (base_dir / "unreachable_hosts.txt").write_text("\n".join(unreachable_list) + ("\n" if unreachable_list else ""), encoding="utf-8", errors="replace")
        (base_dir / "up.txt").write_text("\n".join(live_list) + ("\n" if live_list else ""), encoding="utf-8", errors="replace")

        self.console.append_ansi(f"[i] Discovery summary: {len(live_list)} live/scanable host(s), {len(unreachable_list)} unreachable host(s).\n")
        self.console.append_ansi("[i] Wrote live_hosts.txt and unreachable_hosts.txt.\n")
        return live_list, unreachable_list

    def _on_externals_command_finished(self, exit_code: int) -> None:
        """Advance Externals workflow when a command completes.

        Phases:
        - "discovery": host discovery (best-effort), then start Nmap service scan.
        - "nmap": parse results, run header checks, then queue async TestSSL runs.
        - "tls": run TestSSL sequentially via CommandRunner (non-blocking), then
          summarise Lucky13/Sweet32 issues.
        - "check-discovery": host discovery for the standalone "Check What's Up"
          action; classify hosts as up/down and stop (no full Externals run).
        """
        from pathlib import Path

        if not self._externals_active:
            return

        # Standalone "Check What's Up" discovery-only mode
        if getattr(self, "_externals_check_mode", False) and self._externals_phase == "check-discovery":
            try:
                self._externals_finish_check_whats_up(exit_code)
            except Exception as e:
                self.console.append_ansi(f"[i] 'Check What's Up' post-processing error: {e}\\n")
            # Reset state
            self._externals_active = False
            self._externals_phase = None
            self._externals_context = {}
            self._externals_check_mode = False
            return

        # On discovery completion -> start Nmap scan
        if self._externals_phase == "discovery":
            try:
                live_hosts, unreachable_hosts = self._externals_parse_discovery_results()
                self._externals_context["live_hosts"] = live_hosts
                self._externals_context["unreachable_hosts"] = unreachable_hosts
            except Exception as e:
                self.console.append_ansi(f"[i] Could not parse discovery results into live/unreachable host files: {e}\n")

            if exit_code != 0:
                self.console.append_ansi("[!] Host discovery command failed; continuing with full scan using up.txt.\n")
            else:
                self.console.append_ansi("[i] Host discovery phase complete. Proceeding with Nmap service scan.\n")

            self._externals_phase = "nmap"
            up_name = Path(self._externals_context.get("up_path", "up.txt")).name
            # Use -Pn to avoid treating non-responsive hosts as down; include
            # service/version detection and reasons. -v gives incremental
            # progress output into the console. The full command is user-
            # configurable via the 'Run Externals Test' right-click editor.
            default_cmd = (
                "nmap -Pn -T4 --top-ports 1000 -iL {UP_FILE} -oN Nmap/externals_nmap_fast.txt; "
                "nmap -Pn -n -sS -sV -sC -O --reason -v -iL {UP_FILE} -oN {NMAP_RESULTS_OUT}"
            )
            template = self.command_registry.get("externals_nmap", default_cmd)
            cmd = (
                template
                .replace("{UP_FILE}", up_name)
                .replace("{NMAP_RESULTS_OUT}", self._externals_context['nmap_results_rel'])
            )
            self._run_externals_command(cmd, "Externals Nmap Scan")
            return

        # On Nmap completion -> post-process, headers, then start async TLS checks
        if self._externals_phase == "nmap":
            results_path = Path(self._externals_context["nmap_results_path"])
            if exit_code != 0:
                self.console.append_ansi(f"[!] Nmap externals scan finished with exit code {exit_code}. Results may be incomplete.\n")

            # Post-process Nmap results: highlight dangerous ports and collect
            # HTTP(S) and TLS candidates.
            try:
                dangerous, http_hosts, tls_hosts = self._externals_process_nmap_results(results_path)
                self._externals_print_dangerous_ports_summary(dangerous)
                # Prioritised findings + grouped, Nessus-style summaries.
                try:
                    self._externals_record_dangerous_findings(dangerous)
                    self._externals_write_dangerous_services(dangerous)
                    self._externals_write_open_ports_summary()
                except Exception as e2:
                    self.console.append_ansi(f"[i] Dangerous-service reporting error: {e2}\n")
            except Exception as e:
                self.console.append_ansi(f"[i] Could not post-process Nmap externals results: {e}\n")
                http_hosts, tls_hosts = [], []

            # Run security header checks against HTTP(S) services
            try:
                self._externals_run_security_headers(http_hosts)
            except Exception as e:
                self.console.append_ansi(f"[i] Externals security header checks failed: {e}\n")

            # Save web-facing assets and optionally launch directory enumeration
            # via a real popup. The console is output-only, so never ask for
            # interactive y/n input inside the shell command.
            web_assets = self._externals_write_web_facing_hosts(http_hosts)
            self._externals_context["web_assets"] = web_assets
            tls_hosts = list(sorted(set(tls_hosts or [])))
            self._externals_context["pending_tls_hosts"] = tls_hosts

            if web_assets and self._externals_prompt_directory_enumeration(web_assets):
                self._externals_phase = "directory_enum"
                self._externals_start_directory_enumeration()
                return

            self._externals_start_tls_phase(tls_hosts)
            return

        # Directory enumeration is optional. Once it completes, continue into
        # TLS checks exactly as if the user had selected "No" in the popup.
        if self._externals_phase == "directory_enum":
            if exit_code != 0:
                self.console.append_ansi(f"[!] Directory enumeration finished with exit code {exit_code}. Continuing with TLS checks.\n")
            else:
                self.console.append_ansi("[i] Directory enumeration phase complete. Continuing with TLS checks.\n")
            tls_hosts = self._externals_context.get("pending_tls_hosts") or []
            self._externals_start_tls_phase(tls_hosts)
            return

        # TLS/TestSSL phase: aggregate issues per host and move through queue
        if self._externals_phase == "tls":
            from pathlib import Path as _Path

            tls_hosts = self._externals_context.get("tls_hosts") or []
            idx = self._externals_context.get("tls_index", 0)
            issues = self._externals_context.get("tls_issues") or {}
            current_host = self._externals_context.get("current_tls_host")

            # Parse results for the host we just scanned
            if current_host:
                try:
                    safe_host = self.sanitize_target_for_filename(current_host)
                    ssl_dir = _Path(self.output_dir) / self._externals_context.get("ssl_dir_name", "SSL_Scan")
                    txt_path = ssl_dir / f"externals_{safe_host}_testssl.txt"
                    if txt_path.exists():
                        text = txt_path.read_text(encoding="utf-8", errors="replace")
                    else:
                        text = ""
                except Exception:
                    text = ""

                # Strip ANSI sequences from Externals TestSSL outputs so the
                # saved reports are clean (no stray "\x1b[1m" style markers).
                if text:
                    import re as _re
                    ansi_escape = _re.compile(r"\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])")
                    cleaned = ansi_escape.sub("", text)
                    if cleaned != text:
                        try:
                            txt_path.write_text(cleaned, encoding="utf-8", errors="replace")
                        except Exception:
                            pass
                        text = cleaned
                    # Also clean the corresponding .log file if present
                    try:
                        log_path = ssl_dir / f"externals_{safe_host}_testssl.log"
                        if log_path.exists():
                            raw_log = log_path.read_text(encoding="utf-8", errors="replace")
                            cleaned_log = ansi_escape.sub("", raw_log)
                            if cleaned_log != raw_log:
                                log_path.write_text(cleaned_log, encoding="utf-8", errors="replace")
                    except Exception:
                        pass

                # For aggregation we only need to know *what* issues were
                # detected and, for CBC issues, which ciphers were involved.
                # We intentionally suppress per-host summaries here to avoid
                # noisy output; the normal TestSSL button still prints
                # full, per-target details.
                text_l = text.lower()
                has_lucky = "lucky13" in text_l or "lucky 13" in text_l
                has_sweet = "sweet32" in text_l or "sweet 32" in text_l
                has_beast = "beast" in text_l or ("tls 1.0" in text_l and "cbc" in text_l)
                has_cbc = "cbc" in text_l and ("vulnerable" in text_l or "offered" in text_l)

                # Extract CBC cipher names for Lucky13-style issues
                ciphers = set()
                if has_lucky and text:
                    import re as _re
                    for m in _re.finditer(r"(TLS_[A-Z0-9_]*CBC[A-Z0-9_]*)", text):
                        ciphers.add(m.group(1))

                if has_lucky and has_sweet:
                    key = "Lucky 13 (CBC) & Sweet 32 detected"
                elif has_lucky:
                    key = "Lucky 13 Detected (CBC ciphers in use)"
                elif has_sweet:
                    key = "Sweet 32 Detected (64-bit block ciphers)"
                else:
                    key = None

                if key:
                    bucket = issues.setdefault(key, {"hosts": set(), "ciphers": set()})
                    bucket["hosts"].add(current_host)
                    bucket["ciphers"].update(ciphers)
                    self._externals_context["tls_issues"] = issues

                if has_beast:
                    bucket_beast = issues.setdefault("BEAST Risk (TLS 1.0 with CBC ciphers)", {"hosts": set(), "ciphers": set()})
                    bucket_beast["hosts"].add(current_host)
                    bucket_beast["ciphers"].update(ciphers or {"TLS 1.0 CBC"})
                    self._externals_context["tls_issues"] = issues

                if has_cbc and not has_lucky:
                    bucket_cbc = issues.setdefault("CBC Ciphers Offered (Lucky13-style risk)", {"hosts": set(), "ciphers": set()})
                    bucket_cbc["hosts"].add(current_host)
                    bucket_cbc["ciphers"].update(ciphers or {"CBC cipher suites"})
                    self._externals_context["tls_issues"] = issues

                # Track deprecated TLS protocol versions (1.0/1.1) if they appear
                has_tls10 = ("tls 1.0" in text_l) or ("tlsv1.0" in text_l) or ("tlsv1 " in text_l)
                has_tls11 = ("tls 1.1" in text_l) or ("tlsv1.1" in text_l)
                if has_tls10 or has_tls11:
                    key_proto = "Deprecated TLS Version 1.0 / 1.1"
                    bucket2 = issues.setdefault(key_proto, {"hosts": set(), "ciphers": set()})
                    bucket2["hosts"].add(current_host)
                    if has_tls10:
                        bucket2["ciphers"].add("TLS 1.0")
                    if has_tls11:
                        bucket2["ciphers"].add("TLS 1.1")
                    self._externals_context["tls_issues"] = issues

                cert_checks = [
                    ("Certificate Expired / Not Valid", ("certificate expired", "expired", "not valid at validation time")),
                    ("Certificate Chain Not Trusted", ("not trusted", "chain of trust", "self signed", "self-signed")),
                    ("HSTS Missing", ("hsts not set", "strict-transport-security header missing", "strict transport security    not offered", "not supported - server did not return the header")),
                ]
                for issue_name, needles in cert_checks:
                    if any(n in text_l for n in needles):
                        bucket_cert = issues.setdefault(issue_name, {"hosts": set(), "ciphers": set()})
                        bucket_cert["hosts"].add(current_host)
                        self._externals_context["tls_issues"] = issues

            # Advance to next host, if any
            if idx >= len(tls_hosts):
                # All TLS hosts processed – print grouped summary, write summary
                # file, clean up per-host TestSSL outputs, and finish.
                summary_lines: list[str] = []

                if not issues:
                    msg = "[i] No TLS issues detected (Lucky13, Sweet32, or deprecated TLS 1.0/1.1).\\n"
                    self.console.append_ansi(msg)
                    summary_lines.append("No TLS issues detected (Lucky13, Sweet32, or deprecated TLS 1.0/1.1).\n")
                else:
                    header = "\nSummary of TLS issues across all Externals hosts:\n"
                    self.console.append_ansi(header)
                    summary_lines.append("Summary of TLS issues across all Externals hosts:\n\n")

                    for issue, data in issues.items():
                        hosts = sorted(data.get("hosts") or [])
                        ciphers = sorted(data.get("ciphers") or [])

                        self.console.append_ansi(f"\n{issue}\n")
                        summary_lines.append(f"{issue}\n")

                        for c in ciphers:
                            self.console.append_ansi(f"{c}\n")
                            summary_lines.append(f"{c}\n")
                        if ciphers:
                            self.console.append_ansi("\n")
                            summary_lines.append("\n")

                        for h in hosts:
                            self.console.append_ansi(f"{h}\n")
                            summary_lines.append(f"{h}\n")

                        self.console.append_ansi("\n")
                        summary_lines.append("\n")

                # Write aggregated TLS summary to a single file
                try:
                    summary_path = _Path(self.output_dir) / "externals_tls_summary.txt"
                    with summary_path.open("w", encoding="utf-8", errors="replace") as f_sum:
                        for line in summary_lines:
                            f_sum.write(line)
                    self.console.append_ansi(f"[i] Wrote TLS summary to: {summary_path}\\n")
                except Exception as e:
                    self.console.append_ansi(f"[i] Could not write TLS summary file: {e}\\n")

                # Best-effort cleanup of per-host TestSSL artefacts to avoid
                # clutter when many hosts are scanned.
                try:
                    ssl_dir = _Path(self.output_dir) / self._externals_context.get("ssl_dir_name", "SSL_Scan")
                    if ssl_dir.exists():
                        for p in ssl_dir.glob("externals_*_testssl.*"):
                            try:
                                p.unlink()
                            except Exception:
                                pass
                except Exception:
                    pass

                self.console.append_ansi("\n[i] TLS phase complete. Proceeding to web reconnaissance & reporting.\n")
                self._externals_begin_web_recon()
                return

            # Kick off next TestSSL command
            self._externals_start_next_tls_host()

    def _externals_finish_check_whats_up(self, exit_code: int) -> None:
        """Post-process discovery results for 'Check What's Up' and write up.txt.

        This parses the discovery output (externals_nmap_discovery.txt) to
        classify each IP from ips.txt as UP or DOWN, prints both lists to the
        console under clear headings, and writes only the UP hosts to up.txt.
        """
        from pathlib import Path as _Path
        import re as _re

        ctx = getattr(self, "_externals_context", {}) or {}
        ips_path = _Path(ctx.get("ips_path", _Path(self.output_dir) / "ips.txt"))
        disc_path = _Path(ctx.get("discovery_abs", _Path(self.output_dir) / "Nmap" / "externals_nmap_discovery.txt"))

        # Load original IP list
        ips: list[str] = []
        try:
            if ips_path.exists():
                for ln in ips_path.read_text(encoding="utf-8", errors="replace").splitlines():
                    ln = ln.strip()
                    if ln:
                        ips.append(ln)
        except Exception as e:
            self.console.append_ansi(f"[i] Could not read ips.txt for 'Check What's Up': {e}\\n")

        # Default classification: everything is "down" until proven otherwise
        up_hosts: set[str] = set()
        down_hosts: set[str] = set(ips)

        if disc_path.exists():
            host_pattern = _re.compile(r"^Nmap scan report for\s+(.+)$")
            up_pattern = _re.compile(r"Host is up", _re.IGNORECASE)
            seems_down_pattern = _re.compile(r"Host seems down", _re.IGNORECASE)

            current_host = None
            try:
                with disc_path.open("r", encoding="utf-8", errors="replace") as f:
                    for line in f:
                        m_h = host_pattern.match(line)
                        if m_h:
                            host_str = m_h.group(1).strip()
                            # Prefer a literal IPv4 address if present, even
                            # when Nmap prints a hostname like
                            # "example.com (1.2.3.4)". This ensures our
                            # classification maps cleanly back to the
                            # plain IPs written in ips.txt.
                            m_ip = _re.search(r"([0-9]{1,3}(?:\.[0-9]{1,3}){3})", host_str)
                            if m_ip:
                                current_host = m_ip.group(1)
                            else:
                                current_host = host_str
                            continue

                        if not current_host:
                            continue

                        if up_pattern.search(line):
                            up_hosts.add(current_host)
                            if current_host in down_hosts:
                                down_hosts.discard(current_host)
                        elif seems_down_pattern.search(line):
                            # Explicitly recorded as down; ensure it is in down_hosts
                            if current_host not in up_hosts:
                                down_hosts.add(current_host)
            except Exception as e:
                self.console.append_ansi(f"[i] Could not parse discovery output: {e}\\n")
        else:
            self.console.append_ansi(
                f"[i] Discovery output not found at {disc_path}; treating all hosts as down.\\n"
            )

        # Build the UP list directly from the discovered hosts, so we always
        # report the real responsive IPs (including those that came from CIDR
        # ranges like 203.0.113.0/29).
        up_list: list[str] = sorted(up_hosts)

        # For the DOWN list, only consider plain IPs from ips.txt (not CIDR
        # ranges), and list those that never appeared in up_hosts.
        down_list: list[str] = []
        for src in ips:
            if "/" in src:
                # Source line was a range (e.g. 93.0.0.0/29); we don't try to
                # enumerate and list every non-responsive member here.
                continue
            if src not in up_hosts:
                down_list.append(src)

        # Write up.txt with only the hosts considered UP
        up_path = _Path(self.output_dir) / "up.txt"
        try:
            with up_path.open("w", encoding="utf-8", errors="replace") as f_up:
                for ip in up_list:
                    f_up.write(ip + "\n")
        except Exception as e:
            self.console.append_ansi(f"[i] Could not write up.txt: {e}\\n")

        # Print summary to console
        self.console.append_ansi("\n=== Externals: Check What's Up Results ===\n")
        self.console.append_ansi(f"[i] Nmap discovery exit code: {exit_code}\\n")

        self.console.append_ansi("\n[+] Hosts considered UP:\n")
        if up_list:
            for ip in up_list:
                self.console.append_ansi(ip + "\n")
        else:
            self.console.append_ansi("(none)\\n")

        self.console.append_ansi("\n[-] Hosts considered DOWN / no response:\n")
        if down_list:
            for ip in down_list:
                self.console.append_ansi(ip + "\n")
        else:
            self.console.append_ansi("(none)\\n")

        self.console.append_ansi(
            f"\n[i] Wrote {len(up_list)} reachable hosts to up.txt in {self.output_dir}\\n"
        )

    def _externals_process_nmap_results(self, path: "Path"):
        """Parse Nmap results to identify dangerous ports and HTTP/TLS hosts.

        Returns (dangerous_entries, http_hosts, tls_hosts).
        - dangerous_entries: list of (host, port, proto, service, reason, severity)
        - http_hosts: list of (host, port) for 80/443-like ports
        - tls_hosts: list of host strings (typically those with 443 open)
        """
        import re as _re
        from pathlib import Path as _Path

        path = _Path(path)
        if not path.exists():
            self.console.append_ansi(f"[i] Nmap externals results file not found: {path}\n")
            return [], [], []

        # Static severity ranking
        sev_rank = {"LOW": 0, "MEDIUM": 1, "HIGH": 2}

        port_policies = self._externals_get_dangerous_ports()
        svc_policies = self._externals_get_dangerous_service_keywords()
        admin_indicators = self._externals_get_admin_indicators()

        # Capture the trailing product/version banner too (group 4) so we can
        # fingerprint web technology (nginx/apache/iis/tomcat) and build a
        # grouped open-ports summary.
        open_pattern = _re.compile(r"^(\d+)/(tcp|udp)\s+open\s+(\S+)\s*(.*)$")
        host_pattern = _re.compile(r"^Nmap scan report for\s+(.+)$")

        current_host = None
        dangerous_entries = []
        http_hosts = []
        tls_hosts = []

        ctx = getattr(self, "_externals_context", {}) or {}
        all_open_ports = ctx.get("open_ports") or []
        web_tech = set(ctx.get("web_tech") or [])
        tech_by_host = ctx.get("tech_by_host") or {}
        tech_tokens = ("nginx", "apache", "iis", "microsoft-iis", "tomcat",
                       "coyote", "openresty", "litespeed", "jetty", "express",
                       "asp.net", "php", "wordpress", "drupal", "joomla")

        with open(path, "r", encoding="utf-8", errors="replace") as f:
            for line in f:
                m_host = host_pattern.match(line)
                if m_host:
                    current_host = m_host.group(1).strip()
                    continue

                m_open = open_pattern.match(line.strip())
                if not (m_open and current_host):
                    continue

                port = int(m_open.group(1))
                proto = m_open.group(2)
                service = m_open.group(3)
                version = (m_open.group(4) or "").strip()
                service_l = service.lower()

                # Accumulate every open port for the grouped summary.
                all_open_ports.append({
                    "host": current_host, "port": port, "proto": proto,
                    "service": service, "version": version,
                })

                # Technology fingerprinting from the version banner.
                banner_l = f"{service_l} {version.lower()}"
                for tok in tech_tokens:
                    if tok in banner_l:
                        web_tech.add(tok)
                        tech_by_host.setdefault(current_host, [])
                        if tok not in tech_by_host[current_host]:
                            tech_by_host[current_host].append(tok)

                # Track web services for header checks and optional directory
                # enumeration. Preserve non-standard ports so generated URLs
                # are immediately usable by FFUF/dirsearch/gobuster.
                web_ports = {80, 443, 8080, 8443, 8000, 8888, 9000, 9443, 10443, 3000, 5000, 5601, 9200}
                if port in web_ports or "http" in service_l:
                    http_hosts.append((current_host, port))
                    if port in (443, 8443, 9443, 10443) or "ssl" in service_l or "https" in service_l:
                        tls_hosts.append(current_host if port == 443 else f"{current_host}:{port}")

                severity = None
                reason = None

                # 1) Port-based risk classification
                if port in port_policies:
                    severity, reason = port_policies[port]

                # 2) Service-name based detection (e.g. jenkins, grafana, docker)
                for kw, (sev, label) in svc_policies.items():
                    if kw in service_l:
                        if severity is None or sev_rank.get(sev, 0) > sev_rank.get(severity, 0):
                            severity, reason = sev, label
                        elif label and label not in (reason or ""):
                            reason = f"{reason}; {label}" if reason else label

                # 3) Generic admin keywords (dashboard/admin/management etc.)
                for kw in admin_indicators:
                    if kw in service_l:
                        sev = "MEDIUM"
                        label = f"Service appears to expose an administrative interface ('{kw}' in banner)"
                        if severity is None or sev_rank.get(sev, 0) > sev_rank.get(severity, 0):
                            severity, reason = sev, label
                        elif label not in (reason or ""):
                            reason = f"{reason}; {label}" if reason else label

                if reason:
                    dangerous_entries.append(
                        (current_host, port, proto, service, reason, severity or "HIGH")
                    )

        # Persist accumulated open-port / tech data for later phases & reports.
        ctx["open_ports"] = all_open_ports
        ctx["web_tech"] = sorted(web_tech)
        ctx["tech_by_host"] = tech_by_host
        self._externals_context = ctx

        return dangerous_entries, http_hosts, list(sorted(set(tls_hosts)))

    def _externals_get_dangerous_ports(self):
        """Return mapping of port -> (severity, reason) for risky Internet-facing services.

        Severity is one of:
        - "HIGH"   → almost never justified on the public Internet
        - "MEDIUM" → often legitimate but should be justified and locked down
        """
        ports: dict[int, tuple[str, str]] = {}

        # --------------------------
        # 🔴 HIGH-RISK: Remote admin
        # --------------------------
        ports[20] = ("HIGH", "FTP data (clear-text file transfer)")
        ports[21] = ("HIGH", "FTP (clear-text file transfer)")
        ports[22] = ("HIGH", "SSH remote administration exposed to the Internet")
        ports[23] = ("HIGH", "Telnet (clear-text remote shell) exposed to the Internet")
        ports[2222] = ("HIGH", "Alternate SSH port exposed to the Internet")
        ports[992] = ("HIGH", "Telnet over SSL exposed to the Internet")
        ports[3389] = ("HIGH", "RDP remote desktop exposed to the Internet")
        # VNC range 5900–5999
        for p in range(5900, 6000):
            ports[p] = ("HIGH", "VNC remote desktop exposed to the Internet")
        # Intel AMT 16992–16995
        for p in range(16992, 16996):
            ports[p] = ("HIGH", "Intel AMT remote management exposed to the Internet")
        ports[5985] = ("HIGH", "WinRM (HTTP) / remote PowerShell exposed")
        ports[5986] = ("HIGH", "WinRM (HTTPS) / remote PowerShell exposed")
        ports[990] = ("HIGH", "FTPS (implicit) exposed to the Internet")

        # -----------------------------------
        # 🔴 HIGH-RISK: Databases / datastores
        # -----------------------------------
        ports[3306] = ("HIGH", "MySQL/MariaDB database exposed to the Internet")
        ports[5432] = ("HIGH", "PostgreSQL database exposed to the Internet")
        ports[1433] = ("HIGH", "Microsoft SQL Server exposed to the Internet")
        ports[1434] = ("HIGH", "Microsoft SQL Browser exposed to the Internet")
        ports[1521] = ("HIGH", "Oracle database exposed to the Internet")
        ports[27017] = ("HIGH", "MongoDB exposed to the Internet")
        ports[6379] = ("HIGH", "Redis exposed to the Internet")
        ports[9200] = ("HIGH", "Elasticsearch HTTP API exposed to the Internet")
        ports[9300] = ("HIGH", "Elasticsearch cluster transport exposed to the Internet")
        ports[9042] = ("HIGH", "Cassandra database exposed to the Internet")
        ports[5984] = ("HIGH", "CouchDB exposed to the Internet")
        ports[7474] = ("HIGH", "Neo4j database exposed to the Internet")
        ports[50000] = ("HIGH", "SAP database/service exposed to the Internet")
        ports[11211] = ("HIGH", "Memcached exposed to the Internet")

        # ----------------------------------------
        # 🔴 HIGH-RISK: DevOps / CI / containers
        # ----------------------------------------
        ports[2375] = ("HIGH", "Docker API over HTTP (no TLS) exposed")
        ports[2376] = ("HIGH", "Docker API over TLS exposed")
        ports[6443] = ("HIGH", "Kubernetes API server exposed")
        ports[10250] = ("HIGH", "Kubelet API exposed")
        ports[8080] = ("HIGH", "Common Jenkins / HTTP proxy / admin interface on 8080 exposed")
        ports[9090] = ("HIGH", "Prometheus metrics interface exposed")
        ports[5601] = ("HIGH", "Kibana dashboard exposed")
        ports[3000] = ("HIGH", "Grafana dashboard exposed")
        ports[4243] = ("HIGH", "Legacy Docker API exposed")
        ports[8500] = ("HIGH", "Consul HTTP API exposed")
        ports[8200] = ("HIGH", "HashiCorp Vault API exposed")
        ports[7001] = ("HIGH", "WebLogic administration / application server exposed")
        ports[7002] = ("HIGH", "WebLogic administration / application server exposed")

        # -------------------------------------------
        # 🔴 HIGH-RISK: Network infra / monitoring
        # -------------------------------------------
        ports[161] = ("HIGH", "SNMP exposed (network/device management)")
        ports[162] = ("HIGH", "SNMP trap receiver exposed")
        ports[514] = ("HIGH", "Syslog exposed to the Internet")
        ports[199] = ("HIGH", "SNMP multiplexing service exposed")
        ports[179] = ("HIGH", "BGP exposed to the Internet")
        for p in range(2601, 2605):
            ports[p] = ("HIGH", "Router/Quagga/Zebra management service exposed")
        ports[389] = ("HIGH", "LDAP directory service exposed to the Internet")
        ports[636] = ("HIGH", "LDAPS directory service exposed to the Internet")
        ports[88] = ("HIGH", "Kerberos authentication service exposed")
        ports[464] = ("HIGH", "Kerberos password change service exposed")

        # -----------------------------------------
        # 🔴 HIGH-RISK: File sharing / internal LAN
        # -----------------------------------------
        ports[445] = ("HIGH", "SMB file sharing exposed to the Internet")
        ports[139] = ("HIGH", "NetBIOS session service exposed to the Internet")
        ports[137] = ("HIGH", "NetBIOS name service exposed to the Internet")
        ports[2049] = ("HIGH", "NFS file sharing exposed to the Internet")
        ports[111] = ("HIGH", "RPCBind (portmapper) exposed to the Internet")
        ports[548] = ("HIGH", "AFP/Apple file sharing exposed to the Internet")
        ports[873] = ("HIGH", "rsync file sync service exposed to the Internet")

        # ---------------------------------------------
        # 🔴 HIGH-RISK: Application servers / middleware
        # ---------------------------------------------
        # WebLogic already covered above (7001/7002)
        for p in range(8000, 8010):
            ports[p] = ("HIGH", "Application server / dev HTTP service exposed (8000–8009)")
        for p in range(8081, 8090):
            ports[p] = ("HIGH", "Admin console / alternate HTTP service exposed (8081–8089)")
        ports[9000] = ("HIGH", "SonarQube / application server exposed")
        ports[8888] = ("HIGH", "Jupyter / development notebook interface exposed")
        ports[4848] = ("HIGH", "GlassFish admin console exposed")
        ports[9001] = ("HIGH", "Supervisor / process control interface exposed")
        ports[9443] = ("HIGH", "Admin HTTPS console exposed on 9443")

        # --------------------------------------------
        # 🔴 HIGH-RISK: Legacy / exploitable services
        # --------------------------------------------
        # SMTP/POP3/IMAP are *not* flagged purely by port here; see EXPLICITLY SAFE
        # notes in the methodology. We still surface them via service-name
        # detection if banners reveal something sensitive.
        ports[110] = ("HIGH", "POP3 mailbox service exposed to the Internet")
        ports[143] = ("HIGH", "IMAP mailbox service exposed to the Internet")
        for p in range(512, 515):
            ports[p] = ("HIGH", "rsh/rexec legacy remote shell service exposed")
        ports[1099] = ("HIGH", "Java RMI / remote object service exposed")
        ports[135] = ("HIGH", "Microsoft RPC endpoint mapper exposed")
        ports[1900] = ("HIGH", "UPnP SSDP service exposed to the Internet")
        ports[6667] = ("HIGH", "IRC server exposed to the Internet")
        ports[4444] = ("HIGH", "High-risk backdoor / C2 port (historically abused)")
        ports[31337] = ("HIGH", "High-risk backdoor / C2 port (Back Orifice heritage)")

        # ------------------------------------------
        # 🟠 MEDIUM-HIGH RISK: Flag with context
        # ------------------------------------------
        # These are often legitimate but still worth explicit review when
        # discovered on the public Internet.
        ports[8443] = ("MEDIUM", "Alternate HTTPS (often admin panels) exposed")
        ports[8008] = ("MEDIUM", "HTTP alternate port exposed (8008)")
        ports[8880] = ("MEDIUM", "HTTP alternate / admin portal on 8880 exposed")
        ports[5000] = ("MEDIUM", "Common API / Flask development server on 5000 exposed")
        ports[5001] = ("MEDIUM", "Common API / HTTPS dev endpoint on 5001 exposed")
        ports[7077] = ("MEDIUM", "Apache Spark master exposed")
        ports[9092] = ("MEDIUM", "Kafka broker exposed")
        for p in range(27018, 27020):
            ports[p] = ("MEDIUM", "MongoDB alternate port exposed")

        # NOTE: The "explicitly safe" ports (80, 443, 25, 53, 587, 465, 123) are
        # deliberately *not* flagged purely by port number here; they are only
        # raised if service banners reveal risky software (e.g. Jenkins, Grafana)
        # or admin indicators.

        return ports

    def _externals_get_dangerous_service_keywords(self):
        """Keywords in Nmap service names that indicate dangerous services.

        Returns mapping of lowercase keyword -> (severity, reason).
        """
        return {
            # Always dangerous service families
            "ssh": ("HIGH", "SSH service exposed to the Internet"),
            "telnet": ("HIGH", "Telnet service exposed to the Internet"),
            "rdp": ("HIGH", "RDP service exposed to the Internet"),
            "ms-wbt-server": ("HIGH", "RDP service exposed to the Internet"),
            "vnc": ("HIGH", "VNC remote desktop exposed to the Internet"),
            "mysql": ("HIGH", "MySQL database service exposed to the Internet"),
            "postgres": ("HIGH", "PostgreSQL database service exposed to the Internet"),
            "postgresql": ("HIGH", "PostgreSQL database service exposed to the Internet"),
            "mongodb": ("HIGH", "MongoDB database exposed to the Internet"),
            "redis": ("HIGH", "Redis data store exposed to the Internet"),
            "elasticsearch": ("HIGH", "Elasticsearch cluster/API exposed to the Internet"),
            "kibana": ("HIGH", "Kibana dashboard exposed to the Internet"),
            "jenkins": ("HIGH", "Jenkins CI server exposed to the Internet"),
            "grafana": ("HIGH", "Grafana dashboard exposed to the Internet"),
            "docker": ("HIGH", "Docker API/daemon exposed to the Internet"),
            "kubernetes": ("HIGH", "Kubernetes control-plane service exposed"),
            "consul": ("HIGH", "Consul service registry/API exposed"),
            "vault": ("HIGH", "HashiCorp Vault secrets service exposed"),
            "weblogic": ("HIGH", "WebLogic application server/admin exposed"),
            "glassfish": ("HIGH", "GlassFish admin/application server exposed"),
            "jupyter": ("HIGH", "Jupyter notebook interface exposed"),
            "ldap": ("HIGH", "LDAP directory service exposed"),
            "snmp": ("HIGH", "SNMP device management exposed"),
            "smb": ("HIGH", "SMB file sharing exposed"),
            "netbios": ("HIGH", "NetBIOS service exposed"),
            "nfs": ("HIGH", "NFS file sharing exposed"),
            "rpc": ("HIGH", "RPC service exposed to the Internet"),
        }

    def _externals_get_port_label(self, port: int) -> str | None:
        """Return a short service name label for a given port, when known.

        Used for live Nmap "Discovered open port" lines so testers see which
        high-risk service was discovered (e.g. SSH, RDP, VNC) without waiting
        for the full parsed summary.
        """
        # Common remote admin / infra services
        if port == 22:
            return "SSH"
        if port in (23, 992):
            return "Telnet"
        if port == 21 or port == 20:
            return "FTP"
        if port == 3389:
            return "RDP"
        if 5900 <= port <= 5999:
            return "VNC"
        if port in (5985, 5986):
            return "WinRM"
        if 16992 <= port <= 16995:
            return "Intel AMT"

        # Databases / datastores
        if port == 3306:
            return "MySQL"
        if port == 5432:
            return "PostgreSQL"
        if port in (1433, 1434):
            return "MSSQL"
        if port == 1521:
            return "Oracle DB"
        if port in (27017, 27018, 27019):
            return "MongoDB"
        if port == 6379:
            return "Redis"
        if port == 11211:
            return "Memcached"
        if port == 5984:
            return "CouchDB"
        if port == 7474:
            return "Neo4j"
        if port == 50000:
            return "SAP DB"

        # DevOps / admin HTTP(S)
        if port == 8080:
            return "HTTP-Admin"
        if port in (8000, 8001, 8002, 8003, 8004, 8005, 8006, 8007, 8008, 8009):
            return "App-Server"
        if 8081 <= port <= 8089:
            return "Admin-Console"
        if port == 8443:
            return "HTTPS-Admin"
        if port == 3000:
            return "Grafana"
        if port == 5601:
            return "Kibana"
        if port in (2375, 2376, 4243):
            return "Docker API"
        if port == 6443:
            return "Kubernetes API"
        if port == 10250:
            return "Kubelet"
        if port == 8500:
            return "Consul"
        if port == 8200:
            return "Vault"
        if port in (7001, 7002):
            return "WebLogic"
        if port == 9000:
            return "SonarQube"
        if port == 8888:
            return "Jupyter"
        if port == 4848:
            return "GlassFish"
        if port == 9001:
            return "Supervisor"
        if port == 9443:
            return "HTTPS-Admin"

        # Network infra / directory services
        if port in (389, 636):
            return "LDAP"
        if port in (161, 162, 199):
            return "SNMP"
        if port == 179:
            return "BGP"
        if 2601 <= port <= 2604:
            return "Router-Mgmt"
        if port == 445:
            return "SMB"
        if port in (137, 139):
            return "NetBIOS"
        if port == 2049:
            return "NFS"
        if port == 111:
            return "RPCBind"
        if port == 548:
            return "AFP"
        if port == 873:
            return "rsync"

        # Legacy / risky services
        if port in (110, 143):
            return "Mail"
        if 512 <= port <= 514:
            return "rsh/rexec"
        if port == 1099:
            return "Java RMI"
        if port == 135:
            return "MS RPC"
        if port == 1900:
            return "UPnP"
        if port == 6667:
            return "IRC"
        if port == 4444:
            return "Backdoor"
        if port == 31337:
            return "Backdoor"

        return None

    def _externals_get_admin_indicators(self):
        """Generic admin/dashboard keywords to look for in service names."""
        return [
            "admin",
            "management",
            "console",
            "dashboard",
            "internal",
            "debug",
            "dev",
            "staging",
            "test",
        ]

    def _externals_print_dangerous_ports_summary(self, entries):
        """Print a concise summary of dangerous open ports to the console."""
        if not entries:
            self.console.append_ansi("\n[i] No obviously dangerous open ports detected on external hosts.\n")
            return

        self.console.append_ansi("\n=== Externals: Dangerous Open Ports Detected ===\n")
        for host, port, proto, service, reason, severity in entries:
            sev = (severity or "HIGH").upper()
            if sev == "HIGH":
                marker = "[DANGEROUS]"
            elif sev == "MEDIUM":
                marker = "[WARNING]"
            else:
                marker = "[INFO]"
            line = f"{marker} {host} - {port}/{proto} ({service}) - {reason}\n"
            self.console.append_ansi(line)

        self.console.append_ansi(
            "\n[i] The ports above are highlighted because remote attackers can "
            "directly target Internet-exposed administrative or high-impact "
            "services (e.g. SSH/RDP/SMB, databases, orchestration APIs). "
            "Review exposure and restrict access to trusted networks wherever possible.\n"
        )

    def _externals_run_security_headers(self, http_hosts):
        """Run basic security header checks against discovered HTTP(S) services.

        Produces missing_security_headers.txt summarising missing headers.
        """
        import ssl
        from urllib import request as _request
 
        if not http_hosts:
            self.console.append_ansi("\n[i] No HTTP(S) services discovered for security header checks.\n")
            return
 
        self.console.append_ansi("\n=== Externals: HTTP Security Header Review ===\n")
 
        # Mapping: tuple(sorted_missing_headers) -> set(hosts)
        from collections import defaultdict
        combo_to_hosts = defaultdict(set)
        hosts_checked = 0  # count of hosts where we successfully retrieved headers
 
        for host, port in http_hosts:
            scheme = "https" if port in (443, 8443, 9443, 10443) else "http"
            if (scheme == "http" and port == 80) or (scheme == "https" and port == 443):
                url = f"{scheme}://{host}"
            else:
                url = f"{scheme}://{host}:{port}"
            missing = []
 
            try:
                # For external perimeter review we care about headers even when
                # certificates are self-signed, mismatched, or otherwise
                # untrusted. Use an unverified SSL context for HTTPS so we can
                # still retrieve response headers.
                if scheme == "https":
                    ctx = ssl._create_unverified_context()
                else:
                    ctx = None
                req = _request.Request(url, method="GET")
                with _request.urlopen(req, timeout=8, context=ctx) as resp:
                    hdrs = {k.lower(): v for k, v in resp.getheaders()}
                hosts_checked += 1
            except Exception as e:
                self.console.append_ansi(f"[i] Could not fetch headers from {url}: {e}\n")
                continue

            csp = hdrs.get("content-security-policy")
            if not csp:
                missing.append("Content-Security-Policy (CSP)")
            else:
                # Weak CSP directives are a finding even when the header is set.
                csp_l = csp.lower()
                weak = [w for w in ("unsafe-inline", "unsafe-eval") if w in csp_l]
                if "*" in csp_l:
                    weak.append("wildcard (*)")
                if weak and hasattr(self, "_externals_add_finding"):
                    self._externals_add_finding(
                        "LOW", "Weak Content-Security-Policy", target=url,
                        detail="CSP contains: " + ", ".join(weak), evidence=csp[:160],
                    )

            xfo = hdrs.get("x-frame-options")
            if not xfo:
                missing.append("X-Frame-Options")

            hsts = hdrs.get("strict-transport-security") if scheme == "https" else None
            if scheme == "https" and not hsts:
                missing.append("HTTP Strict-Transport-Security (HSTS)")

            xcto = hdrs.get("x-content-type-options")
            if not xcto or xcto.strip().lower() != "nosniff":
                missing.append("X-Content-Type-Options (nosniff)")

            if not hdrs.get("referrer-policy"):
                missing.append("Referrer-Policy")
            if not hdrs.get("permissions-policy"):
                missing.append("Permissions-Policy")

            # Deprecated header that should NOT be present.
            xxss = hdrs.get("x-xss-protection")
            if xxss is not None and hasattr(self, "_externals_add_finding"):
                self._externals_add_finding(
                    "LOW", "Deprecated X-XSS-Protection header present", target=url,
                    detail="X-XSS-Protection is deprecated and can introduce vulnerabilities; remove it.",
                    evidence=f"X-XSS-Protection: {xxss}",
                )

            # Server-version disclosure via the Server header.
            server_hdr = hdrs.get("server")
            if server_hdr and any(ch.isdigit() for ch in server_hdr) and hasattr(self, "_externals_add_finding"):
                self._externals_add_finding(
                    "INFO", "Server software / version disclosed in HTTP banner",
                    target=url, detail=f"Server: {server_hdr}", evidence=server_hdr,
                )

            if not missing:
                continue

            # Record each missing header as a LOW finding for the central report.
            if hasattr(self, "_externals_add_finding"):
                self._externals_add_finding(
                    "LOW", "Missing HTTP security headers", target=url,
                    detail="Missing: " + ", ".join(missing), evidence="",
                )

            key = tuple(sorted(set(missing)))
            combo_to_hosts[key].add(host)

        if not combo_to_hosts:
            if hosts_checked == 0:
                self.console.append_ansi(
                    "[i] Could not successfully retrieve headers from any HTTP(S) services; "
                    "skipping missing-header summary.\n"
                )
            else:
                self.console.append_ansi(
                    "[i] No missing security headers detected on successfully checked HTTP(S) services.\n"
                )
            return

        # Write report file
        from pathlib import Path
        report_path = Path(self.output_dir) / "missing_security_headers.txt"
        try:
            with open(report_path, "w", encoding="utf-8", errors="replace") as f:
                for combo, hosts in combo_to_hosts.items():
                    header_line = ", ".join(combo)
                    f.write(f"Missing headers: {header_line}\n")
                    for h in sorted(hosts):
                        f.write(f"{h}\n")
                    f.write("\n")
        except Exception as e:
            self.console.append_ansi(f"[i] Could not write missing_security_headers.txt: {e}\n")
        else:
            self.console.append_ansi(f"[i] Wrote missing security header summary to: {report_path}\n")

    def _externals_run_tls_checks(self, tls_hosts):
        """Legacy synchronous TLS check helper (no longer used).

        The Externals workflow now runs TestSSL asynchronously via CommandRunner
        to avoid freezing the UI. This function is kept only for reference and
        is not invoked.
        """
        self.console.append_ansi("[i] Internal note: _externals_run_tls_checks is deprecated and unused.\\n")

    def _externals_write_web_facing_hosts(self, http_hosts) -> list[str]:
        """Write web-facing assets to web_facing_hosts.txt and return URLs."""
        from pathlib import Path as _Path

        web_assets: list[str] = []
        seen: set[str] = set()
        for host, port in http_hosts or []:
            try:
                port_int = int(port)
            except Exception:
                port_int = 443
            scheme = "https" if port_int in (443, 8443, 9443, 10443) else "http"
            if (scheme == "http" and port_int == 80) or (scheme == "https" and port_int == 443):
                url = f"{scheme}://{host}"
            else:
                url = f"{scheme}://{host}:{port_int}"
            if url not in seen:
                web_assets.append(url)
                seen.add(url)

        if not web_assets:
            self.console.append_ansi("\n[i] No web-facing assets discovered for directory enumeration.\n")
            return []

        out_path = _Path(self.output_dir) / "web_facing_hosts.txt"
        try:
            out_path.write_text("\n".join(web_assets) + "\n", encoding="utf-8", errors="replace")
            self.console.append_ansi(f"\n[i] Wrote {len(web_assets)} web-facing assets to web_facing_hosts.txt\n")
        except Exception as e:
            self.console.append_ansi(f"[i] Could not write web_facing_hosts.txt: {e}\n")

        return web_assets

    def _externals_prompt_directory_enumeration(self, web_assets: list[str]) -> bool:
        """Ask whether to run directory enumeration using a GUI popup."""
        reply = QMessageBox.question(
            self,
            "Directory Enumeration",
            (
                f"Web-facing assets discovered: {len(web_assets)}\n\n"
                "Launch directory enumeration now?"
            ),
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
            QMessageBox.StandardButton.No,
        )
        run_enum = reply == QMessageBox.StandardButton.Yes
        self.console.append_ansi(
            "\n[i] Directory enumeration popup selection: "
            + ("Yes - launching FFUF.\n" if run_enum else "No - skipping directory enumeration.\n")
        )
        return run_enum

    def _externals_start_directory_enumeration(self) -> None:
        """Run FFUF against every URL in web_facing_hosts.txt without stdin.

        When web technology was fingerprinted during the Nmap phase (e.g. nginx,
        IIS, Tomcat, WordPress), a matching wordlist is preferred before falling
        back to the generic raft/dirb lists.
        """
        # Build an ordered candidate list: tech-specific first, then generic.
        candidates = []
        try:
            candidates = list(self._externals_select_wordlist_snippet())
        except Exception:
            candidates = []
        candidates += [
            "/usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt",
            "/usr/share/wordlists/dirb/common.txt",
        ]
        # Emit a shell loop that selects the first wordlist that exists.
        picker = "wordlist=; for w in " + " ".join(f'"{c}"' for c in candidates) + "; do "
        picker += "if [ -f \"$w\" ]; then wordlist=\"$w\"; break; fi; done; "
        if self._externals_context.get("web_tech"):
            picker += (
                "echo \"[i] Detected web tech: "
                + ", ".join(self._externals_context.get("web_tech"))
                + "\"; "
            )
        picker += "echo \"[i] Using wordlist: $wordlist\"; "
        cmd = (
            "if command -v ffuf >/dev/null 2>&1; then "
            + picker +
            "if [ -z \"$wordlist\" ] || [ ! -f \"$wordlist\" ]; then echo '[!] No standard directory wordlist found.'; exit 1; fi; "
            ": > directory_findings.txt; "
            "while IFS= read -r url; do "
            "[ -z \"$url\" ] && continue; "
            "echo \"===== $url =====\" | tee -a directory_findings.txt; "
            "ffuf -u \"$url/FUZZ\" -w \"$wordlist\" -t 10 -mc all -fc 404 -noninteractive "
            "2>&1 | tee -a directory_findings.txt; "
            "echo \"\" | tee -a directory_findings.txt; "
            "done < web_facing_hosts.txt; "
            "else echo '[!] ffuf is not installed (command not found). Skipping directory enumeration.'; exit 1; fi"
        )
        self._run_externals_command(cmd, "Externals Directory Enumeration")

    def _externals_start_tls_phase(self, tls_hosts) -> None:
        """Start async TLS checks, or finish the workflow when none exist."""
        tls_hosts = list(sorted(set(tls_hosts or [])))
        if not tls_hosts:
            self.console.append_ansi("\n[i] No TLS services discovered for TestSSL checks.\n")
            self.console.append_ansi("\n[i] Proceeding to web reconnaissance & reporting.\n")
            self._externals_begin_web_recon()
            return

        self.console.append_ansi("\n=== Externals: TLS / TestSSL Summary ===\n")
        self._externals_phase = "tls"
        self._externals_context["tls_hosts"] = tls_hosts
        self._externals_context["tls_index"] = 0
        self._externals_context["tls_issues"] = {}
        self._externals_context["current_tls_host"] = None
        self._externals_start_next_tls_host()

    def _externals_start_next_tls_host(self):
        """Start the next TestSSL run in the Externals TLS queue (async)."""
        from pathlib import Path

        tls_hosts = self._externals_context.get("tls_hosts") or []
        idx = self._externals_context.get("tls_index", 0)
        if idx >= len(tls_hosts):
            return

        host = tls_hosts[idx]
        self._externals_context["tls_index"] = idx + 1
        self._externals_context["current_tls_host"] = host

        safe_host = self.sanitize_target_for_filename(host)
        ssl_dir_name = self._externals_context.get("ssl_dir_name", "SSL_Scan")
        txt_name = f"{ssl_dir_name}/externals_{safe_host}_testssl.txt"
        log_name = f"{ssl_dir_name}/externals_{safe_host}_testssl.log"
        json_name = f"{ssl_dir_name}/externals_{safe_host}_testssl.json"

        # Allow the per-host TestSSL command to be customised via the Externals
        # workflow editor, while still substituting per-host output paths.
        default_cmd = (
            "testssl --logfile {LOG_FILE} --jsonfile {JSON_FILE} {HOST} "
            "| tee {TXT_FILE}"
        )
        template = self.command_registry.get("externals_testssl", default_cmd)
        cmd = (
            template
            .replace("{LOG_FILE}", log_name)
            .replace("{JSON_FILE}", json_name)
            .replace("{TXT_FILE}", txt_name)
            .replace("{HOST}", host)
        )
        self._run_externals_command(cmd, f"Externals TestSSL for {host}")

    def _highlight_nmap_discovered_ports(self, text: str) -> str:
        """Highlight 'Discovered open port' lines for dangerous ports in Nmap output.

        - Adds a [DANGEROUS] or [WARNING] marker based on port severity.
        - Strips noisy service-fingerprint (SF:) blocks from console output.
        """
        import re as _re

        port_policies = self._externals_get_dangerous_ports()
        pattern = _re.compile(r"^Discovered open port\s+(\d+)/(tcp|udp)\s+on\s+(.+)$")

        lines = text.split("\n")
        out_lines = []
        for line in lines:
            stripped = line.strip()
            # Drop verbose Nmap service-fingerprint blobs which include large
            # HTML responses and are not helpful in the live console.
            if stripped.startswith("SF:"):
                continue

            m = pattern.match(stripped)
            if m:
                port = int(m.group(1))
                proto = m.group(2)
                host = m.group(3).strip()
                policy = port_policies.get(port)
                if policy:
                    severity, _reason = policy
                    sev = (severity or "HIGH").upper()
                    marker = "[DANGEROUS]" if sev == "HIGH" else "[WARNING]"
                    label = self._externals_get_port_label(port)
                    if label:
                        # Example: [DANGEROUS] SSH Discovered on open port 22/tcp on 1.2.3.4
                        out_lines.append(
                            f"{marker} {label} Discovered on open port {port}/{proto} on {host}"
                        )
                    else:
                        out_lines.append(f"{marker} {line}")
                else:
                    out_lines.append(line)
            else:
                out_lines.append(line)

        return "\n".join(out_lines)

    def show_externals_button_editor(self, which: str):
        """Right-click handler for Externals tab buttons.

        This lets you inspect and modify the underlying shell commands used by
        the Externals workflows without changing Python code.
        """
        from PyQt6.QtWidgets import QMessageBox

        if which == "tidy":
            # TIDY IPs is a pure Python helper and does not invoke external
            # commands, so there is nothing to edit.
            self.show_themed_message(
                "No Shell Command",
                "'TIDY IPs' is implemented inside Command Bridge and does not run an external command.",
                QMessageBox.Icon.Information,
            )
            return

        if which == "check":
            info = (
                "This template controls the Nmap host discovery used by:\n"
                "- 'Check What's Up'\n"
                "- The discovery phase of 'Run Externals Test'.\n\n"
                "Use {DISCOVERY_OUT} as a placeholder for the discovery output file path\n"
                "(e.g. Nmap/externals_nmap_discovery.txt)."
            )
            default_cmd = "nmap -sn -T4 -n -iL ips.txt -oN {DISCOVERY_OUT}"
            self._open_single_command_editor(
                "Edit Externals Discovery Command",
                "externals_discovery",
                default_cmd,
                info,
            )
            return

        if which == "self_signed":
            info = (
                "This template controls the self-signed certificate check.\n"
                "Use {HOST} as a placeholder for the target host/IP taken from your Primary Target."
            )
            default_cmd = "openssl s_client -connect {HOST}:443 -servername {HOST}"
            self._open_single_command_editor(
                "Edit Self-Signed Cert Command",
                "externals_self_signed",
                default_cmd,
                info,
            )
            return

        if which == "run":
            self._open_externals_workflow_editor()
            return

    def _open_single_command_editor(self, title: str, button_id: str, default_cmd: str, info_text: str) -> None:
        """Open a simple editor dialog for a single command template."""
        from PyQt6.QtWidgets import QDialog, QVBoxLayout, QLabel, QPlainTextEdit, QDialogButtonBox

        dialog = QDialog(self)
        dialog.setWindowTitle(title)
        dialog.resize(900, 420)
        self.apply_theme_to_dialog(dialog)

        layout = QVBoxLayout(dialog)

        info = QLabel(info_text)
        info.setObjectName("fieldLabel")
        info.setWordWrap(True)
        layout.addWidget(info)

        current_cmd = self.command_registry.get(button_id, default_cmd)
        editor = QPlainTextEdit()
        editor.setPlainText(current_cmd)
        editor.setMinimumHeight(260)
        layout.addWidget(editor)

        buttons = QDialogButtonBox(
            QDialogButtonBox.StandardButton.Ok | QDialogButtonBox.StandardButton.Cancel
        )
        buttons.accepted.connect(dialog.accept)
        buttons.rejected.connect(dialog.reject)
        layout.addWidget(buttons)

        if dialog.exec() == QDialog.DialogCode.Accepted:
            new_cmd = editor.toPlainText().strip()
            if new_cmd:
                self.command_registry[button_id] = new_cmd
                self.save_custom_commands()
                self.show_themed_message("Success", "Command updated successfully.")

    def _open_externals_workflow_editor(self) -> None:
        """Edit the commands used by 'Run Externals Test'.

        This includes:
        - Discovery (nmap -sn) against ips.txt
        - The main Nmap service scan against up.txt
        - Per-host TestSSL/TLS checks
        """
        from PyQt6.QtWidgets import QDialog, QVBoxLayout, QLabel, QPlainTextEdit, QDialogButtonBox

        dialog = QDialog(self)
        dialog.setWindowTitle("Edit Externals Workflow Commands")
        dialog.resize(900, 680)
        self.apply_theme_to_dialog(dialog)

        layout = QVBoxLayout(dialog)

        info = QLabel(
            "These templates control the commands used by 'Run Externals Test'.\n"
            "Placeholders you can use:\n"
            "  • {DISCOVERY_OUT}  → discovery Nmap output (e.g. Nmap/externals_nmap_discovery.txt)\n"
            "  • {UP_FILE}        → file that Nmap service scan reads hosts from (usually up.txt)\n"
            "  • {NMAP_RESULTS_OUT} → Nmap service-scan output file (e.g. Nmap/externals_nmap_results.txt)\n"
            "  • {HOST}           → current host for per-target TestSSL checks\n"
            "  • {LOG_FILE}       → per-host TestSSL logfile path\n"
            "  • {JSON_FILE}      → per-host TestSSL JSON report path\n"
            "  • {TXT_FILE}       → per-host TestSSL text report path\n\n"
            "You can freely change flags, timing, and ports. If you remove output\n"
            "placeholders entirely, some of the post-processing (summaries,\n"
            "dangerous-port grouping, etc.) may no longer work as expected."
        )
        info.setObjectName("fieldLabel")
        info.setWordWrap(True)
        layout.addWidget(info)

        defaults = {
            "externals_discovery": "nmap -sn -T4 -n -iL ips.txt -oN {DISCOVERY_OUT}",
            "externals_nmap": "nmap -Pn -n -sS -sV -O --reason -v -iL {UP_FILE} -oN {NMAP_RESULTS_OUT}",
            "externals_testssl": "testssl --logfile {LOG_FILE} --jsonfile {JSON_FILE} {HOST} | tee {TXT_FILE}",
        }

        editors: dict[str, QPlainTextEdit] = {}

        def add_section(title: str, key: str):
            header = QLabel(title)
            header.setObjectName("sectionDivider")
            layout.addWidget(header)

            editor = QPlainTextEdit()
            editor.setMinimumHeight(130)
            editor.setPlainText(self.command_registry.get(key, defaults[key]))
            layout.addWidget(editor)
            editors[key] = editor

        add_section("Discovery (nmap -sn)", "externals_discovery")
        add_section("Nmap Service Scan", "externals_nmap")
        add_section("Per-Host TLS / TestSSL", "externals_testssl")

        buttons = QDialogButtonBox(
            QDialogButtonBox.StandardButton.Ok | QDialogButtonBox.StandardButton.Cancel
        )
        buttons.accepted.connect(dialog.accept)
        buttons.rejected.connect(dialog.reject)
        layout.addWidget(buttons)

        if dialog.exec() == QDialog.DialogCode.Accepted:
            updated_any = False
            for key, editor in editors.items():
                new_cmd = editor.toPlainText().strip()
                if new_cmd:
                    self.command_registry[key] = new_cmd
                    updated_any = True
            if updated_any:
                self.save_custom_commands()
                self.show_themed_message("Success", "Externals workflow commands updated.")

    # ── Bulk SSL/TLS Vulnerability Scan ──────────────────────────────────────

    def run_bulk_ssl_scan(self):
        """Run ssl_cipher_check.py against every host in the URL list."""
        from urllib.parse import urlparse

        if not hasattr(self, "externals_url_input"):
            return

        raw = self.externals_url_input.toPlainText().strip()
        if not raw:
            self.show_themed_message(
                "No Hosts",
                "Paste URLs or hostnames (one per line) in the URL list above the button.",
                QMessageBox.Icon.Warning,
            )
            return

        normalised_urls = self._normalise_externals_url_lines(raw)
        raw = "\n".join(normalised_urls)
        try:
            self.externals_url_input.setPlainText(raw)
        except Exception:
            pass

        hosts: list[str] = []
        seen: set[str] = set()
        for ln in raw.splitlines():
            ln = ln.strip()
            if not ln:
                continue
            if "://" in ln:
                parsed = urlparse(ln)
                host = parsed.hostname or ""
                port = parsed.port
                # Build host:port — default 443 for https, 80 for http (skip plain http)
                if parsed.scheme.lower() == "http" and not port:
                    continue
                entry = f"{host}:{port}" if port else f"{host}:443"
            else:
                # Raw IP/hostname, optionally with :port
                entry = ln if ":" in ln and not ln.startswith("[") else f"{ln}:443"
                host = ln.split(":")[0]

            if entry not in seen and host:
                hosts.append(entry)
                seen.add(entry)

        if not hosts:
            self.show_themed_message(
                "No Valid Hosts",
                "No valid hostnames or IPs were found in the URL list.",
                QMessageBox.Icon.Warning,
            )
            return

        try:
            self.goto_console()
        except Exception:
            pass

        self.console.append_ansi(f"\n{'='*60}\n")
        self.console.append_ansi(f"  Bulk SSL/TLS Vulnerability Scan — {len(hosts)} host(s)\n")
        self.console.append_ansi(f"{'='*60}\n\n")
        for h in hosts:
            self.console.append_ansi(f"  {h}\n")

        self.externals_ssl_scan_btn.setEnabled(False)
        self.externals_ssl_scan_btn.setText("Scanning…")

        script_path = str(BASE_DIR / "command_bridge" / "modules" / "ssl_cipher_check.py")

        self._ssl_worker = _SslScanWorker(hosts, script_path)
        self._ssl_thread = QThread()
        self._ssl_worker.moveToThread(self._ssl_thread)
        self._ssl_thread.started.connect(self._ssl_worker.run)
        self._ssl_worker.progress.connect(self._on_ssl_scan_progress)
        self._ssl_worker.finished.connect(self._on_ssl_scan_done)
        self._ssl_worker.finished.connect(self._ssl_thread.quit)
        self._ssl_thread.start()

    def _on_ssl_scan_progress(self, msg: str):
        self.console.append_ansi(msg)

    def _on_ssl_scan_done(self, summary: dict):
        self.externals_ssl_scan_btn.setEnabled(True)
        self.externals_ssl_scan_btn.setText("🔒  Bulk SSL/TLS Vulnerability Scan")

        import html as _html

        self.console.append_ansi(f"\n{'='*60}\n")
        self.console.append_ansi("  SSL/TLS SCAN SUMMARY\n")
        self.console.append_ansi(f"{'='*60}\n\n")

        # ── Per-host status line ──────────────────────────────────────────────
        for host, entry in summary.items():
            crit  = len(entry["proto_findings"]["CRITICAL"])
            high  = len(entry["proto_findings"]["HIGH"])
            med   = len(entry["proto_findings"]["MEDIUM"])
            low   = len(entry["proto_findings"].get("LOW", []))
            cvulns = len(entry["cipher_vulns"])
            total = crit + high + med + low + cvulns

            if entry["errored"]:
                colour, badge = "#ef4444", "ERROR"
                detail = "scan failed"
            elif total == 0:
                colour, badge = "#22c55e", "OK"
                detail = "no vulnerabilities detected"
            else:
                colour = "#ef4444" if crit else "#f97316"
                badge  = "VULNERABLE"
                parts  = []
                if crit:   parts.append(f"{crit} CRITICAL")
                if high:   parts.append(f"{high} HIGH")
                if med:    parts.append(f"{med} MEDIUM")
                if low:    parts.append(f"{low} LOW")
                if cvulns: parts.append(f"{cvulns} cipher issue(s)")
                detail = ", ".join(parts)

            self.console.append_html(
                f'<span style="color:{colour};font-weight:bold;">[{_html.escape(badge)}]</span>'
                f'&nbsp;<span style="color:#e2e8f0;">{_html.escape(host)}</span>'
                f'&nbsp;<span style="color:#8b949e;">— {_html.escape(detail)}</span><br>'
            )

        self.console.append_ansi("\n")

        # ── Aggregate cipher vulns across all hosts ───────────────────────────
        # cipher_agg: {vuln_name: {"hosts": [...], "ciphers": {cipher_str: True}}}
        cipher_agg: dict = {}
        for host, entry in summary.items():
            for vuln_name, ciphers in entry["cipher_vulns"].items():
                if vuln_name not in cipher_agg:
                    cipher_agg[vuln_name] = {"hosts": [], "ciphers": {}}
                cipher_agg[vuln_name]["hosts"].append(host)
                for c in ciphers:
                    cipher_agg[vuln_name]["ciphers"][c] = True

        # ── Aggregate protocol findings across all hosts ──────────────────────
        proto_agg: dict = {"CRITICAL": {}, "HIGH": {}, "MEDIUM": {}, "LOW": {}}
        for host, entry in summary.items():
            for sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW"):
                for finding in entry["proto_findings"].get(sev, []):
                    proto_agg[sev].setdefault(finding, []).append(host)

        any_finding = bool(cipher_agg) or any(proto_agg[s] for s in proto_agg)

        # ── Print cipher vuln blocks — sorted by most-affected hosts first ────
        for vuln_name, data in sorted(cipher_agg.items(), key=lambda x: -len(x[1]["hosts"])):
            affected = data["hosts"]
            ciphers  = list(data["ciphers"].keys())
            n = len(affected)

            self.console.append_html(
                f'<span style="color:#f97316;font-weight:bold;">'
                f'{"─"*60}</span><br>'
                f'<span style="color:#f97316;font-weight:bold;">'
                f'{_html.escape(vuln_name)} — Affected Hosts ({n})'
                f'</span><br>'
                f'<span style="color:#f97316;font-weight:bold;">'
                f'{"─"*60}</span><br>'
            )
            for h in affected:
                self.console.append_html(
                    f'&nbsp;&nbsp;<span style="color:#e2e8f0;">{_html.escape(h)}</span><br>'
                )

            if ciphers:
                self.console.append_html(
                    '<br>&nbsp;&nbsp;<span style="color:#94a3b8;font-weight:bold;">'
                    'Vulnerable Ciphers:</span><br>'
                )
                for cipher_str in ciphers:
                    # Split name and optional key size for aligned display
                    parts = cipher_str.rsplit("  ", 1)
                    name  = parts[0]
                    bits  = parts[1] if len(parts) == 2 else ""
                    bits_html = (
                        f'&nbsp;<span style="color:#f59e0b;">{_html.escape(bits)}-bit</span>'
                        if bits else ""
                    )
                    self.console.append_html(
                        f'&nbsp;&nbsp;&nbsp;&nbsp;'
                        f'<span style="color:#cbd5e1;">{_html.escape(name)}</span>'
                        f'{bits_html}<br>'
                    )

            self.console.append_ansi("\n")

        # ── Print protocol findings (Heartbleed, HSTS, etc.) ─────────────────
        for sev, colour in (("CRITICAL", "#ef4444"), ("HIGH", "#f97316"), ("MEDIUM", "#f59e0b"), ("LOW", "#38bdf8")):
            if not proto_agg[sev]:
                continue
            for finding, affected in sorted(proto_agg[sev].items(), key=lambda x: -len(x[1])):
                n = len(affected)
                self.console.append_html(
                    f'<span style="color:{colour};font-weight:bold;">'
                    f'{"─"*60}</span><br>'
                    f'<span style="color:{colour};font-weight:bold;">'
                    f'[{_html.escape(sev)}] {_html.escape(finding)} — Affected Hosts ({n})'
                    f'</span><br>'
                    f'<span style="color:{colour};font-weight:bold;">'
                    f'{"─"*60}</span><br>'
                )
                for h in affected:
                    self.console.append_html(
                        f'&nbsp;&nbsp;<span style="color:#e2e8f0;">{_html.escape(h)}</span><br>'
                    )
                self.console.append_ansi("\n")

        if not any_finding:
            self.console.append_html(
                '<span style="color:#22c55e;font-weight:bold;">'
                "✓ No SSL/TLS vulnerabilities detected across all scanned hosts."
                "</span><br>"
            )

        self.console.append_ansi("=" * 60 + "\n")

    # ── Bulk HTTP Response Analysis ───────────────────────────────────────────

    def run_bulk_http_analysis(self):
        """GET each URL from the URL list, inspect security headers, print grouped summary."""
        if not hasattr(self, "externals_url_input"):
            return

        raw = self.externals_url_input.toPlainText().strip()
        if not raw:
            self.show_themed_message(
                "No URLs",
                "Paste one or more URLs (one per line) in the URL list above the button.",
                QMessageBox.Icon.Warning,
            )
            return

        valid_urls = self._normalise_externals_url_lines(raw)
        try:
            self.externals_url_input.setPlainText("\n".join(valid_urls))
        except Exception:
            pass

        if not valid_urls:
            self.show_themed_message("No valid URLs", "Could not parse any URLs from the input.", QMessageBox.Icon.Warning)
            return

        # Switch to Console tab
        try:
            self.goto_console()
        except Exception:
            pass

        self.console.append_ansi(f"\n{'='*60}\n")
        self.console.append_ansi(f"  Bulk HTTP Response Analysis — {len(valid_urls)} URL(s)\n")
        self.console.append_ansi(f"{'='*60}\n\n")
        self.externals_http_analysis_btn.setEnabled(False)
        self.externals_http_analysis_btn.setText("Analysing…")

        # Run in a thread so the UI stays responsive
        self._http_worker = _HttpAnalysisWorker(valid_urls)
        self._http_thread = QThread()
        self._http_worker.moveToThread(self._http_thread)
        self._http_thread.started.connect(self._http_worker.run)
        self._http_worker.progress.connect(self._on_http_progress)
        self._http_worker.finished.connect(self._on_http_analysis_done)
        self._http_worker.finished.connect(self._http_thread.quit)
        self._http_thread.start()

    def _on_http_progress(self, msg):
        self.console.append_ansi(msg)

    def _on_http_analysis_done(self, findings: dict):
        self.externals_http_analysis_btn.setEnabled(True)
        self.externals_http_analysis_btn.setText("🔍  Bulk HTTP Response Analysis")

        import html as _html

        def _strip_scheme(url: str) -> str:
            for prefix in ("https://", "http://"):
                if url.lower().startswith(prefix):
                    return url[len(prefix):]
            return url

        # ── Generic "Missing HTTP Security Headers" ────────────────────────
        # These four headers are grouped together per unique combination of
        # missing headers — matching how a single "Missing HTTP Security
        # Headers" finding is written in the report.
        GENERIC_KEYS = ["missing_csp", "missing_xfo", "missing_xcto", "missing_xpcd"]
        GENERIC_NAMES = {
            "missing_csp":  "Content-Security-Policy",
            "missing_xfo":  "X-Frame-Options",
            "missing_xcto": "X-Content-Type-Options",
            "missing_xpcd": "X-Permitted-Cross-Domain-Policies",
        }
        GENERIC_ORDER = {k: i for i, k in enumerate(GENERIC_KEYS)}

        # Map each URL to the subset of generic headers it is missing
        url_generic = {}
        for key in GENERIC_KEYS:
            for url in findings.get(key, []):
                url_generic.setdefault(url, set()).add(key)

        # Group URLs by their exact combination of missing headers
        generic_groups: dict = {}
        for url, missing_set in url_generic.items():
            generic_groups.setdefault(frozenset(missing_set), []).append(url)

        # ── Separate issues (not part of the generic group) ───────────────
        SEPARATE_LABELS = [
            ("missing_hsts",        "⚠ Missing HSTS",                                                "#ef4444"),
            ("weak_hsts",           "⚠ Misconfigured HSTS (max-age < 1 year)",                       "#f97316"),
            ("hsts_no_subdomains",  "⚠ HSTS missing includeSubDomains",                              "#f97316"),
            ("csp_unsafe_inline",   "⚠ Misconfigured CSP — unsafe-inline present",                   "#f97316"),
            ("csp_unsafe_eval",     "⚠ Misconfigured CSP — unsafe-eval present",                     "#f97316"),
            ("csp_wildcard",        "⚠ Misconfigured CSP — wildcard (*) source present",             "#f97316"),
            ("xpcd_permissive",     "⚠ Permissive X-Permitted-Cross-Domain-Policies",                "#f97316"),
            ("xxss_enabled",        "⚠ X-XSS-Protection set to 1 (deprecated, can introduce risk)", "#f97316"),
            ("server_disclosure",   "⚠ Server Architecture Disclosed",                               "#ef4444"),
            ("xpowered_disclosure", "⚠ Technology Stack Disclosed via X-Powered-By",                 "#ef4444"),
            ("error",               "✕ Request failed",                                               "#ef4444"),
        ]

        any_issues = False
        summary_lines = ["\n" + "="*60 + "\n  SECURITY HEADER SUMMARY\n" + "="*60 + "\n"]

        # ── Print generic grouped findings (most headers missing → first) ──
        for missing_keys, affected_urls in sorted(
            generic_groups.items(), key=lambda x: -len(x[0])
        ):
            any_issues = True
            sorted_keys = sorted(missing_keys, key=lambda k: GENERIC_ORDER[k])
            names = [GENERIC_NAMES[k] for k in sorted_keys]
            if len(names) == 1:
                label = f"⚠ Missing {names[0]}"
            elif len(names) == 2:
                label = f"⚠ Missing {names[0]} & {names[1]}"
            else:
                label = f"⚠ Missing {', '.join(names[:-1])} & {names[-1]}"

            self.console.append_html(
                f'<span style="color:#ef4444;font-weight:bold;">{_html.escape(label)}</span><br>'
            )
            for u in sorted(affected_urls):
                self.console.append_html(
                    f'&nbsp;&nbsp;&nbsp;<span style="color:#8b949e;">'
                    f'{_html.escape(_strip_scheme(u))}</span><br>'
                )
            summary_lines.append(f"{label}:")
            for u in sorted(affected_urls):
                summary_lines.append(f"  {_strip_scheme(u)}")
            summary_lines.append("")
            self.console.append_ansi("")

        # ── Print separate findings ────────────────────────────────────────
        for issue_key, label, colour in SEPARATE_LABELS:
            affected_urls = findings.get(issue_key, [])
            if not affected_urls:
                continue
            any_issues = True
            self.console.append_html(
                f'<span style="color:{colour};font-weight:bold;">{_html.escape(label)}</span><br>'
            )
            for u in affected_urls:
                self.console.append_html(
                    f'&nbsp;&nbsp;&nbsp;<span style="color:#8b949e;">'
                    f'{_html.escape(_strip_scheme(u))}</span><br>'
                )
            summary_lines.append(f"{label}:")
            for u in affected_urls:
                summary_lines.append(f"  {_strip_scheme(u)}")
            summary_lines.append("")
            self.console.append_ansi("")

        if not any_issues:
            self.console.append_html(
                '<span style="color:#22c55e;font-weight:bold;">'
                '✓ No security header issues found across all URLs.</span><br>'
            )

        self.console.append_ansi("\n" + "="*60 + "\n")

    # ── Exposed Services Scan (All Hosts) ─────────────────────────────────────

    def run_externals_nmap_all_hosts(self):
        """Nmap -sV scan against every host in the URL list, grouped by port/service."""
        from urllib.parse import urlparse

        if not hasattr(self, "externals_url_input"):
            return

        raw = self.externals_url_input.toPlainText().strip()
        if not raw:
            self.show_themed_message(
                "No Hosts",
                "Paste URLs or hostnames (one per line) in the URL list above the button.",
                QMessageBox.Icon.Warning,
            )
            return

        normalised_urls = self._normalise_externals_url_lines(raw)
        try:
            self.externals_url_input.setPlainText("\n".join(normalised_urls))
        except Exception:
            pass

        hosts: list[str] = []
        seen: set[str] = set()
        for ln in normalised_urls:
            parsed = urlparse(ln)
            host = (parsed.hostname or "").lower()
            if host.startswith("*."):
                host = host[2:]
            if host and host not in seen:
                hosts.append(host)
                seen.add(host)

        if not hosts:
            self.show_themed_message(
                "No Valid Hosts",
                "No valid hostnames or IPs were found in the URL list.",
                QMessageBox.Icon.Warning,
            )
            return

        try:
            self.goto_console()
        except Exception:
            pass

        self.console.append_ansi(f"\n{'='*60}\n")
        self.console.append_ansi(f"  Exposed Services Scan — {len(hosts)} host(s)\n")
        self.console.append_ansi(f"{'='*60}\n\n")
        for h in hosts:
            self.console.append_ansi(f"  {h}\n")
        self.console.append_ansi("\n")

        if hasattr(self, "externals_nmap_all_btn"):
            self.externals_nmap_all_btn.setEnabled(False)
            self.externals_nmap_all_btn.setText("Scanning…")

        self._nmap_all_worker = _NmapAllHostsWorker(hosts)
        self._nmap_all_thread = QThread()
        self._nmap_all_worker.moveToThread(self._nmap_all_thread)
        self._nmap_all_thread.started.connect(self._nmap_all_worker.run)
        self._nmap_all_worker.progress.connect(self._on_nmap_all_progress)
        self._nmap_all_worker.finished.connect(self._on_nmap_all_done)
        self._nmap_all_worker.finished.connect(self._nmap_all_thread.quit)
        self._nmap_all_thread.start()

    def _on_nmap_all_progress(self, msg: str):
        self.console.append_ansi(msg)

    def _on_nmap_all_done(self, results: dict):
        if hasattr(self, "externals_nmap_all_btn"):
            self.externals_nmap_all_btn.setEnabled(True)
            self.externals_nmap_all_btn.setText("🔌  Exposed Services Scan (All Hosts)")

        import html as _html

        self.console.append_ansi("\n" + "="*60 + "\n")
        self.console.append_ansi("  EXPOSED SERVICES SUMMARY\n")
        self.console.append_ansi("="*60 + "\n\n")

        if not results:
            self.console.append_html(
                '<span style="color:#22c55e;font-weight:bold;">'
                "✓ No interesting exposed services detected across all scanned hosts."
                "</span><br>"
            )
            self.console.append_ansi("\n")
            return

        # Sort: dangerous first → most affected hosts → port number
        web_services: dict[str, list[str]] = {}
        for item in results.values():
            if not item.get("web_service"):
                continue
            service_label = f"{item['port']}/{item['proto']} {item['service_name']}"
            for host in item.get("hosts", []):
                web_services.setdefault(host, []).append(service_label)

        if web_services:
            self.console.append_html(
                '<span style="color:#38bdf8;font-weight:bold;">'
                "Public Web Services Detected</span><br>"
            )
            for host, services in sorted(web_services.items()):
                service_text = ", ".join(sorted(set(services)))
                self.console.append_html(
                    f'&nbsp;&nbsp;<span style="color:#e2e8f0;">{_html.escape(host)}</span>'
                    f'&nbsp;<span style="color:#8b949e;">{_html.escape(service_text)}</span><br>'
                )
            self.console.append_ansi("\n")

        sorted_items = sorted(
            results.values(),
            key=lambda x: (not x["dangerous"], -len(x["hosts"]), x["port"]),
        )

        for item in sorted_items:
            hosts = sorted(item["hosts"])
            n_hosts = len(hosts)
            dangerous = item["dangerous"]
            color = "#ef4444" if dangerous else "#f97316"
            badge = "DANGEROUS" if dangerous else "EXPOSED"

            svc_label = f"{item['port']}/{item['proto']}  {item['service_name']}"
            if item.get("version"):
                svc_label += f"  —  {item['version']}"

            self.console.append_html(
                f'<span style="color:{color};font-weight:bold;">'
                f'[{_html.escape(badge)}] {_html.escape(svc_label)}'
                f"</span><br>"
            )
            self.console.append_html(
                f'<span style="color:#8b949e;">'
                f"&nbsp;&nbsp;Example: {_html.escape(item['example'])}"
                f"</span><br>"
            )
            host_str = "  •  ".join(hosts)
            self.console.append_html(
                f'<span style="color:#94a3b8;">'
                f"&nbsp;&nbsp;Affected ({n_hosts}): {_html.escape(host_str)}"
                f"</span><br><br>"
            )

        self.console.append_ansi("=" * 60 + "\n")


# ── Worker class (runs in a separate QThread) ──────────────────────────────

class _WebFacingCheckWorker(QObject):
    """Fast concurrent TCP-connect check for common web ports across many hosts.

    NOT a full port scan — just enough to answer "does this host appear to
    be running a public-facing web service" for lists of hundreds of IPs,
    where a full nmap -sV pass per host would be far too slow.
    """

    progress = pyqtSignal(str)
    finished = pyqtSignal(dict)

    WEB_PORTS = (443, 80, 8443, 8080)
    CONNECT_TIMEOUT = 2.5
    MAX_WORKERS = 64

    def __init__(self, hosts):
        super().__init__()
        self.hosts = hosts

    def _check_host(self, host):
        import socket
        open_ports = []
        for port in self.WEB_PORTS:
            try:
                with socket.create_connection((host, port), timeout=self.CONNECT_TIMEOUT):
                    open_ports.append(port)
            except Exception:
                continue
        return host, open_ports

    def run(self):
        import concurrent.futures

        exposed = []
        closed = []
        errors = []

        total = len(self.hosts)
        max_workers = max(1, min(self.MAX_WORKERS, total or 1))
        checked = 0

        try:
            with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as pool:
                futures = {pool.submit(self._check_host, host): host for host in self.hosts}
                for future in concurrent.futures.as_completed(futures):
                    host = futures[future]
                    checked += 1
                    try:
                        _host, open_ports = future.result()
                    except Exception:
                        errors.append(host)
                        continue
                    if open_ports:
                        exposed.append((host, open_ports))
                        self.progress.emit(
                            f"  [+] {host} — open: {', '.join(str(p) for p in open_ports)}\n"
                        )
                    else:
                        closed.append(host)
                    if checked % 25 == 0 or checked == total:
                        self.progress.emit(f"  … checked {checked}/{total}\n")
        except Exception as e:
            self.progress.emit(f"  [!] Worker error: {e}\n")

        exposed.sort(key=lambda item: item[0])
        self.finished.emit({"exposed": exposed, "closed": closed, "errors": errors})


class _HttpAnalysisWorker(QObject):
    progress = pyqtSignal(str)
    finished = pyqtSignal(dict)

    ISSUES = [
        "missing_hsts", "weak_hsts", "hsts_no_subdomains",
        "missing_csp", "csp_unsafe_inline", "csp_unsafe_eval", "csp_wildcard",
        "missing_xcto", "missing_xfo",
        "missing_xpcd", "xpcd_permissive",
        "xxss_enabled",
        "server_disclosure", "xpowered_disclosure",
        "error",
    ]

    # Web servers whose presence in the Server header is reportable
    WEB_SERVER_TOKENS = {
        "nginx", "apache", "microsoft-iis", "iis", "lighttpd", "litespeed",
        "lightspeed", "caddy", "tomcat", "jetty", "gunicorn", "openresty",
        "cowboy", "kestrel", "cherokee", "zeus", "gws", "werkzeug", "thin",
    }

    def __init__(self, urls):
        super().__init__()
        self.urls = urls

    def run(self):
        try:
            import urllib.request
            import urllib.error
            import ssl
        except ImportError:
            self.finished.emit({"error": self.urls})
            return

        findings = {k: [] for k in self.ISSUES}
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE

        for url in self.urls:
            self.progress.emit(f"  → {url}\n")
            try:
                req = urllib.request.Request(
                    url,
                    headers={"User-Agent": "Mozilla/5.0 (SecurityHeaderCheck/1.0)"},
                    method="GET",
                )
                with urllib.request.urlopen(req, timeout=10, context=ctx) as resp:
                    headers = {k.lower(): v for k, v in resp.headers.items()}
            except Exception as e:
                self.progress.emit(f"    [!] {e}\n")
                findings["error"].append(url)
                continue

            # ── HSTS (only relevant on HTTPS) ──────────────────────────────
            if url.startswith("https://"):
                hsts = headers.get("strict-transport-security", "")
                if not hsts:
                    findings["missing_hsts"].append(url)
                else:
                    m = re.search(r"max-age\s*=\s*(\d+)", hsts, re.I)
                    if m and int(m.group(1)) < 31536000:
                        findings["weak_hsts"].append(url)
                    if "includesubdomains" not in hsts.lower():
                        findings["hsts_no_subdomains"].append(url)

            # ── CSP ────────────────────────────────────────────────────────
            csp = headers.get("content-security-policy", "")
            if not csp:
                findings["missing_csp"].append(url)
            else:
                if "'unsafe-inline'" in csp:
                    findings["csp_unsafe_inline"].append(url)
                if "'unsafe-eval'" in csp:
                    findings["csp_unsafe_eval"].append(url)
                if re.search(r"(?:^|[\s;])\*(?:[\s;]|$)", csp):
                    findings["csp_wildcard"].append(url)

            # ── X-Content-Type-Options ─────────────────────────────────────
            xcto = headers.get("x-content-type-options", "")
            if "nosniff" not in xcto.lower():
                findings["missing_xcto"].append(url)

            # ── X-Frame-Options — only flag if CSP has no frame-ancestors ──
            csp_has_frame_ancestors = bool(csp and "frame-ancestors" in csp.lower())
            if not csp_has_frame_ancestors:
                xfo = headers.get("x-frame-options", "").strip().upper()
                if not xfo or xfo == "ALLOW-ALL":
                    findings["missing_xfo"].append(url)

            # ── X-Permitted-Cross-Domain-Policies ──────────────────────────
            xpcd = headers.get("x-permitted-cross-domain-policies", "").strip().lower()
            if not xpcd:
                findings["missing_xpcd"].append(url)
            elif xpcd == "all":
                findings["xpcd_permissive"].append(url)

            # ── X-XSS-Protection — flag only if explicitly enabled (= 1) ──
            xxss = headers.get("x-xss-protection", "").strip()
            if xxss.startswith("1"):
                findings["xxss_enabled"].append(url)

            # ── Server header — only flag known web servers, not CDNs ──────
            server = headers.get("server", "").strip()
            if server:
                server_lower = server.lower()
                if any(tok in server_lower for tok in self.WEB_SERVER_TOKENS):
                    findings["server_disclosure"].append(url)

            # ── X-Powered-By — always discloses tech stack ─────────────────
            if headers.get("x-powered-by", ""):
                findings["xpowered_disclosure"].append(url)

        self.finished.emit(findings)


class _NmapAllHostsWorker(QObject):
    """Worker: runs nmap -sV per host and groups findings by (port, proto, service)."""

    progress = pyqtSignal(str)
    finished = pyqtSignal(dict)

    DANGEROUS_PORTS = frozenset({
        20, 21, 22, 23, 25, 53, 69, 110, 111, 135, 137, 139, 143,
        389, 445, 512, 513, 514, 873,
        1433, 1434, 1521, 2049, 2375, 2376,
        3306, 3389, 5432, 5900, 5901, 5985, 5986,
        6379, 7001, 7002, 8080, 9042, 9200, 9300,
        10250, 11211, 27017, 50000,
    })

    WEB_SERVICE_PORTS = frozenset({
        80, 443, 8000, 8008, 8080, 8081, 8088, 8443, 8888, 9443,
    })

    CDN_SKIP_TOKENS = frozenset({
        "cloudflare", "amazon", "awselb", "akamai", "azure", "fastly",
        "incapsula", "imperva", "sucuri",
    })

    def __init__(self, hosts: list):
        super().__init__()
        self.hosts = hosts

    def run(self):
        import subprocess
        import re as _re

        results: dict = {}
        port_re = _re.compile(r'^(\d+)/(tcp|udp)\s+open\s+(\S+)(?:\s+(.*))?$')

        for host in self.hosts:
            self.progress.emit(f"[*] Scanning {host}…\n")
            try:
                proc = subprocess.run(
                    ["nmap", "-sV", "-Pn", "-T4", "--open", "--top-ports", "200", host],
                    stdout=subprocess.PIPE,
                    stderr=subprocess.STDOUT,
                    timeout=180,
                )
                output = proc.stdout.decode("utf-8", errors="replace")
            except subprocess.TimeoutExpired:
                self.progress.emit(f"[!] Scan timed out for {host}\n")
                continue
            except FileNotFoundError:
                self.progress.emit("[!] nmap not found — install it with: sudo apt install nmap\n")
                break
            except Exception as e:
                self.progress.emit(f"[!] Error scanning {host}: {e}\n")
                continue

            open_count = 0
            for line in output.splitlines():
                m = port_re.match(line.strip())
                if not m:
                    continue
                port = int(m.group(1))
                proto = m.group(2)
                service_name = m.group(3)
                version = (m.group(4) or "").strip()

                # Skip generic CDN/cloud banners — not useful for pentest report
                combined = (service_name + " " + version).lower()
                if any(tok in combined for tok in self.CDN_SKIP_TOKENS):
                    continue

                is_dangerous = port in self.DANGEROUS_PORTS
                is_web_service = port in self.WEB_SERVICE_PORTS or "http" in service_name.lower()
                # Include: dangerous ports always; other ports only when a version
                # string is present (i.e. software is disclosed). Web ports are
                # retained even without a version so public pages are visible.
                if not is_dangerous and not is_web_service and not version:
                    continue

                # Clean nmap parenthetical noise: "OpenSSH 8.2p1 (protocol 2.0)" → "OpenSSH 8.2p1"
                version_clean = version.split(" (")[0].strip() if version else ""
                example = f"{port}/{proto}  open  {service_name}  {version}".strip()

                key = (port, proto, service_name)
                if key not in results:
                    results[key] = {
                        "port": port,
                        "proto": proto,
                        "service_name": service_name,
                        "version": version_clean,
                        "example": example,
                        "hosts": [],
                        "dangerous": is_dangerous,
                        "web_service": is_web_service,
                    }

                if host not in results[key]["hosts"]:
                    results[key]["hosts"].append(host)
                    open_count += 1

                # Keep the most informative version string as the example
                if len(version) > len(results[key].get("version", "")):
                    results[key]["version"] = version_clean
                    results[key]["example"] = example

            self.progress.emit(f"[+] {host}: {open_count} interesting port(s) found\n")

        self.finished.emit(results)


# ── Bulk SSL/TLS Scan worker ───────────────────────────────────────────────────

class _SslScanWorker(QObject):
    """Worker: runs ssl_cipher_check.py against each host.

    Parses output into two buckets per host:
      cipher_vulns  — {vuln_name: [cipher_string, ...]}   (Lucky13, Sweet32, etc.)
      proto_findings — {severity: [label, ...]}            (Heartbleed, HSTS, etc.)
    """

    progress = pyqtSignal(str)
    finished = pyqtSignal(dict)

    _ANSI_RE     = re.compile(r"\033\[[0-9;]*m")
    _SEV_RE      = re.compile(r"^\s*\[(CRITICAL|HIGH|MEDIUM|LOW)\]\s+(.*)")
    _VULN_HDR_RE = re.compile(r"^Vulnerable\s+[—\-]\s+(.+)")
    _LOGJAM_RE   = re.compile(r"^Potential LOGJAM")
    # Cipher lines: 2+ leading spaces, long ALL_CAPS_WITH_UNDERSCORES token, optional key size
    _CIPHER_RE   = re.compile(r"^  ([A-Z][A-Z0-9_]{9,})\s*(\d+)?\s*$")

    # States for the line-by-line parser
    _IDLE    = 0
    _IN_DESC = 1   # skip the one-line description that follows "Vulnerable — X"
    _IN_VULN = 2   # collecting cipher lines

    def __init__(self, hosts: list, script_path: str):
        super().__init__()
        self.hosts = hosts
        self.script_path = script_path

    def run(self):
        summary: dict = {}

        for host in self.hosts:
            self.progress.emit(f"\n{'─'*60}\n[*] SSL/TLS scan: {host}\n{'─'*60}\n")
            entry = {
                "cipher_vulns":   {},                              # name → [cipher str, ...]
                "proto_findings": {"CRITICAL": [], "HIGH": [], "MEDIUM": [], "LOW": []},
                "errored":        False,
            }

            state       = self._IDLE
            current_vuln = None

            try:
                proc = subprocess.Popen(
                    [sys.executable, self.script_path, host],
                    stdout=subprocess.PIPE,
                    stderr=subprocess.STDOUT,
                )
                for raw in proc.stdout:
                    line  = raw.decode("utf-8", errors="replace")
                    self.progress.emit(line)
                    clean = self._ANSI_RE.sub("", line)

                    if state == self._IDLE:
                        # ── Cipher vuln block header ──────────────────────
                        m = self._VULN_HDR_RE.match(clean.strip())
                        if m:
                            current_vuln = m.group(1).strip()
                            entry["cipher_vulns"].setdefault(current_vuln, [])
                            state = self._IN_DESC
                            continue
                        # ── LOGJAM flag (no cipher list follows in same format)
                        if self._LOGJAM_RE.match(clean.strip()):
                            entry["cipher_vulns"].setdefault("LOGJAM (DHE)", [])
                            state = self._IN_VULN
                            current_vuln = "LOGJAM (DHE)"
                            continue
                        # ── Severity-tagged protocol finding ──────────────
                        m = self._SEV_RE.match(clean)
                        if m:
                            sev, text = m.group(1), m.group(2).strip()
                            if sev in entry["proto_findings"] and text and text not in entry["proto_findings"][sev]:
                                entry["proto_findings"][sev].append(text)

                    elif state == self._IN_DESC:
                        # Skip the italicised description line, move to cipher collection
                        state = self._IN_VULN

                    elif state == self._IN_VULN:
                        stripped = clean.strip()
                        if not stripped:
                            # Blank line ends this vuln block
                            state = self._IDLE
                            current_vuln = None
                            continue
                        # Another vuln block starting immediately
                        m = self._VULN_HDR_RE.match(stripped)
                        if m:
                            current_vuln = m.group(1).strip()
                            entry["cipher_vulns"].setdefault(current_vuln, [])
                            state = self._IN_DESC
                            continue
                        # Cipher entry line
                        m = self._CIPHER_RE.match(clean)
                        if m and current_vuln is not None:
                            cipher_str = m.group(1)
                            if m.group(2):
                                cipher_str += f"  {m.group(2)}"
                            if cipher_str not in entry["cipher_vulns"][current_vuln]:
                                entry["cipher_vulns"][current_vuln].append(cipher_str)

                proc.wait(timeout=300)
            except subprocess.TimeoutExpired:
                proc.kill()
                self.progress.emit(f"[!] Scan timed out for {host}\n")
                entry["errored"] = True
            except FileNotFoundError:
                self.progress.emit(f"[!] Python/script not found: {self.script_path}\n")
                entry["errored"] = True
                summary[host] = entry
                break
            except Exception as e:
                self.progress.emit(f"[!] Error scanning {host}: {e}\n")
                entry["errored"] = True

            summary[host] = entry

        self.finished.emit(summary)
