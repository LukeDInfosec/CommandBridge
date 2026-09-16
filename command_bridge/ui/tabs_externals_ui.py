"""
Externals tab UI creator.
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



class ExternalsTabUIMixin:
    """Mixin providing externals tab ui creator."""

    def create_externals_tab(self):
        """Create Externals tab for bulk IP testing and reporting."""
        widget = QWidget()
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QFrame.Shape.NoFrame)
        scroll.setWidget(widget)
        layout = QVBoxLayout(widget)
        layout.setContentsMargins(25, 25, 25, 25)
        layout.setSpacing(20)

        # Main card containing IP list on the left and verification playbooks
        # on the right so the text box does not span the entire window.
        card = self.create_card("Internet-Exposed Hosts & Verification")

        main_row = QHBoxLayout()
        main_row.setSpacing(20)

        # -------------------------
        # Left column: IP list + core workflow buttons
        # -------------------------
        left_col = QVBoxLayout()
        left_col.setSpacing(12)

        desc = QLabel(
            "Paste external IPs/CIDRs/hostnames (one per line). 'Run Externals Test' "
            "runs the full recon engine: host discovery → Nmap service scan → grouped "
            "dangerous-service & open-port summaries → web-asset discovery → security "
            "headers → TLS analysis → active web recon (admin panels, exposed .git/"
            "backups, TRACE, directory listing, robots/sitemap, tech fingerprinting via "
            "whatweb/nuclei when installed) → prioritised findings (Critical→Info) → "
            "report files + a Nessus-style summary, all saved to the output folder."
        )
        desc.setWordWrap(True)
        desc.setObjectName("autoDesc")
        left_col.addWidget(desc)

        # Optional single-host helper so you don't need to switch back to
        # Target Setup when validating one IP/host.
        single_row = QHBoxLayout()
        single_label = QLabel("Single host/IP:")
        single_label.setObjectName("fieldLabel")
        single_row.addWidget(single_label)

        self.externals_single_host_input = QLineEdit()
        self.externals_single_host_input.setPlaceholderText("203.0.113.10 or vpn.example.com")
        self.externals_single_host_input.setMaximumWidth(260)
        single_row.addWidget(self.externals_single_host_input)

        use_single_btn = QPushButton("Use as List")
        use_single_btn.setObjectName("secondaryButton")
        use_single_btn.setMinimumHeight(32)
        use_single_btn.clicked.connect(self.set_externals_single_host)
        single_row.addWidget(use_single_btn)

        left_col.addLayout(single_row)

        input_label = QLabel("External IP addresses (one per line):")
        input_label.setObjectName("fieldLabel")
        left_col.addWidget(input_label)

        from PyQt6.QtWidgets import QPlainTextEdit as _QPlainTextEdit
        self.externals_ip_input = _QPlainTextEdit()
        self.externals_ip_input.setPlaceholderText("192.0.2.10\n198.51.100.23\n203.0.113.5")
        self.externals_ip_input.setMinimumHeight(160)
        # Keep the IP box to roughly 1/3 of the window width for better balance.
        self.externals_ip_input.setMaximumWidth(420)
        left_col.addWidget(self.externals_ip_input)

        core_btns = QGridLayout()
        core_btns.setSpacing(8)

        # Step 1: tidy the pasted list into clean IP/CIDR entries
        self.externals_tidy_btn = QPushButton("TIDY IPs")
        self.externals_tidy_btn.setObjectName("secondaryButton")
        self.externals_tidy_btn.setMinimumHeight(40)
        self.externals_tidy_btn.clicked.connect(self.tidy_externals_ips)
        # Right-click: show info (no external command to edit)
        self.externals_tidy_btn.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        self.externals_tidy_btn.customContextMenuRequested.connect(
            lambda pos, which="tidy": self.show_externals_button_editor(which)
        )
        core_btns.addWidget(self.externals_tidy_btn, 0, 0)

        self.externals_csv_btn = QPushButton("Save CSV IPs")
        self.externals_csv_btn.setObjectName("secondaryButton")
        self.externals_csv_btn.setMinimumHeight(40)
        self.externals_csv_btn.setToolTip("Save the IP list as one comma-separated line in the output folder.")
        self.externals_csv_btn.clicked.connect(self.save_externals_ips_csv)
        core_btns.addWidget(self.externals_csv_btn, 0, 1)

        # Step 2: discover which hosts are responsive
        self.externals_check_btn = QPushButton("Check What's Up")
        self.externals_check_btn.setObjectName("secondaryButton")
        self.externals_check_btn.setMinimumHeight(40)
        self.externals_check_btn.clicked.connect(self.run_externals_check_whats_up)
        # Right-click: edit discovery command template
        self.externals_check_btn.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        self.externals_check_btn.customContextMenuRequested.connect(
            lambda pos, which="check": self.show_externals_button_editor(which)
        )
        core_btns.addWidget(self.externals_check_btn, 1, 0)

        # Step 3: full Externals pipeline (Nmap + headers + TLS)
        self.externals_run_btn = QPushButton("Run Externals Test")
        self.externals_run_btn.setObjectName("primaryButton")
        self.externals_run_btn.setMinimumHeight(40)
        self.externals_run_btn.setToolTip(
            "Full automated external recon engine: discovery, Nmap, dangerous-service\n"
            "grouping, web discovery, security headers, TLS analysis, admin-panel &\n"
            "exposure detection, tech fingerprinting, prioritised findings and a full\n"
            "report set (technical_findings.txt, executive_summary.txt, dangerous_\n"
            "services.txt, tls_findings.txt, external_findings.json, …).\n"
            "Right-click to edit the underlying discovery/Nmap/TestSSL commands."
        )
        self.externals_run_btn.clicked.connect(self.run_externals_workflow)
        # Right-click: edit full Externals workflow commands
        self.externals_run_btn.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        self.externals_run_btn.customContextMenuRequested.connect(
            lambda pos, which="run": self.show_externals_button_editor(which)
        )
        core_btns.addWidget(self.externals_run_btn, 1, 1)

        left_col.addLayout(core_btns)

        # Step 4 (optional, fast): bulk web-facing host check for large IP lists
        self.externals_webcheck_btn = QPushButton("🌐  Check Web-Facing Hosts (Bulk)")
        self.externals_webcheck_btn.setObjectName("secondaryButton")
        self.externals_webcheck_btn.setMinimumHeight(40)
        self.externals_webcheck_btn.setToolTip(
            "Fast concurrent TCP-connect check for common web ports (443, 80, 8443,\n"
            "8080) against every host in the list above. Built for large lists\n"
            "(hundreds of IPs) — not a full port scan, just flags which hosts have\n"
            "a reachable web service. Writes bulk_web_facing_hosts.txt."
        )
        self.externals_webcheck_btn.clicked.connect(self.run_externals_web_facing_check)
        left_col.addWidget(self.externals_webcheck_btn)

        # ── URL list + HTTP analysis ──────────────────────────────────────
        url_label = QLabel("URLs for HTTP header analysis (one per line):")
        url_label.setObjectName("fieldLabel")
        left_col.addWidget(url_label)

        self.externals_url_input = QPlainTextEdit()
        self.externals_url_input.setPlaceholderText(
            "https://example.com\nhttps://portal.example.com/login\nhttps://api.example.com"
        )
        self.externals_url_input.setMinimumHeight(110)
        self.externals_url_input.setMaximumWidth(420)
        left_col.addWidget(self.externals_url_input)

        self.externals_http_analysis_btn = QPushButton("🔍  Bulk HTTP Response Analysis")
        self.externals_http_analysis_btn.setObjectName("primaryButton")
        self.externals_http_analysis_btn.setMinimumHeight(40)
        self.externals_http_analysis_btn.clicked.connect(self.run_bulk_http_analysis)
        left_col.addWidget(self.externals_http_analysis_btn)

        self.externals_nmap_all_btn = QPushButton("🔌  Exposed Services Scan (All Hosts)")
        self.externals_nmap_all_btn.setObjectName("primaryButton")
        self.externals_nmap_all_btn.setMinimumHeight(40)
        self.externals_nmap_all_btn.setToolTip(
            "Runs nmap -sV against every host in the URL list above.\n"
            "Strips https:// automatically. Groups results by port/service.\n"
            "Dangerous ports are highlighted red."
        )
        self.externals_nmap_all_btn.clicked.connect(self.run_externals_nmap_all_hosts)
        left_col.addWidget(self.externals_nmap_all_btn)

        self.externals_ssl_scan_btn = QPushButton("🔒  Bulk SSL/TLS Vulnerability Scan")
        self.externals_ssl_scan_btn.setObjectName("primaryButton")
        self.externals_ssl_scan_btn.setMinimumHeight(40)
        self.externals_ssl_scan_btn.setToolTip(
            "Runs full SSL/TLS assessment against every host in the URL list.\n"
            "Checks: deprecated versions, Heartbleed, CRIME, CCS Injection, ROBOT,\n"
            "Lucky13, Sweet32, BEAST, RC4, EXPORT, weak certs, HSTS, BREACH."
        )
        self.externals_ssl_scan_btn.clicked.connect(self.run_bulk_ssl_scan)
        left_col.addWidget(self.externals_ssl_scan_btn)

        # -------------------------
        # Right column: service verification playbooks
        # -------------------------
        right_col = QVBoxLayout()
        right_col.setSpacing(16)

        verify_card = self.create_card("Individual External Checks")
        verify_card.setMaximumWidth(600)
        verify_layout = QGridLayout()
        verify_layout.setSpacing(10)

        # IKE / IPsec aggressive mode (pre-shared key) validation
        self.externals_ike_btn = QPushButton("IKE Aggressive Mode (PSK)")
        self.externals_ike_btn.setObjectName("secondaryButton")
        self.externals_ike_btn.setMinimumHeight(36)
        self.externals_ike_btn.clicked.connect(self.run_externals_ike_aggressive)
        verify_layout.addWidget(self.externals_ike_btn, 0, 0)

        # SSH crypto / configuration audit (weak algorithms, legacy protocols)
        self.externals_ssh_btn = QPushButton("SSH Crypto & Config Audit")
        self.externals_ssh_btn.setObjectName("secondaryButton")
        self.externals_ssh_btn.setMinimumHeight(36)
        self.externals_ssh_btn.clicked.connect(self.run_externals_ssh_audit)
        verify_layout.addWidget(self.externals_ssh_btn, 0, 1)

        # SMB signing / share enumeration (supports many Nessus SMB findings)
        self.externals_smb_btn = QPushButton("Validate SMB Signing / Shares")
        self.externals_smb_btn.setObjectName("secondaryButton")
        self.externals_smb_btn.setMinimumHeight(36)
        self.externals_smb_btn.clicked.connect(self.run_externals_smb_validation)
        verify_layout.addWidget(self.externals_smb_btn, 1, 0)

        # RDP encryption / security level validation
        self.externals_rdp_btn = QPushButton("RDP Encryption & Security")
        self.externals_rdp_btn.setObjectName("secondaryButton")
        self.externals_rdp_btn.setMinimumHeight(36)
        self.externals_rdp_btn.clicked.connect(self.run_externals_rdp_encryption)
        verify_layout.addWidget(self.externals_rdp_btn, 1, 1)

        # FTP anonymous access validation
        self.externals_ftp_btn = QPushButton("Check FTP Anonymous Access")
        self.externals_ftp_btn.setObjectName("secondaryButton")
        self.externals_ftp_btn.setMinimumHeight(36)
        self.externals_ftp_btn.clicked.connect(self.run_externals_ftp_anon)
        verify_layout.addWidget(self.externals_ftp_btn, 2, 0)

        # SMTP open relay validation
        self.externals_smtp_btn = QPushButton("Check SMTP Open Relay")
        self.externals_smtp_btn.setObjectName("secondaryButton")
        self.externals_smtp_btn.setMinimumHeight(36)
        self.externals_smtp_btn.clicked.connect(self.run_externals_smtp_relay)
        verify_layout.addWidget(self.externals_smtp_btn, 2, 1)

        # Wildcard certificate verification across external hosts
        self.externals_wildcard_btn = QPushButton("Check Wildcard Certs")
        self.externals_wildcard_btn.setObjectName("secondaryButton")
        self.externals_wildcard_btn.setMinimumHeight(36)
        self.externals_wildcard_btn.clicked.connect(self.run_externals_wildcard_certs)
        verify_layout.addWidget(self.externals_wildcard_btn, 3, 0)

        # Direct TLS check against the primary target host: self-signed certs
        self.externals_self_signed_btn = QPushButton("Check Self Signed Certs")
        self.externals_self_signed_btn.setObjectName("secondaryButton")
        self.externals_self_signed_btn.setMinimumHeight(36)
        self.externals_self_signed_btn.clicked.connect(self.check_self_signed_cert)
        # Right-click: edit underlying openssl command
        self.externals_self_signed_btn.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        self.externals_self_signed_btn.customContextMenuRequested.connect(
            lambda pos, which="self_signed": self.show_externals_button_editor(which)
        )
        verify_layout.addWidget(self.externals_self_signed_btn, 3, 1)

        # ICMP Timestamp Request Remote Date Disclosure (hping3) against the
        # live host list. Prints one sample reply, then lists affected hosts.
        self.externals_icmp_btn = QPushButton("ICMP Timestamp Disclosure")
        self.externals_icmp_btn.setObjectName("secondaryButton")
        self.externals_icmp_btn.setMinimumHeight(36)
        self.externals_icmp_btn.setToolTip(
            "Runs 'sudo hping3 <ip> --icmp --icmp-ts -c 1 -V' against each host in\n"
            "live_hosts.txt (falls back to up.txt / ips.txt). Shows one sample reply,\n"
            "then lists affected hosts as a comma-separated list. Requires hping3 and\n"
            "cached/passwordless sudo."
        )
        self.externals_icmp_btn.clicked.connect(self.run_externals_icmp_timestamp)
        verify_layout.addWidget(self.externals_icmp_btn, 4, 0)

        verify_card.layout().addLayout(verify_layout)
        right_col.addWidget(verify_card)
        right_col.addStretch()

        main_row.addLayout(left_col, 1)
        main_row.addLayout(right_col, 1)

        card.layout().addLayout(main_row)
        layout.addWidget(card)

        layout.addStretch()
        return scroll
