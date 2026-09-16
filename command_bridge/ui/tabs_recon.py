"""
Reconnaissance tab creator.
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



class ReconTabMixin:
    """Mixin providing reconnaissance tab creator."""

    def create_reconnaissance_tab(self):
        """Create scanning tools tab"""
        widget = QWidget()
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QFrame.Shape.NoFrame)
        scroll.setWidget(widget)
        
        layout = QVBoxLayout(widget)
        layout.setContentsMargins(25, 25, 25, 25)
        layout.setSpacing(20)
        
        # Auto Scan Card - Reduced width (MOVED TO TOP)
        auto_container = QWidget()
        auto_container_layout = QHBoxLayout(auto_container)
        auto_container_layout.setContentsMargins(0, 0, 0, 0)
        
        auto_container_layout.addStretch()
        
        auto_card = self.create_card("⚡ Automated Scanning")
        auto_card.setMaximumWidth(800)
        auto_layout = QVBoxLayout()
        auto_layout.setSpacing(12)
        
        auto_desc = QLabel("Run a comprehensive automated scan sequence: Nmap scans → SSL/TLS analysis → Directory enumeration")
        auto_desc.setObjectName("autoDesc")
        auto_desc.setWordWrap(True)
        auto_layout.addWidget(auto_desc)
        
        # Store default auto scan button
        self.auto_scan_btn = QPushButton("▶  START AUTO SCAN")
        self.auto_scan_btn.setObjectName("primaryButton")
        self.auto_scan_btn.setMinimumHeight(36)
        self.auto_scan_btn.setMaximumHeight(40)
        self.auto_scan_btn.setCursor(QtGui.QCursor(QtCore.Qt.CursorShape.PointingHandCursor))
        self.auto_scan_btn.setStyleSheet(
            "QPushButton { font-size: 12px; font-weight: 700; letter-spacing: 1px; border-radius: 6px; padding: 6px 20px; } "
            "QPushButton:hover { letter-spacing: 1.5px; }"
        )
        self.auto_scan_btn.clicked.connect(self.run_auto_scan)
        
        # Add right-click context menu for auto scan
        self.auto_scan_btn.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        self.auto_scan_btn.customContextMenuRequested.connect(self.show_auto_scan_menu)
        
        auto_layout.addWidget(self.auto_scan_btn)
        
        auto_card.layout().addLayout(auto_layout)
        auto_container_layout.addWidget(auto_card)
        auto_container_layout.addStretch()
        
        layout.addWidget(auto_container)
        
        # Advanced Nmap Card (moved above Nuclei — Nmap scans take priority
        # in the recon workflow order).
        adv_nmap_card = self.create_card("🔥 Advanced Nmap & Vulnerability Scanning")
        adv_nmap_layout = QGridLayout()
        adv_nmap_layout.setSpacing(12)

        adv_nmap_tools = [
            ("Nmap Vuln Scripts", "recon_nmap_vuln",
             "nmap -sV --script vuln -T4 {TARGET_HOST} -oN {SAFE_TARGET}_nmap_vuln.txt"),
            ("Nmap HTTP Scripts", "recon_nmap_http",
             "nmap -sV --script http-title,http-headers,http-methods,http-robots.txt -p 80,443,8080,8443 {TARGET_HOST} -oN {SAFE_TARGET}_nmap_http.txt"),
            ("Nmap SMB Scripts", "recon_nmap_smb",
             "nmap -sV --script smb-vuln*,smb-enum-shares,smb2-security-mode -p 445,139 {TARGET_HOST} -oN {SAFE_TARGET}_nmap_smb.txt"),
            # RustScan replaces the old masscan button. masscan wanted an IP
            # rather than a hostname, needed root for raw sockets, and drowned
            # the console in progress output — all of which RustScan avoids:
            # it resolves hostnames itself, uses ordinary TCP connects (no
            # root), and its entire purpose is to sweep every port fast and
            # then hand the open ones straight to nmap.
            #
            # Everything after `--` is passed through to nmap; RustScan
            # supplies `-Pn -vvv -p <open ports>` itself, so this adds the
            # enumeration flags: service/version detection, default scripts,
            # and OS-independent timing.
            ("RustScan → Nmap", "recon_rustscan",
             "if ! command -v rustscan >/dev/null 2>&1; then "
             "echo '[!] rustscan is not installed. Install it from Target Setup -> '; "
             "echo '    \"Install / Repair Missing Tools\", or manually:'; "
             "echo '    https://github.com/bee-san/RustScan/releases (.deb), or: cargo install rustscan'; "
             "else echo '[*] RustScan: sweeping all 65535 ports, then handing the open ones to nmap…'; "
             "rustscan -a {TARGET_HOST} -r 1-65535 --ulimit 5000 --no-config "
             "-- -sV -sC -oN {SAFE_TARGET}_rustscan_nmap.txt 2>&1; "
             "echo; echo \"[i] Full nmap enumeration written to {SAFE_TARGET}_rustscan_nmap.txt\"; fi"),
            # Ports only, no nmap pass — for when you just want the open list
            # fast (greppable output, one line per host).
            ("RustScan (ports only)", "recon_rustscan_ports",
             "if ! command -v rustscan >/dev/null 2>&1; then "
             "echo '[!] rustscan is not installed (see the RustScan → Nmap button for install options).'; "
             "else rustscan -a {TARGET_HOST} -r 1-65535 --ulimit 5000 --no-config --greppable 2>&1 "
             "| tee {SAFE_TARGET}_rustscan_ports.txt; fi"),
            ("Nmap + NSE CVE Check", "recon_nmap_cve",
             "nmap -sV --script vulners --script-args mincvss=5.0 {TARGET_HOST} -oN {SAFE_TARGET}_nmap_cve.txt"),
            ("Nmap Aggressive Scan", "recon_nmap_aggressive",
             "nmap -A -T4 {TARGET_HOST} -oN {SAFE_TARGET}_nmap_aggressive.txt"),
        ]

        for i, (name, btn_id, cmd) in enumerate(adv_nmap_tools):
            btn = self.create_editable_button(name, btn_id, cmd)
            adv_nmap_layout.addWidget(btn, i // 2, i % 2)

        adv_nmap_card.layout().addLayout(adv_nmap_layout)
        layout.addWidget(adv_nmap_card)

        # Nuclei Scanning Card
        nuclei_card = self.create_card("⚡ Nuclei Scanning")
        nuclei_layout = QGridLayout()
        nuclei_layout.setSpacing(12)

        nuclei_tools = [
            # Quote {TARGET} so query parameters containing '&' are treated as a
            # single URL argument by the shell and do not break the command
            # into multiple statements.
            ("Normal Scan", "nuclei_normal", "nuclei -u '{TARGET}' -o {SAFE_TARGET}_normal_nuclei.txt"),
            ("Automatic Selection", "nuclei_as", "nuclei -u '{TARGET}' -as -o {SAFE_TARGET}_as_nuclei.txt"),
            ("Direct Tag Scanning (XSS)", "nuclei_tags", "nuclei -u '{TARGET}' -tags xss -o {SAFE_TARGET}_tags_nuclei.txt"),
            ("Severity Scanning", "nuclei_sev", "nuclei -u '{TARGET}' -s info,medium,high,critical -o {SAFE_TARGET}_severity_nuclei.txt"),
            ("Rate Limited Scan", "nuclei_rl", "nuclei -u '{TARGET}' -rl 30 -c 2 -o {SAFE_TARGET}_rl_nuclei.txt"),
            # Point at the real template store nuclei downloads into rather
            # than the literal string "/path/to/templates", which could never
            # have worked. Right-click to aim it at your own template folder.
            ("Custom Templates", "nuclei_custom",
             "TPL=\"$HOME/nuclei-templates\"; "
             "if [ ! -d \"$TPL\" ]; then "
             "echo \"[!] No template directory at $TPL — run 'nuclei -update-templates', \"; "
             "echo '    or right-click this button to point it at your own folder.'; "
             "else nuclei -u '{TARGET}' -t \"$TPL\" -o {SAFE_TARGET}_custom_nuclei.txt; fi"),
        ]

        for i, (name, btn_id, cmd) in enumerate(nuclei_tools):
            btn = self.create_editable_button(name, btn_id, cmd)
            nuclei_layout.addWidget(btn, i // 2, i % 2)

        nuclei_card.layout().addLayout(nuclei_layout)
        layout.addWidget(nuclei_card)

        # URL Collection & Crawling Card
        url_card = self.create_card("🔗 URL Collection & Crawling")
        url_layout = QGridLayout()
        url_layout.setSpacing(12)

        url_tools = [
            ("GAU (Get All URLs)", "recon_gau",
             "gau {TARGET_HOST} --threads 5 --retries 2 --subs | sort -u | tee {SAFE_TARGET}_gau.txt"),
            ("Waybackurls", "recon_wayback",
             "echo '{TARGET_HOST}' | waybackurls | sort -u | tee {SAFE_TARGET}_wayback.txt"),
            ("Katana Crawler", "recon_katana",
             "katana -u '{TARGET}' -d 3 -jc -kf all -c 5 -timeout 10 -o {SAFE_TARGET}_katana.txt"),
            # hakrawler's depth flag is -d, not -depth (which it rejects).
            ("Hakrawler", "recon_hakrawler",
             "echo '{TARGET}' | hakrawler -d 3 -insecure -subs | tee {SAFE_TARGET}_hakrawler.txt"),
            ("URLs + Parameter Filter", "recon_urls_params",
             "cat {SAFE_TARGET}_gau.txt {SAFE_TARGET}_wayback.txt 2>/dev/null | sort -u | grep '=' | uro | tee {SAFE_TARGET}_params_raw.txt"),
            ("URO Deduplication", "recon_uro",
             "cat {SAFE_TARGET}_gau.txt 2>/dev/null | uro | tee {SAFE_TARGET}_uro.txt"),
        ]

        for i, (name, btn_id, cmd) in enumerate(url_tools):
            btn = self.create_editable_button(name, btn_id, cmd)
            url_layout.addWidget(btn, i // 2, i % 2)

        url_card.layout().addLayout(url_layout)
        layout.addWidget(url_card)

        # DNS & Asset Discovery Card
        dns_card = self.create_card("🌐 DNS, Certs & Tech Detection")
        dns_layout = QGridLayout()
        dns_layout.setSpacing(12)

        dns_tools = [
            ("DNSX Probe", "recon_dnsx",
             "dnsx -l {SAFE_TARGET}_subdomains.txt -a -aaaa -cname -mx -resp -silent | tee {SAFE_TARGET}_dnsx.txt"),
            ("DNS Brute Force", "recon_dns_brute",
             "dnsx -d {TARGET_HOST} -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt -silent | tee {SAFE_TARGET}_dns_brute.txt"),
            ("CRT.sh Cert Transparency", "recon_crtsh",
             "curl -s 'https://crt.sh/?q=%.{TARGET_HOST}&output=json' | python3 -c \"import json,sys; data=json.load(sys.stdin); [print(n) for d in data for n in d.get('name_value','').split()]\" | sort -u | tee {SAFE_TARGET}_crtsh.txt"),
            ("WhatWeb Tech Detection", "recon_whatweb",
             "whatweb -a 3 '{TARGET}' --log-json={SAFE_TARGET}_whatweb.json 2>&1 | tee {SAFE_TARGET}_whatweb.txt"),
            ("Wafw00f WAF Detect", "recon_wafw00f",
             "wafw00f '{TARGET}' -o {SAFE_TARGET}_waf.txt"),
            ("TheHarvester OSINT", "recon_harvester",
             "theHarvester -d {TARGET_HOST} -b all -l 200 -f {SAFE_TARGET}_harvester 2>&1 | tee {SAFE_TARGET}_harvester.txt"),
        ]

        for i, (name, btn_id, cmd) in enumerate(dns_tools):
            btn = self.create_editable_button(name, btn_id, cmd)
            dns_layout.addWidget(btn, i // 2, i % 2)

        dns_card.layout().addLayout(dns_layout)
        layout.addWidget(dns_card)

        layout.addStretch()

        return scroll
