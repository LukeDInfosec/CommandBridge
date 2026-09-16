"""
Bug Bounty Methodology tab creator.
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



class MethodologyTabMixin:
    """Mixin providing bug bounty methodology tab creator."""

    def create_methodology_tab(self):
        """Create bug bounty methodology tab with XSS and SQLi workflows"""
        widget = QWidget()
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QFrame.Shape.NoFrame)
        scroll.setWidget(widget)
        
        layout = QVBoxLayout(widget)
        layout.setContentsMargins(25, 25, 25, 25)
        layout.setSpacing(20)
        
        # XSS Methodology Card (collapsible, compact multi-column layout)
        xss_card = self.create_card("⚡ XSS Testing Methodology")
        self._init_collapsible_groupbox(xss_card, "methodology_xss_card")
        xss_layout = QVBoxLayout()
        xss_layout.setSpacing(12)
        
        # Subdomain Enumeration section
        xss_sub_label = QLabel("🌎 Subdomain Enumeration")
        xss_sub_label.setObjectName("methodologySection")
        xss_layout.addWidget(xss_sub_label)
        
        xss_tools_1 = [
            ("Subdomain Discovery", "subdomain_discovery", "subfinder -d {TARGET_HOST} -all -recursive > subs.txt"),
            ("Live Subdomain Filtering", "httpx_filter", "cat subs.txt | httpx-toolkit -ports 80,443,8080,8000,8888 -threads 200 -silent > alive.txt"),
            ("Subdomain Takeover Check", "subzy_takeover", "if command -v subzy >/dev/null 2>&1; then subzy run --targets subs.txt --concurrency 100 --hide_fails --verify_ssl; else echo 'Error: subzy is not installed (command not found).'; fi"),
        ]
        
        xss_grid_1 = QGridLayout()
        xss_grid_1.setHorizontalSpacing(10)
        xss_grid_1.setVerticalSpacing(8)
        xss_columns = 3
        for i, (name, btn_id, cmd) in enumerate(xss_tools_1):
            btn = self.create_editable_button(name, btn_id, cmd)
            xss_grid_1.addWidget(btn, i // xss_columns, i % xss_columns)
        xss_layout.addLayout(xss_grid_1)
        
        # URL Collection section
        xss_url_label = QLabel("🔗 URL Collection")
        xss_url_label.setObjectName("methodologySection")
        xss_layout.addWidget(xss_url_label)
        
        xss_tools_2 = [
            # Use the alive.txt host list as katana's input list rather than as a
            # single URL value.
            ("Passive URL Collection", "passive_katana", "katana -list alive.txt -d 5 -ps -pss waybackarchive,commoncrawl,alienvault -kf -jc -fx -ef woff,css,png,svg,jpg -o allurls.txt"),
            ("Advanced URL Fetching", "adv_url_fetch", "echo {TARGET} | katana -d 5 -ps -pss waybackarchive,commoncrawl,alienvault -f qurl | urldedupe > output.txt"),
            ("GAU URL Collection", "gau_urls", "gau {TARGET_HOST} --subs | urldedupe > urls.txt"),
            # Unauthenticated param discovery against the current target URL
            # (no auth). Uses katana to crawl the live target and extract any
            # URLs containing query parameters, then deduplicates them. Lives
            # here (recon/collection) rather than under a separate "XSS
            # Testing" section — that section was removed because it
            # duplicated the Web tab's XSS Pipeline + Dalfox Scan commands
            # (gau|gf xss|uro|Gxss|kxss and dalfox), which already cover
            # single-target XSS testing there.
            ("unauth", "xss_unauth",
             "echo {TARGET} | katana -silent -d 2 | grep '\\?' | urldedupe | sed -E \"s/=([^&#]*)/=/g\" | urldedupe > {SAFE_TARGET}_unauth_params.txt"),
        ]

        xss_grid_2 = QGridLayout()
        xss_grid_2.setHorizontalSpacing(10)
        xss_grid_2.setVerticalSpacing(8)
        for i, (name, btn_id, cmd) in enumerate(xss_tools_2):
            btn = self.create_editable_button(name, btn_id, cmd)
            xss_grid_2.addWidget(btn, i // xss_columns, i % xss_columns)
        xss_layout.addLayout(xss_grid_2)

        xss_card.layout().addLayout(xss_layout)
        layout.addWidget(xss_card)
        
        # SQL Injection Methodology Card (collapsible, compact multi-column layout)
        sqli_card = self.create_card("🛡️ SQL Injection Methodology")
        self._init_collapsible_groupbox(sqli_card, "methodology_sqli_card")
        sqli_layout = QVBoxLayout()
        sqli_layout.setSpacing(12)
        
        # Domain Discovery section
        sqli_domain_label = QLabel("🔍 Domain Discovery")
        sqli_domain_label.setObjectName("methodologySection")
        sqli_layout.addWidget(sqli_domain_label)
        
        sqli_tools_1 = [
            ("Single Domain Detection", "sqli_single_domain", "subfinder -d {TARGET_HOST} -all -silent | httpx-toolkit -td -sc -silent | grep -Ei 'asp|php|jsp|jspx|aspx'"),
            ("Multiple Domain Check", "sqli_multi_domain", "subfinder -dL subdomains.txt -all -silent | httpx-toolkit -td -sc -silent | grep -Ei 'asp|php|jsp|jspx|aspx'"),
        ]
        
        sqli_grid_1 = QGridLayout()
        sqli_grid_1.setHorizontalSpacing(10)
        sqli_grid_1.setVerticalSpacing(8)
        sqli_columns = 3
        for i, (name, btn_id, cmd) in enumerate(sqli_tools_1):
            btn = self.create_editable_button(name, btn_id, cmd)
            sqli_grid_1.addWidget(btn, i // sqli_columns, i % sqli_columns)
        sqli_layout.addLayout(sqli_grid_1)
        
        # Discovering Endpoints section
        sqli_endpoints_label = QLabel("📍 Discovering Potential SQLi Endpoints")
        sqli_endpoints_label.setObjectName("methodologySection")
        sqli_layout.addWidget(sqli_endpoints_label)
        
        sqli_tools_2 = [
            ("Filter Single Target", "sqli_filter_single", "gau {TARGET_HOST} | uro | grep -E '.php|.asp|.aspx|.jspx|.jsp' | grep '=' > urls.txt"),
            ("Katana Deep Crawl", "sqli_katana", "gau {TARGET_HOST} | uro | grep -E '.php|.asp' > urls2.txt"),
            ("Clean Up & Dedupe", "sqli_cleanup", "cat urls.txt urls2.txt | gf sqli | uro > cleaned-sql.txt"),
        ]
        
        sqli_grid_2 = QGridLayout()
        sqli_grid_2.setHorizontalSpacing(10)
        sqli_grid_2.setVerticalSpacing(8)
        for i, (name, btn_id, cmd) in enumerate(sqli_tools_2):
            btn = self.create_editable_button(name, btn_id, cmd)
            sqli_grid_2.addWidget(btn, i // sqli_columns, i % sqli_columns)
        sqli_layout.addLayout(sqli_grid_2)
        
        # Mass Testing section
        sqli_testing_label = QLabel("🚀 Automate Mass SQL Injection Testing")
        sqli_testing_label.setObjectName("methodologySection")
        sqli_layout.addWidget(sqli_testing_label)
        
        sqli_tools_3 = [
            ("Ghauri Scan", "sqli_ghauri", "ghauri -m cleaned-sql.txt --batch --dbs --level 3 --confirm"),
            ("SQLMap Scan", "sqli_sqlmap", "sqlmap -m cleaned-sql.txt --batch --random-agent --tamper=space2comment --level=5 --risk=3 --dbs"),
            ("Advanced Ghauri Pipeline", "sqli_adv_ghauri", "subfinder -d {TARGET_HOST} -all -silent | gau --threads 3 | uro | gf sqli > sql.txt; ghauri -m sql.txt --batch --dbs --level 3"),
            ("Advanced SQLMap Pipeline", "sqli_adv_sqlmap", "subfinder -d {TARGET_HOST} -all -silent | gau --threads 3 | uro | gf sqli > sql.txt; sqlmap -m sql.txt --batch --random-agent --level=5 --risk=3 --dbs"),
        ]
        
        sqli_grid_3 = QGridLayout()
        sqli_grid_3.setHorizontalSpacing(10)
        sqli_grid_3.setVerticalSpacing(8)
        for i, (name, btn_id, cmd) in enumerate(sqli_tools_3):
            btn = self.create_editable_button(name, btn_id, cmd)
            sqli_grid_3.addWidget(btn, i // sqli_columns, i % sqli_columns)
        sqli_layout.addLayout(sqli_grid_3)
        
        sqli_card.layout().addLayout(sqli_layout)
        layout.addWidget(sqli_card)
        
        layout.addStretch()
        
        return scroll
