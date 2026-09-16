"""
API Testing tab creator.
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



class ApiTabMixin:
    """Mixin providing api testing tab creator."""

    def create_api_testing_tab(self):
        """Create comprehensive API testing tab with REST, GraphQL, JWT, and more"""
        widget = QWidget()
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QFrame.Shape.NoFrame)
        scroll.setWidget(widget)
        
        layout = QVBoxLayout(widget)
        layout.setContentsMargins(25, 25, 25, 25)
        layout.setSpacing(20)
        
        # GraphQL Testing Card
        graphql_card = self.create_card("✨ GraphQL Security Testing")
        graphql_layout = QGridLayout()
        graphql_layout.setSpacing(12)

        # Standard GraphQL introspection query (the canonical query used by
        # GraphiQL/graphql-js's getIntrospectionQuery()), POSTed with curl.
        # There is no real "graphql-introspection" CLI tool on Kali — the
        # previous command referenced a binary that doesn't exist.
        _introspection_query = (
            "query IntrospectionQuery { __schema { queryType { name } mutationType { name } "
            "subscriptionType { name } types { ...FullType } directives { name description "
            "locations args { ...InputValue } } } } fragment FullType on __Type { kind name "
            "description fields(includeDeprecated: true) { name description args "
            "{ ...InputValue } type { ...TypeRef } isDeprecated deprecationReason } inputFields "
            "{ ...InputValue } interfaces { ...TypeRef } enumValues(includeDeprecated: true) "
            "{ name description isDeprecated deprecationReason } possibleTypes { ...TypeRef } } "
            "fragment InputValue on __InputValue { name description type { ...TypeRef } "
            "defaultValue } fragment TypeRef on __Type { kind name ofType { kind name ofType "
            "{ kind name ofType { kind name ofType { kind name ofType { kind name ofType "
            "{ kind name ofType { kind name } } } } } } } }"
        )
        introspection_cmd = (
            "echo '[*] Sending GraphQL introspection query to {TARGET}/graphql'; "
            "curl -sk -X POST '{TARGET}/graphql' -H 'Content-Type: application/json' "
            "--data '{\"query\":\"" + _introspection_query + "\"}' "
            "-o {SAFE_TARGET}_graphql_intro.json; "
            "if python3 -m json.tool {SAFE_TARGET}_graphql_intro.json >/dev/null 2>&1 "
            "&& grep -q '__schema' {SAFE_TARGET}_graphql_intro.json; then "
            "echo '[+] Introspection ENABLED — schema saved to {SAFE_TARGET}_graphql_intro.json'; "
            "python3 -m json.tool {SAFE_TARGET}_graphql_intro.json | head -150; "
            "else echo '[!] Introspection appears DISABLED, or {TARGET}/graphql is not a GraphQL "
            "endpoint — check {SAFE_TARGET}_graphql_intro.json for the raw response. Try right-"
            "clicking to point the URL at the real GraphQL path if it is not /graphql.'; fi"
        )

        graphql_tools = [
            ("Introspection Query", "api_graphql_intro", introspection_cmd),
            # graphql-voyager ships as a web UI, not a command-line tool — the old
            # command could only ever print "command not found". Pull the schema
            # instead and hand over a file Voyager can actually load.
            ("GraphQL Schema (for Voyager)", "api_graphql_voyager",
             "echo '[*] Fetching introspection schema from {TARGET}/graphql'; "
             "curl -sk -X POST '{TARGET}/graphql' -H 'Content-Type: application/json' "
             "--data '{\"query\":\"query IntrospectionQuery { __schema { queryType { name } mutationType { name } types { kind name description fields(includeDeprecated: true) { name description args { name description type { kind name ofType { kind name } } } type { kind name ofType { kind name } } } } } }\"}' -o {SAFE_TARGET}_graphql_schema.json; "
             "if grep -q '__schema' {SAFE_TARGET}_graphql_schema.json 2>/dev/null; then "
             "echo '[+] Schema saved to {SAFE_TARGET}_graphql_schema.json'; "
             "echo '    Load it at https://graphql-kit.com/graphql-voyager/ (Change Schema -> Introspection).'; "
             "else echo '[!] No schema returned — introspection is probably disabled.'; fi"),
        ]

        for i, (name, btn_id, cmd) in enumerate(graphql_tools):
            btn = self.create_editable_button(name, btn_id, cmd)
            graphql_layout.addWidget(btn, i // 2, i % 2)

        # GraphQL Cop — real CLI usage is `graphql-cop.py -t URL -o json`, NOT
        # a bare positional URL, and -o takes an output FORMAT ("json"), not
        # a filename — the previous command used neither correctly, which is
        # why it always printed the usage banner and failed.
        graphql_cop_btn = self.create_editable_button(
            "GraphQL Cop",
            "api_graphql_cop",
            "graphql-cop -t '{TARGET}/graphql' -o json > {SAFE_TARGET}_graphql_cop.json 2>&1; "
            "echo; echo '=== GraphQL Cop results ==='; cat {SAFE_TARGET}_graphql_cop.json",
        )
        graphql_cop_btn.setToolTip(
            "GraphQL Cop — automated GraphQL security auditor (Dolev Farhi & Nick Aleks).\n"
            "Runs a battery of known GraphQL vulnerability checks in one pass: introspection\n"
            "exposure, batch query / alias overloading (DoS), field suggestions leaking schema,\n"
            "missing query depth/complexity limits, and more. Results saved as JSON.\n\n"
            "Right-click → Manually Modify Underlying Command to add flags such as\n"
            "-H '{\"Authorization\": \"Bearer <token>\"}' for authenticated testing,\n"
            "-f to force a scan when auto-detection fails, or -e to exclude specific tests."
        )
        graphql_layout.addWidget(graphql_cop_btn, 2, 0)

        # graphw00f — engine fingerprinting, not fuzzing (see modules/graphql_tools.py).
        # Left-click builds + runs fresh from the right-click menu's overrides;
        # right-click exposes every real flag the tool supports.
        graphw00f_btn = QPushButton("GraphQL Engine Fingerprint (graphw00f)")
        graphw00f_btn.setObjectName("secondaryButton")
        graphw00f_btn.setMinimumHeight(42)
        graphw00f_btn.setCursor(QtGui.QCursor(QtCore.Qt.CursorShape.PointingHandCursor))
        graphw00f_btn.setToolTip(self._graphw00f_base_tooltip())
        graphw00f_btn.clicked.connect(self.run_graphw00f)
        graphw00f_btn.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        graphw00f_btn.customContextMenuRequested.connect(self.show_graphw00f_menu)
        self.graphw00f_btn = graphw00f_btn
        graphql_layout.addWidget(graphw00f_btn, 2, 1)

        graphql_card.layout().addLayout(graphql_layout)
        layout.addWidget(graphql_card)

        # REST API Card
        rest_card = self.create_card("📡 REST API Testing")
        rest_layout = QGridLayout()
        rest_layout.setSpacing(12)

        # API Fuzzing — the old default wordlist ("api-wordlist.txt") did not
        # exist anywhere on disk. Point at the real seclists API endpoint
        # list, and add a right-click shortcut to swap just the wordlist
        # without hand-editing the whole command.
        api_fuzz_btn = self.create_editable_button(
            "API Fuzzing",
            "api_ffuf",
            # ffuf's raw "-of json" dump (duration, resultfile, scraper,
            # position, ...) goes to a "_raw.json" file; ffuf_clean.py turns
            # that into the plain "[STATUS] URL" list actually saved as
            # {SAFE_TARGET}_api_fuzz.txt (and printed to the console) — see
            # the identical fix applied to the Web tab's FFUF button.
            "ffuf -u '{TARGET}/api/FUZZ' "
            "-w /usr/share/seclists/Discovery/Web-Content/api/api-endpoints.txt "
            "-ac -s -mc 200,201,204,301,302,307,401,403 -of json -o {SAFE_TARGET}_api_fuzz_raw.json; "
            "python3 {CB_DIR}/command_bridge/modules/ffuf_clean.py "
            "{SAFE_TARGET}_api_fuzz_raw.json {SAFE_TARGET}_api_fuzz.txt",
        )
        api_fuzz_btn.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        api_fuzz_btn.customContextMenuRequested.connect(
            lambda pos, b=api_fuzz_btn: self.show_api_fuzz_menu(b, pos)
        )
        rest_layout.addWidget(api_fuzz_btn, 0, 0)

        arjun_btn = self.create_editable_button(
            "Mass Assignment", "api_arjun", "arjun -u '{TARGET}' -o {SAFE_TARGET}_arjun.txt"
        )
        rest_layout.addWidget(arjun_btn, 0, 1)

        # Rate Limiting — replaced wfuzz command (which had no FUZZ keyword
        # anywhere in the target, so wfuzz had nothing to iterate on and
        # would just error) with a dedicated safe PoC tester that sends a
        # modest, capped, concurrency-limited burst and reports a clear
        # detected/not-detected verdict with a summary table — see
        # modules/rate_limit_check.py.
        ratelimit_btn = self.create_editable_button(
            "Rate Limiting",
            "api_ratelimit",
            "python3 {CB_DIR}/command_bridge/modules/rate_limit_check.py '{TARGET}/api' "
            "--requests 150 --concurrency 10 "
            "--json-out {SAFE_TARGET}_ratelimit.json 2>&1 | tee {SAFE_TARGET}_ratelimit.txt",
        )
        ratelimit_btn.setToolTip(
            "Safely tests whether the target rate-limits requests, without attempting a DoS.\n"
            "Sends a modest, capped burst (default 150 requests, 10 concurrent — both\n"
            "adjustable via right-click) and watches for HTTP 429 responses and Retry-After\n"
            "headers. Prints a summary table (requests sent, time elapsed, req/sec, response\n"
            "breakdown) and a clear DETECTED / NOT DETECTED verdict — copy-paste ready for a\n"
            "pentest report. Also writes a JSON report alongside the console log."
        )
        rest_layout.addWidget(ratelimit_btn, 1, 0)

        # Swagger/OpenAPI — renamed for clarity, and now tries every common
        # spec path (not just the literal Target URL) so it actually finds
        # documentation that isn't hosted at exactly the target path.
        swagger_cmd = (
            "echo '[*] Probing for Swagger/OpenAPI documentation on {TARGET}'; "
            "FOUND=0; "
            "for p in \"\" \"/swagger.json\" \"/openapi.json\" \"/v2/api-docs\" \"/v3/api-docs\" "
            "\"/api-docs\" \"/swagger/v1/swagger.json\" \"/swagger/index.html\"; do "
            "URL=\"{TARGET}$p\"; "
            "echo \"[*] Trying: $URL\"; "
            "curl -sk -m 8 \"$URL\" -o {SAFE_TARGET}_swagger.json; "
            "if python3 -m json.tool {SAFE_TARGET}_swagger.json >/dev/null 2>&1 "
            "&& grep -qE '\"(swagger|openapi)\"' {SAFE_TARGET}_swagger.json; then "
            "echo \"[+] Valid Swagger/OpenAPI spec found at: $URL\"; "
            "echo '[+] Saved to {SAFE_TARGET}_swagger.json'; "
            "python3 -m json.tool {SAFE_TARGET}_swagger.json | head -120; "
            "FOUND=1; break; fi; "
            "done; "
            "if [ \"$FOUND\" -eq 0 ]; then "
            "echo '[!] No Swagger/OpenAPI documentation found at the target path or common "
            "spec locations. Try right-clicking to point the target at a known doc path.'; fi"
        )
        swagger_btn = self.create_editable_button(
            "Detect Swagger/OpenAPI Documentation", "api_swagger", swagger_cmd
        )
        swagger_btn.setToolTip(
            "Checks the target URL itself, then automatically tries the common\n"
            "Swagger/OpenAPI spec paths (/swagger.json, /openapi.json, /v2/api-docs,\n"
            "/v3/api-docs, /api-docs, /swagger/v1/swagger.json, /swagger/index.html)\n"
            "and stops at the first one that returns a valid swagger/openapi JSON spec."
        )
        rest_layout.addWidget(swagger_btn, 1, 1)

        rest_card.layout().addLayout(rest_layout)
        layout.addWidget(rest_card)

        layout.addStretch()

        return scroll

    def show_api_fuzz_menu(self, button, pos):
        """Right-click menu for API Fuzzing: quick wordlist swap or full manual edit."""
        from PyQt6.QtWidgets import QMenu, QFileDialog
        import re as _re

        menu = QMenu(self)
        menu.setObjectName("contextMenu")
        try:
            self.apply_theme_to_menu(menu)
        except Exception:
            pass

        wordlist_action = menu.addAction("📄 Manually Configure API Wordlist")
        edit_action = menu.addAction("✏️ Manually Modify Underlying Command")

        action = menu.exec(button.mapToGlobal(pos))
        if action == wordlist_action:
            path, _ = QFileDialog.getOpenFileName(
                self, "Select API wordlist",
                "/usr/share/seclists/Discovery/Web-Content/api",
                "Text Files (*.txt);;All Files (*)",
            )
            if not path:
                return
            current_cmd = self.command_registry.get(
                "api_ffuf",
                "ffuf -u '{TARGET}/api/FUZZ' -w /usr/share/seclists/Discovery/"
                "Web-Content/api/api-endpoints.txt -ac -s -of json -o {SAFE_TARGET}_api_fuzz_raw.json; "
                "python3 {CB_DIR}/command_bridge/modules/ffuf_clean.py "
                "{SAFE_TARGET}_api_fuzz_raw.json {SAFE_TARGET}_api_fuzz.txt",
            )
            new_cmd, n = _re.subn(r"-w\s+\S+", f"-w '{path}'", current_cmd, count=1)
            if n == 0:
                new_cmd = current_cmd.rstrip() + f" -w '{path}'"
            self.command_registry["api_ffuf"] = new_cmd
            self.save_custom_commands()
            try:
                tt = self._build_tooltip_from_command("API Fuzzing", new_cmd)
                if tt:
                    button.setToolTip(tt)
            except Exception:
                pass
            self.show_themed_message("API Wordlist Updated", f"API Fuzzing wordlist set to:\n{path}")
        elif action == edit_action:
            self.open_command_edit_dialog(button, "api_ffuf", self.command_registry.get("api_ffuf", ""))
