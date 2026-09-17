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

        # API Fuzzing. The old command ran ffuf once against one small path
        # list — a thin pass on REST, and worthless against SOAP, where the
        # service is a single URL and the attack surface is its operation
        # list. api_fuzz.py fingerprints the API first, chains several
        # wordlists for REST (deduplicated, soft-404 calibrated) and then
        # fuzzes HTTP verbs against what it finds, or parses the WSDL and
        # enumerates operations and SOAPActions for SOAP.
        api_fuzz_btn = self.create_editable_button(
            "API Fuzzing",
            "api_ffuf",
            "python3 {CB_DIR}/command_bridge/modules/api_fuzz.py '{TARGET}' "
            "--out {SAFE_TARGET}_api_fuzz.json 2>&1 | tee {SAFE_TARGET}_api_fuzz.txt",
        )
        api_fuzz_btn.setToolTip(
            "Fuzzes the API according to what it actually is.\n\n"
            "REST: chains several endpoint wordlists (deduplicated), calibrates\n"
            "against soft-404s, then fuzzes HTTP verbs on every endpoint found —\n"
            "a path that refuses GET but accepts PUT is broken access control that\n"
            "a GET-only sweep never sees.\n\n"
            "SOAP: finds the WSDL (?wsdl, ?singleWsdl, /service.svc?wsdl, ...) and\n"
            "enumerates its operations and SOAPAction values. Path fuzzing finds\n"
            "nothing against SOAP, which is why the old sweep finished in seconds.\n\n"
            "Right-click to pick wordlists, force REST or SOAP mode, or edit the\n"
            "command. Findings saved as JSON."
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

        # Rate Limiting. Firing bare GETs at {TARGET}/api meant that against
        # anything needing a method, content type, auth or a body, every
        # request was rejected identically and the verdict came from nothing.
        # This now opens an editor for a request known to work — pasted from
        # a proxy or copied as curl — and replays that.
        ratelimit_btn = QPushButton("Rate Limiting")
        ratelimit_btn.setObjectName("secondaryButton")
        ratelimit_btn.setMinimumHeight(40)
        ratelimit_btn.setCursor(QtGui.QCursor(QtCore.Qt.CursorShape.PointingHandCursor))
        ratelimit_btn.setToolTip(
            "Opens an editor to paste the request to replay — raw HTTP from Burp/ZAP,\n"
            "or a curl command copied from browser DevTools. Both are parsed for\n"
            "method, headers and body, so SOAP and authenticated JSON work.\n\n"
            "One request is sent on its own first to confirm it is accepted; if it is\n"
            "rejected the run stops and says so rather than reporting a verdict drawn\n"
            "from a hundred identical errors.\n\n"
            "Then a modest capped burst (adjustable) watches for 429/503 and\n"
            "Retry-After. A detection probe, not a load test. Writes a console table\n"
            "and a JSON report."
        )
        ratelimit_btn.clicked.connect(self.open_rate_limit_dialog)
        rest_layout.addWidget(ratelimit_btn, 1, 0)

        # Swagger/OpenAPI discovery. The previous shell loop only accepted a
        # JSON body, so a client saying "docs are at /swagger" — which serves
        # Swagger UI, an HTML page that loads the spec from somewhere else —
        # came back as "no documentation found". swagger_discover.py probes
        # the real spec paths, recognises a documentation UI and reads the
        # spec URL back out of it (including out of swagger-initializer.js),
        # and accepts YAML as well as JSON.
        swagger_cmd = (
            "python3 {CB_DIR}/command_bridge/modules/swagger_discover.py '{TARGET}' "
            "--out {SAFE_TARGET}_swagger.json 2>&1 | tee {SAFE_TARGET}_swagger_discovery.txt"
        )
        swagger_btn = self.create_editable_button(
            "Detect Swagger/OpenAPI Documentation", "api_swagger", swagger_cmd
        )
        swagger_btn.setToolTip(
            "Finds the API specification, not just the URL you typed.\n\n"
            "Tries the target itself, then ~20 common spec paths (/swagger.json,\n"
            "/openapi.json|yaml, /v2|v3/api-docs, /swagger/v1/swagger.json, ...).\n"
            "If it lands on a documentation UI instead — Swagger UI, Redoc, RapiDoc,\n"
            "Stoplight, Scalar — it reads the spec URL back out of the page and\n"
            "follows it, which is what makes a bare /swagger URL work.\n\n"
            "Accepts YAML specs as well as JSON. Only counts a document as a spec if\n"
            "it declares swagger/openapi, so an ordinary JSON response is not\n"
            "reported as documentation.\n\n"
            "Spec saved to <target>_swagger.json, full probe log alongside it."
        )
        rest_layout.addWidget(swagger_btn, 1, 1)

        rest_card.layout().addLayout(rest_layout)
        layout.addWidget(rest_card)

        layout.addStretch()

        return scroll

