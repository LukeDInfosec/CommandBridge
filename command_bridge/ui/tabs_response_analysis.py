"""
Response Analysis tab — static analysis of a pasted raw HTTP response.

Companion to the Request Analysis tab: paste a raw HTTP response and get
missing/misconfigured security header findings, CORS misconfiguration,
verbose error/sensitive data disclosure, insecure cookie flags, and more —
each with a suggested test, remediation and (where useful) a ready PoC.
Findings already surfaced this session are suppressed on later responses so
pasting several responses from the same target doesn't keep re-flagging the
same site-wide issue; 'Clear Identified Findings' resets that history.
"""
from PyQt6.QtCore import Qt
from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QPushButton, QPlainTextEdit,
    QListWidget, QScrollArea, QFrame, QSplitter,
)

from command_bridge.ui.tabs_request_analysis import _mono


class ResponseAnalysisTabMixin:
    """Mixin providing the Response Analysis tab creator."""

    def create_response_analysis_tab(self):
        widget = QWidget()
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QFrame.Shape.NoFrame)
        scroll.setWidget(widget)
        layout = QVBoxLayout(widget)
        layout.setContentsMargins(25, 25, 25, 25)
        layout.setSpacing(16)

        intro = QLabel(
            "Paste a raw HTTP response (from Burp, devtools, curl -i, or a proxy log). "
            "Command Bridge statically checks it against best-practice security headers "
            "(HSTS, CSP, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, "
            "Permissions-Policy), CORS misconfiguration (wildcard origin, wildcard + "
            "credentials, reflected allow-lists), insecure cookie flags, verbose "
            "errors/stack traces, directory listings, leaked secrets/keys/tokens, weak "
            "caching of sensitive data, risky advertised HTTP methods and more — each with "
            "a suggested test and remediation. Nothing is sent; findings require manual "
            "validation. Findings already shown this session are suppressed on later "
            "responses so pasting several responses from the same target doesn't repeat "
            "the same site-wide issue — use 'Clear Identified Findings' to see them again."
        )
        intro.setWordWrap(True)
        intro.setObjectName("autoDesc")
        layout.addWidget(intro)

        splitter = QSplitter(Qt.Orientation.Horizontal)

        # ── Left: Original Response ─────────────────────────────────────────
        left_card = self.create_card("Original Response")
        left_inner = QVBoxLayout()
        self.resp_input = _mono(QPlainTextEdit())
        self.resp_input.setPlaceholderText(
            "HTTP/1.1 200 OK\n"
            "Server: nginx/1.18.0\n"
            "Content-Type: application/json\n"
            "Access-Control-Allow-Origin: *\n"
            "Set-Cookie: sessionid=abc123; Path=/\n\n"
            "{\n  \"firstName\": \"Luke\"\n}"
        )
        self.resp_input.setMinimumHeight(420)
        left_inner.addWidget(self.resp_input)

        left_btns = QHBoxLayout()
        analyse_btn = QPushButton("Analyse Response")
        analyse_btn.setObjectName("primaryButton")
        analyse_btn.setMinimumHeight(40)
        analyse_btn.clicked.connect(self.analyse_response)
        left_btns.addWidget(analyse_btn)

        clear_btn = QPushButton("Clear")
        clear_btn.setObjectName("secondaryButton")
        clear_btn.setMinimumHeight(40)
        clear_btn.clicked.connect(self.clear_response)
        left_btns.addWidget(clear_btn)

        copy_orig_btn = QPushButton("Copy Original Response")
        copy_orig_btn.setObjectName("secondaryButton")
        copy_orig_btn.setMinimumHeight(40)
        copy_orig_btn.clicked.connect(self.copy_original_response)
        left_btns.addWidget(copy_orig_btn)

        left_inner.addLayout(left_btns)

        clear_identified_btn = QPushButton("🧹 Clear Identified Findings (this session)")
        clear_identified_btn.setObjectName("secondaryButton")
        clear_identified_btn.setMinimumHeight(36)
        clear_identified_btn.setToolTip(
            "Resets the 'already identified' history for this session. Findings that were "
            "suppressed because they were already flagged on an earlier response you pasted "
            "will show up again the next time you click Analyse Response. Saved reports "
            "always include every finding from the current response regardless of this."
        )
        clear_identified_btn.clicked.connect(self.clear_identified_findings)
        left_inner.addWidget(clear_identified_btn)

        left_card.layout().addLayout(left_inner)

        # ── Right: Analysis / Finding Detail ────────────────────────────────
        right_card = self.create_card("Analysis / Finding Detail")
        right_inner = QVBoxLayout()

        sum_lbl = QLabel("Response Summary")
        sum_lbl.setObjectName("sectionDivider")
        right_inner.addWidget(sum_lbl)
        self.resp_summary = _mono(QPlainTextEdit())
        self.resp_summary.setReadOnly(True)
        self.resp_summary.setMinimumHeight(190)
        right_inner.addWidget(self.resp_summary)

        vec_lbl = QLabel("Detected Issues  (select one for detail, PoC & remediation)")
        vec_lbl.setObjectName("sectionDivider")
        right_inner.addWidget(vec_lbl)
        self.resp_vectors = QListWidget()
        self.resp_vectors.setMinimumHeight(140)
        self.resp_vectors.currentRowChanged.connect(self._on_resp_vector_selected)
        right_inner.addWidget(self.resp_vectors)

        self.resp_detail = QLabel("")
        self.resp_detail.setWordWrap(True)
        self.resp_detail.setObjectName("autoDesc")
        self.resp_detail.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
        right_inner.addWidget(self.resp_detail)

        out_lbl = QLabel("PoC / Example (where applicable)")
        out_lbl.setObjectName("sectionDivider")
        right_inner.addWidget(out_lbl)
        self.resp_output = _mono(QPlainTextEdit())
        self.resp_output.setMinimumHeight(160)
        right_inner.addWidget(self.resp_output)

        right_btns = QHBoxLayout()
        copy_out_btn = QPushButton("Copy Finding Detail / PoC")
        copy_out_btn.setObjectName("primaryButton")
        copy_out_btn.setMinimumHeight(40)
        copy_out_btn.clicked.connect(self.copy_response_finding_detail)
        right_btns.addWidget(copy_out_btn)

        save_btn = QPushButton("Save Analysis")
        save_btn.setObjectName("secondaryButton")
        save_btn.setMinimumHeight(40)
        save_btn.clicked.connect(self.save_response_analysis)
        right_btns.addWidget(save_btn)

        right_inner.addLayout(right_btns)
        right_card.layout().addLayout(right_inner)

        splitter.addWidget(left_card)
        splitter.addWidget(right_card)
        splitter.setSizes([520, 620])
        layout.addWidget(splitter)

        return scroll
