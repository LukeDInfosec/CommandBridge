"""
Request Analysis tab — Burp-Repeater-style static analysis of a pasted request.
"""
from PyQt6 import QtGui
from PyQt6.QtCore import Qt
from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QPushButton, QPlainTextEdit,
    QListWidget, QScrollArea, QFrame, QSplitter,
)


def _mono(widget):
    f = QtGui.QFont()
    f.setFamilies(["Cascadia Code", "JetBrains Mono", "Fira Code", "Consolas", "Monospace"])
    f.setPointSize(10)
    widget.setFont(f)
    return widget


class RequestAnalysisTabMixin:
    """Mixin providing the Request Analysis tab creator."""

    def create_request_analysis_tab(self):
        widget = QWidget()
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QFrame.Shape.NoFrame)
        scroll.setWidget(widget)
        layout = QVBoxLayout(widget)
        layout.setContentsMargins(25, 25, 25, 25)
        layout.setSpacing(16)

        intro = QLabel(
            "Paste a raw HTTP request (from Burp, devtools, an API client or proxy logs). "
            "Command Bridge statically analyses it and suggests web/API test points "
            "(IDOR, mass assignment, broken access control, parameter tampering, open redirect, "
            "SSRF, SQLi/NoSQLi, XSS, upload, traversal, GraphQL, XXE, CSRF, host-header, etc.) "
            "and generates a modified request to paste into Burp Repeater. Nothing is sent — "
            "all findings are suggestions requiring manual validation on authorised targets."
        )
        intro.setWordWrap(True)
        intro.setObjectName("autoDesc")
        layout.addWidget(intro)

        splitter = QSplitter(Qt.Orientation.Horizontal)

        # ── Left: Original Request ──────────────────────────────────────────
        left_card = self.create_card("Original Request")
        left_inner = QVBoxLayout()
        self.ra_input = _mono(QPlainTextEdit())
        self.ra_input.setPlaceholderText(
            "POST /api/v1/users/123/profile HTTP/2\n"
            "Host: example.com\n"
            "Cookie: sessionid=abc123; role=user\n"
            "Authorization: Bearer eyJhbGciOiJIUzI1NiIs...\n"
            "Content-Type: application/json\n\n"
            "{\n  \"firstName\": \"Luke\"\n}"
        )
        self.ra_input.setMinimumHeight(420)
        left_inner.addWidget(self.ra_input)

        left_btns = QHBoxLayout()
        analyse_btn = QPushButton("Analyse Request")
        analyse_btn.setObjectName("primaryButton")
        analyse_btn.setMinimumHeight(40)
        analyse_btn.clicked.connect(self.analyse_request)
        left_btns.addWidget(analyse_btn)

        clear_btn = QPushButton("Clear")
        clear_btn.setObjectName("secondaryButton")
        clear_btn.setMinimumHeight(40)
        clear_btn.clicked.connect(self.clear_request)
        left_btns.addWidget(clear_btn)

        copy_orig_btn = QPushButton("Copy Original Request")
        copy_orig_btn.setObjectName("secondaryButton")
        copy_orig_btn.setMinimumHeight(40)
        copy_orig_btn.clicked.connect(self.copy_original_request)
        left_btns.addWidget(copy_orig_btn)

        left_inner.addLayout(left_btns)
        left_card.layout().addLayout(left_inner)

        # ── Right: Analysis / Modified Request ──────────────────────────────
        right_card = self.create_card("Analysis / Modified Request")
        right_inner = QVBoxLayout()

        sum_lbl = QLabel("Request Summary")
        sum_lbl.setObjectName("sectionDivider")
        right_inner.addWidget(sum_lbl)
        self.ra_summary = _mono(QPlainTextEdit())
        self.ra_summary.setReadOnly(True)
        self.ra_summary.setMinimumHeight(190)
        right_inner.addWidget(self.ra_summary)

        vec_lbl = QLabel("Detected Attack Vectors  (select one to generate a modified request)")
        vec_lbl.setObjectName("sectionDivider")
        right_inner.addWidget(vec_lbl)
        self.ra_vectors = QListWidget()
        self.ra_vectors.setMinimumHeight(140)
        self.ra_vectors.currentRowChanged.connect(self._on_ra_vector_selected)
        right_inner.addWidget(self.ra_vectors)

        self.ra_detail = QLabel("")
        self.ra_detail.setWordWrap(True)
        self.ra_detail.setObjectName("autoDesc")
        self.ra_detail.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
        right_inner.addWidget(self.ra_detail)

        mod_lbl = QLabel("Modified Request Output")
        mod_lbl.setObjectName("sectionDivider")
        right_inner.addWidget(mod_lbl)
        self.ra_modified = _mono(QPlainTextEdit())
        self.ra_modified.setMinimumHeight(220)
        right_inner.addWidget(self.ra_modified)

        right_btns = QHBoxLayout()
        copy_mod_btn = QPushButton("Copy Modified Request")
        copy_mod_btn.setObjectName("primaryButton")
        copy_mod_btn.setMinimumHeight(40)
        copy_mod_btn.clicked.connect(self.copy_modified_request)
        right_btns.addWidget(copy_mod_btn)

        save_btn = QPushButton("Save Analysis")
        save_btn.setObjectName("secondaryButton")
        save_btn.setMinimumHeight(40)
        save_btn.clicked.connect(self.save_request_analysis)
        right_btns.addWidget(save_btn)

        right_inner.addLayout(right_btns)
        right_card.layout().addLayout(right_inner)

        splitter.addWidget(left_card)
        splitter.addWidget(right_card)
        splitter.setSizes([520, 620])
        layout.addWidget(splitter)

        return scroll
