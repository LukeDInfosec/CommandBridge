"""
API tab behaviour — the rate-limit request editor and the API fuzz menu.

The rate-limit button used to fire bare GETs at {TARGET}/api, which against
an endpoint that needs a method, a content type, auth or a body produced a
wall of identical 4xx responses and a confident verdict drawn from nothing.
It now opens an editor: paste the request you already know works — straight
out of Burp, or "Copy as cURL" from DevTools — and that gets replayed.
"""

from pathlib import Path

from PyQt6 import QtGui
from PyQt6.QtCore import Qt
from PyQt6.QtWidgets import (
    QDialog, QVBoxLayout, QHBoxLayout, QLabel, QPlainTextEdit, QSpinBox,
    QDialogButtonBox, QMenu, QFileDialog, QMessageBox, QCheckBox,
)

#: Curated lists offered in the fuzz menu. Each is (label, path). Paths are
#: checked at menu build time so the menu only offers what is installed.
CURATED_WORDLISTS = [
    ("API endpoints (SecLists)",
     "/usr/share/seclists/Discovery/Web-Content/api/api-endpoints.txt"),
    ("API endpoints — extended",
     "/usr/share/seclists/Discovery/Web-Content/api/api-endpoints-res.txt"),
    ("API actions",
     "/usr/share/seclists/Discovery/Web-Content/api/actions.txt"),
    ("API objects",
     "/usr/share/seclists/Discovery/Web-Content/api/objects.txt"),
    ("Seen in the wild",
     "/usr/share/seclists/Discovery/Web-Content/api/api-seen-in-wild.txt"),
    ("Common API endpoints (mazen160)",
     "/usr/share/seclists/Discovery/Web-Content/common-api-endpoints-mazen160.txt"),
    ("Swagger / spec paths",
     "/usr/share/seclists/Discovery/Web-Content/swagger.txt"),
    ("GraphQL paths",
     "/usr/share/seclists/Discovery/Web-Content/graphql.txt"),
]

REQUEST_PLACEHOLDER = """Paste the request here. Either form works.

Raw HTTP — Burp/ZAP → Copy to file:

    POST /Service.svc HTTP/1.1
    Host: api.example.co.uk
    Content-Type: application/soap+xml; charset=utf-8
    Authorization: Bearer eyJhbGciOi...

    <soap:Envelope xmlns:soap="http://www.w3.org/2003/05/soap-envelope">
      <soap:Body><GetBalance><AccountId>1</AccountId></GetBalance></soap:Body>
    </soap:Envelope>

or a curl command — DevTools → Copy as cURL:

    curl 'https://api.example.co.uk/v1/orders' -H 'Authorization: Bearer ...' \\
      -H 'Content-Type: application/json' --data-raw '{"id":1}'

Use a request you know returns a success. The test sends one on its own first
and stops if it is rejected — 150 identical 400s prove nothing about rate
limiting."""


class ApiTestingMixin:
    """Mixin providing the API tab's interactive buttons."""

    # ── Rate limiting ────────────────────────────────────────────────────
    def _rate_limit_request_path(self) -> Path:
        """Where the pasted request is kept between runs."""
        config_dir = Path.home() / ".config" / "CommandBridge"
        config_dir.mkdir(parents=True, exist_ok=True)
        return config_dir / "rate_limit_request.txt"

    def open_rate_limit_dialog(self):
        """Ask for the request to replay, then run the tester against it."""
        dialog = QDialog(self)
        dialog.setWindowTitle("Rate Limiting — request to replay")
        dialog.resize(900, 620)
        try:
            self.apply_theme_to_dialog(dialog)
        except Exception:
            pass

        layout = QVBoxLayout(dialog)

        intro = QLabel(
            "Paste a request that you know succeeds — raw HTTP from a proxy, or a "
            "curl command from DevTools. It is sent once on its own to confirm it "
            "is accepted, then replayed to see whether the endpoint throttles."
        )
        intro.setWordWrap(True)
        intro.setObjectName("autoDesc")
        layout.addWidget(intro)

        editor = QPlainTextEdit()
        editor.setPlaceholderText(REQUEST_PLACEHOLDER)
        editor.setMinimumHeight(340)
        saved = self._rate_limit_request_path()
        if saved.exists():
            try:
                editor.setPlainText(saved.read_text(encoding="utf-8", errors="replace"))
            except OSError:
                pass
        layout.addWidget(editor)

        controls = QHBoxLayout()

        controls.addWidget(QLabel("Requests:"))
        requests_spin = QSpinBox()
        requests_spin.setRange(10, 2000)
        requests_spin.setValue(150)
        requests_spin.setToolTip(
            "How many copies of the request to send. 150 is enough to trip a "
            "typical limiter without being a load test."
        )
        controls.addWidget(requests_spin)

        controls.addSpacing(16)
        controls.addWidget(QLabel("Concurrency:"))
        concurrency_spin = QSpinBox()
        concurrency_spin.setRange(1, 100)
        concurrency_spin.setValue(10)
        concurrency_spin.setToolTip("How many requests are in flight at once.")
        controls.addWidget(concurrency_spin)

        controls.addSpacing(16)
        allow_errors = QCheckBox("Run even if the first request fails")
        allow_errors.setToolTip(
            "By default the run stops when the baseline request is rejected, "
            "because 150 rejections say nothing about rate limiting. Tick this "
            "only if you specifically want to test the limiter in front of an "
            "error path."
        )
        controls.addWidget(allow_errors)
        controls.addStretch()
        layout.addLayout(controls)

        buttons = QDialogButtonBox(
            QDialogButtonBox.StandardButton.Ok | QDialogButtonBox.StandardButton.Cancel
        )
        buttons.button(QDialogButtonBox.StandardButton.Ok).setText("Run Test")
        buttons.accepted.connect(dialog.accept)
        buttons.rejected.connect(dialog.reject)
        layout.addWidget(buttons)

        if dialog.exec() != QDialog.DialogCode.Accepted:
            return

        text = editor.toPlainText().strip()
        if not text:
            self.show_themed_message(
                "Nothing to send",
                "Paste a request first — a raw HTTP request or a curl command.",
                QMessageBox.Icon.Warning,
            )
            return

        path = self._rate_limit_request_path()
        try:
            path.write_text(text, encoding="utf-8")
        except OSError as exc:
            self.show_themed_message(
                "Could not save the request", str(exc), QMessageBox.Icon.Critical
            )
            return

        command = (
            "python3 {CB_DIR}/command_bridge/modules/rate_limit_check.py "
            f"--request-file '{path}' "
            f"--requests {requests_spin.value()} "
            f"--concurrency {concurrency_spin.value()} "
            "--base-url '{TARGET}' "
            "--json-out {SAFE_TARGET}_ratelimit.json"
        )
        if allow_errors.isChecked():
            command += " --allow-error-baseline"
        command += " 2>&1 | tee {SAFE_TARGET}_ratelimit.txt"

        # run_raw_command rather than run_command_template: the request carries
        # its own URL, so this works with no target set.
        self.run_raw_command(command, label="Rate Limiting")

    # ── API fuzzing ──────────────────────────────────────────────────────
    def show_api_fuzz_menu(self, button, pos):
        """Right-click menu: pick curated lists, add your own, or edit the command."""
        menu = QMenu(self)
        menu.setObjectName("contextMenu")
        try:
            self.apply_theme_to_menu(menu)
        except Exception:
            pass

        heading = menu.addAction("Wordlists")
        heading.setEnabled(False)

        available = [(label, path) for label, path in CURATED_WORDLISTS
                     if Path(path).is_file()]
        actions = {}
        for label, path in available:
            action = menu.addAction(f"  {label}")
            actions[action] = path
        if not available:
            missing = menu.addAction("  (no SecLists wordlists found)")
            missing.setEnabled(False)

        menu.addSeparator()
        all_action = menu.addAction("Use every available list (slowest, most thorough)")
        custom_action = menu.addAction("Choose a wordlist file…")
        menu.addSeparator()
        soap_action = menu.addAction("Force SOAP mode (enumerate WSDL operations)")
        rest_action = menu.addAction("Force REST mode (path + verb fuzzing)")
        menu.addSeparator()
        edit_action = menu.addAction("Manually Modify Underlying Command")

        chosen = menu.exec(button.mapToGlobal(pos))
        if chosen is None:
            return

        if chosen == edit_action:
            self.open_command_edit_dialog(
                button, "api_ffuf", self.command_registry.get("api_ffuf", "")
            )
            return

        if chosen in (soap_action, rest_action):
            mode = "soap" if chosen == soap_action else "rest"
            self._set_api_fuzz_option(button, "--mode", mode)
            self.show_themed_message(
                "API Fuzzing mode set",
                f"API Fuzzing will run in {mode.upper()} mode.\n\n"
                + ("SOAP mode finds the WSDL and enumerates its operations — path "
                   "fuzzing is close to useless against a SOAP service."
                   if mode == "soap" else
                   "REST mode chains the wordlists, then fuzzes HTTP verbs against "
                   "whatever it finds."),
            )
            return

        if chosen == all_action:
            paths = ",".join(path for _, path in available)
            if not paths:
                self.show_themed_message(
                    "No wordlists found",
                    "Install SecLists first: sudo apt install -y seclists",
                    QMessageBox.Icon.Warning,
                )
                return
            self._set_api_fuzz_option(button, "--wordlists", paths)
            self.show_themed_message(
                "API Wordlists Updated",
                f"Using {len(available)} wordlist(s). Duplicates are removed before "
                "fuzzing, so overlap between lists costs nothing."
            )
            return

        if chosen == custom_action:
            path, _ = QFileDialog.getOpenFileName(
                self, "Select API wordlist",
                "/usr/share/seclists/Discovery/Web-Content",
                "Text Files (*.txt);;All Files (*)",
            )
            if not path:
                return
            self._set_api_fuzz_option(button, "--wordlists", path)
            self.show_themed_message("API Wordlist Updated", f"Wordlist set to:\n{path}")
            return

        if chosen in actions:
            path = actions[chosen]
            self._set_api_fuzz_option(button, "--wordlists", path)
            self.show_themed_message("API Wordlist Updated", f"Wordlist set to:\n{path}")

    def _set_api_fuzz_option(self, button, flag: str, value: str):
        """Set (or replace) one flag on the API fuzz command."""
        import re

        command = self.command_registry.get("api_ffuf", "")
        if not command:
            return
        pattern = rf"{re.escape(flag)}\s+'[^']*'|{re.escape(flag)}\s+\S+"
        replacement = f"{flag} '{value}'"
        updated, count = re.subn(pattern, replacement, command, count=1)
        if count == 0:
            # Insert before the shell redirection so the flag reaches the script.
            if " 2>&1" in updated:
                updated = updated.replace(" 2>&1", f" {replacement} 2>&1", 1)
            else:
                updated = updated.rstrip() + f" {replacement}"
        self.command_registry["api_ffuf"] = updated
        self.save_custom_commands()
        try:
            tooltip = self._build_tooltip_from_command("API Fuzzing", updated)
            if tooltip:
                button.setToolTip(tooltip)
        except Exception:
            pass
