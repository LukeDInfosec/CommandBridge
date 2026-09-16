"""
GraphQL tooling — graphw00f command builder + right-click flag menu.

graphw00f is an engine fingerprinting tool (NOT a field fuzzer — the button
used to be mislabeled "Field Fuzzing"). Real CLI usage:

    Usage: main.py -d -f -t http://example.com
    -r, --noredirect        Do not follow 3xx redirects
    -t URL, --target=URL    target url with the path
    -f, --fingerprint       fingerprint mode
    -d, --detect            detect mode
    -p PROXY, --proxy=PROXY
    -T TIMEOUT, --timeout=TIMEOUT
    -o OUTPUT_FILE, --output-file=OUTPUT_FILE   Output results to a file (CSV)
    -l, --list              List all GraphQL technologies graphw00f can detect
    -u USERAGENT, --user-agent=USERAGENT
    -H HEADER, --header=HEADER   e.g. "Authorization: Bearer ey..."
    -w WORDLIST, --wordlist=WORDLIST   Path to a list of custom GraphQL endpoints
    -v, --version

At least one of -d/-f is required — the previous default command omitted
both, which is why it always failed with the usage banner.
"""
from PyQt6.QtWidgets import QMessageBox


class GraphqlToolsMixin:
    """Mixin providing the graphw00f command builder and its right-click menu."""

    # ── graphw00f ────────────────────────────────────────────────────────────

    _GRAPHW00F_MODE_FLAGS = {
        "detect": "-d",
        "fingerprint": "-f",
        "detect_fingerprint": "-d -f",
    }

    def _build_graphw00f_command(self) -> str:
        """Build the graphw00f command from the current right-click overrides.

        Called fresh every run (like SmartFuzz) so it always reflects the
        latest mode/header/wordlist/proxy/timeout choice — no stale stored
        command to fall out of sync with the menu.
        """
        manual = self.command_registry.get("graphw00f_manual")
        if manual:
            return manual

        mode = self.command_registry.get("graphw00f_mode", "detect_fingerprint")
        mode_flags = self._GRAPHW00F_MODE_FLAGS.get(mode, "-d -f")

        cmd = f"graphw00f {mode_flags} -t '{{TARGET}}'"

        header = self.command_registry.get("graphw00f_header")
        if header:
            escaped = header.replace("'", "'\\''")
            cmd += f" -H '{escaped}'"

        wordlist = self.command_registry.get("graphw00f_wordlist")
        if wordlist:
            cmd += f" -w '{wordlist}'"

        proxy = self.command_registry.get("graphw00f_proxy")
        if proxy:
            cmd += f" -p '{proxy}'"

        timeout = self.command_registry.get("graphw00f_timeout")
        if timeout:
            cmd += f" -T {timeout}"

        cmd += " -o {SAFE_TARGET}_graphw00f.csv"
        return cmd

    def run_graphw00f(self):
        """Left-click: (re)build the command from current overrides and run it."""
        cmd = self._build_graphw00f_command()
        try:
            self.console.append_ansi(f"\n[i] graphw00f command:\n    {cmd}\n\n")
        except Exception:
            pass
        self.run_command_template(cmd)

    def _graphw00f_menu_active_summary(self) -> str:
        mode = self.command_registry.get("graphw00f_mode", "detect_fingerprint")
        mode_label = {"detect": "Detect only", "fingerprint": "Fingerprint only",
                      "detect_fingerprint": "Detect + Fingerprint"}.get(mode, mode)
        lines = [f"Mode: {mode_label}"]
        for key, label in (
            ("graphw00f_header", "Header"),
            ("graphw00f_wordlist", "Wordlist"),
            ("graphw00f_proxy", "Proxy"),
            ("graphw00f_timeout", "Timeout"),
        ):
            val = self.command_registry.get(key)
            if val:
                lines.append(f"{label}: {val}")
        if self.command_registry.get("graphw00f_manual"):
            lines.append("(manual command override active — structured options ignored)")
        return "\n".join(lines)

    def show_graphw00f_menu(self, pos):
        """Right-click menu: all of graphw00f's real flags as quick options,
        so the button is an all-in-one control surface rather than one fixed
        invocation that needs a terminal for anything else."""
        from PyQt6.QtWidgets import QMenu, QFileDialog, QInputDialog

        menu = QMenu(self)
        menu.setObjectName("contextMenu")
        try:
            self.apply_theme_to_menu(menu)
        except Exception:
            pass

        title = menu.addAction("🧬 graphw00f Options")
        title.setEnabled(False)
        menu.addSeparator()

        mode_hdr = menu.addAction("Scan Mode")
        mode_hdr.setEnabled(False)
        cur_mode = self.command_registry.get("graphw00f_mode", "detect_fingerprint")
        detect_action = menu.addAction("   Detect Only (-d)" + ("  ✓" if cur_mode == "detect" else ""))
        fp_action = menu.addAction("   Fingerprint Only (-f)" + ("  ✓" if cur_mode == "fingerprint" else ""))
        both_action = menu.addAction("   Detect + Fingerprint (-d -f)" + ("  ✓" if cur_mode == "detect_fingerprint" else ""))

        menu.addSeparator()
        header_action = menu.addAction("🔑 Set Custom Header (-H, e.g. Authorization)")
        wordlist_action = menu.addAction("📄 Set Custom Endpoint Wordlist (-w)")
        proxy_action = menu.addAction("🌐 Set Proxy (-p)")
        timeout_action = menu.addAction("⏱️  Set Timeout (-T)")
        list_action = menu.addAction("📋 List Detectable Technologies (-l)")

        menu.addSeparator()
        summary_action = menu.addAction("ℹ️  Show Current Options")
        reset_action = menu.addAction("🔄 Reset All Overrides")
        edit_action = menu.addAction("✏️ Manually Modify Underlying Command")

        btn = getattr(self, "graphw00f_btn", None)
        global_pos = btn.mapToGlobal(pos) if btn is not None else self.mapToGlobal(pos)
        action = menu.exec(global_pos)
        if action is None:
            return

        if action == detect_action:
            self.command_registry["graphw00f_mode"] = "detect"
        elif action == fp_action:
            self.command_registry["graphw00f_mode"] = "fingerprint"
        elif action == both_action:
            self.command_registry["graphw00f_mode"] = "detect_fingerprint"
        elif action == header_action:
            text, ok = QInputDialog.getText(
                self, "graphw00f Custom Header",
                "Header (e.g. Authorization: Bearer eyJhbGci...):",
            )
            if ok and text.strip():
                self.command_registry["graphw00f_header"] = text.strip()
        elif action == wordlist_action:
            path, _ = QFileDialog.getOpenFileName(
                self, "Select custom GraphQL endpoint wordlist",
                "/usr/share/seclists/Discovery/Web-Content",
                "Text Files (*.txt);;All Files (*)",
            )
            if path:
                self.command_registry["graphw00f_wordlist"] = path
        elif action == proxy_action:
            text, ok = QInputDialog.getText(
                self, "graphw00f Proxy", "Proxy URL (e.g. http://127.0.0.1:8080):",
            )
            if ok and text.strip():
                self.command_registry["graphw00f_proxy"] = text.strip()
        elif action == timeout_action:
            val, ok = QInputDialog.getInt(
                self, "graphw00f Timeout", "Request timeout (seconds):", 10, 1, 300, 1,
            )
            if ok:
                self.command_registry["graphw00f_timeout"] = str(val)
        elif action == list_action:
            self.run_command_template("graphw00f -l 2>&1 | tee {SAFE_TARGET}_graphw00f_technologies.txt")
            return
        elif action == summary_action:
            self.show_themed_message("graphw00f — Current Options", self._graphw00f_menu_active_summary())
            return
        elif action == reset_action:
            for key in ("graphw00f_mode", "graphw00f_header", "graphw00f_wordlist",
                        "graphw00f_proxy", "graphw00f_timeout", "graphw00f_manual"):
                self.command_registry.pop(key, None)
        elif action == edit_action:
            btn_ref = getattr(self, "graphw00f_btn", None)
            self.open_command_edit_dialog(btn_ref, "graphw00f_manual", self._build_graphw00f_command())
            self.save_custom_commands()
            return
        else:
            return

        self.save_custom_commands()
        try:
            btn_ref = getattr(self, "graphw00f_btn", None)
            if btn_ref is not None:
                tt = self._build_tooltip_from_command("GraphQL Engine Fingerprint (graphw00f)", self._build_graphw00f_command())
                btn_ref.setToolTip(self._graphw00f_base_tooltip() + "\n\n" + tt)
        except Exception:
            pass

    def _graphw00f_base_tooltip(self) -> str:
        return (
            "graphw00f — GraphQL engine fingerprinting (not a fuzzer). Identifies\n"
            "which GraphQL server implementation is running (Apollo, Hasura,\n"
            "Graphene, etc.) via detect mode (-d) and/or deeper fingerprint mode\n"
            "(-f), so you know which engine-specific attacks apply.\n\n"
            "Right-click for all options: mode, custom header (auth), custom\n"
            "endpoint wordlist, proxy, timeout, and the full technology list —\n"
            "no need to drop to a terminal for anything this tool supports."
        )
