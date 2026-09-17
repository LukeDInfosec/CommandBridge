"""
Environment / Tool Setup — check and (best-effort) install/repair every
external command-line tool the app's buttons shell out to.

See install_tools.sh in this same directory for the actual logic; this
module just wires it up to the two Target Setup tab buttons via
run_raw_command() (which, unlike run_command_template(), does not require a
target to already be set — there is nothing target-specific about checking
whether nmap is on PATH).
"""


class ToolSetupMixin:
    """Mixin providing the Check / Install-Repair Tools buttons."""

    def run_check_tools(self):
        """Scan PATH for every tool this app uses and report OK/MISSING/BROKEN.
        Makes no changes — safe to run at any time."""
        self.run_raw_command(
            "bash {CB_DIR}/command_bridge/modules/install_tools.sh --check-only",
            label="Tool Status Check",
        )

    def run_install_tools(self):
        """Best-effort install/repair for every missing or broken tool."""
        self.run_raw_command(
            "bash {CB_DIR}/command_bridge/modules/install_tools.sh",
            label="Tool Install / Repair",
        )

    def confirm_reset_all_commands(self):
        """Ask before discarding every saved command override, then do it."""
        from PyQt6.QtWidgets import QMessageBox

        overrides = [
            bid for bid, cmd in self.command_registry.items()
            if cmd != getattr(self, "default_commands", {}).get(bid, cmd)
        ]
        if not overrides:
            self.show_themed_message(
                "Nothing to reset",
                "Every button is already running the command that ships with "
                "this version.",
            )
            return

        labels = getattr(self, "button_labels", {})
        listed = "\n".join(f"    - {labels.get(bid, bid)}" for bid in sorted(overrides)[:20])
        if len(overrides) > 20:
            listed += f"\n    ... and {len(overrides) - 20} more"

        box = QMessageBox(self)
        box.setIcon(QMessageBox.Icon.Warning)
        box.setWindowTitle("Reset all commands?")
        box.setText(f"{len(overrides)} command(s) differ from the shipped versions.")
        box.setInformativeText(
            "Resetting replaces them with the commands that ship with this "
            "release. Any wordlist choices or manual edits you made will be "
            "lost.\n\nYour target, headers, theme and output directory are not "
            "affected."
        )
        box.setDetailedText(listed)
        reset = box.addButton("Reset all commands", QMessageBox.ButtonRole.DestructiveRole)
        box.addButton("Cancel", QMessageBox.ButtonRole.RejectRole)
        box.setDefaultButton(reset)
        try:
            self.apply_theme_to_dialog(box)
        except Exception:
            pass
        box.exec()
        if box.clickedButton() is not reset:
            return

        count = self.reset_all_commands_to_defaults()
        try:
            self.console.append_ansi(
                f"\n[+] Reset {count} command(s) to the versions shipped with this release.\n"
            )
        except Exception:
            pass
        self.show_themed_message(
            "Commands reset",
            f"{count} command(s) restored to their shipped versions.",
        )
