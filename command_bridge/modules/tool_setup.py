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
            "bash {CB_DIR}/command_bridge/modules/install_tools.sh --check-only"
        )

    def run_install_tools(self):
        """Best-effort install/repair for every missing or broken tool."""
        self.run_raw_command(
            "bash {CB_DIR}/command_bridge/modules/install_tools.sh"
        )
