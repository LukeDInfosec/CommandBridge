"""Application entry point."""

import sys
import traceback
from datetime import datetime
from pathlib import Path

from PyQt6.QtGui import QFont
from PyQt6.QtWidgets import QApplication

from command_bridge.constants import APP_TITLE, APP_VERSION
# The window is imported inside main(), not here. A half-finished update
# breaks at import time — one module expecting another that has not arrived —
# and an import error at module scope happens before there is a QApplication
# to show it with, so the process dies with nothing on screen.

ERROR_LOG = Path.home() / ".config" / "CommandBridge" / "errors.log"


def _install_exception_guard(app: QApplication) -> None:
    """Keep one bad line from killing a running engagement.

    PyQt6 routes an unhandled Python exception raised inside a slot to
    sys.excepthook and then calls abort() — the window simply disappears,
    mid-scan, with nothing on screen to explain it. Since every button in this
    app is a slot, a single typo in a rarely-hit branch could take down a
    session that had been running for an hour.

    This replaces that behaviour: log the traceback, show it in the console
    pane if one exists, and keep the event loop alive. A broken feature then
    costs you one red message instead of the whole application.
    """
    def hook(exc_type, exc, tb):
        if issubclass(exc_type, KeyboardInterrupt):
            sys.__excepthook__(exc_type, exc, tb)
            return

        text = "".join(traceback.format_exception(exc_type, exc, tb))
        stamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        try:
            ERROR_LOG.parent.mkdir(parents=True, exist_ok=True)
            with open(ERROR_LOG, "a", encoding="utf-8") as fh:
                fh.write(f"\n===== {stamp} =====\n{text}")
        except Exception:
            pass

        sys.stderr.write(text)

        # Surface it where the user is already looking.
        try:
            for widget in app.topLevelWidgets():
                console = getattr(widget, "console", None)
                if console is None or not hasattr(console, "append_html"):
                    continue
                summary = f"{exc_type.__name__}: {exc}"
                console.append_html(
                    '<br><span style="color:#f04d5b;font-weight:bold;">'
                    f'[internal error] {_escape(summary)}</span><br>'
                    '<span style="color:#949daf;">The action was cancelled; '
                    'the app is still running. Details in '
                    f'{_escape(str(ERROR_LOG))}</span><br>'
                )
                break
        except Exception:
            pass

    sys.excepthook = hook


def _escape(value: str) -> str:
    from html import escape
    return escape(str(value))


def _install_base_font(app: QApplication) -> None:
    """Pick the best available UI font instead of inheriting the desktop's.

    Distro defaults vary wildly (DejaVu Sans on a stock Kali is noticeably
    wider and heavier than the design targets), so walk a preference list and
    use the first family that is actually installed.
    """
    from PyQt6.QtGui import QFontDatabase

    families = set(QFontDatabase.families())
    for candidate in ("Inter", "SF Pro Text", "Segoe UI", "Ubuntu",
                      "Cantarell", "Noto Sans", "DejaVu Sans"):
        if candidate in families:
            font = QFont(candidate)
            font.setPointSize(10)
            font.setHintingPreference(QFont.HintingPreference.PreferFullHinting)
            app.setFont(font)
            return


def main():
    app = QApplication(sys.argv)
    app.setApplicationName(APP_TITLE)
    app.setApplicationVersion(APP_VERSION)
    app.setOrganizationName("Command Bridge")
    app.setDesktopFileName("command-bridge")

    # Fusion gives every distro the same widget metrics to style against;
    # without it the stylesheet lands differently on GTK vs Breeze systems.
    app.setStyle("Fusion")
    _install_base_font(app)
    _install_exception_guard(app)

    try:
        from command_bridge.ui.window import CommandBridgeV5
        window = CommandBridgeV5()
    except Exception:
        # The window failing to construct is the one error the user cannot
        # see: PyQt tears the process down and nothing appears on screen, so
        # "it won't open" is all they have to go on. Show them the reason.
        _report_startup_failure(traceback.format_exc())
        sys.exit(1)

    window.show()
    sys.exit(app.exec())


def _report_startup_failure(trace: str) -> None:
    """Put a startup crash on screen, in the log, and on stderr."""
    from PyQt6.QtWidgets import QMessageBox, QApplication

    stamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    try:
        ERROR_LOG.parent.mkdir(parents=True, exist_ok=True)
        with open(ERROR_LOG, "a", encoding="utf-8") as handle:
            handle.write(f"\n===== {stamp} startup failed =====\n{trace}")
    except Exception:
        pass
    sys.stderr.write(trace)

    hint = ""
    if "ModuleNotFoundError" in trace or "ImportError" in trace:
        # By far the most likely cause: an update that only half arrived, so
        # one file expects another that is not there yet.
        hint = ("\n\nThis looks like a half-finished update — a file is "
                "importing something that is not in the checkout. Run "
                "`git pull` again from the Command Bridge folder, then start "
                "it once more.")

    box = QMessageBox()
    box.setIcon(QMessageBox.Icon.Critical)
    box.setWindowTitle("Command Bridge could not start")
    box.setText("Command Bridge could not start." + hint)
    box.setInformativeText(f"The full error is in {ERROR_LOG}")
    box.setDetailedText(trace)
    box.exec()


if __name__ == "__main__":
    main()
