#!/usr/bin/env python3
"""The window still builds, with the new tab and without the removed ones.

Runs offscreen, so it works over SSH and in CI. This is the test that catches a
mixin left out of the base list, a builder pointing at a method that no longer
exists, or a tab key in TABS with nothing to build it — none of which show up
until the application is started.
"""

import os
import sys
from pathlib import Path

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

PASS = FAIL = 0


def check(label, got, want=True):
    global PASS, FAIL
    if got == want:
        PASS += 1
        print(f"  \033[32m✓\033[0m {label}")
    else:
        FAIL += 1
        print(f"  \033[31m✗\033[0m {label}  (got {got!r}, wanted {want!r})")


def main():
    from PyQt6.QtWidgets import QApplication, QPushButton, QLabel
    from command_bridge.constants import TABS, RAIL_SECTIONS
    from command_bridge.ui.navigation import _TAB_BUILDERS, _SAFE_BUILD_ORDER
    from command_bridge.ui.window import CommandBridgeV5

    print("\n\033[1mThe tab registry agrees with itself\033[0m")
    keys = [row[0] for row in TABS]
    check("every tab has a builder",
          [k for k in keys if k not in _TAB_BUILDERS], [])
    check("every builder has a tab",
          [k for k in _TAB_BUILDERS if k not in keys], [])
    check("every tab is in the build order",
          sorted(keys), sorted(_SAFE_BUILD_ORDER))
    check("every section named by a tab exists",
          [row[5] for row in TABS if row[5] not in RAIL_SECTIONS + ["PINNED"]],
          [])

    print("\n\033[1mCoffee Break is registered\033[0m")
    check("it is in TABS", "coffee" in keys)
    check("its builder is named", _TAB_BUILDERS.get("coffee"),
          "create_coffee_break_tab")
    check("the window class has the builder",
          hasattr(CommandBridgeV5, "create_coffee_break_tab"))
    check("and the engine", hasattr(CommandBridgeV5, "start_coffee_break"))

    print("\n\033[1mThe analysis tabs are gone\033[0m")
    check("no request tab", "request" in keys, False)
    check("no response tab", "response" in keys, False)
    check("no request builder", "request" in _TAB_BUILDERS, False)
    check("no response builder", "response" in _TAB_BUILDERS, False)
    check("the window has no request analyser",
          hasattr(CommandBridgeV5, "analyse_request"), False)
    check("the window has no response analyser",
          hasattr(CommandBridgeV5, "analyse_response"), False)

    print("\n\033[1mThe window builds\033[0m")
    app = QApplication.instance() or QApplication(sys.argv)
    window = CommandBridgeV5()
    check("it constructed", window is not None)
    check("every tab produced a widget",
          window.tab_widget.count(), len(TABS))
    check("the coffee tab is addressable",
          isinstance(window.tab_index("coffee"), int))

    window.goto_tab("coffee")
    check("and can be shown",
          window.tab_widget.currentIndex(), window.tab_index("coffee"))
    check("its findings table exists", window.cb_table.columnCount(), 5)
    check("it starts empty", window.cb_table.rowCount(), 0)

    print("\n\033[1mThe Coffee Break button is on the Web page\033[0m")
    buttons = [b.text() for b in window.findChildren(QPushButton)]
    check("the button is there",
          any("Coffee Break" in text for text in buttons))

    print("\n\033[1mThe duplicated SQL buttons are gone\033[0m")
    check("the headline button is kept",
          any("Extensive SQLMap" in text for text in buttons))
    for gone in ("Tamper: space2comment", "Union-Based", "OS Shell Attempt",
                 "Error-Based", "Boolean-Based"):
        check(f"{gone!r} is removed", any(gone in t for t in buttons), False)

    print("\n\033[1mFindings render into the table\033[0m")
    from command_bridge.modules.coffee_break import CBFinding
    window._cb_ui_reset(
        [{"key": "headers", "name": "HTTP and security headers"},
         {"key": "nuclei", "name": "Nuclei templates"}], "example.com")
    check("the stage list was drawn", len(window._cb_stage_rows), 2)
    window._cb_ui_finding(CBFinding("CRITICAL", "Path traversal via 'file'",
                                    "http://x/download?file=..",
                                    "reads files", "root:x:0:0", "", "traversal"))
    window._cb_ui_finding(CBFinding("LOW", "No framing protection",
                                    "http://x/", "clickjacking", "", "", "headers"))
    check("both rows are in the table", window.cb_table.rowCount(), 2)
    check("the tally names the severities",
          "critical" in window.cb_tally.text().lower())

    window.cb_filter.setCurrentIndex(
        window.cb_filter.findData("HIGH"))
    check("filtering to high and above hides the low one",
          window.cb_table.rowCount(), 1)
    window.cb_filter.setCurrentIndex(0)
    check("clearing the filter brings it back", window.cb_table.rowCount(), 2)

    check("the worst finding sorts to the top",
          window.cb_table.item(0, 0).text(), "CRITICAL")
    window.cb_table.selectRow(0)
    check("selecting it fills the detail pane with that finding",
          "traversal" in window.cb_detail.toPlainText().lower())
    check("the detail pane carries the evidence",
          "root:x:0:0" in window.cb_detail.toPlainText())

    print("\n\033[1mStage progress\033[0m")
    window._cb_stages = [{"key": "headers"}, {"key": "nuclei"}]
    window._cb_ui_stage("headers", "done", "3 finding(s)")
    check("progress moves when a stage finishes",
          window.cb_progress.value() > 0)
    window._cb_ui_stage("nuclei", "skipped", "not installed")
    check("a skipped stage still counts as progress",
          window.cb_progress.value(), 100)

    window.close()

    print("\n\033[1mA broken tab does not take the window with it\033[0m")
    # Before this guard, a builder that raised meant the application simply
    # did not open — no window, and the traceback in a log file the user had
    # no reason to look in.
    import command_bridge.ui.tabs_coffee as coffee_module
    original = coffee_module.CoffeeBreakTabMixin.create_coffee_break_tab

    def broken(self):
        raise RuntimeError("deliberate failure for the test")

    coffee_module.CoffeeBreakTabMixin.create_coffee_break_tab = broken
    try:
        from PyQt6.QtWidgets import QTextEdit
        hurt = CommandBridgeV5()
        check("the window still builds", hurt is not None)
        check("every tab is still present", hurt.tab_widget.count(), len(TABS))
        hurt.goto_tab("coffee")
        labels = [l.text() for l in
                  hurt.tab_widget.currentWidget().findChildren(QLabel)]
        check("the broken tab says so",
              any("could not be built" in text for text in labels))
        traces = [t.toPlainText() for t in
                  hurt.tab_widget.currentWidget().findChildren(QTextEdit)]
        check("and shows the traceback",
              any("deliberate failure" in text for text in traces))
        hurt.goto_tab("web")
        check("the other tabs still work",
              hurt.tab_widget.currentIndex(), hurt.tab_index("web"))
        hurt.close()
    finally:
        coffee_module.CoffeeBreakTabMixin.create_coffee_break_tab = original

    print(f"\n{PASS} passed, {FAIL} failed")
    return 1 if FAIL else 0


if __name__ == "__main__":
    sys.exit(main())
