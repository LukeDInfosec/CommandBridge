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
DIM = RESET = ""


def check(label, got, want=True):
    global PASS, FAIL
    if got == want:
        PASS += 1
        print(f"  \033[32m✓\033[0m {label}")
    else:
        FAIL += 1
        print(f"  \033[31m✗\033[0m {label}  (got {got!r}, wanted {want!r})")


def main():
    from PyQt6.QtCore import Qt
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

    print("\n\033[1mNo mixin has been dropped from the window\033[0m")
    # The regression this exists for: window.py was replaced with a copy built
    # from an older tree, which silently dropped ApiTestingMixin from the base
    # list. Nothing failed until a tab tried to connect a button to a method
    # that mixin provided, at which point the application would not open at
    # all. Every mixin the package defines should be in the window's MRO.
    import pkgutil
    import importlib
    import command_bridge

    in_mro = {base.__name__ for base in CommandBridgeV5.__mro__}
    #: Mixins that are deliberately not mixed in (they belong to a dialog, or
    #: are a base class for other mixins rather than for the window).
    NOT_EXPECTED = set()
    defined, absent = {}, []
    for finder, name, _is_pkg in pkgutil.walk_packages(
            command_bridge.__path__, "command_bridge."):
        if ".widgets" in name:
            continue
        try:
            module = importlib.import_module(name)
        except Exception:
            absent.append(name)
            continue
        for attribute in dir(module):
            if not attribute.endswith("Mixin"):
                continue
            cls = getattr(module, attribute)
            if isinstance(cls, type) and cls.__module__ == name:
                defined[attribute] = name

    dropped = sorted(n for n in defined
                     if n not in in_mro and n not in NOT_EXPECTED)
    check(f"every mixin the package defines is mixed in "
          f"({len(defined)} checked)", dropped, [])
    if absent:
        print(f"      {DIM if False else ''}(could not import: "
              f"{', '.join(absent)}){RESET if False else ''}")

    print("\n\033[1mActive Scan is registered\033[0m")
    check("it is in TABS", "scan" in keys)
    check("its builder is named", _TAB_BUILDERS.get("scan"),
          "create_active_scan_tab")
    check("the window class has the builder",
          hasattr(CommandBridgeV5, "create_active_scan_tab"))
    check("and the engine", hasattr(CommandBridgeV5, "start_active_scan"))
    check("and a way to stop it",
          hasattr(CommandBridgeV5, "stop_active_scan"))

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

    print("\n\033[1mThe Active Scan tab builds and is usable\033[0m")
    window.goto_tab("scan")
    check("it can be shown",
          window.tab_widget.currentIndex(), window.tab_index("scan"))
    check("its findings table exists", window.as_table.columnCount(), 5)
    check("it starts empty", window.as_table.rowCount(), 0)
    check("the severity column is centred and roomy",
          window.as_table.columnWidth(0) > 80)
    check("every authentication method is offered",
          [window.as_auth_mode.itemData(i)
           for i in range(window.as_auth_mode.count())],
          ["none", "form", "browser", "static", "bearer"])
    check("all three profiles are offered",
          [window.as_profile.itemData(i)
           for i in range(window.as_profile.count())],
          ["safe", "standard", "full"])
    check("standard is the default", window.as_profile.currentData(),
          "standard")
    check("the second-account option is there for IDOR testing",
          window.as_second_user.isChecked(), False)
    # Choosing a login method should enable the credential fields, and
    # choosing none should not.
    window.as_auth_mode.setCurrentIndex(
        [window.as_auth_mode.itemData(i)
         for i in range(window.as_auth_mode.count())].index("form"))
    check("picking form login enables the password box",
          window.as_password.isEnabled())
    window.as_auth_mode.setCurrentIndex(0)
    check("and picking none disables it", window.as_password.isEnabled(),
          False)

    from command_bridge.modules.scanner import ScanFinding, Evidence
    window._as_findings = []
    window._as_on_finding(ScanFinding(
        issue="sqli", where="http://x/item?id=1",
        point="query parameter 'id'", confidence="confirmed",
        evidence=[Evidence(label="true", request="GET /item?id=1 AND 1=1")],
        detail_extra="confirmed by differential"))
    window._as_on_finding(ScanFinding(
        issue="open_redirect", where="http://x/go?next=/a",
        point="query parameter 'next'", confidence="confirmed"))
    check("findings render into the table", window.as_table.rowCount(), 2)
    check("the worst sorts to the top",
          window.as_table.item(0, 0).text(), "CRITICAL")
    window.as_table.selectRow(0)
    check("selecting one shows its evidence",
          "AND 1=1" in window.as_detail.toPlainText())
    window.as_filter.setCurrentIndex(
        [window.as_filter.itemData(i)
         for i in range(window.as_filter.count())].index("HIGH"))
    check("filtering to High+ hides the medium one",
          window.as_table.rowCount(), 1)
    window.as_filter.setCurrentIndex(0)
    check("clearing it brings the finding back", window.as_table.rowCount(), 2)

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
    check("the filter starts at Low+, so info does not bury the rest",
          window.cb_filter.currentData(), "LOW")
    window._cb_ui_finding(CBFinding("CRITICAL", "Path traversal via 'file'",
                                    "http://x/download?file=..",
                                    "reads files", "root:x:0:0", "", "traversal"))
    window._cb_ui_finding(CBFinding("LOW", "No framing protection",
                                    "http://x/", "clickjacking", "", "", "headers"))
    check("both rows are in the table", window.cb_table.rowCount(), 2)
    check("the tally names the severities",
          "critical" in window.cb_tally.text().lower())

    check("the filter reads as a floor, not a range",
          [window.cb_filter.itemText(i)
           for i in range(window.cb_filter.count())],
          ["Everything", "Critical+", "High+", "Medium+", "Low+", "Info+"])
    window.cb_filter.setCurrentIndex(
        window.cb_filter.findData("HIGH"))
    check("filtering to High+ hides the low one",
          window.cb_table.rowCount(), 1)
    window.cb_filter.setCurrentIndex(0)
    check("clearing the filter brings it back", window.cb_table.rowCount(), 2)

    check("the severity is centred in its cell",
          window.cb_table.item(0, 0).textAlignment()
          & int(Qt.AlignmentFlag.AlignHCenter.value) != 0)
    check("the severity column has room to be centred in",
          window.cb_table.columnWidth(0) > 80)

    window.cb_filter.setCurrentIndex(window.cb_filter.findData("LOW"))
    window._cb_ui_finding(CBFinding("INFO", "Technology fingerprint",
                                    "http://x/", "what the stack is", "",
                                    "", "nuclei"))
    check("an informational finding is held back by default",
          window.cb_table.rowCount(), 2)
    check("but it is counted, and the count says so",
          "hidden by the filter" in window.cb_count_label.text())
    window.cb_filter.setCurrentIndex(0)
    check("showing everything brings it in", window.cb_table.rowCount(), 3)

    print("\n\033[1mRepeats of one issue share a row\033[0m")
    repeated = CBFinding("MEDIUM", "Content-Security-Policy is missing",
                         "http://x/", "no CSP", "", "", "headers")
    window._cb_ui_finding(repeated)
    rows_before = window.cb_table.rowCount()
    repeated.add_instance("http://x/about")
    repeated.add_instance("http://x/contact")
    window._cb_ui_refresh(repeated)
    check("no new row is added", window.cb_table.rowCount(), rows_before)
    wheres = [window.cb_table.item(r, 2).text()
              for r in range(window.cb_table.rowCount())]
    check("the row says how many other places it was seen",
          any("(+2 more)" in w for w in wheres))


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
