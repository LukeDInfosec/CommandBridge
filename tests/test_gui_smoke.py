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
    from PyQt6.QtWidgets import (
        QApplication, QPushButton, QLabel, QSplitter)
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

    # The list and the evidence sit side by side. Stacked, the detail pane got
    # whatever vertical room the table left over, which on a laptop meant
    # dragging the divider up for every finding.
    splitter = window.cb_table.parent()
    while splitter is not None and not isinstance(splitter, QSplitter):
        splitter = splitter.parent()
    check("the findings list and the detail pane share a splitter",
          isinstance(splitter, QSplitter))
    check("and it lays them out side by side",
          splitter.orientation(), Qt.Orientation.Horizontal)
    check("neither pane can be collapsed to nothing",
          splitter.childrenCollapsible(), False)
    check("the detail pane starts wider than the list",
          splitter.sizes()[1] > splitter.sizes()[0])
    check("the detail pane is tall enough to read without dragging",
          window.cb_detail.minimumHeight() >= 320)
    for column, name in ((0, "severity"), (1, "finding")):
        check(f"the {name} column is shown",
              window.cb_table.isColumnHidden(column), False)
    for column, name in ((2, "where"), (3, "stage"), (4, "confidence")):
        # Still populated — the filter, the sort and the delete menu read
        # them — just shown in the detail pane instead of in a column two
        # words wide.
        check(f"the {name} column moves to the detail pane",
              window.cb_table.isColumnHidden(column), True)

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

    print("\n\033[1mThe checklist crosses things off\033[0m")
    from command_bridge.modules.coffee_break import CB_STAGE_CATALOGUE
    stages = [{"key": k, "name": n} for k, n, _h in CB_STAGE_CATALOGUE[:5]]
    window._cb_stages = stages
    window._cb_ui_reset(stages, "example.com")
    check("every stage gets a row", len(window._cb_stage_rows), 5)
    check("the card is open, however it was left",
          window._cb_stages_card.isChecked())
    check("nothing is done yet", "0 done" in window.cb_stage_summary.text())
    check("and it says how many are outstanding",
          "5 to go" in window.cb_stage_summary.text())

    window._cb_ui_stage("nmap_quick", "done", "2 finding(s)")
    mark, name, _note = window._cb_stage_rows["nmap_quick"]
    check("a finished step is ticked", mark.text(), "✓")
    check("and struck through", "line-through" in name.styleSheet())
    window._cb_ui_stage("nmap_full", "running", "")
    mark, name, _note = window._cb_stage_rows["nmap_full"]
    check("the running step is marked", mark.text(), "▶")
    check("and stands out", "700" in name.styleSheet())
    mark, name, _note = window._cb_stage_rows["testssl"]
    check("an outstanding step is left plain", mark.text(), "○")
    check("with no strikethrough", "line-through" in name.styleSheet(), False)
    window._cb_ui_stage("nmap_udp", "skipped", "not installed")
    window._cb_ui_stage("headers", "failed", "exit 1")
    check("the summary counts each kind",
          window.cb_stage_summary.text(),
          "1 done · 1 skipped · 1 failed · 2 to go")
    check("progress follows the checklist, not just successes",
          window.cb_progress.value(), 60)

    print("\n\033[1mDimmed text is readable in every theme\033[0m")
    # Qt's own Mid is a dark grey. Nothing set the role, so every widget
    # styled `color: palette(mid)` — the running-command line most of all —
    # rendered near-black, and on a dark theme that is black on black: the
    # command actually running was invisible on most of the palettes.
    from PyQt6.QtGui import QPalette, QColor
    from command_bridge.constants import THEMES

    def relative_luminance(colour):
        channels = []
        for value in (colour.redF(), colour.greenF(), colour.blueF()):
            channels.append(value / 12.92 if value <= 0.03928
                            else ((value + 0.055) / 1.055) ** 2.4)
        return (0.2126 * channels[0] + 0.7152 * channels[1]
                + 0.0722 * channels[2])

    def contrast(first, second):
        a, b = relative_luminance(first), relative_luminance(second)
        return (max(a, b) + 0.05) / (min(a, b) + 0.05)

    worst_theme, worst_ratio = "", 99.0
    for name in THEMES:
        window.apply_theme(name)
        palette = QApplication.instance().palette()
        for role in (QPalette.ColorRole.Mid,
                     QPalette.ColorRole.PlaceholderText):
            ratio = contrast(palette.color(role),
                             QColor(THEMES[name]["panel_bg"]))
            if ratio < worst_ratio:
                worst_theme, worst_ratio = f"{name}/{role.name}", ratio
    check(f"dimmed text clears 4.5:1 on every theme "
          f"(worst: {worst_theme} at {worst_ratio:.1f}:1)",
          worst_ratio >= 4.5)
    check("the running-command line uses that role, not a literal colour",
          "palette(mid)" in window.cb_command.styleSheet())
    window.apply_theme("Obsidian")

    print("\n\033[1mScan options\033[0m")
    check("every stage can be turned off",
          len(window.cb_stage_toggles), len(CB_STAGE_CATALOGUE))
    check("they all start on",
          all(t.isChecked() for t in window.cb_stage_toggles.values()))
    window._cb_choose(["nmap_quick", "headers"])
    check("choosing a subset is remembered",
          window._cb_enabled_stages, {"nmap_quick", "headers"})
    check("and the chain honours it",
          [s["key"] for s in window._cb_stage_list()],
          ["nmap_quick", "headers"])
    window._cb_choose([k for k, _n, _h in CB_STAGE_CATALOGUE])
    check("turning them all back on restores the full chain",
          len(window._cb_stage_list()), len(CB_STAGE_CATALOGUE))
    check("muted types are listed where they can be undone",
          "muted" in window.cb_muted_label.text().lower())

    print("\n\033[1mThe TLS stage is wired to the real cleanup\033[0m")
    # The Coffee Break stage calls a helper that lives on StatusMixin. If that
    # ever moves or is renamed, the stage silently stops clearing the previous
    # run's reports and testssl starts failing on every re-scan again.
    check("the window provides the cleanup the stage relies on",
          hasattr(CommandBridgeV5, "_cleanup_testssl_outputs"))
    check("and the built-in summariser it now feeds",
          hasattr(CommandBridgeV5, "_summarize_testssl_if_applicable"))
    check("the stage builds its own command",
          hasattr(CommandBridgeV5, "_cb_testssl_command"))

    print("\n\033[1mThe screen says what is running\033[0m")
    window._cb_ui_command("nmap -sV -sC -p- -T4 example.com -oN out.txt")
    check("the current command is shown",
          "nmap -sV" in window.cb_command.text())
    check("and the full command is on hover",
          "example.com" in window.cb_command.toolTip())
    long_command = "nuclei -u https://example.com " + "-t x " * 80
    window._cb_ui_command(long_command)
    check("a very long command is elided rather than stretching the card",
          len(window.cb_command.text()) <= 200)
    check("but the whole of it is still on hover",
          window.cb_command.toolTip().endswith("-t x"))

    print("\n\033[1mPause\033[0m")
    check("Pause is offered", window.cb_pause_btn.text(), "Pause")
    window._cb_ui_paused(True)
    check("it becomes Resume while paused", window.cb_pause_btn.text(),
          "Resume")
    check("and the progress bar says so", window.cb_progress.format(), "paused")
    window._cb_ui_paused(False)
    check("and back again", window.cb_pause_btn.text(), "Pause")
    check("the engine has the pause", hasattr(window, "pause_coffee_break"))
    check("pausing when nothing is running does nothing",
          window.pause_coffee_break(), False)

    print("\n\033[1mA chain that is running does not report Idle\033[0m")
    # The symptom: the shared runner announces idle as each step finishes,
    # and again three seconds later — on top of the step that has already
    # started. During a chain both are wrong.
    window._cb_active = True
    window._cb_stages = [{"key": "nmap_quick", "name": "Nmap — service scan"}]
    window._cb_index = 0
    window._cb_current_command = "nmap -sV example.com"
    window._cb_assert_running()
    check("the state chip says running",
          window._status_state, "running")
    check("and names the stage rather than the tool",
          "Coffee Break" in window.current_action_label)
    window._cb_active = False

    print("\n\033[1mThe clock belongs to the scan, not the step\033[0m")
    import time as _time
    window._cb_started_at = _time.time() - 125
    window._cb_paused = False
    window._cb_tick()
    check("the tab shows the elapsed time",
          window.cb_elapsed_label.text(), "running for 2m 05s")
    check("and so does the status bar", window._status_elapsed.text(), "02:05")
    # The bug: this runs at the end of every step, and used to zero the clock
    # fourteen times during one chain.
    window._cb_active = True
    window.stop_progress_animation()
    check("a step ending does not reset the scan's clock",
          window._status_elapsed.text(), "02:05")
    window._cb_active = False
    window.stop_progress_animation()
    check("but the clock does clear once the scan is over",
          window._status_elapsed.text(), "00:00")

    print("\n\033[1mRight-clicking a finding\033[0m")
    window._cb_ui_reset(
        [{"key": "headers", "name": "HTTP and security headers"},
         {"key": "nuclei", "name": "Nuclei templates"}], "example.com")
    window.cb_filter.setCurrentIndex(0)
    one = CBFinding("LOW", "BREACH (HTTP compression with reflected input)",
                    "http://x/", "compression", "", "", "testssl")
    one.key = "breach"
    two = CBFinding("LOW", "BREACH (HTTP compression with reflected input)",
                    "http://y/", "compression", "", "", "nikto")
    two.key = "breach"
    three = CBFinding("HIGH", "Something else", "http://x/", "", "", "", "nuclei")
    three.key = "sqli"
    for finding in (one, two, three):
        window._cb_ui_finding(finding)
    check("three findings are on the table", window.cb_table.rowCount(), 3)

    # The bug: customContextMenuRequested reports a position in the widget's
    # own coordinates, and rowAt() wants the viewport's. The difference is the
    # header's height, which was enough to return -1 for the first row — so
    # right-clicking the top finding opened no menu at all.
    from PyQt6.QtCore import QPoint
    header_height = window.cb_table.horizontalHeader().height()
    row_height = window.cb_table.rowHeight(0) or 24
    first_row = QPoint(40, header_height + row_height // 2)
    check("the first row is found at a widget-coordinate click",
          window._cb_row_at(first_row), 0)
    second_row = QPoint(40, header_height + row_height + row_height // 2)
    check("and so is the second", window._cb_row_at(second_row), 1)
    check("a click in open space falls back to the selection rather than "
          "failing", isinstance(window._cb_row_at(QPoint(40, 4000)), int))
    check("and the row resolves to a real finding",
          window._cb_finding_at(window._cb_row_at(first_row)) is not None)

    spare = CBFinding("INFO", "A finding added for the keyboard test",
                      "http://z/", "", "", "", "nikto")
    spare.key = "version_disclosure"
    window._cb_ui_finding(spare)
    window.cb_table.selectRow(window.cb_table.rowCount() - 1)
    before = window.cb_table.rowCount()
    window._cb_delete_selected()
    check("Delete removes the selected finding",
          window.cb_table.rowCount(), before - 1)
    check("and leaves the other three", window.cb_table.rowCount(), 3)
    check("the menu counts every finding of a type",
          window._cb_count_of(one), 2)
    window._cb_drop(window._cb_same_type(one))
    check("deleting a type removes all of them", window.cb_table.rowCount(), 1)
    check("and leaves the others alone",
          window.cb_table.item(0, 1).text(), "Something else")
    check("copying a finding produces something pasteable",
          "Something else" in window._cb_as_text(three))
    check("and it names the tools that found it",
          "Detected by" in window._cb_as_text(three))

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
