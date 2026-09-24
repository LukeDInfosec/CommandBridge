#!/usr/bin/env python3
"""The chain itself: does stage N+1 start when stage N finishes, and does it
know what stage N found?

This drives the real window, the real CommandRunner and the real
on_command_finished path with a short stage list, because the sequencing is
the part that cannot be tested by calling the parsers directly.
"""

import os
import sys
import tempfile
import threading
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
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


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *a):
        pass

    def do_GET(self):
        if self.path.rstrip("/") == "/admin":
            if self.headers.get("X-Original-URL"):
                body = b"<h1>in</h1>"
                code = 200
            else:
                body, code = b"forbidden", 403
        else:
            body, code = b"<html><title>t</title>ok</html>", 200
        self.send_response(code)
        self.send_header("Content-Type", "text/html")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    do_POST = do_HEAD = do_GET


def main():
    from PyQt6.QtWidgets import QApplication
    from PyQt6.QtCore import QTimer, QEventLoop
    from command_bridge.ui.window import CommandBridgeV5
    from command_bridge.modules.coffee_break import probe_403_bypass

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    base = f"http://127.0.0.1:{server.server_address[1]}"

    app = QApplication.instance() or QApplication(sys.argv)
    window = CommandBridgeV5()
    window.target = base
    window.output_dir = Path(tempfile.mkdtemp())

    order = []

    def fake_stages():
        """Three shell stages and one Python stage, in that order.

        The fuzz stage prints ffuf-shaped output naming a 403, which only the
        bypass stage can act on — so if the artefact handover is broken, the
        last stage finds nothing and the test says so.
        """
        return [
            dict(key="one", name="first shell stage", kind="shell",
                 command="echo 'stage one ran'"),
            dict(key="fuzz", name="fuzz", kind="shell",
                 command=f"printf '/admin  [Status: 403, Size: 9]\\n"
                         f"/login  [Status: 200, Size: 30]\\n'",
                 parser="_cb_parse_fuzz"),
            dict(key="gated", name="a stage that should be skipped",
                 kind="shell", command="echo 'must not run'",
                 when=lambda a: False, skip_note="deliberately gated off"),
            dict(key="bypass", name="403 bypass", kind="python",
                 probe=probe_403_bypass,
                 when=lambda a: bool(a.get("forbidden")),
                 skip_note="nothing answered 401 or 403"),
        ]

    window._cb_stage_list = fake_stages
    original_stage_ui = window._cb_ui_stage

    def record(key, status, note):
        order.append((key, status))
        original_stage_ui(key, status, note)

    window._cb_ui_stage = record

    loop = QEventLoop()
    finished = {"how": None}
    original_finished = window._cb_ui_finished

    def done(how):
        finished["how"] = how
        original_finished(how)
        QTimer.singleShot(50, loop.quit)

    window._cb_ui_finished = done

    QTimer.singleShot(120000, loop.quit)        # never hang the suite
    window.start_coffee_break()
    loop.exec()
    server.shutdown()

    print("\n\033[1mSequencing\033[0m")
    check("the chain finished", finished["how"], "completed")
    started = [key for key, status in order if status == "running"]
    check("the shell stages ran in order", started[:2], ["one", "fuzz"])
    check("each stage started only after the previous finished",
          all(order.index((k, "running")) > order.index((started[i - 1], "done"))
              for i, k in enumerate(started) if i > 0))

    print("\n\033[1mGating\033[0m")
    check("a gated-off stage is skipped", ("gated", "skipped") in order)
    check("and it never ran", ("gated", "running") in order, False)

    print("\n\033[1mArtefacts move between stages\033[0m")
    forbidden = window._cb_artifacts.get("forbidden") or []
    check("the fuzz stage banked the 403", any("/admin" in u for u in forbidden))
    check("the 200 was not banked", any("/login" in u for u in forbidden), False)
    check("the bypass stage ran because of it", ("bypass", "running") in order)

    print("\n\033[1mFindings\033[0m")
    titles = [f.title for f in window._cb_findings]
    check("the bypass was found and reported",
          any("bypassed" in t for t in titles))
    check("it is attributed to the bypass stage",
          all(f.stage == "bypass" for f in window._cb_findings
              if "bypassed" in f.title))
    table = window._cb_artifacts.get("bypass_table") or []
    check("the attempts table was kept", len(table) > 5)

    print("\n\033[1mState is clean afterwards\033[0m")
    check("the chain is no longer active", window._cb_active, False)
    check("the report can be produced",
          "403 bypass attempts" in window.coffee_break_report())

    window.close()
    print(f"\n{PASS} passed, {FAIL} failed")
    return 1 if FAIL else 0


if __name__ == "__main__":
    sys.exit(main())
