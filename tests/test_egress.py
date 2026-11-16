#!/usr/bin/env python3
"""
The traffic-transparency layer: does every outbound request get seen?

The claim this module exists to support is "this tool talks to your
target and nothing else". These tests are the part of that claim that
can be checked mechanically.
"""

import json
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

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
    from command_bridge.modules import egress

    print("\n\033[1mNothing happens until the operator asks\033[0m")
    state = egress.Egress()
    check("no proxy by default", state.active, False)
    check("and no proxies dict to hand to requests", state.proxies(), {})
    check("nor any environment for child processes", state.env_pairs(), {})
    state.configure(proxy_url="127.0.0.1:8080")
    check("a proxy address alone does not switch it on", state.active, False)
    state.configure(proxy_enabled=True)
    check("the toggle does", state.active)

    print("\n\033[1mThe address is normalised, not second-guessed\033[0m")
    check("a bare host:port becomes a URL",
          egress.normalise_proxy("127.0.0.1:8080"), "http://127.0.0.1:8080")
    check("an explicit scheme is kept",
          egress.normalise_proxy("socks5://127.0.0.1:1080"),
          "socks5://127.0.0.1:1080")
    check("and an empty setting stays empty",
          egress.normalise_proxy("  "), "")

    print("\n\033[1mEvery tool gets the proxy, by flag or by "
          "environment\033[0m")
    egress.STATE.configure(proxy_url="127.0.0.1:8080", proxy_enabled=True)
    for command, expected in (
            ("nuclei -u https://x", "-proxy http://127.0.0.1:8080"),
            ("nikto -h x", "-useproxy http://127.0.0.1:8080"),
            ("testssl x", "--proxy 127.0.0.1:8080"),
            ("sqlmap -u https://x", "--proxy=http://127.0.0.1:8080"),
            ("ffuf -u https://x/FUZZ", "-x http://127.0.0.1:8080")):
        check(f"{command.split()[0]} carries its own flag",
              expected in egress.proxy_command(command))
    check("testssl gets host:port, which is what it accepts",
          "--proxy http://" in egress.proxy_command("testssl x"), False)
    check("a tool with no flag is left alone for the environment",
          egress.proxy_command("nmap -sV x"), "nmap -sV x")
    check("an operator's own --proxy is never doubled",
          egress.proxy_command("nuclei -proxy http://127.0.0.1:9999 -u x"),
          "nuclei -proxy http://127.0.0.1:9999 -u x")
    check("and the environment covers everything either way",
          sorted(egress.STATE.env_pairs())[:2], ["ALL_PROXY", "HTTPS_PROXY"])
    print("\n\033[1mTools that cannot be proxied say so, out loud\033[0m")
    # nmap is Coffee Break's first stage and uses raw sockets, so a proxied
    # run shows nothing in Burp for the first minutes. During a credibility
    # demo that silence must be explained, not left to look suspicious.
    egress.STATE.configure(proxy_url="127.0.0.1:8080", proxy_enabled=True)
    check("nmap is flagged as unproxyable",
          "nmap" in egress.proxy_note("nmap -sV host").lower())
    check("   and the note says it is expected, not a problem",
          "expected" in egress.proxy_note("nmap -sV host"))
    check("   through a sudo/stdbuf wrapper too",
          bool(egress.proxy_note("sudo stdbuf -oL nmap -p- host")))
    check("sslscan is flagged (raw TLS, straight to the target)",
          bool(egress.proxy_note("sslscan host")))
    check("an HTTP tool is NOT flagged",
          egress.proxy_note("nuclei -u https://x"), "")
    check("   nor testssl, which honours --proxy",
          egress.proxy_note("testssl host"), "")

    egress.STATE.configure(proxy_enabled=False)
    check("with the proxy off, commands are untouched",
          egress.proxy_command("nuclei -u https://x"), "nuclei -u https://x")
    check("and there is no proxy note when off",
          egress.proxy_note("nmap -sV host"), "")

    print("\n\033[1mThe log records the attempt, and says whose it "
          "was\033[0m")
    with tempfile.TemporaryDirectory() as folder:
        path = Path(folder) / "egress.jsonl"
        logger = egress.Egress()
        logger.configure(log_enabled=True, log_path=str(path))
        logger.set_scope(["target.example.com"])
        logger.record("GET", "https://target.example.com/login",
                      component="coffee_break")
        logger.record("GET", "https://api.target.example.com/v1",
                      component="active_scan")
        logger.record("GET", "https://crt.sh/?q=example", component="recon")
        logger.record("POST", "https://metrics.somewhere.net/collect",
                      component="mystery")
        rows = [json.loads(line) for line in
                path.read_text().splitlines() if line.strip()]
        check("every request is written", len(rows), 4)
        check("the target is in scope", rows[0]["in_scope"])
        check("a subdomain of the target is too", rows[1]["in_scope"])
        check("crt.sh is not in scope but IS documented",
              (rows[2]["in_scope"], rows[2]["known_host"], rows[2]["expected"]),
              (False, True, True))
        check("an undocumented host is marked unexpected",
              rows[3]["expected"], False)
        check("   and named", rows[3]["host"], "metrics.somewhere.net")
        check("   and attributed to the component that made it",
              rows[3]["component"], "mystery")
        check("the method is recorded", rows[3]["method"], "POST")
        check("the count of unexpected requests is one",
              logger.unexpected, 1)

        lines, unexpected, total = logger.summary()
        check("the summary covers every host", len(lines), 4)
        check("   counts the unexpected one", unexpected, 1)
        check("   and totals the requests", total, 4)
        check("the unexpected host is called out in words",
              any("NOT IN SCOPE" in line for line in lines))

        print("\n\033[1mA URL is recorded; a credential is not\033[0m")
        logger.record("GET",
                      "https://target.example.com/cb?token=SECRET123"
                      "&id=7&api_key=AKIAI", component="scan")
        last = json.loads(path.read_text().splitlines()[-1])
        check("the path is kept", "/cb" in last["url"])
        check("an ordinary parameter is kept", "id=7" in last["url"])
        check("a token value is not", "SECRET123" in last["url"], False)
        check("nor an api key", "AKIAI" in last["url"], False)
        check("and the redaction is visible, not silent",
              "<redacted>" in last["url"])

        print("\n\033[1mA command line is recorded as a command\033[0m")
        logger.configure(proxy_url="127.0.0.1:8080", proxy_enabled=True)
        logger.record_command("nuclei -proxy http://127.0.0.1:8080 -u x")
        entry = json.loads(path.read_text().splitlines()[-1])
        check("the command is written", entry["kind"], "command")
        check("   with the proxy state recorded beside it",
              (entry["proxied"], entry["proxy"]),
              (True, "http://127.0.0.1:8080"))
        check("   and it says the tool's own requests are in the proxy",
              "appear in the proxy" in entry["note"])

    print("\n\033[1mNothing is written when logging is off\033[0m")
    with tempfile.TemporaryDirectory() as folder:
        path = Path(folder) / "off.jsonl"
        quiet = egress.Egress()
        quiet.configure(log_enabled=False, log_path=str(path))
        quiet.record("GET", "https://target.example.com/")
        check("no file is created", path.exists(), False)
        check("but the request is still counted for the summary",
              quiet.recorded, 1)

    print("\n\033[1mThe wrapper catches requests made anywhere\033[0m")
    # The point of patching requests.Session.request rather than asking
    # each module to log: a module added next year is covered the day it
    # is written. If this test fails, some library call is invisible.
    try:
        import requests
    except Exception:                                       # noqa: BLE001
        print("  (requests is not installed; skipping)")
    else:
        egress.install()
        before = egress.STATE.recorded
        session = requests.Session()
        session.cb_component = "test"
        try:
            session.get("http://127.0.0.1:1/never-answers", timeout=0.2)
        except Exception:                                   # noqa: BLE001
            pass
        check("a request that FAILED is still recorded",
              egress.STATE.recorded > before)
        check("   because the log records the attempt, not the response",
              "127.0.0.1" in egress.STATE.hosts)

    print(f"\n{PASS} passed, {FAIL} failed")
    return 1 if FAIL else 0


if __name__ == "__main__":
    sys.exit(main())
