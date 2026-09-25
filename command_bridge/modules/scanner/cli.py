"""
``cbscan`` — the scanner without the window.

Same engine, same checks, same report. For a scan you want to start and walk
away from, or run from a box that has no display:

    python3 -m command_bridge.modules.scanner.cli https://app.example \
        --auth form --login-url https://app.example/login \
        --user alice --password - \
        --check-url https://app.example/account --signature "Sign out" \
        --second-user bob --second-password - \
        --out ./reports

The password is read from a prompt when given as ``-``, which keeps it out of
the shell history and out of the process list.
"""

from __future__ import annotations

import argparse
import getpass
import sys
import time
import urllib.parse
from pathlib import Path


def build_parser():
    parser = argparse.ArgumentParser(
        prog="cbscan",
        description="Command Bridge active scanner — crawls an application, "
                    "attacks every parameter it finds, and reports only what "
                    "it could prove.")
    parser.add_argument("target", help="https://app.example")
    parser.add_argument("--profile", default="standard",
                        choices=("safe", "standard", "full"),
                        help="how hard to push (default: standard)")
    parser.add_argument("--out", default=".",
                        help="directory for the HTML, Markdown and JSON "
                             "reports")

    auth = parser.add_argument_group("authentication")
    auth.add_argument("--auth", default="none",
                      choices=("none", "form", "browser", "static", "bearer"))
    auth.add_argument("--login-url", default="")
    auth.add_argument("--user", default="")
    auth.add_argument("--password", default="",
                      help="the password, or '-' to be prompted")
    auth.add_argument("--check-url", default="",
                      help="a page that only works when logged in")
    auth.add_argument("--signature", default="",
                      help="a string that only appears when logged in")
    auth.add_argument("--cookie", action="append", default=[],
                      metavar="NAME=VALUE")
    auth.add_argument("--header", action="append", default=[],
                      metavar="NAME:VALUE")
    auth.add_argument("--second-user", default="",
                      help="a second account, for the IDOR comparison")
    auth.add_argument("--second-password", default="")

    scope = parser.add_argument_group("scope")
    scope.add_argument("--exclude", action="append", default=[],
                       help="a pattern never to request; repeatable")
    scope.add_argument("--include", action="append", default=[])
    scope.add_argument("--subdomains", action="store_true")
    scope.add_argument("--no-browser", action="store_true",
                       help="do not use headless Chromium to confirm XSS")
    scope.add_argument("--browser-crawl", action="store_true",
                       help="render pages while crawling (for SPAs)")
    scope.add_argument("--quiet", action="store_true")
    return parser


def main(argv=None):
    from command_bridge.modules.scanner import (
        AuthConfig, PROFILES, ScanEngine, build_scope)
    from command_bridge.modules.scanner import report as scan_report

    args = build_parser().parse_args(argv)
    password = args.password
    if password == "-":
        password = getpass.getpass("Password: ")
    second_password = args.second_password
    if second_password == "-":
        second_password = getpass.getpass("Second user's password: ")

    auth = AuthConfig(
        args.auth, login_url=args.login_url, username=args.user,
        password=password, check_url=args.check_url,
        logged_in_signature=args.signature,
        cookies=dict(c.split("=", 1) for c in args.cookie if "=" in c),
        headers=dict((h.split(":", 1)[0].strip(), h.split(":", 1)[1].strip())
                     for h in args.header if ":" in h),
        name=args.user or "user")

    second = None
    if args.second_user:
        second = AuthConfig(
            args.auth, login_url=args.login_url, username=args.second_user,
            password=second_password, check_url=args.check_url,
            logged_in_signature=args.signature, name=args.second_user)

    profile = PROFILES[args.profile]()
    profile.use_browser = not args.no_browser
    profile.browser_crawl = args.browser_crawl

    target = args.target
    if not target.startswith(("http://", "https://")):
        target = "https://" + target
    scope = build_scope(target, include=args.include, exclude=args.exclude,
                        allow_subdomains=args.subdomains)

    last = [0.0]

    def log(line):
        if not args.quiet:
            print(line, flush=True)

    def progress(phase, done, total):
        if args.quiet or time.time() - last[0] < 1.0:
            return
        last[0] = time.time()
        print(f"\r  {phase}: {done}/{total}".ljust(70), end="", flush=True)

    engine = ScanEngine(target, auth=auth, second_auth=second,
                        profile=profile, scope=scope, on_log=log,
                        on_progress=progress)
    try:
        result = engine.run()
    except KeyboardInterrupt:
        engine.stop()
        print("\nstopped", file=sys.stderr)
        return 130

    host = urllib.parse.urlparse(result.target).netloc.replace(":", "_")
    written = scan_report.write_all(result, args.out, f"active_scan_{host}")
    print("\n" + "─" * 70)
    for finding in result.findings:
        from command_bridge.modules import cb_issues
        issue = cb_issues.ISSUES.get(finding.issue, {})
        severity = finding.severity or issue.get("severity", "MEDIUM")
        print(f"  [{severity:8}] {issue.get('title', finding.issue)} — "
              f"{finding.point} at {finding.where}")
    if not result.findings:
        print("  nothing confirmed")
    if not result.authenticated and args.auth != "none":
        print("\n  WARNING: the scan could not confirm a logged-in session.")
    print("─" * 70)
    for path in written.values():
        print(f"  {path}")
    # A non-zero exit when something serious was found, so this can gate a
    # pipeline without anybody parsing the output.
    worst = {(f.severity or
              __import__("command_bridge.modules.cb_issues",
                         fromlist=["x"]).ISSUES.get(f.issue, {}).get(
                  "severity", "MEDIUM")) for f in result.findings}
    return 2 if ({"CRITICAL", "HIGH"} & worst) else 0


if __name__ == "__main__":
    sys.exit(main())
