#!/usr/bin/env python3
"""Coffee Break — the parsers, the probes, and the chain that joins them.

Everything here runs against a throwaway HTTP server on 127.0.0.1, so the tests
exercise the real request path — redirect handling, header parsing, traversal
payloads, bypass tricks — without touching anybody's infrastructure.
"""

import json
import re
import sys
import threading
import tempfile
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

import time                                                  # noqa: E402
from command_bridge.modules import cb_control                # noqa: E402
from command_bridge.modules.cb_control import Stopped        # noqa: E402
from command_bridge.modules import cb_evidence               # noqa: E402
from command_bridge.modules import cb_issues                 # noqa: E402
from command_bridge.modules.cb_evidence import Evidence      # noqa: E402
from command_bridge.modules.coffee_break import (          # noqa: E402
    CBFinding, SEVERITIES, SEV_ORDER, CoffeeBreakMixin, finding_from_scan,
    _session, _same_location,
    probe_headers, probe_redirects, probe_traversal, probe_403_bypass,
    BYPASS_TRICKS, TRAVERSAL_PAYLOADS,
)

PASS = FAIL = 0


def check(label, got, want=True):
    global PASS, FAIL
    if got == want:
        PASS += 1
        print(f"  \033[32m✓\033[0m {label}")
    else:
        FAIL += 1
        print(f"  \033[31m✗\033[0m {label}  (got {got!r}, wanted {want!r})")


PASSWD = "root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:/usr/sbin:/bin/sh\n"


class Handler(BaseHTTPRequestHandler):
    """A small site with one of everything the probes look for."""

    protocol_version = "HTTP/1.1"

    def log_message(self, *a):
        pass

    def _send(self, code, body=b"", headers=None, ctype="text/html"):
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        for name, value in (headers or {}).items():
            self.send_header(name, value)
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)

    #: Every request lands here, so a test can prove that pausing really
    #: stops traffic instead of trusting a flag.
    hits = []

    def do_GET(self):
        Handler.hits.append(time.time())
        parsed = urllib.parse.urlparse(self.path)
        query = dict(urllib.parse.parse_qsl(parsed.query))
        path = parsed.path

        # An open redirect on 'next', and only on 'next'.
        if "next" in query:
            return self._send(302, b"", {"Location": query["next"]})
        # Every other redirect parameter is handled safely.
        if any(k in query for k in ("url", "redirect", "dest")):
            return self._send(302, b"", {"Location": "/safe"})

        # A traversal that works, on 'file', and one that does not, on 'page'.
        if path == "/download":
            value = query.get("file", "")
            if ".." in value or value.startswith("/etc"):
                return self._send(200, PASSWD.encode(), ctype="text/plain")
            return self._send(200, b"a file")
        if path == "/view":
            # Echoes the payload back but reads nothing — the classic false
            # positive a naive checker reports.
            return self._send(
                200, f"<p>page not found: {query.get('page','')}</p>".encode())

        # 403 that one specific trick gets past.
        if path.rstrip("/") == "/admin":
            if self.headers.get("X-Original-URL") or \
                    self.headers.get("X-Forwarded-For") == "127.0.0.1":
                return self._send(200, b"<h1>admin console</h1>")
            return self._send(403, b"forbidden")

        # A login panel that is actually distinguishable from the generic
        # page. This server answers 200 with the same body for every
        # unknown path — it is a catch-all, like a single-page app behind
        # a cache — and the Nikto parser now re-requests a claimed path
        # and compares it against a path that cannot exist. A panel whose
        # page is byte-identical to every 404 is not a panel, and the
        # parser is right to drop it; so the fixture has to serve one
        # that differs, the way a real login page does.
        if path.rstrip("/") in ("/umbraco", "/wp-login.php"):
            return self._send(200, b"<html><head><title>Login</title></head>"
                                   b"<body><form method='post' id='login'>"
                                   b"<input name='username'>"
                                   b"<input name='password' type='password'>"
                                   b"<button>Sign in</button></form>"
                                   b"</body></html>")

        body = (b"<html><head><title>Target</title>"
                b"<script src='/static/app.js'></script></head>"
                b"<body>wp-content is here</body></html>")
        return self._send(200, body, {
            "Server": "nginx/1.24.0",
            "X-Powered-By": "PHP/8.1.2",
            "Set-Cookie": "session=abc; Path=/",
        })

    do_POST = do_GET
    do_HEAD = do_GET


class Engine(CoffeeBreakMixin):
    """The mixin with just enough of the window around it to run."""

    def __init__(self, target):
        self.target = target
        self.output_dir = Path(tempfile.mkdtemp())
        self.console = self
        self.printed = []
        self.cleaned = []
        self._cb_reset()

    # console
    def append_ansi(self, text):
        self.printed.append(text)

    # window bits the parsers touch
    def get_scanner_target(self):
        return urllib.parse.urlparse(self._cb_target_url()).netloc.split(":")[0]

    def sanitize_target_for_filename(self, value):
        return re.sub(r"[^A-Za-z0-9_.-]+", "_", value)

    # The status bar and the command runner belong to the window. The stub
    # records what it was told rather than pretending to be either, so the
    # pause and stop paths can be exercised without one.
    def set_status_state(self, state, tool=""):
        self.states = getattr(self, "states", [])
        self.states.append(state)

    def update_status_bar(self, *args, **kwargs):
        pass

    @property
    def runner(self):
        engine = self

        class _NoRunner:
            process = type("P", (), {"processId": staticmethod(lambda: 0)})()

            @staticmethod
            def stop():
                engine.stopped_runner = True
        return _NoRunner()

    # The real window gets this from StatusMixin; the stub mirrors it so the
    # re-run behaviour can be tested.
    def _cleanup_testssl_outputs(self, safe):
        self.cleaned.append(safe)
        for suffix in (".json", ".log", ".txt"):
            path = self.output_dir / f"{safe}_testssl{suffix}"
            if path.exists():
                path.unlink()


def main():
    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    base = f"http://127.0.0.1:{server.server_address[1]}"
    context = {"url": base, "output_dir": tempfile.mkdtemp(), "timeout": 8}
    noop = lambda *a: None                                  # noqa: E731

    try:
        print("\n\033[1mSeverity ordering\033[0m")
        check("critical outranks high",
              SEV_ORDER["CRITICAL"] > SEV_ORDER["HIGH"])
        check("info is the floor",
              min(SEV_ORDER.values()), SEV_ORDER["INFO"])
        findings = [CBFinding("LOW", "b", "x"), CBFinding("CRITICAL", "a", "x"),
                    CBFinding("MEDIUM", "c", "x")]
        check("sorting puts the worst first",
              [f.severity for f in sorted(findings, key=lambda f: f.sort_key())],
              ["CRITICAL", "MEDIUM", "LOW"])

        print("\n\033[1mHeaders\033[0m")
        found, artefacts = probe_headers(context, noop)
        titles = [f.title for f in found]
        check("a missing CSP is reported",
              any("Content-Security-Policy" in t for t in titles))
        check("a missing HSTS is reported",
              any("Strict-Transport-Security" in t for t in titles))
        check("the server banner is reported",
              any("version disclosed in server" in t.lower() for t in titles))
        check("X-Powered-By is reported",
              any("x-powered-by" in t for t in titles))
        check("a cookie without Secure is reported",
              any("without the Secure flag" in t for t in titles))
        check("and the cookie it belongs to is named in the location",
              any("session" in f.where for f in found
                  if "Secure flag" in f.title))
        check("the missing HttpOnly flag is its own issue, as in Burp",
              any("HttpOnly" in t for t in titles))
        check("WordPress is detected from the body",
              "wordpress" in artefacts["tech"])
        check("nginx is detected from the header",
              "nginx" in artefacts["tech"])
        # The test server is plain HTTP, so that finding is correct and is
        # the only one above medium a header pass should ever produce.
        check("plain HTTP is reported",
              any("Unencrypted" in t for t in titles))
        check("and nothing else exceeds medium",
              max([SEV_ORDER[f.severity] for f in found
                   if "Unencrypted" not in f.title] or [0]),
              SEV_ORDER["MEDIUM"])

        print("\n\033[1mOpen redirect\033[0m")
        found, _ = probe_redirects(context, noop)
        check("the vulnerable parameter is found", len(found) >= 1)
        if found:
            check("it names the parameter", "'next'" in found[0].title)
            check("it is reported as medium", found[0].severity, "MEDIUM")
            check("the evidence shows the Location header",
                  "Location:" in found[0].evidence)
        check("safe redirect parameters are not reported",
              any("'url'" in f.title or "'dest'" in f.title for f in found), False)

        print("\n\033[1mPath traversal\033[0m")
        traversal_context = dict(context, param_urls=[
            f"{base}/download?file=report.pdf&id=7",
            f"{base}/view?page=home",
        ])
        found, artefacts = probe_traversal(traversal_context, noop)
        check("the real file read is found", len(found), 1)
        if found:
            check("it is critical", found[0].severity, "CRITICAL")
            check("it names the parameter", "'file'" in found[0].title)
            check("the evidence proves a file was read",
                  "/etc/passwd" in found[0].evidence)
        check("a parameter that merely echoes is not reported",
              any("'page'" in f.title for f in found), False)
        check("requests were actually sent",
              artefacts["traversal_requests"] > 0)

        print("\n\033[1mThe traversal payload replaces the value\033[0m")
        # The bug this guards: keeping ?file=report.pdf and appending the
        # payload, which tests nothing.
        seen = []

        class Recorder(Handler):
            def do_GET(self):
                seen.append(self.path)
                return Handler.do_GET(self)

        recorder = ThreadingHTTPServer(("127.0.0.1", 0), Recorder)
        threading.Thread(target=recorder.serve_forever, daemon=True).start()
        rec_base = f"http://127.0.0.1:{recorder.server_address[1]}"
        probe_traversal(dict(context, url=rec_base, param_urls=[
            f"{rec_base}/download?file=report.pdf&id=7"]), noop)
        recorder.shutdown()
        # Two parameters means two sets of probes: while 'file' is under test
        # 'id' keeps its discovered value, and vice versa. Only the parameter
        # being tested loses its value.
        file_probes = [p for p in seen if "passwd" in p or "win.ini" in p]
        testing_file = [p for p in file_probes if "file=.." in p or "file=/etc" in p]
        testing_id = [p for p in file_probes if "id=.." in p or "id=/etc" in p]
        check("the tested parameter loses its value",
              all("report.pdf" not in p for p in testing_file))
        check("the untested parameter keeps its value",
              testing_file and all("id=7" in p for p in testing_file))
        check("every parameter gets its turn", bool(testing_id))
        check("and the other one keeps its value then",
              testing_id and all("file=report.pdf" in p for p in testing_id))

        print("\n\033[1m403 bypass\033[0m")
        found, artefacts = probe_403_bypass(
            dict(context, forbidden=[f"{base}/admin"]), noop)
        table = artefacts.get("bypass_table") or []
        check("every trick is attempted", len(table), len(BYPASS_TRICKS))
        check("the working tricks are found", len(found) >= 1)
        if found:
            check("they are reported as high", found[0].severity, "HIGH")
            check("the evidence shows the baseline",
                  "baseline was 403" in found[0].evidence)
        worked = {row["trick"] for row in table if row["bypassed"]}
        check("X-Original-URL is among them", "X-Original-URL" in worked)
        check("tricks that do not work are recorded as failures",
              any(not row["bypassed"] for row in table))
        check("nothing is claimed when the list is empty",
              probe_403_bypass(dict(context, forbidden=[]), noop)[0], [])

        print("\n\033[1mParsers\033[0m")
        engine = Engine(base)
        nmap = ("Starting Nmap\n"
                "22/tcp   open  ssh     OpenSSH 8.9\n"
                "80/tcp   open  http    nginx 1.24\n"
                "6379/tcp open  redis   Redis 7.0\n"
                "23/tcp   open  telnet\n")
        produced = engine._cb_parse_nmap({"key": "nmap_quick"}, nmap)
        check("risky services are reported", produced, 2)
        check("every open port is banked",
              len(engine._cb_artifacts["open_ports"]), 4)
        check("redis is high",
              [f.severity for f in engine._cb_findings
               if "redis" in f.title][0], "HIGH")

        engine = Engine(base)
        nuclei = "\n".join(json.dumps(row) for row in [
            {"template-id": "tech-detect", "matched-at": f"{base}/",
             "info": {"name": "Nginx detected", "severity": "info"}},
            {"template-id": "CVE-2021-1234", "matched-at": f"{base}/x",
             "info": {"name": "Remote code execution", "severity": "critical",
                      "description": "It is bad.", "remediation": "Patch it."}},
        ])
        produced = engine._cb_parse_nuclei({"key": "nuclei"}, nuclei)
        # A fingerprinting template is not a finding. It is still kept, but as
        # one collapsed entry rather than a row of its own.
        check("only the real issue counts as a finding", produced, 1)
        check("nuclei severities are carried over",
              sorted(f.severity for f in engine._cb_findings),
              ["CRITICAL", "INFO"])
        check("the fingerprint was folded into one entry",
              [f.title for f in engine._cb_findings
               if f.severity == "INFO"], ["Technology fingerprint"])
        check("and it names what was detected",
              "Nginx detected" in [f for f in engine._cb_findings
                                   if f.severity == "INFO"][0].evidence)
        # A template that names a known bug class is renamed onto the library
        # entry, so the advice is the library's settled wording and nuclei's
        # own text is kept in the detail.
        critical = [f for f in engine._cb_findings if f.severity == "CRITICAL"][0]
        check("a known bug class is renamed onto the library",
              critical.title, "OS command injection")
        check("with the library's remediation",
              "shell" in critical.remediation)
        check("and nuclei's own wording kept in the detail",
              "Remote code execution" in critical.detail)
        check("and a classification",
              critical.cwe.startswith("CWE-"))

        engine = Engine(base)
        fuzz = ("/admin                  [Status: 403, Size: 120]\n"
                "/login                  [Status: 200, Size: 900]\n"
                "/private                [Status: 401, Size: 12]\n")
        engine._cb_parse_fuzz({"key": "smartfuzz"}, fuzz)
        check("endpoints are banked",
              len(engine._cb_artifacts["endpoints"]), 3)
        check("401 and 403 go to the bypass stage",
              sorted(u.rsplit("/", 1)[-1]
                     for u in engine._cb_artifacts["forbidden"]),
              ["admin", "private"])
        check("200s do not", any("login" in u for u in
                                 engine._cb_artifacts["forbidden"]), False)

        engine = Engine(base)
        engine._cb_artifacts["endpoints"] = [f"{base}/search?q=x&lang=en"]
        engine._cb_parse_params({"key": "params"},
                                f"{base}/item?id=1\nnot a url\n")
        check("parameterised URLs are collected for traversal",
              len(engine._cb_artifacts["param_urls"]), 2)

        engine = Engine(base)
        nikto = ("+ Target IP: 127.0.0.1\n"
                 "+ Server: nginx\n"
                 "+ /admin/: Directory indexing found.\n"
                 "+ OSVDB-3233: /icons/README: Apache default file found.\n")
        produced = engine._cb_parse_nikto({"key": "nikto"}, nikto)
        check("banner lines are not counted as findings", produced, 2)
        check("the server banner is kept as information, not a finding",
              [f.severity for f in engine._cb_findings
               if f.key == "version_disclosure"], ["INFO"])
        # Nikto pattern-matches; it does not reproduce anything. On the
        # evidence scale that is a long way from confirmed, whatever Nikto
        # itself says.
        check("nikto findings never come out confirmed",
              all(f.confidence != cb_evidence.CONFIRMED_C
                  for f in engine._cb_findings))
        check("and none of them is presented as exploited",
              all(f.state != cb_evidence.CONFIRMED
                  for f in engine._cb_findings))

        print("\n\033[1mThe issue library\033[0m")
        from command_bridge.modules import cb_issues
        library = cb_issues.ISSUES
        check("it is a library, not a handful", len(library) >= 100)
        check("every entry has a severity the table can sort",
              sorted({i["severity"] for i in library.values()} - set(SEVERITIES)),
              [])
        check("every entry explains itself",
              [k for k, i in library.items() if len(i["detail"]) < 40], [])
        check("every entry says how to fix it",
              [k for k, i in library.items() if len(i["remediation"]) < 15], [])
        check("every entry carries a classification",
              [k for k, i in library.items()
               if not str(i["cwe"]).startswith("CWE-")], [])
        check("no two entries share a title",
              len({i["title"] for i in library.values()}), len(library))

        # The point of the mapping layer: three tools, three vocabularies, one
        # finding. Each of these is the wording a real tool actually emits.
        for text, expected in (
                ("Directory indexing found", "directory_listing"),
                ("/.git/config file found", "vcs_exposed"),
                ("phpinfo() page exposed", "info_page_exposed"),
                ("wp-config.php.bak", "backup_file"),
                ("Blind SQL injection in parameter id", "sqli"),
                ("JWT none algorithm accepted", "jwt_none"),
                ("Apache 2.4.49 path traversal", "traversal"),
                ("Server-side template injection", "ssti"),
                ("AWS access key disclosure", "cloud_key_disclosed"),
                ("Swagger UI exposed", "api_spec_exposed")):
            check(f"{text!r} is named", cb_issues.for_text(text)[0], expected)
        check("a line the library does not know is left alone",
              cb_issues.for_text("the quick brown fox")[0], None)
        check("a CVE template with no bug class falls back to the CVE entry",
              cb_issues.for_nuclei("CVE-2024-9999", "Some product flaw")[0],
              "known_cve")
        check("a fingerprint template is not an issue at all",
              cb_issues.for_nuclei("tech-detect", "Nginx detected")[0], None)
        check("nmap services map to the right kind of problem",
              (cb_issues.NMAP_SERVICES.get("redis"),
               cb_issues.NMAP_SERVICES.get("telnet"),
               cb_issues.NMAP_SERVICES.get("ms-wbt-server")),
              ("exposed_datastore", "cleartext_service",
               "remote_access_exposed"))

        print("\n\033[1mThe TLS stage survives a second run\033[0m")
        # The bug: --jsonfile REFUSES to overwrite. The first scan of a target
        # wrote the file and every scan after it died on a file-exists error,
        # which is why this only appeared on a target being re-scanned. Auto
        # Scan already cleared the files first; Coffee Break did not.
        engine = Engine(base)
        stale = engine.output_dir / \
            f"{engine.sanitize_target_for_filename(base)}_testssl.json"
        stale.write_text("a report from the last run")
        command = engine._cb_testssl_command()
        check("the previous run's reports are cleared first",
              engine.cleaned != [])
        check("so the stale JSON is gone before testssl starts",
              stale.exists(), False)
        check("the log file is written, for the built-in summariser",
              "--logfile" in command)
        check("and the text report, which is what it actually reads",
              "tee" in command)
        check("testssl.sh is tried as well as testssl",
              "testssl.sh" in command)
        check("a missing testssl says so rather than failing silently",
              "not installed" in command)
        check("no unsubstituted placeholders reach the shell",
              [p for p in ("{LOG_FILE}", "{JSON_FILE}", "{HOST}",
                           "{TXT_FILE}", "{TARGET}") if p in command], [])

        print("\n\033[1mA non-zero exit is not always a failure\033[0m")
        # testssl returns non-zero BECAUSE it found something. The
        # application already knew this — _summarize_testssl_if_applicable
        # says so in its own docstring — but the Coffee Break stage was
        # judging purely on the exit code and marking a good scan "failed".
        engine = Engine(base)
        safe = engine.sanitize_target_for_filename(base)
        report = engine.output_dir / f"{safe}_testssl.json"
        report.write_text(json.dumps([
            {"id": "SWEET32", "severity": "LOW", "cve": "CVE-2016-2183",
             "finding": "VULNERABLE, uses 64 bit block ciphers"}]))
        stage = {"key": "testssl", "parser": "_cb_parse_testssl",
                 "judge_by_output": True, "artefact_file": str(report),
                 "name": "TLS configuration (testssl)"}
        check("a report on disk means the stage produced something",
              engine._cb_stage_produced(stage, ""))
        check("no report and no output means it really did fail",
              engine._cb_stage_produced(
                  {"key": "x", "artefact_file": str(engine.output_dir / "no")},
                  ""), False)

        print("\n\033[1mDeprecated protocols and weak ciphers are "
              "reported\033[0m")
        engine = Engine(base)
        records = [
            {"id": "SSLv2", "severity": "OK", "finding": "not offered"},
            {"id": "SSLv3", "severity": "HIGH", "finding": "offered (NOT ok)"},
            {"id": "TLS1", "severity": "LOW", "finding": "offered (deprecated)"},
            {"id": "TLS1_1", "severity": "LOW",
             "finding": "offered (deprecated)"},
            {"id": "TLS1_2", "severity": "OK", "finding": "offered (OK)"},
            {"id": "LUCKY13", "severity": "LOW", "cve": "CVE-2013-0169",
             "finding": "potentially VULNERABLE, uses TLS CBC ciphers"},
            {"id": "SWEET32", "severity": "LOW", "cve": "CVE-2016-2183",
             "finding": "VULNERABLE, uses 64 bit block ciphers"},
            {"id": "RC4", "severity": "HIGH", "cve": "CVE-2013-2566",
             "finding": "VULNERABLE (NOT ok): RC4-SHA RC4-MD5"},
            {"id": "BEAST", "severity": "LOW", "cve": "CVE-2011-3389",
             "finding": "VULNERABLE -- but also supports higher protocols"},
            {"id": "cipherlist_3DES_IDEA", "severity": "MEDIUM",
             "finding": "offered"},
            {"id": "heartbleed", "severity": "OK", "finding": "not vulnerable"},
            {"id": "cert_expirationStatus", "severity": "MEDIUM",
             "finding": "expires < 30 days (17)"},
        ]
        path = engine.output_dir / "report.json"
        path.write_text(json.dumps(records))
        engine._cb_parse_testssl(
            {"key": "testssl", "artefact_file": str(path)}, "")
        by_key = {f.key: f for f in engine._cb_findings}
        for key, label in (("obsolete_protocol", "deprecated protocols"),
                           ("lucky13", "Lucky 13"),
                           ("sweet32", "Sweet32"),
                           ("rc4", "RC4"),
                           ("beast", "BEAST"),
                           ("weak_cipher", "3DES / weak ciphers")):
            check(f"{label} is reported", key in by_key)
        check("the protocol finding names the versions",
              by_key["obsolete_protocol"].title,
              "Obsolete TLS protocol versions enabled: SSLv3, TLS 1.0, TLS 1.1")
        check("and carries each one as evidence",
              all(v in by_key["obsolete_protocol"].evidence
                  for v in ("SSLv3", "TLS1", "TLS1_1")))
        check("a protocol that is not offered is not reported",
              "SSLv2" in by_key["obsolete_protocol"].evidence, False)
        check("and neither is one that is fine",
              "TLS1_2" in by_key["obsolete_protocol"].evidence, False)
        check("a clean Heartbleed result is not a finding",
              "heartbleed" in by_key, False)
        check("a certificate expiring in 17 days is not called expired",
              "cert_expiring" in by_key)
        check("Lucky 13 carries the CVE",
              "CVE-2013-0169" in by_key["lucky13"].references)

        print("\n\033[1mThe library is the scoring policy\033[0m")
        # A tool's rating no longer overrides the library's, in either
        # direction. testssl rates SSLv3 "HIGH"; the house scoring says
        # deprecated protocols are MEDIUM, and the report has to be
        # consistent whichever tool happened to notice.
        from command_bridge.modules.cb_issues import severity_for, TOOL_RATED
        check("Lucky 13 is Low", cb_issues.ISSUES["lucky13"]["severity"],
              "LOW")
        check("deprecated protocols are Medium",
              cb_issues.ISSUES["obsolete_protocol"]["severity"], "MEDIUM")
        check("RC4 is Medium", cb_issues.ISSUES["rc4"]["severity"], "MEDIUM")
        check("a tool cannot escalate a named issue",
              severity_for("obsolete_protocol", "HIGH"), "MEDIUM")
        check("nor lower one", severity_for("info_page_exposed", "LOW"),
              "MEDIUM")
        check("but a CVE passthrough still takes the tool's rating",
              severity_for("known_cve", "CRITICAL"), "CRITICAL")
        check("and an unknown key falls back to it",
              severity_for("no_such_issue", "HIGH"), "HIGH")
        check("the passthrough list is short and deliberate",
              sorted(TOOL_RATED),
              ["known_cve", "scan_information", "tls_generic"])

        engine = Engine(base)
        records = [
            {"id": "SSLv3", "severity": "HIGH", "finding": "offered (NOT ok)"},
            {"id": "TLS1", "severity": "LOW",
             "finding": "offered (deprecated)"},
            {"id": "LUCKY13", "severity": "LOW", "cve": "CVE-2013-0169",
             "finding": "potentially VULNERABLE, uses TLS CBC ciphers"},
            {"id": "RC4", "severity": "HIGH", "cve": "CVE-2013-2566",
             "finding": "VULNERABLE (NOT ok): RC4-SHA"},
        ]
        path = engine.output_dir / "scored.json"
        path.write_text(json.dumps(records))
        engine._cb_parse_testssl(
            {"key": "testssl", "artefact_file": str(path)}, "")
        scored = {f.key: f.severity for f in engine._cb_findings}
        check("SSLv3 rated high by testssl is reported Medium",
              scored.get("obsolete_protocol"), "MEDIUM")
        check("Lucky 13 is reported Low", scored.get("lucky13"), "LOW")
        check("RC4 rated high by testssl is reported Medium",
              scored.get("rc4"), "MEDIUM")

        print("\n\033[1mDiscovered Parameters.txt\033[0m")
        from command_bridge.modules.coffee_break import strip_parameter_values
        check("a value is stripped, the name kept",
              strip_parameter_values("https://example.com/search?q=Test"),
              "https://example.com/search?q=")
        check("every parameter on the URL is kept",
              strip_parameter_values("https://example.com/i?id=7&sort=name"),
              "https://example.com/i?id=&sort=")
        check("order is preserved, not sorted",
              strip_parameter_values("https://example.com/i?z=1&a=2"),
              "https://example.com/i?z=&a=")
        check("a repeated name appears once",
              strip_parameter_values("http://example.com/a?x=1&x=2"),
              "http://example.com/a?x=")
        check("a fragment is dropped",
              strip_parameter_values("https://example.com/p?a=1#top"),
              "https://example.com/p?a=")
        check("a URL with no parameters produces nothing",
              strip_parameter_values("https://example.com/plain"), "")
        check("and neither does rubbish",
              strip_parameter_values("not a url at all"), "")

        engine = Engine(base)
        engine._cb_artifacts["endpoints"] = [
            f"{base}/search?q=Test", f"{base}/item?id=7"]
        engine._cb_parse_params({"key": "params"},
                                f"{base}/view?page=2&id=99\n")
        written = Path(engine.output_dir) / "Discovered Parameters.txt"
        check("the file is written, under that name", written.is_file())
        lines = written.read_text().strip().splitlines()
        check("one line per parameter shape", len(lines), 3)
        check("values are gone",
              [line for line in lines if line.rstrip().endswith(("7", "2", "99",
                                                                "Test"))], [])
        check("the search parameter is there",
              any(line.endswith("/search?q=") for line in lines))
        check("and a two-parameter URL keeps both",
              any(line.endswith("/view?page=&id=") for line in lines))
        check("the traversal stage still gets the real values",
              any("id=7" in u for u in engine._cb_artifacts["param_urls"]))
        check("and the path is recorded for the report",
              engine._cb_artifacts.get("parameter_file"), str(written))
        engine._cb_parse_params({"key": "params"}, "")
        check("a second pass does not duplicate the lines",
              len(written.read_text().strip().splitlines()), 3)

        print("\n\033[1mtestssl becomes named issues\033[0m")
        # The JSON testssl writes, in the shape it writes it. Three of these
        # four records are the scanner saying the host is *fine*, which is what
        # used to fill the findings screen.
        engine = Engine(base)
        records = [
            {"id": "LUCKY13", "severity": "LOW", "cve": "CVE-2013-0169",
             "cwe": "CWE-310",
             "finding": "potentially vulnerable, uses TLS CBC ciphers"},
            {"id": "cbc_tls1_2", "severity": "MEDIUM", "cve": "", "cwe": "",
             "finding": "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384, "
                        "TLS_RSA_WITH_AES_128_CBC_SHA"},
            {"id": "DROWN", "severity": "OK", "cve": "CVE-2016-0800",
             "cwe": "CWE-310", "finding": "not vulnerable to DROWN"},
            {"id": "cipher_order", "severity": "INFO", "cve": "", "cwe": "",
             "finding": "server order honoured"},
        ]
        json_path = engine.output_dir / "x_testssl.json"
        json_path.write_text(json.dumps(records))
        stage = {"key": "testssl", "artefact_file": str(json_path)}
        produced = engine._cb_parse_testssl(stage, "")
        titles = [f.title for f in engine._cb_findings]
        check("CBC ciphers are reported as Lucky 13",
              any(t.startswith("Lucky 13") for t in titles))
        check("the title is not cut off mid-word",
              all(not t.endswith(("…", " ")) for t in titles))
        check("the printed ciphers are the proof",
              any("AES_256_CBC_SHA384" in f.evidence
                  for f in engine._cb_findings))
        check("both CBC records folded into the one issue", produced, 1)
        check("a clean result is not a finding",
              any("DROWN" in t for t in titles), False)
        check("and neither is an informational one",
              any("order" in t.lower() for t in titles), False)
        check("the CVE is carried as a reference",
              "CVE-2013-0169" in engine._cb_findings[0].references)
        check("so is the classification",
              engine._cb_findings[0].cwe, "CWE-203")
        check("the explanation is the library's, not the scanner's line",
              "padding" in engine._cb_findings[0].detail.lower())

        engine = Engine(base)
        text = ("Heartbleed (CVE-2014-0160)   CRITICAL: vulnerable, can read "
                "64k of memory\n")
        check("the console fallback still works when there is no JSON",
              engine._cb_parse_testssl({"key": "testssl"}, text), 1)
        check("and it is the named issue",
              engine._cb_findings[0].title.startswith("Heartbleed"))
        check("at the library's severity",
              engine._cb_findings[0].severity, "CRITICAL")

        print("\n\033[1mConsolidation\033[0m")
        engine = Engine(base)
        for _ in range(3):
            engine._cb_record(CBFinding("HIGH", "same", "same place"))
        check("the same finding in the same place is kept once",
              len(engine._cb_findings), 1)

        engine = Engine(base)
        for page in ("/", "/about", "/contact", "/shop"):
            engine._cb_record(CBFinding(
                "MEDIUM", "Content-Security-Policy is missing",
                base + page, stage="headers"))
        check("one issue across four pages is one row",
              len(engine._cb_findings), 1)
        check("and the other three are instances",
              engine._cb_findings[0].count, 4)
        check("every location is kept",
              len(engine._cb_findings[0].locations()), 4)
        check("a different issue is still its own row",
              (engine._cb_record(CBFinding("LOW", "other", base,
                                           stage="headers")),
               len(engine._cb_findings))[1], 2)

        print("\n\033[1mTitles\033[0m")
        from command_bridge.modules.cb_issues import clean_title
        long_one = ("Deserialization of untrusted data in the session handler "
                    "leading to remote code execution on the application "
                    "server without authentication")
        short = clean_title(long_one)
        check("a long title is cut on a word boundary",
              short.rstrip("…").split()[-1] in long_one.split())
        check("and says it was cut", short.endswith("…"))
        check("a short title is left alone",
              clean_title("Directory indexing found"),
              "Directory indexing found")
        check("colour codes are stripped",
              clean_title("\x1b[31mRC4 ciphers\x1b[0m"), "RC4 ciphers")

        print("\n\033[1mA scanner's bookkeeping is not a finding\033[0m")
        engine = Engine(base)
        nikto = "\n".join("+ " + line for line in [
            "Target IP: 127.0.0.1",
            "Server: nginx/1.24",
            "Retrieved x-powered-by header: PHP/8.1",
            "/test.php: This might be interesting.",
            "8299 requests: 0 errors and 11 items reported on the remote host",
            "1 host(s) tested",
            "ERROR: Failed to check for updates: 403",
            "Platform: Unknown",
            "Start Time: 2026-09-28 10:00:00",
            "/admin/: Directory indexing found.",
            "Umbraco Login Panel found at /umbraco/",
            'The Content-Encoding header is set to "deflate" which may mean '
            "that the server is vulnerable to the BREACH attack",
        ])
        engine._cb_parse_nikto({"key": "nikto"}, nikto)
        titles = [f.title for f in engine._cb_findings]
        for statement in ("host(s) tested", "requests:", "Failed to check",
                          "Platform", "Start Time"):
            check(f"{statement!r} is not reported",
                  any(statement in t for t in titles), False)
        check("a real finding still is",
              any("Directory listing" in t for t in titles))

        print("\n\033[1mSeverity discipline\033[0m")
        panel = [f for f in engine._cb_findings
                 if "login panel" in f.title.lower()]
        check("an exposed admin login panel is found", len(panel), 1)
        check("and it is not Low", panel[0].severity, "MEDIUM")
        check("and it carries the path, not just the host",
              panel[0].where.endswith("/umbraco/"))
        check("observations are collected as Info, not Low",
              [f.severity for f in engine._cb_findings
               if "inventory" in f.title.lower()], ["INFO"])
        check("two tools' wording for the same banner is one finding",
              len([f for f in engine._cb_findings
                   if f.key == "version_disclosure"]), 1)
        check("nothing was reported at Low that is only an observation",
              [f.title for f in engine._cb_findings
               if f.severity == "LOW" and "Server:" in f.evidence], [])

        print("\n\033[1mOne issue, however many tools find it\033[0m")
        # Nikto words BREACH as a Content-Encoding observation; testssl names
        # it. Two tools, two vocabularies, one problem — and previously two
        # findings that a human had to work out were the same.
        breach = [f for f in engine._cb_findings if f.key == "breach"]
        check("Nikto's deflate line is recognised as BREACH", len(breach), 1)
        records = [{"id": "BREACH", "severity": "LOW", "cve": "CVE-2013-3587",
                    "cwe": "CWE-310",
                    "finding": "potentially NOT ok, uses gzip HTTP compression"}]
        json_path = engine.output_dir / "x_testssl.json"
        json_path.write_text(json.dumps(records))
        engine._cb_parse_testssl(
            {"key": "testssl", "artefact_file": str(json_path)}, "")
        breach = [f for f in engine._cb_findings if f.key == "breach"]
        check("testssl's BREACH lands on the same finding", len(breach), 1)
        check("and the finding names both tools",
              sorted(breach[0].sources), ["nikto", "testssl"])
        check("corroboration raises confidence, not severity",
              (breach[0].confidence, breach[0].severity),
              (cb_evidence.HIGH, "LOW"))
        check("and never past the ceiling for something nobody exploited",
              breach[0].confidence != cb_evidence.CONFIRMED_C)

        print("\n\033[1mMuting an issue type\033[0m")
        engine = Engine(base)
        engine._cb_muted = {"breach"}
        engine._cb_record(engine._cb_issue("breach", base, "x", "testssl"))
        check("a muted issue is never recorded", engine._cb_findings, [])
        engine._cb_muted = set()
        engine._cb_record(engine._cb_issue("breach", base, "x", "testssl"))
        check("and is recorded again once unmuted",
              len(engine._cb_findings), 1)

        print("\n\033[1mtestssl says what is actually wrong\033[0m")
        engine = Engine(base)
        records = [
            {"id": "FS_TLS12_sig_algs", "severity": "INFO", "cve": "",
             "cwe": "", "finding": "RSA-PSS-RSAE+SHA256 RSA+SHA256 RSA+SHA1"},
            {"id": "DNS_CAArecord", "severity": "LOW", "cve": "", "cwe": "",
             "finding": ""},
            {"id": "cipher_order", "severity": "OK", "cve": "", "cwe": "",
             "finding": "server order honoured"},
            {"id": "cert_serialNumber", "severity": "INFO", "cve": "",
             "cwe": "", "finding": "0A1B2C3D"},
        ]
        json_path = engine.output_dir / "x_testssl.json"
        json_path.write_text(json.dumps(records))
        engine._cb_parse_testssl(
            {"key": "testssl", "artefact_file": str(json_path)}, "")
        titles = [f.title for f in engine._cb_findings]
        check("a signature algorithm list containing SHA-1 is named",
              any("signature algorithm" in t.lower() for t in titles))
        weak = [f for f in engine._cb_findings
                if f.key == "tls_weak_signature_alg"][0]
        check("and it explains why SHA-1 matters",
              "collision" in weak.detail.lower())
        check("a missing CAA record is Info, not a weakness",
              [f.severity for f in engine._cb_findings
               if f.key == "caa_missing"], ["INFO"])
        check("the cipher order record is not reported at all",
              any("order" in t.lower() for t in titles), False)
        check("nor is the certificate serial number",
              any("serial" in t.lower() for t in titles), False)
        check("nothing came out as an unexplained 'TLS configuration "
              "weakness'",
              any(t == "TLS configuration weakness" for t in titles), False)

        print("\n\033[1mNothing worth reporting is silently folded\033[0m")
        # The regression this exists for: nuclei files its entire
        # exposed-panels library at severity "info" with no remediation, and
        # the fold rule was "info + no remediation = inventory". A publicly
        # reachable Umbraco login page disappeared into "Technology
        # fingerprint". Separately, git-config was ON the fingerprint list, so
        # a readable .git vanished too. Every line below is a real finding and
        # must come out as one.
        engine = Engine(base)
        engine._cb_artifacts["robots_checked"] = False
        must_report = [
            ("umbraco-login", "Umbraco Login Panel", "info",
             "login_panel_exposed"),
            ("phpmyadmin-panel", "phpMyAdmin Panel", "info",
             "login_panel_exposed"),
            ("jenkins-login", "Jenkins Login Panel", "info",
             "login_panel_exposed"),
            ("git-config", "Git Config Exposure", "medium", "vcs_exposed"),
            ("phpinfo-files", "phpinfo() Disclosure", "low",
             "info_page_exposed"),
            ("http-trace", "HTTP TRACE method enabled", "info",
             "trace_enabled"),
            ("swagger-api", "Swagger API Documentation", "info",
             "api_spec_exposed"),
            ("CVE-2021-41773", "Apache 2.4.49 path traversal", "critical",
             "traversal"),
        ]
        rows = [json.dumps({"template-id": tid,
                            "matched-at": f"{base}/{tid}",
                            "info": {"name": name, "severity": sev}})
                for tid, name, sev, _key in must_report]
        # and some that genuinely are inventory
        rows += [json.dumps({"template-id": tid, "matched-at": base,
                             "info": {"name": name, "severity": "info"}})
                 for tid, name in (("tech-detect", "Nginx detected"),
                                   ("waf-detect", "Cloudflare WAF"),
                                   ("ssl-dns-names", "SSL DNS names"))]
        engine._cb_parse_nuclei({"key": "nuclei"}, "\n".join(rows))
        keys = {f.key for f in engine._cb_findings}
        for _tid, name, _sev, key in must_report:
            check(f"{name!r} is reported", key in keys)
        check("an exposed admin panel is Medium, not Info",
              [f.severity for f in engine._cb_findings
               if f.key == "login_panel_exposed"], ["MEDIUM"])
        check("a tool rating cannot lower the library's severity",
              [f.severity for f in engine._cb_findings
               if f.key == "info_page_exposed"], ["MEDIUM"])
        check("three panels on one host are one finding with three places",
              [f.count for f in engine._cb_findings
               if f.key == "login_panel_exposed"], [3])
        check("real fingerprinting is still folded away",
              [f.title for f in engine._cb_findings if f.severity == "INFO"],
              ["Technology fingerprint"])
        check("and the folded entry names what was detected",
              all(word in [f for f in engine._cb_findings
                           if f.severity == "INFO"][0].evidence
                  for word in ("Nginx", "Cloudflare")))

        print("\n\033[1mSecurity headers\033[0m")
        from command_bridge.modules.coffee_break import (
            SECURITY_HEADERS, analyse_csp)
        check("X-Permitted-Cross-Domain-Policies is checked",
              SECURITY_HEADERS.get("x-permitted-cross-domain-policies"),
              "xpcdp_missing")
        check("and it explains what an Adobe client does without it",
              "crossdomain.xml" in
              cb_issues.ISSUES["xpcdp_missing"]["detail"])

        sound = ("default-src 'self'; script-src 'self'; object-src 'none'; "
                 "base-uri 'self'; frame-ancestors 'none'; form-action 'self'")
        check("a sound policy raises nothing", analyse_csp(sound), [])
        check("unsafe-inline is caught",
              "csp_unsafe_script" in analyse_csp(
                  sound.replace("script-src 'self'",
                                "script-src 'self' 'unsafe-inline'")))
        check("a nonce excuses unsafe-inline, as the browser does",
              analyse_csp(sound.replace(
                  "script-src 'self'",
                  "script-src 'nonce-r4nd0m' 'unsafe-inline'")), [])
        check("but never excuses unsafe-eval",
              "csp_unsafe_script" in analyse_csp(sound.replace(
                  "script-src 'self'",
                  "script-src 'nonce-r4nd0m' 'unsafe-eval'")))
        for source, label in (("*", "a bare wildcard"),
                              ("https:", "a scheme-wide source"),
                              ("data:", "a data: source")):
            check(f"{label} in script-src is caught",
                  "csp_wildcard_source" in analyse_csp(
                      sound.replace("script-src 'self'",
                                    f"script-src 'self' {source}")))
        check("a missing object-src is caught",
              "csp_missing_object_base" in analyse_csp(
                  sound.replace("object-src 'none'; ", "")))
        check("a missing base-uri is caught",
              "csp_missing_object_base" in analyse_csp(
                  sound.replace("base-uri 'self'; ", "")))
        check("a missing frame-ancestors is caught",
              "csp_clickjacking" in analyse_csp(
                  sound.replace("frame-ancestors 'none'; ", "")))
        check("script-src falls back to default-src when absent",
              "csp_unsafe_script" in analyse_csp(
                  "default-src 'self' 'unsafe-inline'; object-src 'none'; "
                  "base-uri 'self'; frame-ancestors 'none'; "
                  "form-action 'self'"))
        check("an empty header analyses to nothing", analyse_csp(""), [])

        print("\n\033[1mThe report\033[0m")
        engine = Engine(base)
        engine._cb_record(CBFinding("CRITICAL", "Path traversal via 'file'",
                                    f"{base}/download", "reads files",
                                    "root:x:0:0", "map an id to a file",
                                    "traversal"))
        engine._cb_artifacts["bypass_table"] = [
            {"url": f"{base}/admin", "trick": "X-Original-URL", "method": "GET",
             "status": 200, "length": 24, "baseline": 403, "bypassed": True}]
        report = engine.coffee_break_report()
        check("the finding is in it", "Path traversal via 'file'" in report)
        check("the evidence is in it", "root:x:0:0" in report)
        check("the bypass table is in it", "| X-Original-URL |" in report)
        check("severity headings are used", "## CRITICAL (1)" in report)

        # ─────────────────────────────────────────────────────────────────
        #  The evidence chain
        # ─────────────────────────────────────────────────────────────────
        #
        # These exist because of one real report: a Content-Security-Policy
        # header was published as a CRITICAL CWE-78 OS command injection with
        # "Input reaches a shell" above it and `object-src 'none'` underneath
        # as the proof. Every check below is a different way of asking that
        # the tool cannot do that again.

        def nuclei_line(**over):
            row = {"template-id": "weak-csp-detect", "matched-at": base,
                   "info": {"name": "Weak Content Security Policy - Detect",
                            "severity": "info",
                            "author": ["geeknik"],
                            "tags": ["csp", "misconfig"],
                            "description":
                                "Content Security Policy is an added layer "
                                "of security that helps to detect and "
                                "mitigate certain types of attacks, "
                                "including Cross-Site Scripting and data "
                                "injection attacks, which can lead to "
                                "arbitrary code execution."},
                   "extracted-results":
                       ["object-src 'none'; frame-ancestors 'self' "
                        "https://www.paypal.com"]}
            row.update(over)
            return json.dumps(row)

        print("\n\033[1mTest B — a CSP template stays a CSP finding\033[0m")
        # The exact input that produced the bad report.
        key, _ = cb_issues.for_nuclei(
            "weak-csp-detect", "Weak Content Security Policy - Detect",
            "…which can lead to arbitrary code execution.")
        check("classification comes from the template, not its prose",
              key, "csp_missing")
        check("and CWE-78 is nowhere near it",
              cb_issues.ISSUES[key]["cwe"] != "CWE-78")

        engine = Engine(base)
        engine._cb_parse_nuclei({"key": "nuclei"}, nuclei_line())
        csp = engine._cb_findings[0]
        # weak-csp-detect EXTRACTS the policy, so the header is present
        # and permissive rather than absent. The detector registry
        # classifies it on the template's identity; the old expectation
        # of csp_missing came from keyword matching and contradicted the
        # policy string the same finding carried as its evidence.
        check("the finding is about CSP", csp.key, "csp_unsafe_script")
        check("it is not OS command injection",
              "command injection" not in csp.title.lower())
        check("it is not CRITICAL", csp.severity != "CRITICAL")
        check("the template id survives into the evidence",
              csp.proof.template_id, "weak-csp-detect")
        check("so do nuclei's tags", csp.proof.template_tags,
              ["csp", "misconfig"])
        # csp_missing is LOW in the library as of 6.8.2 — a missing
        # defence-in-depth header is not a Medium beside things that
        # actually do something. nuclei's own rating stays separate.
        check("and nuclei's own severity is kept apart from ours",
              (csp.scanner_severity, csp.severity), ("INFO", "MEDIUM"))
        check("the raw detection is still available",
              "weak-csp-detect" in csp.proof.raw_detection())

        print("\n\033[1mTest D — a claim with no evidence is not "
              "confirmed\033[0m")
        # Force the old failure directly: CWE-78 classification, CSP proof.
        contaminated = CBFinding(
            "CRITICAL", "OS command injection", base,
            detail=cb_issues.ISSUES["command_injection"]["detail"],
            remediation=cb_issues.ISSUES["command_injection"]["remediation"],
            cwe="CWE-78",
            key="command_injection", stage="nuclei",
            proof=Evidence(detector="nuclei", template_id="weak-csp-detect",
                           url=base,
                           extracted=["object-src 'none'; frame-ancestors "
                                      "'self'"]))
        check("it is not presented as confirmed",
              contaminated.state != cb_evidence.CONFIRMED)
        check("it is inconclusive", contaminated.state,
              cb_evidence.INCONCLUSIVE)
        check("confidence is not 'firm'", contaminated.confidence,
              cb_evidence.POTENTIAL_C)
        check("the mismatch is stated, not swallowed",
              any("Classification conflict" in c
                  for c in contaminated.validation.conflicts))
        check("the conflict names both subjects",
              "csp" in contaminated.validation.conflicts[0]
              and "command_injection" in contaminated.validation.conflicts[0])
        check("and it says manual validation is required",
              "MANUAL VALIDATION REQUIRED" in
              contaminated.validation.action.upper())
        check("no PoC is invented", contaminated.proof.poc(), "")
        check("the report says so instead",
              "PoC unavailable" in
              "\n".join(Engine(base)._cb_evidence_block(contaminated)))
        check("no parameter is invented", contaminated.proof.parameter, "")
        check("no payload is invented", contaminated.proof.payload, "")
        check("the false-positive reasons are the missing pieces",
              any("no injection point" in i.lower()
                  for i in
                  contaminated.validation.false_positive_indicators))

        # The same classification with nothing at all behind it: still not a
        # confirmed critical, even without a contradiction to catch it.
        bare = CBFinding("CRITICAL", "OS command injection", base,
                         key="command_injection", stage="nuclei")
        check("an evidence-free CWE-78 is only POTENTIAL",
              bare.state, cb_evidence.POTENTIAL)
        check("with the missing pieces enumerated",
              sorted(bare.validation.missing),
              ["injection_point", "observation", "payload"])

        print("\n\033[1mTest A — a genuine command injection reports "
              "fully\033[0m")

        class FakeEvidence:
            label = "injected payload: ;id"
            request = "GET http://target/ping?host=127.0.0.1%3Bid"
            # The wire form, captured by the check at the moment it sent the
            # request. burp_request() returns this and nothing else: the
            # human-readable summary above is not a request Burp accepts.
            raw_request = ("GET /ping?host=127.0.0.1%3Bid HTTP/1.1\r\n"
                           "Host: target\r\nCookie: sid=abc123\r\n\r\n")
            response = "HTTP/1.1 200 OK\n\nuid=33(www-data) gid=33(www-data)"
            note = ("The response to ';id' contains uid=33(www-data), which "
                    "the baseline response does not.")
            payload = "127.0.0.1;id"

            def render(self):
                return self.request + "\n→\n" + self.response

        class FakeScan:
            issue = "command_injection"
            where = f"{base}/ping"
            point = "host"
            severity = ""
            confidence = "confirmed"
            detail_extra = ""
            evidence = [FakeEvidence()]

            def evidence_text(self):
                return self.evidence[0].render()

        real = finding_from_scan(FakeScan())
        check("it is classified as OS command injection",
              real.title, "OS command injection")
        check("with CWE-78", real.cwe, "CWE-78")
        check("severity is CRITICAL", real.severity, "CRITICAL")
        check("the state is CONFIRMED", real.state, cb_evidence.CONFIRMED)
        check("and the confidence is confirmed", real.confidence,
              cb_evidence.CONFIRMED_C)
        check("the classification is consistent with the evidence",
              real.validation.classification_consistent)
        check("the evidence is sufficient", real.validation.evidence_sufficient)
        check("there are no false-positive indicators",
              real.validation.false_positive_indicators, [])
        poc = real.proof.poc()
        check("a PoC exists", bool(poc))
        check("it names the parameter", "host" in poc)
        check("it shows the payload", "127.0.0.1;id" in poc)
        check("it shows the request", "GET http://target/ping?host=" in poc)
        check("it shows the response", "uid=33(www-data)" in poc)
        check("it explains the observation", "baseline response does not" in poc)
        check("and it pastes into Burp",
              real.proof.burp_request().startswith("GET /ping?host="))

        print("\n\033[1mTest C — findings do not swap evidence\033[0m")
        engine = Engine(base)
        engine._cb_record(real)
        engine._cb_parse_nuclei({"key": "nuclei"}, nuclei_line())
        by_key = {f.key: f for f in engine._cb_findings}
        # weak-csp-detect reports a policy that IS present and
        # permissive — it extracts the policy string itself — so the
        # detector registry classifies it as a permissive CSP, not a
        # missing one. The old expectation here was csp_missing, which
        # came from keyword matching and contradicted the evidence the
        # same finding carried.
        check("both findings are present", sorted(by_key), sorted(
            ["command_injection", "csp_unsafe_script"]))
        check("the injection keeps its own proof",
              "uid=33(www-data)" in by_key["command_injection"].proof.response)
        check("and did not acquire the CSP header",
              "object-src" not in
              by_key["command_injection"].proof.evidence_text())
        check("the CSP finding kept its own proof",
              "object-src" in by_key["csp_unsafe_script"].proof.evidence_text())
        check("and did not acquire the shell output",
              "uid=33" not in by_key["csp_unsafe_script"].proof.evidence_text())
        check("their evidence objects are not the same object",
              by_key["command_injection"].proof is not
              by_key["csp_unsafe_script"].proof)
        check("nor do they share a correlation id",
              by_key["command_injection"].proof.correlation_id !=
              by_key["csp_unsafe_script"].proof.correlation_id)

        # Mutating one must not reach the other, and must not reach whatever
        # built it either.
        source_proof = Evidence(url=base, raw="uid=0(root)",
                                parameter="cmd", payload=";id",
                                detector="probe")
        held = engine._cb_issue("command_injection", base, proof=source_proof,
                                stage="probe")
        source_proof.raw = "MUTATED AFTER THE FACT"
        check("a finding copies the evidence handed to it",
              held.proof.raw, "uid=0(root)")

        print("\n\033[1mTest F — de-duplication does not merge unrelated "
              "evidence\033[0m")
        engine = Engine(base)
        engine._cb_record(CBFinding(
            "MEDIUM", "Missing Content-Security-Policy", f"{base}/one",
            key="csp_missing", stage="nuclei",
            proof=Evidence(url=f"{base}/one", detector="nuclei",
                           raw="Content-Security-Policy: default-src 'self'")))
        engine._cb_record(CBFinding(
            "MEDIUM", "Missing Content-Security-Policy", f"{base}/two",
            key="csp_missing", stage="nikto",
            proof=Evidence(url=f"{base}/two", detector="nikto",
                           raw="Content-Security-Policy header not found")))
        merged = [f for f in engine._cb_findings if f.key == "csp_missing"]
        check("the same issue at two places is one finding", len(merged), 1)
        check("with both locations listed", merged[0].count, 2)
        check("and both tools named", sorted(merged[0].sources),
              ["nikto", "nuclei"])
        check("each sighting keeps its own evidence object",
              len(merged[0].instance_proof), 1)
        check("the second sighting's proof is its own",
              merged[0].instance_proof[0].raw,
              "Content-Security-Policy header not found")
        check("and the first is untouched",
              merged[0].proof.raw,
              "Content-Security-Policy: default-src 'self'")

        # Same key, incompatible evidence: these must NOT become one row.
        engine = Engine(base)
        engine._cb_record(real)
        engine._cb_record(CBFinding(
            "CRITICAL", "OS command injection", f"{base}/other",
            key="command_injection", stage="nuclei",
            proof=Evidence(url=f"{base}/other", detector="nuclei",
                           raw="Content-Security-Policy: object-src 'none'")))
        injections = [f for f in engine._cb_findings
                      if f.key == "command_injection"]
        check("an exploited finding does not absorb an unrelated alert",
              len(injections), 2)
        check("the confirmed one is still confirmed",
              injections[0].state, cb_evidence.CONFIRMED)
        check("the unsupported one is still inconclusive",
              injections[1].state, cb_evidence.INCONCLUSIVE)

        print("\n\033[1mTest E — concurrent scanners do not cross-"
              "contaminate\033[0m")
        engines = []
        errors = []

        def run_one(index):
            try:
                local = Engine(f"{base}/site{index}")
                # One scanner feeding a CSP template, another feeding real
                # shell output, both at once, over and over.
                for _ in range(15):
                    local._cb_parse_nuclei({"key": "nuclei"}, nuclei_line(
                        **{"matched-at": f"{base}/site{index}"}))
                    local._cb_record(CBFinding(
                        "CRITICAL", "OS command injection",
                        f"{base}/site{index}/ping",
                        key="command_injection", stage="active-scan",
                        proof=Evidence(
                            url=f"{base}/site{index}/ping",
                            parameter="host", payload=f";id{index}",
                            detector="active-scan",
                            request=f"GET /ping?host=;id{index}",
                            response=f"uid={index}(user{index})",
                            observed=f"uid={index}(user{index}) came back")))
                engines.append((index, local))
            except Exception as exc:                    # noqa: BLE001
                errors.append(exc)

        workers = [threading.Thread(target=run_one, args=(i,))
                   for i in range(6)]
        for worker in workers:
            worker.start()
        for worker in workers:
            worker.join()
        check("every worker finished", len(engines), 6)
        check("with no exceptions", errors, [])
        clean = True
        for index, local in engines:
            found = {f.key: f for f in local._cb_findings}
            if sorted(found) != ["command_injection", "csp_unsafe_script"]:
                clean = False
                break
            injection = found["command_injection"]
            csp_finding = found["csp_unsafe_script"]
            if f"uid={index}(user{index})" not in injection.proof.response:
                clean = False
            if "object-src" in injection.proof.evidence_text():
                clean = False
            if "uid=" in csp_finding.proof.evidence_text():
                clean = False
            # Nobody else's host may appear anywhere in this engine's proof.
            for other, _ in engines:
                if other != index and \
                        f"site{other}" in injection.proof.evidence_text():
                    clean = False
        check("no engine holds another engine's evidence, URL or "
              "classification", clean)

        print("\n\033[1mThe report separates what was seen from what it "
              "means\033[0m")
        engine = Engine(base)
        engine._cb_record(contaminated)
        text = engine.coffee_break_report()
        check("the state is printed", "**Status:** INCONCLUSIVE" in text)
        check("both severities are shown, and labelled",
              "Severity (tool-assessed)" in text)
        check("the rationale is printed", "Why this was detected" in text)
        check("observed evidence has its own section",
              "**Observed evidence:**" in text)
        check("the generic description has its own section",
              "generic description" in text)
        check("remediation has its own section",
              "**Recommended remediation:**" in text)
        check("the raw tool output is not hidden",
              "Raw detection (what the tool actually said)" in text)
        check("the conflict is in the report",
              "Classification conflict detected" in text)
        check("no PoC is fabricated", "PoC unavailable" in text)

        report_line = cb_evidence.render(
            contaminated.title, contaminated.severity, contaminated.key,
            contaminated.proof, contaminated.validation,
            scanner_severity="INFO", detail=contaminated.detail,
            remediation=contaminated.remediation, cwe=contaminated.cwe)
        check("the console block leads with the state",
              report_line.startswith("[INCONCLUSIVE] OS command injection"))
        # What is missing is still spelled out — it moved. The evidence
        # checklist no longer prints a column of "NOT CAPTURED" beside
        # every finding that was never going to have a payload; the one
        # place that explains why a finding is unproved now carries it.
        check("and spells out what is missing",
              "No test payload was recorded" in report_line
              or "No injection point" in report_line
              or "rests on the detecting tool" in report_line)
        check("without a column of blanks beside every finding",
              "Payload: NOT CAPTURED" not in report_line)

        # ─────────────────────────────────────────────────────────────────
        #  Pause means stop touching the target
        # ─────────────────────────────────────────────────────────────────
        #
        # Pause used to suspend the external tool and hold the chain, and
        # that was all — the Python probes (headers, JavaScript, traversal,
        # 403 bypass) carried on making requests to the client's server after
        # the operator had pressed Pause and walked away. These hold the line
        # that Pause stops ALL of it.

        print("\n\033[1mPause stops the Python probes too\033[0m")
        gate = cb_control.RunGate()
        check("a fresh gate is running", gate.running)
        check("and is not paused", gate.paused, False)
        check("nor stopped", gate.stopped, False)

        probe_session = _session({"gate": gate})
        hits = Handler.hits
        del hits[:]

        stop_flag = {"go": True}
        errors = []

        def hammer():
            try:
                while stop_flag["go"]:
                    probe_session.get(base + "/", timeout=5)
            except Stopped:
                pass                     # the stop working, not a failure
            except Exception as exc:                    # noqa: BLE001
                errors.append(exc)

        worker = threading.Thread(target=hammer, daemon=True)
        worker.start()
        time.sleep(0.4)
        while_running = len(hits)
        check("requests flow while the gate is open", while_running > 0)

        gate.pause()
        time.sleep(0.3)                 # let anything in flight land
        at_pause = len(hits)
        time.sleep(1.0)
        check("NOTHING is sent to the target while paused",
              len(hits) - at_pause, 0)
        check("and the gate says so", gate.paused)

        gate.resume()
        time.sleep(0.4)
        check("and it picks up again on resume", len(hits) > at_pause)

        # Stopping while paused must release the thread. Otherwise closing
        # the window after a pause hangs waiting on a resume that is never
        # coming — which is the whole reason stop() sets the resume event.
        gate.pause()
        time.sleep(0.2)
        released = time.time()
        gate.stop()
        worker.join(timeout=5)
        check("stopping while paused releases the worker",
              worker.is_alive(), False)
        check("and does so immediately", time.time() - released < 2.0)
        check("with no exception escaping the probe", errors, [])
        check("a stopped gate never blocks again", gate.wait(), False)
        check("even though it is not 'paused'", gate.paused, False)
        stop_flag["go"] = False
        del Handler.hits[:]

        print("\n\033[1mThe chain wires the gate to Pause and Stop\033[0m")
        engine = Engine(base)
        engine._cb_active = True
        check("the engine has a gate", isinstance(engine._cb_gate,
                                                  cb_control.RunGate))
        check("which starts open", engine._cb_gate.running)
        engine.pause_coffee_break()
        check("pausing the chain closes it", engine._cb_gate.paused)
        check("and the probe context carries that same gate",
              engine._cb_worker_context()["gate"] is engine._cb_gate)
        engine.pause_coffee_break()
        check("resuming opens it again", engine._cb_gate.running)
        engine.pause_coffee_break()
        engine.stop_coffee_break()
        check("stopping while paused stops the gate", engine._cb_gate.stopped)
        check("and clears the paused flag", engine._cb_paused, False)
        check("so nothing is left waiting", engine._cb_gate.wait(), False)

    finally:
        server.shutdown()

    print("\n\033[1mThe URL handed to a human has to visibly work\033[0m")
    from command_bridge.modules.scanner.checks import xss as xss_check

    reproduction = cb_evidence.Evidence(
        url="http://127.0.0.1:8000/search?q=test",
        parameter="query parameter 'q'", location="query",
        payload='<img src=x onerror="window.__cb_xss_fired=1">',
        proof_payload='<img src=x onerror=alert(document.domain)>')
    url = reproduction.attack_url()
    check("the reproduction URL carries a visible payload",
          "alert(document.domain)" in url)
    check("not the scanner's silent marker",
          "__cb_xss_fired" not in url)
    check("and it is readable rather than fully percent-encoded",
          "%3Cimg" not in url and "<img" in url)

    traversal = cb_evidence.Evidence(
        url="http://t/download?file=brochure.txt",
        parameter="query parameter 'file'", location="query",
        payload="../../../../etc/passwd")
    check("a traversal URL keeps its slashes",
          traversal.attack_url().endswith("file=../../../../etc/passwd"))

    for label in ("body parameter 'author'", "header 'X-Original-URL'",
                  "cookie 'sid'"):
        blocked = cb_evidence.Evidence(url="http://t/guestbook",
                                       parameter=label, payload="x")
        check(f"no fake GET URL for a {label.split()[0]} parameter",
              blocked.attack_url(), "")

    check("every payload context has a visible equivalent",
          all("MARK" not in xss_check.visible(payload)
              for payloads in xss_check.BY_CONTEXT.values()
              for payload in payloads))
    check("the payload set covers more than the three it shipped with",
          sum(len(v) for v in xss_check.BY_CONTEXT.values()) > 40)
    check("including a URL context, for href and src sinks",
          "url" in xss_check.BY_CONTEXT)
    check("and the DOM sinks a reflection never reaches the body through",
          "innerHTML" in xss_check.DOM_SINKS
          and "location.hash" in xss_check.DOM_SOURCES)

    print("\n\033[1mA signature match is re-requested before it is "
          "reported\033[0m")
    probe = Engine("http://127.0.0.1:1")          # nothing is listening
    alive, _ = probe._cb_endpoint_alive("http://127.0.0.1:1/nope")
    check("an unreachable endpoint is not called dead", alive, None)
    check("a URL with no path is not checked at all",
          probe._cb_endpoint_alive("http://127.0.0.1:1/")[0], None)
    check("and neither is something that is not a URL",
          probe._cb_endpoint_alive("somewhere on the target")[0], None)

    print("\n\033[1msqlmap's verdict, not sqlmap's narration\033[0m")
    from command_bridge.modules import sqlmap_verdict

    # The exact shape of the field false positive: sqlmap tested everything,
    # found nothing, and said so. The old parser reported CONFIRMED CRITICAL
    # because one INFO line contained the words "stacked queries".
    refuted = """
[11:27:24] [INFO] testing if (custom) POST parameter '#1*' is dynamic
[11:27:24] [WARNING] heuristic (basic) test shows that (custom) POST parameter '#1*' might not be injectable
[11:27:24] [INFO] testing for SQL injection on (custom) POST parameter '#1*'
[11:28:02] [INFO] testing 'Microsoft SQL Server/Sybase stacked queries (comment)'
[11:28:03] [INFO] testing 'Oracle stacked queries (DBMS_PIPE.RECEIVE_MESSAGE - comment)'
[11:28:07] [WARNING] (custom) POST parameter '#1*' does not seem to be injectable
[11:28:07] [CRITICAL] all tested parameters do not appear to be injectable.
"""
    verdict = sqlmap_verdict.parse(refuted)
    check("a run that found nothing is not a finding", verdict.confirmed, False)
    check("it is recorded as refuted, not merely silent",
          verdict.refuted, True)
    check("'testing ... stacked queries' is narration, not evidence",
          verdict.stacked, False)
    check("sqlmap's [CRITICAL] log level is not a severity",
          verdict.severity, "")
    check("and nothing is printed", verdict.banner(), "")
    check("but the reason is still explained",
          any("not a result" in line for line in verdict.explain()))

    # The genuine article: sqlmap prints a block that cannot be mistaken.
    confirmed = """
        ___
[11:40:03] [INFO] testing 'Microsoft SQL Server/Sybase stacked queries (comment)'
sqlmap identified the following injection point(s) with a total of 71 HTTP(s) requests:
---
Parameter: id (GET)
    Type: boolean-based blind
    Title: AND boolean-based blind - WHERE or HAVING clause
    Payload: id=1 AND 4821=4821
---
[11:40:05] [INFO] the back-end DBMS is MySQL
back-end DBMS: MySQL >= 5.6
"""
    verdict = sqlmap_verdict.parse(confirmed)
    check("a real injection point is confirmed", verdict.confirmed, True)
    check("the parameter comes from the block", verdict.parameters, ["id (GET)"])
    check("so does the technique",
          verdict.injections[0].technique, "boolean-based blind")
    check("and the payload, for replay",
          verdict.injections[0].payload, "id=1 AND 4821=4821")
    check("the DBMS is read without the colon",
          verdict.dbms, "MySQL >= 5.6")
    check("a confirmed boolean-based finding is HIGH, not CRITICAL",
          verdict.severity, "HIGH")
    check("and the banner names the parameter",
          "id (GET)" in verdict.banner())

    # CRITICAL is earned by a technique confirmed in the block itself.
    stacked = confirmed.replace("Type: boolean-based blind",
                                "Type: stacked queries")
    verdict = sqlmap_verdict.parse(stacked)
    check("stacked queries in the verdict block does raise it to CRITICAL",
          verdict.severity, "CRITICAL")

    # An output file holding several runs must not blend them.
    both = sqlmap_verdict.parse(refuted + confirmed)
    check("a failed run before a real one does not suppress it",
          both.confirmed, True)
    both = sqlmap_verdict.parse(confirmed + refuted)
    check("a failed run after a real one does not erase it",
          both.confirmed, True)

    check("an interrupted run claims nothing either",
          sqlmap_verdict.parse("[INFO] testing connection to the target URL"
                               ).confirmed, False)
    check("and says it could not tell",
          any("did not state a verdict" in line for line in
              sqlmap_verdict.parse("[INFO] testing connection").explain()))

    # Colouring follows the same rule: narration is never dressed as a result.
    plain = sqlmap_verdict.Verdict()
    check("a 'testing ... stacked queries' line is not highlighted",
          sqlmap_verdict.highlight_colour(
              "[INFO] testing 'Oracle stacked queries (comment)'", plain), "")
    check("the identification line is",
          sqlmap_verdict.highlight_colour(
              "sqlmap identified the following injection point(s)",
              plain) != "")

    # ── Custom headers reaching the tool that is being run ──────────────
    #
    # Reported from a live engagement: an Authorization bearer token set
    # on the Target tab, and every API check (graphw00f, Introspection,
    # GraphQL Cop) failing against an API that requires it. The header
    # was collected and then applied to nothing but curl.
    print("\n\033[1mCustom headers\033[0m")
    from command_bridge.modules import header_injection as hi

    H = hi.parse("Authorization: Bearer eyJhbGciOiJSUzI1Ni.payload.sig\n"
                 "X-Tenant: acme\n"
                 "Content-Length: 99\n"
                 "\n"
                 "# a comment\n"
                 "Broken:\n")
    check("a bearer token whose value contains colons survives whole",
          H[0], ("Authorization", "Bearer eyJhbGciOiJSUzI1Ni.payload.sig"))
    check("Content-Length is never forwarded",
          any(n.lower() == "content-length" for n, _ in H), False)
    check("a header with no value is dropped", len(H), 2)
    check("the credential's value is never printed",
          "eyJhbGciOiJSUzI1Ni" in hi.describe(H), False)
    check("but the header is named, so it is visible that it was used",
          "Authorization" in hi.describe(H))

    cop, applied, _ = hi.apply(
        "graphql-cop -t 'https://x/graphql' -o json", H)
    check("graphql-cop gets its headers as JSON objects, not Name: Value",
          '-H \'{"Authorization": "Bearer eyJhbGciOiJSUzI1Ni.payload.sig"}\''
          in cop)
    check("and graphql-cop is reported as having received them",
          "graphql-cop" in applied)

    w00f, _, skipped = hi.apply("graphw00f -d -f -t 'https://x/graphql'", H)
    check("graphw00f gets Name: Value", "-H 'Authorization: Bearer" in w00f)
    check("graphw00f's -H is not repeatable, so only one is sent",
          w00f.count("-H "), 1)
    check("the credential is the one chosen, not the first in the box",
          "Authorization" in w00f.split("-H ")[1])
    check("and the dropped header is reported rather than silently lost",
          any("graphw00f" in s for s in skipped))

    # The command this was actually reported against. Its curl already
    # sets Content-Type, and the first version of the fix treated that
    # as "the operator has set headers by hand" and added nothing.
    intro = ("echo '[*] Sending'; curl -sk -X POST 'https://x/graphql' "
             "-H 'Content-Type: application/json' --data '{\"query\":\"q\"}' "
             "-o out.json; if python3 -m json.tool out.json >/dev/null 2>&1; "
             "then echo ok; else echo no; fi")
    got, applied, skipped = hi.apply(intro, H)
    check("an existing Content-Type does not block the bearer token",
          "-H 'Authorization: Bearer" in got)
    check("and Content-Type is not duplicated",
          got.count("Content-Type"), 1)
    check("the shell keywords in the command are not mistaken for tools",
          skipped, [])
    check("nor is the 1 in a 2>&1 redirection",
          "1" not in skipped)

    manual = "curl -H 'Authorization: Bearer MINE' https://x"
    got, _, _ = hi.apply(manual, H)
    check("a hand-written Authorization is left alone",
          got.count("Authorization"), 1)
    check("but other headers are still added alongside it",
          "-H 'X-Tenant: acme'" in got)

    check("arjun takes one newline-separated --headers string",
          "--headers 'Authorization: Bearer eyJhbGciOiJSUzI1Ni.payload.sig\n"
          "X-Tenant: acme'" in hi.apply("arjun -u 'https://x' -o a.txt", H)[0])

    check("ffuf gets a repeated -H",
          hi.apply("ffuf -u 'https://x/FUZZ' -w /l.txt", H)[0].count("-H "), 2)

    _, applied, skipped = hi.apply(
        "nmap -sV -p443 example.org", H)
    check("a port scan is not reported as a missed header",
          (applied, skipped), ([], []))

    check("the word curl inside a filename is not a curl invocation",
          hi.apply("cat curl_notes.txt", H)[0], "cat curl_notes.txt")
    check("and no headers means the command is returned untouched",
          hi.apply("curl https://x", [])[0], "curl https://x")

    # ── testssl writes reports a human can read ─────────────────────────
    print("\n\033[1mtestssl report encoding\033[0m")
    engine = Engine("example.org")
    cmd = engine._cb_testssl_command()
    check("testssl is asked for no colour", "--color 0" in cmd)
    check("both the testssl and testssl.sh branches ask for it",
          cmd.count("--color 0"), 2)

    noisy = ("\x1b[1m\n####################\x1b[m\n"
             "  \x1b[1mtestssl\x1b[m version \x1b[1m3.2.2\x1b[m\n"
             "\x1b[2K\x1b[0;33mTLS 1.0\x1b[m   offered\n")
    clean = CoffeeBreakMixin.strip_ansi(noisy)
    check("colour sequences are stripped from a saved report",
          "\x1b" in clean, False)
    check("erase-line sequences are stripped too, not just colour",
          "[2K" in clean, False)
    check("and the text itself is kept",
          "testssl version 3.2.2" in clean and "TLS 1.0" in clean)

    safe = engine.sanitize_target_for_filename(engine.target)
    noisy_path = Path(engine.output_dir) / f"{safe}_testssl.txt"
    noisy_path.write_text(noisy)
    engine._cb_clean_testssl_reports(safe)
    check("an already-written report is cleaned in place",
          "\x1b" in noisy_path.read_text(), False)


    # ── A token pasted without its header name ──────────────────────────
    #
    # Reported mid-engagement against a GraphQL API: the token was in
    # the Custom Headers box, graphw00f ran without -H, and graphql-cop
    # said the endpoint "does not seem to be running GraphQL" — which
    # is what an unauthenticated probe of an authenticated API looks
    # like. A JWT contains no colon, so "Bearer eyJ..." on its own was
    # dropped by the parser and nothing said so.
    print("\n\033[1mA token pasted without its header name\033[0m")
    JWT = "eyJhbGciOiJSUzI1NiIsImtpZCI6IjkwNGIw.eyJyb2xlcyI6W119.sig"

    got, notes = hi.parse_detailed(f"Bearer {JWT}")
    check("a bare 'Bearer <jwt>' becomes an Authorization header",
          got, [("Authorization", f"Bearer {JWT}")])
    check("and the guess is stated rather than made silently",
          any("Authorization" in n for n in notes))

    got, notes = hi.parse_detailed(JWT)
    check("a naked JWT is recognised too",
          got, [("Authorization", f"Bearer {JWT}")])
    check("and it too is reported", len(notes), 1)

    check("a proper header produces no note at all",
          hi.parse_detailed(f"Authorization: Bearer {JWT}")[1], [])

    got, notes = hi.parse_detailed("this is not a header")
    check("an unusable line is reported, not silently skipped",
          (got, len(notes)), ([], 1))
    check("and the report says what the format should be",
          "Authorization: Bearer" in notes[0])

    check("a name with no value is reported",
          "no value after the colon"
          in hi.parse_detailed("Authorization:")[1][0])
    check("a line that is prose with a colon in it is not a header",
          hi.parse_detailed("my token is: abc")[0], [])

    check("the token value is never echoed whole in a note",
          all(JWT not in n for n in hi.parse_detailed(f"Bearer {JWT}")[1]))

    # The two commands from the report, now carrying the credential.
    w00f = hi.apply("graphw00f -d -f -t 'https://x' -o o.csv",
                    hi.parse(f"Bearer {JWT}"))[0]
    check("graphw00f now gets the token", f"-H 'Authorization: Bearer {JWT}'"
          in w00f)
    cop = hi.apply("graphql-cop -t 'https://x/graphql' -o json",
                   hi.parse(f"Bearer {JWT}"))[0]
    check("and graphql-cop gets it as the JSON object it expects",
          f'-H \'{{"Authorization": "Bearer {JWT}"}}\'' in cop)


    # ── A host that answers 200 for everything ──────────────────────────
    #
    # Reported from an engagement: Nikto claimed /.bash_history had been
    # retrieved. The target is a single-page app behind a cache that
    # answers 200 with the app shell for EVERY path. The shell never says
    # "404" — it is a <title>, some script tags and an empty root div —
    # so the wording-based soft-404 test could not see it, and the
    # finding was reported as observed directly.
    print("\n\033[1mA host that answers 200 for everything\033[0m")

    SHELL = (b"<!doctype html><html><head><title>Shop</title>"
             b"<script src='/main.js'></script></head>"
             b"<body><div id=\"root\"></div></body></html>")

    class _CatchAll(BaseHTTPRequestHandler):
        def do_GET(self):
            if self.path == "/genuine.txt":
                body, kind = b"a real text file, nothing like the shell\n", \
                             "text/plain"
            else:
                body, kind = SHELL, "text/html; charset=utf-8"
            self.send_response(200)
            self.send_header("Content-Type", kind)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *a):
            pass

    spa = ThreadingHTTPServer(("127.0.0.1", 0), _CatchAll)
    threading.Thread(target=spa.serve_forever, daemon=True).start()
    spa_base = f"http://127.0.0.1:{spa.server_address[1]}"
    spa_engine = Engine(spa_base)

    signature = spa_engine._cb_catch_all_signature(spa_base + "/anything")
    check("the catch-all is detected from a path that cannot exist",
          signature is not None)

    alive, note = spa_engine._cb_endpoint_alive(spa_base + "/.bash_history")
    check("a claimed file on a catch-all host is not alive", alive, False)
    check("and the reason says the host serves a catch-all",
          "catch-all" in note)
    check("a response that really differs is still alive",
          spa_engine._cb_endpoint_alive(spa_base + "/genuine.txt")[0], True)

    reported = Engine(spa_base)
    reported._cb_parse_nikto({"key": "nikto"}, (
        "+ [002743] /.bash_history: A user's home directory may be set to "
        "the web root, the shell history was retrieved. This should not be "
        "accessible via the web.\n"))
    # BEHAVIOUR CHANGE, 6.9.2. This used to assert the finding was
    # dropped outright. It is now RETAINED and marked Inconclusive,
    # because silently discarding every unconfirmed detection loses the
    # distinction between "we checked and it is not there" and "we never
    # looked" — and a tester deciding what to probe by hand needs the
    # lead even when the automated check could not settle it.
    #
    # What must not happen is the old failure: it reaching the report as
    # a confirmed high-risk exposure.
    check("the finding is retained rather than discarded",
          len(reported._cb_findings), 1)
    kept = reported._cb_findings[0]
    check("but marked Inconclusive",
          getattr(kept, "status_label", ""), "Inconclusive")
    check("and rated LOW, not HIGH", kept.severity, "LOW")
    check("with the impact it would carry if real still recorded",
          getattr(kept, "impact_if_real", ""), "HIGH")
    check("and the reason stated in what was found",
          "catch-all" in getattr(kept, "summary", ""))
    check("the name does not claim the file was exposed",
          kept.title, "Shell history file is readable")

    # A real host, where the same signature IS worth reporting.
    class _RealFile(BaseHTTPRequestHandler):
        def do_GET(self):
            if self.path == "/.bash_history":
                body, kind, code = (b"cd /var/www\nmysql -u root -phunter2\n",
                                    "text/plain", 200)
            else:
                body, kind, code = b"<h1>404</h1>", "text/html", 404
            self.send_response(code)
            self.send_header("Content-Type", kind)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *a):
            pass

    real = ThreadingHTTPServer(("127.0.0.1", 0), _RealFile)
    threading.Thread(target=real.serve_forever, daemon=True).start()
    real_base = f"http://127.0.0.1:{real.server_address[1]}"
    real_engine = Engine(real_base)

    check("a host that 404s properly has no catch-all signature",
          real_engine._cb_catch_all_signature(real_base + "/x"), None)
    real_engine._cb_parse_nikto({"key": "nikto"}, (
        "+ [002743] /.bash_history: A user's home directory may be set to "
        "the web root, the shell history was retrieved.\n"))
    check("a genuinely readable .bash_history IS reported",
          len(real_engine._cb_findings), 1)
    kept = real_engine._cb_findings[0]
    check("at HIGH, because the path is sensitive and it answered",
          kept.severity, "HIGH")
    check("and the finding points at the file, not the home page",
          kept.where.endswith("/.bash_history"))

    # The severity must come from the verified path, not from the word
    # "shell" appearing in "the shell history was retrieved" — which is
    # what used to grade it alongside remote code execution.
    check("'shell history' alone does not mean shell access",
          real_engine._cb_sensitive_path(real_base + "/readme.txt"), False)

    # An HTML document is not a shell history, whatever the status code.
    plausible, why = real_engine._cb_file_contents_plausible(
        "https://x/.bash_history", "<!doctype html><title>App</title>",
        "text/html")
    check("an HTML body cannot be the file the signature claims",
          plausible, False)
    check("and the reason says so", "HTML" in why)
    check("a plain-text body can be",
          real_engine._cb_file_contents_plausible(
              "https://x/.bash_history", "cd /tmp\nls\n", "text/plain")[0],
          True)

    spa.shutdown()
    real.shutdown()

    # ── A run is not lost when the application is killed ────────────────
    #
    # Reported alongside the freeze: the application had to be killed
    # partway through a long run and forty-five minutes of findings went
    # with it, because the report was only written when somebody clicked
    # Export and chose a filename.
    print("\n\033[1mFindings survive a kill\033[0m")
    saver = Engine("example.org")
    saver._cb_started_at = time.time()
    saver._cb_active = True          # a run in flight, as when it matters
    saver._cb_record(CBFinding("HIGH", "Something real", "https://example.org",
                               evidence="proof"))
    md_path, json_path = saver._cb_autosave_paths()
    check("a finding is written to disk as soon as it is recorded",
          md_path.is_file())
    check("and the Markdown holds it",
          "Something real" in md_path.read_text())
    check("and so does the JSON", json_path.is_file())
    saved = json.loads(json_path.read_text())
    check("the JSON names the target", saved["target"], "example.org")
    check("and carries the finding",
          saved["findings"][0]["title"], "Something real")
    check("and records that the run had not finished",
          saved["complete"], False)
    saver._cb_active = False
    saver._cb_autosave()
    check("a finished run is recorded as finished",
          json.loads(json_path.read_text())["complete"], True)

    stale = Engine("example.org")
    stale.output_dir = saver.output_dir
    stale._cb_report_previous_run()
    check("a previous run's file is announced before it is overwritten",
          any("earlier Coffee Break run" in line for line in stale.printed))
    check("and the operator is told it will be overwritten",
          any("overwrites" in line for line in stale.printed))


    # ── "rce" inside "Subresource" ───────────────────────────────────────
    #
    # Reported from an engagement: nuclei's missing-sri template (INFO,
    # CWE-353) was published as a CRITICAL CWE-78 OS command injection
    # with an SRI-less script URL as its proof. for_nuclei already
    # refuses to classify on a template's description — this came in
    # through its NAME, "Missing Subresource Integrity", because the
    # command_injection pattern had `rce\b` with no LEADING word
    # boundary. "Subresou(rce)" matches. So does "sou(rce)" and
    # "resou(rce)": any finding mentioning a source or a resource became
    # a critical.
    print("\n\033[1mPatterns match words, not fragments of words\033[0m")
    for benign in ("Missing Subresource Integrity",
                   "Source map file exposed",
                   "Cross-origin resource sharing misconfiguration",
                   "Email addresses disclosed in page source",
                   "Subresource integrity attribute absent"):
        check(f"{benign[:38]!r} is not command injection",
              cb_issues.for_text(benign)[0] == "command_injection", False)
    for real in ("RCE in the upload handler",
                 "Remote code execution via deserialisation",
                 "OS command injection on the host parameter"):
        check(f"{real[:34]!r} still is",
              cb_issues.for_text(real)[0], "command_injection")
    check("and the nuclei template itself no longer maps to an exploit",
          cb_issues.for_nuclei("missing-sri", "Missing Subresource Integrity",
                               "Checks if external script tags are missing "
                               "the Subresource Integrity attribute.")[0]
          == "command_injection", False)

    # ── Nikto findings get titles, not truncated sentences ──────────────
    print("\n\033[1mNikto titles name the problem and the file\033[0m")
    check("a shell history file is named as one",
          cb_issues.nikto_title(
              "[002743] /.bash_history: A user's home directory may be set "
              "to the web root, the shell history was retrieved. This should "
              "not be accessible via the web."),
          "Shell history file is readable (/.bash_history)")
    check("and so is the other one Nikto reports",
          cb_issues.nikto_title("[002756] /.sh_history: A user's home "
                                "directory may be set to the web root."),
          "Shell history file is readable (/.sh_history)")
    check("an env file too",
          cb_issues.nikto_title("/.env: may contain secrets."),
          "Environment file is readable (/.env)")
    check("an unknown path keeps Nikto's sentence but gains the path",
          cb_issues.nikto_title("/odd.aspx: Server may leak inodes via ETags")
          .endswith("(/odd.aspx)"))
    check("the boilerplate is not in the title",
          "accessible via the web" in cb_issues.nikto_title(
              "/x.txt: Something. This should not be accessible via the "
              "web."), False)
    check("a line that is not in Nikto's path form returns nothing",
          cb_issues.nikto_title("Retrieved x-powered-by header: PHP/8.1"), "")
    check("no title is a truncated raw line any more",
          "…" in cb_issues.nikto_title(
              "[002743] /.bash_history: A user's home directory may be set "
              "to the web root, the shell history was retrieved."), False)

    # ── A header cannot be absent and misconfigured at once ─────────────
    #
    # Reported: "CSP allows clickjacking", "CSP does not restrict
    # object-src or base-uri", "CSP allows form hijacking" AND
    # "Content-Security-Policy is missing", on the same target. The last
    # contradicts the first three. probe_headers cannot produce that
    # pair on its own, so the "missing" one came from a signature tool.
    # Parsing the header is first-hand evidence that it is there.
    print("\n\033[1mPresent and missing are mutually exclusive\033[0m")
    csp = Engine("https://example.bike")
    for parsed_key in ("csp_clickjacking", "csp_missing_object_base",
                       "csp_form_hijack"):
        csp._cb_record(csp._cb_issue(
            parsed_key, "https://example.bike/",
            "Content-Security-Policy: default-src 'self'", "headers"))
    csp._cb_record(csp._cb_issue("csp_missing", "https://example.bike",
                                 "no CSP header seen", "nuclei"))
    titles = [f.title for f in csp._cb_findings]
    check("the three analyses of the policy are kept", len(titles), 3)
    check("and 'CSP is missing' is not reported alongside them",
          any("missing" in t and "object-src" not in t for t in titles),
          False)
    check("with the reason said out loud",
          any("contradicts" in line for line in csp.printed))

    # The stages do not run in a fixed order, so the other direction too.
    rev = Engine("https://example.bike")
    rev._cb_record(rev._cb_issue("csp_missing", "https://example.bike",
                                 "no CSP header seen", "nuclei"))
    rev._cb_record(rev._cb_issue(
        "csp_clickjacking", "https://example.bike/",
        "Content-Security-Policy: default-src 'self'", "headers"))
    check("a 'missing' already recorded is withdrawn when the header is read",
          [f.key for f in rev._cb_findings], ["csp_clickjacking"])

    only = Engine("https://example.bike")
    only._cb_record(only._cb_issue("csp_missing", "https://example.bike",
                                   "no CSP header seen", "headers"))
    check("a genuinely missing header is still reported",
          [f.key for f in only._cb_findings], ["csp_missing"])

    print("\n\033[1mA trailing slash is the same location\033[0m")
    check("root with and without a slash", 
          _same_location("https://x", "https://x/"))
    check("but two different paths are not",
          _same_location("https://x/a", "https://x/b"), False)
    check("and a sub-path's slash is left alone",
          _same_location("https://x/a", "https://x/a/"), False)

    # ── Lucky 13 names the suites ───────────────────────────────────────
    #
    # Reported: the finding's entire proof was testssl's own sentence,
    # "LUCKY13: potentially vulnerable, uses obsolete TLS CBC ciphers",
    # which cannot be written up — a report has to say which suites.
    print("\n\033[1mLucky 13 lists the cipher suites\033[0m")
    from command_bridge.modules import cbc_suites

    sample = [("TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA", 256, "ECDHE-RSA-AES256-SHA"),
              ("TLS_RSA_WITH_AES_128_CBC_SHA", 128, "AES128-SHA")]
    block = cbc_suites.as_evidence(sample, "example.bike:443")
    check("each suite is on its own line", block.count("\n"), 2)
    check("the IANA name is used, not OpenSSL's short name",
          "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA" in block)
    check("the key size is given", block.rstrip().endswith("128"))
    check("and nothing was invented when there is nothing to list",
          cbc_suites.as_evidence([], "x"), "")
    check("every suite in the table has an IANA name and a size",
          all(iana.startswith("TLS_") and bits > 0
              for _, iana, bits in cbc_suites.SUITES))
    check("TLS 1.3 is excluded, since it has no CBC suites at all",
          "TLSv1_2" in Path(cbc_suites.__file__).read_text())

    print("\n\033[1mCopying a finding keeps its line breaks\033[0m")
    from command_bridge.widgets.plain_copy import as_plain_text
    check("Qt's paragraph separator becomes a newline",
          as_plain_text("a b"), "a\nb")
    check("and its line separator does too, which is what <br> gives",
          as_plain_text("a b"), "a\nb")
    check("non-breaking spaces become ordinary ones",
          as_plain_text("a b"), "a b")
    check("a cipher list survives a round trip",
          as_plain_text("Lucky13   TLS_RSA_WITH_AES_128_CBC_SHA "
                        "  TLS_RSA_WITH_AES_256_CBC_SHA").count("\n"), 2)


    # ═══════════════════════════════════════════════════════════════════
    #  The validation pipeline: detector registry, verification, risk
    # ═══════════════════════════════════════════════════════════════════
    #
    # Named A-G after the failure cases they were written from. Each one
    # reproduces a report that was actually produced and published.
    from command_bridge.modules import detector_registry as dreg
    from command_bridge.modules import risk as riskmod
    from command_bridge.modules import verification as vmod

    SHELL_HISTORY = (b"cd /var/www/html\nmysql -u root -pSuperSecret1 shop\n"
                     b"ssh deploy@10.0.0.5\nexit\n")
    JAMON_PAGE = (b"<html><head><title>JAMon Admin</title></head><body>"
                  b"<h1>JAMon - Java Application Monitor</h1>"
                  b"<p>JAMon version 2.81</p></body></html>")
    SPA_SHELL = (b"<!doctype html><html><head><title>Shop</title></head>"
                 b"<body><div id=\"root\"></div></body></html>")

    class _RealFiles(BaseHTTPRequestHandler):
        """A host where the files genuinely are, and 404s otherwise."""

        def do_GET(self):
            if self.path in ("/.bash_history", "/.sh_history"):
                body, kind, code = SHELL_HISTORY, "text/plain", 200
            elif self.path == "/JAMonAdmin.jsp":
                body, kind, code = JAMON_PAGE, "text/html", 200
            else:
                body, kind, code = b"<h1>404</h1>", "text/html", 404
            self.send_response(code)
            self.send_header("Content-Type", kind)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *a):
            pass

    class _CatchAll(BaseHTTPRequestHandler):
        """A single-page app behind a cache: 200 + shell for every path."""

        def do_GET(self):
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(SPA_SHELL)))
            self.end_headers()
            self.wfile.write(SPA_SHELL)

        def log_message(self, *a):
            pass

    def _serve(handler):
        srv = ThreadingHTTPServer(("127.0.0.1", 0), handler)
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        return srv, f"http://127.0.0.1:{srv.server_address[1]}"

    real_srv, real_base = _serve(_RealFiles)
    spa_srv, spa_base = _serve(_CatchAll)

    NIKTO_HISTORY = ("+ [002743] /.bash_history: A user's home directory may "
                     "be set to the web root, the shell history was "
                     "retrieved. This should not be accessible via the "
                     "web.\n")
    NIKTO_SH = ("+ [002756] /.sh_history: A user's home directory may be set "
                "to the web root, the shell history was retrieved.\n")
    NIKTO_JAMON = ("+ [007303] /JAMonAdmin.jsp: JAMon - Java Application "
                   "Monitor Admin interface identified. Versions 2.7 and "
                   "earlier contain XSS vulnerabilities. See: "
                   "CVE-2013-6235\n")
    SRI_ROW = {
        "template-id": "missing-sri",
        "matched-at": "https://example.co.uk/",
        "info": {"name": "Missing Subresource Integrity", "severity": "info",
                 "tags": ["compliance", "js", "css", "sri", "misconfig",
                          "vuln"],
                 "description": "Checks if external script and stylesheet "
                                "tags in the HTML response are missing the "
                                "Subresource Integrity (SRI) attribute.",
                 "classification": {"cwe-id": ["cwe-353"]}},
        "extracted-results": ["https://7385347281937593344.csidetm.com/"
                              "script.js"],
    }

    # ── Test A — nuclei misclassification ───────────────────────────────
    print("\n\033[1mA — nuclei missing-sri is not command injection\033[0m")
    a = Engine(real_base)
    a._cb_parse_nuclei({"key": "nuclei"}, json.dumps(SRI_ROW))
    check("one finding is produced", len(a._cb_findings), 1)
    sri = a._cb_findings[0]
    check("classified as Subresource Integrity",
          sri.key, "sri_missing")
    check("not as command injection",
          "command" in (sri.title + sri.key).lower(), False)
    check("CWE is the SRI one, not CWE-78", sri.cwe, "CWE-353")
    check("risk rating is Informational, not Critical",
          sri.severity, "INFO")
    check("nuclei's own severity is kept as metadata",
          sri.scanner_severity, "INFO")
    check("the extracted script URL is the observation",
          "csidetm.com" in getattr(sri, "summary", ""))
    rendered = cb_evidence.summary_html(sri)
    for forbidden in ("shell", "command injection", "control of the "
                                                    "application server"):
        check(f"the finding does not mention {forbidden!r}",
              forbidden in rendered.lower(), False)
    check("and the raw template metadata survives in the detail view",
          "missing-sri" in cb_evidence.detail_html(sri))

    # ── Test B — shell history exposure ─────────────────────────────────
    print("\n\033[1mB — a shell history signature is not an exposure\033[0m")
    b_real = Engine(real_base)
    b_real._cb_parse_nikto({"key": "nikto"}, NIKTO_HISTORY + NIKTO_SH)
    # One finding, two locations. /.bash_history and /.sh_history are the
    # same issue, and the consolidation that already groups a missing
    # header seen on two hundred pages groups these as well.
    check("the two paths consolidate into one finding",
          len(b_real._cb_findings), 1)
    check("with the second path kept as an instance",
          len(b_real._cb_findings[0].instances), 1)
    check("and the instance is the other history file",
          any(".sh_history" in str(i)
              for i in b_real._cb_findings[0].instances))
    exposed = b_real._cb_findings[0]
    check("the name is normalised, not Nikto's sentence",
          exposed.title, "Exposed shell history file")
    check("no bracketed plugin id in the name",
          "[002743]" in exposed.title, False)
    check("confirmed, because the contents came back",
          getattr(exposed, "status_label", ""), "Confirmed")
    check("and rated on that evidence", exposed.severity, "HIGH")
    check("what was found says the file is readable",
          "readable" in getattr(exposed, "summary", "").lower())
    check("the raw Nikto message is kept in the evidence record",
          "002743" in cb_evidence.detail_html(exposed))

    b_spa = Engine(spa_base)
    b_spa._cb_parse_nikto({"key": "nikto"}, NIKTO_HISTORY)
    check("on a catch-all host the same signature still appears",
          len(b_spa._cb_findings), 1)
    unproven = b_spa._cb_findings[0]
    check("but as Inconclusive",
          getattr(unproven, "status_label", ""), "Inconclusive")
    check("rated LOW rather than HIGH", unproven.severity, "LOW")
    check("while recording what it would be worth if real",
          getattr(unproven, "impact_if_real", ""), "HIGH")
    check("and saying why it is not confirmed",
          "catch-all" in getattr(unproven, "summary", ""))
    check("the name does not claim exposure",
          unproven.title, "Shell history file is readable")

    # ── Test C — JAMon XSS signature ────────────────────────────────────
    print("\n\033[1mC — a component signature is not reflected XSS\033[0m")
    c = Engine(real_base)
    c._cb_parse_nikto({"key": "nikto"}, NIKTO_JAMON)
    check("a finding is produced", len(c._cb_findings), 1)
    jamon = c._cb_findings[0]
    check("it is not classified as XSS",
          "xss" in (jamon.key + jamon.title).lower(), False)
    check("nor carries CWE-79", jamon.cwe == "CWE-79", False)
    check("it is a component finding",
          jamon.key, "component_admin_exposed")
    check("the CVE is kept as context",
          "CVE-2013-6235" in jamon.references)
    check("the version was read from the response",
          "2.81" in getattr(jamon, "summary", ""))
    check("and it is not called a JavaScript package",
          "javascript" in cb_evidence.summary_html(jamon).lower(), False)
    check("Java is what it is",
          "JAMon" in jamon.title or "JAMon" in
          cb_evidence.detail_html(jamon))

    c_spa = Engine(spa_base)
    c_spa._cb_parse_nikto({"key": "nikto"}, NIKTO_JAMON)
    check("with no reachable interface it is inconclusive",
          getattr(c_spa._cb_findings[0], "status_label", ""),
          "Inconclusive")

    # ── Test D — Lucky13 cipher details ─────────────────────────────────
    print("\n\033[1mD — Lucky 13 lists the suites testssl found\033[0m")
    d = Engine("https://example.bike")
    artefact = {
        "tool": "ssl_cipher_check", "host": "example.bike", "port": 443,
        "suite_count": 6,
        "protocols": {"TLS 1.2": [
            {"name": "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA", "bits": 256},
            {"name": "TLS_RSA_WITH_AES_256_CBC_SHA", "bits": 256},
            {"name": "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA", "bits": 128},
            {"name": "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256", "bits": 128},
            {"name": "TLS_RSA_WITH_AES_128_CBC_SHA", "bits": 128}]},
        "deprecated_protocols": {},
        "vulnerabilities": {"Lucky13": {
            "name": "Lucky13",
            "description": "Timing side-channel on CBC-mode HMAC padding "
                           "— CVE-2013-0169",
            "suites": [
                {"name": "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA", "bits": 256},
                {"name": "TLS_RSA_WITH_AES_256_CBC_SHA", "bits": 256},
                {"name": "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA", "bits": 128},
                {"name": "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256",
                 "bits": 128},
                {"name": "TLS_RSA_WITH_AES_128_CBC_SHA", "bits": 128}]}},
    }
    safe_name = d.sanitize_target_for_filename(d.target)
    (Path(d.output_dir) / f"{safe_name}_ssl_ciphers.json").write_text(
        json.dumps(artefact))
    listing = d._cb_tls_evidence("lucky13")
    for suite, bits in (("TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA", "256"),
                        ("TLS_RSA_WITH_AES_256_CBC_SHA", "256"),
                        ("TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA", "128"),
                        ("TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256", "128"),
                        ("TLS_RSA_WITH_AES_128_CBC_SHA", "128")):
        check(f"{suite} is listed", suite in listing)
    check("each suite carries its key size", listing.count("256") >= 2)
    check("each on its own line", listing.count("\n") >= 5)
    check("the host is named, so evidence is tied to the target",
          "example.bike:443" in listing)
    check("and it was reused rather than re-scanned",
          any("reusing the SSL/TLS Analysis" in line for line in d.printed))
    check("nothing is hardcoded — an empty artefact yields nothing",
          Engine("https://nowhere.test")._cb_tls_evidence("lucky13"), "")

    # ── Test E — other TLS findings keep their evidence ─────────────────
    print("\n\033[1mE — other TLS findings keep their evidence too\033[0m")
    e_eng = Engine("https://example.bike")
    rich = dict(artefact)
    rich["deprecated_protocols"] = {
        "TLS 1.0": {"severity": "HIGH",
                    "reason": "BEAST risk + deprecated by RFC 8996"}}
    rich["protocols"] = dict(artefact["protocols"])
    rich["protocols"]["TLS 1.0"] = [
        {"name": "TLS_RSA_WITH_AES_128_CBC_SHA", "bits": 128}]
    rich["vulnerabilities"] = dict(artefact["vulnerabilities"])
    rich["vulnerabilities"]["ROBOT (static RSA)"] = {
        "name": "ROBOT (static RSA)",
        "description": "RSA PKCS#1 v1.5 key exchange",
        "suites": [{"name": "TLS_RSA_WITH_AES_256_CBC_SHA", "bits": 256}]}
    (Path(e_eng.output_dir)
     / f"{safe_name}_ssl_ciphers.json").write_text(json.dumps(rich))
    check("a protocol finding names the version and its suites",
          "TLS 1.0" in e_eng._cb_tls_evidence("obsolete_protocol"))
    check("and gives the reason",
          "RFC 8996" in e_eng._cb_tls_evidence("obsolete_protocol"))
    check("ROBOT gets its own matching suites",
          "TLS_RSA_WITH_AES_256_CBC_SHA"
          in e_eng._cb_tls_evidence("robot"))
    check("a weak-cipher finding lists the accepted suites by version",
          "TLS 1.2" in e_eng._cb_tls_evidence("weak_cipher"))
    check("a vulnerability with no matching suites gets no invented list",
          e_eng._cb_tls_evidence("sweet32"), "")

    # Section 6's technical correctness: CBC support is the attack's
    # precondition, not the attack. Lucky 13 reports as Potential with
    # the suites as evidence; a certificate or protocol fact, which IS
    # directly observed, reports as Confirmed.
    tls_eng = Engine("https://example.bike")
    (Path(tls_eng.output_dir)
     / f"{safe_name}_ssl_ciphers.json").write_text(json.dumps(rich))
    (Path(tls_eng.output_dir) / f"{safe_name}_testssl.json").write_text(
        json.dumps([
            {"id": "LUCKY13", "severity": "LOW", "cve": "CVE-2013-0169",
             "finding": "potentially vulnerable, uses obsolete TLS CBC "
                        "ciphers"},
            {"id": "cert_signatureAlgorithm", "severity": "MEDIUM",
             "finding": "SHA1 with RSA"},
        ]))
    tls_eng._cb_parse_testssl(
        {"key": "testssl",
         "artefact_file": str(Path(tls_eng.output_dir)
                              / f"{safe_name}_testssl.json")}, "")
    tls_by_key = {f.key: f for f in tls_eng._cb_findings}
    check("Lucky 13 is reported", "lucky13" in tls_by_key)
    l13 = tls_by_key["lucky13"]
    check("as Potential, not Confirmed",
          getattr(l13, "status_label", ""), "Potential")
    check("with the suites still in what was found",
          "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA" in getattr(l13, "summary", ""))
    check("and the precondition/attack distinction stated",
          "not attempted" in getattr(l13, "summary", ""))
    cert = tls_by_key.get("cert_weak_signature")
    if cert is not None:
        check("a directly observed certificate fact is Confirmed",
              getattr(cert, "status_label", ""), "Confirmed")

    # ── Test F — no unsupported severity escalation ─────────────────────
    print("\n\033[1mF — impact is capped by confirmation\033[0m")
    for cls, impact, status, wanted in (
            ("command_injection", "CRITICAL", dreg.INCONCLUSIVE, "INFO"),
            ("command_injection", "CRITICAL", dreg.POTENTIAL, "LOW"),
            ("command_injection", "CRITICAL", dreg.CONFIRMED, "CRITICAL"),
            ("sensitive data exposure", "HIGH", dreg.CONFIRMED, "HIGH"),
            ("sensitive data exposure", "HIGH", dreg.POTENTIAL, "MEDIUM"),
            ("misconfiguration", "LOW", dreg.INFORMATIONAL, "INFO")):
        got, got_impact, _ = riskmod.assess(impact, status, vuln_class=cls)
        check(f"{cls} / {impact} / {status} → {wanted}", got, wanted)
        check("  and the impact is preserved alongside it",
              got_impact, impact)
    check("an INFO template cannot carry an exploit class",
          dreg.exploit_class_admissible(["misconfig", "sri"], "info"), False)
    check("but a template that tests for one can",
          dreg.exploit_class_admissible(["rce", "injection"], "high"))
    check("and a HIGH template with no tags is allowed through",
          dreg.exploit_class_admissible([], "high"))

    # ── Test G — evidence isolation and deduplication ───────────────────
    print("\n\033[1mG — evidence is not mixed between targets\033[0m")
    g_one = Engine(real_base)
    g_one._cb_parse_nikto({"key": "nikto"}, NIKTO_HISTORY)
    g_two = Engine(spa_base)
    g_two.output_dir = g_one.output_dir       # same output directory
    g_two._cb_parse_nikto({"key": "nikto"}, NIKTO_HISTORY)
    check("each target keeps its own verdict",
          (getattr(g_one._cb_findings[0], "status_label", ""),
           getattr(g_two._cb_findings[0], "status_label", "")),
          ("Confirmed", "Inconclusive"))
    check("and its own affected URL",
          g_one._cb_findings[0].where != g_two._cb_findings[0].where)
    check("the confirmed one's evidence mentions its own host",
          real_base.split("//")[1].split(":")[0]
          in g_one._cb_findings[0].where)

    wrong_host = Engine("https://example.bike")
    (Path(wrong_host.output_dir)
     / f"{safe_name}_ssl_ciphers.json").write_text(json.dumps(
         {"host": "someone-else.test", "port": 443, "suite_count": 1,
          "protocols": {"TLS 1.2": [{"name": "TLS_RSA_WITH_AES_128_CBC_SHA",
                                     "bits": 128}]},
          "vulnerabilities": {"Lucky13": {
              "name": "Lucky13", "description": "x",
              "suites": [{"name": "TLS_RSA_WITH_AES_128_CBC_SHA",
                          "bits": 128}]}}}))
    check("an artefact from another host is refused",
          wrong_host._cb_tls_evidence("lucky13"), "")
    check("and the refusal says why",
          any("not using it" in line for line in wrong_host.printed))

    dedup = Engine(real_base)
    dedup._cb_parse_nikto({"key": "nikto"}, NIKTO_HISTORY)
    before = len(dedup._cb_findings)
    dedup._cb_parse_nikto({"key": "nikto"}, NIKTO_HISTORY)
    check("re-scanning does not duplicate the finding",
          len(dedup._cb_findings), before)

    real_srv.shutdown()
    spa_srv.shutdown()

    # ── the Findings section shows four fields ──────────────────────────
    print("\n\033[1mThe Findings section shows four fields\033[0m")
    shown = cb_evidence.summary_html(b_real._cb_findings[0])
    check("the finding name is there", "Exposed shell history file" in shown)
    check("the risk rating is there", "High" in shown)
    check("the confirmation status is there", "Confirmed" in shown)
    check("and what was found", "What was found" in shown)
    for absent in ("Recommended remediation", "What could explain this",
                   "Proof of concept", "Reproduction"):
        check(f"{absent!r} is not in the summary", absent in shown, False)
    full = cb_evidence.detail_html(b_real._cb_findings[0])
    check("but the technical view still has the raw detection",
          "RAW DETECTION" in full or "Raw detection" in full)
    check("and the remediation is still recorded on the finding",
          bool(b_real._cb_findings[0].remediation))

    print(f"\n{PASS} passed, {FAIL} failed")
    return 1 if FAIL else 0


if __name__ == "__main__":
    sys.exit(main())
