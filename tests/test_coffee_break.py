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

from command_bridge.modules.coffee_break import (          # noqa: E402
    CBFinding, SEVERITIES, SEV_ORDER, CoffeeBreakMixin,
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

    def do_GET(self):
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
        self._cb_reset()

    # console
    def append_ansi(self, text):
        self.printed.append(text)

    # window bits the parsers touch
    def get_scanner_target(self):
        return urllib.parse.urlparse(self._cb_target_url()).netloc.split(":")[0]

    def sanitize_target_for_filename(self, value):
        return re.sub(r"[^A-Za-z0-9_.-]+", "_", value)


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
              any("Version disclosure in server" in t for t in titles))
        check("X-Powered-By is reported",
              any("x-powered-by" in t for t in titles))
        check("a cookie without Secure is reported",
              any("without" in t and "session" in t for t in titles))
        check("WordPress is detected from the body",
              "wordpress" in artefacts["tech"])
        check("nginx is detected from the header",
              "nginx" in artefacts["tech"])
        check("nothing is reported above medium for headers alone",
              max(SEV_ORDER[f.severity] for f in found) <= SEV_ORDER["MEDIUM"])

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
        check("the remediation comes with it",
              any(f.remediation == "Patch it." for f in engine._cb_findings))

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
        check("banner lines are not findings", produced, 2)
        check("nikto findings are marked tentative",
              all(f.confidence == "tentative" for f in engine._cb_findings))

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

    finally:
        server.shutdown()

    print(f"\n{PASS} passed, {FAIL} failed")
    return 1 if FAIL else 0


if __name__ == "__main__":
    sys.exit(main())
