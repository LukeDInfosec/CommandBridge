"""
JavaScript reconnaissance & static analysis.

Two phases, run in a background QThread so the UI never blocks:

  Phase 1 — Spider the target (same-domain), parse every page's HTML for
            <script src> and inline .js references, resolve them to absolute
            URLs, and write the unique list to identified_js.txt.

  Phase 2 — Download each JS file, fetch its source map when one is served,
            and run the rule engine in js_findings over it. Findings are
            written to js_analysis_results.txt and printed to the console
            grouped by category, followed by a summary block.

This module owns the network and the presentation; every detection rule lives
in js_findings, which has no Qt and no I/O and can therefore be tested on its
own. The split matters because the rules are where the accuracy lives.

Fetching the source map is done here rather than there because it takes a
request. It is worth making: with a map, a finding in a one-line bundle is
reported as "src/admin/Billing.tsx line 142" instead of an offset, and matches
inside node_modules can be demoted rather than shown to a client.

Wired into CommandBridgeV5 via JsAnalysisMixin. Stdlib only (urllib/ssl/re).
"""
import os
import re
import ssl
import html
import base64
from pathlib import Path
from urllib import request as _urlrequest
from urllib.parse import urlparse, urljoin, unquote
from concurrent.futures import ThreadPoolExecutor, as_completed

from PyQt6.QtCore import QObject, QThread, pyqtSignal
from PyQt6.QtWidgets import QMessageBox


# ── Severity model ──────────────────────────────────────────────────────────
from command_bridge.modules.js_findings import (
    SEV_ORDER, CATEGORY_GUIDANCE, SourceMap, analyse as analyse_javascript,
    merge_findings, is_minified,
)

SEV_COLORS = {
    "CRITICAL": "#ef4444", "HIGH": "#f97316", "MEDIUM": "#f59e0b",
    "LOW": "#38bdf8", "INFO": "#94a3b8",
}

CONFIDENCE_NOTE = {
    "confirmed": "confirmed by an offline check (checksum, decode or structure)",
    "firm": "pattern and context both matched",
    "tentative": "needs manual confirmation before it goes in a report",
}

_UA = "Mozilla/5.0 (CommandBridge JS-Recon)"
MAX_PAGES = 60          # crawl budget
MAX_DEPTH = 2           # how deep to spider from the target
MAX_JS_FILES = 250      # cap on JS files analysed
MAX_JS_BYTES = 3_000_000

# ── Precompiled detection patterns ──────────────────────────────────────────
SCRIPT_SRC_RE = re.compile(r"""<script[^>]+src\s*=\s*['"]([^'"]+)['"]""", re.IGNORECASE)
JS_REF_RE = re.compile(r"""['"]([^'"]+?\.js(?:\?[^'"]*)?)['"]""", re.IGNORECASE)
HREF_RE = re.compile(r"""<a[^>]+href\s*=\s*['"]([^'"#]+)['"]""", re.IGNORECASE)
SOURCEMAP_REF_RE = re.compile(r"//[#@]\s*sourceMappingURL=(\S+)")


def _exposed_map_finding(js_url, content, offset, map_info, note):
    """A source map that is actually served is a finding in its own right.

    The detector in js_findings only sees the reference in the file; whether
    the map is reachable takes a request, which is this module's job. So the
    confirmed-exposure finding is built here, where the HTTP status is known.
    """
    from command_bridge.modules.js_findings import Finding, Location, excerpt

    offset = max(0, offset)
    finding = Finding(
        severity="HIGH" if map_info.get("has_content") else "MEDIUM",
        category="Source map exposed",
        title=f"{map_info['url'].rsplit('/', 1)[-1]} is served (HTTP {map_info['status']})",
        evidence=map_info["url"],
        detail=f"Returned {note}.",
        confidence="confirmed",
        cwe="CWE-540",
        rec=("Download it and reconstruct the original tree — unwebpack-sourcemap, "
             "or `npx source-map-explorer` for a fast view of the module layout. "
             "Then read it for admin components that are never linked, real "
             "parameter names, the permission model, build-time environment "
             "variables and original comments. Report the exposure itself, and "
             "everything it leads to as separate findings."),
        count=1,
    )
    finding.locations.append(Location(
        file=js_url, line=1, column=1, offset=offset,
        excerpt=excerpt(content, offset, min(len(content), offset + 60)),
    ))
    return finding


def _ctx():
    return ssl._create_unverified_context()


def _registrable_domain(host):
    parts = (host or "").split(".")
    return ".".join(parts[-2:]) if len(parts) >= 2 else host


class _JsAnalysisWorker(QObject):
    progress = pyqtSignal(str)
    finished = pyqtSignal(dict)

    def __init__(self, target, output_dir):
        super().__init__()
        self.target = target
        self.output_dir = output_dir
        p = urlparse(target if "://" in target else "http://" + target)
        self.scheme = p.scheme or "http"
        self.base_host = p.netloc
        self.base_domain = _registrable_domain(p.hostname or "")

    # ── HTTP ────────────────────────────────────────────────────────────────
    def _get(self, url, max_bytes=MAX_JS_BYTES, timeout=10):
        try:
            req = _urlrequest.Request(url, headers={"User-Agent": _UA})
            with _urlrequest.urlopen(req, timeout=timeout, context=_ctx()) as r:
                ct = r.headers.get("Content-Type", "")
                body = r.read(max_bytes).decode("utf-8", errors="replace")
                return r.status, ct, body
        except Exception as e:
            return getattr(e, "code", None), "", ""

    def _same_site(self, host):
        return host and (host == self.base_host or _registrable_domain(host) == self.base_domain)

    # ── Phase 1: spider for JS files ────────────────────────────────────────
    def _spider(self):
        start = self.target if "://" in self.target else f"{self.scheme}://{self.target}"
        queue = [(start, 0)]
        visited = set()
        js_urls = set()
        pages = 0
        while queue and pages < MAX_PAGES:
            url, depth = queue.pop(0)
            if url in visited:
                continue
            visited.add(url)
            status, ct, body = self._get(url, max_bytes=1_500_000, timeout=10)
            if not body or "html" not in (ct or "").lower():
                continue
            pages += 1
            self.progress.emit(f"    [crawl {pages}/{MAX_PAGES}] {url}\n")

            for m in SCRIPT_SRC_RE.finditer(body):
                js_urls.add(urljoin(url, m.group(1)))
            for m in JS_REF_RE.finditer(body):
                js_urls.add(urljoin(url, m.group(1)))

            if depth < MAX_DEPTH:
                for m in HREF_RE.finditer(body):
                    nxt = urljoin(url, m.group(1))
                    h = urlparse(nxt).hostname
                    if nxt.startswith("http") and self._same_site(h) and nxt not in visited:
                        queue.append((nxt, depth + 1))

        # keep only .js (allow third-party JS too — they're part of attack surface)
        cleaned = sorted({u for u in js_urls if ".js" in urlparse(u).path.lower() or u.lower().endswith(".js")})
        return cleaned

    # ── Phase 2: analyse one JS file ────────────────────────────────────────
    def _fetch_source_map(self, js_url, content, agg):
        """Fetch the file's source map, if it declares one and it is served.

        This is worth a request per file because it changes the quality of
        everything downstream: with a map, a finding at "offset 418,902" can be
        reported as "src/admin/Billing.tsx line 142", and matches inside
        node_modules can be demoted instead of wasting the client's time.
        """
        m = SOURCEMAP_REF_RE.search(content)
        if not m:
            return None, None

        ref = m.group(1).strip()
        if ref.startswith("data:"):
            # An inline map costs no request at all.
            try:
                payload = ref.split(",", 1)[1]
                raw = base64.b64decode(payload).decode("utf-8", "replace") \
                    if ";base64" in ref.split(",", 1)[0] else unquote(payload)
                agg["sourcemaps"] = agg.get("sourcemaps", 0) + 1
                return SourceMap(raw), {"url": ref[:60] + "…", "status": "inline"}
            except Exception:
                return None, {"url": ref[:60] + "…", "status": "inline (unreadable)"}

        map_url = urljoin(js_url, ref)
        status, _ct, body = self._get(map_url, max_bytes=MAX_JS_BYTES, timeout=12)
        if status != 200 or not body:
            return None, {"url": map_url, "status": status}
        try:
            source_map = SourceMap(body)
        except Exception:
            return None, {"url": map_url, "status": f"{status} (unparseable)"}

        agg["sourcemaps"] = agg.get("sourcemaps", 0) + 1
        agg.setdefault("sourcemap_urls", set()).add(map_url)
        for source in source_map.sources:
            if "node_modules" not in source:
                agg.setdefault("original_sources", set()).add(source)
        return source_map, {
            "url": map_url,
            "status": status,
            "sources": len(source_map.sources),
            "has_content": any(source_map.sources_content or []),
        }

    def _analyse(self, url, content, agg):
        """Run the shared rule engine over one file and return its findings."""
        source_map, map_info = self._fetch_source_map(url, content, agg)
        findings = analyse_javascript(url, content, source_map=source_map, agg=agg)

        if map_info and map_info.get("status") in (200, "inline"):
            first = content.find("sourceMappingURL")
            scanner_note = (
                f"{map_info['sources']} original source file(s)"
                if map_info.get("sources") else "inline map")
            if map_info.get("has_content"):
                scanner_note += ", including the full original source text"
            findings.append(_exposed_map_finding(url, content, first, map_info, scanner_note))

        if is_minified(content):
            agg["minified_files"] = agg.get("minified_files", 0) + 1
        agg["bytes"] = agg.get("bytes", 0) + len(content)
        return findings

    def run(self):
        result = {"js_urls": [], "findings": [], "summary": {}, "error": ""}
        try:
            self.progress.emit("[*] Phase 1: spidering target for JavaScript files…\n")
            js_urls = self._spider()
            result["js_urls"] = js_urls
            self.progress.emit(f"[i] Identified {len(js_urls)} JavaScript file(s).\n")
            if not js_urls:
                result["summary"] = self._empty_summary(0)
                self.finished.emit(result)
                return

            # Shared across every file in the run: inventories that only mean
            # something in aggregate (endpoints, GraphQL operations, recovered
            # source paths) and the counters the summary reports.
            agg = {"sourcemaps": 0, "bytes": 0, "minified_files": 0}
            findings = []
            targets = js_urls[:MAX_JS_FILES]
            self.progress.emit(f"[*] Phase 2: analysing {len(targets)} JavaScript file(s)…\n")

            def fetch_and_analyse(u):
                st, _ct, body = self._get(u)
                if not body:
                    return u, []
                return u, self._analyse(u, body, agg)

            done = 0
            with ThreadPoolExecutor(max_workers=8) as pool:
                futs = {pool.submit(fetch_and_analyse, u): u for u in targets}
                for fut in as_completed(futs):
                    done += 1
                    try:
                        _u, f = fut.result()
                        findings = merge_findings(findings, f)
                    except Exception:
                        pass
                    if done % 10 == 0 or done == len(targets):
                        self.progress.emit(f"    analysed {done}/{len(targets)}\n")

            result["findings"] = findings
            result["summary"] = self._build_summary(len(targets), findings, agg)
        except Exception as e:
            result["error"] = str(e)
        self.finished.emit(result)

    @staticmethod
    def _empty_summary(n):
        return {"files": n, "bytes": 0, "minified_files": 0, "endpoints": 0,
                "sensitive_endpoints": 0, "secrets": 0, "sourcemaps": 0,
                "original_sources": 0, "emails": 0, "websockets": 0,
                "graphql_ops": 0, "subdomains": 0,
                "risk": {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0},
                "confidence": {"confirmed": 0, "firm": 0, "tentative": 0},
                "occurrences": 0,
                "endpoint_list": [], "sensitive_endpoint_list": [],
                "email_list": [], "websocket_list": [], "graphql_list": [],
                "subdomain_list": [], "original_source_list": []}

    def _build_summary(self, files, findings, agg):
        risk = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
        confidence = {"confirmed": 0, "firm": 0, "tentative": 0}
        occurrences = 0
        for f in findings:
            risk[f.severity if f.severity in risk else "INFO"] += 1
            confidence[f.confidence if f.confidence in confidence else "firm"] += 1
            occurrences += f.count

        def listed(key):
            return sorted(agg.get(key, set()))

        return {
            "files": files,
            "bytes": agg.get("bytes", 0),
            "minified_files": agg.get("minified_files", 0),
            "endpoints": len(agg.get("endpoints", set())),
            "sensitive_endpoints": len(agg.get("sensitive_endpoints", set())),
            "secrets": sum(1 for f in findings if f.category == "Exposed Credential"),
            "sourcemaps": agg.get("sourcemaps", 0),
            "original_sources": len(agg.get("original_sources", set())),
            "emails": len(agg.get("emails", set())),
            "websockets": len(agg.get("websockets", set())),
            "graphql_ops": len(agg.get("graphql_ops", set())),
            "subdomains": len(agg.get("subdomains", set())),
            "risk": risk,
            "confidence": confidence,
            "occurrences": occurrences,
            "endpoint_list": listed("endpoints"),
            "sensitive_endpoint_list": listed("sensitive_endpoints"),
            "email_list": listed("emails"),
            "websocket_list": listed("websockets"),
            "graphql_list": listed("graphql_ops"),
            "subdomain_list": listed("subdomains"),
            "original_source_list": listed("original_sources"),
        }


class _LocalJsAnalysisWorker(_JsAnalysisWorker):
    """Run the same detector set over JavaScript already saved to disk.

    "Retrieve JS Files" pulls a site's scripts down with wget but nothing then
    looked at them. This reuses the live analyser's rules — secrets, hardcoded
    credentials, API keys, endpoints, source maps, DOM-XSS sinks, cloud
    storage, JWT handling — against a local folder, so files you grabbed
    earlier (or pulled from a client's bundle by hand) get the same treatment.
    """

    SUFFIXES = (".js", ".mjs", ".cjs", ".jsx", ".ts", ".tsx", ".json", ".map")

    def __init__(self, target, output_dir, js_dir):
        super().__init__(target or "http://local", output_dir)
        self.js_dir = Path(js_dir)

    def _fetch_source_map(self, js_path, content, agg):
        """Look for the map next to the file on disk instead of over HTTP.

        Files pulled down with wget keep their layout, so a map that was
        downloaded alongside its bundle is right there — and it is worth as
        much here as it is online, because it is what turns an offset into an
        original filename and line.
        """
        m = SOURCEMAP_REF_RE.search(content)
        if not m:
            return None, None
        ref = m.group(1).strip()
        if ref.startswith("data:"):
            return super()._fetch_source_map(js_path, content, agg)

        candidate = (Path(js_path).parent / ref.split("?")[0]).resolve()
        if not candidate.is_file():
            candidate = Path(str(js_path) + ".map")
        if not candidate.is_file():
            return None, {"url": ref, "status": "not present locally"}
        try:
            source_map = SourceMap(candidate.read_text(errors="replace"))
        except Exception:
            return None, {"url": str(candidate), "status": "unparseable"}

        agg["sourcemaps"] = agg.get("sourcemaps", 0) + 1
        for source in source_map.sources:
            if "node_modules" not in source:
                agg.setdefault("original_sources", set()).add(source)
        return source_map, {
            "url": str(candidate),
            "status": 200,
            "sources": len(source_map.sources),
            "has_content": any(source_map.sources_content or []),
        }

    def run(self):
        result = {"js_urls": [], "findings": [], "summary": {}, "error": ""}
        try:
            if not self.js_dir.is_dir():
                result["error"] = f"No such directory: {self.js_dir}"
                result["summary"] = self._empty_summary(0)
                self.finished.emit(result)
                return

            files = sorted(
                p for p in self.js_dir.rglob("*")
                if p.is_file() and p.suffix.lower() in self.SUFFIXES
            )
            result["js_urls"] = [str(p) for p in files]
            self.progress.emit(
                f"[i] Found {len(files)} script file(s) under {self.js_dir}\n"
            )
            if not files:
                self.progress.emit(
                    "[!] Nothing to analyse — run 'Retrieve JS Files' first, "
                    "or point this at a folder containing .js files.\n"
                )
                result["summary"] = self._empty_summary(0)
                self.finished.emit(result)
                return

            # Shared across every file in the run: inventories that only mean
            # something in aggregate (endpoints, GraphQL operations, recovered
            # source paths) and the counters the summary reports.
            agg = {"sourcemaps": 0, "bytes": 0, "minified_files": 0}
            findings = []
            targets = files[:MAX_JS_FILES]
            self.progress.emit(f"[*] Analysing {len(targets)} file(s)…\n")

            for index, path in enumerate(targets, start=1):
                try:
                    content = path.read_text(errors="replace")[:MAX_JS_BYTES]
                except Exception as exc:
                    self.progress.emit(f"    [skip] {path.name}: {exc}\n")
                    continue
                findings = merge_findings(findings, self._analyse(str(path), content, agg))
                if index % 10 == 0 or index == len(targets):
                    self.progress.emit(f"    analysed {index}/{len(targets)}\n")

            result["findings"] = findings
            result["summary"] = self._build_summary(len(targets), findings, agg)
        except Exception as e:
            result["error"] = str(e)
        self.finished.emit(result)


class JsAnalysisMixin:
    """Web Scraping → JS recon & analysis button handler."""

    def run_retrieve_and_analyse_js(self):
        """Pull the site's JavaScript down, then analyse what landed.

        Retrieving the scripts and then reading them are one job, not two —
        nobody downloads a folder of JS in order to leave it alone. The wget
        stage runs as a normal editable command (so the depth, host span and
        file types stay tweakable), and a one-shot follow-up hook kicks off
        the static analysis the moment it exits cleanly. If wget fails, the
        follow-up is skipped rather than analysing an empty folder.
        """
        template = self.command_registry.get("web_retrieve_js")
        if not template:
            self.console.append_ansi("\n[!] No retrieve command is configured.\n")
            return
        self._command_follow_up = self._analyse_retrieved_js
        self.run_command_template(template, label="Retrieve & Analyse JS Files")

    def _analyse_retrieved_js(self):
        """Follow-up stage: analyse the folder wget has just populated."""
        safe = self.sanitize_target_for_filename(getattr(self, "target", "") or "target")
        js_dir = Path(self.output_dir) / f"{safe}_js_files"
        if not js_dir.is_dir():
            self.console.append_ansi(
                f"\n[i] Nothing to analyse — {js_dir} was not created, which "
                "usually means the site served no .js files at that crawl depth.\n"
            )
            return
        self.run_downloaded_js_analysis(js_dir=js_dir)

    def run_downloaded_js_analysis(self, js_dir=None):
        """Analyse a folder of downloaded JavaScript.

        Called directly by the retrieve-and-analyse chain with the folder it
        just filled, and still usable on its own — with no folder given it
        looks for <target>_js_files and otherwise asks for one, so a set of
        scripts pulled down by hand can be analysed too.
        """
        from PyQt6.QtWidgets import QFileDialog

        safe = self.sanitize_target_for_filename(getattr(self, "target", "") or "target")
        default_dir = Path(self.output_dir) / f"{safe}_js_files"

        js_dir = Path(js_dir) if js_dir else default_dir
        if not js_dir.is_dir():
            chosen = QFileDialog.getExistingDirectory(
                self,
                "Select a folder of downloaded JavaScript files",
                str(self.output_dir),
            )
            if not chosen:
                self.console.append_ansi(
                    f"\n[!] {default_dir} does not exist yet — run 'Retrieve & "
                    "Analyse JS Files' first, or pick a folder to analyse.\n"
                )
                return
            js_dir = Path(chosen)

        try:
            self.goto_console()
        except Exception:
            pass

        self.console.append_ansi("\n" + "=" * 80 + "\n")
        self.console.append_ansi(f"[*] Static analysis of downloaded JavaScript — {js_dir}\n")
        self.console.append_ansi("=" * 80 + "\n")

        self._js_worker = _LocalJsAnalysisWorker(
            getattr(self, "target", ""), str(self.output_dir), str(js_dir)
        )
        self._js_thread = QThread()
        self._js_worker.moveToThread(self._js_thread)
        self._js_thread.started.connect(self._js_worker.run)
        self._js_worker.progress.connect(lambda m: self.console.append_ansi(m))
        self._js_worker.finished.connect(self._on_js_analysis_done)
        self._js_worker.finished.connect(self._js_thread.quit)
        self._js_thread.start()

    def run_js_analysis(self):
        if not getattr(self, "target", ""):
            self.show_themed_message(
                "No Target", "Set a target in the Target Setup tab first.",
                QMessageBox.Icon.Warning,
            )
            return
        try:
            self.goto_console()
        except Exception:
            pass
        self.console.append_ansi("\n" + "=" * 80 + "\n")
        self.console.append_ansi(f"[*] JavaScript Recon & Analysis — {self.target}\n")
        self.console.append_ansi("=" * 80 + "\n")

        self._js_worker = _JsAnalysisWorker(self.target, str(self.output_dir))
        self._js_thread = QThread()
        self._js_worker.moveToThread(self._js_thread)
        self._js_thread.started.connect(self._js_worker.run)
        self._js_worker.progress.connect(lambda m: self.console.append_ansi(m))
        self._js_worker.finished.connect(self._on_js_analysis_done)
        self._js_worker.finished.connect(self._js_thread.quit)
        self._js_thread.start()

    def _on_js_analysis_done(self, result):
        if result.get("error"):
            self.console.append_ansi(f"[!] JS analysis error: {result['error']}\n")

        js_urls = result.get("js_urls", [])
        try:
            Path(self.output_dir, "identified_js.txt").write_text(
                "\n".join(js_urls) + ("\n" if js_urls else ""),
                encoding="utf-8", errors="replace")
            self.console.append_ansi(f"[i] Wrote identified_js.txt ({len(js_urls)} files)\n")
        except Exception as e:
            self.console.append_ansi(f"[i] Could not write identified_js.txt: {e}\n")

        findings = result.get("findings", [])
        summary = result.get("summary", {})

        if findings:
            self._print_js_findings(findings, summary)

        self._write_js_report(result, findings)
        self._print_js_summary(summary)

        try:
            self.refresh_file_list()
        except Exception:
            pass

    # ── Console rendering ───────────────────────────────────────────────────

    def _print_js_findings(self, findings, summary):
        """Print findings grouped by category, worst first.

        Each finding shows where it is precisely enough to be found again —
        original file and line when a source map was available, otherwise the
        module, line, column and character offset — plus a window of the
        surrounding code with the match marked, because in a minified bundle
        the line number alone tells a reader nothing.
        """
        minified = summary.get("minified_files", 0)
        if minified:
            self.console.append_html(
                f'<br><span style="color:#94a3b8;">{minified} of '
                f'{summary.get("files", 0)} file(s) are minified, so positions are '
                f'given as line:column with a character offset'
                + (' and resolved through the source map where one was served'
                   if summary.get("sourcemaps") else '')
                + '.</span><br>')

        self.console.append_ansi("\n=== JavaScript Findings ===\n")

        by_cat = {}
        for f in findings:
            by_cat.setdefault(f.category, []).append(f)

        def cat_rank(name):
            return max(SEV_ORDER.get(x.severity, 0) for x in by_cat[name])

        for cat in sorted(by_cat, key=lambda c: (-cat_rank(c), c)):
            items = sorted(by_cat[cat],
                           key=lambda x: (-SEV_ORDER.get(x.severity, 0), x.title))
            top = items[0].severity
            colour = SEV_COLORS.get(top, "#94a3b8")
            occurrences = sum(x.count for x in items)
            heading = f"{cat} — {len(items)} finding(s)"
            if occurrences > len(items):
                heading += f", {occurrences} occurrence(s)"
            self.console.append_html(
                f'<br><span style="color:{colour};font-weight:bold;">[{html.escape(top)}] '
                f'{html.escape(heading)}</span><br>')

            guidance = CATEGORY_GUIDANCE.get(cat)
            if guidance:
                for line in guidance.split("\n"):
                    label, _, rest = line.partition(": ")
                    if label.isupper() and rest:
                        self.console.append_html(
                            f'&nbsp;&nbsp;<span style="color:#38bdf8;font-weight:bold;">'
                            f'{html.escape(label)}:</span> '
                            f'<span style="color:#9aa6b2;">{html.escape(rest)}</span><br>')
                    else:
                        self.console.append_html(
                            f'&nbsp;&nbsp;<span style="color:#9aa6b2;">'
                            f'{html.escape(line)}</span><br>')

            for f in items[:25]:
                self._print_one_finding(f)
            if len(items) > 25:
                self.console.append_html(
                    f'&nbsp;&nbsp;<span style="color:#64748b;">… +{len(items) - 25} more '
                    f'in js_analysis_results.txt</span><br>')

    def _print_one_finding(self, f):
        colour = SEV_COLORS.get(f.severity, "#94a3b8")
        header = f.title
        if f.count > 1:
            header += f"   ×{f.count}"
        self.console.append_html(
            f'<br>&nbsp;&nbsp;<span style="color:{colour};font-weight:bold;">'
            f'{html.escape(f.severity)}</span> '
            f'<span style="color:#e2e8f0;font-weight:bold;">{html.escape(header)}</span>'
            + (f' <span style="color:#64748b;">[{html.escape(f.cwe)}]</span>' if f.cwe else '')
            + '<br>')
        if f.evidence:
            self.console.append_html(
                f'&nbsp;&nbsp;&nbsp;&nbsp;<span style="color:#94a3b8;">evidence:</span> '
                f'<span style="color:#cbd5e1;">{html.escape(str(f.evidence)[:200])}</span><br>')
        if f.detail:
            self.console.append_html(
                f'&nbsp;&nbsp;&nbsp;&nbsp;<span style="color:#9aa6b2;">'
                f'{html.escape(f.detail[:400])}</span><br>')
        note = CONFIDENCE_NOTE.get(f.confidence, "")
        if note:
            self.console.append_html(
                f'&nbsp;&nbsp;&nbsp;&nbsp;<span style="color:#94a3b8;">confidence:</span> '
                f'<span style="color:#cbd5e1;">{html.escape(f.confidence)}</span> '
                f'<span style="color:#64748b;">— {html.escape(note)}</span><br>')

        for loc in f.locations:
            self.console.append_html(
                f'&nbsp;&nbsp;&nbsp;&nbsp;<span style="color:#64748b;">'
                f'{html.escape(loc.file)}</span><br>'
                f'&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;<span style="color:#64748b;">'
                f'{html.escape(loc.describe())}</span><br>')
            if loc.excerpt:
                self.console.append_html(
                    f'&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;'
                    f'<span style="color:#7f8ea3;font-family:monospace;">'
                    f'{html.escape(loc.excerpt[:260])}</span><br>')
        if f.count > len(f.locations):
            self.console.append_html(
                f'&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;<span style="color:#64748b;">'
                f'(+{f.count - len(f.locations)} further occurrence(s) — the report '
                f'lists the same exemplars)</span><br>')
        if f.rec:
            self.console.append_html(
                f'&nbsp;&nbsp;&nbsp;&nbsp;<span style="color:#22d3ee;">next step:</span> '
                f'<span style="color:#9aa6b2;">{html.escape(f.rec[:400])}</span><br>')

    # ── Written report ──────────────────────────────────────────────────────

    def _write_js_report(self, result, findings):
        s = result.get("summary", {})
        lines = [
            "JavaScript Static Analysis",
            "=" * 72,
            "",
            f"Files analysed        : {s.get('files', 0)}  "
            f"({s.get('bytes', 0):,} bytes, {s.get('minified_files', 0)} minified)",
            f"Findings              : {len(findings)} distinct, "
            f"{s.get('occurrences', 0)} occurrences",
            f"Source maps served    : {s.get('sourcemaps', 0)}"
            + (f"  ({s.get('original_sources', 0)} original source files recovered)"
               if s.get("original_sources") else ""),
            "",
            "Positions are given as line:column with a character offset, because a "
            "production bundle is a single line and a line number alone identifies "
            "nothing. Where a source map was served, the original file and line are "
            "given first and the minified position follows in brackets.",
            "",
        ]

        by_cat = {}
        for f in findings:
            by_cat.setdefault(f.category, []).append(f)

        def cat_rank(name):
            return max(SEV_ORDER.get(x.severity, 0) for x in by_cat[name])

        for cat in sorted(by_cat, key=lambda c: (-cat_rank(c), c)):
            items = sorted(by_cat[cat],
                           key=lambda x: (-SEV_ORDER.get(x.severity, 0), x.title))
            lines += ["", "=" * 72, f"{cat.upper()}  ({len(items)} finding(s))", "=" * 72]
            guidance = CATEGORY_GUIDANCE.get(cat)
            if guidance:
                lines += ["", *guidance.split("\n"), ""]
            for f in items:
                lines.append("-" * 72)
                lines.append(f"[{f.severity}] {f.title}"
                             + (f"   (x{f.count})" if f.count > 1 else "")
                             + (f"   {f.cwe}" if f.cwe else ""))
                if f.evidence:
                    lines.append(f"  evidence   : {f.evidence}")
                if f.detail:
                    lines.append(f"  detail     : {f.detail}")
                lines.append(f"  confidence : {f.confidence} — "
                             f"{CONFIDENCE_NOTE.get(f.confidence, '')}")
                for loc in f.locations:
                    lines.append(f"  location   : {loc.file}")
                    lines.append(f"               {loc.describe()}")
                    if loc.excerpt:
                        lines.append(f"               {loc.excerpt}")
                if f.count > len(f.locations):
                    lines.append(f"               (+{f.count - len(f.locations)} "
                                 f"further occurrence(s))")
                if f.rec:
                    lines.append(f"  next step  : {f.rec}")

        def block(title, values, limit=400):
            if not values:
                return []
            out = ["", "=" * 72, f"{title}  ({len(values)})", "=" * 72]
            out += [f"  {v}" for v in values[:limit]]
            if len(values) > limit:
                out.append(f"  … +{len(values) - limit} more")
            return out

        lines += block("SENSITIVE ENDPOINTS", s.get("sensitive_endpoint_list", []))
        lines += block("ALL ENDPOINTS REFERENCED", s.get("endpoint_list", []))
        lines += block("ORIGINAL SOURCE FILES (from source maps)",
                       s.get("original_source_list", []))
        lines += block("GRAPHQL OPERATIONS", s.get("graphql_list", []))
        lines += block("WEBSOCKET ENDPOINTS", s.get("websocket_list", []))
        lines += block("SUBDOMAINS", s.get("subdomain_list", []))
        lines += block("EMAIL ADDRESSES", s.get("email_list", []))

        try:
            Path(self.output_dir, "js_analysis_results.txt").write_text(
                "\n".join(lines) + "\n", encoding="utf-8", errors="replace")
            self.console.append_ansi("[i] Wrote js_analysis_results.txt\n")
        except Exception as e:
            self.console.append_ansi(f"[i] Could not write js_analysis_results.txt: {e}\n")

    def _print_js_summary(self, s):
        if not s:
            return
        risk = s.get("risk", {})
        confidence = s.get("confidence", {})
        rows = [
            ("Files Analysed", f"{s.get('files', 0)}  ({s.get('bytes', 0):,} bytes)"),
            ("Minified Bundles", s.get("minified_files", 0)),
            ("Distinct Findings", sum(risk.values())),
            ("Total Occurrences", s.get("occurrences", 0)),
            ("Exposed Credentials", s.get("secrets", 0)),
            ("Source Maps Served", s.get("sourcemaps", 0)),
            ("Original Sources Recovered", s.get("original_sources", 0)),
            ("Endpoints Referenced", s.get("endpoints", 0)),
            ("Sensitive Endpoints", s.get("sensitive_endpoints", 0)),
            ("GraphQL Operations", s.get("graphql_ops", 0)),
            ("WebSocket Endpoints", s.get("websockets", 0)),
            ("Email Addresses", s.get("emails", 0)),
        ]
        bar = "═" * 56
        self.console.append_html(
            f'<br><span style="color:#22d3ee;font-weight:bold;">{bar}</span><br>'
            f'<span style="color:#22d3ee;font-weight:bold;">  JS ANALYSIS COMPLETE</span><br>'
            f'<span style="color:#22d3ee;font-weight:bold;">{bar}</span><br>')
        for label, val in rows:
            self.console.append_html(
                f'&nbsp;&nbsp;<span style="color:#94a3b8;">{html.escape(label)}:</span> '
                f'<span style="color:#e2e8f0;font-weight:bold;">{html.escape(str(val))}</span><br>')

        self.console.append_html('&nbsp;&nbsp;<span style="color:#94a3b8;">By severity:</span><br>')
        for sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"):
            self.console.append_html(
                f'&nbsp;&nbsp;&nbsp;&nbsp;<span style="color:{SEV_COLORS[sev]};font-weight:bold;">'
                f'{sev.title()}: {risk.get(sev, 0)}</span><br>')

        self.console.append_html(
            '&nbsp;&nbsp;<span style="color:#94a3b8;">By confidence:</span><br>'
            f'&nbsp;&nbsp;&nbsp;&nbsp;<span style="color:#e2e8f0;">'
            f'Confirmed: {confidence.get("confirmed", 0)}'
            f' &nbsp; Firm: {confidence.get("firm", 0)}'
            f' &nbsp; Needs manual triage: {confidence.get("tentative", 0)}</span><br>')

        self.console.append_html(
            f'&nbsp;&nbsp;<span style="color:#94a3b8;">Full detail with positions and '
            f'code context:</span> '
            f'<span style="color:#e2e8f0;">js_analysis_results.txt</span><br>'
            f'<span style="color:#22d3ee;font-weight:bold;">{bar}</span><br>')
