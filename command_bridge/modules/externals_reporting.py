"""
Externals reporting & reconnaissance engine.

This module layers an automated external-pentest reconnaissance engine on top of
the base Externals workflow (see externals.py). It adds:

  * A findings/prioritisation engine (Critical/High/Medium/Low/Info).
  * Service-grouped, Nessus-style summaries (Port -> affected hosts).
  * Administrative-interface detection (login/admin panels, dashboards).
  * Additional external checks (HTTP TRACE, exposed .git, backup/.env files,
    directory listing, robots.txt/sitemap.xml, server-version disclosure).
  * Technology fingerprinting (nmap banners + whatweb/nuclei when installed).
  * Consolidated report files + a Nessus-style console summary.

The base state machine (ExternalsMixin._on_externals_command_finished) hands off
to ``_externals_begin_web_recon`` once the TLS phase completes. Active HTTP
probing runs in a background QThread (``_ExternalsWebReconWorker``) so the UI
never blocks; when it finishes, ``_externals_finalize_assessment`` builds every
report file and prints the final summary.
"""
import os
import re
import sys
import json
import html
import shutil
import socket
import tempfile
import subprocess
from datetime import datetime
from pathlib import Path
from urllib import request as _urlrequest
from urllib.parse import urlparse
from concurrent.futures import ThreadPoolExecutor, as_completed

from PyQt6.QtCore import QObject, QThread, pyqtSignal


# ── Severity model ──────────────────────────────────────────────────────────
SEVERITY_ORDER = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "INFO": 0}
SEVERITY_COLORS = {
    "CRITICAL": "#ef4444",
    "HIGH": "#f97316",
    "MEDIUM": "#f59e0b",
    "LOW": "#38bdf8",
    "INFO": "#94a3b8",
}

# Ports that, when exposed to the Internet, are typically unauthenticated and
# allow direct data exposure or remote code execution -> escalate to CRITICAL.
CRITICAL_EXPOSURE_PORTS = {
    6379, 11211, 9200, 9300, 27017, 27018, 27019, 5984, 9042, 7474,
    2375, 4243, 6443, 10250, 8500, 8200, 2379,
}

# Common administrative / management paths probed on each discovered web asset.
ADMIN_PATHS = [
    "/admin", "/login", "/administrator", "/manage", "/management",
    "/dashboard", "/wp-admin/", "/wp-login.php", "/phpmyadmin/",
    "/manager/html", "/jenkins", "/grafana", "/kibana", "/prometheus",
    "/server-status", "/actuator", "/console", "/cpanel", "/webadmin",
    "/admin/login", "/user/login", "/auth/login",
]

# Sensitive files/paths whose exposure is a finding in its own right.
EXPOSURE_PATHS = [
    "/.git/HEAD", "/.env", "/.svn/entries", "/.DS_Store", "/web.config",
    "/backup.zip", "/backup.tar.gz", "/db.sql", "/dump.sql",
    "/config.php.bak", "/.htpasswd", "/server-info",
]

# Paths checked for autoindex / directory listing.
DIR_LISTING_PATHS = ["/", "/uploads/", "/files/", "/images/", "/backup/", "/assets/"]

# Cap on how many web assets receive active probing, to bound runtime.
MAX_ACTIVE_ASSETS = 100

_USER_AGENT = "Mozilla/5.0 (CommandBridge External Recon)"


# ════════════════════════════════════════════════════════════════════════════
#  Background worker — active web reconnaissance
# ════════════════════════════════════════════════════════════════════════════
class _ExternalsWebReconWorker(QObject):
    """Runs active HTTP recon against web assets in a background thread.

    Emits ``finished`` with a results dict:
        {
          "admin":      [ {url, path, status, title} ... ],
          "findings":   [ {severity, title, target, detail, evidence} ... ],
          "tech_by_host": { host: [tech, ...] },
        }
    All network/tool access happens off the GUI thread; the main thread only
    consumes the returned data (no shared mutable state).
    """

    progress = pyqtSignal(str)
    finished = pyqtSignal(dict)

    _TITLE_RE = re.compile(r"<title[^>]*>(.*?)</title>", re.IGNORECASE | re.DOTALL)
    _VER_RE = re.compile(r"\d")

    def __init__(self, web_assets, output_dir, use_whatweb=False, use_nuclei=False):
        super().__init__()
        self.web_assets = list(web_assets)
        self.output_dir = output_dir
        self.use_whatweb = use_whatweb
        self.use_nuclei = use_nuclei

    # ── HTTP helpers ────────────────────────────────────────────────────────
    def _http(self, base, path="", method="GET", timeout=7, max_bytes=24000):
        """Return (status, headers_lower, body_text) or (None, {}, "")."""
        url = base.rstrip("/") + path
        try:
            import ssl as _ssl
            ctx = _ssl._create_unverified_context()
            req = _urlrequest.Request(url, method=method, headers={"User-Agent": _USER_AGENT})
            with _urlrequest.urlopen(req, timeout=timeout, context=ctx) as resp:
                status = resp.status
                headers = {k.lower(): v for k, v in resp.getheaders()}
                body = resp.read(max_bytes).decode("utf-8", errors="replace")
                return status, headers, body
        except Exception as e:
            # HTTPError still carries a status code we want (401/403/500...).
            status = getattr(e, "code", None)
            if status is not None:
                headers = {}
                try:
                    headers = {k.lower(): v for k, v in e.headers.items()}
                except Exception:
                    pass
                body = ""
                try:
                    body = e.read(max_bytes).decode("utf-8", errors="replace")
                except Exception:
                    pass
                return status, headers, body
            return None, {}, ""

    def _title(self, body):
        if not body:
            return ""
        m = self._TITLE_RE.search(body)
        if not m:
            return ""
        title = re.sub(r"\s+", " ", m.group(1)).strip()
        return title[:120]

    @staticmethod
    def _host_of(url):
        try:
            p = urlparse(url)
            return p.hostname or url
        except Exception:
            return url

    # ── Per-asset probing ───────────────────────────────────────────────────
    def _probe_asset(self, url):
        host = self._host_of(url)
        result = {"admin": [], "findings": [], "tech": set()}

        def add(sev, title, detail="", evidence="", target=None):
            result["findings"].append({
                "severity": sev, "title": title,
                "target": target or url, "detail": detail, "evidence": evidence,
            })

        # Root request: server banner, tech, title.
        status, headers, body = self._http(url, "/")
        if status is not None:
            server = headers.get("server", "")
            powered = headers.get("x-powered-by", "")
            if server:
                result["tech"].add(server)
                if self._VER_RE.search(server):
                    add("INFO", "Server software / version disclosed in HTTP banner",
                        detail=f"Server: {server}", evidence=server)
            if powered:
                result["tech"].add(powered)
                add("INFO", "Technology disclosed via X-Powered-By header",
                    detail=f"X-Powered-By: {powered}", evidence=powered)

        # HTTP TRACE
        t_status, _t_headers, t_body = self._http(url, "/", method="TRACE")
        if t_status == 200 and ("TRACE " in (t_body or "") or "Via:" in (t_body or "")):
            add("LOW", "HTTP TRACE method enabled (Cross-Site Tracing)",
                detail="Server responded 200 to a TRACE request and echoed the request.",
                evidence="TRACE / HTTP/1.1 -> 200")

        # Exposed sensitive files
        for p in EXPOSURE_PATHS:
            s, _h, b = self._http(url, p)
            if s != 200 or not b:
                continue
            low = b.lower()
            if p == "/.git/HEAD":
                if "ref:" in low:
                    add("HIGH", "Exposed Git repository (.git directory accessible)",
                        detail="/.git/HEAD is readable; source code/secrets may be recoverable.",
                        evidence=b.strip()[:80], target=url + p)
            elif p == "/.env":
                if "=" in b and "<html" not in low:
                    add("CRITICAL", "Exposed .env file (application secrets)",
                        detail="/.env is readable and may contain credentials/API keys.",
                        evidence=b.strip().splitlines()[0][:80] if b.strip() else "",
                        target=url + p)
            else:
                if "<html" not in low and len(b.strip()) > 0:
                    add("MEDIUM", "Exposed sensitive/backup file",
                        detail=f"{p} returned HTTP 200 with non-HTML content.",
                        evidence=p, target=url + p)

        # Directory listing
        for p in DIR_LISTING_PATHS:
            s, _h, b = self._http(url, p)
            if s == 200 and b and ("Index of /" in b or "<title>Index of" in b):
                add("MEDIUM", "Directory listing enabled",
                    detail=f"Autoindex/directory listing is enabled at {p}.",
                    evidence=p, target=url + p)

        # robots.txt / sitemap.xml
        s, _h, b = self._http(url, "/robots.txt")
        if s == 200 and b and ("disallow" in b.lower() or "allow" in b.lower()):
            interesting = [ln.strip() for ln in b.splitlines()
                           if ln.strip().lower().startswith("disallow")][:8]
            add("INFO", "robots.txt present (may reveal hidden paths)",
                detail="; ".join(interesting) if interesting else "robots.txt accessible",
                evidence="/robots.txt", target=url + "/robots.txt")
        s, _h, b = self._http(url, "/sitemap.xml")
        if s == 200 and b and "<url" in b.lower():
            add("INFO", "sitemap.xml present", detail="Sitemap accessible; enumerates application URLs.",
                evidence="/sitemap.xml", target=url + "/sitemap.xml")

        # Administrative interfaces
        for p in ADMIN_PATHS:
            s, _h, b = self._http(url, p)
            if s is None:
                continue
            if s in (200, 401, 403, 301, 302):
                title = self._title(b) if s == 200 else ""
                result["admin"].append({"url": url + p, "path": p, "status": s, "title": title})
                if s == 200:
                    add("HIGH", "Administrative interface accessible (HTTP 200)",
                        detail=f"{p} returned 200" + (f" — title: {title}" if title else ""),
                        evidence=f"{p} 200", target=url + p)
                elif s in (401, 403):
                    add("MEDIUM", "Administrative interface present (authentication required)",
                        detail=f"{p} returned {s} (login/auth gate exposed to the Internet).",
                        evidence=f"{p} {s}", target=url + p)
                else:
                    add("INFO", "Administrative path redirects (login portal likely)",
                        detail=f"{p} returned {s} redirect.",
                        evidence=f"{p} {s}", target=url + p)

        # Also treat an obvious login title on the root as an admin interface.
        root_title = self._title(body) if body else ""
        if root_title and re.search(r"login|sign in|admin|dashboard|portal|console", root_title, re.IGNORECASE):
            result["admin"].append({"url": url, "path": "/", "status": status or 200, "title": root_title})

        return result

    # ── External tool integration (optional) ────────────────────────────────
    def _run_whatweb(self, url):
        try:
            proc = subprocess.run(
                ["whatweb", "--color=never", "-q", "--no-errors", url],
                stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, timeout=40,
            )
            line = proc.stdout.decode("utf-8", errors="replace").strip()
            return line
        except Exception:
            return ""

    def _run_nuclei(self, assets):
        """Run nuclei once over all assets; yield finding dicts."""
        findings = []
        tmp = None
        try:
            tmp = tempfile.NamedTemporaryFile("w", suffix=".txt", delete=False, encoding="utf-8")
            tmp.write("\n".join(assets) + "\n")
            tmp.close()
            self.progress.emit("[*] Running nuclei (exposures / misconfig / tech / ssl)…\n")
            proc = subprocess.run(
                ["nuclei", "-l", tmp.name, "-silent", "-jsonl",
                 "-severity", "low,medium,high,critical",
                 "-tags", "exposure,misconfig,tech,ssl,default-login",
                 "-timeout", "8", "-rate-limit", "50"],
                stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, timeout=900,
            )
            out = proc.stdout.decode("utf-8", errors="replace")
            for ln in out.splitlines():
                ln = ln.strip()
                if not ln or not ln.startswith("{"):
                    continue
                try:
                    obj = json.loads(ln)
                except Exception:
                    continue
                info = obj.get("info", {}) or {}
                sev = str(info.get("severity", "info")).upper()
                if sev not in SEVERITY_ORDER:
                    sev = "INFO"
                name = info.get("name", obj.get("template-id", "nuclei finding"))
                target = obj.get("matched-at") or obj.get("host") or ""
                findings.append({
                    "severity": sev, "title": f"[nuclei] {name}",
                    "target": target, "detail": obj.get("template-id", ""),
                    "evidence": (obj.get("matched-at") or "")[:160],
                })
            self.progress.emit(f"[i] nuclei produced {len(findings)} finding(s).\n")
        except subprocess.TimeoutExpired:
            self.progress.emit("[!] nuclei timed out; continuing with partial results.\n")
        except Exception as e:
            self.progress.emit(f"[!] nuclei error: {e}\n")
        finally:
            if tmp is not None:
                try:
                    os.unlink(tmp.name)
                except Exception:
                    pass
        return findings

    # ── Entry point ─────────────────────────────────────────────────────────
    def run(self):
        results = {"admin": [], "findings": [], "tech_by_host": {}}
        assets = self.web_assets[:MAX_ACTIVE_ASSETS]
        if len(self.web_assets) > MAX_ACTIVE_ASSETS:
            self.progress.emit(
                f"[i] {len(self.web_assets)} web assets discovered; actively probing the first "
                f"{MAX_ACTIVE_ASSETS} (raise MAX_ACTIVE_ASSETS to cover all).\n"
            )

        self.progress.emit(f"[*] Active web recon across {len(assets)} asset(s)…\n")
        try:
            with ThreadPoolExecutor(max_workers=12) as pool:
                future_map = {pool.submit(self._probe_asset, u): u for u in assets}
                done = 0
                for fut in as_completed(future_map):
                    url = future_map[fut]
                    done += 1
                    try:
                        r = fut.result()
                    except Exception as e:
                        self.progress.emit(f"[!] Recon error for {url}: {e}\n")
                        continue
                    results["admin"].extend(r["admin"])
                    results["findings"].extend(r["findings"])
                    if r["tech"]:
                        host = self._host_of(url)
                        results["tech_by_host"].setdefault(host, [])
                        for t in r["tech"]:
                            if t not in results["tech_by_host"][host]:
                                results["tech_by_host"][host].append(t)
                    if r["admin"]:
                        self.progress.emit(
                            f"[+] {url} — {len(r['admin'])} admin/login path(s)\n"
                        )
                    self.progress.emit(f"    [{done}/{len(assets)}] {url}\n")
        except Exception as e:
            self.progress.emit(f"[!] Web recon pool error: {e}\n")

        # Optional whatweb fingerprinting
        if self.use_whatweb:
            self.progress.emit("[*] Fingerprinting with whatweb…\n")
            for u in assets:
                line = self._run_whatweb(u)
                if line:
                    host = self._host_of(u)
                    results["tech_by_host"].setdefault(host, [])
                    if line not in results["tech_by_host"][host]:
                        results["tech_by_host"][host].append(line)
                    results["findings"].append({
                        "severity": "INFO", "title": "Technology fingerprint (whatweb)",
                        "target": u, "detail": line[:200], "evidence": "",
                    })

        # Optional nuclei templated checks
        if self.use_nuclei and assets:
            results["findings"].extend(self._run_nuclei(assets))

        self.finished.emit(results)


# ════════════════════════════════════════════════════════════════════════════
#  Mixin — wired into CommandBridgeV4 alongside ExternalsMixin
# ════════════════════════════════════════════════════════════════════════════
class ExternalsReportingMixin:
    """Findings engine, recon hand-off, prioritisation and reporting."""

    # ── Findings plumbing ───────────────────────────────────────────────────
    def _externals_findings(self):
        ctx = getattr(self, "_externals_context", {}) or {}
        return ctx.setdefault("findings", [])

    def _externals_finding_severity_for_port(self, port, base_sev):
        if port in CRITICAL_EXPOSURE_PORTS:
            return "CRITICAL"
        return (base_sev or "HIGH").upper()

    # ── Phase 2/3: dangerous services + grouped open-port summary ───────────
    def _externals_record_dangerous_findings(self, dangerous_entries):
        """Turn parsed dangerous nmap entries into prioritised findings."""
        for host, port, proto, service, reason, severity in dangerous_entries or []:
            sev = self._externals_finding_severity_for_port(port, severity)
            label = self._externals_get_port_label(port) or service or "service"
            self._externals_add_finding(
                sev,
                f"Internet-facing {label} ({port}/{proto})",
                target=host,
                detail=reason,
                evidence=f"{port}/{proto} {service}",
            )

    def _externals_write_dangerous_services(self, dangerous_entries):
        """Write dangerous_services.txt grouped by service (Nessus-style)."""
        from collections import defaultdict

        if not dangerous_entries:
            return
        groups = defaultdict(set)          # (label, port) -> {hosts}
        sev_of = {}                        # (label, port) -> severity
        for host, port, proto, service, reason, severity in dangerous_entries:
            label = self._externals_get_port_label(port) or service or "service"
            key = (label, port)
            groups[key].add(host)
            cur = sev_of.get(key)
            new = self._externals_finding_severity_for_port(port, severity)
            if cur is None or SEVERITY_ORDER.get(new, 0) > SEVERITY_ORDER.get(cur, 0):
                sev_of[key] = new

        lines = []
        lines.append("=" * 50)
        lines.append("Dangerous Public Facing Services Detected")
        lines.append("=" * 50)
        lines.append("")
        # Sort by severity desc, then port asc
        for (label, port) in sorted(groups, key=lambda k: (-SEVERITY_ORDER.get(sev_of.get(k, "HIGH"), 0), k[1])):
            hosts = sorted(groups[(label, port)])
            sev = sev_of.get((label, port), "HIGH")
            lines.append(f"{label} ({port})   [{sev}]")
            lines.append("Affected Hosts:")
            lines.extend(hosts)
            lines.append("")
        lines.append("=" * 50)

        self._externals_write_text("dangerous_services.txt", "\n".join(lines) + "\n")

        # Console echo (coloured by [DANGEROUS]/[WARNING] tags the console knows)
        self.console.append_ansi("\n=== Externals: Dangerous Services (grouped) ===\n")
        for (label, port) in sorted(groups, key=lambda k: (-SEVERITY_ORDER.get(sev_of.get(k, "HIGH"), 0), k[1])):
            hosts = sorted(groups[(label, port)])
            sev = sev_of.get((label, port), "HIGH")
            tag = "[DANGEROUS]" if sev in ("CRITICAL", "HIGH") else "[WARNING]"
            self.console.append_ansi(f"\n{tag} {label} ({port}) — {len(hosts)} host(s) [{sev}]\n")
            for h in hosts:
                self.console.append_ansi(f"    {h}\n")

    def _externals_write_open_ports_summary(self):
        """Write open_ports_by_service.txt: every open port -> affected hosts."""
        from collections import defaultdict

        ctx = getattr(self, "_externals_context", {}) or {}
        open_ports = ctx.get("open_ports") or []
        if not open_ports:
            return
        groups = defaultdict(set)     # (port, proto, service) -> {hosts}
        for rec in open_ports:
            key = (rec["port"], rec["proto"], rec.get("service", ""))
            groups[key].add(rec["host"])

        lines = ["Open Ports & Services (grouped by service)", "=" * 50, ""]
        self.console.append_ansi("\n=== Externals: Open Ports by Service ===\n")
        for (port, proto, service) in sorted(groups, key=lambda k: (k[0], k[1])):
            hosts = sorted(groups[(port, proto, service)])
            label = self._externals_get_port_label(port)
            svc = service or (label or "")
            header = f"Port {port}/{proto} {svc}".rstrip()
            lines.append(f"{header}   ({len(hosts)} host(s))")
            lines.extend(f"  {h}" for h in hosts)
            lines.append("")
            self.console.append_ansi(f"\n{header} — {len(hosts)} host(s)\n")
            for h in hosts:
                self.console.append_ansi(f"    {h}\n")
        self._externals_write_text("open_ports_by_service.txt", "\n".join(lines) + "\n")

    # ── Adaptive wordlist selection (Phase 5) ───────────────────────────────
    def _externals_select_wordlist_snippet(self):
        """Return a shell snippet that picks a tech-tailored wordlist.

        Used by directory enumeration so e.g. detecting nginx/IIS/Tomcat picks a
        matching SecLists wordlist before falling back to a generic one.
        """
        ctx = getattr(self, "_externals_context", {}) or {}
        tech = " ".join(sorted(ctx.get("web_tech") or [])).lower()
        base = "/usr/share/seclists/Discovery/Web-Content"
        candidates = []
        if "nginx" in tech or "openresty" in tech:
            candidates.append(f"{base}/nginx.txt")
        if "apache" in tech:
            candidates.append(f"{base}/apache.txt")
        if "iis" in tech or "microsoft" in tech or "asp.net" in tech:
            candidates += [f"{base}/IIS.fuzz.txt", f"{base}/CommonBackdoors-ASP.fuzz.txt"]
        if "tomcat" in tech or "coyote" in tech:
            candidates.append(f"{base}/tomcat.txt")
        if "wordpress" in tech or "wp-" in tech:
            candidates.append("/usr/share/seclists/Discovery/Web-Content/CMS/wordpress.fuzz.txt")
        return candidates

    # ── Phase 7: record TLS findings + tls_findings.txt ─────────────────────
    def _externals_record_tls_findings(self):
        ctx = getattr(self, "_externals_context", {}) or {}
        issues = ctx.get("tls_issues") or {}
        if not issues:
            return

        sev_map = {
            "lucky 13": "MEDIUM", "sweet 32": "MEDIUM", "beast": "MEDIUM",
            "cbc": "MEDIUM", "deprecated tls": "MEDIUM",
            "certificate expired": "HIGH", "chain not trusted": "MEDIUM",
            "self signed": "MEDIUM", "hsts missing": "LOW",
        }

        def severity_for(issue_name):
            low = issue_name.lower()
            for k, v in sev_map.items():
                if k in low:
                    return v
            return "MEDIUM"

        lines = ["TLS / SSL Findings", "=" * 50, ""]
        for issue, data in issues.items():
            hosts = sorted(data.get("hosts") or [])
            ciphers = sorted(data.get("ciphers") or [])
            sev = severity_for(issue)
            lines.append(f"{issue}   [{sev}]")
            if ciphers:
                lines.append("Detected ciphers / versions:")
                lines.extend(f"  {c}" for c in ciphers)
            lines.append("Affected Hosts:")
            lines.extend(hosts)
            lines.append("")
            for h in hosts:
                self._externals_add_finding(
                    sev, issue, target=h,
                    detail=("Ciphers: " + ", ".join(ciphers)) if ciphers else "",
                    evidence=", ".join(ciphers[:6]),
                )
        self._externals_write_text("tls_findings.txt", "\n".join(lines) + "\n")

    # ── Hand-off into active web recon (Phase 6/9) ──────────────────────────
    def _externals_begin_web_recon(self):
        """Start the background web-recon worker, then finalise."""
        self._externals_phase = "web_recon"

        # Record TLS findings now (covers both TLS and no-TLS paths).
        try:
            self._externals_record_tls_findings()
        except Exception as e:
            self.console.append_ansi(f"[i] TLS finding recording failed: {e}\n")

        ctx = getattr(self, "_externals_context", {}) or {}
        web_assets = list(ctx.get("web_assets") or [])
        if not web_assets:
            p = Path(self.output_dir) / "web_facing_hosts.txt"
            if p.exists():
                web_assets = [ln.strip() for ln in p.read_text(encoding="utf-8", errors="replace").splitlines() if ln.strip()]

        if not web_assets:
            self.console.append_ansi("\n[i] No web assets for active reconnaissance; finalising assessment.\n")
            self._externals_finalize_assessment()
            return

        use_whatweb = shutil.which("whatweb") is not None
        use_nuclei = shutil.which("nuclei") is not None

        self.console.append_ansi("\n" + "=" * 80 + "\n")
        self.console.append_ansi("[*] Phase: Active Web Reconnaissance (admin panels, exposures, fingerprinting)\n")
        self.console.append_ansi(
            f"[*] whatweb: {'yes' if use_whatweb else 'not found'} | "
            f"nuclei: {'yes' if use_nuclei else 'not found'}\n"
        )
        self.console.append_ansi("=" * 80 + "\n")

        self._extrecon_worker = _ExternalsWebReconWorker(
            web_assets, str(self.output_dir), use_whatweb, use_nuclei
        )
        self._extrecon_thread = QThread()
        self._extrecon_worker.moveToThread(self._extrecon_thread)
        self._extrecon_thread.started.connect(self._extrecon_worker.run)
        self._extrecon_worker.progress.connect(self._on_externals_web_recon_progress)
        self._extrecon_worker.finished.connect(self._on_externals_web_recon_done)
        self._extrecon_worker.finished.connect(self._extrecon_thread.quit)
        self._extrecon_thread.start()

    def _on_externals_web_recon_progress(self, msg):
        self.console.append_ansi(msg)

    def _on_externals_web_recon_done(self, results):
        ctx = getattr(self, "_externals_context", {}) or {}

        # Merge recon findings into the central DB.
        for f in results.get("findings", []):
            self._externals_add_finding(
                f.get("severity", "INFO"), f.get("title", ""),
                target=f.get("target", ""), detail=f.get("detail", ""),
                evidence=f.get("evidence", ""),
            )

        # Admin interfaces -> file + console.
        admin = results.get("admin", [])
        ctx["admin_interfaces"] = admin
        self._externals_context = ctx
        if admin:
            seen = set()
            lines = []
            self.console.append_ansi("\n=== Externals: Potential Administrative Interfaces ===\n")
            for a in sorted(admin, key=lambda x: (x.get("url", ""))):
                url = a.get("url", "")
                if url in seen:
                    continue
                seen.add(url)
                title = a.get("title") or ""
                status = a.get("status")
                lines.append(url)
                lines.append(f"Status: {status}" + (f"  |  Title: {title}" if title else ""))
                lines.append("")
                self.console.append_ansi(f"[WARNING] {url}  (HTTP {status})" + (f" — {title}" if title else "") + "\n")
            self._externals_write_text("potential_admin_interfaces.txt", "\n".join(lines) + "\n")

        # Technology fingerprints
        tech_by_host = results.get("tech_by_host", {})
        if tech_by_host:
            lines = ["Technology Fingerprints", "=" * 50, ""]
            for host in sorted(tech_by_host):
                lines.append(host)
                for t in tech_by_host[host]:
                    lines.append(f"  {t}")
                lines.append("")
            self._externals_write_text("technology_fingerprints.txt", "\n".join(lines) + "\n")

        # Additional checks summary (TRACE/git/backups/listing/robots)
        self._externals_write_additional_checks()

        self._externals_finalize_assessment()

    def _externals_write_additional_checks(self):
        """Compose additional_external_checks.txt from recorded findings."""
        findings = self._externals_findings()
        buckets = {
            "HTTP TRACE method enabled": [],
            "Exposed Git repository": [],
            "Exposed .env file": [],
            "Exposed sensitive/backup file": [],
            "Directory listing enabled": [],
            "robots.txt present": [],
            "sitemap.xml present": [],
            "Server software / version disclosed": [],
        }
        for f in findings:
            for key in buckets:
                if f["title"].startswith(key):
                    buckets[key].append(f.get("target", ""))
        if not any(buckets.values()):
            return
        lines = ["Additional External Checks", "=" * 50, ""]
        for key, targets in buckets.items():
            if not targets:
                continue
            lines.append(key)
            lines.extend(f"  {t}" for t in sorted(set(targets)))
            lines.append("")
        self._externals_write_text("additional_external_checks.txt", "\n".join(lines) + "\n")

    # ── Phase 10/11: prioritisation + reporting + Nessus summary ────────────
    def _externals_finalize_assessment(self):
        ctx = getattr(self, "_externals_context", {}) or {}
        findings = self._externals_findings()

        # Severity tally (per finding record).
        counts = {s: 0 for s in SEVERITY_ORDER}
        for f in findings:
            sev = (f.get("severity") or "INFO").upper()
            if sev not in counts:
                sev = "INFO"
            counts[sev] += 1

        targets = ctx.get("targets") or []
        live_hosts = ctx.get("live_hosts") or []
        web_assets = ctx.get("web_assets") or []
        admin = ctx.get("admin_interfaces") or []
        admin_count = len({a.get("url") for a in admin})

        meta = {
            "generated": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "targets_provided": len(targets),
            "live_hosts": len(live_hosts),
            "web_assets": len(web_assets),
            "admin_interfaces": admin_count,
            "counts": counts,
        }

        try:
            self._externals_write_technical_findings(findings)
            self._externals_write_executive_summary(meta, findings)
            self._externals_write_assessment_summary(meta, findings)
            self._externals_write_findings_json(meta, findings)
        except Exception as e:
            self.console.append_ansi(f"[i] Report generation error: {e}\n")

        self._externals_print_final_summary(meta)

        try:
            self.refresh_file_list()
        except Exception:
            pass

        # Reset workflow state.
        self._externals_active = False
        self._externals_phase = None
        self._externals_context = {}

    def _externals_aggregate_findings(self, findings):
        """Group identical findings across targets: (sev,title,detail) -> targets."""
        agg = {}
        for f in findings:
            sev = (f.get("severity") or "INFO").upper()
            if sev not in SEVERITY_ORDER:
                sev = "INFO"
            key = (sev, f.get("title", ""), f.get("detail", ""))
            entry = agg.setdefault(key, {"targets": [], "evidence": set()})
            t = f.get("target", "")
            if t and t not in entry["targets"]:
                entry["targets"].append(t)
            if f.get("evidence"):
                entry["evidence"].add(f["evidence"])
        # Return sorted list: severity desc, then most-affected first
        out = []
        for (sev, title, detail), data in agg.items():
            out.append({
                "severity": sev, "title": title, "detail": detail,
                "targets": data["targets"], "evidence": sorted(data["evidence"]),
            })
        out.sort(key=lambda x: (-SEVERITY_ORDER.get(x["severity"], 0), -len(x["targets"]), x["title"]))
        return out

    def _externals_write_technical_findings(self, findings):
        agg = self._externals_aggregate_findings(findings)
        lines = ["TECHNICAL FINDINGS (prioritised)", "=" * 60, ""]
        for sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"):
            block = [a for a in agg if a["severity"] == sev]
            if not block:
                continue
            lines.append("")
            lines.append(f"##### {sev} ({len(block)}) #####")
            lines.append("")
            for a in block:
                lines.append(f"[{sev}] {a['title']}")
                if a["detail"]:
                    lines.append(f"    Detail   : {a['detail']}")
                if a["evidence"]:
                    lines.append(f"    Evidence : {', '.join(a['evidence'][:6])}")
                lines.append(f"    Affected ({len(a['targets'])}):")
                lines.extend(f"      {t}" for t in a["targets"])
                lines.append("")
        self._externals_write_text("technical_findings.txt", "\n".join(lines) + "\n")

    def _externals_write_executive_summary(self, meta, findings):
        agg = self._externals_aggregate_findings(findings)
        c = meta["counts"]
        lines = [
            "EXECUTIVE SUMMARY — External Penetration Test",
            "=" * 60,
            f"Generated: {meta['generated']}",
            "",
            f"Targets provided        : {meta['targets_provided']}",
            f"Live hosts              : {meta['live_hosts']}",
            f"Web assets              : {meta['web_assets']}",
            f"Admin interfaces        : {meta['admin_interfaces']}",
            "",
            "Findings by severity:",
            f"  Critical : {c['CRITICAL']}",
            f"  High     : {c['HIGH']}",
            f"  Medium   : {c['MEDIUM']}",
            f"  Low      : {c['LOW']}",
            f"  Info     : {c['INFO']}",
            "",
        ]
        top = [a for a in agg if a["severity"] in ("CRITICAL", "HIGH")]
        if top:
            lines.append("Key issues requiring immediate attention:")
            lines.append("")
            for a in top[:20]:
                lines.append(f"  [{a['severity']}] {a['title']} — {len(a['targets'])} host(s)")
        else:
            lines.append("No Critical or High severity issues were identified.")
        self._externals_write_text("executive_summary.txt", "\n".join(lines) + "\n")

    def _externals_write_assessment_summary(self, meta, findings):
        c = meta["counts"]
        lines = [
            "=" * 50,
            "EXTERNAL ASSESSMENT SUMMARY",
            "=" * 50,
            "",
            f"Generated         : {meta['generated']}",
            f"Output Directory  : {self.output_dir}",
            "",
            f"Targets Provided  : {meta['targets_provided']}",
            f"Live Hosts        : {meta['live_hosts']}",
            f"Web Assets        : {meta['web_assets']}",
            f"Admin Interfaces  : {meta['admin_interfaces']}",
            "",
            f"Critical Findings : {c['CRITICAL']}",
            f"High Findings     : {c['HIGH']}",
            f"Medium Findings   : {c['MEDIUM']}",
            f"Low Findings      : {c['LOW']}",
            f"Info Findings     : {c['INFO']}",
            "",
            "Generated report files:",
            "  - dangerous_services.txt",
            "  - open_ports_by_service.txt",
            "  - web_facing_hosts.txt",
            "  - potential_admin_interfaces.txt",
            "  - additional_external_checks.txt",
            "  - technology_fingerprints.txt",
            "  - tls_findings.txt",
            "  - missing_security_headers.txt",
            "  - technical_findings.txt",
            "  - executive_summary.txt",
            "  - external_findings.json",
            "=" * 50,
        ]
        self._externals_write_text("external_assessment_summary.txt", "\n".join(lines) + "\n")

    def _externals_write_findings_json(self, meta, findings):
        agg = self._externals_aggregate_findings(findings)
        payload = {"meta": meta, "findings": agg}
        self._externals_write_text("external_findings.json", json.dumps(payload, indent=2))

    def _externals_print_final_summary(self, meta):
        c = meta["counts"]
        try:
            esc = html.escape
            rows = [
                ("Targets Provided", meta["targets_provided"], "#e2e8f0"),
                ("Live Hosts", meta["live_hosts"], "#e2e8f0"),
                ("Web Assets", meta["web_assets"], "#e2e8f0"),
                ("Potential Admin Interfaces", meta["admin_interfaces"], "#f59e0b"),
                ("Critical Findings", c["CRITICAL"], SEVERITY_COLORS["CRITICAL"]),
                ("High Findings", c["HIGH"], SEVERITY_COLORS["HIGH"]),
                ("Medium Findings", c["MEDIUM"], SEVERITY_COLORS["MEDIUM"]),
                ("Low Findings", c["LOW"], SEVERITY_COLORS["LOW"]),
                ("Informational Findings", c["INFO"], SEVERITY_COLORS["INFO"]),
            ]
            bar = "═" * 50
            self.console.append_html(
                f'<br><span style="color:#22d3ee;font-weight:bold;">{bar}</span><br>'
                f'<span style="color:#22d3ee;font-weight:bold;">  ASSESSMENT COMPLETE</span><br>'
                f'<span style="color:#22d3ee;font-weight:bold;">{bar}</span><br>'
            )
            for label, value, color in rows:
                self.console.append_html(
                    f'&nbsp;&nbsp;<span style="color:#94a3b8;">{esc(label):<28}</span>'
                    f'<span style="color:{color};font-weight:bold;">{value}</span><br>'
                )
            self.console.append_html(
                f'&nbsp;&nbsp;<span style="color:#94a3b8;">Output Directory</span> '
                f'<span style="color:#e2e8f0;">{esc(str(self.output_dir))}</span><br>'
                f'<span style="color:#22d3ee;font-weight:bold;">{bar}</span><br>'
            )
        except Exception:
            self.console.append_ansi("\n=== ASSESSMENT COMPLETE ===\n")

    # ── small IO helper ─────────────────────────────────────────────────────
    def _externals_write_text(self, filename, text):
        try:
            path = Path(self.output_dir) / filename
            path.write_text(text, encoding="utf-8", errors="replace")
            self.console.append_ansi(f"[i] Wrote {filename}\n")
        except Exception as e:
            self.console.append_ansi(f"[i] Could not write {filename}: {e}\n")
