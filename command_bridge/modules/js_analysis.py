"""
JavaScript reconnaissance & static analysis.

Two phases, run in a background QThread so the UI never blocks:

  Phase 1 — Spider the target (same-domain), parse every page's HTML for
            <script src> and inline .js references, resolve them to absolute
            URLs, and write the unique list to identified_js.txt.

  Phase 2 — Download each JS file and statically analyse it for the 25 finding
            categories (secrets, credentials, endpoints, source maps, DOM-XSS
            sinks, cloud storage, GraphQL/WebSocket, JWT logic, etc.). Findings
            are written to js_analysis_results.txt and printed (colour-coded by
            severity) to the console, followed by a summary block.

Wired into CommandBridgeV4 via JsAnalysisMixin. Stdlib only (urllib/ssl/re).
"""
import os
import re
import ssl
import html
from pathlib import Path
from urllib import request as _urlrequest
from urllib.parse import urlparse, urljoin
from concurrent.futures import ThreadPoolExecutor, as_completed

from PyQt6.QtCore import QObject, QThread, pyqtSignal
from PyQt6.QtWidgets import QMessageBox


# ── Severity model ──────────────────────────────────────────────────────────
SEV_ORDER = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "INFO": 0}
SEV_COLORS = {
    "CRITICAL": "#ef4444", "HIGH": "#f97316", "MEDIUM": "#f59e0b",
    "LOW": "#38bdf8", "INFO": "#94a3b8",
}

# Per-category exploitation / verification guidance — how an attacker would use
# the finding and how to prove (or disprove) impact for a report.
CATEGORY_GUIDANCE = {
    "Exposed Secret": "Treat as live until disproven. PoC: use the key against its API "
        "(Google key -> call a billable API; AWS AKIA -> `aws sts get-caller-identity`; "
        "Stripe sk_live -> `curl https://api.stripe.com/v1/balance -u <key>:`). Report the "
        "location + a benign authenticated call succeeding. Remediation: rotate + restrict.",
    "Hardcoded Credential": "Try the credential against the login/API it belongs to; screenshot a "
        "successful low-impact action. If it is a DB/connection string, note it is reachable from "
        "client code. Remediation: remove from client, rotate.",
    "Potential DOM XSS Sink": "Trace the sink's input back to a source (location.hash/search, "
        "postMessage, URL param, localStorage). If attacker-controllable, build a URL that reaches "
        "it. PoC: innerHTML -> `#<img src=x onerror=alert(document.domain)>`; eval/new Function -> "
        "inject an expression. Prove with alert(document.domain) and screenshot. If the source is "
        "NOT attacker-controlled, document why it is not exploitable.",
    "Client-Side Authorization Logic": "JS-side authz is bypassable. PoC: call the protected API "
        "directly in Burp as a low-priv user (or flip the flag in devtools) and show the server "
        "still returns the privileged data/action. If the server re-checks, mark as defence-in-depth.",
    "Sensitive Browser Storage": "Tokens in local/sessionStorage are readable by any XSS. PoC if an "
        "XSS exists: `fetch('//collab?c='+localStorage.getItem('token'))`. Otherwise document as an "
        "XSS impact amplifier; recommend HttpOnly cookies.",
    "Source Map": "If the .map returned 200, download and reconstruct source. PoC: `curl -s <url>.map` "
        "and show it reveals server comments/logic/secrets. Remediation: remove maps from prod.",
    "Potential Redirect Logic": "Check if the redirect target is user-controllable. PoC: supply an "
        "external URL and confirm off-site navigation -> open redirect; include the exact param.",
    "Potential SSRF Surface": "If the client-supplied URL is fetched server-side it is SSRF. Pivot to "
        "Burp, replace with a collaborator or http://169.254.169.254/ and confirm interaction.",
    "Weak Cryptography": "Only a weakness if used for security (password hashing, token signing, "
        "integrity). Verify the use; PoC = predictable/forgeable output. Non-security use = informational.",
    "Cloud Storage Reference": "Test the bucket for public read/list. PoC: `curl <bucket-url>` or "
        "`aws s3 ls s3://<bucket> --no-sign-request`; screenshot any listing/sensitive object.",
    "CORS Implementation": "credentials:'include' + a reflected/permissive ACAO is exploitable. PoC: "
        "from an attacker origin fetch the endpoint with credentials and read the response.",
    "Sensitive Comment": "Read for leaked endpoints, creds, bypass flags or security TODOs; test "
        "whatever it reveals and quote it in the report.",
    "Environment Disclosure": "Test whether the staging/dev/internal host is reachable and less "
        "hardened. PoC: connect and show it serves the app (often weaker auth).",
    "Internal IP Reference": "Aids network mapping / SSRF targeting; document the range. Not directly "
        "exploitable alone.",
    "Feature Flag / Hidden Functionality": "Flip the flag (devtools/request param) and see if hidden/"
        "admin features activate without server enforcement.",
    "File Upload Implementation": "Client validation is bypassable — test server-side checks via Burp "
        "(see the Web tab File Upload Testing lab). PoC: upload a disallowed type and retrieve/run it.",
    "WebSocket Usage": "Test handshake auth, Origin checks and per-message authorisation. PoC: connect "
        "from an attacker origin or replay another user's messages.",
    "GraphQL Usage": "Test introspection, IDOR via id args, and unauthorised mutations. PoC: run "
        "`{ __schema { types { name } } }` then request another user's object by id.",
    "JWT Implementation": "Decode alg/claims; test alg=none, signature stripping, weak HMAC secret and "
        "whether access control trusts client-visible claims. PoC: forge a claim and show acceptance.",
    "Third-Party Service": "Check for leaked project keys (Firebase/Sentry DSN) and misconfig. PoC e.g. "
        "`curl https://<project>.firebaseio.com/.json` for an open Firebase DB.",
    "Sensitive Endpoint": "Request directly with/without auth and as a low-priv user (use the Request "
        "Analysis tab). PoC: show it returns data/functions it should not (BOLA/BFLA).",
    "Debug/Dev Artifact": "Debug code can leak data (console.log of tokens/PII) or enable debug modes. "
        "Check console output and debug=true behaviour; quote any leak. Usually low severity.",
    "CORS Reference": "",
}

_UA = "Mozilla/5.0 (CommandBridge JS-Recon)"
MAX_PAGES = 60          # crawl budget
MAX_DEPTH = 2           # how deep to spider from the target
MAX_JS_FILES = 250      # cap on JS files analysed
MAX_JS_BYTES = 3_000_000

# ── Precompiled detection patterns ──────────────────────────────────────────
SECRET_RULES = [
    ("Google API Key", re.compile(r"AIza[0-9A-Za-z\-_]{35}"), "HIGH"),
    ("AWS Access Key ID", re.compile(r"AKIA[0-9A-Z]{16}"), "HIGH"),
    ("Stripe Secret Key", re.compile(r"sk_live_[0-9A-Za-z]{10,}"), "CRITICAL"),
    ("Stripe Publishable Key", re.compile(r"pk_live_[0-9A-Za-z]{10,}"), "MEDIUM"),
    ("GitHub Token", re.compile(r"gh[pousr]_[0-9A-Za-z]{20,}"), "HIGH"),
    ("Slack Token", re.compile(r"xox[baprs]-[0-9A-Za-z\-]{10,}"), "HIGH"),
    ("JWT Token", re.compile(r"eyJ[A-Za-z0-9_-]{6,}\.[A-Za-z0-9_-]{6,}\.[A-Za-z0-9_-]{6,}"), "HIGH"),
    ("Private Key Block", re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----"), "CRITICAL"),
    ("Generic Secret Assignment", re.compile(
        r"(?i)(api[_-]?key|access[_-]?token|auth[_-]?token|client[_-]?secret|"
        r"secret[_-]?key|refresh[_-]?token|private[_-]?key|x-api-key)"
        r"\s*[:=]\s*['\"][^'\"]{6,}['\"]"), "HIGH"),
]

CRED_RE = re.compile(
    r"(?i)\b(password|passwd|pwd|db_pass|db_user|username|user|database|connectionString)\b"
    r"\s*[:=]\s*['\"][^'\"]{3,}['\"]")
CRED_CRITICAL = ("password", "passwd", "pwd", "db_pass")

ENDPOINT_RE = re.compile(r"""['"](/[A-Za-z0-9_\-./]{1,120})['"]""")
FULLURL_RE = re.compile(r"https?://[A-Za-z0-9._~:/?#\[\]@!$&'()*+,;=%-]{4,}")
SENSITIVE_ENDPOINT_KW = ("/admin", "/administrator", "/api", "/internal", "/debug",
                         "/test", "/staging", "/graphql", "/swagger", "/openapi",
                         "/actuator", "/backup", "/config", "/private")
ADMIN_ENDPOINT_KW = ("/admin", "/administrator", "/manage", "/wp-admin", "/actuator")

ENV_RE = re.compile(r"(?i)(localhost|127\.0\.0\.1|0\.0\.0\.0|\bdev\.|\bstaging\.|\buat\.|\btest\.|\binternal\.|[a-z0-9-]+\.local\b)")
SOURCEMAP_RE = re.compile(r"(?://[#@]\s*sourceMappingURL=(\S+))|([A-Za-z0-9_.\-/]+\.js\.map)")
DEBUG_RE = re.compile(r"(?i)\b(console\.(log|debug|warn|info)|debugger|debug\s*=\s*true|isDebug|verbose\s*[:=]|devMode)\b")
AUTHZ_RE = re.compile(r"""(?i)(isAdmin|role\s*===?\s*['"]admin['"]|user\.role|permissions\b|canDelete|canEdit|adminOnly)""")
STORAGE_RE = re.compile(r"(?i)(localStorage\.setItem|sessionStorage\.setItem|document\.cookie\s*=|indexedDB)")
XSS_RE = re.compile(r"(?i)(\.innerHTML\s*=|\.outerHTML\s*=|document\.write\s*\(|insertAdjacentHTML|(?<![A-Za-z0-9_])eval\s*\(|new\s+Function\s*\()")
CORS_RE = re.compile(r"""(?i)(credentials\s*:\s*['"]include['"]|withCredentials|Access-Control-Allow-Origin|mode\s*:\s*['"]cors['"])""")
CLOUD_RE = re.compile(r"(?i)([A-Za-z0-9.\-]*\.s3[.-][A-Za-z0-9.\-]*amazonaws\.com|s3\.amazonaws\.com[A-Za-z0-9./\-]*|storage\.googleapis\.com[A-Za-z0-9./\-]*|[A-Za-z0-9.\-]*\.blob\.core\.windows\.net|[A-Za-z0-9.\-]*\.firebaseio\.com|firebasestorage\.googleapis\.com[A-Za-z0-9./\-]*|[A-Za-z0-9.\-]*\.digitaloceanspaces\.com)")
GRAPHQL_RE = re.compile(r"(?i)(/graphql|__schema|__typename|\bmutation\s+\w|\bquery\s+\w)")
WS_RE = re.compile(r"(?i)(wss?://[A-Za-z0-9._:/?#\-]+|new\s+WebSocket\s*\()")
COMMENT_RE = re.compile(r"(?i)\b(TODO|FIXME|HACK|XXX|TEMP|BYPASS|DISABLE\s*AUTH|REMOVE\s*BEFORE\s*PROD|PASSWORD|SECRET)\b")
JWT_IMPL_RE = re.compile(r"(?i)(jwtDecode|decodeJwt|\bjwt\b|Authorization|Bearer|HS256|RS256)")
FEATUREFLAG_RE = re.compile(r"(?i)(featureFlag|enableAdmin|disabledFeature|experimental|\bbeta\b|hidden\s*[:=]|flags\s*[:=])")
UPLOAD_RE = re.compile(r"(?i)(multipart/form-data|allowedExtensions|maxFileSize|\.upload\b|file\.type|accept\s*=)")
INTERNAL_IP_RE = re.compile(r"\b(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3})\b")
EMAIL_RE = re.compile(r"[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}")
PARAM_RE = re.compile(r"(?i)\b(userId|accountId|admin|role|redirect|returnUrl|next|callback|token|user_id|account_id)\b\s*[:=]")
REDIRECT_RE = re.compile(r"(?i)(window\.location\s*=|document\.location\s*=|redirect\s*=|returnUrl\s*=|next\s*=)")
SSRF_RE = re.compile(r"(?i)(fetch\s*\(\s*[A-Za-z_]\w*\)|axios\.(get|post)\s*\(\s*[A-Za-z_]\w*|targetUrl|callbackUrl|webhook)")
CRYPTO_RE = re.compile(r"(?i)(CryptoJS\.)?\b(MD5|SHA1|DES|RC4)\b")
THIRD_PARTY = {
    "Google Analytics": re.compile(r"(?i)(google-analytics\.com|googletagmanager\.com|gtag\()"),
    "Firebase": re.compile(r"(?i)firebase"),
    "Sentry": re.compile(r"(?i)(sentry\.io|Sentry\.init)"),
    "Datadog": re.compile(r"(?i)(datadoghq|DD_RUM)"),
    "Mixpanel": re.compile(r"(?i)mixpanel"),
    "Segment": re.compile(r"(?i)(segment\.com|analytics\.track)"),
    "Hotjar": re.compile(r"(?i)hotjar"),
    "Intercom": re.compile(r"(?i)intercom"),
    "New Relic": re.compile(r"(?i)(newrelic|NREUM)"),
    "Amplitude": re.compile(r"(?i)amplitude"),
}
SCRIPT_SRC_RE = re.compile(r"""<script[^>]+src\s*=\s*['"]([^'"]+)['"]""", re.IGNORECASE)
JS_REF_RE = re.compile(r"""['"]([^'"]+?\.js(?:\?[^'"]*)?)['"]""", re.IGNORECASE)
HREF_RE = re.compile(r"""<a[^>]+href\s*=\s*['"]([^'"#]+)['"]""", re.IGNORECASE)


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
    def _analyse(self, url, content, agg):
        findings = []

        def add(sev, category, line, match, rec=""):
            findings.append({"severity": sev, "category": category, "file": url,
                             "line": line, "match": match[:200], "rec": rec})

        lines = content.split("\n")
        for i, line in enumerate(lines, 1):
            if len(line) > 5000:
                line = line[:5000]

            for name, rx, sev in SECRET_RULES:
                m = rx.search(line)
                if m:
                    add(sev, "Exposed Secret", i, f"{name}: {m.group(0)}",
                        "Verify if active; rotate and restrict the key.")
                    agg["secrets"] += 1

            m = CRED_RE.search(line)
            if m:
                key = m.group(1).lower()
                sev = "CRITICAL" if key in CRED_CRITICAL else "HIGH"
                add(sev, "Hardcoded Credential", i, m.group(0),
                    "Remove credentials from client-side code.")
                if sev == "CRITICAL":
                    agg["creds"] += 1

            if DEBUG_RE.search(line):
                add("LOW", "Debug/Dev Artifact", i, DEBUG_RE.search(line).group(0))
            if AUTHZ_RE.search(line):
                add("MEDIUM", "Client-Side Authorization Logic", i, AUTHZ_RE.search(line).group(0),
                    "Authorization must be enforced server-side.")
            if STORAGE_RE.search(line):
                add("MEDIUM", "Sensitive Browser Storage", i, STORAGE_RE.search(line).group(0))
            if XSS_RE.search(line):
                add("HIGH", "Potential DOM XSS Sink", i, XSS_RE.search(line).group(0).strip(),
                    "Avoid passing untrusted input to this sink.")
                agg["xss"] += 1
            if CORS_RE.search(line):
                add("INFO", "CORS Implementation", i, CORS_RE.search(line).group(0))
            if REDIRECT_RE.search(line):
                add("MEDIUM", "Potential Redirect Logic", i, REDIRECT_RE.search(line).group(0))
            if SSRF_RE.search(line):
                add("MEDIUM", "Potential SSRF Surface", i, SSRF_RE.search(line).group(0))
            if CRYPTO_RE.search(line) and not re.search(r"(?i)sha1[0-9]", line):
                add("MEDIUM", "Weak Cryptography", i, CRYPTO_RE.search(line).group(0))
            m = COMMENT_RE.search(line)
            if m and ("//" in line or "/*" in line or "*" == line.strip()[:1]):
                add("LOW", "Sensitive Comment", i, line.strip()[:160])
            for cm in CLOUD_RE.finditer(line):
                add("MEDIUM", "Cloud Storage Reference", i, cm.group(0))
                agg["cloud"] += 1
            for em in EMAIL_RE.finditer(line):
                agg["emails"].add(em.group(0))
            for ip in INTERNAL_IP_RE.finditer(line):
                add("LOW", "Internal IP Reference", i, ip.group(0))
                agg["internal_ips"].add(ip.group(0))
            if ENV_RE.search(line):
                add("LOW", "Environment Disclosure", i, ENV_RE.search(line).group(0))
            if FEATUREFLAG_RE.search(line):
                add("LOW", "Feature Flag / Hidden Functionality", i, FEATUREFLAG_RE.search(line).group(0))
                agg["flags"] += 1
            if UPLOAD_RE.search(line):
                add("MEDIUM", "File Upload Implementation", i, UPLOAD_RE.search(line).group(0),
                    "Confirm server-side validation exists.")
            for pm in PARAM_RE.finditer(line):
                agg["params"].add(pm.group(1).lower())

        # whole-file checks
        low = content.lower()
        if WS_RE.search(content):
            for wm in WS_RE.finditer(content):
                tok = wm.group(0)
                if tok.lower().startswith("ws"):
                    agg["ws"].add(tok)
            add("INFO", "WebSocket Usage", 0, (next(iter(agg["ws"]), "new WebSocket")))
        if GRAPHQL_RE.search(content):
            add("INFO", "GraphQL Usage", 0, "GraphQL endpoint/query detected")
            agg["graphql"] += 1
        if "eyj" in low and JWT_IMPL_RE.search(content) or re.search(r"(?i)(jwtDecode|decodeJwt|HS256|RS256)", content):
            add("INFO", "JWT Implementation", 0, "JWT handling logic present")
            agg["jwt"] += 1
        for name, rx in THIRD_PARTY.items():
            if rx.search(content):
                add("INFO", "Third-Party Service", 0, name)
                agg["third_party"].add(name)

        # endpoints + subdomains
        for em in ENDPOINT_RE.finditer(content):
            ep = em.group(1)
            if len(ep) < 2 or ep.startswith("//"):
                continue
            agg["endpoints"].add(ep)
            low_ep = ep.lower()
            if any(k in low_ep for k in SENSITIVE_ENDPOINT_KW):
                add("MEDIUM", "Sensitive Endpoint", 0, ep, "Verify server-side access controls.")
            if any(low_ep.startswith(k) or k in low_ep for k in ADMIN_ENDPOINT_KW):
                agg["admin_endpoints"].add(ep)
        for um in FULLURL_RE.finditer(content):
            host = urlparse(um.group(0)).hostname or ""
            if host and self.base_domain and host.endswith(self.base_domain) and host != self.base_host:
                agg["subdomains"].add(host)

        # source maps (request + status)
        for sm in SOURCEMAP_RE.finditer(content):
            ref = sm.group(1) or sm.group(2)
            if not ref:
                continue
            map_url = urljoin(url, ref)
            st, _ct, _b = self._get(map_url, max_bytes=2000, timeout=8)
            exposed = st == 200
            add("MEDIUM" if exposed else "INFO", "Source Map", 0,
                f"{ref} (HTTP {st})", "Source maps expose original source; remove from production." if exposed else "")
            if exposed:
                agg["sourcemaps"] += 1
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

            agg = {
                "secrets": 0, "creds": 0, "xss": 0, "cloud": 0, "graphql": 0,
                "jwt": 0, "sourcemaps": 0, "flags": 0,
                "endpoints": set(), "subdomains": set(), "admin_endpoints": set(),
                "emails": set(), "params": set(), "internal_ips": set(),
                "ws": set(), "third_party": set(),
            }
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
                        findings.extend(f)
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
        return {"files": n, "endpoints": 0, "subdomains": 0, "secrets": 0, "creds": 0,
                "sourcemaps": 0, "xss": 0, "jwt": 0, "graphql": 0, "ws": 0, "cloud": 0,
                "flags": 0, "admin_endpoints": 0,
                "risk": {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}}

    def _build_summary(self, files, findings, agg):
        risk = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
        for f in findings:
            sev = f["severity"] if f["severity"] in risk else "INFO"
            risk[sev] += 1
        return {
            "files": files,
            "endpoints": len(agg["endpoints"]),
            "subdomains": len(agg["subdomains"]),
            "secrets": agg["secrets"],
            "creds": agg["creds"],
            "sourcemaps": agg["sourcemaps"],
            "xss": agg["xss"],
            "jwt": agg["jwt"],
            "graphql": agg["graphql"],
            "ws": len(agg["ws"]),
            "cloud": agg["cloud"],
            "flags": agg["flags"],
            "admin_endpoints": len(agg["admin_endpoints"]),
            "subdomain_list": sorted(agg["subdomains"]),
            "endpoint_list": sorted(agg["endpoints"]),
            "email_list": sorted(agg["emails"]),
            "risk": risk,
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

            agg = {
                "secrets": 0, "creds": 0, "xss": 0, "cloud": 0, "graphql": 0,
                "jwt": 0, "sourcemaps": 0, "flags": 0,
                "endpoints": set(), "subdomains": set(), "admin_endpoints": set(),
                "emails": set(), "params": set(), "internal_ips": set(),
                "ws": set(), "third_party": set(),
            }
            findings = []
            targets = files[:MAX_JS_FILES]
            self.progress.emit(f"[*] Analysing {len(targets)} file(s)…\n")

            for index, path in enumerate(targets, start=1):
                try:
                    content = path.read_text(errors="replace")[:MAX_JS_BYTES]
                except Exception as exc:
                    self.progress.emit(f"    [skip] {path.name}: {exc}\n")
                    continue
                findings.extend(self._analyse(str(path), content, agg))
                if index % 10 == 0 or index == len(targets):
                    self.progress.emit(f"    analysed {index}/{len(targets)}\n")

            result["findings"] = findings
            result["summary"] = self._build_summary(len(targets), findings, agg)
        except Exception as e:
            result["error"] = str(e)
        self.finished.emit(result)


class JsAnalysisMixin:
    """Web Scraping → JS recon & analysis button handler."""

    def run_downloaded_js_analysis(self):
        """Analyse the JS files that 'Retrieve JS Files' already downloaded."""
        from PyQt6.QtWidgets import QFileDialog

        safe = self.sanitize_target_for_filename(getattr(self, "target", "") or "target")
        default_dir = Path(self.output_dir) / f"{safe}_js_files"

        js_dir = default_dir
        if not js_dir.is_dir():
            chosen = QFileDialog.getExistingDirectory(
                self,
                "Select a folder of downloaded JavaScript files",
                str(self.output_dir),
            )
            if not chosen:
                self.console.append_ansi(
                    f"\n[!] {default_dir} does not exist yet — run 'Retrieve JS Files' "
                    "first, or pick a folder to analyse.\n"
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

        # Write identified_js.txt
        js_urls = result.get("js_urls", [])
        try:
            Path(self.output_dir, "identified_js.txt").write_text(
                "\n".join(js_urls) + ("\n" if js_urls else ""), encoding="utf-8", errors="replace")
            self.console.append_ansi(f"[i] Wrote identified_js.txt ({len(js_urls)} files)\n")
        except Exception as e:
            self.console.append_ansi(f"[i] Could not write identified_js.txt: {e}\n")

        findings = result.get("findings", [])

        # Console output grouped by category, each with how-to-test / PoC guidance
        # so the tester knows how to prove (or disprove) impact for a report.
        if findings:
            self.console.append_ansi("\n=== JavaScript Findings ===\n")
            by_cat = {}
            for f in findings:
                by_cat.setdefault(f["category"], []).append(f)

            def _cat_sev(c):
                return max(SEV_ORDER.get(x["severity"], 0) for x in by_cat[c])

            for cat in sorted(by_cat, key=lambda c: -_cat_sev(c)):
                items = by_cat[cat]
                sev = max(items, key=lambda x: SEV_ORDER.get(x["severity"], 0))["severity"]
                color = SEV_COLORS.get(sev, "#94a3b8")
                self.console.append_html(
                    f'<br><span style="color:{color};font-weight:bold;">[{html.escape(sev)}] '
                    f'{html.escape(cat)} ({len(items)})</span><br>'
                )
                guidance = CATEGORY_GUIDANCE.get(cat)
                if guidance:
                    self.console.append_html(
                        f'&nbsp;&nbsp;<span style="color:#38bdf8;font-weight:bold;">How to test / PoC:</span> '
                        f'<span style="color:#9aa6b2;">{html.escape(guidance)}</span><br>'
                    )
                for f in items[:40]:
                    loc = f"{f['file']}" + (f" : line {f['line']}" if f.get("line") else "")
                    self.console.append_html(
                        f'&nbsp;&nbsp;<span style="color:#cbd5e1;">{html.escape(f["match"])}</span> '
                        f'<span style="color:#64748b;">— {html.escape(loc)}</span><br>'
                    )
                if len(items) > 40:
                    self.console.append_html(
                        f'&nbsp;&nbsp;<span style="color:#64748b;">… +{len(items) - 40} more '
                        f'(see js_analysis_results.txt)</span><br>'
                    )

        # Write js_analysis_results.txt
        self._write_js_report(result, findings)

        # Summary block
        self._print_js_summary(result.get("summary", {}))

        try:
            self.refresh_file_list()
        except Exception:
            pass

    def _write_js_report(self, result, findings):
        s = result.get("summary", {})
        lines = ["JavaScript Static Analysis Results", "=" * 50, ""]
        by_cat = {}
        for f in findings:
            by_cat.setdefault(f["category"], []).append(f)
        for cat in sorted(by_cat, key=lambda c: -SEV_ORDER.get(by_cat[c][0]["severity"], 0)):
            lines.append(f"\n### {cat} ({len(by_cat[cat])}) ###")
            g = CATEGORY_GUIDANCE.get(cat)
            if g:
                lines.append(f"How to test / PoC: {g}")
            for f in by_cat[cat]:
                loc = f"{f['file']}" + (f":{f['line']}" if f.get("line") else "")
                lines.append(f"  [{f['severity']}] {f['match']}")
                lines.append(f"      {loc}")
                if f.get("rec"):
                    lines.append(f"      -> {f['rec']}")
        if s.get("subdomain_list"):
            lines += ["", "Subdomains discovered:", *(f"  {d}" for d in s["subdomain_list"])]
        if s.get("email_list"):
            lines += ["", "Email addresses:", *(f"  {e}" for e in s["email_list"])]
        if s.get("endpoint_list"):
            lines += ["", f"Endpoints ({len(s['endpoint_list'])}):",
                      *(f"  {e}" for e in s["endpoint_list"][:500])]
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
        rows = [
            ("Files Analysed", s.get("files", 0)),
            ("Unique Endpoints Identified", s.get("endpoints", 0)),
            ("Subdomains Identified", s.get("subdomains", 0)),
            ("Potential Secrets Found", s.get("secrets", 0)),
            ("Hardcoded Credentials", s.get("creds", 0)),
            ("Source Maps Exposed", s.get("sourcemaps", 0)),
            ("Potential XSS Sinks", s.get("xss", 0)),
            ("JWT Implementations", s.get("jwt", 0)),
            ("GraphQL Endpoints", s.get("graphql", 0)),
            ("WebSocket Endpoints", s.get("ws", 0)),
            ("Cloud Storage References", s.get("cloud", 0)),
            ("Feature Flags", s.get("flags", 0)),
            ("Hidden Admin Endpoints", s.get("admin_endpoints", 0)),
        ]
        bar = "═" * 50
        self.console.append_html(
            f'<br><span style="color:#22d3ee;font-weight:bold;">{bar}</span><br>'
            f'<span style="color:#22d3ee;font-weight:bold;">  JS ANALYSIS COMPLETE</span><br>'
            f'<span style="color:#22d3ee;font-weight:bold;">{bar}</span><br>'
        )
        for label, val in rows:
            self.console.append_html(
                f'&nbsp;&nbsp;<span style="color:#94a3b8;">{html.escape(label)}:</span> '
                f'<span style="color:#e2e8f0;font-weight:bold;">{val}</span><br>'
            )
        self.console.append_html('&nbsp;&nbsp;<span style="color:#94a3b8;">Risk Summary:</span><br>')
        for sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"):
            self.console.append_html(
                f'&nbsp;&nbsp;&nbsp;&nbsp;<span style="color:{SEV_COLORS[sev]};font-weight:bold;">'
                f'{sev.title()}: {risk.get(sev, 0)}</span><br>'
            )
        self.console.append_html(
            f'&nbsp;&nbsp;<span style="color:#94a3b8;">Detailed results written to:</span> '
            f'<span style="color:#e2e8f0;">js_analysis_results.txt</span><br>'
            f'<span style="color:#22d3ee;font-weight:bold;">{bar}</span><br>'
        )
