"""
Request Analysis engine — static analysis of a pasted raw HTTP request.

Purely passive: it parses a captured request (Burp / devtools / proxy logs),
identifies likely web/API test points (IDOR, mass assignment, broken function
level auth, parameter tampering, open redirect, SSRF, SQLi/NoSQLi, XSS, file
upload, path traversal, GraphQL, XXE, CORS, CSRF, host-header injection, method
tampering, header ACL bypass, rate limiting, user enumeration, excessive data
exposure, API versioning, content-type confusion, cache, request smuggling),
and generates a *suggested modified request* for each — ready to paste into Burp
Repeater. It NEVER sends anything. Findings are suggestions requiring manual
validation against authorised targets only.

Split: pure-Python RequestModel + parse_raw_request + RequestAnalyzer (no Qt, so
unit-testable), plus RequestAnalysisMixin which is the GUI glue.
"""
import re
import json
import base64
from datetime import datetime, timezone


RISK_ORDER = {"Critical": 4, "High": 3, "Medium": 2, "Low": 1, "Info": 0}

# ── Parameter / keyword dictionaries ────────────────────────────────────────
IDOR_PARAMS = {
    "id", "user", "userid", "uid", "account", "accountid", "customer", "customerid",
    "clientid", "tenantid", "organisationid", "orgid", "companyid", "invoiceid",
    "orderid", "paymentid", "documentid", "fileid", "bookingid", "addressid", "profileid",
}
MASS_ASSIGN_FIELDS = [
    "isAdmin", "admin", "role", "roles", "permissions", "accountType", "userType",
    "verified", "emailVerified", "mfaEnabled", "twoFactorEnabled", "authorised",
    "approved", "status", "creditLimit", "discount", "balance", "tenantId",
    "organisationId", "ownerId",
]
PRIV_ENDPOINTS = [
    "/admin", "/administrator", "/manage", "/management", "/roles", "/permissions",
    "/config", "/audit", "/billing", "/payments", "/approve", "/authorise",
    "/disable", "/enable", "/impersonate", "/delete", "/exports",
]
SESSION_URL_PARAMS = {
    "token", "session", "sessionid", "sid", "auth", "access_token", "refresh_token",
    "jwt", "bearer", "api_key", "apikey",
}
SESSION_COOKIE_NAMES = {"session", "sessionid", "sid", "auth", "token", "jwt", "access", "refresh"}
TAMPER_PARAMS = {
    "price", "amount", "total", "quantity", "discount", "role", "status", "isadmin",
    "approved", "verified", "mfa", "accounttype", "plan", "subscription", "currency",
    "accesslevel", "permission",
}
REDIRECT_PARAMS = {
    "redirect", "redirecturl", "return", "returnurl", "next", "continue",
    "callback", "callbackurl", "url", "target", "destination",
}
SSRF_PARAMS = {
    "url", "uri", "path", "link", "callback", "callbackurl", "webhook", "webhookurl",
    "target", "targeturl", "imageurl", "avatarurl", "documenturl", "importurl",
    "feed", "proxy", "endpoint",
}
SQLI_PARAMS = {"id", "search", "q", "query", "filter", "sort", "order", "username", "email", "name", "category", "productid"}
XSS_FIELDS = {"name", "firstname", "lastname", "displayname", "message", "comment", "description", "title", "content", "bio", "address", "search", "q"}
TRAVERSAL_PARAMS = {"file", "filename", "path", "filepath", "document", "download", "template", "image", "attachment", "export"}
CSRF_TOKEN_NAMES = {"csrf", "csrftoken", "xsrf", "xsrftoken", "antiforgery", "requestverificationtoken", "_csrf", "csrf_token"}
AUTH_ENDPOINTS = ("login", "signin", "password", "reset", "otp", "mfa", "2fa", "verify", "code", "token")
ENUM_ENDPOINTS = ("login", "register", "forgot-password", "reset-password", "verify-email", "check-email", "availability")
EXPOSURE_ENDPOINTS = ("/users", "/profile", "/account", "/customers", "/orders", "/invoices", "/search", "/reports")
JWT_RE = re.compile(r"eyJ[A-Za-z0-9_-]{6,}\.[A-Za-z0-9_-]{6,}\.[A-Za-z0-9_-]*")
DEBUG_ENDPOINTS = (
    "/debug", "/actuator", "/metrics", "/trace", "/env", "/_profiler", "/console",
    "/graphiql", "/graphql-playground", "/phpinfo", "/test", "/internal",
    "/swagger", "/swagger-ui", "/api-docs",
)
SENSITIVE_QUERY_PARAM_NAMES = {"apikey", "api_key", "secret", "password", "pwd", "pin", "ssn", "dob"}
EMAIL_RE = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")
CC_RE = re.compile(r"\b4\d{15}\b|\b5[1-5]\d{14}\b|\b3[47]\d{13}\b")
UUID_RE = re.compile(r"/([0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12})(?:/|$)")


def _b64url_decode(seg):
    seg += "=" * (-len(seg) % 4)
    return base64.urlsafe_b64decode(seg.encode()).decode("utf-8", errors="replace")


def decode_jwt(token):
    """Decode JWT header+payload WITHOUT verifying. Returns (header, payload) dicts or (None, None)."""
    try:
        parts = token.split(".")
        if len(parts) < 2:
            return None, None
        header = json.loads(_b64url_decode(parts[0]))
        payload = json.loads(_b64url_decode(parts[1]))
        return header, payload
    except Exception:
        return None, None


class RequestModel:
    """Mutable representation of a raw HTTP request that can serialise back."""

    def __init__(self):
        self.method = "GET"
        self.path = "/"
        self.version = "HTTP/1.1"
        self.headers = []   # list of [name, value] preserving order
        self.body = ""

    # ── header helpers ──────────────────────────────────────────────────────
    def header_get(self, name):
        nl = name.lower()
        for n, v in self.headers:
            if n.lower() == nl:
                return v
        return None

    def header_set(self, name, value):
        nl = name.lower()
        for h in self.headers:
            if h[0].lower() == nl:
                h[1] = value
                return
        self.headers.append([name, value])

    def header_remove(self, name):
        nl = name.lower()
        self.headers = [h for h in self.headers if h[0].lower() != nl]

    # ── derived properties ──────────────────────────────────────────────────
    @property
    def host(self):
        return self.header_get("Host") or ""

    @property
    def content_type(self):
        return (self.header_get("Content-Type") or "").lower()

    @property
    def base_path(self):
        return self.path.split("?", 1)[0]

    @property
    def query_string(self):
        return self.path.split("?", 1)[1] if "?" in self.path else ""

    def query_params(self):
        out = []
        if "?" not in self.path:
            return out
        for pair in self.query_string.split("&"):
            if not pair:
                continue
            k, _, v = pair.partition("=")
            out.append((k, v))
        return out

    def set_query_param(self, name, value):
        params = self.query_params()
        found = False
        for i, (k, _v) in enumerate(params):
            if k == name:
                params[i] = (k, value)
                found = True
        if not found:
            params.append((name, value))
        qs = "&".join(f"{k}={v}" for k, v in params)
        self.path = f"{self.base_path}?{qs}" if qs else self.base_path

    def cookies(self):
        out = {}
        raw = self.header_get("Cookie") or ""
        for pair in raw.split(";"):
            pair = pair.strip()
            if "=" in pair:
                k, _, v = pair.partition("=")
                out[k.strip()] = v.strip()
        return out

    def json_body(self):
        try:
            return json.loads(self.body)
        except Exception:
            return None

    def set_json_body(self, obj):
        self.body = json.dumps(obj, indent=2)
        if self.header_get("Content-Length") is not None:
            self.header_set("Content-Length", str(len(self.body)))

    def clone(self):
        m = RequestModel()
        m.method, m.path, m.version, m.body = self.method, self.path, self.version, self.body
        m.headers = [list(h) for h in self.headers]
        return m

    def serialize(self):
        if self.header_get("Content-Length") is not None and self.body:
            self.header_set("Content-Length", str(len(self.body)))
        lines = [f"{self.method} {self.path} {self.version}"]
        lines += [f"{n}: {v}" for n, v in self.headers]
        text = "\n".join(lines) + "\n"
        if self.body:
            text += "\n" + self.body
        return text


def parse_raw_request(raw):
    """Parse a raw HTTP request string into a RequestModel, or None if invalid."""
    if not raw or not raw.strip():
        return None
    raw = raw.replace("\r\n", "\n").replace("\r", "\n")
    if "\n\n" in raw:
        head, body = raw.split("\n\n", 1)
    else:
        head, body = raw, ""
    lines = head.split("\n")
    request_line = lines[0].strip()
    m = re.match(r"^([A-Z]+)\s+(\S+)\s+(HTTP/[\d.]+)?\s*$", request_line)
    if not m:
        # Tolerate a missing HTTP version
        m = re.match(r"^([A-Z]+)\s+(\S+)\s*$", request_line)
        if not m:
            return None
    model = RequestModel()
    model.method = m.group(1)
    model.path = m.group(2)
    if m.lastindex and m.lastindex >= 3 and m.group(3):
        model.version = m.group(3)
    for line in lines[1:]:
        if ":" in line:
            n, _, v = line.partition(":")
            model.headers.append([n.strip(), v.strip()])
    model.body = body.strip("\n")
    return model


class RequestAnalyzer:
    """Runs every detector over a parsed RequestModel and returns findings."""

    def __init__(self, model):
        self.m = model

    # ── helpers ─────────────────────────────────────────────────────────────
    def _body_fields(self):
        """Return (kind, {field: value}) for json / form bodies; ({}, {}) otherwise."""
        ct = self.m.content_type
        obj = self.m.json_body()
        if obj is not None and isinstance(obj, dict):
            return "json", obj
        if "x-www-form-urlencoded" in ct or (self.m.body and "=" in self.m.body and "{" not in self.m.body and "<" not in self.m.body):
            fields = {}
            for pair in self.m.body.split("&"):
                if "=" in pair:
                    k, _, v = pair.partition("=")
                    fields[k.strip()] = v.strip()
            return "form", fields
        return "", {}

    def _all_param_names(self):
        names = set()
        for k, _v in self.m.query_params():
            names.add(k.lower())
        _kind, fields = self._body_fields()
        for k in fields:
            names.add(k.lower())
        return names

    @staticmethod
    def _finding(title, risk, evidence, suggested_test, modified="", notes="", report=""):
        return {"title": title, "risk": risk, "evidence": evidence,
                "suggested_test": suggested_test, "modified_request": modified,
                "notes": notes, "report_wording": report}

    # ── summary ─────────────────────────────────────────────────────────────
    def summary(self, findings):
        m = self.m
        kind, _f = self._body_fields()
        auth = []
        if m.header_get("Authorization"):
            av = m.header_get("Authorization")
            auth.append("Bearer Token" if av.lower().startswith("bearer") else
                        "Basic Auth" if av.lower().startswith("basic") else "Authorization Header")
        if any(c.lower() in SESSION_COOKIE_NAMES for c in m.cookies()):
            auth.append("Cookie")
        body_type = ("JSON" if kind == "json" else "Form-urlencoded" if kind == "form"
                     else "XML" if "xml" in m.content_type else "Multipart" if "multipart" in m.content_type
                     else "None" if not m.body else "Raw")
        user_id = self._first_path_id()
        return {
            "method": m.method, "path": m.path, "base_path": m.base_path, "host": m.host,
            "content_type": m.content_type or "(none)",
            "authentication": " + ".join(auth) if auth else "None detected",
            "authentication_detected": bool(auth),
            "body_type": body_type,
            "user_identifier": user_id,
            "attack_surface": sorted({f["title"] for f in findings}),
        }

    def _first_path_id(self):
        m = re.search(r"/(\d{1,})(?:/|$)", self.m.base_path)
        return m.group(1) if m else ""

    # ── run all detectors ───────────────────────────────────────────────────
    def analyze(self):
        findings = []
        for fn in (
            self._d_idor, self._d_mass_assignment, self._d_bfla, self._d_session_in_url,
            self._d_insecure_cookie, self._d_authorization, self._d_jwt, self._d_param_tamper,
            self._d_open_redirect, self._d_ssrf, self._d_sqli, self._d_nosqli, self._d_xss,
            self._d_file_upload, self._d_path_traversal, self._d_graphql, self._d_xxe,
            self._d_cors, self._d_csrf, self._d_host_header, self._d_method_tamper,
            self._d_header_acl, self._d_rate_limit, self._d_user_enum, self._d_excessive_data,
            self._d_api_version, self._d_content_type_confusion, self._d_cache, self._d_smuggling,
            self._d_verb_tunneling, self._d_insecure_deserialization, self._d_graphql_batching,
            self._d_debug_endpoint, self._d_sensitive_query_data, self._d_uuid_idor,
        ):
            try:
                res = fn()
                if res:
                    findings.extend(res if isinstance(res, list) else [res])
            except Exception:
                continue
        findings.sort(key=lambda f: -RISK_ORDER.get(f["risk"], 0))
        return findings

    # ── detectors ───────────────────────────────────────────────────────────
    def _d_idor(self):
        out = []
        pid = self._first_path_id()
        if pid:
            mod = self.m.clone()
            mod.path = re.sub(r"/(\d+)(?=/|$)", lambda mm: "/" + str(int(mm.group(1)) + 1),
                              mod.base_path, count=1) + (("?" + mod.query_string) if mod.query_string else "")
            out.append(self._finding(
                "Potential IDOR / Broken Object Level Authorisation", "High",
                f"Numeric object identifier in URL path: {pid}",
                "Change the identifier to another valid/guessed value and confirm whether another user's data is returned. Confirm using a lower-privileged account.",
                mod.serialize(),
                notes="Mutations to try: +1, -1, 0, 1, another user's id/UUID/email placeholder.",
                report="Potential IDOR test point identified; manual validation required."))
        # id-like params in query/body
        names = self._all_param_names()
        hits = sorted(names & IDOR_PARAMS)
        if hits and not pid:
            kind, fields = self._body_fields()
            mod = self.m.clone()
            applied = False
            for k, v in self.m.query_params():
                if k.lower() in IDOR_PARAMS and v.isdigit():
                    mod.set_query_param(k, str(int(v) + 1)); applied = True; break
            if not applied and kind == "json":
                obj = mod.json_body()
                for fk in list(obj):
                    if fk.lower() in IDOR_PARAMS and str(obj[fk]).isdigit():
                        obj[fk] = int(obj[fk]) + 1; mod.set_json_body(obj); applied = True; break
            out.append(self._finding(
                "Potential IDOR / Broken Object Level Authorisation", "High",
                f"User-controlled object identifier parameter(s): {', '.join(hits)}",
                "Replace the identifier with another valid identifier and confirm access control is enforced server-side.",
                mod.serialize() if applied else "",
                report="Potential IDOR test point identified; manual validation required."))
        return out

    def _d_mass_assignment(self):
        if self.m.method not in ("POST", "PUT", "PATCH"):
            return None
        kind, fields = self._body_fields()
        if kind not in ("json", "form") or not fields:
            return None
        path = self.m.base_path.lower()
        relevant = any(k in path for k in ("update", "create", "profile", "account", "user", "settings", "admin"))
        if not (relevant or fields):
            return None
        mod = self.m.clone()
        if kind == "json":
            obj = mod.json_body() or {}
            obj.update({"isAdmin": True, "role": "admin", "authorised": True,
                        "authorisationStatus": "Approved", "mfaEnabled": False})
            mod.set_json_body(obj)
        else:
            extra = "&".join(f"{k}={'true' if k in ('isAdmin','authorised') else 'admin'}"
                             for k in ("isAdmin", "role", "authorised"))
            mod.body = (mod.body + "&" + extra) if mod.body else extra
        return self._finding(
            "Potential Mass Assignment Test Point", "High",
            f"{kind.upper()} body updates object fields: {', '.join(list(fields)[:8])}",
            "Add privileged/server-controlled fields and check whether they are accepted, reflected, stored or acted upon.",
            mod.serialize(),
            notes="Payload profiles — Admin: isAdmin/role/roles/permissions; "
                  "Status: status/approved/authorised; Tenant: tenantId/organisationId; "
                  "Financial: creditLimit/discount/balance.",
            report="Possible mass assignment insertion point; manual validation required.")

    def _d_bfla(self):
        path = self.m.base_path.lower()
        hit = next((p for p in PRIV_ENDPOINTS if p in path), None)
        if not hit:
            return None
        mod = self.m.clone()
        if mod.header_get("Cookie") is not None:
            mod.header_set("Cookie", "INSERT_LOW_PRIVILEGED_SESSION_COOKIE_HERE")
        elif mod.header_get("Authorization") is not None:
            mod.header_set("Authorization", "Bearer INSERT_LOW_PRIVILEGED_USER_TOKEN_HERE")
        return self._finding(
            "Potential Broken Function Level Authorisation", "High",
            f"Privileged endpoint detected: {self.m.base_path} (matched '{hit}')",
            "Replay using a lower-privileged user session and confirm the action is blocked server-side.",
            mod.serialize(),
            report="Suggested broken access control test; confirm server-side enforcement.")

    def _d_session_in_url(self):
        hits = [k for k, _v in self.m.query_params() if k.lower() in SESSION_URL_PARAMS]
        if not hits:
            return None
        return self._finding(
            "Session Token Exposed in URL", "High",
            f"Sensitive token parameter(s) in query string: {', '.join(hits)}",
            "Tokens in URLs can be logged in browser history, proxy/server logs, Referer headers and analytics.",
            notes="Recommendation: move tokens to secure HttpOnly cookies or the Authorization header.")

    def _d_insecure_cookie(self):
        session_cookies = [c for c in self.m.cookies() if c.lower() in SESSION_COOKIE_NAMES]
        if not session_cookies:
            return None
        return self._finding(
            "Session Cookie Detected", "Medium",
            f"Cookie(s) that look session-related: {', '.join(session_cookies)}",
            "Confirm the Set-Cookie response uses Secure, HttpOnly and SameSite attributes; review expiry, scope and predictability.")

    def _d_authorization(self):
        av = self.m.header_get("Authorization")
        out = []
        if av and av.lower().startswith("basic"):
            out.append(self._finding(
                "Basic Authentication Detected", "Medium",
                "Authorization: Basic header present.",
                "Confirm TLS is enforced and credentials are not reused or exposed."))
        if av and av.lower().startswith("bearer"):
            mod = self.m.clone()
            mod.header_set("Authorization", "Bearer INSERT_LOW_PRIVILEGED_USER_TOKEN_HERE")
            out.append(self._finding(
                "Bearer Token Detected", "Info",
                "Authorization: Bearer header present.",
                "Replay with a lower-privileged token; verify server-side signature validation and expiry enforcement.",
                mod.serialize()))
        # X-API-Key style
        for hk in ("X-API-Key", "X-Auth-Token", "Api-Key"):
            if self.m.header_get(hk):
                out.append(self._finding(
                    "API Key Header Detected", "Info",
                    f"{hk} header present.",
                    "Confirm the key is scoped, rotatable and not over-privileged."))
        return out

    def _d_jwt(self):
        # search auth header, cookies, query, body
        candidates = []
        av = self.m.header_get("Authorization") or ""
        candidates.append(("Authorization Header", av))
        for k, v in self.m.cookies().items():
            candidates.append((f"Cookie '{k}'", v))
        for k, v in self.m.query_params():
            candidates.append((f"Query '{k}'", v))
        candidates.append(("Body", self.m.body))
        for loc, text in candidates:
            mm = JWT_RE.search(text or "")
            if not mm:
                continue
            token = mm.group(0)
            header, payload = decode_jwt(token)
            if payload is None:
                continue
            alg = (header or {}).get("alg", "?")
            exp = payload.get("exp")
            exp_h = ""
            if isinstance(exp, (int, float)):
                try:
                    exp_h = datetime.fromtimestamp(exp, tz=timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
                except Exception:
                    exp_h = str(exp)
            risky = []
            if str(alg).lower() == "none":
                risky.append("alg=none")
            if "exp" not in payload:
                risky.append("no exp claim")
            if any(c in payload for c in ("role", "roles", "permissions", "scope")):
                risky.append("role/permission claims present")
            if (header or {}).get("kid"):
                risky.append("kid header present")
            claims = ", ".join(f"{k}={payload[k]}" for k in ("sub", "role", "userId", "email", "iss", "aud") if k in payload)
            return self._finding(
                "JWT Detected", "Info",
                f"Location: {loc}; alg={alg}; exp={exp_h or 'none'}" + (f"; claims: {claims}" if claims else ""),
                "Replay with a lower-privileged token; verify the server validates the signature and expiry and does not trust client-visible claims for access control.",
                notes=("Risk indicators: " + ", ".join(risky)) if risky else "No obvious risky JWT indicators.")
        return None

    def _d_param_tamper(self):
        names = self._all_param_names()
        hits = sorted(names & TAMPER_PARAMS)
        if not hits:
            return None
        kind, fields = self._body_fields()
        mod = self.m.clone()
        if kind == "json":
            obj = mod.json_body() or {}
            for k in list(obj):
                lk = k.lower()
                if lk in ("price", "amount", "total", "balance"):
                    obj[k] = 0.01
                elif lk == "discount":
                    obj[k] = 100
                elif lk == "quantity":
                    obj[k] = 1
            mod.set_json_body(obj)
        else:
            for k, v in self.m.query_params():
                if k.lower() == "price":
                    mod.set_query_param(k, "0.01")
                elif k.lower() == "discount":
                    mod.set_query_param(k, "100")
        return self._finding(
            "Potential Parameter Tampering", "High",
            f"Client-controlled business-logic parameter(s): {', '.join(hits)}",
            "Modify price/discount/quantity/role/status and verify the server recalculates/authorises values server-side.",
            mod.serialize())

    def _d_open_redirect(self):
        hits = [k for k, _v in self.m.query_params() if k.lower() in REDIRECT_PARAMS]
        if not hits:
            return None
        mod = self.m.clone()
        mod.set_query_param(hits[0], "https://example-attacker-domain.test")
        return self._finding(
            "Potential Open Redirect", "Medium",
            f"Redirect parameter(s): {', '.join(hits)}",
            "Replace the value with an external domain and verify redirect behaviour.",
            mod.serialize(),
            notes="Payloads: //example-attacker-domain.test , https://example-attacker-domain.test , "
                  "/\\example-attacker-domain.test , %2f%2fexample-attacker-domain.test")

    def _d_ssrf(self):
        names = self._all_param_names()
        hits = sorted(names & SSRF_PARAMS)
        if not hits:
            return None
        kind, fields = self._body_fields()
        mod = self.m.clone()
        placeholder = "https://collaborator.example.test/ssrf-test"
        if kind == "json":
            obj = mod.json_body() or {}
            for k in list(obj):
                if k.lower() in SSRF_PARAMS:
                    obj[k] = placeholder
            mod.set_json_body(obj)
        else:
            for k, _v in self.m.query_params():
                if k.lower() in SSRF_PARAMS:
                    mod.set_query_param(k, placeholder)
        return self._finding(
            "Potential SSRF Test Point", "High",
            f"URL-fetching / callback parameter(s): {', '.join(hits)}",
            "Replace the URL with a controlled collaborator domain and monitor for interaction (authorised targets only).",
            mod.serialize(),
            notes="Internal-target payloads: http://127.0.0.1/ , http://localhost/ , "
                  "http://169.254.169.254/ , http://[::1]/ , file:///etc/passwd")

    def _d_sqli(self):
        params = [(k, v) for k, v in self.m.query_params() if k.lower() in SQLI_PARAMS]
        if not params:
            return None
        mod = self.m.clone()
        k, v = params[0]
        mod.set_query_param(k, f"{v}%27")
        return self._finding(
            "SQL Injection Test Point", "Medium",
            f"Query parameter(s) commonly used in queries: {', '.join(p[0] for p in params)}",
            "Inject safe test characters and observe error handling or behavioural differences.",
            mod.serialize(),
            notes="Safe payloads: ' \" ` )) %27 %22 ; tautology like OR 1=1 / ORDER BY 1 (authorised testing only).")

    def _d_nosqli(self):
        kind, fields = self._body_fields()
        path = self.m.base_path.lower()
        if kind != "json":
            return None
        lower_fields = {k.lower() for k in fields}
        # Require a login/search/filter endpoint or a password/query field —
        # an email field alone (e.g. a profile update) should not trigger this.
        trigger = (any(x in path for x in ("login", "search", "filter"))
                   or "password" in lower_fields or "query" in lower_fields)
        if not trigger:
            return None
        mod = self.m.clone()
        obj = {}
        for k in (fields or {"username": "", "password": ""}):
            if k.lower() in ("username", "email", "password", "query", "filter", "search"):
                obj[k] = {"$ne": None}
            else:
                obj[k] = fields[k]
        mod.set_json_body(obj)
        return self._finding(
            "NoSQL Injection Test Point", "Medium",
            "JSON authentication/search request — values may accept operators.",
            "Test whether operator objects ($ne/$regex/$gt) are accepted in JSON values.",
            mod.serialize(),
            notes='Also try {"$regex": ".*"} on the username field.')

    def _d_xss(self):
        kind, fields = self._body_fields()
        text_fields = [k for k in fields if k.lower() in XSS_FIELDS]
        q_fields = [k for k, _v in self.m.query_params() if k.lower() in XSS_FIELDS]
        if not text_fields and not q_fields:
            return None
        mod = self.m.clone()
        marker = "xss-test-123\"><svg/onload=alert(1)>"
        if kind == "json" and text_fields:
            obj = mod.json_body() or {}
            obj[text_fields[0]] = marker
            mod.set_json_body(obj)
        elif q_fields:
            mod.set_query_param(q_fields[0], "xss-test-123")
        return self._finding(
            "Potential XSS Test Point", "Medium",
            f"User-controlled text field(s): {', '.join(text_fields + q_fields)}",
            "Insert a harmless marker and observe whether it is reflected or stored unsafely.",
            mod.serialize(),
            notes="Marker: xss-test-123  →  if reflected, escalate to a context-appropriate proof in Burp.")

    def _d_file_upload(self):
        ct = self.m.content_type
        path = self.m.base_path.lower()
        # Boundary-aware so e.g. "/profile" doesn't match "file".
        is_upload = ("multipart/form-data" in ct or "filename=" in self.m.body
                     or any(re.search(r"(^|/)" + kw, path)
                            for kw in ("upload", "file", "document", "image", "avatar", "attachment")))
        if not is_upload:
            return None
        return self._finding(
            "File Upload Functionality Detected", "High",
            f"Endpoint/content-type indicates a file upload: {self.m.base_path}",
            "Verify server-side type validation, magic-byte checks, extension allow-listing, storage location and direct object access.",
            notes="Filename tests: avatar.php , avatar.php.jpg , avatar.svg , ../../test.txt , %2e%2e%2ftest.txt")

    def _d_path_traversal(self):
        hits = [(k, v) for k, v in self.m.query_params() if k.lower() in TRAVERSAL_PARAMS]
        if not hits:
            return None
        mod = self.m.clone()
        k, _v = hits[0]
        mod.set_query_param(k, "..%2f..%2f..%2f..%2fetc%2fpasswd")
        return self._finding(
            "Path Traversal Test Point", "High",
            f"File-path parameter(s): {', '.join(p[0] for p in hits)}",
            "Replace the parameter with traversal payloads and confirm access is restricted.",
            mod.serialize(),
            notes="Payloads: ../../../../etc/passwd , ..%2f..%2f..%2f..%2fwindows%2fwin.ini , ....//....//etc/passwd")

    def _d_graphql(self):
        path = self.m.base_path.lower()
        body = self.m.body or ""
        if "/graphql" not in path and not re.search(r'"(query|mutation|operationName)"', body):
            return None
        mod = self.m.clone()
        new_body = re.sub(r"id:\s*(\d+)", lambda mm: f"id: {int(mm.group(1)) + 1}", body, count=1)
        if new_body != body:
            mod.body = new_body
            if mod.header_get("Content-Length") is not None:
                mod.header_set("Content-Length", str(len(mod.body)))
        intro = self.m.clone()
        intro.set_json_body({"query": "{ __schema { types { name } } }"})
        return self._finding(
            "Potential GraphQL IDOR / Excessive Data Exposure", "High",
            "GraphQL request detected (endpoint or query/mutation body).",
            "Modify object IDs in the query and check whether another user's data is returned; test introspection.",
            mod.serialize(),
            notes="Introspection request:\n" + intro.serialize())

    def _d_xxe(self):
        ct = self.m.content_type
        body = self.m.body or ""
        if "xml" not in ct and not body.lstrip().startswith("<?xml") and "<" not in body[:1]:
            return None
        if "xml" not in ct and not body.lstrip().startswith("<?xml"):
            return None
        mod = self.m.clone()
        mod.body = ('<?xml version="1.0"?>\n<!DOCTYPE root [\n'
                    '<!ENTITY xxe SYSTEM "file:///etc/passwd">\n]>\n'
                    '<root>\n  <data>&xxe;</data>\n</root>')
        if mod.header_get("Content-Length") is not None:
            mod.header_set("Content-Length", str(len(mod.body)))
        return self._finding(
            "XML Input Detected (Potential XXE)", "High",
            "Request body is XML.",
            "Check whether external entity processing is disabled (authorised testing only).",
            mod.serialize())

    def _d_cors(self):
        origin = self.m.header_get("Origin") or self.m.header_get("Referer")
        mod = self.m.clone()
        mod.header_set("Origin", "https://example-attacker-domain.test")
        return self._finding(
            "CORS-Relevant Request", "Medium" if origin else "Info",
            f"Origin/Referer header {'present' if origin else 'can be added'} for cross-origin testing.",
            "Modify the Origin header and review the Access-Control-Allow-Origin / Allow-Credentials response.",
            mod.serialize())

    def _d_csrf(self):
        if self.m.method not in ("POST", "PUT", "PATCH", "DELETE"):
            return None
        cookie_auth = bool(self.m.cookies())
        if not cookie_auth:
            return None
        names = self._all_param_names()
        header_names = {h[0].lower() for h in self.m.headers}
        has_token = bool(names & CSRF_TOKEN_NAMES) or any(t in hn for hn in header_names for t in ("csrf", "xsrf"))
        if has_token:
            return None
        return self._finding(
            "Potential CSRF Test Point", "Medium",
            "State-changing request authenticated by cookies with no obvious CSRF token.",
            "Confirm whether SameSite cookies or server-side CSRF controls are enforced.",
            report="Potential CSRF test point; confirm SameSite/anti-CSRF enforcement.")

    def _d_host_header(self):
        path = self.m.base_path.lower()
        if not any(x in path for x in ("reset", "password", "invite", "verify", "email", "link", "callback")):
            return None
        mod = self.m.clone()
        mod.header_set("Host", "attacker.example.test")
        mod.header_set("X-Forwarded-Host", "attacker.example.test")
        mod.header_set("X-Host", "attacker.example.test")
        return self._finding(
            "Host Header Injection Test Point", "Medium",
            f"Link-generating endpoint detected: {self.m.base_path}",
            "Check whether generated links (e.g. password reset) use the attacker-controlled Host / forwarding headers.",
            mod.serialize())

    def _d_method_tamper(self):
        if not self._first_path_id():
            return None
        alts = [x for x in ("GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS") if x != self.m.method]
        return self._finding(
            "HTTP Method Tampering Suggested", "Info",
            f"Endpoint contains an object identifier ({self.m.base_path}).",
            "Replay under different methods and observe behaviour: " + ", ".join(alts),
            notes="Some frameworks expose different authorisation per method.")

    def _d_header_acl(self):
        path = self.m.base_path
        mod = self.m.clone()
        for h, v in (("X-Forwarded-For", "127.0.0.1"), ("X-Original-URL", path),
                     ("X-Rewrite-URL", path), ("X-Real-IP", "127.0.0.1"), ("X-Client-IP", "127.0.0.1")):
            mod.header_set(h, v)
        return self._finding(
            "Header-Based Access Control Bypass Tests Available", "Info",
            "Common override/proxy headers can be added to test trust boundaries.",
            "Check whether the backend trusts proxy headers (X-Forwarded-For / X-Original-URL etc.).",
            mod.serialize())

    def _d_rate_limit(self):
        path = self.m.base_path.lower()
        if not any(x in path for x in AUTH_ENDPOINTS):
            return None
        return self._finding(
            "Rate Limiting / Brute Force Test Point", "Medium",
            f"Authentication/verification endpoint: {self.m.base_path}",
            "Verify rate limiting, account lockout, OTP/reset-token throttling and username-enumeration differences.")

    def _d_user_enum(self):
        path = self.m.base_path.lower()
        if not any(x in path for x in ENUM_ENDPOINTS):
            return None
        return self._finding(
            "User Enumeration Test Point", "Medium",
            f"Account-related endpoint: {self.m.base_path}",
            "Compare responses (timing, status, message) for a known-valid vs invalid user.",
            notes='Placeholders: known-valid-user@example.com vs definitely-invalid-user-12345@example.com')

    def _d_excessive_data(self):
        path = self.m.base_path.lower()
        if not any(x in path for x in EXPOSURE_ENDPOINTS):
            return None
        return self._finding(
            "Excessive Data Exposure Review Suggested", "Medium",
            f"Endpoint appears to retrieve object/list data: {self.m.base_path}",
            "Review the response for password hashes, reset/MFA tokens, internal IDs, roles/permissions, audit data or other users' PII.")

    def _d_api_version(self):
        m = re.search(r"/(v\d+|beta|legacy|old)/", self.m.base_path.lower())
        if not m:
            return None
        return self._finding(
            "API Version Detected", "Info",
            f"API version segment: /{m.group(1)}/",
            "Check older/other versions for weaker access controls or deprecated functionality (e.g. /v1 vs /v2 vs /legacy).")

    def _d_content_type_confusion(self):
        if self.m.method not in ("POST", "PUT", "PATCH") or not self.m.content_type:
            return None
        return self._finding(
            "Content-Type Confusion Tests Available", "Info",
            f"Current Content-Type: {self.m.content_type}",
            "Check whether the backend parses unexpected content types differently.",
            notes="Try: application/x-www-form-urlencoded, text/plain, application/xml, multipart/form-data.")

    def _d_cache(self):
        cache_headers = [h[0] for h in self.m.headers if h[0].lower() in
                         ("x-forwarded-host", "x-host", "x-original-url", "x-rewrite-url", "cache-control", "vary")]
        if not cache_headers:
            return None
        return self._finding(
            "Cache Behaviour Review Suggested", "Info",
            f"Cache-relevant headers present: {', '.join(cache_headers)}",
            "Check whether user-specific responses are cached or whether untrusted headers affect cached content.")

    def _d_smuggling(self):
        cl = [h for h in self.m.headers if h[0].lower() == "content-length"]
        te = [h for h in self.m.headers if h[0].lower() == "transfer-encoding"]
        if len(cl) > 1 or (cl and te):
            return self._finding(
                "Potential Request Smuggling Indicator", "High",
                "Conflicting/duplicate Content-Length and/or Transfer-Encoding headers detected.",
                "Manually review with authorised request-smuggling tooling; do not rely on this static indicator alone.")
        return None

    def _d_verb_tunneling(self):
        override_headers = [h[0] for h in self.m.headers if h[0].lower() in
                             ("x-http-method-override", "x-method-override", "x-http-method")]
        param_override = [k for k, _v in self.m.query_params() if k.lower() in ("_method", "method")]
        if not override_headers and not param_override:
            return None
        mod = self.m.clone()
        mod.header_set("X-HTTP-Method-Override", "DELETE")
        return self._finding(
            "HTTP Verb Tunneling / Method Override Detected", "Medium",
            f"Override header(s)/param(s) present: {', '.join(override_headers + param_override)}",
            "Try overriding to a more privileged verb (PUT/DELETE/PATCH) via the override "
            "header/parameter and confirm access control still applies to the overridden verb.",
            mod.serialize(),
            notes="Common override headers: X-HTTP-Method-Override, X-Method-Override, "
                  "X-HTTP-Method; common params: _method, method.")

    def _d_insecure_deserialization(self):
        ct = self.m.content_type
        body = self.m.body or ""
        indicators = []
        if "java-serialized-object" in ct or body.startswith("\xac\xed") or body.startswith("rO0"):
            indicators.append("Java serialized object signature")
        if re.match(r"^O:\d+:\"", body) or "x-php-serialized" in ct:
            indicators.append("PHP serialized object signature")
        if body.startswith("\x80\x04") or body.startswith("\x80\x03") or "x-python-pickle" in ct:
            indicators.append("Python pickle signature")
        if "application/x-amf" in ct or "application/marshal" in ct:
            indicators.append("Binary serialisation content-type")
        if not indicators:
            return None
        return self._finding(
            "Potential Insecure Deserialization", "Critical",
            f"Indicators: {', '.join(indicators)}",
            "Confirm what deserializer processes this body and whether it is exploitable "
            "(e.g. ysoserial for Java, PHPGGC for PHP). Do not send crafted gadget chains "
            "without explicit authorisation and a controlled environment.",
            notes="Insecure deserialization of untrusted data can lead to remote code execution.")

    def _d_graphql_batching(self):
        body = (self.m.body or "").strip()
        path = self.m.base_path.lower()
        if "/graphql" not in path and not re.search(r'"(query|mutation|operationName)"', body):
            return None
        if not body.startswith("["):
            return None
        return self._finding(
            "GraphQL Query Batching Detected", "Medium",
            "Request body is a JSON array of GraphQL operations (batched request).",
            "Batched requests can be used to brute-force logins/OTPs in a single HTTP "
            "request (bypassing simple per-request rate limits) or to chain many "
            "authorisation checks at once. Confirm the server enforces per-operation rate "
            "limiting and authorisation, not just per-HTTP-request.",
            report="GraphQL batching detected; confirm per-operation rate limiting/authorisation.")

    def _d_debug_endpoint(self):
        path = self.m.base_path.lower()
        hit = next((p for p in DEBUG_ENDPOINTS if p in path), None)
        if not hit:
            return None
        return self._finding(
            "Debug / Internal Endpoint Detected", "Medium",
            f"Path matches a known debug/introspection pattern: {self.m.base_path} (matched '{hit}')",
            "Confirm this endpoint is not reachable in production, or if it must be, that "
            "it is authenticated and does not leak internals (stack traces, env vars, "
            "config, metrics, other users' data).",
            report="Debug/internal endpoint reachable; confirm it is not exposed in production.")

    def _d_sensitive_query_data(self):
        hits = [k for k, _v in self.m.query_params() if k.lower() in SENSITIVE_QUERY_PARAM_NAMES]
        pii_hits = []
        for k, v in self.m.query_params():
            if EMAIL_RE.search(v or ""):
                pii_hits.append(f"{k} (email-like value)")
            elif CC_RE.search(v or ""):
                pii_hits.append(f"{k} (card-number-like value)")
        if not hits and not pii_hits:
            return None
        return self._finding(
            "Sensitive Data in URL / Query String", "Medium",
            f"Parameter(s): {', '.join(hits + pii_hits)}",
            "Sensitive values in URLs are logged in browser history, proxy/server access "
            "logs and Referer headers. Confirm secrets/PII are sent in the body or headers "
            "instead, over TLS.",
            report="Sensitive-looking data found in the URL; recommend moving to body/headers.")

    def _d_uuid_idor(self):
        # UUID-shaped path identifiers — distinct from the numeric-ID IDOR check above,
        # since UUIDs are unguessable but access control must still be enforced server-side.
        m = UUID_RE.search(self.m.base_path)
        if not m:
            return None
        return self._finding(
            "Potential IDOR (UUID Object Identifier)", "Medium",
            f"UUID-shaped identifier in URL path: {m.group(1)}",
            "UUIDs aren't guessable, but confirm access control is still enforced "
            "server-side rather than relying on the UUID being unguessable — request the "
            "same endpoint with another (known/leaked) user's UUID.",
            report="UUID path identifier present; confirm server-side authorisation, not just unguessability.")


# Risk → colour for the findings list / summary.
RISK_COLORS = {"Critical": "#ef4444", "High": "#f97316", "Medium": "#f59e0b",
               "Low": "#38bdf8", "Info": "#94a3b8"}


class RequestAnalysisMixin:
    """GUI glue for the Request Analysis tab. Passive: never sends requests."""

    def analyse_request(self):
        raw = self.ra_input.toPlainText() if hasattr(self, "ra_input") else ""
        model = parse_raw_request(raw)
        if model is None:
            self.ra_summary.setPlainText(
                "Could not parse a request.\n\nPaste a full raw HTTP request: the request "
                "line (e.g. 'POST /path HTTP/2'), the headers, then an optional blank line "
                "and body. You can copy this straight from Burp (right-click → Copy)."
            )
            self.ra_vectors.clear()
            self.ra_modified.setPlainText("")
            return

        analyzer = RequestAnalyzer(model)
        findings = analyzer.analyze()
        summary = analyzer.summary(findings)
        self._ra_model = model
        self._ra_findings = findings
        self._ra_summary_data = summary

        self.ra_summary.setPlainText(self._ra_format_summary(summary, findings))

        from PyQt6.QtWidgets import QListWidgetItem
        from PyQt6.QtGui import QColor
        self.ra_vectors.clear()
        for f in findings:
            item = QListWidgetItem(f"[{f['risk']}]  {f['title']}")
            item.setForeground(QColor(RISK_COLORS.get(f["risk"], "#e2e8f0")))
            self.ra_vectors.addItem(item)

        if findings:
            self.ra_vectors.setCurrentRow(0)
        else:
            self.ra_modified.setPlainText(model.serialize())
            self.ra_detail.setText("No attack vectors detected for this request.")

    def _ra_format_summary(self, s, findings):
        lines = [
            "=" * 50,
            "REQUEST ANALYSIS COMPLETE",
            "=" * 50,
            f"Method            : {s['method']}",
            f"Host              : {s['host']}",
            f"Path              : {s['path']}",
            f"Content-Type      : {s['content_type']}",
            f"Authentication    : {s['authentication']}",
            f"Body Type         : {s['body_type']}",
        ]
        if s["user_identifier"]:
            lines.append(f"User Identifier   : {s['user_identifier']}")
        lines.append("Potential Attack Surface: " + (", ".join(s["attack_surface"]) or "none"))
        lines += ["", "Detected Attack Vectors:", ""]
        for f in findings:
            lines.append(f"[{f['risk']}] {f['title']}")
            lines.append(f"  Evidence: {f['evidence']}")
            lines.append(f"  Suggested Test: {f['suggested_test']}")
            lines.append("")
        lines.append("Note: these are suggested test points requiring manual validation")
        lines.append("against authorised systems only. No requests have been sent.")
        return "\n".join(lines)

    def _on_ra_vector_selected(self, row):
        findings = getattr(self, "_ra_findings", [])
        if row is None or row < 0 or row >= len(findings):
            return
        f = findings[row]
        detail = (f"[{f['risk']}] {f['title']}\n\n"
                  f"Why flagged: {f['evidence']}\n\n"
                  f"Suggested test: {f['suggested_test']}")
        if f.get("notes"):
            detail += f"\n\nNotes: {f['notes']}"
        if f.get("report_wording"):
            detail += f"\n\nReport wording: {f['report_wording']}"
        self.ra_detail.setText(detail)

        model = getattr(self, "_ra_model", None)
        modified = f.get("modified_request") or (model.serialize() if model else "")
        if not f.get("modified_request"):
            modified = ("# This finding is a manual review point — no automatic request\n"
                        "# mutation is generated. Original request shown below.\n\n") + modified
        self.ra_modified.setPlainText(modified)

    def clear_request(self):
        self.ra_input.setPlainText("")
        self.ra_summary.setPlainText("")
        self.ra_modified.setPlainText("")
        self.ra_detail.setText("")
        self.ra_vectors.clear()
        self._ra_findings = []

    def copy_original_request(self):
        self._ra_copy(self.ra_input.toPlainText(), "Original request")

    def copy_modified_request(self):
        self._ra_copy(self.ra_modified.toPlainText(), "Modified request")

    def _ra_copy(self, text, label):
        if not text.strip():
            self.show_themed_message("Nothing to copy", f"{label} is empty.")
            return
        from PyQt6.QtWidgets import QApplication
        QApplication.clipboard().setText(text)
        try:
            self.flash_status(f"{label} copied")
        except Exception:
            pass

    def save_request_analysis(self):
        findings = getattr(self, "_ra_findings", None)
        summary = getattr(self, "_ra_summary_data", None)
        if not findings and not summary:
            self.show_themed_message("Nothing to Save", "Analyse a request first.")
            return
        from pathlib import Path as _Path
        out = _Path(self.output_dir)
        try:
            (out / "request_analysis_summary.txt").write_text(
                self.ra_summary.toPlainText(), encoding="utf-8", errors="replace")
            (out / "modified_request.txt").write_text(
                self.ra_modified.toPlainText(), encoding="utf-8", errors="replace")
            payload = {
                "method": summary.get("method") if summary else "",
                "host": summary.get("host") if summary else "",
                "path": summary.get("path") if summary else "",
                "content_type": summary.get("content_type") if summary else "",
                "authentication_detected": summary.get("authentication_detected") if summary else False,
                "body_type": (summary.get("body_type") or "").lower() if summary else "",
                "findings": [
                    {"title": f["title"], "risk": f["risk"], "evidence": f["evidence"],
                     "suggested_test": f["suggested_test"], "notes": f.get("notes", ""),
                     "modified_request": f.get("modified_request", "")}
                    for f in (findings or [])
                ],
            }
            (out / "request_analysis_findings.json").write_text(
                json.dumps(payload, indent=2), encoding="utf-8", errors="replace")
        except Exception as e:
            self.show_themed_message("Save Error", f"Could not write analysis files: {e}")
            return
        self.show_themed_message(
            "Saved",
            "Wrote request_analysis_summary.txt, request_analysis_findings.json and "
            "modified_request.txt to the output directory.")
        try:
            self.refresh_file_list()
        except Exception:
            pass
