"""
Named issues — the difference between a scanner and a report.

Burp's scanner does not hand you the line its check printed. It hands you an
*issue definition*: a settled name, a severity, a paragraph on what the problem
actually is, a paragraph on how to fix it, and a CWE. The raw output of the
check becomes the evidence underneath it.

That is what this module is. ``ISSUES`` is the library; ``for_testssl`` maps
one of testssl's JSON records onto an entry in it. The effect on the Coffee
Break screen is the one Luke asked for: a host offering CBC ciphers produces a
finding called **Lucky 13**, not a truncated copy of testssl's own sentence,
and the list of CBC ciphers it printed becomes the proof underneath.

Anything testssl reports that has no entry here still comes through — it just
comes through as a generic TLS finding, with its own text intact rather than
chopped at ninety characters.
"""

from __future__ import annotations

import re

# ─────────────────────────────────────────────────────────────────────────────
#  The library
# ─────────────────────────────────────────────────────────────────────────────
#
# Each entry: severity, title, detail, remediation, cwe, references.
# Severity is the one the issue carries in general; a scanner that is more
# certain than usual can raise it, but the default is here so that two runs of
# the same finding never disagree with each other.

def _issue(severity, title, detail, remediation, cwe="", references=()):
    return {"severity": severity, "title": title, "detail": detail,
            "remediation": remediation, "cwe": cwe,
            "references": list(references)}


ISSUES = {
    # ── TLS: the named attacks ───────────────────────────────────────────
    "lucky13": _issue(
        "MEDIUM", "Lucky 13 (CBC ciphers supported)",
        "The server negotiates CBC-mode cipher suites. The way TLS composes "
        "MAC-then-encrypt with CBC padding leaks, through the time taken to "
        "reject a record, whether the padding was well formed. Given enough "
        "captured records an attacker on the path can recover plaintext a byte "
        "at a time — session cookies being the usual target. The listed suites "
        "are the ones this host actually agreed to.",
        "Prefer AEAD suites (AES-GCM, ChaCha20-Poly1305) and remove the CBC "
        "suites from the server's cipher list. On TLS 1.3 this is automatic; "
        "on TLS 1.2 it means an explicit cipher string.",
        "CWE-203", ("CVE-2013-0169", "https://www.isg.rhul.ac.uk/tls/")),
    "beast": _issue(
        "LOW", "BEAST (CBC ciphers over TLS 1.0)",
        "TLS 1.0 uses a predictable CBC initialisation vector, which lets an "
        "attacker who can inject chosen plaintext into the same connection "
        "recover earlier blocks. Every modern browser has client-side "
        "mitigations, which is why this is low rather than high, but the "
        "protocol version that makes it possible should not be on.",
        "Disable TLS 1.0 and 1.1 entirely.",
        "CWE-326", ("CVE-2011-3389",)),
    "poodle": _issue(
        "HIGH", "POODLE (SSLv3 CBC padding oracle)",
        "SSLv3's CBC padding is not covered by the MAC, so a man in the middle "
        "who can force a downgrade to SSLv3 can decrypt a byte at a time.",
        "Disable SSLv3. There is no configuration that makes it safe.",
        "CWE-310", ("CVE-2014-3566",)),
    "sweet32": _issue(
        "MEDIUM", "Sweet32 (64-bit block ciphers)",
        "3DES and Blowfish use a 64-bit block, so a birthday collision becomes "
        "likely after roughly 32GB on one connection — enough to recover "
        "repeated plaintext such as a session cookie from a long-lived "
        "connection.",
        "Remove 3DES and any other 64-bit block cipher from the cipher list.",
        "CWE-327", ("CVE-2016-2183",)),
    "robot": _issue(
        "HIGH", "ROBOT (RSA PKCS#1 v1.5 padding oracle)",
        "The server's different responses to malformed RSA padding form an "
        "oracle. With enough queries an attacker can decrypt a recorded session "
        "or forge a signature with the server's private key, without ever "
        "holding the key.",
        "Disable RSA key-exchange cipher suites; use ECDHE throughout. Patch "
        "the TLS stack.",
        "CWE-203", ("CVE-2017-13099", "https://robotattack.org/")),
    "heartbleed": _issue(
        "CRITICAL", "Heartbleed (memory disclosure in the TLS heartbeat)",
        "The server returns up to 64KB of its own process memory for each "
        "malformed heartbeat request. That memory routinely contains session "
        "tokens, credentials and the server's private key. There is no trace "
        "of it in any log.",
        "Update OpenSSL, then reissue and revoke the certificate and invalidate "
        "every session — assume the key has been taken.",
        "CWE-119", ("CVE-2014-0160",)),
    "ccs": _issue(
        "HIGH", "CCS injection",
        "The server accepts a ChangeCipherSpec message early in the handshake, "
        "which lets a man in the middle force both sides onto keying material "
        "they know, and so read and modify the session.",
        "Update OpenSSL to a patched release.",
        "CWE-310", ("CVE-2014-0224",)),
    "ticketbleed": _issue(
        "HIGH", "Ticketbleed (session-ticket memory disclosure)",
        "The F5 TLS stack returns uninitialised memory alongside the session "
        "ID, leaking up to 31 bytes per handshake from another connection.",
        "Apply the F5 fix, or disable session tickets.",
        "CWE-200", ("CVE-2016-9244",)),
    "drown": _issue(
        "CRITICAL", "DROWN (SSLv2 cross-protocol attack)",
        "A server that still speaks SSLv2 anywhere on the same key lets an "
        "attacker decrypt recorded TLS sessions, even sessions made by clients "
        "that never used SSLv2.",
        "Disable SSLv2 on every service sharing the key, and reissue the "
        "certificate.",
        "CWE-310", ("CVE-2016-0800",)),
    "freak": _issue(
        "HIGH", "FREAK (export-grade RSA)",
        "The server offers export cipher suites, so a man in the middle can "
        "force a 512-bit RSA key exchange and factor it in hours.",
        "Remove all EXPORT cipher suites.",
        "CWE-310", ("CVE-2015-0204",)),
    "logjam": _issue(
        "MEDIUM", "Logjam (weak or common Diffie-Hellman parameters)",
        "The server's DH group is either export grade or one of the well-known "
        "primes that have been precomputed. Either way the key exchange can be "
        "broken and the session read.",
        "Use a unique 2048-bit-or-larger DH group, or prefer ECDHE.",
        "CWE-310", ("CVE-2015-4000", "https://weakdh.org/")),
    "crime": _issue(
        "MEDIUM", "CRIME (TLS-level compression enabled)",
        "Compression before encryption means the ciphertext length reveals how "
        "much the injected data matched the secret, which recovers session "
        "cookies byte by byte.",
        "Disable TLS compression.",
        "CWE-310", ("CVE-2012-4929",)),
    "breach": _issue(
        "LOW", "BREACH (HTTP compression with reflected input)",
        "HTTP-level compression of a response that contains both a secret (a "
        "CSRF token) and attacker-controlled input leaks the secret through the "
        "response length.",
        "Mask per-response secrets, separate secrets from reflected input, or "
        "disable compression on responses containing tokens.",
        "CWE-310", ("CVE-2013-3587",)),
    "rc4": _issue(
        "MEDIUM", "RC4 cipher suites supported",
        "RC4's keystream is measurably biased. A cookie sent across enough "
        "sessions can be recovered from those biases alone.",
        "Remove every RC4 suite from the cipher list.",
        "CWE-327", ("RFC 7465",)),
    "renegotiation": _issue(
        "MEDIUM", "Insecure or client-initiated TLS renegotiation",
        "Renegotiation without RFC 5746 binding lets an attacker prepend chosen "
        "plaintext to the victim's request; client-initiated renegotiation is "
        "in any case a cheap way to exhaust the server's CPU.",
        "Require secure renegotiation and refuse client-initiated "
        "renegotiation.",
        "CWE-310", ("CVE-2009-3555",)),
    "fallback": _issue(
        "LOW", "No downgrade protection (TLS_FALLBACK_SCSV missing)",
        "Without the fallback signalling suite, an attacker who interrupts the "
        "handshake can make each side think the other only speaks an older "
        "protocol version.",
        "Enable TLS_FALLBACK_SCSV in the TLS stack.",
        "CWE-757", ("RFC 7507",)),

    # ── TLS: protocol versions and certificates ──────────────────────────
    "obsolete_protocol": _issue(
        "MEDIUM", "Obsolete TLS protocol version enabled",
        "The host still negotiates a protocol version that is deprecated and "
        "carries known attacks. Browsers have already removed support, so this "
        "is usually serving nothing but an attacker's downgrade.",
        "Offer TLS 1.2 and 1.3 only.",
        "CWE-326", ("RFC 8996",)),
    "cert_expired": _issue(
        "HIGH", "Certificate expired or not yet valid",
        "Every client sees an interstitial warning, and the ones that do not — "
        "mobile apps, API clients — typically fail closed or, worse, are "
        "configured to ignore certificate errors entirely.",
        "Renew the certificate and automate the renewal.",
        "CWE-298"),
    "cert_untrusted": _issue(
        "MEDIUM", "Certificate chain is not trusted",
        "The chain is self-signed, incomplete, or signed by an authority the "
        "client does not trust. Users are trained by it to click through the "
        "warning that would otherwise stop a real attack.",
        "Serve the full chain from a publicly trusted authority.",
        "CWE-295"),
    "cert_hostname": _issue(
        "MEDIUM", "Certificate does not match the hostname",
        "The common name and subject alternative names do not cover the name "
        "the client asked for, so the certificate cannot authenticate this "
        "host.",
        "Reissue with the correct names, or serve the right certificate for "
        "this virtual host.",
        "CWE-297"),
    "cert_weak_signature": _issue(
        "MEDIUM", "Weak certificate signature algorithm",
        "The certificate is signed with an algorithm (MD5, SHA-1) for which "
        "collisions are practical, so a forged certificate is possible.",
        "Reissue with SHA-256 or better.",
        "CWE-327"),
    "cert_weak_key": _issue(
        "MEDIUM", "Weak certificate key size",
        "The key is below the size now considered sound, which shortens the "
        "work needed to recover it.",
        "Reissue with a 2048-bit RSA key or a 256-bit elliptic curve key.",
        "CWE-326"),
    "weak_cipher": _issue(
        "MEDIUM", "Weak cipher suites offered",
        "The server accepts suites with no encryption, export-grade key sizes, "
        "or broken primitives. Any of them can be forced by an attacker who "
        "controls the handshake.",
        "Set an explicit modern cipher list and remove NULL, anonymous, "
        "export and 3DES suites.",
        "CWE-327"),
    "tls_generic": _issue(
        "LOW", "TLS configuration weakness",
        "Reported by testssl against the TLS configuration.",
        "Review against the server's TLS hardening guide.",
        "CWE-326"),

    # ── Transport ────────────────────────────────────────────────────────
    "cleartext_http": _issue(
        "HIGH", "Unencrypted communications",
        "The application is served over HTTP. Everything — credentials, "
        "session cookies, the content itself — is readable and modifiable by "
        "anyone on the path, and there is no way for the client to know it is "
        "talking to the right server.",
        "Redirect all HTTP to HTTPS and send HSTS.",
        "CWE-319"),
    "mixed_content": _issue(
        "LOW", "Mixed content",
        "An HTTPS page pulls in scripts, styles or frames over HTTP. An "
        "attacker who can modify that request controls the page.",
        "Serve every subresource over HTTPS; add "
        "upgrade-insecure-requests to the CSP.",
        "CWE-311"),
    "cacheable_https": _issue(
        "LOW", "Cacheable HTTPS response",
        "A response containing sensitive content has no cache directives, so "
        "proxies and the browser's disk cache may keep a copy where another "
        "user of the machine can read it.",
        "Send Cache-Control: no-store on responses carrying private data.",
        "CWE-525"),

    # ── Response headers ─────────────────────────────────────────────────
    "csp_missing": _issue(
        "MEDIUM", "Content-Security-Policy is missing",
        "Without a CSP an injected script runs with the full privileges of "
        "the page. It is the single most effective mitigation against XSS, "
        "and the only one that limits the damage when everything else fails.",
        "Set a policy naming the sources you actually use; start in "
        "report-only mode to find them.",
        "CWE-693"),
    "csp_unsafe_script": _issue(
        "MEDIUM", "CSP allows untrusted script execution",
        "The policy permits 'unsafe-inline', 'unsafe-eval' or a wildcard "
        "script source, which means an injected script still runs. The header "
        "is present but is not doing the job it exists for.",
        "Remove unsafe-inline and unsafe-eval; use a per-response nonce or "
        "hash, and name explicit script origins.",
        "CWE-693"),
    "csp_clickjacking": _issue(
        "LOW", "CSP allows clickjacking",
        "The policy has no frame-ancestors directive, so the page can be "
        "framed by any origin.",
        "Add frame-ancestors 'self' (or an explicit allow-list).",
        "CWE-1021"),
    "csp_form_hijack": _issue(
        "LOW", "CSP allows form hijacking",
        "No form-action directive, so injected markup can point a form at an "
        "attacker's origin and collect whatever the user types.",
        "Add form-action 'self'.",
        "CWE-693"),
    "csp_report_only": _issue(
        "LOW", "CSP is not enforced",
        "The policy is sent report-only. It records violations and prevents "
        "none of them.",
        "Move the policy to Content-Security-Policy once the reports are "
        "clean.",
        "CWE-693"),
    "hsts_missing": _issue(
        "MEDIUM", "Strict-Transport-Security is missing",
        "A browser that has never seen the HTTPS site will try HTTP first, "
        "which is where an attacker on the path strips the redirect.",
        "Send 'max-age=31536000; includeSubDomains' over HTTPS, and consider "
        "preloading.",
        "CWE-319"),
    "xfo_missing": _issue(
        "LOW", "No framing protection",
        "The page can be embedded in a frame on another origin, which is what "
        "clickjacking needs.",
        "Send X-Frame-Options: DENY or a CSP frame-ancestors directive.",
        "CWE-1021"),
    "nosniff_missing": _issue(
        "LOW", "X-Content-Type-Options is missing",
        "Browsers may sniff a response's type, so an upload served as text "
        "can be executed as script.",
        "Send 'X-Content-Type-Options: nosniff'.",
        "CWE-430"),
    "referrer_policy": _issue(
        "INFO", "Referrer-Policy is missing",
        "Full URLs — including anything sensitive in the path or query — are "
        "sent to third parties in the Referer header.",
        "Send 'Referrer-Policy: strict-origin-when-cross-origin'.",
        "CWE-200"),
    "permissions_policy": _issue(
        "INFO", "Permissions-Policy is missing",
        "Embedded content inherits access to camera, microphone and location.",
        "Send a Permissions-Policy naming only the features the page uses.",
        "CWE-693"),
    "content_type_missing": _issue(
        "INFO", "Content type is not specified or is wrong",
        "The browser has to guess how to treat the response, and its guess is "
        "attacker-influenceable.",
        "Send an accurate Content-Type with a charset.",
        "CWE-16"),

    # ── Cookies ──────────────────────────────────────────────────────────
    "cookie_no_secure": _issue(
        "LOW", "Cookie set without the Secure flag",
        "The cookie will be sent over plain HTTP, so a single downgraded "
        "request hands it to anyone on the path. On a session cookie this is "
        "account takeover.",
        "Set Secure on every cookie.",
        "CWE-614"),
    "cookie_no_httponly": _issue(
        "LOW", "Cookie set without the HttpOnly flag",
        "Injected script can read the cookie, which turns any XSS into "
        "session theft.",
        "Set HttpOnly on cookies the page's own JavaScript does not need.",
        "CWE-1004"),
    "cookie_no_samesite": _issue(
        "LOW", "Cookie set without SameSite",
        "The cookie rides along on cross-site requests, which is the "
        "precondition for CSRF.",
        "Set SameSite=Lax, or Strict for anything session-bearing.",
        "CWE-1275"),
    "cookie_parent_domain": _issue(
        "LOW", "Cookie scoped to a parent domain",
        "Every sibling host under the parent domain receives the cookie, "
        "including ones this application does not control.",
        "Scope the cookie to the exact host that needs it.",
        "CWE-565"),
    "session_token_in_url": _issue(
        "MEDIUM", "Session token in the URL",
        "The token is written to browser history, proxy and server logs, and "
        "is sent to third parties in the Referer header.",
        "Carry session state in a cookie, never in the query string.",
        "CWE-598"),
    "password_in_cookie": _issue(
        "HIGH", "Password value set in a cookie",
        "The password itself, rather than a session token, is stored on the "
        "client, where script, logs and anyone with the device can read it.",
        "Store an opaque session identifier; never the credential.",
        "CWE-522"),

    # ── Cross-origin ─────────────────────────────────────────────────────
    "cors_arbitrary_origin": _issue(
        "HIGH", "CORS: arbitrary origin trusted",
        "The server reflects whatever Origin it is sent and allows "
        "credentials, so any site the victim visits can read authenticated "
        "responses from this one.",
        "Allow-list specific origins; never reflect the Origin header when "
        "Access-Control-Allow-Credentials is true.",
        "CWE-942"),
    "cors_null_origin": _issue(
        "HIGH", "CORS: null origin trusted",
        "A sandboxed iframe or a data: URL sends Origin: null, so an attacker "
        "can reach authenticated responses from a context they fully control.",
        "Remove null from the allowed origins.",
        "CWE-942"),
    "cors_subdomains": _issue(
        "MEDIUM", "CORS: all subdomains trusted",
        "Any subdomain can read authenticated responses, so one forgotten "
        "staging host or one subdomain takeover becomes access to this "
        "application's data.",
        "Name the origins explicitly.",
        "CWE-942"),
    "cors_insecure_origin": _issue(
        "MEDIUM", "CORS: unencrypted origin trusted",
        "An http:// origin is allowed, so a man in the middle on that origin "
        "can read this application's responses.",
        "Allow HTTPS origins only.",
        "CWE-942"),
    "crossdomain_policy": _issue(
        "MEDIUM", "Permissive cross-domain policy file",
        "crossdomain.xml or clientaccesspolicy.xml grants other domains "
        "read access to this one on the user's behalf.",
        "Remove the file, or restrict it to the domains that need it.",
        "CWE-942"),
    "cross_domain_script": _issue(
        "LOW", "Cross-domain script include",
        "The page executes script from a third-party origin with full "
        "privileges. If that origin is ever compromised, so is this page.",
        "Self-host the script, or pin it with subresource integrity.",
        "CWE-829"),
    "referer_leakage": _issue(
        "LOW", "Cross-domain Referer leakage",
        "Sensitive values in the URL are sent to third-party hosts in the "
        "Referer header.",
        "Keep secrets out of URLs and set a strict Referrer-Policy.",
        "CWE-200"),

    # ── Injection ────────────────────────────────────────────────────────
    "sqli": _issue(
        "CRITICAL", "SQL injection",
        "User input reaches a SQL query as code. Read or modify any data the "
        "database account can touch, and on many deployments run commands on "
        "the database host.",
        "Use parameterised queries throughout. Escaping is not a fix.",
        "CWE-89"),
    "command_injection": _issue(
        "CRITICAL", "OS command injection",
        "Input reaches a shell. This is full control of the application "
        "server under whatever account it runs as.",
        "Do not call a shell with user input. Use an API, or exec with an "
        "argument array and a strict allow-list.",
        "CWE-78"),
    "code_injection": _issue(
        "CRITICAL", "Server-side code injection",
        "Input is evaluated as application code (eval, deserialisation, or a "
        "template engine), which is as complete a compromise as command "
        "injection.",
        "Remove the dynamic evaluation; if unavoidable, take no part of the "
        "expression from user input.",
        "CWE-94"),
    "ssti": _issue(
        "CRITICAL", "Server-side template injection",
        "Input is used to build the template rather than to fill it, so the "
        "template engine evaluates attacker expressions — usually a route to "
        "code execution.",
        "Render a fixed template and pass user data as context only.",
        "CWE-1336"),
    "deserialization": _issue(
        "CRITICAL", "Insecure deserialisation",
        "A serialised object is accepted from the client. Gadget chains in the "
        "application's own dependencies turn that into code execution.",
        "Do not deserialise untrusted input; use a data-only format with a "
        "strict schema.",
        "CWE-502"),
    "ssrf": _issue(
        "HIGH", "Server-side request forgery",
        "The server can be made to fetch a URL of the attacker's choosing, "
        "reaching internal services, cloud metadata endpoints and anything "
        "else the network trusts it to reach.",
        "Allow-list destinations, resolve and check the address, and block "
        "link-local and private ranges.",
        "CWE-918"),
    "xxe": _issue(
        "HIGH", "XML external entity injection",
        "The XML parser resolves external entities, which reads local files "
        "and makes requests from the server.",
        "Disable external entities and DTD processing in the parser.",
        "CWE-611"),
    "ldap_injection": _issue(
        "HIGH", "LDAP injection",
        "Input is placed into an LDAP filter as syntax, which can bypass "
        "authentication or enumerate the directory.",
        "Escape according to RFC 4515, or use a parameterised filter API.",
        "CWE-90"),
    "xpath_injection": _issue(
        "HIGH", "XPath injection",
        "Input alters an XPath query, exposing the whole document rather than "
        "the intended node.",
        "Use parameterised XPath; never concatenate.",
        "CWE-643"),
    "ssi_injection": _issue(
        "HIGH", "Server-side includes injection",
        "SSI directives in user input are executed by the web server, which "
        "reads files and on many configurations runs commands.",
        "Disable SSI where it is not needed and never render user input into "
        "a page the SSI parser processes.",
        "CWE-97"),
    "crlf_injection": _issue(
        "MEDIUM", "HTTP response header injection",
        "A newline in user input splits the response, which allows header "
        "injection, cache poisoning and reflected XSS in the injected body.",
        "Strip CR and LF from anything placed in a header.",
        "CWE-113"),
    "request_smuggling": _issue(
        "HIGH", "HTTP request smuggling",
        "Front-end and back-end disagree about where one request ends, so an "
        "attacker can prepend content to another user's request — capturing "
        "their session or serving them a poisoned response.",
        "Make the whole chain use HTTP/2 end to end, or reject requests with "
        "both Content-Length and Transfer-Encoding.",
        "CWE-444"),
    "cache_poisoning": _issue(
        "HIGH", "Web cache poisoning",
        "An unkeyed input influences a cached response, so one attacker "
        "request serves attacker content to everyone who follows.",
        "Include every input that affects the response in the cache key, or "
        "do not cache those responses.",
        "CWE-444"),
    "host_header_injection": _issue(
        "MEDIUM", "Host header injection",
        "The application builds absolute URLs from the Host header, which "
        "poisons password-reset links and caches.",
        "Use a configured canonical hostname, and reject unexpected Host "
        "values at the edge.",
        "CWE-644"),
    "xss_reflected": _issue(
        "HIGH", "Cross-site scripting (reflected)",
        "Input is echoed into the response without context-correct encoding, "
        "so a crafted link runs script as the victim, in their session.",
        "Encode on output for the context, and add a CSP without "
        "unsafe-inline.",
        "CWE-79"),
    "xss_stored": _issue(
        "HIGH", "Cross-site scripting (stored)",
        "Attacker input is saved and served to other users, so the payload "
        "runs for everyone who views the page — no link required.",
        "Encode on output; validate on input; add a CSP.",
        "CWE-79"),
    "xss_dom": _issue(
        "HIGH", "Cross-site scripting (DOM-based)",
        "Client-side script writes attacker-controlled data into a sink such "
        "as innerHTML or eval, so the payload never has to reach the server.",
        "Use safe DOM APIs (textContent, setAttribute), and Trusted Types "
        "where available.",
        "CWE-79"),
    "prototype_pollution": _issue(
        "HIGH", "Client-side prototype pollution",
        "A property name from the URL or a message reaches Object.prototype, "
        "changing the behaviour of unrelated code — usually into a script "
        "gadget and so into XSS.",
        "Reject __proto__, constructor and prototype as keys; use Map or "
        "Object.create(null).",
        "CWE-1321"),
    "csrf": _issue(
        "MEDIUM", "Cross-site request forgery",
        "A state-changing request can be triggered from another site using "
        "the victim's own session, because nothing in the request proves it "
        "came from this application.",
        "Require a per-session anti-CSRF token on every state change, and set "
        "SameSite on the session cookie.",
        "CWE-352"),
    "traversal": _issue(
        "CRITICAL", "Path traversal",
        "A parameter is used to build a file path and can be walked out of "
        "the intended directory, reading arbitrary files from the server.",
        "Do not build paths from user input. Map an identifier to a known "
        "file, or resolve and confirm the path stays inside the directory.",
        "CWE-22"),
    "file_inclusion": _issue(
        "CRITICAL", "File inclusion",
        "A parameter selects a file that the application then executes. Local "
        "inclusion reaches code execution through log or session files; "
        "remote inclusion is direct code execution.",
        "Use a fixed allow-list of includable files; disable "
        "allow_url_include.",
        "CWE-98"),
    "file_upload": _issue(
        "MEDIUM", "File upload functionality",
        "An upload that does not constrain type, name and storage location is "
        "one of the shortest routes to code execution on the server.",
        "Validate type by content, store outside the web root under a "
        "generated name, and serve with a fixed Content-Type.",
        "CWE-434"),
    "open_redirect": _issue(
        "MEDIUM", "Open redirection",
        "The application sends the browser to a location taken from the "
        "request without checking it. Useful for phishing, and for stealing "
        "OAuth codes when the parameter feeds a redirect_uri.",
        "Allow-list the destinations, or map an opaque key to a destination "
        "server-side.",
        "CWE-601"),
    "graphql_introspection": _issue(
        "LOW", "GraphQL introspection enabled",
        "The full schema — every type, field and mutation, including the ones "
        "not used by the front end — is readable by anyone.",
        "Disable introspection in production.",
        "CWE-200"),
    "graphql_suggestions": _issue(
        "LOW", "GraphQL suggestions enabled",
        "Error messages suggest near-miss field names, which reconstructs the "
        "schema even with introspection off.",
        "Turn off field suggestions in production.",
        "CWE-209"),

    # ── Tokens and secrets ───────────────────────────────────────────────
    "jwt_unverified": _issue(
        "CRITICAL", "JWT signature not verified",
        "The application accepts a token without checking its signature, so "
        "any claim — including the user id and the role — can be set by the "
        "client.",
        "Verify the signature against a pinned key before reading any claim.",
        "CWE-347"),
    "jwt_none": _issue(
        "HIGH", "JWT 'none' algorithm accepted",
        "A token with alg: none is treated as valid, which is an unsigned "
        "token the client writes itself.",
        "Pin the expected algorithm; reject none outright.",
        "CWE-347"),
    "jwt_weak_secret": _issue(
        "HIGH", "JWT signed with a weak HMAC secret",
        "The signing secret can be recovered offline from a single captured "
        "token, after which any token can be forged.",
        "Use a long random secret, or move to an asymmetric algorithm.",
        "CWE-326"),
    "jwt_key_injection": _issue(
        "HIGH", "JWT key injection via header",
        "The token's own jwk, jku or x5u header is trusted to supply the "
        "verification key, so the attacker signs with a key they chose.",
        "Ignore key material in the token header; verify against a "
        "configured key.",
        "CWE-347"),
    "private_key_disclosed": _issue(
        "CRITICAL", "Private key disclosed",
        "A private key is readable. Whatever it authenticates — TLS, signing, "
        "SSH — must now be treated as belonging to whoever found it.",
        "Revoke and rotate the key, then remove it from the served tree and "
        "from version control history.",
        "CWE-522"),
    "credentials_disclosed": _issue(
        "HIGH", "Credentials or API key disclosed",
        "A usable secret is served to anyone who asks for the file.",
        "Rotate the secret, move it to the environment or a secret store, and "
        "purge it from the repository history.",
        "CWE-522"),
    "cloud_key_disclosed": _issue(
        "CRITICAL", "Cloud provider key disclosed",
        "An access key for a cloud account is exposed. These are harvested "
        "automatically within minutes of publication.",
        "Revoke the key immediately, review the account's activity log, then "
        "rotate.",
        "CWE-522"),
    "db_connection_string": _issue(
        "HIGH", "Database connection string disclosed",
        "The host, database name and usually the credentials are readable.",
        "Remove the file from the served tree and rotate the credentials.",
        "CWE-200"),
    "cleartext_password": _issue(
        "HIGH", "Credentials submitted in cleartext or by GET",
        "The password crosses the network unprotected, or is placed in a URL "
        "where it is written to history and logs.",
        "Submit credentials over HTTPS, by POST, in the body.",
        "CWE-319"),

    # ── Exposure ─────────────────────────────────────────────────────────
    "source_code_disclosure": _issue(
        "HIGH", "Source code disclosure",
        "Server-side source is returned rather than executed, handing over "
        "the application's logic and usually its secrets.",
        "Fix the handler mapping so these files are never served.",
        "CWE-540"),
    "backup_file": _issue(
        "HIGH", "Backup or editor file accessible",
        "A .bak, .old, .swp or ~ copy is served as text, which discloses "
        "source and configuration the live file hides.",
        "Remove them, and block the extensions at the web server.",
        "CWE-530"),
    "vcs_exposed": _issue(
        "HIGH", "Version control directory exposed",
        "A .git, .svn or .hg directory is readable, so the full repository — "
        "every past version, including deleted secrets — can be reconstructed.",
        "Block the directory at the web server and stop deploying it.",
        "CWE-527"),
    "env_file_exposed": _issue(
        "CRITICAL", "Environment file exposed",
        "A .env file is served. These hold exactly the values that were kept "
        "out of the code: database credentials, API keys, signing secrets.",
        "Remove it from the served tree and rotate everything it contained.",
        "CWE-497"),
    "config_disclosed": _issue(
        "HIGH", "Configuration file disclosed",
        "A configuration file is readable, exposing internal hostnames, "
        "service credentials and the shape of the deployment.",
        "Move configuration outside the document root.",
        "CWE-497"),
    "directory_listing": _issue(
        "LOW", "Directory listing enabled",
        "The server enumerates a directory's contents, which removes the need "
        "to guess file names and frequently reveals backups and uploads.",
        "Disable automatic indexing.",
        "CWE-548"),
    "debug_enabled": _issue(
        "MEDIUM", "Debug or tracing mode enabled",
        "A debug endpoint or tracing handler is live in production, exposing "
        "configuration, environment and often an interactive console.",
        "Turn debugging off in the production configuration.",
        "CWE-489"),
    "info_page_exposed": _issue(
        "MEDIUM", "Diagnostic page exposed",
        "A phpinfo, server-status, actuator or similar page is reachable, "
        "listing modules, paths, environment variables and live requests.",
        "Remove the page or restrict it to trusted addresses.",
        "CWE-200"),
    "error_message": _issue(
        "LOW", "Verbose error message",
        "The response contains a stack trace or database error, naming "
        "internal paths, component versions and query structure.",
        "Return a generic error to the client and log the detail server-side.",
        "CWE-209"),
    "version_disclosure": _issue(
        "INFO", "Software version disclosed",
        "The response names the software and often its version, which turns "
        "'find a vulnerability' into 'look up a CVE'.",
        "Suppress or flatten the header at the proxy.",
        "CWE-200"),
    "outdated_software": _issue(
        "MEDIUM", "Outdated software version",
        "The version in use is behind the current release and has published "
        "vulnerabilities against it.",
        "Update, and put the component on a patch schedule.",
        "CWE-1104"),
    "vulnerable_dependency": _issue(
        "MEDIUM", "Vulnerable JavaScript dependency",
        "A client-side library with known vulnerabilities is loaded. "
        "Exploitability depends on how the page uses it, so confirm before "
        "reporting it as live.",
        "Upgrade the library; pin versions and keep them under review.",
        "CWE-1104"),
    "known_cve": _issue(
        "HIGH", "Known vulnerability in an exposed component",
        "A component with a published CVE is reachable. Confirm the version "
        "and the affected configuration before treating it as exploitable.",
        "Apply the vendor's fix, or remove the component's exposure.",
        "CWE-1395"),
    "email_disclosure": _issue(
        "INFO", "Email addresses disclosed",
        "Addresses in the response feed phishing and credential-stuffing "
        "lists, and often name valid usernames.",
        "Publish a role address rather than personal ones.",
        "CWE-200"),
    "internal_ip_disclosure": _issue(
        "INFO", "Internal IP address disclosed",
        "The response reveals internal addressing, which maps the network "
        "behind the proxy.",
        "Strip internal addresses from headers and error pages.",
        "CWE-200"),
    "user_enumeration": _issue(
        "LOW", "Usernames enumerable",
        "Valid accounts can be told from invalid ones, which makes password "
        "spraying cheap and targeted.",
        "Return the same response and timing regardless of whether the "
        "account exists.",
        "CWE-204"),
    "api_spec_exposed": _issue(
        "LOW", "API definition exposed",
        "A Swagger, OpenAPI or GraphQL schema is public, listing every "
        "endpoint and parameter including the undocumented ones.",
        "Restrict the specification to authenticated users, or publish only "
        "the intended subset.",
        "CWE-200"),
    "robots_disclosure": _issue(
        "INFO", "Interesting paths in robots.txt",
        "The file names paths the operator wanted hidden from search engines, "
        "which is a shortlist of where to look.",
        "Do not rely on robots.txt to hide anything; control access instead.",
        "CWE-200"),

    # ── Access control and methods ───────────────────────────────────────
    "access_control": _issue(
        "HIGH", "Broken access control",
        "A resource that should require authorisation is reachable without "
        "it, or with the wrong user's.",
        "Enforce authorisation server-side on every request, against the "
        "object being accessed.",
        "CWE-284"),
    "edge_bypass": _issue(
        "HIGH", "Access restriction bypassed",
        "The block is enforced at the edge and can be stepped around with a "
        "header or a path rewrite, so whatever it was protecting is "
        "reachable.",
        "Enforce authorisation in the application, not only in the proxy, and "
        "normalise the path before the rule is applied.",
        "CWE-284"),
    "default_credentials": _issue(
        "CRITICAL", "Default or guessable credentials",
        "An account is reachable with credentials that were never changed. "
        "This needs no skill to exploit and is usually administrative.",
        "Change them, and block the defaults from ever being set.",
        "CWE-1392"),
    "admin_exposed": _issue(
        "MEDIUM", "Administrative interface exposed",
        "A management interface is reachable from the internet, giving "
        "brute-force and known-vulnerability attacks a target.",
        "Restrict it by network, and put it behind strong authentication.",
        "CWE-284"),
    "put_enabled": _issue(
        "HIGH", "HTTP PUT method enabled",
        "Files can be written to the web root, which is a direct route to "
        "uploading a web shell.",
        "Disable PUT, or restrict it to authenticated paths that cannot "
        "execute.",
        "CWE-650"),
    "dangerous_method": _issue(
        "MEDIUM", "Unsafe HTTP method enabled",
        "A method such as DELETE, MOVE or PROPFIND is accepted, exposing "
        "operations the application never intended to offer.",
        "Allow only the methods the application uses.",
        "CWE-650"),
    "trace_enabled": _issue(
        "LOW", "HTTP TRACE method enabled",
        "TRACE echoes the request, including headers the page's script cannot "
        "otherwise read.",
        "Disable TRACE and TRACK.",
        "CWE-16"),

    # ── Network services ─────────────────────────────────────────────────
    "exposed_datastore": _issue(
        "HIGH", "Datastore reachable from the network",
        "A database or cache is answering on a public interface. Several of "
        "these ship with no authentication at all.",
        "Bind it to localhost or a private network, require authentication, "
        "and firewall the port.",
        "CWE-306"),
    "cleartext_service": _issue(
        "MEDIUM", "Cleartext network service",
        "The service carries credentials without encryption, so anyone on the "
        "path can read them.",
        "Replace it with an encrypted equivalent and disable the old one.",
        "CWE-319"),
    "remote_access_exposed": _issue(
        "MEDIUM", "Remote access service exposed",
        "A remote administration service faces the network, where it will be "
        "found and attacked continuously.",
        "Restrict it to a VPN or a bastion, and require key-based "
        "authentication.",
        "CWE-284"),
}


# ─────────────────────────────────────────────────────────────────────────────
#  testssl → issue
# ─────────────────────────────────────────────────────────────────────────────
#
# Matched in order, first hit wins. testssl's ids are stable enough to key on;
# where a family shares a prefix (BEAST_CBC_TLS1, cipherlist_3DES_IDEA) the
# pattern covers the family rather than naming every member.

_TESTSSL_IDS = (
    # testssl reports the CBC suites under their own ids as well as under
    # LUCKY13; they are the same issue and belong on the same finding.
    (r"^(LUCKY13|cbc)", "lucky13"),
    (r"^BEAST", "beast"),
    (r"^POODLE", "poodle"),
    (r"^SWEET32", "sweet32"),
    (r"^ROBOT", "robot"),
    (r"^heartbleed", "heartbleed"),
    (r"^CCS", "ccs"),
    (r"^ticketbleed", "ticketbleed"),
    (r"^DROWN", "drown"),
    (r"^FREAK", "freak"),
    (r"^LOGJAM", "logjam"),
    (r"^CRIME", "crime"),
    (r"^BREACH", "breach"),
    (r"^RC4", "rc4"),
    (r"^(secure_renego|secure_client_renego|renego)", "renegotiation"),
    (r"^fallback_SCSV", "fallback"),
    (r"^(SSLv2|SSLv3|TLS1$|TLS1_1)", "obsolete_protocol"),
    (r"^cert_expiration", "cert_expired"),
    (r"^cert_(chain_of_trust|trust|caIssuers)", "cert_untrusted"),
    (r"^cert_(commonName|subjectAltName|hostname)", "cert_hostname"),
    (r"^cert_signatureAlgorithm", "cert_weak_signature"),
    (r"^cert_keySize", "cert_weak_key"),
    (r"^(cipherlist_|cipher_negotiated|std_)", "weak_cipher"),
)

#: What the finding text says, when the id is not enough. testssl reuses a
#: generic id for several checks in older releases.
_TESTSSL_TEXT = (
    (r"\blucky\s*13\b|CBC ciphers", "lucky13"),
    (r"\bBEAST\b", "beast"),
    (r"\bPOODLE\b", "poodle"),
    (r"\bSWEET32\b|64 bit block", "sweet32"),
    (r"\bROBOT\b", "robot"),
    (r"\bheartbleed\b", "heartbleed"),
    (r"\bDROWN\b", "drown"),
    (r"\bFREAK\b", "freak"),
    (r"\bLOGJAM\b|common prime", "logjam"),
    (r"\bRC4\b", "rc4"),
    (r"\bexport\b|\bNULL cipher|\banon\b|\b3DES\b", "weak_cipher"),
    (r"expired|not yet valid", "cert_expired"),
    (r"self.signed|chain of trust|untrusted", "cert_untrusted"),
    (r"SHA1 with|MD5 with|signature algorithm", "cert_weak_signature"),
)

#: testssl's own severities. OK and INFO mean "we looked, it was fine" — the
#: single biggest source of the noise on the findings screen was treating
#: those as things to report.
TESTSSL_BENIGN = {"OK", "INFO", "DEBUG", "WARN", "FATAL"}

_NOT_VULNERABLE = re.compile(
    r"not vulnerable|no (?:CBC|RC4|weak|export)|not offered|"
    r"not supported|isn't vulnerable|downgrade attack protection", re.I)


def for_testssl(record):
    """Map one testssl JSON record onto a library entry.

    Returns ``(key, issue)`` or ``(None, None)`` when the record is telling us
    the host is *fine* — which is most of them, and none of which belongs on a
    findings screen.
    """
    severity = str(record.get("severity", "")).upper()
    identifier = str(record.get("id", ""))
    finding = str(record.get("finding", ""))

    if severity in TESTSSL_BENIGN:
        return None, None
    if _NOT_VULNERABLE.search(finding):
        return None, None

    for pattern, key in _TESTSSL_IDS:
        # Case-insensitively: testssl's own ids are consistent, but the
        # console fallback reconstructs an id from the printed label, which
        # is capitalised however the section header was.
        if re.search(pattern, identifier, re.I):
            return key, ISSUES[key]
    for pattern, key in _TESTSSL_TEXT:
        if re.search(pattern, finding, re.I):
            return key, ISSUES[key]
    return "tls_generic", ISSUES["tls_generic"]


# ─────────────────────────────────────────────────────────────────────────────
#  Everything else → issue
# ─────────────────────────────────────────────────────────────────────────────
#
# nuclei, Nikto and wpscan all describe the same problems in their own words.
# Matching those words onto the library is what makes three tools produce one
# finding instead of three differently-worded ones. Order matters: the more
# specific pattern has to come first.

_TEXT_ISSUES = (
    (r"\.env\b|env file", "env_file_exposed"),
    (r"\.git/(config|HEAD)|git (config|repository) (exposed|disclos)|"
     r"\.svn/|\.hg/", "vcs_exposed"),
    (r"private key|BEGIN (RSA |EC |OPENSSH |DSA )?PRIVATE KEY", "private_key_disclosed"),
    (r"aws[_ -]?(access[_ -]?key|secret)|AKIA[0-9A-Z]{16}|"
     r"gcp service account|azure storage key", "cloud_key_disclosed"),
    (r"connection string|jdbc:|mongodb(\+srv)?://\S+:", "db_connection_string"),
    (r"api[_ -]?key|secret[_ -]?key|hardcoded credential|token disclos",
     "credentials_disclosed"),
    (r"default (password|credential)|admin:admin|weak credential|"
     r"login bypass with default", "default_credentials"),
    (r"phpinfo|server-status|server-info|actuator|/debug/pprof|"
     r"\bheapdump\b|env endpoint", "info_page_exposed"),
    (r"debug mode|tracing enabled|stack ?trace|django debug|"
     r"werkzeug (console|debugger)", "debug_enabled"),
    (r"backup file|\.bak\b|\.old\b|\.swp\b|~ file", "backup_file"),
    (r"source ?code disclos|source disclos", "source_code_disclosure"),
    (r"directory (listing|indexing)|index of /", "directory_listing"),
    (r"sql ?injection|sqli\b", "sqli"),
    (r"command injection|rce\b|remote code execution|code execution",
     "command_injection"),
    (r"template injection|ssti", "ssti"),
    (r"deserial", "deserialization"),
    (r"\bssrf\b|server.side request forgery", "ssrf"),
    (r"\bxxe\b|external entity", "xxe"),
    (r"ldap injection", "ldap_injection"),
    (r"xpath injection", "xpath_injection"),
    (r"local file inclusion|remote file inclusion|\blfi\b|\brfi\b",
     "file_inclusion"),
    (r"(path|directory) traversal|\.\./\.\./", "traversal"),
    (r"open redirect|unvalidated redirect", "open_redirect"),
    (r"request smuggling", "request_smuggling"),
    (r"cache poison", "cache_poisoning"),
    (r"host header", "host_header_injection"),
    (r"(crlf|response (header )?splitting|header injection)", "crlf_injection"),
    (r"prototype pollution", "prototype_pollution"),
    (r"stored (xss|cross.site scripting)", "xss_stored"),
    (r"dom.based (xss|cross.site scripting)", "xss_dom"),
    (r"(xss|cross.site scripting)", "xss_reflected"),
    (r"\bcsrf\b|cross.site request forgery", "csrf"),
    (r"jwt.*(none|alg)|none algorithm", "jwt_none"),
    (r"jwt.*(weak|brute|secret)", "jwt_weak_secret"),
    (r"jwt.*(jku|x5u|jwk)", "jwt_key_injection"),
    (r"cors|cross.origin resource sharing", "cors_arbitrary_origin"),
    (r"crossdomain\.xml|clientaccesspolicy", "crossdomain_policy"),
    (r"graphql introspection", "graphql_introspection"),
    (r"graphql suggestion", "graphql_suggestions"),
    (r"swagger|openapi|api-docs", "api_spec_exposed"),
    (r"\bput method\b|put is enabled|webdav write", "put_enabled"),
    (r"\btrace\b method|track method", "trace_enabled"),
    (r"(delete|move|copy|propfind|mkcol) method", "dangerous_method"),
    (r"admin (panel|interface|console|login)|/manager/html|phpmyadmin",
     "admin_exposed"),
    (r"unauthenticated|missing authentication|auth(orisation|orization) bypass|"
     r"improper access control", "access_control"),
    (r"file upload", "file_upload"),
    (r"outdated|end.of.life|no longer supported|is out of date",
     "outdated_software"),
    (r"(vulnerable|outdated) (javascript|js) (library|dependency)|"
     r"retire\.?js", "vulnerable_dependency"),
    (r"CVE-\d{4}-\d+", "known_cve"),
    (r"user(name)?s? (enumerat|identified)|account enumeration",
     "user_enumeration"),
    (r"email address", "email_disclosure"),
    (r"internal ip|private ip", "internal_ip_disclosure"),
    (r"robots\.txt", "robots_disclosure"),
    (r"mixed content", "mixed_content"),
    (r"cacheable|cache.control", "cacheable_https"),
    (r"clickjack|frame.?able|x-frame-options", "xfo_missing"),
    (r"content.security.policy|\bcsp\b", "csp_missing"),
    (r"strict.transport.security|\bhsts\b", "hsts_missing"),
    (r"x-content-type-options|mime.?sniff", "nosniff_missing"),
    (r"httponly", "cookie_no_httponly"),
    (r"samesite", "cookie_no_samesite"),
    (r"secure flag|cookie without secure", "cookie_no_secure"),
    (r"session (token|id) in url", "session_token_in_url"),
    (r"version (disclos|leak)|banner", "version_disclosure"),
)


def for_text(text, default=None):
    """Map a tool's own wording onto a library entry.

    Returns ``(key, issue)``, or ``(None, None)`` when nothing matches — in
    which case the caller keeps the tool's line as it stands rather than
    forcing it into an issue it is not.
    """
    blob = str(text or "")
    for pattern, key in _TEXT_ISSUES:
        if re.search(pattern, blob, re.I):
            return key, ISSUES[key]
    if default and default in ISSUES:
        return default, ISSUES[default]
    return None, None


def for_nuclei(template_id, name, description=""):
    """A nuclei match, by template id first and then by its name."""
    identifier = str(template_id or "")
    if re.match(r"^CVE-\d{4}-\d+$", identifier, re.I):
        # The template id is the CVE itself; the name says what kind of bug it
        # is, so look there before falling back to "known CVE".
        key, issue = for_text(f"{name} {description}")
        return (key, issue) if key else ("known_cve", ISSUES["known_cve"])
    return for_text(f"{identifier} {name} {description}")


#: nmap service names that are findings in themselves, and which issue they
#: are. A datastore on a public interface is not the same problem as telnet.
NMAP_SERVICES = {
    "redis": "exposed_datastore", "mongodb": "exposed_datastore",
    "memcached": "exposed_datastore", "elasticsearch": "exposed_datastore",
    "mysql": "exposed_datastore", "postgresql": "exposed_datastore",
    "ms-sql-s": "exposed_datastore", "cassandra": "exposed_datastore",
    "couchdb": "exposed_datastore", "ftp": "cleartext_service",
    "telnet": "cleartext_service", "rsh": "cleartext_service",
    "rlogin": "cleartext_service", "rexec": "cleartext_service",
    "pop3": "cleartext_service", "imap": "cleartext_service",
    "snmp": "cleartext_service", "vnc": "remote_access_exposed",
    "ms-wbt-server": "remote_access_exposed", "rdp": "remote_access_exposed",
    "microsoft-ds": "remote_access_exposed", "smb": "remote_access_exposed",
    "netbios-ssn": "remote_access_exposed",
}

#: A service that is risky enough to raise above the library's default. Telnet
#: carrying a password is worse than an unauthenticated IMAP banner.
NMAP_SEVERITY = {"telnet": "HIGH", "rsh": "HIGH", "rlogin": "HIGH",
                 "rexec": "HIGH", "redis": "HIGH", "mongodb": "HIGH",
                 "memcached": "HIGH", "elasticsearch": "HIGH"}


def worst(*severities):
    """The most serious of the severities given, ignoring anything unknown."""
    order = ("INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL")
    best = 0
    for severity in severities:
        if severity and str(severity).upper() in order:
            best = max(best, order.index(str(severity).upper()))
    return order[best]


# ─────────────────────────────────────────────────────────────────────────────
#  Noise
# ─────────────────────────────────────────────────────────────────────────────
#
# A scanner that prints everything is a scanner nobody reads. Burp keeps this
# material too, but it keeps it as *information*, collapsed, and out of the way
# of the things that need acting on. These are the checks whose output is
# inventory rather than a finding.

#: nuclei template ids (and id prefixes) that describe what the stack is, not
#: what is wrong with it. They are folded into one "Technology fingerprint"
#: entry instead of one row each.
NUCLEI_FINGERPRINT = (
    "tech-detect", "waf-detect", "favicon-detect", "fingerprinthub",
    "ssl-dns-names", "ssl-issuer", "tls-version", "http-missing-security-headers",
    "options-method", "robots-txt", "sitemap", "dns-", "wappalyzer",
    "metatag-cms", "caa-fingerprint", "mx-fingerprint", "txt-fingerprint",
    "nameserver-fingerprint", "ptr-fingerprint", "cname-fingerprint",
    "http-trace", "cookies-without", "security-txt", "openapi", "swagger-api",
    "wordpress-detect", "php-detect", "nginx-version", "apache-detect",
    "iis-version", "server-version", "git-config", "url-analyse",
)

#: Nikto's line prefixes that are inventory, a banner, or the scan's own
#: bookkeeping. Nikto prints a lot of these and every one of them used to
#: become a row.
NIKTO_NOISE = (
    "target ", "start time", "end time", "server:", "root page", "no cgi",
    "scan terminated", "host(s) tested", "ssl info", "allowed http",
    "retrieved x-powered-by", "retrieved access-control", "uncommon header",
    "the anti-clickjacking", "the x-content-type-options",
    "the x-xss-protection", "no cgi directories", "multiple index files",
    "web server returns", "cookie ", "retrieved via header",
    "reports it is", "appears to be outdated",     # handled as its own issue
)


def clean_title(text, limit=118):
    """A title that reads like a title.

    Strips ANSI, collapses whitespace, drops testssl's trailing parentheticals,
    and — this is the part that was wrong before — cuts on a word boundary with
    an ellipsis rather than mid-word at a fixed offset. The full text is always
    kept as the finding's detail, so nothing is lost by shortening it here.
    """
    text = re.sub(r"\x1b\[[0-9;]*m", "", str(text or ""))
    text = re.sub(r"\s+", " ", text).strip(" \t-—:;.")
    if len(text) <= limit:
        return text
    cut = text[:limit].rsplit(" ", 1)[0].rstrip(",;:-")
    return (cut or text[:limit]) + "…"


def is_fingerprint(template_id):
    """True when a nuclei template is describing the stack rather than a bug."""
    lowered = str(template_id or "").lower()
    return any(lowered.startswith(n) or n in lowered
               for n in NUCLEI_FINGERPRINT)


def is_nikto_noise(line):
    lowered = str(line or "").strip().lower()
    return any(lowered.startswith(n) for n in NIKTO_NOISE)
