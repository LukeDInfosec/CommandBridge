#!/usr/bin/env python3
"""Find and fetch a target's OpenAPI/Swagger specification.

Why this exists
───────────────
The old button just fetched whatever was in the target box and declared
failure if the bytes were not JSON. So when a client says "the API docs are
at example.co.uk/swagger" — a URL that opens perfectly in a browser — the
button reported no documentation at all.

Two things were wrong with that. It never probed anywhere else, and, more
importantly, `/swagger` almost never serves the spec. It serves **Swagger UI**:
an HTML page whose JavaScript then loads the spec from somewhere else
entirely (`/swagger/v1/swagger.json`, `/v3/api-docs`, a `configUrl`, …). A
scanner that only accepts JSON will always miss it.

So this does what a tester does by hand:

1. If the target already points at a spec, use it.
2. Otherwise try the paths specs actually live at.
3. When a page turns out to be a documentation UI — Swagger UI, Redoc,
   RapiDoc, Stoplight Elements, Scalar — read the spec URL back out of the
   HTML (including out of `swagger-initializer.js`, where Swagger UI 4+ keeps
   it) and follow it.
4. Accept YAML as well as JSON, because plenty of specs are `openapi.yaml`.

Usage:
    python3 swagger_discover.py <target-url> [--out FILE] [--timeout 10]
                                [--insecure] [--max-print 120]

Exit codes: 0 spec found, 1 nothing found, 2 bad usage.
"""

from __future__ import annotations

import argparse
import json
import re
import ssl
import sys
import urllib.error
import urllib.parse
import urllib.request

# Ordered by how often they pay off in practice. "" is the target itself —
# if the tester pasted the spec URL, nothing else should be tried first.
CANDIDATE_PATHS = [
    "",
    "/swagger.json",
    "/swagger.yaml",
    "/openapi.json",
    "/openapi.yaml",
    "/swagger/v1/swagger.json",
    "/swagger/v2/swagger.json",
    "/v2/api-docs",
    "/v3/api-docs",
    "/api-docs",
    "/api/swagger.json",
    "/api/openapi.json",
    "/api/v1/swagger.json",
    "/api/docs",
    "/api-docs/swagger.json",
    "/docs/swagger.json",
    "/swagger",
    "/swagger/index.html",
    "/swagger-ui.html",
    "/swagger-ui/index.html",
    "/api/swagger-ui.html",
    "/docs",
    "/redoc",
    "/graphql-docs",
]

#: Marks a page as a documentation UI rather than the spec itself.
UI_MARKERS = (
    "swagger-ui", "swagger_ui", "swaggerui", "redoc", "rapidoc",
    "stoplight", "elements-api", "scalar-api", "openapi-explorer",
)

#: Ways a UI page points at its spec. Swagger UI 4+ puts it in a separate
#: swagger-initializer.js, which is why that file is fetched too.
SPEC_URL_PATTERNS = [
    re.compile(r"""["']?(?:swagger|spec|api)?[Uu]rl["']?\s*[:=]\s*["']([^"']+)["']"""),
    re.compile(r"""configUrl\s*[:=]\s*["']([^"']+)["']"""),
    re.compile(r"""spec-url\s*=\s*["']([^"']+)["']"""),
    re.compile(r"""data-url\s*=\s*["']([^"']+)["']"""),
    re.compile(r"""urls\s*:\s*\[\s*\{[^}]*url\s*:\s*["']([^"']+)["']"""),
]

HEADERS = {
    "User-Agent": ("Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
                   "(KHTML, like Gecko) Chrome/125.0 Safari/537.36"),
    "Accept": "application/json, application/yaml, text/yaml, text/html;q=0.9, */*;q=0.8",
}


def build_opener(insecure: bool):
    handlers = []
    if insecure:
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        handlers.append(urllib.request.HTTPSHandler(context=context))
    return urllib.request.build_opener(*handlers)


def fetch(opener, url: str, timeout: int):
    """GET a URL. Returns (status, body, content_type, final_url)."""
    try:
        request = urllib.request.Request(url, headers=HEADERS)
        with opener.open(request, timeout=timeout) as response:
            body = response.read(6 * 1024 * 1024)  # a spec that big is a mistake
            return (response.status,
                    body.decode("utf-8", errors="replace"),
                    response.headers.get("Content-Type", ""),
                    response.geturl())
    except urllib.error.HTTPError as exc:
        return exc.code, "", "", url
    except Exception:
        return 0, "", "", url


def parse_spec(body: str):
    """Return the parsed spec if this text is one, else None.

    A document is only a spec if it declares `swagger` or `openapi` at the
    top level — an arbitrary JSON API response is not documentation, and
    accepting one would be a false positive of exactly the kind that wastes
    time on an engagement.
    """
    text = body.strip()
    if not text:
        return None

    spec = None
    if text[0] in "{[":
        try:
            spec = json.loads(text)
        except json.JSONDecodeError:
            spec = None

    if spec is None:
        # YAML, without requiring PyYAML: a spec's version key is at column 0.
        if re.search(r"^(swagger|openapi)\s*:\s*[\"']?\d", text, re.MULTILINE):
            return {"__yaml__": True}
        return None

    if isinstance(spec, dict) and ("swagger" in spec or "openapi" in spec):
        return spec
    return None


def looks_like_ui(body: str, content_type: str) -> bool:
    lowered = body[:20000].lower()
    if "html" not in content_type.lower() and "<html" not in lowered:
        return False
    return any(marker in lowered for marker in UI_MARKERS)


def spec_urls_from_ui(body: str, page_url: str) -> list[str]:
    """Extract candidate spec URLs referenced by a documentation UI page."""
    found: list[str] = []
    for pattern in SPEC_URL_PATTERNS:
        for match in pattern.findall(body):
            value = match.strip()
            if not value or value.startswith(("data:", "#", "javascript:")):
                continue
            # Skip the UI's own assets — they are not the spec.
            if re.search(r"\.(css|png|svg|ico|woff2?|map)$", value, re.I):
                continue
            if value.endswith(".js") and "initializer" not in value:
                continue
            absolute = urllib.parse.urljoin(page_url, value)
            if absolute not in found:
                found.append(absolute)
    return found


def describe(spec) -> str:
    if spec.get("__yaml__"):
        return "YAML spec"
    version = spec.get("openapi") or spec.get("swagger") or "?"
    info = spec.get("info") or {}
    title = info.get("title") or "untitled API"
    paths = spec.get("paths") or {}
    return f"{title} (spec version {version}, {len(paths)} path(s))"


def main() -> int:
    parser = argparse.ArgumentParser(description="Discover an OpenAPI/Swagger spec")
    parser.add_argument("target")
    parser.add_argument("--out", default="swagger.json")
    parser.add_argument("--timeout", type=int, default=10)
    parser.add_argument("--insecure", action="store_true", default=True)
    parser.add_argument("--max-print", type=int, default=120)
    args = parser.parse_args()

    target = args.target.strip().rstrip("/")
    if not target:
        print("[!] No target given.", file=sys.stderr)
        return 2
    if not target.startswith(("http://", "https://")):
        target = "https://" + target

    opener = build_opener(args.insecure)
    seen: set[str] = set()
    ui_pages: list[tuple[str, str]] = []   # (page_url, body) to mine afterwards

    def try_url(url: str, note: str = "") -> bool:
        if url in seen:
            return False
        seen.add(url)
        status, body, content_type, final_url = fetch(opener, url, args.timeout)
        if status == 0:
            print(f"  [-] {url} — no response")
            return False
        if status >= 400:
            print(f"  [-] {url} — HTTP {status}")
            return False

        spec = parse_spec(body)
        if spec is not None:
            print(f"\n[+] Specification found: {final_url}")
            print(f"[+] {describe(spec)}")
            try:
                with open(args.out, "w", encoding="utf-8") as f:
                    f.write(body)
                print(f"[+] Saved to {args.out}")
            except OSError as exc:
                print(f"[!] Could not write {args.out}: {exc}")

            print("\n" + "-" * 70)
            if spec.get("__yaml__"):
                for line in body.splitlines()[:args.max_print]:
                    print(line)
            else:
                pretty = json.dumps(spec, indent=2).splitlines()
                for line in pretty[:args.max_print]:
                    print(line)
                if len(pretty) > args.max_print:
                    print(f"... {len(pretty) - args.max_print} more lines in {args.out}")
            return True

        if looks_like_ui(body, content_type):
            print(f"  [~] {url} — documentation UI, not the spec itself")
            ui_pages.append((final_url, body))
        else:
            print(f"  [-] {url} — HTTP {status}, not a spec{note}")
        return False

    print(f"[*] Looking for OpenAPI/Swagger documentation on {target}")
    for path in CANDIDATE_PATHS:
        if try_url(target + path):
            return 0

    # Nothing served a spec directly. Mine any UI pages for where their
    # JavaScript loads the spec from — this is the case that matters when the
    # client hands over a /swagger URL.
    if ui_pages:
        print("\n[*] Reading spec locations out of the documentation UI…")
        for page_url, body in ui_pages:
            candidates = spec_urls_from_ui(body, page_url)

            # Swagger UI 4+ keeps the URL in a separate initializer script.
            for script in re.findall(r'src\s*=\s*["\']([^"\']*initializer[^"\']*\.js)["\']',
                                     body, re.I):
                script_url = urllib.parse.urljoin(page_url, script)
                _, script_body, _, script_final = fetch(opener, script_url, args.timeout)
                if script_body:
                    candidates.extend(spec_urls_from_ui(script_body, script_final))

            for candidate in candidates:
                print(f"  [*] UI references: {candidate}")
                if try_url(candidate):
                    return 0

    print("\n[!] No OpenAPI/Swagger specification found.")
    if ui_pages:
        print("[i] A documentation UI was found at "
              + ", ".join(url for url, _ in ui_pages))
        print("[i] but the spec URL could not be read out of it. Open that page "
              "in a browser with DevTools on the Network tab — the spec is the "
              "JSON/YAML request the page makes on load — then right-click this "
              "button and point it straight at that URL.")
    else:
        print("[i] Nothing at the target or the usual spec paths. If the API is "
              "behind auth, add the header on the Target tab and right-click "
              "this button to include it.")
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
