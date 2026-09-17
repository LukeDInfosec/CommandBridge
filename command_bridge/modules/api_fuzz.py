#!/usr/bin/env python3
"""API fuzzing that fits the API in front of you.

The old button ran ffuf once, against one small path list, at `{TARGET}/api/`.
On a REST API that is a thin pass; on a SOAP endpoint it is worthless — a SOAP
service exposes one URL and its attack surface is the *operation list*, not a
directory tree, so path fuzzing finds nothing and finishes in seconds looking
like it worked.

This does three things instead:

1. **Fingerprint.** Fetch the target, look at Content-Type and body. SOAP and
   REST get different treatment because they need different treatment.

2. **SOAP: enumerate operations.** Find the WSDL (``?wsdl``, ``?singleWsdl``,
   ``/service.svc?wsdl`` and friends), parse the operations, bindings and
   SOAPAction values out of it, and report them. That list is the thing worth
   testing — each operation is an entry point, and they are routinely
   inconsistent about authorisation.

3. **REST: chain several wordlists**, deduplicated, with soft-404 calibration,
   then fuzz HTTP verbs against whatever was found. A path that 401s on GET
   and 200s on PUT is broken access control, and a single GET-only sweep never
   sees it.

Findings are written as JSON alongside the console output.

Usage:
    api_fuzz.py <target> [--wordlists a.txt,b.txt] [--mode auto|rest|soap]
                [--threads 20] [--timeout 8] [--out FILE] [--header 'K: V']
                [--max-verb-checks 40] [--insecure]
"""

from __future__ import annotations

import argparse
import concurrent.futures
import json
import re
import ssl
import sys
import urllib.error
import urllib.parse
import urllib.request
import xml.etree.ElementTree as ET
from collections import OrderedDict
from pathlib import Path

RED = "\033[91m"
YELLOW = "\033[93m"
GREEN = "\033[92m"
CYAN = "\033[96m"
BOLD = "\033[1m"
DIM = "\033[2m"
RESET = "\033[0m"

#: Wordlists chained for a REST sweep, best first. Missing files are skipped
#: with a note rather than failing the run — SecLists layouts shift between
#: versions and a missing list should not abort the engagement.
DEFAULT_WORDLISTS = [
    "/usr/share/seclists/Discovery/Web-Content/api/api-endpoints.txt",
    "/usr/share/seclists/Discovery/Web-Content/api/api-endpoints-res.txt",
    "/usr/share/seclists/Discovery/Web-Content/api/actions.txt",
    "/usr/share/seclists/Discovery/Web-Content/api/objects.txt",
    "/usr/share/seclists/Discovery/Web-Content/api/api-seen-in-wild.txt",
    "/usr/share/seclists/Discovery/Web-Content/common-api-endpoints-mazen160.txt",
]

#: Where a spec or WSDL tends to live. Cheap to check and worth a lot when hit.
WSDL_PATHS = ["?wsdl", "?WSDL", "?singleWsdl", "/?wsdl", "/service.svc?wsdl",
              "/Service.svc?wsdl", "/soap?wsdl", "/services?wsdl", "/ws?wsdl",
              "/api?wsdl", "/wsdl", "/service.wsdl"]

VERBS = ["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"]

#: Only these count as a finding when they succeed where GET was refused.
#: OPTIONS is deliberately excluded: a 200/204 to OPTIONS is ordinary CORS
#: preflight behaviour, and flagging it buries the real asymmetries in noise.
STATE_CHANGING = {"POST", "PUT", "PATCH", "DELETE"}

SOAP_HINTS = ("soap:envelope", "soap-env", "application/soap+xml", "wsdl:definitions",
              "<definitions", "text/xml", "xmlns:soap")


def make_context(insecure: bool):
    if not insecure:
        return None
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    return ctx


def request(url, ctx, timeout, method="GET", headers=None, body=None):
    """Returns (status, body_text, content_type, length)."""
    hdrs = {"User-Agent": "CommandBridge-APIFuzz/1.0"}
    hdrs.update(headers or {})
    try:
        req = urllib.request.Request(url, data=body, method=method, headers=hdrs)
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as response:
            text = response.read(2 * 1024 * 1024).decode("utf-8", errors="replace")
            return response.status, text, response.headers.get("Content-Type", ""), len(text)
    except urllib.error.HTTPError as exc:
        try:
            text = exc.read(65536).decode("utf-8", errors="replace")
        except Exception:
            text = ""
        ct = exc.headers.get("Content-Type", "") if exc.headers else ""
        return exc.code, text, ct, len(text)
    except Exception:
        return None, "", "", 0


# ── SOAP ──────────────────────────────────────────────────────────────────

def find_wsdl(target, ctx, timeout, headers):
    """Locate a WSDL document for the target."""
    base = target.rstrip("/")
    candidates = []
    for suffix in WSDL_PATHS:
        candidates.append(base + suffix if suffix.startswith("?") else base + suffix)
    seen = set()
    for url in candidates:
        if url in seen:
            continue
        seen.add(url)
        status, text, content_type, _ = request(url, ctx, timeout, headers=headers)
        if status and 200 <= status < 300 and ("definitions" in text[:4000].lower()
                                               or "wsdl" in content_type.lower()):
            return url, text
    return None, ""


def parse_wsdl(text):
    """Pull operations, SOAPActions and bindings out of a WSDL document.

    Namespace handling is deliberately loose — WSDL in the wild uses wsdl:,
    no prefix, and occasionally something bespoke, and a strict parser trips
    on all of it. Matching on the local tag name is what survives contact
    with real services.
    """
    operations = OrderedDict()
    try:
        root = ET.fromstring(text)
    except ET.ParseError:
        # Malformed or truncated WSDL still leaks operation names.
        for name in re.findall(r'<(?:\w+:)?operation[^>]*name="([^"]+)"', text):
            operations.setdefault(name, {"name": name, "soap_action": None})
        for name, action in re.findall(
                r'<(?:\w+:)?operation[^>]*name="([^"]+)"[^>]*>.*?soapAction="([^"]*)"',
                text, re.S):
            operations.setdefault(name, {"name": name, "soap_action": None})
            operations[name]["soap_action"] = action
        return list(operations.values()), []

    def local(tag):
        return tag.split("}", 1)[-1]

    for element in root.iter():
        if local(element.tag) != "operation":
            continue
        name = element.get("name")
        if not name:
            continue
        entry = operations.setdefault(name, {"name": name, "soap_action": None})
        for child in element.iter():
            action = child.get("soapAction")
            if action is not None:
                entry["soap_action"] = action
                break

    services = []
    for element in root.iter():
        if local(element.tag) in ("address", "SOAPAddress"):
            location = element.get("location")
            if location:
                services.append(location)
    return list(operations.values()), services


def run_soap(target, ctx, timeout, headers, findings):
    print(f"\n{BOLD}{CYAN}[*] SOAP service — enumerating operations{RESET}")
    wsdl_url, text = find_wsdl(target, ctx, timeout, headers)
    if not wsdl_url:
        print(f"{YELLOW}[-] No WSDL found at the usual locations.{RESET}")
        print("[i] Without a WSDL the operation list has to come from captured traffic. "
              "Grab a request from the proxy and read the SOAPAction header and the "
              "first child of <soap:Body> — that names the operation.")
        findings["soap"] = {"wsdl": None, "operations": []}
        return

    print(f"{GREEN}[+] WSDL: {wsdl_url}{RESET}")
    operations, endpoints = parse_wsdl(text)
    findings["soap"] = {
        "wsdl": wsdl_url,
        "endpoints": endpoints,
        "operations": operations,
    }

    if endpoints:
        print(f"[+] Service endpoint(s): {', '.join(endpoints[:5])}")
    if not operations:
        print(f"{YELLOW}[-] WSDL parsed but no operations found.{RESET}")
        return

    print(f"{GREEN}[+] {len(operations)} operation(s):{RESET}")
    for op in operations:
        action = op.get("soap_action")
        suffix = f"   SOAPAction: {action}" if action else ""
        print(f"      - {op['name']}{suffix}")

    print(f"\n{DIM}[i] Each operation is an entry point. Authorisation is frequently "
          f"enforced per-service rather than per-operation, so test each one with a "
          f"low-privilege session — and try operations the UI never calls.{RESET}")


# ── REST ──────────────────────────────────────────────────────────────────

def load_wordlists(paths):
    words, used, missing = OrderedDict(), [], []
    for path in paths:
        p = Path(path)
        if not p.is_file():
            missing.append(path)
            continue
        count = 0
        try:
            for line in p.read_text(encoding="utf-8", errors="replace").splitlines():
                word = line.strip().lstrip("/")
                if word and not word.startswith("#") and word not in words:
                    words[word] = None
                    count += 1
        except OSError:
            missing.append(path)
            continue
        used.append((path, count))
    return list(words), used, missing


def calibrate(target, ctx, timeout, headers):
    """Learn what a miss looks like, so soft-404s can be filtered out."""
    signatures = set()
    for probe in ("cb-probe-zzz-404", "cb-probe-does-not-exist-9821"):
        status, text, _, length = request(f"{target.rstrip('/')}/{probe}", ctx, timeout,
                                          headers=headers)
        if status:
            signatures.add((status, length // 64))
    return signatures


def fuzz_paths(target, words, ctx, timeout, threads, headers, signatures):
    base = target.rstrip("/")
    hits = []
    total = len(words)
    done = 0

    def check(word):
        url = f"{base}/{word}"
        status, _, content_type, length = request(url, ctx, timeout, headers=headers)
        if status is None:
            return None
        if status == 404:
            return None
        if (status, length // 64) in signatures:
            return None   # soft-404
        return {"url": url, "status": status, "length": length,
                "content_type": content_type.split(";")[0]}

    with concurrent.futures.ThreadPoolExecutor(max_workers=threads) as pool:
        for result in pool.map(check, words):
            done += 1
            if done % 500 == 0:
                print(f"    … {done}/{total} paths tested, {len(hits)} hit(s)")
            if result:
                hits.append(result)
                colour = GREEN if 200 <= result["status"] < 300 else YELLOW
                print(f"  {colour}[{result['status']}]{RESET} {result['url']} "
                      f"{DIM}({result['length']} bytes, {result['content_type']}){RESET}")
    return hits


def fuzz_verbs(hits, ctx, timeout, headers, limit):
    """Try other methods against discovered endpoints.

    The interesting result is asymmetry: a path that refuses GET but accepts
    PUT or DELETE is broken access control, and it is invisible to a
    GET-only sweep.
    """
    interesting = []
    targets = hits[:limit]
    if not targets:
        return interesting
    print(f"\n{BOLD}{CYAN}[*] Verb fuzzing {len(targets)} endpoint(s){RESET}")
    for hit in targets:
        baseline = hit["status"]
        row = {"url": hit["url"], "GET": baseline}
        notable = False
        for verb in VERBS:
            if verb == "GET":
                continue
            status, _, _, _ = request(hit["url"], ctx, timeout, method=verb, headers=headers)
            row[verb] = status
            # A state-changing method that succeeds where GET was refused is
            # the finding worth chasing.
            if (verb in STATE_CHANGING and status and 200 <= status < 300
                    and not (200 <= baseline < 300)):
                notable = True
        if notable:
            interesting.append(row)
            allowed = ", ".join(f"{v}={row[v]}" for v in VERBS if row.get(v))
            print(f"  {RED}[!]{RESET} {hit['url']} — GET {baseline} but succeeds on "
                  f"another method  {DIM}({allowed}){RESET}")
    if not interesting:
        print(f"{DIM}    No method asymmetries found.{RESET}")
    return interesting


def main() -> int:
    parser = argparse.ArgumentParser(description="API fuzzing")
    parser.add_argument("target")
    parser.add_argument("--mode", choices=["auto", "rest", "soap"], default="auto")
    parser.add_argument("--wordlists", default="", help="Comma-separated list of wordlists")
    parser.add_argument("--threads", type=int, default=20)
    parser.add_argument("--timeout", type=float, default=8.0)
    parser.add_argument("--out", default="api_fuzz.json")
    parser.add_argument("--header", action="append", default=[],
                        help="Extra header, repeatable: --header 'Authorization: Bearer x'")
    parser.add_argument("--max-verb-checks", type=int, default=40)
    parser.add_argument("--insecure", action="store_true", default=True)
    args = parser.parse_args()

    target = args.target.strip().rstrip("/")
    if not target.startswith(("http://", "https://")):
        target = "https://" + target

    headers = {}
    for item in args.header:
        if ":" in item:
            name, value = item.split(":", 1)
            headers[name.strip()] = value.strip()

    ctx = make_context(args.insecure)
    findings = {"target": target, "mode": args.mode}

    # ── Fingerprint ──────────────────────────────────────────────────────
    print(f"{BOLD}{CYAN}[*] Fingerprinting {target}{RESET}")
    status, text, content_type, _ = request(target, ctx, args.timeout, headers=headers)
    if status is None:
        print(f"{RED}[!] Could not reach the target.{RESET}")
        return 1
    print(f"    HTTP {status}, Content-Type: {content_type or 'unset'}")
    findings["fingerprint"] = {"status": status, "content_type": content_type}

    mode = args.mode
    if mode == "auto":
        blob = (content_type + " " + text[:4000]).lower()
        mode = "soap" if any(hint in blob for hint in SOAP_HINTS) else "rest"
        # A .svc or .asmx path is SOAP regardless of what the root returned.
        if re.search(r"\.(svc|asmx)(\?|$|/)", target, re.I):
            mode = "soap"
        print(f"    Detected: {BOLD}{mode.upper()}{RESET}")
    findings["mode"] = mode

    if mode == "soap":
        run_soap(target, ctx, args.timeout, headers, findings)
    else:
        paths = [p.strip() for p in args.wordlists.split(",") if p.strip()] or DEFAULT_WORDLISTS
        words, used, missing = load_wordlists(paths)
        for path in missing:
            print(f"{YELLOW}[-] Wordlist not found, skipped: {path}{RESET}")
        if not words:
            print(f"{RED}[!] No usable wordlists. Install seclists "
                  f"(sudo apt install -y seclists) or pass --wordlists.{RESET}")
            return 1
        print(f"\n{BOLD}{CYAN}[*] REST sweep — {len(words)} unique path(s) from "
              f"{len(used)} wordlist(s){RESET}")
        for path, count in used:
            print(f"{DIM}      {count:>6} from {path}{RESET}")

        signatures = calibrate(target, ctx, args.timeout, headers)
        if signatures:
            print(f"{DIM}    Calibrated against {len(signatures)} miss signature(s) "
                  f"to filter soft-404s{RESET}")

        hits = fuzz_paths(target, words, ctx, args.timeout, args.threads, headers, signatures)
        findings["endpoints"] = hits
        print(f"\n[+] {len(hits)} endpoint(s) responded.")

        findings["verb_findings"] = fuzz_verbs(hits, ctx, args.timeout, headers,
                                               args.max_verb_checks)

    try:
        Path(args.out).write_text(json.dumps(findings, indent=2), encoding="utf-8")
        print(f"\n[i] Findings written to {args.out}")
    except OSError as exc:
        print(f"[!] Could not write {args.out}: {exc}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
