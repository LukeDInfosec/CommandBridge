#!/usr/bin/env python3
"""crt.sh certificate-transparency subdomain lookup.

Why this is a script and not a one-liner
────────────────────────────────────────
This used to be `curl -s ... | python3 -c "json.load(sys.stdin)..."` piped
into sort. crt.sh is heavily rate-limited and frequently answers with an HTML
error page, a Cloudflare challenge, a 502, or simply nothing — and every one
of those made json.load() raise, dumping a twelve-line Python traceback into
the console. A traceback is the worst possible way to say "the service is
busy, try again in a minute": it reads like the app is broken.

So: one request, retried on the failures that are worth retrying, and a plain
sentence for every way it can go wrong.

Usage:
    python3 crtsh.py <domain> [--timeout 45] [--retries 3]

Prints one name per line, deduplicated and sorted, wildcards stripped.
Exit codes: 0 found something, 1 an error worth reading, 2 nothing found.
"""

from __future__ import annotations

import argparse
import json
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

# crt.sh returns a Cloudflare challenge to obviously-scripted clients, so send
# a normal browser UA. gzip matters too: a busy domain's response is large and
# crt.sh is slow enough without transferring it uncompressed.
HEADERS = {
    "User-Agent": ("Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
                   "(KHTML, like Gecko) Chrome/125.0 Safari/537.36"),
    "Accept": "application/json, text/plain, */*",
    "Accept-Encoding": "gzip, deflate",
}


def fetch(domain: str, timeout: int) -> tuple[int, str]:
    """Return (http_status, body). Network-level failures come back as (0, msg)."""
    query = urllib.parse.urlencode({"q": f"%.{domain}", "output": "json"})
    url = f"https://crt.sh/?{query}"
    request = urllib.request.Request(url, headers=HEADERS)
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            raw = response.read()
            if response.headers.get("Content-Encoding") == "gzip":
                import gzip
                raw = gzip.decompress(raw)
            return response.status, raw.decode("utf-8", errors="replace")
    except urllib.error.HTTPError as exc:
        return exc.code, ""
    except urllib.error.URLError as exc:
        return 0, str(exc.reason)
    except TimeoutError:
        return 0, "timed out"
    except Exception as exc:  # pragma: no cover - defensive
        return 0, f"{type(exc).__name__}: {exc}"


def parse(body: str) -> list[str]:
    """Pull every name out of a crt.sh JSON response.

    One certificate can cover many names, newline-separated inside
    name_value, and the same name appears across every certificate ever
    issued for it — hence the set.
    """
    data = json.loads(body)
    names: set[str] = set()
    for entry in data:
        for name in (entry.get("name_value") or "").split():
            name = name.strip().lower().lstrip("*.")
            if name:
                names.add(name)
    return sorted(names)


def main() -> int:
    parser = argparse.ArgumentParser(description="crt.sh subdomain lookup")
    parser.add_argument("domain")
    parser.add_argument("--timeout", type=int, default=45)
    parser.add_argument("--retries", type=int, default=3)
    args = parser.parse_args()

    domain = args.domain.strip().strip("/")
    if not domain or "." not in domain:
        print(f"[!] '{args.domain}' does not look like a domain.", file=sys.stderr)
        return 1

    last = "no attempt made"
    for attempt in range(1, args.retries + 1):
        status, body = fetch(domain, args.timeout)

        if status == 200 and body.strip():
            try:
                names = parse(body)
            except json.JSONDecodeError:
                # A 200 that is not JSON means an interstitial or an error
                # page. Worth one more go, but show what came back rather
                # than pretending the response was empty.
                last = ("crt.sh returned a 200 that was not JSON "
                        f"(starts: {body.strip()[:80]!r})")
            else:
                if not names:
                    print(f"[i] No certificates found for {domain}.", file=sys.stderr)
                    return 2
                print("\n".join(names))
                print(f"[i] {len(names)} unique name(s) from certificate "
                      f"transparency for {domain}.", file=sys.stderr)
                return 0

        elif status == 200:
            last = "crt.sh returned an empty response"
        elif status in (429, 502, 503, 504):
            last = f"crt.sh is rate-limiting or overloaded (HTTP {status})"
        elif status:
            last = f"crt.sh returned HTTP {status}"
        else:
            last = f"could not reach crt.sh ({body})"

        if attempt < args.retries:
            # crt.sh recovers on the order of seconds, not milliseconds, and
            # hammering it is what got us rate-limited in the first place.
            delay = attempt * 5
            print(f"[i] {last} — retrying in {delay}s "
                  f"({attempt}/{args.retries - 1})…", file=sys.stderr)
            time.sleep(delay)

    print(f"[!] {last}.", file=sys.stderr)
    if "could not reach" in last:
        print("[i] That is a connectivity problem rather than crt.sh being "
              "busy — check DNS, a proxy, or whether egress to crt.sh is "
              "filtered from this host.", file=sys.stderr)
    else:
        print("[i] crt.sh rate-limits aggressively; it is usually worth "
              "another try in a minute.", file=sys.stderr)
    print("[i] Subfinder and Amass cover the same ground without depending "
          "on crt.sh.", file=sys.stderr)
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
