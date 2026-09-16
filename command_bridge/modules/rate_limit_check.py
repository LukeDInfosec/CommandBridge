#!/usr/bin/env python3
"""
rate_limit_check.py — Safe rate-limiting PoC tester.

Sends a modest, capped burst of requests at a controlled concurrency to the
target, and reports whether rate limiting was encountered (HTTP 429,
Retry-After headers, or other throttle-shaped responses) — producing a
console table and a JSON file suitable for pasting into a pentest report.

This replaces a previous button whose command was:
    wfuzz -z range,1-1000 {TARGET}/api -o {SAFE_TARGET}_ratelimit.txt
which was broken (no FUZZ keyword anywhere in the target for the payload
to land on — wfuzz requires one) and gave no structured pass/fail summary.

Defaults (150 requests / 10 concurrent) are deliberately modest: enough to
trip typical rate limiters (which usually threshold well under 100
requests/window) without being a meaningful load/DoS test. Both are
adjustable via flags for cases where a target's limit is known to be higher.

Usage: python3 rate_limit_check.py <url> [--requests N] [--concurrency N]
                                    [--delay SECONDS] [--timeout SECONDS]
"""
import sys
import json
import time
import argparse
import urllib.request
import urllib.error
import ssl
import concurrent.futures

RED = "\033[91m"
YELLOW = "\033[93m"
GREEN = "\033[92m"
CYAN = "\033[96m"
BOLD = "\033[1m"
DIM = "\033[2m"
RESET = "\033[0m"


def _one_request(url, timeout, ctx):
    """Fire a single request; return (status, elapsed, retry_after, error)."""
    start = time.monotonic()
    try:
        req = urllib.request.Request(
            url, headers={"User-Agent": "CommandBridge-RateLimitCheck/1.0"}, method="GET"
        )
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
            elapsed = time.monotonic() - start
            retry_after = resp.headers.get("Retry-After")
            return resp.status, elapsed, retry_after, None
    except urllib.error.HTTPError as e:
        elapsed = time.monotonic() - start
        retry_after = e.headers.get("Retry-After") if e.headers else None
        return e.code, elapsed, retry_after, None
    except Exception as e:
        elapsed = time.monotonic() - start
        return None, elapsed, None, str(e)


def main():
    ap = argparse.ArgumentParser(description="Safe rate-limiting PoC tester")
    ap.add_argument("url", help="Target URL to hit repeatedly")
    ap.add_argument("--requests", type=int, default=150, help="Total requests to send (default: 150)")
    ap.add_argument("--concurrency", type=int, default=10, help="Max in-flight requests (default: 10)")
    ap.add_argument("--delay", type=float, default=0.0, help="Extra delay (s) between dispatching each request (default: 0)")
    ap.add_argument("--timeout", type=float, default=10.0, help="Per-request timeout in seconds (default: 10)")
    ap.add_argument("--json-out", default=None, help="Optional path to also write a JSON report")
    args = ap.parse_args()

    # Sanity clamp — this tool is meant to be a safe PoC, not a load tester.
    n = max(1, min(args.requests, 2000))
    conc = max(1, min(args.concurrency, 50))

    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    print(f"\n{BOLD}{CYAN}{'═' * 62}{RESET}")
    print(f"{BOLD}  Rate Limiting PoC Test — {args.url}{RESET}")
    print(f"{BOLD}{CYAN}{'═' * 62}{RESET}\n")
    print(f"[*] Sending {n} request(s) at up to {conc} concurrent, {args.timeout}s timeout each...")
    print(f"{DIM}    (capped/modest by design — this is a detection probe, not a load test){RESET}\n")

    results = []
    start_time = time.monotonic()

    with concurrent.futures.ThreadPoolExecutor(max_workers=conc) as pool:
        futures = []
        for i in range(n):
            futures.append(pool.submit(_one_request, args.url, args.timeout, ctx))
            if args.delay:
                time.sleep(args.delay)
        completed = 0
        for fut in concurrent.futures.as_completed(futures):
            status, elapsed, retry_after, err = fut.result()
            results.append({"status": status, "elapsed": elapsed, "retry_after": retry_after, "error": err})
            completed += 1
            if completed % 25 == 0 or completed == n:
                print(f"  … {completed}/{n} sent")

    total_elapsed = time.monotonic() - start_time

    status_counts = {}
    retry_after_values = []
    errors = 0
    for r in results:
        if r["error"]:
            errors += 1
            continue
        status_counts[r["status"]] = status_counts.get(r["status"], 0) + 1
        if r["retry_after"]:
            retry_after_values.append(r["retry_after"])

    count_2xx = sum(v for k, v in status_counts.items() if k and 200 <= k < 300)
    count_429 = status_counts.get(429, 0)
    count_other_4xx5xx = sum(
        v for k, v in status_counts.items() if k and (400 <= k < 600) and k != 429
    )
    rps = n / total_elapsed if total_elapsed > 0 else 0.0

    rate_limited = count_429 > 0 or bool(retry_after_values)
    first_429_index = None
    for idx, r in enumerate(results, start=1):
        if r["status"] == 429:
            first_429_index = idx
            break

    # ── Summary table ─────────────────────────────────────────────────────────
    def row(label, value):
        return f"│ {label:<28} │ {str(value):<20} │"

    border_top = "┌" + "─" * 30 + "┬" + "─" * 22 + "┐"
    border_mid = "├" + "─" * 30 + "┼" + "─" * 22 + "┤"
    border_bot = "└" + "─" * 30 + "┴" + "─" * 22 + "┘"

    print(f"\n{BOLD}{border_top}{RESET}")
    print(f"{BOLD}{row('Metric', 'Value')}{RESET}")
    print(f"{BOLD}{border_mid}{RESET}")
    print(row("Total Requests Sent", n))
    print(row("Concurrency", conc))
    print(row("Time Elapsed", f"{total_elapsed:.2f}s"))
    print(row("Requests / sec", f"{rps:.2f}"))
    print(row("2xx Responses", count_2xx))
    print(row("429 (Too Many Requests)", count_429))
    print(row("Other 4xx/5xx", count_other_4xx5xx))
    print(row("Connection Errors", errors))
    print(row("Retry-After Seen", retry_after_values[0] if retry_after_values else "No"))
    if first_429_index:
        print(row("First 429 at request #", first_429_index))
    print(f"{BOLD}{border_bot}{RESET}\n")

    if rate_limited:
        print(f"{BOLD}{GREEN}VERDICT: Rate limiting DETECTED{RESET}")
        detail = []
        if count_429:
            detail.append(f"{count_429}x HTTP 429 response(s)")
        if retry_after_values:
            detail.append(f"Retry-After header present (e.g. {retry_after_values[0]}s)")
        print(f"{DIM}  {' + '.join(detail)}{RESET}")
        if first_429_index:
            print(f"{DIM}  Throttling began around request #{first_429_index} of {n}.{RESET}")
    else:
        print(f"{BOLD}{YELLOW}VERDICT: No rate limiting detected across {n} requests in {total_elapsed:.2f}s{RESET}")
        print(f"{DIM}  No 429s or Retry-After headers seen. This does not prove no limiting")
        print(f"{DIM}  exists — retest with a higher --requests count or against a different")
        print(f"{DIM}  endpoint/method if the target is known to rate-limit elsewhere.{RESET}")

    print(f"\n{BOLD}{'═' * 62}{RESET}\n")

    if args.json_out:
        try:
            with open(args.json_out, "w", encoding="utf-8") as f:
                json.dump({
                    "url": args.url,
                    "requests": n,
                    "concurrency": conc,
                    "elapsed_seconds": total_elapsed,
                    "requests_per_second": rps,
                    "status_counts": {str(k): v for k, v in status_counts.items()},
                    "errors": errors,
                    "retry_after_seen": retry_after_values[:1],
                    "rate_limited": rate_limited,
                    "first_429_at_request": first_429_index,
                }, f, indent=2)
            print(f"[i] JSON report written to {args.json_out}")
        except Exception as e:
            print(f"[!] Could not write JSON report: {e}")


if __name__ == "__main__":
    main()
