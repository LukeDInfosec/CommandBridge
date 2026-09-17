#!/usr/bin/env python3
"""Rate-limiting tester — replays a real request and reports what happened.

Why it works this way
─────────────────────
The previous version fired 150 bare GETs at `{TARGET}/api`. Against anything
that needs a method, a content type, auth or a body — a SOAP endpoint, say —
that produced 150 identical 4xx responses and a confident "NOT DETECTED"
verdict. 150 rejections prove nothing about rate limiting: the requests never
reached the logic that would throttle them.

So this replays a request the tester knows is good, pasted straight from a
proxy or copied as curl. And it establishes that first: one baseline request
goes out on its own, and if it does not come back successful the run stops
and says so, instead of burning 150 requests to produce a meaningless table.

None of this is a load test. The defaults are deliberately modest — enough to
trip a limiter that thresholds in the tens, not enough to be a DoS.

Usage:
    rate_limit_check.py --request-file req.txt [--base-url https://host]
    rate_limit_check.py <url>                      # simple GET, as before

    [--requests N] [--concurrency N] [--delay S] [--timeout S]
    [--json-out FILE] [--allow-error-baseline]
"""

from __future__ import annotations

import argparse
import concurrent.futures
import json
import ssl
import sys
import time
import urllib.error
import urllib.request
from collections import Counter
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from http_request import ParsedRequest, RequestParseError, parse_any  # noqa: E402

RED = "\033[91m"
YELLOW = "\033[93m"
GREEN = "\033[92m"
CYAN = "\033[96m"
BOLD = "\033[1m"
DIM = "\033[2m"
RESET = "\033[0m"

#: Responses that mean "you are being throttled". 429 is the standard one;
#: the others are what real deployments actually send — Cloudflare and
#: friends often answer with 503/403 plus a Retry-After rather than 429.
THROTTLE_CODES = {429, 503}


def build_context(insecure: bool = True):
    if not insecure:
        return None
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    return ctx


def send_once(request: ParsedRequest, timeout: float, ctx):
    """Fire one copy of the request. Returns (status, elapsed, retry_after, error)."""
    start = time.monotonic()
    try:
        req = urllib.request.Request(
            request.url, data=request.body, method=request.method,
            headers=request.headers or {"User-Agent": "CommandBridge-RateLimitCheck/2.0"},
        )
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as response:
            return response.status, time.monotonic() - start, response.headers.get("Retry-After"), None
    except urllib.error.HTTPError as exc:
        retry_after = exc.headers.get("Retry-After") if exc.headers else None
        return exc.code, time.monotonic() - start, retry_after, None
    except Exception as exc:
        return None, time.monotonic() - start, None, f"{type(exc).__name__}: {exc}"


def table(rows) -> str:
    width_left = max(len(str(a)) for a, _ in rows) + 2
    width_right = max(len(str(b)) for _, b in rows) + 2
    top = "┌" + "─" * width_left + "┬" + "─" * width_right + "┐"
    sep = "├" + "─" * width_left + "┼" + "─" * width_right + "┤"
    bottom = "└" + "─" * width_left + "┴" + "─" * width_right + "┘"
    lines = [top, f"│ {'Metric'.ljust(width_left - 2)} │ {'Value'.ljust(width_right - 2)} │", sep]
    for left, right in rows:
        lines.append(f"│ {str(left).ljust(width_left - 2)} │ {str(right).ljust(width_right - 2)} │")
    lines.append(bottom)
    return "\n".join(lines)


def main() -> int:
    parser = argparse.ArgumentParser(description="Rate-limiting detection probe")
    parser.add_argument("url", nargs="?", help="Simple mode: GET this URL")
    parser.add_argument("--request-file", help="File containing a raw HTTP request or a curl command")
    parser.add_argument("--base-url", default="", help="Scheme/host for a raw request with no Host header")
    parser.add_argument("--requests", type=int, default=150)
    parser.add_argument("--concurrency", type=int, default=10)
    parser.add_argument("--delay", type=float, default=0.0)
    parser.add_argument("--timeout", type=float, default=10.0)
    parser.add_argument("--json-out")
    parser.add_argument("--allow-error-baseline", action="store_true",
                        help="Run even if the baseline request does not succeed")
    args = parser.parse_args()

    # ── Build the request ────────────────────────────────────────────────
    if args.request_file:
        try:
            text = Path(args.request_file).read_text(encoding="utf-8", errors="replace")
            request = parse_any(text, args.base_url)
        except RequestParseError as exc:
            print(f"{RED}[!] Could not parse the request: {exc}{RESET}")
            return 2
        except OSError as exc:
            print(f"{RED}[!] Could not read {args.request_file}: {exc}{RESET}")
            return 2
    elif args.url:
        request = ParsedRequest(method="GET", url=args.url,
                                headers={"User-Agent": "CommandBridge-RateLimitCheck/2.0"})
    else:
        print(f"{RED}[!] Give a URL or --request-file.{RESET}")
        return 2

    ctx = build_context()
    print(f"{BOLD}{CYAN}[*] Request under test{RESET}")
    print(f"    {request.summary()}")
    content_type = request.header("Content-Type")
    if content_type:
        print(f"    Content-Type: {content_type}")

    # ── Baseline ─────────────────────────────────────────────────────────
    # One request, on its own, before anything else. Without this the whole
    # run can produce a confident verdict from responses that never reached
    # the application.
    print(f"\n{BOLD}[*] Baseline: sending one request to confirm it is accepted…{RESET}")
    status, elapsed, retry_after, error = send_once(request, args.timeout, ctx)

    # A raw proxy request carries only a path, so the scheme is inferred and
    # https is the right guess almost always — except for internal services on
    # odd ports, which are common on an internal engagement. Rather than fail
    # with an opaque TLS error, fall back to http once and say so.
    if error and "SSL" in error and request.url.startswith("https://"):
        http_url = "http://" + request.url[len("https://"):]
        print(f"{DIM}    https failed on TLS; retrying over http…{RESET}")
        retry = ParsedRequest(method=request.method, url=http_url,
                              headers=request.headers, body=request.body)
        status, elapsed, retry_after, retry_error = send_once(retry, args.timeout, ctx)
        if not retry_error:
            print(f"{YELLOW}    [i] Endpoint is plain HTTP — using {http_url}{RESET}")
            request = retry
            error = None
        else:
            error = retry_error

    if error:
        print(f"{RED}[!] Baseline request failed: {error}{RESET}")
        print("[i] Fix connectivity or the request itself before testing rate limiting.")
        return 1

    baseline_status = status
    print(f"    HTTP {baseline_status} in {elapsed * 1000:.0f}ms")
    baseline_ok = 200 <= (baseline_status or 0) < 400
    if not baseline_ok:
        if baseline_status in THROTTLE_CODES:
            print(f"{YELLOW}[!] The very first request was throttled (HTTP {baseline_status})."
                  f"{RESET}")
            print("[i] Either a limiter is already engaged from earlier testing, or this "
                  "endpoint throttles aggressively. Wait for the window to reset and re-run.")
            return 0
        print(f"{RED}[!] The baseline request was rejected (HTTP {baseline_status}).{RESET}")
        print("[i] Sending 150 more would produce 150 identical rejections and prove "
              "nothing about rate limiting — the requests never reach the logic that "
              "would throttle them.")
        print("[i] Paste a request you know returns a success, including method, "
              "Content-Type, auth headers and body. Re-run with --allow-error-baseline "
              "if you specifically want to test the limiter in front of the error path.")
        if not args.allow_error_baseline:
            return 1
        print(f"{YELLOW}[i] --allow-error-baseline set; continuing anyway.{RESET}")

    # ── Burst ────────────────────────────────────────────────────────────
    print(f"\n{BOLD}[*] Sending {args.requests} request(s) at up to {args.concurrency} "
          f"concurrent, {args.timeout}s timeout each…{RESET}")
    print(f"{DIM}    (capped and modest by design — a detection probe, not a load test){RESET}")

    statuses: Counter = Counter()
    errors: list[str] = []
    retry_after_values: list[str] = []
    first_throttled_at = None
    latencies: list[float] = []

    start_time = time.monotonic()
    with concurrent.futures.ThreadPoolExecutor(max_workers=args.concurrency) as pool:
        futures = {}
        for index in range(args.requests):
            if args.delay:
                time.sleep(args.delay)
            futures[pool.submit(send_once, request, args.timeout, ctx)] = index
        done = 0
        for future in concurrent.futures.as_completed(futures):
            index = futures[future]
            status, elapsed, retry_after, error = future.result()
            done += 1
            if done % 25 == 0:
                print(f"    … {done}/{args.requests} sent")
            latencies.append(elapsed)
            if error:
                errors.append(error)
                continue
            statuses[status] += 1
            if retry_after:
                retry_after_values.append(retry_after)
            if status in THROTTLE_CODES and (first_throttled_at is None or index < first_throttled_at):
                first_throttled_at = index
    duration = time.monotonic() - start_time

    # ── Report ───────────────────────────────────────────────────────────
    success = sum(count for code, count in statuses.items() if 200 <= code < 300)
    throttled = sum(count for code, count in statuses.items() if code in THROTTLE_CODES)
    client_err = sum(count for code, count in statuses.items() if 400 <= code < 500
                     and code not in THROTTLE_CODES)
    server_err = sum(count for code, count in statuses.items() if 500 <= code < 600
                     and code not in THROTTLE_CODES)

    breakdown = ", ".join(f"{code}×{count}" for code, count in sorted(statuses.items()))
    rows = [
        ("Baseline response", f"HTTP {baseline_status} "
                              f"({'accepted' if baseline_ok else 'rejected'})"),
        ("Total Requests Sent", args.requests),
        ("Concurrency", args.concurrency),
        ("Time Elapsed", f"{duration:.2f}s"),
        ("Requests / sec", f"{args.requests / duration:.2f}" if duration else "n/a"),
        ("Median latency", f"{sorted(latencies)[len(latencies) // 2] * 1000:.0f}ms" if latencies else "n/a"),
        ("2xx Responses", success),
        ("Throttled (429/503)", throttled),
        ("Other 4xx", client_err),
        ("Other 5xx", server_err),
        ("Connection Errors", len(errors)),
        ("Retry-After Seen", retry_after_values[0] if retry_after_values else "No"),
        ("Status breakdown", breakdown or "none"),
    ]
    print()
    print(table(rows))

    print()
    if throttled:
        print(f"{GREEN}{BOLD}[+] RATE LIMITING DETECTED{RESET}")
        print(f"    {throttled} of {args.requests} requests were throttled"
              + (f", first at request ~{first_throttled_at + 1}" if first_throttled_at is not None else "")
              + ".")
        if retry_after_values:
            print(f"    Retry-After: {retry_after_values[0]}")
        verdict = "detected"
    elif success == 0 and not baseline_ok:
        print(f"{YELLOW}{BOLD}[!] INCONCLUSIVE{RESET}")
        print("    No request succeeded, so nothing exercised the rate limiter.")
        verdict = "inconclusive"
    elif success == 0:
        print(f"{YELLOW}{BOLD}[!] INCONCLUSIVE{RESET}")
        print("    The baseline succeeded but none of the burst did — the endpoint may "
              "be failing for another reason (session expiry, replay protection, a "
              "nonce or timestamp in the body).")
        verdict = "inconclusive"
    else:
        print(f"{YELLOW}{BOLD}[-] NO RATE LIMITING DETECTED{RESET}")
        print(f"    {success} of {args.requests} requests succeeded at "
              f"{args.requests / duration:.0f} req/sec with no throttling response.")
        print("    Worth reporting: an unauthenticated or authenticated endpoint that "
              "accepts this rate invites credential stuffing, enumeration and "
              "resource exhaustion.")
        verdict = "not detected"

    if args.json_out:
        report = {
            "url": request.url,
            "method": request.method,
            "content_type": content_type,
            "baseline_status": baseline_status,
            "baseline_accepted": baseline_ok,
            "requests": args.requests,
            "concurrency": args.concurrency,
            "duration_seconds": round(duration, 3),
            "requests_per_second": round(args.requests / duration, 2) if duration else None,
            "status_counts": {str(k): v for k, v in sorted(statuses.items())},
            "throttled": throttled,
            "retry_after": retry_after_values[:5],
            "connection_errors": errors[:5],
            "verdict": verdict,
        }
        try:
            Path(args.json_out).write_text(json.dumps(report, indent=2), encoding="utf-8")
            print(f"\n[i] JSON report written to {args.json_out}")
        except OSError as exc:
            print(f"[!] Could not write {args.json_out}: {exc}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
