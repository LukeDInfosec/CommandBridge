#!/usr/bin/env python3
"""
ffuf_clean.py — turn an ffuf "-of json" result file into a clean, plain-text
list of findings: "[STATUS] URL", one per line, sorted by status then URL.

Command Bridge runs ffuf with -of json so nothing is lost or mis-parsed, then
pipes the raw JSON through this script to produce the file the user actually
wants to open — no ffuf JSON metadata (duration, resultfile, scraper,
position, words/lines counters, redirectlocation, host, ...), just the
findings, in the exact form that can be highlighted in the console and
pasted straight into a report or a browser.

Soft-404 / wildcard backstop: the ffuf command Command Bridge runs already
passes -ac (auto-calibrate), which is ffuf's own fix for a server that
returns HTTP 200 with the *same* body for literally every path — but -ac's
calibration probes a handful of random paths up front, and some servers
respond differently to "obviously random junk" vs. "a real dictionary word
that just happens not to be a real page", so it doesn't always catch every
case. As a backstop, this script also groups all results by response length:
if one exact byte size accounts for a large chunk of the results, that's
almost certainly one static/soft-404 page being served for every one of
those paths, not 500 separate real endpoints. Those get pulled out into a
clearly-labelled section at the bottom instead of being silently deleted —
so nothing is lost, but the signal (genuinely distinct pages) isn't buried
under hundreds of copies of the same "not found" page.

Usage: ffuf_clean.py <raw_json_file> [clean_txt_file]
Prints the clean lines to stdout (so the caller can see them in the console)
and, if a second argument is given, also writes them to that file.
"""
import sys
import json
from collections import Counter

# A response length is treated as a likely soft-404/wildcard page when it
# accounts for at least this many results AND at least this fraction of all
# results — both conditions have to hold, so a handful of genuinely-identical
# small real pages (e.g. several blank stub pages) won't get swept up, but a
# catch-all responder serving the bulk of the wordlist will.
_SUSPECT_MIN_COUNT = 5
_SUSPECT_MIN_FRACTION = 0.25


def main():
    if len(sys.argv) < 2:
        print("[!] Usage: ffuf_clean.py <raw_json_file> [clean_txt_file]", file=sys.stderr)
        sys.exit(1)

    raw_path = sys.argv[1]
    out_path = sys.argv[2] if len(sys.argv) > 2 else None

    try:
        with open(raw_path, "r", encoding="utf-8", errors="replace") as f:
            data = json.load(f)
    except Exception as e:
        print(f"[!] Could not parse ffuf JSON output ({raw_path}): {e}", file=sys.stderr)
        # Still write an (empty-ish) clean file so downstream tooling that
        # expects it to exist doesn't also fail.
        if out_path:
            try:
                with open(out_path, "w", encoding="utf-8") as f:
                    f.write(f"[!] Could not parse ffuf output: {e}\n")
            except Exception:
                pass
        sys.exit(1)

    results = data.get("results", []) or []
    rows = []
    for r in results:
        status = r.get("status", "?")
        url = r.get("url", "")
        length = r.get("length")
        words = r.get("words")
        rows.append((str(status), url, length, words))

    total = len(rows)
    length_counts = Counter(r[2] for r in rows if r[2] is not None)

    suspect_lengths = {
        length
        for length, count in length_counts.items()
        if count >= _SUSPECT_MIN_COUNT and total > 0 and (count / total) >= _SUSPECT_MIN_FRACTION
    }

    def fmt(row):
        status, url, length, words = row
        extra = f"  (len={length}, words={words})" if length is not None else ""
        return f"[{status}] {url}{extra}"

    main_rows = [r for r in rows if r[2] not in suspect_lengths]
    suspect_rows = [r for r in rows if r[2] in suspect_lengths]

    main_rows.sort(key=lambda r: (r[0], r[1]))
    suspect_rows.sort(key=lambda r: (r[0], r[1]))

    out_lines = [fmt(r) for r in main_rows]
    if not out_lines:
        out_lines = ["No matches found (0 results)." if not suspect_rows else
                      "No genuine findings — every match looked like a soft-404/wildcard page (see below)."]

    if suspect_lengths:
        out_lines.append("")
        out_lines.append("=" * 70)
        for length in sorted(suspect_lengths):
            count = length_counts[length]
            out_lines.append(
                f"[FILTERED] {count} of {total} results were {length} bytes — almost "
                f"certainly one soft-404/wildcard page served for every one of those "
                f"paths, not {count} real endpoints. Listed separately, not deleted:"
            )
        out_lines.append("=" * 70)
        for r in suspect_rows:
            out_lines.append("  " + fmt(r))

    for line in out_lines:
        print(line)

    if out_path:
        try:
            with open(out_path, "w", encoding="utf-8") as f:
                for line in out_lines:
                    f.write(line + "\n")
        except Exception as e:
            print(f"[!] Could not write clean output file {out_path}: {e}", file=sys.stderr)


if __name__ == "__main__":
    main()
