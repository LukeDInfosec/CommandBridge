#!/usr/bin/env bash
# param_finder.sh — collect URLs and extract unique query-string parameter names.
#
# Usage:
#   param_finder.sh --mode dev|live --target <url> --output <file>
#
# Modes:
#   dev   Historical data only (waybackurls + gau). Fast, no live traffic.
#   live  Real-time crawl (katana) supplemented with gau. Generates live requests.

set -euo pipefail

MODE=""
TARGET=""
OUTPUT=""

while [[ $# -gt 0 ]]; do
    case "$1" in
        --mode)   MODE="$2";   shift 2 ;;
        --target) TARGET="$2"; shift 2 ;;
        --output) OUTPUT="$2"; shift 2 ;;
        *) echo "[!] Unknown argument: $1" >&2; exit 1 ;;
    esac
done

if [[ -z "$MODE" || -z "$TARGET" || -z "$OUTPUT" ]]; then
    echo "[!] Usage: param_finder.sh --mode dev|live --target <url> --output <file>" >&2
    exit 1
fi

if [[ "$MODE" != "dev" && "$MODE" != "live" ]]; then
    echo "[!] --mode must be 'dev' or 'live'" >&2
    exit 1
fi

# Derive bare hostname (strip scheme, path, port)
HOST=$(printf '%s' "$TARGET" | sed 's|https\?://||' | cut -d'/' -f1 | cut -d':' -f1)

echo "[*] Parameter Finder ($MODE mode)"
echo "[*] Target : $TARGET"
echo "[*] Host   : $HOST"
echo "[*] Output : $OUTPUT"
echo ""

TMP_URLS=$(mktemp /tmp/param_finder_urls.XXXXXX)
trap 'rm -f "$TMP_URLS"' EXIT

# ── Step 1: collect URLs ──────────────────────────────────────────────────────
echo "[*] Collecting URLs..."

if [[ "$MODE" == "dev" ]]; then
    if command -v waybackurls >/dev/null 2>&1; then
        echo "$HOST" | waybackurls 2>/dev/null | sort -u >> "$TMP_URLS"
        echo "[+] waybackurls: done"
    else
        echo "[!] waybackurls not found — skipping"
    fi
    if command -v gau >/dev/null 2>&1; then
        gau "$HOST" --threads 3 --retries 2 2>/dev/null | sort -u >> "$TMP_URLS"
        echo "[+] gau: done"
    else
        echo "[!] gau not found — skipping"
    fi
else
    if command -v katana >/dev/null 2>&1; then
        katana -u "$TARGET" -d 3 -jc -kf all -c 5 -timeout 10 -silent 2>/dev/null \
            | sort -u >> "$TMP_URLS"
        echo "[+] katana: done"
    else
        echo "[!] katana not found — skipping"
    fi
    if command -v gau >/dev/null 2>&1; then
        gau "$HOST" --threads 3 --retries 2 --subs 2>/dev/null | sort -u >> "$TMP_URLS"
        echo "[+] gau (supplementary): done"
    else
        echo "[!] gau not found — skipping"
    fi
fi

TOTAL_URLS=$(wc -l < "$TMP_URLS")
echo "[*] Total URLs collected: $TOTAL_URLS"
echo ""

if [[ "$TOTAL_URLS" -eq 0 ]]; then
    echo "[!] No URLs collected — verify the target is reachable and tools are installed."
    exit 0
fi

# ── Step 2: filter URLs that carry at least one query parameter ──────────────
echo "[*] Filtering parameterised URLs..."
PARAM_URLS=$(grep '?' "$TMP_URLS" | sort -u || true)
PARAM_URL_COUNT=$(printf '%s\n' "$PARAM_URLS" | grep -c . || true)
echo "[+] Parameterised URLs : $PARAM_URL_COUNT"

# ── Step 3: extract unique parameter names ───────────────────────────────────
echo "[*] Extracting unique parameter names..."
PARAMS=$(printf '%s\n' "$PARAM_URLS" | grep -oP '[?&]\K[^=&]+(?==)' | sort -u || true)
PARAM_COUNT=$(printf '%s\n' "$PARAMS" | grep -c . || true)
echo "[+] Unique parameters  : $PARAM_COUNT"

# ── Step 4: write report ─────────────────────────────────────────────────────
{
    echo "=== Parameter Finder Report ==="
    echo "Mode   : $MODE"
    echo "Target : $TARGET"
    echo "Host   : $HOST"
    echo ""
    echo "=== Unique Parameter Names ($PARAM_COUNT) ==="
    printf '%s\n' "$PARAMS"
    echo ""
    echo "=== URLs with Parameters ($PARAM_URL_COUNT) ==="
    printf '%s\n' "$PARAM_URLS"
} > "$OUTPUT"

echo ""
echo "[*] Results written to: $OUTPUT"
echo "[*] Done."
