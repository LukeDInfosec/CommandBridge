#!/usr/bin/env python3
"""
SmartFuzz — Intelligent Adaptive Web Fuzzer
Detects the underlying server/technology stack from response headers and
discovered paths, then automatically switches to the most appropriate
wordlist for deep enumeration.

Flow:
  Phase 0 — Single HTTP probe: read Server/X-Powered-By headers.
             If a known technology is identified, skip Phase 1.
  Phase 1 — Generic scan (common.txt). Stops the moment a technology
             signature path is found and transitions immediately to Phase 2.
  Phase 2 — Technology-specific deep scan with the matched wordlist.
"""

import sys
import json
import subprocess
import re
import argparse
import ssl
import urllib.request
import urllib.error
import time
from pathlib import Path


# Strips ANSI escape/colour codes (some ffuf builds colourise their progress
# line even when stdout is piped, not just when connected to a real TTY).
_ANSI_RE = re.compile(r'\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])')

# Matches ffuf's live progress/status line regardless of any leading noise
# left after ANSI-stripping, e.g.:
#   :: Progress: [36/41] :: Job [1/1] :: 0 req/sec :: Duration: [0:00:00] :: Errors: 0 ::
_PROGRESS_RE = re.compile(r'::\s*Progress:.*::\s*Errors:\s*\d+\s*::')


# ── Colours ───────────────────────────────────────────────────────────────────

class C:
    HEADER  = '\033[95m'
    BLUE    = '\033[94m'
    CYAN    = '\033[96m'
    GREEN   = '\033[92m'
    YELLOW  = '\033[93m'
    RED     = '\033[91m'
    BOLD    = '\033[1m'
    END     = '\033[0m'


# ── Wordlist constants ────────────────────────────────────────────────────────

_WC = '/usr/share/seclists/Discovery/Web-Content'
_WS = f'{_WC}/Web-Servers'
_CM = f'{_WC}/CMS'

INITIAL_WORDLIST  = f'{_WC}/common.txt'
FALLBACK_WORDLIST = f'{_WC}/raft-small-words.txt'


# ── Technology signatures ─────────────────────────────────────────────────────

SIGNATURES = {
    'wordpress': {
        'paths':    ['/wp-admin', '/wp-content', '/wp-includes', '/wp-login.php', '/xmlrpc.php'],
        'headers':  [],
        'wordlist': f'{_CM}/trickest-cms-wordlist/wordpress.txt',
        'priority': 10,
    },
    'drupal': {
        'paths':    ['/user/login', '/node', '/modules', '/sites/default', '/admin/config'],
        'headers':  ['drupal'],
        'wordlist': f'{_CM}/trickest-cms-wordlist/drupal.txt',
        'priority': 9,
    },
    'joomla': {
        'paths':    ['/administrator', '/components', '/modules', '/templates', '/plugins'],
        'headers':  ['joomla'],
        'wordlist': f'{_CM}/trickest-cms-wordlist/joomla.txt',
        'priority': 9,
    },
    'laravel': {
        'paths':    ['/storage', '/.env', '/artisan', '/vendor', '/public'],
        'headers':  ['laravel'],
        'wordlist': f'{_CM}/trickest-cms-wordlist/laravel.txt',
        'priority': 8,
    },
    'tomcat': {
        'paths':    ['/manager/html', '/host-manager', '/manager/status'],
        'headers':  ['apache-coyote', 'tomcat'],
        'wordlist': f'{_WS}/Apache-Tomcat.txt',
        'priority': 8,
    },
    'nginx': {
        'paths':    ['/nginx_status', '/server-status'],
        'headers':  ['nginx'],
        'wordlist': f'{_WS}/nginx.txt',
        'priority': 7,
    },
    'apache': {
        'paths':    ['/server-status', '/server-info', '/cgi-bin/', '/.htaccess'],
        'headers':  ['apache/', 'apache '],
        'wordlist': f'{_WS}/Apache.txt',
        'priority': 7,
    },
    'iis': {
        'paths':    ['/aspnet_client', '/iisstart.htm', '/web.config'],
        'headers':  ['microsoft-iis', 'iis/'],
        'wordlist': f'{_WS}/IIS.txt',
        'priority': 7,
    },
}


# ── SmartFuzz ─────────────────────────────────────────────────────────────────

class SmartFuzz:
    """Intelligent adaptive fuzzer that detects technology and switches wordlists."""

    def __init__(self, target, initial_wordlist=None, threads=10, timeout=10,
                 auth_header=None):
        self.target          = target.rstrip('/')
        self.initial_wordlist = initial_wordlist or INITIAL_WORDLIST
        self.threads         = threads
        self.timeout         = timeout
        self.auth_header     = auth_header
        self.discovered_paths: list[str] = []
        self.scanned_with:    set[str]   = set()

    # ── Banner / config ───────────────────────────────────────────────────────

    def _banner(self):
        print(f"""
{C.CYAN}{C.BOLD}
  ███████╗███╗   ███╗ █████╗ ██████╗ ████████╗███████╗██╗   ██╗███████╗███████╗
  ██╔════╝████╗ ████║██╔══██╗██╔══██╗╚══██╔══╝██╔════╝██║   ██║╚════██║╚════██║
  ███████╗██╔████╔██║███████║██████╔╝   ██║   █████╗  ██║   ██║    ██╔╝    ██╔╝
  ╚════██║██║╚██╔╝██║██╔══██║██╔══██╗   ██║   ██╔══╝  ██║   ██║   ██╔╝    ██╔╝
  ███████║██║ ╚═╝ ██║██║  ██║██║  ██║   ██║   ██║     ╚██████╔╝   ██║     ██║
  ╚══════╝╚═╝     ╚═╝╚═╝  ╚═╝╚═╝  ╚═╝   ╚═╝   ╚═╝      ╚═════╝    ╚═╝     ╚═╝
{C.END}{C.GREEN}  Intelligent Adaptive Web Fuzzer — auto-detects stack, auto-switches wordlist{C.END}
{C.BLUE}  ════════════════════════════════════════════════════════════════════════════{C.END}
""")

    def _print_config(self):
        wl_name = Path(self.initial_wordlist).name if Path(self.initial_wordlist).exists() else self.initial_wordlist
        print(f"  {C.BOLD}Target  :{C.END}  {self.target}")
        print(f"  {C.BOLD}Wordlist:{C.END}  {wl_name}  (initial)")
        print(f"  {C.BOLD}Threads :{C.END}  {self.threads}")
        print(f"  {C.BOLD}Timeout :{C.END}  {self.timeout}s")
        if self.auth_header:
            print(f"  {C.BOLD}Auth    :{C.END}  Custom header set")
        print()

    # ── Phase 0: Header probe ─────────────────────────────────────────────────

    def detect_from_headers(self):
        """
        Probe the target root and inspect response headers.
        Returns (tech_name_or_None, server_string).
        """
        print(f"{C.CYAN}[*] Probing {self.target} for server fingerprint…{C.END}")
        try:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode    = ssl.CERT_NONE

            req = urllib.request.Request(
                self.target,
                headers={'User-Agent': 'Mozilla/5.0 (SmartFuzz/2.0)'},
            )
            with urllib.request.urlopen(req, timeout=self.timeout, context=ctx) as resp:
                server    = (resp.getheader('Server',       '') or '').lower()
                powered   = (resp.getheader('X-Powered-By', '') or '').lower()
                aspnet    = (resp.getheader('X-AspNet-Version', '') or '').lower()
                via       = (resp.getheader('Via',          '') or '').lower()
                combined  = f"{server} {powered} {aspnet} {via}"

                for tech, info in SIGNATURES.items():
                    for sig in info.get('headers', []):
                        if sig.lower() in combined:
                            display = server or powered or '(detected via headers)'
                            print(f"  {C.BOLD}Server header:{C.END}  {display}")
                            return tech, display

                display = server or powered or '(not disclosed)'
                print(f"  {C.BOLD}Server header:{C.END}  {display}")
                return None, display

        except Exception as e:
            print(f"{C.YELLOW}[!] Probe failed: {e}{C.END}")
            return None, ''

    # ── Path-based signature check ────────────────────────────────────────────

    def _path_matches_tech(self, path: str):
        """Return tech name if path matches any known signature, else None."""
        path_lower = path.lower()
        best_tech, best_pri = None, -1
        for tech, info in SIGNATURES.items():
            for sig_path in info['paths']:
                if sig_path.lower() in path_lower:
                    if info['priority'] > best_pri:
                        best_tech, best_pri = tech, info['priority']
        return best_tech

    # ── ffuf runner ───────────────────────────────────────────────────────────

    def _run_ffuf(self, wordlist: str, description: str, stop_on_detect: bool = False):
        """
        Run ffuf against self.target/FUZZ using the given wordlist.

        Uses -json so output is newline-delimited JSON — no regex fragility.
        Drops the -sf / -se flags that caused premature termination.

        Returns (found_paths, detected_tech_or_None).
        detected_tech is set only when stop_on_detect=True and a signature
        path was found; in that case ffuf is killed immediately.
        """
        if not Path(wordlist).exists():
            print(f"{C.RED}[!] Wordlist not found: {wordlist}{C.END}")
            return [], None

        print(f"\n{C.YELLOW}{C.BOLD}[*] {description}{C.END}")
        print(f"{C.CYAN}[*] Wordlist : {Path(wordlist).name}  ({self._wl_size(wordlist)} entries){C.END}")
        print(f"{C.CYAN}[*] Target   : {self.target}/FUZZ{C.END}\n")

        cmd_parts = [
            'ffuf',
            '-u',       f'{self.target}/FUZZ',
            '-w',       wordlist,
            '-t',       str(self.threads),
            '-timeout', str(self.timeout),
            '-mc',      '200,201,204,301,302,307,308,401,403',
            '-fc',      '404,500',
            '-noninteractive',
            '-s',       # silent — suppresses ffuf's own banner/progress bar
                        # at the source. Without this, ffuf keeps printing
                        # ":: Progress: ... ::" between every JSON result no
                        # matter what gets filtered on our end, which is what
                        # was spamming the console. The Python-side filter
                        # below is kept as a second line of defence.
            '-json',
        ]
        if self.auth_header:
            cmd_parts.extend(['-H', self.auth_header])

        # Run ffuf directly (no shell pipe) so this works on any platform and
        # ffuf's raw JSON can never leak past us. stderr is merged into stdout
        # so genuine errors are visible; progress lines are filtered in Python.
        try:
            proc = subprocess.Popen(
                cmd_parts,
                shell=False,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                universal_newlines=True,
                bufsize=1,
            )
        except Exception as e:
            print(f"{C.RED}[!] Failed to start ffuf: {e}{C.END}")
            return [], None

        found_paths: list[tuple[str, str]] = []
        early_tech: str | None = None
        hits = 0
        last_progress = time.time()

        for raw_line in proc.stdout:
            # Strip ANSI colour codes first — some ffuf builds colourise the
            # progress line even when stdout is piped (not just on a real
            # TTY), which otherwise defeats a plain startswith('::') check
            # since the line then starts with an escape sequence instead.
            line = _ANSI_RE.sub('', raw_line).rstrip('\n')
            if not line.strip():
                continue

            # Drop ffuf's status/progress chatter (':: Progress: ...', etc.)
            # so the console only ever shows discovered URLs. Matched by
            # content, not just a startswith('::') prefix check, so it still
            # catches the line even if something else is glued in front of it.
            if line.lstrip().startswith('::') or _PROGRESS_RE.search(line):
                continue

            # Progress heartbeat every 5 min
            now = time.time()
            if now - last_progress >= 300:
                print(f"{C.YELLOW}[⏳] Still scanning — {hits} hits so far…{C.END}")
                last_progress = now

            # Try to parse as JSON (ffuf -json result record)
            try:
                data = json.loads(line)
                if 'status' not in data or 'url' not in data:
                    continue

                url_str = data.get('url', '')
                status  = str(data.get('status', ''))
                path    = url_str.replace(self.target, '') or '/'
                if not path.startswith('/'):
                    path = '/' + path

                found_paths.append((status, path))
                self.discovered_paths.append(path)
                hits += 1

                full_url = f"{self.target}{path}"
                if status == '200':
                    print(f"  {C.GREEN}[{status}]{C.END}  {full_url}")
                elif status.startswith('3'):
                    print(f"  {C.YELLOW}[{status}]{C.END}  {full_url}")
                elif status.startswith('4'):
                    print(f"  {C.RED}[{status}]{C.END}  {full_url}")
                else:
                    print(f"  [{status}]  {full_url}")

                # Check for technology signature match
                if stop_on_detect:
                    tech = self._path_matches_tech(path)
                    if tech:
                        print(
                            f"\n  {C.GREEN}{C.BOLD}[✓] Signature match: "
                            f"'{path}' → {tech.upper()}{C.END}"
                        )
                        print(
                            f"  {C.YELLOW}[→] Stopping generic scan — "
                            f"switching to {tech.upper()}-specific wordlist{C.END}\n"
                        )
                        early_tech = tech
                        proc.kill()
                        proc.wait()
                        return found_paths, early_tech

            except (json.JSONDecodeError, ValueError):
                # Non-JSON line: ffuf banner, info message, etc.
                stripped = line.strip()
                if stripped and not stripped.startswith('::'):
                    print(line)

        proc.wait()
        return found_paths, early_tech

    @staticmethod
    def _wl_size(wordlist: str) -> str:
        try:
            n = sum(1 for _ in open(wordlist, encoding='utf-8', errors='ignore'))
            return f'{n:,}'
        except Exception:
            return '?'

    # ── Phase 1 path analysis (fallback) ─────────────────────────────────────

    def _analyse_paths(self, paths: list[tuple[str, str]]) -> dict:
        """Score discovered paths against all signatures. Returns {tech: info}."""
        detected: dict = {}
        for tech, info in SIGNATURES.items():
            matches: list[str] = []
            for status, path in paths:
                path_lower = path.lower()
                for sig_path in info['paths']:
                    if sig_path.lower() in path_lower:
                        matches.append(path)
            if matches:
                detected[tech] = {
                    'matches':  len(matches),
                    'paths':    matches,
                    'wordlist': info['wordlist'],
                    'priority': info['priority'],
                }
        return detected

    # ── Main run ──────────────────────────────────────────────────────────────

    def run(self):
        self._banner()
        self._print_config()

        sep = f"{C.BLUE}{'═' * 68}{C.END}"

        # ── Phase 0: Header fingerprinting ────────────────────────────────────
        print(sep)
        print(f"{C.BOLD}  PHASE 0 — Server Fingerprinting{C.END}")
        print(sep)

        detected_tech, server_str = self.detect_from_headers()

        if detected_tech:
            print(
                f"\n  {C.GREEN}{C.BOLD}[✓] Server identified: "
                f"{detected_tech.upper()}{C.END}  (from response headers)"
            )
            print(
                f"  {C.YELLOW}[→] Skipping generic scan — jumping straight to "
                f"{detected_tech.upper()}-specific wordlist{C.END}\n"
            )
            phase1_results: list[tuple[str, str]] = []
        else:
            print(f"\n  {C.YELLOW}[!] Server type not identified from headers — starting generic discovery{C.END}\n")

            # ── Phase 1: Generic scan with real-time detection ─────────────────
            print(sep)
            print(f"{C.BOLD}  PHASE 1 — Generic Discovery  (stops on first signature match){C.END}")
            print(sep)

            phase1_results, detected_tech = self._run_ffuf(
                self.initial_wordlist,
                "Generic broad scan",
                stop_on_detect=True,
            )
            self.scanned_with.add(self.initial_wordlist)

            if not detected_tech:
                # No real-time signature found; check path patterns in bulk
                if phase1_results:
                    detected_map = self._analyse_paths(phase1_results)
                    if detected_map:
                        best = max(detected_map.items(), key=lambda x: x[1]['priority'])
                        detected_tech = best[0]
                        print(
                            f"\n  {C.GREEN}[✓] Technology inferred from paths: "
                            f"{detected_tech.upper()}{C.END}"
                        )
                    else:
                        print(
                            f"\n  {C.YELLOW}[!] No technology signature detected — "
                            f"results saved as-is{C.END}"
                        )
                else:
                    print(f"\n  {C.YELLOW}[!] No endpoints found in generic scan{C.END}")

        # ── Phase 2: Technology-specific deep scan ─────────────────────────────
        if detected_tech:
            print(sep)
            print(f"{C.BOLD}  PHASE 2 — Adaptive Deep Scan  [{detected_tech.upper()}]{C.END}")
            print(sep)

            info     = SIGNATURES.get(detected_tech, {})
            wordlist = info.get('wordlist', '')

            if wordlist and Path(wordlist).exists() and wordlist not in self.scanned_with:
                self._run_ffuf(
                    wordlist,
                    f"{detected_tech.upper()}-specific deep scan",
                    stop_on_detect=False,
                )
                self.scanned_with.add(wordlist)
            else:
                if wordlist and not Path(wordlist).exists():
                    print(f"\n  {C.YELLOW}[!] Wordlist missing: {wordlist}{C.END}")

                # Fall back to broad wordlist
                fallback = FALLBACK_WORDLIST
                if fallback not in self.scanned_with and Path(fallback).exists():
                    print(f"  {C.CYAN}[*] Falling back to: {Path(fallback).name}{C.END}")
                    self._run_ffuf(fallback, "Broad fallback scan", stop_on_detect=False)
                    self.scanned_with.add(fallback)

        # ── Summary ────────────────────────────────────────────────────────────
        self._print_summary(detected_tech)

    def _print_summary(self, detected_tech):
        sep = f"{C.GREEN}{'═' * 68}{C.END}"
        print(f"\n{sep}")
        print(f"{C.BOLD}  SCAN COMPLETE{C.END}")
        print(sep)
        print(f"  {C.BOLD}Total endpoints found  :{C.END}  {len(self.discovered_paths)}")
        print(f"  {C.BOLD}Technology detected    :{C.END}  {detected_tech.upper() if detected_tech else 'Unknown'}")
        print(f"  {C.BOLD}Wordlists used         :{C.END}  {len(self.scanned_with)}")
        print(f"{sep}\n")


# ── CLI entry point ───────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description='SmartFuzz — Intelligent Adaptive Web Fuzzer',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='''
Examples:
  smartfuzz.py -u https://example.com
  smartfuzz.py -u https://example.com -w /path/to/wordlist.txt -t 20
  smartfuzz.py -u https://example.com -H "Authorization: Bearer TOKEN"
        ''',
    )
    parser.add_argument('-u', '--url', required=True, help='Target URL')
    parser.add_argument('-w', '--wordlist', default=INITIAL_WORDLIST,
                        help=f'Initial wordlist (default: {Path(INITIAL_WORDLIST).name})')
    parser.add_argument('-t', '--threads', type=int, default=10,
                        help='Number of threads (default: 10)')
    parser.add_argument('-timeout', type=int, default=10,
                        help='Request timeout in seconds (default: 10)')
    parser.add_argument('-H', '--header', help='Custom header, e.g. "Authorization: Bearer TOKEN"')
    parser.add_argument('--wl', action='append', default=[], metavar='TECH=PATH',
                        help='Override the wordlist for a detected technology, '
                             'e.g. --wl nginx=/path/nginx.txt (repeatable). '
                             'Valid TECH: ' + ', '.join(SIGNATURES.keys()))

    args = parser.parse_args()

    # Apply per-technology wordlist overrides so users can point each
    # architecture at wordlists stored anywhere on their system.
    for item in args.wl:
        if '=' not in item:
            continue
        tech, path = item.split('=', 1)
        tech, path = tech.strip().lower(), path.strip()
        if tech in SIGNATURES and path:
            SIGNATURES[tech]['wordlist'] = path
            print(f"{C.CYAN}[*] Wordlist override: {tech} -> {path}{C.END}")

    fuzzer = SmartFuzz(
        target=args.url,
        initial_wordlist=args.wordlist,
        threads=args.threads,
        timeout=args.timeout,
        auth_header=args.header,
    )

    try:
        fuzzer.run()
    except KeyboardInterrupt:
        print(f"\n{C.RED}[!] Interrupted by user{C.END}")
        sys.exit(1)


if __name__ == '__main__':
    main()
