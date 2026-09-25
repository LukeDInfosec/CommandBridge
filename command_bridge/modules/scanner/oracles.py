"""
How the scanner knows.

This is the part that separates a scanner somebody acts on from one they learn
to ignore. Anything can send a quote and see a 500; the work is proving that
what came back means what it appears to mean, and proving it in a way that
survives a flaky network, a load balancer and a page with a CSRF token that
changes on every request.

Four oracles, in the order they should be trusted:

  **Differential** — send a condition that is true and one that is false. If
  the true one matches the original page and the false one does not, the
  application evaluated the condition. Nothing about the response text is
  assumed; only that the two differ in the way a real injection makes them
  differ. This is the strongest signal available without out-of-band
  interaction, because it cannot be produced by an error handler.

  **Timing** — ask the application to wait, and see whether it does. Taken
  seriously only when the delay scales: a five-second payload that takes five
  seconds and a ten-second payload that takes ten is an injection; both taking
  six seconds is a slow server. Every timing result is measured against a
  sampled baseline, never against a fixed threshold.

  **Error signature** — the database said so. Good evidence for a report and
  poor evidence on its own, so it is reported at lower confidence unless
  another oracle agrees.

  **Reflection** — where the input landed in the response, and in what syntax.
  Necessary for XSS, and never sufficient: reflection is not execution, which
  is why the XSS check finishes in a browser.

Volatile content — tokens, timestamps, nonces — is normalised out before
anything is compared, because a page that differs from itself defeats every
comparison in this file.
"""

from __future__ import annotations

import difflib
import re
import statistics
import time


# ─────────────────────────────────────────────────────────────────────────────
#  Normalising and comparing
# ─────────────────────────────────────────────────────────────────────────────

#: Everything that legitimately changes between two identical requests. If
#: this list is short the comparisons get noisy and the scanner reports
#: nonsense; if it is too aggressive it hides real differences.
VOLATILE = (
    (re.compile(r"""(name=["']?(?:csrf|_token|authenticity_token|__RequestVerificationToken)[^>]*value=["'])[^"']+""",
                re.I), r"\1X"),
    (re.compile(r"\b[0-9a-f]{32,64}\b", re.I), "HEX"),
    (re.compile(r"\b\d{4}-\d{2}-\d{2}[ T]\d{2}:\d{2}(:\d{2})?\b"), "TIME"),
    (re.compile(r"\b\d{10,13}\b"), "EPOCH"),
    (re.compile(r"\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b",
                re.I), "UUID"),
    # Long digit runs: counters, ids, random padding. Short numbers are left
    # alone because a price or a quantity changing is exactly the kind of
    # difference a differential test is looking for.
    (re.compile(r"\d{6,}"), "N"),
    (re.compile(r"\s+"), " "),
)

COMPARE_LIMIT = 40000


def normalise(text):
    """Strip what changes on its own, so what is left is the page itself."""
    text = (text or "")[:COMPARE_LIMIT]
    for pattern, replacement in VOLATILE:
        text = pattern.sub(replacement, text)
    return text.strip()


def similarity(first, second):
    """0.0 to 1.0. Cheap, and stable enough to threshold against."""
    first, second = normalise(first), normalise(second)
    if first == second:
        return 1.0
    if not first or not second:
        return 0.0
    # Length alone rules out most pairs without the expensive comparison.
    shorter, longer = sorted((len(first), len(second)))
    if longer and shorter / longer < 0.4:
        return shorter / longer
    return difflib.SequenceMatcher(None, first, second).quick_ratio()


class Baseline:
    """What the application does when nothing is wrong.

    Sampled rather than assumed: the same request is sent several times so the
    scanner knows how much this endpoint varies by itself. An endpoint that
    varies wildly is one where differential results have to be discarded, and
    knowing that up front prevents a page of false positives.
    """

    def __init__(self, responses, elapsed):
        self.responses = responses
        self.elapsed = elapsed
        self.status = responses[0].status_code if responses else 0
        self.body = responses[0].text if responses else ""
        self.length = len(self.body)
        self.self_similarity = (
            min(similarity(responses[0].text, other.text)
                for other in responses[1:]) if len(responses) > 1 else 1.0)

    @property
    def stable(self):
        """Is this endpoint consistent enough to compare against?"""
        return self.self_similarity >= 0.98

    @property
    def strict_threshold(self):
        """How similar a response must be to count as *the same page*.

        Taken from the endpoint itself rather than fixed. A flat 0.95 was the
        single worst idea in the first version of this file: on any page with
        a navigation bar and a footer, "no such record" is still 96% identical
        to "here is the record", so every true/false pair looked the same and
        no blind injection could ever be confirmed. The right bar is "as
        similar as this page is to itself", which is 1.0 for a static page and
        drops only as far as the page's own volatility.
        """
        return min(0.999, self.self_similarity)

    @property
    def median_time(self):
        return statistics.median(self.elapsed) if self.elapsed else 0.0

    @property
    def slowest(self):
        return max(self.elapsed) if self.elapsed else 0.0

    def time_ceiling(self):
        """Above this, a response is slower than this endpoint ever is.

        Median plus four times the spread, floored at the slowest sample, so a
        single slow sample raises the bar rather than being averaged away.
        """
        if len(self.elapsed) < 2:
            return max(self.slowest * 2, self.median_time + 2.0)
        spread = statistics.pstdev(self.elapsed) or 0.1
        return max(self.slowest + 0.5, self.median_time + 4 * spread)

    def matches(self, response, threshold=None):
        if response is None:
            return False
        if response.status_code != self.status:
            return False
        if threshold is None:
            threshold = self.strict_threshold
        return similarity(self.body, response.text) >= threshold


def take_baseline(auth, request, samples=3, timeout=None):
    """Send the untouched request a few times and measure it."""
    responses, elapsed = [], []
    for _ in range(samples):
        started = time.time()
        response = auth.send(request, timeout=timeout)
        elapsed.append(time.time() - started)
        if response is None:
            return None
        responses.append(response)
    return Baseline(responses, elapsed)


# ─────────────────────────────────────────────────────────────────────────────
#  Differential
# ─────────────────────────────────────────────────────────────────────────────

class Differential:
    """A true/false pair, judged against the baseline.

    Returns a verdict only when the evidence is unambiguous:

      * the true payload must produce something the baseline recognises,
      * the false payload must produce something it does not,
      * and the two must differ from each other.

    If the endpoint was not stable to begin with, no verdict is given at all.
    A missing answer is a much better outcome than a confident wrong one.
    """

    def __init__(self, auth, baseline, threshold=None):
        self.auth = auth
        self.baseline = baseline
        self.threshold = threshold or baseline.strict_threshold

    def test(self, point, true_payload, false_payload, mode="append"):
        if not self.baseline.stable:
            return None
        true_request = point.build(true_payload, mode)
        false_request = point.build(false_payload, mode)
        true_response = self.auth.send(true_request)
        false_response = self.auth.send(false_request)
        if true_response is None or false_response is None:
            return None

        true_like_baseline = self.baseline.matches(true_response,
                                                   self.threshold)
        false_like_baseline = self.baseline.matches(false_response,
                                                    self.threshold)
        pair_similarity = similarity(true_response.text, false_response.text)

        confirmed = (true_like_baseline and not false_like_baseline
                     and pair_similarity < self.threshold)
        return {
            "confirmed": confirmed,
            "true_request": true_request, "true_response": true_response,
            "false_request": false_request, "false_response": false_response,
            "pair_similarity": round(pair_similarity, 3),
            "true_matches_baseline": true_like_baseline,
            "false_matches_baseline": false_like_baseline,
        }

    def confirm(self, point, pairs, mode="append"):
        """Run several true/false pairs; require two independent agreements.

        One pair can agree by accident — a value that happens to change the
        result, a cache that happens to expire. Two different pairs of
        payloads agreeing does not happen by accident.
        """
        agreed = []
        for true_payload, false_payload in pairs:
            result = self.test(point, true_payload, false_payload, mode)
            if result and result["confirmed"]:
                agreed.append(result)
            if len(agreed) >= 2:
                return agreed
        return agreed if len(agreed) >= 2 else []


# ─────────────────────────────────────────────────────────────────────────────
#  Timing
# ─────────────────────────────────────────────────────────────────────────────

class Timing:
    """Did the application wait because we asked it to?

    The test is proportionality, not a threshold. A payload asking for N
    seconds should take about N seconds, and one asking for 2N should take
    about 2N. A congested network makes responses slow; it does not make them
    slow *in proportion to a number in the payload*.
    """

    def __init__(self, auth, baseline, base_delay=5):
        self.auth = auth
        self.baseline = baseline
        self.base_delay = base_delay

    def measure(self, request):
        started = time.time()
        response = self.auth.send(request, timeout=self.base_delay * 4 + 20)
        return time.time() - started, response

    def test(self, point, template, mode="append"):
        """``template`` contains {d}, replaced with the delay in seconds."""
        ceiling = self.baseline.time_ceiling()
        short = self.base_delay
        long = self.base_delay * 2

        short_request = point.build(template.format(d=short), mode)
        short_time, short_response = self.measure(short_request)
        if short_response is None or short_time < short * 0.8:
            return None
        if short_time <= ceiling:
            return None

        long_request = point.build(template.format(d=long), mode)
        long_time, long_response = self.measure(long_request)
        if long_response is None:
            return None

        # The long payload must take clearly longer, and roughly in
        # proportion. Both conditions matter: a server that is simply slow
        # fails the second one.
        scaled = long_time >= short_time * 1.6
        proportional = (long * 0.7) <= long_time <= (long * 2.5)
        if not (scaled and proportional):
            return None

        return {
            "confirmed": True,
            "short_request": short_request, "short_time": round(short_time, 2),
            "long_request": long_request, "long_time": round(long_time, 2),
            "short_delay": short, "long_delay": long,
            "baseline_median": round(self.baseline.median_time, 2),
            "baseline_ceiling": round(ceiling, 2),
            "response": long_response,
        }


# ─────────────────────────────────────────────────────────────────────────────
#  Error signatures
# ─────────────────────────────────────────────────────────────────────────────

DB_ERRORS = (
    ("MySQL", re.compile(
        r"SQL syntax.*MySQL|Warning.*mysqli?_|MySqlException|"
        r"valid MySQL result|check the manual that corresponds to your "
        r"(MySQL|MariaDB) server version", re.I)),
    ("PostgreSQL", re.compile(
        r"PostgreSQL.*ERROR|Warning.*\bpg_|valid PostgreSQL result|"
        r"Npgsql\.|PG::SyntaxError|unterminated quoted string at or near",
        re.I)),
    ("SQLite", re.compile(
        r"SQLite/JDBCDriver|SQLite\.Exception|System\.Data\.SQLite\.|"
        r"sqlite3\.OperationalError|SQLITE_ERROR|unrecognized token:|"
        r"near \".*\": syntax error", re.I)),
    ("Microsoft SQL Server", re.compile(
        r"Driver.*SQL[\-_ ]*Server|OLE DB.*SQL Server|Unclosed quotation mark "
        r"after the character string|Microsoft SQL Native Client error|"
        r"System\.Data\.SqlClient\.SqlException", re.I)),
    ("Oracle", re.compile(
        r"\bORA-\d{4,5}\b|Oracle error|quoted string not properly terminated",
        re.I)),
)

#: What a command interpreter says when it has been handed something odd.
COMMAND_ERRORS = re.compile(
    r"sh: \d+:|/bin/(ba)?sh:|command not found|Syntax error: |"
    r"'.*' is not recognized as an internal or external command", re.I)


def database_error(text):
    """Which engine complained, if any."""
    body = text or ""
    for engine, pattern in DB_ERRORS:
        match = pattern.search(body)
        if match:
            start = max(0, match.start() - 80)
            return engine, body[start:match.end() + 160].strip()
    return None, ""


# ─────────────────────────────────────────────────────────────────────────────
#  Reflection
# ─────────────────────────────────────────────────────────────────────────────

def reflection_contexts(body, canary):
    """Where a canary landed, described by the syntax around it.

    The context decides the payload: what breaks out of an attribute does
    nothing inside a script block, and a scanner that fires the same payload
    at every reflection finds a fraction of what is there.
    """
    contexts = []
    for match in re.finditer(re.escape(canary), body or ""):
        before = body[max(0, match.start() - 220):match.start()]
        after = body[match.end():match.end() + 120]
        if re.search(r"<script[^>]*>(?:(?!</script>)[\s\S])*$", before, re.I):
            kind = "script"
        elif re.search(r"<[^>]+=\s*\"[^\"]*$", before):
            kind = "attribute-double"
        elif re.search(r"<[^>]+=\s*'[^']*$", before):
            kind = "attribute-single"
        elif re.search(r"<[^>]+=\s*[^\s\"'>]*$", before):
            kind = "attribute-bare"
        elif re.search(r"<(!--)(?:(?!-->)[\s\S])*$", before):
            kind = "comment"
        elif re.search(r"<(style|textarea|title)[^>]*>(?:(?!</)[\s\S])*$",
                       before, re.I):
            kind = "raw-text"
        else:
            kind = "html"
        contexts.append({"kind": kind, "offset": match.start(),
                         "excerpt": (before[-90:] + canary + after[:60])})
    return contexts


def survives(body, canary, characters):
    """Which of the characters that matter came back unencoded."""
    intact = []
    for character in characters:
        if f"{canary}{character}" in (body or ""):
            intact.append(character)
    return intact
