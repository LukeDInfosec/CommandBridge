#!/usr/bin/env python3
"""
What would the current logic make of scans you have already run?

    python3 reclassify_report.py [directory ...]

Reads the findings JSON that Coffee Break autosaves next to every run
(``*_coffee_break_findings.json``), replays each finding's recorded
classification through the current decision engine, and reports how many
would now be reported differently.

Read-only. It opens the saved files and writes nothing, so a historical
scan is never altered or deleted — the point is to measure the change,
not to rewrite the record.

What it can and cannot measure, stated plainly: a saved finding holds
the classification, severity and status that were assigned at the time,
plus its evidence. It does NOT hold the live response, so verification
cannot be re-run from it — a path that answered in August cannot be
re-requested from a JSON file. So the comparison covers the parts that
are decided from the saved evidence:

  * whether the class the finding was given could be supported by the
    kind of observation behind it (the engine's stage 3), and
  * what severity that class and status justify (stage 6).

A finding whose verdict depended on a live check is reported as "not
assessable from the record" rather than guessed at.
"""

from __future__ import annotations

import json
import sys
from collections import Counter
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from command_bridge.modules import cb_issues                 # noqa: E402
from command_bridge.modules import classification as engine   # noqa: E402
from command_bridge.modules import detector_registry as reg    # noqa: E402
from command_bridge.modules import risk                        # noqa: E402

#: Vulnerability classes that a saved finding may claim. Anything in
#: engine.BEHAVIOURAL_CLASSES needs a demonstrated behaviour, so a saved
#: finding carrying one of these with no payload or parameter in its
#: evidence is the case worth counting.
BEHAVIOURAL = set(engine.BEHAVIOURAL_CLASSES)


def observation_kind(row):
    """Infer what a saved finding's evidence actually was.

    Conservative: a row whose evidence names a parameter and a payload
    is treated as a demonstration, because that is what the scanner
    recorded. Everything else is read from the shape of the evidence.
    """
    evidence = " ".join(str(row.get(field, "")) for field in
                        ("evidence", "detail", "where")).lower()
    if any(token in evidence for token in
           ("payload:", "parameter:", "uid=", "injected", "differential")):
        return engine.DEMONSTRATED
    if "cipher" in evidence or "tls_" in evidence:
        return engine.CIPHER_CONFIG
    if any(token in evidence for token in
           ("header:", "content-security-policy", "x-frame-options",
            "x-xss-protection", "strict-transport-security")):
        return engine.HEADER_VALUE
    if "http " in evidence and "bytes" in evidence:
        return engine.RESPONSE_BODY
    if evidence.strip().startswith("/") or "path" in evidence:
        return engine.PATH_EXISTS
    return engine.UNKNOWN_OBSERVATION


def assess(row):
    """``(verdict, detail)`` for one saved finding."""
    key = str(row.get("key") or "")
    severity = str(row.get("severity") or "INFO").upper()
    state = str(row.get("state") or "").upper()

    if not key:
        return "unclassified", "the finding carried no issue key"

    kind = observation_kind(row)
    observation = engine.Observation(kind=kind)
    ok, why = engine.consistent(key, observation)

    if not ok:
        return "reclassified", (
            f"{key} at {severity} — {why.split(', which')[0]}; would now be "
            f"reported as an observation")

    if kind == engine.UNKNOWN_OBSERVATION and key in BEHAVIOURAL:
        return "not_assessable", (
            f"{key} — its verdict rested on a live check that cannot be "
            f"repeated from the record")

    status = {"CONFIRMED": reg.CONFIRMED, "VALIDATED": reg.CONFIRMED,
              "POTENTIAL": reg.POTENTIAL,
              "INCONCLUSIVE": reg.INCONCLUSIVE,
              "DETECTED": reg.INCONCLUSIVE}.get(state, reg.INCONCLUSIVE)
    library = cb_issues.ISSUES.get(key, {})
    impact = library.get("severity") or severity
    now, _, _ = risk.assess(impact, status, vuln_class=key)

    if risk.RANK.get(now, 0) < risk.RANK.get(severity, 0):
        return "downgraded", (f"{key} — {severity} → {now} "
                              f"(status {state or 'unknown'})")
    if risk.RANK.get(now, 0) > risk.RANK.get(severity, 0):
        return "raised", f"{key} — {severity} → {now}"
    return "retained", f"{key} at {severity}"


def main(argv=None):
    roots = [Path(a) for a in (argv or sys.argv[1:])] or \
        [Path.home() / "CommandBridge_Output", Path.cwd()]
    files = []
    for root in roots:
        if root.is_file():
            files.append(root)
        elif root.is_dir():
            files.extend(sorted(root.rglob("*coffee_break_findings.json")))

    if not files:
        print("No saved Coffee Break findings were found.\n")
        print("Looked in:")
        for root in roots:
            print(f"  {root}")
        print("\nPass a directory, or a findings JSON file, as an argument.")
        return 1

    counts = Counter()
    examples = {}
    scanned = 0
    for path in files:
        try:
            blob = json.loads(path.read_text(errors="replace"))
        except Exception as exc:                            # noqa: BLE001
            print(f"  ! could not read {path.name}: {exc}")
            continue
        rows = blob.get("findings") or []
        scanned += 1
        for row in rows:
            verdict, detail = assess(row)
            counts[verdict] += 1
            examples.setdefault(verdict, []).append(
                f"{blob.get('target', path.stem)}: {detail}")

    total = sum(counts.values())
    print(f"Read {total} finding(s) from {scanned} saved run(s) "
          f"in {len(files)} file(s).\n")
    if not total:
        print("The files held no findings.")
        return 0

    order = ("reclassified", "downgraded", "raised", "retained",
             "not_assessable", "unclassified")
    label = {
        "reclassified": "RECLASSIFIED — the class was not supportable by "
                        "the evidence",
        "downgraded":   "DOWNGRADED — same class, lower rating",
        "raised":       "RAISED — same class, higher rating",
        "retained":     "RETAINED — unchanged",
        "not_assessable": "NOT ASSESSABLE from the record — needs a live "
                          "check",
        "unclassified": "NO ISSUE KEY — left as the scanner's own wording",
    }
    for verdict in order:
        if not counts[verdict]:
            continue
        share = 100.0 * counts[verdict] / total
        print(f"{counts[verdict]:5}  ({share:5.1f}%)  {label[verdict]}")
        for line in examples[verdict][:4]:
            print(f"           {line}")
        if len(examples[verdict]) > 4:
            print(f"           … and {len(examples[verdict]) - 4} more")
        print()

    print("Nothing was modified. The saved files are unchanged.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
