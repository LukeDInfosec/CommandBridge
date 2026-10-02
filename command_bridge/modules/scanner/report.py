"""
The report.

Three formats, for three readers: HTML for the client, Markdown for whoever is
writing the engagement up, JSON for whatever comes next. All three are built
from the same findings, so they cannot disagree.

Two things the HTML report does that most do not:

  * every finding carries the **request and response pair that proved it**, in
    full, so a developer can reproduce it without asking anybody;
  * the header says what was *not* tested — pages skipped as destructive,
    whether the session held, whether a browser was available. A report that
    only lists what was found invites the reader to assume the rest is clean.
"""

from __future__ import annotations

import html
import json
import time

from command_bridge.modules import cb_evidence, cb_issues
from command_bridge.modules.scanner import grading

SEVERITY_ORDER = ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO")

#: Classes the Active Scan does not test for. A report that lists only what
#: was found invites the reader to assume the rest was checked and came back
#: clean, so this is printed in both the Markdown and the HTML header.
NOT_TESTED = (
    "server-side request forgery (SSRF)",
    "XML external entity injection (XXE)",
    "unsafe deserialization",
)
SEVERITY_COLOUR = {"CRITICAL": "#c1121f", "HIGH": "#e35d2b",
                   "MEDIUM": "#c78b12", "LOW": "#2f6fdb", "INFO": "#5c6b7f"}
#: Deliberately not the severity palette. A confirmed low and a potential
#: critical must not be able to look like each other at a glance.
CONFIDENCE_COLOUR = {"confirmed": "#1f7a4d", "likely": "#5c7fb8",
                     "potential": "#6b7280", "inconclusive": "#8a8f98"}


def severity_of(finding):
    issue = cb_issues.ISSUES.get(finding.issue, {})
    return finding.severity or issue.get("severity", "MEDIUM")


def title_of(finding):
    return cb_issues.ISSUES.get(finding.issue, {}).get("title", finding.issue)


def sorted_findings(result):
    return sorted(result.findings,
                  key=lambda f: (SEVERITY_ORDER.index(severity_of(f))
                                 if severity_of(f) in SEVERITY_ORDER else 9,
                                 title_of(f), f.where))


CONFIDENCE_ORDER = ("confirmed", "likely", "potential", "inconclusive")


def confidence_tally(result):
    """How many findings are proved, and how many are only suspected."""
    tally = {}
    for finding in result.findings:
        _, validation = cb_evidence.assess_scan(finding)
        key = validation.confidence
        tally[key] = tally.get(key, 0) + 1
    return tally


def counts(result):
    tally = {}
    for finding in result.findings:
        severity = severity_of(finding)
        tally[severity] = tally.get(severity, 0) + 1
    return tally


# ─────────────────────────────────────────────────────────────────────────────
#  Markdown
# ─────────────────────────────────────────────────────────────────────────────

def as_markdown(result):
    tally = counts(result)
    lines = [f"# Active scan — {result.target}", ""]
    lines.append(f"- **Finished:** "
                 f"{time.strftime('%Y-%m-%d %H:%M', time.localtime(result.finished or time.time()))}")
    lines.append(f"- **Duration:** {int(result.duration // 60)}m "
                 f"{int(result.duration % 60)}s")
    lines.append(f"- **Profile:** {result.profile}")
    # The authentication line decides whether anything below it means
    # much, so it carries the method and the verdict's reason rather than a
    # bare yes/no.
    outcome = getattr(result, "auth_outcome", None)
    if outcome is not None and getattr(outcome, "finished", False):
        lines.append(f"- **Authenticated:** {outcome.summary()} "
                     f"({outcome.method}) — {outcome.reason}")
    else:
        lines.append(f"- **Authenticated:** "
                     f"{'yes' if result.authenticated else 'no'}")
    if getattr(result, "parameter_file", ""):
        lines.append(f"- **Discovered parameters:** "
                     f"{result.parameter_file}")
    lines.append(f"- **Coverage:** {result.pages_crawled} page(s) crawled, "
                 f"{result.requests_seen} distinct request(s), "
                 f"{result.points_tested} insertion point(s) tested")
    if tally:
        lines.append("- **Findings:** " + ", ".join(
            f"{tally[s]} {s.lower()}" for s in SEVERITY_ORDER if tally.get(s)))
        # Severity counts say how bad things would be; this says how much of
        # it is actually proved. Both belong in the header (§18).
        graded = confidence_tally(result)
        if graded:
            lines.append("- **Evidence:** " + ", ".join(
                f"{graded[c]} {c}" for c in CONFIDENCE_ORDER
                if graded.get(c)))
    else:
        lines.append("- **Findings:** none")
    lines.append("")

    for note in result.notes:
        lines.append(f"> {note}")
    lines.append("> Not tested by this scan: " + ", ".join(NOT_TESTED)
                 + ". These require an out-of-band collaborator the scanner "
                   "does not run, and no check for them exists. Their "
                   "absence from this report is not evidence of their "
                   "absence from the application.")
    if result.skipped_destructive:
        lines.append(f"> {len(result.skipped_destructive)} link(s) were not "
                     f"followed because they appeared to log out or delete "
                     f"something. They were not tested.")
    lines.append("")

    for finding in sorted_findings(result):
        issue = cb_issues.ISSUES.get(finding.issue, {})
        # The same evidence chain and verdict the Findings screens show, so
        # the written report and the screen cannot disagree.
        proof, validation = cb_evidence.assess_scan(finding)
        verdict = getattr(finding, "verdict", None)
        severity = severity_of(finding)
        confidence = validation.confidence
        label = grading.severity_label(severity, confidence)
        auth = getattr(finding, "auth_context", {}) or {}

        # §18 — severity and confidence are two different statements and are
        # never multiplied together. The heading carries both, spelled out.
        lines.append(f"## [{confidence.upper()}] [{label}] "
                     f"{title_of(finding)}")
        lines.append("")

        # §16 — the same fields, in the same order, on every finding.
        lines.append(f"- **Issue:** {title_of(finding)}")
        lines.append(f"- **Severity:** {severity} "
                     f"(impact if the issue is real)")
        lines.append(f"- **Confidence:** {confidence} "
                     f"(how well it is evidenced)")
        lines.append(f"- **Status:** {validation.state}")
        lines.append(f"- **URL:** {finding.where}")
        lines.append(f"- **Method:** {getattr(finding, 'method', '') or '—'}")
        lines.append(f"- **Insertion point:** {finding.point}")
        lines.append(f"- **Detection method:** "
                     f"{getattr(verdict, 'detection_method', '') or '—'}")
        # §15 — who the scanner was when it found this.
        lines.append(f"- **Authentication context:** "
                     f"{auth.get('label', 'unknown')}"
                     + (f" as {auth['identity']}" if auth.get("identity")
                        else "")
                     + (f" via {auth['method']}" if auth.get("method")
                        and auth.get("method") != "none" else ""))
        if issue.get("cwe"):
            lines.append(f"- **Classification:** {issue['cwe']}")
        lines.append("")

        # §17 — raw detection first and on its own: exactly what was
        # measured or matched, with no interpretation wrapped around it.
        lines.append("### Raw detection")
        lines.append("")
        signals = list(getattr(verdict, "signals", None)
                       or getattr(finding, "signals", []) or [])
        if signals:
            for signal in signals:
                name = grading.GRADE_NAMES.get(signal.grade, signal.grade)
                lines.append(f"- **{name}**"
                             + (" (reproduced)" if signal.reproduced else "")
                             + f": {signal.detail}")
                for key in sorted(signal.measurements):
                    lines.append(f"    - {key}: "
                                 f"{signal.measurements[key]}")
        else:
            lines.append("- No graded signals were recorded for this "
                         "finding.")
        if getattr(finding, "measurements", None):
            lines.append("")
            lines.append("```")
            for key in sorted(finding.measurements):
                lines.append(f"{key}: {finding.measurements[key]}")
            lines.append("```")
        lines.append("")
        if finding.evidence:
            lines.append("```http")
            lines.append(finding.evidence_text())
            lines.append("```")
            lines.append("")

        # Then, separately, what the scanner believes it means.
        lines.append("### Interpreted finding")
        lines.append("")
        lines.append(validation.rationale
                     or "Detection rationale unavailable.")
        lines.append("")
        if issue.get("detail"):
            lines.append(issue["detail"])
            lines.append("")
        if finding.detail_extra:
            lines.append(finding.detail_extra)
            lines.append("")

        lines.append("### Observed evidence")
        lines.append("")
        lines.append("```")
        lines += cb_evidence.evidence_checklist(finding.issue, proof)
        lines.append("```")
        lines.append("")
        lines.append("### Proof of concept")
        lines.append("")
        lines.append("```")
        lines += cb_evidence.poc_section(finding.issue, proof)
        lines.append("```")
        lines.append("")
        if validation.false_positive_indicators:
            lines.append("### What could explain this without the "
                         "vulnerability")
            lines.append("")
            lines += [f"- {item}"
                      for item in validation.false_positive_indicators]
            lines.append("")
        if confidence != "confirmed":
            lines.append("### How to confirm it")
            lines.append("")
            lines.append(getattr(verdict, "verification", "")
                         or validation.action
                         or "Manual validation required.")
            lines.append("")
        for conflict in validation.conflicts:
            lines.append(f"> ⚠ {conflict}")
            lines.append("")
        if issue.get("remediation"):
            lines.append(f"**Fix.** {issue['remediation']}")
            lines.append("")
    return "\n".join(lines)


# ─────────────────────────────────────────────────────────────────────────────
#  JSON
# ─────────────────────────────────────────────────────────────────────────────

def as_json(result):
    payload = {
        "target": result.target,
        "profile": result.profile,
        "started": result.started,
        "finished": result.finished,
        "duration_seconds": round(result.duration, 1),
        "authenticated": result.authenticated,
        "coverage": {
            "pages_crawled": result.pages_crawled,
            "requests": result.requests_seen,
            "insertion_points": result.points_tested,
            "http_requests_sent": result.http_sent,
            "session_relogins": result.relogins,
            "skipped_as_destructive": result.skipped_destructive,
        },
        "notes": result.notes,
        "findings": [],
    }
    for finding in sorted_findings(result):
        issue = cb_issues.ISSUES.get(finding.issue, {})
        proof, validation = cb_evidence.assess_scan(finding)
        verdict = getattr(finding, "verdict", None)
        payload["findings"].append({
            "issue": finding.issue,
            "title": title_of(finding),
            # Severity and confidence stay two separate fields (§18) and the
            # printable label that combines them is given, never substituted
            # for either.
            "severity": severity_of(finding),
            "confidence": validation.confidence,
            "severity_label": grading.severity_label(
                severity_of(finding), validation.confidence),
            "status": validation.state,
            "method": getattr(finding, "method", ""),
            "detection_method": getattr(verdict, "detection_method", ""),
            "rationale": validation.rationale,
            "limitations": validation.false_positive_indicators,
            "verification": getattr(verdict, "verification", "")
                            or validation.action,
            # §17 — the raw signals and their measurements, kept apart from
            # the prose above so a consumer can re-judge them itself.
            "raw_detection": {
                "signals": [sig.as_dict()
                            for sig in (getattr(verdict, "signals", None)
                                        or getattr(finding, "signals", [])
                                        or [])],
                "measurements": getattr(finding, "measurements", {}) or {},
            },
            "auth_context": getattr(finding, "auth_context", {}) or {},
            "url": finding.where,
            "parameter": finding.point,
            "cwe": issue.get("cwe", ""),
            "description": issue.get("detail", ""),
            "confirmation": finding.detail_extra,
            "remediation": issue.get("remediation", ""),
            "references": issue.get("references", []),
            "evidence": [{"label": e.label, "request": e.request,
                          "response": e.response, "note": e.note}
                         for e in finding.evidence],
        })
    return json.dumps(payload, indent=2)


# ─────────────────────────────────────────────────────────────────────────────
#  HTML
# ─────────────────────────────────────────────────────────────────────────────

_CSS = """
:root { color-scheme: light dark;
        --bg:#ffffff; --fg:#14181f; --dim:#5c6b7f; --line:#e3e8ef;
        --card:#f7f9fc; --code:#0f1319; --code-fg:#dbe3ef; }
@media (prefers-color-scheme: dark) {
  :root { --bg:#12161c; --fg:#e7ecf3; --dim:#94a3b8; --line:#232b36;
          --card:#191f27; --code:#0b0e13; --code-fg:#d6deea; } }
* { box-sizing:border-box; }
body { margin:0; padding:0 16px 80px; background:var(--bg); color:var(--fg);
       font:15px/1.6 -apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,sans-serif; }
.wrap { max-width:960px; margin:0 auto; }
h1 { font-size:26px; margin:32px 0 4px; }
h2 { font-size:19px; margin:34px 0 10px; }
h4 { font-size:13px; margin:18px 0 6px; text-transform:uppercase;
     letter-spacing:.05em; color:var(--dim); }
.finding ul { margin:6px 0; padding-left:20px; }
.finding li { margin:3px 0; }
.sub { color:var(--dim); margin:0 0 24px; }
.facts { display:grid; grid-template-columns:repeat(auto-fit,minmax(150px,1fr));
         gap:10px; margin:20px 0 6px; }
.fact { background:var(--card); border:1px solid var(--line);
        border-radius:10px; padding:12px 14px; }
.fact b { display:block; font-size:20px; }
.fact span { color:var(--dim); font-size:12px; text-transform:uppercase;
             letter-spacing:.04em; }
.note { background:var(--card); border-left:3px solid #c78b12;
        border-radius:6px; padding:10px 14px; margin:10px 0; color:var(--dim); }
.finding { border:1px solid var(--line); border-radius:12px; padding:18px 20px;
           margin:16px 0; background:var(--card); }
.finding h3 { margin:0 0 6px; font-size:17px; }
.pill { display:inline-block; padding:2px 10px; border-radius:999px;
        font-size:11px; font-weight:700; letter-spacing:.06em; color:#fff;
        vertical-align:middle; margin-right:8px; }
.meta { color:var(--dim); font-size:13px; margin:6px 0 12px;
        word-break:break-all; }
.meta code { background:transparent; }
pre { background:var(--code); color:var(--code-fg); padding:14px 16px;
      border-radius:8px; overflow-x:auto; font-size:12.5px; line-height:1.5; }
code { font-family:ui-monospace,SFMono-Regular,Menlo,monospace; }
.fix { border-left:3px solid #2f8f5b; padding:8px 14px; margin-top:12px;
       background:var(--bg); border-radius:6px; }
.clean { text-align:center; padding:60px 20px; color:var(--dim); }
@media (max-width:640px){ .facts{grid-template-columns:1fr 1fr;} }
"""


def as_html(result):
    tally = counts(result)
    findings = sorted_findings(result)
    out = ["<!doctype html><html lang='en'><head><meta charset='utf-8'>",
           "<meta name='viewport' content='width=device-width,initial-scale=1'>",
           f"<title>Active scan — {html.escape(result.target)}</title>",
           f"<style>{_CSS}</style></head><body><div class='wrap'>"]

    out.append(f"<h1>Active scan</h1>")
    out.append(f"<p class='sub'>{html.escape(result.target)} · "
               f"{result.profile} profile · "
               f"{'authenticated' if result.authenticated else 'unauthenticated'}"
               f" · {time.strftime('%d %B %Y %H:%M', time.localtime(result.finished or time.time()))}</p>")

    out.append("<div class='facts'>")
    out.append(f"<div class='fact'><b>{len(findings)}</b>"
               f"<span>confirmed findings</span></div>")
    for severity in SEVERITY_ORDER:
        if tally.get(severity):
            out.append(f"<div class='fact'><b style='color:"
                       f"{SEVERITY_COLOUR[severity]}'>{tally[severity]}</b>"
                       f"<span>{severity.lower()}</span></div>")
    out.append(f"<div class='fact'><b>{result.points_tested}</b>"
               f"<span>parameters tested</span></div>")
    out.append(f"<div class='fact'><b>{result.pages_crawled}</b>"
               f"<span>pages crawled</span></div>")
    out.append(f"<div class='fact'><b>{int(result.duration // 60)}m</b>"
               f"<span>duration</span></div>")
    out.append("</div>")

    for note in result.notes:
        out.append(f"<div class='note'>{html.escape(note)}</div>")
    out.append("<div class='note'><b>Not tested by this scan:</b> "
               + ", ".join(NOT_TESTED)
               + ". No check for these exists in the Active Scan — they need "
                 "an out-of-band collaborator it does not run. Their absence "
                 "from this report is not evidence of their absence from the "
                 "application.</div>")
    if result.skipped_destructive:
        out.append(f"<div class='note'>{len(result.skipped_destructive)} "
                   f"link(s) were not followed because they appeared to log "
                   f"out or delete something, and were therefore not tested."
                   f"</div>")
    if not result.authenticated:
        out.append("<div class='note'>This scan ran without a confirmed "
                   "logged-in session. Anything behind authentication was not "
                   "reached.</div>")

    if not findings:
        out.append("<div class='clean'><h2>Nothing confirmed</h2>"
                   "<p>Every check ran and none of them could prove an issue. "
                   "That is not the same as the application being secure — it "
                   "means these checks, over this coverage, found nothing.</p>"
                   "</div>")
    else:
        out.append("<h2>Findings</h2>")

    for finding in findings:
        issue = cb_issues.ISSUES.get(finding.issue, {})
        severity = severity_of(finding)
        proof, validation = cb_evidence.assess_scan(finding)
        verdict = getattr(finding, "verdict", None)
        confidence = validation.confidence
        auth = getattr(finding, "auth_context", {}) or {}
        out.append("<div class='finding'>")
        # Two pills, not one: how bad it would be, and how well it is known.
        out.append(f"<h3><span class='pill' style='background:"
                   f"{SEVERITY_COLOUR.get(severity, '#5c6b7f')}'>{severity}"
                   f"</span><span class='pill' style='background:"
                   f"{CONFIDENCE_COLOUR.get(confidence, '#5c6b7f')}'>"
                   f"{confidence}</span>"
                   f"{html.escape(title_of(finding))}</h3>")
        out.append(f"<div class='meta'><code>{html.escape(finding.where)}"
                   f"</code><br>"
                   f"{html.escape(getattr(finding, 'method', '') or '')} "
                   f"{html.escape(finding.point)} · "
                   f"{html.escape(grading.severity_label(severity, confidence))}"
                   + (f" · detected by "
                      f"{html.escape(verdict.detection_method)}"
                      if getattr(verdict, "detection_method", "") else "")
                   + f" · {html.escape(auth.get('label', 'auth unknown'))}"
                   + (f" as {html.escape(auth['identity'])}"
                      if auth.get("identity") else "")
                   + (f" · {issue['cwe']}" if issue.get("cwe") else "")
                   + "</div>")

        # §17 — raw detection, then interpretation, never mixed.
        signals = list(getattr(verdict, "signals", None)
                       or getattr(finding, "signals", []) or [])
        if signals or getattr(finding, "measurements", None):
            out.append("<h4>Raw detection</h4><ul>")
            for signal in signals:
                name = grading.GRADE_NAMES.get(signal.grade, signal.grade)
                extra = ""
                if signal.measurements:
                    extra = " <code>" + html.escape(", ".join(
                        f"{k}={signal.measurements[k]}"
                        for k in sorted(signal.measurements))) + "</code>"
                out.append(f"<li><b>{html.escape(name)}</b>"
                           + (" (reproduced)" if signal.reproduced else "")
                           + f": {html.escape(signal.detail)}{extra}</li>")
            for key in sorted(getattr(finding, "measurements", {}) or {}):
                out.append(f"<li><b>{html.escape(key)}</b>: "
                           f"{html.escape(str(finding.measurements[key]))}"
                           f"</li>")
            out.append("</ul>")
        if finding.evidence:
            out.append(f"<pre><code>"
                       f"{html.escape(finding.evidence_text())}</code></pre>")

        out.append("<h4>Interpreted finding</h4>")
        if validation.rationale:
            out.append(f"<p>{html.escape(validation.rationale)}</p>")
        if issue.get("detail"):
            out.append(f"<p>{html.escape(issue['detail'])}</p>")
        if finding.detail_extra:
            out.append(f"<p>{html.escape(finding.detail_extra)}</p>")
        if validation.false_positive_indicators:
            out.append("<h4>What could explain this without the "
                       "vulnerability</h4><ul>")
            for item in validation.false_positive_indicators:
                out.append(f"<li>{html.escape(item)}</li>")
            out.append("</ul>")
        if confidence != "confirmed":
            advice = (getattr(verdict, "verification", "")
                      or validation.action
                      or "Manual validation required.")
            out.append(f"<div class='note'><b>Not proved.</b> "
                       f"{html.escape(advice)}</div>")
        if issue.get("remediation"):
            out.append(f"<div class='fix'><b>Fix.</b> "
                       f"{html.escape(issue['remediation'])}</div>")
        out.append("</div>")

    out.append("<p class='sub' style='margin-top:40px;font-size:12px'>"
               "Generated by Command Bridge. Each finding above carries the "
               "evidence it was graded on. Findings marked anything other "
               "than <b>confirmed</b> are not proved: the raw detection "
               "shows what was actually observed, and the confirmation "
               "advice says what would settle it.</p>")
    out.append("</div></body></html>")
    return "\n".join(out)


def write_all(result, directory, stem="active_scan"):
    """Write all three formats. Returns the paths."""
    from pathlib import Path
    directory = Path(directory)
    directory.mkdir(parents=True, exist_ok=True)
    written = {}
    for suffix, renderer in (("html", as_html), ("md", as_markdown),
                             ("json", as_json)):
        path = directory / f"{stem}.{suffix}"
        path.write_text(renderer(result), encoding="utf-8")
        written[suffix] = str(path)
    return written
