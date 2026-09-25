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

from command_bridge.modules import cb_issues

SEVERITY_ORDER = ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO")
SEVERITY_COLOUR = {"CRITICAL": "#c1121f", "HIGH": "#e35d2b",
                   "MEDIUM": "#c78b12", "LOW": "#2f6fdb", "INFO": "#5c6b7f"}


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
    lines.append(f"- **Authenticated:** "
                 f"{'yes' if result.authenticated else 'no'}")
    lines.append(f"- **Coverage:** {result.pages_crawled} page(s) crawled, "
                 f"{result.requests_seen} distinct request(s), "
                 f"{result.points_tested} insertion point(s) tested")
    if tally:
        lines.append("- **Findings:** " + ", ".join(
            f"{tally[s]} {s.lower()}" for s in SEVERITY_ORDER if tally.get(s)))
    else:
        lines.append("- **Findings:** none confirmed")
    lines.append("")

    for note in result.notes:
        lines.append(f"> {note}")
    if result.skipped_destructive:
        lines.append(f"> {len(result.skipped_destructive)} link(s) were not "
                     f"followed because they appeared to log out or delete "
                     f"something. They were not tested.")
    lines.append("")

    for finding in sorted_findings(result):
        issue = cb_issues.ISSUES.get(finding.issue, {})
        lines.append(f"## [{severity_of(finding)}] {title_of(finding)}")
        lines.append("")
        lines.append(f"- **Where:** {finding.where}")
        lines.append(f"- **Parameter:** {finding.point}")
        lines.append(f"- **Confidence:** {finding.confidence}")
        if issue.get("cwe"):
            lines.append(f"- **Classification:** {issue['cwe']}")
        lines.append("")
        if issue.get("detail"):
            lines.append(issue["detail"])
            lines.append("")
        if finding.detail_extra:
            lines.append(f"**How it was confirmed.** {finding.detail_extra}")
            lines.append("")
        if finding.evidence:
            lines.append("### Evidence")
            lines.append("")
            lines.append("```http")
            lines.append(finding.evidence_text())
            lines.append("```")
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
        payload["findings"].append({
            "issue": finding.issue,
            "title": title_of(finding),
            "severity": severity_of(finding),
            "confidence": finding.confidence,
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
        out.append("<div class='finding'>")
        out.append(f"<h3><span class='pill' style='background:"
                   f"{SEVERITY_COLOUR.get(severity, '#5c6b7f')}'>{severity}"
                   f"</span>{html.escape(title_of(finding))}</h3>")
        out.append(f"<div class='meta'><code>{html.escape(finding.where)}"
                   f"</code><br>{html.escape(finding.point)} · "
                   f"{finding.confidence}"
                   + (f" · {issue['cwe']}" if issue.get("cwe") else "")
                   + "</div>")
        if issue.get("detail"):
            out.append(f"<p>{html.escape(issue['detail'])}</p>")
        if finding.detail_extra:
            out.append(f"<p><b>How it was confirmed.</b> "
                       f"{html.escape(finding.detail_extra)}</p>")
        if finding.evidence:
            out.append(f"<pre><code>"
                       f"{html.escape(finding.evidence_text())}</code></pre>")
        if issue.get("remediation"):
            out.append(f"<div class='fix'><b>Fix.</b> "
                       f"{html.escape(issue['remediation'])}</div>")
        out.append("</div>")

    out.append("<p class='sub' style='margin-top:40px;font-size:12px'>"
               "Generated by Command Bridge. Every finding above was "
               "confirmed by the evidence shown with it; checks that could "
               "not be proved were discarded rather than reported.</p>")
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
