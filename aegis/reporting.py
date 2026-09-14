"""Shareable HTML security report (``aegis report``).

One self-contained file with no scripts or external resources, so it can be
emailed, attached to a ticket, printed, or opened offline. Every stored value is
HTML-escaped: alert titles and process names come from the observed system and
may be attacker-influenced.
"""
from __future__ import annotations

import platform
from datetime import datetime
from html import escape

from aegis import __version__
from aegis.detection.guidance import guidance_for
from aegis.posture.base import CheckStatus, PostureReport

_SEVERITY_CLASS = {"CRITICAL": "critical", "HIGH": "high", "MEDIUM": "medium",
                   "LOW": "low", "INFO": "info"}
_STATUS_ORDER = {CheckStatus.FAIL: 0, CheckStatus.WARN: 1, CheckStatus.PASS: 2,
                 CheckStatus.SKIP: 3}

_CSS = """
body{font:14px/1.5 system-ui,-apple-system,"Segoe UI",Roboto,sans-serif;color:#1b1f24;
background:#fff;margin:0;padding:32px 16px}
main{max-width:960px;margin:0 auto}
h1{font-size:24px;margin:0}h2{font-size:17px;margin:32px 0 8px;padding-bottom:4px;
border-bottom:2px solid #1b1f24}
.meta{color:#5d6673;margin:4px 0 20px}
.tiles{display:grid;grid-template-columns:repeat(auto-fit,minmax(160px,1fr));gap:10px}
.tile{border:1px solid #dde1e7;border-radius:8px;padding:12px}
.tile b{display:block;font-size:26px}.tile span{color:#5d6673;font-size:12.5px}
table{width:100%;border-collapse:collapse;margin-top:6px}
th{text-align:left;font-size:12px;color:#5d6673;border-bottom:1px solid #dde1e7;padding:6px}
td{border-bottom:1px solid #eef0f3;padding:6px;vertical-align:top}
.sev,.st{font-size:11px;font-weight:700;padding:1px 6px;border-radius:4px;
border:1px solid currentColor;white-space:nowrap}
.critical{background:#7f1d1d;color:#fff;border-color:#7f1d1d}.high{color:#b91c1c}
.medium{color:#b45309}.low{color:#2563eb}.info{color:#5d6673}
.fail{color:#b91c1c}.warn{color:#b45309}.pass{color:#15803d}.skip{color:#5d6673}
.muted{color:#5d6673}.small{font-size:12.5px}.mono{font-family:ui-monospace,Consolas,monospace;
font-size:12.5px;word-break:break-all}
ol.todo li{margin-bottom:8px}
.table-wrap{overflow-x:auto}
@media print{body{padding:0}h2{break-after:avoid}tr{break-inside:avoid}}
"""


def _badge(severity: str) -> str:
    css = _SEVERITY_CLASS.get(str(severity).upper(), "info")
    return f'<span class="sev {css}">{escape(str(severity))}</span>'


def _table(headers: list[str], rows: list[str], empty: str) -> str:
    if not rows:
        return f'<p class="muted">{escape(empty)}</p>'
    head = "".join(f"<th>{escape(h)}</th>" for h in headers)
    return (f'<div class="table-wrap"><table><thead><tr>{head}</tr></thead>'
            f'<tbody>{"".join(rows)}</tbody></table></div>')


def build_report(store, posture: PostureReport | None, *, hostname: str | None = None,
                 now: datetime | None = None) -> str:
    now = now or datetime.now()
    hostname = hostname if hostname is not None else platform.node()
    stats = store.stats()
    open_alerts = store.recent_alerts(50, unacknowledged_only=True)
    alerts = store.recent_alerts(25)
    findings = store.recent_findings(25)
    audit = store.recent_audit(25)

    score = f"{posture.score}/100" if posture and posture.evaluated else "not run"
    grade = f"grade {posture.grade}" if posture and posture.evaluated else "security check"
    tiles = "".join(
        f'<div class="tile"><b>{escape(str(value))}</b><span>{escape(label)}</span></div>'
        for value, label in ((score, grade), (stats["open_alerts"], "open alerts"),
                             (stats["total_findings"], "findings"),
                             (stats["total_events"], "events observed")))

    # -- action list: worst configuration problems, then urgent alerts ----- #
    todo: list[str] = []
    if posture:
        for r in sorted(posture.results, key=lambda r: (_STATUS_ORDER[r.status], -r.severity.rank)):
            if r.status in (CheckStatus.FAIL, CheckStatus.WARN) and r.remediation:
                todo.append(f"<li><b>{escape(r.title)}</b>: {escape(r.summary)}<br>"
                            f'<span class="small">Fix: {escape(r.remediation)}</span></li>')
    for a in open_alerts:
        if a.severity.value in ("CRITICAL", "HIGH"):
            technique = a.technique.split(" ", 1)[0] if a.technique else ""
            todo.append(f"<li>{_badge(a.severity.value)} <b>{escape(a.title)}</b> "
                        f'<span class="mono">{escape(a.source)}</span><br>'
                        f'<span class="small">{escape(guidance_for(technique))}</span></li>')
    todo_html = (f'<ol class="todo">{"".join(todo)}</ol>' if todo
                 else '<p class="muted">Nothing urgent. Keep monitoring enabled.</p>')

    posture_html = '<p class="muted">The security check was not run for this report.</p>'
    if posture:
        rows = []
        for r in sorted(posture.results, key=lambda r: (_STATUS_ORDER[r.status], -r.severity.rank)):
            details = "".join(f"<li>{escape(d)}</li>" for d in r.details)
            rows.append(
                f'<tr><td><span class="st {r.status.value}">{r.status.value.upper()}</span></td>'
                f"<td><b>{escape(r.title)}</b><br>{escape(r.summary)}"
                f'{f"<ul class=small>{details}</ul>" if details else ""}</td>'
                f"<td>{_badge(r.severity.value)}</td></tr>")
        posture_html = _table(["Result", "Check", "Severity"], rows,
                              "No checks apply to this platform.")

    technique_rows = [
        f'<tr><td class="mono">{escape(t["technique"])}</td><td>{t["n"]}</td>'
        f'<td class="small">{escape(guidance_for(t["technique"]))}</td></tr>'
        for t in stats["top_techniques"]]
    alert_rows = [
        f"<tr><td>{_badge(a.severity.value)}</td><td><b>{escape(a.title)}</b>"
        f'<br><span class="muted small">{escape(a.technique)}</span></td>'
        f'<td class="mono">{escape(a.source)}</td>'
        f'<td class="small">{escape(a.timestamp.isoformat(sep=" ", timespec="minutes"))}</td>'
        f'<td class="small">{"acknowledged" if a.acknowledged else "open"}</td></tr>'
        for a in alerts]
    finding_rows = [
        f'<tr><td>{_badge(f["severity"])}</td><td><b>{escape(f["title"] or "")}</b>'
        f'<br><span class="muted small">{escape(f["reasons"] or "")}</span></td>'
        f'<td class="mono">{escape(f["entity"] or "")}</td>'
        f'<td class="small">{escape(f["ts"] or "")}</td></tr>'
        for f in findings]
    audit_rows = [
        f'<tr><td class="small">{escape(e.timestamp.isoformat(sep=" ", timespec="minutes"))}</td>'
        f"<td>{escape(e.category)}</td><td>{escape(e.message)}"
        f'<br><span class="muted small">{escape(e.detail)}</span></td>'
        f"<td>{escape(e.actor)}</td></tr>"
        for e in audit]

    title = f"Aegis security report - {hostname}" if hostname else "Aegis security report"
    return f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>{escape(title)}</title><style>{_CSS}</style></head>
<body><main>
<h1>{escape(title)}</h1>
<p class="meta">Generated {escape(now.isoformat(sep=" ", timespec="minutes"))} by Aegis
{escape(__version__)}{f" &middot; {escape(posture.platform)}" if posture else ""}</p>
<div class="tiles">{tiles}</div>

<h2>What to do first</h2>{todo_html}
<h2>Security check</h2>{posture_html}
<h2>Top ATT&amp;CK techniques</h2>
{_table(["Technique", "Findings", "What it means / what to do"], technique_rows,
        "No detections recorded.")}
<h2>Recent alerts</h2>
{_table(["Severity", "Alert", "Source", "When", "Status"], alert_rows, "No alerts recorded.")}
<h2>Recent findings</h2>
{_table(["Severity", "Detection", "Subject", "When"], finding_rows, "No findings recorded.")}
<h2>Audit trail</h2>
{_table(["When", "Category", "Event", "By"], audit_rows, "The audit trail is empty.")}
</main></body></html>
"""
