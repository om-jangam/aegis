"""Mapping of Aegis objects to the shared SENTINEL-X event schema.

``shared/event_schema.json`` is the contract. :func:`to_shared_event` is the one
place that decides what leaves the machine, so every field mapping, the MITRE
names and the redaction rules live here.

Never forwarded: API keys, the dashboard token, raw collector records, file
contents. Command lines and free text pass through :func:`redact` first.
"""
from __future__ import annotations

import re
import uuid
from dataclasses import dataclass
from datetime import UTC, datetime

from aegis.core.events import Event, FileEvent, NetworkEvent, ProcessEvent
from aegis.core.models import Alert, Finding, Severity
from aegis.detection.guidance import guidance_for
from aegis.forwarding.agent import AgentInfo
from aegis.posture.base import CheckStatus, PostureReport

SCHEMA_VERSION = "1.0"
RESPONSES = ("none", "blocked_host", "notified")
MAX_COMMAND_LINE = 1024
MAX_MESSAGE = 2000

TECHNIQUE_NAMES: dict[str, str] = {
    "T1003": "OS Credential Dumping",
    "T1021": "Remote Services",
    "T1036": "Masquerading",
    "T1046": "Network Service Discovery",
    "T1059": "Command and Scripting Interpreter",
    "T1059.001": "PowerShell",
    "T1059.004": "Unix Shell",
    "T1071": "Application Layer Protocol",
    "T1098": "Account Manipulation",
    "T1105": "Ingress Tool Transfer",
    "T1110": "Brute Force",
    "T1218": "System Binary Proxy Execution",
    "T1486": "Data Encrypted for Impact",
    "T1490": "Inhibit System Recovery",
    "T1543": "Create or Modify System Process",
    "T1554": "Compromise Host Software Binary",
    "T1565": "Data Manipulation",
    "T1565.001": "Stored Data Manipulation",
    "T1566": "Phishing",
    "T1566.001": "Spearphishing Attachment",
    "T1571": "Non-Standard Port",
}

_TECHNIQUE_ID = re.compile(r"^T\d{4}(\.\d{3})?$")
_TACTIC_IN_PARENS = re.compile(r"\(([^)]*)\)")


@dataclass(frozen=True)
class Heartbeat:
    """Periodic sign of life, carrying the latest security check if there is one."""

    posture: PostureReport | None = None


# --------------------------------------------------------------------------- #
# Redaction
# --------------------------------------------------------------------------- #
_SECRET_PATTERNS: tuple[tuple[re.Pattern[str], str], ...] = (
    (re.compile(r"(?i)\b(bearer|basic)\s+[A-Za-z0-9._~+/=-]{8,}"), r"\1 [REDACTED]"),
    (re.compile(r"(?i)(\w+://)[^/\s:@]+:[^/\s@]+@"), r"\1[REDACTED]@"),
    (re.compile(
        r"(?i)([\w.-]*(?:password|passwd|pwd|secret|token|api[_-]?key|access[_-]?key|"
        r"credential)[\w.-]*)(\s*[=:]\s*|\s+)(\"[^\"]*\"|'[^']*'|[^\s&;]+)"),
     r"\1\2[REDACTED]"),
)


def redact(text: str, limit: int) -> str:
    """Mask likely secrets (passwords, tokens, keys, URL credentials) and truncate."""
    text = text or ""
    for pattern, replacement in _SECRET_PATTERNS:
        text = pattern.sub(replacement, text)
    return text if len(text) <= limit else text[: limit - 3] + "..."


# --------------------------------------------------------------------------- #
# Field helpers
# --------------------------------------------------------------------------- #
def rule_source(rule_id: str) -> str:
    rule_id = (rule_id or "").upper()
    if rule_id.startswith("SIGMA-"):
        return "sigma"
    if rule_id == "NET-THREAT-INTEL":
        return "threat_intel"
    if rule_id.startswith("ML-"):
        return "ml"
    return "python"


def _utc(moment: datetime | None) -> str:
    moment = moment or datetime.now(tz=UTC)
    # Aegis stores naive local times; astimezone() interprets them as local.
    return moment.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def _mitre(technique: str, tactic: str) -> list[dict]:
    reference = (technique or "").strip()
    technique_id = reference.split(" ", 1)[0].upper()
    if not _TECHNIQUE_ID.match(technique_id):
        return []
    if not tactic:
        match = _TACTIC_IN_PARENS.search(reference)
        tactic = match.group(1).strip() if match else ""
    name = TECHNIQUE_NAMES.get(technique_id) or TECHNIQUE_NAMES.get(technique_id.split(".")[0], "")
    return [{"technique_id": technique_id, "technique_name": name, "tactic": tactic}]


def _no_network() -> dict:
    return {"src_ip": "", "dst_ip": "", "dst_port": 0, "protocol": ""}


def _details(event: Event | None, message: str) -> dict:
    details: dict = {"network": _no_network(), "message": redact(message, MAX_MESSAGE)}
    if isinstance(event, NetworkEvent):
        details["network"] = {
            "src_ip": event.local_ip or "",
            "dst_ip": event.remote_ip or "",
            "dst_port": int(event.remote_port or 0),
            "protocol": (event.protocol or "").lower(),
        }
        details["process"] = {"name": event.process_name or "", "pid": event.pid}
    elif isinstance(event, ProcessEvent):
        details["process"] = {
            "name": event.name or "",
            "pid": event.pid,
            "ppid": event.ppid,
            "parent_name": event.parent_name,
            "executable": event.exe or "",
            "command_line": redact(event.cmdline, MAX_COMMAND_LINE),
            "user": event.username or "",
        }
    elif isinstance(event, FileEvent):
        details["file"] = {
            "path": event.path,
            "action": event.action,
            "size": event.size,
            "previous_size": event.previous_size,
            "digest": event.digest,
            "previous_digest": event.previous_digest,
        }
    return details


def _audit(report: PostureReport | None) -> dict | None:
    if report is None:
        return None
    checked = report.evaluated > 0
    return {
        "score": report.score if checked else None,
        "grade": report.grade if checked else None,
        "failed": report.count(CheckStatus.FAIL),
        "warnings": report.count(CheckStatus.WARN),
        "passed": report.count(CheckStatus.PASS),
        "checked_at": _utc(report.generated_at),
    }


def _audit_severity(report: PostureReport) -> str:
    if not report.evaluated:
        return "info"
    score = report.score
    if score >= 90:
        return "info"
    if score >= 70:
        return "low"
    if score >= 50:
        return "medium"
    return "high"


def _finding_message(title: str, reasons: list[str], technique: str) -> str:
    because = "; ".join(r for r in reasons if r)
    parts = [title + "."]
    if because:
        parts.append(because + ".")
    parts.append("What to do: " + guidance_for(technique.split(" ", 1)[0] if technique else ""))
    return " ".join(parts)


# --------------------------------------------------------------------------- #
# The mapping
# --------------------------------------------------------------------------- #
def to_shared_event(item: Finding | Alert | PostureReport | Heartbeat, agent: AgentInfo, *,
                    source_event: Event | None = None, finding: Finding | None = None,
                    response_taken: str = "none") -> dict:
    """Convert one Aegis object into a shared-schema event.

    ``source_event`` is the telemetry that triggered a finding or alert, used for
    the process/network/file details. ``finding`` is the finding behind an
    alert, which carries the rule identity the alert itself does not store.
    """
    if response_taken not in RESPONSES:
        raise ValueError(f"unknown response_taken {response_taken!r}")

    audit = None
    if isinstance(item, Finding):
        event_type = "finding"
        severity = item.severity
        rule = {"id": item.rule_id, "name": item.title, "source": rule_source(item.rule_id)}
        mitre = _mitre(item.technique, item.tactic)
        message = _finding_message(item.title, item.reasons, item.technique)
        timestamp = item.timestamp
    elif isinstance(item, Alert):
        event_type = "alert"
        severity = item.severity
        if finding is not None:
            rule = {"id": finding.rule_id, "name": finding.title,
                    "source": rule_source(finding.rule_id)}
            mitre = _mitre(finding.technique, finding.tactic)
            message = _finding_message(finding.title, finding.reasons, finding.technique)
        else:
            rule = {"id": "AEGIS-ALERT", "name": item.title, "source": "python"}
            mitre = _mitre(item.technique, "")
            message = f"{item.title}. {item.message}"
        timestamp = item.timestamp
    elif isinstance(item, PostureReport):
        event_type = "audit_score"
        severity = _audit_severity(item)
        rule = {"id": "AEGIS-SECURITY-CHECK", "name": "Security check", "source": "python"}
        mitre = []
        audit = _audit(item)
        message = (f"Security check score {audit['score']}/100 (grade {audit['grade']}): "
                   f"{audit['failed']} failed, {audit['warnings']} warnings."
                   if audit["score"] is not None else "The security check could not evaluate this host.")
        timestamp = item.generated_at
    elif isinstance(item, Heartbeat):
        event_type = "heartbeat"
        severity = "info"
        rule = {"id": "AEGIS-HEARTBEAT", "name": "Agent heartbeat", "source": "python"}
        mitre = []
        audit = _audit(item.posture)
        message = "Aegis is running."
        timestamp = None
    else:
        raise TypeError(f"cannot forward {type(item).__name__}")

    details = _details(source_event, message)
    if audit is not None:
        details["audit"] = audit
    return {
        "schema_version": SCHEMA_VERSION,
        "event_id": str(uuid.uuid4()),
        "timestamp": _utc(timestamp),
        "agent": agent.to_dict(),
        "event_type": event_type,
        "severity": severity.value.lower() if isinstance(severity, Severity) else severity,
        "rule": rule,
        "mitre": mitre,
        "details": details,
        "response_taken": response_taken,
    }
