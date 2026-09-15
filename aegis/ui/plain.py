"""Everyday wording for the security data shown in the desktop app.

Most people who open Aegis are not security analysts. This module turns raw
states ("ESTABLISHED", "DETECTION", "T1071 (Command and Control)") into words
anyone understands. It has no UI imports, so the wording is unit-tested.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime

from aegis.detection.guidance import guidance_for

AUDIT_FILTERS: tuple[tuple[str, str], ...] = (
    ("All", "Everything"),
    ("DETECTION", "Alerts"),
    ("RESPONSE", "Blocked addresses"),
    ("RULE", "Firewall changes"),
    ("SYSTEM", "Aegis itself"),
)
_AUDIT_CATEGORY = {"DETECTION": "Alert", "RESPONSE": "Blocked", "RULE": "Firewall",
                   "SYSTEM": "Aegis"}
_CONNECTION_STATE = {
    "ESTABLISHED": "Connected",
    "LISTEN": "Waiting for connections",
    "SYN_SENT": "Connecting",
    "SYN_RECV": "Connecting",
    "TIME_WAIT": "Closing",
    "CLOSE_WAIT": "Closing",
    "FIN_WAIT1": "Closing",
    "FIN_WAIT2": "Closing",
    "LAST_ACK": "Closing",
    "CLOSING": "Closing",
    "NONE": "",
}


def plural(count: int, word: str, many: str | None = None) -> str:
    return f"{count} {word if count == 1 else (many or word + 's')}"


def audit_category(category: str) -> str:
    return _AUDIT_CATEGORY.get((category or "").upper(), (category or "").title())


def connection_state(status: str) -> str:
    key = (status or "").upper()
    return _CONNECTION_STATE.get(key, key.replace("_", " ").title())


def advice_for_alert(technique_ref: str) -> str:
    """What to do about an alert, from its stored "T1071 (Tactic)" reference."""
    technique = (technique_ref or "").split(" ", 1)[0]
    return guidance_for(technique)


def time_ago(when: datetime, now: datetime | None = None) -> str:
    now = now or datetime.now()
    seconds = (now - when).total_seconds()
    if seconds < 60:
        return "just now"
    if seconds < 3600:
        return f"{plural(int(seconds // 60), 'minute')} ago"
    if seconds < 86400:
        return f"{plural(int(seconds // 3600), 'hour')} ago"
    if seconds < 2 * 86400:
        return "yesterday"
    return when.strftime("%d %b %Y, %H:%M")


@dataclass
class ProtectionStatus:
    level: str                 # "ok" | "warn" | "danger" | "paused"
    headline: str
    details: list[str] = field(default_factory=list)


def protection_status(*, monitoring: bool, serious_alerts: int, failed_checks: int | None
                      ) -> ProtectionStatus:
    """One sentence answering "am I safe?", plus what needs doing.

    ``failed_checks`` is None when no security check has run yet.
    """
    problems: list[str] = []
    if serious_alerts:
        problems.append(f"{plural(serious_alerts, 'serious alert')} to review")
    if failed_checks:
        problems.append(f"{plural(failed_checks, 'security setting')} to fix")

    if not monitoring:
        return ProtectionStatus("paused", "Monitoring is paused",
                                ["Aegis is not watching for attacks right now.", *problems])
    if problems:
        count = serious_alerts + (failed_checks or 0)
        verb = "needs" if count == 1 else "need"
        return ProtectionStatus("danger" if serious_alerts else "warn",
                                f"{plural(count, 'thing')} {verb} your attention", problems)
    details = ["Monitoring is on and no serious alerts are waiting."]
    details.append("Run a security check to find weak settings." if failed_checks is None
                   else "All security checks passed.")
    return ProtectionStatus("ok", "Your computer is protected", details)
