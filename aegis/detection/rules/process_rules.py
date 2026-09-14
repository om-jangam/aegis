"""Process detection rules (MITRE ATT&CK-mapped)."""
from __future__ import annotations

from aegis.collectors.processes import flag_reasons
from aegis.core.events import Event, EventType, ProcessEvent
from aegis.core.models import Severity
from aegis.detection.base import DetectionContext, DetectionRule


class SuspiciousProcessLocationRule(DetectionRule):
    rule_id = "PROC-SUSPICIOUS-PATH"
    title = "Process launched from a suspicious location"
    severity = Severity.MEDIUM
    technique = "T1036"
    tactic = "Defense Evasion"
    description = ("Process running from a temp/download directory, without an "
                   "absolute path, or masquerading as a system binary.")
    event_types = (EventType.PROCESS_START,)

    def evaluate(self, event: Event, context: DetectionContext):
        if not isinstance(event, ProcessEvent):
            return None
        reasons = flag_reasons(event.exe, event.name)
        if reasons:
            return self.make_finding(
                score=45 + 10 * (len(reasons) - 1),
                reasons=reasons + [f"exe: {event.exe or 'unknown'}"],
                entity=f"proc:{event.name}",
                source_summary=event.summary())
        return None


PROCESS_RULES = [
    SuspiciousProcessLocationRule(),
]
