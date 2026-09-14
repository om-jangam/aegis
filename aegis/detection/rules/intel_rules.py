"""Threat-intelligence detection: connections to known-malicious infrastructure."""
from __future__ import annotations

from aegis.config import settings
from aegis.core.events import Event, EventType, NetworkEvent
from aegis.core.models import Severity
from aegis.detection.base import DetectionContext, DetectionRule
from aegis.intel import ThreatIntel, get_intel


class ThreatIntelMatchRule(DetectionRule):
    rule_id = "NET-THREAT-INTEL"
    title = "Connection to known-malicious infrastructure"
    severity = Severity.CRITICAL
    technique = "T1071"
    tactic = "Command and Control"
    description = ("The remote address appears on a threat-intelligence blocklist, such as "
                   "a botnet command-and-control server or a hijacked network. Unlike "
                   "behavioural rules this fires even on ordinary ports like 443.")
    event_types = (EventType.NETWORK_CONNECTION,)

    def __init__(self, intel: ThreatIntel | None = None):
        self._intel = intel

    def evaluate(self, event: Event, context: DetectionContext):
        if not isinstance(event, NetworkEvent) or not event.remote_ip:
            return None
        if not settings.threat_intel_enabled or event.remote_ip in settings.trusted_remote_ips:
            return None
        intel = self._intel if self._intel is not None else get_intel()
        match = intel.match(event.remote_ip)
        if match is None:
            return None
        where = "is listed" if "/" not in match.indicator \
            else f"is inside the listed range {match.indicator}"
        return self.make_finding(
            score=95,
            reasons=[f"{event.remote_ip} {where} in threat feed '{match.source}'",
                     f"Process: {event.process_name or 'unknown'}"],
            entity=f"{event.remote_ip}:{event.remote_port}",
            source_summary=event.summary())


INTEL_RULES = [ThreatIntelMatchRule()]
