"""Network detection rules, each mapped to a MITRE ATT&CK technique.

Every rule is small, explainable and independently testable. Rules only fire on
routable/remote peers unless the technique is specifically about internal
movement (e.g. RDP/SMB lateral movement).
"""
from __future__ import annotations

from aegis.config import settings
from aegis.core.events import Event, EventType, NetworkEvent
from aegis.core.models import Severity
from aegis.detection.base import DetectionContext, DetectionRule
from aegis.detection.ports import (
    C2_PORTS,
    COMMON_PORTS,
    LEGACY_PORTS,
    REMOTE_ADMIN_PORTS,
)


def _trusted(event: NetworkEvent) -> bool:
    return event.remote_ip in settings.trusted_remote_ips


class SuspiciousC2PortRule(DetectionRule):
    rule_id = "NET-C2-PORT"
    title = "Connection to a known C2 / backdoor port"
    severity = Severity.HIGH
    technique = "T1571"
    tactic = "Command and Control"
    description = ("Outbound connection to a port commonly used as a default by "
                   "command-and-control frameworks or backdoors.")
    event_types = (EventType.NETWORK_CONNECTION,)

    def evaluate(self, event: Event, context: DetectionContext):
        if not isinstance(event, NetworkEvent):
            return None
        if _trusted(event):
            return None
        if event.remote_port in C2_PORTS:
            score = 85 if event.is_remote else 60
            return self.make_finding(
                score=score,
                reasons=[f"Remote port {event.remote_port} is a common C2/backdoor default",
                         f"Process: {event.process_name}"],
                entity=f"{event.remote_ip}:{event.remote_port}",
                source_summary=event.summary())
        return None


class RemoteServicesRule(DetectionRule):
    rule_id = "NET-REMOTE-SVC"
    title = "Remote administration service connection"
    severity = Severity.MEDIUM
    technique = "T1021"
    tactic = "Lateral Movement"
    description = ("Connection over a remote-administration protocol (RDP, SMB, "
                   "WinRM). Legitimate for admins, but also a lateral-movement path.")
    event_types = (EventType.NETWORK_CONNECTION,)

    def evaluate(self, event: Event, context: DetectionContext):
        if not isinstance(event, NetworkEvent):
            return None
        if _trusted(event):
            return None
        svc = REMOTE_ADMIN_PORTS.get(event.remote_port)
        if svc:
            sev = Severity.HIGH if event.is_remote else Severity.MEDIUM
            return self.make_finding(
                severity=sev,
                score=70 if event.is_remote else 40,
                reasons=[f"{svc} connection to {event.remote_ip}",
                         "Public peer" if event.is_remote else "Internal peer"],
                entity=f"{event.remote_ip}:{event.remote_port}",
                source_summary=event.summary())
        return None


class LegacyPlaintextProtocolRule(DetectionRule):
    rule_id = "NET-LEGACY-PROTO"
    title = "Legacy / plaintext protocol to a public host"
    severity = Severity.MEDIUM
    technique = "T1071"
    tactic = "Command and Control"
    description = ("Use of an unencrypted legacy protocol (Telnet, FTP, SMTP…) to "
                   "a public host — credential/exfiltration risk.")
    event_types = (EventType.NETWORK_CONNECTION,)

    def evaluate(self, event: Event, context: DetectionContext):
        if not isinstance(event, NetworkEvent):
            return None
        if _trusted(event):
            return None
        proto = LEGACY_PORTS.get(event.remote_port)
        if proto and event.is_remote:
            return self.make_finding(
                score=55,
                reasons=[f"{proto} (plaintext) to public host {event.remote_ip}"],
                entity=f"{event.remote_ip}:{event.remote_port}",
                source_summary=event.summary())
        return None


class UncommonPortToPublicRule(DetectionRule):
    rule_id = "NET-UNCOMMON-PORT"
    title = "Uncommon port to a public host"
    severity = Severity.LOW
    technique = "T1571"
    tactic = "Command and Control"
    description = ("Outbound to a non-standard port on a public host. Weak signal "
                   "on its own; useful in aggregate / with other findings.")
    event_types = (EventType.NETWORK_CONNECTION,)

    def evaluate(self, event: Event, context: DetectionContext):
        if not isinstance(event, NetworkEvent):
            return None
        if _trusted(event) or not event.is_remote:
            return None
        p = event.remote_port
        if p and p not in COMMON_PORTS and p not in C2_PORTS and p >= 1024:
            return self.make_finding(
                score=25,
                reasons=[f"Uncommon port {p} to public IP {event.remote_ip}"],
                entity=f"{event.remote_ip}:{event.remote_port}",
                source_summary=event.summary())
        return None


class InterpreterNetworkRule(DetectionRule):
    rule_id = "NET-INTERPRETER"
    title = "Script interpreter making a network connection"
    severity = Severity.HIGH
    technique = "T1059"
    tactic = "Execution"
    description = ("A scripting interpreter (PowerShell, cmd, wscript, mshta…) is "
                   "talking to the network — a common living-off-the-land pattern.")
    event_types = (EventType.NETWORK_CONNECTION,)
    _INTERPRETERS = {"powershell.exe", "pwsh.exe", "cmd.exe", "wscript.exe",
                     "cscript.exe", "mshta.exe", "rundll32.exe", "regsvr32.exe"}

    def evaluate(self, event: Event, context: DetectionContext):
        if not isinstance(event, NetworkEvent):
            return None
        if _trusted(event) or not event.is_remote:
            return None
        if event.process_name.lower() in self._INTERPRETERS:
            return self.make_finding(
                score=75,
                reasons=[f"{event.process_name} connected to {event.remote_ip}:{event.remote_port}",
                         "Living-off-the-land binary with network activity"],
                entity=f"{event.remote_ip}:{event.remote_port}",
                source_summary=event.summary())
        return None


class NetworkScanningRule(DetectionRule):
    rule_id = "NET-SCAN"
    title = "Possible network scanning / sweep"
    severity = Severity.HIGH
    technique = "T1046"
    tactic = "Discovery"
    description = ("A single process contacted many distinct hosts in a short "
                   "window — consistent with host/port scanning.")
    event_types = (EventType.NETWORK_CONNECTION,)
    DISTINCT_HOST_THRESHOLD = 15

    def evaluate(self, event: Event, context: DetectionContext):
        if not isinstance(event, NetworkEvent):
            return None
        if not event.pid:
            return None
        peers = {
            e.remote_ip for e in context.recent(EventType.NETWORK_CONNECTION)
            if isinstance(e, NetworkEvent) and e.pid == event.pid and e.remote_ip
        }
        if len(peers) >= self.DISTINCT_HOST_THRESHOLD:
            return self.make_finding(
                score=80,
                reasons=[f"{event.process_name} contacted {len(peers)} distinct hosts recently"],
                entity=f"pid:{event.pid}:{event.process_name}",
                source_summary=event.summary())
        return None


class ListeningOnSensitivePortRule(DetectionRule):
    rule_id = "NET-LISTEN-SENSITIVE"
    title = "Listening on a sensitive port"
    severity = Severity.MEDIUM
    technique = "T1571"
    tactic = "Command and Control"
    description = "A process is listening on a port often used by backdoors/RATs."
    event_types = (EventType.NETWORK_LISTEN,)

    def evaluate(self, event: Event, context: DetectionContext):
        if not isinstance(event, NetworkEvent):
            return None
        if event.local_port in C2_PORTS or event.local_port in set(settings.suspicious_ports):
            return self.make_finding(
                score=50,
                reasons=[f"{event.process_name} is listening on port {event.local_port}"],
                entity=f"listen:{event.local_port}",
                source_summary=event.summary())
        return None


NETWORK_RULES = [
    SuspiciousC2PortRule(),
    RemoteServicesRule(),
    LegacyPlaintextProtocolRule(),
    InterpreterNetworkRule(),
    NetworkScanningRule(),
    ListeningOnSensitivePortRule(),
    UncommonPortToPublicRule(),
]
