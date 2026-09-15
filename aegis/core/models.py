"""Domain, detection and audit models.

Separated from :mod:`aegis.core.events` (raw telemetry) on purpose:

* ``events``  -> what was *observed* (immutable facts from collectors)
* ``models``  -> what Aegis *decides and does* (findings, alerts, rules, audit)

Keeping "observation" and "judgement" in different modules mirrors how real
detection platforms separate the data plane from the decision plane.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from enum import StrEnum


# --------------------------------------------------------------------------- #
# Shared severity scale
# --------------------------------------------------------------------------- #
class Severity(StrEnum):
    INFO = "INFO"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"

    @property
    def rank(self) -> int:
        return {"INFO": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}[self.value]

    # Rank-based ordering so `Severity.HIGH > Severity.LOW` is meaningful.
    # All four operators are defined to stay consistent (the inherited ``str``
    # ordering would otherwise compare members lexicographically).
    def __ge__(self, other: object) -> bool:
        if isinstance(other, Severity):
            return self.rank >= other.rank
        return NotImplemented

    def __gt__(self, other: object) -> bool:
        if isinstance(other, Severity):
            return self.rank > other.rank
        return NotImplemented

    def __le__(self, other: object) -> bool:
        if isinstance(other, Severity):
            return self.rank <= other.rank
        return NotImplemented

    def __lt__(self, other: object) -> bool:
        if isinstance(other, Severity):
            return self.rank < other.rank
        return NotImplemented


# --------------------------------------------------------------------------- #
# Firewall domain (the "response"/rule side)
# --------------------------------------------------------------------------- #
class FirewallDirection(StrEnum):
    IN = "In"
    OUT = "Out"


class FirewallAction(StrEnum):
    ALLOW = "Allow"
    BLOCK = "Block"
    BYPASS = "Bypass"


class Protocol(StrEnum):
    TCP = "TCP"
    UDP = "UDP"
    ICMP = "ICMPv4"
    ANY = "Any"


@dataclass
class FirewallRule:
    """A Windows firewall rule managed by Aegis (tagged in its name)."""

    name: str
    direction: FirewallDirection = FirewallDirection.IN
    action: FirewallAction = FirewallAction.ALLOW
    enabled: bool = True
    protocol: Protocol = Protocol.ANY
    local_ip: str = "any"
    local_port: str = "any"
    remote_ip: str = "any"
    remote_port: str = "any"
    program: str = ""
    service: str = ""
    description: str = ""
    profile: str = ""


# --------------------------------------------------------------------------- #
# Detection side
# --------------------------------------------------------------------------- #
@dataclass
class Finding:
    """The result of a detection rule firing on one or more events.

    A finding is *explainable*: it always carries the rule that produced it, the
    MITRE ATT&CK technique it maps to, a numeric score, and human-readable
    ``reasons``. This is what makes the detection layer defensible rather than a
    black box.
    """

    rule_id: str
    title: str
    severity: Severity
    score: int = 0                       # 0-100 confidence/risk
    technique: str = ""                  # MITRE ATT&CK id, e.g. "T1071"
    tactic: str = ""                     # e.g. "Command and Control"
    description: str = ""
    reasons: list[str] = field(default_factory=list)
    source_summary: str = ""             # short description of the triggering event
    entity: str = ""                     # the subject (ip:port / process) for dedup
    timestamp: datetime = field(default_factory=datetime.now)
    id: int | None = None
    process_name: str = ""               # program involved, when known
    parent_name: str = ""                # program that started it, when known

    @property
    def attack_ref(self) -> str:
        if self.technique and self.tactic:
            return f"{self.technique} ({self.tactic})"
        return self.technique or ""


@dataclass
class Alert:
    """A finding promoted to a user-facing alert (crossed the alert threshold)."""

    title: str
    message: str
    severity: Severity = Severity.MEDIUM
    source: str = ""
    technique: str = ""
    score: int = 0
    acknowledged: bool = False
    timestamp: datetime = field(default_factory=datetime.now)
    id: int | None = None
    process_name: str = ""
    parent_name: str = ""


# --------------------------------------------------------------------------- #
# Audit side
# --------------------------------------------------------------------------- #
@dataclass
class AuditEvent:
    """An immutable record of something Aegis did or observed (for accountability)."""

    category: str          # "RULE" | "DETECTION" | "RESPONSE" | "SYSTEM"
    action: str            # machine-readable action, e.g. "rule_created"
    severity: Severity = Severity.INFO
    message: str = ""
    detail: str = ""
    actor: str = "aegis"
    timestamp: datetime = field(default_factory=datetime.now)
    id: int | None = None
