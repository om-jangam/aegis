"""Detection rule contract.

A ``DetectionRule`` inspects a single normalized event (optionally using recent
history via :class:`DetectionContext`) and returns a :class:`Finding` when its
condition matches, or ``None`` otherwise.

Every rule carries metadata that makes its output explainable and defensible:

* ``rule_id``   — stable identifier (used in tests, dedup, audit).
* ``technique`` / ``tactic`` — MITRE ATT&CK mapping (the language of blue teams).
* ``severity``  — baseline severity when the rule fires.

This mirrors detection-as-code practice (e.g. Sigma): rules are small, testable,
individually documented units — not opaque model outputs.
"""
from __future__ import annotations

import abc
import threading
from collections import deque

from aegis.core.events import Event, EventType
from aegis.core.models import Finding, Severity


class DetectionContext:
    """Rolling window of recent events, shared with rules for stateful logic.

    Some detections need history (e.g. "same process contacted 20 distinct hosts
    in 60 seconds" = beaconing/scanning). The context provides bounded recent
    history without each rule maintaining its own state.

    Thread-safe: multiple collector threads feed the shared engine concurrently,
    so ``remember`` (append) and ``recent`` (snapshot) are guarded by a lock —
    otherwise iterating the deque while another thread appends could raise.
    """

    def __init__(self, maxlen: int = 2000) -> None:
        self._events: deque[Event] = deque(maxlen=maxlen)
        self._lock = threading.Lock()

    def remember(self, event: Event) -> None:
        with self._lock:
            self._events.append(event)

    def recent(self, event_type: EventType | None = None) -> list[Event]:
        with self._lock:
            snapshot = list(self._events)      # copy under lock, filter outside
        if event_type is None:
            return snapshot
        return [e for e in snapshot if e.type == event_type]

    def __len__(self) -> int:
        with self._lock:
            return len(self._events)


class DetectionRule(abc.ABC):
    """Abstract base for all detection rules."""

    #: Stable unique id, e.g. "NET-C2-UNCOMMON-PORT".
    rule_id: str = "RULE"
    #: Short human title shown in findings/alerts.
    title: str = "Detection rule"
    #: Baseline severity when this rule fires.
    severity: Severity = Severity.MEDIUM
    #: MITRE ATT&CK technique/tactic this rule maps to.
    technique: str = ""
    tactic: str = ""
    #: Longer description of what the rule detects and why it matters.
    description: str = ""
    #: Event types this rule wants to see; the engine filters on this.
    event_types: tuple[EventType, ...] = ()
    #: Whether the rule is active.
    enabled: bool = True

    @abc.abstractmethod
    def evaluate(self, event: Event, context: DetectionContext) -> Finding | None:
        """Return a Finding if ``event`` matches this rule, else ``None``."""
        raise NotImplementedError

    def wants(self, event: Event) -> bool:
        """Whether this rule should be offered the given event."""
        return not self.event_types or event.type in self.event_types

    # Convenience for subclasses to build a consistent Finding.
    def make_finding(self, *, score: int, reasons: list[str], entity: str,
                     source_summary: str, severity: Severity | None = None) -> Finding:
        return Finding(
            rule_id=self.rule_id,
            title=self.title,
            severity=severity or self.severity,
            score=max(0, min(100, score)),
            technique=self.technique,
            tactic=self.tactic,
            description=self.description,
            reasons=reasons,
            entity=entity,
            source_summary=source_summary,
        )
