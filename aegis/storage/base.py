"""Storage contract.

Defines the persistence interface the rest of the app depends on. The concrete
SQLite implementation is added in a later phase; keeping an interface here means
the store can later be swapped (e.g. for OpenSearch in a distributed deployment)
without touching callers.
"""
from __future__ import annotations

import abc
from collections.abc import Iterable

from aegis.core.events import Event
from aegis.core.models import Alert, AuditEvent, Finding


class EventStore(abc.ABC):
    """Abstract persistence layer for telemetry, findings, alerts and audit."""

    @abc.abstractmethod
    def save_events(self, events: Iterable[Event]) -> None: ...

    @abc.abstractmethod
    def save_finding(self, finding: Finding) -> int: ...

    @abc.abstractmethod
    def save_alert(self, alert: Alert) -> int: ...

    @abc.abstractmethod
    def add_audit(self, event: AuditEvent) -> int: ...

    @abc.abstractmethod
    def recent_alerts(self, limit: int = 100, unacknowledged_only: bool = False) -> list[Alert]: ...

    @abc.abstractmethod
    def recent_audit(self, limit: int = 200, category: str | None = None) -> list[AuditEvent]: ...

    @abc.abstractmethod
    def purge_old(self, days: int) -> int: ...

    @abc.abstractmethod
    def close(self) -> None: ...
