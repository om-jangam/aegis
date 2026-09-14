"""Collector contract.

A collector turns a raw telemetry source into normalized events. Concrete
collectors implement :meth:`poll`, which the pipeline drives on a fixed interval
(e.g. psutil scanning the socket table); :meth:`available` lets a collector
declare it can't run here (e.g. Sysmon not installed) so the pipeline skips it
instead of crashing.

Keeping this contract tiny is deliberate: the pipeline depends on *this* abstract
type, never on psutil/Sysmon/ETW directly, so telemetry sources are swappable.
"""
from __future__ import annotations

import abc
import logging
from collections.abc import Iterable

from aegis.core.events import Event, EventSource

log = logging.getLogger(__name__)


class Collector(abc.ABC):
    """Abstract base for all telemetry collectors."""

    #: Human-readable collector name (used in logs and the UI).
    name: str = "collector"
    #: Which telemetry source this collector represents.
    source: EventSource = EventSource.SYSTEM

    def __init__(self) -> None:
        self._running = False

    @abc.abstractmethod
    def poll(self) -> Iterable[Event]:
        """Return the events observed since the last poll. Must not block long."""
        raise NotImplementedError

    # -- lifecycle ---------------------------------------------------------- #
    def start(self) -> None:
        self._running = True
        log.info("Collector '%s' started (source=%s).", self.name, self.source.value)

    def stop(self) -> None:
        self._running = False
        log.info("Collector '%s' stopped.", self.name)

    @property
    def running(self) -> bool:
        return self._running

    def available(self) -> bool:
        """Whether this collector can run in the current environment.

        Lets the pipeline gracefully skip, e.g., a Sysmon collector on a host
        without Sysmon installed, instead of crashing.
        """
        return True
