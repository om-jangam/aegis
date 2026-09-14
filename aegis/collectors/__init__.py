"""Telemetry collectors.

Each collector observes one source of host activity (network sockets, processes,
and — in future — Sysmon/ETW) and yields normalized
:class:`~aegis.core.events.Event` objects. The pipeline depends only on the
:class:`Collector` contract, so sources are swappable.
"""
from aegis.collectors.base import Collector
from aegis.collectors.network import NetworkCollector
from aegis.collectors.processes import ProcessCollector

__all__ = ["Collector", "NetworkCollector", "ProcessCollector"]
