"""Network connection collector (psutil).

Polls the OS socket table and emits normalized :class:`NetworkEvent` objects.
A per-poll de-duplication set means each distinct connection is reported once,
so the detection engine isn't spammed by the same long-lived socket.

Fidelity note (see THREAT_MODEL.md): psutil polling is portable but can miss
connections that open and close *between* polls. Sysmon/ETW collectors (future)
close that gap; they will emit the same ``NetworkEvent`` type, so nothing
downstream changes.
"""
from __future__ import annotations

import logging
from collections.abc import Iterable

import psutil

from aegis.collectors.base import Collector
from aegis.core.events import Direction, EventSource, EventType, NetworkEvent

log = logging.getLogger(__name__)

_PROTO = {1: "TCP", 2: "UDP"}   # psutil socket .type -> label (SOCK_STREAM/DGRAM)


class NetworkCollector(Collector):
    name = "network"
    source = EventSource.PSUTIL

    def __init__(self, dedup: bool = True) -> None:
        super().__init__()
        self._dedup = dedup
        self._seen: set[str] = set()
        self._proc_cache: dict[int, str] = {}

    def available(self) -> bool:
        try:
            psutil.net_connections(kind="inet")
            return True
        except (psutil.AccessDenied, PermissionError):
            # Still partially usable; full visibility needs admin.
            return True
        except Exception:  # noqa: BLE001
            return False

    def poll(self) -> Iterable[NetworkEvent]:
        events: list[NetworkEvent] = []
        try:
            conns = psutil.net_connections(kind="inet")
        except (psutil.AccessDenied, PermissionError):
            log.warning("Access denied enumerating connections (full view needs admin).")
            return events

        for c in conns:
            if not c.raddr and c.status != psutil.CONN_LISTEN:
                continue
            is_listen = c.status == psutil.CONN_LISTEN or not c.raddr
            event = NetworkEvent(
                type=EventType.NETWORK_LISTEN if is_listen else EventType.NETWORK_CONNECTION,
                source=self.source,
                pid=c.pid,
                process_name=self._proc_name(c.pid),
                protocol=_PROTO.get(c.type, str(c.type)),
                local_ip=c.laddr.ip if c.laddr else "",
                local_port=c.laddr.port if c.laddr else 0,
                remote_ip=c.raddr.ip if c.raddr else "",
                remote_port=c.raddr.port if c.raddr else 0,
                status=c.status,
                direction=Direction.LISTEN if is_listen else Direction.OUTBOUND,
            )
            if self._dedup:
                if event.dedup_key in self._seen:
                    continue
                self._seen.add(event.dedup_key)
                if len(self._seen) > 5000:
                    self._seen.clear()
            events.append(event)
        return events

    def _proc_name(self, pid: int | None) -> str:
        if not pid:
            return "System"
        if pid in self._proc_cache:
            return self._proc_cache[pid]
        try:
            name = psutil.Process(pid).name()
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            name = f"pid:{pid}"
        self._proc_cache[pid] = name
        if len(self._proc_cache) > 2000:
            self._proc_cache.clear()
        return name
