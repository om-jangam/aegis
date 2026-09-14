"""Process collector (psutil).

Provides two things:

* :meth:`ProcessCollector.poll` — emits :class:`ProcessEvent` for newly-seen
  processes (feeds the detection engine, e.g. "script interpreter started").
* :func:`snapshot` — a point-in-time list of processes enriched with connection
  counts and suspicion flags, used by the UI's Processes view and by process-
  context detection rules.
"""
from __future__ import annotations

import logging
import os
from collections.abc import Iterable
from dataclasses import dataclass, field

import psutil

from aegis.collectors.base import Collector
from aegis.core.events import EventSource, EventType, ProcessEvent

log = logging.getLogger(__name__)

# Locations legitimate long-running network software rarely runs from.
_SUSPICIOUS_DIRS = ("\\temp\\", "\\tmp\\", "\\appdata\\local\\temp",
                    "\\downloads\\", "\\$recycle.bin")
_SYSTEM_NAMES = {"svchost.exe", "lsass.exe", "services.exe", "csrss.exe", "winlogon.exe"}


@dataclass
class ProcessInfo:
    pid: int
    name: str
    exe: str = ""
    username: str = ""
    memory_mb: float = 0.0
    num_connections: int = 0
    create_time: float = 0.0
    suspicious_reasons: list[str] = field(default_factory=list)

    @property
    def is_suspicious(self) -> bool:
        return bool(self.suspicious_reasons)


def flag_reasons(exe: str, name: str) -> list[str]:
    """Heuristic suspicion flags for a process (used by rules and the UI)."""
    reasons: list[str] = []
    low = (exe or "").lower()
    if any(d in low for d in _SUSPICIOUS_DIRS):
        reasons.append("Runs from a temporary/download directory")
    if exe and not os.path.isabs(exe):
        reasons.append("Executable path is not absolute")
    if name.lower() in _SYSTEM_NAMES and low and "\\windows\\" not in low:
        reasons.append(f"System-like name '{name}' outside the Windows directory")
    return reasons


def snapshot(limit: int | None = None) -> list[ProcessInfo]:
    """Return running processes, most-connected / suspicious first."""
    conn_counts: dict[int, int] = {}
    try:
        for c in psutil.net_connections(kind="inet"):
            if c.pid:
                conn_counts[c.pid] = conn_counts.get(c.pid, 0) + 1
    except (psutil.AccessDenied, PermissionError):
        pass

    procs: list[ProcessInfo] = []
    for p in psutil.process_iter(["pid", "name", "username", "create_time", "memory_info"]):
        try:
            info = p.info
            exe = ""
            try:
                exe = p.exe()
            except (psutil.AccessDenied, psutil.NoSuchProcess):
                pass
            mem = info.get("memory_info")
            pi = ProcessInfo(
                pid=info["pid"],
                name=info.get("name") or "?",
                exe=exe,
                username=(info.get("username") or "").split("\\")[-1],
                memory_mb=round(mem.rss / (1024 * 1024), 1) if mem else 0.0,
                num_connections=conn_counts.get(info["pid"], 0),
                create_time=info.get("create_time") or 0.0,
            )
            pi.suspicious_reasons = flag_reasons(pi.exe, pi.name)
            procs.append(pi)
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            continue

    procs.sort(key=lambda x: (x.is_suspicious, x.num_connections), reverse=True)
    return procs[:limit] if limit else procs


class ProcessCollector(Collector):
    name = "processes"
    source = EventSource.PSUTIL

    def __init__(self) -> None:
        super().__init__()
        self._seen_pids: set[int] = set()

    def poll(self) -> Iterable[ProcessEvent]:
        events: list[ProcessEvent] = []
        for p in psutil.process_iter(["pid", "name", "ppid", "username"]):
            try:
                pid = p.info["pid"]
                if pid in self._seen_pids:
                    continue
                self._seen_pids.add(pid)
                exe = ""
                try:
                    exe = p.exe()
                except (psutil.AccessDenied, psutil.NoSuchProcess):
                    pass
                events.append(ProcessEvent(
                    type=EventType.PROCESS_START, source=self.source,
                    pid=pid, ppid=p.info.get("ppid"), name=p.info.get("name") or "?",
                    exe=exe, username=(p.info.get("username") or "").split("\\")[-1],
                ))
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                continue
        if len(self._seen_pids) > 8000:
            self._seen_pids.clear()
        return events
