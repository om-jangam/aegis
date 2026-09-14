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
import re
from collections.abc import Iterable
from dataclasses import dataclass, field

import psutil

from aegis.collectors.base import Collector
from aegis.core.events import EventSource, EventType, ProcessEvent

log = logging.getLogger(__name__)

# Locations legitimate long-running network software rarely runs from. Matched
# against a separator-normalised path so one list covers every platform.
_SUSPICIOUS_DIRS = ("/temp/", "/tmp/", "/appdata/local/temp", "/downloads/",
                    "/$recycle.bin", "/var/tmp/", "/dev/shm/", "/.cache/")

# Processes whose *name* is impersonated by malware, paired with the directories
# the genuine binary must live in. Checked for every platform's names regardless
# of the host OS: an `svchost.exe` on a Linux box is just as wrong as one in a
# user's Downloads folder.
_SYSTEM_PROCESSES: tuple[tuple[frozenset[str], tuple[str, ...]], ...] = (
    (frozenset({"svchost.exe", "lsass.exe", "services.exe", "csrss.exe",
                "winlogon.exe", "smss.exe", "wininit.exe", "explorer.exe"}),
     ("/windows/",)),
    (frozenset({"systemd", "init", "sshd", "cron", "crond", "dbus-daemon",
                "udevd", "rsyslogd", "journald"}),
     ("/usr/", "/sbin/", "/bin/", "/lib/", "/libexec/")),
    (frozenset({"launchd", "kernel_task", "mds", "mdworker", "windowserver",
                "securityd", "coreaudiod", "distnoted"}),
     ("/usr/", "/system/", "/sbin/", "/bin/", "/library/")),
)

# Absolute-path forms across platforms: POSIX (/x), UNC (\\host\share) and
# Windows drive-letter (C:\x). os.path.isabs() only recognises the host OS's
# form, which would misjudge paths from the other platform under test or in CI.
_ABSOLUTE_RE = re.compile(r"^(?:/|\\\\|[A-Za-z]:[\\/])")


def _normalise(path: str) -> str:
    """Lower-case a path and use forward slashes, so one match list fits all OSes."""
    return (path or "").replace("\\", "/").lower()


def _looks_absolute(path: str) -> bool:
    return bool(_ABSOLUTE_RE.match(path or ""))


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
    """Heuristic suspicion flags for a process (used by rules and the UI).

    Platform-agnostic: the checks are expressed over a normalised path, so the
    same heuristics apply whether the host is Windows, Linux or macOS.
    """
    reasons: list[str] = []
    low = _normalise(exe)
    if any(d in low for d in _SUSPICIOUS_DIRS):
        reasons.append("Runs from a temporary/download directory")
    if exe and not _looks_absolute(exe):
        reasons.append("Executable path is not absolute")

    lowered_name = (name or "").lower()
    for names, system_dirs in _SYSTEM_PROCESSES:
        if lowered_name in names and low and not any(d in low for d in system_dirs):
            reasons.append(
                f"System-like name '{name}' outside its expected system directory"
            )
            break
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
