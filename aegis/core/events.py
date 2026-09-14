"""Normalized telemetry event model — the spine of the Aegis pipeline.

Every collector (psutil today; Sysmon / ETW later) emits these typed events, and
every detection rule consumes them. Because the schema is source-agnostic, we can
add a new telemetry source without changing a single line of detection code.

Design notes
------------
* Events are immutable value objects (``frozen`` dataclasses). Once observed, an
  event is a historical fact and must not mutate.
* ``Event`` is the common base; concrete subtypes add domain fields. A detection
  rule declares which ``EventType`` values it cares about and is only handed
  matching events.
* ``raw`` carries the untouched source record (useful for debugging / forensics)
  without polluting the normalized fields.
"""
from __future__ import annotations

import ipaddress
from dataclasses import dataclass, field
from datetime import datetime
from enum import StrEnum
from typing import Any


class EventType(StrEnum):
    """The kind of activity an event describes."""

    NETWORK_CONNECTION = "network_connection"
    NETWORK_LISTEN = "network_listen"
    PROCESS_START = "process_start"
    PROCESS_STOP = "process_stop"


class EventSource(StrEnum):
    """Where an event was observed. Lets us reason about telemetry fidelity."""

    PSUTIL = "psutil"          # socket/process polling (portable, misses short-lived)
    SYSMON = "sysmon"          # Sysinternals Sysmon event log (high fidelity)
    ETW = "etw"                # Event Tracing for Windows (kernel-grade)
    FIREWALL = "firewall"      # Windows Firewall / netsh
    SYSTEM = "system"          # Aegis itself


class Direction(StrEnum):
    INBOUND = "inbound"
    OUTBOUND = "outbound"
    LISTEN = "listen"
    UNKNOWN = "unknown"


@dataclass(frozen=True)
class Event:
    """Base telemetry event. All concrete events inherit from this."""

    type: EventType
    source: EventSource
    timestamp: datetime = field(default_factory=datetime.now)
    host: str = ""
    raw: dict[str, Any] | None = None

    def summary(self) -> str:  # pragma: no cover - overridden
        return f"{self.type.value} from {self.source.value}"


@dataclass(frozen=True)
class NetworkEvent(Event):
    """A network connection or listening socket."""

    pid: int | None = None
    process_name: str = ""
    protocol: str = ""                 # TCP / UDP
    local_ip: str = ""
    local_port: int = 0
    remote_ip: str = ""
    remote_port: int = 0
    status: str = ""
    direction: Direction = Direction.UNKNOWN

    @property
    def is_remote(self) -> bool:
        """True when the peer is a routable, non-local address."""
        if not self.remote_ip:
            return False
        try:
            ip = ipaddress.ip_address(self.remote_ip)
            return not (ip.is_private or ip.is_loopback or ip.is_unspecified
                        or ip.is_link_local or ip.is_multicast)
        except ValueError:
            return False

    @property
    def dedup_key(self) -> str:
        """Stable identity used to avoid re-processing the same connection."""
        return f"{self.pid}:{self.protocol}:{self.remote_ip}:{self.remote_port}"

    def summary(self) -> str:
        peer = f"{self.remote_ip}:{self.remote_port}" if self.remote_ip else "(listening)"
        return f"{self.process_name or '?'} → {peer} [{self.protocol}]"


@dataclass(frozen=True)
class ProcessEvent(Event):
    """A process starting or stopping."""

    pid: int | None = None
    ppid: int | None = None
    name: str = ""
    exe: str = ""
    cmdline: str = ""
    username: str = ""

    def summary(self) -> str:
        return f"{self.name or '?'} (pid={self.pid}, ppid={self.ppid})"
