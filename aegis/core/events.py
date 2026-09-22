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
    FILE_CREATED = "file_created"
    FILE_MODIFIED = "file_modified"
    FILE_DELETED = "file_deleted"
    AUTH_FAILURE = "auth_failure"            # a sign-in was refused
    AUTH_SUCCESS = "auth_success"            # a sign-in was accepted
    ACCOUNT_CREATED = "account_created"      # a new user account
    ACCOUNT_PRIVILEGED = "account_privileged"  # an account gained admin rights
    ACCOUNT_LOCKED = "account_locked"        # an account was locked out


class EventSource(StrEnum):
    """Where an event was observed. Lets us reason about telemetry fidelity."""

    PSUTIL = "psutil"          # socket/process polling (portable, misses short-lived)
    SYSMON = "sysmon"          # Sysinternals Sysmon event log (high fidelity)
    ETW = "etw"                # Event Tracing for Windows (kernel-grade)
    FIREWALL = "firewall"      # Windows Firewall / netsh
    FILESYSTEM = "filesystem"  # file integrity baseline comparison
    AUTH_LOG = "auth_log"      # the OS sign-in record (Security log, auth.log, journal)
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

    @property
    def parent_name(self) -> str:
        """Name of the process that started this one, when the collector knew it."""
        return str((self.raw or {}).get("parent_name") or "")

    def summary(self) -> str:
        name = self.name or "?"
        if self.parent_name:
            return f"{name} (pid {self.pid}), started by {self.parent_name} (pid {self.ppid})"
        return f"{name} (pid {self.pid}, parent pid {self.ppid})"


@dataclass(frozen=True)
class AuthEvent(Event):
    """A sign-in attempt, or a change to an account, as the OS recorded it.

    ``user`` is who signed in (or was refused); ``actor`` is who made an account
    change. ``source_ip`` is the machine the attempt came from, empty for a
    local sign-in. Passwords never appear here: the OS does not log them and
    Aegis never asks for them.
    """

    user: str = ""
    actor: str = ""
    source_ip: str = ""
    method: str = ""        # e.g. "network", "remote desktop", "ssh", "sudo"
    reason: str = ""        # why it failed, in the OS's words
    group: str = ""         # the group an account was added to
    record_id: str = ""     # the OS log record, so the same entry is read once

    @property
    def who(self) -> str:
        return self.user or self.actor or "unknown user"

    @property
    def where(self) -> str:
        return f" from {self.source_ip}" if self.source_ip else ""

    def summary(self) -> str:
        if self.type is EventType.AUTH_FAILURE:
            reason = f" ({self.reason})" if self.reason else ""
            return f"Sign-in refused for {self.who}{self.where} via {self.method or 'login'}{reason}"
        if self.type is EventType.AUTH_SUCCESS:
            return f"Signed in as {self.who}{self.where} via {self.method or 'login'}"
        if self.type is EventType.ACCOUNT_CREATED:
            by = f", created by {self.actor}" if self.actor else ""
            return f"New account {self.user}{by}"
        if self.type is EventType.ACCOUNT_PRIVILEGED:
            by = f", by {self.actor}" if self.actor else ""
            return f"{self.user} added to {self.group or 'an administrator group'}{by}"
        if self.type is EventType.ACCOUNT_LOCKED:
            return f"Account {self.user} locked out{self.where}"
        return f"{self.type.value} for {self.who}"


@dataclass(frozen=True)
class FileEvent(Event):
    """A watched file was created, modified or deleted.

    ``digest`` is the content hash after the change (empty for a deletion) and
    ``previous_digest`` the one before it. Carrying both is what lets an analyst
    prove *what* changed, not merely that something did.
    """

    path: str = ""
    size: int = 0
    previous_size: int = 0
    digest: str = ""
    previous_digest: str = ""
    mode: str = ""

    @property
    def action(self) -> str:
        return {
            EventType.FILE_CREATED: "created",
            EventType.FILE_MODIFIED: "modified",
            EventType.FILE_DELETED: "deleted",
        }.get(self.type, "changed")

    def summary(self) -> str:
        detail = f" ({self.previous_size} -> {self.size} bytes)" \
            if self.type == EventType.FILE_MODIFIED else ""
        return f"{self.path} {self.action}{detail}"
