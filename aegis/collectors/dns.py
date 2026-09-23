"""Which names this computer looked up.

A connection tells you an address; a DNS lookup tells you the *name* behind it,
which is what threat intelligence lists, what malware generates by the thousand
when it hunts for a live controller, and what data is smuggled inside when
someone tunnels traffic out through DNS.

Where the names come from
-------------------------
* **Windows** — ``Get-DnsClientCache``, the resolver's own cache of recent
  answers. No administrator rights needed.
* **Linux** — ``resolvectl show-cache`` when systemd-resolved is running.
* **macOS** — not supported: its resolver cache cannot be read without root,
  and a half-working source is worse than an honest gap.

The cache holds a name only while its time-to-live lasts, so the collector polls
it and reports names it has not seen before. It shows *what* was looked up, not
which program asked: the cache does not record that.
"""
from __future__ import annotations

import logging
import re
import subprocess
from collections.abc import Iterable

from aegis.collectors.base import Collector
from aegis.config import settings
from aegis.core.events import DnsEvent, EventSource, EventType
from aegis.platforms import is_linux, is_windows
from aegis.response.command import CommandRunner, decode, default_runner

log = logging.getLogger(__name__)

#: Windows reports the record type as a number.
RECORD_TYPES = {"1": "A", "2": "NS", "5": "CNAME", "6": "SOA", "12": "PTR", "15": "MX",
                "16": "TXT", "28": "AAAA", "33": "SRV", "65": "HTTPS"}
#: Names the machine asks for constantly and that carry no signal.
LOCAL_SUFFIXES = (".local", ".localdomain", ".home.arpa", ".in-addr.arpa", ".ip6.arpa",
                  ".lan", ".internal")
_WINDOWS_SCRIPT = ("Get-DnsClientCache -ErrorAction SilentlyContinue | "
                   "ForEach-Object { $_.Entry + '|' + $_.Type + '|' + $_.Data }")
_RESOLVECTL_KEY = re.compile(r"^\s*(?:key|question):\s+IN\s+(?P<type>\S+)\s+(?P<name>\S+)")
_RESOLVECTL_DATA = re.compile(r"^\s*data:\s+IN\s+(?P<type>\S+)\s+(?P<name>\S+)\s+(?P<data>.+)$")


def is_boring(domain: str) -> bool:
    """True for names that say nothing about safety: local, empty or reverse lookups."""
    name = (domain or "").strip().rstrip(".").lower()
    if not name or "." not in name:
        return True            # single-label names are local or short-hand
    return name.endswith(LOCAL_SUFFIXES)


def parse_windows_cache(output: str) -> list[DnsEvent]:
    """Group ``entry|type|data`` lines into one event per name and record type."""
    grouped: dict[tuple[str, str], list[str]] = {}
    for line in output.splitlines():
        fields = line.strip().split("|")
        if len(fields) < 3:
            continue
        entry, record_type, data = fields[0], fields[1], fields[2]
        name = entry.strip().rstrip(".").lower()
        if is_boring(name):
            continue
        key = (name, RECORD_TYPES.get(record_type.strip(), record_type.strip()))
        answers = grouped.setdefault(key, [])
        if data.strip() and data.strip() not in answers:
            answers.append(data.strip())
    return [_event(name, record_type, answers)
            for (name, record_type), answers in grouped.items()]


def parse_resolvectl_cache(output: str) -> list[DnsEvent]:
    """Read ``resolvectl show-cache`` output: a key line, then its answers."""
    grouped: dict[tuple[str, str], list[str]] = {}
    current: tuple[str, str] | None = None
    for line in output.splitlines():
        key = _RESOLVECTL_KEY.match(line)
        if key:
            name = key["name"].strip().rstrip(".").lower()
            current = None if is_boring(name) else (name, key["type"])
            if current is not None:
                grouped.setdefault(current, [])
            continue
        data = _RESOLVECTL_DATA.match(line)
        if data and current is not None:
            answer = data["data"].strip()
            if answer and answer not in grouped[current]:
                grouped[current].append(answer)
    return [_event(name, record_type, answers)
            for (name, record_type), answers in grouped.items()]


def _event(domain: str, record_type: str, answers: list[str]) -> DnsEvent:
    return DnsEvent(type=EventType.DNS_QUERY, source=EventSource.DNS_CACHE,
                    domain=domain, record_type=record_type, answers=tuple(answers))


class DnsCollector(Collector):
    """Emits a :class:`DnsEvent` for each newly-seen name in the resolver cache."""

    name = "dns"
    source = EventSource.DNS_CACHE
    #: Names remembered so one cached answer is reported once, not every poll.
    MAX_REMEMBERED = 20_000

    def __init__(self, runner: CommandRunner | None = None):
        super().__init__()
        self._runner = runner or default_runner
        self._seen: set[tuple[str, str, tuple[str, ...]]] = set()

    def available(self) -> bool:
        if not settings.dns_monitoring_enabled:
            return False
        if is_windows():
            return True
        if is_linux():
            return self._run(["resolvectl", "--version"]) is not None
        log.info("DNS monitoring is not supported on this platform.")
        return False

    def poll(self) -> Iterable[DnsEvent]:
        try:
            events = self._poll_windows() if is_windows() else self._poll_linux()
        except Exception:  # noqa: BLE001 - a cache we cannot read must not stop monitoring
            log.exception("Could not read the DNS cache")
            return []
        fresh = []
        for event in events:
            key = (event.domain, event.record_type, event.answers)
            if key in self._seen:
                continue
            self._seen.add(key)
            fresh.append(event)
        if len(self._seen) > self.MAX_REMEMBERED:
            self._seen = set(list(self._seen)[-self.MAX_REMEMBERED // 2:])
        return fresh

    def _poll_windows(self) -> list[DnsEvent]:
        out = self._run(["powershell", "-NoProfile", "-NonInteractive", "-Command",
                         _WINDOWS_SCRIPT], timeout=45)
        return parse_windows_cache(out) if out else []

    def _poll_linux(self) -> list[DnsEvent]:
        out = self._run(["resolvectl", "show-cache"], timeout=30)
        return parse_resolvectl_cache(out) if out else []

    def _run(self, args: list[str], timeout: int = 20) -> str | None:
        try:
            result = self._runner(args, timeout)
        except (OSError, subprocess.SubprocessError):
            return None
        return decode(result.stdout) if result.returncode == 0 else None
