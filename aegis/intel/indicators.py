"""Threat-intelligence indicators (IOCs).

Rules recognise *behaviour*; indicators recognise *infrastructure*. A connection
to a botnet controller on port 443 looks normal to every behavioural rule; only
knowing that the address is bad catches it.

Indicator files are plain text, one IP address or CIDR range per line, with
``#`` or ``;`` comments. That is the format of abuse.ch, Spamhaus DROP and most
public blocklists, so a list can be dropped in unchanged.

Entries covering private, loopback or reserved space, or networks broader than
/8 (IPv4) or /32 (IPv6), are rejected: one careless ``0.0.0.0/0`` line in a
feed must not turn every connection into a critical alert.
"""
from __future__ import annotations

import ipaddress
import logging
from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path

log = logging.getLogger(__name__)

_MIN_PREFIX = {4: 8, 6: 32}
INDICATOR_SUFFIXES = frozenset({".txt", ".list", ".netset", ".ipset"})

IPNetwork = ipaddress.IPv4Network | ipaddress.IPv6Network
IPAddress = ipaddress.IPv4Address | ipaddress.IPv6Address


@dataclass(frozen=True)
class IntelMatch:
    indicator: str   # the listed address or range that matched
    source: str      # the list it came from


def parse_indicator(token: str) -> IPNetwork | None:
    """Parse one IP or CIDR indicator, or return None if it is unusable."""
    token = token.strip()
    if not token:
        return None
    try:
        net = ipaddress.ip_network(token, strict=False)
    except ValueError:
        return None
    if net.prefixlen < _MIN_PREFIX[net.version]:
        return None
    addr = net.network_address
    if (net.is_private or net.is_reserved or net.is_multicast or net.is_link_local
            or addr.is_loopback or addr.is_unspecified):
        return None
    return net


def _normalise(ip: str) -> IPAddress | None:
    try:
        addr = ipaddress.ip_address(ip.split("%", 1)[0])
    except ValueError:
        return None
    if isinstance(addr, ipaddress.IPv6Address) and addr.ipv4_mapped:
        return addr.ipv4_mapped
    return addr


class ThreatIntel:
    """An in-memory set of malicious addresses and ranges."""

    def __init__(self) -> None:
        self._hosts: dict[IPAddress, str] = {}
        self._networks: list[tuple[IPNetwork, str]] = []
        #: Accepted indicator count per source list.
        self.sources: dict[str, int] = {}
        #: Lines that were not a usable indicator (headers, private ranges...).
        self.rejected = 0

    def add(self, token: str, source: str) -> bool:
        net = parse_indicator(token)
        if net is None:
            return False
        if net.num_addresses == 1:
            self._hosts.setdefault(net.network_address, source)
        else:
            self._networks.append((net, source))
        self.sources[source] = self.sources.get(source, 0) + 1
        return True

    def load_text(self, text: str, source: str) -> int:
        added = 0
        for line in text.splitlines():
            line = line.split("#", 1)[0].split(";", 1)[0].strip()
            if not line:
                continue
            token = line.replace(",", " ").split()[0]
            if self.add(token, source):
                added += 1
            else:
                self.rejected += 1
        return added

    def load_path(self, path: Path | str) -> int:
        """Load a single indicator file, or every indicator file in a directory."""
        path = Path(path)
        if path.is_dir():
            return sum(self.load_path(p) for p in sorted(path.iterdir())
                       if p.is_file() and p.suffix.lower() in INDICATOR_SUFFIXES)
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError as exc:
            log.warning("Could not read indicator file %s: %s", path, exc)
            return 0
        return self.load_text(text, source=path.stem)

    def match(self, ip: str) -> IntelMatch | None:
        addr = _normalise(ip)
        if addr is None:
            return None
        source = self._hosts.get(addr)
        if source is not None:
            return IntelMatch(str(addr), source)
        for net, src in self._networks:
            if addr.version == net.version and addr in net:
                return IntelMatch(str(net), src)
        return None

    def indicators(self) -> Iterator[str]:
        yield from (str(addr) for addr in self._hosts)
        yield from (str(net) for net, _ in self._networks)

    def __len__(self) -> int:
        return len(self._hosts) + len(self._networks)
