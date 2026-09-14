"""The firewall backend contract.

Aegis speaks one vocabulary — :class:`~aegis.core.models.FirewallRule` — and
each platform backend translates it into that OS's native firewall dialect:

* Windows → ``netsh advfirewall`` (:mod:`aegis.response.firewall`)
* Linux   → ``nft`` / nftables    (:mod:`aegis.response.linux`)
* macOS   → ``pfctl`` / pf        (:mod:`aegis.response.macos`)

The service layer and UI depend only on this interface, so adding a platform
means writing one class — nothing upstream changes. This is the same
dependency-inversion seam the collectors and detections already use.
"""
from __future__ import annotations

import abc

from aegis.core.models import FirewallRule
from aegis.response.command import FirewallResult


class FirewallBackend(abc.ABC):
    """Abstract host-firewall control plane for one operating system."""

    #: Human-readable backend name, surfaced in the UI and audit trail.
    backend_name: str = "firewall"

    #: The native tool this backend drives, for "not installed" diagnostics.
    required_binary: str = ""

    @abc.abstractmethod
    def available(self) -> bool:
        """Whether this backend can actually run on this host."""
        raise NotImplementedError

    @abc.abstractmethod
    def list_rules(self, only_aegis: bool = True) -> list[FirewallRule]:
        """Return firewall rules, by default only those created by Aegis."""
        raise NotImplementedError

    @abc.abstractmethod
    def search_rules(self, keyword: str, only_aegis: bool = False) -> list[FirewallRule]:
        """Return rules whose fields contain ``keyword`` (case-insensitive)."""
        raise NotImplementedError

    @abc.abstractmethod
    def create_rule(self, rule: FirewallRule) -> FirewallResult:
        """Validate and create a firewall rule."""
        raise NotImplementedError

    @abc.abstractmethod
    def delete_rule(self, name: str) -> FirewallResult:
        """Delete a rule by its exact (validated) name."""
        raise NotImplementedError

    @abc.abstractmethod
    def set_rule_enabled(self, name: str, enabled: bool) -> FirewallResult:
        """Enable or disable an existing rule without deleting it."""
        raise NotImplementedError

    @abc.abstractmethod
    def block_ip(self, ip: str, note: str = "",
                 directions: tuple[str, ...] = ("out", "in")) -> FirewallResult:
        """Containment action: block all traffic to/from a remote IP."""
        raise NotImplementedError
