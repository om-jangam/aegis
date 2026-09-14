"""Selects the firewall backend for the host Aegis is running on.

The service layer calls :func:`get_firewall` and receives whichever
:class:`~aegis.response.backend.FirewallBackend` fits this OS. Nothing upstream
branches on the platform.

When no native firewall tool is usable — an unsupported OS, or nftables simply
not installed — the factory returns a :class:`NullFirewall` rather than raising.
Monitoring and detection are the parts of Aegis that matter most and they need
no privileges at all, so a host that cannot *respond* must still be able to
*observe*. The null backend reports honestly why it cannot act, and the UI
surfaces that instead of pretending a block succeeded.
"""
from __future__ import annotations

import logging

from aegis.core.models import FirewallRule
from aegis.platforms import CURRENT_OS, is_linux, is_macos, is_windows, privilege_hint
from aegis.response.backend import FirewallBackend
from aegis.response.command import FirewallResult

log = logging.getLogger(__name__)


class NullFirewall(FirewallBackend):
    """Inert backend for hosts with no supported firewall control plane."""

    backend_name = "unavailable"

    def __init__(self, reason: str = ""):
        self.reason = reason or f"No supported firewall backend for {CURRENT_OS.value}."

    def available(self) -> bool:
        return False

    def _blocked(self) -> FirewallResult:
        return FirewallResult(False, self.reason)

    def list_rules(self, only_aegis: bool = True) -> list[FirewallRule]:
        return []

    def search_rules(self, keyword: str, only_aegis: bool = False) -> list[FirewallRule]:
        return []

    def create_rule(self, rule: FirewallRule) -> FirewallResult:
        return self._blocked()

    def delete_rule(self, name: str) -> FirewallResult:
        return self._blocked()

    def set_rule_enabled(self, name: str, enabled: bool) -> FirewallResult:
        return self._blocked()

    def block_ip(self, ip: str, note: str = "",
                 directions: tuple[str, ...] = ("out", "in")) -> FirewallResult:
        return self._blocked()


def get_firewall(**kwargs) -> FirewallBackend:
    """Return the firewall backend appropriate to this host.

    Extra keyword arguments (``runner``, ``timeout``) are forwarded to the
    concrete backend, which is what lets tests inject a fake command runner.
    """
    if is_windows():
        from aegis.response.firewall import FirewallManager

        backend: FirewallBackend = FirewallManager(**kwargs)
    elif is_linux():
        from aegis.response.linux import NftablesManager

        backend = NftablesManager(**kwargs)
    elif is_macos():
        from aegis.response.macos import PfManager

        backend = PfManager(**kwargs)
    else:
        return NullFirewall()

    if not backend.available():
        reason = (
            f"{backend.backend_name} is unavailable — `{backend.required_binary}` "
            f"was not found on PATH. Monitoring and detection still work; "
            f"containment does not."
        )
        log.warning("%s", reason)
        return NullFirewall(reason)
    return backend


def response_capability() -> str:
    """One-line description of what this host can do, for the UI status bar."""
    backend = get_firewall()
    if not backend.available():
        return f"Response disabled — {getattr(backend, 'reason', 'no backend')}"
    from aegis.platforms import is_elevated

    if not is_elevated():
        return f"{backend.backend_name} — read-only. {privilege_hint()}"
    return f"{backend.backend_name} — full response enabled."
