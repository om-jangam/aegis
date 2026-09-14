"""Response actions.

Responders act on findings — e.g. containing a suspicious host by adding a
firewall block rule. All responses are audited.

This package exposes the two contracts (:class:`Responder` for findings,
:class:`FirewallBackend` for the OS firewall) and the per-platform engines that
implement them: ``netsh`` on Windows, ``nftables`` on Linux, ``pf`` on macOS.
Call :func:`get_firewall` rather than constructing a backend directly.
"""
from aegis.response.backend import FirewallBackend
from aegis.response.base import Responder, ResponseResult
from aegis.response.command import (
    CommandRunner,
    FirewallError,
    FirewallResult,
    RunResult,
)
from aegis.response.factory import NullFirewall, get_firewall, response_capability
from aegis.response.firewall import FirewallManager, FirewallResponder, is_admin

__all__ = [
    "CommandRunner",
    "FirewallBackend",
    "FirewallError",
    "FirewallManager",
    "FirewallResponder",
    "FirewallResult",
    "NullFirewall",
    "Responder",
    "ResponseResult",
    "RunResult",
    "get_firewall",
    "is_admin",
    "response_capability",
]
