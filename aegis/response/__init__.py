"""Response actions.

Responders act on findings — e.g. containing a suspicious host by adding a
firewall block rule. All responses are audited. This package exposes the
contract (:class:`Responder`) and the secure Windows Firewall engine.
"""
from aegis.response.base import Responder, ResponseResult
from aegis.response.firewall import (
    FirewallManager,
    FirewallResponder,
    FirewallResult,
    is_admin,
)

__all__ = [
    "Responder",
    "ResponseResult",
    "FirewallManager",
    "FirewallResponder",
    "FirewallResult",
    "is_admin",
]
