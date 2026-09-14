"""Response contract.

A ``Responder`` decides whether it can act on a given finding and, if so,
performs a containment/mitigation action. Responders must be:

* **Idempotent-ish** — re-running the same response should not create havoc.
* **Auditable** — every action returns a :class:`ResponseResult` the caller logs.
* **Opt-in / safe by default** — automatic response is gated by policy; nothing
  destructive happens without explicit configuration.
"""
from __future__ import annotations

import abc
from dataclasses import dataclass

from aegis.core.models import Finding


@dataclass
class ResponseResult:
    """Outcome of a response action (always audited by the caller)."""

    ok: bool
    action: str
    message: str
    needs_admin: bool = False


class Responder(abc.ABC):
    """Abstract base for all response actions."""

    name: str = "responder"

    @abc.abstractmethod
    def can_handle(self, finding: Finding) -> bool:
        """Whether this responder is applicable to ``finding``."""
        raise NotImplementedError

    @abc.abstractmethod
    def respond(self, finding: Finding) -> ResponseResult:
        """Perform the response action for ``finding``."""
        raise NotImplementedError
