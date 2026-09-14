"""Host security posture assessment (``aegis check``)."""
from __future__ import annotations

import logging

from aegis.posture.base import (
    CheckResult,
    CheckStatus,
    Listener,
    PostureCheck,
    PostureContext,
    PostureReport,
)
from aegis.posture.checks import default_checks

log = logging.getLogger(__name__)


def run_posture_checks(ctx: PostureContext | None = None,
                       checks: list[PostureCheck] | None = None) -> PostureReport:
    """Run every applicable check. A check that crashes is reported as skipped."""
    ctx = ctx or PostureContext()
    results: list[CheckResult] = []
    for check in checks if checks is not None else default_checks():
        if not check.applies(ctx):
            continue
        try:
            results.append(check.run(ctx))
        except Exception as exc:  # noqa: BLE001 - one broken check must not hide the rest
            log.exception("Posture check %s failed", check.check_id)
            results.append(check.result(CheckStatus.SKIP, f"Check could not run: {exc}"))
    return PostureReport(results=results, platform=ctx.os.value)


__all__ = [
    "CheckResult",
    "CheckStatus",
    "Listener",
    "PostureCheck",
    "PostureContext",
    "PostureReport",
    "default_checks",
    "run_posture_checks",
]
