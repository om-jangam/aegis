"""Noticing when this computer's security settings get worse.

The security check answers "how safe is this machine right now?". Comparing one
check with the one before it answers a different and equally important question:
"did something just get turned off?" Malware disables the firewall or the
antivirus, and people switch things off to make an app work and forget to put
them back. Either way the change deserves an alert, not a quieter score.
"""
from __future__ import annotations

from dataclasses import dataclass

from aegis.core.models import Severity
from aegis.posture.base import CheckResult, CheckStatus, PostureReport

#: A setting getting worse is a defence being impaired (MITRE ATT&CK).
TECHNIQUE = "T1562.001"
TACTIC = "Defense Evasion"
_RANK = {CheckStatus.PASS: 0, CheckStatus.WARN: 1, CheckStatus.FAIL: 2}


@dataclass(frozen=True)
class Regression:
    """A check that used to be better than it is now."""

    result: CheckResult
    before: CheckStatus

    @property
    def check_id(self) -> str:
        return self.result.check_id

    @property
    def severity(self) -> Severity:
        """A setting that failed outright is worse than one that only warns."""
        if self.result.status is CheckStatus.FAIL:
            return max(self.result.severity, Severity.HIGH)
        return self.result.severity

    @property
    def headline(self) -> str:
        return f"Security setting changed: {self.result.title}"

    def reasons(self) -> list[str]:
        lines = [f"This check was {self.before.value} at the last security check and is "
                 f"now {self.result.status.value}.",
                 self.result.summary]
        lines.extend(self.result.details[:3])
        if self.result.remediation:
            lines.append(f"Put it back: {self.result.remediation}")
        return lines


def regressions(previous: PostureReport | None,
                current: PostureReport) -> list[Regression]:
    """Checks that were healthier in ``previous`` than they are in ``current``.

    Checks that could not run (skipped) are ignored in both directions: a check
    that stops working is a gap in visibility, not evidence that a setting
    changed, and reporting it as one would cry wolf.
    """
    if previous is None:
        return []
    before = {r.check_id: r.status for r in previous.results}
    worse = []
    for result in current.results:
        was = before.get(result.check_id)
        if was is None or was is CheckStatus.SKIP or result.status is CheckStatus.SKIP:
            continue
        if _RANK[result.status] > _RANK[was]:
            worse.append(Regression(result, was))
    return worse
