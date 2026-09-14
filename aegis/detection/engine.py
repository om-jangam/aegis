"""Detection engine — runs events through the rule set.

The engine is deliberately thin: it owns the shared :class:`DetectionContext`
(rolling history), offers each event to every rule that ``wants`` it, and
collects the resulting :class:`Finding` objects. All the intelligence lives in
the individual, independently-testable rules.
"""
from __future__ import annotations

import logging

from aegis.core.events import Event
from aegis.core.models import Finding
from aegis.detection.base import DetectionContext, DetectionRule

log = logging.getLogger(__name__)


class DetectionEngine:
    def __init__(self, rules: list[DetectionRule] | None = None,
                 context: DetectionContext | None = None,
                 sigma_paths: list[str] | None = None):
        #: Report from the last Sigma load, so callers can show what was skipped.
        self.sigma_report = None
        if rules is not None:
            self.rules: list[DetectionRule] = rules
        else:
            from aegis.config import settings
            from aegis.detection.ruleset import build_ruleset

            self.rules, self.sigma_report = build_ruleset(
                include_bundled_sigma=settings.sigma_enabled,
                sigma_paths=sigma_paths if sigma_paths is not None
                else list(settings.sigma_rule_paths),
            )
        self.context = context or DetectionContext()

    def process(self, event: Event) -> list[Finding]:
        """Evaluate one event against all applicable rules."""
        self.context.remember(event)
        findings: list[Finding] = []
        for rule in self.rules:
            if not rule.enabled or not rule.wants(event):
                continue
            try:
                finding = rule.evaluate(event, self.context)
            except Exception:  # noqa: BLE001 - a bad rule must not crash detection
                log.exception("Rule %s raised while evaluating an event", rule.rule_id)
                continue
            if finding:
                findings.append(finding)
        return findings

    def process_batch(self, events) -> list[Finding]:
        out: list[Finding] = []
        for e in events:
            out.extend(self.process(e))
        return out

    @property
    def rule_count(self) -> int:
        return len(self.rules)
