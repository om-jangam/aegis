"""Concrete detection rules, MITRE ATT&CK-mapped.

``default_rules()`` returns the standard rule set the engine loads. Each rule is
a small, independently-testable :class:`~aegis.detection.base.DetectionRule`.
"""
from aegis.detection.base import DetectionRule
from aegis.detection.rules.network_rules import NETWORK_RULES
from aegis.detection.rules.process_rules import PROCESS_RULES


def default_rules() -> list[DetectionRule]:
    return [*NETWORK_RULES, *PROCESS_RULES]


__all__ = ["default_rules", "NETWORK_RULES", "PROCESS_RULES"]
