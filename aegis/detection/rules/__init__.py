"""Concrete detection rules, MITRE ATT&CK-mapped.

``default_rules()`` returns the standard rule set the engine loads. Each rule is
a small, independently-testable :class:`~aegis.detection.base.DetectionRule`.
"""
from aegis.detection.base import DetectionRule
from aegis.detection.rules.file_rules import FILE_RULES
from aegis.detection.rules.intel_rules import INTEL_RULES
from aegis.detection.rules.network_rules import NETWORK_RULES
from aegis.detection.rules.process_rules import PROCESS_RULES


def default_rules() -> list[DetectionRule]:
    return [*INTEL_RULES, *NETWORK_RULES, *PROCESS_RULES, *FILE_RULES]


__all__ = ["default_rules", "FILE_RULES", "INTEL_RULES", "NETWORK_RULES", "PROCESS_RULES"]
