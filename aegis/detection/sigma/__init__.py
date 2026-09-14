"""Sigma rule support — detection-as-code, in the industry's own format.

Aegis ships eight hand-written ATT&CK-mapped rules. Sigma is the open standard
those rules would otherwise be written in, and the community maintains thousands
of them. This package lets Aegis run that ruleset directly:

    from aegis.detection.sigma import load_rules

    report = load_rules("path/to/sigma/rules")
    print(report.summary())
    engine = DetectionEngine(rules=default_rules() + report.rules)

Compiled Sigma rules implement the ordinary
:class:`~aegis.detection.base.DetectionRule` interface, so nothing downstream —
engine, service, storage, UI — changes to accommodate them.

Scope is declared rather than implied: Aegis collects process-creation and
network-connection telemetry via psutil, so it runs the Sigma rules built on
those logsources and *reports* the ones it cannot, with a reason. See
:mod:`aegis.detection.sigma.loader`.
"""
from aegis.detection.sigma.conditions import SigmaConditionError, parse_condition
from aegis.detection.sigma.loader import LoadReport, SkippedRule, load_file, load_rules
from aegis.detection.sigma.mapping import (
    CATEGORY_EVENT_TYPES,
    fields_for,
    supported_fields,
    unsupported_fields,
)
from aegis.detection.sigma.rule import (
    SigmaDetectionRule,
    SigmaRule,
    SigmaRuleError,
    compile_rule,
)

__all__ = [
    "CATEGORY_EVENT_TYPES",
    "LoadReport",
    "SigmaConditionError",
    "SigmaDetectionRule",
    "SigmaRule",
    "SigmaRuleError",
    "SkippedRule",
    "compile_rule",
    "fields_for",
    "load_file",
    "load_rules",
    "parse_condition",
    "supported_fields",
    "unsupported_fields",
]
