"""Assembles the rule set the detection engine runs.

Aegis has two kinds of rule and they are complementary:

* **built-in rules** — a handful of hand-written, stateful Python detections.
  These do things a declarative format cannot: correlate across events, count
  distinct peers over a window, reason about history.
* **Sigma rules** — declarative, per-event pattern matches in the industry's own
  format. These give breadth, and let anyone add coverage by dropping in a YAML
  file rather than writing Python.

Composing them here keeps :class:`~aegis.detection.engine.DetectionEngine`
ignorant of where its rules came from.
"""
from __future__ import annotations

import logging
from pathlib import Path

from aegis.detection.base import DetectionRule
from aegis.detection.rules import default_rules
from aegis.detection.sigma.loader import LoadReport, load_rules

log = logging.getLogger(__name__)

#: Curated Sigma rules shipped inside the package.
BUNDLED_SIGMA_DIR: Path = Path(__file__).resolve().parent / "sigma" / "rules"


def build_ruleset(
    *,
    include_builtin: bool = True,
    include_bundled_sigma: bool = True,
    sigma_paths: list[str] | None = None,
    strict_fields: bool = True,
) -> tuple[list[DetectionRule], LoadReport]:
    """Build the active rule set, returning it with the Sigma load report.

    The report is returned rather than logged and discarded so callers can show
    the user exactly how many external rules were skipped and why.
    """
    rules: list[DetectionRule] = list(default_rules()) if include_builtin else []
    combined = LoadReport()

    sources: list[Path | str] = []
    if include_bundled_sigma and BUNDLED_SIGMA_DIR.is_dir():
        sources.append(BUNDLED_SIGMA_DIR)
    sources.extend(sigma_paths or [])

    seen_ids: set[str] = set()
    for source in sources:
        report = load_rules(source, strict_fields=strict_fields)
        for rule in report.rules:
            # A user-supplied ruleset may legitimately contain the same rule id
            # as the bundled set; first one wins so bundled rules stay stable.
            if rule.rule_id in seen_ids:
                continue
            seen_ids.add(rule.rule_id)
            combined.rules.append(rule)
        combined.skipped.extend(report.skipped)

    rules.extend(combined.rules)
    log.info("Rule set: %d built-in, %d Sigma (%d skipped).",
             len(rules) - len(combined.rules), len(combined.rules), combined.skipped_count)
    return rules, combined
