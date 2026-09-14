"""Loading Sigma rules from disk, with an honest account of what was skipped.

Pointing Aegis at a checkout of the community Sigma repository loads every rule
it can faithfully evaluate and *reports* the rest with a reason. The report is
the point: a tool that silently drops 60% of a ruleset while claiming to run it
is worse than one that says which 60% and why.

Rules are skipped when they target telemetry Aegis does not collect (a Windows
registry or image-load logsource), reference a field psutil cannot supply
(``ParentCommandLine``, file hashes), or use a construct the engine does not
implement (aggregation conditions). See :mod:`aegis.detection.sigma.mapping`.
"""
from __future__ import annotations

import logging
from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path

from aegis.detection.sigma.mapping import unsupported_fields
from aegis.detection.sigma.rule import (
    SigmaDetectionRule,
    SigmaRule,
    SigmaRuleError,
    compile_rule,
)

log = logging.getLogger(__name__)

#: Rule file extensions Sigma uses.
RULE_SUFFIXES = (".yml", ".yaml")


@dataclass
class SkippedRule:
    path: str
    title: str
    reason: str


@dataclass
class LoadReport:
    """What a load produced, and what it could not."""

    rules: list[SigmaDetectionRule] = field(default_factory=list)
    skipped: list[SkippedRule] = field(default_factory=list)

    @property
    def loaded_count(self) -> int:
        return len(self.rules)

    @property
    def skipped_count(self) -> int:
        return len(self.skipped)

    @property
    def total(self) -> int:
        return self.loaded_count + self.skipped_count

    @property
    def coverage(self) -> float:
        """Fraction of discovered rules Aegis can actually evaluate."""
        return self.loaded_count / self.total if self.total else 0.0

    def reasons(self) -> Counter:
        """How many rules were skipped for each distinct reason."""
        return Counter(s.reason for s in self.skipped)

    def summary(self) -> str:
        if not self.total:
            return "No Sigma rules found."
        lines = [
            f"Loaded {self.loaded_count} of {self.total} Sigma rules "
            f"({self.coverage:.0%} coverage).",
        ]
        if self.skipped:
            lines.append("Skipped:")
            for reason, count in self.reasons().most_common(10):
                lines.append(f"  {count:>5}  {reason}")
        return "\n".join(lines)


def _summarise_reason(exc: Exception) -> str:
    """Collapse a per-rule error into a groupable reason string."""
    text = str(exc)
    for prefix in ("logsource category", "unsupported modifier"):
        if text.startswith(prefix):
            return prefix.replace("_", " ") + " not supported"
    if "aggregation conditions" in text:
        return "aggregation conditions not supported"
    if "requires unavailable field" in text:
        return text
    return text[:120]


def load_file(path: Path, *, strict_fields: bool = True) -> list[SigmaRule]:
    """Compile every Sigma rule in one YAML file.

    Sigma files may hold several documents; ``action: global`` collection rules
    are not supported and are reported as skipped by the caller.
    """
    import yaml

    documents = [d for d in yaml.safe_load_all(path.read_text(encoding="utf-8")) if d]
    if not documents:
        raise SigmaRuleError("file contains no YAML documents")
    if len(documents) > 1 or any(
        isinstance(d, dict) and d.get("action") for d in documents
    ):
        raise SigmaRuleError("multi-document / collection rules are not supported")

    rule = compile_rule(documents[0], source_path=str(path))
    if strict_fields:
        missing = unsupported_fields(rule.category, rule.referenced_fields)
        if missing:
            raise SigmaRuleError(
                f"requires unavailable field(s): {', '.join(sorted(missing))}"
            )
    return [rule]


def load_rules(source: Path | str, *, strict_fields: bool = True) -> LoadReport:
    """Load Sigma rules from a file or (recursively) a directory.

    ``strict_fields`` skips rules that reference telemetry Aegis cannot observe.
    Turning it off loads them anyway, which is useful for measuring how much a
    richer collector (Sysmon, eBPF) would unlock.
    """
    source = Path(source)
    report = LoadReport()

    if source.is_file():
        paths = [source]
    elif source.is_dir():
        paths = sorted(p for p in source.rglob("*")
                       if p.suffix.lower() in RULE_SUFFIXES and p.is_file())
    else:
        log.warning("Sigma rule path does not exist: %s", source)
        return report

    for path in paths:
        try:
            for rule in load_file(path, strict_fields=strict_fields):
                report.rules.append(SigmaDetectionRule(rule))
        except SigmaRuleError as exc:
            report.skipped.append(SkippedRule(str(path), path.stem, _summarise_reason(exc)))
        except Exception as exc:  # noqa: BLE001 - a malformed rule must not abort the load
            report.skipped.append(
                SkippedRule(str(path), path.stem, f"could not parse: {type(exc).__name__}")
            )
    return report
