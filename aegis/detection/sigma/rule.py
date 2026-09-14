"""Sigma rule compilation, matching and adaptation to the Aegis rule contract.

A Sigma rule is compiled **once at load time** into predicates and a condition
AST, then evaluated per event. The engine offers every process start and network
connection to every loaded rule, so re-interpreting YAML per event would not be
viable.

:class:`SigmaDetectionRule` wraps a compiled rule in the existing
:class:`~aegis.detection.base.DetectionRule` interface, which is why hundreds of
community rules can join the eight hand-written ones without the engine, the
service, the storage layer or the UI changing at all. That is the payoff of the
original abstraction.
"""
from __future__ import annotations

import base64
import re
from dataclasses import dataclass, field
from typing import Any

from aegis.core.events import Event
from aegis.core.models import Finding, Severity
from aegis.detection.base import DetectionContext, DetectionRule
from aegis.detection.sigma.conditions import SigmaConditionError, parse_condition
from aegis.detection.sigma.mapping import CATEGORY_EVENT_TYPES, fields_for

# Sigma severity vocabulary -> the Aegis scale.
_LEVELS = {
    "critical": Severity.CRITICAL,
    "high": Severity.HIGH,
    "medium": Severity.MEDIUM,
    "low": Severity.LOW,
    "informational": Severity.INFO,
    "info": Severity.INFO,
}

# Baseline confidence score per level, mirroring the hand-written rules' scale.
_LEVEL_SCORES = {
    Severity.CRITICAL: 95,
    Severity.HIGH: 78,
    Severity.MEDIUM: 55,
    Severity.LOW: 28,
    Severity.INFO: 12,
}

# Value modifiers Aegis implements faithfully. Anything else causes the rule to
# be rejected at load time rather than silently mis-evaluated.
SUPPORTED_MODIFIERS = frozenset({
    "contains", "startswith", "endswith", "re", "all", "cased",
    "lt", "lte", "gt", "gte", "base64", "base64offset", "windash", "expand",
})

_ATTACK_TACTICS = {
    "initial-access": "Initial Access", "execution": "Execution",
    "persistence": "Persistence", "privilege-escalation": "Privilege Escalation",
    "defense-evasion": "Defense Evasion", "credential-access": "Credential Access",
    "discovery": "Discovery", "lateral-movement": "Lateral Movement",
    "collection": "Collection", "command-and-control": "Command and Control",
    "exfiltration": "Exfiltration", "impact": "Impact",
    "reconnaissance": "Reconnaissance", "resource-development": "Resource Development",
}

_TECHNIQUE_RE = re.compile(r"^t(\d{4})(\.\d{3})?$", re.IGNORECASE)


class SigmaRuleError(ValueError):
    """Raised when a Sigma rule cannot be compiled into something Aegis can run."""


# --------------------------------------------------------------------------- #
# Value matching
# --------------------------------------------------------------------------- #
def _wildcard_body(value: str) -> str:
    """Translate a Sigma value into regex source, honouring the spec's escaping.

    Per the Sigma specification a backslash escapes ``*``, ``?`` and itself; a
    backslash before anything else (a Windows path separator, overwhelmingly) is
    a literal backslash.
    """
    out: list[str] = []
    i = 0
    while i < len(value):
        ch = value[i]
        if ch == "\\" and i + 1 < len(value) and value[i + 1] in "*?\\":
            out.append(re.escape(value[i + 1]))
            i += 2
            continue
        if ch == "*":
            out.append(".*")
        elif ch == "?":
            out.append(".")
        else:
            out.append(re.escape(ch))
        i += 1
    return "".join(out)


def _wildcard_regex(value: str, cased: bool, wrap: str = "") -> re.Pattern:
    """Compile a Sigma value into a full-match regex.

    ``wrap`` applies ``contains``/``startswith``/``endswith`` **after** escape
    parsing rather than by concatenating ``*`` onto the raw string. Wrapping the
    raw text first would let a value ending in a backslash — every Windows path
    prefix, e.g. ``\\AppData\\Local\\Temp\\`` — escape the very wildcard being
    appended, turning the match into a search for a literal asterisk.
    """
    body = _wildcard_body(value)
    if wrap == "contains":
        body = f".*{body}.*"
    elif wrap == "startswith":
        body = f"{body}.*"
    elif wrap == "endswith":
        body = f".*{body}"
    flags = 0 if cased else re.IGNORECASE
    return re.compile(body + r"\Z", flags | re.DOTALL)


def _windash_variants(value: str) -> list[str]:
    """Command-line dash variants: ``-flag`` is equivalent to ``/flag`` and dashes."""
    if not value or value[0] not in "-/":
        return [value]
    rest = value[1:]
    return [prefix + rest for prefix in ("-", "/", "--", "–", "—")]


def _base64_variants(value: str, offset: bool) -> list[str]:
    """Base64 encodings of a value, optionally at all three byte offsets."""
    raw = value.encode("utf-8")
    if not offset:
        return [base64.b64encode(raw).decode("ascii")]
    # base64offset matches a value embedded anywhere in a larger encoded blob,
    # which shifts the alignment. Trimming the ragged ends is what makes the
    # middle of the encoding comparable.
    variants = []
    for pad in range(3):
        encoded = base64.b64encode(b"\x00" * pad + raw).decode("ascii")
        start = (pad * 4) // 3 + (1 if pad else 0)
        variants.append(encoded[start:].rstrip("="))
    return variants


def _compile_value(value: Any, modifiers: list[str]) -> Any:
    """Compile one expected value into a predicate over the observed value."""
    cased = "cased" in modifiers

    if value is None:
        return lambda observed: observed is None or observed == ""

    if "re" in modifiers:
        pattern = re.compile(str(value), 0 if cased else re.IGNORECASE)
        return lambda observed: bool(pattern.search(_as_text(observed)))

    for op, compare in (("lt", lambda a, b: a < b), ("lte", lambda a, b: a <= b),
                        ("gt", lambda a, b: a > b), ("gte", lambda a, b: a >= b)):
        if op in modifiers:
            bound = float(value)
            def numeric(observed, _c=compare, _b=bound):
                try:
                    return _c(float(observed), _b)
                except (TypeError, ValueError):
                    return False
            return numeric

    text = str(value)
    candidates = [text]
    if "windash" in modifiers:
        candidates = _windash_variants(text)
    if "base64" in modifiers or "base64offset" in modifiers:
        candidates = [v for c in candidates
                      for v in _base64_variants(c, "base64offset" in modifiers)]

    wrap = next((m for m in ("contains", "startswith", "endswith") if m in modifiers), "")
    patterns = [_wildcard_regex(c, cased, wrap) for c in candidates]
    return lambda observed: any(p.match(_as_text(observed)) for p in patterns)


def _as_text(observed: Any) -> str:
    if observed is None:
        return ""
    if isinstance(observed, bool):
        return "true" if observed else "false"
    return str(observed)


@dataclass(frozen=True)
class FieldMatcher:
    """One ``field|modifier: value`` entry, compiled to a predicate."""

    field_name: str
    predicates: tuple
    require_all: bool

    def matches(self, fields: dict) -> bool:
        observed = fields.get(self.field_name)
        checks = (p(observed) for p in self.predicates)
        return all(checks) if self.require_all else any(checks)


def _compile_field(key: str, value: Any) -> FieldMatcher:
    name, _, modifier_text = key.partition("|")
    modifiers = [m.strip().lower() for m in modifier_text.split("|") if m.strip()]
    unknown = set(modifiers) - SUPPORTED_MODIFIERS
    if unknown:
        raise SigmaRuleError(f"unsupported modifier(s) {sorted(unknown)} on field {name!r}")

    values = value if isinstance(value, list) else [value]
    predicates = tuple(_compile_value(v, modifiers) for v in values)
    return FieldMatcher(name.strip().lower(), predicates, require_all="all" in modifiers)


def _compile_selection(spec: Any) -> Any:
    """Compile one search identifier into a predicate over the field mapping."""
    if isinstance(spec, dict):
        matchers = [_compile_field(k, v) for k, v in spec.items()]
        return lambda fields: all(m.matches(fields) for m in matchers)

    if isinstance(spec, list):
        # A list of maps is an OR of those maps; a list of bare strings is a
        # keyword search across every observed value.
        if all(isinstance(item, dict) for item in spec):
            branches = [_compile_selection(item) for item in spec]
            return lambda fields: any(b(fields) for b in branches)
        patterns = [_wildcard_regex(str(item), cased=False, wrap="contains") for item in spec]
        def keywords(fields, _p=patterns):
            haystack = " ".join(_as_text(v) for v in fields.values())
            return any(p.match(haystack) for p in _p)
        return keywords

    patterns = [_wildcard_regex(str(spec), cased=False, wrap="contains")]
    return lambda fields: any(
        p.match(" ".join(_as_text(v) for v in fields.values())) for p in patterns
    )


# --------------------------------------------------------------------------- #
# The rule
# --------------------------------------------------------------------------- #
@dataclass
class SigmaRule:
    """A compiled Sigma rule Aegis can evaluate."""

    id: str
    title: str
    category: str
    level: Severity
    condition: Any
    selections: dict[str, Any]
    description: str = ""
    author: str = ""
    references: list[str] = field(default_factory=list)
    tags: list[str] = field(default_factory=list)
    falsepositives: list[str] = field(default_factory=list)
    source_path: str = ""
    referenced_fields: set[str] = field(default_factory=set)

    @property
    def technique(self) -> str:
        """The most specific ATT&CK technique in the rule's tags, e.g. T1059.001."""
        best = ""
        for tag in self.tags:
            suffix = tag.lower().removeprefix("attack.")
            match = _TECHNIQUE_RE.match(suffix)
            if match:
                candidate = f"T{match.group(1)}{match.group(2) or ''}"
                if len(candidate) > len(best):
                    best = candidate
        return best

    @property
    def tactic(self) -> str:
        for tag in self.tags:
            name = _ATTACK_TACTICS.get(tag.lower().removeprefix("attack."))
            if name:
                return name
        return ""

    def matches(self, fields: dict) -> bool:
        results = {name: predicate(fields) for name, predicate in self.selections.items()}
        return self.condition.evaluate(results)


def compile_rule(document: dict, source_path: str = "") -> SigmaRule:
    """Compile a parsed Sigma YAML document into a :class:`SigmaRule`.

    Raises :class:`SigmaRuleError` for any rule Aegis cannot run faithfully.
    """
    if not isinstance(document, dict):
        raise SigmaRuleError("rule is not a YAML mapping")

    title = str(document.get("title") or "").strip()
    if not title:
        raise SigmaRuleError("rule has no title")

    logsource = document.get("logsource") or {}
    category = str(logsource.get("category") or "").strip().lower()
    if category not in CATEGORY_EVENT_TYPES:
        raise SigmaRuleError(
            f"logsource category {category or '(none)'!r} is not one Aegis collects"
        )

    detection = document.get("detection") or {}
    if not isinstance(detection, dict):
        raise SigmaRuleError("detection block is not a mapping")
    condition_text = detection.get("condition")
    if isinstance(condition_text, list):
        # A list of conditions means "any of these"; join them accordingly.
        condition_text = " or ".join(f"({c})" for c in condition_text)
    if not condition_text:
        raise SigmaRuleError("detection block has no condition")

    selections: dict[str, Any] = {}
    referenced: set[str] = set()
    for name, spec in detection.items():
        if name == "condition":
            continue
        selections[name] = _compile_selection(spec)
        referenced |= _referenced_fields(spec)
    if not selections:
        raise SigmaRuleError("detection block defines no search identifiers")

    try:
        condition = parse_condition(str(condition_text))
    except SigmaConditionError as exc:
        raise SigmaRuleError(str(exc)) from exc

    missing = condition.identifiers() - set(selections)
    if missing:
        raise SigmaRuleError(f"condition references undefined identifier(s) {sorted(missing)}")

    tags = [str(t) for t in (document.get("tags") or [])]
    falsepositives = [str(f) for f in (document.get("falsepositives") or [])]
    references = [str(r) for r in (document.get("references") or [])]

    return SigmaRule(
        id=str(document.get("id") or title),
        title=title,
        category=category,
        level=_LEVELS.get(str(document.get("level") or "medium").lower(), Severity.MEDIUM),
        condition=condition,
        selections=selections,
        description=str(document.get("description") or "").strip(),
        author=str(document.get("author") or "").strip(),
        references=references,
        tags=tags,
        falsepositives=falsepositives,
        source_path=source_path,
        referenced_fields=referenced,
    )


def _referenced_fields(spec: Any) -> set[str]:
    """Every field name a search identifier reads, for coverage checking."""
    if isinstance(spec, dict):
        return {str(k).partition("|")[0].strip().lower() for k in spec}
    if isinstance(spec, list):
        return set().union(*(_referenced_fields(item) for item in spec)) if spec else set()
    return set()


# --------------------------------------------------------------------------- #
# Adapter to the Aegis rule contract
# --------------------------------------------------------------------------- #
class SigmaDetectionRule(DetectionRule):
    """Runs a compiled :class:`SigmaRule` inside the Aegis detection engine."""

    def __init__(self, sigma: SigmaRule):
        self.sigma = sigma
        self.rule_id = f"SIGMA-{sigma.id}"
        self.title = sigma.title
        self.severity = sigma.level
        self.technique = sigma.technique
        self.tactic = sigma.tactic
        self.description = sigma.description
        self.event_types = CATEGORY_EVENT_TYPES[sigma.category]
        self.enabled = True

    def evaluate(self, event: Event, context: DetectionContext) -> Finding | None:
        fields = fields_for(event)
        if not fields or not self.sigma.matches(fields):
            return None

        reasons = [f"Sigma rule '{self.sigma.title}' matched"]
        if self.sigma.description:
            reasons.append(self.sigma.description)
        if self.sigma.falsepositives:
            # Surfacing the rule author's own caveats next to the alert is what
            # keeps a large imported ruleset triageable instead of noisy.
            reasons.append("Known false positives: " + "; ".join(self.sigma.falsepositives))

        return self.make_finding(
            score=_LEVEL_SCORES.get(self.sigma.level, 50),
            reasons=reasons,
            entity=_entity_for(event, fields),
            source_summary=event.summary(),
        )


def _entity_for(event: Event, fields: dict) -> str:
    """The thing a finding is about — what response and dedup key on."""
    remote_ip = fields.get("destinationip")
    if remote_ip:
        return f"{remote_ip}:{fields.get('destinationport', '')}"
    name = fields.get("image") or ""
    return f"proc:{name.replace(chr(92), '/').rsplit('/', 1)[-1]}" if name else "unknown"
