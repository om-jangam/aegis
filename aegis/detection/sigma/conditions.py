"""Parser and evaluator for Sigma ``condition`` expressions.

A Sigma rule's detection block defines named search identifiers and combines
them with a small boolean language::

    selection
    selection and not filter
    (sel_a or sel_b) and not filter_legit
    1 of selection_*
    all of them

This module turns that string into an AST once, at load time, and evaluates it
per event against a mapping of ``{identifier: bool}``. Parsing once rather than
re-interpreting the string on every event matters: the engine evaluates rules
against every process start and network connection on the host.

Grammar
-------
``or``/``and``/``not`` with conventional precedence (``not`` binds tightest,
then ``and``, then ``or``), parentheses, and the aggregate forms ``1 of X``,
``any of X``, ``all of X`` where ``X`` is ``them`` or a ``prefix*`` wildcard.

Aggregate *correlation* conditions (``| count() > 5``) are deliberately not
supported — they need a stateful backend Aegis does not have — and are reported
as a parse error so the loader skips the rule instead of silently mis-evaluating
it.
"""
from __future__ import annotations

import fnmatch
import re
from dataclasses import dataclass
from typing import Protocol

_TOKEN_RE = re.compile(r"\(|\)|\||[\w*]+")
_KEYWORDS = {"and", "or", "not", "of"}
_QUANTIFIERS = {"1", "any", "all"}


class Condition(Protocol):
    """Anything in a parsed condition tree: an identifier, or a combination of them."""

    def evaluate(self, matches: dict[str, bool]) -> bool: ...

    def identifiers(self) -> set[str]: ...


class SigmaConditionError(ValueError):
    """Raised when a condition expression cannot be parsed or resolved."""


# --------------------------------------------------------------------------- #
# AST
# --------------------------------------------------------------------------- #
@dataclass(frozen=True)
class Identifier:
    name: str

    def evaluate(self, matches: dict[str, bool]) -> bool:
        if self.name not in matches:
            raise SigmaConditionError(f"condition references unknown identifier {self.name!r}")
        return matches[self.name]

    def identifiers(self) -> set[str]:
        return {self.name}


@dataclass(frozen=True)
class Not:
    operand: Condition

    def evaluate(self, matches: dict[str, bool]) -> bool:
        return not self.operand.evaluate(matches)

    def identifiers(self) -> set[str]:
        return self.operand.identifiers()


@dataclass(frozen=True)
class And:
    operands: tuple

    def evaluate(self, matches: dict[str, bool]) -> bool:
        return all(op.evaluate(matches) for op in self.operands)

    def identifiers(self) -> set[str]:
        return set().union(*(op.identifiers() for op in self.operands))


@dataclass(frozen=True)
class Or:
    operands: tuple

    def evaluate(self, matches: dict[str, bool]) -> bool:
        return any(op.evaluate(matches) for op in self.operands)

    def identifiers(self) -> set[str]:
        return set().union(*(op.identifiers() for op in self.operands))


@dataclass(frozen=True)
class Quantified:
    """``1 of selection_*`` / ``all of them`` — resolved against live identifiers."""

    quantifier: str          # "1" | "any" | "all"
    pattern: str             # "them" or a glob like "selection_*"

    def _selected(self, matches: dict[str, bool]) -> list[bool]:
        if self.pattern == "them":
            chosen = list(matches.values())
        else:
            chosen = [v for k, v in matches.items() if fnmatch.fnmatchcase(k, self.pattern)]
        if not chosen:
            raise SigmaConditionError(
                f"'{self.quantifier} of {self.pattern}' matches no search identifier"
            )
        return chosen

    def evaluate(self, matches: dict[str, bool]) -> bool:
        chosen = self._selected(matches)
        return all(chosen) if self.quantifier == "all" else any(chosen)

    def identifiers(self) -> set[str]:
        return set()


# --------------------------------------------------------------------------- #
# Parser
# --------------------------------------------------------------------------- #
class _Parser:
    def __init__(self, tokens: list[str]):
        self._tokens = tokens
        self._pos = 0

    def _peek(self) -> str | None:
        return self._tokens[self._pos] if self._pos < len(self._tokens) else None

    def _next(self) -> str | None:
        token = self._peek()
        if token is not None:
            self._pos += 1
        return token

    def parse(self):
        node = self._parse_or()
        if self._peek() is not None:
            raise SigmaConditionError(f"unexpected token {self._peek()!r} in condition")
        return node

    def _parse_or(self):
        operands = [self._parse_and()]
        while self._peek() == "or":
            self._next()
            operands.append(self._parse_and())
        return operands[0] if len(operands) == 1 else Or(tuple(operands))

    def _parse_and(self):
        operands = [self._parse_not()]
        while self._peek() == "and":
            self._next()
            operands.append(self._parse_not())
        return operands[0] if len(operands) == 1 else And(tuple(operands))

    def _parse_not(self):
        if self._peek() == "not":
            self._next()
            return Not(self._parse_not())
        return self._parse_primary()

    def _parse_primary(self):
        token = self._next()
        if token is None:
            raise SigmaConditionError("condition ended unexpectedly")
        if token == "(":
            node = self._parse_or()
            if self._next() != ")":
                raise SigmaConditionError("unbalanced parentheses in condition")
            return node
        if token == ")":
            raise SigmaConditionError("unbalanced parentheses in condition")
        if token in _QUANTIFIERS and self._peek() == "of":
            self._next()
            pattern = self._next()
            if pattern is None:
                raise SigmaConditionError(f"'{token} of' is missing its target")
            return Quantified(token, pattern)
        if token in _KEYWORDS:
            raise SigmaConditionError(f"unexpected keyword {token!r} in condition")
        return Identifier(token)


def parse_condition(condition: str):
    """Parse a Sigma condition string into an evaluable AST.

    Raises :class:`SigmaConditionError` for anything Aegis cannot faithfully
    evaluate, so the loader can skip that rule with a reason rather than
    silently treating it as never matching.
    """
    if not condition or not condition.strip():
        raise SigmaConditionError("condition is empty")
    if "|" in condition:
        raise SigmaConditionError(
            "aggregation conditions (e.g. '| count() > 5') are not supported"
        )
    tokens = [t.lower() if t.lower() in _KEYWORDS | _QUANTIFIERS else t
              for t in _TOKEN_RE.findall(condition)]
    if not tokens:
        raise SigmaConditionError(f"could not tokenise condition {condition!r}")
    return _Parser(tokens).parse()
