"""Tests for the Sigma condition expression parser and evaluator.

The condition is the boolean glue of every Sigma rule; getting precedence or a
negation wrong would silently invert a detection. Constructs Aegis cannot
evaluate faithfully must raise, so the loader skips the rule with a reason
instead of running a rule that can never (or always) match.
"""
import pytest

from aegis.detection.sigma.conditions import SigmaConditionError, parse_condition


def ev(condition: str, **matches: bool) -> bool:
    return parse_condition(condition).evaluate(matches)


# --------------------------------------------------------------------------- #
# Basic boolean logic
# --------------------------------------------------------------------------- #
def test_single_identifier():
    assert ev("selection", selection=True) is True
    assert ev("selection", selection=False) is False


def test_and():
    assert ev("a and b", a=True, b=True) is True
    assert ev("a and b", a=True, b=False) is False


def test_or():
    assert ev("a or b", a=False, b=True) is True
    assert ev("a or b", a=False, b=False) is False


def test_not():
    assert ev("not a", a=False) is True
    assert ev("not a", a=True) is False


def test_the_canonical_selection_and_not_filter():
    assert ev("selection and not filter", selection=True, filter=False) is True
    assert ev("selection and not filter", selection=True, filter=True) is False
    assert ev("selection and not filter", selection=False, filter=False) is False


def test_and_binds_tighter_than_or():
    # a or (b and c) — not (a or b) and c
    assert ev("a or b and c", a=True, b=False, c=False) is True


def test_not_binds_tighter_than_and():
    # (not a) and b
    assert ev("not a and b", a=False, b=True) is True
    assert ev("not a and b", a=True, b=True) is False


def test_parentheses_override_precedence():
    assert ev("(a or b) and c", a=True, b=False, c=False) is False
    assert ev("(a or b) and c", a=True, b=False, c=True) is True


def test_double_negation():
    assert ev("not not a", a=True) is True


def test_chained_operators():
    assert ev("a and b and c", a=True, b=True, c=True) is True
    assert ev("a and b and c", a=True, b=True, c=False) is False
    assert ev("a or b or c", a=False, b=False, c=True) is True


# --------------------------------------------------------------------------- #
# Quantified forms
# --------------------------------------------------------------------------- #
def test_one_of_wildcard():
    assert ev("1 of selection_*", selection_a=False, selection_b=True) is True
    assert ev("1 of selection_*", selection_a=False, selection_b=False) is False


def test_all_of_wildcard():
    assert ev("all of selection_*", selection_a=True, selection_b=True) is True
    assert ev("all of selection_*", selection_a=True, selection_b=False) is False


def test_any_of_is_synonymous_with_one_of():
    assert ev("any of sel*", sel_a=False, sel_b=True) is True


def test_all_of_them():
    assert ev("all of them", a=True, b=True) is True
    assert ev("all of them", a=True, b=False) is False


def test_one_of_them():
    assert ev("1 of them", a=False, b=True) is True


def test_quantifier_only_selects_matching_identifiers():
    """A filter identifier must not be swept into '1 of selection_*'."""
    assert ev("1 of selection_*", selection_a=False, filter_x=True) is False


def test_quantifier_combined_with_negation():
    assert ev("1 of selection_* and not filter",
              selection_a=True, filter=False) is True
    assert ev("1 of selection_* and not filter",
              selection_a=True, filter=True) is False


def test_quantifier_matching_nothing_is_an_error():
    """Silently evaluating to False would make the rule permanently dead."""
    with pytest.raises(SigmaConditionError, match="matches no search identifier"):
        ev("1 of missing_*", selection=True)


# --------------------------------------------------------------------------- #
# Rejected constructs
# --------------------------------------------------------------------------- #
def test_aggregation_is_rejected():
    with pytest.raises(SigmaConditionError, match="aggregation"):
        parse_condition("selection | count() > 5")


def test_empty_condition_is_rejected():
    with pytest.raises(SigmaConditionError):
        parse_condition("")
    with pytest.raises(SigmaConditionError):
        parse_condition("   ")


def test_unbalanced_parentheses_are_rejected():
    for bad in ("(a and b", "a and b)", "((a)"):
        with pytest.raises(SigmaConditionError):
            parse_condition(bad)


def test_dangling_operator_is_rejected():
    for bad in ("a and", "and a", "a or or b", "not"):
        with pytest.raises(SigmaConditionError):
            parse_condition(bad)


def test_unknown_identifier_at_evaluation_is_an_error():
    with pytest.raises(SigmaConditionError, match="unknown identifier"):
        ev("selection and missing", selection=True)


def test_identifiers_are_reported_for_validation():
    node = parse_condition("selection and not filter_x")
    assert node.identifiers() == {"selection", "filter_x"}


def test_quantifier_reports_no_static_identifiers():
    """Wildcards resolve at evaluation time, so they cannot be pre-validated."""
    assert parse_condition("1 of selection_*").identifiers() == set()


def test_keywords_are_case_insensitive():
    assert ev("a AND NOT b", a=True, b=False) is True
    assert ev("a Or b", a=False, b=True) is True


def test_identifiers_are_case_sensitive():
    """Sigma identifiers are user-defined names, not keywords."""
    with pytest.raises(SigmaConditionError):
        ev("Selection", selection=True)
