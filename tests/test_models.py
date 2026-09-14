"""Tests for domain / detection models."""
from aegis.core.models import Finding, Severity


def test_severity_ordering():
    assert Severity.CRITICAL.rank > Severity.HIGH.rank > Severity.MEDIUM.rank
    assert Severity.HIGH >= Severity.MEDIUM
    assert Severity.CRITICAL > Severity.LOW
    assert not (Severity.LOW >= Severity.HIGH)
    # full, rank-based (not lexicographic) ordering in both directions
    assert Severity.LOW < Severity.CRITICAL
    assert Severity.MEDIUM <= Severity.MEDIUM
    assert sorted([Severity.HIGH, Severity.INFO, Severity.CRITICAL, Severity.LOW]) == \
        [Severity.INFO, Severity.LOW, Severity.HIGH, Severity.CRITICAL]


def test_severity_is_str_value():
    # StrEnum: the member *is* its string value (handy for JSON / UI).
    assert Severity.HIGH == "HIGH"
    assert f"{Severity.CRITICAL}" == "CRITICAL"


def test_finding_attack_ref():
    f = Finding(rule_id="NET-C2", title="C2 beacon", severity=Severity.HIGH,
                technique="T1071", tactic="Command and Control")
    assert f.attack_ref == "T1071 (Command and Control)"


def test_finding_attack_ref_technique_only():
    f = Finding(rule_id="X", title="x", severity=Severity.LOW, technique="T1046")
    assert f.attack_ref == "T1046"


def test_finding_defaults():
    f = Finding(rule_id="X", title="x", severity=Severity.INFO)
    assert f.score == 0
    assert f.reasons == []
    assert f.entity == ""
