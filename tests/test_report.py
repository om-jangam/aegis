"""HTML report generation and plain-language guidance."""
from datetime import datetime

import pytest

from aegis.core.models import Alert, AuditEvent, Finding, Severity
from aegis.detection.guidance import DEFAULT_GUIDANCE, guidance_for
from aegis.posture.base import CheckResult, CheckStatus, PostureReport
from aegis.reporting import build_report
from aegis.storage.database import SQLiteEventStore


@pytest.fixture
def store(tmp_path):
    s = SQLiteEventStore(tmp_path / "report.db")
    yield s
    s.close()


def _posture():
    return PostureReport([
        CheckResult("A", "Host firewall is enabled", "Network", CheckStatus.FAIL, Severity.HIGH,
                    "Firewall is OFF.", ["Public profile"], remediation="Turn the firewall on."),
        CheckResult("B", "UAC", "Privilege", CheckStatus.PASS, Severity.HIGH, "UAC is on."),
    ], platform="windows")


def test_report_contains_score_actions_and_sections(store):
    store.save_alert(Alert(title="Known C2", message="", severity=Severity.CRITICAL,
                           source="45.9.1.1:443", technique="T1071 (Command and Control)"))
    store.save_finding(Finding(rule_id="R", title="Known C2", severity=Severity.CRITICAL,
                               technique="T1071", entity="45.9.1.1:443"))
    store.add_audit(AuditEvent(category="SYSTEM", action="x", message="Monitoring started"))

    html = build_report(store, _posture(), hostname="laptop", now=datetime(2026, 9, 14, 10, 30))

    assert "Aegis security report - laptop" in html
    assert "85/100" in html
    assert "Turn the firewall on." in html
    assert "block the address" in html          # guidance for the open critical alert
    assert "Monitoring started" in html
    assert "2026-09-14 10:30" in html
    assert "<script" not in html


def test_report_escapes_attacker_controlled_values(store):
    store.save_alert(Alert(title="<script>alert(1)</script>", message="",
                           severity=Severity.HIGH, source='"><img src=x onerror=alert(1)>'))
    html = build_report(store, None, hostname="<b>host</b>")
    assert "<script>alert(1)" not in html
    assert "<img src=x" not in html
    assert "&lt;script&gt;" in html
    assert "<b>host</b>" not in html


def test_report_without_posture_or_data(store):
    html = build_report(store, None, hostname="")
    assert "not run" in html
    assert "No alerts recorded." in html
    assert "Nothing urgent" in html


@pytest.mark.parametrize(("technique", "fragment"), [
    ("T1059.001", "command interpreter"),
    ("t1486", "ransomware"),
    ("T1566.001", "attachment"),
])
def test_guidance_matches_exact_parent_and_case(technique, fragment):
    assert fragment in guidance_for(technique)


def test_guidance_falls_back_for_unknown_or_missing_techniques():
    assert guidance_for("T9999") == DEFAULT_GUIDANCE
    assert guidance_for("") == DEFAULT_GUIDANCE


def test_every_technique_used_by_a_rule_has_specific_guidance():
    from aegis.detection.ruleset import build_ruleset

    rules, _ = build_ruleset()
    missing = {r.technique for r in rules if r.technique and guidance_for(r.technique) == DEFAULT_GUIDANCE}
    assert missing == set()
