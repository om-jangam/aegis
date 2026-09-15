"""Plain-language wording used by the desktop app."""
from datetime import datetime, timedelta

import pytest

from aegis.ui.plain import (
    AUDIT_FILTERS,
    advice_for_alert,
    audit_category,
    connection_state,
    plural,
    protection_status,
    time_ago,
)

NOW = datetime(2026, 9, 15, 18, 0)


def test_plural():
    assert plural(1, "alert") == "1 alert"
    assert plural(3, "alert") == "3 alerts"
    assert plural(2, "entry", "entries") == "2 entries"


@pytest.mark.parametrize(("raw", "expected"), [
    ("ESTABLISHED", "Connected"), ("LISTEN", "Waiting for connections"),
    ("time_wait", "Closing"), ("NONE", ""), ("SOMETHING_NEW", "Something New"), ("", ""),
])
def test_connection_state(raw, expected):
    assert connection_state(raw) == expected


def test_audit_categories_and_filters_use_everyday_words():
    assert audit_category("RESPONSE") == "Blocked"
    assert audit_category("custom") == "Custom"
    assert AUDIT_FILTERS[0] == ("All", "Everything")
    assert {key for key, _ in AUDIT_FILTERS[1:]} == {"DETECTION", "RESPONSE", "RULE", "SYSTEM"}


def test_advice_reads_the_stored_technique_reference():
    assert "block the address" in advice_for_alert("T1071 (Command and Control)")
    assert advice_for_alert("") == advice_for_alert("T9999")


@pytest.mark.parametrize(("delta", "expected"), [
    (timedelta(seconds=20), "just now"),
    (timedelta(minutes=1), "1 minute ago"),
    (timedelta(minutes=45), "45 minutes ago"),
    (timedelta(hours=5), "5 hours ago"),
    (timedelta(hours=30), "yesterday"),
    (timedelta(days=4), "11 Sep 2026, 18:00"),
])
def test_time_ago(delta, expected):
    assert time_ago(NOW - delta, now=NOW) == expected


def test_status_protected_before_and_after_a_check():
    before = protection_status(monitoring=True, serious_alerts=0, failed_checks=None)
    assert before.level == "ok"
    assert before.headline == "Your computer is protected"
    assert "Run a security check" in before.details[-1]
    after = protection_status(monitoring=True, serious_alerts=0, failed_checks=0)
    assert after.details[-1] == "All security checks passed."


def test_status_lists_what_needs_attention():
    status = protection_status(monitoring=True, serious_alerts=2, failed_checks=1)
    assert status.level == "danger"
    assert status.headline == "3 things need your attention"
    assert status.details == ["2 serious alerts to review", "1 security setting to fix"]


def test_failed_settings_alone_are_a_warning_with_singular_grammar():
    status = protection_status(monitoring=True, serious_alerts=0, failed_checks=1)
    assert status.level == "warn"
    assert status.headline == "1 thing needs your attention"


def test_paused_monitoring_takes_priority_but_keeps_the_problems():
    status = protection_status(monitoring=False, serious_alerts=1, failed_checks=None)
    assert status.level == "paused"
    assert status.headline == "Monitoring is paused"
    assert "1 serious alert to review" in status.details
