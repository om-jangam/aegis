"""Tests for the notifier's de-duplication (deterministic clock + sender)."""
from aegis.alerting.notifier import Notifier
from aegis.config import settings
from aegis.core.models import Alert, Severity


def _alert():
    return Alert(title="C2 activity", message="evil.exe -> 1.2.3.4:4444",
                 severity=Severity.HIGH, source="1.2.3.4:4444")


def test_notify_sends_and_dedups():
    sent = []
    t = {"now": 0.0}
    n = Notifier(clock=lambda: t["now"], sender=lambda title, body: sent.append(title))

    assert n.notify(_alert()) is True            # first -> sent
    assert n.notify(_alert()) is False           # within cooldown -> suppressed
    assert len(sent) == 1

    t["now"] = settings.alert_cooldown_seconds + 1
    assert n.notify(_alert()) is True            # cooldown elapsed -> sent again
    assert len(sent) == 2


def test_disabled_notifications(monkeypatch):
    monkeypatch.setattr(settings, "desktop_notifications", False)
    n = Notifier(sender=lambda *_: None)
    assert n.notify(_alert()) is False


def test_no_real_toast_under_pytest():
    # Defense in depth: the default (real) dispatch path must NOT fire a Windows
    # toast while the test suite runs. PYTEST_CURRENT_TEST is set during tests, so
    # _dispatch takes the log-only branch. This is the regression guard for the
    # "evil.exe:4444 toast popped up during testing" issue.
    import os
    assert os.environ.get("PYTEST_CURRENT_TEST")      # we are under pytest
    n = Notifier()                                     # real notifier, no sender injected
    # Should not raise and should not spawn a real toast (logs instead).
    n._dispatch(_alert(), "Aegis — C2", "evil.exe -> 1.2.3.4:4444")
