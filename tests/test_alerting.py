"""Tests for the notifier's de-duplication (deterministic clock + sender) and
for the escaping that keeps attacker-influenced alert text out of AppleScript."""
import pytest

from aegis.alerting.notifier import (
    Notifier,
    escape_applescript,
    notification_backend,
)
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


# --- AppleScript escaping ---------------------------------------------------
# Alert text embeds attacker-influenced data (process names, remote addresses).
# On macOS it is interpolated into an AppleScript string literal, so a crafted
# process name must not be able to terminate that literal and append commands.
def test_escape_applescript_escapes_quotes():
    assert escape_applescript('evil" say "pwned') == 'evil\\" say \\"pwned'


def test_escape_applescript_escapes_backslashes_before_quotes():
    """Order matters: quotes-first would leave an unescaped backslash pair."""
    assert escape_applescript(r'a\"b') == r'a\\\"b'


def test_escape_applescript_strips_control_characters():
    escaped = escape_applescript('line1\nline2\r\tend\x00')
    assert "\n" not in escaped and "\r" not in escaped and "\x00" not in escaped


@pytest.mark.parametrize("payload", [
    'x" with title "hacked',
    'x"; do shell script "id',
    'x\\"; do shell script "whoami',
])
def test_escaped_payload_cannot_close_the_string_literal(payload):
    escaped = escape_applescript(payload)
    script = f'display notification "{escaped}" with title "Aegis"'
    # Every quote inside the payload region must remain backslash-escaped, so
    # the literal has exactly the two delimiters we wrote plus the title's pair.
    unescaped = [
        i for i, ch in enumerate(script)
        if ch == '"' and (i == 0 or script[i - 1] != "\\")
    ]
    assert len(unescaped) == 4, f"payload broke out of the literal: {script}"


def test_notification_backend_is_a_known_channel():
    assert notification_backend() in {"toast", "notify-send", "osascript", "log"}
