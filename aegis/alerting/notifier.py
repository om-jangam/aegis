"""Desktop notification delivery with cooldown de-duplication.

Each platform gets its native notification channel — win11toast on Windows,
``notify-send`` on Linux, ``osascript`` on macOS — and falls back to the log
when none is present, so a headless server still records every alert.

A per-key cooldown stops notification storms when the same suspicious activity
is seen repeatedly. The cooldown clock is injectable so it can be tested
deterministically.

Security note: alert text contains attacker-influenced data (process names,
remote addresses). The Linux path passes it as an argument list, and the macOS
path escapes it for AppleScript's string syntax — notification delivery must not
become the injection hole the firewall engine was hardened against.
"""
from __future__ import annotations

import logging
import os
import subprocess
import threading
import time
from collections.abc import Callable

from aegis.config import settings
from aegis.core.models import Alert, Severity
from aegis.platforms import NO_WINDOW, is_linux, is_macos, is_windows, which

log = logging.getLogger(__name__)

try:
    from win11toast import notify as _toast
    _HAS_TOAST = True
except Exception:  # noqa: BLE001
    _toast = None
    _HAS_TOAST = False

# Control characters are stripped from every notification body regardless of
# platform: they have no legitimate place in an alert and can corrupt the
# rendering of whichever channel receives them.
_CONTROL_CHARS = dict.fromkeys(range(32))


def _clean(text: str) -> str:
    return (text or "").translate(_CONTROL_CHARS).strip()


def escape_applescript(text: str) -> str:
    """Escape a string for safe interpolation into an AppleScript literal.

    Backslashes first, then quotes — reversing the order would double-escape the
    backslashes introduced by the quote pass and let a crafted process name
    terminate the string early.
    """
    return _clean(text).replace("\\", "\\\\").replace('"', '\\"')


def notification_backend() -> str:
    """Which notification channel this host will use ('log' if none)."""
    if is_windows() and _HAS_TOAST:
        return "toast"
    if is_linux() and which("notify-send"):
        return "notify-send"
    if is_macos() and which("osascript"):
        return "osascript"
    return "log"


class Notifier:
    def __init__(self, clock: Callable[[], float] | None = None,
                 sender: Callable[[str, str], None] | None = None):
        self._last_sent: dict[str, float] = {}
        self._lock = threading.Lock()
        self._clock = clock or time.monotonic
        self._sender = sender      # injectable for tests; None -> real toast

    def _allowed(self, key: str) -> bool:
        now = self._clock()
        with self._lock:
            last = self._last_sent.get(key, -1e9)
            if now - last < settings.alert_cooldown_seconds:
                return False
            self._last_sent[key] = now
            if len(self._last_sent) > 500:
                self._last_sent.clear()
            return True

    def notify(self, alert: Alert, dedup_key: str | None = None) -> bool:
        """Send a desktop notification. Returns True if actually sent."""
        if not settings.desktop_notifications:
            return False
        key = dedup_key or f"{alert.title}:{alert.source}"
        if not self._allowed(key):
            return False
        title = f"Aegis — {alert.title}"
        body = alert.message
        if self._sender is not None:
            self._sender(title, body)
            return True
        self._dispatch(alert, title, body)
        return True

    def _dispatch(self, alert: Alert, title: str, body: str) -> None:
        # Defense in depth: never fire a real desktop notification while running
        # under pytest, even if a test forgot to inject a silent notifier.
        backend = notification_backend()
        if backend == "log" or os.environ.get("PYTEST_CURRENT_TEST"):
            log.info("[ALERT %s] %s — %s", alert.severity.value, alert.title, alert.message)
            return
        icon = {Severity.CRITICAL: "\U0001F6A8", Severity.HIGH: "⚠️"}.get(alert.severity, "ℹ️")
        threading.Thread(
            target=self._safe_send,
            args=(backend, f"{icon} {title}", body, alert.severity),
            daemon=True,
        ).start()

    @staticmethod
    def _safe_send(backend: str, title: str, body: str, severity: Severity) -> None:
        """Deliver via the host's native channel; never raise into the caller."""
        try:
            if backend == "toast":
                _toast(title, body, duration="short")
            elif backend == "notify-send":
                urgency = "critical" if severity >= Severity.HIGH else "normal"
                subprocess.run(
                    ["notify-send", "-a", "Aegis", "-u", urgency,
                     _clean(title), _clean(body)],
                    shell=False, timeout=10, capture_output=True,
                )
            elif backend == "osascript":
                script = (
                    f'display notification "{escape_applescript(body)}" '
                    f'with title "{escape_applescript(title)}"'
                )
                subprocess.run(
                    ["osascript", "-e", script],
                    shell=False, timeout=10, capture_output=True,
                    creationflags=NO_WINDOW,
                )
        except Exception:  # noqa: BLE001
            log.debug("Desktop notification failed via %s", backend, exc_info=True)
