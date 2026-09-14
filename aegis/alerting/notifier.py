"""Desktop notification delivery with cooldown de-duplication.

Uses win11toast when available (native Windows toast). A per-key cooldown stops
notification storms when the same suspicious activity is seen repeatedly. The
cooldown clock is injectable so it can be tested deterministically.
"""
from __future__ import annotations

import logging
import os
import threading
import time
from collections.abc import Callable

from aegis.config import settings
from aegis.core.models import Alert, Severity

log = logging.getLogger(__name__)

try:
    from win11toast import notify as _toast
    _HAS_TOAST = True
except Exception:  # noqa: BLE001
    _toast = None
    _HAS_TOAST = False


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
        # Defense in depth: never fire a real desktop toast while running under
        # pytest, even if a test forgot to inject a silent notifier.
        if not _HAS_TOAST or os.environ.get("PYTEST_CURRENT_TEST"):
            log.info("[ALERT %s] %s — %s", alert.severity.value, alert.title, alert.message)
            return
        icon = {Severity.CRITICAL: "\U0001F6A8", Severity.HIGH: "⚠️"}.get(alert.severity, "ℹ️")
        threading.Thread(
            target=self._safe_toast, args=(f"{icon} {title}", body), daemon=True).start()

    @staticmethod
    def _safe_toast(title: str, body: str) -> None:
        try:
            _toast(title, body, duration="short")
        except Exception:  # noqa: BLE001
            log.debug("Toast notification failed", exc_info=True)
