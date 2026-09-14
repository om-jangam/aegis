"""Rotating-file + console logging configuration for Aegis."""
from __future__ import annotations

import logging
import threading
from logging.handlers import RotatingFileHandler

from aegis.config import LOG_DIR

_CONFIGURED = False
_LOCK = threading.Lock()


def setup_logging(level: int = logging.INFO) -> None:
    # Locked check-then-set so two threads can't both attach handlers
    # (which would double every log line).
    global _CONFIGURED
    with _LOCK:
        if _CONFIGURED:
            return
        fmt = logging.Formatter(
            "%(asctime)s | %(levelname)-8s | %(name)s | %(message)s",
            datefmt="%Y-%m-%d %H:%M:%S",
        )
        root = logging.getLogger()
        root.setLevel(level)

        console = logging.StreamHandler()
        console.setFormatter(fmt)
        root.addHandler(console)

        try:
            file_handler = RotatingFileHandler(
                LOG_DIR / "aegis.log", maxBytes=2_000_000, backupCount=5, encoding="utf-8",
            )
            file_handler.setFormatter(fmt)
            root.addHandler(file_handler)
        except OSError as exc:
            # A previous instance can briefly retain the log on Windows. The
            # application must still start, with diagnostics on the console.
            root.warning("File logging unavailable: %s", exc)

        _CONFIGURED = True
