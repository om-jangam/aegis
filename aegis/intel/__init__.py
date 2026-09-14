"""Threat intelligence: known-malicious IP addresses and ranges.

:func:`get_intel` returns the indicator set built from the ``intel`` folder in
the data directory plus any ``intel_paths`` in settings. It notices when those
files change, so ``aegis intel update`` takes effect in a running monitor
without a restart.
"""
from __future__ import annotations

import logging
import threading
import time
from pathlib import Path

from aegis.intel.indicators import IntelMatch, ThreatIntel, parse_indicator

log = logging.getLogger(__name__)

_RECHECK_SECONDS = 30.0
_lock = threading.Lock()
_cache: dict = {"intel": None, "signature": None, "checked": 0.0}


def intel_dir() -> Path:
    from aegis.config import DATA_DIR

    path = DATA_DIR / "intel"
    path.mkdir(parents=True, exist_ok=True)
    return path


def _configured_paths() -> list[Path]:
    from aegis.config import settings

    return [intel_dir(), *(Path(p).expanduser() for p in settings.intel_paths)]


def _signature(paths: list[Path]) -> tuple:
    entries = []
    for base in paths:
        if base.is_file():
            files = [base]
        elif base.is_dir():
            files = sorted(p for p in base.iterdir() if p.is_file())
        else:
            files = []
        for f in files:
            try:
                st = f.stat()
            except OSError:
                continue
            entries.append((str(f), st.st_mtime_ns, st.st_size))
    return tuple(entries)


def get_intel() -> ThreatIntel:
    """The active indicator set, reloaded when its files change."""
    now = time.monotonic()
    with _lock:
        intel = _cache["intel"]
        if intel is not None and now - _cache["checked"] < _RECHECK_SECONDS:
            return intel
        _cache["checked"] = now
        paths = _configured_paths()
        signature = _signature(paths)
        if intel is not None and signature == _cache["signature"]:
            return intel
        fresh = ThreatIntel()
        for path in paths:
            if path.exists():
                fresh.load_path(path)
        _cache.update(intel=fresh, signature=signature)
        log.info("Threat intel loaded: %d indicators from %d list(s).",
                 len(fresh), len(fresh.sources))
        return fresh


def reset_cache() -> None:
    with _lock:
        _cache.update(intel=None, signature=None, checked=0.0)


__all__ = ["IntelMatch", "ThreatIntel", "get_intel", "intel_dir", "parse_indicator",
           "reset_cache"]
