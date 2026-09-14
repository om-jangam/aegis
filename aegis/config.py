"""Central configuration and filesystem paths for Aegis.

All runtime state (database, logs, config, ML model) lives under a single
per-user application-data directory so the packaged executable never needs to
write next to itself (which would require admin rights on Program Files).
"""
from __future__ import annotations

import json
import os
import threading
from dataclasses import asdict, dataclass, field
from pathlib import Path

# Guards the atomic config write against concurrent savers (UI + workers).
_SAVE_LOCK = threading.Lock()


def _app_data_dir() -> Path:
    """Return the per-user data directory, creating it if needed."""
    base = os.environ.get("LOCALAPPDATA") or os.environ.get("APPDATA")
    root = Path(base) if base else Path.home()
    path = root / "Aegis"
    path.mkdir(parents=True, exist_ok=True)
    return path


DATA_DIR: Path = _app_data_dir()
DB_PATH: Path = DATA_DIR / "aegis.db"
LOG_DIR: Path = DATA_DIR / "logs"
LOG_DIR.mkdir(exist_ok=True)
MODEL_PATH: Path = DATA_DIR / "anomaly_model.joblib"
CONFIG_PATH: Path = DATA_DIR / "config.json"

# Project asset directory (fonts / images), resolved relative to the package.
ASSETS_DIR: Path = Path(__file__).resolve().parent.parent / "assets"


@dataclass
class Settings:
    """User-adjustable settings, persisted to config.json."""

    # Monitoring
    network_poll_interval: float = 2.0      # seconds between connection scans
    process_poll_interval: float = 3.0      # seconds between process scans
    monitoring_enabled: bool = True

    # Threat detection
    anomaly_detection_enabled: bool = True
    threat_score_alert_threshold: int = 70  # 0-100; >= this raises an alert
    auto_learn: bool = True                 # keep feeding the ML baseline

    # Alerts
    desktop_notifications: bool = True
    alert_cooldown_seconds: int = 30        # suppress duplicate alerts

    # UI
    theme: str = "dark"                     # "dark" | "light"

    # Data retention
    event_retention_days: int = 30

    # Known-safe / trusted destinations (never alerted on)
    trusted_remote_ips: list[str] = field(default_factory=lambda: [
        "127.0.0.1", "::1", "0.0.0.0",
    ])
    # Ports considered high-risk if seen on unexpected processes
    suspicious_ports: list[int] = field(default_factory=lambda: [
        23, 445, 3389, 4444, 5555, 6667, 31337, 1337, 9001,
    ])

    def save(self) -> None:
        # Atomic write: serialize to a temp file, then os.replace() so a crash
        # mid-write can never leave a half-written / corrupt config.json.
        with _SAVE_LOCK:
            tmp = CONFIG_PATH.with_suffix(".json.tmp")
            tmp.write_text(json.dumps(asdict(self), indent=2), encoding="utf-8")
            os.replace(tmp, CONFIG_PATH)

    @classmethod
    def load(cls) -> Settings:
        if CONFIG_PATH.exists():
            try:
                data = json.loads(CONFIG_PATH.read_text(encoding="utf-8"))
                known = {k: v for k, v in data.items() if k in cls.__dataclass_fields__}
                return cls(**known)
            except (json.JSONDecodeError, TypeError, ValueError):
                pass
        settings = cls()
        settings.save()
        return settings


# Singleton settings instance used across the app.
settings: Settings = Settings.load()
