"""Tests for configuration defaults and (de)serialization.

These avoid clobbering the real user config file by exercising the dataclass
in isolation rather than the on-disk singleton.
"""
from dataclasses import asdict

from aegis.config import Settings


def test_defaults_are_sane():
    s = Settings()
    assert s.network_poll_interval > 0
    assert 0 <= s.threat_score_alert_threshold <= 100
    assert s.event_retention_days >= 1
    assert isinstance(s.trusted_remote_ips, list)
    assert "127.0.0.1" in s.trusted_remote_ips


def test_roundtrip_via_dict():
    s = Settings(network_poll_interval=5.0, threat_score_alert_threshold=80)
    data = asdict(s)
    restored = Settings(**{k: v for k, v in data.items()
                           if k in Settings.__dataclass_fields__})
    assert restored.network_poll_interval == 5.0
    assert restored.threat_score_alert_threshold == 80


def test_unknown_keys_ignored_on_construct():
    # Simulates loading a config written by a newer version with extra keys.
    data = asdict(Settings())
    data["some_future_setting"] = 123
    restored = Settings(**{k: v for k, v in data.items()
                           if k in Settings.__dataclass_fields__})
    assert isinstance(restored, Settings)
