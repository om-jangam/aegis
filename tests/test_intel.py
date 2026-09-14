"""Threat intelligence: indicator parsing, matching, feed updates and the detection rule."""
import pytest

import aegis.intel as intel_pkg
from aegis.core.events import Direction, EventSource, EventType, NetworkEvent
from aegis.core.models import Severity
from aegis.detection.base import DetectionContext
from aegis.detection.rules.intel_rules import ThreatIntelMatchRule
from aegis.intel import ThreatIntel, get_intel, parse_indicator, reset_cache
from aegis.intel.feeds import Feed, https_fetch, update_feeds
from aegis.response.firewall import FirewallResponder


@pytest.mark.parametrize("token", [
    "45.9.1.1", "1.10.16.0/20", "2a00:1450::/32", "2a00:1450:4001::1",
])
def test_parse_accepts_public_addresses_and_ranges(token):
    assert parse_indicator(token) is not None


@pytest.mark.parametrize("token", [
    "", "garbage", "10.0.0.5", "192.168.0.0/16", "127.0.0.1", "0.0.0.0/0",
    "4.0.0.0/7", "::1", "fe80::1", "224.0.0.1", "2a00::/16",
])
def test_parse_rejects_private_reserved_and_overbroad_entries(token):
    assert parse_indicator(token) is None


SPAMHAUS_STYLE = """; Spamhaus DROP List
; Last-Modified: today
1.10.16.0/20 ; SBL256894
45.9.1.1
# comment line
192.168.1.0/24 ; would flag the LAN, must be rejected
not-an-ip
"""


def test_load_text_counts_accepted_and_rejected():
    intel = ThreatIntel()
    assert intel.load_text(SPAMHAUS_STYLE, "drop") == 2
    assert intel.rejected == 2
    assert intel.sources == {"drop": 2}
    assert len(intel) == 2


def test_match_exact_range_mapped_and_miss():
    intel = ThreatIntel()
    intel.load_text(SPAMHAUS_STYLE, "drop")
    assert intel.match("45.9.1.1").indicator == "45.9.1.1"
    assert intel.match("1.10.20.7").indicator == "1.10.16.0/20"
    assert intel.match("::ffff:45.9.1.1").source == "drop"
    assert intel.match("8.8.8.8") is None
    assert intel.match("not an ip") is None


def test_load_path_reads_indicator_files_and_ignores_others(tmp_path):
    (tmp_path / "botnet.txt").write_text("45.9.1.1\n", encoding="utf-8")
    (tmp_path / "partial.txt.tmp").write_text("45.9.1.2\n", encoding="utf-8")
    (tmp_path / "notes.md").write_text("45.9.1.3\n", encoding="utf-8")
    intel = ThreatIntel()
    assert intel.load_path(tmp_path) == 1
    assert intel.sources == {"botnet": 1}


# --------------------------------------------------------------------------- #
# Feeds
# --------------------------------------------------------------------------- #
GOOD = Feed("good", "https://example.test/good.txt", "good feed")
BAD = Feed("bad", "https://example.test/bad.txt", "unreachable feed")


def test_update_writes_validated_indicators(tmp_path):
    def fetch(url, max_bytes):
        if url == BAD.url:
            raise OSError("connection refused")
        return b"# header\n45.9.1.1\n10.0.0.1\n1.10.16.0/20\n"

    results = update_feeds(tmp_path, [GOOD, BAD], fetch=fetch)
    assert [(r.feed.name, r.ok, r.indicators) for r in results] == [
        ("good", True, 2), ("bad", False, 0)]
    assert "connection refused" in results[1].message

    written = (tmp_path / "good.txt").read_text(encoding="utf-8")
    assert "10.0.0.1" not in written
    intel = ThreatIntel()
    intel.load_path(tmp_path)
    assert intel.match("45.9.1.1") and intel.match("1.10.16.1")


def test_update_keeps_previous_copy_when_response_has_no_indicators(tmp_path):
    (tmp_path / "good.txt").write_text("45.9.1.1\n", encoding="utf-8")
    results = update_feeds(tmp_path, [GOOD], fetch=lambda url, n: b"<html>Service down</html>")
    assert results[0].ok is False
    assert (tmp_path / "good.txt").read_text(encoding="utf-8") == "45.9.1.1\n"


def test_fetch_refuses_plain_http():
    with pytest.raises(ValueError, match="HTTPS"):
        https_fetch("http://example.test/list.txt", 100)


# --------------------------------------------------------------------------- #
# Detection
# --------------------------------------------------------------------------- #
def _conn(ip, port=443, name="updater.exe"):
    return NetworkEvent(type=EventType.NETWORK_CONNECTION, source=EventSource.PSUTIL, pid=7,
                        process_name=name, protocol="TCP", remote_ip=ip, remote_port=port,
                        direction=Direction.OUTBOUND)


@pytest.fixture
def listed():
    intel = ThreatIntel()
    intel.load_text("45.9.1.1\n1.10.16.0/20\n", "feodo")
    return intel


def test_rule_fires_on_listed_address_even_on_port_443(listed):
    finding = ThreatIntelMatchRule(listed).evaluate(_conn("45.9.1.1"), DetectionContext())
    assert finding.severity is Severity.CRITICAL
    assert finding.entity == "45.9.1.1:443"
    assert "feodo" in finding.reasons[0]
    assert FirewallResponder(manager=object()).can_handle(finding)


def test_rule_explains_range_matches(listed):
    finding = ThreatIntelMatchRule(listed).evaluate(_conn("1.10.17.9"), DetectionContext())
    assert "range 1.10.16.0/20" in finding.reasons[0]


def test_rule_ignores_unlisted_and_trusted_addresses(listed, monkeypatch):
    rule = ThreatIntelMatchRule(listed)
    assert rule.evaluate(_conn("8.8.8.8"), DetectionContext()) is None
    from aegis.config import settings
    monkeypatch.setattr(settings, "trusted_remote_ips", ["45.9.1.1"])
    assert rule.evaluate(_conn("45.9.1.1"), DetectionContext()) is None


def test_rule_can_be_disabled(listed, monkeypatch):
    from aegis.config import settings
    monkeypatch.setattr(settings, "threat_intel_enabled", False)
    assert ThreatIntelMatchRule(listed).evaluate(_conn("45.9.1.1"), DetectionContext()) is None


def test_get_intel_reloads_when_files_change(tmp_path, monkeypatch):
    monkeypatch.setattr(intel_pkg, "_configured_paths", lambda: [tmp_path])
    monkeypatch.setattr(intel_pkg, "_RECHECK_SECONDS", 0.0)
    reset_cache()
    try:
        assert len(get_intel()) == 0
        (tmp_path / "custom.txt").write_text("45.9.1.1\n", encoding="utf-8")
        assert get_intel().match("45.9.1.1").source == "custom"
    finally:
        reset_cache()
