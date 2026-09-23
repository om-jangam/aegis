"""DNS monitoring: reading the resolver cache, domain intel, and the detections."""
from datetime import datetime, timedelta

import pytest

from aegis.collectors.dns import (
    DnsCollector,
    is_boring,
    parse_resolvectl_cache,
    parse_windows_cache,
)
from aegis.core.events import DnsEvent, EventSource, EventType
from aegis.core.models import Severity
from aegis.detection.base import DetectionContext
from aegis.detection.engine import DetectionEngine
from aegis.detection.rules.dns_rules import DNS_RULES, looks_generated, shannon_entropy
from aegis.intel import reset_cache
from aegis.intel.indicators import ThreatIntel, parse_domain
from aegis.response.command import RunResult

NOW = datetime(2026, 9, 24, 10, 0, 0)

WINDOWS_CACHE = """
ocsp.digicert.com|5|ocsp.edge.digicert.com
ocsp.digicert.com|1|93.184.220.29
ocsp.digicert.com|1|93.184.220.30
evil.example|1|203.0.113.5
printer.local|1|192.168.1.50
30.1.168.192.in-addr.arpa|12|printer.local
"""
RESOLVECTL_CACHE = """
-- Cache for link 2 (wlan0):
    key: IN A example.com
    data: IN A example.com 93.184.216.34
    key: IN A evil.example
    data: IN A evil.example 203.0.113.5
    key: IN A printer.local
    data: IN A printer.local 192.168.1.50
"""


def _dns(domain="example.com", answers=("93.184.216.34",), record_type="A", minutes=0):
    return DnsEvent(type=EventType.DNS_QUERY, source=EventSource.DNS_CACHE,
                    timestamp=NOW + timedelta(minutes=minutes), domain=domain,
                    record_type=record_type, answers=tuple(answers))


def _findings(events):
    # Fresh rule objects per call: the real rules are long-lived and remember
    # what they have already reported, which would leak between tests.
    engine = DetectionEngine(rules=[type(rule)() for rule in DNS_RULES],
                             context=DetectionContext())
    found = []
    for event in events:
        found.extend(engine.process(event))
    return found


@pytest.fixture
def intel(monkeypatch):
    """A threat-intel set the rules will use, with nothing read from disk."""
    feed = ThreatIntel()
    feed.load_text("0.0.0.0 evil.example\n45.9.1.1\n", "test-feed")
    monkeypatch.setattr("aegis.detection.rules.dns_rules.get_intel", lambda: feed)
    reset_cache()
    return feed


# --------------------------------------------------------------------------- #
# Reading the cache
# --------------------------------------------------------------------------- #
def test_windows_cache_groups_answers_per_name_and_type():
    events = {(e.domain, e.record_type): e for e in parse_windows_cache(WINDOWS_CACHE)}
    assert set(events) == {("ocsp.digicert.com", "CNAME"), ("ocsp.digicert.com", "A"),
                           ("evil.example", "A")}
    assert events[("ocsp.digicert.com", "A")].answers == ("93.184.220.29", "93.184.220.30")
    assert events[("ocsp.digicert.com", "CNAME")].answers == ("ocsp.edge.digicert.com",)


def test_local_and_reverse_lookups_are_left_out():
    names = {e.domain for e in parse_windows_cache(WINDOWS_CACHE)}
    assert "printer.local" not in names
    assert not any(name.endswith("in-addr.arpa") for name in names)


@pytest.mark.parametrize("name", ["printer.local", "host.lan", "1.0.168.192.in-addr.arpa",
                                  "localhost", "", "server"])
def test_boring_names(name):
    assert is_boring(name)


def test_resolvectl_cache_is_read():
    events = {e.domain: e for e in parse_resolvectl_cache(RESOLVECTL_CACHE)}
    assert set(events) == {"example.com", "evil.example"}
    assert events["example.com"].answers == ("93.184.216.34",)
    assert events["example.com"].record_type == "A"


def test_a_name_is_reported_once_per_answer(monkeypatch):
    monkeypatch.setattr("aegis.collectors.dns.is_windows", lambda: True)
    output = ["evil.example|1|203.0.113.5"]

    def runner(args, timeout):
        return RunResult(0, "\n".join(output).encode())

    collector = DnsCollector(runner=runner)
    assert [e.domain for e in collector.poll()] == ["evil.example"]
    assert list(collector.poll()) == []                 # same cache entry, no repeat
    output.append("evil.example|1|203.0.113.9")         # a new answer is news again
    assert len(list(collector.poll())) == 1


def test_dns_monitoring_can_be_turned_off(monkeypatch):
    from aegis.config import settings

    monkeypatch.setattr("aegis.collectors.dns.is_windows", lambda: True)
    assert DnsCollector().available() is True
    monkeypatch.setattr(settings, "dns_monitoring_enabled", False)
    assert DnsCollector().available() is False


def test_an_unreadable_cache_does_not_raise(monkeypatch):
    monkeypatch.setattr("aegis.collectors.dns.is_windows", lambda: True)

    def broken(args, timeout):
        raise OSError("powershell is missing")

    assert list(DnsCollector(runner=broken).poll()) == []


def test_the_parent_domain_groups_subdomains():
    assert _dns("a.b.files.evil.co.uk").parent_domain == "evil.co.uk"   # not bare co.uk
    assert _dns("cdn.evil.example").parent_domain == "evil.example"
    assert _dns("evil.example").parent_domain == "evil.example"


# --------------------------------------------------------------------------- #
# Domain indicators
# --------------------------------------------------------------------------- #
def test_a_listed_domain_matches_its_subdomains():
    feed = ThreatIntel()
    feed.load_text("evil.example\n", "feed")
    assert feed.match_domain("cdn.evil.example").indicator == "evil.example"
    assert feed.match_domain("evil.example") is not None
    assert feed.match_domain("notevil.example") is None


def test_hosts_file_lines_are_read_as_domains():
    feed = ThreatIntel()
    added = feed.load_text("0.0.0.0 malware.test\n127.0.0.1 phish.test\n", "hostfile")
    assert added == 2
    assert feed.match_domain("malware.test") and feed.match_domain("phish.test")
    assert feed.match("127.0.0.1") is None       # the blackhole address is not an indicator


@pytest.mark.parametrize("token", ["com", "a", "-bad.example", "not_a_domain", ""])
def test_useless_domain_indicators_are_rejected(token):
    assert parse_domain(token) is None


def test_domains_and_addresses_live_in_one_feed():
    feed = ThreatIntel()
    feed.load_text("evil.example\n45.9.1.1\n", "mixed")
    assert len(feed) == 2
    assert set(feed.indicators()) == {"evil.example", "45.9.1.1"}


# --------------------------------------------------------------------------- #
# Detections
# --------------------------------------------------------------------------- #
def test_a_listed_domain_is_critical(intel):
    found = _findings([_dns("cdn.evil.example", ("203.0.113.5",))])
    assert [f.rule_id for f in found] == ["DNS-THREAT-INTEL"]
    assert found[0].severity is Severity.CRITICAL
    assert "test-feed" in found[0].reasons[0]


def test_a_name_resolving_to_a_listed_address_is_caught(intel):
    found = _findings([_dns("safe-looking.example", ("45.9.1.1",))])
    assert [f.rule_id for f in found] == ["DNS-INTEL-ANSWER"]
    assert "45.9.1.1" in found[0].reasons[1]


def test_ordinary_lookups_raise_nothing(intel):
    quiet = ["microsoft.com", "fonts.gstatic.com", "sessions.bugsnag.com",
             "d1a2b3c4d5e6f7.cloudfront.net", "deadbeefcafe1234.example.com",
             "firebaseremoteconfig.googleapis.com"]
    assert _findings([_dns(name) for name in quiet]) == []


def test_threat_intel_can_be_turned_off(intel, monkeypatch):
    from aegis.config import settings

    monkeypatch.setattr(settings, "threat_intel_enabled", False)
    assert _findings([_dns("cdn.evil.example")]) == []


def test_a_machine_generated_name_is_reported(intel):
    found = _findings([_dns("kq3v9z7x2wlp.biz")])
    assert [f.rule_id for f in found] == ["DNS-GENERATED-NAME"]
    assert found[0].severity is Severity.MEDIUM
    assert found[0].technique == "T1568.002"


def test_a_generated_name_is_reported_once_per_site(intel):
    events = [_dns("kq3v9z7x2wlp.biz", minutes=m) for m in (0, 1, 2)]
    assert len(_findings(events)) == 1


@pytest.mark.parametrize("label", ["microsoft", "googleapis", "deadbeefcafe1234", "short"])
def test_normal_names_are_not_called_generated(label):
    assert looks_generated(label)[0] is False


def test_entropy_rises_with_randomness():
    assert shannon_entropy("aaaaaaaa") < shannon_entropy("microsoft") \
        < shannon_entropy("kq3v9z7x2wlp")


def test_many_subdomains_of_one_site_look_like_a_tunnel(intel):
    events = [_dns(f"chunk{i}.tunnel.example", minutes=i * 0.1) for i in range(30)]
    tunnels = [f for f in _findings(events) if f.rule_id == "DNS-TUNNEL"]
    assert len(tunnels) == 1
    assert "different subdomains" in tunnels[0].reasons[0]
    assert tunnels[0].severity is Severity.HIGH


def test_one_very_long_label_looks_like_a_tunnel(intel):
    long_label = "a1b2c3d4e5" * 5
    tunnels = [f for f in _findings([_dns(f"{long_label}.tunnel.example")])
               if f.rule_id == "DNS-TUNNEL"]
    assert len(tunnels) == 1
    assert "characters long" in tunnels[0].reasons[0]


def test_a_content_network_is_not_mistaken_for_a_tunnel(intel):
    events = [_dns(f"chunk{i}.cloudfront.net", minutes=i * 0.1) for i in range(40)]
    assert [f for f in _findings(events) if f.rule_id == "DNS-TUNNEL"] == []


def test_a_handful_of_subdomains_is_normal(intel):
    events = [_dns(f"img{i}.example.com", minutes=i * 0.1) for i in range(8)]
    assert _findings(events) == []


def test_every_dns_rule_is_mapped_and_explained():
    for rule in DNS_RULES:
        assert rule.technique.startswith("T") and rule.tactic, rule.rule_id
        assert rule.description and rule.title, rule.rule_id
