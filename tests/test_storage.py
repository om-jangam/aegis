"""Tests for the SQLite EventStore (uses a temp DB, never the real one)."""
import pytest

from aegis.core.events import Direction, EventSource, EventType, NetworkEvent, ProcessEvent
from aegis.core.models import Alert, AuditEvent, Finding, Severity
from aegis.storage.database import SQLiteEventStore


@pytest.fixture
def store(tmp_path):
    s = SQLiteEventStore(tmp_path / "test.db")
    yield s
    s.close()


def _net(remote_ip="8.8.8.8", remote_port=443):
    return NetworkEvent(
        type=EventType.NETWORK_CONNECTION, source=EventSource.PSUTIL,
        pid=1, process_name="chrome.exe", protocol="TCP",
        remote_ip=remote_ip, remote_port=remote_port, direction=Direction.OUTBOUND)


def test_save_and_query_network_events(store):
    store.save_events([_net(), _net("1.1.1.1", 53)])
    rows = store.recent_network_events()
    assert len(rows) == 2
    assert rows[0]["process_name"] == "chrome.exe"


def test_save_process_event(store):
    store.save_events([ProcessEvent(
        type=EventType.PROCESS_START, source=EventSource.PSUTIL,
        pid=10, ppid=4, name="powershell.exe", exe=r"C:\ps.exe")])
    # process events land in the events table with the extra JSON blob
    assert store.stats()["total_events"] == 1


def test_findings_roundtrip(store):
    fid = store.save_finding(Finding(
        rule_id="NET-C2", title="C2", severity=Severity.HIGH, score=80,
        technique="T1571", tactic="C2", entity="8.8.8.8:4444",
        reasons=["port 4444"]))
    assert fid > 0
    rows = store.recent_findings()
    assert rows[0]["technique"] == "T1571"
    assert rows[0]["score"] == 80


def test_alerts_and_ack(store):
    aid = store.save_alert(Alert(title="t", message="m", severity=Severity.HIGH,
                                 source="8.8.8.8:4444", technique="T1571", score=80))
    assert len(store.recent_alerts(unacknowledged_only=True)) == 1
    store.acknowledge_alert(aid)
    assert len(store.recent_alerts(unacknowledged_only=True)) == 0


def test_audit_log(store):
    store.add_audit(AuditEvent(category="RULE", action="rule_created",
                               severity=Severity.INFO, message="made a rule"))
    store.add_audit(AuditEvent(category="RESPONSE", action="ip_blocked",
                               severity=Severity.MEDIUM, message="blocked 1.2.3.4"))
    assert len(store.recent_audit()) == 2
    assert len(store.recent_audit(category="RULE")) == 1


def test_stats_and_timeline(store):
    store.save_events([_net("9.9.9.9", 4444), _net("9.9.9.9", 80)])
    store.save_finding(Finding(rule_id="R", title="t", severity=Severity.HIGH,
                               technique="T1571"))
    store.save_alert(Alert(title="t", message="m", severity=Severity.HIGH))
    stats = store.stats()
    assert stats["total_events"] == 2
    assert stats["total_alerts"] == 1
    assert stats["alerts_by_severity"].get("HIGH") == 1
    assert any(r["remote_ip"] == "9.9.9.9" for r in stats["top_remote_ips"])
    assert any(r["technique"] == "T1571" for r in stats["top_techniques"])


def test_purge_old_keeps_recent(store):
    store.save_events([_net()])
    # nothing older than 30 days -> purge removes 0
    assert store.purge_old(days=30) == 0
    assert store.stats()["total_events"] == 1


def test_purge_counts_events_and_findings_but_retains_audit(store):
    store.save_events([_net(), _net("1.1.1.1", 53)])
    store.save_finding(Finding(rule_id="R", title="t", severity=Severity.HIGH))
    store.save_alert(Alert(title="t", message="m", severity=Severity.HIGH))
    store.add_audit(AuditEvent(category="RULE", action="x", severity=Severity.INFO))
    # days=-1 -> cutoff is in the future, so all telemetry is purged
    removed = store.purge_old(days=-1)
    assert removed == 3                       # 2 events + 1 finding (correct total)
    assert store.stats()["total_events"] == 0
    # alerts + audit are the security record — intentionally retained
    assert len(store.recent_alerts()) == 1
    assert len(store.recent_audit()) == 1
