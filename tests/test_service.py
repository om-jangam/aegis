"""Integration test for the orchestration service (no threads, no real netsh).

Uses a temp store, a fake collector, and a recording firewall runner so the full
pipeline (event -> detection -> store -> alert -> audit) runs deterministically.
"""
from aegis.alerting.notifier import Notifier
from aegis.core.events import Direction, EventSource, EventType, NetworkEvent
from aegis.core.models import FirewallRule
from aegis.response.firewall import FirewallManager, RunResult
from aegis.service import SecurityService, severity_for
from aegis.storage.database import SQLiteEventStore


class RecordingRunner:
    def __init__(self):
        self.calls = []

    def __call__(self, args, timeout):
        self.calls.append(list(args))
        return RunResult(0, b"Ok.\r\n\r\n")


def _silent_notifier():
    # A no-op sender ensures tests NEVER emit a real Windows toast.
    return Notifier(sender=lambda title, body: None)


def _svc(tmp_path):
    store = SQLiteEventStore(tmp_path / "svc.db")
    fw = FirewallManager(runner=RecordingRunner())
    # ml=None avoids the real model file; a silent notifier avoids real toasts;
    # collectors=[] because we feed events manually.
    return SecurityService(store=store, firewall=fw, ml=None, collectors=[],
                           notifier=_silent_notifier())


def test_severity_mapping():
    assert severity_for(95).value == "CRITICAL"
    assert severity_for(75).value == "HIGH"
    assert severity_for(50).value == "MEDIUM"
    assert severity_for(10).value == "INFO"


def test_pipeline_c2_event_raises_alert_and_audit(tmp_path):
    svc = _svc(tmp_path)
    alerts = []
    svc.on_alert(alerts.append)

    evil = NetworkEvent(type=EventType.NETWORK_CONNECTION, source=EventSource.PSUTIL,
                        pid=1, process_name="evil.exe", protocol="TCP",
                        remote_ip="45.9.1.1", remote_port=4444, direction=Direction.OUTBOUND)
    findings = svc.ingest([evil])

    assert any(f.technique == "T1571" for f in findings)
    assert len(alerts) >= 1                       # HIGH severity -> alert raised
    assert svc.store.stats()["total_events"] == 1
    assert svc.store.stats()["open_alerts"] >= 1
    # audit trail recorded the detection
    audit = svc.store.recent_audit(category="DETECTION")
    assert len(audit) >= 1
    svc.store.close()


def test_pipeline_normal_event_no_alert(tmp_path):
    svc = _svc(tmp_path)
    alerts = []
    svc.on_alert(alerts.append)
    normal = NetworkEvent(type=EventType.NETWORK_CONNECTION, source=EventSource.PSUTIL,
                          pid=1, process_name="chrome.exe", protocol="TCP",
                          remote_ip="140.82.112.3", remote_port=443, direction=Direction.OUTBOUND)
    svc.ingest([normal])
    assert alerts == []
    svc.store.close()


def _c2(remote_ip="45.9.1.1"):
    return NetworkEvent(type=EventType.NETWORK_CONNECTION, source=EventSource.PSUTIL,
                        pid=1, process_name="evil.exe", protocol="TCP",
                        remote_ip=remote_ip, remote_port=4444, direction=Direction.OUTBOUND)


def test_repeated_detection_raises_one_alert_but_keeps_every_finding(tmp_path):
    svc = _svc(tmp_path)
    alerts = []
    svc.on_alert(alerts.append)
    first = svc.ingest([_c2()])
    second = svc.ingest([_c2()])
    c2_alerts = [a for a in alerts if a.source == "45.9.1.1:4444"]
    assert first and second
    assert len({a.title for a in c2_alerts}) == len(c2_alerts)   # one alert per rule
    assert svc.store.stats()["total_findings"] == len(first) + len(second)
    svc.store.close()


def test_same_rule_on_a_different_subject_still_alerts(tmp_path):
    svc = _svc(tmp_path)
    alerts = []
    svc.on_alert(alerts.append)
    svc.ingest([_c2("45.9.1.1")])
    svc.ingest([_c2("45.9.1.2")])
    assert {a.source for a in alerts} >= {"45.9.1.1:4444", "45.9.1.2:4444"}
    svc.store.close()


def test_alert_dedup_can_be_disabled(tmp_path, monkeypatch):
    from aegis.config import settings
    monkeypatch.setattr(settings, "alert_dedup_minutes", 0)
    svc = _svc(tmp_path)
    alerts = []
    svc.on_alert(alerts.append)
    svc.ingest([_c2()])
    once = len(alerts)
    svc.ingest([_c2()])
    assert len(alerts) == 2 * once
    svc.store.close()


def test_create_rule_is_audited(tmp_path):
    svc = _svc(tmp_path)
    result = svc.create_rule(FirewallRule(name="test rule"))
    assert result.ok is True
    audit = svc.store.recent_audit(category="RULE")
    assert any(a.action == "rule_created" for a in audit)
    svc.store.close()
