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


def test_create_rule_is_audited(tmp_path):
    svc = _svc(tmp_path)
    result = svc.create_rule(FirewallRule(name="test rule"))
    assert result.ok is True
    audit = svc.store.recent_audit(category="RULE")
    assert any(a.action == "rule_created" for a in audit)
    svc.store.close()
