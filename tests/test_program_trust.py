"""Parent program names on alerts, and alerts suppressed for trusted programs."""
import sqlite3

import pytest

from aegis.alerting.notifier import Notifier
from aegis.config import settings
from aegis.core.events import Direction, EventSource, EventType, NetworkEvent, ProcessEvent
from aegis.core.models import Alert, Severity
from aegis.detection.base import DetectionRule
from aegis.detection.engine import DetectionEngine
from aegis.response.firewall import FirewallManager, RunResult
from aegis.service import SecurityService
from aegis.storage.database import SQLiteEventStore
from aegis.ui.views.detections_view import program_line


def _process(name="powershell.exe", parent="claude.exe"):
    return ProcessEvent(type=EventType.PROCESS_START, source=EventSource.PSUTIL, pid=13856,
                        ppid=2988, name=name, cmdline=f"{name} -enc SQBFAFgA",
                        raw={"parent_name": parent} if parent else None)


def _connection(name="updater.exe"):
    return NetworkEvent(type=EventType.NETWORK_CONNECTION, source=EventSource.PSUTIL, pid=5,
                        process_name=name, protocol="TCP", remote_ip="45.9.1.1",
                        remote_port=443, direction=Direction.OUTBOUND)


class AlwaysHigh(DetectionRule):
    rule_id = "TEST-HIGH"
    title = "Test detection"
    severity = Severity.HIGH

    def evaluate(self, event, context):
        return self.make_finding(score=90, reasons=["test"], entity=event.summary(),
                                 source_summary=event.summary())


@pytest.fixture
def service(tmp_path, monkeypatch):
    # Independent of the programs trusted in the real user profile.
    monkeypatch.setattr(settings, "trusted_programs", [])
    svc = SecurityService(
        store=SQLiteEventStore(tmp_path / "trust.db"),
        engine=DetectionEngine(rules=[AlwaysHigh()]),
        firewall=FirewallManager(runner=lambda args, timeout: RunResult(0, b"Ok.")),
        notifier=Notifier(sender=lambda title, body: None), ml=None, collectors=[])
    yield svc
    svc.store.close()


# --------------------------------------------------------------------------- #
# Wording
# --------------------------------------------------------------------------- #
def test_process_summary_names_the_parent_program():
    assert _process().summary() == "powershell.exe (pid 13856), started by claude.exe (pid 2988)"


def test_process_summary_without_a_known_parent_still_reads_plainly():
    assert _process(parent="").summary() == "powershell.exe (pid 13856, parent pid 2988)"


def test_program_line():
    assert program_line("powershell.exe", "claude.exe") == \
        "Program: powershell.exe, started by claude.exe"
    assert program_line("chrome.exe", "") == "Program: chrome.exe"
    assert program_line("", "") == ""


# --------------------------------------------------------------------------- #
# Alerts carry the program names
# --------------------------------------------------------------------------- #
def test_alerts_record_program_and_parent(service):
    alerts = []
    service.on_alert(alerts.append)
    service.ingest([_process()])
    assert (alerts[0].process_name, alerts[0].parent_name) == ("powershell.exe", "claude.exe")
    stored = service.store.recent_alerts()[0]
    assert (stored.process_name, stored.parent_name) == ("powershell.exe", "claude.exe")


def test_network_alerts_record_the_program(service):
    service.ingest([_connection()])
    assert service.store.recent_alerts()[0].process_name == "updater.exe"


def test_existing_databases_gain_the_new_alert_columns(tmp_path):
    path = tmp_path / "old.db"
    old = sqlite3.connect(path)
    old.execute("CREATE TABLE alerts (id INTEGER PRIMARY KEY AUTOINCREMENT, ts TEXT NOT NULL,"
                " title TEXT NOT NULL, message TEXT, severity TEXT NOT NULL, source TEXT,"
                " technique TEXT, score INTEGER DEFAULT 0, acknowledged INTEGER DEFAULT 0)")
    old.execute("INSERT INTO alerts (ts, title, severity) VALUES ('2026-07-26T10:00:00', 'Old', 'HIGH')")
    old.commit()
    old.close()

    store = SQLiteEventStore(path)
    assert store.recent_alerts()[0].process_name == ""
    store.save_alert(Alert(title="New", message="", process_name="a.exe", parent_name="b.exe"))
    assert store.recent_alerts()[0].parent_name == "b.exe"
    store.close()
    SQLiteEventStore(path).close()   # reopening an upgraded database is a no-op


# --------------------------------------------------------------------------- #
# Trusted programs
# --------------------------------------------------------------------------- #
def test_trusted_parent_suppresses_the_alert_but_keeps_the_finding(service, monkeypatch):
    monkeypatch.setattr(settings, "trusted_programs", ["claude.exe"])
    alerts = []
    service.on_alert(alerts.append)
    findings = service.ingest([_process()])
    assert findings and alerts == []
    assert service.store.stats()["total_findings"] == 1


def test_trusted_program_suppresses_its_network_alerts(service, monkeypatch):
    monkeypatch.setattr(settings, "trusted_programs", ["UPDATER.EXE"])
    service.ingest([_connection()])
    assert service.store.recent_alerts() == []


def test_programs_started_by_something_else_still_alert(service, monkeypatch):
    monkeypatch.setattr(settings, "trusted_programs", ["claude.exe"])
    service.ingest([_process(parent="winword.exe")])
    assert len(service.store.recent_alerts()) == 1


def test_trusting_an_interpreter_has_no_effect(service, monkeypatch):
    monkeypatch.setattr(settings, "trusted_programs", ["powershell.exe"])
    service.ingest([_process(parent="winword.exe")])
    assert len(service.store.recent_alerts()) == 1
