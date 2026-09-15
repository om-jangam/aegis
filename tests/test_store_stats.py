"""Dashboard figures computed by the SQLite store."""
from aegis.core.events import Direction, EventSource, EventType, NetworkEvent, ProcessEvent
from aegis.core.models import Alert, Severity
from aegis.storage.database import SQLiteEventStore


def _conn(name):
    return NetworkEvent(type=EventType.NETWORK_CONNECTION, source=EventSource.PSUTIL, pid=1,
                        process_name=name, protocol="TCP", remote_ip="142.250.4.1",
                        remote_port=443, direction=Direction.OUTBOUND)


def test_top_processes_counts_only_named_network_programs(tmp_path):
    store = SQLiteEventStore(tmp_path / "s.db")
    store.save_events([_conn("chrome.exe")] * 3 + [_conn("spotify.exe"), _conn("System"),
                                                   _conn("")])
    store.save_events([ProcessEvent(type=EventType.PROCESS_START, source=EventSource.PSUTIL,
                                    pid=2, name="notepad.exe")])
    top = store.stats()["top_processes"]
    assert top == [{"process_name": "chrome.exe", "n": 3}, {"process_name": "spotify.exe", "n": 1}]
    store.close()


def test_open_serious_alerts_ignores_minor_and_reviewed_alerts(tmp_path):
    store = SQLiteEventStore(tmp_path / "s.db")
    store.save_alert(Alert(title="a", message="", severity=Severity.CRITICAL))
    reviewed = store.save_alert(Alert(title="b", message="", severity=Severity.HIGH))
    store.save_alert(Alert(title="c", message="", severity=Severity.MEDIUM))
    store.acknowledge_alert(reviewed)
    stats = store.stats()
    assert stats["open_serious_alerts"] == 1
    assert stats["open_alerts"] == 2
    store.close()
