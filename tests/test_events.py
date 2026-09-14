"""Tests for the normalized telemetry event model."""
from datetime import datetime

from aegis.core.events import Direction, EventSource, EventType, NetworkEvent, ProcessEvent


def _net(remote_ip="8.8.8.8", remote_port=443, pid=1234, proto="TCP"):
    return NetworkEvent(
        type=EventType.NETWORK_CONNECTION, source=EventSource.PSUTIL,
        pid=pid, process_name="chrome.exe", protocol=proto,
        local_ip="192.168.1.5", local_port=51000,
        remote_ip=remote_ip, remote_port=remote_port,
        status="ESTABLISHED", direction=Direction.OUTBOUND,
    )


def test_public_remote_is_flagged_remote():
    assert _net("8.8.8.8").is_remote is True


def test_private_and_loopback_not_remote():
    assert _net("192.168.1.20").is_remote is False
    assert _net("127.0.0.1").is_remote is False
    assert _net("10.1.2.3").is_remote is False
    assert _net("").is_remote is False


def test_dedup_key_is_stable_and_distinct():
    a = _net(pid=1, remote_ip="8.8.8.8", remote_port=443)
    b = _net(pid=1, remote_ip="8.8.8.8", remote_port=443)
    c = _net(pid=1, remote_ip="8.8.8.8", remote_port=444)
    assert a.dedup_key == b.dedup_key
    assert a.dedup_key != c.dedup_key


def test_network_summary_readable():
    assert "chrome.exe" in _net().summary()
    assert "8.8.8.8:443" in _net().summary()


def test_events_are_immutable():
    e = _net()
    try:
        e.remote_ip = "1.1.1.1"  # type: ignore[misc]
    except Exception as exc:  # frozen dataclass raises FrozenInstanceError
        assert "cannot assign" in str(exc).lower() or exc.__class__.__name__ == "FrozenInstanceError"
    else:
        raise AssertionError("Event should be immutable")


def test_process_event_summary():
    p = ProcessEvent(type=EventType.PROCESS_START, source=EventSource.PSUTIL,
                     pid=10, ppid=4, name="powershell.exe")
    assert "powershell.exe" in p.summary()
    assert p.timestamp <= datetime.now()
