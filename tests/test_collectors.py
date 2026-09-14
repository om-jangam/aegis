"""Tests for psutil collectors.

Deterministic heuristics are unit-tested directly; the live collectors are
exercised read-only against the real host (safe, no mutation).
"""
from aegis.collectors.network import NetworkCollector
from aegis.collectors.processes import ProcessCollector, flag_reasons, snapshot
from aegis.core.events import NetworkEvent, ProcessEvent


# --- deterministic heuristics ----------------------------------------------
def test_flag_reasons_temp_dir():
    reasons = flag_reasons(r"C:\Users\me\AppData\Local\Temp\evil.exe", "evil.exe")
    assert any("temporary" in r.lower() for r in reasons)


def test_flag_reasons_masquerade():
    reasons = flag_reasons(r"C:\Users\me\Downloads\svchost.exe", "svchost.exe")
    assert any("system-like" in r.lower() for r in reasons)


def test_flag_reasons_clean_process():
    assert flag_reasons(r"C:\Windows\System32\svchost.exe", "svchost.exe") == []


# --- live, read-only --------------------------------------------------------
def test_network_collector_emits_events():
    col = NetworkCollector()
    assert col.available()
    events = list(col.poll())
    assert all(isinstance(e, NetworkEvent) for e in events)


def test_network_collector_dedup():
    col = NetworkCollector(dedup=True)
    first = list(col.poll())
    second = list(col.poll())          # same connections -> deduped to (near) empty
    assert len(second) <= len(first)


def test_process_collector_and_snapshot():
    col = ProcessCollector()
    events = list(col.poll())
    assert all(isinstance(e, ProcessEvent) for e in events)
    assert len(events) > 0              # this test process exists at minimum

    procs = snapshot(limit=20)
    assert len(procs) > 0
    assert all(p.pid > 0 for p in procs)
