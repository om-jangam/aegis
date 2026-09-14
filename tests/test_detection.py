"""Tests for detection rules and the engine.

Each rule is verified to fire on the malicious case and stay silent on benign
traffic (false-positive discipline), and to carry the right ATT&CK mapping.
"""
from aegis.core.events import Direction, EventSource, EventType, NetworkEvent, ProcessEvent
from aegis.core.models import Severity
from aegis.detection.base import DetectionContext
from aegis.detection.engine import DetectionEngine
from aegis.detection.rules import default_rules
from aegis.detection.rules.network_rules import (
    InterpreterNetworkRule,
    LegacyPlaintextProtocolRule,
    ListeningOnSensitivePortRule,
    NetworkScanningRule,
    RemoteServicesRule,
    SuspiciousC2PortRule,
    UncommonPortToPublicRule,
)
from aegis.detection.rules.process_rules import SuspiciousProcessLocationRule


def net(remote_ip="45.9.1.1", remote_port=443, pid=1000, name="app.exe",
        etype=EventType.NETWORK_CONNECTION, local_port=0):
    return NetworkEvent(
        type=etype, source=EventSource.PSUTIL, pid=pid, process_name=name,
        protocol="TCP", local_ip="192.168.1.5", local_port=local_port,
        remote_ip=remote_ip, remote_port=remote_port, direction=Direction.OUTBOUND)


ctx = DetectionContext()


# --- individual rules -------------------------------------------------------
def test_c2_port_rule_fires():
    f = SuspiciousC2PortRule().evaluate(net(remote_port=4444), ctx)
    assert f is not None
    assert f.technique == "T1571"
    assert f.severity == Severity.HIGH
    assert f.score >= 80


def test_c2_port_rule_silent_on_https():
    assert SuspiciousC2PortRule().evaluate(net(remote_port=443), ctx) is None


def test_remote_services_rule_rdp():
    f = RemoteServicesRule().evaluate(net(remote_port=3389), ctx)
    assert f is not None and f.technique == "T1021"


def test_interpreter_network_rule():
    f = InterpreterNetworkRule().evaluate(net(name="powershell.exe", remote_port=8081), ctx)
    assert f is not None and f.technique == "T1059"
    # a normal browser must not trigger it
    assert InterpreterNetworkRule().evaluate(net(name="chrome.exe", remote_port=8081), ctx) is None


def test_uncommon_port_low_signal():
    f = UncommonPortToPublicRule().evaluate(net(remote_port=8899), ctx)
    assert f is not None and f.severity == Severity.LOW


def test_legacy_plaintext_rule_fires_on_telnet_to_public():
    f = LegacyPlaintextProtocolRule().evaluate(net(remote_port=23), ctx)  # Telnet
    assert f is not None and f.technique == "T1071"
    # ...but not to a private/internal host
    assert LegacyPlaintextProtocolRule().evaluate(
        net(remote_ip="192.168.1.10", remote_port=23), ctx) is None


def test_listening_on_sensitive_port_rule():
    listen = NetworkEvent(type=EventType.NETWORK_LISTEN, source=EventSource.PSUTIL,
                          pid=999, process_name="backdoor.exe", protocol="TCP",
                          local_ip="0.0.0.0", local_port=4444, direction=Direction.LISTEN)
    f = ListeningOnSensitivePortRule().evaluate(listen, ctx)
    assert f is not None and f.rule_id == "NET-LISTEN-SENSITIVE"
    # a normal listener (e.g. port 139) should not fire
    normal = NetworkEvent(type=EventType.NETWORK_LISTEN, source=EventSource.PSUTIL,
                          pid=4, process_name="System", protocol="TCP",
                          local_ip="0.0.0.0", local_port=139, direction=Direction.LISTEN)
    assert ListeningOnSensitivePortRule().evaluate(normal, ctx) is None


def test_trusted_ip_not_flagged():
    # loopback / trusted addresses are never flagged
    assert SuspiciousC2PortRule().evaluate(net(remote_ip="127.0.0.1", remote_port=4444), ctx) is None


def test_scanning_rule_uses_context():
    rule = NetworkScanningRule()
    context = DetectionContext()
    last = None
    for i in range(20):
        e = net(remote_ip=f"10.0.0.{i}", remote_port=445, pid=777, name="scanner.exe")
        context.remember(e)
        last = rule.evaluate(e, context)
    assert last is not None
    assert last.technique == "T1046"


def test_process_location_rule():
    ev = ProcessEvent(type=EventType.PROCESS_START, source=EventSource.PSUTIL,
                      pid=5, name="svchost.exe", exe=r"C:\Users\me\Downloads\svchost.exe")
    f = SuspiciousProcessLocationRule().evaluate(ev, ctx)
    assert f is not None and f.technique == "T1036"


# --- engine -----------------------------------------------------------------
def test_engine_loads_default_rules():
    eng = DetectionEngine()
    assert eng.rule_count >= 7


def test_engine_produces_findings_for_c2():
    eng = DetectionEngine()
    findings = eng.process(net(remote_port=4444, name="evil.exe"))
    assert any(f.technique == "T1571" for f in findings)


def test_engine_quiet_on_normal_traffic():
    eng = DetectionEngine()
    findings = eng.process(net(remote_ip="140.82.112.3", remote_port=443, name="chrome.exe"))
    # normal HTTPS to a public host should not raise high-severity findings
    assert all(f.severity.rank < Severity.HIGH.rank for f in findings)


def test_all_rules_have_attack_mapping():
    for rule in default_rules():
        assert rule.rule_id
        assert rule.technique.startswith("T"), f"{rule.rule_id} missing ATT&CK technique"
        assert rule.tactic, f"{rule.rule_id} missing tactic"


def test_engine_is_thread_safe_under_concurrent_load():
    # Two collector threads feed the shared engine concurrently in production;
    # the stateful scanning rule iterates recent history while events arrive.
    # This stresses that path to guard against "deque mutated during iteration".
    import threading

    eng = DetectionEngine()
    errors = []

    def worker(base):
        try:
            for i in range(400):
                eng.process(net(remote_ip=f"10.{base}.0.{i % 250}", remote_port=445,
                                pid=base, name="scanner.exe"))
        except Exception as exc:  # noqa: BLE001
            errors.append(exc)

    threads = [threading.Thread(target=worker, args=(b,)) for b in range(6)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    assert not errors, f"engine raised under concurrency: {errors[:3]}"
