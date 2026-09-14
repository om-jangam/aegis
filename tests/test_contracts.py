"""Tests that the subsystem contracts (ABCs) are usable and wire together.

We implement throwaway collector/rule/responder subclasses to prove the base
classes form a coherent pipeline before any real subsystem exists.
"""
from collections.abc import Iterable

from aegis.collectors.base import Collector
from aegis.core.events import Direction, Event, EventSource, EventType, NetworkEvent
from aegis.core.models import Finding, Severity
from aegis.detection.base import DetectionContext, DetectionRule
from aegis.response.base import Responder, ResponseResult


class DummyCollector(Collector):
    name = "dummy"
    source = EventSource.PSUTIL

    def poll(self) -> Iterable[Event]:
        return [NetworkEvent(
            type=EventType.NETWORK_CONNECTION, source=self.source,
            pid=1, process_name="x.exe", protocol="TCP",
            remote_ip="8.8.8.8", remote_port=4444, direction=Direction.OUTBOUND,
        )]


class SuspiciousPortRule(DetectionRule):
    rule_id = "TEST-PORT-4444"
    title = "Connection to suspicious port 4444"
    severity = Severity.HIGH
    technique = "T1071"
    tactic = "Command and Control"
    event_types = (EventType.NETWORK_CONNECTION,)

    def evaluate(self, event: Event, context: DetectionContext) -> Finding | None:
        if isinstance(event, NetworkEvent) and event.remote_port == 4444:
            return self.make_finding(
                score=80, reasons=["Remote port 4444 is a common C2 default"],
                entity=f"{event.remote_ip}:{event.remote_port}",
                source_summary=event.summary())
        return None


class DummyResponder(Responder):
    name = "dummy-block"

    def can_handle(self, finding: Finding) -> bool:
        return finding.score >= 70

    def respond(self, finding: Finding) -> ResponseResult:
        return ResponseResult(ok=True, action="block", message=f"blocked {finding.entity}")


def test_pipeline_flows_end_to_end():
    collector = DummyCollector()
    rule = SuspiciousPortRule()
    responder = DummyResponder()
    ctx = DetectionContext()

    findings = []
    for event in collector.poll():
        ctx.remember(event)
        if rule.wants(event):
            f = rule.evaluate(event, ctx)
            if f:
                findings.append(f)

    assert len(findings) == 1
    finding = findings[0]
    assert finding.attack_ref == "T1071 (Command and Control)"
    assert finding.severity == Severity.HIGH
    assert responder.can_handle(finding)
    assert responder.respond(finding).ok
    assert len(ctx) == 1


def test_rule_wants_filters_event_types():
    rule = SuspiciousPortRule()
    net = NetworkEvent(type=EventType.NETWORK_CONNECTION, source=EventSource.PSUTIL)
    proc = Event(type=EventType.PROCESS_START, source=EventSource.PSUTIL)
    assert rule.wants(net) is True
    assert rule.wants(proc) is False
