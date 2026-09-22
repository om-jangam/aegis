"""Forwarding to SENTINEL-X: schema mapping, queue, delivery, retries and the off switch."""
import json
import re
import threading
import time
import urllib.request
import uuid
from dataclasses import asdict
from datetime import datetime
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest

from aegis.alerting.notifier import Notifier
from aegis.config import ForwardingSettings, Settings, settings
from aegis.core.events import (
    Direction,
    EventSource,
    EventType,
    FileEvent,
    NetworkEvent,
    ProcessEvent,
)
from aegis.core.models import Alert, Finding, Severity
from aegis.forwarding import (
    AgentInfo,
    Backoff,
    EventQueue,
    Forwarder,
    Heartbeat,
    Sender,
    build_forwarder,
    load_or_create_agent_id,
    to_shared_event,
    validate_server_url,
)
from aegis.forwarding.schema import TECHNIQUE_NAMES, rule_source
from aegis.forwarding.sender import _NoRedirect
from aegis.posture.base import CheckResult, CheckStatus, PostureReport
from aegis.response.firewall import FirewallManager, RunResult
from aegis.service import SecurityService
from aegis.storage.database import SQLiteEventStore

SCHEMA = json.loads((Path(__file__).resolve().parent.parent / "shared" / "event_schema.json")
                    .read_text(encoding="utf-8"))
AGENT = AgentInfo(str(uuid.uuid4()), "test-host", "windows", "1.1.0")
API_KEY = "sx-ingest-0123456789abcdef"
_PY_TYPES = {"object": dict, "array": list, "string": str, "integer": int, "boolean": bool,
             "null": type(None)}


def assert_matches_schema(instance, schema=SCHEMA, path="$"):
    """A small JSON Schema check covering the keywords the contract uses."""
    if "const" in schema:
        assert instance == schema["const"], path
    if "enum" in schema:
        assert instance in schema["enum"], f"{path}={instance!r}"
    if "type" in schema:
        types = schema["type"] if isinstance(schema["type"], list) else [schema["type"]]
        assert any(isinstance(instance, _PY_TYPES[t])
                   and not (t == "integer" and isinstance(instance, bool)) for t in types), \
            f"{path} has type {type(instance).__name__}, expected {types}"
    if "pattern" in schema and isinstance(instance, str):
        assert re.search(schema["pattern"], instance), f"{path}={instance!r}"
    if isinstance(instance, int) and not isinstance(instance, bool):
        assert instance >= schema.get("minimum", instance), path
        assert instance <= schema.get("maximum", instance), path
    if isinstance(instance, dict):
        for key in schema.get("required", []):
            assert key in instance, f"{path}.{key} is missing"
        for key, sub in schema.get("properties", {}).items():
            if key in instance:
                assert_matches_schema(instance[key], sub, f"{path}.{key}")
    if isinstance(instance, list) and "items" in schema:
        for i, item in enumerate(instance):
            assert_matches_schema(item, schema["items"], f"{path}[{i}]")


def _net(remote_ip="45.9.1.1", port=4444):
    return NetworkEvent(type=EventType.NETWORK_CONNECTION, source=EventSource.PSUTIL, pid=321,
                        process_name="evil.exe", protocol="TCP", local_ip="192.168.1.20",
                        local_port=50123, remote_ip=remote_ip, remote_port=port,
                        direction=Direction.OUTBOUND)


def _finding(rule_id="NET-C2-PORT", technique="T1571", tactic="Command and Control",
             severity=Severity.HIGH):
    return Finding(rule_id=rule_id, title="Connection to a known C2 / backdoor port",
                   severity=severity, score=85, technique=technique, tactic=tactic,
                   reasons=["Remote port 4444 is a common C2/backdoor default"],
                   entity="45.9.1.1:4444", timestamp=datetime(2026, 9, 16, 12, 0, 0))


def _posture(status=CheckStatus.FAIL):
    return PostureReport([
        CheckResult("A", "Firewall", "Network", status, Severity.HIGH, "off"),
        CheckResult("B", "UAC", "Privilege", CheckStatus.PASS, Severity.HIGH, "on"),
    ], platform="windows", generated_at=datetime(2026, 9, 16, 11, 0, 0))


class FakeServer:
    """A transport that records requests and answers with scripted statuses."""

    def __init__(self, *statuses):
        self.statuses = list(statuses)
        self.calls = []

    def __call__(self, url, body, headers, timeout, verify_tls):
        self.calls.append({"url": url, "body": json.loads(body), "headers": headers,
                           "verify_tls": verify_tls})
        status = self.statuses.pop(0) if self.statuses else 202
        if isinstance(status, Exception):
            raise status
        return status


# --------------------------------------------------------------------------- #
# Schema mapping
# --------------------------------------------------------------------------- #
def test_finding_maps_to_the_contract():
    event = to_shared_event(_finding(), AGENT, source_event=_net())
    assert_matches_schema(event)
    assert uuid.UUID(event["event_id"]).version == 4
    assert event["event_type"] == "finding"
    assert event["severity"] == "high"
    assert event["rule"] == {"id": "NET-C2-PORT",
                             "name": "Connection to a known C2 / backdoor port",
                             "source": "python"}
    assert event["mitre"] == [{"technique_id": "T1571", "technique_name": "Non-Standard Port",
                               "tactic": "Command and Control"}]
    assert event["details"]["network"] == {"src_ip": "192.168.1.20", "dst_ip": "45.9.1.1",
                                           "dst_port": 4444, "protocol": "tcp"}
    assert "What to do:" in event["details"]["message"]
    assert event["agent"] == AGENT.to_dict()
    assert event["response_taken"] == "none"
    assert event["timestamp"].endswith("Z")


def test_alert_uses_the_finding_for_rule_identity_and_records_the_response():
    alert = Alert(title="C2", message="evil.exe -> 45.9.1.1:4444", severity=Severity.CRITICAL,
                  technique="T1571 (Command and Control)")
    event = to_shared_event(alert, AGENT, source_event=_net(), finding=_finding(),
                            response_taken="blocked_host")
    assert_matches_schema(event)
    assert (event["event_type"], event["severity"], event["response_taken"]) == \
        ("alert", "critical", "blocked_host")
    assert event["rule"]["id"] == "NET-C2-PORT"


def test_alert_without_its_finding_parses_the_stored_technique():
    alert = Alert(title="C2", message="m", severity=Severity.HIGH,
                  technique="T1059.001 (Execution)")
    event = to_shared_event(alert, AGENT)
    assert_matches_schema(event)
    assert event["mitre"] == [{"technique_id": "T1059.001", "technique_name": "PowerShell",
                               "tactic": "Execution"}]


@pytest.mark.parametrize(("rule_id", "expected"), [
    ("SIGMA-aegis-0001-encoded-powershell", "sigma"), ("NET-THREAT-INTEL", "threat_intel"),
    ("ML-ANOMALY", "ml"), ("PROC-SUSPICIOUS-PATH", "python"), ("FILE-HOSTS", "python"),
])
def test_rule_source(rule_id, expected):
    assert rule_source(rule_id) == expected


def test_findings_without_attack_mapping_send_an_empty_mitre_list():
    event = to_shared_event(_finding(rule_id="ML-ANOMALY", technique="", tactic=""), AGENT)
    assert event["mitre"] == []
    assert event["rule"]["source"] == "ml"


def test_every_technique_aegis_detects_has_a_name():
    from aegis.detection.ruleset import build_ruleset

    rules, _ = build_ruleset()
    missing = {r.technique for r in rules if r.technique
               and not (TECHNIQUE_NAMES.get(r.technique)
                        or TECHNIQUE_NAMES.get(r.technique.split(".")[0]))}
    assert missing == set()


def test_process_details_redact_secrets_and_never_include_raw_records():
    process = ProcessEvent(
        type=EventType.PROCESS_START, source=EventSource.PSUTIL, pid=10, ppid=4,
        name="curl.exe", exe=r"C:\tools\curl.exe", username="alice",
        cmdline=("curl -H 'Authorization: Bearer abcdefghijklmnop' --password hunter2 "
                 "https://bob:s3cret@example.com http://127.0.0.1:8765/#token=dashboard-secret"),
        raw={"parent_name": "cmd.exe", "environment": "AWS_SECRET_ACCESS_KEY=leak"})
    event = to_shared_event(_finding(), AGENT, source_event=process)
    text = json.dumps(event)
    assert_matches_schema(event)
    for secret in ("abcdefghijklmnop", "hunter2", "s3cret", "dashboard-secret", "leak"):
        assert secret not in text, secret
    assert event["details"]["process"]["parent_name"] == "cmd.exe"
    assert "[REDACTED]" in event["details"]["process"]["command_line"]


def test_long_command_lines_are_truncated():
    process = ProcessEvent(type=EventType.PROCESS_START, source=EventSource.PSUTIL, pid=1,
                           name="powershell.exe", cmdline="powershell -enc " + "A" * 5000)
    command_line = to_shared_event(_finding(), AGENT, source_event=process)["details"]["process"]["command_line"]
    assert len(command_line) <= 1024 and command_line.endswith("...")


def test_file_details_carry_hashes_not_contents():
    change = FileEvent(type=EventType.FILE_MODIFIED, source=EventSource.FILESYSTEM,
                       path="/etc/hosts", size=220, previous_size=200, digest="aa", previous_digest="bb")
    event = to_shared_event(_finding(rule_id="FILE-HOSTS", technique="T1565.001"), AGENT,
                            source_event=change)
    assert_matches_schema(event)
    assert event["details"]["file"] == {"path": "/etc/hosts", "action": "modified", "size": 220,
                                        "previous_size": 200, "digest": "aa", "previous_digest": "bb"}


def test_security_check_maps_to_audit_score():
    event = to_shared_event(_posture(), AGENT)
    assert_matches_schema(event)
    assert event["event_type"] == "audit_score"
    assert event["details"]["audit"]["score"] == 85
    assert (event["details"]["audit"]["failed"], event["details"]["audit"]["passed"]) == (1, 1)
    assert event["severity"] == "info" or event["severity"] == "low"


def test_heartbeat_with_and_without_a_security_check():
    bare = to_shared_event(Heartbeat(), AGENT)
    assert_matches_schema(bare)
    assert bare["event_type"] == "heartbeat" and "audit" not in bare["details"]
    scored = to_shared_event(Heartbeat(posture=_posture(CheckStatus.PASS)), AGENT)
    assert_matches_schema(scored)
    assert scored["details"]["audit"]["score"] == 100


def test_mapping_rejects_unknown_types_and_responses():
    with pytest.raises(TypeError):
        to_shared_event(object(), AGENT)
    with pytest.raises(ValueError):
        to_shared_event(_finding(), AGENT, response_taken="deleted")


# --------------------------------------------------------------------------- #
# Agent identity
# --------------------------------------------------------------------------- #
def test_agent_id_is_generated_once_and_reused(tmp_path):
    first = load_or_create_agent_id(tmp_path)
    assert uuid.UUID(first).version == 4
    assert load_or_create_agent_id(tmp_path) == first


def test_corrupt_agent_id_is_replaced(tmp_path):
    (tmp_path / "agent_id").write_text("not-a-uuid", encoding="utf-8")
    replaced = load_or_create_agent_id(tmp_path)
    assert uuid.UUID(replaced)
    assert (tmp_path / "agent_id").read_text(encoding="utf-8") == replaced


# --------------------------------------------------------------------------- #
# Queue
# --------------------------------------------------------------------------- #
def test_queue_is_fifo_and_survives_reopening(tmp_path):
    path = tmp_path / "q.db"
    queue = EventQueue(path)
    for n in range(3):
        queue.put({"n": n})
    rows = queue.peek(2)
    assert [payload["n"] for _, payload in rows] == [0, 1]
    queue.delete([rows[0][0]])
    queue.close()

    reopened = EventQueue(path)
    assert len(reopened) == 2
    assert [payload["n"] for _, payload in reopened.peek(10)] == [1, 2]
    reopened.close()


def test_full_queue_drops_the_oldest_events(tmp_path):
    queue = EventQueue(tmp_path / "q.db", max_rows=3)
    for n in range(5):
        queue.put({"n": n})
    assert [payload["n"] for _, payload in queue.peek(10)] == [2, 3, 4]
    assert queue.dropped == 2
    queue.close()


# --------------------------------------------------------------------------- #
# Sender
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize("url", ["https://sentinel.example.com/", "http://127.0.0.1:8000",
                                 "http://localhost:8000", "http://[::1]:8000"])
def test_server_url_accepts_https_and_local_http(url):
    assert not validate_server_url(url).endswith("/")


@pytest.mark.parametrize("url", ["http://sentinel.example.com", "ftp://sentinel.example.com",
                                 "sentinel.example.com", "https://user:pass@sentinel.example.com", ""])
def test_server_url_rejects_plain_http_credentials_and_junk(url):
    with pytest.raises(ValueError):
        validate_server_url(url)


def test_sender_posts_a_batch_with_bearer_auth():
    server = FakeServer(202)
    result = Sender("https://sentinel.example.com/", API_KEY, transport=server).send([{"a": 1}])
    assert result.ok and result.status == 202
    call = server.calls[0]
    assert call["url"] == "https://sentinel.example.com/api/v1/ingest/events"
    assert call["headers"]["Authorization"] == f"Bearer {API_KEY}"
    assert call["body"] == {"events": [{"a": 1}]}
    assert call["verify_tls"] is True


def test_sender_reports_failures_without_raising():
    assert not Sender("https://s.example", API_KEY, transport=FakeServer(503)).send([]).ok
    unreachable = Sender("https://s.example", API_KEY, transport=FakeServer(ConnectionRefusedError()))
    result = unreachable.send([])
    assert not result.ok and result.status is None and result.error == "ConnectionRefusedError"


def test_sender_requires_a_key_and_hides_it():
    with pytest.raises(ValueError):
        Sender("https://s.example", "")
    assert API_KEY not in repr(Sender("https://s.example", API_KEY))


def test_redirects_are_never_followed():
    assert _NoRedirect().redirect_request(None, None, 307, "", {}, "https://elsewhere") is None


def test_backoff_grows_exponentially_and_caps():
    backoff = Backoff(base=1, factor=2, maximum=10, jitter=0.2, rng=lambda: 0.5)
    assert [backoff.next_delay() for _ in range(6)] == [1, 2, 4, 8, 10, 10]
    backoff.reset()
    assert backoff.next_delay() == 1


def test_real_http_round_trip_against_a_local_server():
    received = []

    class Handler(BaseHTTPRequestHandler):
        def do_POST(self):  # noqa: N802
            body = self.rfile.read(int(self.headers["Content-Length"]))
            received.append((self.path, self.headers.get("Authorization"), json.loads(body)))
            if self.path == "/moved":
                self.send_response(307)
                self.send_header("Location", "/api/v1/ingest/events")
                self.send_header("Content-Length", "0")
                self.end_headers()
                return
            payload = b'{"accepted": 1}'
            self.send_response(202)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(payload)))
            self.end_headers()
            self.wfile.write(payload)

        def log_message(self, *args):
            pass

    httpd = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    base = f"http://127.0.0.1:{httpd.server_address[1]}"
    try:
        result = Sender(base, API_KEY).send([{"x": 1}])
        assert result.ok and result.status == 202
        assert received[0] == ("/api/v1/ingest/events", f"Bearer {API_KEY}", {"events": [{"x": 1}]})

        moved = Sender(base, API_KEY, ingest_path="/moved").send([{"x": 2}])
        assert not moved.ok and moved.status == 307
        assert len(received) == 2          # the redirect was not followed
    finally:
        httpd.shutdown()
        httpd.server_close()


# --------------------------------------------------------------------------- #
# Forwarder: delivery, retries, heartbeats
# --------------------------------------------------------------------------- #
def _forwarder(tmp_path, server, **options):
    return Forwarder(Sender("https://sentinel.example.com", API_KEY, transport=server),
                     EventQueue(tmp_path / "q.db"), AGENT, **options)


def test_events_are_deleted_only_after_a_2xx(tmp_path):
    server = FakeServer(500, ConnectionResetError(), 202)
    fwd = _forwarder(tmp_path, server)
    fwd.submit(_finding(), source_event=_net())
    assert fwd.flush_once() is False and len(fwd.queue) == 1
    assert fwd.flush_once() is False and len(fwd.queue) == 1
    assert fwd.flush_once() is True and len(fwd.queue) == 0
    assert fwd.sent == 1 and fwd.failed_attempts == 2
    assert_matches_schema(server.calls[-1]["body"]["events"][0])
    fwd.queue.close()


def test_batches_respect_batch_size_and_shrink_on_413(tmp_path):
    server = FakeServer(413, 202, 202)
    fwd = _forwarder(tmp_path, server, batch_size=4)
    for _ in range(5):
        fwd.submit(_finding())
    assert fwd.flush_once() is False and fwd.batch_size == 2
    fwd.flush_once()
    fwd.flush_once()
    assert [len(c["body"]["events"]) for c in server.calls] == [4, 2, 2]
    assert len(fwd.queue) == 1
    fwd.queue.close()


def test_background_loop_retries_with_backoff_until_delivered(tmp_path):
    server = FakeServer(503, 503, 202)
    fwd = _forwarder(tmp_path, server, flush_interval=0.05, heartbeat_interval=3600,
                     backoff=Backoff(base=0.01, maximum=0.05, rng=lambda: 0.5))
    fwd.submit(_finding())
    fwd.start()
    deadline = time.monotonic() + 5
    while time.monotonic() < deadline and not any(
            e["event_type"] == "finding" for c in server.calls[2:] for e in c["body"]["events"]):
        time.sleep(0.02)
    fwd.stop()
    delivered = [e["event_type"] for c in server.calls[2:] for e in c["body"]["events"]]
    assert "finding" in delivered
    assert len(server.calls) >= 3


def test_heartbeat_carries_the_latest_security_check(tmp_path):
    server = FakeServer()
    fwd = _forwarder(tmp_path, server, posture_provider=lambda: _posture(CheckStatus.PASS))
    fwd.heartbeat()
    fwd.flush_once()
    event = server.calls[0]["body"]["events"][0]
    assert event["event_type"] == "heartbeat"
    assert event["details"]["audit"]["score"] == 100
    fwd.queue.close()


def test_submit_never_raises_into_detection(tmp_path):
    fwd = _forwarder(tmp_path, FakeServer())
    fwd.submit(object())
    assert len(fwd.queue) == 0
    fwd.queue.close()


def test_the_api_key_never_enters_the_queue(tmp_path):
    fwd = _forwarder(tmp_path, FakeServer())
    fwd.submit(_finding(), source_event=_net())
    fwd.heartbeat()
    assert API_KEY not in json.dumps([payload for _, payload in fwd.queue.peek(10)])
    fwd.queue.close()


# --------------------------------------------------------------------------- #
# Configuration and the off switch
# --------------------------------------------------------------------------- #
def test_forwarding_settings_round_trip_and_default_off():
    assert Settings().forwarding.enabled is False
    data = asdict(Settings(forwarding=ForwardingSettings(enabled=True, server_url="https://s.example")))
    data["forwarding"]["future_option"] = 1
    restored = Settings(**{k: v for k, v in data.items() if k in Settings.__dataclass_fields__})
    assert restored.forwarding == ForwardingSettings(enabled=True, server_url="https://s.example")
    assert restored.forwarding.batch_size == 50 and restored.forwarding.flush_interval_seconds == 10
    assert restored.forwarding.verify_tls is True


def test_disabled_forwarding_builds_nothing(tmp_path):
    server = FakeServer()
    assert build_forwarder(ForwardingSettings(server_url="https://s.example", api_key=API_KEY),
                           tmp_path, transport=server) is None
    assert server.calls == []
    assert not (tmp_path / "forward_queue.db").exists()


def test_build_forwarder_rejects_bad_configuration(tmp_path, monkeypatch):
    monkeypatch.delenv("AEGIS_FORWARDING_API_KEY", raising=False)
    with pytest.raises(ValueError):
        build_forwarder(ForwardingSettings(enabled=True, server_url="https://s.example"), tmp_path)
    with pytest.raises(ValueError):
        build_forwarder(ForwardingSettings(enabled=True, server_url="http://s.example",
                                           api_key=API_KEY), tmp_path)


def test_api_key_can_come_from_the_environment(tmp_path, monkeypatch):
    monkeypatch.setenv("AEGIS_FORWARDING_API_KEY", API_KEY)
    server = FakeServer()
    fwd = build_forwarder(ForwardingSettings(enabled=True, server_url="https://s.example"),
                          tmp_path, transport=server)
    fwd.submit(_finding())
    fwd.flush_once()
    assert server.calls[0]["headers"]["Authorization"] == f"Bearer {API_KEY}"
    fwd.queue.close()


# --------------------------------------------------------------------------- #
# Service integration
# --------------------------------------------------------------------------- #
class RecordingForwarder:
    def __init__(self):
        self.submitted = []
        self.started = self.stopped = False
        self.posture_provider = None

    def submit(self, item, **options):
        self.submitted.append((item, options))

    def start(self):
        self.started = True

    def stop(self):
        self.stopped = True


def _service(tmp_path, forwarder, auto_respond=False):
    return SecurityService(
        store=SQLiteEventStore(tmp_path / "svc.db"),
        firewall=FirewallManager(runner=lambda args, timeout: RunResult(0, b"Ok.\r\n\r\n")),
        notifier=Notifier(sender=lambda title, body: None), ml=None, collectors=[],
        forwarder=forwarder, auto_respond=auto_respond)


def test_disabled_forwarding_makes_no_network_calls(tmp_path, monkeypatch):
    monkeypatch.setattr(settings, "forwarding",
                        ForwardingSettings(enabled=False, server_url="https://s.example",
                                           api_key=API_KEY))

    def no_network(*args, **kwargs):
        raise AssertionError("forwarding is disabled but a network call was made")

    monkeypatch.setattr(urllib.request.OpenerDirector, "open", no_network)
    monkeypatch.setattr(urllib.request, "urlopen", no_network)
    svc = _service(tmp_path, forwarder="default")
    assert svc.forwarder is None
    svc.start()
    svc.ingest([_net()])
    svc.record_posture(_posture())
    svc.close()


def test_service_forwards_findings_alerts_and_scores(tmp_path, monkeypatch):
    monkeypatch.setattr(settings, "desktop_notifications", True)
    recorder = RecordingForwarder()
    svc = _service(tmp_path, recorder)
    svc.start()
    svc.ingest([_net()])
    svc.record_posture(_posture())
    svc.close()

    kinds = [type(item).__name__ for item, _ in recorder.submitted]
    assert kinds == ["Finding", "Alert", "PostureReport"]
    finding_options = recorder.submitted[0][1]
    alert_options = recorder.submitted[1][1]
    assert finding_options["source_event"].remote_ip == "45.9.1.1"
    assert alert_options["finding"].rule_id == "NET-C2-PORT"
    assert alert_options["response_taken"] == "notified"
    assert recorder.started and recorder.stopped
    assert recorder.posture_provider() is svc.latest_posture


def test_service_reports_blocked_hosts(tmp_path, monkeypatch):
    monkeypatch.setattr(settings, "desktop_notifications", False)
    recorder = RecordingForwarder()
    svc = _service(tmp_path, recorder, auto_respond=True)
    svc.ingest([_net()])
    svc.close()
    alert_options = [o for item, o in recorder.submitted if isinstance(item, Alert)][0]
    assert alert_options["response_taken"] == "blocked_host"


def test_monitor_refuses_misconfigured_forwarding():
    from aegis.cli import main

    assert main(["monitor", "--forward-url", "http://sentinel.example.com",
                 "--forward-api-key", API_KEY]) == 2
