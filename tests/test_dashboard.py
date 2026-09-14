"""Web dashboard: routing, authentication, Host checks and a real HTTP round trip."""
import json
import threading
import urllib.error
import urllib.request

import pytest

from aegis.api.server import DashboardApp, allowed_hosts, create_server
from aegis.core.models import Alert, Finding, Severity
from aegis.posture.base import CheckResult, CheckStatus, PostureReport
from aegis.storage.database import SQLiteEventStore

TOKEN = "t" * 40
HOSTS = allowed_hosts("127.0.0.1", 8765)
OK_HOST = {"host": "127.0.0.1:8765"}
AUTH = {**OK_HOST, "authorization": f"Bearer {TOKEN}"}


@pytest.fixture
def store(tmp_path):
    s = SQLiteEventStore(tmp_path / "dash.db")
    yield s
    s.close()


@pytest.fixture
def posture_calls():
    return []


@pytest.fixture
def app(store, posture_calls):
    def posture():
        posture_calls.append(1)
        return PostureReport([CheckResult("P", "Firewall", "Network", CheckStatus.FAIL,
                                          Severity.HIGH, "off", remediation="turn it on")])
    return DashboardApp(store, TOKEN, HOSTS, posture=posture)


def body(response):
    return json.loads(response.body)


def test_page_is_served_without_a_token(app):
    response = app.handle("GET", "/", OK_HOST)
    assert response.status == 200
    assert response.content_type.startswith("text/html")
    assert b"/static/app.js" in response.body


def test_wrong_host_header_is_rejected_to_stop_dns_rebinding(app):
    assert app.handle("GET", "/", {"host": "evil.example:8765"}).status == 421
    assert app.handle("GET", "/api/summary",
                      {**AUTH, "host": "attacker.test"}).status == 421


@pytest.mark.parametrize("headers", [
    OK_HOST,
    {**OK_HOST, "authorization": "Bearer wrong"},
    {**OK_HOST, "authorization": TOKEN},
    {**OK_HOST, "authorization": f"Basic {TOKEN}"},
])
def test_api_requires_the_bearer_token(app, headers):
    assert app.handle("GET", "/api/summary", headers).status == 401


def test_summary(app):
    response = app.handle("GET", "/api/summary", AUTH)
    assert response.status == 200
    data = body(response)
    assert data["monitoring"] is False
    assert data["stats"]["total_alerts"] == 0


def test_alerts_and_acknowledge_is_audited(app, store):
    alert_id = store.save_alert(Alert(title="C2", message="m", severity=Severity.HIGH,
                                      source="45.9.1.1:4444"))
    alerts = body(app.handle("GET", "/api/alerts?open=1", AUTH))
    assert [a["id"] for a in alerts] == [alert_id]

    assert app.handle("POST", f"/api/alerts/{alert_id}/ack", AUTH).status == 200
    assert body(app.handle("GET", "/api/alerts?open=1", AUTH)) == []
    audit = store.recent_audit()
    assert audit[0].actor == "dashboard" and audit[0].action == "alert_acknowledged"


def test_acknowledge_all(app, store):
    store.save_alert(Alert(title="a", message=""))
    store.save_alert(Alert(title="b", message=""))
    assert app.handle("POST", "/api/alerts/ack-all", AUTH).status == 200
    assert store.stats()["open_alerts"] == 0


def test_findings_carry_plain_language_guidance(app, store):
    store.save_finding(Finding(rule_id="R", title="PowerShell download", severity=Severity.HIGH,
                               technique="T1059.001"))
    findings = body(app.handle("GET", "/api/findings", AUTH))
    assert "command interpreter" in findings[0]["guidance"]


def test_posture_is_cached_until_refresh(app, posture_calls):
    first = body(app.handle("GET", "/api/posture", AUTH))
    app.handle("GET", "/api/posture", AUTH)
    assert len(posture_calls) == 1
    app.handle("GET", "/api/posture?refresh=1", AUTH)
    assert len(posture_calls) == 2
    assert first["results"][0]["remediation"] == "turn it on"


@pytest.mark.parametrize(("method", "path"), [
    ("GET", "/api/nope"),
    ("GET", "/api/alerts/1/ack"),
    ("POST", "/api/summary"),
    ("GET", "/static/../server.py"),
    ("GET", "/static/server.py"),
])
def test_unknown_routes_are_404(app, method, path):
    assert app.handle(method, path, AUTH).status == 404


def test_limit_is_clamped(app, store):
    for i in range(3):
        store.save_alert(Alert(title=str(i), message=""))
    assert len(body(app.handle("GET", "/api/alerts?limit=2", AUTH))) == 2
    assert len(body(app.handle("GET", "/api/alerts?limit=-5", AUTH))) == 1
    assert len(body(app.handle("GET", "/api/alerts?limit=abc", AUTH))) == 3


def test_internal_errors_do_not_leak_details(store):
    def broken():
        raise RuntimeError("secret stack detail")
    app = DashboardApp(store, TOKEN, HOSTS, posture=broken)
    response = app.handle("GET", "/api/posture", AUTH)
    assert response.status == 500
    assert b"secret" not in response.body


def test_short_tokens_are_refused(store):
    with pytest.raises(ValueError):
        DashboardApp(store, "short", HOSTS)


def test_allowed_hosts_adds_a_specific_bind_address():
    assert "192.168.1.5:9000" in allowed_hosts("192.168.1.5", 9000)
    assert "0.0.0.0:9000" not in allowed_hosts("0.0.0.0", 9000)


def test_real_http_round_trip_sets_security_headers(store):
    httpd = create_server("127.0.0.1", 0, store=store, token=TOKEN)
    port = httpd.server_address[1]
    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()
    try:
        request = urllib.request.Request(f"http://127.0.0.1:{port}/api/summary",
                                         headers={"Authorization": f"Bearer {TOKEN}"})
        with urllib.request.urlopen(request, timeout=5) as response:
            assert response.status == 200
            assert "default-src 'none'" in response.headers["Content-Security-Policy"]
            assert response.headers["X-Frame-Options"] == "DENY"
            assert json.loads(response.read())["version"]

        with pytest.raises(urllib.error.HTTPError) as denied:
            urllib.request.urlopen(f"http://127.0.0.1:{port}/api/summary", timeout=5)
        assert denied.value.code == 401

        with urllib.request.urlopen(f"http://127.0.0.1:{port}/static/app.js", timeout=5) as js:
            assert b"textContent" in js.read()
    finally:
        httpd.shutdown()
        httpd.server_close()
