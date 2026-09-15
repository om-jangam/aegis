"""Local web dashboard and JSON API (``aegis serve``).

A browser works on every OS, over SSH port forwarding, and on headless servers
where the desktop console cannot run. The server is built for one trusted user:

* it binds to 127.0.0.1 unless told otherwise;
* every ``/api`` call needs a random bearer token. The printed link carries it in
  the URL *fragment*, which browsers never send to a server or write to its logs;
* the ``Host`` header must name the bound address, which defeats DNS-rebinding
  pages trying to reach the API through the user's browser;
* responses carry a strict Content-Security-Policy, and the page renders every
  value with ``textContent``, so data from the network cannot become markup.

Routing lives in :class:`DashboardApp`, separate from the socket server, so it
is tested without opening a port.
"""
from __future__ import annotations

import hmac
import json
import logging
import re
import socket
import threading
from collections.abc import Callable
from dataclasses import dataclass, field
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

from aegis import __version__
from aegis.core.models import AuditEvent, Severity
from aegis.detection.guidance import guidance_for
from aegis.platforms import CURRENT_OS

log = logging.getLogger(__name__)

STATIC_DIR = Path(__file__).resolve().parent / "static"
_STATIC_FILES = {
    "/": ("index.html", "text/html; charset=utf-8"),
    "/static/app.js": ("app.js", "text/javascript; charset=utf-8"),
    "/static/app.css": ("app.css", "text/css; charset=utf-8"),
}
SECURITY_HEADERS = {
    "Content-Security-Policy": ("default-src 'none'; script-src 'self'; style-src 'self'; "
                                "connect-src 'self'; img-src 'self' data:; base-uri 'none'; "
                                "form-action 'none'; frame-ancestors 'none'"),
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "no-referrer",
    "Cache-Control": "no-store",
}
MAX_BODY_BYTES = 64 * 1024
_ACK_PATH = re.compile(r"^/api/alerts/(\d{1,12})/ack$")


@dataclass
class Response:
    status: int
    body: bytes = b""
    content_type: str = "application/json"
    headers: dict[str, str] = field(default_factory=dict)


def _json(status: int, payload) -> Response:
    return Response(status, json.dumps(payload).encode("utf-8"))


def _limit(query: dict[str, list[str]], default: int) -> int:
    try:
        value = int(query.get("limit", [default])[0])
    except ValueError:
        return default
    return max(1, min(1000, value))


def allowed_hosts(host: str, port: int) -> set[str]:
    hosts = {f"127.0.0.1:{port}", f"localhost:{port}", f"[::1]:{port}"}
    if host not in ("127.0.0.1", "localhost", "::1", "0.0.0.0", "::"):
        hosts.add(f"[{host}]:{port}" if ":" in host else f"{host}:{port}")
    return hosts


class DashboardApp:
    def __init__(self, store, token: str, hosts: set[str], service=None,
                 posture: Callable | None = None):
        if len(token) < 16:
            raise ValueError("dashboard token is too short")
        self.store = store
        self.service = service
        self._token = token.encode("utf-8")
        self._hosts = hosts
        if posture is None:
            from aegis.posture import run_posture_checks
            posture = run_posture_checks
        self._posture = posture
        self._posture_cache: dict | None = None
        self._posture_lock = threading.Lock()

    # -- entry point -------------------------------------------------------- #
    def handle(self, method: str, target: str, headers: dict[str, str]) -> Response:
        if headers.get("host", "").lower() not in self._hosts:
            return _json(HTTPStatus.MISDIRECTED_REQUEST, {"error": "unexpected Host header"})
        parts = urlsplit(target)
        path, query = parts.path, parse_qs(parts.query)

        if method == "GET" and path in _STATIC_FILES:
            name, content_type = _STATIC_FILES[path]
            return Response(HTTPStatus.OK, (STATIC_DIR / name).read_bytes(), content_type)
        if not path.startswith("/api/"):
            return _json(HTTPStatus.NOT_FOUND, {"error": "not found"})
        if not self._authorised(headers):
            return _json(HTTPStatus.UNAUTHORIZED, {"error": "missing or invalid token"})

        try:
            return self._route(method, path, query)
        except Exception:  # noqa: BLE001 - never leak a traceback to the client
            log.exception("Dashboard request failed: %s %s", method, path)
            return _json(HTTPStatus.INTERNAL_SERVER_ERROR, {"error": "internal error"})

    def _authorised(self, headers: dict[str, str]) -> bool:
        scheme, _, supplied = headers.get("authorization", "").partition(" ")
        return scheme.lower() == "bearer" and hmac.compare_digest(
            supplied.strip().encode("utf-8"), self._token)

    # -- routes ------------------------------------------------------------- #
    def _route(self, method: str, path: str, query: dict[str, list[str]]) -> Response:
        if method == "GET":
            if path == "/api/summary":
                return _json(HTTPStatus.OK, self._summary())
            if path == "/api/alerts":
                open_only = query.get("open", ["0"])[0] == "1"
                alerts = self.store.recent_alerts(_limit(query, 100), unacknowledged_only=open_only)
                return _json(HTTPStatus.OK, [_alert_dict(a) for a in alerts])
            if path == "/api/findings":
                rows = self.store.recent_findings(_limit(query, 100))
                for row in rows:
                    row["guidance"] = guidance_for(row.get("technique") or "")
                return _json(HTTPStatus.OK, rows)
            if path == "/api/audit":
                return _json(HTTPStatus.OK,
                             [_audit_dict(a) for a in self.store.recent_audit(_limit(query, 100))])
            if path == "/api/posture":
                return _json(HTTPStatus.OK, self._posture_report(query.get("refresh") == ["1"]))
        elif method == "POST":
            if path == "/api/alerts/ack-all":
                self.store.acknowledge_all_alerts()
                self._audit("alerts_acknowledged", "All alerts acknowledged")
                return _json(HTTPStatus.OK, {"ok": True})
            match = _ACK_PATH.match(path)
            if match:
                alert_id = int(match.group(1))
                self.store.acknowledge_alert(alert_id)
                self._audit("alert_acknowledged", f"Alert {alert_id} acknowledged")
                return _json(HTTPStatus.OK, {"ok": True})
        return _json(HTTPStatus.NOT_FOUND, {"error": "not found"})

    def _summary(self) -> dict:
        return {
            "version": __version__,
            "platform": CURRENT_OS.value,
            "monitoring": bool(self.service is not None and self.service.running),
            "stats": self.store.stats(),
            "timeline": self.store.alerts_timeline(24),
        }

    def _posture_report(self, refresh: bool) -> dict:
        with self._posture_lock:
            if self._posture_cache is None or refresh:
                self._posture_cache = self._posture().to_dict()
            return self._posture_cache

    def _audit(self, action: str, message: str) -> None:
        self.store.add_audit(AuditEvent(category="SYSTEM", action=action, severity=Severity.INFO,
                                        message=message, actor="dashboard"))


def _alert_dict(alert) -> dict:
    return {
        "id": alert.id, "ts": alert.timestamp.isoformat(timespec="seconds"),
        "title": alert.title, "message": alert.message, "severity": alert.severity.value,
        "source": alert.source, "technique": alert.technique, "score": alert.score,
        "acknowledged": alert.acknowledged, "process_name": alert.process_name,
        "parent_name": alert.parent_name,
    }


def _audit_dict(event) -> dict:
    return {
        "ts": event.timestamp.isoformat(timespec="seconds"), "category": event.category,
        "action": event.action, "severity": event.severity.value, "message": event.message,
        "detail": event.detail, "actor": event.actor,
    }


# --------------------------------------------------------------------------- #
# HTTP server
# --------------------------------------------------------------------------- #
def _handler_for(app: DashboardApp) -> type[BaseHTTPRequestHandler]:
    class Handler(BaseHTTPRequestHandler):
        server_version = "Aegis"
        sys_version = ""

        def _dispatch(self, method: str) -> None:
            try:
                length = int(self.headers.get("Content-Length") or 0)
            except ValueError:
                length = -1
            if length < 0 or length > MAX_BODY_BYTES:
                response = _json(HTTPStatus.REQUEST_ENTITY_TOO_LARGE, {"error": "body too large"})
            else:
                if length:
                    self.rfile.read(length)  # no endpoint takes a body; drain it
                headers = {k.lower(): v for k, v in self.headers.items()}
                response = app.handle(method, self.path, headers)
            self.send_response(response.status)
            for name, value in {**SECURITY_HEADERS, **response.headers}.items():
                self.send_header(name, value)
            self.send_header("Content-Type", response.content_type)
            self.send_header("Content-Length", str(len(response.body)))
            self.end_headers()
            self.wfile.write(response.body)

        def do_GET(self) -> None:  # noqa: N802 - http.server naming
            self._dispatch("GET")

        def do_POST(self) -> None:  # noqa: N802
            self._dispatch("POST")

        def log_message(self, format: str, *args) -> None:  # noqa: A002
            log.debug("dashboard %s - " + format, self.address_string(), *args)

    return Handler


class _IPv4Server(ThreadingHTTPServer):
    address_family = socket.AF_INET
    daemon_threads = True


class _IPv6Server(ThreadingHTTPServer):
    address_family = socket.AF_INET6
    daemon_threads = True


def create_server(host: str, port: int, *, store, token: str,
                  service=None) -> ThreadingHTTPServer:
    """Bind the dashboard. Pass port 0 to pick a free port."""
    server_cls = _IPv6Server if ":" in host else _IPv4Server
    # Bind first so the Host allow-list can name the real port when port is 0.
    httpd = server_cls((host, port), BaseHTTPRequestHandler)
    app = DashboardApp(store, token, allowed_hosts(host, httpd.server_address[1]),
                       service=service)
    httpd.RequestHandlerClass = _handler_for(app)
    return httpd
