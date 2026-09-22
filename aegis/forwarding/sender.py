"""HTTPS delivery of event batches to SENTINEL-X, using only the standard library.

``urllib`` plus ``ssl`` covers everything forwarding needs (POST, headers, TLS
verification, timeouts), so no third-party HTTP client is added to a security
tool's dependency tree.

Safety properties:

* HTTPS is required; plain HTTP is accepted only for a loopback server
  (local testing).
* Redirects are never followed, so the bearer token cannot be re-sent to a
  different host.
* The API key is kept out of ``repr`` and log messages.
"""
from __future__ import annotations

import ipaddress
import json
import random
import ssl
import urllib.error
import urllib.request
from collections.abc import Callable
from dataclasses import dataclass, field
from urllib.parse import urlsplit

from aegis import __version__

DEFAULT_INGEST_PATH = "/api/v1/ingest/events"

#: (url, body, headers, timeout_seconds, verify_tls) -> HTTP status code.
#: Raises OSError (or a subclass) when the server cannot be reached at all.
Transport = Callable[[str, bytes, dict[str, str], float, bool], int]


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):  # noqa: D401, ANN001
        return None


def https_transport(url: str, body: bytes, headers: dict[str, str], timeout: float,
                    verify_tls: bool) -> int:
    context = ssl.create_default_context()
    if not verify_tls:
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
    opener = urllib.request.build_opener(_NoRedirect(),
                                         urllib.request.HTTPSHandler(context=context))
    request = urllib.request.Request(url, data=body, headers=headers, method="POST")
    try:
        with opener.open(request, timeout=timeout) as response:  # noqa: S310 - scheme validated
            return response.status
    except urllib.error.HTTPError as exc:
        return exc.code


def _is_loopback(host: str) -> bool:
    if host.lower() == "localhost":
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


def validate_server_url(url: str) -> str:
    """Return the server base URL without a trailing slash, or raise ValueError."""
    parts = urlsplit((url or "").strip())
    if not parts.scheme or not parts.hostname:
        raise ValueError("forwarding.server_url must be a full URL, e.g. https://sentinel.example.com")
    if parts.username or parts.password:
        raise ValueError("forwarding.server_url must not contain credentials; use forwarding.api_key")
    if parts.scheme == "http" and not _is_loopback(parts.hostname):
        raise ValueError("forwarding.server_url must use https:// (http:// is allowed only for localhost)")
    if parts.scheme not in ("https", "http"):
        raise ValueError("forwarding.server_url must use https://")
    return f"{parts.scheme}://{parts.netloc}{parts.path}".rstrip("/")


@dataclass
class Backoff:
    """Exponential backoff with jitter: about 1s, 2s, 4s... capped at ``maximum``."""

    base: float = 1.0
    factor: float = 2.0
    maximum: float = 300.0
    jitter: float = 0.2
    rng: Callable[[], float] = field(default=random.random, repr=False)
    attempts: int = 0

    def next_delay(self) -> float:
        delay = min(self.maximum, self.base * self.factor ** self.attempts)
        self.attempts += 1
        spread = delay * self.jitter
        return max(0.0, delay - spread + 2 * spread * self.rng())

    def reset(self) -> None:
        self.attempts = 0


@dataclass(frozen=True)
class SendResult:
    ok: bool
    status: int | None = None
    error: str = ""


class Sender:
    def __init__(self, server_url: str, api_key: str, *,
                 ingest_path: str = DEFAULT_INGEST_PATH, verify_tls: bool = True,
                 timeout: float = 15.0, transport: Transport = https_transport):
        if not api_key:
            raise ValueError("forwarding.api_key is required (or set AEGIS_FORWARDING_API_KEY)")
        self.url = f"{validate_server_url(server_url)}/{(ingest_path or DEFAULT_INGEST_PATH).lstrip('/')}"
        self.verify_tls = verify_tls
        self.timeout = timeout
        self._transport = transport
        self._headers = {
            "Authorization": f"Bearer {api_key}",
            "Content-Type": "application/json",
            "User-Agent": f"Aegis/{__version__}",
        }

    def send(self, events: list[dict]) -> SendResult:
        body = json.dumps({"events": events}, separators=(",", ":"), ensure_ascii=False).encode()
        try:
            status = self._transport(self.url, body, dict(self._headers), self.timeout,
                                     self.verify_tls)
        except (OSError, ValueError) as exc:
            return SendResult(False, None, type(exc).__name__)
        return SendResult(200 <= status < 300, status)

    def __repr__(self) -> str:
        return f"Sender(url={self.url!r}, verify_tls={self.verify_tls}, api_key=***)"
