"""Forwarding of Aegis events to a SENTINEL-X server (off by default).

Contract: ``shared/event_schema.json``. When forwarding is disabled,
:func:`build_forwarder` returns None and no forwarding code touches the network.
"""
from __future__ import annotations

import os
from collections.abc import Callable
from pathlib import Path

from aegis.forwarding.agent import AgentInfo, current_agent, load_or_create_agent_id
from aegis.forwarding.forwarder import HEARTBEAT_SECONDS, Forwarder
from aegis.forwarding.queue import EventQueue
from aegis.forwarding.schema import Heartbeat, redact, to_shared_event
from aegis.forwarding.sender import (
    DEFAULT_INGEST_PATH,
    Backoff,
    Sender,
    Transport,
    https_transport,
    validate_server_url,
)
from aegis.posture.base import PostureReport

API_KEY_ENV = "AEGIS_FORWARDING_API_KEY"
QUEUE_FILE = "forward_queue.db"


def build_forwarder(config, data_dir: Path | str, *, api_key: str | None = None,
                    posture_provider: Callable[[], PostureReport | None] | None = None,
                    transport: Transport = https_transport) -> Forwarder | None:
    """A ready (not yet started) forwarder, or None when forwarding is disabled.

    The API key comes from, in order: ``api_key`` (a CLI flag), the
    ``AEGIS_FORWARDING_API_KEY`` environment variable, then the config file.
    Raises ValueError for an unusable configuration.
    """
    if not config.enabled:
        return None
    key = api_key or os.environ.get(API_KEY_ENV) or config.api_key
    sender = Sender(config.server_url, key, ingest_path=config.ingest_path,
                    verify_tls=config.verify_tls, transport=transport)
    data_dir = Path(data_dir)
    return Forwarder(
        sender,
        EventQueue(data_dir / QUEUE_FILE),
        current_agent(data_dir),
        batch_size=min(1000, max(1, int(config.batch_size))),
        flush_interval=max(1.0, float(config.flush_interval_seconds)),
        posture_provider=posture_provider,
    )


__all__ = [
    "API_KEY_ENV", "AgentInfo", "Backoff", "DEFAULT_INGEST_PATH", "EventQueue", "Forwarder",
    "HEARTBEAT_SECONDS", "Heartbeat", "QUEUE_FILE", "Sender", "Transport", "build_forwarder",
    "current_agent", "https_transport", "load_or_create_agent_id", "redact", "to_shared_event",
    "validate_server_url",
]
