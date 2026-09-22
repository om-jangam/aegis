"""Durable local queue for events waiting to reach SENTINEL-X.

Events are written to SQLite before any network attempt, so a server outage or
an Aegis restart loses nothing. Rows are removed only after the server confirms
receipt. A row cap keeps a long outage from filling the disk; when it is hit,
the oldest events are dropped first and the drop is logged and counted.
"""
from __future__ import annotations

import json
import logging
import sqlite3
import threading
from datetime import UTC, datetime
from pathlib import Path

log = logging.getLogger(__name__)

DEFAULT_MAX_ROWS = 100_000


class EventQueue:
    def __init__(self, path: Path | str, max_rows: int = DEFAULT_MAX_ROWS):
        self._max_rows = max(1, max_rows)
        self._lock = threading.Lock()
        self._conn = sqlite3.connect(str(path), check_same_thread=False)
        self._conn.execute("PRAGMA journal_mode=WAL;")
        self._conn.execute("PRAGMA synchronous=NORMAL;")
        with self._lock:
            self._conn.execute(
                "CREATE TABLE IF NOT EXISTS outbox ("
                " id INTEGER PRIMARY KEY AUTOINCREMENT,"
                " enqueued_at TEXT NOT NULL,"
                " payload TEXT NOT NULL)")
            self._conn.commit()
        #: Events discarded because the queue was full.
        self.dropped = 0

    def put(self, event: dict) -> None:
        payload = json.dumps(event, separators=(",", ":"), ensure_ascii=False)
        with self._lock:
            self._conn.execute("INSERT INTO outbox (enqueued_at, payload) VALUES (?, ?)",
                               (datetime.now(tz=UTC).isoformat(timespec="seconds"), payload))
            excess = self._count() - self._max_rows
            if excess > 0:
                self._conn.execute(
                    "DELETE FROM outbox WHERE id IN (SELECT id FROM outbox ORDER BY id LIMIT ?)",
                    (excess,))
                self.dropped += excess
                log.warning("Forwarding queue full; dropped %d oldest event(s).", excess)
            self._conn.commit()

    def peek(self, limit: int) -> list[tuple[int, dict]]:
        """The oldest ``limit`` events, without removing them."""
        with self._lock:
            rows = self._conn.execute(
                "SELECT id, payload FROM outbox ORDER BY id LIMIT ?", (max(1, limit),)).fetchall()
        return [(row_id, json.loads(payload)) for row_id, payload in rows]

    def delete(self, ids: list[int]) -> None:
        if not ids:
            return
        with self._lock:
            self._conn.executemany("DELETE FROM outbox WHERE id = ?", [(i,) for i in ids])
            self._conn.commit()

    def _count(self) -> int:
        return self._conn.execute("SELECT COUNT(*) FROM outbox").fetchone()[0]

    def __len__(self) -> int:
        with self._lock:
            return self._count()

    def close(self) -> None:
        with self._lock:
            self._conn.close()
