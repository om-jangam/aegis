"""SQLite implementation of the :class:`~aegis.storage.base.EventStore`.

A single connection is shared across the monitor threads and the UI thread
(``check_same_thread=False``) and guarded by a re-entrant lock; WAL mode keeps
readers and the writer from blocking each other. This is appropriate for a
single-host desktop tool with a handful of background threads.

Only this module knows SQL — callers depend on the :class:`EventStore`
interface, so the backend could later be swapped (e.g. OpenSearch) without
touching the rest of the app.
"""
from __future__ import annotations

import json
import sqlite3
import threading
from datetime import datetime, timedelta
from pathlib import Path

from aegis.config import DB_PATH
from aegis.core.events import Event, EventType, NetworkEvent, ProcessEvent
from aegis.core.models import Alert, AuditEvent, Finding, Severity
from aegis.storage.base import EventStore

_SCHEMA = """
CREATE TABLE IF NOT EXISTS events (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    ts           TEXT NOT NULL,
    type         TEXT NOT NULL,
    source       TEXT NOT NULL,
    pid          INTEGER,
    process_name TEXT,
    protocol     TEXT,
    local_ip     TEXT,
    local_port   INTEGER,
    remote_ip    TEXT,
    remote_port  INTEGER,
    status       TEXT,
    direction    TEXT,
    extra        TEXT
);
CREATE INDEX IF NOT EXISTS idx_events_ts ON events(ts);
CREATE INDEX IF NOT EXISTS idx_events_remote ON events(remote_ip);

CREATE TABLE IF NOT EXISTS findings (
    id             INTEGER PRIMARY KEY AUTOINCREMENT,
    ts             TEXT NOT NULL,
    rule_id        TEXT NOT NULL,
    title          TEXT,
    severity       TEXT NOT NULL,
    score          INTEGER DEFAULT 0,
    technique      TEXT,
    tactic         TEXT,
    entity         TEXT,
    reasons        TEXT,
    source_summary TEXT
);
CREATE INDEX IF NOT EXISTS idx_findings_ts ON findings(ts);

CREATE TABLE IF NOT EXISTS alerts (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    ts           TEXT NOT NULL,
    title        TEXT NOT NULL,
    message      TEXT,
    severity     TEXT NOT NULL,
    source       TEXT,
    technique    TEXT,
    score        INTEGER DEFAULT 0,
    acknowledged INTEGER DEFAULT 0,
    process_name TEXT,
    parent_name  TEXT
);
CREATE INDEX IF NOT EXISTS idx_alerts_ts ON alerts(ts);

CREATE TABLE IF NOT EXISTS audit (
    id       INTEGER PRIMARY KEY AUTOINCREMENT,
    ts       TEXT NOT NULL,
    category TEXT NOT NULL,
    action   TEXT NOT NULL,
    severity TEXT NOT NULL,
    message  TEXT,
    detail   TEXT,
    actor    TEXT
);
CREATE INDEX IF NOT EXISTS idx_audit_ts ON audit(ts);
CREATE INDEX IF NOT EXISTS idx_audit_cat ON audit(category);
"""

# Columns added after the first release. ``CREATE TABLE IF NOT EXISTS`` leaves an
# existing table untouched, so databases from older versions gain them here.
_ADDED_COLUMNS: dict[str, tuple[tuple[str, str], ...]] = {
    "alerts": (("process_name", "TEXT"), ("parent_name", "TEXT")),
}


class SQLiteEventStore(EventStore):
    """Thread-safe SQLite persistence for events, findings, alerts and audit."""

    def __init__(self, path: Path | str = DB_PATH):
        self._lock = threading.RLock()
        self._conn = sqlite3.connect(str(path), check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        self._conn.execute("PRAGMA journal_mode=WAL;")
        self._conn.execute("PRAGMA synchronous=NORMAL;")
        with self._lock:
            self._conn.executescript(_SCHEMA)
            self._migrate()
            self._conn.commit()

    def _migrate(self) -> None:
        for table, columns in _ADDED_COLUMNS.items():
            existing = {row[1] for row in self._conn.execute(f"PRAGMA table_info({table})")}
            for name, sql_type in columns:
                if name not in existing:
                    self._conn.execute(f"ALTER TABLE {table} ADD COLUMN {name} {sql_type}")

    # -- events ------------------------------------------------------------- #
    def save_events(self, events) -> None:
        rows = [self._event_row(e) for e in events]
        if not rows:
            return
        with self._lock:
            self._conn.executemany(
                "INSERT INTO events (ts, type, source, pid, process_name, protocol,"
                " local_ip, local_port, remote_ip, remote_port, status, direction, extra)"
                " VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)", rows,
            )
            self._conn.commit()

    @staticmethod
    def _event_row(e: Event) -> tuple:
        ts = e.timestamp.isoformat(timespec="seconds")
        if isinstance(e, NetworkEvent):
            return (ts, e.type.value, e.source.value, e.pid, e.process_name, e.protocol,
                    e.local_ip, e.local_port, e.remote_ip, e.remote_port, e.status,
                    e.direction.value, None)
        if isinstance(e, ProcessEvent):
            extra = json.dumps({"ppid": e.ppid, "exe": e.exe, "cmdline": e.cmdline,
                                "username": e.username})
            return (ts, e.type.value, e.source.value, e.pid, e.name, None,
                    None, None, None, None, None, None, extra)
        return (ts, e.type.value, e.source.value, None, None, None,
                None, None, None, None, None, None, None)

    def recent_network_events(self, limit: int = 300) -> list[dict]:
        with self._lock:
            rows = self._conn.execute(
                "SELECT * FROM events WHERE type IN (?,?) ORDER BY id DESC LIMIT ?",
                (EventType.NETWORK_CONNECTION.value, EventType.NETWORK_LISTEN.value, limit),
            ).fetchall()
        return [dict(r) for r in rows]

    # -- findings ----------------------------------------------------------- #
    def save_finding(self, finding: Finding) -> int:
        with self._lock:
            cur = self._conn.execute(
                "INSERT INTO findings (ts, rule_id, title, severity, score, technique,"
                " tactic, entity, reasons, source_summary) VALUES (?,?,?,?,?,?,?,?,?,?)",
                (finding.timestamp.isoformat(timespec="seconds"), finding.rule_id,
                 finding.title, finding.severity.value, finding.score, finding.technique,
                 finding.tactic, finding.entity, "; ".join(finding.reasons),
                 finding.source_summary),
            )
            self._conn.commit()
            return cur.lastrowid

    def recent_findings(self, limit: int = 200) -> list[dict]:
        with self._lock:
            rows = self._conn.execute(
                "SELECT * FROM findings ORDER BY id DESC LIMIT ?", (limit,)).fetchall()
        return [dict(r) for r in rows]

    # -- alerts ------------------------------------------------------------- #
    def save_alert(self, alert: Alert) -> int:
        with self._lock:
            cur = self._conn.execute(
                "INSERT INTO alerts (ts, title, message, severity, source, technique,"
                " score, acknowledged, process_name, parent_name)"
                " VALUES (?,?,?,?,?,?,?,?,?,?)",
                (alert.timestamp.isoformat(timespec="seconds"), alert.title, alert.message,
                 alert.severity.value, alert.source, alert.technique, alert.score,
                 int(alert.acknowledged), alert.process_name, alert.parent_name),
            )
            self._conn.commit()
            return cur.lastrowid

    def recent_alerts(self, limit: int = 100, unacknowledged_only: bool = False) -> list[Alert]:
        sql = "SELECT * FROM alerts"
        if unacknowledged_only:
            sql += " WHERE acknowledged = 0"
        sql += " ORDER BY id DESC LIMIT ?"
        with self._lock:
            rows = self._conn.execute(sql, (limit,)).fetchall()
        return [self._row_to_alert(r) for r in rows]

    def acknowledge_alert(self, alert_id: int) -> None:
        with self._lock:
            self._conn.execute("UPDATE alerts SET acknowledged=1 WHERE id=?", (alert_id,))
            self._conn.commit()

    def acknowledge_all_alerts(self) -> None:
        with self._lock:
            self._conn.execute("UPDATE alerts SET acknowledged=1")
            self._conn.commit()

    # -- audit -------------------------------------------------------------- #
    def add_audit(self, event: AuditEvent) -> int:
        with self._lock:
            cur = self._conn.execute(
                "INSERT INTO audit (ts, category, action, severity, message, detail, actor)"
                " VALUES (?,?,?,?,?,?,?)",
                (event.timestamp.isoformat(timespec="seconds"), event.category, event.action,
                 event.severity.value, event.message, event.detail, event.actor),
            )
            self._conn.commit()
            return cur.lastrowid

    def recent_audit(self, limit: int = 200, category: str | None = None) -> list[AuditEvent]:
        sql = "SELECT * FROM audit"
        params: list = []
        if category:
            sql += " WHERE category = ?"
            params.append(category)
        sql += " ORDER BY id DESC LIMIT ?"
        params.append(limit)
        with self._lock:
            rows = self._conn.execute(sql, params).fetchall()
        return [self._row_to_audit(r) for r in rows]

    # -- analytics (for the dashboard) -------------------------------------- #
    def stats(self) -> dict:
        with self._lock:
            c = self._conn
            total_events = c.execute("SELECT COUNT(*) FROM events").fetchone()[0]
            total_findings = c.execute("SELECT COUNT(*) FROM findings").fetchone()[0]
            total_alerts = c.execute("SELECT COUNT(*) FROM alerts").fetchone()[0]
            open_alerts = c.execute("SELECT COUNT(*) FROM alerts WHERE acknowledged=0").fetchone()[0]
            by_sev = dict(c.execute(
                "SELECT severity, COUNT(*) FROM alerts GROUP BY severity").fetchall())
            top_remote = c.execute(
                "SELECT remote_ip, COUNT(*) n FROM events"
                " WHERE remote_ip IS NOT NULL AND remote_ip NOT IN ('','127.0.0.1','::1')"
                " GROUP BY remote_ip ORDER BY n DESC LIMIT 8").fetchall()
            top_tech = c.execute(
                "SELECT technique, COUNT(*) n FROM findings WHERE technique != ''"
                " GROUP BY technique ORDER BY n DESC LIMIT 8").fetchall()
            top_processes = c.execute(
                "SELECT process_name, COUNT(*) n FROM events WHERE type = ?"
                " AND process_name IS NOT NULL AND process_name NOT IN ('', 'System')"
                " GROUP BY process_name ORDER BY n DESC LIMIT 8",
                (EventType.NETWORK_CONNECTION.value,)).fetchall()
            open_serious = c.execute(
                "SELECT COUNT(*) FROM alerts WHERE acknowledged=0"
                " AND severity IN ('HIGH', 'CRITICAL')").fetchone()[0]
        return {
            "total_events": total_events,
            "total_findings": total_findings,
            "total_alerts": total_alerts,
            "open_alerts": open_alerts,
            "open_serious_alerts": open_serious,
            "top_processes": [dict(r) for r in top_processes],
            "alerts_by_severity": by_sev,
            "top_remote_ips": [dict(r) for r in top_remote],
            "top_techniques": [dict(r) for r in top_tech],
        }

    def alerts_timeline(self, hours: int = 24) -> list[tuple[str, int]]:
        since = (datetime.now() - timedelta(hours=hours)).isoformat()
        with self._lock:
            rows = self._conn.execute(
                "SELECT substr(ts,1,13) hour, COUNT(*) FROM alerts WHERE ts >= ?"
                " GROUP BY hour ORDER BY hour", (since,)).fetchall()
        return [(r[0], r[1]) for r in rows]

    # -- maintenance -------------------------------------------------------- #
    def purge_old(self, days: int) -> int:
        """Purge high-volume telemetry (events + findings) older than ``days``.

        ``alerts`` and ``audit`` are intentionally **retained** — they are the
        low-volume security record and accountability trail, which a defender
        wants to keep. Returns the total number of rows deleted.
        """
        cutoff = (datetime.now() - timedelta(days=days)).isoformat()
        with self._lock:
            deleted = self._conn.execute("DELETE FROM events WHERE ts < ?", (cutoff,)).rowcount
            deleted += self._conn.execute("DELETE FROM findings WHERE ts < ?", (cutoff,)).rowcount
            self._conn.commit()
            return deleted

    def close(self) -> None:
        with self._lock:
            self._conn.close()

    # -- row mappers -------------------------------------------------------- #
    @staticmethod
    def _row_to_alert(r: sqlite3.Row) -> Alert:
        return Alert(
            id=r["id"], title=r["title"], message=r["message"] or "",
            severity=Severity(r["severity"]), source=r["source"] or "",
            technique=r["technique"] or "", score=r["score"],
            acknowledged=bool(r["acknowledged"]), timestamp=datetime.fromisoformat(r["ts"]),
            process_name=r["process_name"] or "", parent_name=r["parent_name"] or "")

    @staticmethod
    def _row_to_audit(r: sqlite3.Row) -> AuditEvent:
        return AuditEvent(
            id=r["id"], category=r["category"], action=r["action"],
            severity=Severity(r["severity"]), message=r["message"] or "",
            detail=r["detail"] or "", actor=r["actor"] or "aegis",
            timestamp=datetime.fromisoformat(r["ts"]))
