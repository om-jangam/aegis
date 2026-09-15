"""Application service layer — the orchestrator.

Owns the subsystems and connects them into the pipeline:

    collectors → detection engine (+ ML assist) → store / alert / (optional) respond

It is the single façade the UI talks to. Collectors run on background daemon
threads; each poll is fully guarded so a failure logs and the loop continues —
a monitoring tool must never crash the host it protects.
"""
from __future__ import annotations

import logging
import threading
from datetime import datetime, timedelta

from aegis.alerting.notifier import Notifier
from aegis.collectors.base import Collector
from aegis.collectors.filesystem import FileIntegrityCollector
from aegis.collectors.network import NetworkCollector
from aegis.collectors.processes import ProcessCollector
from aegis.config import settings
from aegis.core.events import Event
from aegis.core.models import Alert, AuditEvent, Finding, FirewallRule, Severity
from aegis.detection.engine import DetectionEngine
from aegis.response.factory import get_firewall
from aegis.response.firewall import FirewallResponder
from aegis.storage.database import SQLiteEventStore

log = logging.getLogger(__name__)


def severity_for(score: int) -> Severity:
    if score >= 90:
        return Severity.CRITICAL
    if score >= 70:
        return Severity.HIGH
    if score >= 40:
        return Severity.MEDIUM
    if score >= 20:
        return Severity.LOW
    return Severity.INFO


class SecurityService:
    def __init__(self, store=None, engine=None, notifier=None, firewall=None,
                 collectors=None, ml="default", auto_respond=False):
        self.store = store or SQLiteEventStore()
        self.engine = engine or DetectionEngine()
        self.notifier = notifier or Notifier()
        self.firewall = firewall or get_firewall()
        self.responder = FirewallResponder(self.firewall)
        if ml == "default":
            from aegis.detection.ml_assist import MLAssist
            ml = MLAssist()
        self.ml = ml                      # MLAssist or None
        self.collectors: list[Collector] = collectors or [
            NetworkCollector(), ProcessCollector(), FileIntegrityCollector(),
        ]
        self.auto_respond = auto_respond

        self._threads: list[threading.Thread] = []
        self._stop = threading.Event()
        self._running = False
        self._poll_count = 0
        self._lock = threading.Lock()
        self._finding_listeners = []
        self._alert_listeners = []
        self._alerted: dict[tuple[str, str], datetime] = {}

    # -- listeners (UI subscribes) ----------------------------------------- #
    def on_finding(self, fn) -> None:
        self._finding_listeners.append(fn)

    def on_alert(self, fn) -> None:
        self._alert_listeners.append(fn)

    # -- lifecycle ---------------------------------------------------------- #
    def start(self) -> None:
        if self._running:
            return
        self._running = True
        self._stop.clear()
        # Enforce data retention on startup so the local store can't grow forever.
        try:
            removed = self.purge_old()
            if removed:
                log.info("Retention purge removed %d old rows.", removed)
        except Exception:  # noqa: BLE001
            log.exception("Retention purge failed")
        for col in self.collectors:
            if not col.available():
                log.warning("Collector '%s' unavailable; skipping.", col.name)
                continue
            col.start()
            t = threading.Thread(target=self._run_collector, args=(col,),
                                 name=f"collector-{col.name}", daemon=True)
            t.start()
            self._threads.append(t)
        self.audit("SYSTEM", "monitoring_started", Severity.INFO, "Live monitoring started.")
        log.info("SecurityService started with %d collectors.", len(self._threads))

    def stop(self) -> None:
        self._running = False
        self._stop.set()
        for col in self.collectors:
            col.stop()
        # Join collector threads so no poll is mid-flight when we persist the
        # model, and so restarts don't accumulate dead Thread objects.
        for t in self._threads:
            t.join(timeout=5)
        self._threads.clear()
        if self.ml is not None:
            self.ml.save()
        self.audit("SYSTEM", "monitoring_stopped", Severity.INFO, "Live monitoring stopped.")

    def close(self) -> None:
        """Release resources on application shutdown (not on pause)."""
        if self._running:
            self.stop()
        self.store.close()

    @property
    def running(self) -> bool:
        return self._running

    def _interval_for(self, collector: Collector) -> float:
        if collector.name == "processes":
            return max(1.0, settings.process_poll_interval)
        if collector.name == "filesystem":
            # Walking and hashing a tree is orders of magnitude heavier than
            # reading the socket table, so FIM runs on its own slow interval.
            return max(10.0, settings.fim_poll_interval)
        return max(0.5, settings.network_poll_interval)

    def _run_collector(self, collector: Collector) -> None:
        interval = self._interval_for(collector)
        while not self._stop.is_set():
            try:
                events = list(collector.poll())
                if events:
                    self.ingest(events)
            except Exception:  # noqa: BLE001 - never let a monitor crash the app
                log.exception("Collector '%s' poll failed", collector.name)
            self._stop.wait(interval)

    # -- the pipeline ------------------------------------------------------- #
    def ingest(self, events: list[Event]) -> list[Finding]:
        """Persist events, run detection (+ML), raise alerts. Returns findings."""
        self.store.save_events(events)
        all_findings: list[Finding] = []
        for event in events:
            findings = self.engine.process(event)
            if self.ml is not None:
                self.ml.observe(event)
                ml_finding = self.ml.score(event)
                if ml_finding:
                    findings.append(ml_finding)
            for finding in findings:
                self._handle_finding(finding)
            all_findings.extend(findings)

        with self._lock:
            self._poll_count += 1
            if self.ml is not None and self._poll_count % 15 == 0:
                self.ml.maybe_train()
        return all_findings

    def _handle_finding(self, finding: Finding) -> None:
        self.store.save_finding(finding)
        for fn in list(self._finding_listeners):   # snapshot: listeners may be added concurrently
            _safe_call(fn, finding)

        threshold = settings.threat_score_alert_threshold
        if (finding.score >= threshold or finding.severity >= Severity.HIGH) \
                and self._first_alert_in_window(finding):
            self._raise_alert(finding)

    def _first_alert_in_window(self, finding: Finding) -> bool:
        """One alert per rule and subject per dedup window; repeats stay as findings."""
        window = timedelta(minutes=max(0, settings.alert_dedup_minutes))
        key = (finding.rule_id, finding.entity)
        with self._lock:
            last = self._alerted.get(key)
            if last is not None and finding.timestamp - last < window:
                return False
            self._alerted[key] = finding.timestamp
            if len(self._alerted) > 5000:
                self._alerted = {k: t for k, t in self._alerted.items()
                                 if finding.timestamp - t < window}
        return True

    def _raise_alert(self, finding: Finding) -> None:
        alert = Alert(
            title=finding.title,
            message=f"{finding.source_summary}\n{'; '.join(finding.reasons)}",
            severity=finding.severity,
            source=finding.entity,
            technique=finding.attack_ref,
            score=finding.score,
        )
        alert.id = self.store.save_alert(alert)
        self.audit("DETECTION", "alert_raised", finding.severity,
                   finding.title, f"{finding.attack_ref} · {finding.entity}")
        self.notifier.notify(alert, dedup_key=finding.entity or finding.rule_id)

        if self.auto_respond and self.responder.can_handle(finding):
            result = self.responder.respond(finding)
            self.audit("RESPONSE", "auto_block", Severity.MEDIUM,
                       f"Auto-block {finding.entity}", result.message)

        for fn in list(self._alert_listeners):   # snapshot copy (thread-safe iteration)
            _safe_call(fn, alert)

    # -- firewall passthrough (audited) ------------------------------------ #
    def create_rule(self, rule: FirewallRule):
        result = self.firewall.create_rule(rule)
        self.audit("RULE", "rule_created" if result.ok else "rule_create_failed",
                   Severity.INFO if result.ok else Severity.LOW,
                   f"Create rule '{rule.name}'", result.message)
        return result

    def delete_rule(self, name: str):
        result = self.firewall.delete_rule(name)
        self.audit("RULE", "rule_deleted", Severity.INFO, f"Delete rule '{name}'", result.message)
        return result

    def set_rule_enabled(self, name: str, enabled: bool):
        result = self.firewall.set_rule_enabled(name, enabled)
        self.audit("RULE", "rule_toggled", Severity.INFO,
                   f"{'Enable' if enabled else 'Disable'} '{name}'", result.message)
        return result

    def block_ip(self, ip: str, note: str = "manual"):
        result = self.firewall.block_ip(ip, note=note)
        self.audit("RESPONSE", "ip_blocked", Severity.MEDIUM, f"Block {ip}", result.message)
        return result

    # -- audit -------------------------------------------------------------- #
    def audit(self, category: str, action: str, severity: Severity,
              message: str, detail: str = "") -> None:
        self.store.add_audit(AuditEvent(category=category, action=action,
                                        severity=severity, message=message, detail=detail))

    def purge_old(self) -> int:
        return self.store.purge_old(settings.event_retention_days)


def _safe_call(fn, arg) -> None:
    try:
        fn(arg)
    except Exception:  # noqa: BLE001
        log.exception("listener failed")
