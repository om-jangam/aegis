"""Application service layer — the orchestrator.

Owns the subsystems and connects them into the pipeline:

    collectors → detection engine (+ ML assist) → store / alert / (optional) respond

It is the single façade the UI talks to. Collectors run on background daemon
threads; each poll is fully guarded so a failure logs and the loop continues —
a monitoring tool must never crash the host it protects.

Exporting to SENTINEL-X is an optional integration: when it is disabled (the
default) no exporter exists and nothing here changes behaviour.
"""
from __future__ import annotations

import logging
import threading
from datetime import datetime, timedelta

from aegis.alerting.notifier import Notifier
from aegis.collectors.auth import AuthCollector
from aegis.collectors.base import Collector
from aegis.collectors.filesystem import FileIntegrityCollector
from aegis.collectors.network import NetworkCollector
from aegis.collectors.processes import ProcessCollector
from aegis.config import DATA_DIR, settings
from aegis.core.events import Event, NetworkEvent, ProcessEvent
from aegis.core.models import Alert, AuditEvent, Finding, FirewallRule, Severity
from aegis.detection.engine import DetectionEngine
from aegis.detection.trust import is_trusted
from aegis.posture.watch import TACTIC, TECHNIQUE, regressions
from aegis.response.actions import ProcessStopper, Quarantine
from aegis.response.factory import get_firewall
from aegis.response.firewall import FirewallResponder
from aegis.storage.database import SQLiteEventStore

log = logging.getLogger(__name__)


def _attach_program(finding: Finding, event: Event) -> None:
    """Record which program (and its parent) a finding is about, when rules did not."""
    if isinstance(event, ProcessEvent):
        finding.process_name = finding.process_name or event.name
        finding.parent_name = finding.parent_name or event.parent_name
    elif isinstance(event, NetworkEvent):
        finding.process_name = finding.process_name or event.process_name


def _default_forwarder():
    """The configured SENTINEL-X exporter, or None when export is off or misconfigured."""
    if not settings.forwarding.enabled:
        return None
    from aegis.forwarding import build_forwarder

    try:
        return build_forwarder(settings.forwarding, DATA_DIR)
    except ValueError as exc:
        log.error("Export to SENTINEL-X is disabled: %s", exc)
        return None


class SecurityService:
    def __init__(self, store=None, engine=None, notifier=None, firewall=None,
                 collectors=None, ml="default", auto_respond=False, forwarder="default"):
        self.store = store or SQLiteEventStore()
        self.engine = engine or DetectionEngine()
        self.notifier = notifier or Notifier()
        self.firewall = firewall or get_firewall()
        self.responder = FirewallResponder(self.firewall)
        if ml == "default":
            from aegis.detection.ml_assist import MLAssist
            ml = MLAssist()
        self.ml = ml                      # MLAssist or None
        # An explicit empty list means "no collectors" (events are fed in by hand).
        self.collectors: list[Collector] = collectors if collectors is not None else [
            NetworkCollector(), ProcessCollector(), FileIntegrityCollector(),
            AuthCollector(state_path=DATA_DIR / "auth_state.json"),
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

        #: Containment actions on this computer, each confirmed by a person.
        self.stopper = ProcessStopper()
        self.quarantine = Quarantine(DATA_DIR / "quarantine")
        #: Latest security-check report (attached to exported heartbeats).
        self.latest_posture = None
        self._hardening = None
        #: Optional SENTINEL-X exporter; None unless export is enabled.
        self.forwarder = _default_forwarder() if forwarder == "default" else forwarder
        if self.forwarder is not None and getattr(self.forwarder, "posture_provider", None) is None:
            self.forwarder.posture_provider = lambda: self.latest_posture

    @property
    def hardening(self):
        """The hardening engine, sharing this service's store and audit trail."""
        if self._hardening is None:
            from aegis.hardening import HardeningEngine

            self._hardening = HardeningEngine(self.store)
        return self._hardening

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
        self._restore_firewall_rules()
        for col in self.collectors:
            if not col.available():
                log.warning("Collector '%s' unavailable; skipping.", col.name)
                continue
            col.start()
            t = threading.Thread(target=self._run_collector, args=(col,),
                                 name=f"collector-{col.name}", daemon=True)
            t.start()
            self._threads.append(t)
        if self.forwarder is not None:
            self.forwarder.start()
        self._start_security_recheck()
        self.audit("SYSTEM", "monitoring_started", Severity.INFO, "Live monitoring started.")
        log.info("SecurityService started with %d collectors.", len(self._threads))

    def _restore_firewall_rules(self) -> None:
        """Re-apply saved block rules on backends that lose them at reboot (nftables)."""
        sync = getattr(self.firewall, "sync", None)
        if sync is None:
            return
        from aegis.platforms import is_elevated

        if not is_elevated():
            return
        try:
            restored = sync()
        except Exception:  # noqa: BLE001 - restoring rules must not stop monitoring
            log.exception("Restoring saved firewall rules failed")
            return
        if restored:
            self.audit("RULE", "rules_restored", Severity.INFO,
                       f"Re-applied {restored} saved firewall rule(s).")

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
        if self.forwarder is not None:
            try:
                self.forwarder.stop()
            except Exception:  # noqa: BLE001 - shutdown must still close the store
                log.exception("Stopping the SENTINEL-X exporter failed")
        self.store.close()

    @property
    def running(self) -> bool:
        return self._running

    def _interval_for(self, collector: Collector) -> float:
        if collector.name == "processes":
            return max(1.0, settings.process_poll_interval)
        if collector.name == "auth":
            # Reading the Security log shells out to PowerShell; polling it as
            # often as the socket table would cost more than it is worth.
            return max(10.0, settings.auth_poll_interval)
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
                _attach_program(finding, event)
                self._handle_finding(finding, event)
            all_findings.extend(findings)

        with self._lock:
            self._poll_count += 1
            if self.ml is not None and self._poll_count % 15 == 0:
                self.ml.maybe_train()
        return all_findings

    def _handle_finding(self, finding: Finding, event: Event | None = None) -> None:
        self.store.save_finding(finding)
        for fn in list(self._finding_listeners):   # snapshot: listeners may be added concurrently
            _safe_call(fn, finding)
        self._export(finding, source_event=event)

        threshold = settings.threat_score_alert_threshold
        if (finding.score >= threshold or finding.severity >= Severity.HIGH) \
                and not is_trusted(finding.process_name, finding.parent_name,
                                   settings.trusted_programs) \
                and self._first_alert_in_window(finding):
            self._raise_alert(finding, event)

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

    def _raise_alert(self, finding: Finding, event: Event | None = None) -> None:
        alert = Alert(
            title=finding.title,
            message=f"{finding.source_summary}\n{'; '.join(finding.reasons)}",
            severity=finding.severity,
            source=finding.entity,
            technique=finding.attack_ref,
            score=finding.score,
            process_name=finding.process_name,
            parent_name=finding.parent_name,
        )
        alert.id = self.store.save_alert(alert)
        self.audit("DETECTION", "alert_raised", finding.severity,
                   finding.title, f"{finding.attack_ref} · {finding.entity}")
        notified = self.notifier.notify(alert, dedup_key=finding.entity or finding.rule_id)
        response = "notified" if notified else "none"

        if self.auto_respond and self.responder.can_handle(finding):
            result = self.responder.respond(finding)
            self.audit("RESPONSE", "auto_block", Severity.MEDIUM,
                       f"Auto-block {finding.entity}", result.message)
            if result.ok:
                response = "blocked_host"

        for fn in list(self._alert_listeners):   # snapshot copy (thread-safe iteration)
            _safe_call(fn, alert)
        self._export(alert, source_event=event, finding=finding, response_taken=response)

    # -- security check ----------------------------------------------------- #
    def record_posture(self, report) -> None:
        """Remember the latest security-check result, and alert on anything that got worse."""
        previous, self.latest_posture = self.latest_posture, report
        for regression in regressions(previous, report):
            self._handle_finding(self._setting_changed(regression))
        self._export(report)

    @staticmethod
    def _setting_changed(regression) -> Finding:
        """A security setting that was healthy and no longer is, as a finding."""
        return Finding(
            rule_id="POSTURE-CHANGED",
            title=regression.headline,
            severity=regression.severity,
            score=80 if regression.severity >= Severity.HIGH else 55,
            technique=TECHNIQUE,
            tactic=TACTIC,
            description=("A security setting on this computer is weaker than it was at the "
                         "last check. Malware turns protections off, and so do people who "
                         "forget to turn them back on."),
            reasons=regression.reasons(),
            entity=f"setting:{regression.check_id}",
            source_summary=regression.result.summary)

    def _start_security_recheck(self) -> None:
        """Re-run the security check on a timer so switched-off protections surface."""
        minutes = settings.security_recheck_minutes
        if minutes <= 0:
            return

        def loop() -> None:
            while not self._stop.wait(max(60.0, minutes * 60)):
                try:
                    from aegis.posture import run_posture_checks

                    self.record_posture(run_posture_checks())
                except Exception:  # noqa: BLE001 - a failed check must not stop monitoring
                    log.exception("Scheduled security check failed")

        thread = threading.Thread(target=loop, name="security-recheck", daemon=True)
        thread.start()
        self._threads.append(thread)

    # -- optional export ---------------------------------------------------- #
    def _export(self, item, **options) -> None:
        if self.forwarder is None:
            return
        try:
            self.forwarder.submit(item, **options)
        except Exception:  # noqa: BLE001 - export must never break detection
            log.exception("Export of %s failed", type(item).__name__)

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

    def stop_process(self, pid: int, name: str = "", *, confirmed: bool = False,
                     reason: str = "manual"):
        """Stop a running program (after confirmation), and record the attempt."""
        result = self.stopper.stop(pid, name, confirmed=confirmed, reason=reason)
        self.audit("RESPONSE", "process_stopped" if result.ok else "process_stop_refused",
                   Severity.MEDIUM if result.ok else Severity.INFO,
                   f"Stop {name or 'process'} (pid {pid})", result.message)
        return result

    def quarantine_file(self, path, *, confirmed: bool = False, reason: str = "manual"):
        """Move a file out of reach (after confirmation), keeping it restorable."""
        result = self.quarantine.add(path, confirmed=confirmed, reason=reason)
        self.audit("RESPONSE", "file_quarantined" if result.ok else "quarantine_refused",
                   Severity.MEDIUM if result.ok else Severity.INFO,
                   f"Quarantine {path}", result.message)
        return result

    def restore_quarantined(self, record_id: str, *, confirmed: bool = False):
        """Put a quarantined file back where it was."""
        result = self.quarantine.restore(record_id, confirmed=confirmed)
        self.audit("RESPONSE", "file_restored" if result.ok else "restore_refused",
                   Severity.INFO, f"Restore quarantined file {record_id}", result.message)
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
