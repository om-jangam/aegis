"""Sign-in monitoring: reading the OS records, the detections, and settings that get worse."""
import json
from datetime import datetime, timedelta

import pytest

from aegis.alerting.notifier import Notifier
from aegis.collectors.auth import (
    AuthCollector,
    parse_linux_line,
    parse_windows_event,
)
from aegis.core.accounts import is_admin_group
from aegis.core.events import AuthEvent, EventSource, EventType
from aegis.core.models import Severity
from aegis.detection.base import DetectionContext
from aegis.detection.engine import DetectionEngine
from aegis.detection.rules.auth_rules import AUTH_RULES
from aegis.posture.base import CheckResult, CheckStatus, PostureReport
from aegis.posture.watch import regressions
from aegis.response.command import RunResult
from aegis.response.firewall import FirewallManager
from aegis.service import SecurityService
from aegis.storage.database import SQLiteEventStore

NOW = datetime(2026, 9, 23, 21, 30, 0)

WINDOWS_FAILURE = """
<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'>
 <System><EventID>4625</EventID><EventRecordID>9001</EventRecordID>
  <TimeCreated SystemTime='2026-09-23T18:00:00.000000000Z'/></System>
 <EventData>
  <Data Name='TargetUserName'>omipc</Data>
  <Data Name='SubjectUserName'>-</Data>
  <Data Name='LogonType'>10</Data>
  <Data Name='IpAddress'>203.0.113.9</Data>
  <Data Name='Status'>0xC000006D</Data>
  <Data Name='SubStatus'>0xC000006A</Data>
 </EventData>
</Event>
"""
WINDOWS_MACHINE_ACCOUNT = WINDOWS_FAILURE.replace(">omipc<", ">DESKTOP-1$<")
WINDOWS_GROUP_ADD = """
<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'>
 <System><EventID>4732</EventID><EventRecordID>9002</EventRecordID>
  <TimeCreated SystemTime='2026-09-23T18:05:00.000000000Z'/></System>
 <EventData>
  <Data Name='TargetUserName'>Administrators</Data>
  <Data Name='TargetDomainName'>Administrators</Data>
  <Data Name='SubjectUserName'>omipc</Data>
 </EventData>
</Event>
"""


def _auth(kind=EventType.AUTH_FAILURE, user="omipc", ip="203.0.113.9", minutes=0, **kw):
    return AuthEvent(type=kind, source=EventSource.AUTH_LOG,
                     timestamp=NOW + timedelta(minutes=minutes), user=user, source_ip=ip,
                     method="remote desktop", **kw)


def _findings(events):
    """Run events through an engine with only the sign-in rules, newest event last."""
    engine = DetectionEngine(rules=list(AUTH_RULES), context=DetectionContext())
    found = []
    for event in events:
        found.extend(engine.process(event))
    return found


# --------------------------------------------------------------------------- #
# Reading the records
# --------------------------------------------------------------------------- #
def test_windows_failed_signin_is_read_in_plain_words():
    event = parse_windows_event(WINDOWS_FAILURE)
    assert event.type is EventType.AUTH_FAILURE
    assert (event.user, event.source_ip, event.method) == ("omipc", "203.0.113.9",
                                                           "remote desktop")
    assert event.reason == "wrong password"
    assert event.record_id == "9001"
    assert event.summary() == ("Sign-in refused for omipc from 203.0.113.9 via "
                               "remote desktop (wrong password)")


def test_windows_computer_accounts_are_ignored():
    assert parse_windows_event(WINDOWS_MACHINE_ACCOUNT) is None


def test_windows_group_membership_change_is_read():
    event = parse_windows_event(WINDOWS_GROUP_ADD)
    assert event.type is EventType.ACCOUNT_PRIVILEGED
    assert (event.user, event.group, event.actor) == ("Administrators", "Administrators",
                                                      "omipc")
    assert is_admin_group(event.group)


@pytest.mark.parametrize("xml", ["<Event><System><EventID>4689</EventID></System></Event>",
                                 "not xml at all", "<Event/>"])
def test_uninteresting_or_broken_windows_records_are_skipped(xml):
    assert parse_windows_event(xml) is None


@pytest.mark.parametrize(("line", "kind", "user", "ip"), [
    ("Sep 23 21:30:01 box sshd[1]: Failed password for root from 203.0.113.9 port 4022 ssh2",
     EventType.AUTH_FAILURE, "root", "203.0.113.9"),
    ("Sep 23 21:30:02 box sshd[1]: Failed password for invalid user admin from 10.0.0.5 port 1",
     EventType.AUTH_FAILURE, "admin", "10.0.0.5"),
    ("Sep 23 21:31:00 box sshd[1]: Accepted password for omipc from 10.0.0.5 port 2 ssh2",
     EventType.AUTH_SUCCESS, "omipc", "10.0.0.5"),
    ("Sep 23 21:32:00 box useradd[9]: new user: name=backdoor, UID=1002, GID=1002",
     EventType.ACCOUNT_CREATED, "backdoor", ""),
    ("Sep 23 21:33:00 box usermod[9]: add 'backdoor' to group 'sudo'",
     EventType.ACCOUNT_PRIVILEGED, "backdoor", ""),
])
def test_linux_auth_lines_are_read(line, kind, user, ip):
    event = parse_linux_line(line, now=NOW)
    assert (event.type, event.user, event.source_ip) == (kind, user, ip)
    assert event.timestamp.year == NOW.year


def test_linux_sudo_failure_is_read():
    event = parse_linux_line("Sep 23 21:34:00 box sudo:   omipc : authentication failure; "
                             "logname=omipc uid=1000", now=NOW)
    assert (event.type, event.user, event.method) == (EventType.AUTH_FAILURE, "omipc", "sudo")


def test_routine_log_lines_are_ignored():
    assert parse_linux_line("Sep 23 21:30:00 box CRON[123]: (root) CMD (run-parts)") is None
    assert parse_linux_line("Sep 23 21:30:00 box systemd: Started Daily apt job.") is None


def test_group_changes_that_grant_nothing_are_ignored():
    assert parse_linux_line("Sep 23 21:33:00 box usermod[9]: add 'omipc' to group 'audio'",
                            now=NOW) is None


def test_linux_lines_keep_the_year_even_in_january():
    january = datetime(2027, 1, 1, 0, 10, 0)
    event = parse_linux_line("Dec 31 23:59:00 box sshd[1]: Failed password for root "
                             "from 10.0.0.5 port 1 ssh2", now=january)
    assert event.timestamp.year == 2026


# --------------------------------------------------------------------------- #
# The collector
# --------------------------------------------------------------------------- #
def test_linux_collector_reads_only_new_lines(tmp_path, monkeypatch):
    monkeypatch.setattr("aegis.collectors.auth.is_windows", lambda: False)
    log_file = tmp_path / "auth.log"
    log_file.write_text("Sep 23 21:00:00 box sshd[1]: Failed password for root "
                        "from 203.0.113.9 port 1 ssh2\n", encoding="utf-8")
    collector = AuthCollector(state_path=tmp_path / "state.json", log_paths=[str(log_file)])

    assert list(collector.poll()) == []        # the first read starts at the end
    with log_file.open("a", encoding="utf-8") as fh:
        fh.write("Sep 23 21:05:00 box sshd[1]: Accepted password for omipc "
                 "from 10.0.0.5 port 2 ssh2\n")
    events = list(collector.poll())
    assert [e.type for e in events] == [EventType.AUTH_SUCCESS]
    assert list(collector.poll()) == []        # nothing new the next time


def test_collector_remembers_its_place_across_restarts(tmp_path, monkeypatch):
    monkeypatch.setattr("aegis.collectors.auth.is_windows", lambda: False)
    log_file = tmp_path / "auth.log"
    log_file.write_text("Sep 23 21:00:00 box systemd: started\n", encoding="utf-8")
    state = tmp_path / "state.json"
    AuthCollector(state_path=state, log_paths=[str(log_file)]).poll()
    with log_file.open("a", encoding="utf-8") as fh:
        fh.write("Sep 23 21:05:00 box sshd[1]: Failed password for root from 10.0.0.5 port 1\n")

    restarted = AuthCollector(state_path=state, log_paths=[str(log_file)])
    assert [e.type for e in restarted.poll()] == [EventType.AUTH_FAILURE]
    assert json.loads(state.read_text(encoding="utf-8"))["offsets"]


def test_windows_collector_reads_the_security_log_once_per_record(monkeypatch):
    monkeypatch.setattr("aegis.collectors.auth.is_windows", lambda: True)
    calls = []

    def runner(args, timeout):
        calls.append(args)
        return RunResult(0, (WINDOWS_FAILURE + WINDOWS_GROUP_ADD).encode())

    collector = AuthCollector(runner=runner)
    first = list(collector.poll())
    assert [e.type for e in first] == [EventType.AUTH_FAILURE, EventType.ACCOUNT_PRIVILEGED]
    assert "Security" in calls[0][-1] and "4625" in calls[0][-1]
    assert list(collector.poll()) == []       # the same records are not re-read


def test_windows_sign_in_monitoring_needs_administrator(monkeypatch):
    monkeypatch.setattr("aegis.collectors.auth.is_windows", lambda: True)
    monkeypatch.setattr("aegis.collectors.auth.is_elevated", lambda: False)
    assert AuthCollector().available() is False
    monkeypatch.setattr("aegis.collectors.auth.is_elevated", lambda: True)
    assert AuthCollector().available() is True


def test_sign_in_monitoring_can_be_turned_off(monkeypatch):
    from aegis.config import settings

    monkeypatch.setattr("aegis.collectors.auth.is_windows", lambda: True)
    monkeypatch.setattr("aegis.collectors.auth.is_elevated", lambda: True)
    monkeypatch.setattr(settings, "auth_monitoring_enabled", False)
    assert AuthCollector().available() is False


def test_a_log_that_cannot_be_read_does_not_raise(tmp_path, monkeypatch):
    monkeypatch.setattr("aegis.collectors.auth.is_windows", lambda: False)
    collector = AuthCollector(state_path=tmp_path / "s.json",
                              log_paths=[str(tmp_path / "missing.log")])
    monkeypatch.setattr(collector, "_read_journal", lambda: [])
    assert list(collector.poll()) == []


# --------------------------------------------------------------------------- #
# Detections
# --------------------------------------------------------------------------- #
def test_repeated_failures_raise_one_guessing_finding():
    found = _findings([_auth(minutes=i * 0.2) for i in range(8)])
    guessing = [f for f in found if f.rule_id == "AUTH-GUESSING"]
    assert len(guessing) == 1
    assert guessing[0].severity is Severity.HIGH
    assert guessing[0].technique == "T1110"
    assert "refused sign-ins" in guessing[0].reasons[0]


def test_a_few_failures_are_not_an_attack():
    assert _findings([_auth(minutes=i) for i in range(3)]) == []


def test_failures_spread_over_hours_are_not_an_attack():
    assert _findings([_auth(minutes=i * 30) for i in range(8)]) == []


def test_many_accounts_from_one_address_is_spraying():
    events = [_auth(user=f"user{i}", minutes=i * 0.5) for i in range(5)]
    sprays = [f for f in _findings(events) if f.rule_id == "AUTH-SPRAY"]
    assert len(sprays) == 1
    assert sprays[0].technique == "T1110.003"
    assert "4 different accounts" in sprays[0].reasons[0]   # reported as soon as it is clear


def test_success_after_failures_is_critical():
    events = [_auth(minutes=i * 0.2) for i in range(5)]
    events.append(_auth(kind=EventType.AUTH_SUCCESS, minutes=1.5))
    guessed = [f for f in _findings(events) if f.rule_id == "AUTH-GUESSED-PASSWORD"]
    assert len(guessed) == 1
    assert guessed[0].severity is Severity.CRITICAL
    assert guessed[0].score >= 90


def test_a_normal_sign_in_raises_nothing():
    assert _findings([_auth(kind=EventType.AUTH_SUCCESS)]) == []


def test_new_account_and_admin_rights_are_reported():
    events = [
        _auth(kind=EventType.ACCOUNT_CREATED, user="backdoor", ip="", actor="omipc"),
        _auth(kind=EventType.ACCOUNT_PRIVILEGED, user="backdoor", ip="", group="sudo"),
    ]
    found = {f.rule_id: f for f in _findings(events)}
    assert found["AUTH-NEW-ACCOUNT"].technique == "T1136.001"
    assert found["AUTH-ADMIN-GRANTED"].technique == "T1098"
    assert found["AUTH-ADMIN-GRANTED"].severity is Severity.HIGH
    assert "backdoor" in found["AUTH-ADMIN-GRANTED"].reasons[0]


def test_lockout_is_reported():
    found = _findings([_auth(kind=EventType.ACCOUNT_LOCKED)])
    assert [f.rule_id for f in found] == ["AUTH-LOCKOUT"]


def test_every_sign_in_rule_is_mapped_and_explained():
    for rule in AUTH_RULES:
        assert rule.technique.startswith("T") and rule.tactic, rule.rule_id
        assert rule.description and rule.title, rule.rule_id


# --------------------------------------------------------------------------- #
# Security settings that get worse
# --------------------------------------------------------------------------- #
def _report(*statuses, severity=Severity.HIGH):
    return PostureReport([
        CheckResult(f"CHECK-{i}", f"Check {i}", "Network", status, severity,
                    f"summary {i}", remediation="turn it back on")
        for i, status in enumerate(statuses)
    ], platform="windows")


def test_a_setting_turning_bad_is_a_regression():
    before = _report(CheckStatus.PASS, CheckStatus.PASS)
    after = _report(CheckStatus.FAIL, CheckStatus.PASS)
    changed = regressions(before, after)
    assert [r.check_id for r in changed] == ["CHECK-0"]
    assert changed[0].before is CheckStatus.PASS
    assert "was pass" in changed[0].reasons()[0]
    assert changed[0].headline == "Security setting changed: Check 0"


def test_improvements_and_first_checks_are_not_regressions():
    assert regressions(None, _report(CheckStatus.FAIL)) == []
    assert regressions(_report(CheckStatus.FAIL), _report(CheckStatus.PASS)) == []


def test_checks_that_stop_running_are_not_reported_as_changes():
    assert regressions(_report(CheckStatus.PASS), _report(CheckStatus.SKIP)) == []
    assert regressions(_report(CheckStatus.SKIP), _report(CheckStatus.FAIL)) == []


def test_a_warning_becoming_a_failure_is_a_regression():
    changed = regressions(_report(CheckStatus.WARN), _report(CheckStatus.FAIL))
    assert len(changed) == 1 and changed[0].severity >= Severity.HIGH


def test_service_alerts_when_a_protection_is_switched_off(tmp_path):
    svc = SecurityService(store=SQLiteEventStore(tmp_path / "svc.db"),
                          firewall=FirewallManager(runner=lambda a, t: RunResult(0, b"Ok.")),
                          ml=None, collectors=[], forwarder=None,
                          notifier=Notifier(sender=lambda title, body: None))
    alerts = []
    svc.on_alert(alerts.append)

    svc.record_posture(_report(CheckStatus.PASS))
    assert alerts == []
    svc.record_posture(_report(CheckStatus.FAIL))

    assert [a.title for a in alerts] == ["Security setting changed: Check 0"]
    finding = svc.store.recent_findings()[0]
    assert finding["rule_id"] == "POSTURE-CHANGED"
    assert finding["technique"] == "T1562.001"
    svc.store.close()
