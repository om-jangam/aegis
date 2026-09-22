"""Containment on this computer: stopping a program and quarantining a file.

No real process is ever stopped here: a fake process object records what was
asked of it. Quarantine works on real files, inside pytest's temporary folder.
"""
import json

import psutil
import pytest

from aegis.alerting.notifier import Notifier
from aegis.response.actions import (
    MAX_QUARANTINE_BYTES,
    ProcessStopper,
    Quarantine,
    is_protected_path,
    is_protected_process,
)
from aegis.response.command import RunResult
from aegis.response.firewall import FirewallManager
from aegis.service import SecurityService
from aegis.storage.database import SQLiteEventStore


class FakeProcess:
    """Stands in for psutil.Process: records terminate/kill instead of doing them."""

    def __init__(self, pid, name="evil.exe", *, dies_on="terminate", raises=None):
        self.pid = pid
        self._name = name
        self._dies_on = dies_on
        self._raises = raises
        self.calls: list[str] = []
        self.alive = True

    def name(self):
        if isinstance(self._raises, Exception) and not self.calls:
            raise self._raises
        return self._name

    def terminate(self):
        self.calls.append("terminate")
        if isinstance(self._raises, Exception):
            raise self._raises
        if self._dies_on == "terminate":
            self.alive = False

    def kill(self):
        self.calls.append("kill")
        if self._dies_on == "kill":
            self.alive = False

    def is_running(self):
        return self.alive


@pytest.fixture
def stopper(monkeypatch):
    """A stopper wired to one fake process, with waiting made instant."""
    created: dict[int, FakeProcess] = {}

    def wait_procs(procs, timeout=None):
        alive = [p for p in procs if p.alive]
        return [p for p in procs if not p.alive], alive

    monkeypatch.setattr(psutil, "wait_procs", wait_procs)

    def make(process: FakeProcess, own_pid: int = 999):
        created[process.pid] = process
        return ProcessStopper(process_source=lambda pid: created[pid], own_pid=own_pid)

    return make


# --------------------------------------------------------------------------- #
# Stopping a program
# --------------------------------------------------------------------------- #
def test_stopping_needs_confirmation(stopper):
    proc = FakeProcess(1234)
    result = stopper(proc).stop(1234, "evil.exe")
    assert not result.ok and "confirmation" in result.message
    assert proc.calls == []


def test_a_program_is_asked_to_close_before_it_is_killed(stopper):
    proc = FakeProcess(1234, dies_on="terminate")
    result = stopper(proc).stop(1234, "evil.exe", confirmed=True, reason="from an alert")
    assert result.ok and proc.calls == ["terminate"]
    assert "Stopped evil.exe (process 1234)" in result.message
    assert "from an alert" in result.message


def test_a_program_that_ignores_the_request_is_killed(stopper):
    proc = FakeProcess(1234, dies_on="kill")
    assert stopper(proc).stop(1234, confirmed=True).ok
    assert proc.calls == ["terminate", "kill"]


def test_a_program_that_will_not_stop_is_reported(stopper):
    proc = FakeProcess(1234, dies_on="never")
    result = stopper(proc).stop(1234, confirmed=True)
    assert not result.ok and "refused to stop" in result.message


@pytest.mark.parametrize("name", ["lsass.exe", "System", "systemd", "WinLogon.exe"])
def test_system_processes_are_refused(stopper, name):
    proc = FakeProcess(4, name)
    result = stopper(proc).stop(4, confirmed=True)
    assert not result.ok and "operating system" in result.message
    assert proc.calls == []
    assert is_protected_process(name)


def test_aegis_will_not_stop_itself(stopper):
    proc = FakeProcess(999)
    result = stopper(proc, own_pid=999).stop(999, confirmed=True)
    assert not result.ok and "itself" in result.message


def test_a_reused_process_number_is_not_stopped(stopper):
    proc = FakeProcess(1234, "chrome.exe")
    result = stopper(proc).stop(1234, "evil.exe", confirmed=True)
    assert not result.ok and "now chrome.exe" in result.message
    assert proc.calls == []


def test_a_program_that_already_exited_is_reported(monkeypatch):
    def gone(pid):
        raise psutil.NoSuchProcess(pid)

    result = ProcessStopper(process_source=gone, own_pid=1).stop(5, confirmed=True)
    assert not result.ok and "any more" in result.message


def test_missing_rights_ask_for_administrator(monkeypatch):
    def denied(pid):
        raise psutil.AccessDenied(pid)

    result = ProcessStopper(process_source=denied, own_pid=1).stop(5, confirmed=True)
    assert not result.ok and result.needs_admin


# --------------------------------------------------------------------------- #
# Quarantine
# --------------------------------------------------------------------------- #
@pytest.fixture
def quarantine(tmp_path):
    return Quarantine(tmp_path / "quarantine")


def _malware(tmp_path, name="dropper.exe", content=b"MZ evil"):
    path = tmp_path / name
    path.write_bytes(content)
    return path


def test_quarantine_needs_confirmation(quarantine, tmp_path):
    path = _malware(tmp_path)
    result = quarantine.add(path)
    assert not result.ok and "confirmation" in result.message
    assert path.exists()


def test_a_file_is_moved_not_deleted_and_can_be_restored(quarantine, tmp_path):
    path = _malware(tmp_path)
    result = quarantine.add(path, confirmed=True, reason="flagged by NET-C2-PORT")
    assert result.ok and not path.exists()

    [record] = quarantine.records()
    assert record.original_path.endswith("dropper.exe")
    assert record.digest and record.size == len(b"MZ evil")
    assert record.reason == "flagged by NET-C2-PORT" and record.can_restore
    assert (quarantine.directory / record.stored_name).read_bytes() == b"MZ evil"

    restored = quarantine.restore(record.id, confirmed=True)
    assert restored.ok and path.read_bytes() == b"MZ evil"
    assert not quarantine.records()[0].can_restore


def test_restoring_needs_confirmation_and_happens_once(quarantine, tmp_path):
    path = _malware(tmp_path)
    quarantine.add(path, confirmed=True)
    record_id = quarantine.records()[0].id

    assert not quarantine.restore(record_id).ok
    assert not path.exists()
    assert quarantine.restore(record_id, confirmed=True).ok
    assert not quarantine.restore(record_id, confirmed=True).ok


def test_a_file_back_in_place_is_not_overwritten(quarantine, tmp_path):
    path = _malware(tmp_path)
    quarantine.add(path, confirmed=True)
    record_id = quarantine.records()[0].id
    path.write_bytes(b"something else")

    result = quarantine.restore(record_id, confirmed=True)
    assert not result.ok and "move it aside" in result.message
    assert path.read_bytes() == b"something else"


def test_system_files_are_refused(quarantine, monkeypatch, tmp_path):
    path = _malware(tmp_path, "kernel32.dll")
    monkeypatch.setattr("aegis.response.actions.is_protected_path", lambda p: True)
    result = quarantine.add(path, confirmed=True)
    assert not result.ok and "operating system" in result.message
    assert path.exists()


@pytest.mark.parametrize("path", ["C:/Windows/System32/lsass.exe", "/usr/bin/sshd", "/etc/passwd"])
def test_operating_system_folders_are_recognised(path):
    assert is_protected_path(path)


def test_a_users_own_file_is_not_protected(tmp_path):
    assert not is_protected_path(tmp_path / "notes.txt")


def test_oversized_and_missing_files_are_refused(quarantine, tmp_path, monkeypatch):
    missing = quarantine.add(tmp_path / "nope.exe", confirmed=True)
    assert not missing.ok and "Cannot read" in missing.message

    big = _malware(tmp_path, "big.bin")
    monkeypatch.setattr("aegis.response.actions.MAX_QUARANTINE_BYTES", 2)
    assert MAX_QUARANTINE_BYTES > 2          # the real limit is not tiny
    result = quarantine.add(big, confirmed=True)
    assert not result.ok and "too large" in result.message
    assert big.exists()


def test_a_folder_is_refused(quarantine, tmp_path):
    folder = tmp_path / "folder"
    folder.mkdir()
    assert not quarantine.add(folder, confirmed=True).ok


def test_an_unreadable_index_does_not_lose_the_folder(quarantine, tmp_path):
    quarantine.directory.mkdir(parents=True)
    (quarantine.directory / "index.json").write_text("{not json", encoding="utf-8")
    assert quarantine.records() == []
    assert quarantine.add(_malware(tmp_path), confirmed=True).ok
    assert len(json.loads((quarantine.directory / "index.json").read_text())) == 1


# --------------------------------------------------------------------------- #
# Through the service: everything is audited
# --------------------------------------------------------------------------- #
@pytest.fixture
def service(tmp_path):
    svc = SecurityService(store=SQLiteEventStore(tmp_path / "svc.db"),
                          firewall=FirewallManager(runner=lambda a, t: RunResult(0, b"Ok.")),
                          ml=None, collectors=[], forwarder=None,
                          notifier=Notifier(sender=lambda title, body: None))
    svc.quarantine = Quarantine(tmp_path / "q")
    yield svc
    svc.store.close()


def test_service_records_a_quarantine_and_its_restore(service, tmp_path):
    path = _malware(tmp_path)
    assert service.quarantine_file(path, confirmed=True, reason="test").ok
    record_id = service.quarantine.records()[0].id
    assert service.restore_quarantined(record_id, confirmed=True).ok

    actions = [a.action for a in service.store.recent_audit(category="RESPONSE")]
    assert actions[:2] == ["file_restored", "file_quarantined"]


def test_service_records_refusals_too(service, tmp_path):
    path = _malware(tmp_path)
    assert not service.quarantine_file(path, confirmed=False).ok
    assert path.exists()
    audit = service.store.recent_audit(category="RESPONSE")
    assert audit[0].action == "quarantine_refused"


def test_service_records_a_refused_process_stop(service):
    result = service.stop_process(1234, "evil.exe", confirmed=False)
    assert not result.ok
    audit = service.store.recent_audit(category="RESPONSE")
    assert audit[0].action == "process_stop_refused"
    assert "confirmation" in audit[0].detail
