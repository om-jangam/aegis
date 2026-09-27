"""Watching after the window closes: the single-watcher lock, and autostart.

Nothing here registers anything on the machine running the tests: the registry,
systemd and launchctl are all replaced with fakes, and files are written inside
pytest's temporary folder.
"""
import os
import plistlib

import pytest

from aegis.alerting.notifier import Notifier
from aegis.autostart import (
    ENTRY_NAME,
    LAUNCH_AGENT,
    SERVICE_NAME,
    Autostart,
    monitor_command,
    quote,
)
from aegis.platforms import OS
from aegis.response.command import RunResult
from aegis.response.firewall import FirewallManager
from aegis.runlock import MonitorLock
from aegis.service import SecurityService
from aegis.storage.database import SQLiteEventStore


# --------------------------------------------------------------------------- #
# One watcher at a time
# --------------------------------------------------------------------------- #
def test_the_first_watcher_takes_the_lock(tmp_path):
    lock = MonitorLock(tmp_path / "monitor.lock")
    assert lock.acquire() is True
    assert lock.held_by_me
    holder = lock.holder()
    assert holder.pid == os.getpid() and holder.kind == "app"
    assert "another Aegis window" in holder.describe()


def test_a_second_watcher_is_turned_away(tmp_path, monkeypatch):
    path = tmp_path / "monitor.lock"
    MonitorLock(path, "background").acquire()
    monkeypatch.setattr("aegis.runlock.os.getpid", lambda: 999999)   # a different process
    monkeypatch.setattr("aegis.runlock._alive", lambda pid: True)

    second = MonitorLock(path)
    assert second.acquire() is False
    assert "the background service" in second.holder().describe()


def test_a_lock_left_by_a_dead_process_is_ignored(tmp_path, monkeypatch):
    path = tmp_path / "monitor.lock"
    MonitorLock(path).acquire()
    monkeypatch.setattr("aegis.runlock.os.getpid", lambda: 999999)
    monkeypatch.setattr("aegis.runlock._alive", lambda pid: False)   # it crashed

    assert MonitorLock(path).holder() is None
    assert MonitorLock(path).acquire() is True


def test_a_damaged_lock_file_does_not_stop_watching(tmp_path):
    path = tmp_path / "monitor.lock"
    path.write_text("not json", encoding="utf-8")
    assert MonitorLock(path).holder() is None
    assert MonitorLock(path).acquire() is True


def test_releasing_lets_the_next_watcher_in(tmp_path):
    path = tmp_path / "monitor.lock"
    first = MonitorLock(path)
    first.acquire()
    first.release()
    assert not path.exists()
    assert MonitorLock(path).acquire() is True


def test_release_leaves_somebody_elses_lock_alone(tmp_path, monkeypatch):
    path = tmp_path / "monitor.lock"
    mine = MonitorLock(path)
    mine.acquire()
    monkeypatch.setattr("aegis.runlock.os.getpid", lambda: 999999)
    monkeypatch.setattr("aegis.runlock._alive", lambda pid: True)
    MonitorLock(path, "background").acquire()   # somebody else took over

    mine.release()
    assert path.exists()


def _service(tmp_path, lock):
    return SecurityService(store=SQLiteEventStore(tmp_path / "svc.db"),
                           firewall=FirewallManager(runner=lambda a, t: RunResult(0, b"Ok.")),
                           ml=None, collectors=[], forwarder=None, lock=lock,
                           notifier=Notifier(sender=lambda title, body: None))


def test_a_second_aegis_shows_instead_of_watching(tmp_path, monkeypatch):
    path = tmp_path / "monitor.lock"
    MonitorLock(path, "background").acquire()
    monkeypatch.setattr("aegis.runlock.os.getpid", lambda: 999999)
    monkeypatch.setattr("aegis.runlock._alive", lambda pid: True)

    service = _service(tmp_path, MonitorLock(path))
    service.start()
    assert service.read_only is True
    audit = service.store.recent_audit(category="SYSTEM")
    assert audit[0].action == "monitoring_deferred"
    assert "the background service" in audit[0].message
    service.stop()
    service.store.close()


def test_the_only_aegis_watches_normally(tmp_path):
    service = _service(tmp_path, MonitorLock(tmp_path / "monitor.lock"))
    service.start()
    assert service.read_only is False
    assert [a.action for a in service.store.recent_audit(category="SYSTEM")][0] == \
        "monitoring_started"
    service.stop()
    service.store.close()


# --------------------------------------------------------------------------- #
# Starting with the computer
# --------------------------------------------------------------------------- #
class FakeSystem:
    """Records the commands autostart runs, and answers the ones it reads."""

    def __init__(self, enabled=False):
        self.calls: list[list[str]] = []
        self.enabled = enabled

    def __call__(self, args, timeout):
        self.calls.append(list(args))
        if args[:3] == ["systemctl", "--user", "is-enabled"]:
            return RunResult(0 if self.enabled else 1,
                             b"enabled\n" if self.enabled else b"disabled\n")
        if args[:3] == ["systemctl", "--user", "enable"]:
            self.enabled = True
        if args[:3] == ["systemctl", "--user", "disable"]:
            self.enabled = False
        return RunResult(0, b"")


def test_the_registered_command_runs_monitoring_not_the_window():
    command = monitor_command()
    assert command[-1] == "monitor"
    assert "aegis" in quote(command).lower()


def test_nothing_is_registered_without_confirmation(tmp_path):
    system = FakeSystem()
    autostart = Autostart(runner=system, home=tmp_path, os_name=OS.LINUX)
    ok, message = autostart.enable()
    assert not ok and "confirmation" in message
    assert system.calls == [] and not autostart.service_file.exists()

    ok, message = autostart.disable()
    assert not ok and "confirmation" in message


def test_linux_writes_a_user_service_and_enables_it(tmp_path):
    system = FakeSystem()
    autostart = Autostart(runner=system, home=tmp_path, os_name=OS.LINUX)
    assert autostart.state().enabled is False

    ok, message = autostart.enable(confirmed=True)
    assert ok and SERVICE_NAME in message
    unit = autostart.service_file.read_text(encoding="utf-8")
    assert "ExecStart=" in unit and "monitor" in unit
    assert ["systemctl", "--user", "enable", "--now", SERVICE_NAME] in system.calls
    assert autostart.state().enabled is True

    ok, message = autostart.disable(confirmed=True)
    assert ok and not autostart.service_file.exists()
    assert ["systemctl", "--user", "disable", "--now", SERVICE_NAME] in system.calls


def test_macos_writes_a_launch_agent(tmp_path):
    system = FakeSystem()
    autostart = Autostart(runner=system, home=tmp_path, os_name=OS.MACOS)
    ok, _ = autostart.enable(confirmed=True)
    assert ok

    plist = plistlib.loads(autostart.agent_file.read_bytes())
    assert plist["Label"] == LAUNCH_AGENT and plist["RunAtLoad"] is True
    assert plist["ProgramArguments"][-1] == "monitor"
    assert ["launchctl", "load", str(autostart.agent_file)] in system.calls
    assert autostart.state().enabled is True

    autostart.disable(confirmed=True)
    assert not autostart.agent_file.exists()
    assert ["launchctl", "unload", str(autostart.agent_file)] in system.calls


def test_windows_uses_the_per_user_run_key(tmp_path, monkeypatch):
    registry: dict[str, str] = {}
    autostart = Autostart(home=tmp_path, os_name=OS.WINDOWS)
    monkeypatch.setattr(autostart, "_read_run_value", lambda: registry.get(ENTRY_NAME))
    monkeypatch.setattr(autostart, "_write_run_value",
                        lambda command: registry.__setitem__(ENTRY_NAME, command))
    monkeypatch.setattr(autostart, "_delete_run_value", lambda: registry.pop(ENTRY_NAME, None))

    assert autostart.state().enabled is False
    ok, message = autostart.enable(confirmed=True)
    assert ok and "Run" in message
    assert "monitor" in registry[ENTRY_NAME]
    assert autostart.state().enabled is True

    assert autostart.disable(confirmed=True)[0] is True
    assert registry == {}


def test_an_unsupported_platform_says_so(tmp_path):
    autostart = Autostart(home=tmp_path, os_name=OS.UNKNOWN)
    state = autostart.state()
    assert not state.supported and "not supported" in state.describe()
    assert autostart.enable(confirmed=True)[0] is False


def test_a_failure_is_reported_not_raised(tmp_path, monkeypatch):
    autostart = Autostart(home=tmp_path, os_name=OS.WINDOWS)

    def refuse(command):
        raise PermissionError("access denied")

    monkeypatch.setattr(autostart, "_write_run_value", refuse)
    ok, message = autostart.enable(confirmed=True)
    assert not ok and "access denied" in message


@pytest.mark.parametrize("command", [["C:/Program Files/Aegis/Aegis.exe", "monitor"],
                                     ["/usr/bin/python3", "-m", "aegis", "monitor"]])
def test_paths_with_spaces_stay_one_argument(command):
    quoted = quote(command)
    assert quoted.endswith("monitor")
    assert quoted.count('"') == (2 if " " in command[0] else 0)
