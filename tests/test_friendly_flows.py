"""The three places a person used to get stuck: administrator rights, fixing
everything safe at once, and protection stopping when the window closes.

Nothing here restarts anything or changes a real setting: Windows' own
elevation call is replaced with a recorder, and fixes run against the fake
machine from the hardening tests.
"""
import pytest

from aegis.elevate import can_elevate, restart_as_admin, restart_command
from aegis.hardening import HardeningEngine, Outcome
from aegis.hardening.fixes import default_fixes
from aegis.posture import run_posture_checks
from aegis.storage.database import SQLiteEventStore
from tests.test_hardening import RDP, SMB, TS, WINLOGON, Machine


# --------------------------------------------------------------------------- #
# Restarting with administrator rights
# --------------------------------------------------------------------------- #
class FakeShell:
    """Stands in for Windows' ShellExecuteW, which shows the consent dialog."""

    def __init__(self, code=42):
        self.calls: list[tuple[str, str, str]] = []
        self.code = code

    def __call__(self, program, arguments, directory):
        self.calls.append((program, arguments, directory))
        return self.code


def test_restarting_needs_confirmation(monkeypatch):
    monkeypatch.setattr("aegis.elevate.is_elevated", lambda: False)
    monkeypatch.setattr("aegis.elevate.is_windows", lambda: True)
    shell = FakeShell()
    result = restart_as_admin(shell_execute=shell)
    assert not result.ok and "confirmation" in result.message
    assert shell.calls == []


def test_windows_is_asked_to_start_aegis_again(monkeypatch):
    monkeypatch.setattr("aegis.elevate.is_elevated", lambda: False)
    monkeypatch.setattr("aegis.elevate.is_windows", lambda: True)
    shell = FakeShell()
    result = restart_as_admin(confirmed=True, shell_execute=shell)
    assert result.ok and result.restarting
    program, arguments, _ = shell.calls[0]
    assert program == restart_command()[0]
    assert "aegis" in arguments.lower()


def test_declining_the_windows_prompt_leaves_aegis_running(monkeypatch):
    monkeypatch.setattr("aegis.elevate.is_elevated", lambda: False)
    monkeypatch.setattr("aegis.elevate.is_windows", lambda: True)
    result = restart_as_admin(confirmed=True, shell_execute=FakeShell(code=1223))
    assert not result.ok and not result.restarting
    assert "declined" in result.message


def test_a_refusal_from_windows_is_explained(monkeypatch):
    monkeypatch.setattr("aegis.elevate.is_elevated", lambda: False)
    monkeypatch.setattr("aegis.elevate.is_windows", lambda: True)
    result = restart_as_admin(confirmed=True, shell_execute=FakeShell(code=5))
    assert not result.ok and "refused" in result.message


def test_nothing_to_do_when_aegis_already_has_the_rights(monkeypatch):
    monkeypatch.setattr("aegis.elevate.is_elevated", lambda: True)
    monkeypatch.setattr("aegis.elevate.is_windows", lambda: True)
    assert can_elevate() is False
    assert restart_as_admin(confirmed=True).ok is False


def test_other_platforms_are_told_what_to_type(monkeypatch):
    monkeypatch.setattr("aegis.elevate.is_elevated", lambda: False)
    monkeypatch.setattr("aegis.elevate.is_windows", lambda: False)
    monkeypatch.setattr("aegis.platforms.is_windows", lambda: False)   # for the hint
    assert can_elevate() is False
    assert "sudo" in restart_as_admin(confirmed=True).message


# --------------------------------------------------------------------------- #
# Fixing everything that is safe to fix
# --------------------------------------------------------------------------- #
@pytest.fixture
def store(tmp_path):
    s = SQLiteEventStore(tmp_path / "harden.db")
    yield s
    s.close()


@pytest.fixture
def weak_machine():
    """A Windows machine with several weaknesses, safe and not."""
    m = Machine()
    m.registry[("HKLM", SMB, "SMB1")] = 1                       # routine
    m.registry[("HKLM", RDP, "UserAuthentication")] = 0          # routine
    m.registry[("HKLM", TS, "fDenyTSConnections")] = 0
    m.registry[("HKLM", WINLOGON, "AutoAdminLogon")] = "1"       # not routine
    m.registry[("HKLM", WINLOGON, "DefaultPassword")] = "secret"
    from aegis.posture.base import Listener
    m.listening = [Listener("0.0.0.0", 3389, "svchost.exe")]
    return m


def test_the_batch_leaves_out_what_could_lock_you_out(store, weak_machine):
    engine = HardeningEngine(store, ctx=weak_machine.context())
    report = run_posture_checks(engine.ctx)
    offered = {fix.fix_id for fix, _ in engine.routine_fixes(report)}

    assert "FIX-WIN-SMB1" in offered and "FIX-WIN-RDP-NLA" in offered
    assert "FIX-WIN-RDP-OFF" not in offered      # would cut off a remote session
    assert "FIX-WIN-AUTOLOGON" not in offered    # deletes a password for good


def test_applying_the_batch_fixes_each_one_and_records_it(store, weak_machine):
    engine = HardeningEngine(store, ctx=weak_machine.context())
    results = engine.apply_routine(run_posture_checks(engine.ctx), confirmed=True)

    assert results and all(r.outcome is Outcome.FIXED for r in results)
    assert weak_machine.registry[("HKLM", SMB, "SMB1")] == 0
    assert weak_machine.registry[("HKLM", RDP, "UserAuthentication")] == 1
    # each fix is its own record, so each can be undone on its own
    history = engine.history()
    assert {r.fix_id for r in history} == {r.fix_id for r in results}
    assert all(r.can_undo for r in history)


def test_the_batch_changes_nothing_without_confirmation(store, weak_machine):
    engine = HardeningEngine(store, ctx=weak_machine.context())
    results = engine.apply_routine(run_posture_checks(engine.ctx))
    assert all(r.outcome is Outcome.NEEDS_CONFIRMATION for r in results)
    assert weak_machine.registry[("HKLM", SMB, "SMB1")] == 1
    assert engine.history() == []


def test_a_healthy_machine_has_nothing_to_fix(store):
    healthy = Machine()
    desktop = r"Control Panel\Desktop"          # the screen already locks itself
    healthy.registry[("HKCU", desktop, "ScreenSaveActive")] = "1"
    healthy.registry[("HKCU", desktop, "ScreenSaverIsSecure")] = "1"
    healthy.registry[("HKCU", desktop, "ScreenSaveTimeOut")] = "600"
    engine = HardeningEngine(store, ctx=healthy.context())
    assert engine.routine_fixes(run_posture_checks(engine.ctx)) == []
    assert engine.apply_routine(run_posture_checks(engine.ctx), confirmed=True) == []


def test_every_fix_says_whether_it_belongs_in_the_batch():
    for fix in default_fixes():
        assert isinstance(fix.routine, bool), fix.fix_id
        # anything that cannot be fully undone must never be applied in bulk
        if not fix.reversible:
            assert not fix.routine, fix.fix_id
