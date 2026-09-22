"""Hardening: every safeguard (confirm, privileges, backup, verify, record, undo) and every fix.

All fixes run against an in-memory machine (registry, files, permissions and
command output), so nothing on the computer running the tests is changed.
"""
import json
import stat

import pytest

from aegis import cli
from aegis.core.models import Remediation
from aegis.hardening import HardeningContext, HardeningEngine, HardeningError, Outcome
from aegis.hardening.fixes import default_fixes
from aegis.platforms import OS
from aegis.posture import CheckStatus, Listener, run_posture_checks
from aegis.posture.checks import default_checks
from aegis.response.command import RunResult
from aegis.storage.database import SQLiteEventStore

SMB = r"SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters"
TS = r"SYSTEM\CurrentControlSet\Control\Terminal Server"
RDP = TS + r"\WinStations\RDP-Tcp"
UAC = r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
WINLOGON = r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"
PASSWORD = "hunter2-plaintext"


class Machine:
    """A fake computer: registry, files, permissions and scripted commands."""

    def __init__(self, os=OS.WINDOWS, elevated=True):
        self.os = os
        self.elevated = elevated
        self.registry: dict[tuple[str, str], object] = {}
        self.files: dict[str, str] = {}
        self.modes: dict[str, int] = {}
        self.listening: list[Listener] = []
        self.commands: dict[tuple, object] = {}
        self.calls: list[list[str]] = []
        self.fail_write_number: int | None = None
        self.ignore_writes = False
        self._writes = 0

    # readers
    def run(self, args, timeout):
        self.calls.append(list(args))
        answer = self.commands.get(tuple(args))
        if callable(answer):
            answer = answer()
        if answer is None:
            raise FileNotFoundError(args[0])
        code, text = answer
        return RunResult(code, text.encode())

    # writers
    def write_registry(self, hive, key, name, value, kind):
        self._writes += 1
        if self._writes == self.fail_write_number:
            raise HardeningError("access denied")
        if self.ignore_writes:
            return
        if value is None:
            self.registry.pop((hive, key, name), None)
        else:
            self.registry[(hive, key, name)] = int(value) if kind == "dword" else str(value)

    def write_text(self, path, text):
        self.files[path] = text

    def chmod(self, path, mode):
        self.modes[path] = stat.S_IFREG | mode

    def context(self):
        return HardeningContext(
            os=self.os, elevated=self.elevated, runner=self.run,
            listeners=lambda: list(self.listening),
            read_text=self.files.get, stat_mode=self.modes.get,
            read_registry=lambda key, name: self.registry.get(("HKLM", key, name)),
            registry_values=lambda hive, key: {
                name: value for (h, k, name), value in self.registry.items()
                if (h, k) == (hive, key)}, glob=lambda pattern: [],
            env=lambda name: None,
            write_registry=self.write_registry, write_text=self.write_text, chmod=self.chmod)


@pytest.fixture
def store(tmp_path):
    s = SQLiteEventStore(tmp_path / "harden.db")
    yield s
    s.close()


def engine_for(machine, store):
    return HardeningEngine(store, ctx=machine.context())


# --------------------------------------------------------------------------- #
# The safeguards
# --------------------------------------------------------------------------- #
def test_fix_is_applied_verified_recorded_and_audited(store):
    m = Machine()
    m.registry[("HKLM", SMB, "SMB1")] = 1
    result = engine_for(m, store).apply("FIX-WIN-SMB1", confirmed=True)

    assert result.outcome is Outcome.FIXED and result.ok
    assert m.registry[("HKLM", SMB, "SMB1")] == 0
    assert result.check_status == "pass"
    assert "Restart" in result.message
    record = store.remediation(result.record_id)
    assert record.status == "fixed" and record.can_undo
    assert record.changes == [{"setting": f"HKLM\\{SMB}\\SMB1", "current": "1", "target": "0"}]
    audit = store.recent_audit(category="HARDENING")
    assert audit[0].action == "fix_fixed"


def test_nothing_changes_without_confirmation(store):
    m = Machine()
    m.registry[("HKLM", SMB, "SMB1")] = 1
    result = engine_for(m, store).apply("FIX-WIN-SMB1")
    assert result.outcome is Outcome.NEEDS_CONFIRMATION
    assert result.changes and m.registry[("HKLM", SMB, "SMB1")] == 1
    assert store.recent_remediations() == []


def test_changes_needing_admin_are_refused_up_front(store):
    m = Machine(elevated=False)
    m.registry[("HKLM", SMB, "SMB1")] = 1
    result = engine_for(m, store).apply("FIX-WIN-SMB1", confirmed=True)
    assert result.outcome is Outcome.NEEDS_ADMIN
    assert m.registry[("HKLM", SMB, "SMB1")] == 1
    assert store.recent_remediations()[0].status == "needs_admin"


def test_safe_settings_need_nothing(store):
    m = Machine()   # SMB1 absent: Windows treats that as off
    engine = engine_for(m, store)
    assert engine.preview("FIX-WIN-SMB1").outcome is Outcome.NOTHING_TO_DO
    assert engine.apply("FIX-WIN-SMB1", confirmed=True).outcome is Outcome.NOTHING_TO_DO
    assert m.registry == {}


def test_a_failure_part_way_is_rolled_back(store):
    m = Machine()
    m.registry[("HKLM", UAC, "EnableLUA")] = 0
    m.registry[("HKLM", UAC, "ConsentPromptBehaviorAdmin")] = 0
    m.fail_write_number = 2       # the first value is written, the second fails
    result = engine_for(m, store).apply("FIX-WIN-UAC", confirmed=True)
    assert result.outcome is Outcome.FAILED
    assert "restored" in result.message
    assert (m.registry[("HKLM", UAC, "EnableLUA")], m.registry[("HKLM", UAC, "ConsentPromptBehaviorAdmin")]) \
        == (0, 0)
    assert not store.remediation(result.record_id).can_undo


def test_a_change_that_does_not_stick_is_reported_not_verified(store):
    m = Machine()
    m.registry[("HKLM", SMB, "SMB1")] = 1
    m.ignore_writes = True
    result = engine_for(m, store).apply("FIX-WIN-SMB1", confirmed=True)
    assert result.outcome is Outcome.NOT_VERIFIED and not result.ok
    assert "still reads as unsafe" in result.message
    assert store.remediation(result.record_id).can_undo


def test_undo_restores_the_backup_once(store):
    m = Machine()
    m.registry[("HKLM", RDP, "UserAuthentication")] = 0
    engine = engine_for(m, store)
    applied = engine.apply("FIX-WIN-RDP-NLA", confirmed=True)
    assert m.registry[("HKLM", RDP, "UserAuthentication")] == 1

    asked = engine.undo(applied.record_id)
    assert asked.outcome is Outcome.NEEDS_CONFIRMATION
    assert m.registry[("HKLM", RDP, "UserAuthentication")] == 1

    undone = engine.undo(applied.record_id, confirmed=True)
    assert undone.outcome is Outcome.UNDONE
    assert m.registry[("HKLM", RDP, "UserAuthentication")] == 0
    assert store.remediation(applied.record_id).undone_at is not None
    assert store.remediation(undone.record_id).undo_of == applied.record_id
    assert engine.undo(applied.record_id, confirmed=True).outcome is Outcome.FAILED


def test_undo_also_needs_admin(store):
    m = Machine()
    m.registry[("HKLM", SMB, "SMB1")] = 1
    engine = engine_for(m, store)
    applied = engine.apply("FIX-WIN-SMB1", confirmed=True)
    engine.ctx.elevated = False
    assert engine.undo(applied.record_id, confirmed=True).outcome is Outcome.NEEDS_ADMIN
    assert m.registry[("HKLM", SMB, "SMB1")] == 0


def test_unknown_fixes_and_records_are_rejected(store):
    engine = engine_for(Machine(), store)
    with pytest.raises(ValueError):
        engine.apply("FIX-NOPE", confirmed=True)
    with pytest.raises(ValueError):
        engine.undo(999)


def test_fixes_for_other_platforms_are_not_offered(store):
    engine = engine_for(Machine(os=OS.LINUX), store)
    assert engine.fix("FIX-WIN-SMB1") is None
    with pytest.raises(ValueError):
        engine.apply("FIX-WIN-SMB1", confirmed=True)


def test_recommendations_pair_weak_checks_with_fixes_and_guidance(store):
    m = Machine()
    m.registry[("HKLM", SMB, "SMB1")] = 1
    m.registry[("HKLM", TS, "fDenyTSConnections")] = 0
    m.registry[("HKLM", RDP, "UserAuthentication")] = 0
    m.listening = [Listener("0.0.0.0", 3389, "svchost.exe")]
    engine = engine_for(m, store)
    report = run_posture_checks(engine.ctx)
    recs = {r.check.check_id: r for r in engine.recommendations(report)}

    assert [f.fix_id for f, _ in recs["POSTURE-SMB1"].fixes] == ["FIX-WIN-SMB1"]
    assert [f.fix_id for f, _ in recs["POSTURE-RDP"].fixes] == \
        ["FIX-WIN-RDP-NLA", "FIX-WIN-RDP-OFF"]
    assert recs["POSTURE-RDP"].guidance
    assert all(r.check.status in (CheckStatus.FAIL, CheckStatus.WARN) for r in recs.values())


# --------------------------------------------------------------------------- #
# Individual fixes
# --------------------------------------------------------------------------- #
def test_autologon_fix_never_reads_out_or_keeps_the_password(store):
    m = Machine()
    m.registry[("HKLM", WINLOGON, "AutoAdminLogon")] = "1"
    m.registry[("HKLM", WINLOGON, "DefaultPassword")] = PASSWORD
    engine = engine_for(m, store)

    preview = engine.preview("FIX-WIN-AUTOLOGON")
    assert PASSWORD not in json.dumps(preview.to_dict())
    result = engine.apply("FIX-WIN-AUTOLOGON", confirmed=True)
    assert result.outcome is Outcome.FIXED
    assert m.registry[("HKLM", WINLOGON, "AutoAdminLogon")] == "0"
    assert ("HKLM", WINLOGON, "DefaultPassword") not in m.registry

    record = store.remediation(result.record_id)
    stored = json.dumps([record.changes, record.backup, record.message,
                         [a.detail for a in store.recent_audit()]])
    assert PASSWORD not in stored

    undone = engine.undo(result.record_id, confirmed=True)
    assert "cannot be restored" in undone.message
    assert m.registry[("HKLM", WINLOGON, "AutoAdminLogon")] == "1"
    assert ("HKLM", WINLOGON, "DefaultPassword") not in m.registry


def test_autologon_fix_has_nothing_to_do_while_autologon_is_off(store):
    m = Machine()
    m.registry[("HKLM", WINLOGON, "AutoAdminLogon")] = "0"
    assert engine_for(m, store).preview("FIX-WIN-AUTOLOGON").outcome is Outcome.NOTHING_TO_DO


NETSH_STATE = """
Domain Profile Settings:
----------------------------------------------------------------------
State                                 ON

Private Profile Settings:
----------------------------------------------------------------------
State                                 {private}

Public Profile Settings:
----------------------------------------------------------------------
State                                 {public}
Ok.
"""


def _netsh_machine():
    m = Machine()
    state = {"private": "OFF", "public": "OFF"}
    show = ("netsh", "advfirewall", "show", "allprofiles", "state")
    m.commands[show] = lambda: (0, NETSH_STATE.format(**state))

    def turn_on():
        state.update(private="ON", public="ON")
        return (0, "Ok.")

    def turn_off(profile):
        def run():
            state[profile] = "OFF"
            return (0, "Ok.")
        return run

    m.commands[("netsh", "advfirewall", "set", "allprofiles", "state", "on")] = turn_on
    for profile in ("domain", "private", "public"):
        m.commands[("netsh", "advfirewall", "set", f"{profile}profile", "state", "off")] = \
            turn_off(profile)
    return m, state


def test_windows_firewall_fix_and_undo_touch_only_the_profiles_that_were_off(store):
    m, state = _netsh_machine()
    engine = engine_for(m, store)
    result = engine.apply("FIX-WIN-FIREWALL", confirmed=True)
    assert result.outcome is Outcome.FIXED
    assert [c.setting for c in result.changes] == \
        ["Windows Firewall (private profile)", "Windows Firewall (public profile)"]
    assert result.check_status == "pass"

    engine.undo(result.record_id, confirmed=True)
    assert state == {"private": "OFF", "public": "OFF"}
    assert ["netsh", "advfirewall", "set", "domainprofile", "state", "off"] not in m.calls


def test_unreadable_netsh_output_changes_nothing(store):
    m = Machine()
    m.commands[("netsh", "advfirewall", "show", "allprofiles", "state")] = \
        (0, "Profil de domaine :\nÉtat    Actif\n")
    result = engine_for(m, store).apply("FIX-WIN-FIREWALL", confirmed=True)
    assert result.outcome is Outcome.FAILED
    assert all(call[2] == "show" for call in m.calls)


SSHD = "Include /etc/ssh/sshd_config.d/*.conf\nPort 22\nPermitRootLogin yes\n" \
       "PermitEmptyPasswords no\nMatch User backup\n    PasswordAuthentication yes\n"


def _ssh_machine(validate=(0, "")):
    m = Machine(os=OS.LINUX)
    m.files["/etc/ssh/sshd_config"] = SSHD
    m.commands[("sshd", "-t", "-f", "/etc/ssh/sshd_config")] = validate
    m.commands[("systemctl", "reload", "ssh")] = (0, "")
    m.commands[("ufw", "version")] = None
    return m


def test_ssh_fix_prepends_a_marked_block_validates_and_reloads(store):
    m = _ssh_machine()
    engine = engine_for(m, store)
    result = engine.apply("FIX-SSH-LOGIN", confirmed=True)
    assert result.outcome is Outcome.FIXED
    text = m.files["/etc/ssh/sshd_config"]
    assert text.startswith("# >>> Aegis hardening")
    block = text[:text.index("# <<< Aegis hardening")]
    assert "PermitRootLogin no" in block and "PermitEmptyPasswords" not in block
    assert text.endswith(SSHD)
    assert ["systemctl", "reload", "ssh"] in m.calls

    engine.undo(result.record_id, confirmed=True)
    assert m.files["/etc/ssh/sshd_config"] == SSHD


def test_ssh_fix_is_rolled_back_when_sshd_rejects_it(store):
    m = _ssh_machine(validate=(255, "line 2: Bad configuration option"))
    result = engine_for(m, store).apply("FIX-SSH-LOGIN", confirmed=True)
    assert result.outcome is Outcome.FAILED
    assert "rejected" in result.message
    assert m.files["/etc/ssh/sshd_config"] == SSHD


def test_ssh_fix_asks_for_a_restart_when_it_cannot_reload(store):
    m = _ssh_machine()
    m.commands[("systemctl", "reload", "ssh")] = (5, "not found")
    m.commands[("systemctl", "reload", "sshd")] = (5, "not found")
    result = engine_for(m, store).apply("FIX-SSH-LOGIN", confirmed=True)
    assert result.outcome is Outcome.FIXED
    assert "Restart the SSH service" in result.message


def test_file_permission_fix_removes_only_the_unsafe_bits(store):
    m = Machine(os=OS.LINUX)
    m.commands[("ufw", "version")] = None
    m.modes = {"/etc/shadow": stat.S_IFREG | 0o644, "/etc/passwd": stat.S_IFREG | 0o644,
               "/etc/sudoers": stat.S_IFREG | 0o442}
    engine = engine_for(m, store)
    result = engine.apply("FIX-FILE-PERMISSIONS", confirmed=True)
    assert result.outcome is Outcome.FIXED
    assert stat.S_IMODE(m.modes["/etc/shadow"]) == 0o640
    assert stat.S_IMODE(m.modes["/etc/sudoers"]) == 0o440
    assert stat.S_IMODE(m.modes["/etc/passwd"]) == 0o644

    engine.undo(result.record_id, confirmed=True)
    assert stat.S_IMODE(m.modes["/etc/shadow"]) == 0o644
    assert stat.S_IMODE(m.modes["/etc/sudoers"]) == 0o442


def _ufw_machine(ssh_rule_exists=False):
    m = Machine(os=OS.LINUX)
    state = {"active": False}
    m.commands[("ufw", "version")] = (0, "ufw 0.36")
    m.commands[("ufw", "status")] = lambda: (
        0, "Status: active\n" if state["active"] else "Status: inactive\n")
    m.commands[("ufw", "show", "added")] = (
        0, "Added user rules:\nufw allow 22/tcp\n" if ssh_rule_exists else "(None)\n")
    m.commands[("ufw", "allow", "22/tcp")] = (0, "Rules updated")
    m.commands[("ufw", "delete", "allow", "22/tcp")] = (0, "Rule deleted")

    def enable():
        state["active"] = True
        return (0, "Firewall is active")

    def disable():
        state["active"] = False
        return (0, "Firewall stopped")

    m.commands[("ufw", "--force", "enable")] = enable
    m.commands[("ufw", "--force", "disable")] = disable
    m.listening = [Listener("0.0.0.0", 22, "sshd")]
    return m, state


def test_ufw_fix_allows_ssh_before_enabling_and_undo_reverses_both(store):
    m, state = _ufw_machine()
    engine = engine_for(m, store)
    result = engine.apply("FIX-LINUX-UFW", confirmed=True)
    assert result.outcome is Outcome.FIXED and state["active"]
    assert m.calls.index(["ufw", "allow", "22/tcp"]) < m.calls.index(["ufw", "--force", "enable"])

    engine.undo(result.record_id, confirmed=True)
    assert not state["active"]
    assert ["ufw", "delete", "allow", "22/tcp"] in m.calls


def test_ufw_fix_leaves_an_existing_ssh_rule_alone(store):
    m, _ = _ufw_machine(ssh_rule_exists=True)
    engine = engine_for(m, store)
    result = engine.apply("FIX-LINUX-UFW", confirmed=True)
    engine.undo(result.record_id, confirmed=True)
    assert ["ufw", "allow", "22/tcp"] not in m.calls
    assert ["ufw", "delete", "allow", "22/tcp"] not in m.calls


def test_macos_firewall_fix(store):
    m = Machine(os=OS.MACOS)
    tool = "/usr/libexec/ApplicationFirewall/socketfilterfw"
    state = {"on": False}
    m.commands[(tool, "--getglobalstate")] = lambda: (
        0, "Firewall is enabled. (State = 1)" if state["on"]
        else "Firewall is disabled. (State = 0)")

    def set_state(on):
        def run():
            state["on"] = on
            return (0, "")
        return run

    m.commands[(tool, "--setglobalstate", "on")] = set_state(True)
    m.commands[(tool, "--setglobalstate", "off")] = set_state(False)
    engine = engine_for(m, store)
    result = engine.apply("FIX-MAC-FIREWALL", confirmed=True)
    assert result.outcome is Outcome.FIXED and state["on"]
    engine.undo(result.record_id, confirmed=True)
    assert not state["on"]


def test_every_fix_is_described_and_targets_a_real_check():
    checks = {c.check_id for c in default_checks()}
    fixes = default_fixes()
    assert len({f.fix_id for f in fixes}) == len(fixes)
    for fix in fixes:
        assert fix.check_id in checks, fix.fix_id
        assert fix.title and fix.risk and fix.effect, fix.fix_id
        assert fix.platforms, fix.fix_id


# --------------------------------------------------------------------------- #
# Storage
# --------------------------------------------------------------------------- #
def test_remediation_history_round_trips(store):
    rec_id = store.save_remediation(Remediation(
        fix_id="FIX-X", check_id="POSTURE-X", title="X", action="apply", status="fixed",
        changes=[{"setting": "s", "current": "a", "target": "b"}], backup={"k": [1, "v"]}))
    rec = store.remediation(rec_id)
    assert (rec.changes, rec.backup, rec.can_undo) == \
        ([{"setting": "s", "current": "a", "target": "b"}], {"k": [1, "v"]}, True)
    store.mark_remediation_undone(rec_id, rec.timestamp)
    assert not store.remediation(rec_id).can_undo
    assert store.remediation(rec_id + 1) is None


# --------------------------------------------------------------------------- #
# CLI
# --------------------------------------------------------------------------- #
@pytest.fixture
def cli_machine(tmp_path, monkeypatch):
    m = Machine()
    m.registry[("HKLM", SMB, "SMB1")] = 1
    monkeypatch.setattr(cli, "_hardening_engine", lambda: HardeningEngine(
        SQLiteEventStore(tmp_path / "cli.db"), ctx=m.context()))
    return m


def test_cli_dry_run_changes_nothing(cli_machine, capsys):
    assert cli.main(["harden", "apply", "FIX-WIN-SMB1", "--dry-run"]) == 0
    out = capsys.readouterr().out
    assert "SMB1: 1 -> 0" in out and "nothing was changed" in out
    assert cli_machine.registry[("HKLM", SMB, "SMB1")] == 1


def test_cli_refuses_without_confirmation_when_it_cannot_ask(cli_machine, capsys, monkeypatch):
    monkeypatch.setattr("sys.stdin.isatty", lambda: False)
    assert cli.main(["harden", "apply", "FIX-WIN-SMB1"]) == 1
    assert cli_machine.registry[("HKLM", SMB, "SMB1")] == 1
    assert "--yes" in capsys.readouterr().err


def test_cli_apply_history_and_undo(cli_machine, capsys):
    assert cli.main(["harden", "apply", "FIX-WIN-SMB1", "--yes"]) == 0
    assert cli_machine.registry[("HKLM", SMB, "SMB1")] == 0
    assert "FIXED" in capsys.readouterr().out

    assert cli.main(["harden", "history", "--json"]) == 0
    history = json.loads(capsys.readouterr().out)
    assert history[0]["fix_id"] == "FIX-WIN-SMB1" and history[0]["can_undo"]

    assert cli.main(["harden", "undo", str(history[0]["id"]), "--yes"]) == 0
    assert cli_machine.registry[("HKLM", SMB, "SMB1")] == 1


def test_cli_lists_fixes_for_weak_checks(cli_machine, capsys):
    assert cli.main(["harden"]) == 0
    out = capsys.readouterr().out
    assert "Fix FIX-WIN-SMB1" in out and "aegis harden apply" in out


def test_cli_unknown_fix(cli_machine, capsys):
    assert cli.main(["harden", "apply", "FIX-NOPE", "--yes"]) == 2
