"""The account, service and screen-lock checks, and the fixes that go with them.

Every check reads through a PostureContext, so these run on any OS without
touching the machine under test.
"""
import pytest

from aegis.core.models import Severity
from aegis.hardening import HardeningEngine, Outcome
from aegis.platforms import OS
from aegis.posture.base import CheckStatus, PostureContext
from aegis.posture.checks import (
    GuestAccountCheck,
    PasswordPolicyCheck,
    RiskyServicesCheck,
    ScreenLockCheck,
)
from aegis.response.command import RunResult
from aegis.storage.database import SQLiteEventStore
from tests.test_hardening import Machine

NET_ACCOUNTS = """
Force user logoff how long after time expires?:       Never
Minimum password age (days):                          0
Maximum password age (days):                          42
Minimum password length:                              {length}
Length of password history maintained:                None
Lockout threshold:                                    {lockout}
Lockout duration (minutes):                           30
The command completed successfully.
"""
NET_USER_GUEST = """
User name                    Guest
Account active               {active}
Local Group Memberships      *Guests
The command completed successfully.
"""


def _ctx(os=OS.WINDOWS, commands=None, texts=None, registry=None):
    commands = commands or {}
    texts = texts or {}

    def runner(args, timeout):
        answer = commands.get(tuple(args))
        if answer is None:
            raise FileNotFoundError(args[0])
        return RunResult(answer[0], answer[1].encode())

    return PostureContext(os=os, elevated=True, runner=runner, listeners=lambda: [],
                          read_text=texts.get, stat_mode=lambda p: None,
                          read_registry=lambda k, n: None,
                          registry_values=lambda hive, key: (registry or {}).get((hive, key)),
                          glob=lambda p: [], env=lambda n: None)


# --------------------------------------------------------------------------- #
# Password policy
# --------------------------------------------------------------------------- #
def _policy_ctx(length, lockout):
    return _ctx(commands={("net", "accounts"):
                          (0, NET_ACCOUNTS.format(length=length, lockout=lockout))})


def test_short_passwords_and_no_lockout_fail():
    result = PasswordPolicyCheck().run(_policy_ctx(0, "Never"))
    assert result.status is CheckStatus.FAIL
    assert "may be empty" in " ".join(result.details).lower()
    assert "never locked" in " ".join(result.details).lower()
    assert "net accounts" in result.remediation


def test_a_sensible_policy_passes():
    assert PasswordPolicyCheck().run(_policy_ctx(12, 5)).status is CheckStatus.PASS


def test_a_high_lockout_threshold_is_flagged():
    result = PasswordPolicyCheck().run(_policy_ctx(12, 50))
    assert result.status is CheckStatus.FAIL
    assert "50 wrong passwords" in " ".join(result.details)


def test_an_unreadable_policy_is_skipped():
    assert PasswordPolicyCheck().run(_ctx()).status is CheckStatus.SKIP


def test_linux_password_policy_reads_login_defs():
    ctx = _ctx(os=OS.LINUX, texts={"/etc/login.defs": "PASS_MAX_DAYS 99999\nPASS_MIN_LEN 4\n"})
    result = PasswordPolicyCheck().run(ctx)
    assert result.status is CheckStatus.FAIL
    assert "4 characters" in " ".join(result.details)


def test_linux_password_policy_without_login_defs_is_skipped():
    assert PasswordPolicyCheck().run(_ctx(os=OS.LINUX)).status is CheckStatus.SKIP


# --------------------------------------------------------------------------- #
# Guest account
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize(("active", "status"), [("Yes", CheckStatus.FAIL),
                                                ("No", CheckStatus.PASS)])
def test_guest_account_state_is_read(active, status):
    ctx = _ctx(commands={("net", "user", "Guest"): (0, NET_USER_GUEST.format(active=active))})
    assert GuestAccountCheck().run(ctx).status is status


def test_no_guest_account_at_all_is_skipped():
    ctx = _ctx(commands={("net", "user", "Guest"): (2, "The user name could not be found.")})
    assert GuestAccountCheck().run(ctx).status is CheckStatus.SKIP


# --------------------------------------------------------------------------- #
# Risky services
# --------------------------------------------------------------------------- #
def _services_ctx(output, code=1):
    check = RiskyServicesCheck()
    names = ",".join({**check.UNSAFE, **check.QUESTIONABLE})
    command = ("powershell", "-NoProfile", "-NonInteractive", "-Command",
               check._SCRIPT.format(names=names))
    return check, _ctx(commands={command: (code, output)})


def test_a_cleartext_service_running_fails():
    check, ctx = _services_ctx("TlntSvr=Running\nRemoteRegistry=Stopped\n")
    result = check.run(ctx)
    assert result.status is CheckStatus.FAIL
    assert "Telnet" in " ".join(result.details)


def test_a_questionable_service_only_warns():
    check, ctx = _services_ctx("SharedAccess=Running\n")
    result = check.run(ctx)
    assert result.status is CheckStatus.WARN
    assert result.severity is Severity.MEDIUM


def test_nothing_running_passes_even_though_powershell_exits_non_zero():
    check, ctx = _services_ctx("RemoteRegistry=Stopped\n", code=1)
    assert check.run(ctx).status is CheckStatus.PASS


def test_services_that_cannot_be_read_are_skipped():
    check = RiskyServicesCheck()
    assert check.run(_ctx()).status is CheckStatus.SKIP


# --------------------------------------------------------------------------- #
# Screen lock
# --------------------------------------------------------------------------- #
def _screen_ctx(**values):
    return _ctx(registry={("HKCU", ScreenLockCheck._DESKTOP): values})


def test_no_screen_lock_fails():
    assert ScreenLockCheck().run(_screen_ctx(ScreenSaveActive="0")).status is CheckStatus.FAIL


def test_a_screen_saver_without_a_password_fails():
    result = ScreenLockCheck().run(_screen_ctx(ScreenSaveActive="1", ScreenSaverIsSecure="0",
                                               ScreenSaveTimeOut="600"))
    assert result.status is CheckStatus.FAIL


def test_a_long_wait_only_warns():
    result = ScreenLockCheck().run(_screen_ctx(ScreenSaveActive="1", ScreenSaverIsSecure="1",
                                               ScreenSaveTimeOut="3600"))
    assert result.status is CheckStatus.WARN
    assert "60 minutes" in result.summary


def test_a_locking_screen_passes():
    result = ScreenLockCheck().run(_screen_ctx(ScreenSaveActive="1", ScreenSaverIsSecure="1",
                                               ScreenSaveTimeOut="600"))
    assert result.status is CheckStatus.PASS
    assert "10 minute" in result.summary


def test_unreadable_screen_settings_are_skipped():
    assert ScreenLockCheck().run(_ctx()).status is CheckStatus.SKIP


# --------------------------------------------------------------------------- #
# The fixes for these checks
# --------------------------------------------------------------------------- #
@pytest.fixture
def store(tmp_path):
    s = SQLiteEventStore(tmp_path / "harden.db")
    yield s
    s.close()


def test_screen_lock_fix_writes_this_users_settings_and_needs_no_admin(store):
    machine = Machine(elevated=False)
    machine.registry[("HKCU", ScreenLockCheck._DESKTOP, "ScreenSaveActive")] = "0"
    engine = HardeningEngine(store, ctx=machine.context())

    result = engine.apply("FIX-WIN-SCREEN-LOCK", confirmed=True)
    assert result.outcome is Outcome.FIXED       # not refused, despite no admin rights
    desktop = ScreenLockCheck._DESKTOP
    assert machine.registry[("HKCU", desktop, "ScreenSaveActive")] == "1"
    assert machine.registry[("HKCU", desktop, "ScreenSaverIsSecure")] == "1"
    assert machine.registry[("HKCU", desktop, "ScreenSaveTimeOut")] == "600"

    engine.undo(result.record_id, confirmed=True)
    assert machine.registry[("HKCU", desktop, "ScreenSaveActive")] == "0"


def test_guest_account_fix_turns_it_off_and_back_on(store):
    machine = Machine()
    state = {"active": "Yes"}
    machine.commands[("net", "user", "Guest")] = lambda: (
        0, NET_USER_GUEST.format(active=state["active"]))

    def switch(value):
        def run():
            state["active"] = value
            return (0, "The command completed successfully.")
        return run

    machine.commands[("net", "user", "Guest", "/active:no")] = switch("No")
    machine.commands[("net", "user", "Guest", "/active:yes")] = switch("Yes")
    engine = HardeningEngine(store, ctx=machine.context())

    result = engine.apply("FIX-WIN-GUEST", confirmed=True)
    assert result.outcome is Outcome.FIXED and state["active"] == "No"
    assert result.check_status == "pass"

    engine.undo(result.record_id, confirmed=True)
    assert state["active"] == "Yes"


def test_password_policy_fix_sets_length_and_lockout(store):
    machine = Machine()
    state = {"length": "0", "lockout": "Never"}
    machine.commands[("net", "accounts")] = lambda: (
        0, NET_ACCOUNTS.format(**state))

    def applied(args):
        def run():
            for arg in args:
                if arg.startswith("/minpwlen:"):
                    state["length"] = arg.split(":")[1]
                if arg.startswith("/lockoutthreshold:"):
                    state["lockout"] = arg.split(":")[1]
            return (0, "The command completed successfully.")
        return run

    for args in (["net", "accounts", "/minpwlen:12", "/lockoutthreshold:5",
                  "/lockoutduration:15", "/lockoutwindow:15"],
                 ["net", "accounts", "/minpwlen:0", "/lockoutthreshold:0"]):
        machine.commands[tuple(args)] = applied(args)
    engine = HardeningEngine(store, ctx=machine.context())

    preview = engine.preview("FIX-WIN-PASSWORD-POLICY")
    assert [c.setting for c in preview.changes] == ["Shortest allowed password",
                                                    "Account locks after"]
    result = engine.apply("FIX-WIN-PASSWORD-POLICY", confirmed=True)
    assert result.outcome is Outcome.FIXED
    assert state == {"length": "12", "lockout": "5"}

    engine.undo(result.record_id, confirmed=True)
    assert state == {"length": "0", "lockout": "0"}
