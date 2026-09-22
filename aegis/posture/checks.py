"""The built-in posture checks.

Each check targets a misconfiguration that is common, exploited in practice,
and fixable by an ordinary user or administrator. Output strings stay ASCII so
they print cleanly on any console code page.
"""
from __future__ import annotations

import ipaddress
import re
import stat
from datetime import datetime

from aegis.core.models import Severity
from aegis.platforms import OS
from aegis.posture.base import CheckResult, CheckStatus, PostureCheck, PostureContext

_WINDOWS = (OS.WINDOWS,)
_POSIX = (OS.LINUX, OS.MACOS)


def _as_int(value) -> int | None:
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _after(text: str, pattern: str, multiline: bool = False) -> str | None:
    """The first capture of ``pattern`` in ``text``, or None."""
    match = re.search(pattern, text or "", re.MULTILINE if multiline else 0)
    return match.group(1) if match else None


# --------------------------------------------------------------------------- #
# Network
# --------------------------------------------------------------------------- #
class FirewallEnabledCheck(PostureCheck):
    check_id = "POSTURE-FIREWALL"
    title = "Host firewall is enabled"
    category = "Network"
    severity = Severity.HIGH

    def run(self, ctx: PostureContext) -> CheckResult:
        if ctx.os is OS.WINDOWS:
            return self._windows(ctx)
        if ctx.os is OS.MACOS:
            return self._macos(ctx)
        if ctx.os is OS.LINUX:
            return self._linux(ctx)
        return self.result(CheckStatus.SKIP, "Unsupported platform.")

    def _windows(self, ctx: PostureContext) -> CheckResult:
        out = ctx.run(["netsh", "advfirewall", "show", "allprofiles", "state"])
        if out is None:
            return self.result(CheckStatus.SKIP, "netsh is not available.")
        text = out[1]
        names = re.findall(r"^\s*(\w+) Profile Settings", text, re.MULTILINE)
        states = re.findall(r"^\s*State\s+(ON|OFF)\s*$", text, re.IGNORECASE | re.MULTILINE)
        if not states:
            return self.result(CheckStatus.SKIP,
                               "Could not read the firewall state (unrecognised netsh output).")
        if len(names) != len(states):
            names = [f"profile {i + 1}" for i in range(len(states))]
        off = [name for name, state in zip(names, states, strict=True) if state.upper() == "OFF"]
        if off:
            return self.result(
                CheckStatus.FAIL,
                f"Windows Firewall is OFF for the {', '.join(off)} profile(s).",
                remediation="Open Windows Security > Firewall & network protection and turn the "
                            "firewall on for every profile, or run as Administrator: "
                            "netsh advfirewall set allprofiles state on")
        return self.result(CheckStatus.PASS,
                           f"Windows Firewall is on for all {len(states)} profiles.")

    def _macos(self, ctx: PostureContext) -> CheckResult:
        out = ctx.run(["/usr/libexec/ApplicationFirewall/socketfilterfw", "--getglobalstate"])
        if out is None:
            return self.result(CheckStatus.SKIP, "The application firewall tool is not available.")
        text = out[1].lower()
        if "disabled" in text or "state = 0" in text:
            return self.result(
                CheckStatus.FAIL, "The macOS application firewall is off.",
                remediation="System Settings > Network > Firewall > On, or: sudo "
                            "/usr/libexec/ApplicationFirewall/socketfilterfw --setglobalstate on")
        if "enabled" in text:
            return self.result(CheckStatus.PASS, "The macOS application firewall is on.")
        return self.result(CheckStatus.SKIP, "Could not read the application firewall state.")

    def _linux(self, ctx: PostureContext) -> CheckResult:
        firewalld = ctx.run(["firewall-cmd", "--state"])
        if firewalld and firewalld[0] == 0 and "running" in firewalld[1]:
            return self.result(CheckStatus.PASS, "firewalld is running.")

        ufw = ctx.run(["ufw", "status"])
        if ufw and ufw[0] == 0:
            if re.search(r"Status:\s*active", ufw[1]):
                return self.result(CheckStatus.PASS, "ufw is active.")
            if re.search(r"Status:\s*inactive", ufw[1]):
                return self.result(
                    CheckStatus.FAIL, "ufw is installed but inactive.",
                    remediation="Allow SSH first if this is a remote machine "
                                "(sudo ufw allow OpenSSH), then: sudo ufw enable")

        nft = ctx.run(["nft", "list", "ruleset"])
        if nft and nft[0] == 0:
            if re.search(r"^\s*chain\s", nft[1], re.MULTILINE):
                return self.result(CheckStatus.PASS, "nftables has an active rule set.")
            return self.result(
                CheckStatus.FAIL, "No nftables rules are loaded, so traffic is unfiltered.",
                remediation="Enable a firewall: sudo ufw enable (Debian/Ubuntu) or "
                            "sudo systemctl enable --now firewalld (Fedora/RHEL).")

        if not ctx.elevated:
            return self.result(CheckStatus.SKIP,
                               "The firewall state needs root to read; re-run with sudo.")
        return self.result(
            CheckStatus.WARN, "No ufw, firewalld or nftables firewall was detected.",
            remediation="Install and enable a host firewall such as ufw or firewalld.")


# Services that ship without authentication (or in cleartext): reachable from
# the network, they are routinely found and taken over by internet scanners.
_UNSAFE_SERVICES = {
    23: "Telnet",
    2375: "Docker API (no TLS)",
    6379: "Redis",
    9200: "Elasticsearch",
    11211: "Memcached",
    27017: "MongoDB",
}
# Legitimate when intended, but high-value targets that should rarely face a network.
_SENSITIVE_SERVICES = {
    21: "FTP",
    1433: "SQL Server",
    3306: "MySQL",
    3389: "Remote Desktop",
    5432: "PostgreSQL",
    5900: "VNC",
    5985: "WinRM",
}
# SMB listens on every Windows install by default; on Linux/macOS it means a
# file server was deliberately started and is worth a second look.
_POSIX_SENSITIVE = {445: "SMB file sharing"}


def _is_loopback(ip: str) -> bool:
    try:
        return ipaddress.ip_address(ip.split("%", 1)[0]).is_loopback
    except ValueError:
        return False


class ExposedServicesCheck(PostureCheck):
    check_id = "POSTURE-EXPOSED-SERVICES"
    title = "No risky services exposed to the network"
    category = "Network"
    severity = Severity.HIGH
    remediation = ("Stop services you do not use. For the rest, bind them to 127.0.0.1, "
                   "require authentication, and restrict the port to trusted addresses "
                   "in the host firewall.")

    def run(self, ctx: PostureContext) -> CheckResult:
        listeners = ctx.listeners()
        if not listeners:
            return self.result(CheckStatus.SKIP,
                               "Could not enumerate listening sockets (try running elevated).")

        sensitive = dict(_SENSITIVE_SERVICES)
        if ctx.os is not OS.WINDOWS:
            sensitive.update(_POSIX_SENSITIVE)

        unsafe: list[str] = []
        risky: list[str] = []
        seen: set[tuple[int, str]] = set()
        for sock in listeners:
            if _is_loopback(sock.ip) or (sock.port, sock.process) in seen:
                continue
            seen.add((sock.port, sock.process))
            where = "all interfaces" if sock.ip in ("", "0.0.0.0", "::") else sock.ip
            owner = sock.process or "unknown process"
            if sock.port in _UNSAFE_SERVICES:
                unsafe.append(f"{_UNSAFE_SERVICES[sock.port]} on port {sock.port} "
                              f"({owner}) listening on {where}")
            elif sock.port in sensitive:
                risky.append(f"{sensitive[sock.port]} on port {sock.port} "
                             f"({owner}) listening on {where}")

        if unsafe:
            return self.result(
                CheckStatus.FAIL,
                f"{len(unsafe)} service(s) that allow unauthenticated or cleartext access "
                f"are reachable from the network.",
                unsafe + risky)
        if risky:
            return self.result(
                CheckStatus.WARN,
                f"{len(risky)} remote-access or database service(s) listen on network interfaces.",
                risky, severity=Severity.MEDIUM)
        return self.result(CheckStatus.PASS,
                           f"No high-risk services exposed ({len(listeners)} listening "
                           f"sockets reviewed).")


# --------------------------------------------------------------------------- #
# Windows
# --------------------------------------------------------------------------- #
class DefenderRealtimeCheck(PostureCheck):
    check_id = "POSTURE-DEFENDER"
    title = "Antivirus real-time protection is on"
    category = "Malware protection"
    severity = Severity.HIGH
    platforms = _WINDOWS
    remediation = ("Windows Security > Virus & threat protection > Manage settings > "
                   "turn Real-time protection on.")

    def run(self, ctx: PostureContext) -> CheckResult:
        out = ctx.run(["powershell", "-NoProfile", "-NonInteractive", "-Command",
                       "(Get-MpComputerStatus).RealTimeProtectionEnabled"], timeout=30)
        answer = out[1].strip().splitlines()[-1].strip().lower() if out and out[1].strip() else ""
        if answer == "true":
            return self.result(CheckStatus.PASS, "Microsoft Defender real-time protection is on.")
        if answer == "false":
            return self.result(CheckStatus.FAIL,
                               "Microsoft Defender real-time protection is OFF.")
        return self.result(CheckStatus.SKIP,
                           "Could not query Microsoft Defender (expected if another "
                           "antivirus product is installed).")


class UserAccountControlCheck(PostureCheck):
    check_id = "POSTURE-UAC"
    title = "User Account Control is enabled"
    category = "Privilege"
    severity = Severity.HIGH
    platforms = _WINDOWS
    _KEY = r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"

    def run(self, ctx: PostureContext) -> CheckResult:
        lua = _as_int(ctx.read_registry(self._KEY, "EnableLUA"))
        if lua is None:
            return self.result(CheckStatus.SKIP, "Could not read the UAC setting.")
        if lua == 0:
            return self.result(
                CheckStatus.FAIL,
                "UAC is disabled: every program an administrator runs gets full control.",
                remediation="Search 'Change User Account Control settings', set the slider to "
                            "the default level, and restart.")
        prompt = _as_int(ctx.read_registry(self._KEY, "ConsentPromptBehaviorAdmin"))
        if prompt == 0:
            return self.result(
                CheckStatus.WARN,
                "UAC elevates administrators without asking, so malware can silently gain "
                "admin rights.",
                remediation="Search 'Change User Account Control settings' and move the slider "
                            "up to 'Notify me only when apps try to make changes'.")
        return self.result(CheckStatus.PASS, "UAC is enabled and prompts before elevation.")


class RemoteDesktopCheck(PostureCheck):
    check_id = "POSTURE-RDP"
    title = "Remote Desktop is off or protected"
    category = "Remote access"
    severity = Severity.MEDIUM
    platforms = _WINDOWS
    _TS = r"SYSTEM\CurrentControlSet\Control\Terminal Server"
    _RDP_TCP = _TS + r"\WinStations\RDP-Tcp"

    def run(self, ctx: PostureContext) -> CheckResult:
        deny = _as_int(ctx.read_registry(self._TS, "fDenyTSConnections"))
        if deny is None:
            return self.result(CheckStatus.SKIP, "Could not read the Remote Desktop setting.")
        if deny == 1:
            return self.result(CheckStatus.PASS, "Remote Desktop is disabled.")
        # The setting alone over-reports: Home editions keep it but cannot host
        # sessions. Only a live listener on the RDP port proves exposure.
        port = _as_int(ctx.read_registry(self._RDP_TCP, "PortNumber")) or 3389
        listeners = ctx.listeners()
        if listeners and not any(sock.port == port for sock in listeners):
            return self.result(CheckStatus.PASS,
                               f"Remote Desktop is allowed in settings, but nothing is "
                               f"accepting connections on port {port}.")
        nla = _as_int(ctx.read_registry(self._RDP_TCP, "UserAuthentication"))
        if nla == 0:
            return self.result(
                CheckStatus.FAIL,
                "Remote Desktop is enabled WITHOUT Network Level Authentication.",
                severity=Severity.HIGH,
                remediation="Settings > System > Remote Desktop > Advanced settings > require "
                            "Network Level Authentication, or turn Remote Desktop off.")
        return self.result(
            CheckStatus.WARN, "Remote Desktop is enabled.",
            remediation="Turn it off if unused (Settings > System > Remote Desktop). Never "
                        "expose port 3389 to the internet; reach it through a VPN instead.")


class SMBv1Check(PostureCheck):
    check_id = "POSTURE-SMB1"
    title = "SMBv1 is disabled"
    category = "Network"
    severity = Severity.HIGH
    platforms = _WINDOWS
    remediation = ("Run as Administrator in PowerShell: "
                   "Disable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol")
    _SERVER = r"SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters"
    _CLIENT = r"SYSTEM\CurrentControlSet\Services\mrxsmb10"
    _DISABLED_START = 4

    def run(self, ctx: PostureContext) -> CheckResult:
        if _as_int(ctx.read_registry(self._SERVER, "SMB1")) == 1:
            return self.result(
                CheckStatus.FAIL,
                "The SMBv1 server is enabled; this is the protocol WannaCry and NotPetya spread over.")
        client_start = _as_int(ctx.read_registry(self._CLIENT, "Start"))
        if client_start is not None and client_start != self._DISABLED_START:
            return self.result(CheckStatus.WARN, "The SMBv1 client driver is installed and enabled.",
                               severity=Severity.MEDIUM)
        return self.result(CheckStatus.PASS, "SMBv1 is not enabled.")


class AutoLogonCheck(PostureCheck):
    check_id = "POSTURE-AUTOLOGON"
    title = "No automatic logon with a stored password"
    category = "Credentials"
    severity = Severity.HIGH
    platforms = _WINDOWS
    remediation = ("Turn off automatic sign-in (run netplwiz and tick 'Users must enter a user "
                   "name and password') and change the password that was stored.")
    _KEY = r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"

    def run(self, ctx: PostureContext) -> CheckResult:
        enabled = str(ctx.read_registry(self._KEY, "AutoAdminLogon") or "").strip() == "1"
        if not enabled:
            return self.result(CheckStatus.PASS, "Automatic logon is not configured.")
        if ctx.read_registry(self._KEY, "DefaultPassword"):
            return self.result(
                CheckStatus.FAIL,
                "Automatic logon is on and the password is stored in plaintext in the registry.")
        return self.result(CheckStatus.WARN,
                           "Automatic logon is on: anyone with physical access gets a session.",
                           severity=Severity.MEDIUM)


# --------------------------------------------------------------------------- #
# Data protection
# --------------------------------------------------------------------------- #
# System.Volume.BitLockerProtection shell property values.
_BITLOCKER_ON = {1, 3, 6}
_BITLOCKER_OFF = 2
_BITLOCKER_SUSPENDED = {4, 5}


class DiskEncryptionCheck(PostureCheck):
    check_id = "POSTURE-DISK-ENCRYPTION"
    title = "System disk is encrypted"
    category = "Data protection"
    severity = Severity.MEDIUM

    def run(self, ctx: PostureContext) -> CheckResult:
        if ctx.os is OS.WINDOWS:
            return self._windows(ctx)
        if ctx.os is OS.MACOS:
            return self._macos(ctx)
        if ctx.os is OS.LINUX:
            return self._linux(ctx)
        return self.result(CheckStatus.SKIP, "Unsupported platform.")

    def _windows(self, ctx: PostureContext) -> CheckResult:
        drive = (ctx.env("SystemDrive") or "C:").strip()
        if not re.fullmatch(r"[A-Za-z]:", drive):
            drive = "C:"
        # The shell property is readable without Administrator, unlike manage-bde.
        script = (f"(New-Object -ComObject Shell.Application).NameSpace('{drive}')"
                  f".Self.ExtendedProperty('System.Volume.BitLockerProtection')")
        out = ctx.run(["powershell", "-NoProfile", "-NonInteractive", "-Command", script],
                      timeout=30)
        value = _as_int(out[1].strip()) if out else None
        if value in _BITLOCKER_ON:
            return self.result(CheckStatus.PASS, f"BitLocker protects {drive}.")
        if value in _BITLOCKER_SUSPENDED:
            return self.result(
                CheckStatus.WARN, f"BitLocker on {drive} is suspended or decrypting.",
                remediation="Resume protection: Control Panel > BitLocker Drive Encryption.")
        if value == _BITLOCKER_OFF:
            return self.result(
                CheckStatus.FAIL, f"{drive} is not encrypted.",
                remediation="Turn on BitLocker (Pro editions) or Device encryption "
                            "(Settings > Privacy & security) so a lost or stolen device "
                            "does not expose your files.")
        return self.result(CheckStatus.SKIP, "Could not determine BitLocker status.")

    def _macos(self, ctx: PostureContext) -> CheckResult:
        out = ctx.run(["fdesetup", "status"])
        text = out[1] if out else ""
        if "FileVault is On" in text or "Encryption in progress" in text:
            return self.result(CheckStatus.PASS, "FileVault is on.")
        if "FileVault is Off" in text:
            return self.result(
                CheckStatus.FAIL, "FileVault is off.",
                remediation="System Settings > Privacy & Security > FileVault > Turn On.")
        return self.result(CheckStatus.SKIP, "Could not determine FileVault status.")

    def _linux(self, ctx: PostureContext) -> CheckResult:
        out = ctx.run(["lsblk", "-rno", "TYPE"])
        if out is None or out[0] != 0:
            return self.result(CheckStatus.SKIP, "Could not list block devices.")
        if "crypt" in {line.strip() for line in out[1].splitlines()}:
            return self.result(CheckStatus.PASS, "A LUKS-encrypted volume is in use.")
        return self.result(
            CheckStatus.WARN, "No encrypted volumes were found.",
            remediation="Use LUKS full-disk encryption on laptops and on any machine holding "
                        "sensitive data (normally chosen when installing the OS).")


# --------------------------------------------------------------------------- #
# POSIX
# --------------------------------------------------------------------------- #
_SSHD_LINE = re.compile(r"^(\S+?)(?:\s*=\s*|\s+)(.*)$")


def sshd_options(ctx: PostureContext, text: str, base_dir: str = "/etc/ssh",
                 depth: int = 0) -> dict[str, str]:
    """Effective global sshd options. sshd takes the first value it reads for
    each keyword, so earlier lines (and earlier Includes) win."""
    options: dict[str, str] = {}
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        match = _SSHD_LINE.match(line)
        if not match:
            continue
        key, value = match.group(1).lower(), match.group(2).strip()
        if key == "match":
            break  # everything after applies only to matching connections
        if key == "include":
            if depth >= 3:
                continue
            for pattern in value.split():
                if not pattern.startswith("/"):
                    pattern = f"{base_dir}/{pattern}"
                for path in sorted(ctx.glob(pattern)):
                    included = ctx.read_text(path)
                    if included is None:
                        continue
                    for k, v in sshd_options(ctx, included, base_dir, depth + 1).items():
                        options.setdefault(k, v)
            continue
        options.setdefault(key, value.lower())
    return options


class SSHHardeningCheck(PostureCheck):
    check_id = "POSTURE-SSH"
    title = "SSH server refuses risky logins"
    category = "Remote access"
    severity = Severity.HIGH
    platforms = _POSIX
    CONFIG = "/etc/ssh/sshd_config"
    remediation = ("In /etc/ssh/sshd_config set 'PermitRootLogin no', "
                   "'PasswordAuthentication no' (after installing an SSH key) and "
                   "'PermitEmptyPasswords no', then restart sshd.")

    def run(self, ctx: PostureContext) -> CheckResult:
        text = ctx.read_text(self.CONFIG)
        if text is None:
            return self.result(CheckStatus.SKIP, "No OpenSSH server configuration found.")
        options = sshd_options(ctx, text)

        failures: list[str] = []
        warnings: list[str] = []
        if options.get("permitemptypasswords") == "yes":
            failures.append("PermitEmptyPasswords yes: accounts without a password can log in")
        if options.get("permitrootlogin") == "yes":
            failures.append("PermitRootLogin yes: root can log in with a password")
        password = options.get("passwordauthentication")
        if password is None:
            warnings.append("PasswordAuthentication is not set (OpenSSH defaults to yes), "
                            "leaving logins open to password guessing")
        elif password == "yes":
            warnings.append("PasswordAuthentication yes: logins are open to password guessing")

        if failures:
            return self.result(CheckStatus.FAIL, "sshd allows dangerous logins.",
                               failures + warnings)
        if warnings:
            return self.result(CheckStatus.WARN, "sshd accepts password logins.", warnings,
                               severity=Severity.MEDIUM)
        return self.result(CheckStatus.PASS, "sshd refuses root and password logins.")


class SensitiveFilePermissionsCheck(PostureCheck):
    check_id = "POSTURE-FILE-PERMISSIONS"
    title = "Account and privilege files have safe permissions"
    category = "Privilege"
    severity = Severity.HIGH
    platforms = _POSIX
    remediation = ("Restore the defaults: sudo chmod 644 /etc/passwd; sudo chmod 640 "
                   "/etc/shadow; sudo chmod 440 /etc/sudoers; sudo chmod 644 "
                   "/etc/ssh/sshd_config")
    FILES: tuple[tuple[str, int, str], ...] = (
        ("/etc/passwd", stat.S_IWOTH, "writable by every user"),
        ("/etc/shadow", stat.S_IROTH | stat.S_IWOTH, "readable or writable by every user"),
        ("/etc/sudoers", stat.S_IWOTH, "writable by every user"),
        ("/etc/ssh/sshd_config", stat.S_IWOTH, "writable by every user"),
    )

    def run(self, ctx: PostureContext) -> CheckResult:
        checked = 0
        problems: list[str] = []
        for path, mask, description in self.FILES:
            mode = ctx.stat_mode(path)
            if mode is None:
                continue
            checked += 1
            if mode & mask:
                problems.append(f"{path} is {description} (mode {stat.S_IMODE(mode):o})")
        if not checked:
            return self.result(CheckStatus.SKIP, "None of the sensitive files could be inspected.")
        if problems:
            return self.result(CheckStatus.FAIL,
                               "Files that control accounts or privileges are exposed.", problems)
        return self.result(CheckStatus.PASS, f"{checked} sensitive files have safe permissions.")


# --------------------------------------------------------------------------- #
# Patching
# --------------------------------------------------------------------------- #
class SystemUpdatesCheck(PostureCheck):
    check_id = "POSTURE-UPDATES"
    title = "Operating system updates are current"
    category = "Patching"
    severity = Severity.HIGH
    platforms = (OS.WINDOWS, OS.LINUX)
    #: Windows ships security fixes monthly; two missed cycles is a failure.
    WARN_DAYS = 35
    FAIL_DAYS = 60
    _HOTFIX_SCRIPT = (
        "$h = Get-HotFix | Where-Object { $_.InstalledOn } | Sort-Object InstalledOn "
        "-Descending | Select-Object -First 1; "
        "if ($h) { $h.InstalledOn.ToString('yyyy-MM-dd') + ' ' + $h.HotFixID }")

    def run(self, ctx: PostureContext) -> CheckResult:
        return self._windows(ctx) if ctx.os is OS.WINDOWS else self._linux(ctx)

    def _windows(self, ctx: PostureContext) -> CheckResult:
        out = ctx.run(["powershell", "-NoProfile", "-NonInteractive", "-Command",
                       self._HOTFIX_SCRIPT], timeout=60)
        match = re.search(r"(\d{4}-\d{2}-\d{2})\s+(\S+)", out[1]) if out else None
        if not match:
            return self.result(CheckStatus.SKIP, "Could not read the Windows update history.")
        days = (ctx.now() - datetime.strptime(match.group(1), "%Y-%m-%d")).days
        details = [f"Most recent update: {match.group(2)}, installed {match.group(1)}"]
        fix = "Open Settings > Windows Update, install everything offered, and restart."
        if days > self.FAIL_DAYS:
            return self.result(CheckStatus.FAIL,
                               f"No Windows update has been installed for {days} days.",
                               details, remediation=fix)
        if days > self.WARN_DAYS:
            return self.result(CheckStatus.WARN,
                               f"The last Windows update was installed {days} days ago.",
                               details, remediation=fix, severity=Severity.MEDIUM)
        return self.result(CheckStatus.PASS,
                           f"Windows was updated {max(days, 0)} day(s) ago.", details)

    def _linux(self, ctx: PostureContext) -> CheckResult:
        reboot_pending = ctx.read_text("/var/run/reboot-required") is not None

        apt = ctx.run(["apt", "list", "--upgradable"], timeout=60)
        if apt and apt[0] == 0:
            pending = [line for line in apt[1].splitlines() if "[upgradable" in line]
            security = [line.split("/", 1)[0] for line in pending if "-security" in line]
            return self._package_verdict(
                len(pending), security, reboot_pending,
                fix="Run: sudo apt update && sudo apt upgrade, then restart if asked. "
                    "Enable automatic security updates with: sudo apt install "
                    "unattended-upgrades")

        # -C uses the local metadata cache: fast, and no network access.
        dnf = ctx.run(["dnf", "-C", "-q", "check-update"], timeout=60)
        if dnf and dnf[0] in (0, 100):
            count = 0
            if dnf[0] == 100:
                count = sum(1 for line in dnf[1].splitlines()
                            if line.strip() and not line.startswith(" "))
            return self._package_verdict(count, [], reboot_pending,
                                         fix="Run: sudo dnf upgrade, then restart if asked.")

        return self.result(CheckStatus.SKIP, "No supported package manager (apt, dnf) was found.")

    def _package_verdict(self, pending: int, security: list[str], reboot_pending: bool,
                         fix: str) -> CheckResult:
        details: list[str] = []
        if security:
            shown = ", ".join(security[:10]) + (" ..." if len(security) > 10 else "")
            details.append(f"Security updates: {shown}")
        if reboot_pending:
            details.append("A restart is required to finish installing updates")
        if security:
            return self.result(CheckStatus.FAIL,
                               f"{len(security)} security update(s) are waiting to be installed.",
                               details, remediation=fix)
        if pending:
            return self.result(CheckStatus.WARN, f"{pending} package update(s) are waiting.",
                               details, remediation=fix, severity=Severity.MEDIUM)
        if reboot_pending:
            return self.result(CheckStatus.WARN,
                               "Updates are installed but a restart is still required.",
                               details, remediation="Restart the machine.",
                               severity=Severity.MEDIUM)
        return self.result(CheckStatus.PASS,
                           "All packages are up to date (as of the last package index refresh).")


# --------------------------------------------------------------------------- #
# Persistence
# --------------------------------------------------------------------------- #
_SUSPICIOUS_COMMANDS: tuple[tuple[re.Pattern[str], str], ...] = (
    (re.compile(r"%te?mp%|\\appdata\\local\\temp\\|\\windows\\temp\\|\\downloads\\"
                r"|\\users\\public\\|(^|[\s\"'=])/(tmp|var/tmp|dev/shm)/", re.IGNORECASE),
     "runs from a temporary, downloads or shared folder"),
    (re.compile(r"\b(powershell|pwsh)(\.exe)?\b.*\s[-/](e|ec|en|enc\w*)\s", re.IGNORECASE),
     "runs encoded PowerShell"),
    (re.compile(r"\b(powershell|pwsh)(\.exe)?\b.*\s[-/]w(indowstyle)?\s+hidden", re.IGNORECASE),
     "runs a hidden PowerShell window"),
    (re.compile(r"\b(mshta|rundll32|regsvr32|wscript|cscript|certutil|bitsadmin)(\.exe)?\b"
                r".*https?://", re.IGNORECASE),
     "loads code from the internet through a Windows system tool"),
    (re.compile(r"\b(curl|wget)\b[^|;]*\|\s*(sudo\s+)?(ba|z|da)?sh\b", re.IGNORECASE),
     "downloads a script from the internet and runs it"),
    (re.compile(r"/dev/tcp/|\bn(c|cat)\b.*\s-e\s", re.IGNORECASE),
     "opens a reverse shell"),
)


def suspicious_reasons(command: str) -> list[str]:
    """Why a startup command looks like malware persistence (empty if it does not)."""
    return [reason for pattern, reason in _SUSPICIOUS_COMMANDS if pattern.search(command)]


class StartupProgramsCheck(PostureCheck):
    check_id = "POSTURE-STARTUP"
    title = "Startup programs look legitimate"
    category = "Persistence"
    severity = Severity.HIGH
    platforms = (OS.WINDOWS, OS.LINUX)
    remediation = ("Look up each flagged entry. If you did not set it up, remove it (Task "
                   "Manager > Startup apps, the registry value, or the cron line) and run a "
                   "full antivirus scan.")
    RUN_KEYS: tuple[tuple[str, str], ...] = (
        ("HKLM", r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run"),
        ("HKLM", r"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce"),
        ("HKLM", r"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run"),
        ("HKCU", r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run"),
        ("HKCU", r"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce"),
    )
    CRON_FILES = ("/etc/crontab", "/etc/cron.d/*", "/var/spool/cron/crontabs/*",
                  "/var/spool/cron/*")
    _CRON_ENV = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*\s*=")

    def run(self, ctx: PostureContext) -> CheckResult:
        entries = self._windows_entries(ctx) if ctx.os is OS.WINDOWS else self._cron_entries(ctx)
        if entries is None:
            return self.result(CheckStatus.SKIP, "Could not read any startup entries.")
        flagged = []
        for where, command in entries:
            reasons = suspicious_reasons(command)
            if reasons:
                shown = command if len(command) <= 160 else command[:157] + "..."
                flagged.append(f"{where}: {shown} ({'; '.join(reasons)})")
        if flagged:
            return self.result(CheckStatus.FAIL,
                               f"{len(flagged)} startup entry(ies) look like malware persistence.",
                               flagged)
        return self.result(CheckStatus.PASS,
                           f"{len(entries)} startup entries reviewed; none look suspicious.")

    def _windows_entries(self, ctx: PostureContext) -> list[tuple[str, str]] | None:
        entries: list[tuple[str, str]] = []
        readable = False
        for hive, key in self.RUN_KEYS:
            values = ctx.registry_values(hive, key)
            if values is None:
                continue
            readable = True
            label = f"{hive}\\...\\{key.rsplit(chr(92), 1)[-1]}"
            entries.extend((f"{label}\\{name}", str(value)) for name, value in values.items())
        return entries if readable else None

    def _cron_entries(self, ctx: PostureContext) -> list[tuple[str, str]] | None:
        paths: list[str] = []
        for pattern in self.CRON_FILES:
            paths.extend(sorted(ctx.glob(pattern)) if "*" in pattern else [pattern])
        entries: list[tuple[str, str]] = []
        readable = False
        for path in dict.fromkeys(paths):
            text = ctx.read_text(path)
            if text is None:
                continue
            readable = True
            for line in text.splitlines():
                line = line.strip()
                if line and not line.startswith("#") and not self._CRON_ENV.match(line):
                    entries.append((path, line))
        return entries if readable else None


# --------------------------------------------------------------------------- #
# Accounts and sign-in policy
# --------------------------------------------------------------------------- #
class PasswordPolicyCheck(PostureCheck):
    check_id = "POSTURE-PASSWORD-POLICY"
    title = "Passwords must be long enough, and guessing locks the account"
    category = "Credentials"
    severity = Severity.HIGH
    platforms = (OS.WINDOWS, OS.LINUX)
    #: Shorter than this is guessable with ordinary hardware.
    MIN_LENGTH = 8
    #: More attempts than this without a lockout means guessing can run forever.
    MAX_ATTEMPTS = 10

    def run(self, ctx: PostureContext) -> CheckResult:
        return self._windows(ctx) if ctx.os is OS.WINDOWS else self._linux(ctx)

    def _verdict(self, length: int | None, lockout: int | None, details: list[str],
                 fix: str) -> CheckResult:
        problems = []
        if length is not None and length < self.MIN_LENGTH:
            problems.append(f"the shortest allowed password is {length} characters"
                            if length else "passwords may be empty")
        if lockout == 0:
            problems.append("an account is never locked, so passwords can be guessed forever")
        elif lockout is not None and lockout > self.MAX_ATTEMPTS:
            problems.append(f"an account is only locked after {lockout} wrong passwords")
        if length is None and lockout is None:
            return self.result(CheckStatus.SKIP, "Could not read the password policy.")
        if problems:
            return self.result(CheckStatus.FAIL,
                               "The password policy is weaker than it should be.",
                               [p.capitalize() for p in problems] + details, remediation=fix)
        return self.result(CheckStatus.PASS,
                           "Passwords must be reasonably long and guessing locks the account.",
                           details)

    def _windows(self, ctx: PostureContext) -> CheckResult:
        out = ctx.run(["net", "accounts"])
        if out is None or out[0] != 0:
            return self.result(CheckStatus.SKIP, "Could not read the password policy.")
        length = _as_int(_after(out[1], r"Minimum password length[^:]*:\s*(\S+)"))
        lockout_text = _after(out[1], r"Lockout threshold[^:]*:\s*(\S+)")
        lockout = 0 if (lockout_text or "").lower() == "never" else _as_int(lockout_text)
        details = [f"Minimum password length: {length if length is not None else 'unknown'}",
                   f"Account locks after: {lockout_text or 'unknown'} wrong passwords"]
        return self._verdict(length, lockout, details,
                             fix="Run as Administrator: net accounts /minpwlen:12 "
                                 "/lockoutthreshold:5 /lockoutduration:15")

    def _linux(self, ctx: PostureContext) -> CheckResult:
        text = ctx.read_text("/etc/login.defs")
        if text is None:
            return self.result(CheckStatus.SKIP, "No /etc/login.defs on this system.")
        length = _as_int(_after(text, r"^\s*PASS_MIN_LEN\s+(\d+)", multiline=True))
        faillock = ctx.read_text("/etc/security/faillock.conf") or ""
        deny = _as_int(_after(faillock, r"^\s*deny\s*=\s*(\d+)", multiline=True))
        details = [f"Minimum password length: {length if length is not None else 'not set'}"]
        if deny is not None:
            details.append(f"Account locks after {deny} wrong passwords")
        return self._verdict(length, deny, details,
                             fix="Set PASS_MIN_LEN 12 in /etc/login.defs, and configure "
                                 "lockouts with pam_faillock (deny=5 in "
                                 "/etc/security/faillock.conf).")


class GuestAccountCheck(PostureCheck):
    check_id = "POSTURE-GUEST"
    title = "The guest account is off"
    category = "Credentials"
    severity = Severity.HIGH
    platforms = _WINDOWS
    remediation = ("Run as Administrator: net user Guest /active:no "
                   "(the Security Check page can do this for you).")

    def run(self, ctx: PostureContext) -> CheckResult:
        out = ctx.run(["net", "user", "Guest"])
        if out is None or out[0] != 0:
            return self.result(CheckStatus.SKIP, "There is no guest account on this computer.")
        active = _after(out[1], r"Account active\s+(\S+)")
        if (active or "").lower() in ("yes", "ja", "oui", "si", "sí"):
            return self.result(
                CheckStatus.FAIL,
                "The guest account is switched on: anyone can sign in without a password.")
        if not active:
            return self.result(CheckStatus.SKIP, "Could not read the guest account state.")
        return self.result(CheckStatus.PASS, "The guest account is switched off.")


class RiskyServicesCheck(PostureCheck):
    check_id = "POSTURE-RISKY-SERVICES"
    title = "Risky Windows services are not running"
    category = "Network"
    severity = Severity.HIGH
    platforms = _WINDOWS
    #: Services that are never safe on an ordinary computer: they send passwords
    #: in clear text or hand out settings to anyone who asks.
    UNSAFE = {
        "TlntSvr": "Telnet server (sends passwords in clear text)",
        "FTPSVC": "FTP server (sends passwords in clear text)",
        "SNMP": "SNMP (usually left with the default community string)",
        "simptcp": "Simple TCP/IP Services (old, unauthenticated network services)",
    }
    #: Legitimate, but worth knowing about: each one widens what the computer
    #: offers to the network.
    QUESTIONABLE = {
        "RemoteRegistry": "Remote Registry lets other machines read this computer's settings",
        "SharedAccess": "Internet Connection Sharing shares this computer's network with others",
        "WinRM": "Windows Remote Management accepts remote PowerShell sessions",
    }
    _SCRIPT = ("Get-Service -Name {names} -ErrorAction SilentlyContinue | "
               "ForEach-Object {{ $_.Name + '=' + $_.Status }}")

    def run(self, ctx: PostureContext) -> CheckResult:
        names = {**self.UNSAFE, **self.QUESTIONABLE}
        # Names that do not exist on this machine make PowerShell exit non-zero
        # even when it printed the services that do, so the output is what counts.
        out = ctx.run(["powershell", "-NoProfile", "-NonInteractive", "-Command",
                       self._SCRIPT.format(names=",".join(names))], timeout=45)
        if out is None:
            return self.result(CheckStatus.SKIP, "Could not read the list of services.")
        running = [name for name, status in
                   (line.split("=", 1) for line in out[1].splitlines() if "=" in line)
                   if status.strip().lower() == "running"]
        unsafe = [n for n in running if n in self.UNSAFE]
        questionable = [n for n in running if n in self.QUESTIONABLE]
        details = [f"{name}: {names[name]}" for name in unsafe + questionable]
        fix = ("Turn off what you do not use: Services (services.msc), or run as "
               "Administrator: sc.exe config <name> start= disabled")
        if unsafe:
            return self.result(CheckStatus.FAIL,
                               f"{len(unsafe)} service(s) that are never safe are running.",
                               details, remediation=fix)
        if questionable:
            return self.result(CheckStatus.WARN,
                               f"{len(questionable)} service(s) widen what this computer "
                               f"offers to the network.", details, remediation=fix,
                               severity=Severity.MEDIUM)
        if not out[1].strip():
            return self.result(CheckStatus.PASS, "None of the risky services are installed.")
        return self.result(CheckStatus.PASS, "No risky services are running.")


class ScreenLockCheck(PostureCheck):
    check_id = "POSTURE-SCREEN-LOCK"
    title = "The screen locks when the computer is left alone"
    category = "Privilege"
    severity = Severity.MEDIUM
    platforms = _WINDOWS
    remediation = ("Settings > Personalisation > Lock screen > Screen saver settings: tick "
                   "'On resume, display logon screen' and set a wait of 15 minutes or less.")
    _DESKTOP = r"Control Panel\Desktop"
    #: Longer than this, and a walk-away leaves the screen open.
    MAX_MINUTES = 15

    def run(self, ctx: PostureContext) -> CheckResult:
        values = ctx.registry_values("HKCU", self._DESKTOP)
        if values is None:
            return self.result(CheckStatus.SKIP, "Could not read the screen-lock settings.")
        active = str(values.get("ScreenSaveActive", "")).strip() == "1"
        secure = str(values.get("ScreenSaverIsSecure", "")).strip() == "1"
        timeout = _as_int(values.get("ScreenSaveTimeOut"))
        minutes = (timeout or 0) // 60
        if not active or not secure:
            return self.result(
                CheckStatus.FAIL,
                "The screen does not lock itself: anyone walking past can use this computer.")
        if minutes > self.MAX_MINUTES:
            return self.result(
                CheckStatus.WARN,
                f"The screen only locks after {minutes} minutes.",
                severity=Severity.LOW)
        return self.result(CheckStatus.PASS,
                           f"The screen locks after {minutes or 1} minute(s) of inactivity.")


def default_checks() -> list[PostureCheck]:
    return [
        FirewallEnabledCheck(),
        ExposedServicesCheck(),
        SystemUpdatesCheck(),
        StartupProgramsCheck(),
        DefenderRealtimeCheck(),
        UserAccountControlCheck(),
        RemoteDesktopCheck(),
        SMBv1Check(),
        AutoLogonCheck(),
        DiskEncryptionCheck(),
        SSHHardeningCheck(),
        SensitiveFilePermissionsCheck(),
        PasswordPolicyCheck(),
        GuestAccountCheck(),
        RiskyServicesCheck(),
        ScreenLockCheck(),
    ]
