"""The built-in posture checks.

Each check targets a misconfiguration that is common, exploited in practice,
and fixable by an ordinary user or administrator. Output strings stay ASCII so
they print cleanly on any console code page.
"""
from __future__ import annotations

import ipaddress
import re
import stat

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


def default_checks() -> list[PostureCheck]:
    return [
        FirewallEnabledCheck(),
        ExposedServicesCheck(),
        DefenderRealtimeCheck(),
        UserAccountControlCheck(),
        RemoteDesktopCheck(),
        SMBv1Check(),
        AutoLogonCheck(),
        DiskEncryptionCheck(),
        SSHHardeningCheck(),
        SensitiveFilePermissionsCheck(),
    ]
