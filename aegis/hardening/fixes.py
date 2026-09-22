"""The built-in fixes.

Only changes that are safe to make automatically and can be undone are here.
Anything that needs judgement (encrypting a disk, installing updates, choosing
which service to stop) stays as written guidance in the security check.
"""
from __future__ import annotations

import re
import stat

from aegis.hardening.base import (
    Change,
    Fix,
    HardeningContext,
    HardeningError,
    RegistryFix,
    RegistryValue,
)
from aegis.platforms import OS
from aegis.posture.base import PostureContext
from aegis.posture.checks import (
    AutoLogonCheck,
    RemoteDesktopCheck,
    SensitiveFilePermissionsCheck,
    SMBv1Check,
    SSHHardeningCheck,
    UserAccountControlCheck,
    sshd_options,
)

_POSIX = (OS.LINUX, OS.MACOS)


# --------------------------------------------------------------------------- #
# Firewall
# --------------------------------------------------------------------------- #
_NETSH_PROFILES = {"domain", "private", "public"}


def windows_firewall_profiles(ctx: PostureContext) -> dict[str, str]:
    """Firewall state per profile, e.g. {"domain": "ON", "public": "OFF"}."""
    out = ctx.run(["netsh", "advfirewall", "show", "allprofiles", "state"])
    if out is None:
        raise HardeningError("netsh is not available.")
    text = out[1]
    names = [n.lower() for n in re.findall(r"^\s*(\w+) Profile Settings", text, re.MULTILINE)]
    states = [s.upper() for s in
              re.findall(r"^\s*State\s+(ON|OFF)\s*$", text, re.IGNORECASE | re.MULTILINE)]
    if not states or len(names) != len(states) or not set(names) <= _NETSH_PROFILES:
        raise HardeningError("Could not read the firewall state from netsh (non-English "
                             "Windows?). Turn the firewall on in Windows Security instead.")
    return dict(zip(names, states, strict=True))


class WindowsFirewallFix(Fix):
    fix_id = "FIX-WIN-FIREWALL"
    check_id = "POSTURE-FIREWALL"
    title = "Turn on Windows Firewall for every profile"
    risk = ("With the firewall off, any program listening on this computer can be reached "
            "by every device on the network, including on public Wi-Fi.")
    effect = ("Unsolicited incoming connections are blocked. Programs you already allowed "
              "keep working; Windows asks the first time a new program wants to accept "
              "connections.")
    platforms = (OS.WINDOWS,)

    def plan(self, ctx: HardeningContext) -> list[Change]:
        return [Change(f"Windows Firewall ({name} profile)", state, "ON")
                for name, state in windows_firewall_profiles(ctx).items() if state != "ON"]

    def snapshot(self, ctx: HardeningContext) -> dict:
        return {"off": [n for n, s in windows_firewall_profiles(ctx).items() if s != "ON"]}

    def apply(self, ctx: HardeningContext) -> str:
        ctx.must_run(["netsh", "advfirewall", "set", "allprofiles", "state", "on"],
                     "turn the firewall on")
        return ""

    def restore(self, ctx: HardeningContext, backup: dict) -> str:
        for name in backup.get("off", []):
            if name not in _NETSH_PROFILES:
                continue
            ctx.must_run(["netsh", "advfirewall", "set", f"{name}profile", "state", "off"],
                         f"turn the {name} firewall profile back off")
        return ""


class MacFirewallFix(Fix):
    fix_id = "FIX-MAC-FIREWALL"
    check_id = "POSTURE-FIREWALL"
    title = "Turn on the macOS application firewall"
    risk = ("With the firewall off, any app listening on this Mac can be reached by every "
            "device on the network.")
    effect = "macOS asks before an app accepts incoming connections."
    platforms = (OS.MACOS,)
    TOOL = "/usr/libexec/ApplicationFirewall/socketfilterfw"

    def _enabled(self, ctx: HardeningContext) -> bool:
        out = ctx.run([self.TOOL, "--getglobalstate"])
        if out is None:
            raise HardeningError("The application firewall tool is not available.")
        text = out[1].lower()
        return "enabled" in text and "disabled" not in text

    def plan(self, ctx: HardeningContext) -> list[Change]:
        return [] if self._enabled(ctx) else [Change("Application firewall", "off", "on")]

    def snapshot(self, ctx: HardeningContext) -> dict:
        return {"enabled": self._enabled(ctx)}

    def apply(self, ctx: HardeningContext) -> str:
        ctx.must_run([self.TOOL, "--setglobalstate", "on"], "turn the firewall on")
        return ""

    def restore(self, ctx: HardeningContext, backup: dict) -> str:
        if not backup.get("enabled", True):
            ctx.must_run([self.TOOL, "--setglobalstate", "off"], "turn the firewall back off")
        return ""


class UfwFirewallFix(Fix):
    fix_id = "FIX-LINUX-UFW"
    check_id = "POSTURE-FIREWALL"
    title = "Turn on the ufw firewall"
    risk = "With no firewall, every listening service can be reached from the network."
    effect = ("Incoming connections are blocked by default. If an SSH server is running, "
              "SSH (port 22) is allowed first so a remote session is not cut off.")
    platforms = (OS.LINUX,)

    def _status(self, ctx: HardeningContext) -> str | None:
        out = ctx.run(["ufw", "status"])
        if out is None or out[0] != 0:
            return None
        if re.search(r"Status:\s*active", out[1]):
            return "active"
        if re.search(r"Status:\s*inactive", out[1]):
            return "inactive"
        return None

    def applies(self, ctx: PostureContext) -> bool:
        return super().applies(ctx) and ctx.run(["ufw", "version"]) is not None

    def plan(self, ctx: HardeningContext) -> list[Change]:
        status = self._status(ctx)
        if status is None:
            raise HardeningError("Could not read the ufw status (run with sudo).")
        return [] if status == "active" else [Change("ufw", "inactive", "active")]

    @staticmethod
    def _needs_ssh_rule(ctx: HardeningContext) -> bool:
        """An SSH server is listening and no rule for it exists yet."""
        if not any(sock.port == 22 for sock in ctx.listeners()):
            return False
        added = ctx.run(["ufw", "show", "added"])
        return not (added and re.search(r"allow\s+(22/tcp|22|OpenSSH)(\s|$)", added[1],
                                        re.MULTILINE))

    def snapshot(self, ctx: HardeningContext) -> dict:
        return {"was_active": self._status(ctx) == "active",
                "allowed_ssh": self._needs_ssh_rule(ctx)}

    def apply(self, ctx: HardeningContext) -> str:
        if self._needs_ssh_rule(ctx):
            ctx.must_run(["ufw", "allow", "22/tcp"], "allow SSH through the firewall")
        ctx.must_run(["ufw", "--force", "enable"], "enable ufw")
        return ""

    def restore(self, ctx: HardeningContext, backup: dict) -> str:
        if not backup.get("was_active", False):
            ctx.must_run(["ufw", "--force", "disable"], "disable ufw")
        if backup.get("allowed_ssh"):
            ctx.must_run(["ufw", "delete", "allow", "22/tcp"], "remove the SSH rule")
        return ""


# --------------------------------------------------------------------------- #
# Windows settings
# --------------------------------------------------------------------------- #
class SMBv1ServerFix(RegistryFix):
    fix_id = "FIX-WIN-SMB1"
    check_id = SMBv1Check.check_id
    title = "Turn off the SMBv1 file-sharing server"
    risk = ("SMBv1 is a 30-year-old file-sharing protocol with no modern protections. "
            "The WannaCry and NotPetya outbreaks spread through it.")
    effect = ("File sharing keeps working over SMBv2/3. Only devices older than about "
              "2007 (some old printers and NAS boxes) can no longer reach shares on this PC.")
    restart_note = "Restart the computer to finish turning SMBv1 off."
    VALUES = (RegistryValue(SMBv1Check._SERVER, "SMB1", 0, missing_is_safe=True),)


class RemoteDesktopNlaFix(RegistryFix):
    fix_id = "FIX-WIN-RDP-NLA"
    check_id = RemoteDesktopCheck.check_id
    title = "Require sign-in before a Remote Desktop session starts (NLA)"
    risk = ("Without Network Level Authentication, anyone who can reach the computer gets "
            "a login screen and can try passwords, and pre-login flaws like BlueKeep are "
            "exposed.")
    effect = ("Remote Desktop keeps working. Users sign in before the session opens; very "
              "old Remote Desktop clients can no longer connect.")
    VALUES = (RegistryValue(RemoteDesktopCheck._RDP_TCP, "UserAuthentication", 1,
                            missing_is_safe=True),)


class RemoteDesktopOffFix(RegistryFix):
    fix_id = "FIX-WIN-RDP-OFF"
    check_id = RemoteDesktopCheck.check_id
    title = "Turn off Remote Desktop"
    risk = ("Remote Desktop is one of the most attacked services on the internet. If you "
            "do not use it, it should not be on.")
    effect = ("Nobody can connect to this computer with Remote Desktop, including you. "
              "Do not use this if you are connected over Remote Desktop right now.")
    VALUES = (RegistryValue(RemoteDesktopCheck._TS, "fDenyTSConnections", 1),)


class UserAccountControlFix(RegistryFix):
    fix_id = "FIX-WIN-UAC"
    check_id = UserAccountControlCheck.check_id
    title = "Turn User Account Control back on at the default level"
    risk = ("Without UAC prompts, any program an administrator runs, including malware, "
            "silently gets full control of the computer.")
    effect = "Windows asks for confirmation before a program makes system-wide changes."
    restart_note = "Restart the computer for User Account Control to take effect."
    VALUES = (
        RegistryValue(UserAccountControlCheck._KEY, "EnableLUA", 1),
        RegistryValue(UserAccountControlCheck._KEY, "ConsentPromptBehaviorAdmin", 5,
                      missing_is_safe=True),
    )


class AutoLogonFix(RegistryFix):
    fix_id = "FIX-WIN-AUTOLOGON"
    check_id = AutoLogonCheck.check_id
    title = "Turn off automatic sign-in and delete the stored password"
    risk = ("Automatic sign-in gives a session to anyone who turns the computer on, and "
            "the password is kept in the registry in plain text.")
    effect = ("You type your password when the computer starts. The stored copy of the "
              "password is deleted and is not kept by Aegis, so Undo turns automatic "
              "sign-in back on but cannot bring the password back. Change that password, "
              "since it was readable.")
    reversible = False
    VALUES = (
        RegistryValue(AutoLogonCheck._KEY, "AutoAdminLogon", "0", kind="sz"),
        RegistryValue(AutoLogonCheck._KEY, "DefaultPassword", None, kind="sz", secret=True),
    )

    def plan(self, ctx: HardeningContext) -> list[Change]:
        # Nothing to do while automatic sign-in is off, even if a stale password remains.
        if str(ctx.read_registry(AutoLogonCheck._KEY, "AutoAdminLogon") or "").strip() != "1":
            return []
        return super().plan(ctx)


# --------------------------------------------------------------------------- #
# SSH server
# --------------------------------------------------------------------------- #
_BLOCK_START = "# >>> Aegis hardening (FIX-SSH-LOGIN). Undo in Aegis or delete this block."
_BLOCK_END = "# <<< Aegis hardening"


def _without_aegis_block(text: str) -> str:
    pattern = re.compile(rf"^{re.escape(_BLOCK_START)}\n.*?^{re.escape(_BLOCK_END)}\n?",
                         re.MULTILINE | re.DOTALL)
    return pattern.sub("", text)


class SSHLoginFix(Fix):
    fix_id = "FIX-SSH-LOGIN"
    check_id = SSHHardeningCheck.check_id
    title = "Stop root and empty-password logins over SSH"
    risk = ("Letting root log in with a password, or accounts log in with no password, is "
            "what automated SSH attacks try first.")
    effect = ("Log in as a normal user and use sudo. Password logins for normal users are "
              "unchanged, so you cannot lock yourself out; switch to SSH keys separately.")
    platforms = _POSIX
    CONFIG = SSHHardeningCheck.CONFIG
    TARGETS = {"permitrootlogin": "PermitRootLogin", "permitemptypasswords": "PermitEmptyPasswords"}

    def _config(self, ctx: HardeningContext) -> str:
        text = ctx.read_text(self.CONFIG)
        if text is None:
            raise HardeningError(f"Could not read {self.CONFIG}.")
        return text

    def plan(self, ctx: HardeningContext) -> list[Change]:
        options = sshd_options(ctx, self._config(ctx))
        return [Change(f"{self.CONFIG}: {name}", "yes", "no")
                for key, name in self.TARGETS.items() if options.get(key) == "yes"]

    def snapshot(self, ctx: HardeningContext) -> dict:
        return {"config": self._config(ctx)}

    def _validate_and_reload(self, ctx: HardeningContext) -> str:
        for sshd in ("sshd", "/usr/sbin/sshd"):
            out = ctx.run([sshd, "-t", "-f", self.CONFIG])
            if out is not None:
                break
        else:
            raise HardeningError("Could not find sshd to validate the new configuration.")
        if out[0] != 0:
            raise HardeningError(f"sshd rejected the new configuration: {out[1].strip()}")
        reloads = ([["launchctl", "kickstart", "-k", "system/com.openssh.sshd"]]
                   if ctx.os is OS.MACOS else
                   [["systemctl", "reload", "ssh"], ["systemctl", "reload", "sshd"]])
        for args in reloads:
            done = ctx.run(args)
            if done is not None and done[0] == 0:
                return ""
        return "Restart the SSH service for the change to take effect."

    def apply(self, ctx: HardeningContext) -> str:
        original = self._config(ctx)
        rest = _without_aegis_block(original)
        options = sshd_options(ctx, rest)
        wanted = [name for key, name in self.TARGETS.items() if options.get(key) == "yes"]
        if not wanted:
            return ""
        # sshd uses the first value it reads, so a block at the very top wins over
        # later lines and included files.
        block = "\n".join([_BLOCK_START, *(f"{name} no" for name in wanted), _BLOCK_END])
        ctx.write_text(self.CONFIG, f"{block}\n{rest}")
        try:
            return self._validate_and_reload(ctx)
        except HardeningError:
            ctx.write_text(self.CONFIG, original)
            raise

    def restore(self, ctx: HardeningContext, backup: dict) -> str:
        original = backup.get("config")
        if not isinstance(original, str):
            raise HardeningError("The saved SSH configuration is missing.")
        ctx.write_text(self.CONFIG, original)
        return self._validate_and_reload(ctx)


# --------------------------------------------------------------------------- #
# File permissions
# --------------------------------------------------------------------------- #
class FilePermissionsFix(Fix):
    fix_id = "FIX-FILE-PERMISSIONS"
    check_id = SensitiveFilePermissionsCheck.check_id
    title = "Remove unsafe permissions from account and privilege files"
    risk = ("If any user can write /etc/passwd or /etc/sudoers, or read /etc/shadow, any "
            "program they run can take over the computer or crack passwords offline.")
    effect = "Only the unsafe permission bits are removed; owners and groups are unchanged."
    platforms = _POSIX
    FILES = SensitiveFilePermissionsCheck.FILES

    def _unsafe(self, ctx: HardeningContext) -> list[tuple[str, int, int]]:
        found = []
        for path, mask, _ in self.FILES:
            mode = ctx.stat_mode(path)
            if mode is not None and mode & mask:
                current = stat.S_IMODE(mode)
                found.append((path, current, current & ~mask))
        return found

    def plan(self, ctx: HardeningContext) -> list[Change]:
        return [Change(path, f"{current:o}", f"{target:o}")
                for path, current, target in self._unsafe(ctx)]

    def snapshot(self, ctx: HardeningContext) -> dict:
        return {"modes": {path: current for path, current, _ in self._unsafe(ctx)}}

    def apply(self, ctx: HardeningContext) -> str:
        for path, _, target in self._unsafe(ctx):
            ctx.chmod(path, target)
        return ""

    def restore(self, ctx: HardeningContext, backup: dict) -> str:
        known = {path for path, _, _ in self.FILES}
        for path, mode in backup.get("modes", {}).items():
            if path in known:
                ctx.chmod(path, int(mode))
        return ""


def default_fixes() -> list[Fix]:
    return [
        WindowsFirewallFix(), MacFirewallFix(), UfwFirewallFix(),
        SMBv1ServerFix(), RemoteDesktopNlaFix(), RemoteDesktopOffFix(),
        UserAccountControlFix(), AutoLogonFix(),
        SSHLoginFix(), FilePermissionsFix(),
    ]
