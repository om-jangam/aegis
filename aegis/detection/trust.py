"""Programs the user has chosen to trust.

Developer tools, IT agents and backup software legitimately do things that look
like attacks: run encoded PowerShell, spawn shells, open many connections.
Trusting such a program stops *alerts* about it and about what it starts.
Findings are still recorded, so the evidence trail stays complete.

Some programs can never be trusted. Interpreters and core system processes are
exactly what attackers hide behind; trusting ``powershell.exe`` or
``explorer.exe`` would silence detection for nearly every real attack.
"""
from __future__ import annotations

NEVER_TRUST: frozenset[str] = frozenset({
    # Windows shells, script hosts and proxy-execution binaries
    "powershell.exe", "pwsh.exe", "cmd.exe", "wscript.exe", "cscript.exe", "mshta.exe",
    "rundll32.exe", "regsvr32.exe", "msiexec.exe", "certutil.exe", "bitsadmin.exe",
    "wmic.exe", "conhost.exe",
    # Windows core processes
    "system", "registry", "smss.exe", "csrss.exe", "wininit.exe", "winlogon.exe",
    "services.exe", "lsass.exe", "svchost.exe", "explorer.exe", "taskhostw.exe",
    "dllhost.exe", "sihost.exe", "runtimebroker.exe", "userinit.exe",
    # POSIX shells and core processes
    "sh", "bash", "zsh", "dash", "fish", "ksh", "csh", "tcsh", "systemd", "init", "launchd",
    "sudo", "su", "cron", "crond", "sshd", "login",
    # General-purpose interpreters
    "python", "python.exe", "python3", "pythonw.exe", "perl", "ruby", "node", "node.exe",
    "java", "java.exe", "php",
})


def normalise(name: str) -> str:
    return (name or "").strip().lower()


def can_trust(name: str) -> bool:
    """Whether a program may be added to the trusted list."""
    key = normalise(name)
    return bool(key) and key not in NEVER_TRUST


def is_trusted(process_name: str, parent_name: str, trusted: list[str]) -> bool:
    """True if the program, or the program that started it, is trusted.

    Entries that can never be trusted are ignored even if they reach the
    settings file some other way.
    """
    allowed = {normalise(t) for t in trusted if can_trust(t)}
    return bool(allowed) and (normalise(process_name) in allowed
                              or normalise(parent_name) in allowed)


def trust_candidate(process_name: str, parent_name: str) -> str:
    """The program an alert should offer to trust, or "" if none is safe.

    The parent is preferred: when a trusted tool launches PowerShell, the tool
    is what the user recognises, and PowerShell itself must stay watched.
    """
    for name in (parent_name, process_name):
        if can_trust(name):
            return name.strip()
    return ""
