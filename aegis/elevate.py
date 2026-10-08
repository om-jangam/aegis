"""Restarting Aegis with administrator rights.

Several things genuinely need them: reading the Windows sign-in log, creating
firewall rules, and two of the hardening fixes. Without them Aegis says so and
carries on, but "run it as administrator" is a dead end for somebody who does
not know how. This restarts Aegis for them: Windows asks for consent in its own
dialog, which is the part that matters — Aegis cannot grant itself rights, it
can only ask the operating system to ask the person.

On Linux and macOS there is no equivalent that works from a running app without
a password prompt Aegis would have to handle itself, which it will not do. There
the honest answer is the command to type.
"""
from __future__ import annotations

import logging
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path

from aegis.platforms import is_elevated, is_windows, privilege_hint

log = logging.getLogger(__name__)

#: What ShellExecuteW returns below, for "the person said no" and friends.
_CANCELLED = 1223       # ERROR_CANCELLED: the UAC prompt was declined


@dataclass(frozen=True)
class ElevateResult:
    ok: bool
    message: str
    #: True when Aegis should now close, because an elevated copy is starting.
    restarting: bool = False


def restart_command() -> list[str]:
    """The program and arguments that start Aegis again, as this copy was started."""
    if getattr(sys, "frozen", False):        # the packaged Aegis.exe
        return [sys.executable, *sys.argv[1:]]
    return [sys.executable, "-m", "aegis", *(sys.argv[1:] or ["console"])]


def can_elevate() -> bool:
    """Whether a one-click restart is possible here."""
    return is_windows() and not is_elevated()


def restart_as_admin(*, confirmed: bool = False, shell_execute=None) -> ElevateResult:
    """Start Aegis again with administrator rights, asking Windows to confirm.

    Returns a result rather than exiting: the caller decides when to close the
    window, so nothing is lost half-way through.
    """
    if not confirmed:
        return ElevateResult(False, "Restarting as administrator needs confirmation.")
    if is_elevated():
        return ElevateResult(False, "Aegis already has administrator rights.")
    if not is_windows():
        return ElevateResult(False, privilege_hint())

    command = restart_command()
    program, arguments = command[0], command[1:]
    try:
        runner = shell_execute or _shell_execute
        code = runner(program, _join(arguments), str(Path.cwd()))
    except Exception as exc:  # noqa: BLE001 - report, never crash the window
        log.exception("Could not restart Aegis as administrator")
        return ElevateResult(False, f"Could not restart as administrator: {exc}")

    if code == _CANCELLED:
        return ElevateResult(False, "Windows asked for permission and it was declined, "
                                    "so Aegis is still running as a standard user.")
    # ShellExecuteW returns a value above 32 when it started the program.
    if code <= 32:
        return ElevateResult(False, f"Windows refused to restart Aegis (code {code}). "
                                    f"{privilege_hint()}")
    return ElevateResult(True, "Aegis is restarting with administrator rights.",
                         restarting=True)


def _join(arguments: list[str]) -> str:
    return subprocess.list2cmdline(arguments)


def _shell_execute(program: str, arguments: str, directory: str) -> int:
    """Ask Windows to start a program elevated; it shows the consent dialog."""
    import ctypes

    # "runas" is the verb behind "Run as administrator" in Explorer.
    return int(ctypes.windll.shell32.ShellExecuteW(None, "runas", program, arguments,
                                                   directory, 1))
