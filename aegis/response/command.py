"""Shared command-execution primitives for every firewall backend.

The single most important security property of Aegis lives here: privileged
commands are executed as an **argument list with ``shell=False``**, never as an
interpolated string. That is what makes shell metacharacters in a rule name or
IP address inert rather than executable.

Every platform backend (netsh, nftables, pf) routes through :func:`default_runner`,
so none of them can regress that property independently. The runner is also
dependency-injected, which is what lets the whole response layer be unit tested
without root/Administrator rights or a real firewall.
"""
from __future__ import annotations

import subprocess
from collections.abc import Callable
from dataclasses import dataclass

from aegis.platforms import NO_WINDOW


@dataclass
class RunResult:
    """Minimal, decode-agnostic result of running a command."""

    returncode: int
    stdout: bytes = b""
    stderr: bytes = b""


@dataclass
class FirewallResult:
    """Typed outcome of a firewall operation (replaces the original magic ints)."""

    ok: bool
    message: str
    needs_admin: bool = False
    rule_name: str = ""


class FirewallError(Exception):
    """A firewall command could not be executed at all (missing binary, timeout)."""


# A command runner takes an argv list + timeout and returns a RunResult.
CommandRunner = Callable[[list[str], int], RunResult]


def default_runner(args: list[str], timeout: int) -> RunResult:
    """Run a command securely: argument list, no shell, no console window."""
    proc = subprocess.run(
        args,
        capture_output=True,
        shell=False,                 # <- the core security property
        timeout=timeout,
        creationflags=NO_WINDOW,
    )
    return RunResult(proc.returncode, proc.stdout or b"", proc.stderr or b"")


def decode(data: bytes) -> str:
    """Decode command output tolerant of the active OEM/ANSI code page.

    Windows ``netsh`` emits text in the console code page rather than UTF-8, and
    it varies by locale, so we try the plausible encodings in order instead of
    assuming one.
    """
    for enc in ("utf-8", "cp1252", "cp437", "latin-1"):
        try:
            return data.decode(enc)
        except UnicodeDecodeError:
            continue
    return data.decode("utf-8", errors="replace")
