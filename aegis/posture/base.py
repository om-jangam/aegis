"""Host security posture: models, scoring and the check contract.

Detection answers "is something bad happening right now?". Posture answers the
question most people should ask first: "how easy have I made it?". A posture
check inspects one configuration fact (is the firewall on, is a database
listening on every interface) and returns a verdict with a plain-language fix.

Checks never change the system. Everything they read (command output, sockets,
files, registry values) arrives through :class:`PostureContext`, so every check
is unit-testable on any OS without privileges.
"""
from __future__ import annotations

import abc
import glob as _glob
import os
import subprocess
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import datetime
from enum import StrEnum

from aegis.core.models import Severity
from aegis.platforms import CURRENT_OS, OS, is_elevated
from aegis.response.command import CommandRunner, decode, default_runner


class CheckStatus(StrEnum):
    PASS = "pass"
    WARN = "warn"
    FAIL = "fail"
    SKIP = "skip"


@dataclass(frozen=True)
class Listener:
    """A socket accepting connections."""

    ip: str
    port: int
    process: str = ""
    pid: int | None = None


@dataclass
class CheckResult:
    check_id: str
    title: str
    category: str
    status: CheckStatus
    severity: Severity
    summary: str
    details: list[str] = field(default_factory=list)
    remediation: str = ""

    def to_dict(self) -> dict:
        return {
            "id": self.check_id,
            "title": self.title,
            "category": self.category,
            "status": self.status.value,
            "severity": self.severity.value,
            "summary": self.summary,
            "details": list(self.details),
            "remediation": self.remediation,
        }


# --------------------------------------------------------------------------- #
# Default, real-system readers
# --------------------------------------------------------------------------- #
def _read_text(path: str) -> str | None:
    try:
        with open(path, encoding="utf-8", errors="replace") as fh:
            return fh.read()
    except OSError:
        return None


def _stat_mode(path: str) -> int | None:
    try:
        return os.stat(path).st_mode
    except OSError:
        return None


def _read_registry(key_path: str, value_name: str):
    """Read a value under HKEY_LOCAL_MACHINE; None if absent or not on Windows."""
    try:
        import winreg
    except ImportError:
        return None
    try:
        # Read the 64-bit view even from a 32-bit interpreter, or security
        # settings would silently come from the WOW64 shadow hive.
        access = winreg.KEY_READ | getattr(winreg, "KEY_WOW64_64KEY", 0)
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, key_path, 0, access) as key:
            value, _ = winreg.QueryValueEx(key, value_name)
            return value
    except OSError:
        return None


def listening_sockets() -> list[Listener]:
    """Enumerate TCP listening sockets with their owning process."""
    import psutil

    pairs: list[tuple[int | None, object]] = []
    try:
        pairs = [(c.pid, c) for c in psutil.net_connections(kind="inet")]
    except (psutil.AccessDenied, PermissionError):
        # macOS refuses the system-wide table to non-root users; the
        # per-process view still covers everything this user owns.
        for proc in psutil.process_iter():
            try:
                pairs.extend((proc.pid, c) for c in proc.net_connections(kind="inet"))
            except (psutil.Error, PermissionError):
                continue

    names: dict[int, str] = {}
    out: list[Listener] = []
    seen: set[tuple[str, int, int | None]] = set()
    for pid, conn in pairs:
        if conn.status != psutil.CONN_LISTEN or not conn.laddr:
            continue
        key = (conn.laddr.ip, conn.laddr.port, pid)
        if key in seen:
            continue
        seen.add(key)
        if pid and pid not in names:
            try:
                names[pid] = psutil.Process(pid).name()
            except psutil.Error:
                names[pid] = ""
        out.append(Listener(conn.laddr.ip, conn.laddr.port, names.get(pid, "") if pid else "", pid))
    return out


_getenv = os.environ.get


@dataclass
class PostureContext:
    """Everything a check may read. Swap any field out in tests."""

    os: OS = CURRENT_OS
    elevated: bool = field(default_factory=is_elevated)
    runner: CommandRunner = default_runner
    listeners: Callable[[], list[Listener]] = listening_sockets
    read_text: Callable[[str], str | None] = _read_text
    stat_mode: Callable[[str], int | None] = _stat_mode
    read_registry: Callable[[str, str], object] = _read_registry
    glob: Callable[[str], list[str]] = _glob.glob
    env: Callable[[str], str | None] = _getenv

    def run(self, args: list[str], timeout: int = 20) -> tuple[int, str] | None:
        """Run a fixed, read-only command. None when it could not run at all."""
        try:
            result = self.runner(args, timeout)
        except (OSError, subprocess.SubprocessError):
            return None
        return result.returncode, decode(result.stdout)


class PostureCheck(abc.ABC):
    check_id: str = "POSTURE"
    title: str = ""
    category: str = ""
    severity: Severity = Severity.MEDIUM
    #: Operating systems the check applies to; empty means all.
    platforms: tuple[OS, ...] = ()
    remediation: str = ""

    def applies(self, ctx: PostureContext) -> bool:
        return not self.platforms or ctx.os in self.platforms

    @abc.abstractmethod
    def run(self, ctx: PostureContext) -> CheckResult:
        raise NotImplementedError

    def result(self, status: CheckStatus, summary: str, details: list[str] | None = None,
               *, remediation: str | None = None,
               severity: Severity | None = None) -> CheckResult:
        fix = self.remediation if remediation is None else remediation
        return CheckResult(
            check_id=self.check_id,
            title=self.title,
            category=self.category,
            status=status,
            severity=severity or self.severity,
            summary=summary,
            details=details or [],
            remediation=fix if status in (CheckStatus.WARN, CheckStatus.FAIL) else "",
        )


# --------------------------------------------------------------------------- #
# Report and scoring
# --------------------------------------------------------------------------- #
# A failed check costs its severity's penalty; a warning costs half.
_PENALTY = {
    Severity.INFO: 0,
    Severity.LOW: 3,
    Severity.MEDIUM: 8,
    Severity.HIGH: 15,
    Severity.CRITICAL: 25,
}


@dataclass
class PostureReport:
    results: list[CheckResult]
    platform: str = CURRENT_OS.value
    generated_at: datetime = field(default_factory=datetime.now)

    def count(self, status: CheckStatus) -> int:
        return sum(1 for r in self.results if r.status is status)

    @property
    def evaluated(self) -> int:
        return len(self.results) - self.count(CheckStatus.SKIP)

    @property
    def score(self) -> int:
        penalty = 0
        for r in self.results:
            if r.status is CheckStatus.FAIL:
                penalty += _PENALTY[r.severity]
            elif r.status is CheckStatus.WARN:
                penalty += _PENALTY[r.severity] // 2
        return max(0, 100 - penalty)

    @property
    def grade(self) -> str:
        score = self.score
        for threshold, grade in ((90, "A"), (80, "B"), (70, "C"), (50, "D")):
            if score >= threshold:
                return grade
        return "F"

    def failing(self, min_severity: Severity) -> list[CheckResult]:
        return [r for r in self.results
                if r.status is CheckStatus.FAIL and r.severity >= min_severity]

    def to_dict(self) -> dict:
        return {
            "generated_at": self.generated_at.isoformat(timespec="seconds"),
            "platform": self.platform,
            "score": self.score,
            "grade": self.grade,
            "counts": {s.value: self.count(s) for s in CheckStatus},
            "results": [r.to_dict() for r in self.results],
        }
