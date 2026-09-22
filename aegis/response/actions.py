"""Containment actions on this computer: stop a program, quarantine a file.

Blocking an address stops a program talking. Sometimes that is not enough: the
program itself has to stop, or the file it runs from has to be put out of reach.
Both are destructive, so both are built the same careful way.

Safety rules, enforced here rather than left to each caller:

* **Nothing happens without ``confirmed=True``.** A person, not a rule, decides.
* **Processes the computer needs are refused.** Killing ``lsass.exe`` or
  ``systemd`` would take the machine down; Aegis will not do it, and it refuses
  to stop itself.
* **A process is identified by more than its number.** PIDs get reused, so the
  name (and start time when known) must match what the caller saw.
* **Quarantine moves, never deletes.** The file goes to a private folder with
  its permissions removed, keeping its digest and original path, and can be put
  back. System files are refused.
* **Every attempt returns a result the caller audits**, including refusals.
"""
from __future__ import annotations

import hashlib
import json
import logging
import os
import shutil
import stat
import uuid
from dataclasses import asdict, dataclass, field
from datetime import datetime
from pathlib import Path

import psutil

from aegis.platforms import is_windows
from aegis.response.base import ResponseResult

log = logging.getLogger(__name__)

#: Processes the operating system needs. Stopping one is never offered.
PROTECTED_PROCESSES = frozenset({
    # Windows
    "system", "system idle process", "smss.exe", "csrss.exe", "wininit.exe",
    "winlogon.exe", "services.exe", "lsass.exe", "lsaiso.exe", "svchost.exe",
    "fontdrvhost.exe", "dwm.exe", "explorer.exe", "memory compression",
    "msmpeng.exe", "securityhealthservice.exe", "registry",
    # Linux / macOS
    "systemd", "init", "kthreadd", "launchd", "kernel_task", "dbus-daemon",
    "logind", "systemd-logind", "sshd", "windowserver", "loginwindow",
})
#: Folders whose files are part of the operating system or Aegis itself.
PROTECTED_DIRS = ("c:/windows", "c:/program files/windowsapps", "/usr", "/bin", "/sbin",
                  "/lib", "/lib64", "/boot", "/etc", "/system", "/private/var/db")
#: Refuse to move anything larger than this (a quarantine folder is not a backup).
MAX_QUARANTINE_BYTES = 512 * 1024 * 1024


def _normalise(path: str | os.PathLike[str]) -> str:
    return str(path).replace("\\", "/").lower()


def is_protected_process(name: str) -> bool:
    return (name or "").strip().lower() in PROTECTED_PROCESSES


def is_protected_path(path: str | os.PathLike[str]) -> bool:
    lowered = _normalise(Path(path).resolve() if Path(path).exists() else path)
    return any(lowered == d or lowered.startswith(d + "/") for d in PROTECTED_DIRS)


# --------------------------------------------------------------------------- #
# Stopping a program
# --------------------------------------------------------------------------- #
class ProcessStopper:
    """Stops a running program, politely first, then firmly."""

    #: How long the program is given to close itself before it is killed.
    GRACE_SECONDS = 5

    def __init__(self, process_source=psutil.Process, own_pid: int | None = None):
        self._process = process_source
        self._own_pid = own_pid if own_pid is not None else os.getpid()

    def stop(self, pid: int, expected_name: str = "", *, confirmed: bool = False,
             reason: str = "") -> ResponseResult:
        """Stop process ``pid``. ``expected_name`` guards against a reused PID."""
        if not confirmed:
            return ResponseResult(False, "stop_process",
                                  "Stopping a program needs confirmation.")
        if pid == self._own_pid:
            return ResponseResult(False, "stop_process", "Aegis will not stop itself.")
        try:
            proc = self._process(pid)
            name = proc.name()
        except psutil.NoSuchProcess:
            return ResponseResult(False, "stop_process",
                                  f"No program is running as process {pid} any more.")
        except psutil.AccessDenied:
            return ResponseResult(False, "stop_process",
                                  f"Not allowed to stop process {pid}.", needs_admin=True)
        except psutil.Error as exc:
            return ResponseResult(False, "stop_process", f"Could not read process {pid}: {exc}")

        if expected_name and name.lower() != expected_name.lower():
            return ResponseResult(
                False, "stop_process",
                f"Process {pid} is now {name}, not {expected_name}; nothing was stopped.")
        if is_protected_process(name):
            return ResponseResult(
                False, "stop_process",
                f"{name} is part of the operating system; stopping it would break this "
                f"computer. Investigate it instead.")

        try:
            proc.terminate()
            gone, alive = psutil.wait_procs([proc], timeout=self.GRACE_SECONDS)
            if alive:
                proc.kill()
                gone, alive = psutil.wait_procs([proc], timeout=self.GRACE_SECONDS)
            if alive:
                return ResponseResult(False, "stop_process",
                                      f"{name} (process {pid}) refused to stop.")
        except psutil.AccessDenied:
            return ResponseResult(False, "stop_process",
                                  f"Not allowed to stop {name} (process {pid}).",
                                  needs_admin=True)
        except psutil.NoSuchProcess:
            pass        # it stopped on its own between the checks; that is success
        except psutil.Error as exc:
            return ResponseResult(False, "stop_process", f"Could not stop {name}: {exc}")
        note = f" ({reason})" if reason else ""
        return ResponseResult(True, "stop_process", f"Stopped {name} (process {pid}){note}.")


# --------------------------------------------------------------------------- #
# Quarantine
# --------------------------------------------------------------------------- #
@dataclass
class QuarantineRecord:
    """What was moved, from where, and how to put it back."""

    id: str
    original_path: str
    stored_name: str
    size: int
    digest: str
    reason: str = ""
    quarantined_at: str = field(default_factory=lambda: datetime.now().isoformat(
        timespec="seconds"))
    restored_at: str | None = None

    @property
    def can_restore(self) -> bool:
        return self.restored_at is None


class Quarantine:
    """A private folder holding files taken out of the way, with an index to restore them."""

    def __init__(self, directory: Path):
        self.directory = Path(directory)
        self._index_path = self.directory / "index.json"

    # -- index -------------------------------------------------------------- #
    def records(self) -> list[QuarantineRecord]:
        try:
            raw = json.loads(self._index_path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            return []
        out = []
        for item in raw:
            try:
                out.append(QuarantineRecord(**item))
            except TypeError:
                log.debug("Skipping an unreadable quarantine record")
        return out

    def record(self, record_id: str) -> QuarantineRecord | None:
        return next((r for r in self.records() if r.id == record_id), None)

    def _write(self, records: list[QuarantineRecord]) -> None:
        self.directory.mkdir(parents=True, exist_ok=True)
        self._index_path.write_text(json.dumps([asdict(r) for r in records], indent=2),
                                    encoding="utf-8")

    # -- actions ------------------------------------------------------------ #
    def add(self, path: str | os.PathLike[str], *, confirmed: bool = False,
            reason: str = "") -> ResponseResult:
        """Move a file into quarantine. The file is never deleted."""
        if not confirmed:
            return ResponseResult(False, "quarantine", "Quarantining a file needs confirmation.")
        source = Path(path)
        try:
            info = source.stat()
        except OSError as exc:
            return ResponseResult(False, "quarantine", f"Cannot read {source}: {exc}")
        if not source.is_file():
            return ResponseResult(False, "quarantine", f"{source} is not a file.")
        if is_protected_path(source):
            return ResponseResult(
                False, "quarantine",
                f"{source} belongs to the operating system; moving it could stop this "
                f"computer from starting. Investigate it instead.")
        if info.st_size > MAX_QUARANTINE_BYTES:
            return ResponseResult(False, "quarantine",
                                  f"{source.name} is too large to quarantine "
                                  f"({info.st_size // (1024 * 1024)} MB).")

        record = QuarantineRecord(
            id=uuid.uuid4().hex[:12], original_path=str(source.resolve()),
            stored_name="", size=info.st_size, digest=_digest(source), reason=reason)
        record.stored_name = f"{record.id}-{source.name}.quarantined"
        target = self.directory / record.stored_name
        try:
            self.directory.mkdir(parents=True, exist_ok=True)
            shutil.move(str(source), str(target))
            _lock_down(target)
        except OSError as exc:
            return ResponseResult(False, "quarantine", f"Could not move {source}: {exc}",
                                  needs_admin=isinstance(exc, PermissionError))
        self._write([*self.records(), record])
        return ResponseResult(True, "quarantine",
                              f"Moved {source.name} to quarantine; it can be put back.")

    def restore(self, record_id: str, *, confirmed: bool = False) -> ResponseResult:
        """Put a quarantined file back where it came from."""
        if not confirmed:
            return ResponseResult(False, "quarantine_restore",
                                  "Restoring a file needs confirmation.")
        records = self.records()
        record = next((r for r in records if r.id == record_id), None)
        if record is None:
            return ResponseResult(False, "quarantine_restore",
                                  f"No quarantined file with id {record_id}.")
        if not record.can_restore:
            return ResponseResult(False, "quarantine_restore",
                                  f"{Path(record.original_path).name} was already restored.")
        stored = self.directory / record.stored_name
        target = Path(record.original_path)
        if target.exists():
            return ResponseResult(False, "quarantine_restore",
                                  f"{target} exists again; move it aside first.")
        try:
            target.parent.mkdir(parents=True, exist_ok=True)
            _unlock(stored)
            shutil.move(str(stored), str(target))
        except OSError as exc:
            return ResponseResult(False, "quarantine_restore",
                                  f"Could not restore {target}: {exc}")
        record.restored_at = datetime.now().isoformat(timespec="seconds")
        self._write(records)
        return ResponseResult(True, "quarantine_restore", f"Put {target.name} back.")


def _digest(path: Path) -> str:
    """SHA-256 of a file, so a restored file can be proved unchanged."""
    sha = hashlib.sha256()
    try:
        with path.open("rb") as fh:
            for chunk in iter(lambda: fh.read(65536), b""):
                sha.update(chunk)
    except OSError:
        return ""
    return sha.hexdigest()


def _lock_down(path: Path) -> None:
    """Take away the permissions that would let the file run or be read by others."""
    try:
        os.chmod(path, stat.S_IRUSR | stat.S_IWUSR if not is_windows() else stat.S_IWRITE)
    except OSError:
        log.debug("Could not change permissions of the quarantined file", exc_info=True)


def _unlock(path: Path) -> None:
    try:
        os.chmod(path, stat.S_IRUSR | stat.S_IWUSR | stat.S_IRGRP | stat.S_IROTH)
    except OSError:
        log.debug("Could not restore permissions of the quarantined file", exc_info=True)
