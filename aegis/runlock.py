"""One watcher at a time.

Aegis can run as a background process that starts with the computer, and as a
desktop app the person opens. If both watched at once they would poll the same
sockets, write the same events to the same database and raise every alert
twice. So whoever starts first takes a lock, and the other one opens read-only:
it still shows everything the watcher records, it simply does not watch too.

The lock is a small file holding the process id and when it started. A crashed
process leaves the file behind, which is why the holder is verified against the
live process table rather than trusted: a stale lock must never leave a
computer unwatched.
"""
from __future__ import annotations

import json
import logging
import os
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path

log = logging.getLogger(__name__)

LOCK_FILE = "monitor.lock"


@dataclass(frozen=True)
class Holder:
    """The process currently watching."""

    pid: int
    started: str
    kind: str          # "app" or "background"

    @property
    def is_me(self) -> bool:
        return self.pid == os.getpid()

    def describe(self) -> str:
        where = "the background service" if self.kind == "background" else "another Aegis window"
        return f"{where} (process {self.pid})"


def _alive(pid: int) -> bool:
    """Whether a process with this id is running, and is not a recycled stranger."""
    try:
        import psutil

        process = psutil.Process(pid)
        name = process.name().lower()
    except Exception:  # noqa: BLE001 - no such process, or no permission to look
        return False
    # The pid may have been reused by something unrelated since Aegis died.
    return "python" in name or "aegis" in name or "pythonw" in name


class MonitorLock:
    """Claims the right to watch this computer, for as long as it is held."""

    def __init__(self, path: Path, kind: str = "app"):
        self.path = Path(path)
        self.kind = kind
        self._held = False

    # -- reading ------------------------------------------------------------ #
    def holder(self) -> Holder | None:
        """Who is watching right now, or None if nobody is."""
        try:
            data = json.loads(self.path.read_text(encoding="utf-8"))
            holder = Holder(int(data["pid"]), str(data.get("started", "")),
                            str(data.get("kind", "app")))
        except (OSError, ValueError, KeyError, TypeError):
            return None
        if holder.is_me or _alive(holder.pid):
            return holder
        log.info("Ignoring a stale monitor lock left by process %d.", holder.pid)
        return None

    @property
    def held_by_me(self) -> bool:
        return self._held

    # -- taking and giving back --------------------------------------------- #
    def acquire(self) -> bool:
        """Take the lock. False when somebody else is already watching."""
        current = self.holder()
        if current is not None and not current.is_me:
            return False
        try:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            self.path.write_text(json.dumps({
                "pid": os.getpid(), "kind": self.kind,
                "started": datetime.now().isoformat(timespec="seconds"),
            }), encoding="utf-8")
        except OSError:
            # Without a lock file the safe choice is to watch: missing one
            # watcher is worse than the small chance of two.
            log.warning("Could not write the monitor lock; watching anyway.", exc_info=True)
        self._held = True
        return True

    def release(self) -> None:
        if not self._held:
            return
        self._held = False
        holder = self.holder()
        if holder is not None and not holder.is_me:
            return                      # somebody else owns it now; leave theirs alone
        try:
            self.path.unlink(missing_ok=True)
        except OSError:
            log.debug("Could not remove the monitor lock", exc_info=True)
