"""File integrity monitoring — the collector a HIDS is defined by.

Aegis watched sockets and processes but not the filesystem, which left it blind
to the thing host intrusion detection exists for: something changing files it
has no business changing. A backdoored ``sshd``, a new cron entry, an added SSH
authorized key and ransomware rewriting a user's documents are all invisible in
socket and process telemetry, and all obvious here.

How it works
------------
A **baseline** records size, mtime and content digest for every watched file.
Each poll re-stats those files and compares. The comparison is deliberately
two-tier: size and mtime are read from the directory entry and cost almost
nothing, so a file is only hashed when that cheap check says it may have
changed. Hashing every watched file every poll would make the collector the
most expensive thing on the host.

Work is also **bounded per poll** (:attr:`FileIntegrityCollector.hash_budget`).
A monitoring tool that stalls the machine it protects gets uninstalled, so a
large tree is absorbed across several polls instead of one long freeze.

The first poll **establishes** the baseline and reports nothing: without that,
every file on the host would be reported as newly created on startup.
"""
from __future__ import annotations

import hashlib
import json
import logging
import os
import stat
from collections.abc import Iterable, Iterator
from pathlib import Path

from aegis.collectors.base import Collector
from aegis.config import settings
from aegis.core.events import EventSource, EventType, FileEvent
from aegis.platforms import data_dir, is_linux, is_macos, is_windows

log = logging.getLogger(__name__)

#: Read size when hashing. Large enough to be efficient, small enough not to
#: hold a big buffer per file.
_CHUNK = 65536


def default_watch_paths() -> list[str]:
    """High-value, low-volume paths worth watching on this platform.

    Deliberately small. Watching all of ``C:\\Windows\\System32`` or ``/usr``
    would cost far more than it detects; these are the locations where an
    unexpected change is, on its own, strong evidence of compromise.
    """
    home = Path.home()
    if is_windows():
        system_root = Path(os.environ.get("SystemRoot", r"C:\Windows"))
        appdata = os.environ.get("APPDATA")
        paths = [
            system_root / "System32" / "drivers" / "etc",
            system_root / "Tasks",
        ]
        if appdata:
            paths.append(Path(appdata) / "Microsoft" / "Windows" / "Start Menu"
                         / "Programs" / "Startup")
    elif is_macos():
        paths = [
            Path("/etc"),
            Path("/Library/LaunchDaemons"),
            Path("/Library/LaunchAgents"),
            home / "Library" / "LaunchAgents",
            home / ".ssh",
        ]
    elif is_linux():
        paths = [
            Path("/etc/cron.d"),
            Path("/etc/systemd/system"),
            Path("/etc/ssh"),
            Path("/etc/passwd"),
            Path("/etc/shadow"),
            Path("/etc/sudoers"),
            Path("/etc/sudoers.d"),
            home / ".ssh",
            home / ".config" / "systemd" / "user",
        ]
    else:
        paths = []
    return [str(p) for p in paths]


def hash_file(path: Path, algorithm: str = "sha256", max_bytes: int = 0) -> str:
    """Content digest of ``path``, or ``""`` if it cannot be read.

    ``max_bytes`` of 0 means no limit. Files above the limit are digested from
    their first ``max_bytes`` and marked, so a multi-gigabyte file still gets a
    change signal without being read in full on every poll.
    """
    digest = hashlib.new(algorithm)
    read = 0
    try:
        with path.open("rb") as handle:
            while True:
                chunk = handle.read(_CHUNK)
                if not chunk:
                    break
                digest.update(chunk)
                read += len(chunk)
                if max_bytes and read >= max_bytes:
                    return f"{digest.hexdigest()}:partial"
    except (OSError, ValueError):
        return ""
    return digest.hexdigest()


class FileIntegrityCollector(Collector):
    """Detects changes to watched files by comparing against a stored baseline."""

    name = "filesystem"
    source = EventSource.FILESYSTEM

    #: Files hashed per poll. Bounds CPU so a large tree never stalls the host.
    hash_budget = 400
    #: Hard cap on tracked files, so a misconfigured path cannot exhaust memory.
    max_tracked_files = 20000

    def __init__(self, paths: list[str] | None = None,
                 baseline_path: Path | None = None,
                 algorithm: str = "sha256",
                 max_file_size: int = 64 * 1024 * 1024):
        super().__init__()
        self._configured_paths = paths
        self._baseline_path = baseline_path or (data_dir() / "fim_baseline.json")
        self._algorithm = algorithm
        self._max_file_size = max_file_size
        self._baseline: dict[str, dict] = {}
        self._established = False
        self._load_baseline()

    # -- configuration ------------------------------------------------------ #
    @property
    def watch_paths(self) -> list[str]:
        if self._configured_paths is not None:
            return self._configured_paths
        configured = list(getattr(settings, "fim_paths", []) or [])
        return configured or default_watch_paths()

    def available(self) -> bool:
        if not getattr(settings, "fim_enabled", True):
            return False
        return any(Path(p).exists() for p in self.watch_paths)

    # -- baseline persistence ----------------------------------------------- #
    def _load_baseline(self) -> None:
        try:
            data = json.loads(self._baseline_path.read_text(encoding="utf-8"))
            self._baseline = data.get("files", {})
            self._established = bool(self._baseline)
        except (OSError, json.JSONDecodeError, AttributeError):
            self._baseline, self._established = {}, False

    def _save_baseline(self) -> None:
        try:
            self._baseline_path.parent.mkdir(parents=True, exist_ok=True)
            tmp = self._baseline_path.with_suffix(".json.tmp")
            tmp.write_text(
                json.dumps({"algorithm": self._algorithm, "files": self._baseline}),
                encoding="utf-8")
            tmp.replace(self._baseline_path)
        except OSError:
            log.exception("Could not persist the file integrity baseline")

    def reset_baseline(self) -> None:
        """Forget the baseline so the next poll re-establishes it.

        Used after a deliberate change (a package upgrade) to accept the new
        state as normal rather than alerting on every file it touched.
        """
        self._baseline, self._established = {}, False
        self._save_baseline()

    # -- scanning ------------------------------------------------------------ #
    def _iter_files(self) -> Iterator[Path]:
        seen = 0
        for root in self.watch_paths:
            path = Path(root)
            try:
                if path.is_file():
                    yield path
                    seen += 1
                    continue
                if not path.is_dir():
                    continue
                for dirpath, dirnames, filenames in os.walk(path, followlinks=False):
                    # Symlinked directories are skipped: following them can
                    # escape the watched tree entirely, or loop forever.
                    dirnames[:] = [d for d in dirnames
                                   if not os.path.islink(os.path.join(dirpath, d))]
                    for filename in filenames:
                        yield Path(dirpath) / filename
                        seen += 1
                        if seen >= self.max_tracked_files:
                            log.warning(
                                "FIM reached its %d file cap; narrow fim_paths.",
                                self.max_tracked_files)
                            return
            except (OSError, PermissionError):
                continue

    @staticmethod
    def _stat_of(path: Path) -> tuple[int, float, str] | None:
        try:
            info = path.lstat()
        except (OSError, PermissionError):
            return None
        if not stat.S_ISREG(info.st_mode):
            return None       # devices, sockets and symlinks are not content
        return info.st_size, info.st_mtime, stat.filemode(info.st_mode)

    def poll(self) -> Iterable[FileEvent]:
        events: list[FileEvent] = []
        current: dict[str, dict] = {}
        hashed = 0

        for path in self._iter_files():
            stats = self._stat_of(path)
            if stats is None:
                continue
            size, mtime, mode = stats
            key = str(path)
            known = self._baseline.get(key)

            # The cheap check: an unchanged size and mtime means the content is
            # almost certainly unchanged, so skip the expensive hash.
            unchanged = (known is not None
                         and known.get("size") == size
                         and known.get("mtime") == mtime)
            if unchanged and known is not None:
                current[key] = known
                continue

            if hashed >= self.hash_budget:
                # Out of budget this poll: carry the old record forward so the
                # file is not misreported as deleted, and revisit it next time.
                if known is not None:
                    current[key] = known
                continue

            digest = hash_file(path, self._algorithm, self._max_file_size)
            hashed += 1
            record = {"size": size, "mtime": mtime, "digest": digest, "mode": mode}
            current[key] = record

            if not self._established:
                continue
            if known is None:
                events.append(FileEvent(
                    type=EventType.FILE_CREATED, source=self.source,
                    path=key, size=size, digest=digest, mode=mode))
            elif known.get("digest") != digest:
                events.append(FileEvent(
                    type=EventType.FILE_MODIFIED, source=self.source,
                    path=key, size=size, previous_size=known.get("size", 0),
                    digest=digest, previous_digest=known.get("digest", ""), mode=mode))

        if self._established:
            for key, known in self._baseline.items():
                if key not in current:
                    events.append(FileEvent(
                        type=EventType.FILE_DELETED, source=self.source,
                        path=key, previous_size=known.get("size", 0),
                        previous_digest=known.get("digest", ""),
                        mode=known.get("mode", "")))

        self._baseline = current
        if not self._established:
            self._established = True
            log.info("File integrity baseline established over %d files.", len(current))
        self._save_baseline()
        return events

    @property
    def tracked_count(self) -> int:
        return len(self._baseline)

    @property
    def baseline_established(self) -> bool:
        return self._established
