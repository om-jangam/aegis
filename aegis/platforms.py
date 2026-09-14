"""Platform detection, privilege checks and per-OS filesystem locations.

Aegis runs on Windows, Linux and macOS. The differences between them are
confined to this module so the rest of the codebase can ask *what* it needs
(the data directory, whether we are elevated) without branching on
``sys.platform`` in a dozen places.

Named ``platforms`` (plural) rather than ``platform`` so it can never be
confused with the standard-library module it wraps.
"""
from __future__ import annotations

import os
import subprocess
import sys
from enum import StrEnum
from pathlib import Path


class OS(StrEnum):
    """The host operating system family Aegis is running on."""

    WINDOWS = "windows"
    LINUX = "linux"
    MACOS = "macos"
    UNKNOWN = "unknown"


def _detect() -> OS:
    if sys.platform.startswith("win"):
        return OS.WINDOWS
    if sys.platform.startswith("linux"):
        return OS.LINUX
    if sys.platform == "darwin":
        return OS.MACOS
    return OS.UNKNOWN


CURRENT_OS: OS = _detect()


def is_windows() -> bool:
    return CURRENT_OS is OS.WINDOWS


def is_linux() -> bool:
    return CURRENT_OS is OS.LINUX


def is_macos() -> bool:
    return CURRENT_OS is OS.MACOS


def is_posix() -> bool:
    return CURRENT_OS in (OS.LINUX, OS.MACOS)


# --------------------------------------------------------------------------- #
# Privileges
# --------------------------------------------------------------------------- #
def is_elevated() -> bool:
    """True if the process can modify firewall state.

    Administrator on Windows, root (uid 0) on Linux/macOS. Monitoring never
    needs this; only rule creation and containment do.
    """
    if is_windows():
        try:
            import ctypes

            return bool(ctypes.windll.shell32.IsUserAnAdmin())  # type: ignore[attr-defined]
        except Exception:  # noqa: BLE001 - restricted or non-Windows environment
            return False
    try:
        return os.geteuid() == 0
    except AttributeError:  # pragma: no cover - geteuid missing off POSIX
        return False


def privilege_hint() -> str:
    """How this user should re-launch Aegis to get response capability."""
    if is_windows():
        return "Run Aegis as Administrator to create firewall rules or block hosts."
    return "Run Aegis with sudo to create firewall rules or block hosts."


# --------------------------------------------------------------------------- #
# Filesystem locations
# --------------------------------------------------------------------------- #
def data_dir() -> Path:
    """Return the per-user application-data directory, creating it if needed.

    Follows each platform's own convention so Aegis never writes next to its
    own executable (which would need admin rights under Program Files):

    * Windows — ``%LOCALAPPDATA%\\Aegis``
    * macOS   — ``~/Library/Application Support/Aegis``
    * Linux   — ``$XDG_DATA_HOME/aegis`` (default ``~/.local/share/aegis``)

    ``AEGIS_DATA_DIR`` overrides all of the above, which keeps tests and
    containerised agents from touching the real user profile.
    """
    override = os.environ.get("AEGIS_DATA_DIR")
    if override:
        path = Path(override).expanduser()
    elif is_windows():
        base = os.environ.get("LOCALAPPDATA") or os.environ.get("APPDATA")
        path = (Path(base) if base else Path.home()) / "Aegis"
    elif is_macos():
        path = Path.home() / "Library" / "Application Support" / "Aegis"
    else:
        base = os.environ.get("XDG_DATA_HOME")
        path = (Path(base) if base else Path.home() / ".local" / "share") / "aegis"
    path.mkdir(parents=True, exist_ok=True)
    return path


# --------------------------------------------------------------------------- #
# Subprocess hygiene
# --------------------------------------------------------------------------- #
# Suppresses the console window that would otherwise flash when a frozen,
# windowed build shells out. Resolves to 0 (no-op) off Windows.
NO_WINDOW: int = getattr(subprocess, "CREATE_NO_WINDOW", 0)


def which(binary: str) -> str | None:
    """Absolute path to ``binary`` on PATH, or None if it is not installed.

    Used by the firewall backends to report an actionable "nftables is not
    installed" instead of an opaque FileNotFoundError.
    """
    from shutil import which as _which

    return _which(binary)
