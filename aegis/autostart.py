"""Starting Aegis with the computer.

Until now Aegis watched only while its window was open, which is not how people
expect security software to behave: the attack arrives while nobody is looking.
Turning this on registers the *monitor* (not the window) to start when the
person signs in, so the computer stays watched.

Each platform's ordinary, per-user mechanism is used, so nothing needs
administrator rights and anything can be undone by hand:

* **Windows** — a value under ``HKCU\\...\\Run``.
* **Linux** — a systemd *user* service.
* **macOS** — a LaunchAgent in the person's own ``~/Library/LaunchAgents``.

Aegis registers the same command a person could type themselves, and it always
says exactly what it wrote and where, because a security tool that installs
itself invisibly is indistinguishable from the thing it is meant to catch.
"""
from __future__ import annotations

import logging
import plistlib
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path

from aegis.platforms import OS, is_linux, is_macos, is_windows
from aegis.response.command import CommandRunner, decode, default_runner

log = logging.getLogger(__name__)

#: The name Aegis registers itself under, on every platform.
ENTRY_NAME = "Aegis"
RUN_KEY = r"Software\Microsoft\Windows\CurrentVersion\Run"
SERVICE_NAME = "aegis-monitor.service"
LAUNCH_AGENT = "com.aegis.monitor"
SERVICE_UNIT = """[Unit]
Description=Aegis endpoint monitoring
After=network.target

[Service]
Type=simple
ExecStart={command}
Restart=on-failure
RestartSec=30

[Install]
WantedBy=default.target
"""


@dataclass(frozen=True)
class AutostartState:
    """Whether Aegis starts with the computer, and where that is written."""

    enabled: bool
    supported: bool = True
    where: str = ""
    command: str = ""
    detail: str = ""

    def describe(self) -> str:
        if not self.supported:
            return self.detail or "Starting with the computer is not supported here."
        if self.enabled:
            return f"Aegis starts with this computer ({self.where})."
        return "Aegis only watches while its window is open."


def monitor_command() -> list[str]:
    """The command that runs monitoring with no window.

    A packaged build is one executable that takes the same subcommands as the
    installed ``aegis``; from a source checkout it is this interpreter, using
    ``pythonw`` on Windows so no console flashes up at every sign-in.
    """
    if getattr(sys, "frozen", False):
        return [sys.executable, "monitor"]
    python = Path(sys.executable)
    if is_windows():
        windowless = python.with_name("pythonw.exe")
        if windowless.exists():
            python = windowless
    return [str(python), "-m", "aegis", "monitor"]


def quote(command: list[str]) -> str:
    return " ".join(f'"{part}"' if " " in part else part for part in command)


class Autostart:
    """Reads and changes whether Aegis starts with the computer."""

    def __init__(self, runner: CommandRunner | None = None,
                 home: Path | None = None, os_name: OS | None = None):
        self._runner = runner or default_runner
        self._home = Path(home) if home else Path.home()
        self._os = os_name

    # -- platform ----------------------------------------------------------- #
    @property
    def _windows(self) -> bool:
        return is_windows() if self._os is None else self._os is OS.WINDOWS

    @property
    def _linux(self) -> bool:
        return is_linux() if self._os is None else self._os is OS.LINUX

    @property
    def _macos(self) -> bool:
        return is_macos() if self._os is None else self._os is OS.MACOS

    @property
    def service_file(self) -> Path:
        return self._home / ".config" / "systemd" / "user" / SERVICE_NAME

    @property
    def agent_file(self) -> Path:
        return self._home / "Library" / "LaunchAgents" / f"{LAUNCH_AGENT}.plist"

    # -- reading ------------------------------------------------------------ #
    def state(self) -> AutostartState:
        try:
            if self._windows:
                return self._windows_state()
            if self._linux:
                return self._linux_state()
            if self._macos:
                return self._macos_state()
        except Exception as exc:  # noqa: BLE001 - never break the page that shows this
            log.exception("Could not read whether Aegis starts with the computer")
            return AutostartState(False, detail=str(exc))
        return AutostartState(False, supported=False,
                              detail="Starting with the computer is not supported here.")

    def _windows_state(self) -> AutostartState:
        value = self._read_run_value()
        return AutostartState(enabled=bool(value), where=f"HKCU\\{RUN_KEY}\\{ENTRY_NAME}",
                              command=value or "")

    def _linux_state(self) -> AutostartState:
        if not self.service_file.exists():
            return AutostartState(False, where=str(self.service_file))
        out = self._run(["systemctl", "--user", "is-enabled", SERVICE_NAME])
        enabled = out is not None and out.strip().startswith("enabled")
        return AutostartState(enabled=enabled, where=str(self.service_file),
                              command=self._unit_command())

    def _macos_state(self) -> AutostartState:
        if not self.agent_file.exists():
            return AutostartState(False, where=str(self.agent_file))
        try:
            plist = plistlib.loads(self.agent_file.read_bytes())
            command = quote(list(plist.get("ProgramArguments", [])))
        except (OSError, ValueError):
            command = ""
        return AutostartState(enabled=True, where=str(self.agent_file), command=command)

    # -- changing ----------------------------------------------------------- #
    def enable(self, *, confirmed: bool = False) -> tuple[bool, str]:
        """Register Aegis to start with the computer. Returns (ok, message)."""
        if not confirmed:
            return False, "Starting Aegis with the computer needs confirmation."
        command = monitor_command()
        try:
            if self._windows:
                self._write_run_value(quote(command))
                where = f"HKCU\\{RUN_KEY}\\{ENTRY_NAME}"
            elif self._linux:
                where = self._enable_linux(command)
            elif self._macos:
                where = self._enable_macos(command)
            else:
                return False, "Starting with the computer is not supported here."
        except Exception as exc:  # noqa: BLE001 - report, never crash the caller
            log.exception("Could not register Aegis to start with the computer")
            return False, f"Could not set this up: {exc}"
        return True, (f"Aegis will start with this computer. It runs {quote(command)}, "
                      f"registered at {where}.")

    def disable(self, *, confirmed: bool = False) -> tuple[bool, str]:
        """Stop Aegis starting with the computer."""
        if not confirmed:
            return False, "Changing this needs confirmation."
        try:
            if self._windows:
                self._delete_run_value()
            elif self._linux:
                self._run(["systemctl", "--user", "disable", "--now", SERVICE_NAME])
                self.service_file.unlink(missing_ok=True)
                self._run(["systemctl", "--user", "daemon-reload"])
            elif self._macos:
                self._run(["launchctl", "unload", str(self.agent_file)])
                self.agent_file.unlink(missing_ok=True)
            else:
                return False, "Starting with the computer is not supported here."
        except Exception as exc:  # noqa: BLE001
            log.exception("Could not remove the Aegis startup entry")
            return False, f"Could not remove it: {exc}"
        return True, ("Aegis no longer starts with this computer; it watches while its "
                      "window is open.")

    # -- platform details --------------------------------------------------- #
    def _enable_linux(self, command: list[str]) -> str:
        self.service_file.parent.mkdir(parents=True, exist_ok=True)
        self.service_file.write_text(SERVICE_UNIT.format(command=quote(command)),
                                     encoding="utf-8")
        self._run(["systemctl", "--user", "daemon-reload"])
        self._run(["systemctl", "--user", "enable", "--now", SERVICE_NAME])
        return str(self.service_file)

    def _enable_macos(self, command: list[str]) -> str:
        self.agent_file.parent.mkdir(parents=True, exist_ok=True)
        self.agent_file.write_bytes(plistlib.dumps({
            "Label": LAUNCH_AGENT,
            "ProgramArguments": command,
            "RunAtLoad": True,
            "KeepAlive": {"SuccessfulExit": False},
        }))
        self._run(["launchctl", "load", str(self.agent_file)])
        return str(self.agent_file)

    def _unit_command(self) -> str:
        try:
            for line in self.service_file.read_text(encoding="utf-8").splitlines():
                if line.startswith("ExecStart="):
                    return line.split("=", 1)[1].strip()
        except OSError:
            pass
        return ""

    # -- the Windows registry ----------------------------------------------- #
    def _read_run_value(self) -> str | None:
        try:
            import winreg

            with winreg.OpenKey(winreg.HKEY_CURRENT_USER, RUN_KEY) as key:
                value, _ = winreg.QueryValueEx(key, ENTRY_NAME)
                return str(value)
        except (ImportError, OSError):
            return None

    def _write_run_value(self, command: str) -> None:
        import winreg

        with winreg.CreateKeyEx(winreg.HKEY_CURRENT_USER, RUN_KEY, 0,
                                winreg.KEY_SET_VALUE) as key:
            winreg.SetValueEx(key, ENTRY_NAME, 0, winreg.REG_SZ, command)

    def _delete_run_value(self) -> None:
        import winreg

        try:
            with winreg.OpenKey(winreg.HKEY_CURRENT_USER, RUN_KEY, 0,
                                winreg.KEY_SET_VALUE) as key:
                winreg.DeleteValue(key, ENTRY_NAME)
        except FileNotFoundError:
            pass

    def _run(self, args: list[str], timeout: int = 20) -> str | None:
        try:
            result = self._runner(args, timeout)
        except (OSError, subprocess.SubprocessError):
            return None
        return decode(result.stdout) if result.returncode == 0 else None
