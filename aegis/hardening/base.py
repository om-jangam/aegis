"""The fix contract and the context fixes act through.

A :class:`Fix` knows one thing: how to move a setting from a weak value to a
safe one and back. It does not decide *whether* to act. Confirmation, the
privilege check, the backup, verification and the record are enforced by
:class:`~aegis.hardening.engine.HardeningEngine` for every fix alike, so no
individual fix can skip a safeguard.

Like posture checks, fixes read and write only through their context. Every
write (registry, file, permission, command) is a replaceable function, so each
fix is unit-tested on any OS without touching the machine running the tests.
"""
from __future__ import annotations

import abc
import os
import stat
import tempfile
from collections.abc import Callable
from dataclasses import dataclass

from aegis.platforms import OS
from aegis.posture.base import PostureContext


class HardeningError(Exception):
    """A fix could not read, change or restore a setting."""


@dataclass(frozen=True)
class Change:
    """One setting a fix will change: where it lives, its value now and its target."""

    setting: str
    current: str
    target: str

    def to_dict(self) -> dict:
        return {"setting": self.setting, "current": self.current, "target": self.target}


# --------------------------------------------------------------------------- #
# Default, real-system writers
# --------------------------------------------------------------------------- #
def _write_registry(key_path: str, name: str, value, kind: str) -> None:
    """Set (or, when ``value`` is None, delete) a value under HKEY_LOCAL_MACHINE."""
    try:
        import winreg
    except ImportError as exc:
        raise HardeningError("The Windows registry is not available here.") from exc
    access = winreg.KEY_SET_VALUE | getattr(winreg, "KEY_WOW64_64KEY", 0)
    try:
        with winreg.CreateKeyEx(winreg.HKEY_LOCAL_MACHINE, key_path, 0, access) as key:
            if value is None:
                try:
                    winreg.DeleteValue(key, name)
                except FileNotFoundError:
                    pass
            elif kind == "dword":
                winreg.SetValueEx(key, name, 0, winreg.REG_DWORD, int(value))
            else:
                winreg.SetValueEx(key, name, 0, winreg.REG_SZ, str(value))
    except PermissionError as exc:
        raise HardeningError("Changing this setting needs administrator rights.") from exc
    except OSError as exc:
        raise HardeningError(f"Could not change HKLM\\{key_path}\\{name}: {exc}") from exc


def _write_text(path: str, text: str) -> None:
    """Replace a file atomically, keeping its permissions."""
    directory = os.path.dirname(path) or "."
    try:
        mode = stat.S_IMODE(os.stat(path).st_mode)
    except OSError:
        mode = 0o644
    fd, tmp = tempfile.mkstemp(dir=directory, prefix=".aegis-")
    try:
        with os.fdopen(fd, "w", encoding="utf-8", newline="") as fh:
            fh.write(text)
        os.chmod(tmp, mode)
        os.replace(tmp, path)
    except OSError as exc:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise HardeningError(f"Could not write {path}: {exc}") from exc


def _chmod(path: str, mode: int) -> None:
    try:
        os.chmod(path, mode)
    except OSError as exc:
        raise HardeningError(f"Could not change permissions of {path}: {exc}") from exc


@dataclass
class HardeningContext(PostureContext):
    """A posture context that can also change settings. Swap any writer in tests."""

    write_registry: Callable[[str, str, object, str], None] = _write_registry
    write_text: Callable[[str, str], None] = _write_text
    chmod: Callable[[str, int], None] = _chmod

    def must_run(self, args: list[str], what: str, timeout: int = 60) -> str:
        """Run a command that changes something; raise unless it succeeds."""
        out = self.run(args, timeout)
        if out is None:
            raise HardeningError(f"Could not {what}: {args[0]} is not available.")
        code, text = out
        if code != 0:
            detail = text.strip().splitlines()[-1] if text.strip() else f"exit code {code}"
            raise HardeningError(f"Could not {what}: {detail}")
        return text


# --------------------------------------------------------------------------- #
# The fix contract
# --------------------------------------------------------------------------- #
class Fix(abc.ABC):
    fix_id: str = "FIX"
    #: The security check this fix resolves (all or part of).
    check_id: str = ""
    #: Short action, e.g. "Turn on Windows Firewall".
    title: str = ""
    #: Why the weakness matters, in plain language.
    risk: str = ""
    #: What the person will notice afterwards, including side effects.
    effect: str = ""
    platforms: tuple[OS, ...] = ()
    requires_admin: bool = True
    #: Whether undo restores everything. A partial undo is explained in ``effect``.
    reversible: bool = True
    #: Set when the change only fully applies after a restart.
    restart_note: str = ""

    def applies(self, ctx: PostureContext) -> bool:
        return not self.platforms or ctx.os in self.platforms

    @abc.abstractmethod
    def plan(self, ctx: HardeningContext) -> list[Change]:
        """The changes still needed. An empty list means the setting is already safe.

        Called before applying (to show the person what will change) and again
        afterwards (to verify that nothing is left to change).
        """

    def snapshot(self, ctx: HardeningContext) -> dict:
        """The current values, saved before applying so the fix can be undone."""
        return {}

    @abc.abstractmethod
    def apply(self, ctx: HardeningContext) -> str:
        """Make the change. Returns an optional note for the person."""

    def restore(self, ctx: HardeningContext, backup: dict) -> str:
        """Put the settings in ``backup`` back. Returns an optional note."""
        raise HardeningError("This change cannot be undone automatically.")

    def describe(self) -> dict:
        return {"id": self.fix_id, "check_id": self.check_id, "title": self.title,
                "risk": self.risk, "effect": self.effect,
                "requires_admin": self.requires_admin, "reversible": self.reversible,
                "restart_note": self.restart_note}


# --------------------------------------------------------------------------- #
# Registry-backed fixes (most Windows settings)
# --------------------------------------------------------------------------- #
@dataclass(frozen=True)
class RegistryValue:
    key: str
    name: str
    target: object          # None means "remove the value"
    kind: str = "dword"     # "dword" or "sz"
    #: Never read out, shown or backed up (e.g. a stored password).
    secret: bool = False
    #: Windows treats an absent value as safe, so there is nothing to change.
    missing_is_safe: bool = False


def _shown(value) -> str:
    return "(not set)" if value is None else str(value)


class RegistryFix(Fix):
    platforms = (OS.WINDOWS,)
    VALUES: tuple[RegistryValue, ...] = ()

    @staticmethod
    def _pending(current, value: RegistryValue) -> bool:
        if value.target is None:
            return current is not None
        if current is None:
            return not value.missing_is_safe
        return str(current).strip() != str(value.target)

    def plan(self, ctx: HardeningContext) -> list[Change]:
        changes = []
        for value in self.VALUES:
            current = ctx.read_registry(value.key, value.name)
            if not self._pending(current, value):
                continue
            shown = "(stored, not shown)" if value.secret else _shown(current)
            target = "(removed)" if value.target is None else str(value.target)
            changes.append(Change(f"HKLM\\{value.key}\\{value.name}", shown, target))
        return changes

    def snapshot(self, ctx: HardeningContext) -> dict:
        saved = []
        for value in self.VALUES:
            if value.secret:
                continue
            current = ctx.read_registry(value.key, value.name)
            saved.append({"key": value.key, "name": value.name, "kind": value.kind,
                          "value": current if isinstance(current, (int, str)) else None})
        return {"registry": saved}

    def apply(self, ctx: HardeningContext) -> str:
        for value in self.VALUES:
            if self._pending(ctx.read_registry(value.key, value.name), value):
                ctx.write_registry(value.key, value.name, value.target, value.kind)
        return self.restart_note

    def restore(self, ctx: HardeningContext, backup: dict) -> str:
        for item in backup.get("registry", []):
            ctx.write_registry(item["key"], item["name"], item["value"], item["kind"])
        return self.restart_note

