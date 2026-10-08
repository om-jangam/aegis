"""What is installed on this computer, and which version.

Most computers are not broken into through a clever new trick. They are broken
into through a program the owner installed and never updated, for which the
flaw is public and the exploit is on the shelf. Answering "what is installed
here, and is any of it known to be vulnerable?" needs a list first, and that is
all this module produces: names and version numbers.

Nothing here reaches the network, and nothing is changed. The list is read from
the places the operating system already keeps it: the uninstall entries in the
Windows registry, the package manager on Linux, the application bundles on
macOS. Every reader is injectable, so the whole module is testable on any OS.
"""
from __future__ import annotations

import re
from collections.abc import Callable, Iterable
from dataclasses import dataclass

from aegis.platforms import CURRENT_OS, OS
from aegis.response.command import CommandRunner, decode, default_runner

#: Registry roots holding uninstall entries: 64-bit, 32-bit, and per-user.
UNINSTALL_KEYS: tuple[tuple[str, str], ...] = (
    ("HKLM", r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall"),
    ("HKLM", r"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall"),
    ("HKCU", r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall"),
)

# Bitness, locale and installation-scope decorations that belong to the
# installer rather than to the product.
_PAREN_NOISE = re.compile(
    r"\(\s*(?:x64|x86|amd64|arm64|32[- ]?bit|64[- ]?bit|user|machine|per[- ]user)\s*\)",
    re.IGNORECASE)
_LOCALE = re.compile(r"\s-\s[a-z]{2}-[a-z]{2}\b", re.IGNORECASE)
_BITNESS = re.compile(r"\s+(?:32|64)[- ]?bit\b", re.IGNORECASE)
# A trailing version needs a dot, or the word "version" in front of it, so a
# year that is part of the product name ("Visual C++ 2012") is never taken for
# a version and stripped.
_TRAILING_VERSION = re.compile(r"\s+(?:version\s+)?v?\d+(?:\.\d+)+\s*$", re.IGNORECASE)
_TRAILING_NAMED_VERSION = re.compile(r"\s+version\s+v?\d[\w.]*\s*$", re.IGNORECASE)
#: A version sitting inside the display name. Vendors keep that one closer to
#: the version their advisories name than the registry's DisplayVersion field.
_VERSION_IN_NAME = re.compile(r"(?<![\w.])(\d+(?:\.\d+){1,3})(?![\w.])")
_VERSION_CHARS = re.compile(r"^[0-9][0-9.]*$")

#: Entries that are a piece of Windows or a driver rather than a program
#: somebody chose to install. They carry no useful public vulnerability record,
#: and listing them would bury the ones that matter.
_SKIP_NAMES = re.compile(
    r"^(?:microsoft\s+(?:visual\s+c\+\+|windows\s+(?:desktop\s+)?runtime"
    r"|\.net\s+runtime|edge\s+webview|gameinput|windows\s+application)"
    r"|windows\s+(?:driver|software)\s)", re.IGNORECASE)


@dataclass(frozen=True)
class Program:
    """One installed program, as its own installer described it."""

    name: str
    version: str = ""
    publisher: str = ""
    source: str = ""

    @property
    def product(self) -> str:
        """The name with installer decoration removed, for looking it up."""
        return clean_name(self.name)

    @property
    def key(self) -> str:
        """Stable identity for caching: same program and version, same key."""
        return f"{self.product.lower()}@{self.version}"

    def to_dict(self) -> dict:
        return {"name": self.name, "version": self.version,
                "publisher": self.publisher, "source": self.source,
                "product": self.product}


def clean_name(display: str) -> str:
    """Strip bitness, locale and a trailing version from a display name."""
    name = _PAREN_NOISE.sub(" ", display or "")
    name = _LOCALE.sub(" ", name)
    name = _BITNESS.sub(" ", name)
    for _ in range(4):               # "Foo 1.2 - 3.4" needs more than one pass
        shorter = _TRAILING_NAMED_VERSION.sub("", name)
        shorter = _TRAILING_VERSION.sub("", shorter).strip(" -")
        if not shorter or shorter == name.strip(" -"):
            name = shorter or name
            break
        name = shorter
    return " ".join(name.split())


def clean_version(program_name: str, display_version: str) -> str:
    """The version to look up.

    Prefers the one printed in the display name: vendors put the version their
    advisories name there ("Python 3.12.10"), while the registry's
    DisplayVersion is often an internal build number ("3.12.10150.0").
    """
    in_name = _VERSION_IN_NAME.search(program_name or "")
    if in_name:
        return in_name.group(1)
    version = (display_version or "").strip()
    return version if _VERSION_CHARS.match(version) else ""


def is_interesting(program: Program) -> bool:
    """Whether a program is worth looking up at all."""
    return bool(program.product and program.version
                and not _SKIP_NAMES.match(program.product))


# --------------------------------------------------------------------------- #
# Readers, one per platform
# --------------------------------------------------------------------------- #
#: Takes (hive, key path) and yields one dict of values per subkey.
RegistryLister = Callable[[str, str], Iterable[dict[str, object]]]


def _registry_subkey_values(key) -> dict[str, object]:
    import winreg

    values: dict[str, object] = {}
    for index in range(winreg.QueryInfoKey(key)[1]):
        try:
            name, value, _ = winreg.EnumValue(key, index)
        except OSError:
            break
        values[name] = value
    return values


def _list_registry_subkeys(hive: str, key_path: str) -> list[dict[str, object]]:
    """Every subkey's values under one uninstall root; empty off Windows."""
    try:
        import winreg
    except ImportError:
        return []
    roots = {"HKLM": winreg.HKEY_LOCAL_MACHINE, "HKCU": winreg.HKEY_CURRENT_USER}
    root = roots.get(hive)
    if root is None:
        return []
    access = winreg.KEY_READ | getattr(winreg, "KEY_WOW64_64KEY", 0)
    entries: list[dict[str, object]] = []
    try:
        with winreg.OpenKey(root, key_path, 0, access) as key:
            for index in range(winreg.QueryInfoKey(key)[0]):
                try:
                    name = winreg.EnumKey(key, index)
                    with winreg.OpenKey(key, name, 0, access) as sub:
                        entries.append(_registry_subkey_values(sub))
                except OSError:
                    continue            # one unreadable entry is not a failure
    except OSError:
        return []
    return entries


def windows_programs(lister: RegistryLister = _list_registry_subkeys) -> list[Program]:
    """Installed programs from the Windows uninstall entries."""
    found: dict[str, Program] = {}
    for hive, key_path in UNINSTALL_KEYS:
        for values in lister(hive, key_path):
            name = str(values.get("DisplayName") or "").strip()
            if not name or values.get("SystemComponent"):
                continue
            if values.get("ParentKeyName") or values.get("ReleaseType"):
                continue            # an update or hotfix for something else
            program = Program(
                name=name,
                version=clean_version(name, str(values.get("DisplayVersion") or "")),
                publisher=str(values.get("Publisher") or "").strip(),
                source="registry")
            found.setdefault(program.key, program)
    return sorted(found.values(), key=lambda p: p.name.lower())


def _package_version(raw: str) -> str:
    """The upstream part of a package version: 1:2.34-1ubuntu1 -> 2.34."""
    version = raw.strip().split(":")[-1].split("-")[0].split("+")[0]
    match = _VERSION_IN_NAME.search(version)
    return match.group(1) if match else ""


def _run_lines(runner: CommandRunner, args: list[str], source: str) -> list[Program]:
    try:
        result = runner(args, 60)
    except Exception:               # noqa: BLE001 - a missing tool is not an error
        return []
    if result.returncode != 0:
        return []
    programs: list[Program] = []
    for line in decode(result.stdout).splitlines():
        name, _, version = line.partition("\t")
        if name.strip():
            programs.append(Program(name.strip(), _package_version(version),
                                    source=source))
    return sorted(programs, key=lambda p: p.name.lower())


def linux_programs(runner: CommandRunner = default_runner) -> list[Program]:
    """Installed packages from dpkg, or from rpm where dpkg is absent."""
    programs = _run_lines(runner, ["dpkg-query", "-W", "-f=${Package}\t${Version}\n"],
                          "dpkg")
    if programs:
        return programs
    return _run_lines(runner, ["rpm", "-qa", "--qf", "%{NAME}\t%{VERSION}\n"], "rpm")


def _plist_value(plist: str, key: str) -> str:
    match = re.search(rf"<key>{re.escape(key)}</key>\s*<string>([^<]*)</string>", plist)
    return match.group(1).strip() if match else ""


def macos_programs(glob: Callable[[str], list[str]],
                   read_text: Callable[[str], str | None]) -> list[Program]:
    """Installed applications from their bundle metadata."""
    programs: list[Program] = []
    for app in sorted(glob("/Applications/*.app")):
        plist = read_text(f"{app}/Contents/Info.plist") or ""
        name = app.rsplit("/", 1)[-1].removesuffix(".app")
        version = _plist_value(plist, "CFBundleShortVersionString")
        programs.append(Program(name, clean_version(name, version),
                                source="applications"))
    return programs


def _read_file(path: str) -> str | None:
    from pathlib import Path

    try:
        return Path(path).read_text(encoding="utf-8", errors="replace")
    except OSError:
        return None


def installed_programs(os_name: OS = CURRENT_OS, **readers) -> list[Program]:
    """Every installed program this platform can tell us about."""
    if os_name is OS.WINDOWS:
        return windows_programs(readers.get("lister", _list_registry_subkeys))
    if os_name is OS.LINUX:
        return linux_programs(readers.get("runner", default_runner))
    if os_name is OS.MACOS:
        import glob as _glob

        return macos_programs(readers.get("glob", _glob.glob),
                              readers.get("read_text", _read_file))
    return []
