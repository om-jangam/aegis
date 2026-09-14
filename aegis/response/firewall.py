"""Secure Windows Firewall engine (the "ACT" plane).

This is the hardened replacement for the original project's `netsh` code, which
built command *strings* with raw user input and ran them through ``shell=True``
(a command-injection hole). Here:

* Commands are executed as an **argument list** with ``shell=False`` — shell
  metacharacters in any field can never be interpreted.
* Every user-supplied field is **validated** (:mod:`aegis.core.validators`)
  *before* an argument is built, so malicious input is rejected before the
  command runner is ever called.
* The command runner is **dependency-injected**, making the whole engine unit
  testable without Administrator rights or a real ``netsh``.
* Results are typed (:class:`FirewallResult`) instead of magic integers.

Two public types:

* :class:`FirewallManager` — safe firewall CRUD + containment (`block_ip`).
* :class:`FirewallResponder` — adapts a :class:`~aegis.core.models.Finding`
  into a firewall block action (implements the :class:`Responder` contract).

Known limitation: parsing ``netsh`` text output is oriented to English-locale
field names. The locale-independent path is the Windows COM API
(``INetFwPolicy2``), noted as future work in ``docs/ARCHITECTURE.md``.
"""
from __future__ import annotations

import logging
import re
import subprocess
from collections.abc import Callable
from dataclasses import dataclass

from aegis import LEGACY_RULE_TAG, RULE_TAG
from aegis.core import validators
from aegis.core.models import (
    Finding,
    FirewallAction,
    FirewallDirection,
    FirewallRule,
    Protocol,
)
from aegis.core.validators import ValidationError
from aegis.response.base import Responder, ResponseResult

log = logging.getLogger(__name__)

# Avoid a console window flashing when frozen as a windowed PyInstaller app.
_NO_WINDOW = getattr(subprocess, "CREATE_NO_WINDOW", 0)

_NETSH = ["netsh", "advfirewall", "firewall"]


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


# A command runner takes an argv list + timeout and returns a RunResult.
CommandRunner = Callable[[list[str], int], RunResult]


def _default_runner(args: list[str], timeout: int) -> RunResult:
    """Run a command securely: argument list, no shell, no console window."""
    proc = subprocess.run(
        args,
        capture_output=True,
        shell=False,                 # <- the core security property
        timeout=timeout,
        creationflags=_NO_WINDOW,
    )
    return RunResult(proc.returncode, proc.stdout or b"", proc.stderr or b"")


class FirewallError(Exception):
    pass


class FirewallManager:
    """Safe wrapper around ``netsh advfirewall firewall``."""

    def __init__(self, runner: CommandRunner | None = None, timeout: int = 20):
        self._run_cmd: CommandRunner = runner or _default_runner
        self._timeout = timeout

    # -- low level ---------------------------------------------------------- #
    def _run(self, args: list[str]) -> RunResult:
        try:
            return self._run_cmd(args, self._timeout)
        except subprocess.TimeoutExpired as exc:
            raise FirewallError(f"Command timed out: {' '.join(args)}") from exc
        except FileNotFoundError as exc:
            raise FirewallError("`netsh` not found — Aegis requires Windows.") from exc

    @staticmethod
    def _decode(data: bytes) -> str:
        """Decode netsh output tolerant of the active OEM/ANSI code page."""
        for enc in ("utf-8", "cp1252", "cp437", "latin-1"):
            try:
                return data.decode(enc)
            except UnicodeDecodeError:
                continue
        return data.decode("utf-8", errors="replace")

    # -- argument building (pure, validated, testable) ---------------------- #
    def _build_add_args(self, rule: FirewallRule) -> list[str]:
        """Validate a rule and build the ``netsh add rule`` argument list.

        Raises :class:`ValidationError` if any field is invalid — so a malicious
        value can never be turned into a command argument.
        """
        name = validators.validate_name(rule.name)
        if not (name.startswith(RULE_TAG) or name.startswith(LEGACY_RULE_TAG)):
            name = f"{RULE_TAG} {name}"

        local_ip = validators.validate_ip(rule.local_ip, "Local IP")
        remote_ip = validators.validate_ip(rule.remote_ip, "Remote IP")
        local_port = validators.validate_port(rule.local_port, "Local port")
        remote_port = validators.validate_port(rule.remote_port, "Remote port")
        program = validators.validate_path(rule.program, "Program")

        args = [
            *_NETSH, "add", "rule",
            f"name={name}",
            f"dir={'in' if rule.direction == FirewallDirection.IN else 'out'}",
            f"action={rule.action.value.lower()}",
            f"enable={'yes' if rule.enabled else 'no'}",
        ]

        if rule.protocol != Protocol.ANY:
            proto = "icmpv4" if rule.protocol == Protocol.ICMP else rule.protocol.value.lower()
            args.append(f"protocol={proto}")
            # netsh only accepts port arguments for TCP/UDP.
            if rule.protocol in (Protocol.TCP, Protocol.UDP):
                if local_port != "any":
                    args.append(f"localport={local_port}")
                if remote_port != "any":
                    args.append(f"remoteport={remote_port}")

        if local_ip != "any":
            args.append(f"localip={local_ip}")
        if remote_ip != "any":
            args.append(f"remoteip={remote_ip}")
        if program:
            args.append(f"program={program}")
        if rule.service:
            args.append(f"service={rule.service}")
        if rule.description:
            args.append(f"description={rule.description[:255]}")

        return args

    # -- parsing ------------------------------------------------------------ #
    @staticmethod
    def _extract_blocks(text: str) -> list[str]:
        blocks = re.split(r"(?=Rule Name:)", text)
        return [b.strip() for b in blocks if b.strip() and "Rule Name:" in b]

    @staticmethod
    def _parse_block(block: str) -> dict:
        record: dict[str, str] = {}
        for line in block.splitlines():
            if ":" not in line:
                continue
            key, _, value = line.partition(":")
            key, value = key.strip(), value.strip()
            if key:
                record[key] = value
        return record

    @classmethod
    def _parse_rules(cls, text: str) -> list[dict]:
        return [cls._parse_block(b) for b in cls._extract_blocks(text)]

    @staticmethod
    def _is_aegis_rule(record: dict) -> bool:
        name = record.get("Rule Name", "")
        return name.startswith(RULE_TAG) or name.startswith(LEGACY_RULE_TAG)

    @staticmethod
    def _rule_from_record(record: dict) -> FirewallRule:
        def g(*keys, default=""):
            for k in keys:
                if record.get(k):
                    return record[k]
            return default

        dir_raw = g("Direction", default="In").lower()
        act_raw = g("Action", default="Allow").lower()
        proto_raw = g("Protocol", default="Any").upper()

        direction = FirewallDirection.IN if dir_raw.startswith("in") else FirewallDirection.OUT
        action = {
            "allow": FirewallAction.ALLOW, "block": FirewallAction.BLOCK,
            "bypass": FirewallAction.BYPASS,
        }.get(act_raw, FirewallAction.ALLOW)
        protocol = (
            Protocol.TCP if "TCP" in proto_raw else
            Protocol.UDP if "UDP" in proto_raw else
            Protocol.ICMP if "ICMP" in proto_raw else Protocol.ANY
        )
        return FirewallRule(
            name=g("Rule Name"),
            direction=direction,
            action=action,
            enabled=g("Enabled", default="Yes").lower().startswith("y"),
            protocol=protocol,
            local_ip=g("LocalIP", default="any"),
            local_port=g("LocalPort", default="any"),
            remote_ip=g("RemoteIP", default="any"),
            remote_port=g("RemotePort", default="any"),
            program=g("Program"),
            service=g("Service"),
            description=g("Description"),
            profile=g("Profiles", "Profile"),
        )

    # -- public API --------------------------------------------------------- #
    def list_rules(self, only_aegis: bool = True) -> list[FirewallRule]:
        """Return firewall rules, by default only those created by Aegis."""
        out = self._run([*_NETSH, "show", "rule", "name=all"])
        records = self._parse_rules(self._decode(out.stdout))
        if only_aegis:
            records = [r for r in records if self._is_aegis_rule(r)]
        return [self._rule_from_record(r) for r in records]

    def search_rules(self, keyword: str, only_aegis: bool = False) -> list[FirewallRule]:
        keyword = (keyword or "").casefold()
        out = self._run([*_NETSH, "show", "rule", "name=all"])
        records = self._parse_rules(self._decode(out.stdout))
        results = []
        for record in records:
            if only_aegis and not self._is_aegis_rule(record):
                continue
            if not keyword or any(keyword in str(v).casefold() for v in record.values()):
                results.append(self._rule_from_record(record))
        return results

    def create_rule(self, rule: FirewallRule) -> FirewallResult:
        """Validate and create a firewall rule (auto-tagged with the Aegis prefix)."""
        try:
            args = self._build_add_args(rule)
        except ValidationError as exc:
            # Rejected before any command is run — the injection guarantee.
            log.warning("Rejected invalid firewall rule: %s", exc)
            return FirewallResult(False, f"Invalid rule: {exc}")

        out = self._run(args)
        result = self._interpret(out)
        result.rule_name = args[5].removeprefix("name=")  # for the caller/audit
        return result

    def delete_rule(self, name: str) -> FirewallResult:
        """Delete a rule by its exact (validated) name."""
        try:
            name = validators.validate_name(name)
        except ValidationError as exc:
            return FirewallResult(False, f"Invalid rule name: {exc}")
        out = self._run([*_NETSH, "delete", "rule", f"name={name}"])
        return self._interpret(out)

    def set_rule_enabled(self, name: str, enabled: bool) -> FirewallResult:
        """Enable/disable an existing rule without deleting it."""
        try:
            name = validators.validate_name(name)
        except ValidationError as exc:
            return FirewallResult(False, f"Invalid rule name: {exc}")
        out = self._run([
            *_NETSH, "set", "rule", f"name={name}", "new",
            f"enable={'yes' if enabled else 'no'}",
        ])
        return self._interpret(out)

    def block_ip(self, ip: str, note: str = "", directions: tuple[str, ...] = ("out", "in")) -> FirewallResult:
        """Containment action: block all traffic to/from a remote IP.

        Used by the IDS layer to quarantine a suspicious host. Refuses to block
        'any' (which would sever all connectivity).
        """
        try:
            ip = validators.validate_ip(ip, "Remote IP")
        except ValidationError as exc:
            return FirewallResult(False, f"Invalid IP: {exc}")
        if ip == "any":
            return FirewallResult(False, "Refusing to block 'any' (would cut all traffic).")

        label = f"Block {ip}"
        if note:
            label += f" ({note})"

        last = FirewallResult(False, "No direction blocked.")
        for d in directions:
            rule = FirewallRule(
                name=f"{label} [{d}]",
                direction=FirewallDirection.OUT if d == "out" else FirewallDirection.IN,
                action=FirewallAction.BLOCK,
                remote_ip=ip,
                description=f"Auto-block by Aegis. {note}".strip(),
            )
            last = self.create_rule(rule)
            if not last.ok:
                return last
        return FirewallResult(True, f"Blocked {ip} ({', '.join(directions)}).", rule_name=label)

    # -- result interpretation --------------------------------------------- #
    def _interpret(self, out: RunResult) -> FirewallResult:
        text = (self._decode(out.stdout) + self._decode(out.stderr)).strip()
        lowered = text.lower()
        if out.returncode == 0 and (not text or lowered.startswith("ok")):
            return FirewallResult(True, "Firewall rule applied successfully.")
        if "run as administrator" in lowered or "requires elevation" in lowered:
            return FirewallResult(False, "Administrator privileges required.", needs_admin=True)
        first_line = next((ln for ln in text.splitlines() if ln.strip()), "Unknown error")
        return FirewallResult(out.returncode == 0, first_line)


# --------------------------------------------------------------------------- #
# Responder adapter
# --------------------------------------------------------------------------- #
_IP_RE = re.compile(r"^\s*((?:\d{1,3}\.){3}\d{1,3}|[0-9a-fA-F:]+)")


def _extract_ip(entity: str) -> str:
    """Pull a bare IP from a finding entity like '45.9.1.1:4444'."""
    if not entity:
        return ""
    m = _IP_RE.match(entity)
    if not m:
        return ""
    candidate = m.group(1)
    try:
        return validators.validate_ip(candidate)
    except ValidationError:
        return ""


class FirewallResponder(Responder):
    """Contain a network-based finding by blocking its remote IP."""

    name = "firewall-block"

    def __init__(self, manager: FirewallManager | None = None):
        self._manager = manager or FirewallManager()

    def can_handle(self, finding: Finding) -> bool:
        ip = _extract_ip(finding.entity)
        return bool(ip) and ip != "any"

    def respond(self, finding: Finding) -> ResponseResult:
        ip = _extract_ip(finding.entity)
        if not ip:
            return ResponseResult(False, "block_ip", "No blockable IP in finding.")
        note = f"{finding.rule_id} {finding.technique}".strip()
        result = self._manager.block_ip(ip, note=note)
        return ResponseResult(
            ok=result.ok,
            action="block_ip",
            message=result.message,
            needs_admin=result.needs_admin,
        )


def is_admin() -> bool:
    """True if the current process has Administrator rights."""
    try:
        import ctypes
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:  # noqa: BLE001 - non-Windows or restricted environment
        return False
