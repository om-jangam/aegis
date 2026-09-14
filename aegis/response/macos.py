"""Secure macOS firewall engine (pf) — the macOS "ACT" plane.

Implements the same :class:`~aegis.response.backend.FirewallBackend` contract as
the Windows and Linux engines, with the same security properties: validated
input, argument-list execution, no ``shell=True``, injected command runner.

Design notes specific to pf
---------------------------
Unlike ``netsh`` and ``nft``, pf is **declarative** — you load a complete
ruleset rather than mutating rules one at a time. Aegis therefore keeps its rule
definitions in a sidecar file, renders the whole Aegis ruleset from it, and loads
that into a private pf **anchor** named ``aegis``. Nothing outside the anchor is
touched, so Aegis can never disturb macOS's own ``com.apple`` rules, and
enable/disable falls out naturally: a disabled rule is simply not rendered.

One-time host setup
-------------------
pf only evaluates an anchor that ``/etc/pf.conf`` references. Because editing
that file is a privileged, system-wide change, Aegis does **not** do it silently
— :meth:`PfManager.anchor_installed` reports whether it is wired up and
:meth:`PfManager.setup_instructions` tells the user exactly what to add.
"""
from __future__ import annotations

import ipaddress
import json
import logging
import subprocess
from dataclasses import asdict
from pathlib import Path

from aegis import LEGACY_RULE_TAG, RULE_TAG
from aegis.core import validators
from aegis.core.models import (
    FirewallAction,
    FirewallDirection,
    FirewallRule,
    Protocol,
)
from aegis.core.validators import ValidationError
from aegis.platforms import data_dir, is_macos, which
from aegis.response.backend import FirewallBackend
from aegis.response.command import (
    CommandRunner,
    FirewallError,
    FirewallResult,
    RunResult,
    decode,
    default_runner,
)

log = logging.getLogger(__name__)

_PFCTL = "pfctl"
ANCHOR = "aegis"
PF_CONF = Path("/etc/pf.conf")


def _addr_expr(value: str, field: str) -> str:
    """Render a validated IP token as a pf address expression.

    pf understands single addresses and CIDR but has no dash-range syntax (that
    needs a table), so a range is rejected with an explanatory message rather
    than being silently translated into something that means something else.
    """
    if "-" in value:
        raise ValidationError(
            f"{field}: pf does not support '{value}' address ranges — use CIDR "
            f"notation (e.g. 192.168.1.0/24) on macOS."
        )
    return value


def _port_expr(port: str) -> str:
    """Render a validated port token as a pf port expression.

    ``443`` -> ``port 443``; ``8000-8080`` -> ``port 8000:8080``;
    ``80,443`` -> ``port { 80, 443 }``.
    """
    if "," in port:
        return "port { " + ", ".join(p.strip() for p in port.split(",")) + " }"
    if "-" in port:
        lo, _, hi = port.partition("-")
        return f"port {lo.strip()}:{hi.strip()}"
    return f"port {port}"


def _af_for(*addresses: str) -> str:
    """pf address-family keyword implied by the addresses in a rule."""
    for value in addresses:
        token = value.split("/")[0].strip()
        try:
            if ipaddress.ip_address(token).version == 6:
                return "inet6"
        except ValueError:
            continue
    return "inet"


class PfManager(FirewallBackend):
    """Safe wrapper around ``pfctl`` using a private Aegis anchor."""

    backend_name = "macOS pf"
    required_binary = _PFCTL

    def __init__(self, runner: CommandRunner | None = None, timeout: int = 20,
                 state_path: Path | None = None, anchor_path: Path | None = None):
        self._run_cmd: CommandRunner = runner or default_runner
        self._timeout = timeout
        base = data_dir()
        self._state_path = state_path or (base / "pf_rules.json")
        self._anchor_path = anchor_path or (base / "pf.aegis.conf")

    def available(self) -> bool:
        return is_macos() and which(_PFCTL) is not None

    # -- low level ---------------------------------------------------------- #
    def _run(self, args: list[str]) -> RunResult:
        try:
            return self._run_cmd(args, self._timeout)
        except subprocess.TimeoutExpired as exc:
            raise FirewallError(f"Command timed out: {' '.join(args)}") from exc
        except FileNotFoundError as exc:
            raise FirewallError("`pfctl` not found — Aegis requires macOS here.") from exc

    def anchor_installed(self) -> bool:
        """Whether /etc/pf.conf references the Aegis anchor."""
        try:
            return f'anchor "{ANCHOR}"' in PF_CONF.read_text(encoding="utf-8")
        except OSError:
            return False

    @staticmethod
    def setup_instructions() -> str:
        return (
            f'Add these two lines to /etc/pf.conf (requires sudo), then run '
            f'`sudo pfctl -f /etc/pf.conf`:\n'
            f'    anchor "{ANCHOR}"\n'
            f'    load anchor "{ANCHOR}" from "/etc/pf.anchors/{ANCHOR}"'
        )

    # -- sidecar state ------------------------------------------------------ #
    def _load_state(self) -> dict[str, dict]:
        try:
            return json.loads(self._state_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            return {}

    def _save_state(self, state: dict[str, dict]) -> None:
        try:
            self._state_path.parent.mkdir(parents=True, exist_ok=True)
            tmp = self._state_path.with_suffix(".json.tmp")
            tmp.write_text(json.dumps(state, indent=2), encoding="utf-8")
            tmp.replace(self._state_path)
        except OSError:
            log.exception("Could not persist pf rule state")

    # -- rule rendering (pure, validated, testable) ------------------------- #
    def render_rule(self, rule: FirewallRule) -> str:
        """Validate a rule and render it as one pf rule line.

        Raises :class:`ValidationError` if any field is invalid, so a malicious
        value is rejected before it can reach the ruleset.
        """
        name = validators.validate_name(rule.name)
        if not (name.startswith(RULE_TAG) or name.startswith(LEGACY_RULE_TAG)):
            name = f"{RULE_TAG} {name}"

        local_ip = validators.validate_ip(rule.local_ip, "Local IP")
        remote_ip = validators.validate_ip(rule.remote_ip, "Remote IP")
        local_port = validators.validate_port(rule.local_port, "Local port")
        remote_port = validators.validate_port(rule.remote_port, "Remote port")

        outbound = rule.direction == FirewallDirection.OUT
        parts = [
            "block drop" if rule.action == FirewallAction.BLOCK else "pass",
            "out" if outbound else "in",
            "quick",
            _af_for(local_ip, remote_ip),
        ]

        if rule.protocol == Protocol.ICMP:
            parts += ["proto", "icmp"]
        elif rule.protocol in (Protocol.TCP, Protocol.UDP):
            parts += ["proto", rule.protocol.value.lower()]

        # "from" is the local side on egress and the peer on ingress.
        src_ip, dst_ip = (local_ip, remote_ip) if outbound else (remote_ip, local_ip)
        src_port, dst_port = ((local_port, remote_port) if outbound
                              else (remote_port, local_port))

        parts += ["from", "any" if src_ip == "any" else _addr_expr(src_ip, "Source IP")]
        if src_port != "any" and rule.protocol in (Protocol.TCP, Protocol.UDP):
            parts.append(_port_expr(src_port))
        parts += ["to", "any" if dst_ip == "any" else _addr_expr(dst_ip, "Destination IP")]
        if dst_port != "any" and rule.protocol in (Protocol.TCP, Protocol.UDP):
            parts.append(_port_expr(dst_port))

        # The name is carried as a trailing comment so the ruleset round-trips.
        return f"{' '.join(parts)}  # {name}"

    def _render_anchor(self, state: dict[str, dict]) -> str:
        lines = [
            "# Aegis-managed pf rules. Generated file — edits here are overwritten.",
            f"# Anchor: {ANCHOR}",
        ]
        for name, stored in state.items():
            if not stored.get("enabled", True):
                continue
            try:
                lines.append(self.render_rule(self._rule_from_stored(stored)))
            except (ValidationError, TypeError, ValueError):
                log.warning("Skipping unrenderable stored rule %r", name)
        return "\n".join(lines) + "\n"

    def _apply(self, state: dict[str, dict]) -> FirewallResult:
        """Write the anchor file and load it into pf."""
        try:
            self._anchor_path.parent.mkdir(parents=True, exist_ok=True)
            self._anchor_path.write_text(self._render_anchor(state), encoding="utf-8")
        except OSError as exc:
            return FirewallResult(False, f"Could not write pf anchor file: {exc}")
        out = self._run([_PFCTL, "-a", ANCHOR, "-f", str(self._anchor_path)])
        return self._interpret(out)

    @staticmethod
    def _rule_from_stored(stored: dict) -> FirewallRule:
        fields = {k: v for k, v in stored.items() if k in FirewallRule.__dataclass_fields__}
        fields.pop("enabled", None)
        rule = FirewallRule(**fields)
        rule.direction = FirewallDirection(rule.direction)
        rule.action = FirewallAction(rule.action)
        rule.protocol = Protocol(rule.protocol)
        return rule

    # -- public API --------------------------------------------------------- #
    def create_rule(self, rule: FirewallRule) -> FirewallResult:
        """Validate and create a firewall rule (auto-tagged with the Aegis prefix)."""
        try:
            self.render_rule(rule)          # validate before mutating any state
            name = validators.validate_name(rule.name)
        except ValidationError as exc:
            # Rejected before any command is run — the injection guarantee.
            log.warning("Rejected invalid firewall rule: %s", exc)
            return FirewallResult(False, f"Invalid rule: {exc}")
        if not (name.startswith(RULE_TAG) or name.startswith(LEGACY_RULE_TAG)):
            name = f"{RULE_TAG} {name}"

        state = self._load_state()
        stored = asdict(rule)
        stored["name"] = name
        stored["enabled"] = True
        state[name] = stored

        result = self._apply(state)
        if result.ok:
            self._save_state(state)
        result.rule_name = name
        return result

    def delete_rule(self, name: str) -> FirewallResult:
        try:
            name = validators.validate_name(name)
        except ValidationError as exc:
            return FirewallResult(False, f"Invalid rule name: {exc}")
        state = self._load_state()
        if name not in state:
            return FirewallResult(False, f"No Aegis rule named '{name}'.")
        del state[name]
        result = self._apply(state)
        if result.ok:
            self._save_state(state)
        result.rule_name = name
        return result

    def set_rule_enabled(self, name: str, enabled: bool) -> FirewallResult:
        """Enable or disable a rule by including/excluding it from the anchor."""
        try:
            name = validators.validate_name(name)
        except ValidationError as exc:
            return FirewallResult(False, f"Invalid rule name: {exc}")
        state = self._load_state()
        stored = state.get(name)
        if stored is None:
            return FirewallResult(False, f"No Aegis rule named '{name}'.")
        stored["enabled"] = enabled
        state[name] = stored
        result = self._apply(state)
        if result.ok:
            self._save_state(state)
        result.rule_name = name
        return result

    def list_rules(self, only_aegis: bool = True) -> list[FirewallRule]:
        rules = []
        for stored in self._load_state().values():
            try:
                rule = self._rule_from_stored(stored)
            except (TypeError, ValueError):
                continue
            rule.enabled = bool(stored.get("enabled", True))
            rules.append(rule)
        return rules

    def search_rules(self, keyword: str, only_aegis: bool = False) -> list[FirewallRule]:
        keyword = (keyword or "").casefold()
        rules = self.list_rules()
        if not keyword:
            return rules
        return [
            r for r in rules
            if any(keyword in str(v).casefold() for v in asdict(r).values())
        ]

    def block_ip(self, ip: str, note: str = "",
                 directions: tuple[str, ...] = ("out", "in")) -> FirewallResult:
        """Containment action: block all traffic to/from a remote IP."""
        try:
            ip = validators.validate_ip(ip, "Remote IP")
        except ValidationError as exc:
            return FirewallResult(False, f"Invalid IP: {exc}")
        if ip == "any":
            return FirewallResult(False, "Refusing to block 'any' (would cut all traffic).")

        label = f"Block {ip}"
        if note:
            label += f" ({note})"

        for d in directions:
            rule = FirewallRule(
                name=f"{label} [{d}]",
                direction=FirewallDirection.OUT if d == "out" else FirewallDirection.IN,
                action=FirewallAction.BLOCK,
                remote_ip=ip,
                description=f"Auto-block by Aegis. {note}".strip(),
            )
            result = self.create_rule(rule)
            if not result.ok:
                return result
        return FirewallResult(True, f"Blocked {ip} ({', '.join(directions)}).", rule_name=label)

    # -- result interpretation --------------------------------------------- #
    def _interpret(self, out: RunResult) -> FirewallResult:
        text = (decode(out.stdout) + decode(out.stderr)).strip()
        lowered = text.lower()
        if out.returncode == 0:
            return FirewallResult(True, "Firewall rule applied successfully.")
        if "permission denied" in lowered or "operation not permitted" in lowered:
            return FirewallResult(False, "Root privileges required (run with sudo).",
                                  needs_admin=True)
        first_line = next((ln for ln in text.splitlines() if ln.strip()), "Unknown error")
        return FirewallResult(False, first_line)
