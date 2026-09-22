"""Secure Linux firewall engine (nftables) — the Linux "ACT" plane.

Mirrors :class:`~aegis.response.firewall.FirewallManager` for Linux hosts,
implementing the same :class:`~aegis.response.backend.FirewallBackend` contract
with the same security properties:

* commands run as an **argument list** with ``shell=False``,
* every user-supplied field is **validated** before an argument is built,
* the command runner is dependency-injected, so this is fully unit-testable
  without root or a real nftables.

Design notes specific to nftables
---------------------------------
Aegis owns a dedicated ``inet aegis`` table and never touches the distribution's
own tables, so uninstalling is a single ``nft delete table inet aegis`` and a
bug here cannot corrupt the host's existing firewall policy. Both chains are
created with an explicit ``policy accept`` — a filter chain that defaulted to
``drop`` would sever the host's connectivity the moment it was created.

nftables has no concept of a *disabled* rule, and its ruleset is empty after a
reboot. Aegis therefore keeps a small sidecar file of the rules it manages, which
gives Linux two things the raw tool does not have: working enable/disable, and
rules that survive a restart via :meth:`NftablesManager.sync`.
"""
from __future__ import annotations

import ipaddress
import json
import logging
import subprocess
from dataclasses import asdict
from pathlib import Path

from aegis import RULE_TAG
from aegis.core import validators
from aegis.core.models import (
    FirewallAction,
    FirewallDirection,
    FirewallRule,
    Protocol,
)
from aegis.core.validators import ValidationError
from aegis.platforms import data_dir, is_linux, which
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

_NFT = "nft"
FAMILY = "inet"
TABLE = "aegis"


def _is_ipv6(value: str) -> bool:
    """Whether an already-validated IP/CIDR/range token is IPv6."""
    token = value.split("-")[0].split("/")[0].strip()
    try:
        return ipaddress.ip_address(token).version == 6
    except ValueError:
        return False


def _port_expr(port: str) -> str:
    """Render a validated port token as an nftables port expression.

    ``443`` -> ``443``; ``8000-8080`` -> ``8000-8080``; ``80,443`` -> ``{ 80, 443 }``.
    """
    if "," in port:
        return "{ " + ", ".join(p.strip() for p in port.split(",")) + " }"
    return port


class NftablesManager(FirewallBackend):
    """Safe wrapper around ``nft`` (nftables)."""

    backend_name = "Linux nftables"
    required_binary = _NFT

    def __init__(self, runner: CommandRunner | None = None, timeout: int = 20,
                 state_path: Path | None = None):
        self._run_cmd: CommandRunner = runner or default_runner
        self._timeout = timeout
        self._state_path = state_path or (data_dir() / "nftables_rules.json")
        self._table_ready = False

    def available(self) -> bool:
        return is_linux() and which(_NFT) is not None

    # -- low level ---------------------------------------------------------- #
    def _run(self, args: list[str]) -> RunResult:
        try:
            return self._run_cmd(args, self._timeout)
        except subprocess.TimeoutExpired as exc:
            raise FirewallError(f"Command timed out: {' '.join(args)}") from exc
        except FileNotFoundError as exc:
            raise FirewallError(
                "`nft` not found — install nftables (e.g. `apt install nftables`)."
            ) from exc

    def ensure_table(self) -> None:
        """Create the Aegis table and chains if absent. Idempotent.

        Both chains are created with ``policy accept`` so that merely installing
        Aegis can never drop the host's traffic; only explicit rules block.
        """
        if self._table_ready:
            return
        self._run([_NFT, "add", "table", FAMILY, TABLE])
        for chain, hook in (("input", "input"), ("output", "output")):
            self._run([
                _NFT, "add", "chain", FAMILY, TABLE, chain,
                "{", "type", "filter", "hook", hook,
                "priority", "0", ";", "policy", "accept", ";", "}",
            ])
        self._table_ready = True

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
            log.exception("Could not persist nftables rule state")

    # -- argument building (pure, validated, testable) ---------------------- #
    def _build_add_args(self, rule: FirewallRule) -> list[str]:
        """Validate a rule and build the ``nft add rule`` argument list.

        Raises :class:`ValidationError` if any field is invalid, so a malicious
        value is rejected before it can ever become a command argument.
        """
        name = validators.validate_name(rule.name)
        if not (name.startswith(RULE_TAG)):
            name = f"{RULE_TAG} {name}"

        local_ip = validators.validate_ip(rule.local_ip, "Local IP")
        remote_ip = validators.validate_ip(rule.remote_ip, "Remote IP")
        local_port = validators.validate_port(rule.local_port, "Local port")
        remote_port = validators.validate_port(rule.remote_port, "Remote port")

        outbound = rule.direction == FirewallDirection.OUT
        chain = "output" if outbound else "input"
        args = [_NFT, "add", "rule", FAMILY, TABLE, chain]

        # The "remote" peer is the destination on egress and the source on ingress.
        if remote_ip != "any":
            proto_kw = "ip6" if _is_ipv6(remote_ip) else "ip"
            args += [proto_kw, "daddr" if outbound else "saddr", remote_ip]
        if local_ip != "any":
            proto_kw = "ip6" if _is_ipv6(local_ip) else "ip"
            args += [proto_kw, "saddr" if outbound else "daddr", local_ip]

        if rule.protocol == Protocol.ICMP:
            args += ["meta", "l4proto", "{ icmp, icmpv6 }"]
        elif rule.protocol in (Protocol.TCP, Protocol.UDP):
            proto = rule.protocol.value.lower()
            if remote_port != "any":
                args += [proto, "dport" if outbound else "sport", _port_expr(remote_port)]
            if local_port != "any":
                args += [proto, "sport" if outbound else "dport", _port_expr(local_port)]
            # A bare protocol match still needs the protocol keyword present.
            if remote_port == "any" and local_port == "any":
                args += ["meta", "l4proto", proto]

        args.append("drop" if rule.action == FirewallAction.BLOCK else "accept")
        args += ["comment", name]
        return args

    # -- public API --------------------------------------------------------- #
    def create_rule(self, rule: FirewallRule) -> FirewallResult:
        """Validate and create a firewall rule (auto-tagged with the Aegis prefix)."""
        try:
            args = self._build_add_args(rule)
        except ValidationError as exc:
            # Rejected before any command is run — the injection guarantee.
            log.warning("Rejected invalid firewall rule: %s", exc)
            return FirewallResult(False, f"Invalid rule: {exc}")

        self.ensure_table()
        out = self._run(args)
        result = self._interpret(out)
        name = args[args.index("comment") + 1]
        result.rule_name = name

        if result.ok:
            state = self._load_state()
            stored = asdict(rule)
            stored["name"] = name
            stored["enabled"] = True
            state[name] = stored
            self._save_state(state)
        return result

    def delete_rule(self, name: str) -> FirewallResult:
        """Delete a rule by its exact (validated) name."""
        try:
            name = validators.validate_name(name)
        except ValidationError as exc:
            return FirewallResult(False, f"Invalid rule name: {exc}")

        removed = self._delete_live(name)
        state = self._load_state()
        if name in state:
            del state[name]
            self._save_state(state)
            removed = True
        if not removed:
            return FirewallResult(False, f"No Aegis rule named '{name}'.")
        return FirewallResult(True, "Firewall rule applied successfully.", rule_name=name)

    def _delete_live(self, name: str) -> bool:
        """Remove every live nft rule carrying ``name`` as its comment."""
        deleted = False
        for chain, handle in self._handles_for(name):
            out = self._run([_NFT, "delete", "rule", FAMILY, TABLE, chain,
                             "handle", str(handle)])
            deleted = deleted or out.returncode == 0
        return deleted

    def _handles_for(self, name: str) -> list[tuple[str, int]]:
        """Look up (chain, handle) pairs for Aegis rules whose comment is ``name``.

        Uses nftables' native JSON output rather than scraping its text form.
        """
        out = self._run([_NFT, "-j", "list", "table", FAMILY, TABLE])
        if out.returncode != 0:
            return []
        try:
            payload = json.loads(decode(out.stdout) or "{}")
        except json.JSONDecodeError:
            return []
        found: list[tuple[str, int]] = []
        for item in payload.get("nftables", []):
            entry = item.get("rule")
            if not entry:
                continue
            if entry.get("comment") == name and entry.get("handle") is not None:
                found.append((entry.get("chain", ""), entry["handle"]))
        return found

    def set_rule_enabled(self, name: str, enabled: bool) -> FirewallResult:
        """Enable or disable a rule.

        nftables cannot mark a rule inactive, so Aegis removes it from the live
        ruleset while retaining its definition in the sidecar, and re-applies it
        on enable. The rule's identity and settings survive the round trip.
        """
        try:
            name = validators.validate_name(name)
        except ValidationError as exc:
            return FirewallResult(False, f"Invalid rule name: {exc}")

        state = self._load_state()
        stored = state.get(name)
        if stored is None:
            return FirewallResult(False, f"No Aegis rule named '{name}'.")

        if enabled:
            rule = self._rule_from_stored(stored)
            try:
                args = self._build_add_args(rule)
            except ValidationError as exc:
                return FirewallResult(False, f"Invalid rule: {exc}")
            self.ensure_table()
            result = self._interpret(self._run(args))
        else:
            self._delete_live(name)
            result = FirewallResult(True, "Firewall rule applied successfully.")

        if result.ok:
            stored["enabled"] = enabled
            state[name] = stored
            self._save_state(state)
        result.rule_name = name
        return result

    @staticmethod
    def _rule_from_stored(stored: dict) -> FirewallRule:
        fields = {k: v for k, v in stored.items() if k in FirewallRule.__dataclass_fields__}
        fields.pop("enabled", None)
        rule = FirewallRule(**fields)
        rule.direction = FirewallDirection(rule.direction)
        rule.action = FirewallAction(rule.action)
        rule.protocol = Protocol(rule.protocol)
        return rule

    def list_rules(self, only_aegis: bool = True) -> list[FirewallRule]:
        """Return the rules Aegis manages, including ones currently disabled."""
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
        """Containment action: block all traffic to/from a remote IP.

        Refuses to block 'any', which would sever all connectivity.
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

    def sync(self) -> int:
        """Re-apply every enabled Aegis rule to the live ruleset.

        nftables does not persist across reboots on its own; calling this at
        startup restores the rules the user created in a previous session.
        Returns the number of rules re-applied.
        """
        self.ensure_table()
        applied = 0
        for name, stored in self._load_state().items():
            if not stored.get("enabled", True):
                continue
            if self._handles_for(name):
                continue  # already live
            try:
                args = self._build_add_args(self._rule_from_stored(stored))
            except (ValidationError, TypeError, ValueError):
                log.warning("Skipping unrestorable stored rule %r", name)
                continue
            if self._run(args).returncode == 0:
                applied += 1
        return applied

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
