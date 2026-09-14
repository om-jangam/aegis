"""Tests for the secure firewall response engine.

Uses a dependency-injected *recording runner* so the whole engine is tested
without Administrator rights or a real ``netsh``. The runner captures the exact
argument list, which lets us prove the security properties:

* malicious input is rejected before any command is built/run,
* commands are passed as an argument **list** (never a shell string),
* the default runner calls subprocess with ``shell=False``.
"""
import pytest

from aegis import RULE_TAG
from aegis.core.models import (
    Finding,
    FirewallAction,
    FirewallDirection,
    FirewallRule,
    Protocol,
    Severity,
)
from aegis.core.validators import ValidationError
from aegis.response import firewall as fw
from aegis.response.firewall import (
    FirewallManager,
    FirewallResponder,
    RunResult,
    _default_runner,
    _extract_ip,
)


class RecordingRunner:
    """Fake CommandRunner: records argv lists, returns canned results."""

    def __init__(self, result: RunResult | None = None, results: list[RunResult] | None = None):
        self.calls: list[list[str]] = []
        self._result = result if result is not None else RunResult(0, b"Ok.\r\n\r\n")
        self._results = results

    def __call__(self, args, timeout):
        assert isinstance(args, list), "commands must be argument lists, not strings"
        assert all(isinstance(a, str) for a in args)
        self.calls.append(list(args))
        if self._results is not None:
            return self._results[len(self.calls) - 1]
        return self._result


def _mgr(runner=None):
    return FirewallManager(runner=runner or RecordingRunner())


# --------------------------------------------------------------------------- #
# Argument construction
# --------------------------------------------------------------------------- #
def test_build_args_basic_block_rule():
    mgr = _mgr()
    rule = FirewallRule(name="bad host", direction=FirewallDirection.OUT,
                        action=FirewallAction.BLOCK, protocol=Protocol.TCP,
                        remote_ip="45.9.1.1", remote_port="4444")
    args = mgr._build_add_args(rule)
    assert args[:5] == ["netsh", "advfirewall", "firewall", "add", "rule"]
    assert f"name={RULE_TAG} bad host" in args
    assert "dir=out" in args and "action=block" in args and "enable=yes" in args
    assert "protocol=tcp" in args
    assert "remoteport=4444" in args
    assert "remoteip=45.9.1.1" in args
    # every token is a single argv element (defense-in-depth vs injection)
    assert all(isinstance(a, str) for a in args)


def test_build_args_autotags_name_once():
    mgr = _mgr()
    already = FirewallRule(name=f"{RULE_TAG} keep", action=FirewallAction.ALLOW)
    args = mgr._build_add_args(already)
    names = [a for a in args if a.startswith("name=")]
    assert names == [f"name={RULE_TAG} keep"]  # not double-tagged


def test_build_args_ports_only_for_tcp_udp():
    mgr = _mgr()
    icmp = FirewallRule(name="ping", protocol=Protocol.ICMP,
                        local_port="80", remote_port="443")
    args = mgr._build_add_args(icmp)
    assert not any(a.startswith("localport=") or a.startswith("remoteport=") for a in args)
    assert "protocol=icmpv4" in args


def test_build_args_any_protocol_and_any_ip_omitted():
    mgr = _mgr()
    rule = FirewallRule(name="broad", protocol=Protocol.ANY,
                        local_ip="any", remote_ip="any")
    args = mgr._build_add_args(rule)
    assert not any(a.startswith("protocol=") for a in args)
    assert not any(a.startswith("localip=") or a.startswith("remoteip=") for a in args)


def test_build_args_includes_program():
    mgr = _mgr()
    rule = FirewallRule(name="app", program=r"C:\Windows\System32\curl.exe")
    args = mgr._build_add_args(rule)
    assert r"program=C:\Windows\System32\curl.exe" in args


# --------------------------------------------------------------------------- #
# Injection regression — the whole point of the rewrite
# --------------------------------------------------------------------------- #
INJECTION_NAMES = [
    'x" & del /q C:\\important',
    "x | shutdown /s",
    "x; rm -rf /",
    "x`whoami`",
    "x$(id)",
    "x\nnetsh advfirewall reset",
    "x & start calc",
]


@pytest.mark.parametrize("payload", INJECTION_NAMES)
def test_build_args_rejects_injection_before_building(payload):
    mgr = _mgr()
    rule = FirewallRule(name=payload, action=FirewallAction.BLOCK)
    with pytest.raises(ValidationError):
        mgr._build_add_args(rule)


@pytest.mark.parametrize("payload", INJECTION_NAMES)
def test_create_rule_rejects_injection_without_running(payload):
    runner = RecordingRunner()
    mgr = FirewallManager(runner=runner)
    result = mgr.create_rule(FirewallRule(name=payload, action=FirewallAction.BLOCK))
    assert result.ok is False
    assert "Invalid" in result.message
    assert runner.calls == []          # command runner was NEVER invoked


def test_create_rule_rejects_injection_in_ip():
    runner = RecordingRunner()
    mgr = FirewallManager(runner=runner)
    result = mgr.create_rule(FirewallRule(name="ok name", remote_ip="1.2.3.4 & calc"))
    assert result.ok is False
    assert runner.calls == []


# --------------------------------------------------------------------------- #
# Behavior via the fake runner
# --------------------------------------------------------------------------- #
def test_create_rule_success():
    runner = RecordingRunner(RunResult(0, b"Ok.\r\n\r\n"))
    mgr = FirewallManager(runner=runner)
    result = mgr.create_rule(FirewallRule(name="good", action=FirewallAction.BLOCK))
    assert result.ok is True
    assert result.rule_name == f"{RULE_TAG} good"
    assert len(runner.calls) == 1


def test_create_rule_needs_admin():
    out = RunResult(1, b"The requested operation requires elevation (Run as administrator).\r\n")
    mgr = FirewallManager(runner=RecordingRunner(out))
    result = mgr.create_rule(FirewallRule(name="x"))
    assert result.ok is False
    assert result.needs_admin is True


def test_create_rule_generic_error():
    out = RunResult(1, b"The parameter is incorrect.\r\n")
    mgr = FirewallManager(runner=RecordingRunner(out))
    result = mgr.create_rule(FirewallRule(name="x"))
    assert result.ok is False
    assert "parameter" in result.message.lower()


def test_delete_rule_builds_expected_args():
    runner = RecordingRunner()
    mgr = FirewallManager(runner=runner)
    mgr.delete_rule(f"{RULE_TAG} old")
    assert runner.calls[0] == [
        "netsh", "advfirewall", "firewall", "delete", "rule", f"name={RULE_TAG} old",
    ]


def test_delete_rule_rejects_bad_name():
    runner = RecordingRunner()
    mgr = FirewallManager(runner=runner)
    result = mgr.delete_rule('evil" & calc')
    assert result.ok is False
    assert runner.calls == []


def test_set_rule_enabled_args():
    runner = RecordingRunner()
    mgr = FirewallManager(runner=runner)
    mgr.set_rule_enabled(f"{RULE_TAG} r", enabled=False)
    assert runner.calls[0] == [
        "netsh", "advfirewall", "firewall", "set", "rule",
        f"name={RULE_TAG} r", "new", "enable=no",
    ]


# --------------------------------------------------------------------------- #
# Containment: block_ip
# --------------------------------------------------------------------------- #
def test_block_ip_refuses_any():
    runner = RecordingRunner()
    mgr = FirewallManager(runner=runner)
    result = mgr.block_ip("any")
    assert result.ok is False
    assert runner.calls == []


def test_block_ip_creates_out_and_in_rules():
    runner = RecordingRunner(RunResult(0, b"Ok.\r\n\r\n"))
    mgr = FirewallManager(runner=runner)
    result = mgr.block_ip("45.9.1.1", note="C2")
    assert result.ok is True
    assert len(runner.calls) == 2                       # outbound + inbound
    joined = [" ".join(c) for c in runner.calls]
    assert any("dir=out" in c and "action=block" in c and "remoteip=45.9.1.1" in c for c in joined)
    assert any("dir=in" in c and "action=block" in c for c in joined)


def test_block_ip_rejects_bad_ip():
    runner = RecordingRunner()
    mgr = FirewallManager(runner=runner)
    result = mgr.block_ip("999.999.1.1")
    assert result.ok is False
    assert runner.calls == []


# --------------------------------------------------------------------------- #
# Parsing netsh output (English-locale sample)
# --------------------------------------------------------------------------- #
SAMPLE = (
    "\r\n"
    "Rule Name:                            [AEGIS] Block bad host\r\n"
    "----------------------------------------------------------------------\r\n"
    "Enabled:                              Yes\r\n"
    "Direction:                            Out\r\n"
    "Profiles:                             Domain,Private,Public\r\n"
    "LocalIP:                              Any\r\n"
    "RemoteIP:                             45.9.1.1/32\r\n"
    "Protocol:                             TCP\r\n"
    "LocalPort:                            Any\r\n"
    "RemotePort:                           Any\r\n"
    "Action:                               Block\r\n"
    "\r\n"
    "Rule Name:                            Core Networking (DNS-Out)\r\n"
    "----------------------------------------------------------------------\r\n"
    "Enabled:                              Yes\r\n"
    "Direction:                            Out\r\n"
    "Action:                               Allow\r\n"
)


def test_list_rules_only_aegis_filter():
    runner = RecordingRunner(RunResult(0, SAMPLE.encode()))
    mgr = FirewallManager(runner=runner)
    aegis_only = mgr.list_rules(only_aegis=True)
    all_rules = mgr.list_rules(only_aegis=False)
    assert len(aegis_only) == 1
    assert len(all_rules) == 2
    r = aegis_only[0]
    assert r.name == "[AEGIS] Block bad host"
    assert r.action == FirewallAction.BLOCK
    assert r.direction == FirewallDirection.OUT
    assert r.protocol == Protocol.TCP
    assert r.enabled is True
    assert r.remote_ip == "45.9.1.1/32"


def test_search_rules_matches_keyword():
    runner = RecordingRunner(RunResult(0, SAMPLE.encode()))
    mgr = FirewallManager(runner=runner)
    hits = mgr.search_rules("dns")
    assert len(hits) == 1
    assert "DNS" in hits[0].name


# --------------------------------------------------------------------------- #
# Responder adapter
# --------------------------------------------------------------------------- #
def test_extract_ip():
    assert _extract_ip("45.9.1.1:4444") == "45.9.1.1"
    assert _extract_ip("10.0.0.5") == "10.0.0.5"
    assert _extract_ip("not-an-ip") == ""
    assert _extract_ip("") == ""


def _finding(entity):
    return Finding(rule_id="NET-C2", title="C2", severity=Severity.HIGH,
                   technique="T1571", entity=entity)


def test_responder_can_handle():
    resp = FirewallResponder(FirewallManager(runner=RecordingRunner()))
    assert resp.can_handle(_finding("45.9.1.1:4444")) is True
    assert resp.can_handle(_finding("chrome.exe")) is False
    assert resp.can_handle(_finding("")) is False


def test_responder_blocks_ip():
    runner = RecordingRunner(RunResult(0, b"Ok.\r\n\r\n"))
    resp = FirewallResponder(FirewallManager(runner=runner))
    result = resp.respond(_finding("45.9.1.1:4444"))
    assert result.ok is True
    assert result.action == "block_ip"
    assert len(runner.calls) == 2      # out + in block rules created


# --------------------------------------------------------------------------- #
# Security property of the DEFAULT runner: shell=False
# --------------------------------------------------------------------------- #
def test_default_runner_uses_no_shell(monkeypatch):
    captured = {}

    class FakeProc:
        returncode = 0
        stdout = b"Ok.\r\n\r\n"
        stderr = b""

    def fake_run(args, **kwargs):
        captured["args"] = args
        captured["kwargs"] = kwargs
        return FakeProc()

    monkeypatch.setattr(fw.subprocess, "run", fake_run)
    _default_runner(["netsh", "advfirewall", "firewall", "show", "rule", "name=all"], 20)

    assert isinstance(captured["args"], list)          # argv list, not a string
    assert captured["kwargs"]["shell"] is False        # the core guarantee
    assert captured["kwargs"]["timeout"] == 20
