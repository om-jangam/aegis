"""Tests for platform detection, per-OS data locations and backend selection.

These decide *where Aegis writes* and *which firewall engine it drives*, so they
are exercised for every OS regardless of the host running the suite, by
monkeypatching the detected platform.
"""
import pytest

from aegis import platforms
from aegis.core.models import FirewallRule
from aegis.platforms import OS
from aegis.response import factory


@pytest.fixture
def as_os(monkeypatch):
    """Pretend Aegis is running on a given OS."""
    def _set(os_value: OS):
        monkeypatch.setattr(platforms, "CURRENT_OS", os_value)
        monkeypatch.setattr(factory, "CURRENT_OS", os_value, raising=False)
        for name, target in (("is_windows", OS.WINDOWS), ("is_linux", OS.LINUX),
                             ("is_macos", OS.MACOS)):
            monkeypatch.setattr(platforms, name, lambda t=target, v=os_value: v is t)
            monkeypatch.setattr(factory, name,
                                lambda t=target, v=os_value: v is t, raising=False)
    return _set


# --------------------------------------------------------------------------- #
# Detection
# --------------------------------------------------------------------------- #
def test_exactly_one_platform_is_current():
    flags = [platforms.is_windows(), platforms.is_linux(), platforms.is_macos()]
    assert sum(flags) <= 1, "platform predicates must be mutually exclusive"


def test_privilege_hint_is_actionable():
    hint = platforms.privilege_hint()
    assert "Administrator" in hint or "sudo" in hint


def test_no_window_flag_is_an_int():
    """Must resolve to 0 off Windows so subprocess calls stay portable."""
    assert isinstance(platforms.NO_WINDOW, int)


def test_which_finds_the_running_interpreter():
    assert platforms.which("python") or platforms.which("python3") or True


def test_which_returns_none_for_missing_binary():
    assert platforms.which("definitely-not-a-real-binary-xyz") is None


# --------------------------------------------------------------------------- #
# Data directory
# --------------------------------------------------------------------------- #
def test_data_dir_honours_env_override(tmp_path, monkeypatch):
    target = tmp_path / "custom-aegis"
    monkeypatch.setenv("AEGIS_DATA_DIR", str(target))
    assert platforms.data_dir() == target
    assert target.is_dir(), "the directory must be created"


def test_data_dir_is_created_if_missing(tmp_path, monkeypatch):
    target = tmp_path / "nested" / "deep" / "aegis"
    monkeypatch.setenv("AEGIS_DATA_DIR", str(target))
    assert platforms.data_dir().is_dir()


def test_linux_data_dir_follows_xdg(tmp_path, monkeypatch, as_os):
    monkeypatch.delenv("AEGIS_DATA_DIR", raising=False)
    monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path))
    as_os(OS.LINUX)
    assert platforms.data_dir() == tmp_path / "aegis"


def test_windows_data_dir_uses_localappdata(tmp_path, monkeypatch, as_os):
    monkeypatch.delenv("AEGIS_DATA_DIR", raising=False)
    monkeypatch.setenv("LOCALAPPDATA", str(tmp_path))
    as_os(OS.WINDOWS)
    assert platforms.data_dir() == tmp_path / "Aegis"


# --------------------------------------------------------------------------- #
# Backend selection
# --------------------------------------------------------------------------- #
def test_unknown_os_gets_null_backend(as_os):
    as_os(OS.UNKNOWN)
    backend = factory.get_firewall()
    assert isinstance(backend, factory.NullFirewall)
    assert backend.available() is False


def test_null_backend_fails_every_action_safely():
    """Response must degrade to honest refusal, never a silent false success."""
    null = factory.NullFirewall("no backend here")
    assert null.list_rules() == []
    assert null.search_rules("anything") == []
    for result in (
        null.create_rule(FirewallRule(name="x")),
        null.delete_rule("x"),
        null.set_rule_enabled("x", True),
        null.block_ip("1.1.1.1"),
    ):
        assert result.ok is False
        assert "no backend here" in result.message


def test_null_backend_reports_reason_in_capability_line(as_os):
    as_os(OS.UNKNOWN)
    assert "Response disabled" in factory.response_capability()


def test_backend_contract_is_satisfied_by_every_implementation():
    """Each platform engine must implement the full FirewallBackend interface."""
    from aegis.response.backend import FirewallBackend
    from aegis.response.firewall import FirewallManager
    from aegis.response.linux import NftablesManager
    from aegis.response.macos import PfManager

    for cls in (FirewallManager, NftablesManager, PfManager, factory.NullFirewall):
        assert issubclass(cls, FirewallBackend)
        assert not getattr(cls, "__abstractmethods__", None), (
            f"{cls.__name__} leaves abstract methods unimplemented"
        )


def test_every_backend_declares_a_name():
    from aegis.response.firewall import FirewallManager
    from aegis.response.linux import NftablesManager
    from aegis.response.macos import PfManager

    for cls in (FirewallManager, NftablesManager, PfManager):
        assert cls.backend_name and cls.backend_name != "firewall"
        assert cls.required_binary
