"""Security tests for input validation.

The original project was vulnerable to command injection because it built
``netsh`` command strings with raw user input and ``shell=True``. These tests
lock in the fix: malicious inputs must be rejected by validation *before* they
can ever reach a subprocess. They are the regression guard for the single most
important security property of the tool.
"""
import pytest

from aegis.core import validators
from aegis.core.validators import ValidationError


# --- rule name --------------------------------------------------------------
@pytest.mark.parametrize("name", [
    "Block torrent client",
    "web-server rule (in)",
    "App [ICEBOX] 01",
])
def test_valid_names_pass(name):
    assert validators.validate_name(name) == name.strip()


@pytest.mark.parametrize("payload", [
    'x" & del /q C:\\important',          # command chaining
    "x | shutdown /s",                     # pipe
    "x; rm -rf /",                          # semicolon
    "x`whoami`",                            # backtick
    "x$(id)",                               # subshell
    "x > out.txt",                          # redirection
    "x\nnetsh advfirewall reset",          # newline injection
    "x & start calc",                       # ampersand
])
def test_injection_payloads_are_rejected(payload):
    with pytest.raises(ValidationError):
        validators.validate_name(payload)


def test_empty_name_rejected():
    with pytest.raises(ValidationError):
        validators.validate_name("   ")


# --- IP ---------------------------------------------------------------------
@pytest.mark.parametrize("value,expected", [
    ("", "any"), ("any", "any"), ("0.0.0.0", "any"),
    ("192.168.1.10", "192.168.1.10"),
    ("10.0.0.0/8", "10.0.0.0/8"),
    ("192.168.0.1-192.168.0.9", "192.168.0.1-192.168.0.9"),
])
def test_valid_ips(value, expected):
    assert validators.validate_ip(value) == expected


@pytest.mark.parametrize("bad", ["999.1.1.1", "1.2.3", "10.0.0.0/40", "evil&", "1.1.1.1;drop"])
def test_bad_ips_rejected(bad):
    with pytest.raises(ValidationError):
        validators.validate_ip(bad)


# --- port -------------------------------------------------------------------
@pytest.mark.parametrize("value,expected", [
    ("", "any"), ("any", "any"),
    ("443", "443"), ("80,443", "80,443"), ("1000-2000", "1000-2000"),
])
def test_valid_ports(value, expected):
    assert validators.validate_port(value) == expected


@pytest.mark.parametrize("bad", ["70000", "-1", "80;rm", "abc", "22|nc"])
def test_bad_ports_rejected(bad):
    with pytest.raises(ValidationError):
        validators.validate_port(bad)


# --- program path -----------------------------------------------------------
def test_valid_path_kept():
    p = r"C:\Program Files\App\app.exe"
    assert validators.validate_path(p) == p


@pytest.mark.parametrize("bad", [r"C:\a & calc", "app|nc", "x`id`", "x$(id)"])
def test_path_metacharacters_rejected(bad):
    with pytest.raises(ValidationError):
        validators.validate_path(bad)
