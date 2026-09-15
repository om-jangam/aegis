"""Trusted programs: what may be trusted and how trust is matched."""
import pytest

from aegis.detection.trust import can_trust, is_trusted, trust_candidate


@pytest.mark.parametrize("name", ["claude.exe", "Code.exe", "veeam-agent.exe", "backupd"])
def test_ordinary_programs_can_be_trusted(name):
    assert can_trust(name)


@pytest.mark.parametrize("name", [
    "powershell.exe", "PowerShell.EXE", "cmd.exe", "svchost.exe", "explorer.exe",
    "bash", "python.exe", "rundll32.exe", "", "   ",
])
def test_interpreters_system_processes_and_blanks_can_never_be_trusted(name):
    assert not can_trust(name)


def test_trust_matches_the_program_or_its_parent_case_insensitively():
    trusted = ["Claude.exe"]
    assert is_trusted("powershell.exe", "claude.exe", trusted)
    assert is_trusted("CLAUDE.EXE", "", trusted)
    assert not is_trusted("powershell.exe", "winword.exe", trusted)
    assert not is_trusted("powershell.exe", "claude.exe", [])


def test_untrustable_entries_in_settings_are_ignored():
    assert not is_trusted("powershell.exe", "explorer.exe", ["powershell.exe", "explorer.exe"])


@pytest.mark.parametrize(("process", "parent", "expected"), [
    ("powershell.exe", "claude.exe", "claude.exe"),     # prefer the launching tool
    ("updater.exe", "explorer.exe", "updater.exe"),     # parent untrustable: offer the program
    ("powershell.exe", "explorer.exe", ""),             # neither is safe to trust
    ("chrome.exe", "", "chrome.exe"),                   # network alerts have no parent
])
def test_trust_candidate(process, parent, expected):
    assert trust_candidate(process, parent) == expected
