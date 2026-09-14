"""Tests for Sigma rule compilation, value modifiers and field matching.

Value matching is where a detection quietly fails: a modifier implemented with
the wrong semantics produces a rule that loads, reports as active and never
fires. Each modifier is therefore pinned both ways — what it must match and what
it must not.
"""
import pytest
import yaml

from aegis.core.events import (
    Direction,
    EventSource,
    EventType,
    NetworkEvent,
    ProcessEvent,
)
from aegis.core.models import Severity
from aegis.detection.base import DetectionContext
from aegis.detection.sigma.mapping import fields_for, unsupported_fields
from aegis.detection.sigma.rule import (
    SigmaDetectionRule,
    SigmaRuleError,
    compile_rule,
)


def build(detection: dict, *, category="process_creation", **extra):
    """Compile a minimal rule around a detection block."""
    document = {
        "title": extra.pop("title", "Test rule"),
        "logsource": {"category": category},
        "detection": detection,
        **extra,
    }
    return compile_rule(document)


def proc(name="powershell.exe", exe=r"C:\Windows\powershell.exe", cmdline="",
         parent="", user="alice", pid=100, ppid=4):
    return ProcessEvent(type=EventType.PROCESS_START, source=EventSource.PSUTIL,
                        pid=pid, ppid=ppid, name=name, exe=exe, cmdline=cmdline,
                        username=user, raw={"parent_name": parent})


def net(proc_name="chrome.exe", ip="1.2.3.4", port=443, protocol="TCP"):
    return NetworkEvent(type=EventType.NETWORK_CONNECTION, source=EventSource.PSUTIL,
                        pid=1, process_name=proc_name, protocol=protocol,
                        remote_ip=ip, remote_port=port, direction=Direction.OUTBOUND)


def matches(rule, event) -> bool:
    return rule.matches(fields_for(event))


# --------------------------------------------------------------------------- #
# Plain matching
# --------------------------------------------------------------------------- #
def test_exact_match_is_case_insensitive():
    rule = build({"selection": {"Image": r"C:\Windows\powershell.exe"}, "condition": "selection"})
    assert matches(rule, proc(exe=r"c:\WINDOWS\POWERSHELL.EXE"))


def test_value_list_is_an_or():
    rule = build({"selection": {"Image": [r"C:\a.exe", r"C:\Windows\powershell.exe"]},
                  "condition": "selection"})
    assert matches(rule, proc(exe=r"C:\Windows\powershell.exe"))
    assert not matches(rule, proc(exe=r"C:\other.exe"))


def test_multiple_fields_are_an_and():
    rule = build({"selection": {"Image|endswith": "powershell.exe",
                                "CommandLine|contains": "-enc"},
                  "condition": "selection"})
    assert matches(rule, proc(cmdline="powershell -enc AAA"))
    assert not matches(rule, proc(cmdline="powershell -File a.ps1"))


def test_list_of_maps_is_an_or():
    rule = build({"selection": [{"Image|endswith": "cmd.exe"},
                                {"Image|endswith": "powershell.exe"}],
                  "condition": "selection"})
    assert matches(rule, proc(exe=r"C:\W\cmd.exe"))
    assert matches(rule, proc(exe=r"C:\W\powershell.exe"))
    assert not matches(rule, proc(exe=r"C:\W\notepad.exe"))


# --------------------------------------------------------------------------- #
# Modifiers
# --------------------------------------------------------------------------- #
def test_contains():
    rule = build({"selection": {"CommandLine|contains": "mimikatz"}, "condition": "selection"})
    assert matches(rule, proc(cmdline="run mimikatz now"))
    assert not matches(rule, proc(cmdline="run something else"))


def test_startswith():
    rule = build({"selection": {"CommandLine|startswith": "powershell"},
                  "condition": "selection"})
    assert matches(rule, proc(cmdline="powershell -enc x"))
    assert not matches(rule, proc(cmdline="run powershell -enc x"))


def test_endswith():
    rule = build({"selection": {"Image|endswith": r"\powershell.exe"},
                  "condition": "selection"})
    assert matches(rule, proc(exe=r"C:\Windows\System32\powershell.exe"))
    assert not matches(rule, proc(exe=r"C:\Windows\powershell.exe.bak"))


def test_regex():
    rule = build({"selection": {"CommandLine|re": r"-e(nc)?\s+[A-Za-z0-9+/]{8,}"},
                  "condition": "selection"})
    assert matches(rule, proc(cmdline="powershell -enc SQBFAFgAIAA="))
    assert not matches(rule, proc(cmdline="powershell -File a.ps1"))


def test_all_modifier_requires_every_value():
    rule = build({"selection": {"CommandLine|contains|all": ["socket", "subprocess"]},
                  "condition": "selection"})
    assert matches(rule, proc(cmdline="python -c import socket,subprocess"))
    assert not matches(rule, proc(cmdline="python -c import socket"))


def test_cased_modifier_is_case_sensitive():
    rule = build({"selection": {"CommandLine|contains|cased": "IEX"},
                  "condition": "selection"})
    assert matches(rule, proc(cmdline="IEX(New-Object Net.WebClient)"))
    assert not matches(rule, proc(cmdline="iex(new-object net.webclient)"))


def test_windash_treats_slash_and_dash_as_equivalent():
    rule = build({"selection": {"CommandLine|windash|contains": "-urlcache"},
                  "condition": "selection"})
    assert matches(rule, proc(cmdline="certutil -urlcache -f http://x"))
    assert matches(rule, proc(cmdline="certutil /urlcache /f http://x"))
    assert not matches(rule, proc(cmdline="certutil --split x"))


def test_base64_modifier():
    rule = build({"selection": {"CommandLine|base64|contains": "whoami"},
                  "condition": "selection"})
    assert matches(rule, proc(cmdline="powershell -enc d2hvYW1p"))
    assert not matches(rule, proc(cmdline="powershell -enc bm90aGluZw=="))


def test_numeric_comparisons():
    rule = build({"selection": {"DestinationPort|gte": 1024}, "condition": "selection"},
                 category="network_connection")
    assert matches(rule, net(port=4444))
    assert not matches(rule, net(port=443))


def test_null_value_matches_absent_field():
    rule = build({"selection": {"CommandLine": None}, "condition": "selection"})
    assert matches(rule, proc(cmdline=""))
    assert not matches(rule, proc(cmdline="something"))


def test_unsupported_modifier_is_rejected_at_compile_time():
    with pytest.raises(SigmaRuleError, match="unsupported modifier"):
        build({"selection": {"CommandLine|utf16le|base64offset|contains": "x"},
               "condition": "selection"})


# --------------------------------------------------------------------------- #
# Wildcards
# --------------------------------------------------------------------------- #
def test_star_wildcard():
    rule = build({"selection": {"Image": "C:/Users/*/AppData/*/evil.exe"},
                  "condition": "selection"})
    assert matches(rule, proc(exe="C:/Users/bob/AppData/Local/evil.exe"))
    assert not matches(rule, proc(exe="C:/Program Files/evil.exe"))


def test_backslash_before_star_escapes_it_per_the_sigma_spec():
    r"""In Sigma, ``\*`` denotes a literal asterisk, consuming the backslash.

    The spec reserves ``\`` as the escape character for ``*``, ``?`` and itself,
    so ``foo\*bar`` matches the literal text ``foo*bar`` rather than acting as a
    wildcard. Pinned here because it is genuinely surprising when writing
    Windows paths.
    """
    rule = build({"selection": {"CommandLine": r"foo\*bar"}, "condition": "selection"})
    assert matches(rule, proc(cmdline="foo*bar"))
    assert not matches(rule, proc(cmdline="fooANYTHINGbar"))


def test_contains_value_ending_in_a_backslash():
    r"""Regression: the appended wildcard must not be eaten by a trailing ``\``.

    Wrapping the raw value as ``*<value>*`` before parsing escapes turned the
    trailing separator of a Windows path prefix into ``\*`` — an escaped literal
    asterisk — so the rule searched for a ``*`` character and never matched.
    """
    rule = build({"selection": {"Image|contains": "\\AppData\\Local\\Temp\\"},
                  "condition": "selection"})
    assert matches(rule, proc(exe=r"C:\Users\bob\AppData\Local\Temp\evil.exe"))
    assert not matches(rule, proc(exe=r"C:\Program Files\good.exe"))


def test_startswith_value_ending_in_a_backslash():
    rule = build({"selection": {"Image|startswith": "C:\\Users\\"},
                  "condition": "selection"})
    assert matches(rule, proc(exe=r"C:\Users\bob\evil.exe"))
    assert not matches(rule, proc(exe=r"C:\Windows\good.exe"))


def test_lone_backslash_is_a_literal_separator():
    r"""``\p`` is not an escape, so endswith on a path prefix works normally."""
    rule = build({"selection": {"Image|endswith": r"\powershell.exe"},
                  "condition": "selection"})
    assert matches(rule, proc(exe=r"C:\Windows\System32\powershell.exe"))


def test_question_mark_wildcard_matches_exactly_one_character():
    rule = build({"selection": {"Image": r"C:\a?.exe"}, "condition": "selection"})
    assert matches(rule, proc(exe=r"C:\ab.exe"))
    assert not matches(rule, proc(exe=r"C:\abc.exe"))


def test_escaped_wildcard_is_a_literal():
    rule = build({"selection": {"CommandLine": r"cmd \* literal"}, "condition": "selection"})
    assert matches(rule, proc(cmdline="cmd * literal"))
    assert not matches(rule, proc(cmdline="cmd anything literal"))


def test_regex_metacharacters_in_values_are_escaped():
    """A '.' in a rule value must match a literal dot, not any character."""
    rule = build({"selection": {"Image|endswith": "a.exe"}, "condition": "selection"})
    assert matches(rule, proc(exe=r"C:\a.exe"))
    assert not matches(rule, proc(exe=r"C:\axexe"))


# --------------------------------------------------------------------------- #
# Compilation and metadata
# --------------------------------------------------------------------------- #
def test_level_maps_to_severity():
    for level, expected in [("critical", Severity.CRITICAL), ("high", Severity.HIGH),
                            ("medium", Severity.MEDIUM), ("low", Severity.LOW),
                            ("informational", Severity.INFO)]:
        rule = build({"selection": {"Image": "x"}, "condition": "selection"}, level=level)
        assert rule.level is expected


def test_missing_level_defaults_to_medium():
    rule = build({"selection": {"Image": "x"}, "condition": "selection"})
    assert rule.level is Severity.MEDIUM


def test_most_specific_attack_technique_wins():
    rule = build({"selection": {"Image": "x"}, "condition": "selection"},
                 tags=["attack.execution", "attack.t1059", "attack.t1059.001"])
    assert rule.technique == "T1059.001"


def test_tactic_from_tags():
    rule = build({"selection": {"Image": "x"}, "condition": "selection"},
                 tags=["attack.credential-access", "attack.t1003"])
    assert rule.tactic == "Credential Access"


def test_rule_without_attack_tags_claims_no_technique():
    rule = build({"selection": {"Image": "x"}, "condition": "selection"})
    assert rule.technique == ""
    assert rule.tactic == ""


def test_missing_title_is_rejected():
    with pytest.raises(SigmaRuleError, match="no title"):
        compile_rule({"logsource": {"category": "process_creation"},
                      "detection": {"selection": {"Image": "x"}, "condition": "selection"}})


def test_uncollected_logsource_is_rejected():
    with pytest.raises(SigmaRuleError, match="not one Aegis collects"):
        build({"selection": {"TargetObject": "x"}, "condition": "selection"},
              category="registry_set")


def test_missing_condition_is_rejected():
    with pytest.raises(SigmaRuleError, match="no condition"):
        build({"selection": {"Image": "x"}})


def test_detection_without_selections_is_rejected():
    with pytest.raises(SigmaRuleError, match="no search identifiers"):
        build({"condition": "selection"})


def test_condition_referencing_undefined_identifier_is_rejected():
    with pytest.raises(SigmaRuleError, match="undefined identifier"):
        build({"selection": {"Image": "x"}, "condition": "selection and missing"})


def test_condition_list_is_treated_as_or():
    rule = build({"sel_a": {"Image|endswith": "cmd.exe"},
                  "sel_b": {"Image|endswith": "powershell.exe"},
                  "condition": ["sel_a", "sel_b"]})
    assert matches(rule, proc(exe=r"C:\W\cmd.exe"))
    assert matches(rule, proc(exe=r"C:\W\powershell.exe"))
    assert not matches(rule, proc(exe=r"C:\W\notepad.exe"))


def test_referenced_fields_are_recorded():
    rule = build({"selection": {"Image|endswith": "x", "CommandLine|contains": "y"},
                  "condition": "selection"})
    assert rule.referenced_fields == {"image", "commandline"}


# --------------------------------------------------------------------------- #
# Field mapping
# --------------------------------------------------------------------------- #
def test_process_fields_are_exposed():
    fields = fields_for(proc(cmdline="x -enc y", parent="winword.exe"))
    assert fields["commandline"] == "x -enc y"
    assert fields["parentimage"] == "winword.exe"
    assert fields["user"] == "alice"


def test_network_fields_are_exposed():
    fields = fields_for(net(ip="45.9.1.1", port=4444))
    assert fields["destinationip"] == "45.9.1.1"
    assert fields["destinationport"] == 4444
    assert fields["initiated"] is True


def test_fields_aegis_cannot_observe_are_reported():
    missing = unsupported_fields("process_creation", {"Image", "ParentCommandLine", "Hashes"})
    assert "ParentCommandLine" in missing
    assert "Hashes" in missing
    assert "Image" not in missing


def test_parent_image_matching_works_end_to_end():
    rule = build({"selection": {"ParentImage|endswith": "winword.exe",
                                "Image|endswith": "powershell.exe"},
                  "condition": "selection"})
    assert matches(rule, proc(exe=r"C:\W\powershell.exe", parent="winword.exe"))
    assert not matches(rule, proc(exe=r"C:\W\powershell.exe", parent="explorer.exe"))


# --------------------------------------------------------------------------- #
# Adapter into the Aegis engine
# --------------------------------------------------------------------------- #
def test_adapter_produces_an_explainable_finding():
    rule = SigmaDetectionRule(build(
        {"selection": {"CommandLine|contains": "mimikatz"}, "condition": "selection"},
        title="Credential theft tool", level="critical",
        description="Detects mimikatz.",
        tags=["attack.credential-access", "attack.t1003"],
        falsepositives=["Security testing"],
    ))
    finding = rule.evaluate(proc(cmdline="mimikatz sekurlsa"), DetectionContext())

    assert finding is not None
    assert finding.severity is Severity.CRITICAL
    assert finding.technique == "T1003"
    assert finding.tactic == "Credential Access"
    assert any("Credential theft tool" in r for r in finding.reasons)
    # The rule author's own caveats travel with the alert, so a large imported
    # ruleset stays triageable rather than just noisy.
    assert any("Security testing" in r for r in finding.reasons)


def test_adapter_returns_none_when_no_match():
    rule = SigmaDetectionRule(build(
        {"selection": {"CommandLine|contains": "mimikatz"}, "condition": "selection"}))
    assert rule.evaluate(proc(cmdline="notepad.exe"), DetectionContext()) is None


def test_adapter_only_wants_its_own_event_type():
    rule = SigmaDetectionRule(build(
        {"selection": {"Image": "x"}, "condition": "selection"}))
    assert rule.wants(proc()) is True
    assert rule.wants(net()) is False


def test_network_rule_entity_is_the_peer():
    rule = SigmaDetectionRule(build(
        {"selection": {"DestinationPort": 4444}, "condition": "selection"},
        category="network_connection"))
    finding = rule.evaluate(net(ip="45.9.1.1", port=4444), DetectionContext())
    assert finding is not None
    # The entity is what the responder blocks, so it must carry the address.
    assert finding.entity.startswith("45.9.1.1")


def test_real_yaml_round_trips():
    text = """
    title: Suspicious Encoded Command
    id: test-0001
    level: high
    logsource:
        category: process_creation
    detection:
        selection:
            Image|endswith: '\\powershell.exe'
            CommandLine|contains: ' -enc '
        filter:
            CommandLine|contains: 'Get-WinEvent'
        condition: selection and not filter
    tags:
        - attack.execution
        - attack.t1059.001
    """
    rule = compile_rule(yaml.safe_load(text))
    assert rule.technique == "T1059.001"
    assert matches(rule, proc(exe=r"C:\W\powershell.exe", cmdline="ps -enc AAA"))
    assert not matches(rule, proc(exe=r"C:\W\powershell.exe",
                                  cmdline="ps -enc AAA Get-WinEvent"))
