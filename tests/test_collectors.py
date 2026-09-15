"""Tests for psutil collectors.

Deterministic heuristics are unit-tested directly; the live collectors are
exercised read-only against the real host (safe, no mutation).
"""
from aegis.collectors.network import NetworkCollector
from aegis.collectors.processes import ProcessCollector, flag_reasons, snapshot
from aegis.core.events import NetworkEvent, ProcessEvent


# --- deterministic heuristics ----------------------------------------------
def test_flag_reasons_temp_dir():
    reasons = flag_reasons(r"C:\Users\me\AppData\Local\Temp\evil.exe", "evil.exe")
    assert any("temporary" in r.lower() for r in reasons)


def test_flag_reasons_masquerade():
    reasons = flag_reasons(r"C:\Users\me\Downloads\svchost.exe", "svchost.exe")
    assert any("system-like" in r.lower() for r in reasons)


def test_flag_reasons_clean_process():
    assert flag_reasons(r"C:\Windows\System32\svchost.exe", "svchost.exe") == []


# --- cross-platform heuristics ----------------------------------------------
# These must hold identically on every OS, including in CI, so the checks are
# written over both path styles regardless of the host running the suite.
def test_flag_reasons_linux_temp_dir():
    assert any("temporary" in r.lower()
               for r in flag_reasons("/tmp/evil", "evil"))


def test_flag_reasons_linux_shared_memory_dir():
    assert any("temporary" in r.lower()
               for r in flag_reasons("/dev/shm/payload", "payload"))


def test_flag_reasons_linux_clean_system_process():
    assert flag_reasons("/usr/lib/systemd/systemd", "systemd") == []


def test_flag_reasons_linux_masquerade():
    assert any("system-like" in r.lower()
               for r in flag_reasons("/home/user/systemd", "systemd"))


def test_flag_reasons_macos_clean_system_process():
    assert flag_reasons("/sbin/launchd", "launchd") == []


def test_flag_reasons_macos_masquerade():
    assert any("system-like" in r.lower()
               for r in flag_reasons("/Users/me/Downloads/launchd", "launchd"))


def test_windows_binary_on_posix_path_is_masquerade():
    """A Windows system name outside a Windows directory is wrong anywhere."""
    assert any("system-like" in r.lower()
               for r in flag_reasons("/opt/app/svchost.exe", "svchost.exe"))


def test_absolute_path_detection_is_platform_independent():
    """os.path.isabs() only understands the host OS; these must not be flagged."""
    for path in (r"C:\Windows\System32\foo.exe", "/usr/bin/foo", r"\\server\share\foo.exe"):
        assert not any("not absolute" in r for r in flag_reasons(path, "foo")), path


def test_relative_path_is_flagged_on_any_platform():
    assert any("not absolute" in r for r in flag_reasons("evil.exe", "evil.exe"))
    assert any("not absolute" in r for r in flag_reasons("./evil", "evil"))


def test_windows_kernel_processes_without_an_image_file_are_not_flagged():
    for name in ("Registry", "MemCompression", "System", "Secure System", "vmmem"):
        assert flag_reasons(name, name) == [], name


def test_pathless_exemption_does_not_cover_other_names_or_temp_paths():
    assert any("not absolute" in r for r in flag_reasons("Registry", "evil.exe"))
    assert any("temporary" in r.lower()
               for r in flag_reasons(r"C:\Users\me\AppData\Local\Temp\Registry", "Registry"))


# --- live, read-only --------------------------------------------------------
def test_network_collector_emits_events():
    col = NetworkCollector()
    assert col.available()
    events = list(col.poll())
    assert all(isinstance(e, NetworkEvent) for e in events)


def test_network_collector_dedup():
    col = NetworkCollector(dedup=True)
    first = list(col.poll())
    second = list(col.poll())          # same connections -> deduped to (near) empty
    assert len(second) <= len(first)


def test_process_collector_and_snapshot():
    col = ProcessCollector()
    events = list(col.poll())
    assert all(isinstance(e, ProcessEvent) for e in events)
    assert len(events) > 0              # this test process exists at minimum

    procs = snapshot(limit=20)
    assert len(procs) > 0
    assert all(p.pid > 0 for p in procs)
