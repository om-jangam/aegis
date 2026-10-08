"""Finding installed programs with publicly known flaws.

Nothing here reaches the network: the database is replaced by a recorder that
answers from fixtures, which also lets the privacy promise be tested directly -
the only things that may ever leave this computer are a program name and a
version number.
"""
import json
import urllib.parse
from datetime import UTC, datetime, timedelta

import pytest

from aegis.core.models import Severity
from aegis.intel.vulns import (
    NvdClient,
    ProgramReport,
    Vulnerability,
    VulnerabilityCache,
    affects,
    best_match,
    refresh,
)
from aegis.platforms import OS
from aegis.posture import CheckStatus, PostureContext
from aegis.posture.checks import VulnerableSoftwareCheck
from aegis.response.command import RunResult
from aegis.software import (
    Program,
    clean_name,
    clean_version,
    installed_programs,
    is_interesting,
    linux_programs,
    macos_programs,
    windows_programs,
)


# --------------------------------------------------------------------------- #
# Reading the list of installed programs
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize(("display", "expected"), [
    ("Python 3.12.10 (64-bit)", "Python"),
    ("Oracle VirtualBox 7.2.2", "Oracle VirtualBox"),
    ("Inno Setup version 6.7.3", "Inno Setup"),
    ("Cisco Packet Tracer 9.0.0 64Bit", "Cisco Packet Tracer"),
    ("Microsoft 365 Apps for enterprise - en-us", "Microsoft 365 Apps for enterprise"),
    ("Microsoft Visual Studio Code (User)", "Microsoft Visual Studio Code"),
    ("Google Chrome", "Google Chrome"),
    ("", ""),
])
def test_installer_decoration_is_stripped_from_a_name(display, expected):
    assert clean_name(display) == expected


def test_a_year_in_the_product_name_is_not_a_version():
    """"Visual C++ 2012" is what the product is called, not which version."""
    assert clean_name("Microsoft Visual C++ 2012 Redistributable (x64) - 11.0.61030") == (
        "Microsoft Visual C++ 2012 Redistributable")


@pytest.mark.parametrize(("name", "display_version", "expected"), [
    # the version in the name is the published one; DisplayVersion is a build
    ("Python 3.12.10 (64-bit)", "3.12.10150.0", "3.12.10"),
    ("Google Chrome", "154.0.8037.99", "154.0.8037.99"),
    ("Node.js", "", ""),
    ("Some Tool", "not a version", ""),
])
def test_the_version_to_look_up(name, display_version, expected):
    assert clean_version(name, display_version) == expected


def test_windows_programs_come_from_all_three_uninstall_roots():
    entries = {
        ("HKLM", "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall"): [
            {"DisplayName": "VLC media player", "DisplayVersion": "3.0.20",
             "Publisher": "VideoLAN"},
            {"DisplayName": "Windows SDK", "DisplayVersion": "10.0", "SystemComponent": 1},
            {"DisplayName": "Update for Office", "DisplayVersion": "1.0",
             "ParentKeyName": "Office"},
            {"DisplayVersion": "9.9"},                      # no name at all
        ],
        ("HKLM", "SOFTWARE\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall"): [
            {"DisplayName": "VLC media player", "DisplayVersion": "3.0.20"},   # duplicate
            {"DisplayName": "7-Zip 21.07", "DisplayVersion": "21.07"},
        ],
        ("HKCU", "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall"): [
            {"DisplayName": "Notion 7.27.0", "DisplayVersion": "7.27.0"},
        ],
    }
    programs = windows_programs(lambda hive, key: entries.get((hive, key), []))

    assert [(p.product, p.version) for p in programs] == [
        ("7-Zip", "21.07"), ("Notion", "7.27.0"), ("VLC media player", "3.0.20")]
    assert programs[2].publisher == "VideoLAN"


def test_an_unreadable_registry_is_an_empty_list_not_a_crash():
    def broken(hive, key):
        raise OSError("access denied")

    with pytest.raises(OSError):
        broken("HKLM", "x")                 # the fake really does raise
    assert windows_programs(lambda hive, key: []) == []


def test_linux_packages_come_from_dpkg():
    def runner(args, timeout):
        if args[0] == "dpkg-query":
            return RunResult(0, b"openssl\t3.0.2-0ubuntu1.15\nvim\t2:9.0.1000-1\n")
        raise FileNotFoundError(args[0])

    assert [(p.name, p.version, p.source) for p in linux_programs(runner)] == [
        ("openssl", "3.0.2", "dpkg"), ("vim", "9.0.1000", "dpkg")]


def test_rpm_is_used_where_dpkg_is_absent():
    def runner(args, timeout):
        if args[0] == "dpkg-query":
            raise FileNotFoundError("dpkg-query")
        return RunResult(0, b"openssl\t3.0.7\n")

    assert [(p.name, p.version, p.source) for p in linux_programs(runner)] == [
        ("openssl", "3.0.7", "rpm")]


def test_macos_applications_come_from_their_bundle():
    plist = ("<dict><key>CFBundleShortVersionString</key><string>3.0.20</string></dict>")
    programs = macos_programs(lambda pattern: ["/Applications/VLC.app"],
                              lambda path: plist)
    assert [(p.name, p.version) for p in programs] == [("VLC", "3.0.20")]


def test_an_unsupported_platform_reports_nothing_rather_than_guessing():
    assert installed_programs(OS.UNKNOWN) == []


@pytest.mark.parametrize(("program", "wanted"), [
    (Program("VLC media player", "3.0.20"), True),
    (Program("VLC media player", ""), False),                   # no version to match
    (Program("Microsoft Visual C++ 2012 Redistributable", "11.0"), False),
    (Program("Microsoft Edge WebView2 Runtime", "1.0"), False),
    (Program("", "1.0"), False),
])
def test_only_real_programs_with_a_version_are_looked_up(program, wanted):
    assert is_interesting(program) is wanted


# --------------------------------------------------------------------------- #
# Matching a name to a database entry
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize(("name", "candidates", "expected"), [
    # the database calls it vm_virtualbox; the vendor makes up the difference
    ("Oracle VirtualBox", [("oracle", "vm_virtualbox")], "oracle:vm_virtualbox"),
    ("Google Chrome", [("google", "chrome")], "google:chrome"),
    ("VLC media player", [("videolan", "vlc_media_player")], "videolan:vlc_media_player"),
    ("Node.js", [("nodejs", "node.js")], "nodejs:node.js"),
    # a name the search merely mentioned is not this program
    ("Oracle VirtualBox", [("acme", "unrelated_tool")], ""),
    ("ShareX", [], ""),
    ("", [("x", "y")], ""),
])
def test_only_a_genuine_name_match_is_accepted(name, candidates, expected):
    assert best_match(name, candidates) == expected


def test_the_closest_entry_wins_when_several_fit():
    candidates = [("python", "python"), ("python", "python"),
                  ("python", "python_docs_theme")]
    assert best_match("Python", candidates) == "python:python"


# --------------------------------------------------------------------------- #
# Only the genuinely vulnerable product counts
# --------------------------------------------------------------------------- #
#: The real shape of CVE-2020-29396: an Odoo sandbox escape. Python appears
#: because Odoo is written in it, and is marked not vulnerable.
ODOO_CVE = {
    "id": "CVE-2020-29396",
    "configurations": [{"nodes": [{"cpeMatch": [
        {"vulnerable": True, "criteria": "cpe:2.3:a:odoo:odoo:*:*:*:*:community:*:*:*",
         "versionStartIncluding": "11.0", "versionEndIncluding": "13.0"},
        {"vulnerable": False, "criteria": "cpe:2.3:a:python:python:*:*:*:*:*:*:*:*"},
    ]}]}],
}


def test_a_flaw_in_something_else_is_not_a_flaw_in_python():
    assert affects(ODOO_CVE, "odoo:odoo", "12.0") is True
    assert affects(ODOO_CVE, "python:python", "3.12.10") is False


RANGE_CVE = {
    "id": "CVE-2026-0001",
    "configurations": [{"nodes": [{"cpeMatch": [
        {"vulnerable": True, "criteria": "cpe:2.3:a:nodejs:node.js:*:*:*:*:*:*:*:*",
         "versionStartIncluding": "24.0.0", "versionEndExcluding": "24.19.0"},
    ]}]}],
}


@pytest.mark.parametrize(("version", "affected"), [
    ("24.18.0", True),
    ("24.0.0", True),            # the start is included
    ("24.19.0", False),          # the end is not
    ("23.9.0", False),
    ("25.1.0", False),
])
def test_a_version_range_is_respected(version, affected):
    assert affects(RANGE_CVE, "nodejs:node.js", version) is affected


def test_version_numbers_are_compared_as_numbers_not_text():
    """3.10 is newer than 3.9, which sorting as text gets backwards."""
    cve = {"configurations": [{"nodes": [{"cpeMatch": [
        {"vulnerable": True, "criteria": "cpe:2.3:a:python:python:*:*:*:*:*:*:*:*",
         "versionEndExcluding": "3.10"}]}]}]}
    assert affects(cve, "python:python", "3.9.0") is True
    assert affects(cve, "python:python", "3.10.0") is False


def test_an_exact_version_in_the_entry_must_equal_the_installed_one():
    cve = {"configurations": [{"nodes": [{"cpeMatch": [
        {"vulnerable": True, "criteria": "cpe:2.3:a:7-zip:7-zip:21.07:*:*:*:*:*:*:*"}]}]}]}
    assert affects(cve, "7-zip:7-zip", "21.07") is True
    assert affects(cve, "7-zip:7-zip", "24.09") is False


def test_an_entry_with_no_configuration_affects_nothing():
    assert affects({"id": "CVE-X"}, "python:python", "3.12") is False


# --------------------------------------------------------------------------- #
# The client
# --------------------------------------------------------------------------- #
CPE_ANSWER = {"products": [
    {"cpe": {"cpeName": "cpe:2.3:a:videolan:vlc_media_player:3.0.20:*:*:*:*:*:*:*"}},
    {"cpe": {"cpeName": "cpe:2.3:o:videolan:firmware:1.0:*:*:*:*:*:*:*"}},   # not an app
]}
CVE_ANSWER = {"vulnerabilities": [
    {"cve": {
        "id": "CVE-2026-1111",
        "published": "2026-02-03T00:00:00.000",
        "descriptions": [{"lang": "es", "value": "ignorado"},
                         {"lang": "en", "value": "A  heap overflow\nin the demuxer."}],
        "metrics": {"cvssMetricV31": [{"cvssData": {"baseSeverity": "HIGH",
                                                    "baseScore": 8.8}}],
                    "cvssMetricV2": [{"baseSeverity": "MEDIUM", "cvssData": {}}]},
        "configurations": [{"nodes": [{"cpeMatch": [
            {"vulnerable": True,
             "criteria": "cpe:2.3:a:videolan:vlc_media_player:*:*:*:*:*:*:*:*",
             "versionEndExcluding": "3.0.21"}]}]}],
    }},
    {"cve": ODOO_CVE},            # must be dropped: VLC is not the vulnerable product
]}


class FakeNvd:
    """Records every question asked, and answers from fixtures."""

    def __init__(self, cpe=None, cve=None, fail=False):
        self.urls: list[str] = []
        self.cpe = CPE_ANSWER if cpe is None else cpe
        self.cve = CVE_ANSWER if cve is None else cve
        self.fail = fail

    def __call__(self, url: str, max_bytes: int) -> bytes:
        self.urls.append(url)
        if self.fail:
            raise OSError("no network")
        answer = self.cpe if "/cpes/" in url else self.cve
        return json.dumps(answer).encode()


def client(fetch, **kwargs):
    return NvdClient(fetch=fetch, key="", sleep=lambda _s: None, delay=0, **kwargs)


def test_a_product_is_resolved_from_the_database():
    fetch = FakeNvd()
    assert client(fetch).find_product("VLC media player") == "videolan:vlc_media_player"
    assert "keywordSearch=VLC+media+player" in fetch.urls[0]


def test_only_flaws_in_this_product_and_version_are_returned():
    found, listed = client(FakeNvd()).vulnerabilities("videolan:vlc_media_player",
                                                      "3.0.20")
    assert [v.cve_id for v in found] == ["CVE-2026-1111"]
    assert listed == 2, "both offered entries were counted, one was ruled out"
    assert found[0].severity == "HIGH" and found[0].score == 8.8
    assert found[0].summary == "A heap overflow in the demuxer."
    assert found[0].published == "2026-02-03"
    assert found[0].url.endswith("CVE-2026-1111")


def test_a_newer_version_is_not_reported_as_vulnerable():
    found, _ = client(FakeNvd()).vulnerabilities("videolan:vlc_media_player", "3.0.21")
    assert found == []


def test_a_partial_answer_says_so_rather_than_looking_complete():
    """Chrome really does have more flaws on record than one page holds."""
    many = {"totalResults": 143, "vulnerabilities": CVE_ANSWER["vulnerabilities"]}
    cache = VulnerabilityCache()
    program = Program("VLC media player", "3.0.20")
    refresh([program], cache=cache, client=client(FakeNvd(cve=many)), limit=5)

    report = cache.answer(program.key)
    assert report is not None and report.listed == 143 and report.truncated


def test_a_complete_answer_is_not_called_partial():
    cache = VulnerabilityCache()
    program = Program("VLC media player", "3.0.20")
    refresh([program], cache=cache, client=client(FakeNvd()), limit=5)
    report = cache.answer(program.key)
    assert report is not None and not report.truncated


def test_the_published_rate_limit_is_respected():
    waits: list[float] = []
    nvd = NvdClient(fetch=FakeNvd(), key="", sleep=waits.append)
    nvd.find_product("VLC media player")
    nvd.vulnerabilities("videolan:vlc_media_player", "3.0.20")
    # the first question goes out at once; every later one waits first
    assert waits == [pytest.approx(nvd.pause)]
    assert nvd.pause >= 6.0, "five questions per thirty seconds without a key"


def test_an_api_key_only_raises_the_rate_limit():
    assert NvdClient(fetch=FakeNvd(), key="abc").pause < 1.0


# --------------------------------------------------------------------------- #
# The privacy promise
# --------------------------------------------------------------------------- #
#: The only things a question may ever consist of.
ALLOWED_PARAMETERS = {"keywordSearch", "virtualMatchString", "resultsPerPage"}


def test_nothing_but_a_name_and_a_version_ever_leaves_this_computer():
    fetch = FakeNvd()
    refresh([Program("VLC media player", "3.0.20",
                     publisher="Private Publisher Ltd", source="registry")],
            cache=VulnerabilityCache(), client=client(fetch), limit=5)

    assert fetch.urls, "the database was asked something"
    for url in fetch.urls:
        assert url.startswith("https://services.nvd.nist.gov/"), url
        sent = url.split("?", 1)[1]
        assert set(urllib.parse.parse_qs(sent)) <= ALLOWED_PARAMETERS, sent
        # nothing about where the program came from, and no identifier of any
        # kind: not the publisher, not the install source, not a path or token
        for private in ("Private Publisher", "registry", "token", "C:\\",
                        "aegis", "localhost"):
            assert private.lower() not in sent.lower(), f"{private} appeared in {sent}"


# --------------------------------------------------------------------------- #
# The cache
# --------------------------------------------------------------------------- #
def stamp(days_ago: float) -> str:
    return (datetime.now(tz=UTC) - timedelta(days=days_ago)).isoformat(timespec="seconds")


def test_the_cache_survives_a_round_trip(tmp_path):
    cache = VulnerabilityCache()
    cache.remember_match("VLC media player", "videolan:vlc_media_player")
    cache.remember_answer("vlc@3.0.20", ProgramReport(
        "VLC media player", "3.0.20", "videolan:vlc_media_player",
        [Vulnerability("CVE-2026-1111", "HIGH", 8.8, "boom", "2026-02-03")]))
    path = cache.save(tmp_path / "v.json")

    again = VulnerabilityCache.read(path)
    assert again.match("vlc media player") == "videolan:vlc_media_player"
    stored = again.answer("vlc@3.0.20")
    assert stored is not None
    assert stored.vulnerabilities[0].cve_id == "CVE-2026-1111"
    assert stored.worst == "HIGH"


def test_a_damaged_cache_starts_empty_instead_of_failing():
    assert VulnerabilityCache.load("not json at all").answers == {}
    assert VulnerabilityCache.load("[1, 2, 3]").matches == {}
    assert VulnerabilityCache.load(None).reports() == []


def test_a_missing_cache_file_is_not_an_error(tmp_path):
    assert VulnerabilityCache.read(tmp_path / "absent.json").reports() == []


def test_an_old_answer_is_asked_again():
    cache = VulnerabilityCache()
    cache.answers["vlc@3.0.20"] = ProgramReport(
        "VLC", "3.0.20", "videolan:vlc_media_player", [], stamp(90)).to_dict()
    assert cache.answer("vlc@3.0.20") is None


def test_the_worst_programs_are_listed_first():
    cache = VulnerabilityCache()
    for key, severity in (("a@1", "MEDIUM"), ("b@1", "CRITICAL"), ("c@1", "")):
        found = [Vulnerability("CVE-1", severity)] if severity else []
        cache.remember_answer(key, ProgramReport(key, "1", "v:p", found))
    assert [r.worst for r in cache.reports()] == ["CRITICAL", "MEDIUM", "NONE"]


# --------------------------------------------------------------------------- #
# Refreshing
# --------------------------------------------------------------------------- #
def test_a_cached_answer_is_not_asked_about_again():
    fetch = FakeNvd()
    cache = VulnerabilityCache()
    program = Program("VLC media player", "3.0.20")
    cache.remember_answer(program.key, ProgramReport(
        program.name, "3.0.20", "videolan:vlc_media_player",
        [Vulnerability("CVE-2026-1111", "HIGH")]))

    summary = refresh([program], cache=cache, client=client(fetch), limit=5)
    assert fetch.urls == []
    assert summary.from_cache == 1 and summary.checked == 0 and summary.vulnerable == 1


def test_a_known_product_name_is_not_resolved_twice():
    fetch = FakeNvd()
    cache = VulnerabilityCache()
    cache.remember_match("VLC media player", "videolan:vlc_media_player")
    refresh([Program("VLC media player", "3.0.20")], cache=cache, client=client(fetch),
            limit=5)
    assert all("/cpes/" not in url for url in fetch.urls)


def test_a_program_the_database_does_not_know_is_never_called_clean():
    cache = VulnerabilityCache()
    summary = refresh([Program("ShareX", "21.0.0")], cache=cache,
                      client=client(FakeNvd(cpe={"products": []})), limit=5)
    report = cache.answer(Program("ShareX", "21.0.0").key)
    assert summary.unmatched == 1 and summary.vulnerable == 0
    assert report is not None and not report.matched


def test_the_run_stops_at_the_limit_and_says_what_is_left():
    programs = [Program(f"Tool {n}", "1.0") for n in range(5)]
    summary = refresh(programs, cache=VulnerabilityCache(),
                      client=client(FakeNvd(cpe={"products": []})), limit=2)
    assert summary.checked == 2 and summary.remaining == 3


def test_an_uninstalled_program_stops_being_reported():
    """A weakness somebody already removed must not be held against them."""
    cache = VulnerabilityCache()
    old = Program("Oracle VirtualBox", "7.2.2")
    cache.remember_answer(old.key, ProgramReport(
        old.name, "7.2.2", "oracle:vm_virtualbox", [Vulnerability("CVE-1", "HIGH")]))
    still_here = Program("VLC media player", "3.0.20")

    summary = refresh([still_here], cache=cache, client=client(FakeNvd()), limit=5)

    assert summary.forgotten == 1
    assert cache.answer(old.key) is None
    assert [r.name for r in cache.reports()] == ["VLC media player"]


def test_a_version_is_not_printed_twice_for_an_installer_that_includes_it():
    cache = VulnerabilityCache()
    program = Program("Oracle VirtualBox 7.2.2", "7.2.2")
    refresh([program], cache=cache, client=client(FakeNvd(cpe={"products": []})), limit=5)

    report = cache.answer(program.key)
    assert report is not None
    assert report.name == "Oracle VirtualBox" and report.version == "7.2.2"


def test_a_program_that_is_still_installed_keeps_its_answer():
    cache = VulnerabilityCache()
    program = Program("VLC media player", "3.0.20")
    cache.remember_answer(program.key, ProgramReport(
        program.name, "3.0.20", "videolan:vlc_media_player", []))

    summary = refresh([program], cache=cache, client=client(FakeNvd()), limit=5)
    assert summary.forgotten == 0 and cache.answer(program.key) is not None


def test_a_long_run_can_be_stopped_and_keeps_what_it_already_has():
    cache = VulnerabilityCache()
    programs = [Program(f"Tool {n}", "1.0") for n in range(5)]
    # stop once the first program has been dealt with
    summary = refresh(programs, cache=cache, client=client(FakeNvd(cpe={"products": []})),
                      limit=5, should_stop=lambda: bool(cache.answers))

    assert summary.stopped and summary.checked == 1 and summary.remaining == 4
    assert cache.answer(programs[0].key) is not None


def test_a_run_that_finishes_is_not_reported_as_stopped():
    summary = refresh([Program("Tool", "1.0")], cache=VulnerabilityCache(),
                      client=client(FakeNvd(cpe={"products": []})), limit=5,
                      should_stop=lambda: False)
    assert not summary.stopped and summary.remaining == 0


def test_one_unreachable_lookup_does_not_stop_the_rest():
    lines: list[str] = []
    summary = refresh([Program("VLC media player", "3.0.20"), Program("Git", "2.54.0")],
                      cache=VulnerabilityCache(), client=client(FakeNvd(fail=True)),
                      limit=5, progress=lines.append)
    assert summary.failed == 2 and summary.checked == 2
    assert any("could not reach" in line for line in lines)


def test_programs_that_are_part_of_windows_are_skipped_entirely():
    fetch = FakeNvd()
    summary = refresh([Program("Microsoft Visual C++ 2012 Redistributable", "11.0")],
                      cache=VulnerabilityCache(), client=client(fetch), limit=5)
    assert fetch.urls == [] and summary.checked == 0


# --------------------------------------------------------------------------- #
# The security check, which must work with no network at all
# --------------------------------------------------------------------------- #
def check_with(reports, *, age_days=0.0):
    """Run the check against a cache holding exactly these reports."""
    cache = VulnerabilityCache()
    for index, report in enumerate(reports):
        cache.remember_answer(f"p{index}@1", report)
    cache.updated = stamp(age_days)
    body = json.dumps({"version": 1, "updated": cache.updated,
                       "matches": cache.matches, "answers": cache.answers})
    ctx = PostureContext(os=OS.WINDOWS, read_text=lambda path: body)
    return VulnerableSoftwareCheck().run(ctx)


def test_the_check_says_so_when_nothing_has_been_looked_up_yet():
    ctx = PostureContext(os=OS.WINDOWS, read_text=lambda path: None)
    result = VulnerableSoftwareCheck().run(ctx)
    assert result.status is CheckStatus.SKIP
    assert "aegis vulns check" in result.summary


def test_a_high_rated_flaw_fails_the_check():
    result = check_with([ProgramReport("Oracle VirtualBox", "7.2.2", "oracle:vm_virtualbox",
                                       [Vulnerability("CVE-1", "HIGH", 8.2)])])
    assert result.status is CheckStatus.FAIL
    assert result.severity is Severity.HIGH
    assert "Oracle VirtualBox 7.2.2" in " ".join(result.details)
    assert "1 high" in " ".join(result.details)


def test_a_medium_rated_flaw_is_a_warning_not_a_failure():
    result = check_with([ProgramReport("Some Tool", "1.0", "v:p",
                                       [Vulnerability("CVE-2", "MEDIUM", 5.0)])])
    assert result.status is CheckStatus.WARN
    assert result.severity is Severity.MEDIUM


def test_the_check_passes_when_nothing_is_known_against_anything():
    result = check_with([ProgramReport("VLC media player", "3.0.23",
                                       "videolan:vlc_media_player", [])])
    assert result.status is CheckStatus.PASS
    assert "1 program" in result.summary


def test_programs_with_no_database_entry_are_reported_as_unchecked():
    result = check_with([ProgramReport("ShareX", "21.0.0", "", []),
                         ProgramReport("VLC", "3.0.23", "videolan:vlc_media_player", [])])
    details = " ".join(result.details)
    assert result.status is CheckStatus.PASS
    assert "1 had no database entry and were not checked" in details
    # the one program that was really checked is the only one called clean
    assert "No known vulnerabilities in the 1 program(s)" in result.summary


def test_stale_answers_are_flagged_as_stale():
    result = check_with([ProgramReport("VLC", "3.0.23", "videolan:vlc_media_player", [])],
                        age_days=45)
    assert "45 days old" in " ".join(result.details)


def test_the_check_names_the_entry_it_matched_so_a_wrong_match_is_visible():
    """"GitHub Copilot" can match "github:copilot-cli", a different product."""
    result = check_with([ProgramReport("GitHub Copilot", "1.0.10", "github:copilot-cli",
                                       [Vulnerability("CVE-3", "HIGH", 7.5)])])
    assert "[matched github:copilot-cli]" in " ".join(result.details)


def test_a_partial_answer_is_not_presented_as_the_whole_truth():
    result = check_with([ProgramReport(
        "Google Chrome", "154.0.8037.99", "google:chrome",
        [Vulnerability(f"CVE-{n}", "CRITICAL", 9.8) for n in range(100)], listed=143)])
    details = " ".join(result.details)
    assert "the database lists 143" in details
    assert result.status is CheckStatus.FAIL


def test_many_vulnerable_programs_are_summarised_rather_than_all_listed():
    reports = [ProgramReport(f"Tool {n}", "1.0", "v:p",
                             [Vulnerability(f"CVE-{n}", "HIGH", 7.5)]) for n in range(9)]
    details = " ".join(check_with(reports).details)
    assert "and 3 more" in details
