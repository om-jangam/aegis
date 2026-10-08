"""Known vulnerabilities in the programs installed on this computer.

The National Vulnerability Database, run by NIST, is the public record of
software flaws. It is free, needs no account, and it knows which versions each
flaw affects. That last part is what makes this useful rather than alarming: a
flaw is only reported here when the version actually installed is in range.

Two rules shape this module.

Aegis never reaches the network on its own. Looking up vulnerabilities happens
only when somebody asks (``aegis vulns check``). The answers are written to a
cache file, and the security check only ever reads that cache, so a check stays
offline, instant, and the same every time.

Only a program name and a version number are ever sent, to one government
database, over HTTPS. No file contents, no hashes, no identifiers, nothing
about the computer itself. The list of what is installed is yours; what Aegis
asks is the same question anybody could ask from any computer.

When a program cannot be matched to a database entry it is reported as "not
checked", never as "no vulnerabilities found". Saying a program is clean when
nobody looked would be the worst thing this could do.
"""
from __future__ import annotations

import json
import logging
import os
import re
import time
import urllib.parse
from collections.abc import Callable, Iterable
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path

from aegis.intel.feeds import Fetcher, https_fetch
from aegis.software import Program, is_interesting

log = logging.getLogger(__name__)

CVE_API = "https://services.nvd.nist.gov/rest/json/cves/2.0"
CPE_API = "https://services.nvd.nist.gov/rest/json/cpes/2.0"
MAX_RESPONSE_BYTES = 8 * 1024 * 1024
#: How many database entries one question returns.
PAGE_SIZE = 100
#: The environment variable holding an optional NVD API key. A key only raises
#: the rate limit; it is never written to the settings file or logged.
API_KEY_ENV = "AEGIS_NVD_API_KEY"
#: NVD allows 5 requests per 30 seconds without a key, 50 with one. Stay under.
DELAY_WITHOUT_KEY = 6.5
DELAY_WITH_KEY = 0.7
#: How long an answer stays usable. New flaws are published constantly, so a
#: month-old answer is worth re-asking; a name-to-database match rarely moves.
ANSWER_DAYS = 14
MATCH_DAYS = 180
#: Severity, worst first, as the database words it.
SEVERITIES = ("CRITICAL", "HIGH", "MEDIUM", "LOW", "NONE", "UNKNOWN")
_RANK = {name: index for index, name in enumerate(SEVERITIES)}
_WORD = re.compile(r"[a-z0-9+]+")
#: Words that carry no weight when matching a name to a database entry.
_FILLER = frozenset({"the", "for", "and", "inc", "llc", "ltd", "corporation",
                     "software", "project", "edition", "enu"})


@dataclass(frozen=True)
class Vulnerability:
    """One published flaw affecting an installed version."""

    cve_id: str
    severity: str = "UNKNOWN"
    score: float = 0.0
    summary: str = ""
    published: str = ""

    @property
    def rank(self) -> int:
        return _RANK.get(self.severity.upper(), _RANK["UNKNOWN"])

    @property
    def url(self) -> str:
        return f"https://nvd.nist.gov/vuln/detail/{self.cve_id}"

    def to_dict(self) -> dict:
        return {"id": self.cve_id, "severity": self.severity, "score": self.score,
                "summary": self.summary, "published": self.published}

    @classmethod
    def from_dict(cls, data: dict) -> Vulnerability:
        return cls(str(data.get("id", "")), str(data.get("severity", "UNKNOWN")),
                   float(data.get("score") or 0.0), str(data.get("summary", "")),
                   str(data.get("published", "")))


@dataclass
class ProgramReport:
    """What is known about one installed program."""

    name: str
    version: str
    product: str = ""                 # the database entry it matched, if any
    vulnerabilities: list[Vulnerability] = field(default_factory=list)
    checked: str = ""
    #: How many entries the database said it had, before Aegis checked which of
    #: them name this product as the vulnerable one. Larger than one page means
    #: the rest were never examined, which has to be said rather than implied.
    listed: int = 0

    @property
    def matched(self) -> bool:
        return bool(self.product)

    @property
    def truncated(self) -> bool:
        return self.listed > PAGE_SIZE

    @property
    def worst(self) -> str:
        if not self.vulnerabilities:
            return "NONE"
        return min(self.vulnerabilities, key=lambda v: v.rank).severity.upper()

    def count(self, severity: str) -> int:
        return sum(1 for v in self.vulnerabilities if v.severity.upper() == severity)

    def to_dict(self) -> dict:
        return {"name": self.name, "version": self.version, "product": self.product,
                "checked": self.checked, "listed": self.listed,
                "vulnerabilities": [v.to_dict() for v in self.vulnerabilities]}

    @classmethod
    def from_dict(cls, data: dict) -> ProgramReport:
        return cls(
            str(data.get("name", "")), str(data.get("version", "")),
            str(data.get("product", "")),
            [Vulnerability.from_dict(v) for v in data.get("vulnerabilities", [])],
            str(data.get("checked", "")), int(data.get("listed") or 0))


# --------------------------------------------------------------------------- #
# The cache on disk
# --------------------------------------------------------------------------- #
#: Where the answers live, inside the intel folder in the data directory.
CACHE_NAME = "vulnerabilities.json"


def cache_path() -> Path:
    """The cache file. Reading it must never create anything, so the folder is
    made only when something is actually written."""
    from aegis.config import DATA_DIR

    return DATA_DIR / "intel" / CACHE_NAME


def _now() -> str:
    return datetime.now(tz=UTC).isoformat(timespec="seconds")


def _age_days(stamp: str, now: datetime | None = None) -> float:
    try:
        when = datetime.fromisoformat(stamp)
    except (TypeError, ValueError):
        return 1e9
    if when.tzinfo is None:
        when = when.replace(tzinfo=UTC)
    return ((now or datetime.now(tz=UTC)) - when).total_seconds() / 86400


@dataclass
class VulnerabilityCache:
    """Everything already asked and answered, so nothing is asked twice."""

    #: cleaned program name -> {"product": "vendor:product", "checked": stamp}
    matches: dict[str, dict] = field(default_factory=dict)
    #: program key -> a stored :class:`ProgramReport`
    answers: dict[str, dict] = field(default_factory=dict)
    updated: str = ""

    @classmethod
    def load(cls, text: str | None) -> VulnerabilityCache:
        """Build from the file's contents; anything unreadable starts empty."""
        if not text:
            return cls()
        try:
            data = json.loads(text)
        except (TypeError, ValueError):
            log.warning("The vulnerability cache could not be read; starting fresh.")
            return cls()
        if not isinstance(data, dict):
            return cls()
        matches = data.get("matches")
        answers = data.get("answers")
        return cls(matches if isinstance(matches, dict) else {},
                   answers if isinstance(answers, dict) else {},
                   str(data.get("updated", "")))

    @classmethod
    def read(cls, path: Path | None = None) -> VulnerabilityCache:
        target = path or cache_path()
        try:
            return cls.load(target.read_text(encoding="utf-8"))
        except OSError:
            return cls()

    def save(self, path: Path | None = None) -> Path:
        target = path or cache_path()
        self.updated = _now()
        target.parent.mkdir(parents=True, exist_ok=True)
        body = json.dumps({"version": 1, "updated": self.updated,
                           "matches": self.matches, "answers": self.answers},
                          indent=1)
        tmp = target.with_name(target.name + ".tmp")
        tmp.write_text(body, encoding="utf-8")
        os.replace(tmp, target)
        return target

    # -- matches ----------------------------------------------------------- #
    def match(self, name: str) -> str | None:
        """The database entry for a name: "" for "looked, found nothing"."""
        entry = self.matches.get(name.lower())
        if not isinstance(entry, dict) or _age_days(entry.get("checked", "")) > MATCH_DAYS:
            return None
        return str(entry.get("product", ""))

    def remember_match(self, name: str, product: str) -> None:
        self.matches[name.lower()] = {"product": product, "checked": _now()}

    # -- answers ----------------------------------------------------------- #
    def answer(self, key: str) -> ProgramReport | None:
        entry = self.answers.get(key)
        if not isinstance(entry, dict):
            return None
        report = ProgramReport.from_dict(entry)
        return None if _age_days(report.checked) > ANSWER_DAYS else report

    def remember_answer(self, key: str, report: ProgramReport) -> None:
        report.checked = report.checked or _now()
        self.answers[key] = report.to_dict()

    def reports(self) -> list[ProgramReport]:
        """Every stored answer, worst first."""
        stored = [ProgramReport.from_dict(v) for v in self.answers.values()
                  if isinstance(v, dict)]
        return sorted(stored, key=lambda r: (_RANK.get(r.worst, 9),
                                             -len(r.vulnerabilities),
                                             r.name.lower()))

    def age_days(self) -> float:
        return _age_days(self.updated)


# --------------------------------------------------------------------------- #
# Matching a program name to a database entry
# --------------------------------------------------------------------------- #
def _words(text: str) -> set[str]:
    return {w for w in _WORD.findall(text.lower()) if w not in _FILLER}


def best_match(name: str, candidates: Iterable[tuple[str, str]]) -> str:
    """Pick the database entry that really is this program, or "".

    ``candidates`` are (vendor, product) pairs the database offered for the
    name. One is accepted only when every meaningful word of one side appears
    in the other: a search for "Oracle VirtualBox" may legitimately answer
    "oracle / vm_virtualbox", but it must not answer "some_other_tool". A wrong
    match would invent vulnerabilities, which is worse than finding none.
    """
    wanted = _words(name)
    if not wanted:
        return ""
    tally: dict[str, int] = {}
    for vendor, product in candidates:
        tally[f"{vendor}:{product}"] = tally.get(f"{vendor}:{product}", 0) + 1

    accepted: list[tuple[int, int, str]] = []
    for entry, seen in tally.items():
        vendor, _, product = entry.partition(":")
        offered = _words(f"{vendor} {product}")
        if wanted <= offered or offered <= wanted:
            # Fewer words in the entry means a closer fit, so prefer it; then
            # prefer the one the database offered most often.
            accepted.append((-seen, len(offered), entry))
    if not accepted:
        return ""
    return sorted(accepted)[0][2]


# --------------------------------------------------------------------------- #
# The client
# --------------------------------------------------------------------------- #
def api_key() -> str:
    return (os.environ.get(API_KEY_ENV) or "").strip()


@dataclass
class NvdClient:
    """Asks the National Vulnerability Database, politely and slowly."""

    fetch: Fetcher = https_fetch
    key: str = field(default_factory=api_key)
    sleep: Callable[[float], None] = time.sleep
    #: Set for tests; otherwise derived from whether a key is present.
    delay: float | None = None
    requests: int = 0

    @property
    def pause(self) -> float:
        if self.delay is not None:
            return self.delay
        return DELAY_WITH_KEY if self.key else DELAY_WITHOUT_KEY

    def _get(self, url: str, params: dict[str, str]) -> dict:
        if self.requests:
            self.sleep(self.pause)      # never faster than the published limit
        self.requests += 1
        query = urllib.parse.urlencode(params, safe=":*")
        body = self.fetch(f"{url}?{query}", MAX_RESPONSE_BYTES)
        data = json.loads(body.decode("utf-8", errors="replace"))
        return data if isinstance(data, dict) else {}

    def find_product(self, name: str) -> str:
        """The database entry for a program name, or "" when there is none."""
        data = self._get(CPE_API, {"keywordSearch": name, "resultsPerPage": "500"})
        candidates = []
        for product in data.get("products", []):
            parts = str(product.get("cpe", {}).get("cpeName", "")).split(":")
            if len(parts) > 5 and parts[2] == "a":      # an application entry
                candidates.append((parts[3], parts[4]))
        return best_match(name, candidates)

    def vulnerabilities(self, product: str,
                        version: str) -> tuple[list[Vulnerability], int]:
        """Published flaws in exactly this version, and how many were offered.

        The second number is what the database said it had in total. Only the
        first page is examined, so a bigger number means the answer is partial.
        """
        vendor, _, name = product.partition(":")
        match_string = f"cpe:2.3:a:{vendor}:{name}:{version}:*:*:*:*:*:*:*"
        data = self._get(CVE_API, {"virtualMatchString": match_string,
                                   "resultsPerPage": str(PAGE_SIZE)})
        found = []
        for entry in data.get("vulnerabilities", []):
            cve = entry.get("cve", {})
            if not isinstance(cve, dict) or not affects(cve, product, version):
                continue
            found.append(_vulnerability(cve))
        listed = int(data.get("totalResults") or len(data.get("vulnerabilities", [])))
        return (sorted([v for v in found if v.cve_id], key=lambda v: (v.rank, -v.score)),
                listed)


def _version_key(version: str) -> tuple:
    """Sortable form of a version, so 3.10 comes after 3.9 and not before it."""
    parts = []
    for piece in re.split(r"[._-]", version.strip()):
        if piece.isdigit():
            parts.append((0, int(piece), ""))
        elif piece:
            # A suffix like "rc1" or "beta" sorts before the plain release.
            parts.append((-1, 0, piece.lower()))
    return tuple(parts)


def _within(version: str, match: dict) -> bool:
    """Whether a version falls inside one entry's version range."""
    here = _version_key(version)
    bounds = (
        ("versionStartIncluding", lambda a, b: a >= b),
        ("versionStartExcluding", lambda a, b: a > b),
        ("versionEndIncluding", lambda a, b: a <= b),
        ("versionEndExcluding", lambda a, b: a < b),
    )
    for field_name, compare in bounds:
        edge = match.get(field_name)
        if edge and not compare(here, _version_key(str(edge))):
            return False
    return True


def affects(cve: dict, product: str, version: str) -> bool:
    """Whether the database says *this* product is the vulnerable one.

    An entry lists every product involved in a flaw, including the ones the
    vulnerable program merely runs on: the Odoo sandbox escape CVE-2020-29396
    names Python, because Odoo is written in it. The database marks those
    ``vulnerable: false``, and only the genuinely affected product true. Taking
    the whole list at face value would tell somebody their Python is critically
    vulnerable because of a bug in a web suite they do not have installed.
    """
    for configuration in cve.get("configurations", []):
        for node in configuration.get("nodes", []) if isinstance(configuration, dict) else []:
            for match in node.get("cpeMatch", []) if isinstance(node, dict) else []:
                if not isinstance(match, dict) or not match.get("vulnerable"):
                    continue
                parts = str(match.get("criteria", "")).split(":")
                if len(parts) < 6 or f"{parts[3]}:{parts[4]}" != product:
                    continue
                exact = parts[5]
                if exact not in ("*", "-"):
                    if _version_key(exact) == _version_key(version):
                        return True
                    continue
                if _within(version, match):
                    return True
    return False


def _vulnerability(cve: dict) -> Vulnerability:
    severity, score = _worst_metric(cve.get("metrics", {}))
    english = [d.get("value", "") for d in cve.get("descriptions", [])
               if d.get("lang") == "en"]
    summary = " ".join((english[0] if english else "").split())
    return Vulnerability(str(cve.get("id", "")), severity, score,
                         summary[:400], str(cve.get("published", ""))[:10])


def _worst_metric(metrics: dict) -> tuple[str, float]:
    """The worst rating across every scoring version the entry carries."""
    best = ("UNKNOWN", 0.0)
    for entries in metrics.values():
        for entry in entries if isinstance(entries, list) else []:
            if not isinstance(entry, dict):
                continue
            data = entry.get("cvssData", {})
            severity = str(data.get("baseSeverity")
                           or entry.get("baseSeverity") or "UNKNOWN").upper()
            score = float(data.get("baseScore") or 0.0)
            if (_RANK.get(severity, 9), -score) < (_RANK.get(best[0], 9), -best[1]):
                best = (severity, score)
    return best


# --------------------------------------------------------------------------- #
# Refreshing
# --------------------------------------------------------------------------- #
@dataclass
class RefreshSummary:
    checked: int = 0
    from_cache: int = 0
    unmatched: int = 0
    failed: int = 0
    vulnerable: int = 0
    requests: int = 0
    remaining: int = 0
    #: True when the run was asked to stop rather than finishing or hitting the limit.
    stopped: bool = False
    #: Answers dropped because the program is no longer installed.
    forgotten: int = 0
    message: str = ""


def refresh(programs: Iterable[Program], *, cache: VulnerabilityCache,
            client: NvdClient | None = None, limit: int = 40,
            progress: Callable[[str], None] | None = None,
            should_stop: Callable[[], bool] | None = None) -> RefreshSummary:
    """Ask the database about each program, skipping anything already known.

    ``limit`` caps how many programs are asked about in one run, because
    without an API key the database allows five questions every thirty seconds.
    Whatever is left over is reported, and the next run picks it up: the cache
    means no question is ever repeated unnecessarily. ``should_stop`` is checked
    between programs, so a long run can be abandoned without losing the answers
    already collected.
    """
    nvd = client or NvdClient()
    summary = RefreshSummary()
    say = progress or (lambda _message: None)
    present = list(programs)
    todo = [p for p in present if is_interesting(p)]
    summary.forgotten = _forget_uninstalled(cache, present)

    for program in todo:
        if summary.checked >= limit or (should_stop is not None and should_stop()):
            summary.remaining = len(todo) - summary.from_cache - summary.checked
            summary.stopped = should_stop is not None and should_stop()
            break

        stored = cache.answer(program.key)
        if stored is not None:
            summary.from_cache += 1
            if stored.vulnerabilities:
                summary.vulnerable += 1
            elif not stored.matched:
                summary.unmatched += 1
            continue

        summary.checked += 1
        try:
            report = _ask(nvd, program, cache)
        except Exception as exc:        # noqa: BLE001 - one failure, not a stop
            log.info("Could not look up %s: %s", program.product, exc)
            summary.failed += 1
            say(f"  ?    {program.product}: could not reach the database ({exc})")
            continue

        cache.remember_answer(program.key, report)
        if not report.matched:
            summary.unmatched += 1
            say(f"  -    {program.product} {program.version}: no database entry")
        elif report.vulnerabilities:
            summary.vulnerable += 1
            say(f"  !    {program.product} {program.version}: "
                f"{len(report.vulnerabilities)} known, worst {report.worst}")
        else:
            say(f"  ok   {program.product} {program.version}: nothing known")

    summary.requests = nvd.requests
    return summary


def _forget_uninstalled(cache: VulnerabilityCache, present: list[Program]) -> int:
    """Drop answers about programs that are no longer installed.

    Without this, uninstalling a vulnerable program would leave it being
    reported for ever: a weakness the person already fixed, held against them.
    """
    installed = {program.key for program in present}
    gone = [key for key in cache.answers if key not in installed]
    for key in gone:
        del cache.answers[key]
    return len(gone)


def _ask(nvd: NvdClient, program: Program, cache: VulnerabilityCache) -> ProgramReport:
    """One program: find its database entry, then its flaws for this version."""
    product = cache.match(program.product)
    if product is None:
        product = nvd.find_product(program.product)
        cache.remember_match(program.product, product)
    # The cleaned name, not the raw one: an installer that calls itself
    # "Oracle VirtualBox 7.2.2" would otherwise be shown with its version twice.
    if not product:
        return ProgramReport(program.product, program.version, "", [], _now())
    found, listed = nvd.vulnerabilities(product, program.version)
    return ProgramReport(program.product, program.version, product, found, _now(), listed)
