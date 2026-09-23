"""Opt-in download of free public threat-intelligence feeds.

Aegis makes no network requests on its own. This module runs only when a user
explicitly asks (``aegis intel update``). It fetches a few well-known IP
blocklists over HTTPS, validates every line, and writes the surviving
indicators into the intel directory, where detection picks them up.
"""
from __future__ import annotations

import os
import urllib.request
from collections.abc import Callable, Iterable
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path

from aegis import __version__
from aegis.intel.indicators import ThreatIntel

MAX_FEED_BYTES = 10 * 1024 * 1024

#: Takes (url, max_bytes) and returns the response body.
Fetcher = Callable[[str, int], bytes]


@dataclass(frozen=True)
class Feed:
    name: str
    url: str
    description: str


FEEDS: tuple[Feed, ...] = (
    Feed("abusech-feodo",
         "https://feodotracker.abuse.ch/downloads/ipblocklist_recommended.txt",
         "abuse.ch Feodo Tracker: active botnet command-and-control servers"),
    Feed("et-compromised",
         "https://rules.emergingthreats.net/blockrules/compromised-ips.txt",
         "Emerging Threats: hosts known to be compromised"),
    Feed("urlhaus-domains",
         "https://urlhaus.abuse.ch/downloads/hostfile/",
         "abuse.ch URLhaus: domain names serving malware"),
    Feed("spamhaus-drop",
         "https://www.spamhaus.org/drop/drop.txt",
         "Spamhaus DROP: netblocks hijacked or leased by criminals"),
)


@dataclass
class FeedResult:
    feed: Feed
    ok: bool
    indicators: int = 0
    message: str = ""


def https_fetch(url: str, max_bytes: int) -> bytes:
    if not url.startswith("https://"):
        raise ValueError("feeds must be fetched over HTTPS")
    request = urllib.request.Request(url, headers={"User-Agent": f"Aegis/{__version__}"})
    with urllib.request.urlopen(request, timeout=30) as response:  # noqa: S310 - https only
        data = response.read(max_bytes + 1)
    if len(data) > max_bytes:
        raise ValueError(f"response larger than {max_bytes} bytes")
    return data


def update_feeds(target_dir: Path, feeds: Iterable[Feed] = FEEDS,
                 fetch: Fetcher = https_fetch) -> list[FeedResult]:
    target_dir.mkdir(parents=True, exist_ok=True)
    results: list[FeedResult] = []
    for feed in feeds:
        try:
            body = fetch(feed.url, MAX_FEED_BYTES)
        except Exception as exc:  # noqa: BLE001 - one unreachable feed must not stop the rest
            results.append(FeedResult(feed, False, message=f"download failed: {exc}"))
            continue

        parsed = ThreatIntel()
        count = parsed.load_text(body.decode("utf-8", errors="replace"), feed.name)
        if count == 0:
            # An error page or empty body must not wipe out the last good copy.
            results.append(FeedResult(
                feed, False, message="no valid indicators in the response; kept previous copy"))
            continue

        stamp = datetime.now(tz=UTC).isoformat(timespec="seconds")
        lines = [f"# {feed.description}", f"# Source: {feed.url}", f"# Fetched: {stamp}",
                 *parsed.indicators()]
        path = target_dir / f"{feed.name}.txt"
        tmp = path.with_name(path.name + ".tmp")
        tmp.write_text("\n".join(lines) + "\n", encoding="utf-8")
        os.replace(tmp, path)
        results.append(FeedResult(feed, True, count, f"{count} indicators"))
    return results
