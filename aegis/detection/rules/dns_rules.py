"""Detections on the names this computer looks up.

Three different things are worth catching in DNS:

* the name, or what it resolves to, is already known to be malicious;
* the name looks machine-generated, which is how malware finds a controller
  that has not been taken down yet;
* one site is being asked for hundreds of different subdomains, which is what
  data leaving over DNS looks like.
"""
from __future__ import annotations

import math
import re
import threading
from collections import Counter
from datetime import datetime, timedelta

from aegis.core.events import DnsEvent, Event, EventType
from aegis.core.models import Severity
from aegis.detection.base import DetectionContext, DetectionRule
from aegis.intel import get_intel

#: Cloud and content networks hand out random-looking names by design, so a
#: name under one of these is never called machine-generated.
RANDOM_BY_DESIGN = (
    "cloudfront.net", "akamai.net", "akamaiedge.net", "akamaitechnologies.com",
    "azureedge.net", "azurewebsites.net", "trafficmanager.net", "windows.net",
    "amazonaws.com", "cloudflare.net", "cloudflare.com", "cdn77.org", "fastly.net",
    "googleusercontent.com", "googlevideo.com", "gvt1.com", "1e100.net",
    "digitaloceanspaces.com", "herokuapp.com", "b-cdn.net", "edgekey.net",
    "edgesuite.net", "llnwd.net", "doubleclick.net", "e2ro.com", "dropboxusercontent.com",
)
_VOWELS = set("aeiou")
_HEX = re.compile(r"^[0-9a-f]+$")


def shannon_entropy(text: str) -> float:
    """Bits of randomness per character: high means the name has little structure."""
    if not text:
        return 0.0
    counts = Counter(text)
    total = len(text)
    return -sum((n / total) * math.log2(n / total) for n in counts.values())


def looks_generated(label: str) -> tuple[bool, list[str]]:
    """Whether one label looks produced by an algorithm, and why.

    Deliberately strict. A false alarm here means telling somebody their normal
    browsing is an attack, so a name must be long *and* unstructured *and* not
    simply hexadecimal (which is ordinary in cache and CDN names) to qualify.
    """
    name = label.lower()
    if len(name) < 12 or _HEX.match(name):
        return False, []
    reasons = []
    entropy = shannon_entropy(name)
    letters = [c for c in name if c.isalpha()]
    vowel_share = sum(1 for c in letters if c in _VOWELS) / len(letters) if letters else 1.0
    digits = sum(1 for c in name if c.isdigit()) / len(name)
    if entropy >= 3.6:
        reasons.append(f"the name has little structure (entropy {entropy:.1f} bits)")
    if vowel_share < 0.25:
        reasons.append(f"only {vowel_share * 100:.0f}% of its letters are vowels")
    if digits >= 0.3:
        reasons.append(f"{digits * 100:.0f}% of it is digits")
    return len(reasons) >= 2, reasons


class _DnsRule(DetectionRule):
    event_types = (EventType.DNS_QUERY,)

    def __init__(self) -> None:
        self._last_fired: dict[str, datetime] = {}
        self._lock = threading.Lock()

    def _first_in_window(self, key: str, when: datetime,
                         window: timedelta = timedelta(minutes=30)) -> bool:
        with self._lock:
            last = self._last_fired.get(key)
            if last is not None and when - last < window:
                return False
            self._last_fired[key] = when
            if len(self._last_fired) > 4000:
                self._last_fired = {k: t for k, t in self._last_fired.items()
                                    if when - t < window}
        return True


class MaliciousDomainRule(_DnsRule):
    rule_id = "DNS-THREAT-INTEL"
    title = "Lookup of a known-malicious domain"
    severity = Severity.CRITICAL
    technique = "T1071.004"
    tactic = "Command and Control"
    description = ("A name on a threat-intelligence blocklist was looked up. Something on "
                   "this computer wanted to reach infrastructure known to serve malware or "
                   "take orders from attackers.")

    def evaluate(self, event: Event, context: DetectionContext):
        from aegis.config import settings

        if not isinstance(event, DnsEvent) or not settings.threat_intel_enabled:
            return None
        match = get_intel().match_domain(event.domain)
        if match is None:
            return None
        return self.make_finding(
            score=95,
            reasons=[f"{event.domain} is listed in threat feed '{match.source}'"
                     + (f" (as {match.indicator})" if match.indicator != event.domain else ""),
                     f"It resolved to {', '.join(event.answers[:3]) or 'nothing yet'}",
                     "Find the program that asked for it; block the address if it connects"],
            entity=f"dns:{event.domain}",
            source_summary=event.summary())


class MaliciousAnswerRule(_DnsRule):
    rule_id = "DNS-INTEL-ANSWER"
    title = "A name resolved to a known-malicious address"
    severity = Severity.HIGH
    technique = "T1071"
    tactic = "Command and Control"
    description = ("The name itself is not listed, but the address it points to is. "
                   "Attackers change names constantly; the server behind them moves less.")

    def evaluate(self, event: Event, context: DetectionContext):
        from aegis.config import settings

        if not isinstance(event, DnsEvent) or not settings.threat_intel_enabled:
            return None
        intel = get_intel()
        for answer in event.answers:
            match = intel.match(answer)
            if match is not None:
                return self.make_finding(
                    score=90,
                    reasons=[f"{event.domain} resolved to {answer}",
                             f"{answer} is listed in threat feed '{match.source}'"
                             + (f" (inside {match.indicator})"
                                if match.indicator != answer else "")],
                    entity=f"dns:{event.domain}",
                    source_summary=event.summary())
        return None


class GeneratedDomainRule(_DnsRule):
    rule_id = "DNS-GENERATED-NAME"
    title = "Lookup of a machine-generated domain name"
    severity = Severity.MEDIUM
    technique = "T1568.002"
    tactic = "Command and Control"
    description = ("The name looks produced by an algorithm rather than chosen by a person. "
                   "Malware generates names by the thousand so its controller can move as "
                   "fast as defenders take it down.")

    def evaluate(self, event: Event, context: DetectionContext):
        if not isinstance(event, DnsEvent):
            return None
        parent = event.parent_domain
        if parent.endswith(RANDOM_BY_DESIGN) or parent in RANDOM_BY_DESIGN:
            return None
        label = parent.split(".")[0]
        generated, reasons = looks_generated(label)
        if not generated:
            return None
        if not self._first_in_window(f"dga:{parent}", event.timestamp):
            return None
        return self.make_finding(
            score=55,
            reasons=[f"{event.domain} was looked up, and '{label}' {reasons[0]}",
                     *(f"Also, {reason}" for reason in reasons[1:]),
                     "Harmless on its own; worrying together with an alert about the "
                     "program that asked"],
            entity=f"dns:{parent}",
            source_summary=event.summary())


class DnsTunnelRule(_DnsRule):
    rule_id = "DNS-TUNNEL"
    title = "Data may be leaving through DNS lookups"
    severity = Severity.HIGH
    technique = "T1071.004"
    tactic = "Command and Control"
    description = ("One site was asked for many different subdomains in a short time. DNS "
                   "is allowed out of almost every network, so it is used to smuggle data "
                   "out and commands in, one lookup at a time.")
    WINDOW = timedelta(minutes=10)
    #: Distinct subdomains of one site before this counts as a tunnel.
    THRESHOLD = 25
    #: A label this long is carrying data, not naming a server.
    LONG_LABEL = 40

    def evaluate(self, event: Event, context: DetectionContext):
        if not isinstance(event, DnsEvent):
            return None
        parent = event.parent_domain
        if not parent or parent.endswith(RANDOM_BY_DESIGN):
            return None
        since = event.timestamp - self.WINDOW
        names = {e.domain for e in context.recent(EventType.DNS_QUERY)
                 if isinstance(e, DnsEvent) and e.parent_domain == parent
                 and e.timestamp >= since}
        longest = max((len(label) for label in event.labels), default=0)
        if len(names) < self.THRESHOLD and longest < self.LONG_LABEL:
            return None
        if not self._first_in_window(f"tunnel:{parent}", event.timestamp):
            return None
        reasons = []
        if len(names) >= self.THRESHOLD:
            reasons.append(f"{len(names)} different subdomains of {parent} were looked up "
                           f"in {int(self.WINDOW.total_seconds() // 60)} minutes")
        if longest >= self.LONG_LABEL:
            reasons.append(f"one part of the name is {longest} characters long, which is "
                           f"data rather than a server name")
        reasons.append("Some security and anti-virus products do this legitimately")
        return self.make_finding(
            score=80, reasons=reasons, entity=f"dns:{parent}",
            source_summary=event.summary())


DNS_RULES = [
    MaliciousDomainRule(),
    MaliciousAnswerRule(),
    GeneratedDomainRule(),
    DnsTunnelRule(),
]
