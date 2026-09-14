"""Translation between Aegis events and the Sigma field taxonomy.

Sigma rules are written against Sysmon/Windows Event Log field names
(``Image``, ``CommandLine``, ``DestinationIp``…). Aegis observes the host with
psutil, which sees a *subset* of those fields. This module is the honest seam
between the two.

Why unsupported fields are tracked rather than ignored
------------------------------------------------------
The tempting shortcut is to treat a field Aegis cannot observe as "no match".
That silently turns a rule into dead weight: it loads, it reports as active, and
it can never fire. A detection tool that quietly does nothing is worse than one
that admits a gap, so every field Aegis cannot supply is recorded, and
:func:`unsupported_fields` lets the loader skip and *report* rules that depend on
them. ``aegis sigma stats`` surfaces that coverage.
"""
from __future__ import annotations

from aegis.core.events import Direction, Event, EventType, NetworkEvent, ProcessEvent

# Sigma logsource categories Aegis can serve, mapped to the event types that
# feed them.
CATEGORY_EVENT_TYPES: dict[str, tuple[EventType, ...]] = {
    "process_creation": (EventType.PROCESS_START,),
    "network_connection": (EventType.NETWORK_CONNECTION,),
}

# Sigma field -> callable extracting it from an Aegis event. Field names are
# matched case-insensitively, as Sigma rules in the wild are inconsistent.
_PROCESS_FIELDS = {
    "image": lambda e: e.exe or e.name,
    "commandline": lambda e: e.cmdline,
    "parentimage": lambda e: (e.raw or {}).get("parent_name", ""),
    "user": lambda e: e.username,
    "processid": lambda e: e.pid,
    "parentprocessid": lambda e: e.ppid,
    # Aegis has the process name but not a separate signed OriginalFileName;
    # exposing the name is closer to the rule's intent than supplying nothing.
    "originalfilename": lambda e: e.name,
}

_NETWORK_FIELDS = {
    "image": lambda e: e.process_name,
    "destinationip": lambda e: e.remote_ip,
    "destinationport": lambda e: e.remote_port,
    "sourceip": lambda e: e.local_ip,
    "sourceport": lambda e: e.local_port,
    "protocol": lambda e: e.protocol,
    "initiated": lambda e: e.direction == Direction.OUTBOUND,
    "destinationisipv6": lambda e: ":" in (e.remote_ip or ""),
    "processid": lambda e: e.pid,
}

# Fields Aegis genuinely cannot observe with psutil polling. Rules that depend
# on one of these are skipped by the loader with a recorded reason, rather than
# being loaded as a rule that can never match.
UNSUPPORTED_FIELDS: frozenset[str] = frozenset({
    "parentcommandline", "hashes", "md5", "sha1", "sha256", "imphash",
    "integritylevel", "logonid", "company", "product", "description",
    "signed", "signature", "signaturestatus", "currentdirectory",
    "parentuser", "grandparentimage", "targetfilename", "details",
})


def fields_for(event: Event) -> dict:
    """Return the Sigma-named fields extractable from ``event``."""
    if isinstance(event, ProcessEvent):
        extractors = _PROCESS_FIELDS
    elif isinstance(event, NetworkEvent):
        extractors = _NETWORK_FIELDS
    else:
        return {}
    return {name: fn(event) for name, fn in extractors.items()}


def supported_fields(category: str) -> frozenset[str]:
    """The Sigma field names Aegis can populate for a logsource category."""
    if category == "process_creation":
        return frozenset(_PROCESS_FIELDS)
    if category == "network_connection":
        return frozenset(_NETWORK_FIELDS)
    return frozenset()


def unsupported_fields(category: str, fields: set[str]) -> set[str]:
    """Which of ``fields`` this category cannot supply.

    A field is unsupported either because it is on the explicit deny list (Aegis
    has no way to observe it) or simply because no extractor exists for it in
    this category.
    """
    known = supported_fields(category)
    return {f for f in fields if f.lower() in UNSUPPORTED_FIELDS or f.lower() not in known}
