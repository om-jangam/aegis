"""Input validation for firewall rule fields.

The original project built `netsh` command strings with raw f-strings and ran
them through `shell=True`, which allowed command injection via a crafted rule
name (e.g. a name containing `" & del ...`). Aegis fixes this at two layers:

    1.  Every field is *validated* here before use.
    2.  The firewall engine passes arguments as a list (no shell), so even if a
        value contained shell metacharacters they are never interpreted.

This module is the first line of defence and is exhaustively unit-tested.
"""
from __future__ import annotations

import ipaddress
import re

# Characters that must never appear in a value forwarded to a subprocess call.
# Even though we do not use shell=True, we reject these defensively so a rule
# name can never smuggle a new netsh token or break argument parsing.
_FORBIDDEN = set('"|&;<>^%`$\n\r\t\0')

_NAME_RE = re.compile(r"^[\w\-. ()\[\]/:+#@]{1,255}$", re.UNICODE)
_PORT_TOKEN_RE = re.compile(r"^\d{1,5}(-\d{1,5})?$")


class ValidationError(ValueError):
    """Raised when a user-supplied firewall field fails validation."""


def _reject_forbidden(value: str, field: str) -> None:
    bad = _FORBIDDEN.intersection(value)
    if bad:
        raise ValidationError(
            f"{field} contains forbidden character(s): {''.join(sorted(bad))!r}"
        )


def validate_name(name: str) -> str:
    name = (name or "").strip()
    if not name:
        raise ValidationError("Rule name is required.")
    _reject_forbidden(name, "Rule name")
    if not _NAME_RE.match(name):
        raise ValidationError(
            "Rule name may only contain letters, numbers, spaces and - . ( ) [ ] / : + # @"
        )
    return name


def validate_ip(value: str, field: str = "IP address") -> str:
    """Accept 'any', a single IP, a CIDR range, or a start-end IP range."""
    value = (value or "").strip()
    if not value or value.lower() in ("any", "0.0.0.0", "*"):
        return "any"
    _reject_forbidden(value, field)

    # Range form:  192.168.0.1-192.168.0.50
    if "-" in value:
        start, _, end = value.partition("-")
        try:
            ipaddress.ip_address(start.strip())
            ipaddress.ip_address(end.strip())
        except ValueError as exc:
            raise ValidationError(f"Invalid {field} range: {value}") from exc
        return f"{start.strip()}-{end.strip()}"

    # CIDR or single address.
    try:
        if "/" in value:
            ipaddress.ip_network(value, strict=False)
        else:
            ipaddress.ip_address(value)
    except ValueError as exc:
        raise ValidationError(f"Invalid {field}: {value}") from exc
    return value


def validate_port(value: str, field: str = "Port") -> str:
    """Accept 'any', a single port, a range 'a-b', or a comma list '80,443'."""
    value = (value or "").strip()
    if not value or value.lower() in ("any", "*"):
        return "any"
    _reject_forbidden(value, field)

    tokens = [t.strip() for t in value.split(",") if t.strip()]
    if not tokens:
        return "any"
    for token in tokens:
        if not _PORT_TOKEN_RE.match(token):
            raise ValidationError(f"Invalid {field}: {token!r}")
        for part in token.split("-"):
            if not (0 <= int(part) <= 65535):
                raise ValidationError(f"{field} out of range (0-65535): {part}")
    return ",".join(tokens)


def validate_path(value: str, field: str = "Program path") -> str:
    """Program/service path is optional; reject shell metacharacters if given."""
    value = (value or "").strip().strip('"')
    if not value:
        return ""
    # Paths legitimately contain characters like ':' and '\'; only block the
    # dangerous shell/redirection set.
    bad = set('|&;<>^`$\n\r\0').intersection(value)
    if bad:
        raise ValidationError(f"{field} contains forbidden character(s).")
    return value
