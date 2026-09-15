"""Shared port constants used by detection rules and the ML feature function.

Kept in one place so the rule engine and the anomaly model agree on what
"common" vs "suspicious" ports are (single source of truth).
"""
from __future__ import annotations

# Ordinary client traffic — never suspicious on its own.
COMMON_PORTS: frozenset[int] = frozenset(
    # 5223 / 5228: Apple and Google push-notification services.
    {80, 443, 53, 123, 22, 993, 995, 587, 465, 3478, 5223, 5228, 8080, 8443}
)

# Common default ports for C2 frameworks / backdoors.
C2_PORTS: frozenset[int] = frozenset(
    {4444, 5555, 6666, 6667, 1337, 31337, 9001, 9002, 12345, 54321}
)

# Remote-administration / lateral-movement services.
REMOTE_ADMIN_PORTS: dict[int, str] = {
    3389: "RDP", 445: "SMB", 5985: "WinRM", 5986: "WinRM-S", 135: "RPC",
}

# Legacy plaintext protocols.
LEGACY_PORTS: dict[int, str] = {
    23: "Telnet", 21: "FTP", 25: "SMTP", 110: "POP3", 143: "IMAP", 512: "rexec",
}
