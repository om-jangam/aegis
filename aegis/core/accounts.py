"""Account facts shared by the collectors that read sign-in records and the rules
that judge them: which groups hand out administrator rights.
"""
from __future__ import annotations

#: Linux/macOS groups whose members can act as administrator.
POSIX_ADMIN_GROUPS = ("sudo", "wheel", "admin", "root", "adm")
#: Windows groups that grant administrator-level or remote access (English
#: names; a group under another name is still reported, just without the
#: "administrator" wording).
WINDOWS_ADMIN_GROUPS = ("administrators", "domain admins", "enterprise admins",
                        "remote desktop users", "backup operators")


def is_admin_group(name: str) -> bool:
    """True when membership of ``name`` grants administrator-level rights."""
    lowered = (name or "").strip().lower()
    return lowered in POSIX_ADMIN_GROUPS or lowered in WINDOWS_ADMIN_GROUPS
