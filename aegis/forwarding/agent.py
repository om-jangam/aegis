"""Agent identity included in every forwarded event."""
from __future__ import annotations

import logging
import os
import platform
import uuid
from dataclasses import dataclass
from pathlib import Path

from aegis import __version__
from aegis.platforms import CURRENT_OS, OS

log = logging.getLogger(__name__)

AGENT_ID_FILE = "agent_id"
_OS_NAMES = {OS.WINDOWS: "windows", OS.LINUX: "linux", OS.MACOS: "macos"}


@dataclass(frozen=True)
class AgentInfo:
    agent_id: str
    hostname: str
    os: str
    aegis_version: str

    def to_dict(self) -> dict:
        return {
            "agent_id": self.agent_id,
            "hostname": self.hostname,
            "os": self.os,
            "aegis_version": self.aegis_version,
        }


def load_or_create_agent_id(directory: Path | str) -> str:
    """The install's agent id: generated once, then read back on every start."""
    path = Path(directory) / AGENT_ID_FILE
    try:
        return str(uuid.UUID(path.read_text(encoding="utf-8").strip()))
    except FileNotFoundError:
        pass
    except (OSError, ValueError):
        log.warning("Agent id file %s is unreadable; generating a new id.", path)

    agent_id = str(uuid.uuid4())
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(path.name + ".tmp")
    tmp.write_text(agent_id, encoding="utf-8")
    os.replace(tmp, path)
    return agent_id


def current_agent(directory: Path | str) -> AgentInfo:
    return AgentInfo(
        agent_id=load_or_create_agent_id(directory),
        hostname=platform.node() or "unknown",
        os=_OS_NAMES.get(CURRENT_OS, "linux"),
        aegis_version=__version__,
    )
