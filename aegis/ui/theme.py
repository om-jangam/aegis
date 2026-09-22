"""Design tokens for a professional dark "security console" look."""
from __future__ import annotations

from aegis.core.models import Severity

BG = "#020409"
# Panels are tinted glass, so the space backdrop shows through them.
SURFACE = "#131c2e,0.88"
SURFACE_ALT = "#1b2740,0.9"
BORDER = "#243350"
PRIMARY = "#22d3ee"
ACCENT = "#38bdf8"
TEXT = "#e5edff"
TEXT_MUTED = "#8ea3c7"

OK = "#22c55e"
WARN = "#f59e0b"
DANGER = "#ef4444"
CRIT = "#dc2626"
INFO = "#38bdf8"

SEVERITY_COLOR = {
    Severity.INFO: INFO,
    Severity.LOW: OK,
    Severity.MEDIUM: WARN,
    Severity.HIGH: DANGER,
    Severity.CRITICAL: CRIT,
}


def severity_color(name: str) -> str:
    return {"INFO": INFO, "LOW": OK, "MEDIUM": WARN, "HIGH": DANGER, "CRITICAL": CRIT}.get(
        name, INFO)
