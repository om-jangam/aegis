"""Hardening: safely fix weaknesses the security check finds (``aegis harden``)."""
from aegis.hardening.base import Change, Fix, HardeningContext, HardeningError
from aegis.hardening.engine import HardeningEngine, HardeningResult, Outcome, Recommendation
from aegis.hardening.fixes import default_fixes

__all__ = [
    "Change",
    "Fix",
    "HardeningContext",
    "HardeningEngine",
    "HardeningError",
    "HardeningResult",
    "Outcome",
    "Recommendation",
    "default_fixes",
]
