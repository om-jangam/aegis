"""Detection engine.

Consumes normalized events and produces explainable, MITRE ATT&CK-mapped
:class:`~aegis.core.models.Finding` objects. Rules lead; a machine-learning
anomaly model acts as a clearly-scoped, evaluated *assist*.
"""
from aegis.detection.base import DetectionContext, DetectionRule
from aegis.detection.engine import DetectionEngine

__all__ = ["DetectionRule", "DetectionContext", "DetectionEngine"]
