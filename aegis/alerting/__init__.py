"""Alerting: turn high-severity findings into desktop notifications, with
per-key cooldown de-duplication.
"""
from aegis.alerting.notifier import Notifier

__all__ = ["Notifier"]
