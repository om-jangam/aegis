"""Persistence layer.

Defines the :class:`~aegis.storage.base.EventStore` interface and its SQLite
implementation.
"""
from aegis.storage.base import EventStore
from aegis.storage.database import SQLiteEventStore

__all__ = ["EventStore", "SQLiteEventStore"]
