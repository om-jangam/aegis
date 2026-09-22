"""Shared test setup."""
import pytest

from aegis.config import Settings, settings


@pytest.fixture(autouse=True)
def default_settings(monkeypatch):
    """Run every test with default settings, not the developer's saved preferences."""
    defaults = Settings()
    for name in Settings.__dataclass_fields__:
        monkeypatch.setattr(settings, name, getattr(defaults, name))
    monkeypatch.setattr(Settings, "save", lambda self: None)
