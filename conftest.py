"""Test-wide setup that has to happen before ``aegis`` is imported.

Aegis decides where its data lives (database, logs, ML model, quarantine) when
``aegis.config`` is first imported. Without this, running the tests would write
into the real profile of whoever ran them: the developer's own alerts, logs and
settings. Pointing the data directory at a temporary folder first keeps a test
run from touching anything a person cares about.
"""
import os
import tempfile
from pathlib import Path

os.environ.setdefault("AEGIS_DATA_DIR", str(Path(tempfile.gettempdir()) / "aegis-test-data"))
