"""Layering rules: the endpoint engine never depends on its front ends or on export.

Aegis must work fully on its own. Detection, the security check, collectors,
response and storage may not import the UI, the dashboard, the CLI, the service
orchestrator or the optional SENTINEL-X export.
"""
import ast
from pathlib import Path

import pytest

PACKAGE = Path(__file__).resolve().parent.parent / "aegis"

ENGINE = ["core", "collectors", "detection", "posture", "hardening", "response", "storage",
          "alerting", "intel"]
FRONT_ENDS = ("aegis.ui", "aegis.api", "aegis.cli", "aegis.service", "aegis.forwarding")


def _imports(path: Path) -> set[str]:
    names: set[str] = set()
    for node in ast.walk(ast.parse(path.read_text(encoding="utf-8"))):
        if isinstance(node, ast.Import):
            names.update(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module and node.level == 0:
            names.add(node.module)
    return names


def _violations(files, forbidden) -> list[str]:
    return [f"{path.relative_to(PACKAGE.parent)} imports {name}"
            for path in files for name in sorted(_imports(path))
            if any(name == f or name.startswith(f + ".") for f in forbidden)]


@pytest.mark.parametrize("layer", ENGINE)
def test_engine_layers_do_not_import_front_ends_or_export(layer):
    assert _violations((PACKAGE / layer).rglob("*.py"), FRONT_ENDS) == []


def test_export_depends_only_on_the_engine():
    forbidden = ("aegis.ui", "aegis.api", "aegis.cli", "aegis.service")
    assert _violations((PACKAGE / "forwarding").rglob("*.py"), forbidden) == []


def test_service_does_not_import_front_ends():
    assert _violations([PACKAGE / "service.py"], ("aegis.ui", "aegis.api", "aegis.cli")) == []
