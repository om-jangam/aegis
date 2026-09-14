# Contributing to Aegis

Thanks for your interest! Aegis is a modular host-security tool; contributions of
detection rules, collectors, and fixes are welcome.

## Development setup

```bash
python -m venv .venv
.venv\Scripts\activate        # Windows
pip install -e ".[dev]"        # installs the package + pytest, ruff
```

## Before you push

```bash
ruff check aegis tests evaluation      # lint (must be clean)
pytest --cov=aegis                     # tests (must pass)
```

CI runs the same checks on Windows for Python 3.11 and 3.12.

## Adding a detection rule

Detection is "detection-as-code": each rule is a small, tested, MITRE ATT&CK-mapped
unit.

1. Subclass `DetectionRule` in `aegis/detection/rules/` and set `rule_id`, `title`,
   `severity`, `technique`, `tactic`, `description`, and `event_types`.
2. Implement `evaluate(event, context) -> Finding | None` using `self.make_finding(...)`.
3. Register it in `aegis/detection/rules/__init__.py::default_rules()`.
4. Add a test that (a) fires on the malicious case and (b) stays silent on benign
   traffic — false-positive discipline is required.

See `docs/DETECTIONS.md` and existing rules for the pattern.

## Adding a collector

Subclass `Collector` (`aegis/collectors/base.py`), implement `poll()` returning
normalized `Event`s and `available()`. The engine depends only on the `Event`
contract, so nothing downstream changes.

## Coding standards

- Python 3.11+, type hints, `from __future__ import annotations`.
- Ruff-clean (config in `pyproject.toml`); 100-col soft limit.
- No `shell=True`; validate all external input; catch specific exceptions.
- Keep functions small and documented; add tests for new behavior.

## Commit / PR

- Small, focused PRs with a clear description and passing CI.
- Note any security-relevant change explicitly.
