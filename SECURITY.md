# Security Policy

Aegis is a defensive security tool, so its own security is taken seriously.

## Reporting a vulnerability

Please **do not** open a public issue for security vulnerabilities. Instead,
report privately via GitHub's **"Report a vulnerability"** (Security → Advisories)
or email the maintainer listed in `pyproject.toml`.

Include: affected version, a description, reproduction steps, and impact. You can
expect an acknowledgement within a few days and a fix or mitigation timeline after
triage.

## Scope & threat model

Aegis' security scope, assets, adversaries, and **explicit limitations** are
documented in [`docs/THREAT_MODEL.md`](docs/THREAT_MODEL.md). In summary:

- The firewall engine executes `netsh` with **argument lists and `shell=False`**;
  all rule input is validated first (see `aegis/core/validators.py`). Command
  injection is regression-tested.
- Aegis performs **no network egress** — telemetry stays on the host.
- Read-only monitoring runs unprivileged; only rule mutation needs Administrator.

## Known residual risks

- **ML model deserialization:** the anomaly model is persisted with
  `joblib`/pickle under `%LOCALAPPDATA%\Aegis`. A local attacker who can write that
  file could achieve code execution on load. Mitigations: per-user directory,
  guarded load, and the ML assist can be disabled in Settings. A signed/integrity-
  checked model format is planned (see CHANGELOG "Unreleased").
- **`netsh` text parsing is English-locale oriented;** a locale-independent COM
  (`INetFwPolicy2`) path is planned.

## Supported versions

The latest released version receives security fixes.
