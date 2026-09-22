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
- Telemetry, findings and reports **stay on the host by default**. Outbound
  requests happen only when a user asks for them:
  - `aegis intel update` fetches fixed HTTPS feed URLs with a size cap and
    validates every line;
  - forwarding to SENTINEL-X (off by default) sends shared-schema events over
    HTTPS with a bearer token, never follows redirects, redacts secrets from
    command lines, and never sends API keys, the dashboard token or file
    contents.
- Read-only monitoring, `aegis check` and the dashboard run unprivileged; only
  firewall mutation needs Administrator / root.
- The web dashboard (`aegis serve`) binds to loopback by default, requires a
  per-run random bearer token, rejects unexpected `Host` headers (DNS
  rebinding), and sends a strict Content-Security-Policy.

## Known residual risks

- **ML model deserialization:** the anomaly model is persisted with
  `joblib`/pickle under `%LOCALAPPDATA%\Aegis`. A local attacker who can write that
  file could achieve code execution on load. Mitigations: per-user directory,
  guarded load, and the ML assist can be disabled in Settings. A signed/integrity-
  checked model format is planned (see CHANGELOG "Unreleased").
- **`netsh` text parsing is English-locale oriented;** a locale-independent COM
  (`INetFwPolicy2`) path is planned. The posture firewall check reports "skipped"
  rather than a false verdict when it cannot parse localized output.
- **Dashboard over plain HTTP:** the token protects against other users and web
  pages, not against someone who can read the loopback traffic or the terminal
  where the link is printed. Binding `--host` to a network address exposes the
  token to the network; use SSH port forwarding instead.
- **Threat-intel trust:** feed publishers decide what is flagged. With
  `--auto-respond`, a wrong entry could block a legitimate host; add it to
  `trusted_remote_ips` to override.

## Supported versions

The latest released version receives security fixes.
