# Changelog

All notable changes to Aegis are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/), and the project aims to follow
[Semantic Versioning](https://semver.org/).

## [Unreleased]

### Planned
- Sysmon / ETW collectors for kernel-grade telemetry (short-lived connections,
  in-memory techniques).
- Signed / integrity-checked ML model format to remove the `joblib` pickle
  residual risk.
- Locale-independent firewall management via the Windows COM API (`INetFwPolicy2`).
- UI test coverage; screenshots and a demo GIF in the README.

## [1.0.0] - 2026-07-26

First complete release: a modular host firewall + intrusion-detection system.

### Added
- **Collectors**: psutil network + process telemetry, normalized into a typed
  `Event` stream.
- **Detection engine**: 8 explainable, MITRE ATT&CK-mapped rules (T1571, T1021,
  T1071, T1059, T1046, T1036) plus a thread-safe rolling context.
- **ML anomaly assist**: IsolationForest with a reproducible evaluation harness
  (`evaluation/evaluate_ml.py`, `docs/ML_EVALUATION.md`).
- **Secure firewall engine**: `netsh` via argument lists with `shell=False` and
  full input validation; create/delete/toggle rules and block/contain IPs.
- **Storage**: SQLite `EventStore` (WAL, thread-safe) for events, findings,
  alerts and an append-only audit trail; retention purge for high-volume telemetry.
- **Alerting**: Windows toast notifications with cooldown de-duplication.
- **UI**: Flet security console with 7 views (Dashboard, Connections, Processes,
  Detections, Firewall Rules, Audit Log, Settings).
- **Docs**: threat model, architecture, detection catalog, ML evaluation.
- **Quality**: 120+ tests (injection, concurrency, integration), Ruff lint, CI.

### Security
- Eliminated the original project's command-injection vulnerability
  (`shell=True` + string-built `netsh` commands); regression-tested.
