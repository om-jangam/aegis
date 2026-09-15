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
- DNS telemetry, so threat intel can match malicious domains as well as IPs.

### Added
- Desktop console **Security Check** page: posture score, every check with its
  fix, threat-intel status and a one-click "Update blocklists" button. Checks
  and downloads run in the background so the window stays responsive.
- Settings switch to turn threat-intelligence matching on or off.
- Posture check **OS updates** (`POSTURE-UPDATES`): days since the last Windows
  update (warn after 35, fail after 60); pending security updates and required
  restarts on Linux via the local apt / dnf cache, with no network access.
- Posture check **startup programs** (`POSTURE-STARTUP`): flags Windows Run /
  RunOnce entries and Linux cron jobs that launch from temp or download folders,
  run encoded or hidden PowerShell, pull code through system tools, pipe
  `curl` into a shell, or open a reverse shell.

- **Windows installer**: `packaging\build_windows.ps1` freezes the desktop app
  with PyInstaller and builds a per-user Inno Setup installer (no administrator
  rights, Start-menu and optional desktop shortcut). CI publishes it as the
  `aegis-windows-installer` artifact.
- **Welcome guide** on first start, explaining where to begin in three steps.
- **Trusted programs**: an alert can trust the program that caused it (for example
  a developer tool that runs encoded PowerShell). Trusted programs, and programs
  they start, raise no alerts; findings are still recorded, and Settings lists
  them for removal. Interpreters and core system processes can never be trusted.
- Process alerts name the parent program ("powershell.exe, started by
  claude.exe") instead of a bare parent process id; alerts store the program
  and parent names (existing databases are upgraded automatically).
- **Home page** answers "is my computer safe?" in one sentence ("Your computer
  is protected" / "3 things need your attention") with a button for the next
  step, clickable tiles, severity and 24-hour charts, the programs using the
  internet most, and the latest alerts.

### Changed
- **Plain language throughout the desktop app.** Pages are renamed (Home,
  Alerts, Network Activity, Running Programs, Firewall, Activity History), every
  alert shows "What should I do?", times read "5 minutes ago", connection states
  and settings are described in everyday words, and technical references
  (ATT&CK ids, process ids) move to small print or tooltips.
- Firewall page shows a clear "view only, run as administrator" notice and
  disables changes without administrator rights; blocking an address from
  Network Activity asks for confirmation; "Mark all as reviewed" confirms first.
- Console live-refresh now selects views by type instead of sidebar position,
  so adding pages no longer breaks which views refresh.
- **Alert floods:** the same rule on the same subject now raises at most one
  alert per `alert_dedup_minutes` (default 10). Repeats are still recorded as
  findings, so no evidence is lost.

### Fixed
- `NET-SCAN` fired on ordinary web browsing (153 false alerts from Brave and
  Chrome in real use) and re-fired on every later connection. It now requires,
  within 60 seconds, 10+ hosts on the same non-web port or 15+ ports on one
  host, ignores ports 80/443, and reports each scan once per 10 minutes.
- Windows kernel processes without an image file (`Registry`,
  `MemCompression`, `System`...) are no longer flagged as having a
  non-absolute executable path.
- Push-notification ports 5223 (Apple) and 5228 (Google) no longer count as
  uncommon ports.

## [1.1.0] - 2026-09-14

Aegis becomes useful to people who are not security analysts: it now tells you
how exposed your machine is and how to fix it, recognises known-malicious
infrastructure, and runs in any browser.

### Added
- **`aegis check`**: read-only security posture audit with a 0-100 score, a
  letter grade and a plain-language fix for every problem. Checks the host
  firewall, network-exposed risky services (Redis, MongoDB, Telnet, RDP...),
  Microsoft Defender, UAC, Remote Desktop and NLA, SMBv1, auto-logon with a
  stored password, disk encryption (BitLocker / FileVault / LUKS), SSH server
  hardening and permissions on account files. `--json` and `--fail-on LEVEL`
  make it usable in scripts and CI.
- **Threat intelligence**: `NET-THREAT-INTEL` flags connections to listed IPs
  and CIDR ranges (critical severity, auto-containment capable) even on normal
  ports. `aegis intel update` downloads abuse.ch Feodo Tracker, Emerging Threats
  and Spamhaus DROP over HTTPS; `aegis intel lookup` / `status` query them; any
  plain-text IP list dropped into the intel folder is picked up live.
- **`aegis serve`**: local web dashboard and JSON API (security score, alerts
  with acknowledge, findings, top techniques and talkers, audit trail).
  Loopback by default, bearer token in the URL fragment, Host-header allow-list
  against DNS rebinding, strict CSP; `--monitor` runs live detection alongside.
- **`aegis report`**: self-contained HTML report with a prioritised
  "what to do first" list, suitable for emailing or printing.
- **Guidance**: every ATT&CK technique Aegis detects is paired with a short,
  non-expert explanation of what to do next (dashboard and report).
- Cross-platform response (nftables on Linux, pf on macOS), collectors and
  alerting; headless CLI (`monitor`, `status`, `rules`, `block`, `sigma`);
  Sigma rule engine with bundled rules; file integrity monitoring.

### Security
- Intel feeds are validated line by line; private, reserved and over-broad
  ranges (wider than /8 or IPv6 /32) are rejected so a bad feed line cannot
  flag every connection. A failed or empty download keeps the previous copy.
- `aegis intel update` is the only command that makes network requests, and it
  runs only when invoked.

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
