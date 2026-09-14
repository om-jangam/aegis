# Aegis — Detection Catalog (MITRE ATT&CK)

Every detection is a small, independently-tested rule that emits an **explainable
`Finding`** carrying its ATT&CK technique, a numeric score, and human-readable
reasons. Rules are the **primary** detection layer; the ML anomaly assist is
secondary (see [`ML_EVALUATION.md`](ML_EVALUATION.md)).

## Rule catalog

| Rule ID | Title | ATT&CK | Tactic | Severity | Signal |
|---------|-------|:------:|--------|:--------:|--------|
| `NET-C2-PORT` | Connection to a known C2 / backdoor port | **T1571** | Command & Control | HIGH | Outbound to 4444, 5555, 31337, 1337, 9001… |
| `NET-REMOTE-SVC` | Remote administration service connection | **T1021** | Lateral Movement | MED–HIGH | RDP (3389), SMB (445), WinRM (5985/6) |
| `NET-LEGACY-PROTO` | Legacy / plaintext protocol to a public host | **T1071** | Command & Control | MEDIUM | Telnet, FTP, SMTP, POP3, IMAP to public IP |
| `NET-INTERPRETER` | Script interpreter making a network connection | **T1059** | Execution | HIGH | powershell/cmd/wscript/mshta/rundll32 → net |
| `NET-SCAN` | Possible network scanning / sweep | **T1046** | Discovery | HIGH | One PID → many distinct hosts (context window) |
| `NET-LISTEN-SENSITIVE` | Listening on a sensitive port | **T1571** | Command & Control | MEDIUM | Bind/listen on a backdoor-associated port |
| `NET-UNCOMMON-PORT` | Uncommon port to a public host | **T1571** | Command & Control | LOW | Non-standard high port to public IP (weak signal) |
| `PROC-SUSPICIOUS-PATH` | Process from a suspicious location | **T1036** | Defense Evasion | MEDIUM | Temp/Downloads exec, non-absolute path, name spoof |
| `ML-ANOMALY` | Anomalous connection (ML assist) | — | (assist) | LOW–MED | IsolationForest outlier vs learned baseline |

## Design principles

- **Explainable:** a rule never fires without recording *why* (its `reasons`).
- **False-positive discipline:** trusted/loopback/private peers are excluded where
  the technique implies internet egress; each rule is tested to stay silent on
  benign traffic.
- **Scored & thresholded:** findings carry a 0–100 score; alerts are raised at/above
  the configurable threshold (default 70, or any HIGH+ finding).
- **Honest ML:** the anomaly assist makes **no ATT&CK claim** (technique is blank)
  and is capped at MEDIUM so it can't override a real rule.

## Telemetry limits (what these rules cannot see)

These rules run on `psutil` socket/process polling. Techniques requiring
kernel/ETW/Sysmon telemetry — **process injection (T1055)**, in-memory execution,
registry-based **persistence (T1547)** — are out of scope until the Sysmon/ETW
collectors are added. This is stated plainly in [`THREAT_MODEL.md`](THREAT_MODEL.md).

## Adding a detection

Subclass `DetectionRule`, set the ATT&CK metadata, implement `evaluate()`, and add
it to `default_rules()`. Nothing else changes — the engine iterates rules
generically. See `aegis/detection/rules/`.
