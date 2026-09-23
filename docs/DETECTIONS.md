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
| `NET-SCAN` | Possible network scanning / sweep | **T1046** | Discovery | HIGH | Within 60 s, one PID → ≥10 hosts on the same non-web port, or ≥15 ports on one host; ports 80/443 ignored; reported once per 10 min |
| `NET-LISTEN-SENSITIVE` | Listening on a sensitive port | **T1571** | Command & Control | MEDIUM | Bind/listen on a backdoor-associated port |
| `NET-UNCOMMON-PORT` | Uncommon port to a public host | **T1571** | Command & Control | LOW | Non-standard high port to public IP (weak signal) |
| `DNS-THREAT-INTEL` | Lookup of a known-malicious domain | **T1071.004** | Command & Control | CRITICAL | The name, or a parent of it, is on a threat feed |
| `DNS-INTEL-ANSWER` | A name resolved to a known-malicious address | **T1071** | Command & Control | HIGH | The answer is on an IP blocklist |
| `DNS-GENERATED-NAME` | Lookup of a machine-generated domain | **T1568.002** | Command & Control | MEDIUM | 12+ characters, high entropy, few vowels or mostly digits; CDN and cloud suffixes excluded |
| `DNS-TUNNEL` | Data may be leaving through DNS | **T1071.004** | Command & Control | HIGH | 25+ subdomains of one site in 10 min, or a label of 40+ characters |
| `AUTH-GUESSING` | Repeated failed sign-ins | **T1110** | Credential Access | HIGH | ≥6 refused sign-ins for one account or from one address within 5 min |
| `AUTH-SPRAY` | One password tried against many accounts | **T1110.003** | Credential Access | HIGH | ≥4 different accounts refused from one address in 15 min |
| `AUTH-GUESSED-PASSWORD` | Sign-in succeeded after repeated failures | **T1110** | Credential Access | CRITICAL | A success within 10 min of ≥4 failures for the same account or address |
| `AUTH-NEW-ACCOUNT` | New user account created | **T1136.001** | Persistence | MEDIUM | Windows 4720, or `useradd` in the auth log |
| `AUTH-ADMIN-GRANTED` | Account given administrator rights | **T1098** | Persistence | HIGH | Added to Administrators / sudo / wheel |
| `AUTH-LOCKOUT` | Account locked out | **T1110** | Credential Access | MEDIUM | Windows 4740 |
| `POSTURE-CHANGED` | Security setting changed for the worse | **T1562.001** | Defense Evasion | HIGH | A security check that passed now warns or fails |
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

DNS rules read the resolver cache (`Get-DnsClientCache`, or `resolvectl
show-cache` on Linux), which records the name and its answer but not which
program asked, and only while the answer's time-to-live lasts. A short-lived
lookup between two polls can therefore be missed, and macOS is not supported
at all. Sign-in rules read the platform's own record: the Windows Security log (which
needs administrator rights) or `/var/log/auth.log`, `/var/log/secure` or the
journal on Linux. Without those, Aegis says sign-in monitoring is unavailable
rather than reporting quiet. macOS is not supported: its unified log cannot be
polled cheaply. The other rules run on `psutil` socket/process polling. Techniques requiring
kernel/ETW/Sysmon telemetry — **process injection (T1055)**, in-memory execution,
registry-based **persistence (T1547)** — are out of scope until the Sysmon/ETW
collectors are added. This is stated plainly in [`THREAT_MODEL.md`](THREAT_MODEL.md).

## Adding a detection

Subclass `DetectionRule`, set the ATT&CK metadata, implement `evaluate()`, and add
it to `default_rules()`. Nothing else changes — the engine iterates rules
generically. See `aegis/detection/rules/`.
