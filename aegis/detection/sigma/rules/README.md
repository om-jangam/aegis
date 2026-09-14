# Bundled Sigma rules

These rules ship with Aegis so `aegis sigma` does something useful the moment
it is installed, without cloning an external repository first.

They are deliberately a **small, curated set**, not a mirror of the community
ruleset. Every rule here:

- uses only telemetry Aegis actually collects (process image, command line,
  parent image, user, destination address/port) — see
  [`../mapping.py`](../mapping.py) for the full field list;
- maps to MITRE ATT&CK via its `tags`;
- documents its own false positives, which Aegis surfaces alongside the alert
  so a match can be triaged rather than just counted.

## Using the full community ruleset

Aegis can run the upstream [SigmaHQ](https://github.com/SigmaHQ/sigma) rules
directly:

```bash
git clone --depth 1 https://github.com/SigmaHQ/sigma /opt/sigma
aegis sigma stats /opt/sigma/rules
aegis monitor --sigma /opt/sigma/rules
```

`aegis sigma stats` reports how many rules loaded and, for the rest, exactly why
they were skipped. Most skips are logsource categories Aegis does not collect
(registry, image load, WMI) or fields psutil cannot supply (`ParentCommandLine`,
file hashes). That report is the honest measure of coverage — and of what a
higher-fidelity collector such as Sysmon or eBPF would unlock.

## Writing your own

Drop any `.yml` file with a `process_creation` or `network_connection` logsource
into a directory and point Aegis at it. Supported modifiers are listed in
`SUPPORTED_MODIFIERS` in [`../rule.py`](../rule.py); anything else is rejected at
load time with a reason rather than silently never matching.
