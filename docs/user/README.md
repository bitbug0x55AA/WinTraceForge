# User docs

These guides are for operators investigating path-dependent Windows security visibility: the same operation or equivalent outcome, different implementation paths, and their observable evidence. Today's supported experiments center on Defender Antivirus, ASR, and Windows Firewall controls/configuration; comparisons across runs and with EDR/SIEM evidence are operator-led.

| Guide | Use it to |
| --- | --- |
| [Installation](installation.md) | Check requirements, verify a download, and prepare the binaries. |
| [Commands](commands.md) | Learn shared options and find a command by control family. |
| [Defender Antivirus exclusions](defender.md) | Check or add AV exclusions and preserve existing values during cleanup. |
| [Attack Surface Reduction](asr.md) | Inspect posture, change one rule or exclusion, and understand experimental verification. |
| [Windows Firewall](firewall.md) | Inspect profiles and manage narrowly scoped, marked test rules. |
| [Telemetry](telemetry.md) | Collect Event Log / ETW evidence and understand correlation and capture limits. |
| [Results and cleanup](results-and-cleanup.md) | Interpret exit codes, retain evidence, and restore test changes. |

Start with installation and read-only checks. Before making a change, read the relevant control guide and agree on a cleanup plan. Readback, enforcement, telemetry delivery, and EDR/SIEM alerting are separate observations.

[All documentation](../README.md) | [Repository overview](../../README.md)
