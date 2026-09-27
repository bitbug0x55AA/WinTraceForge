# Command reference

[User docs](README.md)

```text
wtf.exe <module> <command> [options]
```

The commands below are the currently implemented security-control / configuration experiments. Select a supported transport to vary the implementation path for the same operation, collect local evidence, and compare observations across runs. Command success and detection response remain separate results; WTF does not automate the comparison.

| Command | Purpose | Changes host state? |
| --- | --- | --- |
| `defender exclusion --check` | Read capabilities and requested AV exclusion values. | No |
| `defender exclusion` | Add requested AV exclusions. | Persistent policy change |
| `defender asr status` | Read rule actions, policy sources, and exclusion exposure. | No |
| `defender asr exclusion [--check]` | Check or add ASR-only global exclusions. | Persistent unless `--check` |
| `defender asr rule [--check]` | Read or set one rule's action. | Persistent unless `--check` |
| `defender asr verify [--check]` | Run or prepare an experimental behavioral test. | Test artifacts/processes unless `--check`; automatic cleanup attempted |
| `firewall profiles` | Read profile state and exposed policy settings. | No |
| `firewall rule add` | Add one marked test rule. | Persistent rule |
| `firewall rule check` | Inspect a uniquely owned test rule. | No |
| `firewall rule remove` | Remove one uniquely owned test rule. | Persistent rule removal |

## Shared options

Place module flags after the module and command, for example `wtf.exe defender exclusion --transport native --check`.

| Option | Values / default | Meaning |
| --- | --- | --- |
| `--transport` | `management`, `com`, `native` | Defender / ASR default to `management`; Firewall defaults to `com`. No automatic fallback. |
| `--telemetry` | `none` (default), `eventlog`, `etw` | Select local evidence collection. |
| `--telemetry-wait` | `0..30`; default `3` seconds | Allow time for events to publish after the operation. |
| `--verbose` | Flag | Expand evidence, guidance, and help notes. |
| `--no-color` | Flag | Plain text output. Also automatic when output is redirected. |

`NO_COLOR` and `TERM=dumb` are respected. Values containing spaces must be quoted. Retain stdout and stderr together when saving a report:

```powershell
.\wtf.exe firewall profiles --telemetry eventlog --no-color *> .\firewall-report.txt
```

## Find detailed help

```powershell
.\wtf.exe --help
.\wtf.exe defender exclusion --help
.\wtf.exe defender asr --help
.\wtf.exe firewall --help
.\wtf.exe firewall rule --help --verbose
```

Continue with [Defender exclusions](defender.md), [ASR](asr.md), or [Firewall](firewall.md). See [telemetry](telemetry.md) and [results and cleanup](results-and-cleanup.md) before interpreting a run.
