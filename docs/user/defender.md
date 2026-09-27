# Defender Antivirus exclusions

[User docs](README.md) | [Shared command options](commands.md)

## Inspect first

```powershell
.\wtf.exe defender exclusion --check -ExclusionPath "C:\Lab Data"
.\wtf.exe defender exclusion --transport native --check -ExclusionPath "C:\Lab Data"
```

`--check` validates metadata, prepares the request, and reads a baseline for specified values without writing or requiring elevation. A bare `--check` can inspect capabilities without requesting an exclusion. Defender can hide exclusion content from a non-administrator; an unreadable list is not an empty list. Re-run elevated when you need to observe that content.

Older exclusion commands must now include the `defender exclusion` prefix.

## Select a path and exclusion type

| Transport | Execution path |
| --- | --- |
| `management` (default) | Managed WMI |
| `com` | COM Automation to WMI |
| `native` | Native C++ WMI through the matching DLL |

All target the same Defender preference interface, with no fallback. Supported types are `-ExclusionPath`, `-ExclusionExtension`, `-ExclusionProcess`, and `-ExclusionIpAddress` (subject to provider support).

Pass values as separate arguments, not PowerShell comma-separated arrays. Names are case-insensitive and repeated types are supported. Use `-ExclusionTYPE=VALUE` for a value beginning with a dash. No implicit default exclusion is added.

## Add an authorized test exclusion

From an elevated PowerShell session:

```powershell
.\wtf.exe defender exclusion -ExclusionPath "C:\Lab Data" --telemetry eventlog
```

The command preserves existing exclusions and reads every requested value back. A known nonzero API return remains a failure; a missing return code is reported as ambiguous rather than silently treated as success. Values already present are not new changes. Batch changes are not transactional, so a failed operation may still have changed part of the request.

## Restore

Exclusions persist and are not cleaned up automatically. Record the baseline and remove only values introduced by this test through your approved administration channel. For example, if the path below was absent before the test, an elevated cleanup command is:

```powershell
Remove-MpPreference -ExclusionPath "C:\Lab Data"
.\wtf.exe defender exclusion --check -ExclusionPath "C:\Lab Data"
```

An absent test value on a post-cleanup check is expected; inspect the result rather than assuming every nonzero exit is a cleanup failure. Preserve pre-existing or organizational exclusions. See [results and cleanup](results-and-cleanup.md) for evidence retention and interpretation.
