# Defender Antivirus exclusions

[User docs](README.md) | [Shared command options](commands.md)

```text
wtf.exe defender exclusion <command> [options] [-ExclusionTYPE VALUE [VALUE ...]]
```

| Command | Needs values? | Changes host state? | What it does |
| --- | --- | --- | --- |
| `check` | Optional | No | With values: reads the lists and reports whether each value is present. Without values: capability check only. |
| `list` | No | No | Shows every readable exclusion, per type. |
| `add` | Yes | Persistent | Adds the values you name; reads each one back. |
| `remove` | Yes (type **and** value) | Persistent | Removes only the values you name; reads each one back. There is no remove-all mode. |

The command word comes first, and a command word written after a value (`add -ExclusionPath C:\Lab remove`, or in the older syntax `-ExclusionPath C:\Lab remove`) is rejected rather than taken as a value; for a value that really is a command word, use `-ExclusionTYPE=VALUE`. The four exclusion types keep their existing parameters: `-ExclusionPath`, `-ExclusionExtension`, `-ExclusionProcess` and `-ExclusionIpAddress` (subject to provider support). Pass values as separate arguments, not PowerShell comma-separated arrays. Names are case-insensitive and repeated types are supported. Use `-ExclusionTYPE=VALUE` for a value beginning with a dash. No implicit default exclusion is added.

## Select a path

| Transport | Execution path |
| --- | --- |
| `management` (default) | Managed WMI |
| `com` | COM Automation to WMI |
| `native` | Native C++ WMI through the matching DLL |
| `powershell` | Shells to `powershell.exe` and drives `Add-MpPreference`/`Remove-MpPreference`/`Get-MpPreference` |

Every command uses the transport you select, for every exclusion type, with no fallback: if the selected path fails, the command fails rather than switching to another.

`powershell` invokes System32's own `powershell.exe` directly (not a `PATH` lookup, and with its module search path restricted to the system module directory) and requires the `ConfigDefender` module. `Add-MpPreference` and `Remove-MpPreference` are void cmdlets with no WMI return code to report, so this transport always confirms a write through readback rather than a status code. It also launches its own `powershell.exe` process (once to connect, once per readback, and for `add`/`remove` once per write; `remove` sends one request per value), which is itself something a detection stack can observe (AMSI, script-block logging, the process image and command line) that the other three transports never produce -- differing telemetry between `powershell` and the others is evidence about this process-launch path, not about `MSFT_MpPreference` itself. A value containing an unpaired UTF-16 surrogate is rejected when parsed, before any transport runs; this is exceedingly unlikely to occur from ordinary path input.

## Inspect first

```powershell
.\wtf.exe defender exclusion check -ExclusionPath "C:\Lab Data"
.\wtf.exe defender exclusion check --transport native -ExclusionPath "C:\Lab Data"
.\wtf.exe defender exclusion list
.\wtf.exe defender exclusion check
```

`check` and `list` are read-only and do not require elevation. A bare `check` reports which exclusion types the provider's `Add` interface accepts (`supported (string[])`), without reading any list; use `list` to see what can actually be read. `check` with values validates metadata, prepares the request, and reads a baseline for those values; it does not validate provider acceptance, write permission, or prevention policy.

### What `list` and `check` can say

For each type, `list` reports exactly one of:

| Status | Meaning |
| --- | --- |
| *N entries* | The list was read; the entries follow (sorted, so output is comparable across transports). |
| `EMPTY` | The list was read and contains nothing. |
| `UNSUPPORTED` | The type is not a readable field of the provider's preference object. This is decided from the read surface, not from `add`/`remove` metadata, so a type that only `add` omits is still listed. |
| `UNREADABLE` | Defender answered but withheld the contents from the current identity (typically a non-administrator, or a policy that hides exclusions). |

An unreadable list is **never** reported as empty, and a value is **never** reported as absent because its list could not be read. `check` over an unreadable type reports each requested value as `unknown - list unreadable`. Because the answer is incomplete, `list` and `check` exit `3` in that case (`LIST_INCOMPLETE` / `CHECK_INCOMPLETE`); re-run elevated to observe the contents. A read that fails outright is an error (exit `1`, `LIST_FAILED` / `CHECK_FAILED`), not an empty list. That includes a provider that returns no `MSFT_MpPreference` instance, or more than one: the lists are unobserved or ambiguous, so they are never shown as empty or merged. If no type is readable at all, `list` is incomplete (exit `3`), not complete.

## Add an authorized test exclusion

From an elevated PowerShell session:

```powershell
.\wtf.exe defender exclusion add -ExclusionPath "C:\Lab Data" --telemetry eventlog
```

The command preserves existing exclusions and reads every requested value back. A known nonzero API return remains a failure; a missing return code is reported as ambiguous rather than silently treated as success. Values already present are not new changes. If the list cannot be read after the write, the add is reported as unconfirmed. Batch changes are not transactional, so a failed operation may still have changed part of the request.

## Remove named values

From an elevated PowerShell session:

```powershell
.\wtf.exe defender exclusion remove -ExclusionPath "C:\Lab Data"
.\wtf.exe defender exclusion remove -ExclusionPath "C:\Lab Data" "C:\Lab Logs" -ExclusionExtension .lablog
```

`remove` acts only on the type and value you give it; it cannot remove everything and it never widens a request.

1. **Baseline first.** The lists are read before anything is sent. A value that is already absent is reported `ALREADY_ABSENT` and is not sent to Defender. If every value is already absent, nothing is invoked and the command exits `0` (`ALREADY_ABSENT`).
2. **Unreadable list: refusal.** If a requested type's list cannot be read, presence cannot be established, so the whole command is refused (exit `1`, `NOT_ATTEMPTED`) before any removal, even for the types that could be read. A type that is not a readable field, or that the `Remove` method does not accept, is refused the same way (the `Add` interface's support is not consulted).
3. **One request per value.** Each present value is sent as its own request, using the spelling Defender has stored (a case or trailing-backslash difference from your request does not matter), so a rejection or error is attributed to exactly that value and the rest of the batch still runs.
4. **Readback per value.** Afterwards the lists are read again and every value gets its own result:

| Result | Meaning |
| --- | --- |
| `REMOVED_CONFIRMED` | The request returned without error and the value is no longer observed in readback. |
| `NOT_CONFIRMED` | The request returned, but the value is still present (or the readback could not confirm it). |
| `ERROR` | The request was rejected or failed; the detail says why and whether the value is still observed. |
| `ALREADY_ABSENT` | The value was not in the baseline; no request was sent. |

If a batch partly succeeds, each value's result is listed individually (outcome `PARTIAL_REMOVAL`, exit `1`). **There is no automatic rollback**: values that were removed stay removed. Exit `0` means every value sent was confirmed removed (`REMOVAL_CONFIRMED`) or was already absent; `3` means at least one removal is unconfirmed (`REMOVAL_UNCONFIRMED`, or `PARTIAL_REMOVAL_UNCONFIRMED` when at least one value was confirmed removed).

Exclusions carry no WTF ownership marker, so `remove` never claims that a value was created by WTF and does not limit itself to values WTF added. It removes what you name, including organizational or pre-existing entries, if you name them. Review the baseline it prints before relying on the result.

## Older syntax

During a migration period the previous forms still work, and print a warning naming the replacement:

| Previous | Use instead |
| --- | --- |
| `defender exclusion -ExclusionPath "C:\Lab Data"` (implicit add) | `defender exclusion add -ExclusionPath "C:\Lab Data"` |
| `defender exclusion --check [values]` | `defender exclusion check [values]` |

`--check` cannot be combined with a command word. These forms will be removed in a future release.

## Restore

Exclusions persist and are not cleaned up automatically. Record the baseline (`list`) before a test and remove only values introduced by this test. For example, if the path below was absent before the test, an elevated cleanup is:

```powershell
.\wtf.exe defender exclusion remove -ExclusionPath "C:\Lab Data"
.\wtf.exe defender exclusion check -ExclusionPath "C:\Lab Data"
```

`remove` reports `REMOVED_CONFIRMED` when readback no longer shows the value; the follow-up `check` is an independent confirmation, and an absent test value there is expected. If a value was removed in error, `remove` prints a re-add command (`defender exclusion add ...`). Preserve pre-existing or organizational exclusions. See [results and cleanup](results-and-cleanup.md) for evidence retention and interpretation.
