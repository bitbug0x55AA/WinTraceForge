# Attack Surface Reduction (ASR)

[User docs](README.md) | [Shared command options](commands.md)

ASR commands support `--transport management|com|native|powershell`, defaulting to `management`. Each route targets the same Defender preference class with no fallback. `powershell` invokes System32's own `powershell.exe` directly (its module search path restricted to the system module directory) and drives the `ConfigDefender` module's `Add-MpPreference`/`Get-MpPreference` cmdlets; it always confirms a write through readback since `Add-MpPreference` has no WMI return code to report. It also launches its own `powershell.exe` process, which a detection stack can observe in ways the other three transports never produce -- a telemetry difference between `powershell` and the others is evidence about this process-launch path, not about `MSFT_MpPreference` itself. A `-Path` value containing an unpaired UTF-16 surrogate is rejected when parsed, before any transport runs.

## Inspect posture

```powershell
.\wtf.exe defender asr status
.\wtf.exe defender asr rule --check -RuleId D3E037E1-3EB8-44C8-A917-57927947596D
.\wtf.exe defender asr exclusion --check -Path "C:\Lab Data"
```

`status` and every `--check` are read-only and do not require elevation. `status` reports configured rule actions, policy sources, ASR-only global exclusions, and ordinary AV exclusions that also widen the ASR exception surface. Each rule is printed as its GUID plus its name on the following line; a GUID that is not in the built-in catalog is labeled `(name unknown; not in catalog)`. A small set of known rule GUIDs is shown as `NotConfigured` when Defender's configuration has no entry for them. Unrecognized GUIDs are supported; only their display names are missing.

Policy sources are `Local`, `GroupPolicy`, `Unknown`, or `N/A`:

- `N/A` means Defender's current configuration has no entry for the rule (`NotConfigured  source=N/A`), so there is no policy source to attribute. It does not mean the source could not be identified.
- `Local` and `GroupPolicy` are derived from the corresponding registry settings for a rule that has a configuration entry.
- `Unknown` means the rule does have a configuration entry, but neither registry key explains it. Intune/MDM and Windows Security defaults that populate neither key remain `Unknown`; the output is not a complete resultant-policy report.

A rule that is explicitly configured as `NotConfigured` still has an entry, so it reports its real source (`Local`, `GroupPolicy`, or `Unknown`) rather than `N/A`.

Defender may hide exclusion content from non-administrators. The tool reports that it could not observe the list, rather than showing an empty list. An exclusion `--check` over hidden content is unconfirmed (exit 3). Re-run elevated to read it. `exclusion --check` requires `-Path`; use `status` for a general listing.

## Add a global ASR exclusion

From an elevated PowerShell session:

```powershell
.\wtf.exe defender asr exclusion -Path "C:\Lab Data"
```

This is a persistent policy change verified by readback. The printed cleanup command uses `Remove-MpPreference -AttackSurfaceReductionOnlyExclusions` and names only paths absent from the captured baseline. Preserve pre-existing exclusions; this command cannot remove them itself.

## Change one rule action

Record the baseline before changing a rule:

```powershell
.\wtf.exe defender asr rule --check -RuleId D3E037E1-3EB8-44C8-A917-57927947596D
.\wtf.exe defender asr rule -RuleId D3E037E1-3EB8-44C8-A917-57927947596D -Action Block
```

Writes require administrator rights. Supported actions are `Block`, `Audit`, `Warn`, `Disabled`, and `NotConfigured`. The change persists; use the printed cleanup command to restore the captured prior action. A previously unconfigured rule is restored with `NotConfigured`. Readback accepts either an explicit unconfigured entry or an absent entry.

## Experimental behavioral verification

```powershell
.\wtf.exe defender asr verify -RuleId D3E037E1-3EB8-44C8-A917-57927947596D --check
.\wtf.exe defender asr verify -RuleId D3E037E1-3EB8-44C8-A917-57927947596D --telemetry eventlog
```

The first command prepares a read-only check. Without `--check`, the command launches a benign Internet-zone-marked script that attempts to start `notepad.exe`, targeting the rule for JavaScript/VBScript launching downloaded executable content. It does not require elevation for the primitive itself; ETW may require it.

The built-in primitive is **EXPERIMENTAL**: whether it actually engages this rule has not been confirmed in any environment. `verify` never reports confirmed enforcement from process observation:

- A matching payload process observed under `Block` or `Warn` is reported as a mismatch. The primitive may simply not engage the rule; this alone does not prove failed protection.
- Other outcomes are unconfirmed (exit 3), including no child process, `Audit`, `Disabled`, and `NotConfigured`. Absence could mean ASR, AppLocker/WDAC, disabled WSH, a script error, or a primitive that does not trigger the rule.
- Inspect correlated Defender event 1121 (block, including Warn's default behavior) or 1122 (audit) for enforcement evidence. Audit allows and logs; process presence alone does not establish that logging occurred.

Other rules require an authorized caller-supplied `-TestCommand` executable and optional `-TestArguments`; custom commands always have an unconfirmed enforcement outcome because no expected child signature is known. The tool does not create additional built-in payloads.

## Cleanup boundaries

`verify` attempts automatic cleanup of its artifact directory under `%LOCALAPPDATA%\WinTraceForge\AsrTests\<run-id>\`, launcher, and owned direct child processes. It does not discover grandchildren or undo arbitrary side effects of custom commands. Choose a test command whose effects you can restore independently.

Cleanup status concerns the test artifact/processes, not ASR policy. Windows packaged-app redirection or unavailable WMI process queries can prevent process cleanup confirmation; the tool reports `CLEANUP_UNVERIFIABLE` (exit 1). Retain the run output and inspect the remaining artifacts/processes. Policy changes from `rule` and `exclusion` still require manual cleanup even if a later `verify` run cleans up successfully.
