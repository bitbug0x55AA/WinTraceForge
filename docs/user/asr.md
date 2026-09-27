# Attack Surface Reduction (ASR)

[User docs](README.md) | [Shared command options](commands.md)

ASR commands support `--transport management|com|native`, defaulting to `management`. Each route targets the same Defender preference class with no fallback.

## Inspect posture

```powershell
.\wtf.exe defender asr status
.\wtf.exe defender asr rule --check -RuleId D3E037E1-3EB8-44C8-A917-57927947596D
.\wtf.exe defender asr exclusion --check -Path "C:\Lab Data"
```

`status` and every `--check` are read-only and do not require elevation. `status` reports configured rule actions, policy sources, ASR-only global exclusions, and ordinary AV exclusions that also widen the ASR exception surface. A small set of known rule GUIDs is shown as `NotConfigured` when absent. Unknown GUIDs are supported; only their display names may be missing.

Policy sources are `Local`, `GroupPolicy`, or `Unknown`, based on corresponding registry settings. Intune/MDM and Windows Security defaults that populate neither key remain `Unknown`; the output is not a complete resultant-policy report.

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
