# Changelog

All notable changes to WinTraceForge are recorded here. The project follows [Semantic Versioning](https://semver.org/) for release tags.

## Unreleased

### Changed

- Reframed the project as a Windows security telemetry differential testing harness / lab focused on path-dependent security visibility: same operation or equivalent outcome, different implementation paths, and comparison of observable security evidence. Updated documentation, help wording, and assembly description while retaining current Defender Antivirus, ASR, and Firewall experiments and their existing CLI/lifecycle. No new execution experiments or behavior families are introduced.

### Added

- `defender asr` now supports `--transport com` and `--transport native` (in addition to the existing `management`), matching `defender exclusion`'s three-transport architecture: all three target the same `MSFT_MpPreference` class through a shared snapshot-assembly and single-instance-readback guard.
- `defender exclusion` and `defender asr` now both support `--transport powershell`, which invokes System32's own `powershell.exe` directly (an absolute path, not a bare name subject to CreateProcess search-order hijacking) and drives the `ConfigDefender` module's module-qualified `Add-MpPreference`/`Get-MpPreference` cmdlets instead of talking to WMI directly. The script is passed via `-EncodedCommand`, never written to a temp file first, and the child process' `PSModulePath` is restricted to the system module directory -- so neither the script nor the `ConfigDefender` module resolution can be substituted by another process running as the same non-elevated user (module-qualifying a call alone only guards against a same-named function/alias, not the module itself being shadowed from a user-writable `PSModulePath` entry). Every value that could ever contain caller-supplied or non-ASCII content -- exclusion values, ASR-only exclusions, error messages, readback results -- is Base64-encoded end to end, immune to the OEM/ANSI/UTF-8 codepage mismatches that would otherwise corrupt non-ASCII text or split a value containing an embedded newline into multiple values; a value containing an unpaired UTF-16 surrogate (which cannot be represented in UTF-8 at all) is instead rejected at CLI-parse time, identically for every transport. Every read script asserts `Get-MpPreference` returned exactly one instance and that each requested field actually exists before reading it, reads every field with a bare (unguarded) `foreach` rather than one gated behind an `if` (PowerShell's truthiness of a one-element array is that of its single element, so an `if`-guarded read would silently drop a rule whose action is the falsy byte `0`, i.e. `Disabled`), and reports an explicit success/failure marker rather than ever letting an incomplete or failed script read back as an empty snapshot. `Add-MpPreference` is a void cmdlet with no WMI return code, so a successful Add always confirms through readback (`MutationStatus.ApiUnknown`); a script that ends without either marker (e.g. torn down externally after the cmdlet may already have run) is classified the same way, not as a known failure, and its `stderr`/`stdout` is printed alongside the warning since that is often the only evidence of why. `defender asr`'s `powershell` backend reuses the shared `PowerShellRunner` process-execution helper introduced in `WinTraceForge.Defender.cs`, the same way its existing `com` backend reuses `DefenderModule.ComObjects`. An oversized Add request (too many/too long values for `-EncodedCommand`'s command-line budget) is rejected during `Prepare()`, before Connect()/Add() ever run, so the lifecycle reports `Mutation=NotAttempted` rather than misreporting it as `MutationStatus.ApiFailed`. The ASR `AttackSurfaceReductionRules_Actions` field is read back with an explicit `[int]` cast ahead of `[string]`, so a build that ever surfaces it as an enum-backed type rather than a plain byte reads back its numeric value, not its member name. The `PSModulePath` restriction is applied by temporarily overriding `wtf.exe`'s own environment variable around `Process.Start` rather than `ProcessStartInfo.EnvironmentVariables`, since that property's first access always copies the whole current-process environment into a case-insensitive dictionary and throws on a host whose raw environment already has two case-variant entries for the same variable (observed for `Path`/`PATH`); both `powershell` transports previously failed to even launch `powershell.exe` on such a host.
- `firewall` now supports `--transport management` (in addition to the existing `com` and `native`), targeting the WMI Firewall provider (`MSFT_NetFirewallRule` in `root\StandardCimv2`, the same provider PowerShell's `New-NetFirewallRule` uses) instead of the `INetFwPolicy2`/`INetFwRule3` COM interfaces `com`/`native` share. All three transports read/write the same persisted rule store through the same ownership schema and readback comparison, so a rule added with one can be checked or removed with any other; `management` looks a rule up by `ElementName` rather than `InstanceID`, since a rule created through `com`/`native`'s `HNetCfg.FWRule` gets an opaque provider-generated `InstanceID` with its netfw `Name` surfaced only in `ElementName` (confirmed by live cross-transport add/check/remove testing in both directions). `management`'s `profiles` command explicitly reads `PolicyStore=ActiveStore` rather than the default local/persistent store, matching `com`/`native`'s always-effective-policy semantics (confirmed live on a domain-managed host); its rule readback also refuses rather than silently misreports a rule secured with `Authentication`/`Encryption`/`OverrideBlockRules`, since this transport never creates such rules and always reports `SecureFlags=0`.

## 0.1.0 — 2026-09-25

Initial public release of WinTraceForge (WTF), a Windows x64 defense-control test harness.

### Added

- Defender Antivirus exclusion checks and controlled additions through managed WMI, COM Automation, and native WMI execution paths.
- Attack Surface Reduction (ASR) posture inspection, ASR-only exclusion checks and additions, single-rule action checks and changes, and a controlled behavioral verification command.
- Windows Firewall test-rule add, check, and remove operations through managed and native COM paths, plus read-only profile inspection.
- Existing Event Log collection and bounded raw ETW capture with module-specific correlation for Defender, ASR, and Firewall operations.
- `wtf.exe --version` and `wtf.exe -v`, with SemVer metadata in both `wtf.exe` and `WinTraceForge.Native.dll`.
- Automated Windows builds and non-mutating regression tests, including native Firewall `INetFwRules::Add` boundary coverage.
- Version-tagged release packaging with a Windows x64 ZIP, SHA-256 checksum, and signed GitHub build-provenance attestations.
- MPL-2.0 licensing and a security policy.

### Changed

- Standardized public branding as WinTraceForge (WTF) and organized managed and native sources by responsibility under `src/managed/` and `src/native/`.
- Introduced a shared control lifecycle for probe, mutation, verification, and restoration, with explicit read-only paths and cleanup guidance for persistent changes.
- Excluded generated binaries from the source branch; release binaries are distributed as GitHub Release assets.

### Known limitations

- ASR behavioral verification is experimental. Local process observation alone cannot confirm rule enforcement; inspect the correlated telemetry before drawing a conclusion.
- Defender exclusion and ASR rule/exclusion changes persist until manually restored. Firewall rules require the printed cleanup command and test ID for removal.
