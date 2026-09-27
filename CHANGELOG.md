# Changelog

All notable changes to WinTraceForge are recorded here. The project follows [Semantic Versioning](https://semver.org/) for release tags.

## Unreleased

### Added

- `defender asr` now supports `--transport com` and `--transport native` (in addition to the existing `management`), matching `defender exclusion`'s three-transport architecture: all three target the same `MSFT_MpPreference` class through a shared snapshot-assembly and single-instance-readback guard.
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
