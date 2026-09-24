# Changelog

All notable changes to WinTraceForge are recorded here. The project follows [Semantic Versioning](https://semver.org/) for release tags.

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
