# Changelog

All notable changes to WinTraceForge are recorded here. The project follows [Semantic Versioning](https://semver.org/) for release tags.

## Unreleased

### Added

- SHA-pinned GitHub Actions for checkout, artifact upload and provenance generation.
- Signed GitHub build-provenance attestations for release archives and both runtime binaries.
- SemVer metadata in `wtf.exe` and `WinTraceForge.Native.dll`.
- `wtf.exe --version` and `wtf.exe -v`.
- Automated ZIP packaging, SHA-256 generation and GitHub Release publication for version tags.
- CI regression coverage for the native Firewall `INetFwRules::Add` boundary: unspecified program/service stay NULL BSTRs, NULL and empty strings stay distinct across the managed/native codec, and Add HRESULTs propagate unchanged.

### Changed

- Public branding now presents the project as WinTraceForge (WTF).
- Managed and native sources are grouped by responsibility under `src/managed/` and `src/native/`.
- Generated binaries are excluded from the source branch.

## Initial public baseline — 2026-09-24

### Added

- Defender Antivirus exclusion checks and controlled additions through managed WMI, COM Automation and native WMI execution paths.
- Windows Firewall rule add, check and remove operations through managed and native COM paths.
- Read-only Windows Firewall profile inspection.
- Existing Event Log collection and bounded raw ETW capture with module-specific correlation.
- Non-mutating managed, native ABI and integration regression suites.
- MPL-2.0 licensing, security policy and automated Windows CI.
