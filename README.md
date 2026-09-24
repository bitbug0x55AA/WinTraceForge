# WinTraceForge

WinTraceForge is a Windows x64 security-control validation harness. It exercises narrowly scoped Microsoft Defender Antivirus exclusion and Windows Firewall management paths, captures local telemetry, and reports what was observed without claiming that a configuration readback proves enforcement or detection.

> [!WARNING]
> Run WinTraceForge only in an environment where you are authorized to change security controls. Defender exclusion changes are not removed automatically. Firewall rules must be removed with the printed cleanup command and test ID.

## Scope

The command-line format is:

```text
wtf.exe <module> <command> [options]
```

| Module | Command | Behavior |
| --- | --- | --- |
| `defender` | `exclusion` | Check or add Defender Antivirus exclusions through management, COM, or native WMI routes. |
| `firewall` | `rule add\|check\|remove` | Manage only uniquely marked test rules through COM or native Windows Firewall interfaces. |
| `firewall` | `profiles` | Read active profile state and exposed policy settings without changing them. |

WinTraceForge does not disable Windows Firewall, change firewall profiles, install WFP filters or callouts, bypass privileges, generate test traffic, or query a SIEM/EDR backend.

## Requirements

- Windows x64
- .NET Framework 4.8 or later
- Relevant Windows Defender Antivirus and Windows Firewall services
- Administrator rights for Defender exclusion writes and firewall rule add/remove operations
- Visual Studio C++ Build Tools with a Windows SDK when building from source

Keep `wtf.exe` and `WinTraceForge.Native.dll` in the same directory. The native DLL is required for native transports and raw ETW capture.

## Install

Download the `WinTraceForge-<version>-win-x64.zip` asset from the corresponding GitHub Release, verify it against the accompanying `.sha256` file, and extract both binaries to the same directory. Generated binaries are not committed to the source branch.

## Quick start

Show the command tree:

```powershell
.\wtf.exe --help
.\wtf.exe defender exclusion --help
.\wtf.exe firewall --help
```

Run read-only checks first:

```powershell
.\wtf.exe defender exclusion --check -ExclusionPath "C:\Lab Data"
.\wtf.exe firewall profiles
.\wtf.exe firewall rule check --id <GUID>
```

Add and remove a narrowly scoped test firewall rule:

```powershell
.\wtf.exe firewall rule add `
  --remote-address 192.0.2.10 `
  --remote-port 44443

.\wtf.exe firewall rule remove --id <GUID>
```

The add command prints the generated test ID and exact cleanup command before it creates a rule. Use an approved endpoint and retain that output.

Add a Defender exclusion only when the test plan requires it:

```powershell
.\wtf.exe defender exclusion -ExclusionPath "C:\Lab Data"
```

This operation requires elevation, preserves existing exclusions, verifies requested values by readback, and does not automatically clean up the new exclusion.

## Telemetry

All modules accept:

```text
--telemetry none|eventlog|etw
--telemetry-wait 0..30
--verbose
--no-color
```

`eventlog` reads existing relevant channels after the operation. It does not enable channels or audit policy. `etw` starts a bounded, tool-owned file session before the operation and stores ETL evidence under:

```text
%LOCALAPPDATA%\WinTraceForge\Traces\<run-id>\capture.etl
```

ETL files may contain unrelated activity from the selected providers and should be handled as sensitive evidence. Missing events do not prove that no detection occurred.

## Build and test

The build has no package-download step. From PowerShell:

```powershell
.\Build.ps1
.\Build.ps1 -Test
```

Outputs are written to `build\` by default:

```text
build\wtf.exe
build\WinTraceForge.Native.dll
```

`-Test` builds optimized x64 binaries with warnings treated as errors and runs fake-backend regression tests. The broader integration suite performs real read-only Windows checks and a private ETW round trip, but does not invoke persistent Defender Add or Firewall Add/Remove operations:

```powershell
.\Build.ps1 -Integration
```

Integration results depend on local policy, installed services, event-channel access, elevation, and ETW permissions. GitHub Actions runs the non-mutating `-Test` suite.

## Safety model and limits

- No transport fallback is performed. A missing or incompatible native DLL is an explicit failure.
- Firewall add refuses an existing deterministic rule name instead of overwriting it.
- Firewall remove requires a unique rule whose name, grouping, and description match the WinTraceForge ownership schema.
- Rules created by builds predating the WinTraceForge ownership schema are intentionally not treated as WinTraceForge-owned. Verify and clean them up with the matching legacy build or standard Windows administration tools.
- Configuration readback is not proof of packet enforcement, prevention, compliance, SIEM ingestion, alerting, analyst triage, or response.
- Firewall ownership markers prevent accidental cleanup of unrelated rules; they are not a security boundary or authorization mechanism.
- Abrupt termination can leave an ETW session or a partially completed control change. Preserve the printed run ID and cleanup details.

See [docs/technical-reference.md](docs/technical-reference.md) for transport mappings, event providers, evidence bounds, exit codes, and detailed cleanup behavior.

## Repository contents

- `src/WinTraceForge/managed/` — managed CLI, control modules, native interop, telemetry, and console output
- `src/WinTraceForge/native/` — native WMI, Windows Firewall, and ETW implementation
- `tests/` — regression and non-mutating integration runners
- `.github/workflows/build.yml` — Windows CI build and regression workflow
- `Build.ps1` — reproducible local build/test entry point

Generated executables, DLLs, symbols, ETL files, and build directories are intentionally excluded from source control. Release binaries should be published as GitHub Release assets rather than committed to the source tree.

## Publishing a release

Pushing a semantic version tag automatically builds and tests the project on a GitHub-hosted Windows runner, creates a ZIP package and SHA-256 checksum, and publishes both as GitHub Release assets:

```powershell
git tag v0.1.0
git push origin v0.1.0
```

The release workflow is idempotent: rerunning it replaces the assets on an existing release for the same tag. No `bin/` directory or compiled binary needs to be committed.

## License

WinTraceForge is licensed under the [Mozilla Public License 2.0](LICENSE).
