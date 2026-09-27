# Build and test

[Developer docs](README.md) | [Architecture](architecture.md)

## Toolchain and build

Use Windows x64 with .NET Framework 4.8+, Visual Studio C++ Build Tools, and a Windows SDK. The build uses the Framework x64 C# compiler and finds Visual Studio x64 C++ tools through `vswhere`; an x64 developer terminal is also suitable. There is no package-download step or proprietary test harness.

Run from the repository root in PowerShell:

```powershell
.\Build.ps1
.\Build.ps1 -Test -Version 0.1.0-dev
```

The script compiles managed sources recursively under `src/managed/` and the explicit native sources under `src/native/defender/`, `src/native/firewall/`, and `src/native/telemetry/`. It generates version metadata for both binaries.

| Parameter | Purpose |
| --- | --- |
| `-OutputDirectory` | Override the default `build/` output directory. |
| `-VcVarsPath` | Supply an explicit `vcvars64.bat` when automatic discovery is unavailable. |
| `-Version` | Set SemVer metadata; default `0.1.0-dev`. |
| `-Test` | Build and run deterministic/fake-backend regressions. |
| `-Integration` | Run regressions plus host-dependent integration checks. |

Outputs include `build/wtf.exe` and `build/WinTraceForge.Native.dll`. Keep them together. Generated binaries, version sources, and build intermediates are excluded from source control.

## Test suites

`-Test` runs managed parser, lifecycle, ownership/race/readback, ASR, and telemetry regressions with fake backends, plus native codec and Firewall Add-boundary tests (`Firewall.Native.CppTests.exe --deterministic`). Those tests submit detached rules to a probe collection without opening persistent firewall policy. [Windows CI](https://github.com/bitbug0x55AA/WinTraceForge/blob/main/.github/workflows/build.yml) runs this suite. The ASR primitive fixture also needs write access to its test-artifact directory under `%LOCALAPPDATA%\WinTraceForge\AsrTests\`; it does not launch the primitive in this suite.

Run host-dependent checks separately:

```powershell
.\Build.ps1 -Integration
```

`-Integration` also performs real read-only Defender/ASR/Firewall checks, detached COM rule preparation, native ABI tests, and a private ETW round trip. Neither mode invokes persistent Defender Add or Firewall Add/Remove. Non-admin refusal checks are skipped under an elevated token. Local policy, services, event-channel access, elevation, and ETW permissions can affect integration observations; runners report these limits.

All regression and integration sources are in `tests/`. New normal-suite tests must use fakes for persistent mutations; authorized live-write experiments must be explicitly separated.

## Validation limits

The regression suite builds optimized x64 managed and native binaries with
warnings treated as errors. Mutation workflows use fake backends for ownership,
collision, readback and cleanup behavior. Add-boundary tests inject a fake
INetFwRules collection around a detached rule and snapshot the exact object
Add receives: NULL ApplicationName/ServiceName, explicit program/service,
NULL versus empty Description, protocol, ports, addresses, direction, action,
profiles, enabled and edge state, and exact propagation of injected Add
HRESULTs. A negative control confirms the probe still sees an allocated empty
BSTR, so the NULL assertions cannot pass vacuously on a future Windows build.
Managed and native codec tests share golden bytes for NULL (-1) versus empty
(0) strings. None of this writes to the persistent Windows collection.

Integration checks exercise actual read-only Defender and Firewall routes,
detached TCP/UDP rule preparation, native ABI/codec behavior, and a private ETW
provider-to-ETL round trip. Development checks never invoke Defender Add or
Firewall Add/Remove. Assertion counts and read-only snapshots can vary with the
host, installed rules, token elevation, event-channel access and ETW permissions;
each runner reports its own results.

Successful production-provider ETW collection, authorized live mutations and
packet enforcement must be validated separately in the intended environment.
Access-denied and unavailable-provider paths are reported explicitly.
