# Architecture and extension workflow

[Developer docs](README.md)

WinTraceForge runs one validated control operation against one explicitly selected backend. It is not a general workflow engine. Defender AV exclusions, ASR, and Firewall are separate control families sharing CLI conventions, lifecycle orchestration, console presentation, and evidence parsing.

## Source layout

| Location | Responsibility |
| --- | --- |
| `src/managed/app/` | Entry point, shared CLI/core support, and console UI. |
| `src/managed/lifecycle/` | Shared runner, phase contracts, typed results, and restoration policy. |
| `src/managed/defender/` | Defender AV exclusion CLI, operations, and preference backends. |
| `src/managed/asr/` | ASR CLI, snapshots, backends, and phase implementation. |
| `src/managed/firewall/` | Firewall CLI, ownership/readback checks, managed COM/WMI backends, native adapter, and phase implementation. |
| `src/managed/telemetry/` | Runtime capture, module profiles/correlation, evidence presentation, and native ETW adapter. |
| `src/native/defender/` | Native WMI preference transport. |
| `src/native/firewall/` | Native Firewall COM transport and packet codec. |
| `src/native/telemetry/` | ETW session capture and decoding. |
| `tests/` | Fake-backend regressions, native boundary/codec tests, and separately invoked integration runners. |
| `Build.ps1` | Local x64 build, version generation, and selected test suites. |
| `.github/workflows/` | Windows CI and release packaging. |

The Defender phase adapter is currently in `WinTraceForge.Defender.cs`; ASR and Firewall use dedicated `.Operation.cs` files. The shared runner is in `WinTraceForge.ControlLifecycle.cs`.

## Operation flow

The runner owns `Probe → Mutate → Verify → Observe → Restore → Complete`. Read-only operations stop after Probe, with optional evidence collection. Mandatory ETW capture starts before the control operation; setup failure prevents the operation. The telemetry runtime owns capture shutdown and collection ordering.

Families provide typed request/baseline data, separate reader/writer views, and an explicit telemetry profile. Backends must have no persistent construction side effects. Probe and Verify are read-only. Only Mutate and Restore may cause persistent or destructive host effects. API success must remain separate from configuration verification and observation.

Defender and ASR preference transports target `MSFT_MpPreference` via managed WMI, COM Automation, or native WMI. Firewall COM/native target `INetFwPolicy2` / `INetFwRule3`; management targets `MSFT_NetFirewallRule` in `root\StandardCimv2`. Explicit transport selection never falls back. See [backend details](backend-reference.md) before changing interop or readback behavior.

Telemetry profiles own channel/provider selection, correlation, interesting fields, and interpretation. Shared collectors and presentation consume the profile; a new family must not inherit another family's providers through a default branch.

## Add or change a control family

1. Read the [lifecycle contract](control-lifecycle.md) and identify typed request/baseline data, narrow reader/writer capabilities, and restoration policy.
2. Implement phase methods in the family, preserving the single shared runner. Keep write capabilities out of Probe and Verify.
3. Add an explicit CLI route and telemetry profile/correlator. Preserve exact transport selection and fail-before-operation ETW behavior.
4. Add fake-backend regression cases for preconditions, ambiguous writes, mismatched/unavailable readback, observation failure, and restoration failure. Keep live writes out of the normal suite.
5. Run the appropriate [build and test checks](build-and-test.md). Validate production-provider evidence and authorized mutations separately in the intended environment.
6. Update command/help text, user guidance, developer contracts, and changelog for the final behavior.

Do not add Firewall Off/profile mutations, WFP filters/callouts, privilege bypass, or SIEM/EDR backend queries as an incidental extension. These are outside the current scope.
