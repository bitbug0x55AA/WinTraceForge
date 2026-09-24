# Control lifecycle contract

This document records the repository review and the contract for adding a control family. The unit of execution is one **control operation**: one validated request against one selected backend. A CLI invocation may run one operation; it is not a general workflow engine.

## Hardening review (2026-09-24)

The shared lifecycle already handled phase order, verification, observation, and restoration. The remaining escape paths were:

- `DefenderOperation` and `FirewallOperation` retained guarded `IPreferenceBackend` / `IFirewallBackend` instances and their `ControlMutationGate`. The gate's `Open`, `Close`, and `RequireWrite` methods were accessible to the family. Both raw backend contracts also exposed writes. The fix removes the gate and passes separate reader and writer facades only to the corresponding phase methods. The operation objects retain neither facade nor raw backend.
- `ControlLifecycleResult` exposed internal transition setters, and `RunEvidence.RecordObservation` in both families called `SetObservation`. The observer received the mutable result. The fix makes the result immutable with a private constructor and keeps mutable state in a private runner state object. The observer receives a copied `IControlLifecycleSnapshot` containing status values only.
- `TelemetryEvidence.PrintEvent` contained provider-specific interpretation branches and `DisplayField` contained a global union of interesting fields. The fix moves both choices into each `TelemetryProfile`; shared presentation only invokes the profile. Correlation was already profile-owned.

`ControlRuntime.Execute` still owns ETW setup, capture shutdown, Event Log collection, and assessment order. Backends and native interop remain unchanged. Explicit transport selection, Firewall ownership checks, profile freezing, and COM NULL versus empty semantics remain in their existing locations.

## Execution contract

The shared runner owns `Probe → Mutate → Verify → Observe → Restore → Complete`. A read-only operation ends after `Probe` and may then collect evidence. The family owns typed baseline and request data. The runner owns phase statuses, exception capture, and exit code mapping. Probe receives a read-only backend view; mutation and restoration receive a write view. This is a compile-time boundary for normal implementations; tests with fake backends verify that no write occurs before a successful probe. Backend constructors must have no persistent side effects.

`IControlOperation<TBaseline, TReader, TWriter>` exposes `Probe(TReader)`, `Mutate(TBaseline, TWriter)`, `Verify(TBaseline, TReader)`, `Restore(TBaseline, TWriter)`, and `VerifyRestored(TBaseline, TReader)`. Reader facades expose no persistent write methods and cannot be cast to the writer facade. Only the runner passes the writer argument, during mutation or restoration. The runner records an attempted write **before** invoking it. An exception, nonzero API status, or ambiguous return all leave mutation as attempted; the runner must not assume the host remained unchanged. Verification is mandatory after a returned mutation request, including ambiguous API status when a safe readback exists. A failing API can also be read back to discover partial mutation. Observation uses a control-supplied `TelemetryProfile` and is evidence only. The observer starts before mutation when required (ETW), is stopped and disposed in `finally`, and cannot overwrite control verification or prevent restoration.

The result has separate typed dimensions: `ProbeStatus`, `MutationStatus` (`NotAttempted`, `Attempted`, `ApiSucceeded`, `ApiFailed`, `ApiUnknown`), `VerificationStatus` (`NotRun`, `Confirmed`, `Mismatch`, `Unavailable`), `ObservationStatus` (`NotRequested`, `Observed`, `NotObserved`, `Incomplete`, `Failed`, `Unavailable`), and `RestorationStatus` (`NotRequired`, `Required`, `Attempted`, `Succeeded`, `Failed`, `Unavailable`, `ManualRequired`). It also carries the typed baseline, selected transport, phase error details, and warnings. Do not create a general object dictionary. A successful write is never itself a successful control result.

Restoration policy is explicit. `Automatic` restores from the captured baseline and independently reads it back in a `finally` path after any attempted mutation. `Manual` records `ManualRequired` and prints the narrow cleanup instruction; it is an intentional persistent test operation. `None` is for read-only or no-op cases. If an API throws or returns an ambiguous result, restoration remains required because state may have changed. A restoration API return without matching readback is `Failed` or `Unavailable`, never `Succeeded`. If the original baseline cannot be obtained, abort before mutation. If the baseline is unsafe to restore automatically (for example a pre-existing or foreign Firewall rule), refuse the write or require manual intervention.

Existing CLI semantics remain: 0 means read-only/idempotent or readback-confirmed requested state, 1 means operation error or safety refusal, 2 invalid arguments, 3 unconfirmed state, and 4 mandatory ETW setup failed before the control operation. Restoration failure must be shown even if the operation exit code is 0; when automatic restoration is introduced, map its failure to 1 while retaining all phase results. Telemetry collection after a successful setup does not change the exit code. No requested backend silently falls back.

| Condition | Later phases | Restore | Result and exit |
| --- | --- | --- | --- |
| Probe/precondition fails | No mutation, verification, or control observation | Not required | Probe error; 1 (arguments: 2) |
| Mandatory ETW setup fails | No control operation | Not required | Observation setup failure; 4 |
| Read-only probe succeeds | Observe if requested | Not required | Probe outcome; 0 or 3 for absent expected state |
| Mutation API fails or throws | Safe readback if available, then observe | Automatic or manual plan still applies | API failure and any actual state change separately; 1 |
| Mutation returns, verification mismatches | Observe | Automatic or manual plan | Mismatch; 3 |
| Verification throws/unavailable | Observe | Automatic or manual plan | Unavailable; 3 |
| Observation fails after mutation | Continue | Always follow restoration plan | Control truth retained; telemetry warning |
| Automatic restore API succeeds, readback fails | Complete | Failed | Restoration failure visible; 1 |
| Manual restoration selected | Complete | ManualRequired | Existing control exit code and cleanup instruction |

## Existing families

**Defender exclusion:** Probe connects and prepares the selected `IPreferenceBackend`, checks support and reads each requested exclusion type into a typed baseline. `--check` is read-only and never asks for elevation. Mutate calls `Add`, retaining the WMI return code or ambiguity. Verify uses `Read` plus `VerifyExclusions`, independent of the Add return. Its profile contains Defender/WMI/process providers and `CorrelateDefender`. Existing adds remain persistent, so restore is `ManualRequired`: remove only newly introduced values through an approved channel and verify the original baseline. `NativeBackend`, `ComBackend`, and `ManagementBackend` remain transport implementations. `EvaluateAddResult` remains a compatibility/parser helper while migration proceeds.

**Firewall:** Probe opens the requested backend, checks elevation only for add/remove, reads name matches, verifies exact ownership, freezes the active profile mask, checks local modify state, prepares a detached rule, and refreshes the name immediately before a write. `profiles` and `rule check` remain read-only. Mutate calls exactly one `Add` or `Remove`. Verify rereads the name and checks exact constrained attributes for add or absence for remove. Its profile owns WFAS/Security/Sysmon correlation. Existing rule changes remain persistent and report the exact ownership-checked cleanup command as `ManualRequired` when a write was attempted. The native packet codec, COM ownership checks, and NULL/empty regression tests remain unchanged.

**Future family shape (structure only):** Define narrow reader and writer capabilities, an operation with phase-specific parameters, and a telemetry profile with correlation, interesting fields, and interpretation. Add one explicit CLI route. No shared family-specific telemetry presentation branch is needed.

## Migration and test contract

1. Add typed lifecycle results and runner with a synthetic fake operation, keeping the existing CLI intact.
2. Move Defender's phase decisions into an operation adapter; retain WMI/native backends and parser behavior.
3. Move Firewall's phase decisions into an operation adapter; retain ownership, race, and native codec checks.
4. Connect the existing telemetry runtime to observation results and restoration ordering, preserving ETW's fail-before-mutation rule.
5. Run `Build.ps1 -Test`, then the non-mutating integration suite where the Windows host permits it. Persistent-write tests must be separate and explicitly invoked.

Regression tests cover phase interface signatures and backend retention, API-success/readback mismatch, unavailable verification, telemetry failure with unchanged control truth, restoration after observation failure, failed restoration/readback, failed mandatory preconditions, exact transport selection, fake lifecycle branches, synthetic third-family correlation and presentation, native NULL/empty semantics, and default test host safety. New family tests should use fakes and must not call live writes in the normal suite.
