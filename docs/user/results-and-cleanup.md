# Results, evidence, and cleanup

[User docs](README.md)

## Keep conclusions separate

An API return, configuration readback, enforcement, telemetry completeness, compliance, and detection/response are different observations. Readback is a point-in-time configuration observation. Local events do not establish SIEM/EDR ingestion, alerting, analyst triage, or response.

The WTF name reflects environment-specific manual tests where successful changes often produced little useful detection. Treat silence as a question to investigate: telemetry gaps, correlation, auditing, ingestion delay, policy, access, and detection coverage can all matter.

Preserve the command, selected transport, run/test ID, UTC window, host, user, PID, binary hash, before/after configuration, and event channel/record IDs. Compare them with your approved change record and expected policy. Validate ingestion and response separately. For unauthorized changes, preserve evidence and follow your incident playbook.

## Exit codes

| Code | Meaning |
| --- | --- |
| `0` | Confirmed state, read-only success, help, or documented idempotent absence. |
| `1` | Operation error, safety refusal, or failed/unconfirmed automatic restoration. |
| `2` | Invalid command or arguments. |
| `3` | Unconfirmed state or missing expected configuration. |
| `4` | Mandatory ETW setup failed before the control operation. |

Consult the command's output and help for absence behavior. A missing firewall rule on `check` exits 3; removing an already-absent rule is idempotent. ASR `verify` never confirms enforcement from process observation, and `CLEANUP_UNVERIFIABLE` exits 1. Later telemetry failures do not replace the control operation's exit code. Always inspect the separate cleanup status.

## Restoration responsibilities

| Operation | Cleanup |
| --- | --- |
| Defender AV exclusion add | Manual: remove only test-created values through an approved administration channel, preserving the baseline. |
| ASR exclusion add | Manual: use the printed command, which includes only newly introduced paths. |
| ASR rule change | Manual: use the printed command to restore the captured prior action. |
| ASR behavioral verify | Automatic cleanup attempted for owned test artifacts and launcher/direct children; inspect the reported restoration status. |
| Firewall rule add | Manual: use the printed ownership-checked remove command and test ID. |
| ETW capture | Session normally stopped automatically; retained ETL is not deleted. Inspect the exact owned session after abrupt termination. |

A write can change the host even when its API throws, returns an error, or reports an ambiguous result. Batch changes are not transactional. Preserve output and inspect actual state before cleanup. Remove only test-created values or explicitly marked rules; never broadly reset firewall or Defender configuration.

Firewall ownership markers prevent accidental deletion but are not a security boundary. Do not reuse IDs concurrently. Pre-schema legacy rules require their matching build or standard Windows tools. Abrupt termination can leave traces, sessions, or partially completed changes.

See the [Defender](defender.md), [ASR](asr.md), [Firewall](firewall.md), and [telemetry](telemetry.md) guides for operation-specific cleanup and limitations.
