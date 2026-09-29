# Telemetry and evidence limits

[User docs](README.md) | [Results and cleanup](results-and-cleanup.md)

Comparing observable security evidence across implementation paths is WTF's central research objective. The current modules collect local evidence for security-control / configuration experiments, including read-only operations; collection is opt-in, not conditional on changing a setting. WinTraceForge does not query your SIEM/EDR backend or automatically compare runs.

All modules accept `--telemetry none|eventlog|etw`, `--telemetry-wait 0..30` (default 3 seconds), and `--verbose`. The default is no telemetry collection.

For a comparison, repeat the same operation through the module's supported transports with comparable baselines and capture conditions. Record any differences in outcome, process context, policy, permissions, and auditing; an already-present value can make a later run a no-op. Compare local records, EDR/SIEM ingestion, alerts, and response separately. The paths may share an underlying interface, so a different transport does not guarantee different evidence. See [results and cleanup](results-and-cleanup.md) for the records to retain.

## Existing Windows Event Log records

```powershell
.\wtf.exe firewall profiles --telemetry eventlog
.\wtf.exe defender asr status --telemetry eventlog --verbose
```

`eventlog` reads existing channels after the operation. It does not enable channels or audit policy. The query includes a 2-second lookback and the configured publication wait. At most the newest 200 filtered events per channel are scanned; truncation and read failures are reported.

| Module | Channels and event IDs |
| --- | --- |
| Defender exclusions | Defender Operational: 5007 / 5013; WMI-Activity Operational: 5857–5861 |
| ASR | Defender Operational: 1121 (block, including Warn by default), 1122 (audit), 5007 / 5013; WMI-Activity Operational: 5857–5861 |
| Firewall rules/profiles | Windows Firewall With Advanced Security/Firewall: 2004 (add), 2005 (modify), 2006 (delete); Security: 4946 / 4947 / 4948 |

All modules also inspect Security 4688 and Sysmon Operational 1 when available. Security audit events require appropriate policy and permissions.

Firewall correlation requires the exact requested rule name, not a substring or a generic Firewall mention. ASR correlation matches the requested rule GUID or exclusion path substring within event fields; an event without that value is time-only evidence. Process-start evidence and rule-change evidence are separate. Defender, ASR, and Firewall evidence are not interchangeable.

The Defender/ASR/Firewall `powershell` transport introduces a child process and possible PowerShell logging surfaces; Firewall's `cmd` transport introduces a `cmd.exe`/`netsh.exe` child process pair instead. WTF does not record those children's PIDs, command lines, or step (which call each one came from) for its PID-based correlation; compare their activity manually using timestamps and command lines. A single `firewall rule add --transport powershell|cmd` invocation shells out several times (module/tool availability check, baseline read, the mutation itself, post-mutation readback), not once, so a single alert or process event cannot be attributed to the write specifically without that manual correlation. A telemetry difference reflects the tested implementation path, not evidence that the underlying preference interface or enforcement changed. For `cmd` specifically, remember the created rule's *content* also differs from the other four transports (no `Grouping` marker; see [firewall.md](firewall.md)) — a telemetry or EDR rule keyed on that field is a confound distinct from the transport itself. Word conclusions narrowly, e.g. "no alert was observed for this transport under these conditions," not "this transport is undetected."

## Raw ETW capture

```powershell
.\wtf.exe firewall profiles --telemetry etw --telemetry-wait 5
```

ETW creates a unique file-mode session before the operation, captures during it, waits for the requested tail, stops the session, and then decodes the ETL. This is raw ETW, not Event Log scraping or live console streaming. No kernel trace or WFP filters/callouts are installed.

| Module | Providers |
| --- | --- |
| Defender exclusions / ASR | Microsoft-Windows-WMI-Activity (`1418ef04-b0b4-4623-bf7e-d74ab47bbdaa`); Microsoft-Windows-Windows Defender (`11cd958a-c507-4ef3-b3f2-5fd9dfbd2c78`) |
| Firewall | Microsoft-Windows-Windows Firewall With Advanced Security (`d1bc9aff-2abf-4d71-9146-ecb2a986eb85`) |

Providers use verbose level 5, all match-any keywords, and no match-all keywords. Provider enable success does not guarantee emission. Partial coverage is reported. ETW requires suitable permissions, commonly elevation. If startup fails or no provider enables, the control operation does not run (exit 4), with no fallback. Failures after the operation starts do not replace its exit code.

Traces remain at:

```text
%LOCALAPPDATA%\WinTraceForge\Traces\<run-id>\capture.etl
```

ETLs can contain other processes' activity. Post-capture correlation is not a capture-time process filter. Treat ETLs as sensitive evidence; they are not deleted automatically.

### Capture bounds and attribution

- 32 MB sequential file and 120-second safety timer.
- At most 10,000 decoded provider events and 64 top-level fields per event.
- Scalar fields decoded through TDH; unsupported arrays/structures, missing schemas, parsing/callback failures, and event/buffer losses reported explicitly.
- Default view shows up to 3 candidates; `--verbose` expands within the cap. Shortened fields are marked.

ETW sequence numbers are not Event Log Record IDs. Header PID is the emitter, not necessarily the WMI ClientProcessId or the requester. Activity IDs are observed values, not synthesized attribution.

### Session cleanup

Normal completion, handled errors, Ctrl+C, and the safety timeout stop only the tool-owned session. Abrupt termination or power failure can prevent cleanup. An authorized administrator can inspect the printed session name and stop that exact session:

```powershell
logman stop "WinTraceForge-<run-id>" -ets
```

Replace the placeholder with the recorded run ID. Never stop unrelated sessions.

Missing events can result from auditing, access, timing, retention, or existing state. A missing alert is **an observation under tested conditions, not a bypass claim**. Neither missing local events nor missing EDR/SIEM alerts establish that nothing happened; record the tested path, outcome, and capture limits.
