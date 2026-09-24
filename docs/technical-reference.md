WinTraceForge technical reference
=================================

Requirements and scope
----------------------
Windows x64, .NET Framework 4.8+, and the relevant Windows control services.
Keep `wtf.exe` and `WinTraceForge.Native.dll` together.
Use only in an authorized test environment.

Control modules:
  wtf.exe defender exclusion ...
  wtf.exe firewall rule add|check|remove ...
  wtf.exe firewall profiles ...

Defender exclusions and Firewall rules are independent modules. They share
CLI conventions, console presentation, telemetry lifecycle and evidence
parsing. Firewall requests are not passed through Defender exclusion APIs.
No Firewall Off, profile changes, WFP filter/callout manipulation, privilege
escalation, or protection bypass is implemented.

Quick reference
---------------
  wtf.exe --help
  wtf.exe defender exclusion --help
  wtf.exe firewall rule --help
  wtf.exe firewall profiles

Both module help pages use the same section order, aligned option rows and
shared telemetry/display descriptions: Usage, Options, module-specific
commands/types, Routes, Quick start and Before you run.
Add --verbose to --help for Extended notes (ownership, telemetry limits and
cleanup details). Firewall module, rule and profile help share this layout:
  wtf.exe firewall --help
  wtf.exe firewall rule --help --verbose
  wtf.exe defender exclusion --help --verbose

Shared flags:
  --telemetry none|eventlog|etw   default: none
  --telemetry-wait 0..30         default: 3 seconds
  --verbose                     expanded evidence and defensive guidance
  --no-color                    plain text; automatic for redirected output

Module flags follow the module/subcommand. Do not place them before
"defender exclusion" or "firewall rule". Redirect stdout and stderr together
when retaining a report. NO_COLOR and TERM=dumb are respected.

Defender Antivirus / Exclusions
-------------------------------
Migration: prepend "defender exclusion" to previous exclusion commands:
  wtf.exe defender exclusion --transport native --check -ExclusionPath "C:\Lab Data"

Routes:
  --transport management (default)
    System.Management -> WMI -> MSFT_MpPreference.Add
  --transport com
    COM Automation SWbemLocator/SWbemServices -> WMI -> MSFT_MpPreference.Add
  --transport native
    P/Invoke -> native C++ IWbemLocator/IWbemServices::ExecMethod
    -> WMI -> MSFT_MpPreference.Add
No transport fallback is performed.

Types: -ExclusionPath, -ExclusionExtension, -ExclusionProcess,
-ExclusionIpAddress (subject to provider support).
Values are separate arguments, not PowerShell comma-separated arrays.
Quote spaces. Names are case-insensitive; repeated types are supported.
Use -ExclusionTYPE=VALUE for a value beginning with a dash.
No implicit default exclusion is added.

--check is read-only: metadata validation, request preparation and a baseline
read for specified values. Without --check, Add requires an administrator.
The tool preserves existing exclusions and reads every requested value back.
A missing WMI return code is a warning, not silent success. Known nonzero
codes remain failures. Pre-existing values are not new changes.
Batch changes are not transactional and no automatic cleanup occurs.

Windows Firewall / Rules
------------------------
Routes (supported on rule add/check/remove and profiles):
  --transport com (default)
    C# COM interop -> INetFwPolicy2 / INetFwRule3 -> Windows Firewall
  --transport native
    C# P/Invoke -> native C++ typed SDK INetFwPolicy2 / INetFwRule3
    -> Windows Firewall
The native DLL performs policy/rule enumeration, property access, detached
rule preparation and Add/Remove; it does not delegate these to C# reflection.
Both use the same Windows Firewall COM management interfaces and ownership
schema. This compares caller implementations, not different policy engines.
It is not a WFP API test, privilege bypass or proof of different detection.

Optional-property construction:
  Protocol is set before any explicitly requested port restriction.
  Omitted ports are left at the TCP/UDP object's default rather than setting
  a wildcard string; readback can legitimately display "*" for those ports.
  Omitted ApplicationName/ServiceName are left unset, preserving the native
  NULL BSTR defaults instead of assigning allocated empty strings.
  Explicit program paths and port restrictions are still set and read back.
These rules apply equally to com and native. Detached setter/readback
success does not guarantee that INetFwRules::Add will accept/persist a rule.
A reported native Add E_INVALIDARG prompted this correction; the regression
suite covers preservation of unspecified NULL defaults at the Add boundary.
Detached tests do not establish live Add acceptance, and an E_INVALIDARG result
must not be attributed to that difference without separate evidence.
Failure output identifies INetFwRules::Add/Remove and reports the original
HRESULT once. Never retry a failed mutation through another route implicitly.

No automatic transport fallback is performed. A missing, wrong-architecture
or outdated native DLL is an explicit operation failure; com is not tried.
Keep the matching x64 DLL from this package next to the EXE. Firewall com
does not require the DLL unless --telemetry etw is selected.
--transport management/cim/wmi is not implemented for Firewall and is rejected.
CIM requires a separate MSFT_NetFirewallRule/filter/operation-option mapping;
it is not an alias for either COM route or Defender's WMI implementation.

Read-only comparison:
  wtf.exe firewall profiles --transport com
  wtf.exe firewall profiles --transport native

Use a unique GUID per authorized test and retain it for cleanup. For example:
  wtf.exe firewall rule add --id 8dd2c54c-d2b2-4b2a-9880-2ae82a9e2bd9 --direction out --action block --protocol tcp --remote-address 192.0.2.10 --remote-port 44443 --profiles private
  wtf.exe firewall rule check --id 8dd2c54c-d2b2-4b2a-9880-2ae82a9e2bd9
  wtf.exe firewall rule remove --id 8dd2c54c-d2b2-4b2a-9880-2ae82a9e2bd9

Append --transport native to any rule command to select the C++ path.
Printed cleanup commands preserve the selected transport. Either transport
can inspect/remove a rule created by the other if its exact ownership markers
match; transport is not part of ownership. Existing commands default to com.
Raw ETW/eventlog provider selection remains Firewall-specific for both routes.

The documentation address above is an example, not a connectivity test.
Choose an approved endpoint for an actual experiment. Add/remove require
administrator rights and may still be restricted by central policy.
Required add scope: one literal IPv4/IPv6 remote address (no hostnames,
ranges or subnets), plus a direction-appropriate port from 1..65535:
  outbound: --remote-port required; --local-port optional (default: all)
  inbound:  --local-port required; --remote-port optional (default: all)
Defaults: outbound, block, TCP, all local addresses, all programs and no
service/interface restriction. Example inbound TCP/443 test:
  wtf.exe firewall rule add --direction in --remote-address 192.0.2.10 --local-port 443 --transport native
The current active profile mask is frozen before the write, unless explicitly
specified with --profiles domain,private,public or --profiles all.
An invalid/empty active mask refuses the write; it never defaults to all.
Optional --program requires an absolute executable path; --local-port sets
one local port. For inbound rules, --remote-port means the sender's source
port, NOT the local listening port (use --local-port for that).
Rule3 restriction inspection requires Windows 8/Server 2012 or later.
Before add, LocalPolicyModifyState is read and printed, including GP_OVERRIDE
or INBOUND_BLOCKED when returned. This is policy restriction context, NOT a
complete resultant GPO/MDM policy or a per-rule merge/enforcement verdict.
Nonzero state is a warning, not silently treated as failure/success of Add;
the actual call and property readback still determine the operation outcome.

Rules are identified by a deterministic name derived from the test GUID,
a fixed tool grouping, and a versioned ownership description. These are
operational markers, not cryptographic ownership or authorization.
Exact markers (GUID is lowercase canonical D format):
  Name: WinTraceForge.Firewall.<GUID>
  Grouping: WinTraceForge.Firewall.v1
  Description: WinTraceForge;kind=firewall-rule;schema=1;id=<GUID>
Add refuses an existing same-name rule; it does not overwrite or upsert.
Check is read-only: it verifies unique ownership and displays current
properties, not a comparison with the original add request. An absent check
returns exit 3. Remove verifies all ownership markers and refuses
ambiguous, duplicate or foreign rules. An already-absent removal is reported
explicitly without performing a deletion.
Ownership is re-read before removal, but COM Remove is by name: there is no
atomic compare-and-delete transaction. Do not run concurrent tests with the
same ID or allow concurrent writers to modify marked rules during cleanup.
Rules created by builds predating the WinTraceForge ownership schema have legacy
names and markers. WinTraceForge intentionally refuses to treat them as owned;
verify and remove them with the matching legacy build or standard Windows
administration tools rather than weakening the current ownership checks.

Add follows baseline -> request -> create -> property readback -> telemetry
(when selected) -> assessment. Add confirms all constrained properties,
including Rule3 restrictions; it never calls this an effective-policy proof.
Stable outcomes include FIREWALL_RULE_CONFIRMED, FIREWALL_RULE_UNCONFIRMED,
FIREWALL_RULE_OWNERSHIP_CONFIRMED, FIREWALL_RULE_REMOVED,
FIREWALL_RULE_ALREADY_ABSENT, FIREWALL_PROFILES_READ and operation/setup errors.
The generated or supplied ID and cleanup command are shown before creation.
Readback mismatches remain failures/unconfirmed results; inspect the rule
and use the printed cleanup command for a partially completed test.
Automatic rollback is not performed, to avoid deleting evidence or a rule
that another administrator may have changed in the meantime.

Rule visibility and matching properties do NOT prove packet enforcement.
Profiles, policy merging, GPO/MDM, rule precedence, application/service scope,
the network path and the actual traffic all affect enforcement.
Perform a separate authorized connectivity test if packet behavior is the
test objective. The tool neither generates traffic nor changes profile state.

Windows Firewall / Profiles
---------------------------
  wtf.exe firewall profiles
  wtf.exe firewall profiles --telemetry eventlog
This is a read-only inspection of profile state and exposed policy settings.
It does not turn the firewall off, toggle a profile, or change default actions.
Settings exposed through COM are not a complete GPO/MDM resultant-policy report.

Telemetry: Windows Event Log
----------------------------
Architecture: each control module explicitly supplies a TelemetryProfile
with event-log channels, ETW provider descriptors, evidence-value selection
and a correlator. Collectors consume this profile, not a Defender-versus-
everything-else branch. Adding a control family requires its own explicit
profile/correlator; unknown families never inherit Firewall telemetry.
The native ETW v2 ABI takes a validated list of 1..16 unique nonempty provider
GUIDs, not a module number. Per-provider enable status and event/loss/decode
limits are preserved. Older ETW DLLs fail explicitly with no fallback.

--telemetry eventlog reads existing channels after the operation.
It never enables audit policy or channels. Query time includes a 2-second
lookback plus the configured publication wait. At most the newest 200
filtered events per channel are scanned; truncation and read failures are
explicit. EventData and UserData are parsed from XML with DTDs disabled.

Defender module:
  Microsoft-Windows-Windows Defender/Operational: 5007 / 5013
  Microsoft-Windows-WMI-Activity/Operational: 5857..5861
Firewall modules:
  Microsoft-Windows-Windows Firewall With Advanced Security/Firewall:
    2004 rule added, 2005 rule modified, 2006 rule deleted
  Security: 4946 rule added, 4947 modified, 4948 deleted
Both also inspect Security 4688 and Sysmon Operational 1 when available.
Security audit events require the appropriate policy and permissions.

Firewall rule correlation requires an exact requested rule name in the event.
It is not enough for an event to mention "Firewall" or a name substring.
Process-start evidence is separate from rule-change evidence.
Defender exclusion evidence and Firewall evidence are not interchangeable.
Missing events do not prove no detection; event delivery, access, auditing,
retention and existing state all affect observations.

Telemetry: raw ETW
------------------
--telemetry etw creates a unique file-mode session before the operation,
captures while it runs, waits for the requested tail, stops that session,
then consumes the ETL with OpenTrace/ProcessTrace and TDH.
This is raw ETW collection, not Event Log scraping and not live console
streaming. No kernel trace or WFP filters/callouts are installed.

Provider selection follows the module:
  Defender exclusions:
    Microsoft-Windows-WMI-Activity
      {1418ef04-b0b4-4623-bf7e-d74ab47bbdaa}
    Microsoft-Windows-Windows Defender
      {11cd958a-c507-4ef3-b3f2-5fd9dfbd2c78}
  Firewall rules/profiles:
    Microsoft-Windows-Windows Firewall With Advanced Security
      {d1bc9aff-2abf-4d71-9146-ecb2a986eb85}
Providers use verbose level 5, all match-any keywords and no match-all keywords.
Provider enable success does not guarantee event emission.

Example, without a rule mutation:
  wtf.exe firewall profiles --telemetry etw --telemetry-wait 5

ETW requires suitable tracing permissions, commonly elevation. If session
startup fails or none of the module's providers enables, the operation does
not run (exit 4). There is no fallback. Partial provider coverage is reported.
After the operation starts, telemetry failures do not replace its exit code.

ETL location:
  %LOCALAPPDATA%\WinTraceForge\Traces\<run-id>\capture.etl
ETLs may contain other processes' activity from the selected providers.
Post-capture correlation is not a capture-time process filter.
Protect ETLs as sensitive evidence; they are not automatically deleted.

Bounds: 32 MB sequential file; 120-second safety timer; 10,000 decoded
provider events; 64 top-level fields per event. Scalar fields are decoded
with TDH. Unsupported arrays/structures, missing schemas, parse failures,
callback failures and event/buffer losses are explicitly reported.
The default view shows up to 3 candidates; --verbose expands candidates
within the cap. Shortened fields are marked. ETW sequence numbers are not
Windows Event Log Record IDs. Header PID is the emitter, not necessarily
the WMI ClientProcessId or the process that requested a rule change.
Activity IDs are observed values, not synthesized attribution.

Only the tool-owned session is stopped on normal completion, handled errors,
Ctrl+C and the safety timeout. Abrupt process termination/power failure can
prevent cleanup. An authorized administrator may inspect the exact printed
session name and stop only that owned session:
  logman stop "WinTraceForge-<run-id>" -ets
Never stop unrelated tracing sessions.

Assessment and response
-----------------------
Operation outcome, telemetry completeness, compliance and detection/response
are separate conclusions. Local events do not establish SIEM/EDR alerting,
analyst triage or response. Readback is a point-in-time configuration
observation, not a functional protection test.
Preserve before/after configuration, command, ID, UTC window, host, user,
PID, binary hash and record/channel IDs. Compare with an approved change
record and expected policy. Validate alert ingestion and response separately.
For unauthorized changes, preserve evidence and follow the incident playbook.
For cleanup, remove only the explicitly marked test rule or test-created
exclusion; never broadly reset the firewall or wipe existing configuration.

Exit codes:
  0 confirmed/read-only/help/idempotent absence where documented
  1 operation error or safety refusal
  2 invalid command/arguments
  3 unconfirmed/missing expected configuration
  4 ETW setup failed before any control operation
Consult per-module help for operation-specific absence behavior.

Build
-----
Use an x64 Visual Studio developer terminal with the Windows SDK installed.
Native:
  cl /nologo /LD /O2 /MT /W4 /WX /EHsc /std:c++17 src\WinTraceForge\native\WinTraceForge.Native.cpp src\WinTraceForge\native\WinTraceForge.Etw.cpp src\WinTraceForge\native\WinTraceForge.Firewall.Native.cpp /link /OUT:WinTraceForge.Native.dll wbemuuid.lib ole32.lib oleaut32.lib advapi32.lib tdh.lib
Managed:
  "%WINDIR%\Microsoft.NET\Framework64\v4.0.30319\csc.exe" /nologo /target:exe /platform:x64 /optimize+ /warn:4 /warnaserror+ /reference:System.Management.dll /main:WinTraceForge /out:wtf.exe src\WinTraceForge\managed\WinTraceForge*.cs

Reproducible build/test entrypoint (included source, no downloads):
  powershell -NoProfile -File .\Build.ps1 -Test
  powershell -NoProfile -File .\Build.ps1 -Integration
The script finds Visual Studio x64 C++ tools with vswhere, or accepts
-VcVarsPath, and builds into .\build (override with -OutputDirectory).
-Test runs managed parser, ownership/race/readback and telemetry regressions
using fake backends. -Integration also runs actual read-only Windows checks,
detached COM rule preparation, native ABI tests and a private ETW roundtrip.
Neither mode invokes persistent Defender Add or Firewall Add/Remove.
Non-admin refusal checks are skipped under an elevated token. Event channel
access/ETW permissions can affect integration observations; they are reported.
The tests directory contains all regression/integration sources rather than
only assertion counts. No proprietary test harness is required.
The included GitHub Actions workflow runs Build.ps1 -Test on Windows.

Validation limits
-----------------
The regression suite builds optimized x64 managed and native binaries with
warnings treated as errors. Mutation workflows use fake backends for ownership,
collision, readback and cleanup behavior. Add-boundary tests inject a fake
INetFwRules collection around a detached rule, checking NULL defaults, ports
and HRESULT propagation without writing to the persistent Windows collection.

Integration checks exercise actual read-only Defender and Firewall routes,
detached TCP/UDP rule preparation, native ABI/codec behavior, and a private ETW
provider-to-ETL round trip. Development checks never invoke Defender Add or
Firewall Add/Remove. Assertion counts and read-only snapshots can vary with the
host, installed rules, token elevation, event-channel access and ETW permissions;
each runner reports its own results.

Successful production-provider ETW collection, authorized live mutations and
packet enforcement must be validated separately in the intended environment.
Access-denied and unavailable-provider paths are reported explicitly.

References
----------
https://learn.microsoft.com/en-us/windows/win32/api/netfw/nn-netfw-inetfwpolicy2
https://learn.microsoft.com/en-us/windows/win32/api/netfw/nn-netfw-inetfwrule
https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4946
https://learn.microsoft.com/en-us/defender-endpoint/troubleshoot-microsoft-defender-antivirus
