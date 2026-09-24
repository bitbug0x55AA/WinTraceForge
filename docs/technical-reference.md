WinTraceForge (WTF) technical reference
=======================================

Requirements and scope
----------------------
Windows x64, .NET Framework 4.8+, and the relevant Windows control services.
Keep `wtf.exe` and `WinTraceForge.Native.dll` together.
Use only in an authorized test environment.

Control modules:
  wtf.exe defender exclusion ...
  wtf.exe defender asr status|exclusion|rule|verify ...
  wtf.exe firewall rule add|check|remove ...
  wtf.exe firewall profiles ...

Defender exclusions, Attack Surface Reduction (ASR) and Firewall rules are
independent modules. They share CLI conventions, console presentation,
telemetry lifecycle and evidence parsing. Firewall requests are not passed
through Defender exclusion APIs, and ASR requests are a separate module from
Defender exclusions even though both target MSFT_MpPreference.
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

Defender Attack Surface Reduction (ASR)
---------------------------------------
  wtf.exe defender asr status
  wtf.exe defender asr exclusion [--check] -Path VALUE [VALUE ...]
  wtf.exe defender asr rule --check -RuleId GUID
  wtf.exe defender asr rule -RuleId GUID -Action Block|Audit|Warn|Disabled
  wtf.exe defender asr verify -RuleId GUID [--check] [-TestCommand PATH -TestArguments "..."]

Only --transport management is implemented (System.Management -> WMI ->
MSFT_MpPreference); com/native are not implemented for this module and are
rejected rather than silently falling back.

`status` and every `--check` are read-only and never require elevation.
`status` lists every rule found in AttackSurfaceReductionRules_Ids/_Actions
plus a small best-effort set of well-known rule GUIDs shown as NotConfigured
when absent (unrecognized GUIDs are still fully supported; only the display
name is best-effort), each rule's policy source, the ASR-only (global)
exclusion list (AttackSurfaceReductionOnlyExclusions), and a cross-reference
against ordinary Defender antivirus exclusions, since those also widen the
effective ASR exception surface. Policy source classifies each rule/exclusion
list as Local or GroupPolicy by checking the corresponding registry key under
HKLM\SOFTWARE\{Policies\,}Microsoft\Windows Defender\Windows Defender Exploit
Guard\ASR; Intune/MDM-applied settings and Windows Security app defaults that
populate neither key are reported as Unknown, not misclassified as Local.

MSFT_MpPreference hides exclusion-list content (both AttackSurfaceReduction-
OnlyExclusions and the four ordinary AV exclusion fields) from a
non-administrator caller by returning a single sentinel string instead of
real array data; rule configuration itself is not gated this way. The tool
detects that sentinel and reports "could not observe", never a false empty
or absent result. Re-run elevated for a real reading of exclusion content.

`exclusion` mirrors `defender exclusion`, with one deliberate difference:
-Path is required for --check too, not only for a real Add. Unlike
`defender exclusion`, a bare --check here has no distinct "capabilities"
report of its own, and `status` already gives a full read-only exclusion
listing, so a --check with no path would only ever produce a content-free
"passed" that checked nothing. --check reads
AttackSurfaceReductionOnlyExclusions without writing; otherwise it calls Add
and verifies by readback. Administrator is required for a real Add. A
non-administrator's --check that hits Defender's exclusion-visibility
sentinel (see above) is reported unconfirmed (exit 3), never a false
CHECK_ONLY success over content it could not actually see. The printed
cleanup command names only the path(s) that were NOT already present in the
captured baseline -- a request that mixes a genuinely new path with an
already-existing (possibly organizational) one never tells the operator to
remove the pre-existing one -- and gives the exact
`Remove-MpPreference -AttackSurfaceReductionOnlyExclusions ...` command,
since this module only ever calls Add and cannot remove an entry itself.

`rule` reads or sets one rule's action via AttackSurfaceReductionRules_Ids/
_Actions Add; administrator is required for a real Add. The real
AttackSurfaceReductionRules_Actions property is a UInt8Array, not UInt32 --
Add-MpPreference's own action values are byte-sized (Disabled=0, Enabled=1,
AuditMode=2, NotConfigured=5, Warn=6); the tool's WMI property-type check is
schema-driven per property rather than assuming one numeric width for all of
them. Mutation is RestorationPolicy.Manual (persistent Defender policy, same
rationale as Defender exclusions): the printed cleanup command restores the
captured pre-run action, using the real NotConfigured (5) action value when
the rule was previously unconfigured, so restoration is always an executable
`defender asr rule -Action ...` command, never a separate Remove-MpPreference
step. Whether requesting NotConfigured leaves Defender with an explicit
(guid, 5) entry or removes it entirely has not been observed either way, so
readback treats both as an equally valid Confirmed result rather than
requiring one specific representation -- Microsoft documents both as
functionally unconfigured.

`verify` is the module's behavioral-verification primitive and does not
require elevation, since ASR enforcement is not conditioned on the caller's
privilege. It ships exactly one built-in primitive, explicitly marked
EXPERIMENTAL in its own output: a benign script marked Internet-zone (a
Zone.Identifier alternate data stream with ZoneId=3, simulating "downloaded"
content, written via a direct P/Invoke of CreateFileW because the managed
File APIs reject alternate-data-stream paths under this build's legacy path
handling) and run via wscript.exe //B, whose only effect is launching
notepad.exe, targeting the "Block JavaScript or VBScript from launching
downloaded executable content" rule (D3E037E1-3EB8-44C8-A917-57927947596D).
Whether this specific primitive actually triggers that rule (Block ->
observed event 1121) has not been confirmed in any environment; a Mismatch
result may mean the primitive simply never engages the rule, not that
protection failed, and the tool says so in its own Mismatch output rather
than only in --help. Any other rule requires an authorized -TestCommand (and
optional -TestArguments) supplied by the caller; the tool does not fabricate
additional attack-shaped payloads.

It captures the rule's action as a baseline, runs the primitive, and checks
whether a child process appeared, identified by Windows' own ParentProcessId
(not merely "some process with the same name started recently", which could
belong to the user or an unrelated task) and, for the enforcement decision
specifically, matched to the expected image name; a candidate must also have
been created no earlier than the launcher itself. This check is read-only (a
WMI query): `verify` never terminates a process during Verify, only during
Restore. Local process-presence evidence can only ever support one
unambiguous conclusion: the primitive's payload ran despite an action
(Block, or Warn's default block-with-bypass-option behavior) that should
have stopped it, reported Mismatch. Every other combination -- including
absence (ambiguous: WSH disabled, AppLocker/WDAC, a script error, the
primitive not engaging the rule at all, and an actual block are all
indistinguishable this way), Audit (real evidence is event 1122, not process
presence), and Disabled/NotConfigured (presence is simply expected) -- is
reported Unavailable (exit 3); `verify` never reports Confirmed, and directs
the operator to --telemetry etw|eventlog and the correlated 1121/1122
evidence for actual confirmation. A custom -TestCommand has no known
expected child-process signature at all, so its enforcement outcome is
always Unavailable.

Some Windows builds redirect notepad.exe launches to a packaged app via
Image File Execution Options (HKLM\...\Image File Execution Options\
notepad.exe, UseFilter=1, with per-path AppExecutionAliasRedirect=1
subkeys); `verify` detects this and warns explicitly, because the real
launched process may then not appear as a child of the launcher at all --
neither a missing observation nor a reported successful cleanup can be
trusted on such a host, and VerifyRestored reports Unavailable rather than a
false Confirmed whenever this is detected. This still exits 1 like any other
unconfirmed restoration, but the printed outcome is the distinct
CLEANUP_UNVERIFIABLE rather than a generic OPERATION_ERROR, since the
primitive itself ran fine and this is specifically about not being able to
confirm the process tree it may have spawned was fully cleaned up. The same
CLEANUP_UNVERIFIABLE/Unavailable result is also reported whenever the
Win32_Process query itself fails (some hosts restrict WMI process queries);
that query never returning an empty result as a stand-in for "could not ask"
is exactly the "unobserved is not absent" rule this module applies
everywhere else (the exclusion-visibility sentinel, elevation-gated reads).
VerifyRestored also independently re-confirms the launcher process itself
has actually exited (not just that no owned child was found), since a
swallowed exception from a failed Kill could otherwise leave a live launcher
process while still reporting a clean Restoration.

For cleanup, `verify` re-queries for any DIRECT child process of the launcher
(not filtered by expected name -- this also covers a custom -TestCommand's
otherwise-untracked children -- but still only one level deep: a grandchild,
e.g. a launcher that runs cmd.exe which itself runs the real payload, is not
discovered) independently in both Restore and VerifyRestored, rather than
reusing whatever Verify found, so cleanup stays correct even on a path where
Verify never ran. Restore kills the launcher itself before enumerating and
killing its children, not after: were the launcher killed last, it could
still spawn a new, unaccounted-for child in the gap between listing children
and terminating it. Before actually terminating a discovered child, it
re-opens the process handle, forces that one native handle to be cached
(touching .Handle) so the same handle is used for the StartTime read, the
identity check and the eventual Kill/WaitForExit, and requires that handle's
own StartTime to match the CreationDate WMI reported when the candidate was
found: killing by a bare PID races with PID reuse (the target can exit and
its PID be reused by an unrelated process between the query and
the kill). Pinning one handle up front and reusing it throughout closes that
window, rather than merely narrowing it -- reading StartTime through a
short-lived, separately-opened handle (the default if .Handle is never
touched) would not. `verify` is this codebase's first real
(non-synthetic) use of RestorationPolicy.Automatic: artifact ownership is
recorded before either write that could still fail, so Restore can always
find and delete whatever was created under
%LOCALAPPDATA%\WinTraceForge\AsrTests\<run-id>\. RestorationStatus reflects
that artifact/process cleanup, not the Defender rule/exclusion state, which
`exclusion`/`rule` still report as ManualRequired when mutated.

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
A reported native Add E_INVALIDARG prompted this correction; the -Test (CI)
suite covers preservation of unspecified NULL defaults at the Add boundary.
NULL BSTR, allocated empty BSTR, a default value and a never-assigned property
are treated as distinct until the target API demonstrates otherwise. Readback
comparison may normalize NULL and "", but rule construction must not.
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

Defender exclusion module:
  Microsoft-Windows-Windows Defender/Operational: 5007 / 5013
  Microsoft-Windows-WMI-Activity/Operational: 5857..5861
Defender ASR module:
  Microsoft-Windows-Windows Defender/Operational: 1121 (rule blocked --
    Block and Warn both raise this by default) / 1122 (rule audited,
    AuditMode only: allowed and logged, not blocked) / 5007 / 5013
  Microsoft-Windows-WMI-Activity/Operational: 5857..5861
Firewall modules:
  Microsoft-Windows-Windows Firewall With Advanced Security/Firewall:
    2004 rule added, 2005 rule modified, 2006 rule deleted
  Security: 4946 rule added, 4947 modified, 4948 deleted
All three also inspect Security 4688 and Sysmon Operational 1 when available.
Security audit events require the appropriate policy and permissions.

Firewall rule correlation requires an exact requested rule name in the event.
It is not enough for an event to mention "Firewall" or a name substring.
ASR correlation matches on the requested rule GUID or exclusion path
substring within an event's fields; an ASR block/audit event that does not
mention the requested value is reported time-only, not a match.
Process-start evidence is separate from rule-change evidence.
Defender exclusion, ASR and Firewall evidence are not interchangeable.
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
  Defender exclusions and Defender ASR (each module owns its own profile
  instance, but both use these same two provider GUIDs):
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
`Build.ps1` compiles C# sources recursively from `src/managed/` and the explicit
C++ sources in `src/native/defender/`, `src/native/firewall/`, and
`src/native/telemetry/`. It also generates version metadata for both binaries.

Reproducible build/test entrypoint (included source, no downloads):
  powershell -NoProfile -File .\Build.ps1 -Test
  powershell -NoProfile -File .\Build.ps1 -Integration
The script finds Visual Studio x64 C++ tools with vswhere, or accepts
-VcVarsPath, and builds into .\build (override with -OutputDirectory).
-Test runs managed parser, ownership/race/readback and telemetry regressions
using fake backends, plus native codec and Firewall Add-boundary tests
(Firewall.Native.CppTests.exe --deterministic) that never open firewall policy.
-Integration also runs actual read-only Windows checks, detached COM rule
preparation, the remaining native ABI tests and a private ETW roundtrip.
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

References
----------
https://learn.microsoft.com/en-us/windows/win32/api/netfw/nn-netfw-inetfwpolicy2
https://learn.microsoft.com/en-us/windows/win32/api/netfw/nn-netfw-inetfwrule
https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4946
https://learn.microsoft.com/en-us/defender-endpoint/troubleshoot-microsoft-defender-antivirus
https://learn.microsoft.com/en-us/defender-endpoint/attack-surface-reduction-rules-reference
https://learn.microsoft.com/en-us/defender-endpoint/attack-surface-reduction-rules-deployment-test
