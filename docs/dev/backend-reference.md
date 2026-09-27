# Backend and interop reference

[Developer docs](README.md) | [Control lifecycle](control-lifecycle.md)

This reference describes backend behavior and implementation constraints. For command syntax and operator guidance, see the [user docs](../user/README.md).

## Defender preference transports

Defender AV exclusions and ASR are separate modules targeting `MSFT_MpPreference`. The `management` route uses `System.Management`; `com` uses COM Automation through `SWbemLocator` / `SWbemServices`; `native` uses P/Invoke to native C++ `IWbemLocator` / `IWbemServices::ExecMethod`. There is no fallback between routes.

Both readback and schema validation must stay independent of the write return code. Missing WMI status is ambiguous, known nonzero status remains an error, and batch writes are not transactional. Defender exclusion Add preserves existing values and requires manual restoration of newly introduced entries only.

## ASR rule schema and behavioral verification

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
(Block, or Warn's default block-with-user-override behavior) that should
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

## Firewall transports and native property semantics

Routes (supported on rule add/check/remove and profiles):

```text
  --transport com (default)
    C# COM interop -> INetFwPolicy2 / INetFwRule3 -> Windows Firewall
  --transport native
    C# P/Invoke -> native C++ typed SDK INetFwPolicy2 / INetFwRule3
    -> Windows Firewall
  --transport management
    System.Management -> WMI root\StandardCimv2 MSFT_NetFirewallRule
    -> Windows Firewall
```

The native DLL performs policy/rule enumeration, property access, detached
rule preparation and Add/Remove; it does not delegate these to C# reflection.
com and native use the same Windows Firewall COM management interfaces and
ownership schema; management targets the separate WMI Firewall provider
PowerShell's New-NetFirewallRule/NetSecurity module wraps (MSFT_NetFirewallRule
plus its per-rule MSFT_Net*Filter associations). All three read/write the
same persisted rule store and share the same ownership schema and readback
comparison (FirewallModule.Mismatches), so a rule added by one transport can
be checked/removed with any other. This compares caller implementations, not
different policy engines. It is not a WFP API test or proof
of different detection.

MSFT_NetFirewallRule does not expose address/port/program/service scoping as
flat instance properties the way INetFwRule3 does; the provider derives the
per-rule filter associations from named values passed through the WMI call
context at Put() time (the documented "Firewall WMI Provider Extended
Syntax"). Because those filter instances do not exist until a real Put()
persists them, management's PrepareAdd can only pre-validate the rule's
direct properties (name/group/description/enabled/direction/action/profiles)
before Add; full attribute verification, including address/port/program,
relies on the shared post-Add Verify() readback every transport already goes
through. management always creates rules with no interface, local/remote-user
or remote-machine restriction and edge traversal Block, matching the fixed
defaults com/native use, and reports LocalPolicyModifyState from the
WindowsFirewall Group Policy registry keys (AllowLocalPolicyMerge /
AllowLocalIPsecPolicyMerge) since MSFT_NetFirewallRule/-Profile expose no
direct equivalent to INetFwPolicy2.LocalPolicyModifyState; it never reports
2 (INBOUND_BLOCKED).

management looks a rule up by ElementName, never InstanceID. A rule created
through com/native's HNetCfg.FWRule gets an opaque, provider-generated
InstanceID (confirmed live, e.g. {7310AAE3-...}), with the netfw Name property
surfaced only in ElementName; querying by InstanceID silently finds zero rows
for such a rule. Add leaves InstanceID unset (matching New-NetFirewallRule's
own optional-InstanceID behavior) instead of assigning it, so a
management-created rule's identity behaves like every other rule rather than
depending on a caller-supplied key being honored. One consequence: Put's
CreateOnly option only rejects a literal InstanceID collision, so with
InstanceID left unset it no longer guards against two rules sharing an
ElementName; duplicate-name protection rests entirely on the same
non-atomic, application-level baseline/preflight checks com/native already
use. Verified live in both write directions (management-created rules read
and removed via com/native, and com/native-created rules read and removed
via management), with no rule left behind in either direction.

management's rule readback refuses (FirewallReadbackUnsupportedException)
rather than silently reports a rule whose MSFT_NetNetworkLayerSecurityFilter
sets Authentication, Encryption, or OverrideBlockRules: this transport never
sets those when creating a rule (SecureFlags always reads back as 0), so a
rule that actually requires them would otherwise show a false, unrestricted
security state on check and could mask a real mismatch after Add.

management's profiles command explicitly queries MSFT_NetFirewallProfile with
PolicyStore=ActiveStore rather than the default (unspecified) store, which is
the local/persistent configuration, not the GPO-merged effective policy --
confirmed live: on a domain-managed host, the default query returned
DefaultInboundAction/AllowInboundRules as NotConfigured while an explicit
ActiveStore query resolved the same profile to the real effective values.
INetFwPolicy2 (com/native) always reports the effective policy; reading the
default store here would have silently diverged from com/native on any
GPO-managed host, even though the built-in-default fallback this module still
carries (for the tri-state values ActiveStore itself should never actually
return) happened to coincide with an unmanaged host's real values.

Optional-property construction:

```text
  Protocol is set before any explicitly requested port restriction.
  Omitted ports are left at the TCP/UDP object's default rather than setting
  a wildcard string; readback can legitimately display "*" for those ports.
  Omitted ApplicationName/ServiceName are left unset, preserving the native
  NULL BSTR defaults instead of assigning allocated empty strings.
  Explicit program paths and port restrictions are still set and read back.
```

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
and management do not require the DLL unless --telemetry etw is selected.
--transport cim/wmi are not recognized aliases for management and are rejected.

## Telemetry profiles and native ABI

Architecture: each control module explicitly supplies a TelemetryProfile
with event-log channels, ETW provider descriptors, evidence-value selection
and a correlator. Collectors consume this profile, not a Defender-versus-
everything-else branch. Adding a control family requires its own explicit
profile/correlator; unknown families never inherit Firewall telemetry.
The native ETW v2 ABI takes a validated list of 1..16 unique nonempty provider
GUIDs, not a module number. Per-provider enable status and event/loss/decode
limits are preserved. Older ETW DLLs fail explicitly with no fallback.

Event Log payload parsing reads EventData and UserData from XML with DTDs disabled. Capture/decoding bounds and operator attribution limits are documented in the [telemetry guide](../user/telemetry.md).

## Platform references

- [INetFwPolicy2](https://learn.microsoft.com/en-us/windows/win32/api/netfw/nn-netfw-inetfwpolicy2)
- [INetFwRule](https://learn.microsoft.com/en-us/windows/win32/api/netfw/nn-netfw-inetfwrule)
- [Security event 4946](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4946)
- [Defender Antivirus troubleshooting](https://learn.microsoft.com/en-us/defender-endpoint/troubleshoot-microsoft-defender-antivirus)
- [ASR rules reference](https://learn.microsoft.com/en-us/defender-endpoint/attack-surface-reduction-rules-reference)
- [ASR deployment and testing](https://learn.microsoft.com/en-us/defender-endpoint/attack-surface-reduction-rules-deployment-test)
