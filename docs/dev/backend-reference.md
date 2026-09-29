# Backend and interop reference

[Developer docs](README.md) | [Control lifecycle](control-lifecycle.md)

This reference describes backend behavior and implementation constraints. For command syntax and operator guidance, see the [user docs](../user/README.md).

## Defender preference transports

Defender AV exclusions and ASR are separate modules targeting `MSFT_MpPreference`. The `management` route uses `System.Management`; `com` uses COM Automation through `SWbemLocator` / `SWbemServices`; `native` uses P/Invoke to native C++ `IWbemLocator` / `IWbemServices::ExecMethod`; `powershell` invokes System32's own `powershell.exe` and drives the `ConfigDefender` module's own `Add-MpPreference`/`Get-MpPreference` cmdlets (module-qualified as `ConfigDefender\Add-MpPreference` etc., so a same-named function or alias earlier on the path cannot shadow them), which are themselves a thin wrapper over the same `MSFT_MpPreference` class. There is no fallback between routes.

Both readback and schema validation must stay independent of the write return code. Missing WMI status is ambiguous, known nonzero status remains an error, and batch writes are not transactional. Defender exclusion Add preserves existing values and requires manual restoration of newly introduced entries only.

`powershell` never has a WMI return code to inspect at all: `Add-MpPreference` is a void cmdlet, so a successful Add always yields `MutationStatus.ApiUnknown` and falls back to readback, the same path the other three transports take whenever the underlying WMI call itself returns no usable status; a script that ends without either its `WTF_ADD_OK` or `WTF_ADD_ERROR` marker (e.g. torn down externally, after the cmdlet may already have run) is treated the same way rather than as a known failure, since only an explicit error marker means the cmdlet itself actually rejected the request.

`powershell.exe` is resolved by absolute path (`%SystemRoot%\System32\WindowsPowerShell\v1.0\powershell.exe`, via `Environment.SystemDirectory`), not a bare `"powershell.exe"` name: with `UseShellExecute=false`, .NET calls `CreateProcess` with `lpApplicationName=NULL`, whose search order checks the launching EXE's own directory and the current working directory before `PATH`, so a bare name would let a same-directory- or cwd-planted `powershell.exe` run instead of the real one (every Add path already requires an administrator token, so that substitute would run elevated). The child process' `PSModulePath` environment variable is also overridden to only the system module directory (`PowerShellRunner.TrustedModulePath`): module-qualifying a call as `ConfigDefender\Add-MpPreference` only guards against a same-named function or alias in the caller's own scope, never against the `ConfigDefender` module itself being resolved from a different path, and a per-user `PSModulePath` entry is writable by that same non-elevated user (confirmed live: a fixture module planted on a widened `PSModulePath` is discoverable by an unrestricted child process, but invisible to one launched through `PowerShellRunner.RunScript`).

That restriction is applied by temporarily overriding `wtf.exe`'s own `PSModulePath` immediately before `Process.Start` and restoring it immediately after (the child only reads the variable once, at its own startup), not by setting `ProcessStartInfo.EnvironmentVariables["PSModulePath"]`. `RunScript` deliberately never touches that property at all: its first access unconditionally copies the entire current-process environment into a case-insensitive `StringDictionary` (lowercasing every key before insertion), and on a minority of real hosts the raw environment block already contains two case-variant entries for the same variable (observed in practice for `Path`/`PATH`, typically left behind by a third-party `PATH`-manipulating tool or shell integration) -- `CreateProcess` and `GetEnvironmentVariableW` are case-insensitive and tolerate this, but that `StringDictionary` copy is not and throws `ArgumentException` on the very first touch, before `PSModulePath` is ever set. On such a host `Connect()` failed for both `defender exclusion --check` and `defender asr status`, with `powershell.exe` never launched at all. Avoiding the property entirely sidesteps this: when it is never accessed, `Process.Start` passes `CreateProcess` a `NULL` environment block, so the child simply inherits `wtf.exe`'s real, current environment as-is, including the temporary override.

The script itself is passed via `-EncodedCommand` (Base64 UTF-16LE), never written to a temp file first: earlier revisions wrote the script (and per-value files) under a fresh `%TEMP%\WinTraceForge-ps-<guid>\` directory and invoked `powershell.exe -File`, which left a window between that write and `powershell.exe` reading it back for another process running as the same non-elevated user to overwrite the file before the elevated process read it. `-EncodedCommand` removes the temp directory, the per-value files, and that race entirely -- there is nothing on disk for another process to find or overwrite. Its underlying command line is capped at 32,768 UTF-16 characters by Windows itself, so `PowerShellRunner.RunScript`/`ValidateScriptLength` rejects an oversized script/value payload (`MaxScriptLength`, checked in original-character count with a wide margin) with a clear message rather than letting `CreateProcess` fail cryptically. Both `Add()` implementations build and length-validate their script inside `Prepare()` (during Probe), not inside `Add()` itself: an oversized request must fail before `evidence.AddAttempted` is ever set, so the lifecycle reports `Mutation=NotAttempted` rather than misreporting an oversized request `powershell.exe` never even ran as `MutationStatus.ApiFailed`.

Every value that could ever contain caller-supplied or non-ASCII content -- exclusion values, ASR-only exclusions, error messages, readback results -- is Base64-encoded end to end (`PowerShellRunner.EncodeValue`/`DecodeValue`) rather than passed as raw text. Values going *into* a script (`PowerShellRunner.EncodeValuesExpression`) are embedded directly as literal Base64 strings in the script text itself -- e.g. `(@('<b64>','<b64>') | ForEach-Object { ... })` -- never through a side-channel file: Base64's alphabet (`[A-Za-z0-9+/=]`) contains no quote character, so each value sits inside a single-quoted literal with no escaping needed at all. Every value a script emits on stdout is likewise Base64-encoded before `Write-Output`. This is not merely about avoiding script-injection-style escaping: without it, a value containing an embedded `\r`/`\n` would be split across multiple lines -- and therefore multiple exclusions -- by any line-oriented channel, and raw non-ASCII text is vulnerable to OEM/ANSI/UTF-8 codepage mismatches between the script, `Get-Content`'s encoding guess, and captured stdout. Base64 sidesteps both, since its output is pure ASCII with no embedded line breaks regardless of the original byte content. (One residual gap: a value containing an unpaired UTF-16 surrogate cannot be represented as valid UTF-8 at all; rather than let it be silently replaced with U+FFFD, `CommonArguments.HasUnpairedSurrogate` rejects such a value at CLI-parse time, identically for every transport, not just `powershell`.)

`Read()` never lets an incomplete or failed script pass for an empty snapshot: `PowerShellRunner.BuildReadScript` asserts `@(ConfigDefender\Get-MpPreference).Count -eq 1` and that each requested field actually exists on the returned object (`$pref.PSObject.Properties[$field]`) before reading it, wrapped in `try`/`catch` with `$ErrorActionPreference = 'Stop'`; only a script that reaches its own `WTF_READ_OK` marker is treated as having actually completed, and any other outcome -- an explicit `WTF_READ_ERROR`, a nonzero exit with neither marker, or a process that never produced one -- throws rather than returning whatever partial output was captured. This is the same "unobserved is not absent" invariant `BuildSnapshot`/`RequireSingleInstance` enforce for every other transport; unlike those, a broken PowerShell/Defender environment (a stopped Defender service, third-party AV interference) reaches this transport as a `Get-MpPreference` non-terminating error rather than a `ManagementException`/`COMException`, so it needed its own explicit guard rather than inheriting one from a shared WMI code path.

Each field's values are emitted with a bare `foreach ($v in $pref.<field>) { ... }`, deliberately never guarded by `if ($pref.<field>) { foreach ... }`: PowerShell's truthiness of a one-element array is the truthiness of that single element, so a one-element array holding a falsy value would vanish from the output entirely under such a guard. `AttackSurfaceReductionRules_Actions` is a `UInt8Array` whose real `Disabled` value is the byte `0` -- a falsy single-element array is exactly what a test machine with only one ASR rule configured, set to `Disabled`, produces. A bare `foreach` over `$null` already iterates zero times (PSv3+); `@($pref.<field>)` must not be used as a substitute, since `@($null)` produces a one-element array containing `$null`, not an empty one.

Each field's value is cast to `[string]` before Base64-encoding, except for names passed in `BuildReadScript`'s `integerFields` set (currently only `AttackSurfaceReductionRules_Actions`), which are cast `[string][int]$v` instead: if some Defender build ever surfaces that field as an enum-backed type rather than a plain byte, a bare `[string]` cast would read back that enum member's *name* (e.g. `"Disabled"`), which `AsrModule.DecodeUInt32Array` cannot parse, rather than the numeric value it expects. This only affects the ASR backend; every Defender exclusion field is a plain string and is never cast via `[int]` (`Read()` passes `null` for `integerFields`).

Add()'s script result is classified purely from its own explicit markers (`PowerShellRunner.ClassifyAddResult`), never the bare process exit code: `Add-MpPreference` is a void cmdlet, so a successful Add always yields `MutationStatus.ApiUnknown` and falls back to readback, the same path the other three transports take whenever the underlying WMI call itself returns no usable status; a script that ends without either its `WTF_ADD_OK` or `WTF_ADD_ERROR` marker (e.g. torn down externally, after the cmdlet may already have run) is classified `Unknown` and treated the same way as a missing status code, rather than as a known failure, since only an explicit error marker means the cmdlet itself actually rejected the request. `Add()` also prints `stderr`/`stdout` detail alongside its `Unknown`-outcome warning, since that is often the only evidence of *why* -- an AMSI or execution-policy block, for example, writes its reason there.

`Supports(name)` reflects the `ConfigDefender` module's own `Add-MpPreference` parameter metadata (`(Get-Command ConfigDefender\Add-MpPreference).Parameters.ContainsKey(name)`) rather than the WMI class schema `management`/`com`/`native` inspect directly; in practice the module's cmdlet parameters mirror the same provider on a given build, but this is a different (client-side) capability check than the other three transports perform, worth keeping in mind when comparing `Supports()` results across transports. Only `ConfigDefender` is recognized (not the older `Defender` module some builds also carry); on a build where only the latter exists, `Connect()` fails explicitly (module unavailable) rather than silently guessing which one to use.

`Read()` uses a disposable, per-call marker-delimited text protocol (`WTF_BEGIN_<marker>:<field>` / `WTF_END_<marker>:<field>`) rather than JSON, since the codebase has no JSON library reference; a fresh GUID marker per call rules out a value colliding with the literal delimiter text, and every value line between a `BEGIN`/`END` pair is itself Base64-encoded.

This transport changes what a detection stack actually observes, not merely which client library is used: it introduces a `powershell.exe` process image, a `-EncodedCommand` command line, and everything PowerShell's own AMSI/script-block-logging surfaces do or do not capture, none of which the other three transports produce. Comparing detections across transports therefore compares these differences too, not the "same API call over a different wire" comparison `com`/`native`/`management` give each other -- treat a difference in observed telemetry between `powershell` and the other three as evidence about this process-launch path specifically, not about `MSFT_MpPreference` itself. If AMSI or an EDR blocks the script, this surfaces as an ordinary `Connect()`/`Add()`/`Read()` failure (module unavailable, or an unmarked nonzero exit, now with its `stderr`/`stdout` detail surfaced) with no distinct signal that a security product specifically intervened. The child `powershell.exe` process' PID is not recorded and does not participate in this tool's own PID-based telemetry correlation (`ClientProcessId`/`NewProcessId` in a WMI-Activity, 4688 or Sysmon event reflects the child, not `wtf.exe`'s own `evidence.ProcessId`); correlate this transport's activity manually via timestamp and command line instead.

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
  --transport powershell
    Process -> powershell.exe -> New-/Get-/Remove-NetFirewallRule
    (NetSecurity module) -> WMI root\StandardCimv2 MSFT_NetFirewallRule
  --transport cmd
    Process -> cmd.exe -> netsh.exe advfirewall firewall add/show/delete rule
    -> Windows Firewall
```

The native DLL performs policy/rule enumeration, property access, detached
rule preparation and Add/Remove; it does not delegate these to C# reflection.
com and native use the same Windows Firewall COM management interfaces and
ownership schema; management and powershell both target the WMI Firewall
provider (MSFT_NetFirewallRule plus its per-rule MSFT_Net*Filter
associations), management directly and powershell through the NetSecurity
module's own cmdlets, which are a thin wrapper over the identical provider
(confirmed live: casting a filter/rule CIM-enum property to `[int]` yields the
identical raw WMI value PowerShellFirewallBackend and ManagementFirewallBackend
both decode). com, native, management and powershell read/write the same
persisted rule store and share the same ownership schema and readback
comparison (FirewallModule.Mismatches), so a rule added by one of these four
transports can be checked/removed with any other. cmd instead shells to
netsh.exe, the last of the classic text-oriented Windows Firewall surfaces;
see its own subsection below for the two real limits that make it not fully
interchangeable with the other four. This compares caller implementations,
not different policy engines. It is not a WFP API test or proof of different
detection.

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

powershell reuses ManagementFirewallBackend's raw-value codecs/normalizers
(AnySentinel, ProtocolNumber/-Name, RuleActionFromRaw/-ToRaw,
RuleEnabledFromRaw/-ToRaw, ResolveGpoBoolean/-ProfileAction, FirstOrAny,
NoneIfAny, FilterUnconfiguredSentinel, NetworkCategoryToProfileBit) rather
than re-deriving them, and DefenderModule.PowerShellRunner's process-execution
hardening (absolute powershell.exe path, restricted PSModulePath,
-EncodedCommand, Base64-encoded values) rather than duplicating it -- the same
reuse pattern PowerShellRunner and ComObjects already establish for
AsrModule's own PowerShell/COM backends. New-NetFirewallRule has no
WMI-ReturnValue equivalent to check, so a successful Add always falls through
to the shared post-Add readback for confirmation, exactly like Defender's
powershell transport. FindByName pipes each matched rule through
Get-NetFirewallAddressFilter/-PortFilter/-ApplicationFilter/-ServiceFilter/
-InterfaceTypeFilter/-InterfaceFilter/-SecurityFilter (the cmdlet equivalent
of ManagementFirewallBackend.RequireOneRelated's GetRelated calls) and applies
the identical "exactly one of each filter kind, or refuse" invariant.

cmd shells to netsh.exe's `advfirewall firewall`/`advfirewall` context. Several
real, verified limits, not implementation shortcuts:

```text
  netsh advfirewall firewall add rule has no group=/grouping= parameter
  (checked against Microsoft's own documented parameter list). A cmd-created
  rule can never carry this tool's Grouping marker the way the other four
  transports do. FirewallModule.ExpectedGrouping returns "" instead of Group
  only for --transport cmd, and RequireOwnedUnique/Mismatches compare against
  that instead -- so a cmd-created rule's ownership rests on Name+Description
  alone. The other four transports correctly refuse it as a Grouping
  mismatch, and cmd itself correctly refuses a rule created by any of the
  other four (it cannot prove a marker it never wrote, in either direction --
  CrossTransportOwnershipRefusal in the regression suite pins both).
  add rule also has no "any" keyword documented for program= (unlike
  localport=/remoteport=, which do document "any"): BuildAddCommand omits
  program= entirely for an unrestricted rule rather than sending the literal
  text "any" as a path, matching com/management's own "preserve unspecified
  defaults" behavior (CmdAddCommandOmitsProgramWhenUnset pins this).

  Readback parses the fixed-column text of "netsh advfirewall firewall show
  rule ... verbose" and "netsh advfirewall show allprofiles/currentprofile",
  not a typed API -- inherently more fragile (locale- and Windows-version-
  sensitive label text) than the other four transports. ParseShowRuleBlocks
  refuses outright (FirewallReadbackUnsupportedException) on any label it
  does not have in its known-label set (verified against a live sweep of
  every one of 380 distinct real rule names on a development host: 229
  decoded, 46 came back empty by MUI-name mismatch -- see below -- and 81+24
  hit an already-documented refusal, none an unhandled exception type), and
  DecodeShowRuleBlock separately refuses a comma-joined ("multi-value")
  RemoteIP the same way management/powershell's FirstOrAny already does,
  rather than accepting the raw joined text as a single value.

  ExcludedInterfaces reads back as the literal string "not available (cmd)",
  not an empty array: netsh exposes no such field via any show command, and
  ReadProfiles is purely diagnostic display (never compared against an
  expected value), so this cannot affect ownership/verification.
  LocalAppPackageId/LocalUserOwner and the three authorized-user/-machine
  list fields are hard-coded to "" for the same structural reason (no
  corresponding netsh text field exists at all, not merely an "Any"
  sentinel) -- correct for this tool's own rules (which never request such a
  restriction) but means a check via cmd cannot prove the *absence* of one
  of these restrictions on a third-party rule.

  Confirmed live: netsh advfirewall show store reports "Policy Store: Local"
  by default, with no netsh command found to select the GPO-merged/
  ActiveStore equivalent com/native (always effective) and
  management/powershell (both explicitly request PolicyStore=ActiveStore)
  read. ReadProfiles's Enabled/BlockAllInbound/DefaultInboundAction/
  DefaultOutboundAction can therefore diverge from the other four transports
  on a GPO-managed host -- the same failure mode ManagementFirewallBackend's
  own ActiveStore fix was written to avoid, but with no netsh-level fix
  available here. This affects only the read-only `firewall profiles`
  command; CurrentProfiles (live network-category membership, not a
  GPO-overridable setting) and add/check/remove are unaffected.

  Confirmed live: a rule with Profiles raw WMI value 0 ("Any"/unset,
  distinct from an explicit Domain|Private|Public=7) and one with raw value
  7 are textually indistinguishable in netsh's output (both show
  "Domain,Private,Public") -- immaterial for this tool's own rules, which
  always request an explicit nonzero mask and so are never actually stored
  as the raw-0 sentinel, but a genuine fidelity gap for a third-party rule
  read through this transport.

  Confirmed live: querying show rule by a built-in rule's raw, unresolved
  MUI ElementName (e.g. "@FirewallAPI.dll,-32765") both matches and returns
  the resolved display text ("Network Discovery (UPnP-Out)"); a Program path
  stored with an environment-variable macro (e.g. "%SystemRoot%\...") is
  shown already expanded. Neither affects this tool's own rules (Name is
  always a literal GUID-based string; --program is already required to be
  an absolute, already-resolved path with no '%').

  Mutation ambiguity: unlike a genuinely confirmed script-side error marker
  (powershell's WTF_ADD_ERROR/WTF_REMOVE_ERROR, written only by our own
  try/catch), netsh is an opaque external process whose own nonzero exit or
  missing "Ok." trailer cannot be trusted as a definite rejection -- an
  externally-killed cmd.exe/netsh.exe after the rule was already written
  would look identical. Add()/Remove() therefore return MutationStatus.
  ApiUnknown (warn, defer to the shared post-mutation Verify() readback) in
  that case rather than throwing, exactly like powershell's own handling of
  its "no marker found" case; only a definite invariant violation this
  transport itself detects (e.g. Remove's own immediate re-check finding
  other than exactly one match before the name-based delete, since
  "netsh ... delete rule name=..." has no per-object handle and would
  otherwise remove every match) still throws.
```

netsh's `add rule`/`show rule`/`delete rule` are launched as
`cmd.exe /d /v:off /s /c "<netsh.exe path> <args>"`: `/D` disables AutoRun
(the cmd.exe analogue of PowerShell's `-NoProfile`/`-ExecutionPolicy
Bypass`), `/V:OFF` disables delayed variable expansion for this invocation
regardless of the machine/user `DelayedExpansion` registry default (`/D`
alone only disables AutoRun; with delayed expansion enabled by that separate
setting, an unescaped `!` inside an otherwise-safe quoted value would be
rewritten by cmd.exe before netsh ever saw it), and `/S` is the documented
modifier that makes cmd.exe strip only the single outer quote pair wrapping
the whole netsh invocation, leaving netsh's own inner
`name="..."`/`program="..."` quoting untouched for its own argument parser --
the identical nested-quoting shape Build.ps1's own `Invoke-VcCommand` already
uses for `$env:ComSpec /d /s /c`. Every value embedded in that command line
is additionally checked (CmdFirewallBackend.RequireSafeForCmd) to contain no
`"`, `%`, `!`, or control character before being concatenated in -- `!` as a
second, registry-independent layer on top of `/V:OFF` -- on top of the CLI's
own `--program` validation (FirewallModule.ParseProgram already forbids `"`,
`%`, `*`, `?`). Redirected output is decoded with the OEM codepage
(`CultureInfo.CurrentCulture.TextInfo.OEMCodePage`), not .NET's `Encoding.
Default` (the ANSI codepage): console apps including netsh write redirected
output in the OEM codepage, which differs from ANSI on many Western Windows
installs (e.g. 850 vs 1252) and would otherwise garble a non-ASCII
`--program` path on readback; this tool's own fixed English label text and
GUID-based Name/Description are pure ASCII and unaffected either way.

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
Keep the matching x64 DLL from this package next to the EXE. Firewall com,
management, powershell and cmd do not require the DLL unless --telemetry etw
is selected.
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
