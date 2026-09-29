# Windows Firewall

[User docs](README.md) | [Shared command options](commands.md)

## Inspect profiles

```powershell
.\wtf.exe firewall profiles
.\wtf.exe firewall profiles --transport native
.\wtf.exe firewall profiles --transport management --telemetry eventlog
.\wtf.exe firewall profiles --transport powershell
.\wtf.exe firewall profiles --transport cmd
```

This command reads profile state and exposed policy settings. It does not turn the firewall off, toggle profiles, or change default actions. The output is not a complete GPO/MDM resultant-policy report.

## Select an execution path

| Transport | Path |
| --- | --- |
| `com` (default) | Managed Windows Firewall COM |
| `native` | Native C++ Windows Firewall COM via the matching DLL |
| `management` | Managed WMI Firewall provider |
| `powershell` | `powershell.exe` -> `New-`/`Get-`/`Remove-NetFirewallRule` (NetSecurity module) |
| `cmd` | `cmd.exe` -> `netsh.exe advfirewall firewall add`/`show`/`delete rule` |

com, native, management and powershell all operate on the same persisted rule store and use the same ownership and readback checks; a rule created by one of these four can be checked or removed by another. No route silently falls back. `cim` and `wmi` are not aliases for `management`.

COM and native compare caller implementations of the same Windows interfaces; management and powershell both use the WMI Firewall provider (powershell through its own cmdlets, management directly). This is not a WFP API test or proof of different detection. COM and management do not require the native DLL unless ETW is selected. powershell and cmd shell out to `powershell.exe`/`cmd.exe` from `System32` (no `PATH` lookup); powershell needs the `NetSecurity`/`NetConnection` modules, cmd needs `netsh.exe`.

**cmd is not interchangeable with the other four**, in several confirmed, structural ways:

- `netsh advfirewall firewall add rule` has no `group=`/`grouping=` parameter, so a rule the cmd transport creates can never carry this tool's `Grouping` marker (every other transport can, including powershell, whose `-Group` sets the identical property management writes directly). Ownership for a cmd-created rule therefore rests on Name+Description alone; check/remove it with `--transport cmd` specifically, since the other four transports will refuse it as a Grouping mismatch, and cmd itself will refuse a rule created by any of the other four (it cannot prove the Grouping marker either way).
- cmd's readback comes from parsing the fixed-column text of `netsh advfirewall firewall show rule ... verbose` and `netsh advfirewall show allprofiles`/`currentprofile` rather than a typed API, so it is more sensitive to locale/Windows-version label-text changes than the other transports, and it refuses outright (rather than guessing) on any label or value it does not recognize, including a multi-value address scope the other transports also refuse.
- `netsh advfirewall show store` reports `Policy Store: Local` on this transport by default, with no netsh command found to select the GPO-merged/`ActiveStore` equivalent com/native/management/powershell all read. On a GPO-managed host, `firewall profiles --transport cmd` can therefore show different `Enabled`/inbound/outbound-default values than the other four transports for the identical live policy. This affects only the read-only `profiles` command, not add/check/remove.
- `ExcludedInterfaces` is reported as `not available (cmd)`, not an empty list: netsh exposes no such field via any `show` command, so this is "not observed," not "confirmed none."
- `LocalAppPackageId`/`LocalUserOwner` and the three authorized-user/-machine list fields always read back empty for cmd: netsh's rule output has no corresponding fields at all. This never affects this tool's own rules (which never request such a restriction), but means a `check` via cmd cannot be used to prove the *absence* of one of these restrictions on a third-party rule.
- Matching by name additionally matches (and resolves the display text of) a built-in rule's raw MUI resource-string `ElementName`, and a `%SystemRoot%`-style macro in a `Program` path is shown already expanded — both confirmed live, neither relevant to this tool's own rules.

If you are comparing transports for detection/telemetry purposes, keep in mind cmd's rule content differs from the other four transports' (no `Grouping`) as well as its process path — a telemetry difference could reflect either.

## Add, inspect, and remove a test rule

Run writes from an elevated PowerShell session. Use a unique GUID for each test and retain it:

```powershell
$testId = [guid]::NewGuid().ToString()
.\wtf.exe firewall rule add --id $testId `
  --direction out --action block --protocol tcp `
  --remote-address 192.0.2.10 --remote-port 44443 --profiles private
.\wtf.exe firewall rule check --id $testId
.\wtf.exe firewall rule remove --id $testId
```

If `--id` is omitted on add, the tool generates one. The ID and exact cleanup command are printed before creation; cleanup preserves the selected transport. Choose an approved endpoint; the documentation address above is an example and no traffic is generated.

### Required scope and defaults

- One literal IPv4/IPv6 remote address; hostnames, ranges, and subnets are rejected.
- Outbound rules require `--remote-port`; `--local-port` is optional.
- Inbound rules require `--local-port`; `--remote-port` is optional and refers to the sender's source port.
- Each specified port must be in `1..65535`.

Defaults are outbound, block, TCP, all local addresses, all programs, and no service/interface restriction. Omitted ports retain the object's default and can display `*` on readback. `--program` requires an absolute executable path.

The current active profile mask is frozen before a write unless you specify `--profiles domain,private,public` or `--profiles all`. An invalid/empty active mask refuses the write rather than defaulting to all profiles. Example inbound test:

```powershell
.\wtf.exe firewall rule add --direction in --remote-address 192.0.2.10 `
  --local-port 443 --transport native
```

The same add/check/remove sequence works with `--transport powershell` or `--transport cmd`; remember cmd's cleanup command must also use `--transport cmd` (see above).

## Ownership and outcomes

Rules use these exact markers, with a lowercase canonical GUID:

```text
Name: WinTraceForge.Firewall.<GUID>
Grouping: WinTraceForge.Firewall.v1
Description: WinTraceForge;kind=firewall-rule;schema=1;id=<GUID>
```

These markers prevent accidental cleanup of unrelated rules; they are not an authorization mechanism or security boundary. Add refuses an existing same-name rule. Check verifies unique ownership and displays current properties; it does not compare against the original add request. An absent check exits 3. Remove refuses ambiguous, duplicate, or foreign rules; an already-absent rule is reported explicitly without deletion.

Ownership is re-read before removal, but deletion is by name and is not atomic with that check. Avoid concurrent tests using the same ID or concurrent writers changing marked rules. Legacy rules from builds predating this schema require the matching legacy build or standard Windows administration tools.

Add verifies all constrained properties, including Rule3 restrictions (Windows 8 / Server 2012 or later). Outcomes include `FIREWALL_RULE_CONFIRMED`, `FIREWALL_RULE_UNCONFIRMED`, `FIREWALL_RULE_OWNERSHIP_CONFIRMED`, `FIREWALL_RULE_REMOVED`, `FIREWALL_RULE_ALREADY_ABSENT`, and `FIREWALL_PROFILES_READ`. API errors identify Add/Remove and retain the original HRESULT. A failed add can leave a rule behind; inspect it and use the printed cleanup command. Automatic rollback is not performed.

## Interpret policy and enforcement

`LocalPolicyModifyState` provides restriction context such as `GP_OVERRIDE` or `INBOUND_BLOCKED` when exposed by the route. A nonzero state is a warning; the actual API call and readback determine the operation result. management, powershell, and cmd all derive this context from the same Group Policy merge registry settings (not a WMI/COM/netsh property) and cannot report `INBOUND_BLOCKED`. management's and powershell's profile inspection both read effective `ActiveStore` policy; cmd's instead reads the `Local` store only (see above), which can diverge from the other four on a GPO-managed host. management's and powershell's rule readback both explicitly refuse unsupported IPsec security restrictions rather than displaying a false unrestricted state; cmd refuses what it can detect this way but cannot detect a user/machine-list restriction at all (see above).

Visibility and matching properties do not prove packet enforcement. Profiles, policy merging, GPO/MDM, precedence, application/service scope, network paths, and traffic affect enforcement. Perform a separate authorized connectivity test when that is the objective.
