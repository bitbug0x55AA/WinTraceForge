# Windows Firewall

[User docs](README.md) | [Shared command options](commands.md)

## Inspect profiles

```powershell
.\wtf.exe firewall profiles
.\wtf.exe firewall profiles --transport native
.\wtf.exe firewall profiles --transport management --telemetry eventlog
```

This command reads profile state and exposed policy settings. It does not turn the firewall off, toggle profiles, or change default actions. The output is not a complete GPO/MDM resultant-policy report.

## Select an execution path

| Transport | Path |
| --- | --- |
| `com` (default) | Managed Windows Firewall COM |
| `native` | Native C++ Windows Firewall COM via the matching DLL |
| `management` | Managed WMI Firewall provider |

All three operate on the same persisted rule store and use the same ownership and readback checks. A rule created by one transport can be checked or removed by another. No route silently falls back. `cim` and `wmi` are not aliases for `management`.

COM and native compare caller implementations of the same Windows interfaces; management uses the separate WMI provider. This is not a WFP API test or proof of different detection. COM and management do not require the native DLL unless ETW is selected.

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

`LocalPolicyModifyState` provides restriction context such as `GP_OVERRIDE` or `INBOUND_BLOCKED` when exposed by the route. A nonzero state is a warning; the actual API call and readback determine the operation result. The management route derives this context from Group Policy merge settings and cannot report `INBOUND_BLOCKED`. Its profile inspection reads effective `ActiveStore` policy, and its rule readback explicitly refuses unsupported IPsec security restrictions rather than displaying a false unrestricted state.

Visibility and matching properties do not prove packet enforcement. Profiles, policy merging, GPO/MDM, precedence, application/service scope, network paths, and traffic affect enforcement. Perform a separate authorized connectivity test when that is the objective.
