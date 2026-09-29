// This Source Code Form is subject to the terms of the
// Mozilla Public License, v. 2.0.
// If a copy of the MPL was not distributed with this file, You can obtain one at https://mozilla.org/MPL/2.0/.

using System;
using System.Collections.Generic;
using System.Globalization;
using System.Text;

// Shells to powershell.exe and drives the NetSecurity module's own cmdlets (New-/Get-/Remove-
// NetFirewallRule, the Get-NetFirewall*Filter family, Get-NetFirewallProfile) and the NetConnection
// module's Get-NetConnectionProfile, instead of talking to WMI or netfw COM directly like the other
// three transports. These cmdlets are a thin PowerShell wrapper over the very same root\StandardCimv2
// MSFT_NetFirewallRule/-Profile/-*Filter provider ManagementFirewallBackend already queries directly:
// confirmed live (casting a filter/rule CIM-enum property to [int] yields the identical raw WMI value
// for every field this backend reads -- Action, Enabled, Profiles, EdgeTraversalPolicy, Authentication,
// Encryption, InterfaceType, and NetConnectionProfile.NetworkCategory all matched a live host's raw
// MSFT_NetFirewallRule/-ConnectionProfile query byte-for-byte). This backend therefore reuses
// ManagementFirewallBackend's raw-value codecs/normalizers (AnySentinel, ProtocolNumber/-Name,
// RuleActionFromRaw/-ToRaw, RuleEnabledFromRaw/-ToRaw, ResolveGpoBoolean/-ProfileAction, FirstOrAny,
// NoneIfAny, FilterUnconfiguredSentinel, NetworkCategoryToProfileBit) rather than re-deriving them, so
// both stay in lockstep by construction instead of by convention.
// See DefenderModule.PowerShellRunner's own remarks for the full set of process-execution hardening
// measures (absolute executable path, restricted module path, -EncodedCommand, Base64-encoded values)
// this backend reuses wholesale rather than duplicating.
internal sealed class PowerShellFirewallBackend : IFirewallBackend
{
    private string pendingAddScript;

    internal PowerShellFirewallBackend()
    {
        StringBuilder script = new StringBuilder();
        script.Append("$ErrorActionPreference = 'Stop'\r\n");
        script.Append("try {\r\n");
        foreach (string command in new[]
        {
            "NetSecurity\\New-NetFirewallRule", "NetSecurity\\Get-NetFirewallRule", "NetSecurity\\Remove-NetFirewallRule",
            "NetSecurity\\Get-NetFirewallAddressFilter", "NetSecurity\\Get-NetFirewallPortFilter",
            "NetSecurity\\Get-NetFirewallApplicationFilter", "NetSecurity\\Get-NetFirewallServiceFilter",
            "NetSecurity\\Get-NetFirewallInterfaceTypeFilter", "NetSecurity\\Get-NetFirewallInterfaceFilter",
            "NetSecurity\\Get-NetFirewallSecurityFilter", "NetSecurity\\Get-NetFirewallProfile",
            "NetConnection\\Get-NetConnectionProfile"
        })
        {
            script.Append("    Get-Command " + command + " | Out-Null\r\n");
        }
        script.Append("    Write-Output 'WTF_CONNECT_OK'\r\n");
        script.Append("} catch {\r\n");
        script.Append(DefenderModule.PowerShellRunner.EmitErrorMarkerStatement("WTF_CONNECT_ERROR:"));
        script.Append("    exit 1\r\n");
        script.Append("}\r\n");

        DefenderModule.PowerShellRunner.Result result = DefenderModule.PowerShellRunner.RunScript(script.ToString());
        string errorMessage = DefenderModule.PowerShellRunner.FindMarkerMessage(result.Stdout, "WTF_CONNECT_ERROR:");
        if (errorMessage != null || !DefenderModule.PowerShellRunner.ContainsMarker(result.Stdout, "WTF_CONNECT_OK"))
        {
            throw new NotSupportedException("PowerShell NetSecurity/NetConnection modules (New-/Get-/Remove-NetFirewallRule, " +
                "Get-NetFirewall*Filter, Get-NetFirewallProfile, Get-NetConnectionProfile) are unavailable. " +
                (errorMessage ?? DefenderModule.PowerShellRunner.DescribeFailure(result)));
        }
    }

    public int CurrentProfiles
    {
        get
        {
            StringBuilder script = new StringBuilder();
            script.Append("$ErrorActionPreference = 'Stop'\r\n");
            script.Append("try {\r\n");
            script.Append("    foreach ($p in @(NetConnection\\Get-NetConnectionProfile)) { Write-Output ('WTF_CAT:' + [int]$p.NetworkCategory) }\r\n");
            script.Append("    Write-Output 'WTF_CAT_OK'\r\n");
            script.Append("} catch {\r\n");
            script.Append(DefenderModule.PowerShellRunner.EmitErrorMarkerStatement("WTF_CAT_ERROR:"));
            script.Append("    exit 1\r\n");
            script.Append("}\r\n");
            DefenderModule.PowerShellRunner.Result result = DefenderModule.PowerShellRunner.RunScript(script.ToString());
            string errorMessage = DefenderModule.PowerShellRunner.FindMarkerMessage(result.Stdout, "WTF_CAT_ERROR:");
            if (errorMessage != null || !DefenderModule.PowerShellRunner.ContainsMarker(result.Stdout, "WTF_CAT_OK"))
            {
                throw new InvalidOperationException("Get-NetConnectionProfile (PowerShell) failed: " +
                    (errorMessage ?? DefenderModule.PowerShellRunner.DescribeFailure(result)));
            }
            int mask = 0;
            foreach (string line in DefenderModule.PowerShellRunner.SplitLines(result.Stdout))
            {
                if (!line.StartsWith("WTF_CAT:", StringComparison.Ordinal)) { continue; }
                int category;
                if (!int.TryParse(line.Substring("WTF_CAT:".Length), NumberStyles.Integer, CultureInfo.InvariantCulture, out category))
                { throw new FirewallRefusalException("Unrecognized NetConnectionProfile.NetworkCategory readback."); }
                mask |= ManagementFirewallBackend.NetworkCategoryToProfileBit(category);
            }
            return mask;
        }
    }

    // A plain registry read (the same WindowsFirewall GPO keys ManagementFirewallBackend reads), not
    // a WMI/COM/cmdlet property -- reused directly rather than re-implemented via a PowerShell script.
    public int LocalPolicyModifyState { get { return FirewallGroupPolicy.ReadLocalPolicyModifyState(CurrentProfiles); } }

    public IList<FirewallProfileData> ReadProfiles()
    {
        string marker = Guid.NewGuid().ToString("N");
        StringBuilder script = new StringBuilder();
        script.Append("$ErrorActionPreference = 'Stop'\r\n");
        script.Append("try {\r\n");
        script.Append("    $profiles = @(NetSecurity\\Get-NetFirewallProfile -PolicyStore ActiveStore -Name Domain,Private,Public)\r\n");
        script.Append("    if ($profiles.Count -ne 3) { throw ('Expected exactly 3 firewall profiles, got ' + $profiles.Count) }\r\n");
        script.Append("    foreach ($p in $profiles) {\r\n");
        script.Append("        Write-Output ('WTF_PROFILE_" + marker + ":' + $p.Name + ':' + [int]$p.Enabled + ':' + " +
            "[int]$p.AllowInboundRules + ':' + [int]$p.DefaultInboundAction + ':' + [int]$p.DefaultOutboundAction)\r\n");
        script.Append("        foreach ($alias in $p.DisabledInterfaceAliases) {\r\n");
        script.Append("            Write-Output ('WTF_IFACE_" + marker + ":' + $p.Name + ':' + " +
            "[Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes([string]$alias)))\r\n");
        script.Append("        }\r\n");
        script.Append("    }\r\n");
        script.Append("    Write-Output 'WTF_PROFILES_OK'\r\n");
        script.Append("} catch {\r\n");
        script.Append(DefenderModule.PowerShellRunner.EmitErrorMarkerStatement("WTF_PROFILES_ERROR:"));
        script.Append("    exit 1\r\n");
        script.Append("}\r\n");

        DefenderModule.PowerShellRunner.Result result = DefenderModule.PowerShellRunner.RunScript(script.ToString());
        string errorMessage = DefenderModule.PowerShellRunner.FindMarkerMessage(result.Stdout, "WTF_PROFILES_ERROR:");
        if (errorMessage != null)
        { throw new InvalidOperationException("Get-NetFirewallProfile (PowerShell) failed: " + errorMessage); }
        if (!DefenderModule.PowerShellRunner.ContainsMarker(result.Stdout, "WTF_PROFILES_OK"))
        {
            throw new InvalidOperationException("Get-NetFirewallProfile (PowerShell) readback did not complete (exit " +
                result.ExitCode + "): " + DefenderModule.PowerShellRunner.DescribeFailure(result));
        }

        Dictionary<string, FirewallProfileData> byName = new Dictionary<string, FirewallProfileData>(StringComparer.OrdinalIgnoreCase);
        Dictionary<string, List<string>> aliasesByName = new Dictionary<string, List<string>>(StringComparer.OrdinalIgnoreCase);
        string profilePrefix = "WTF_PROFILE_" + marker + ":";
        string ifacePrefix = "WTF_IFACE_" + marker + ":";
        foreach (string line in DefenderModule.PowerShellRunner.SplitLines(result.Stdout))
        {
            if (line.StartsWith(profilePrefix, StringComparison.Ordinal))
            {
                string[] parts = line.Substring(profilePrefix.Length).Split(':');
                if (parts.Length != 5) { throw new InvalidOperationException("Malformed PowerShell profile readback line."); }
                int bit = NameToProfileBit(parts[0]);
                if (byName.ContainsKey(parts[0])) { throw new FirewallRefusalException("Duplicate firewall profile in PowerShell readback: " + parts[0]); }
                byName[parts[0]] = new FirewallProfileData
                {
                    Profile = bit,
                    Enabled = ManagementFirewallBackend.ResolveGpoBoolean(ParseInt(parts[1]), true),
                    BlockAllInbound = !ManagementFirewallBackend.ResolveGpoBoolean(ParseInt(parts[2]), true),
                    DefaultInboundAction = ManagementFirewallBackend.ResolveProfileAction(ParseInt(parts[3]), 0),
                    DefaultOutboundAction = ManagementFirewallBackend.ResolveProfileAction(ParseInt(parts[4]), 1),
                    ExcludedInterfaces = new string[0]
                };
                continue;
            }
            if (line.StartsWith(ifacePrefix, StringComparison.Ordinal))
            {
                string remainder = line.Substring(ifacePrefix.Length);
                int separator = remainder.IndexOf(':');
                if (separator < 0) { throw new InvalidOperationException("Malformed PowerShell interface readback line."); }
                string name = remainder.Substring(0, separator);
                List<string> aliases;
                if (!aliasesByName.TryGetValue(name, out aliases))
                { aliases = new List<string>(); aliasesByName[name] = aliases; }
                aliases.Add(DefenderModule.PowerShellRunner.DecodeValue(remainder.Substring(separator + 1)));
            }
        }
        List<FirewallProfileData> result2 = new List<FirewallProfileData>();
        foreach (string name in new[] { "Domain", "Private", "Public" })
        {
            FirewallProfileData profile;
            if (!byName.TryGetValue(name, out profile))
            { throw new FirewallRefusalException("Missing firewall profile in PowerShell readback: " + name); }
            List<string> aliases;
            if (aliasesByName.TryGetValue(name, out aliases))
            { profile.ExcludedInterfaces = ManagementFirewallBackend.FilterUnconfiguredSentinel(aliases.ToArray()); }
            result2.Add(profile);
        }
        return result2;
    }

    private static int NameToProfileBit(string name)
    {
        if (string.Equals(name, "Domain", StringComparison.OrdinalIgnoreCase)) { return 1; }
        if (string.Equals(name, "Private", StringComparison.OrdinalIgnoreCase)) { return 2; }
        if (string.Equals(name, "Public", StringComparison.OrdinalIgnoreCase)) { return 4; }
        throw new FirewallRefusalException("Unrecognized firewall profile name in PowerShell readback: " + name);
    }

    private static int ParseInt(string text)
    {
        int value;
        if (!int.TryParse(text, NumberStyles.Integer, CultureInfo.InvariantCulture, out value))
        { throw new InvalidOperationException("Malformed integer in PowerShell firewall readback: " + text); }
        return value;
    }

    // One CIM-backed object per rule plus each of its 7 associated MSFT_Net*Filter objects (the exact
    // same object shape ManagementFirewallBackend.ReadRule reads via GetRelated), fetched through the
    // matching Get-NetFirewall*Filter cmdlet piped from the rule instead of a WQL relationship query.
    private static readonly string[] RuleFields =
    {
        "ElementName", "RuleGroup", "Description", "Enabled", "Direction", "Action", "Profiles",
        "EdgeTraversalPolicy", "PackageFamilyName", "Owner", "LocalAddress", "RemoteAddress",
        "LocalPort", "RemotePort", "Protocol", "AppPath", "ServiceName", "InterfaceType",
        "InterfaceAlias", "Authentication", "Encryption", "OverrideBlockRules", "LocalUsers",
        "RemoteUsers", "RemoteMachines"
    };

    public IList<FirewallRuleData> FindByName(string name)
    {
        string marker = Guid.NewGuid().ToString("N");
        StringBuilder script = new StringBuilder();
        script.Append("$ErrorActionPreference = 'Stop'\r\n");
        script.Append("try {\r\n");
        script.Append("    $name = " + DefenderModule.PowerShellRunner.EncodeValueExpression(name) + "\r\n");
        script.Append("    $rules = @(NetSecurity\\Get-NetFirewallRule | Where-Object { $_.DisplayName -eq $name })\r\n");
        script.Append("    Write-Output ('WTF_COUNT_" + marker + ":' + $rules.Count)\r\n");
        script.Append("    function Emit([string]$field, $values) {\r\n");
        script.Append("        Write-Output ('WTF_BEGIN_" + marker + ":' + $i + ':' + $field)\r\n");
        script.Append("        foreach ($v in $values) { Write-Output ([Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes([string]$v))) }\r\n");
        script.Append("        Write-Output ('WTF_END_" + marker + ":' + $i + ':' + $field)\r\n");
        script.Append("    }\r\n");
        script.Append("    for ($i = 0; $i -lt $rules.Count; $i++) {\r\n");
        script.Append("        $rule = $rules[$i]\r\n");
        script.Append("        $addr = @($rule | NetSecurity\\Get-NetFirewallAddressFilter)\r\n");
        script.Append("        if ($addr.Count -ne 1) { throw ('Expected exactly one address filter, got ' + $addr.Count) }\r\n");
        script.Append("        $port = @($rule | NetSecurity\\Get-NetFirewallPortFilter)\r\n");
        script.Append("        if ($port.Count -ne 1) { throw ('Expected exactly one port filter, got ' + $port.Count) }\r\n");
        script.Append("        $app = @($rule | NetSecurity\\Get-NetFirewallApplicationFilter)\r\n");
        script.Append("        if ($app.Count -ne 1) { throw ('Expected exactly one application filter, got ' + $app.Count) }\r\n");
        script.Append("        $svc = @($rule | NetSecurity\\Get-NetFirewallServiceFilter)\r\n");
        script.Append("        if ($svc.Count -ne 1) { throw ('Expected exactly one service filter, got ' + $svc.Count) }\r\n");
        script.Append("        $ifType = @($rule | NetSecurity\\Get-NetFirewallInterfaceTypeFilter)\r\n");
        script.Append("        if ($ifType.Count -ne 1) { throw ('Expected exactly one interface type filter, got ' + $ifType.Count) }\r\n");
        script.Append("        $ifAlias = @($rule | NetSecurity\\Get-NetFirewallInterfaceFilter)\r\n");
        script.Append("        if ($ifAlias.Count -ne 1) { throw ('Expected exactly one interface filter, got ' + $ifAlias.Count) }\r\n");
        script.Append("        $sec = @($rule | NetSecurity\\Get-NetFirewallSecurityFilter)\r\n");
        script.Append("        if ($sec.Count -ne 1) { throw ('Expected exactly one security filter, got ' + $sec.Count) }\r\n");
        script.Append("        Emit 'ElementName' @($rule.DisplayName)\r\n");
        script.Append("        Emit 'RuleGroup' @($rule.Group)\r\n");
        script.Append("        Emit 'Description' @($rule.Description)\r\n");
        script.Append("        Emit 'Enabled' @([int]$rule.Enabled)\r\n");
        script.Append("        Emit 'Direction' @([int]$rule.Direction)\r\n");
        script.Append("        Emit 'Action' @([int]$rule.Action)\r\n");
        script.Append("        Emit 'Profiles' @([int]$rule.Profile)\r\n");
        script.Append("        Emit 'EdgeTraversalPolicy' @([int]$rule.EdgeTraversalPolicy)\r\n");
        script.Append("        Emit 'PackageFamilyName' @($rule.PackageFamilyName)\r\n");
        script.Append("        Emit 'Owner' @($rule.Owner)\r\n");
        script.Append("        Emit 'LocalAddress' @($addr[0].LocalAddress)\r\n");
        script.Append("        Emit 'RemoteAddress' @($addr[0].RemoteAddress)\r\n");
        script.Append("        Emit 'LocalPort' @($port[0].LocalPort)\r\n");
        script.Append("        Emit 'RemotePort' @($port[0].RemotePort)\r\n");
        script.Append("        Emit 'Protocol' @($port[0].Protocol)\r\n");
        script.Append("        Emit 'AppPath' @($app[0].Program)\r\n");
        script.Append("        Emit 'ServiceName' @($svc[0].Service)\r\n");
        script.Append("        Emit 'InterfaceType' @([int]$ifType[0].InterfaceType)\r\n");
        script.Append("        Emit 'InterfaceAlias' @($ifAlias[0].InterfaceAlias)\r\n");
        script.Append("        Emit 'Authentication' @([int]$sec[0].Authentication)\r\n");
        script.Append("        Emit 'Encryption' @([int]$sec[0].Encryption)\r\n");
        script.Append("        Emit 'OverrideBlockRules' @([int]$sec[0].OverrideBlockRules)\r\n");
        script.Append("        Emit 'LocalUsers' @($sec[0].LocalUser)\r\n");
        script.Append("        Emit 'RemoteUsers' @($sec[0].RemoteUser)\r\n");
        script.Append("        Emit 'RemoteMachines' @($sec[0].RemoteMachine)\r\n");
        script.Append("    }\r\n");
        script.Append("    Write-Output 'WTF_READ_OK'\r\n");
        script.Append("} catch {\r\n");
        script.Append(DefenderModule.PowerShellRunner.EmitErrorMarkerStatement("WTF_READ_ERROR:"));
        script.Append("    exit 1\r\n");
        script.Append("}\r\n");
        string scriptText = script.ToString();
        DefenderModule.PowerShellRunner.ValidateScriptLength(scriptText);

        DefenderModule.PowerShellRunner.Result result = DefenderModule.PowerShellRunner.RunScript(scriptText);
        string errorMessage = DefenderModule.PowerShellRunner.FindMarkerMessage(result.Stdout, "WTF_READ_ERROR:");
        if (errorMessage != null)
        { throw new InvalidOperationException("Get-NetFirewallRule (PowerShell) readback failed: " + errorMessage); }
        if (!DefenderModule.PowerShellRunner.ContainsMarker(result.Stdout, "WTF_READ_OK"))
        {
            throw new InvalidOperationException("Get-NetFirewallRule (PowerShell) readback did not complete (exit " +
                result.ExitCode + "): " + DefenderModule.PowerShellRunner.DescribeFailure(result));
        }
        return ParseRules(result.Stdout, marker);
    }

    private static IList<FirewallRuleData> ParseRules(string stdout, string marker)
    {
        string countPrefix = "WTF_COUNT_" + marker + ":";
        int? count = null;
        List<Dictionary<string, List<string>>> byIndex = new List<Dictionary<string, List<string>>>();
        string beginPrefix = "WTF_BEGIN_" + marker + ":";
        string endPrefix = "WTF_END_" + marker + ":";
        int currentIndex = -1;
        string currentField = null;
        foreach (string line in DefenderModule.PowerShellRunner.SplitLines(stdout))
        {
            if (line.StartsWith(countPrefix, StringComparison.Ordinal))
            {
                int parsed;
                if (!int.TryParse(line.Substring(countPrefix.Length), NumberStyles.Integer, CultureInfo.InvariantCulture, out parsed))
                { throw new InvalidOperationException("Malformed PowerShell rule count readback."); }
                count = parsed;
                for (int i = 0; i < parsed; i++)
                { byIndex.Add(new Dictionary<string, List<string>>(StringComparer.OrdinalIgnoreCase)); }
                continue;
            }
            if (line.StartsWith(beginPrefix, StringComparison.Ordinal))
            {
                string[] parts = line.Substring(beginPrefix.Length).Split(new[] { ':' }, 2);
                if (parts.Length != 2) { throw new InvalidOperationException("Malformed PowerShell rule readback begin marker."); }
                currentIndex = ParseInt(parts[0]);
                currentField = parts[1];
                if (currentIndex < 0 || count == null || currentIndex >= byIndex.Count)
                { throw new InvalidOperationException("PowerShell rule readback index out of range."); }
                if (!byIndex[currentIndex].ContainsKey(currentField)) { byIndex[currentIndex][currentField] = new List<string>(); }
                continue;
            }
            if (line.StartsWith(endPrefix, StringComparison.Ordinal))
            {
                string[] parts = line.Substring(endPrefix.Length).Split(new[] { ':' }, 2);
                if (parts.Length != 2 || ParseInt(parts[0]) != currentIndex || parts[1] != currentField)
                { throw new InvalidOperationException("PowerShell rule readback begin/end marker mismatch."); }
                currentIndex = -1;
                currentField = null;
                continue;
            }
            if (currentField != null && line.Length > 0)
            { byIndex[currentIndex][currentField].Add(DefenderModule.PowerShellRunner.DecodeValue(line)); }
        }
        if (currentField != null) { throw new InvalidOperationException("PowerShell rule readback truncated for field: " + currentField); }
        if (count == null) { throw new InvalidOperationException("PowerShell rule readback never reported a count."); }

        List<FirewallRuleData> rules = new List<FirewallRuleData>();
        foreach (Dictionary<string, List<string>> fields in byIndex) { rules.Add(DecodeRule(fields)); }
        return rules;
    }

    private static FirewallRuleData DecodeRule(Dictionary<string, List<string>> fields)
    {
        foreach (string field in RuleFields)
        {
            if (!fields.ContainsKey(field)) { throw new InvalidOperationException("Missing PowerShell readback field: " + field); }
        }
        FirewallRuleData result = new FirewallRuleData
        {
            Name = One(fields, "ElementName"),
            Grouping = One(fields, "RuleGroup") ?? "",
            Description = One(fields, "Description") ?? "",
            Enabled = ManagementFirewallBackend.RuleEnabledFromRaw(ParseInt(One(fields, "Enabled"))),
            Direction = ParseInt(One(fields, "Direction")),
            Action = ManagementFirewallBackend.RuleActionFromRaw(ParseInt(One(fields, "Action"))),
            Profiles = ParseInt(One(fields, "Profiles")),
            LocalAppPackageId = ManagementFirewallBackend.NoneIfAny(One(fields, "PackageFamilyName")),
            LocalUserOwner = ManagementFirewallBackend.NoneIfAny(One(fields, "Owner")),
            LocalUserAuthorizedList = ManagementFirewallBackend.NoneIfAny(One(fields, "LocalUsers")),
            RemoteUserAuthorizedList = ManagementFirewallBackend.NoneIfAny(One(fields, "RemoteUsers")),
            RemoteMachineAuthorizedList = ManagementFirewallBackend.NoneIfAny(One(fields, "RemoteMachines")),
            SecureFlags = 0, Interfaces = new string[0], InterfaceTypes = "All",
            EdgeTraversal = false, EdgeTraversalOptions = 0
        };
        int edgeTraversalRaw = ParseInt(One(fields, "EdgeTraversalPolicy"));
        if (edgeTraversalRaw != 0) { result.EdgeTraversal = true; result.EdgeTraversalOptions = edgeTraversalRaw; }

        result.LocalAddresses = ManagementFirewallBackend.FirstOrAny(fields["LocalAddress"].ToArray());
        result.RemoteAddresses = ManagementFirewallBackend.FirstOrAny(fields["RemoteAddress"].ToArray());
        result.LocalPorts = ManagementFirewallBackend.FirstOrAny(fields["LocalPort"].ToArray());
        result.RemotePorts = ManagementFirewallBackend.FirstOrAny(fields["RemotePort"].ToArray());
        result.Protocol = ManagementFirewallBackend.ProtocolNumber(One(fields, "Protocol"));
        result.ApplicationName = ManagementFirewallBackend.NoneIfAny(One(fields, "AppPath"));
        result.ServiceName = ManagementFirewallBackend.NoneIfAny(One(fields, "ServiceName"));

        int interfaceTypeRaw = ParseInt(One(fields, "InterfaceType"));
        if (interfaceTypeRaw != 0)
        { throw new FirewallReadbackUnsupportedException("Unsupported InterfaceType restriction on a powershell-transport rule readback."); }
        string[] aliases = fields["InterfaceAlias"].ToArray();
        if (aliases.Length != 0 && !(aliases.Length == 1 && aliases[0] == ManagementFirewallBackend.AnySentinel))
        { throw new FirewallReadbackUnsupportedException("Unsupported interface-alias restriction on a powershell-transport rule readback."); }

        int authentication = ParseInt(One(fields, "Authentication"));
        int encryption = ParseInt(One(fields, "Encryption"));
        bool overrideBlockRules = ParseInt(One(fields, "OverrideBlockRules")) != 0;
        if (authentication != 0 || encryption != 0 || overrideBlockRules)
        {
            throw new FirewallReadbackUnsupportedException(
                "Unsupported Authentication/Encryption/OverrideBlockRules restriction on a powershell-transport rule readback.");
        }
        return result;
    }

    private static string One(Dictionary<string, List<string>> fields, string field)
    {
        List<string> values = fields[field];
        if (values.Count == 0) { return ""; }
        if (values.Count != 1) { throw new InvalidOperationException("Expected exactly one value for PowerShell field: " + field); }
        return values[0];
    }

    public void PrepareAdd(FirewallRuleData rule)
    {
        if (rule == null) { throw new ArgumentNullException("rule"); }
        if (rule.Interfaces == null || rule.Interfaces.Length != 0)
        { throw new FirewallRefusalException("Detached firewall rules must have no interface restrictions."); }
        if (pendingAddScript != null) { throw new FirewallRefusalException("A detached rule is already prepared."); }
        pendingAddScript = BuildAddScript(rule);
    }

    private static string BuildAddScript(FirewallRuleData rule)
    {
        StringBuilder script = new StringBuilder();
        script.Append("$ErrorActionPreference = 'Stop'\r\n");
        script.Append("try {\r\n");
        script.Append("    NetSecurity\\New-NetFirewallRule");
        script.Append(" -DisplayName " + DefenderModule.PowerShellRunner.EncodeValueExpression(rule.Name));
        script.Append(" -Description " + DefenderModule.PowerShellRunner.EncodeValueExpression(rule.Description));
        script.Append(" -Group " + DefenderModule.PowerShellRunner.EncodeValueExpression(rule.Grouping));
        script.Append(" -Enabled True");
        script.Append(" -Direction '" + (rule.Direction == 1 ? "Inbound" : "Outbound") + "'");
        script.Append(" -Action '" + (rule.Action == 1 ? "Allow" : "Block") + "'");
        script.Append(" -Protocol '" + ManagementFirewallBackend.ProtocolName(rule.Protocol) + "'");
        script.Append(" -RemoteAddress '" + rule.RemoteAddresses + "'");
        script.Append(" -LocalPort '" + (rule.LocalPorts == "*" ? "Any" : rule.LocalPorts) + "'");
        script.Append(" -RemotePort '" + (rule.RemotePorts == "*" ? "Any" : rule.RemotePorts) + "'");
        script.Append(" -Program " + (string.IsNullOrEmpty(rule.ApplicationName) ?
            "'Any'" : DefenderModule.PowerShellRunner.EncodeValueExpression(rule.ApplicationName)));
        script.Append(" -EdgeTraversalPolicy Block");
        script.Append(" -Profile " + FirewallModule.ProfileList(rule.Profiles));
        script.Append(" | Out-Null\r\n");
        script.Append("    Write-Output 'WTF_ADD_OK'\r\n");
        script.Append("} catch {\r\n");
        script.Append(DefenderModule.PowerShellRunner.EmitErrorMarkerStatement("WTF_ADD_ERROR:"));
        script.Append("    exit 1\r\n");
        script.Append("}\r\n");
        string result = script.ToString();
        DefenderModule.PowerShellRunner.ValidateScriptLength(result);
        return result;
    }

    public MutationStatus Add()
    {
        if (pendingAddScript == null) { throw new FirewallRefusalException("No detached rule was prepared."); }
        DefenderModule.PowerShellRunner.Result result = DefenderModule.PowerShellRunner.RunScript(pendingAddScript);
        pendingAddScript = null;
        string errorMessage = DefenderModule.PowerShellRunner.FindMarkerMessage(result.Stdout, "WTF_ADD_ERROR:");
        if (errorMessage != null)
        { throw new InvalidOperationException("New-NetFirewallRule (PowerShell) failed: " + errorMessage); }
        if (DefenderModule.PowerShellRunner.ContainsMarker(result.Stdout, "WTF_ADD_OK")) { return MutationStatus.ApiSucceeded; }
        // No WMI ReturnValue exists for a PowerShell cmdlet call and no marker was found either
        // (crash, or the process torn down externally after New-NetFirewallRule may already have
        // run): genuinely unknown, not a known failure. The shared FirewallOperation.Verify()
        // readback that always follows is the only thing that can settle it either way.
        ConsoleUi.Status("WARN", "powershell.exe ended (exit code " + result.ExitCode +
            ") without a clear success/failure marker; verifying configuration by readback.");
        ConsoleUi.Detail(DefenderModule.PowerShellRunner.DescribeFailure(result));
        return MutationStatus.ApiUnknown;
    }

    public MutationStatus Remove(string name)
    {
        StringBuilder script = new StringBuilder();
        script.Append("$ErrorActionPreference = 'Stop'\r\n");
        script.Append("try {\r\n");
        script.Append("    $name = " + DefenderModule.PowerShellRunner.EncodeValueExpression(name) + "\r\n");
        script.Append("    $rules = @(NetSecurity\\Get-NetFirewallRule | Where-Object { $_.DisplayName -eq $name })\r\n");
        script.Append("    if ($rules.Count -ne 1) { throw ('Expected exactly one rule to remove, found ' + $rules.Count) }\r\n");
        script.Append("    $rules[0] | NetSecurity\\Remove-NetFirewallRule\r\n");
        script.Append("    Write-Output 'WTF_REMOVE_OK'\r\n");
        script.Append("} catch {\r\n");
        script.Append(DefenderModule.PowerShellRunner.EmitErrorMarkerStatement("WTF_REMOVE_ERROR:"));
        script.Append("    exit 1\r\n");
        script.Append("}\r\n");
        string scriptText = script.ToString();
        DefenderModule.PowerShellRunner.ValidateScriptLength(scriptText);

        DefenderModule.PowerShellRunner.Result result = DefenderModule.PowerShellRunner.RunScript(scriptText);
        string errorMessage = DefenderModule.PowerShellRunner.FindMarkerMessage(result.Stdout, "WTF_REMOVE_ERROR:");
        if (errorMessage != null)
        { throw new InvalidOperationException("Remove-NetFirewallRule (PowerShell) failed: " + errorMessage); }
        if (DefenderModule.PowerShellRunner.ContainsMarker(result.Stdout, "WTF_REMOVE_OK")) { return MutationStatus.ApiSucceeded; }
        ConsoleUi.Status("WARN", "powershell.exe ended (exit code " + result.ExitCode +
            ") without a clear success/failure marker; verifying configuration by readback.");
        ConsoleUi.Detail(DefenderModule.PowerShellRunner.DescribeFailure(result));
        return MutationStatus.ApiUnknown;
    }

    public void Dispose() { }
}
