// This Source Code Form is subject to the terms of the
// Mozilla Public License, v. 2.0.
// If a copy of the MPL was not distributed with this file, You can obtain one at https://mozilla.org/MPL/2.0/.

using System;
using System.Collections.Generic;
using System.Globalization;
using System.Management;
using System.Security;
using Microsoft.Win32;

// Best-effort mirror of netfw's INetFwPolicy2.LocalPolicyModifyState: MSFT_NetFirewallRule/-Profile
// expose no equivalent property, so this reads the same GPO ADMX-backed registry values Group Policy
// itself writes for the WindowsFirewall administrative templates. It only ever reports 0 (OK) or
// 1 (GP_OVERRIDE); it never claims 2 (INBOUND_BLOCKED), since that distinction cannot be derived
// from these two values alone. Verify against a real GPO-managed host before relying on it.
internal static class FirewallGroupPolicy
{
    private static readonly KeyValuePair<int, string>[] ProfileKeys = new[]
    {
        new KeyValuePair<int, string>(1, @"SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile"),
        new KeyValuePair<int, string>(2, @"SOFTWARE\Policies\Microsoft\WindowsFirewall\StandardProfile"),
        new KeyValuePair<int, string>(4, @"SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile")
    };

    internal static int ReadLocalPolicyModifyState(int activeProfiles)
    {
        foreach (KeyValuePair<int, string> entry in ProfileKeys)
        {
            if ((activeProfiles & entry.Key) != 0 && IsMergeDisabled(entry.Value)) { return 1; }
        }
        return 0;
    }

    private static bool IsMergeDisabled(string path)
    {
        try
        {
            using (RegistryKey key = Registry.LocalMachine.OpenSubKey(path))
            {
                if (key == null) { return false; }
                object policyMerge = key.GetValue("AllowLocalPolicyMerge");
                object ipsecMerge = key.GetValue("AllowLocalIPsecPolicyMerge");
                return (policyMerge is int && (int)policyMerge == 0) || (ipsecMerge is int && (int)ipsecMerge == 0);
            }
        }
        catch (SecurityException) { return false; }
        catch (UnauthorizedAccessException) { return false; }
    }
}

// System.Management access to the WMI Firewall provider (root\StandardCimv2\MSFT_NetFirewallRule),
// the same provider PowerShell's New-NetFirewallRule/NetSecurity module wraps. Unlike netfw's flat
// HNetCfg.FWRule COM object (com/native), a rule's address/port/program/service scoping is not a
// property of MSFT_NetFirewallRule itself: the provider derives separate MSFT_Net*Filter instances
// from named values supplied through the WMI call context at Put() time (documented as the "Firewall
// WMI Provider Extended Syntax"; CDXML's cim:OperationOption:* parameters are the same mechanism).
// Those filter instances do not exist until a real Put() persists them, so PrepareAdd here can only
// pre-validate the handful of properties that live directly on MSFT_NetFirewallRule (name/group/
// description/enabled/direction/action/profiles); full attribute verification -- including address/
// port/program -- relies on the shared post-Add Verify() readback every transport already goes through.
internal sealed class ManagementFirewallBackend : IFirewallBackend, IFirewallRuleEnumerator
{
    // AnySentinel and the raw-value codecs/normalizers below are internal (not private): reused by
    // PowerShellFirewallBackend and CmdFirewallBackend, which read the same root\StandardCimv2
    // provider through NetSecurity cmdlets / netsh respectively and observe the identical "Any"
    // sentinel and raw enum values this class already decodes -- the same reuse rationale as
    // DefenderModule.ComObjects/PowerShellRunner being shared with AsrModule.
    internal const string AnySentinel = "Any";
    private readonly ManagementScope scope = new ManagementScope(@"\\.\root\StandardCimv2");
    private FirewallRuleData preparedRule;

    internal ManagementFirewallBackend() { scope.Connect(); }

    public int CurrentProfiles
    {
        get
        {
            int mask = 0;
            using (ManagementObjectSearcher searcher = new ManagementObjectSearcher(scope,
                new ObjectQuery("SELECT NetworkCategory FROM MSFT_NetConnectionProfile")))
            using (ManagementObjectCollection results = searcher.Get())
            {
                foreach (ManagementObject profile in results)
                {
                    using (profile)
                    { mask |= NetworkCategoryToProfileBit(Convert.ToInt32(profile["NetworkCategory"], CultureInfo.InvariantCulture)); }
                }
            }
            return mask;
        }
    }

    public int LocalPolicyModifyState { get { return FirewallGroupPolicy.ReadLocalPolicyModifyState(CurrentProfiles); } }

    internal static int NetworkCategoryToProfileBit(int category)
    {
        // MSFT_NetConnectionProfile.NetworkCategory: 0=Public, 1=Private, 2=DomainAuthenticated.
        switch (category)
        {
            case 0: return 4;
            case 1: return 2;
            case 2: return 1;
            default: throw new FirewallRefusalException("Unrecognized NetConnectionProfile.NetworkCategory; current profile mask cannot be trusted.");
        }
    }

    // Querying MSFT_NetFirewallProfile with no PolicyStore context reads the local/persistent store,
    // NOT the GPO-merged effective policy -- confirmed live: on a host with a domain-pushed inbound
    // policy, the default query returned DefaultInboundAction/AllowInboundRules = NotConfigured while
    // an explicit PolicyStore=ActiveStore query resolved the same profile to the real effective
    // values. INetFwPolicy2 (com/native) always reports the effective policy, so reading the default
    // store here would silently diverge from com/native on any GPO-managed host, even though the
    // built-in-default fallbacks in ResolveGpoBoolean/ResolveProfileAction below happen to coincide
    // with an unmanaged host's real values (why this was easy to miss without one to test against).
    public IList<FirewallProfileData> ReadProfiles()
    {
        List<FirewallProfileData> result = new List<FirewallProfileData>();
        EnumerationOptions activeStore = new EnumerationOptions();
        activeStore.Context.Add("PolicyStore", "ActiveStore");
        foreach (KeyValuePair<int, string> entry in new[]
            { new KeyValuePair<int, string>(1, "Domain"), new KeyValuePair<int, string>(2, "Private"), new KeyValuePair<int, string>(4, "Public") })
        {
            using (ManagementObjectSearcher searcher = new ManagementObjectSearcher(scope,
                new ObjectQuery("SELECT * FROM MSFT_NetFirewallProfile WHERE Name = '" + entry.Value + "'"), activeStore))
            using (ManagementObjectCollection results = searcher.Get())
            using (ManagementObject profile = RequireOne(results, "MSFT_NetFirewallProfile:" + entry.Value))
            {
                result.Add(new FirewallProfileData
                {
                    Profile = entry.Key,
                    Enabled = ResolveGpoBoolean(Convert.ToInt32(profile["Enabled"], CultureInfo.InvariantCulture), true),
                    BlockAllInbound = !ResolveGpoBoolean(Convert.ToInt32(profile["AllowInboundRules"], CultureInfo.InvariantCulture), true),
                    DefaultInboundAction = ResolveProfileAction(Convert.ToInt32(profile["DefaultInboundAction"], CultureInfo.InvariantCulture), 0),
                    DefaultOutboundAction = ResolveProfileAction(Convert.ToInt32(profile["DefaultOutboundAction"], CultureInfo.InvariantCulture), 1),
                    ExcludedInterfaces = FilterUnconfiguredSentinel(ReadStringArray(profile["DisabledInterfaceAliases"]))
                });
            }
        }
        return result;
    }

    // NetSecurity.GpoBoolean: 0=False, 1=True, 2=NotConfigured. NotConfigured resolves to the
    // documented Windows Firewall built-in default (profiles enabled; inbound rules honored) so this
    // reports the same *effective* value netfw's own (tri-state-free) COM properties would return.
    internal static bool ResolveGpoBoolean(int raw, bool notConfiguredDefault)
    {
        if (raw == 0) { return false; }
        if (raw == 1) { return true; }
        if (raw == 2) { return notConfiguredDefault; }
        throw new FirewallRefusalException("Unrecognized firewall profile GPO-boolean value: " + raw.ToString(CultureInfo.InvariantCulture));
    }

    // NetSecurity.Action: 0=NotConfigured, 2=Allow, 4=Block. NotConfigured resolves to Windows
    // Firewall's built-in default action for the given direction (Block inbound, Allow outbound).
    internal static int ResolveProfileAction(int raw, int notConfiguredDefault)
    {
        if (raw == 0) { return notConfiguredDefault; }
        if (raw == 2) { return 1; }
        if (raw == 4) { return 0; }
        throw new FirewallRefusalException("Unrecognized firewall profile default action value: " + raw.ToString(CultureInfo.InvariantCulture));
    }

    // ElementName, not InstanceID, is this tool's ownership identity: MSFT_NetFirewallRule's
    // InstanceID is only a mirror of the requested name for rules this transport itself created
    // (Add omits it and lets the provider auto-generate one, exactly like every other rule). A rule
    // created through HNetCfg.FWRule (com/native) gets an opaque provider-generated InstanceID (e.g.
    // "{7310AAE3-...}") with the netfw Name surfaced only via ElementName -- confirmed live: querying
    // by InstanceID silently found zero rows for a com-created rule, which Remove then misreported
    // as "already absent" without deleting it. ElementName is where com/native's Name property always
    // lands, regardless of which API created the rule, so it is the only reliable lookup key here.
    public IList<FirewallRuleData> FindByName(string name)
    {
        List<FirewallRuleData> result = new List<FirewallRuleData>();
        using (ManagementObjectSearcher searcher = new ManagementObjectSearcher(scope,
            new ObjectQuery("SELECT * FROM MSFT_NetFirewallRule WHERE ElementName = '" + EscapeWql(name) + "'")))
        using (ManagementObjectCollection matches = searcher.Get())
        {
            foreach (ManagementObject rule in matches) { using (rule) { result.Add(ReadRule(rule)); } }
        }
        return result;
    }

    // Read-only inventory of every MSFT_NetFirewallRule in the chosen policy store. Reads only the rule
    // object's own direct properties -- none of the per-rule MSFT_Net*Filter associations ReadRule needs --
    // so a rule shape ReadRule would refuse (an interface, IPsec or multi-value restriction) is still
    // listed. PolicyStore is always set explicitly to a literal store name (BuildListOptions), never left
    // to the provider's default. The localized connection is made before any enumeration starts, so a
    // failure there is an ordinary error, not an incomplete list; any failure once rules are being read
    // is an incomplete list (ReadAll), never a shorter one.
    public IList<FirewallRuleSummary> ListRules(FirewallPolicyStore store)
    {
        ManagementScope listScope = ListScope();
        EnumerationOptions options = BuildListOptions(store);
        using (ManagementObjectSearcher searcher = new ManagementObjectSearcher(listScope,
            new ObjectQuery("SELECT * FROM MSFT_NetFirewallRule"), options))
        using (ManagementObjectCollection rules = searcher.Get())
        {
            return ReadAll(ReadEachRule(rules), FirewallRuleListCodec.StoreProviderName(store));
        }
    }

    internal static EnumerationOptions BuildListOptions(FirewallPolicyStore store)
    {
        EnumerationOptions options = new EnumerationOptions();
        options.Context.Add("PolicyStore", FirewallRuleListCodec.StoreProviderName(store));
        return options;
    }

    private static IEnumerable<IDictionary<string, object>> ReadEachRule(ManagementObjectCollection rules)
    {
        foreach (ManagementObject rule in rules)
        {
            using (rule) { yield return ReadDirectValues(rule); }
        }
    }

    // Test seam: the iteration is where a provider/RPC failure surfaces. Any exception while pulling rows
    // becomes FirewallListIncompleteException (carrying how many were read); the rows read so far are
    // discarded, never returned.
    internal static IList<FirewallRuleSummary> ReadAll(IEnumerable<IDictionary<string, object>> rows, string storeName)
    {
        List<FirewallRuleSummary> result = new List<FirewallRuleSummary>();
        try
        {
            foreach (IDictionary<string, object> row in rows) { result.Add(SummarizeRule(row)); }
        }
        catch (Exception error)
        {
            throw new FirewallListIncompleteException("MSFT_NetFirewallRule enumeration (" + storeName + ") failed after " +
                result.Count.ToString(CultureInfo.InvariantCulture) + " rule(s): " + error.Message, result.Count, error);
        }
        return result;
    }

    // MSFT_NetFirewallRule.DisplayName is the provider's own resolved text for a rule whose ElementName is a
    // resource reference, produced for the request's WMI locale. System.Management defaults that locale to
    // the thread's culture (formats), which need not be a UI language at all; confirmed live on a host whose
    // culture and user UI language were zh-CN but whose system UI language was en-US: this transport read
    // the same rules as Chinese text while the powershell transport's child process (NetSecurity cmdlets)
    // read them as English. The system UI language is requested explicitly so both transports show the same
    // text there; on a host with a single UI language the two settings coincide. Display text is localized
    // either way -- the rule id is the stable key.
    private ManagementScope ListScope()
    {
        ConnectionOptions connection = BuildListConnection();
        if (connection == null) { return scope; }
        ManagementScope localized = new ManagementScope(@"\\.\root\StandardCimv2", connection);
        localized.Connect();
        return localized;
    }

    // The connection options of the listing scope (no connect): the system UI language as the WMI locale, or
    // null when that culture has no usable LCID. Kept separate so a test can pin where the locale comes from.
    internal static ConnectionOptions BuildListConnection()
    {
        string locale = ListLocale(CultureInfo.InstalledUICulture);
        if (locale == null) { return null; }
        ConnectionOptions connection = new ConnectionOptions();
        connection.Locale = locale;
        return connection;
    }

    // WMI locale name ("MS_<hex LCID>") for a culture, or null when the culture has no usable LCID
    // (neutral, invariant 0x7F, or a custom culture 0x1000) and the default locale must be kept.
    internal static string ListLocale(CultureInfo culture)
    {
        if (culture.IsNeutralCulture || culture.LCID == 0x1000 || culture.LCID == 0x7F) { return null; }
        return "MS_" + culture.LCID.ToString("x", CultureInfo.InvariantCulture);
    }

    // Snapshot of the rule's property values by name. A property the provider does not expose on this
    // Windows build is simply absent from the map (reported as a per-rule read limit), not an error.
    private static Dictionary<string, object> ReadDirectValues(ManagementObject rule)
    {
        Dictionary<string, object> values = new Dictionary<string, object>(StringComparer.OrdinalIgnoreCase);
        foreach (PropertyData property in rule.Properties) { values[property.Name] = property.Value; }
        return values;
    }

    internal static FirewallRuleSummary SummarizeRule(IDictionary<string, object> values)
    {
        string displayName = TextValue(values, "DisplayName");
        bool fallback = false;
        if (displayName == null) { displayName = TextValue(values, "ElementName"); fallback = displayName != null; }
        FirewallRuleSummary summary = FirewallRuleListCodec.Build(TextValue(values, "InstanceID"), displayName,
            IntValue(values, "Enabled"), IntValue(values, "Direction"), IntValue(values, "Action"),
            IntValue(values, "Profiles"), IntValue(values, "PolicyStoreSourceType"), TextValue(values, "PolicyStoreSource"));
        if (fallback) { summary.Limits.Add("DisplayName property unavailable; raw ElementName shown"); }
        return summary;
    }

    private static string TextValue(IDictionary<string, object> values, string name)
    {
        object value;
        if (!values.TryGetValue(name, out value) || value == null || value == DBNull.Value) { return null; }
        string text = value as string;
        return text != null ? text : null;
    }

    private static int? IntValue(IDictionary<string, object> values, string name)
    {
        object value;
        if (!values.TryGetValue(name, out value) || value == null || value == DBNull.Value) { return null; }
        try { return Convert.ToInt32(value, CultureInfo.InvariantCulture); }
        catch (FormatException) { return null; }
        catch (InvalidCastException) { return null; }
        catch (OverflowException) { return null; }
    }

    private static FirewallRuleData ReadRule(ManagementObject rule)
    {
        FirewallRuleData result = new FirewallRuleData
        {
            Name = (string)rule["ElementName"],
            Grouping = (string)rule["RuleGroup"] ?? "",
            Description = (string)rule["Description"] ?? "",
            Enabled = RuleEnabledFromRaw(Convert.ToInt32(rule["Enabled"], CultureInfo.InvariantCulture)),
            Direction = Convert.ToInt32(rule["Direction"], CultureInfo.InvariantCulture),
            Action = RuleActionFromRaw(Convert.ToInt32(rule["Action"], CultureInfo.InvariantCulture)),
            Profiles = Convert.ToInt32(rule["Profiles"], CultureInfo.InvariantCulture),
            LocalAppPackageId = NoneIfAny((string)rule["PackageFamilyName"]),
            LocalUserOwner = NoneIfAny((string)rule["Owner"]),
            LocalUserAuthorizedList = "", RemoteUserAuthorizedList = "", RemoteMachineAuthorizedList = "",
            SecureFlags = 0, Interfaces = new string[0], InterfaceTypes = "All",
            EdgeTraversal = false, EdgeTraversalOptions = 0
        };
        int edgeTraversalRaw = Convert.ToInt32(rule["EdgeTraversalPolicy"], CultureInfo.InvariantCulture);
        if (edgeTraversalRaw != 0) { result.EdgeTraversal = true; result.EdgeTraversalOptions = edgeTraversalRaw; }

        using (ManagementObject address = RequireOneRelated(rule, "MSFT_NetAddressFilter"))
        {
            result.LocalAddresses = FirstOrAny(ReadStringArray(address["LocalAddress"]));
            result.RemoteAddresses = FirstOrAny(ReadStringArray(address["RemoteAddress"]));
        }
        using (ManagementObject port = RequireOneRelated(rule, "MSFT_NetProtocolPortFilter"))
        {
            result.LocalPorts = FirstOrAny(ReadStringArray(port["LocalPort"]));
            result.RemotePorts = FirstOrAny(ReadStringArray(port["RemotePort"]));
            result.Protocol = ProtocolNumber((string)port["Protocol"]);
        }
        using (ManagementObject application = RequireOneRelated(rule, "MSFT_NetApplicationFilter"))
        { result.ApplicationName = NoneIfAny((string)application["AppPath"]); }
        using (ManagementObject service = RequireOneRelated(rule, "MSFT_NetServiceFilter"))
        { result.ServiceName = NoneIfAny((string)service["ServiceName"]); }
        using (ManagementObject interfaceType = RequireOneRelated(rule, "MSFT_NetInterfaceTypeFilter"))
        {
            int raw = Convert.ToInt32(interfaceType["InterfaceType"], CultureInfo.InvariantCulture);
            if (raw != 0)
            { throw new FirewallReadbackUnsupportedException("Unsupported InterfaceType restriction on a management-transport rule readback."); }
        }
        using (ManagementObject byInterface = RequireOneRelated(rule, "MSFT_NetInterfaceFilter"))
        {
            string[] aliases = ReadStringArray(byInterface["InterfaceAlias"]);
            if (aliases.Length != 0 && !(aliases.Length == 1 && aliases[0] == AnySentinel))
            { throw new FirewallReadbackUnsupportedException("Unsupported interface-alias restriction on a management-transport rule readback."); }
        }
        using (ManagementObject security = RequireOneRelated(rule, "MSFT_NetNetworkLayerSecurityFilter"))
        {
            // SecureFlags is fixed at 0 above (this transport never sets Authentication/Encryption/
            // OverrideBlockRules when creating a rule), so a rule that actually requires them here
            // must be refused rather than silently reported as SecureFlags=0 -- otherwise a check
            // against an IPsec-secured rule would show the wrong security state, and an Add's post-
            // write property comparison could miss a real difference.
            int authentication = Convert.ToInt32(security["Authentication"], CultureInfo.InvariantCulture);
            int encryption = Convert.ToInt32(security["Encryption"], CultureInfo.InvariantCulture);
            bool overrideBlockRules = Convert.ToBoolean(security["OverrideBlockRules"], CultureInfo.InvariantCulture);
            if (authentication != 0 || encryption != 0 || overrideBlockRules)
            {
                throw new FirewallReadbackUnsupportedException(
                    "Unsupported Authentication/Encryption/OverrideBlockRules restriction on a management-transport rule readback.");
            }
            result.LocalUserAuthorizedList = NoneIfAny((string)security["LocalUsers"]);
            result.RemoteUserAuthorizedList = NoneIfAny((string)security["RemoteUsers"]);
            result.RemoteMachineAuthorizedList = NoneIfAny((string)security["RemoteMachines"]);
        }
        return result;
    }

    public void PrepareAdd(FirewallRuleData rule)
    {
        if (rule == null) { throw new ArgumentNullException("rule"); }
        if (rule.Interfaces == null || rule.Interfaces.Length != 0)
        { throw new FirewallRefusalException("Detached firewall rules must have no interface restrictions."); }
        if (preparedRule != null) { throw new FirewallRefusalException("A detached rule is already prepared."); }
        // Protocol/program cannot be verified pre-commit (see class remarks), but an unsupported
        // protocol is a pure input-validation failure that costs nothing to catch this early.
        ProtocolName(rule.Protocol);
        using (ManagementClass ruleClass = new ManagementClass(scope, new ManagementPath("MSFT_NetFirewallRule"), null))
        using (ManagementObject detached = ruleClass.CreateInstance())
        {
            if (detached == null) { throw new FirewallRefusalException("MSFT_NetFirewallRule.CreateInstance returned no instance."); }
            ApplyDirectProperties(detached, rule);
            IList<string> differences = DirectPropertyMismatches(rule, ReadDirectProperties(detached));
            if (differences.Count != 0)
            {
                throw new FirewallRefusalException("New management rule has unexpected attributes before commit: " +
                    string.Join(", ", differences));
            }
        }
        preparedRule = rule;
    }

    public MutationStatus Add()
    {
        if (preparedRule == null) { throw new FirewallRefusalException("No detached rule was prepared."); }
        FirewallRuleData rule = preparedRule;
        using (ManagementClass ruleClass = new ManagementClass(scope, new ManagementPath("MSFT_NetFirewallRule"), null))
        using (ManagementObject instance = ruleClass.CreateInstance())
        {
            ApplyDirectProperties(instance, rule);
            PutOptions options = new PutOptions();
            // CreateOnly only rejects a literal key (InstanceID) collision; since InstanceID is left
            // unset above, every Put gets its own fresh auto-generated key, so this no longer guards
            // against two rules sharing an ElementName the way it would if InstanceID were still
            // explicitly set to rule.Name. Duplicate-name protection now rests entirely on the
            // application-level baseline/preflight checks in FirewallOperation.Probe, the same
            // non-atomic name-based model com/native already rely on (see the ownership-race warning
            // printed before every add/remove).
            options.Type = PutType.CreateOnly;
            if (rule.RemoteAddresses != "*") { options.Context.Add("RemoteAddress", new[] { rule.RemoteAddresses }); }
            options.Context.Add("Protocol", ProtocolName(rule.Protocol));
            if (rule.LocalPorts != "*") { options.Context.Add("LocalPort", new[] { rule.LocalPorts }); }
            if (rule.RemotePorts != "*") { options.Context.Add("RemotePort", new[] { rule.RemotePorts }); }
            if (!string.IsNullOrEmpty(rule.ApplicationName)) { options.Context.Add("Program", rule.ApplicationName); }
            instance.Put(options);
        }
        preparedRule = null;
        return MutationStatus.ApiSucceeded;
    }

    public MutationStatus Remove(string name)
    {
        using (ManagementObjectSearcher searcher = new ManagementObjectSearcher(scope,
            new ObjectQuery("SELECT * FROM MSFT_NetFirewallRule WHERE ElementName = '" + EscapeWql(name) + "'")))
        using (ManagementObjectCollection matches = searcher.Get())
        using (ManagementObject only = RequireOne(matches, "MSFT_NetFirewallRule:" + name))
        {
            only.Delete();
        }
        return MutationStatus.ApiSucceeded;
    }

    public void Dispose() { }

    private static void ApplyDirectProperties(ManagementObject instance, FirewallRuleData rule)
    {
        // InstanceID is deliberately left unset: New-NetFirewallRule's own CDXML does not require it
        // either, and the provider auto-generates one the same way it does for every com/native-
        // created rule (see the FindByName remarks above) -- so a management-created rule's identity
        // behavior matches every other rule instead of depending on a caller-supplied key being honored.
        instance["ElementName"] = rule.Name;
        instance["Description"] = rule.Description;
        instance["RuleGroup"] = rule.Grouping;
        instance["Enabled"] = (ushort)RuleEnabledToRaw(rule.Enabled);
        instance["Direction"] = (ushort)rule.Direction;
        instance["Action"] = (ushort)RuleActionToRaw(rule.Action);
        instance["Profiles"] = (ushort)rule.Profiles;
        instance["EdgeTraversalPolicy"] = (ushort)0;
    }

    private static FirewallRuleData ReadDirectProperties(ManagementObject detached)
    {
        return new FirewallRuleData
        {
            Name = (string)detached["ElementName"],
            Grouping = (string)detached["RuleGroup"] ?? "",
            Description = (string)detached["Description"] ?? "",
            Enabled = RuleEnabledFromRaw(Convert.ToInt32(detached["Enabled"], CultureInfo.InvariantCulture)),
            Direction = Convert.ToInt32(detached["Direction"], CultureInfo.InvariantCulture),
            Action = RuleActionFromRaw(Convert.ToInt32(detached["Action"], CultureInfo.InvariantCulture)),
            Profiles = Convert.ToInt32(detached["Profiles"], CultureInfo.InvariantCulture)
        };
    }

    private static IList<string> DirectPropertyMismatches(FirewallRuleData expected, FirewallRuleData actual)
    {
        List<string> result = new List<string>();
        if (!string.Equals(expected.Name, actual.Name, StringComparison.Ordinal)) { result.Add("Name"); }
        if (!string.Equals(expected.Grouping, actual.Grouping, StringComparison.Ordinal)) { result.Add("Grouping"); }
        if (!string.Equals(expected.Description, actual.Description, StringComparison.Ordinal)) { result.Add("Description"); }
        if (expected.Enabled != actual.Enabled) { result.Add("Enabled"); }
        if (expected.Direction != actual.Direction) { result.Add("Direction"); }
        if (expected.Action != actual.Action) { result.Add("Action"); }
        if (expected.Profiles != actual.Profiles) { result.Add("Profiles"); }
        return result;
    }

    // MSFT_NetFirewallRule.Action's live ValueMap (Get-CimClass against root\StandardCimv2 on a
    // real host) is {2, 3, 4}, not {0, 2, 4}: 0 (NotConfigured) is a NetSecurity.Action value the
    // PowerShell-facing enum shares with profile-level DefaultInboundAction/DefaultOutboundAction
    // (see ResolveProfileAction) but which a rule's own Action never actually takes. Raw value 3 is
    // a real, named CIM value this schema query could not identify by name (no rule using it existed
    // on the host used to verify this mapping); this tool only ever creates Allow(2)/Block(4) rules,
    // so 3 is recognized-but-unsupported rather than truly unrecognized.
    internal static int RuleActionFromRaw(int raw)
    {
        if (raw == 2) { return 1; }
        if (raw == 4) { return 0; }
        if (raw == 3)
        {
            throw new FirewallReadbackUnsupportedException(
                "MSFT_NetFirewallRule.Action=3 is a recognized but unsupported action; this transport only creates Allow/Block rules.");
        }
        throw new FirewallRefusalException("Unrecognized MSFT_NetFirewallRule.Action value: " + raw.ToString(CultureInfo.InvariantCulture));
    }

    internal static int RuleActionToRaw(int action) { return action == 1 ? 2 : 4; }

    // MSFT_NetFirewallRule.Enabled: 1=True, 2=False (NetSecurity.Enabled; distinct from the profile-
    // level NetSecurity.GpoBoolean used by MSFT_NetFirewallProfile.Enabled).
    internal static bool RuleEnabledFromRaw(int raw)
    {
        if (raw == 1) { return true; }
        if (raw == 2) { return false; }
        throw new FirewallRefusalException("Unrecognized MSFT_NetFirewallRule.Enabled value: " + raw.ToString(CultureInfo.InvariantCulture));
    }

    internal static int RuleEnabledToRaw(bool enabled) { return enabled ? 1 : 2; }

    // Message text deliberately does not name a transport: reused as-is by PowerShellFirewallBackend
    // and CmdFirewallBackend, whose callers already prefix/attribute the failure to their own
    // transport where it matters (see FindByName's callers in each).
    internal static int ProtocolNumber(string protocol)
    {
        if (string.Equals(protocol, "TCP", StringComparison.OrdinalIgnoreCase)) { return 6; }
        if (string.Equals(protocol, "UDP", StringComparison.OrdinalIgnoreCase)) { return 17; }
        throw new FirewallReadbackUnsupportedException("Unsupported protocol on a firewall rule readback: " + protocol);
    }

    internal static string ProtocolName(int protocol)
    {
        if (protocol == 6) { return "TCP"; }
        if (protocol == 17) { return "UDP"; }
        throw new FirewallRefusalException("Unsupported protocol for the management transport.");
    }

    private static string[] ReadStringArray(object value)
    {
        if (value == null || value == DBNull.Value) { return new string[0]; }
        string[] array = value as string[];
        if (array != null) { return array; }
        string single = value as string;
        if (single != null) { return new[] { single }; }
        throw new FirewallRefusalException("Unexpected firewall filter array type.");
    }

    // Message text deliberately does not name a transport: reused as-is by PowerShellFirewallBackend.
    internal static string FirstOrAny(string[] values)
    {
        if (values.Length == 0) { return "*"; }
        if (values.Length == 1) { return values[0] == AnySentinel ? "*" : values[0]; }
        throw new FirewallReadbackUnsupportedException("Unsupported multi-value firewall filter on a firewall rule readback.");
    }

    internal static string NoneIfAny(string value)
    {
        return string.IsNullOrEmpty(value) || value == AnySentinel ? "" : value;
    }

    // DisabledInterfaceAliases (unlike the address/port/application/service filters above, which use
    // the "Any" sentinel) reports an unset value as a single-element ["NotConfigured"] array rather
    // than an empty one; normalize both to empty so management's readback matches com/native's.
    internal static string[] FilterUnconfiguredSentinel(string[] values)
    {
        return values.Length == 1 && (values[0] == "NotConfigured" || values[0] == AnySentinel) ? new string[0] : values;
    }

    // WQL treats \ as an escape character; a name containing one (e.g. a pre-existing rule's
    // ElementName like "@%SystemRoot%\system32\firewallapi.dll,-37305") makes an unescaped WHERE
    // clause an invalid query (WBEM_E_INVALID_QUERY), not merely a non-match. Escape \ before '
    // so the quote-doubling below can't reinterpret an escaped backslash.
    private static string EscapeWql(string value) { return value.Replace("\\", "\\\\").Replace("'", "''"); }

    // Every real firewall rule always carries exactly one instance of each MSFT_Net*Filter kind
    // (Windows itself creates the full filter tuple, defaulted to "no restriction", for every rule);
    // zero or multiple is an unobserved/ambiguous provider state, not "no restriction", so this fails
    // loud rather than silently picking one -- mirroring AsrModule.RequireSingleInstance.
    private static ManagementObject RequireOneRelated(ManagementObject rule, string relatedClass)
    {
        using (ManagementObjectCollection related = rule.GetRelated(relatedClass))
        {
            return RequireOne(related, relatedClass);
        }
    }

    // This refusal must stay a plain FirewallRefusalException, never FirewallReadbackUnsupportedException:
    // finding zero or more than one of a filter kind is a structural anomaly (something is actually
    // broken), not a merely-unsupported-but-valid rule shape, so it must never be treated as skippable
    // by a caller like the regression test's real-rule candidate loop. Not covered by a unit test --
    // exercising it needs a live ManagementObjectCollection with a contrived 0-or-2+-count shape, which
    // construction-only testing cannot produce (see ManagementReadbackClassification in the tests).
    private static ManagementObject RequireOne(ManagementObjectCollection collection, string description)
    {
        ManagementObject only = null;
        int count = 0;
        foreach (ManagementObject candidate in collection)
        {
            count++;
            if (only == null) { only = candidate; } else { candidate.Dispose(); }
        }
        if (count != 1)
        {
            if (only != null) { only.Dispose(); }
            throw new FirewallRefusalException("Expected exactly one " + description + "; found " +
                count.ToString(CultureInfo.InvariantCulture) + ".");
        }
        return only;
    }
}
