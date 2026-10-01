// This Source Code Form is subject to the terms of the
// Mozilla Public License, v. 2.0.
// If a copy of the MPL was not distributed with this file, You can obtain one at https://mozilla.org/MPL/2.0/.

using System;
using System.Collections.Generic;
using System.Globalization;
using System.Text;

// Which Windows Firewall policy store "firewall rule list" enumerates. Active is the rule set the
// firewall currently applies to this host (NetSecurity's -PolicyStore ActiveStore); Persistent is the
// machine-local persistent store (-PolicyStore PersistentStore), for checking local configuration.
internal enum FirewallPolicyStore { Active, Persistent }

// One rule as shown by "firewall rule list": an inventory summary, deliberately not the full
// FirewallRuleData readback (no address/port/program/security-filter decoding). Every value is the
// decoded display text of the raw provider value, so two transports that read the same rule produce
// identical strings and can be compared field by field. A value that could not be read or decoded is
// never dropped: it is shown as "Unavailable"/"Unknown(<raw>)" and named in Limits.
internal sealed class FirewallRuleSummary
{
    internal string Id, DisplayName, Enabled, Direction, Action, Profiles, Source;
    internal readonly List<string> Limits = new List<string>();
}

// Enumeration-only read contract, separate from IFirewallBackend on purpose: listing every rule must
// not be routed through the per-rule ownership/readback path ("rule check"), and this interface has no
// way to add, change or remove anything.
internal interface IFirewallRuleEnumerator : IDisposable
{
    IList<FirewallRuleSummary> ListRules(FirewallPolicyStore store);
}

// The enumeration did not run to a trustworthy end. Never mapped to an empty or partial list: the caller
// reports the inventory as incomplete and exits non-zero. ReadCount is how many rules had been decoded
// when it failed (-1 when unknown); those rules are not shown.
internal sealed class FirewallListIncompleteException : InvalidOperationException
{
    internal readonly int ReadCount;
    internal FirewallListIncompleteException(string message, int readCount, Exception inner) : base(message, inner)
    { ReadCount = readCount; }
    internal FirewallListIncompleteException(string message, int readCount) : this(message, readCount, null) { }
}

internal static class FirewallRuleListCodec
{
    internal const string Unreadable = "(unreadable)";

    internal static string StoreLabel(FirewallPolicyStore store)
    {
        return store == FirewallPolicyStore.Active ? "active" : "persistent";
    }

    // The literal NetSecurity/WMI PolicyStore name. Never derived from caller text.
    internal static string StoreProviderName(FirewallPolicyStore store)
    {
        return store == FirewallPolicyStore.Active ? "ActiveStore" : "PersistentStore";
    }

    internal static string StoreMeaning(FirewallPolicyStore store)
    {
        return store == FirewallPolicyStore.Active ?
            "the provider's ActiveStore view (rules the firewall service reports as active; GPO/MDM merge outcome not established)" :
            "rules in the machine-local persistent store (PersistentStore)";
    }

    // Raw MSFT_NetFirewallRule values (identical from WMI and from a NetSecurity cmdlet cast to [int]).
    internal static string EnabledName(int raw) { return raw == 1 ? "True" : raw == 2 ? "False" : null; }
    internal static string DirectionName(int raw) { return raw == 1 ? "Inbound" : raw == 2 ? "Outbound" : null; }

    // Action 3 exists in the provider's ValueMap but this tool has never identified it by name, so it is
    // reported as an undecoded value rather than guessed at.
    internal static string ActionName(int raw) { return raw == 2 ? "Allow" : raw == 4 ? "Block" : null; }

    // Profiles is a bitmask (1=Domain, 2=Private, 4=Public); 0 is "Any". A rule stored with 0 and one stored
    // with 7 are different raw states and are shown differently, exactly as the provider reports them.
    internal static string ProfilesName(int raw)
    {
        if (raw == 0) { return "Any"; }
        if (raw < 0 || (raw & ~7) != 0) { return null; }
        return FirewallModule.ProfileList(raw);
    }

    // NetSecurity.PolicyStoreType.
    internal static string SourceTypeName(int raw)
    {
        switch (raw)
        {
            case 0: return "None";
            case 1: return "Local";
            case 2: return "GroupPolicy";
            case 3: return "Dynamic";
            case 4: return "Generated";
            case 5: return "Hardcoded";
            case 6: return "MDM";
            case 8: return "HostFirewallLocal";
            case 9: return "HostFirewallGroupPolicy";
            case 10: return "HostFirewallDynamic";
            case 11: return "HostFirewallMDM";
            default: return null;
        }
    }

    // A null argument means the transport could not read that value at all.
    internal static FirewallRuleSummary Build(string id, string displayName, int? enabled, int? direction,
        int? action, int? profiles, int? sourceType, string source)
    {
        FirewallRuleSummary summary = new FirewallRuleSummary();
        if (id == null) { summary.Id = Unreadable; summary.Limits.Add("Id unavailable"); }
        else { summary.Id = id; }
        if (displayName == null) { summary.DisplayName = Unreadable; summary.Limits.Add("DisplayName unavailable"); }
        else
        {
            summary.DisplayName = displayName;
            // Built-in and app-package rules store a resource reference ("@FirewallAPI.dll,-32765") that the
            // provider resolves into DisplayName for the caller's locale. One it could not resolve is
            // flagged, not hidden.
            if (displayName.StartsWith("@", StringComparison.Ordinal))
            { summary.Limits.Add("DisplayName may be an unresolved resource reference"); }
        }
        summary.Enabled = Decode(enabled, "Enabled", summary.Limits, EnabledName);
        summary.Direction = Decode(direction, "Direction", summary.Limits, DirectionName);
        summary.Action = Decode(action, "Action", summary.Limits, ActionName);
        summary.Profiles = Decode(profiles, "Profiles", summary.Limits, ProfilesName);
        string type = Decode(sourceType, "PolicyStoreSourceType", summary.Limits, SourceTypeName);
        summary.Source = string.IsNullOrEmpty(source) ? type : type + " (" + source + ")";
        return summary;
    }

    private static string Decode(int? raw, string field, List<string> limits, Func<int, string> name)
    {
        if (raw == null) { limits.Add(field + " unavailable"); return "Unavailable"; }
        string text = name(raw.Value);
        if (text != null) { return text; }
        limits.Add(field + " value " + raw.Value.ToString(CultureInfo.InvariantCulture) + " not decoded");
        return "Unknown(" + raw.Value.ToString(CultureInfo.InvariantCulture) + ")";
    }

    // Third-party rules control these strings; a terminal escape sequence or a line break in a rule name
    // must not reach the console as such.
    internal static string Clean(string value)
    {
        if (value == null) { return ""; }
        StringBuilder builder = new StringBuilder(value.Length);
        foreach (char c in value) { builder.Append(c < ' ' || c == '\u007f' ? '?' : c); }
        return builder.ToString();
    }
}
