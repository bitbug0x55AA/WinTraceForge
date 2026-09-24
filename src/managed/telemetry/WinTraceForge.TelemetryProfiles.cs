// This Source Code Form is subject to the terms of the
// Mozilla Public License, v. 2.0.
// If a copy of the MPL was not distributed with this file, You can obtain one at https://mozilla.org/MPL/2.0/.

using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;

internal sealed class EventLogChannel
{
    internal readonly string Name, Provider, Filter;
    internal EventLogChannel(string name, string provider, string filter)
    {
        if (string.IsNullOrWhiteSpace(name) || string.IsNullOrWhiteSpace(provider) || string.IsNullOrWhiteSpace(filter))
        { throw new ArgumentException("An event-log channel requires a name, provider and filter."); }
        Name = name; Provider = provider; Filter = filter;
    }
}

internal sealed class EtwProvider
{
    internal readonly string Name;
    internal readonly Guid Id;
    internal EtwProvider(string name, Guid id)
    {
        if (string.IsNullOrWhiteSpace(name) || id == Guid.Empty)
        { throw new ArgumentException("An ETW provider requires a name and nonempty GUID."); }
        Name = name; Id = id;
    }
}

internal sealed class TelemetryProfile
{
    internal const int MaxEtwProviders = 16;
    internal readonly string Name;
    internal readonly ReadOnlyCollection<EventLogChannel> EventLogChannels;
    internal readonly ReadOnlyCollection<EtwProvider> EtwProviders;
    internal readonly Func<ControlOptions, IEnumerable<string>> EvidenceValues;
    private readonly Func<TelemetryEvidence.ParsedEvent, IEnumerable<string>, int, string> correlator;
    private readonly Func<string, bool> interestingField;
    private readonly Func<TelemetryEvidence.ParsedEvent, string> interpreter;

    internal TelemetryProfile(string name, EventLogChannel[] channels, EtwProvider[] providers,
        Func<ControlOptions, IEnumerable<string>> evidenceValues,
        Func<TelemetryEvidence.ParsedEvent, IEnumerable<string>, int, string> correlator,
        Func<string, bool> interestingField,
        Func<TelemetryEvidence.ParsedEvent, string> interpreter)
    {
        if (string.IsNullOrWhiteSpace(name) || channels == null || channels.Length == 0 ||
            providers == null || providers.Length == 0 || providers.Length > MaxEtwProviders ||
            evidenceValues == null || correlator == null || interestingField == null || interpreter == null)
        { throw new ArgumentException("Telemetry profile requires explicit channels, 1..16 providers, evidence and correlator."); }
        var ids = new HashSet<Guid>();
        foreach (EtwProvider provider in providers)
        {
            if (provider == null || !ids.Add(provider.Id))
            { throw new ArgumentException("Telemetry profile has null or duplicate ETW providers."); }
        }
        foreach (EventLogChannel channel in channels)
        {
            if (channel == null) { throw new ArgumentException("Telemetry profile has a null channel."); }
        }
        Name = name;
        EventLogChannels = Array.AsReadOnly((EventLogChannel[])channels.Clone());
        EtwProviders = Array.AsReadOnly((EtwProvider[])providers.Clone());
        EvidenceValues = evidenceValues;
        this.correlator = correlator;
        this.interestingField = interestingField;
        this.interpreter = interpreter;
    }

    internal bool DisplayField(string name) { return interestingField(name); }
    internal string Interpret(TelemetryEvidence.ParsedEvent parsed) { return interpreter(parsed); }

    internal Guid[] ProviderIds()
    {
        var result = new Guid[EtwProviders.Count];
        for (int i = 0; i < result.Length; i++) { result[i] = EtwProviders[i].Id; }
        return result;
    }

    internal void ResolveEtwProviderName(TelemetryEvidence.ParsedEvent parsed)
    {
        if (!string.IsNullOrEmpty(parsed.Provider) && parsed.Provider != "(missing)") { return; }
        Guid id;
        if (!Guid.TryParse(parsed.ProviderGuid, out id)) { return; }
        foreach (EtwProvider provider in EtwProviders)
        {
            if (provider.Id == id) { parsed.Provider = provider.Name; return; }
        }
    }

    internal bool ContainsEtwProvider(TelemetryEvidence.ParsedEvent parsed)
    {
        Guid id;
        bool hasId = Guid.TryParse(parsed.ProviderGuid, out id);
        foreach (EtwProvider provider in EtwProviders)
        {
            if (hasId ? provider.Id == id : provider.Name == parsed.Provider) { return true; }
        }
        return false;
    }

    internal string Correlate(TelemetryEvidence.ParsedEvent parsed, ControlOptions options, int processId)
    {
        return correlator(parsed, EvidenceValues(options), processId);
    }
}

internal static class CommonTelemetryChannels
{
    internal static readonly EventLogChannel ProcessCreation = new EventLogChannel(
        "Security", "Microsoft-Windows-Security-Auditing", "(EventID=4688)");
    internal static readonly EventLogChannel Sysmon = new EventLogChannel(
        "Microsoft-Windows-Sysmon/Operational", "Microsoft-Windows-Sysmon", "(EventID=1)");
}

internal static class TelemetryPresentation
{
    internal static Func<string, bool> Fields(params string[] names)
    {
        var allowed = new HashSet<string>(names, StringComparer.OrdinalIgnoreCase);
        return delegate(string name) { return allowed.Contains(name.Replace(" ", "").Replace("_", "")); };
    }
    internal static readonly Func<string, bool> DefenderFields = Fields(
        "OldValue", "NewValue", "Setting", "SettingName", "Value", "ClientProcessId",
        "ProcessId", "NewProcessId", "NewProcessName", "ParentProcessName", "Image",
        "ParentImage", "CommandLine", "User", "SubjectUserName", "SubjectDomainName",
        "Operation", "ResultCode", "PossibleCause", "ClientMachine", "ProcessGuid");
    internal static readonly Func<string, bool> FirewallFields = Fields(
        "RuleName", "RuleId", "Action", "Direction", "Profiles", "Active",
        "ApplicationPath", "ModifyingApplication", "ModifyingUser", "RemoteAddresses",
        "RemotePorts", "LocalPorts", "Protocol", "LocalAddresses", "ServiceName",
        "EdgeTraversal", "SecurityOptions", "RuleStatus", "Origin", "ProcessId",
        "NewProcessId", "NewProcessName", "ParentProcessName", "Image", "ParentImage",
        "CommandLine", "User", "SubjectUserName", "SubjectDomainName", "ProcessGuid");
}

// Compatibility aliases for existing tests; new families own their profiles in their own files.
internal static class TelemetryProfiles
{
    internal static readonly TelemetryProfile DefenderExclusion = DefenderTelemetry.Profile;
    internal static readonly TelemetryProfile Firewall = FirewallTelemetry.Profile;
}

internal static class DefenderTelemetry
{
    internal static readonly TelemetryProfile Profile = new TelemetryProfile(
        "Defender exclusions",
        new[] {
            new EventLogChannel("Microsoft-Windows-Windows Defender/Operational",
                "Microsoft-Windows-Windows Defender", "(EventID=5007 or EventID=5013)"),
            new EventLogChannel("Microsoft-Windows-WMI-Activity/Operational", "Microsoft-Windows-WMI-Activity",
                "(EventID=5857 or EventID=5858 or EventID=5859 or EventID=5860 or EventID=5861)"),
            CommonTelemetryChannels.ProcessCreation, CommonTelemetryChannels.Sysmon
        },
        new[] {
            new EtwProvider("Microsoft-Windows-WMI-Activity", new Guid("1418ef04-b0b4-4623-bf7e-d74ab47bbdaa")),
            new EtwProvider("Microsoft-Windows-Windows Defender", new Guid("11cd958a-c507-4ef3-b3f2-5fd9dfbd2c78"))
        }, RequestedValues, TelemetryEvidence.CorrelateDefender,
        TelemetryPresentation.DefenderFields, Interpret);

    private static IEnumerable<string> RequestedValues(ControlOptions options) { return options.EvidenceValues; }
    private static string Interpret(TelemetryEvidence.ParsedEvent parsed)
    {
        if (parsed.Provider == "Microsoft-Windows-WMI-Activity")
        { return "WMI activity may be a query; it does not by itself prove Add was invoked."; }
        if (parsed.Provider == "Microsoft-Windows-Windows Defender")
        { return parsed.Id == 5007 ? "Configuration change: verify setting and authorization." :
            "Blocked setting change: verify the setting and attribution to this run."; }
        return "Process-start evidence only; not proof of a WMI method invocation.";
    }
}

internal static class FirewallTelemetry
{
    internal static readonly TelemetryProfile Profile = new TelemetryProfile(
        "Windows Firewall",
        new[] {
            new EventLogChannel("Microsoft-Windows-Windows Firewall With Advanced Security/Firewall",
                "Microsoft-Windows-Windows Firewall With Advanced Security", "(EventID=2004 or EventID=2005 or EventID=2006)"),
            new EventLogChannel("Security", "Microsoft-Windows-Security-Auditing",
                "(EventID=4688 or EventID=4946 or EventID=4947 or EventID=4948)"),
            CommonTelemetryChannels.Sysmon
        },
        new[] {
            new EtwProvider("Microsoft-Windows-Windows Firewall With Advanced Security",
                new Guid("d1bc9aff-2abf-4d71-9146-ecb2a986eb85"))
        }, RequestedValues, TelemetryEvidence.CorrelateFirewall,
        TelemetryPresentation.FirewallFields, Interpret);

    private static IEnumerable<string> RequestedValues(ControlOptions options) { return options.EvidenceValues; }
    private static string Interpret(TelemetryEvidence.ParsedEvent parsed)
    {
        if (parsed.Provider == "Microsoft-Windows-Windows Firewall With Advanced Security" ||
            (parsed.Provider == "Microsoft-Windows-Security-Auditing" && parsed.Id >= 4946 && parsed.Id <= 4948))
        { return "Firewall rule-change evidence only; not proof of packet blocking/allowing."; }
        return "Process-start evidence only; not proof of a WMI method invocation.";
    }
}
