// This Source Code Form is subject to the terms of the
// Mozilla Public License, v. 2.0.
// If a copy of the MPL was not distributed with this file, You can obtain one at https://mozilla.org/MPL/2.0/.

using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Management;
using System.Net;
using System.Net.Sockets;
using System.Reflection;
using System.Runtime.ExceptionServices;
using System.Runtime.InteropServices;
using System.Security;
using System.Security.Principal;

internal sealed class FirewallOptions : ControlOptions
{
    internal string Operation;
    internal string Transport = "com";
    internal Guid Id;
    internal bool GeneratedId;
    internal string RemoteAddress;
    internal int RemotePort;
    internal int LocalPort;
    internal int Direction = 2;
    internal int Action;
    internal int Protocol = 6;
    internal int Profiles;
    internal string Program = "";
    internal string RuleName { get { return FirewallModule.NameFor(Id); } }
    internal override TelemetryProfile Telemetry { get { return FirewallTelemetry.Profile; } }
    internal override IEnumerable<string> EvidenceValues
    {
        get
        {
            if (Kind == ControlKind.FirewallRule)
            {
                yield return RuleName;
            }
        }
    }
}

internal sealed class FirewallRunEvidence : ControlRunEvidence
{
    internal ControlLifecycleResult<FirewallBaseline> Lifecycle;
    internal bool BaselineRead;
    internal bool MutationAttempted;
    internal bool MutationReturned;
    internal MutationStatus MutationOutcome = MutationStatus.NotAttempted;
    internal bool ReadbackConfirmed;
    internal bool AlreadyAbsent;
    internal int FrozenProfiles;
    internal int? PolicyModifyState;
    internal string Outcome = "Not started; no mutation attempted.";
}

internal sealed class FirewallRuleData
{
    internal string Name, Grouping, Description, ApplicationName, ServiceName;
    internal string LocalAddresses, RemoteAddresses, LocalPorts, RemotePorts, InterfaceTypes;
    internal string LocalAppPackageId, LocalUserOwner, LocalUserAuthorizedList;
    internal string RemoteUserAuthorizedList, RemoteMachineAuthorizedList;
    internal string[] Interfaces = new string[0];
    internal int Protocol, Direction, Action, Profiles, EdgeTraversalOptions, SecureFlags;
    internal bool Enabled, EdgeTraversal;
    internal FirewallRuleData Copy()
    {
        FirewallRuleData result = (FirewallRuleData)MemberwiseClone();
        result.Interfaces = (string[])Interfaces.Clone();
        return result;
    }
}

internal sealed class FirewallProfileData
{
    internal int Profile, DefaultInboundAction, DefaultOutboundAction;
    internal bool Enabled, BlockAllInbound;
    internal string[] ExcludedInterfaces;
}

internal interface IFirewallBackend : IDisposable
{
    int CurrentProfiles { get; }
    int LocalPolicyModifyState { get; }
    IList<FirewallProfileData> ReadProfiles();
    IList<FirewallRuleData> FindByName(string name);
    void PrepareAdd(FirewallRuleData rule);
    // Returns ApiSucceeded or ApiUnknown only; a definite rejection is reported by throwing, never by
    // returning ApiFailed (see FirewallOperation.Mutate, which passes this straight through to the
    // shared runner). com/native/management always return ApiSucceeded: COM/WMI either throw or
    // definitively succeed. powershell and cmd shell out to a separate process and can legitimately
    // complete without a trustworthy signal either way (no marker found; an ambiguous exit code that
    // could equally mean "netsh rejected this" or "something killed the process after it already
    // wrote the rule") -- ApiUnknown lets the shared post-mutation Verify() readback settle it, the
    // same fallback DefenderModule.PowerShellBackend.Add() already uses for the identical situation.
    MutationStatus Add();
    MutationStatus Remove(string name);
}

internal interface IFirewallReader
{
    int CurrentProfiles { get; }
    int LocalPolicyModifyState { get; }
    IList<FirewallProfileData> ReadProfiles();
    IList<FirewallRuleData> FindByName(string name);
    void PrepareAdd(FirewallRuleData rule);
}

internal interface IFirewallWriter
{
    MutationStatus Add();
    MutationStatus Remove(string name);
}

internal class FirewallRefusalException : InvalidOperationException
{
    internal FirewallRefusalException(string message) : base(message) { }
}

// A precise, catchable subtype for a readback limitation this transport documents as deliberate
// (a rule shape -- interface-alias/interface-type restriction, or an unsupported Action value --
// that ReadRule/RuleActionFromRaw refuse to decode), distinct from a plain FirewallRefusalException
// that signals something is actually broken. Lets callers (the regression test's real-rule candidate
// loop) distinguish "skip, known unsupported shape" from "this must never silently pass" by type
// rather than by matching exact message wording, which would silently stop working if a message
// were reworded.
internal sealed class FirewallReadbackUnsupportedException : FirewallRefusalException
{
    internal FirewallReadbackUnsupportedException(string message) : base(message) { }
}

internal static partial class FirewallModule
{
    internal const string Group = "WinTraceForge.Firewall.v1";
    private const string NamePrefix = "WinTraceForge.Firewall.";
    internal static string NameFor(Guid id) { return NamePrefix + id.ToString("D"); }
    internal static string DescriptionFor(Guid id)
    {
        return "WinTraceForge;kind=firewall-rule;schema=1;id=" + id.ToString("D");
    }

    internal static int Main(string[] args)
    {
        FirewallOptions options;
        try { options = Parse(args); }
        catch (ArgumentException error)
        {
            ConsoleUi.Configure(false, true);
            ConsoleUi.Status("FAIL", error.Message, true);
            Help();
            return 2;
        }
        ConsoleUi.Configure(options.Verbose, options.NoColor);
        ConsoleUi.Banner();
        if (options.Help) { Help(); return 0; }
        FirewallRunEvidence evidence = new FirewallRunEvidence();
        return ControlRuntime.Execute(options, evidence,
            delegate { return Execute(options, evidence, delegate { return CreateBackend(options.Transport); }, IsAdministrator); },
            delegate(int exitCode) { Assess(options, evidence, exitCode); });
    }

    internal static IFirewallBackend CreateBackend(string transport)
    {
        switch (transport)
        {
            case "com": return new ComFirewallBackend();
            case "native": return new NativeFirewallBackend();
            case "management": return new ManagementFirewallBackend();
            case "powershell": return new PowerShellFirewallBackend();
            case "cmd": return new CmdFirewallBackend();
            default: throw new FirewallRefusalException("Unknown Firewall transport; no fallback.");
        }
    }

    internal static FirewallOptions Parse(string[] args)
    {
        if (args == null) { throw new ArgumentException("Missing firewall command."); }
        FirewallOptions options = new FirewallOptions();
        options.Kind = ControlKind.FirewallRule;
        int start;
        if (args.Length >= 1 && IsHelp(args[0]))
        {
            options.Help = true;
            options.Operation = "help";
            start = 0;
        }
        else if (args.Length >= 1 && string.Equals(args[0], "profiles", StringComparison.OrdinalIgnoreCase))
        {
            options.Kind = ControlKind.FirewallProfiles;
            options.Operation = "profiles";
            start = 1;
        }
        else if (args.Length >= 2 && string.Equals(args[0], "rule", StringComparison.OrdinalIgnoreCase) && IsHelp(args[1]))
        {
            options.Help = true;
            options.Operation = "help";
            start = 1;
        }
        else if (args.Length >= 2 && string.Equals(args[0], "rule", StringComparison.OrdinalIgnoreCase))
        {
            options.Operation = args[1].ToLowerInvariant();
            if (options.Operation != "add" && options.Operation != "check" && options.Operation != "remove")
            {
                throw new ArgumentException("Expected rule add, rule check, or rule remove.");
            }
            start = 2;
        }
        else { throw new ArgumentException("Expected firewall rule add|check|remove or firewall profiles."); }

        HashSet<string> seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        HashSet<string> allSeen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        for (int i = start; i < args.Length; i++)
        {
            string key = args[i].ToLowerInvariant();
            string canonicalKey = IsHelp(key) ? "--help" : key;
            if (!allSeen.Add(canonicalKey)) { throw new ArgumentException("Duplicate option: " + key); }
            if (CommonArguments.TryParse(args, ref i, options, seen)) { continue; }
            if (key == "--transport")
            {
                if (i + 1 >= args.Length) { throw new ArgumentException("--transport requires com, native, management, powershell, or cmd."); }
                options.Transport = args[++i].ToLowerInvariant();
                if (options.Transport != "com" && options.Transport != "native" && options.Transport != "management" &&
                    options.Transport != "powershell" && options.Transport != "cmd")
                {
                    throw new ArgumentException("Firewall transports: com, native, management, powershell, cmd. No fallback.");
                }
                continue;
            }
            if (options.Kind == ControlKind.FirewallProfiles) { throw new ArgumentException("Unknown profiles option: " + key); }
            if (key != "--id" && options.Operation != "add")
            {
                throw new ArgumentException("Check/remove accept only --id, --transport and common options; check does not compare an add request.");
            }
            if (key != "--id" && key != "--remote-address" && key != "--remote-port" &&
                key != "--local-port" && key != "--direction" && key != "--action" &&
                key != "--protocol" && key != "--profiles" && key != "--program")
            {
                throw new ArgumentException("Unknown option: " + key);
            }
            if (i + 1 >= args.Length) { throw new ArgumentException("Missing value for " + key); }
            string value = args[++i];
            switch (key)
            {
                case "--id":
                    if (!Guid.TryParse(value, out options.Id) || options.Id == Guid.Empty)
                    {
                        throw new ArgumentException("--id requires a nonempty GUID.");
                    }
                    break;
                case "--remote-address": options.RemoteAddress = ParseAddress(value); break;
                case "--remote-port": options.RemotePort = ParsePort(value, key); break;
                case "--local-port": options.LocalPort = ParsePort(value, key); break;
                case "--direction": options.Direction = Choice(value, "in", 1, "out", 2, key); break;
                case "--action": options.Action = Choice(value, "block", 0, "allow", 1, key); break;
                case "--protocol": options.Protocol = Choice(value, "tcp", 6, "udp", 17, key); break;
                case "--profiles": options.Profiles = ParseProfiles(value); break;
                case "--program": options.Program = ParseProgram(value); break;
            }
        }
        CommonArguments.Validate(options, seen);
        if (options.Help) { return options; }
        if (options.Kind == ControlKind.FirewallProfiles) { return options; }
        if (options.Operation == "add")
        {
            if (options.RemoteAddress == null || (options.Direction == 2 ? options.RemotePort == 0 : options.LocalPort == 0))
            {
                throw new ArgumentException("Add requires --remote-address literal-IP; outbound requires --remote-port, " +
                    "inbound requires --local-port (1..65535). The opposite-side port is optional.");
            }
            if (options.Id == Guid.Empty) { options.Id = Guid.NewGuid(); options.GeneratedId = true; }
        }
        else if (options.Id == Guid.Empty) { throw new ArgumentException("Check/remove require --id GUID."); }
        return options;
    }

    private static bool IsHelp(string value)
    {
        return string.Equals(value, "--help", StringComparison.OrdinalIgnoreCase) ||
            string.Equals(value, "-help", StringComparison.OrdinalIgnoreCase) || value == "-?";
    }

    private static int Choice(string value, string a, int av, string b, int bv, string key)
    {
        if (string.Equals(value, a, StringComparison.OrdinalIgnoreCase)) { return av; }
        if (string.Equals(value, b, StringComparison.OrdinalIgnoreCase)) { return bv; }
        throw new ArgumentException(key + " requires " + a + " or " + b + ".");
    }

    private static int ParsePort(string value, string key)
    {
        int port;
        if (!int.TryParse(value, NumberStyles.None, CultureInfo.InvariantCulture, out port) || port < 1 || port > 65535)
        {
            throw new ArgumentException(key + " requires an integer from 1 to 65535.");
        }
        return port;
    }

    internal static string ParseAddress(string value)
    {
        IPAddress address;
        if (string.IsNullOrEmpty(value) || value.IndexOf('%') >= 0 || value.IndexOf('[') >= 0 ||
            value != value.Trim() || !IPAddress.TryParse(value, out address))
        {
            throw new ArgumentException("--remote-address requires one unscoped literal IPv4 or IPv6 address, not a host, range, or subnet.");
        }
        if (address.AddressFamily == AddressFamily.InterNetwork)
        {
            string[] parts = value.Split('.');
            if (parts.Length != 4) { throw new ArgumentException("IPv4 must use four decimal octets."); }
            foreach (string part in parts)
            {
                int octet;
                if (part.Length == 0 || (part.Length > 1 && part[0] == '0') ||
                    !int.TryParse(part, NumberStyles.None, CultureInfo.InvariantCulture, out octet) || octet > 255)
                {
                    throw new ArgumentException("IPv4 must use four unambiguous decimal octets.");
                }
            }
        }
        else if (address.AddressFamily != AddressFamily.InterNetworkV6)
        {
            throw new ArgumentException("Only IPv4 and IPv6 literals are supported.");
        }
        return address.ToString();
    }

    private static int ParseProfiles(string value)
    {
        int result = 0;
        string[] values = value.Split(',');
        foreach (string token in values)
        {
            int profile;
            switch (token.ToLowerInvariant())
            {
                case "domain": profile = 1; break;
                case "private": profile = 2; break;
                case "public": profile = 4; break;
                case "all":
                    if (values.Length != 1) { throw new ArgumentException("'all' cannot be combined with other profiles."); }
                    profile = 7;
                    break;
                default: throw new ArgumentException("--profiles requires domain,private,public or all.");
            }
            if ((result & profile) != 0) { throw new ArgumentException("Duplicate profile: " + token); }
            result |= profile;
        }
        return result;
    }

    private static string ParseProgram(string value)
    {
        // Drive-relative, root-relative, device, and alternate-stream paths must not broaden scope.
        bool drive = value.Length >= 3 && char.IsLetter(value[0]) && value[1] == ':' &&
            (value[2] == '\\' || value[2] == '/');
        bool unc = value.StartsWith(@"\\", StringComparison.Ordinal) && !value.StartsWith(@"\\?\", StringComparison.Ordinal) &&
            !value.StartsWith(@"\\.\", StringComparison.Ordinal);
        if ((!drive && !unc) || value.IndexOfAny(Path.GetInvalidPathChars()) >= 0 ||
            value.IndexOfAny(new char[] { '*', '?', '%', '"' }) >= 0 ||
            value.IndexOf(':', drive ? 2 : 0) >= 0 ||
            !string.Equals(Path.GetExtension(value), ".exe", StringComparison.OrdinalIgnoreCase))
        {
            throw new ArgumentException("--program requires a full absolute .exe path without wildcards, variables, or device/stream syntax.");
        }
        string full;
        try { full = Path.GetFullPath(value); }
        catch (PathTooLongException error) { throw new ArgumentException("--program path is too long.", error); }
        catch (NotSupportedException error) { throw new ArgumentException("--program path format is not supported.", error); }
        if (unc && full.Substring(2).Split('\\').Length < 3)
        {
            throw new ArgumentException("UNC program paths require server, share, and executable.");
        }
        return full;
    }

    private static bool IsAdministrator()
    {
        using (WindowsIdentity identity = WindowsIdentity.GetCurrent())
        {
            return new WindowsPrincipal(identity).IsInRole(WindowsBuiltInRole.Administrator);
        }
    }

    internal static int Execute(FirewallOptions options, FirewallRunEvidence evidence,
        Func<IFirewallBackend> createBackend, Func<bool> isAdministrator)
    {
        try
        {
            ConsoleUi.Section("Run");
            ConsoleUi.Row("Control", options.Kind == ControlKind.FirewallProfiles ? "Windows Firewall / Profiles" : "Windows Firewall / Rules");
            ConsoleUi.Row("Operation", options.Operation);
            ConsoleUi.Row("Transport", options.Transport);
            ConsoleUi.Row("Route", RouteDescription(options));
            ConsoleUi.Row("Run ID", evidence.RunId);
            ConsoleUi.Row("Start UTC", evidence.StartUtc.ToString("O", CultureInfo.InvariantCulture));
            ConsoleUi.Row("Host / PID", Environment.MachineName + " / " + evidence.ProcessId);
            using (WindowsIdentity identity = WindowsIdentity.GetCurrent()) { ConsoleUi.Row("Identity", identity.Name); }
            bool mutation = options.Operation == "add" || options.Operation == "remove";
            evidence.Stage = "Firewall preflight";
            if (mutation && !isAdministrator())
            {
                throw new FirewallRefusalException("An elevated administrator token is required for add/remove. No mutation attempted.");
            }
            evidence.Stage = "Firewall " + options.Transport + " backend initialization";
            using (IFirewallBackend backend = createBackend())
            {
                ControlLifecycleResult<FirewallBaseline> result = ControlLifecycle.Run(
                    new FirewallOperation(options, evidence), new FirewallReader(backend), new FirewallWriter(backend),
                    delegate(IControlLifecycleSnapshot current) { return evidence.ObserveNow(); });
                evidence.Lifecycle = result;
                if (result.Errors.Count != 0)
                {
                    evidence.Outcome = evidence.Stage + ": " + string.Join("; ", result.Errors) + ". " +
                        (evidence.MutationAttempted ? "A mutation was attempted; inspect the rule using its ID before cleanup." : "No mutation attempted.");
                }
                if (result.Restoration == RestorationStatus.ManualRequired)
                { ConsoleUi.Row("Restoration", "MANUAL_REQUIRED - " + result.ManualRestoration); }
                return result.ExitCode;
            }
        }
        catch (FirewallRefusalException error) { return Failure(evidence, error); }
        catch (COMException error) { return Failure(evidence, error); }
        catch (ManagementException error) { return Failure(evidence, error); }
        catch (UnauthorizedAccessException error) { return Failure(evidence, error); }
        catch (SecurityException error) { return Failure(evidence, error); }
        catch (InvalidCastException error) { return Failure(evidence, error); }
        catch (NotSupportedException error) { return Failure(evidence, error); }
        catch (MissingMemberException error) { return Failure(evidence, error); }
        catch (DllNotFoundException error) { return NativeLoadFailure(evidence, error); }
        catch (BadImageFormatException error) { return NativeLoadFailure(evidence, error); }
        catch (EntryPointNotFoundException error) { return NativeLoadFailure(evidence, error); }
    }

    // management touches different WMI classes for profiles (MSFT_NetFirewallProfile /
    // MSFT_NetConnectionProfile) than for rule add/check/remove (MSFT_NetFirewallRule and its
    // MSFT_Net*Filter associations); naming MSFT_NetFirewallRule unconditionally would overclaim
    // which boundary a profiles run actually crossed.
    private static string RouteDescription(FirewallOptions options)
    {
        if (options.Transport == "native") { return "P/Invoke -> C++ INetFwPolicy2 / INetFwRule3 -> Windows Firewall"; }
        if (options.Transport == "management")
        {
            return options.Kind == ControlKind.FirewallProfiles ?
                "System.Management -> WMI root\\StandardCimv2 MSFT_NetFirewallProfile / MSFT_NetConnectionProfile -> Windows Firewall" :
                "System.Management -> WMI root\\StandardCimv2 MSFT_NetFirewallRule -> Windows Firewall";
        }
        if (options.Transport == "powershell")
        {
            return options.Kind == ControlKind.FirewallProfiles ?
                "Process -> powershell.exe -> Get-NetFirewallProfile/Get-NetConnectionProfile (NetSecurity/NetConnection modules) -> WMI" :
                "Process -> powershell.exe -> New-/Get-/Remove-NetFirewallRule (NetSecurity module) -> WMI";
        }
        if (options.Transport == "cmd")
        {
            return options.Kind == ControlKind.FirewallProfiles ?
                "Process -> cmd.exe -> netsh.exe advfirewall show allprofiles/currentprofile -> Windows Firewall" :
                "Process -> cmd.exe -> netsh.exe advfirewall firewall add/show/delete rule -> Windows Firewall";
        }
        return "C# COM interop -> INetFwPolicy2 / INetFwRule3 -> Windows Firewall";
    }

    private static int NativeLoadFailure(FirewallRunEvidence evidence, Exception error)
    {
        int result = Failure(evidence, error);
        evidence.Outcome += " Native transport requires the matching x64 WinTraceForge.Native.dll beside the EXE. " +
            "No fallback to com was performed.";
        return result;
    }

    internal static string CleanupCommand(FirewallOptions options)
    {
        return "wtf.exe firewall rule remove --id " + options.Id.ToString("D") +
            " --transport " + options.Transport;
    }

    private static int Failure(FirewallRunEvidence evidence, Exception error)
    {
        evidence.Outcome = evidence.Stage + ": " + error.Message + " (HRESULT 0x" +
            error.HResult.ToString("X8", CultureInfo.InvariantCulture) + "). " +
            (evidence.MutationAttempted ? "A mutation was attempted; inspect the rule using its ID before cleanup." : "No mutation attempted.");
        return evidence.MutationReturned ? 3 : 1;
    }

    internal static void Assess(FirewallOptions options, FirewallRunEvidence evidence, int exitCode)
    {
        ConsoleUi.Section("Assessment");
        if (exitCode == 4) { evidence.Outcome = "ETW setup failed; firewall operation was not run."; }
        string code = exitCode == 4 ? "FIREWALL_NOT_ATTEMPTED" :
            exitCode == 3 ? "FIREWALL_RULE_UNCONFIRMED" :
            exitCode != 0 ? "FIREWALL_OPERATION_ERROR" :
            options.Kind == ControlKind.FirewallProfiles ? "FIREWALL_PROFILES_READ" :
            options.Operation == "add" ? "FIREWALL_RULE_CONFIRMED" :
            options.Operation == "check" ? "FIREWALL_RULE_OWNERSHIP_CONFIRMED" :
            evidence.AlreadyAbsent ? "FIREWALL_RULE_ALREADY_ABSENT" : "FIREWALL_RULE_REMOVED";
        ConsoleUi.Status(exitCode == 0 ? "OK" : exitCode == 3 ? "WARN" : "FAIL", "Outcome: " + code);
        ConsoleUi.Row("Exit / stage", exitCode + " / " + evidence.Stage);
        ConsoleUi.Row("Transport", options.Transport);
        ConsoleUi.Status(exitCode == 0 ? "OK" : exitCode == 3 ? "WARN" : "FAIL", evidence.Outcome, exitCode != 0);
        ConsoleUi.Row("Mutation attempted", evidence.MutationAttempted.ToString());
        ConsoleUi.Row("Mutation returned", evidence.MutationReturned.ToString());
        ConsoleUi.Row("Readback confirmed", evidence.ReadbackConfirmed.ToString());
        if (evidence.Lifecycle != null)
        {
            ConsoleUi.Row("Lifecycle", "probe=" + evidence.Lifecycle.Probe +
                "; mutation=" + evidence.Lifecycle.Mutation +
                "; verification=" + evidence.Lifecycle.Verification +
                "; observation=" + evidence.Lifecycle.Observation +
                "; restoration=" + evidence.Lifecycle.Restoration);
        }
        ConsoleUi.Text("Configuration evidence only: no claim of traffic enforcement, effective GPO/MDM precedence, " +
            "or local-rule merge acceptance. Firewall enablement is never changed; WFP filters are never manipulated.");
        ConsoleUi.Text("Compliance: NOT_ASSESSED | Detection/response: NOT_MEASURED");
        if (options.Kind == ControlKind.FirewallRule && options.Id != Guid.Empty && evidence.MutationAttempted)
        {
            ConsoleUi.Text("Cleanup (ownership-checked): " + CleanupCommand(options));
        }
        if (!options.Verbose)
        {
            ConsoleUi.Text("Use --verbose for Firewall Detection & Response guidance.");
            return;
        }
        ConsoleUi.Section("Firewall Detection & Response");
        ConsoleUi.Row("End UTC", evidence.OperationEndUtc.ToString("O", CultureInfo.InvariantCulture));
        ConsoleUi.Text("WFAS/Firewall events 2004/2005/2006 describe rule add/modify/delete; correlate the exact test rule name.");
        ConsoleUi.Text("Security 4946/4947/4948 require applicable firewall policy-change auditing. Missing events do not prove no detection.");
        ConsoleUi.Text("Use Security 4688, Sysmon 1 or EDR process telemetry to investigate the initiating user, image and parent.");
        ConsoleUi.Text("A rule-change event does not prove traffic enforcement. Validate traffic separately under the applicable profile and central policy.");
        ConsoleUi.Text("For approved tests: retain the ID, baseline, requested properties and matching event records; verify exact cleanup by ID.");
        ConsoleUi.Text("For unauthorized changes: preserve evidence, scope the affected endpoints/applications and follow the incident playbook.");
        ConsoleUi.Text("Do not disable Firewall or broadly reset policy to clean up a rule test. No automatic rollback is performed.");
    }

    // netsh advfirewall firewall add rule has no group=/grouping= parameter (confirmed against
    // Microsoft's own documented parameter list for "add rule"); a rule created by the cmd transport
    // can never carry this tool's Grouping marker the way com/native/management/powershell all do
    // (PowerShell's New-NetFirewallRule -Group sets the same MSFT_NetFirewallRule.RuleGroup property
    // management writes directly, so it is unaffected). Ownership for a cmd-created rule therefore
    // rests on Name+Description alone; RequireOwnedUnique/Mismatches/ExpectedRule all call this so a
    // rule created by one transport is not silently treated as ownable by another that expects a
    // Grouping value netsh could never have written. See docs\user\firewall.md for the consequence:
    // cmd-created rules should be checked/removed with --transport cmd.
    internal static string ExpectedGrouping(string transport) { return transport == "cmd" ? "" : Group; }

    // Renders a Profiles bitmask as the comma-separated profile-name list both New-NetFirewallRule's
    // -Profile parameter and netsh's profile= parameter accept and echo back verbatim on readback
    // (confirmed live: an all-profile rule reads back "Domain,Private,Public", never the word "Any",
    // regardless of how it was created) -- shared between PowerShellFirewallBackend and
    // CmdFirewallBackend rather than duplicated. mask is always a nonzero 1..7 value here: Probe()
    // refuses an invalid/empty mask before any backend is asked to add a rule.
    internal static string ProfileList(int mask)
    {
        List<string> names = new List<string>();
        if ((mask & 1) != 0) { names.Add("Domain"); }
        if ((mask & 2) != 0) { names.Add("Private"); }
        if ((mask & 4) != 0) { names.Add("Public"); }
        if (names.Count == 0) { throw new FirewallRefusalException("Invalid empty firewall profile mask."); }
        return string.Join(",", names.ToArray());
    }

    internal static FirewallRuleData ExpectedRule(FirewallOptions options, int profiles)
    {
        return new FirewallRuleData
        {
            Name = options.RuleName, Grouping = ExpectedGrouping(options.Transport), Description = DescriptionFor(options.Id),
            Enabled = true, Direction = options.Direction, Action = options.Action, Protocol = options.Protocol,
            Profiles = profiles, LocalAddresses = "*", RemoteAddresses = options.RemoteAddress,
            LocalPorts = options.LocalPort == 0 ? "*" : options.LocalPort.ToString(CultureInfo.InvariantCulture),
            RemotePorts = options.RemotePort == 0 ? "*" : options.RemotePort.ToString(CultureInfo.InvariantCulture),
            ApplicationName = options.Program, ServiceName = "", InterfaceTypes = "All",
            EdgeTraversal = false, EdgeTraversalOptions = 0,
            LocalAppPackageId = "", LocalUserOwner = "", LocalUserAuthorizedList = "",
            RemoteUserAuthorizedList = "", RemoteMachineAuthorizedList = "", SecureFlags = 0
        };
    }

    private static void RequireOwnedUnique(FirewallOptions options, IList<FirewallRuleData> rules)
    {
        if (rules.Count != 1) { throw new FirewallRefusalException("Refused: duplicate/ambiguous rule name; no mutation."); }
        FirewallRuleData rule = rules[0];
        if (!string.Equals(rule.Name, options.RuleName, StringComparison.Ordinal) ||
            !string.Equals(rule.Grouping, ExpectedGrouping(options.Transport), StringComparison.Ordinal) ||
            !string.Equals(rule.Description, DescriptionFor(options.Id), StringComparison.Ordinal))
        {
            throw new FirewallRefusalException("Refused: name/group/description do not exactly match this tool's ownership schema.");
        }
    }

    internal static IList<string> Mismatches(FirewallRuleData expected, FirewallRuleData actual)
    {
        List<string> result = new List<string>();
        Match(result, "Name", expected.Name, actual.Name, StringComparison.Ordinal);
        Match(result, "Grouping", expected.Grouping, actual.Grouping, StringComparison.Ordinal);
        Match(result, "Description", expected.Description, actual.Description, StringComparison.Ordinal);
        Match(result, "ApplicationName", NormalizeApplication(expected.ApplicationName), NormalizeApplication(actual.ApplicationName), StringComparison.OrdinalIgnoreCase);
        Match(result, "ServiceName", expected.ServiceName ?? "", actual.ServiceName ?? "", StringComparison.Ordinal);
        Match(result, "LocalAddresses", NormalizeAddress(expected.LocalAddresses), NormalizeAddress(actual.LocalAddresses), StringComparison.OrdinalIgnoreCase);
        Match(result, "RemoteAddresses", NormalizeAddress(expected.RemoteAddresses), NormalizeAddress(actual.RemoteAddresses), StringComparison.OrdinalIgnoreCase);
        Match(result, "LocalPorts", NormalizePort(expected.LocalPorts), NormalizePort(actual.LocalPorts), StringComparison.Ordinal);
        Match(result, "RemotePorts", NormalizePort(expected.RemotePorts), NormalizePort(actual.RemotePorts), StringComparison.Ordinal);
        Match(result, "InterfaceTypes", expected.InterfaceTypes, actual.InterfaceTypes, StringComparison.OrdinalIgnoreCase);
        if (actual.Interfaces == null || actual.Interfaces.Length != 0) { result.Add("Interfaces"); }
        if (expected.Enabled != actual.Enabled) { result.Add("Enabled"); }
        if (expected.Direction != actual.Direction) { result.Add("Direction"); }
        if (expected.Action != actual.Action) { result.Add("Action"); }
        if (expected.Protocol != actual.Protocol) { result.Add("Protocol"); }
        if (expected.Profiles != actual.Profiles) { result.Add("Profiles"); }
        if (expected.EdgeTraversal != actual.EdgeTraversal) { result.Add("EdgeTraversal"); }
        if (expected.EdgeTraversalOptions != actual.EdgeTraversalOptions) { result.Add("EdgeTraversalOptions"); }
        if (expected.SecureFlags != actual.SecureFlags) { result.Add("SecureFlags"); }
        Match(result, "LocalAppPackageId", expected.LocalAppPackageId ?? "", actual.LocalAppPackageId ?? "", StringComparison.Ordinal);
        Match(result, "LocalUserOwner", expected.LocalUserOwner ?? "", actual.LocalUserOwner ?? "", StringComparison.Ordinal);
        Match(result, "LocalUserAuthorizedList", expected.LocalUserAuthorizedList ?? "", actual.LocalUserAuthorizedList ?? "", StringComparison.Ordinal);
        Match(result, "RemoteUserAuthorizedList", expected.RemoteUserAuthorizedList ?? "", actual.RemoteUserAuthorizedList ?? "", StringComparison.Ordinal);
        Match(result, "RemoteMachineAuthorizedList", expected.RemoteMachineAuthorizedList ?? "", actual.RemoteMachineAuthorizedList ?? "", StringComparison.Ordinal);
        return result;
    }

    private static void Match(List<string> result, string name, string expected, string actual, StringComparison comparison)
    {
        if (!string.Equals(expected, actual, comparison)) { result.Add(name); }
    }

    private static string NormalizeApplication(string value)
    {
        return (value ?? "").Replace('/', '\\');
    }

    private static string NormalizePort(string value)
    {
        int port;
        if (int.TryParse(value, NumberStyles.None, CultureInfo.InvariantCulture, out port) && port > 0 && port <= 65535)
        {
            return port.ToString(CultureInfo.InvariantCulture);
        }
        return value;
    }

    private static string NormalizeAddress(string value)
    {
        if (value == null || value == "*") { return value; }
        string[] range = value.Split('-');
        if (range.Length == 2)
        {
            IPAddress first, last;
            if (IPAddress.TryParse(range[0], out first) && IPAddress.TryParse(range[1], out last) && first.Equals(last))
            {
                return first.ToString();
            }
            return value;
        }
        string[] parts = value.Split('/');
        IPAddress address;
        if (parts.Length > 2 || !IPAddress.TryParse(parts[0], out address)) { return value; }
        if (parts.Length == 2)
        {
            bool fullHost = address.AddressFamily == AddressFamily.InterNetwork ?
                (parts[1] == "32" || parts[1] == "255.255.255.255") : parts[1] == "128";
            if (!fullHost) { return value; }
        }
        return address.ToString();
    }

    private static void ShowRule(FirewallRuleData rule)
    {
        ConsoleUi.Row("Name", rule.Name);
        ConsoleUi.Row("Grouping", rule.Grouping);
        ConsoleUi.Row("Description", rule.Description);
        ConsoleUi.Row("Enabled", rule.Enabled.ToString());
        ConsoleUi.Row("Direction/action", rule.Direction.ToString(CultureInfo.InvariantCulture) + " / " + ActionName(rule.Action));
        ConsoleUi.Row("Protocol/profiles", rule.Protocol.ToString(CultureInfo.InvariantCulture) + " / " + rule.Profiles.ToString(CultureInfo.InvariantCulture));
        ConsoleUi.Row("Local address:ports", rule.LocalAddresses + " : " + rule.LocalPorts);
        ConsoleUi.Row("Remote address:ports", rule.RemoteAddresses + " : " + rule.RemotePorts);
        ConsoleUi.Row("Program/service", (rule.ApplicationName ?? "") + " / " + (rule.ServiceName ?? ""));
        ConsoleUi.Row("Interfaces/types", string.Join(", ", rule.Interfaces) + " / " + rule.InterfaceTypes);
        ConsoleUi.Row("Edge traversal", rule.EdgeTraversal + " / options=" + rule.EdgeTraversalOptions.ToString(CultureInfo.InvariantCulture));
        ConsoleUi.Row("App package/owner", (rule.LocalAppPackageId ?? "") + " / " + (rule.LocalUserOwner ?? ""));
        ConsoleUi.Row("Local user auth", rule.LocalUserAuthorizedList ?? "");
        ConsoleUi.Row("Remote user auth", rule.RemoteUserAuthorizedList ?? "");
        ConsoleUi.Row("Remote machine auth", rule.RemoteMachineAuthorizedList ?? "");
        ConsoleUi.Row("Secure flags", rule.SecureFlags.ToString(CultureInfo.InvariantCulture));
    }

    private static string ActionName(int value)
    {
        return value == 0 ? "block" : value == 1 ? "allow" : "unknown (" + value.ToString(CultureInfo.InvariantCulture) + ")";
    }
    private static string ProfileName(int value) { return value == 1 ? "Domain" : value == 2 ? "Private" : "Public"; }
    private static string ModifyState(int value)
    {
        return value == 0 ? "0 (OK)" : value == 1 ? "1 (GP_OVERRIDE)" :
            value == 2 ? "2 (INBOUND_BLOCKED)" : value.ToString(CultureInfo.InvariantCulture) + " (unknown)";
    }

    internal static void Help()
    {
        ConsoleUi.Section("Usage");
        ConsoleUi.Text("wtf.exe firewall <command> [options]");
        ConsoleUi.Section("Options");
        ConsoleUi.Row("--transport", "com|native|management|powershell|cmd  (default: com; no automatic fallback)");
        ConsoleUi.Row("--id", "Test GUID: generated for add; required for check/remove.");
        ConsoleUi.Row("--remote-address", "One literal IPv4/IPv6 address  (required for add)");
        ConsoleUi.Row("--remote-port", "1..65535  (required outbound; optional inbound, default: all)");
        ConsoleUi.Row("--direction", "in|out  (add only; default: out)");
        ConsoleUi.Row("--action", "block|allow  (add only; default: block)");
        ConsoleUi.Row("--protocol", "tcp|udp  (add only; default: tcp)");
        ConsoleUi.Row("--profiles", "domain,private,public|all  (add only; default: active mask)");
        ConsoleUi.Row("--program", "Absolute executable path  (add only; default: all programs)");
        ConsoleUi.Row("--local-port", "1..65535  (required inbound; optional outbound, default: all)");
        ConsoleUi.HelpOptions();
        ConsoleUi.Section("Commands");
        ConsoleUi.Row("rule add", "Create a marked test rule; never overwrite an existing name.");
        ConsoleUi.Row("rule check", "Read-only: verify ownership and display current properties.");
        ConsoleUi.Row("rule remove", "Remove only a uniquely owned rule; already absent is OK.");
        ConsoleUi.Row("profiles", "Read-only: inspect profile settings; never change them.");
        ConsoleUi.Section("Routes");
        ConsoleUi.Row("com", "C# COM interop -> INetFwPolicy2 / INetFwRule3");
        ConsoleUi.Row("native", "P/Invoke -> C++ INetFwPolicy2 / INetFwRule3");
        ConsoleUi.Row("management", "System.Management -> WMI MSFT_NetFirewallRule (root\\StandardCimv2)");
        ConsoleUi.Row("powershell", "powershell.exe -> New-/Get-/Remove-NetFirewallRule (NetSecurity module)");
        ConsoleUi.Row("cmd", "cmd.exe -> netsh.exe advfirewall firewall add/show/delete rule");
        ConsoleUi.Text("com/native target Windows Firewall COM (netfw); management and powershell both target the " +
            "same WMI Firewall provider (powershell through its own cmdlets, management directly). All four " +
            "read/write the same persisted rule store, not WFP filters; a rule added with one of these four " +
            "transports can be checked/removed with another.");
        ConsoleUi.Text("cmd instead shells to netsh, which has no group=/grouping= parameter for 'add rule': a " +
            "cmd-created rule can never carry this tool's Grouping marker, so its ownership rests on Name+" +
            "Description alone. Check/remove a cmd-created rule with --transport cmd; the other four transports " +
            "will refuse it as a Grouping mismatch (by design -- see the Extended notes below).");
        ConsoleUi.Section("Quick start");
        ConsoleUi.Text("Add a test rule (administrator required; retain the printed ID):");
        ConsoleUi.Text("  .\\wtf.exe firewall rule add --remote-address 192.0.2.10 --remote-port 44443");
        ConsoleUi.Text("Inbound: use --direction in --remote-address IP --local-port 443 (source port optional).");
        ConsoleUi.Text("Check / cleanup (replace <GUID> with the test ID):");
        ConsoleUi.Text("  .\\wtf.exe firewall rule check --id <GUID>");
        ConsoleUi.Text("  .\\wtf.exe firewall rule remove --id <GUID>");
        ConsoleUi.HelpTelemetry();
        ConsoleUi.Section("Before you run");
        ConsoleUi.Text("Add/remove require elevation. Quote paths with spaces; use an approved test endpoint.");
        ConsoleUi.Text("Native transport and ETW require WinTraceForge.Native.dll; Rule3 requires Windows 8+.");
        ConsoleUi.Text("powershell/cmd use System32's own powershell.exe/cmd.exe (no PATH lookup) and need the " +
            "NetSecurity module / netsh.exe advfirewall firewall context respectively.");
        ConsoleUi.Text("Configuration readback is not proof of traffic blocking/allowing or effective policy.");
        ConsoleUi.HelpExitCodes();
        ConsoleUi.Status("WARN", "Authorized testing only; no Firewall Off, profile mutation or automatic cleanup.");
        if (!ConsoleUi.Verbose) { return; }
        ConsoleUi.Section("Extended notes");
        ConsoleUi.Text("--transport applies to add/check/remove/profiles. Native rule operations execute in C++, not C# COM.");
        ConsoleUi.Text("com/native/management/powershell share the same ownership schema; any of the four can inspect/clean " +
            "up a rule created by another. cmd cannot stamp Grouping (see Routes above), so use --transport cmd " +
            "consistently for a rule it created; the other four will refuse it as a Grouping mismatch.");
        ConsoleUi.Text("Cleanup commands preserve the selected transport. No failure triggers automatic transport switching.");
        ConsoleUi.Text("Native requires this release's x64 DLL beside the EXE; older Defender-only DLLs are incompatible.");
        ConsoleUi.Text("management scopes address/port/program via the WMI Firewall provider's call-context " +
            "(\"Extended Syntax\"), not flat rule properties; PrepareAdd can only pre-validate the rule's direct " +
            "properties (name/group/description/enabled/direction/action/profiles) before Add persists it. Full " +
            "attribute verification, including address/port/program, still happens in the shared post-Add readback.");
        ConsoleUi.Text("management always creates rules with no interface, local/remote-user, or remote-machine " +
            "restriction and edge traversal Block, matching the fixed defaults com/native also use.");
        ConsoleUi.Text("management's Local modify state is read from the WindowsFirewall Group Policy registry keys " +
            "(AllowLocalPolicyMerge/AllowLocalIPsecPolicyMerge), since MSFT_NetFirewallRule/-Profile expose no direct " +
            "equivalent to INetFwPolicy2.LocalPolicyModifyState; it never reports 2 (INBOUND_BLOCKED). powershell and " +
            "cmd read the identical registry keys the same way (they are not WMI/COM properties either).");
        ConsoleUi.Text("powershell drives the NetSecurity module's own cmdlets (New-/Get-/Remove-NetFirewallRule, " +
            "Get-NetFirewall*Filter, Get-NetFirewallProfile) and the NetConnection module's Get-NetConnectionProfile " +
            "for the active profile mask; these are a thin cmdlet wrapper over the same WMI provider management " +
            "queries directly, so readback fidelity matches management's.");
        ConsoleUi.Text("cmd parses the fixed-column text of 'netsh advfirewall firewall show rule ... verbose' and " +
            "'netsh advfirewall show allprofiles/currentprofile'; this is inherently more fragile than a typed API " +
            "(locale- and version-sensitive label text) and refuses outright on any unrecognized label. Only " +
            "specific fields (LocalIP, InterfaceTypes, Security, Edge traversal, Action, Direction, Enabled, " +
            "Profiles, Protocol, RemoteIP when comma-joined) are value-checked against known text; Program, " +
            "Service, Description and a single-value RemoteIP/port are passed through as plain text. A missing " +
            "'Description:' line (netsh omits it, not an 'Any' sentinel, when a rule has none) reads as ''.");
        ConsoleUi.Text("cmd never reads ExcludedInterfaces (netsh exposes no such field); it reads back as the " +
            "literal text 'not available (cmd)', not an empty list, so it is never mistaken for a confirmed none.");
        ConsoleUi.Text("cmd's 'firewall profiles' reads netsh's Local policy store, not the GPO-merged effective " +
            "policy management/powershell explicitly request; the printed 'Policy store' line says which.");
        ConsoleUi.Text("netsh advfirewall firewall add rule has no group=/grouping= parameter, so cmd-created rules " +
            "carry an empty Grouping; RequireOwnedUnique/Mismatches compare against '' instead of " + Group + " only " +
            "for --transport cmd. Use --transport cmd consistently for a rule you created with it.");
        ConsoleUi.Text("Changing caller implementation alone does not establish different enforcement or detection; compare evidence.");
        ConsoleUi.Text("Add defaults: all local addresses and no program, service or interface restriction.");
        ConsoleUi.Text("Outbound requires remote port; inbound requires local port. The opposite-side port defaults to all.");
        ConsoleUi.Text("The active profile mask is frozen before add; an invalid/empty mask never falls back to all.");
        ConsoleUi.Text("Remote address must be one unscoped literal IP, not a hostname, range or subnet.");
        ConsoleUi.Text("For inbound rules, --remote-port is the sender's source port; --local-port is the listening port.");
        ConsoleUi.Text("Check/remove accept only --id, --transport and common options. Check does not compare the original add request.");
        ConsoleUi.Text("Absent check returns 3; absent remove returns 0 without calling Remove.");
        ConsoleUi.Text("Ownership schema (GUID is lowercase canonical D format):");
        ConsoleUi.Row("Name", NamePrefix + "<GUID>");
        ConsoleUi.Row("Grouping", Group);
        ConsoleUi.Row("Description", "WinTraceForge;kind=firewall-rule;schema=1;id=<GUID>");
        ConsoleUi.Text("Remove requires exact unique ownership. Markers are operational labels, not authentication.");
        ConsoleUi.Text("Name-based COM changes are not atomic; avoid concurrent writers using the same ID.");
        ConsoleUi.Text("No automatic rollback is attempted on readback mismatch; inspect and clean up by the printed ID.");
        ConsoleUi.Text("Eventlog reads existing WFAS 2004/2005/2006, Security 4946/4947/4948 and process-start evidence.");
        ConsoleUi.Text("ETW uses the Windows Firewall With Advanced Security provider, not Defender/WMI providers.");
        ConsoleUi.Text("Rule-change correlation requires the exact rule name; no matching event does not prove no detection.");
        ConsoleUi.Text("ETW setup failure aborts before the operation (exit 4); no fallback. Later telemetry failures are separate.");
        ConsoleUi.Text("ETW caps: 32 MB file, 120s capture, 10,000 decoded provider events. Loss/partial decoding is reported.");
        ConsoleUi.Text("ETL is saved under LocalAppData\\WinTraceForge\\Traces\\<run-id>; it may contain unrelated activity.");
        ConsoleUi.Text("Compliance and detection/response are not automatically assessed. No SIEM/EDR alerts are queried.");
        ConsoleUi.Text("NO_COLOR is supported. Redirect stdout and stderr together to preserve warnings.");
        ConsoleUi.Text("See docs\\user\\README.md for evidence limits and restoration guidance.");
    }
}

// Disciplined IDispatch access to the official HNetCfg.FwPolicy2/FWRule COM objects.
// Policy access is exclusively GetProperty; the only persistent writes are Rules.Add/Remove.
internal sealed class ComFirewallBackend : IFirewallBackend
{
    private object policy;
    private object rules;
    private object preparedRule;

    internal ComFirewallBackend()
    {
        bool ready = false;
        try
        {
            policy = Activator.CreateInstance(Type.GetTypeFromProgID("HNetCfg.FwPolicy2", true));
            rules = Get(policy, "Rules");
            ready = true;
        }
        finally { if (!ready) { Dispose(); } }
    }

    public int CurrentProfiles { get { return (int)Get(policy, "CurrentProfileTypes"); } }
    public int LocalPolicyModifyState { get { return (int)Get(policy, "LocalPolicyModifyState"); } }

    public IList<FirewallProfileData> ReadProfiles()
    {
        List<FirewallProfileData> result = new List<FirewallProfileData>();
        foreach (int profile in new int[] { 1, 2, 4 })
        {
            result.Add(new FirewallProfileData
            {
                Profile = profile,
                Enabled = (bool)Get(policy, "FirewallEnabled", profile),
                BlockAllInbound = (bool)Get(policy, "BlockAllInboundTraffic", profile),
                DefaultInboundAction = (int)Get(policy, "DefaultInboundAction", profile),
                DefaultOutboundAction = (int)Get(policy, "DefaultOutboundAction", profile),
                ExcludedInterfaces = Strings(Get(policy, "ExcludedInterfaces", profile))
            });
        }
        return result;
    }

    public IList<FirewallRuleData> FindByName(string name)
    {
        List<FirewallRuleData> result = new List<FirewallRuleData>();
        object enumeration = null;
        object[] item = new object[1];
        try
        {
            // Own the raw IEnumVARIANT RCW; the managed IEnumerable adapter can hide it
            // behind a non-disposable wrapper and defer release until garbage collection.
            IntPtr pointer;
            int enumerationStatus = ((IFirewallRulesEnumerator)rules).GetNewEnum(out pointer);
            try
            {
                Marshal.ThrowExceptionForHR(enumerationStatus);
                enumeration = Marshal.GetTypedObjectForIUnknown(pointer, typeof(IFirewallEnumVariant));
            }
            finally { if (pointer != IntPtr.Zero) { Marshal.Release(pointer); } }
            IFirewallEnumVariant enumerator = (IFirewallEnumVariant)enumeration;
            while (true)
            {
                int status = enumerator.Next(1, item, IntPtr.Zero);
                try
                {
                    if (status == 1) { break; }
                    if (status != 0)
                    {
                        if (status < 0) { Marshal.ThrowExceptionForHR(status); }
                        throw new COMException("Unexpected firewall enumeration status.", status);
                    }
                    object rule = item[0];
                    // Windows rule names may compare without case; treat case variants as conflicts.
                    if (string.Equals((string)Get(rule, "Name"), name, StringComparison.OrdinalIgnoreCase))
                    {
                        result.Add(ReadRule(rule));
                    }
                }
                finally { Release(item[0]); item[0] = null; }
            }
        }
        finally { Release(item[0]); Release(enumeration); }
        return result;
    }

    [ComImport, Guid("9C4C6277-5027-441E-AFAE-CA1F542DA009"), InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
    internal interface IFirewallRulesEnumerator
    {
        // INetFwRules is dual. Declare the four IDispatch slots and all preceding
        // INetFwRules slots to retrieve _NewEnum without CLR's custom enumerator adapter.
        [PreserveSig] int GetTypeInfoCount(out uint count);
        [PreserveSig] int GetTypeInfo(uint index, uint locale, out IntPtr info);
        [PreserveSig] int GetIdsOfNames(ref Guid iid, IntPtr names, uint count, uint locale, IntPtr ids);
        [PreserveSig] int DispatchInvoke(int id, ref Guid iid, uint locale, ushort flags, IntPtr args, IntPtr result, IntPtr exception, IntPtr argumentError);
        [PreserveSig] int GetCount(out int count);
        [PreserveSig] int Add([MarshalAs(UnmanagedType.Interface)] object rule);
        [PreserveSig] int Remove([MarshalAs(UnmanagedType.BStr)] string name);
        [PreserveSig] int Item([MarshalAs(UnmanagedType.BStr)] string name, out IntPtr rule);
        [PreserveSig] int GetNewEnum(out IntPtr enumerator);
    }

    [ComImport, Guid("00020404-0000-0000-C000-000000000046"), InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
    internal interface IFirewallEnumVariant
    {
        [PreserveSig]
        int Next(uint count, [Out, MarshalAs(UnmanagedType.LPArray, ArraySubType = UnmanagedType.Struct, SizeParamIndex = 0)] object[] values, IntPtr fetched);
        [PreserveSig]
        int Skip(uint count);
        [PreserveSig]
        int Reset();
        void Clone([MarshalAs(UnmanagedType.Interface)] out IFirewallEnumVariant copy);
    }

    public void PrepareAdd(FirewallRuleData expected)
    {
        if (preparedRule != null) { throw new FirewallRefusalException("A detached rule is already prepared."); }
        object rule = null;
        try
        {
            rule = Activator.CreateInstance(Type.GetTypeFromProgID("HNetCfg.FWRule", true));
            Set(rule, "Name", expected.Name);
            Set(rule, "Description", expected.Description);
            Set(rule, "Grouping", expected.Grouping);
            Set(rule, "Protocol", expected.Protocol);
            Set(rule, "LocalAddresses", expected.LocalAddresses);
            Set(rule, "RemoteAddresses", expected.RemoteAddresses);
            // Preserve unspecified defaults instead of writing empty BSTR scopes.
            if (!string.IsNullOrEmpty(expected.LocalPorts) && expected.LocalPorts != "*")
            { Set(rule, "LocalPorts", expected.LocalPorts); }
            if (!string.IsNullOrEmpty(expected.RemotePorts) && expected.RemotePorts != "*")
            { Set(rule, "RemotePorts", expected.RemotePorts); }
            if (!string.IsNullOrEmpty(expected.ApplicationName)) { Set(rule, "ApplicationName", expected.ApplicationName); }
            if (!string.IsNullOrEmpty(expected.ServiceName)) { Set(rule, "ServiceName", expected.ServiceName); }
            Set(rule, "InterfaceTypes", expected.InterfaceTypes);
            Set(rule, "Direction", expected.Direction);
            Set(rule, "Action", expected.Action);
            Set(rule, "Profiles", expected.Profiles);
            Set(rule, "EdgeTraversal", false);
            Set(rule, "EdgeTraversalOptions", 0);
            Set(rule, "Enabled", expected.Enabled);
            // Newly constructed rules have no interface/IPsec/package/user restrictions.
            // Check defaults before persistence rather than silently assuming them.
            FirewallRuleData detached = ReadRule(rule);
            IList<string> differences = FirewallModule.Mismatches(expected, detached);
            if (differences.Count != 0)
            {
                throw new FirewallRefusalException("New COM rule has unexpected attributes before Rules.Add: " + string.Join(", ", differences) +
                    "; remote-address readback=" + detached.RemoteAddresses);
            }
            preparedRule = rule;
            rule = null;
        }
        finally { Release(rule); }
    }

    public MutationStatus Add()
    {
        if (preparedRule == null) { throw new FirewallRefusalException("No detached rule was prepared."); }
        Invoke(rules, "Add", BindingFlags.InvokeMethod, new object[] { preparedRule });
        return MutationStatus.ApiSucceeded;
    }

    public MutationStatus Remove(string name)
    {
        Invoke(rules, "Remove", BindingFlags.InvokeMethod, new object[] { name });
        return MutationStatus.ApiSucceeded;
    }

    private static FirewallRuleData ReadRule(object rule)
    {
        return new FirewallRuleData
        {
            Name = (string)Get(rule, "Name"), Description = (string)Get(rule, "Description"),
            Grouping = (string)Get(rule, "Grouping"), ApplicationName = (string)Get(rule, "ApplicationName"),
            ServiceName = (string)Get(rule, "ServiceName"), Protocol = (int)Get(rule, "Protocol"),
            LocalAddresses = (string)Get(rule, "LocalAddresses"), RemoteAddresses = (string)Get(rule, "RemoteAddresses"),
            LocalPorts = (string)Get(rule, "LocalPorts"), RemotePorts = (string)Get(rule, "RemotePorts"),
            Direction = (int)Get(rule, "Direction"), Action = (int)Get(rule, "Action"),
            Profiles = (int)Get(rule, "Profiles"), Enabled = (bool)Get(rule, "Enabled"),
            Interfaces = Strings(Get(rule, "Interfaces")), InterfaceTypes = (string)Get(rule, "InterfaceTypes"),
            EdgeTraversal = (bool)Get(rule, "EdgeTraversal"), EdgeTraversalOptions = (int)Get(rule, "EdgeTraversalOptions"),
            LocalAppPackageId = (string)Get(rule, "LocalAppPackageId"), LocalUserOwner = (string)Get(rule, "LocalUserOwner"),
            LocalUserAuthorizedList = (string)Get(rule, "LocalUserAuthorizedList"),
            RemoteUserAuthorizedList = (string)Get(rule, "RemoteUserAuthorizedList"),
            RemoteMachineAuthorizedList = (string)Get(rule, "RemoteMachineAuthorizedList"),
            SecureFlags = (int)Get(rule, "SecureFlags")
        };
    }

    private static string[] Strings(object value)
    {
        // VT_EMPTY/VT_NULL represent no interface restriction, not a failed property read.
        if (value == null || value == DBNull.Value) { return new string[0]; }
        Array array = value as Array;
        if (array == null) { throw new InvalidCastException("Expected a COM SAFEARRAY of interface names."); }
        List<string> result = new List<string>();
        foreach (object item in array) { result.Add((string)item); }
        return result.ToArray();
    }

    private static object Get(object target, string name, params object[] arguments)
    {
        return Invoke(target, name, BindingFlags.GetProperty, arguments);
    }

    private static void Set(object target, string name, object value)
    {
        Invoke(target, name, BindingFlags.SetProperty, new object[] { value });
    }

    private static object Invoke(object target, string name, BindingFlags flags, object[] arguments)
    {
        try
        {
            return target.GetType().InvokeMember(name, flags, null, target, arguments, CultureInfo.InvariantCulture);
        }
        catch (TargetInvocationException error)
        {
            if (error.InnerException == null) { throw; }
            ExceptionDispatchInfo.Capture(error.InnerException).Throw();
            throw;
        }
    }

    private static void Release(object value)
    {
        if (value != null && Marshal.IsComObject(value)) { Marshal.FinalReleaseComObject(value); }
    }

    public void Dispose()
    {
        try { Release(preparedRule); }
        finally
        {
            preparedRule = null;
            try { Release(rules); }
            finally { rules = null; Release(policy); policy = null; }
        }
    }
}
