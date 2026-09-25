// This Source Code Form is subject to the terms of the
// Mozilla Public License, v. 2.0.
// If a copy of the MPL was not distributed with this file, You can obtain one at https://mozilla.org/MPL/2.0/.

using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Diagnostics;
using System.Globalization;
using System.Management;
using System.Runtime.InteropServices;
using System.Security;
using System.Security.Principal;
using Microsoft.Win32;

// Numeric values match the real ASRRuleActionType enum bound by Add-MpPreference/Set-MpPreference
// (verified against Add-MpPreference's parameter metadata: Disabled=0, Enabled=1, AuditMode=2,
// NotConfigured=5, Warn=6). "Block"/"Audit" are this tool's own friendlier names for Enabled/AuditMode,
// matching the terminology Microsoft's ASR rule reference itself uses.
internal enum AsrAction : uint { Disabled = 0, Block = 1, Audit = 2, NotConfigured = 5, Warn = 6 }

internal enum AsrPolicySourceKind { NotConfigured, Local, GroupPolicy, Unknown }

internal enum AsrRequestKind { RuleAction, GlobalExclusion }

internal sealed class AsrMutationRequest
{
    internal AsrRequestKind Kind;
    internal string RuleId;
    internal AsrAction Action;
    internal List<string> ExclusionPaths;
}

internal sealed class AsrSnapshot
{
    internal readonly Dictionary<string, AsrAction> Rules;
    internal readonly List<string> GlobalExclusions;
    internal readonly Dictionary<string, List<string>> AvExclusions;

    // MSFT_MpPreference hides exclusion-list content from a non-administrator by returning a
    // single sentinel string instead of the real array (rule *configuration*, i.e. Rules above,
    // is not gated this way). These flags say "we could not observe this", never "this is empty".
    internal readonly bool GlobalExclusionsRequireElevation;
    internal readonly bool AvExclusionsRequireElevation;

    internal AsrSnapshot(Dictionary<string, AsrAction> rules, List<string> globalExclusions,
        Dictionary<string, List<string>> avExclusions, bool globalExclusionsRequireElevation = false,
        bool avExclusionsRequireElevation = false)
    {
        Rules = rules; GlobalExclusions = globalExclusions; AvExclusions = avExclusions;
        GlobalExclusionsRequireElevation = globalExclusionsRequireElevation;
        AvExclusionsRequireElevation = avExclusionsRequireElevation;
    }
}

// Best-effort GUID -> friendly name mapping for a small set of Attack Surface Reduction rules
// that are extremely consistently documented (Microsoft Learn's ASR rules reference at the time
// of writing). This list may drift from a given Windows/Defender build; verify against the current
// Microsoft Learn page before relying on the name. Correctness of the tool never depends on this
// table: any rule GUID not listed here is still fully read/reported/mutated by GUID alone.
internal static class AsrRuleCatalog
{
    internal const string JavaScriptOrVbScriptRuleId = "D3E037E1-3EB8-44C8-A917-57927947596D";

    private static readonly Dictionary<string, string> Names = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
    {
        { "D4F940AB-401B-4EFC-AADC-AD5F3C50688A", "Block all Office applications from creating child processes" },
        { "9E6C4E1F-7D60-472F-BA1A-A39EF669E4B2", "Block credential stealing from the Windows local security authority subsystem" },
        { "BE9BA2D9-53EA-4CDC-84E5-9B1EEEE46550", "Block executable content from email client and webmail" },
        { "5BEB7EFE-FD9A-4556-801D-275E5FFC04CC", "Block execution of potentially obfuscated scripts" },
        { JavaScriptOrVbScriptRuleId, "Block JavaScript or VBScript from launching downloaded executable content" },
        { "01443614-CD74-433A-B99E-2ECDC07BFC25", "Block executable files from running unless they meet a prevalence, age, or trusted list criterion" },
        { "3B576869-A4EC-4529-8536-B80A7769E899", "Block Office applications from creating executable content" }
    };

    internal static readonly IEnumerable<string> KnownRuleIds = Names.Keys;

    internal static string NameOf(string ruleId)
    {
        string name;
        return Names.TryGetValue(ruleId, out name) ? name : "(unrecognized rule; verify against Microsoft Learn)";
    }
}

// Read-only, best-effort classification of where an ASR setting appears to come from. Neither
// registry location distinguishes MDM/Intune-applied CSPs or Windows Security app defaults from
// each other; both fall into Unknown when the effective (WMI) value has no match in either key.
internal static class AsrRegistry
{
    internal const string GlobalExclusionsSourceKey = "*ASR-only-exclusions*";

    private const string PolicyRulesPath = @"SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules";
    private const string LocalRulesPath = @"SOFTWARE\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules";
    private const string PolicyExclusionsPath = @"SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\ASROnlyExclusions";
    private const string LocalExclusionsPath = @"SOFTWARE\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\ASROnlyExclusions";

    internal static Dictionary<string, AsrPolicySourceKind> ReadPolicySource(IEnumerable<string> keys)
    {
        HashSet<string> policyRules = ReadValueNames(PolicyRulesPath);
        HashSet<string> localRules = ReadValueNames(LocalRulesPath);
        bool policyExclusions = KeyHasAnyValue(PolicyExclusionsPath);
        bool localExclusions = KeyHasAnyValue(LocalExclusionsPath);
        var result = new Dictionary<string, AsrPolicySourceKind>(StringComparer.OrdinalIgnoreCase);
        foreach (string key in keys)
        {
            if (string.Equals(key, GlobalExclusionsSourceKey, StringComparison.Ordinal))
            {
                result[key] = policyExclusions ? AsrPolicySourceKind.GroupPolicy :
                    localExclusions ? AsrPolicySourceKind.Local : AsrPolicySourceKind.Unknown;
                continue;
            }
            result[key] = policyRules.Contains(key) ? AsrPolicySourceKind.GroupPolicy :
                localRules.Contains(key) ? AsrPolicySourceKind.Local : AsrPolicySourceKind.Unknown;
        }
        return result;
    }

    private static HashSet<string> ReadValueNames(string path)
    {
        var names = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        try
        {
            using (RegistryKey key = Registry.LocalMachine.OpenSubKey(path))
            {
                if (key != null) { foreach (string name in key.GetValueNames()) { names.Add(name); } }
            }
        }
        catch (SecurityException) { }
        catch (UnauthorizedAccessException) { }
        return names;
    }

    private static bool KeyHasAnyValue(string path)
    {
        try
        {
            using (RegistryKey key = Registry.LocalMachine.OpenSubKey(path))
            {
                return key != null && key.GetValueNames().Length != 0;
            }
        }
        catch (SecurityException) { return false; }
        catch (UnauthorizedAccessException) { return false; }
    }

    // Some Windows builds redirect notepad.exe launches to a packaged app via Image File Execution
    // Options' UseFilter, confirmed present as HKLM\...\Image File Execution Options\notepad.exe
    // (UseFilter=1) with per-path AppExecutionAliasRedirect=1 subkeys. The 'verify' built-in primitive
    // uses this as its warning signal that process-tree-based tracking may not see the real target.
    internal static bool IsNotepadRedirectionActive()
    {
        try
        {
            using (RegistryKey key = Registry.LocalMachine.OpenSubKey(
                @"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\notepad.exe"))
            {
                if (key == null) { return false; }
                object useFilter = key.GetValue("UseFilter");
                return useFilter is int && (int)useFilter != 0;
            }
        }
        catch (SecurityException) { return false; }
        catch (UnauthorizedAccessException) { return false; }
    }
}

internal sealed class AsrOptions : ControlOptions
{
    internal string Operation;
    internal string Transport = "management";
    internal bool CheckOnly;
    internal readonly List<string> Paths = new List<string>();
    internal Guid RuleId;
    internal AsrAction? Action;
    internal string TestCommand;
    internal string TestArguments = "";
    internal override TelemetryProfile Telemetry { get { return AsrTelemetry.Profile; } }
    internal override IEnumerable<string> EvidenceValues
    {
        get
        {
            if (Kind == ControlKind.DefenderAsrExclusion)
            {
                foreach (string path in Paths) { yield return path; }
            }
            else if ((Kind == ControlKind.DefenderAsrRule || Kind == ControlKind.DefenderAsrVerify) && RuleId != Guid.Empty)
            {
                yield return RuleId.ToString("D");
            }
        }
    }
}

internal sealed class AsrRunEvidence : ControlRunEvidence
{
    internal bool MutationAttempted;
    internal bool MutationReturned;
    internal ControlLifecycleResult<AsrBaseline> Lifecycle;
}

internal interface IAsrBackend : IDisposable
{
    void Connect();
    void Prepare(AsrMutationRequest request);
    bool Supports(string name);
    object Add();
    AsrSnapshot Read();
    Dictionary<string, AsrPolicySourceKind> ReadPolicySource(IEnumerable<string> keys);
    bool IsNotepadRedirectionActive();
}

internal interface IAsrReader
{
    void Connect();
    void Prepare(AsrMutationRequest request);
    bool Supports(string name);
    AsrSnapshot Read();
    Dictionary<string, AsrPolicySourceKind> ReadPolicySource(IEnumerable<string> keys);
    bool IsNotepadRedirectionActive();
}

internal interface IAsrWriter { object Add(); }

// Pure lookup of the real MSFT_MpPreference CIM type for each property this module writes,
// verified against Get-CimClass MSFT_MpPreference: the Ids and OnlyExclusions arrays are
// StringArray, but Actions is a UInt8Array (NOT UInt32 -- Add-MpPreference's own action enum is
// byte-sized). Gating Supports() on the wrong type makes every real rule mutation fail Probe
// before Add is ever attempted (fails safe, but the sub-command becomes entirely unusable).
internal static class AsrPropertySchema
{
    internal static CimType ExpectedType(string propertyName)
    {
        return string.Equals(propertyName, "AttackSurfaceReductionRules_Actions", StringComparison.OrdinalIgnoreCase) ?
            CimType.UInt8 : CimType.String;
    }
}

internal static partial class AsrModule
{
    internal static int Main(string[] args)
    {
        AsrOptions options;
        try { options = Parse(args); }
        catch (ArgumentException error)
        {
            ConsoleUi.Configure(false, true);
            ConsoleUi.Status("FAIL", "Invalid arguments: " + error.Message, true);
            ConsoleUi.Text("Use --help for usage. No settings were changed.");
            return 2;
        }

        ConsoleUi.Configure(options.Verbose, options.NoColor);
        ConsoleUi.Banner();
        if (options.Help) { PrintHelp(); return 0; }

        var evidence = new AsrRunEvidence();
        return ControlRuntime.Execute(options, evidence,
            delegate { return ExecuteSafely(options, evidence); },
            delegate(int exitCode) { PrintAssessment(options, evidence, exitCode); });
    }

    private static int ExecuteSafely(AsrOptions options, AsrRunEvidence evidence)
    {
        try { return Run(options, evidence); }
        catch (ManagementException ex) { return ReportError("Defender WMI error (" + ex.ErrorCode + "): " + ex.Message); }
        catch (UnauthorizedAccessException ex) { return ReportError("Access denied: " + ex.Message); }
        catch (COMException ex) { return ReportError("WMI COM error (0x" + ex.ErrorCode.ToString("X8") + "): " + ex.Message); }
        catch (SecurityException ex) { return ReportError("Security error: " + ex.Message); }
        catch (InvalidOperationException ex) { return ReportError(ex.Message); }
        catch (Win32Exception ex) { return ReportError("Test primitive launch failed: " + ex.Message); }
        catch (MissingMemberException ex) { return ReportError("WMI COM Automation interface mismatch: " + ex.Message); }
        catch (NotSupportedException ex) { return ReportError("The selected transport is unavailable: " + ex.Message); }
        catch (DllNotFoundException ex)
        {
            return ReportError("Native backend DLL is missing or could not be loaded. Keep the matching DLL beside the EXE. " + ex.Message);
        }
        catch (BadImageFormatException ex)
        { return ReportError("Native backend architecture mismatch. Use the matching x64 EXE and DLL. " + ex.Message); }
        catch (EntryPointNotFoundException ex) { return ReportError("Native backend DLL version mismatch: " + ex.Message); }
    }

    private static int Run(AsrOptions options, AsrRunEvidence evidence)
    {
        evidence.Stage = "Identity";
        ConsoleUi.Section("Run");
        ConsoleUi.Row("Control", "Defender / Attack Surface Reduction");
        ConsoleUi.Row("Operation", options.Operation);
        ConsoleUi.Row("Run ID", evidence.RunId);
        ConsoleUi.Row("Start UTC", evidence.StartUtc.ToString("yyyy-MM-dd HH:mm:ss.fff'Z'", CultureInfo.InvariantCulture));
        using (Process process = Process.GetCurrentProcess())
        {
            evidence.ProcessId = process.Id;
            ConsoleUi.Row("Host / PID", Environment.MachineName + " / " + process.Id);
        }
        ConsoleUi.Row("Transport", options.Transport);
        // Only 'exclusion'/'rule' without --check ever reach MSFT_MpPreference.Add; every other
        // sub-command (status, every --check, verify) only ever calls ExecQuery/Get -- the Route
        // line must not claim a write path it did not take.
        bool willInvokeAdd = !options.CheckOnly &&
            (options.Kind == ControlKind.DefenderAsrExclusion || options.Kind == ControlKind.DefenderAsrRule);
        string endpoint = willInvokeAdd ? "MSFT_MpPreference.Add" : "MSFT_MpPreference (read-only ExecQuery/Get)";
        ConsoleUi.Detail("Route: " + (options.Transport == "native" ?
            "P/Invoke -> native C++ IWbemLocator/IWbemServices -> WMI -> " + endpoint :
            options.Transport == "com" ?
            ".NET COM interop -> SWbemLocator/SWbemServices -> WMI -> " + endpoint :
            "System.Management -> WMI -> " + endpoint));

        bool isAdministrator;
        using (WindowsIdentity identity = WindowsIdentity.GetCurrent())
        {
            isAdministrator = new WindowsPrincipal(identity).IsInRole(WindowsBuiltInRole.Administrator);
            ConsoleUi.Row("Identity", identity.Name);
        }
        ConsoleUi.Row("Administrator", isAdministrator ? "Yes" : "No");

        bool mutating = !options.CheckOnly &&
            (options.Kind == ControlKind.DefenderAsrExclusion || options.Kind == ControlKind.DefenderAsrRule);
        if (mutating && !isAdministrator)
        {
            return ReportError("Open a terminal with Run as administrator, then run this EXE again.");
        }

        evidence.Stage = "Connect";
        using (IAsrBackend backend = CreateBackend(options.Transport))
        {
            return RunWithBackend(options, evidence, backend);
        }
    }

    internal static IAsrBackend CreateBackend(string transport)
    {
        switch (transport)
        {
            case "management": return new ManagementAsrBackend();
            case "com": return new ComAsrBackend();
            case "native": return new NativeAsrBackend();
            default: throw new InvalidOperationException("Unknown ASR transport; no fallback.");
        }
    }

    internal static int RunWithBackend(AsrOptions options, AsrRunEvidence evidence, IAsrBackend backend)
    {
        ControlLifecycleResult<AsrBaseline> result = ControlLifecycle.Run(
            new AsrOperation(options, evidence), new AsrReader(backend), new AsrWriter(backend),
            delegate(IControlLifecycleSnapshot current) { return evidence.ObserveNow(); });
        evidence.Lifecycle = result;
        foreach (string error in result.Errors) { ConsoleUi.Status("FAIL", error, true); }
        if (result.Restoration == RestorationStatus.ManualRequired)
        { ConsoleUi.Row("Restoration", "MANUAL_REQUIRED - " + result.ManualRestoration); }
        return result.ExitCode;
    }

    private static int ReportError(string message)
    {
        ConsoleUi.Status("FAIL", message, true);
        ConsoleUi.Text("Check permissions/policy. If a write was attempted, inspect settings for partial changes.");
        ConsoleUi.Detail("This program does not disable or bypass organizational policy or tamper protection.");
        return 1;
    }

    private static bool IsHelp(string value)
    {
        return string.Equals(value, "--help", StringComparison.OrdinalIgnoreCase) ||
            string.Equals(value, "-help", StringComparison.OrdinalIgnoreCase) || value == "-?";
    }

    private static AsrAction ParseAction(string value)
    {
        if (string.Equals(value, "Block", StringComparison.OrdinalIgnoreCase)) { return AsrAction.Block; }
        if (string.Equals(value, "Audit", StringComparison.OrdinalIgnoreCase)) { return AsrAction.Audit; }
        if (string.Equals(value, "Warn", StringComparison.OrdinalIgnoreCase)) { return AsrAction.Warn; }
        if (string.Equals(value, "Disabled", StringComparison.OrdinalIgnoreCase)) { return AsrAction.Disabled; }
        if (string.Equals(value, "NotConfigured", StringComparison.OrdinalIgnoreCase)) { return AsrAction.NotConfigured; }
        throw new ArgumentException("-Action must be one of: Block, Audit, Warn, Disabled, NotConfigured.");
    }

    internal static AsrOptions Parse(string[] args)
    {
        if (args == null || args.Length == 0)
        { throw new ArgumentException("Expected 'status', 'exclusion', 'rule', or 'verify'."); }

        var options = new AsrOptions();
        int start;
        if (IsHelp(args[0]))
        {
            options.Help = true;
            options.Operation = "help";
            options.Kind = ControlKind.DefenderAsrStatus;
            start = 0;
        }
        else if (string.Equals(args[0], "status", StringComparison.OrdinalIgnoreCase))
        { options.Operation = "status"; options.Kind = ControlKind.DefenderAsrStatus; start = 1; }
        else if (string.Equals(args[0], "exclusion", StringComparison.OrdinalIgnoreCase))
        { options.Operation = "exclusion"; options.Kind = ControlKind.DefenderAsrExclusion; start = 1; }
        else if (string.Equals(args[0], "rule", StringComparison.OrdinalIgnoreCase))
        { options.Operation = "rule"; options.Kind = ControlKind.DefenderAsrRule; start = 1; }
        else if (string.Equals(args[0], "verify", StringComparison.OrdinalIgnoreCase))
        { options.Operation = "verify"; options.Kind = ControlKind.DefenderAsrVerify; start = 1; }
        else { throw new ArgumentException("Expected 'status', 'exclusion', 'rule', or 'verify'."); }

        if (!options.Help && start < args.Length && IsHelp(args[start]))
        {
            options.Help = true;
            options.Operation = "help";
            start++;
        }

        var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var allSeen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        bool ruleIdSeen = false, actionSeen = false, testCommandSeen = false, testArgumentsSeen = false;
        for (int i = start; i < args.Length; i++)
        {
            string key = args[i].ToLowerInvariant();
            string canonicalKey = IsHelp(key) ? "--help" : key;
            if (!allSeen.Add(canonicalKey)) { throw new ArgumentException("Duplicate option: " + key); }
            if (CommonArguments.TryParse(args, ref i, options, seen)) { continue; }

            if (key == "--transport")
            {
                if (i + 1 >= args.Length) { throw new ArgumentException("Specify --transport once, followed by management, com, or native."); }
                options.Transport = args[++i].ToLowerInvariant();
                if (options.Transport != "management" && options.Transport != "com" && options.Transport != "native")
                { throw new ArgumentException("Unknown transport. Supported values: management, com, native."); }
                continue;
            }
            if (key == "--check")
            {
                if (options.Kind == ControlKind.DefenderAsrStatus)
                { throw new ArgumentException("'status' is always read-only; --check is not accepted."); }
                options.CheckOnly = true;
                continue;
            }
            if (key == "-path" || key == "-ruleid" || key == "-action" || key == "-testcommand" || key == "-testarguments")
            {
                if (options.Kind == ControlKind.DefenderAsrStatus)
                { throw new ArgumentException("'status' accepts only --transport and common options."); }
                switch (key)
                {
                    case "-path":
                        if (options.Kind != ControlKind.DefenderAsrExclusion)
                        { throw new ArgumentException("-Path is only valid with 'exclusion'."); }
                        int count = 0;
                        while (i + 1 < args.Length && !args[i + 1].StartsWith("-", StringComparison.Ordinal))
                        {
                            string value = args[++i];
                            if (string.IsNullOrWhiteSpace(value)) { throw new ArgumentException("-Path does not accept empty values."); }
                            if (!options.Paths.Exists(delegate(string existing)
                                { return string.Equals(existing, value, StringComparison.OrdinalIgnoreCase); }))
                            { options.Paths.Add(value); }
                            count++;
                        }
                        if (count == 0) { throw new ArgumentException("-Path requires at least one value."); }
                        break;
                    case "-ruleid":
                        if (options.Kind != ControlKind.DefenderAsrRule && options.Kind != ControlKind.DefenderAsrVerify)
                        { throw new ArgumentException("-RuleId is only valid with 'rule' or 'verify'."); }
                        if (ruleIdSeen || i + 1 >= args.Length || !Guid.TryParse(args[++i], out options.RuleId) ||
                            options.RuleId == Guid.Empty)
                        { throw new ArgumentException("-RuleId requires one nonempty GUID."); }
                        ruleIdSeen = true;
                        break;
                    case "-action":
                        if (options.Kind != ControlKind.DefenderAsrRule)
                        { throw new ArgumentException("-Action is only valid with 'rule'."); }
                        if (actionSeen || i + 1 >= args.Length) { throw new ArgumentException("-Action requires one value."); }
                        options.Action = ParseAction(args[++i]);
                        actionSeen = true;
                        break;
                    case "-testcommand":
                        if (options.Kind != ControlKind.DefenderAsrVerify)
                        { throw new ArgumentException("-TestCommand is only valid with 'verify'."); }
                        if (testCommandSeen || i + 1 >= args.Length || string.IsNullOrWhiteSpace(args[i + 1]))
                        { throw new ArgumentException("-TestCommand requires one nonempty path."); }
                        options.TestCommand = args[++i];
                        testCommandSeen = true;
                        break;
                    case "-testarguments":
                        if (options.Kind != ControlKind.DefenderAsrVerify)
                        { throw new ArgumentException("-TestArguments is only valid with 'verify'."); }
                        if (testArgumentsSeen || i + 1 >= args.Length) { throw new ArgumentException("-TestArguments requires one value."); }
                        options.TestArguments = args[++i];
                        testArgumentsSeen = true;
                        break;
                }
                continue;
            }
            throw new ArgumentException("Unknown option: " + key);
        }
        CommonArguments.Validate(options, seen);
        if (options.Help) { return options; }
        if (options.Kind == ControlKind.DefenderAsrStatus) { return options; }

        if (options.Kind == ControlKind.DefenderAsrExclusion)
        {
            // Unlike 'defender exclusion', a bare --check here has no distinct "capabilities" report
            // of its own to fall back on, and 'status' already gives a full read-only exclusion
            // listing -- so a --check with no -Path would only ever produce a content-free "passed"
            // that checked nothing, which is worse than just requiring a path.
            if (options.Paths.Count == 0)
            { throw new ArgumentException("Specify at least one -Path (for --check or Add); use 'status' for a full read-only listing."); }
            return options;
        }
        if (options.Kind == ControlKind.DefenderAsrRule)
        {
            if (options.RuleId == Guid.Empty) { throw new ArgumentException("'rule' requires -RuleId."); }
            if (!options.CheckOnly && options.Action == null)
            { throw new ArgumentException("Specify -Action for a mutating rule change, or use --check."); }
            if (options.CheckOnly && options.Action != null)
            { throw new ArgumentException("--check reads the current action; it does not accept -Action."); }
            return options;
        }

        // verify
        if (options.RuleId == Guid.Empty) { throw new ArgumentException("'verify' requires -RuleId."); }
        if (testArgumentsSeen && options.TestCommand == null)
        { throw new ArgumentException("-TestArguments requires -TestCommand."); }
        if (options.TestCommand == null &&
            !string.Equals(options.RuleId.ToString("D"), AsrRuleCatalog.JavaScriptOrVbScriptRuleId, StringComparison.OrdinalIgnoreCase))
        { throw new ArgumentException("This rule has no built-in test primitive; specify -TestCommand (and optionally -TestArguments)."); }
        return options;
    }

    private static void PrintHelp()
    {
        ConsoleUi.Section("Usage");
        ConsoleUi.Text("wtf.exe defender asr status");
        ConsoleUi.Text("wtf.exe defender asr exclusion [--check] -Path VALUE [VALUE ...]");
        ConsoleUi.Text("wtf.exe defender asr rule --check -RuleId GUID");
        ConsoleUi.Text("wtf.exe defender asr rule -RuleId GUID -Action Block|Audit|Warn|Disabled|NotConfigured");
        ConsoleUi.Text("wtf.exe defender asr verify -RuleId GUID [--check] [-TestCommand PATH -TestArguments \"...\"]");
        ConsoleUi.Section("Sub-commands");
        ConsoleUi.Row("status", "Read-only posture: rules, policy source, global/AV exclusion exposure.");
        ConsoleUi.Row("exclusion", "Add/check ASR-only (global) exclusions (AttackSurfaceReductionOnlyExclusions).");
        ConsoleUi.Row("rule", "Read or set one rule's action (AttackSurfaceReductionRules_Ids/_Actions).");
        ConsoleUi.Row("verify", "Run a controlled test primitive; observe local enforcement + telemetry.");
        ConsoleUi.Section("Options");
        ConsoleUi.Row("--transport", "management|com|native  (default: management)");
        ConsoleUi.Row("--check", "Read-only for exclusion/rule/verify; never mutates Defender settings.");
        ConsoleUi.Row("-Path", "One or more file/folder paths for the 'exclusion' sub-command.");
        ConsoleUi.Row("-RuleId", "ASR rule GUID, for 'rule' and 'verify'.");
        ConsoleUi.Row("-Action", "Block | Audit | Warn | Disabled | NotConfigured, for 'rule'.");
        ConsoleUi.Row("-TestCommand", "An authorized executable to launch directly, for 'verify'. To run a " +
            "script, point this at its interpreter (e.g. wscript.exe) and pass the script path via -TestArguments.");
        ConsoleUi.Row("-TestArguments", "Arguments passed to -TestCommand.");
        ConsoleUi.HelpOptions();
        ConsoleUi.Section("Routes");
        ConsoleUi.Row("management", "System.Management -> WMI");
        ConsoleUi.Row("com", "SWbemServices COM Automation -> WMI");
        ConsoleUi.Row("native", "C++ IWbemServices::ExecQuery/ExecMethod -> WMI");
        ConsoleUi.Text("All routes target MSFT_MpPreference; ExecMethod only for a mutating Add, ExecQuery/Get " +
            "for every read (status, every --check, verify). No fallback or privilege bypass.");
        ConsoleUi.Section("Quick start");
        ConsoleUi.Text("Read-only posture:");
        ConsoleUi.Text("  .\\wtf.exe defender asr status");
        ConsoleUi.Text("Check a rule, then set it (administrator required):");
        ConsoleUi.Text("  .\\wtf.exe defender asr rule --check -RuleId " + AsrRuleCatalog.JavaScriptOrVbScriptRuleId);
        ConsoleUi.Text("  .\\wtf.exe defender asr rule -RuleId " + AsrRuleCatalog.JavaScriptOrVbScriptRuleId + " -Action Block");
        ConsoleUi.Text("Run the built-in JS/VBScript primitive against that rule:");
        ConsoleUi.Text("  .\\wtf.exe defender asr verify -RuleId " + AsrRuleCatalog.JavaScriptOrVbScriptRuleId);
        ConsoleUi.HelpTelemetry();
        ConsoleUi.Section("Before you run");
        ConsoleUi.Text("'status' and every --check are read-only and never require elevation.");
        ConsoleUi.Text("'exclusion' and 'rule' mutations are persistent Defender policy changes; no automatic cleanup.");
        ConsoleUi.Text("'verify' does not require elevation: ASR enforcement is not conditioned on the caller's privilege.");
        ConsoleUi.Text("'verify' only ships one built-in primitive (JS/VBScript launching a downloaded executable, GUID " +
            AsrRuleCatalog.JavaScriptOrVbScriptRuleId + "); other rules require your own authorized -TestCommand.");
        ConsoleUi.Status("WARN", "The built-in primitive has not been independently verified end-to-end (Block -> " +
            "expected 1121 event) in every environment; validate it once in an authorized disposable VM before relying on it.");
        ConsoleUi.Text("'verify' never reports CONFIRMED: local process observation alone cannot prove enforcement. " +
            "It reports Mismatch only for the unambiguous case (the primitive ran despite Block/Warn), and otherwise " +
            "Unavailable; use --telemetry etw or eventlog and inspect the correlated 1121/1122 evidence directly.");
        ConsoleUi.HelpExitCodes();
        ConsoleUi.Status("WARN", "ASR rule/exclusion changes reduce protection. Authorized testing only.");
        ConsoleUi.Text("Native transport requires WinTraceForge.Native.dll beside the EXE.");
        if (!ConsoleUi.Verbose) { return; }
        ConsoleUi.Section("Extended notes");
        ConsoleUi.Text("All transports target the same MSFT_MpPreference class and share identical read/write semantics; none elevates privileges.");
        ConsoleUi.Text("The rule name table is best-effort and may not match your Defender build; unrecognized GUIDs still work.");
        ConsoleUi.Text("Policy source classifies Local vs GroupPolicy registry keys only; Intune/MDM and Security Center " +
            "defaults that do not populate either key are reported as Unknown, not misclassified as Local.");
        ConsoleUi.Text("'exclusion'/'rule' use the WMI Add method only (adds/updates one entry, never removes one from " +
            "the array); to fully reset a rule use -Action NotConfigured, which the printed cleanup command does automatically.");
        ConsoleUi.Text("'verify' creates its test artifact under %LOCALAPPDATA%\\WinTraceForge\\AsrTests\\<run-id>\\ and " +
            "removes it automatically afterward (RestorationStatus reflects that cleanup, not the Defender rule state).");
        ConsoleUi.Text("A 'verify' result reports whether the run matched the *expected* outcome for the rule's current " +
            "action; it is not a general antivirus/EDR verdict, and a benign primitive does not represent real attacker tooling.");
        ConsoleUi.Text("Compliance and detection/response are not automatically assessed.");
        ConsoleUi.Text("See README.md and docs\\technical-reference.md for evidence limits and restoration guidance.");
    }

    internal static void PrintAssessment(AsrOptions options, AsrRunEvidence evidence, int exitCode)
    {
        ConsoleUi.Section("Result");
        string outcome;
        if (exitCode == 4) { outcome = "NOT_ATTEMPTED"; }
        else if (options.Kind == ControlKind.DefenderAsrStatus) { outcome = exitCode == 0 ? "STATUS_READ" : "STATUS_READ_ERROR"; }
        else if (options.CheckOnly) { outcome = exitCode == 0 ? "CHECK_ONLY" : "CHECK_ERROR"; }
        else if (exitCode == 0) { outcome = "CONFIRMED"; }
        else if (exitCode == 3) { outcome = "UNCONFIRMED"; }
        // Only 'verify' can ever produce this (Manual restoration for exclusion/rule never reports
        // Unavailable): the primitive ran and this host's process-tree cleanup could not be confirmed
        // (typically the notepad.exe redirection warning above), not a genuine operation failure. This
        // still exits 1 like any other unconfirmed restoration -- see docs/technical-reference.md.
        else if (evidence.Lifecycle != null && evidence.Lifecycle.Restoration == RestorationStatus.Unavailable)
        { outcome = "CLEANUP_UNVERIFIABLE"; }
        else { outcome = "OPERATION_ERROR"; }
        ConsoleUi.Status(exitCode == 0 ? "OK" : exitCode == 3 ? "WARN" : "FAIL", "Outcome: " + outcome);
        ConsoleUi.Row("Exit / stage", exitCode + " / " + evidence.Stage);
        if (evidence.Lifecycle != null)
        {
            ConsoleUi.Row("Lifecycle", "probe=" + evidence.Lifecycle.Probe +
                "; mutation=" + evidence.Lifecycle.Mutation +
                "; verification=" + evidence.Lifecycle.Verification +
                "; observation=" + evidence.Lifecycle.Observation +
                "; restoration=" + evidence.Lifecycle.Restoration);
        }
        ConsoleUi.Text("Compliance: NOT_ASSESSED | Detection/response: NOT_MEASURED");
        if (options.Kind != ControlKind.DefenderAsrVerify)
        { ConsoleUi.Text("No automatic cleanup of Defender policy; preserve pre-existing entries when restoring test changes."); }
        if (!options.Verbose)
        {
            ConsoleUi.Text("Use --verbose for diagnostic detail and Detection & Response guidance.");
            return;
        }
        ConsoleUi.Section("Diagnostics");
        ConsoleUi.Row("Run ID", evidence.RunId);
        ConsoleUi.Row("End UTC", evidence.OperationEndUtc.ToString("O", CultureInfo.InvariantCulture));
        ConsoleUi.Text("Transport: " + options.Transport + "; last stage: " + evidence.Stage);
        ConsoleUi.Section("Detection & Response");
        ConsoleUi.Row("1. Correlate", "Use UTC, host, identity, PID and the rule GUID/exclusion value. Run ID is local, not injected into events.");
        ConsoleUi.Row("2. Defender", "Event 1121: rule blocked (Block and Warn both raise 1121 by default; Warn additionally " +
            "offers the user a bypass this event alone does not confirm). Event 1122: rule audited (AuditMode only, allowed " +
            "and logged). Event 5007/5013: policy configuration change.");
        ConsoleUi.Row("3. Process", "Security 4688 (audit policy required), Sysmon 1, or EDR: correlate parent process, command line and hash.");
        ConsoleUi.Row("4. Validate", "Check collection, ingestion delay, sensor coverage and triage latency separately.");
        ConsoleUi.Row("5. Restore", "Rule/exclusion changes: use the printed manual cleanup command. 'verify' cleans its own artifact automatically.");
        ConsoleUi.Text("Reference: https://learn.microsoft.com/en-us/defender-endpoint/attack-surface-reduction-rules-reference");
    }

    // Shared by every transport: all three back the same MSFT_MpPreference class, so the AV
    // exclusion field list, the elevation-hiding sentinel, the array decoders and the snapshot
    // assembly logic are identical -- only how each transport fetches one named field differs.
    // internal (not private): exercised directly by deterministic regression tests, since the
    // snapshot this builds is the sole evidence behind every rule/exclusion Confirmed verdict and
    // every printed manual-restoration command.
    internal static readonly string[] AvExclusionTypes =
        { "ExclusionPath", "ExclusionExtension", "ExclusionProcess", "ExclusionIpAddress" };

    // MSFT_MpPreference returns this single-element sentinel array instead of real exclusion
    // content when the caller is not an administrator; it must never be read as literal data.
    internal static bool IsElevationPlaceholder(string[] values)
    {
        return values.Length == 1 && values[0] != null &&
            values[0].StartsWith("N/A:", StringComparison.OrdinalIgnoreCase);
    }

    internal static string[] DecodeStringArray(object raw)
    {
        if (raw == null || raw == DBNull.Value) { return new string[0]; }
        Array values = raw as Array;
        if (values == null) { throw new InvalidOperationException("Unexpected readback type for a string array."); }
        var result = new List<string>();
        foreach (object value in values)
        {
            if (value != null && !(value is string))
            { throw new InvalidOperationException("Unexpected array element for a string array."); }
            result.Add((string)value);
        }
        return result.ToArray();
    }

    internal static uint[] DecodeUInt32Array(object raw)
    {
        if (raw == null || raw == DBNull.Value) { return new uint[0]; }
        Array values = raw as Array;
        if (values == null) { throw new InvalidOperationException("Unexpected readback type for an action array."); }
        var result = new uint[values.Length];
        for (int i = 0; i < values.Length; i++)
        { result[i] = Convert.ToUInt32(values.GetValue(i), CultureInfo.InvariantCulture); }
        return result;
    }

    // A rule's Ids and Actions arrays are positionally paired by the provider; a length mismatch
    // (e.g. a native transport's two independent queries racing a concurrent GP/MDM policy push)
    // means the pairing cannot be trusted, so this fails loudly rather than defaulting whatever
    // Action is missing to Disabled -- silently fabricating a rule state no one actually observed.
    internal static Dictionary<string, AsrAction> BuildRuleActions(object rawIds, object rawActions)
    {
        string[] ids = DecodeStringArray(rawIds);
        uint[] actions = DecodeUInt32Array(rawActions);
        if (ids.Length != actions.Length)
        {
            throw new InvalidOperationException("AttackSurfaceReductionRules_Ids/_Actions length mismatch (" +
                ids.Length + " vs " + actions.Length + "); rule action readback cannot be trusted.");
        }
        var rules = new Dictionary<string, AsrAction>(StringComparer.OrdinalIgnoreCase);
        for (int i = 0; i < ids.Length; i++) { rules[ids[i]] = (AsrAction)actions[i]; }
        return rules;
    }

    // MSFT_MpPreference is a singleton class; every transport must see exactly one instance for a
    // readback to mean anything. Zero or multiple instances is an unobserved/ambiguous provider
    // state, not "nothing configured" -- so it must fail, never be read as an empty snapshot.
    internal static void RequireSingleInstance(int count)
    {
        if (count != 1)
        {
            throw new InvalidOperationException("MSFT_MpPreference returned " + count +
                " instance(s); expected exactly one. ASR posture cannot be trusted.");
        }
    }

    // Shared snapshot assembly: callers must first establish that exactly one
    // MSFT_MpPreference instance supplied the fields. Management/COM use ReadSnapshot for
    // that guard; native reads enforce singleton results in the native DLL.
    internal static AsrSnapshot BuildSnapshot(Func<string, object> field)
    {
        Dictionary<string, AsrAction> rules = BuildRuleActions(
            field("AttackSurfaceReductionRules_Ids"), field("AttackSurfaceReductionRules_Actions"));

        bool globalElevationRequired = false;
        var globalExclusions = new List<string>();
        string[] global = DecodeStringArray(field("AttackSurfaceReductionOnlyExclusions"));
        if (IsElevationPlaceholder(global)) { globalElevationRequired = true; }
        else { globalExclusions.AddRange(global); }

        bool avElevationRequired = false;
        var avExclusions = new Dictionary<string, List<string>>(StringComparer.OrdinalIgnoreCase);
        foreach (string type in AvExclusionTypes)
        {
            string[] values = DecodeStringArray(field(type));
            if (IsElevationPlaceholder(values)) { avElevationRequired = true; avExclusions.Add(type, new List<string>()); }
            else { avExclusions.Add(type, new List<string>(values)); }
        }
        return new AsrSnapshot(rules, globalExclusions, avExclusions, globalElevationRequired, avElevationRequired);
    }

    // Convention for the query-then-enumerate transports (management, COM): their Read()
    // implementations pass raw per-instance field lookups here, so the singleton check
    // precedes snapshot assembly. BuildSnapshot is internal and can be called separately;
    // tests cover this entry point as well as the two constituent helpers.
    internal static AsrSnapshot ReadSnapshot(IEnumerable<Func<string, object>> records)
    {
        Func<string, object> only = null;
        int count = 0;
        foreach (Func<string, object> record in records)
        {
            count++;
            if (only == null) { only = record; }
        }
        RequireSingleInstance(count);
        return BuildSnapshot(only);
    }

    private sealed class ManagementAsrBackend : IAsrBackend
    {
        private readonly ManagementScope scope = new ManagementScope(@"\\.\root\Microsoft\Windows\Defender");
        private ManagementClass preferenceClass;
        private ManagementBaseObject input;

        public void Connect() { scope.Connect(); }

        public void Prepare(AsrMutationRequest request)
        {
            preferenceClass = new ManagementClass(scope, new ManagementPath("MSFT_MpPreference"), null);
            preferenceClass.Get();
            input = preferenceClass.GetMethodParameters("Add");
            if (input == null) { throw new InvalidOperationException("Defender WMI Add parameter metadata is unavailable."); }
            if (request.Kind == AsrRequestKind.GlobalExclusion)
            {
                if (!Supports("AttackSurfaceReductionOnlyExclusions"))
                { throw new InvalidOperationException("Unsupported property: AttackSurfaceReductionOnlyExclusions"); }
                input["AttackSurfaceReductionOnlyExclusions"] = request.ExclusionPaths.ToArray();
            }
            else
            {
                if (!Supports("AttackSurfaceReductionRules_Ids") || !Supports("AttackSurfaceReductionRules_Actions"))
                { throw new InvalidOperationException("Unsupported property: AttackSurfaceReductionRules_Ids/Actions"); }
                input["AttackSurfaceReductionRules_Ids"] = new[] { request.RuleId };
                input["AttackSurfaceReductionRules_Actions"] = new[] { (byte)request.Action };
            }
        }

        public bool Supports(string name)
        {
            CimType expected = AsrPropertySchema.ExpectedType(name);
            return HasArrayProperty(input.Properties, name, expected) &&
                HasArrayProperty(preferenceClass.Properties, name, expected);
        }

        private static bool HasArrayProperty(PropertyDataCollection properties, string name, CimType expected)
        {
            foreach (PropertyData property in properties)
            {
                if (string.Equals(property.Name, name, StringComparison.OrdinalIgnoreCase))
                { return property.IsArray && property.Type == expected; }
            }
            return false;
        }

        public object Add()
        {
            using (ManagementBaseObject result = preferenceClass.InvokeMethod("Add", input, null))
            {
                if (result != null)
                {
                    foreach (PropertyData property in result.Properties)
                    {
                        if (string.Equals(property.Name, "ReturnValue", StringComparison.OrdinalIgnoreCase))
                        { return property.Value; }
                    }
                }
            }
            return null;
        }

        public AsrSnapshot Read()
        {
            var fields = new List<string>
            {
                "AttackSurfaceReductionRules_Ids", "AttackSurfaceReductionRules_Actions",
                "AttackSurfaceReductionOnlyExclusions"
            };
            fields.AddRange(AvExclusionTypes);

            using (var searcher = new ManagementObjectSearcher(scope,
                new ObjectQuery("SELECT " + string.Join(", ", fields) + " FROM MSFT_MpPreference")))
            using (ManagementObjectCollection results = searcher.Get())
            {
                var instances = new List<ManagementObject>();
                try
                {
                    var records = new List<Func<string, object>>();
                    foreach (ManagementObject candidate in results)
                    {
                        instances.Add(candidate);
                        ManagementObject captured = candidate;
                        records.Add(name => captured[name]);
                    }
                    return ReadSnapshot(records);
                }
                finally { foreach (ManagementObject instance in instances) { instance.Dispose(); } }
            }
        }

        public Dictionary<string, AsrPolicySourceKind> ReadPolicySource(IEnumerable<string> keys)
        { return AsrRegistry.ReadPolicySource(keys); }

        public bool IsNotepadRedirectionActive() { return AsrRegistry.IsNotepadRedirectionActive(); }

        public void Dispose()
        {
            if (input != null) { input.Dispose(); }
            if (preferenceClass != null) { preferenceClass.Dispose(); }
        }
    }

    // Disciplined IDispatch access to the official WbemScripting.SWbemLocator/SWbemServices COM
    // Automation objects, reusing DefenderModule's ComObjects RCW bookkeeping since both backends
    // talk to the same root\Microsoft\Windows\Defender namespace and MSFT_MpPreference class.
    private sealed class ComAsrBackend : IAsrBackend
    {
        private readonly DefenderModule.ComObjects objects = new DefenderModule.ComObjects();
        private object services;
        private object input;
        private Dictionary<string, object> inputProperties;
        private Dictionary<string, object> classProperties;

        public void Connect()
        {
            Type locatorType = Type.GetTypeFromProgID("WbemScripting.SWbemLocator");
            if (locatorType == null)
            {
                throw new NotSupportedException("WbemScripting.SWbemLocator is not registered.");
            }
            object locator = objects.Own(Activator.CreateInstance(locatorType));
            services = objects.Call(locator, "ConnectServer", ".", @"root\Microsoft\Windows\Defender",
                "", "", "", "", 128, new DispatchWrapper(null));
            object security = objects.Get(services, "Security_");
            objects.Set(security, "ImpersonationLevel", 3);
        }

        public void Prepare(AsrMutationRequest request)
        {
            object preferenceClass = objects.Call(services, "Get", "MSFT_MpPreference", 0, new DispatchWrapper(null));
            object methods = objects.Get(preferenceClass, "Methods_");
            object add = objects.Call(methods, "Item", "Add", 0);
            object definition = objects.Get(add, "InParameters");
            if (definition == null)
            {
                throw new InvalidOperationException("Defender COM Add parameter metadata is unavailable.");
            }
            input = objects.Call(definition, "SpawnInstance_", 0);
            inputProperties = objects.Properties(input);
            classProperties = objects.Properties(preferenceClass);
            if (request.Kind == AsrRequestKind.GlobalExclusion)
            {
                if (!Supports("AttackSurfaceReductionOnlyExclusions"))
                { throw new InvalidOperationException("Unsupported property: AttackSurfaceReductionOnlyExclusions"); }
                objects.Set(inputProperties["AttackSurfaceReductionOnlyExclusions"], "Value", request.ExclusionPaths.ToArray());
            }
            else
            {
                if (!Supports("AttackSurfaceReductionRules_Ids") || !Supports("AttackSurfaceReductionRules_Actions"))
                { throw new InvalidOperationException("Unsupported property: AttackSurfaceReductionRules_Ids/Actions"); }
                objects.Set(inputProperties["AttackSurfaceReductionRules_Ids"], "Value", new[] { request.RuleId });
                objects.Set(inputProperties["AttackSurfaceReductionRules_Actions"], "Value", new[] { (byte)request.Action });
            }
        }

        public bool Supports(string name)
        {
            CimType expected = AsrPropertySchema.ExpectedType(name);
            return IsArrayOfType(inputProperties, name, expected) && IsArrayOfType(classProperties, name, expected);
        }

        private bool IsArrayOfType(Dictionary<string, object> properties, string name, CimType expected)
        {
            object property;
            return properties.TryGetValue(name, out property) &&
                Convert.ToInt32(objects.Get(property, "CIMType"), CultureInfo.InvariantCulture) == (int)expected &&
                Convert.ToBoolean(objects.Get(property, "IsArray"), CultureInfo.InvariantCulture);
        }

        public object Add()
        {
            object result = objects.Call(services, "ExecMethod", "MSFT_MpPreference", "Add", input, 0, new DispatchWrapper(null));
            if (result == null) { return null; }
            object property;
            return objects.Properties(result).TryGetValue("ReturnValue", out property) ?
                objects.Get(property, "Value") : null;
        }

        public AsrSnapshot Read()
        {
            var fields = new List<string>
            {
                "AttackSurfaceReductionRules_Ids", "AttackSurfaceReductionRules_Actions",
                "AttackSurfaceReductionOnlyExclusions"
            };
            fields.AddRange(AvExclusionTypes);

            object results = objects.Call(services, "ExecQuery",
                "SELECT " + string.Join(", ", fields) + " FROM MSFT_MpPreference", "WQL", 0, new DispatchWrapper(null));
            int count = Convert.ToInt32(objects.Get(results, "Count"), CultureInfo.InvariantCulture);
            var records = new List<Func<string, object>>();
            for (int i = 0; i < count; i++)
            {
                object record = objects.Call(results, "ItemIndex", i);
                Dictionary<string, object> properties = objects.Properties(record);
                records.Add(name => FieldValue(properties, name));
            }
            return ReadSnapshot(records);
        }

        private object FieldValue(Dictionary<string, object> properties, string name)
        {
            object property;
            if (!properties.TryGetValue(name, out property))
            { throw new InvalidOperationException("Missing COM readback field: " + name); }
            return objects.Get(property, "Value");
        }

        public Dictionary<string, AsrPolicySourceKind> ReadPolicySource(IEnumerable<string> keys)
        { return AsrRegistry.ReadPolicySource(keys); }

        public bool IsNotepadRedirectionActive() { return AsrRegistry.IsNotepadRedirectionActive(); }

        public void Dispose() { objects.Dispose(); }
    }

    // P/Invoke bridge to the shared native transport (WinTraceForge.Native.dll): the same
    // IWbemLocator/IWbemServices ExecMethod session Defender's native backend uses, extended to
    // set the UInt8 Actions array (NativeSetByteValues) that a rule mutation also needs.
    private sealed class NativeAsrBackend : IAsrBackend
    {
        private IntPtr handle;

        public void Connect()
        {
            CheckNative(NativeMethods.NativeOpen(out handle), "IWbemLocator::ConnectServer / proxy security");
        }

        public void Prepare(AsrMutationRequest request)
        {
            CheckNative(NativeMethods.NativePrepare(handle), "GetObject / GetMethod / SpawnInstance");
            if (request.Kind == AsrRequestKind.GlobalExclusion)
            {
                if (!Supports("AttackSurfaceReductionOnlyExclusions"))
                { throw new InvalidOperationException("Unsupported property: AttackSurfaceReductionOnlyExclusions"); }
                string[] values = request.ExclusionPaths.ToArray();
                CheckNative(NativeMethods.NativeSetValues(handle, "AttackSurfaceReductionOnlyExclusions", values, values.Length),
                    "IWbemClassObject::Put(AttackSurfaceReductionOnlyExclusions)");
            }
            else
            {
                if (!Supports("AttackSurfaceReductionRules_Ids") || !Supports("AttackSurfaceReductionRules_Actions"))
                { throw new InvalidOperationException("Unsupported property: AttackSurfaceReductionRules_Ids/Actions"); }
                string[] ids = { request.RuleId };
                CheckNative(NativeMethods.NativeSetValues(handle, "AttackSurfaceReductionRules_Ids", ids, ids.Length),
                    "IWbemClassObject::Put(AttackSurfaceReductionRules_Ids)");
                byte[] actions = { (byte)request.Action };
                CheckNative(NativeMethods.NativeSetByteValues(handle, "AttackSurfaceReductionRules_Actions", actions, actions.Length),
                    "IWbemClassObject::Put(AttackSurfaceReductionRules_Actions)");
            }
        }

        public bool Supports(string name)
        {
            bool supported;
            CheckNative(NativeMethods.NativeSupports(handle, name, out supported), "Get parameter metadata: " + name);
            return supported;
        }

        public object Add()
        {
            object returnValue;
            CheckNative(NativeMethods.NativeAdd(handle, out returnValue), "IWbemServices::ExecMethod(Add)");
            return returnValue;
        }

        // Ids/Actions must be paired from one atomic ExecQuery (NativeReadPair), not two
        // independent ones: a length-only check cannot catch a same-length reshuffle (e.g. a GP/MDM
        // push that removes one rule and adds another between two separate queries), only a
        // length change. Every other field here has no such pairing to protect and stays per-field
        // (each still fails closed -- WBEM_E_NOT_FOUND / WBEM_E_PROVIDER_FAILURE -- unless exactly
        // one MSFT_MpPreference instance answers it).
        public AsrSnapshot Read()
        {
            object cachedIds = null, cachedActions = null;
            bool ruleActionsFetched = false;
            return BuildSnapshot(delegate(string name)
            {
                if (name == "AttackSurfaceReductionRules_Ids" || name == "AttackSurfaceReductionRules_Actions")
                {
                    if (!ruleActionsFetched)
                    {
                        CheckNative(NativeMethods.NativeReadPair(handle, "AttackSurfaceReductionRules_Ids",
                            "AttackSurfaceReductionRules_Actions", out cachedIds, out cachedActions),
                            "ExecQuery / Get: AttackSurfaceReductionRules_Ids + _Actions (paired)");
                        ruleActionsFetched = true;
                    }
                    return name == "AttackSurfaceReductionRules_Ids" ? cachedIds : cachedActions;
                }
                object raw;
                CheckNative(NativeMethods.NativeRead(handle, name, out raw), "ExecQuery / Get: " + name);
                return raw;
            });
        }

        public Dictionary<string, AsrPolicySourceKind> ReadPolicySource(IEnumerable<string> keys)
        { return AsrRegistry.ReadPolicySource(keys); }

        public bool IsNotepadRedirectionActive() { return AsrRegistry.IsNotepadRedirectionActive(); }

        // RunWithBackend is synchronous; COM initialization and release remain on the same thread.
        public void Dispose()
        {
            if (handle != IntPtr.Zero)
            {
                NativeMethods.NativeClose(handle);
                handle = IntPtr.Zero;
            }
        }

        private static void CheckNative(int hresult, string operation)
        {
            if (hresult < 0)
            {
                throw new COMException("Native " + operation + " failed: " +
                    Marshal.GetExceptionForHR(hresult).Message, hresult);
            }
        }
    }

    private static class NativeMethods
    {
        private const string Library = "WinTraceForge.Native.dll";

        [DllImport(Library, CallingConvention = CallingConvention.Cdecl, ExactSpelling = true)]
        [DefaultDllImportSearchPaths(DllImportSearchPath.AssemblyDirectory | DllImportSearchPath.System32)]
        internal static extern int NativeOpen(out IntPtr handle);

        [DllImport(Library, CallingConvention = CallingConvention.Cdecl, ExactSpelling = true)]
        [DefaultDllImportSearchPaths(DllImportSearchPath.AssemblyDirectory | DllImportSearchPath.System32)]
        internal static extern int NativePrepare(IntPtr handle);

        [DllImport(Library, CallingConvention = CallingConvention.Cdecl, ExactSpelling = true, CharSet = CharSet.Unicode)]
        [DefaultDllImportSearchPaths(DllImportSearchPath.AssemblyDirectory | DllImportSearchPath.System32)]
        internal static extern int NativeSupports(IntPtr handle, string name, [MarshalAs(UnmanagedType.Bool)] out bool supported);

        [DllImport(Library, CallingConvention = CallingConvention.Cdecl, ExactSpelling = true, CharSet = CharSet.Unicode)]
        [DefaultDllImportSearchPaths(DllImportSearchPath.AssemblyDirectory | DllImportSearchPath.System32)]
        internal static extern int NativeSetValues(IntPtr handle, string name,
            [In, MarshalAs(UnmanagedType.LPArray, ArraySubType = UnmanagedType.LPWStr, SizeParamIndex = 3)] string[] values, int count);

        [DllImport(Library, CallingConvention = CallingConvention.Cdecl, ExactSpelling = true, CharSet = CharSet.Unicode)]
        [DefaultDllImportSearchPaths(DllImportSearchPath.AssemblyDirectory | DllImportSearchPath.System32)]
        internal static extern int NativeSetByteValues(IntPtr handle, string name,
            [In, MarshalAs(UnmanagedType.LPArray, ArraySubType = UnmanagedType.U1, SizeParamIndex = 3)] byte[] values, int count);

        [DllImport(Library, CallingConvention = CallingConvention.Cdecl, ExactSpelling = true)]
        [DefaultDllImportSearchPaths(DllImportSearchPath.AssemblyDirectory | DllImportSearchPath.System32)]
        internal static extern int NativeAdd(IntPtr handle, [MarshalAs(UnmanagedType.Struct)] out object returnValue);

        [DllImport(Library, CallingConvention = CallingConvention.Cdecl, ExactSpelling = true, CharSet = CharSet.Unicode)]
        [DefaultDllImportSearchPaths(DllImportSearchPath.AssemblyDirectory | DllImportSearchPath.System32)]
        internal static extern int NativeRead(IntPtr handle, string name, [MarshalAs(UnmanagedType.Struct)] out object values);

        [DllImport(Library, CallingConvention = CallingConvention.Cdecl, ExactSpelling = true, CharSet = CharSet.Unicode)]
        [DefaultDllImportSearchPaths(DllImportSearchPath.AssemblyDirectory | DllImportSearchPath.System32)]
        internal static extern int NativeReadPair(IntPtr handle, string firstName, string secondName,
            [MarshalAs(UnmanagedType.Struct)] out object firstValues, [MarshalAs(UnmanagedType.Struct)] out object secondValues);

        [DllImport(Library, CallingConvention = CallingConvention.Cdecl, ExactSpelling = true)]
        [DefaultDllImportSearchPaths(DllImportSearchPath.AssemblyDirectory | DllImportSearchPath.System32)]
        internal static extern void NativeClose(IntPtr handle);
    }
}
