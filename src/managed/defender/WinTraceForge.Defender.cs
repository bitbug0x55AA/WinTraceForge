// This Source Code Form is subject to the terms of the
// Mozilla Public License, v. 2.0.
// If a copy of the MPL was not distributed with this file, You can obtain one at https://mozilla.org/MPL/2.0/.

using System;
using System.Collections;
using System.Collections.Generic;
using System.ComponentModel;
using System.Diagnostics;
using System.Globalization;
using System.IO;
using System.Management;
using System.Reflection;
using System.Runtime.ExceptionServices;
using System.Runtime.InteropServices;
using System.Security;
using System.Security.Principal;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

internal static class DefenderModule
{
    private static readonly string[] ExclusionTypes =
    {
        "ExclusionPath", "ExclusionExtension", "ExclusionProcess", "ExclusionIpAddress"
    };

    // The explicit command word that follows "defender exclusion". Add is also the mode of the
    // legacy implicit syntax (values without a command word), flagged by Options.LegacySyntax.
    internal enum ExclusionMode { Add, Check, List, Remove }

    // Defender returns this text in place of the real values when the caller may not read the
    // exclusion lists (a non-administrator, or a policy that hides them from local administrators).
    // Only the language-independent "N/A:" prefix is matched, since the sentence itself is localized.
    private const string UnreadableMarkerPrefix = "N/A:";

    internal sealed class Options : ControlOptions
    {
        internal ExclusionMode Mode = ExclusionMode.Add;
        // True when the legacy implicit-add / --check syntax was used instead of a command word.
        internal bool LegacySyntax;
        // Legacy view of Mode: setting it maps to Check/Add, as the old --check flag did.
        internal bool CheckOnly
        {
            get { return Mode == ExclusionMode.Check; }
            set { Mode = value ? ExclusionMode.Check : ExclusionMode.Add; }
        }
        internal bool ReadOnly { get { return Mode == ExclusionMode.Check || Mode == ExclusionMode.List; } }
        internal string Transport = "management";
        internal readonly Dictionary<string, List<string>> Exclusions =
            new Dictionary<string, List<string>>(StringComparer.OrdinalIgnoreCase);
        internal Options() { Kind = ControlKind.DefenderExclusion; }
        internal override TelemetryProfile Telemetry { get { return DefenderTelemetry.Profile; } }
        internal override IEnumerable<string> EvidenceValues
        {
            get
            {
                foreach (var item in Exclusions)
                {
                    foreach (string value in item.Value) { yield return value; }
                }
            }
        }
    }

    internal static int Main(string[] args)
    {
        Options options;
        try
        {
            options = ParseArguments(args);
        }
        catch (ArgumentException ex)
        {
            ConsoleUi.Status("FAIL", "Invalid arguments: " + ex.Message, true);
            ConsoleUi.Text("Use --help for usage. No settings were changed.");
            return 2;
        }

        ConsoleUi.Configure(options.Verbose, options.NoColor);
        ConsoleUi.Banner();
        if (options.Help)
        {
            PrintHelp();
            return 0;
        }
        PrintLegacyHint(options);

        var evidence = new RunEvidence();
        return ControlRuntime.Execute(options, evidence,
            delegate { return ExecuteSafely(options, evidence); },
            delegate(int exitCode) { PrintAssessment(options, evidence, exitCode); });
    }

    private static int ExecuteSafely(Options options, RunEvidence evidence)
    {
        try
        {
            return Run(options, evidence);
        }
        catch (ManagementException ex)
        {
            return ReportError("Defender WMI error (" + ex.ErrorCode + "): " + ex.Message);
        }
        catch (UnauthorizedAccessException ex)
        {
            return ReportError("Access denied: " + ex.Message);
        }
        catch (COMException ex)
        {
            return ReportError("WMI COM error (0x" + ex.ErrorCode.ToString("X8") + "): " + ex.Message);
        }
        catch (SecurityException ex)
        {
            return ReportError("Security error: " + ex.Message);
        }
        catch (InvalidOperationException ex)
        {
            return ReportError(ex.Message);
        }
        catch (MissingMemberException ex)
        {
            return ReportError("WMI COM Automation interface mismatch: " + ex.Message);
        }
        catch (NotSupportedException ex)
        {
            return ReportError("The selected transport is unavailable: " + ex.Message);
        }
        catch (DllNotFoundException ex)
        {
            return ReportError("Native backend DLL is missing or could not be loaded. Keep the matching DLL beside the EXE. " + ex.Message);
        }
        catch (BadImageFormatException ex)
        {
            return ReportError("Native backend architecture mismatch. Use the matching x64 EXE and DLL. " + ex.Message);
        }
        catch (EntryPointNotFoundException ex)
        {
            return ReportError("Native backend DLL version mismatch: " + ex.Message);
        }
    }

    internal static Options ParseArguments(string[] args)
    {
        var options = new Options();
        bool transportSpecified = false;
        var commonSeen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        if (args.Length == 0)
        {
            throw new ArgumentException("Specify a command (add, check, list, or remove) or --help. There is no default exclusion.");
        }

        int first = 0;
        bool explicitCommand = TryParseCommand(args[0], out options.Mode);
        if (explicitCommand) { first = 1; }
        bool legacyCheck = false;

        for (int i = first; i < args.Length; i++)
        {
            string argument = args[i];
            if (CommonArguments.TryParse(args, ref i, options, commonSeen)) { continue; }

            if (string.Equals(argument, "--check", StringComparison.OrdinalIgnoreCase))
            {
                if (explicitCommand)
                {
                    throw new ArgumentException("--check is the legacy spelling and cannot follow a command. Use 'check' as the command.");
                }
                legacyCheck = true;
                options.Mode = ExclusionMode.Check;
                continue;
            }

            if (string.Equals(argument, "--transport", StringComparison.OrdinalIgnoreCase))
            {
                if (transportSpecified || i + 1 >= args.Length)
                {
                    throw new ArgumentException("Specify --transport once, followed by management, com, native, or powershell.");
                }
                options.Transport = args[++i].ToLowerInvariant();
                if (options.Transport != "management" && options.Transport != "com" &&
                    options.Transport != "native" && options.Transport != "powershell")
                {
                    throw new ArgumentException("Unknown transport. Supported values: management, com, native, powershell.");
                }
                transportSpecified = true;
                continue;
            }

            int equals = argument.IndexOf('=');
            string name = equals < 0 ? argument : argument.Substring(0, equals);
            string type = null;
            foreach (string candidate in ExclusionTypes)
            {
                if (string.Equals(name, "-" + candidate, StringComparison.OrdinalIgnoreCase))
                {
                    type = candidate;
                    break;
                }
            }
            if (type == null)
            {
                ExclusionMode misplaced;
                if (TryParseCommand(argument, out misplaced))
                {
                    throw new ArgumentException("The command must come first: wtf.exe defender exclusion " +
                        argument.ToLowerInvariant() + " [options]. Unexpected: " + argument);
                }
                throw new ArgumentException("Unknown option or unexpected value: " + argument);
            }

            int count = 0;
            if (equals >= 0)
            {
                AddValue(options, type, argument.Substring(equals + 1));
                count++;
            }
            while (i + 1 < args.Length && !args[i + 1].StartsWith("-", StringComparison.Ordinal))
            {
                ExclusionMode word;
                if (TryParseCommand(args[i + 1], out word))
                {
                    // A trailing command word would otherwise be swallowed as a value (and add would
                    // persist an exclusion with that name). This applies to the legacy implicit add too:
                    // it is the likeliest misplacement during migration, and -ExclusionTYPE=VALUE covers
                    // the rare literal value.
                    throw new ArgumentException("'" + args[i + 1] + "' follows -" + type +
                        " and would be taken as a value. The command must come first; for a literal value use -" +
                        type + "=" + args[i + 1] + ".");
                }
                AddValue(options, type, args[++i]);
                count++;
            }
            if (count == 0)
            {
                throw new ArgumentException("-" + type + " requires at least one value.");
            }
        }
        if (options.Help)
        {
            if (legacyCheck || options.Exclusions.Count != 0 ||
                transportSpecified || commonSeen.Count != 0)
            {
                throw new ArgumentException("Use --help by itself, or with --verbose / --no-color.");
            }
            return options;
        }
        if (!explicitCommand)
        {
            // Migration period: the old syntax still works, but main prints the replacement command.
            options.LegacySyntax = true;
            if (!legacyCheck && options.Exclusions.Count == 0)
            {
                throw new ArgumentException("Specify a command (add, check, list, or remove), a legacy exclusion, or --help. There is no default exclusion.");
            }
            if (!legacyCheck) { options.Mode = ExclusionMode.Add; }
        }
        else if (options.Mode == ExclusionMode.Add && options.Exclusions.Count == 0)
        {
            throw new ArgumentException("'add' requires at least one -ExclusionTYPE VALUE; there is no default exclusion.");
        }
        else if (options.Mode == ExclusionMode.Remove && options.Exclusions.Count == 0)
        {
            throw new ArgumentException("'remove' requires an explicit -ExclusionTYPE and value; there is no remove-all mode.");
        }
        else if (options.Mode == ExclusionMode.List && options.Exclusions.Count != 0)
        {
            throw new ArgumentException("'list' reads every readable exclusion and does not accept values; use 'check' for specific values.");
        }
        CommonArguments.Validate(options, commonSeen);
        return options;
    }

    private static bool TryParseCommand(string word, out ExclusionMode mode)
    {
        foreach (ExclusionMode candidate in new[] { ExclusionMode.Add, ExclusionMode.Check,
            ExclusionMode.List, ExclusionMode.Remove })
        {
            if (string.Equals(word, candidate.ToString(), StringComparison.OrdinalIgnoreCase))
            {
                mode = candidate;
                return true;
            }
        }
        mode = ExclusionMode.Add;
        return false;
    }

    internal static void PrintLegacyHint(Options options)
    {
        if (!options.LegacySyntax) { return; }
        string command = options.Mode == ExclusionMode.Check ? "check" : "add";
        ConsoleUi.Status("WARN", (options.Mode == ExclusionMode.Check ?
            "'--check' is deprecated and will be removed." : "Implicit add is deprecated and will be removed.") +
            " Use: wtf.exe defender exclusion " + command + " [options]" +
            (options.Mode == ExclusionMode.Check ? "" : " -ExclusionTYPE VALUE") + ".", true);
    }

    private static void AddValue(Options options, string type, string value)
    {
        if (string.IsNullOrWhiteSpace(value))
        {
            throw new ArgumentException("-" + type + " does not accept empty or whitespace-only values.");
        }
        if (CommonArguments.HasUnpairedSurrogate(value))
        {
            throw new ArgumentException("-" + type + " does not accept a value containing an unpaired UTF-16 surrogate.");
        }
        List<string> values;
        if (!options.Exclusions.TryGetValue(type, out values))
        {
            values = new List<string>();
            options.Exclusions.Add(type, values);
        }
        if (!values.Exists(delegate(string existing)
            { return string.Equals(existing, value, StringComparison.OrdinalIgnoreCase); }))
        {
            values.Add(value);
        }
    }

    private static void PrintHelp()
    {
        ConsoleUi.Section("Usage");
        ConsoleUi.Text("wtf.exe defender exclusion <command> [options] [-ExclusionTYPE VALUE [VALUE ...]]");
        ConsoleUi.Section("Options");
        ConsoleUi.Row("--transport", "management|com|native|powershell  (default: management)");
        ConsoleUi.HelpOptions();
        ConsoleUi.Section("Commands");
        ConsoleUi.Row("add", "Add the values you name (administrator required).");
        ConsoleUi.Row("check", "Read-only: are these values present? No values: capability check.");
        ConsoleUi.Row("list", "Read-only: each type's entries. An unreadable list is never shown as empty.");
        ConsoleUi.Row("remove", "Remove only named values (admin). No remove-all; refuses unreadable lists.");
        ConsoleUi.Section("Exclusion types");
        ConsoleUi.Row("-ExclusionPath", "Files or directories");
        ConsoleUi.Row("-ExclusionExtension", "File extensions");
        ConsoleUi.Row("-ExclusionProcess", "Process names or executable paths (Defender semantics)");
        ConsoleUi.Row("-ExclusionIpAddress", "IP addresses (requires provider support)");
        ConsoleUi.Section("Routes");
        ConsoleUi.Row("management", "System.Management -> WMI");
        ConsoleUi.Row("com", "SWbemServices COM Automation -> WMI");
        ConsoleUi.Row("native", "C++ IWbemServices::ExecMethod -> WMI");
        ConsoleUi.Row("powershell", "powershell.exe -> Add-/Remove-/Get-MpPreference");
        ConsoleUi.Section("Quick start");
        ConsoleUi.Text("  .\\wtf.exe defender exclusion check -ExclusionPath \"C:\\Lab Data\"");
        ConsoleUi.Text("  .\\wtf.exe defender exclusion add -ExclusionPath \"C:\\Lab Data\"");
        ConsoleUi.Text("  .\\wtf.exe defender exclusion remove -ExclusionPath \"C:\\Lab Data\"");
        ConsoleUi.Section("Before you run");
        ConsoleUi.Text("No command: usage error. Old implicit add and --check still work but warn.");
        ConsoleUi.Text("Native transport and ETW require WinTraceForge.Native.dll beside the EXE.");
        ConsoleUi.Text("powershell transport uses System32's own powershell.exe (no PATH lookup) and needs ConfigDefender.");
        ConsoleUi.HelpExitCodes();
        ConsoleUi.Status("WARN", "Exclusions reduce protection. Authorized testing only; no automatic cleanup.");
        if (!ConsoleUi.Verbose) { return; }
        ConsoleUi.Section("Extended notes");
        ConsoleUi.HelpTelemetry();
        ConsoleUi.Text("Quote paths with spaces; separate values with spaces, not commas.");
        ConsoleUi.Text("All routes target Defender preferences directly or via Defender cmdlets; no fallback.");
        ConsoleUi.Text("Parameter names are case-insensitive and may be combined or repeated.");
        ConsoleUi.Text("PowerShell array syntax and parameter abbreviations are not supported.");
        ConsoleUi.Text("For a value starting with '-', use -ExclusionTYPE=VALUE.");
        ConsoleUi.Text("The command must come first. The legacy --check cannot follow a command.");
        ConsoleUi.Text("check alone reads metadata; with values it also prepares inputs and reads the baseline.");
        ConsoleUi.Text("check does not validate provider acceptance, write permissions, or prevention policy.");
        ConsoleUi.Text("list shows each type as entries, EMPTY (readable, none), UNSUPPORTED (not a readable preference field) or UNREADABLE (contents withheld from this identity, e.g. non-administrator).");
        ConsoleUi.Text("UNREADABLE is never reported as empty and never as 'value absent'; check/list then exit 3.");
        ConsoleUi.Text("Existing exclusions are preserved. Every requested item is read back after add.");
        ConsoleUi.Text("remove reads a baseline first: values already absent are reported ALREADY_ABSENT and never sent to Remove; an unreadable list refuses the whole command.");
        ConsoleUi.Text("remove sends one request per value, reads every value back, and lists REMOVED_CONFIRMED, NOT_CONFIRMED, ERROR or ALREADY_ABSENT for each. No rollback.");
        ConsoleUi.Text("Exclusions carry no WTF ownership marker: remove never claims a value was created by WTF.");
        ConsoleUi.Text("A missing WMI return code is a warning; known nonzero codes remain errors.");
        ConsoleUi.Text("Pre-existing values do not prove a new change. Batch changes are not transactional.");
        ConsoleUi.Text("Eventlog reads existing channels; it does not start raw ETW tracing or enable audit policies.");
        ConsoleUi.Text("ETW creates a unique file-mode session before the operation, stops it, then decodes the ETL with TDH.");
        ConsoleUi.Text("ETW providers: WMI-Activity and Windows Defender; verbose level, all keywords, no kernel trace.");
        ConsoleUi.Text("ETL is saved under LocalAppData\\WinTraceForge\\Traces\\<run-id>; it may contain unrelated activity.");
        ConsoleUi.Text("ETW setup failure aborts before the operation (exit 4); no fallback. Later telemetry failures are separate.");
        ConsoleUi.Text("ETW caps: 32 MB file, 120s capture, 10,000 decoded provider events. Loss/partial decoding is reported.");
        ConsoleUi.Text("Telemetry failures do not change the operation exit code. No SIEM/EDR alerts are queried.");
        ConsoleUi.Text("Compliance and detection/response are not automatically assessed.");
        ConsoleUi.Text("NO_COLOR is supported. Redirect stdout and stderr together to preserve warnings.");
        ConsoleUi.Text("See docs\\user\\README.md for evidence limits and restoration guidance.");
    }

    internal sealed class RunEvidence : ControlRunEvidence
    {
        internal bool AddAttempted;
        internal bool AddReturned;
        // Remove sends one request per value; these count requests sent and requests that returned.
        internal int RemoveInvoked;
        internal int RemoveReturned;
        internal bool RemoveAttempted { get { return RemoveInvoked > 0; } }
        // null when some requested type's list could not be read, so presence is unknown.
        internal bool? AllPresentBefore;
        // check/list: at least one examined type could not be read (never reported as empty/absent).
        internal bool ListUnreadable;
        internal readonly List<RemoveItem> RemoveItems = new List<RemoveItem>();
        internal ControlLifecycleResult<DefenderBaseline> Lifecycle;
    }

    internal enum RemoveState { Pending, AlreadyAbsent, Removed, NotConfirmed, Error }

    // One requested value of a remove command. Stored holds the spelling(s) Defender actually
    // reported, which is what the Remove request sends, so a case or trailing-backslash difference
    // between the request and the stored entry cannot make the request silently match nothing.
    internal sealed class RemoveItem
    {
        internal readonly string Type;
        internal readonly string Requested;
        internal readonly List<string> Stored = new List<string>();
        internal RemoveState State = RemoveState.Pending;
        internal string Detail;
        internal bool Invoked;
        internal RemoveItem(string type, string requested) { Type = type; Requested = requested; }
        internal string Label
        {
            get
            {
                switch (State)
                {
                    case RemoveState.AlreadyAbsent: return "ALREADY_ABSENT";
                    case RemoveState.Removed: return "REMOVED_CONFIRMED";
                    case RemoveState.NotConfirmed: return "NOT_CONFIRMED";
                    case RemoveState.Error: return "ERROR";
                    default: return "PENDING";
                }
            }
        }
    }

    // A readback with the unreadable-list case separated out: a type in Unreadable has no usable
    // values (Defender returned its "N/A:" placeholder), so callers must report "unknown" for it,
    // never "empty" or "value absent". The placeholder text itself is dropped from Values.
    internal sealed class ExclusionSnapshot
    {
        internal readonly Dictionary<string, List<string>> Values =
            new Dictionary<string, List<string>>(StringComparer.OrdinalIgnoreCase);
        internal readonly HashSet<string> Unreadable = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        internal static ExclusionSnapshot From(Dictionary<string, List<string>> raw)
        {
            var snapshot = new ExclusionSnapshot();
            foreach (var entry in raw)
            {
                if (entry.Value.Exists(delegate(string value)
                    { return value != null && value.StartsWith(UnreadableMarkerPrefix, StringComparison.OrdinalIgnoreCase); }))
                {
                    snapshot.Unreadable.Add(entry.Key);
                    snapshot.Values[entry.Key] = new List<string>();
                }
                else
                {
                    snapshot.Values[entry.Key] = entry.Value;
                }
            }
            return snapshot;
        }
    }

    private static int Run(Options options, RunEvidence evidence)
    {
        return Execute(options, evidence,
            delegate { return CreateBackend(options.Transport); }, IsAdministrator);
    }

    private static bool IsAdministrator()
    {
        using (WindowsIdentity identity = WindowsIdentity.GetCurrent())
        {
            return new WindowsPrincipal(identity).IsInRole(WindowsBuiltInRole.Administrator);
        }
    }

    // The run header, the elevation gate and the lifecycle, with the backend factory and the
    // elevation test injected (the same shape as FirewallModule.Execute) so tests can prove the gate
    // refuses a write before any backend is created. Header first, gate second, backend last.
    internal static int Execute(Options options, RunEvidence evidence,
        Func<IPreferenceBackend> createBackend, Func<bool> isAdministrator)
    {
        evidence.Stage = "Identity";
        ConsoleUi.Section("Run");
        ConsoleUi.Row("Control", "Defender Antivirus / Exclusions");
        ConsoleUi.Row("Run ID", evidence.RunId);
        ConsoleUi.Row("Start UTC", evidence.StartUtc.ToString("yyyy-MM-dd HH:mm:ss.fff'Z'", CultureInfo.InvariantCulture));
        using (Process process = Process.GetCurrentProcess())
        {
            evidence.ProcessId = process.Id;
            ConsoleUi.Row("Host / PID", Environment.MachineName + " / " + process.Id);
        }
        ConsoleUi.Detail("Executable: " + Assembly.GetExecutingAssembly().Location);
        ConsoleUi.Row("Transport", options.Transport);
        ConsoleUi.Detail("Route: " + DescribeRoute(options.Transport, options.Mode));
        ConsoleUi.Row("Mode", options.Mode == ExclusionMode.Check ? "CHECK ONLY - no changes" :
            options.Mode == ExclusionMode.List ? "LIST - read-only, no changes" :
            options.Mode == ExclusionMode.Remove ? "REMOVE exclusions" : "ADD exclusions");

        using (WindowsIdentity identity = WindowsIdentity.GetCurrent())
        {
            ConsoleUi.Row("Identity", identity.Name);
        }
        bool elevated = isAdministrator();
        ConsoleUi.Row("Administrator", elevated ? "Yes" : "No");
        ConsoleUi.Detail("Elevated administrator: " + elevated);
        if (options.Exclusions.Count > 0) { ConsoleUi.Section("Requested exclusions"); }
        foreach (var exclusion in options.Exclusions)
        {
            foreach (string value in exclusion.Value)
            {
                ConsoleUi.Row(exclusion.Key, value);
            }
        }

        if (!options.ReadOnly && !elevated)
        {
            return ReportError("Open a terminal with Run as administrator, then run this EXE again.");
        }

        evidence.Stage = "Connect";
        using (IPreferenceBackend backend = createBackend())
        {
            return RunWithBackend(options, evidence, backend);
        }
    }

    private static string DescribeRoute(string transport, ExclusionMode mode)
    {
        string method = mode == ExclusionMode.Add ? "MSFT_MpPreference.Add" :
            mode == ExclusionMode.Remove ? "MSFT_MpPreference.Remove (after a baseline read)" :
            "MSFT_MpPreference query (read-only)";
        string cmdlet = mode == ExclusionMode.Add ? "Add-MpPreference" :
            mode == ExclusionMode.Remove ? "Remove-MpPreference" : "Get-MpPreference";
        switch (transport)
        {
            case "native": return "P/Invoke -> native C++ IWbemLocator/IWbemServices::ExecMethod -> WMI -> " + method;
            case "com": return ".NET COM interop -> SWbemLocator/SWbemServices -> WMI -> " + method;
            case "powershell": return "Process -> powershell.exe -> " + cmdlet + "/Get-MpPreference (Defender PowerShell module) -> " + method;
            default: return "System.Management -> WMI -> " + method;
        }
    }

    internal static IPreferenceBackend CreateBackend(string transport)
    {
        switch (transport)
        {
            case "management": return new ManagementBackend();
            case "native": return new NativeBackend();
            case "com": return new ComBackend();
            case "powershell": return new PowerShellBackend();
            default: throw new InvalidOperationException("Unknown Defender transport; no fallback.");
        }
    }

    internal static int RunWithBackend(Options options, RunEvidence evidence, IPreferenceBackend backend)
    {
        ControlLifecycleResult<DefenderBaseline> result = ControlLifecycle.Run(
            new DefenderOperation(options, evidence), new PreferenceReader(backend), new PreferenceWriter(backend),
            delegate(IControlLifecycleSnapshot current) { return evidence.ObserveNow(); });
        evidence.Lifecycle = result;
        foreach (string error in result.Errors) { ConsoleUi.Status("FAIL", error, true); }
        if (result.Restoration == RestorationStatus.ManualRequired)
        { ConsoleUi.Row("Restoration", "MANUAL_REQUIRED - " + result.ManualRestoration); }
        return result.ExitCode;
    }

    internal sealed class DefenderBaseline
    {
        internal readonly ExclusionSnapshot Snapshot;
        internal DefenderBaseline(ExclusionSnapshot snapshot) { Snapshot = snapshot; }
    }

    private sealed class DefenderOperation : IControlOperation<DefenderBaseline, IPreferenceReader, IPreferenceWriter>
    {
        private readonly Options options;
        private readonly RunEvidence evidence;
        internal DefenderOperation(Options options, RunEvidence evidence)
        { this.options = options; this.evidence = evidence; }
        public string Transport { get { return options.Transport; } }
        // A partly failed remove must still be read back so every value gets its own result.
        public bool VerifyAfterApiFailure { get { return options.Mode == ExclusionMode.Remove; } }
        public string ManualRestoration
        {
            get
            {
                return options.Mode == ExclusionMode.Remove ? DescribeRemoveRestoration(options, evidence) :
                    "Remove only test-created exclusions; preserve the captured baseline.";
            }
        }

        public ProbeResult<DefenderBaseline> Probe(IPreferenceReader backend)
        {
            evidence.Stage = "Connect";
            backend.Connect();
            evidence.Stage = "Prepare";
            switch (options.Mode)
            {
                case ExclusionMode.List: return ProbeList(backend);
                case ExclusionMode.Remove: return ProbeRemove(backend);
                default: return ProbeAddOrCheck(backend);
            }
        }

        private ProbeResult<DefenderBaseline> ProbeAddOrCheck(IPreferenceReader backend)
        {
            bool check = options.Mode == ExclusionMode.Check;
            backend.Prepare(options.Exclusions);
            if (check && options.Exclusions.Count == 0) { ConsoleUi.Section("Capabilities"); }
            foreach (string type in ExclusionTypes)
            {
                if (check && (options.Exclusions.Count == 0 || options.Exclusions.ContainsKey(type)) &&
                    (options.Exclusions.Count == 0 || options.Verbose))
                { ConsoleUi.Text(type + ": " + (backend.Supports(type) ? "supported (string[])" : "unsupported")); }
            }
            ExclusionSnapshot baseline = null;
            if (options.Exclusions.Count > 0)
            {
                evidence.Stage = "Baseline read";
                baseline = ExclusionSnapshot.From(backend.Read(options.Exclusions.Keys));
                bool allPresent = true;
                bool unknown = false;
                ConsoleUi.Section("Baseline");
                foreach (var exclusion in options.Exclusions)
                {
                    foreach (string value in exclusion.Value)
                    {
                        if (baseline.Unreadable.Contains(exclusion.Key))
                        {
                            ConsoleUi.Status("WARN", exclusion.Key + ": " + value + " [unknown - list unreadable]");
                            unknown = true;
                            continue;
                        }
                        bool present = ContainsExclusion(baseline.Values, exclusion.Key, value);
                        ConsoleUi.Status(present ? "SEEN" : "INFO", exclusion.Key + ": " + value +
                            (present ? " [present]" : " [not observed]"));
                        allPresent &= present;
                    }
                }
                if (unknown)
                {
                    ConsoleUi.Text(UnreadableExplanation);
                }
                evidence.ListUnreadable = unknown;
                evidence.AllPresentBefore = unknown ? (bool?)null : allPresent;
            }
            if (check)
            {
                evidence.Stage = "Check complete";
                if (evidence.ListUnreadable)
                {
                    ConsoleUi.Status("WARN", "Check incomplete: an unreadable list says nothing about whether a value is present. No settings were changed.");
                    return new ProbeResult<DefenderBaseline>(new DefenderBaseline(baseline),
                        ProbeStatus.ReadOnlyMismatch, RestorationPolicy.None);
                }
                ConsoleUi.Status("OK", "Read-only check passed. No settings were changed.");
                return new ProbeResult<DefenderBaseline>(new DefenderBaseline(baseline),
                    ProbeStatus.ReadOnlyConfirmed, RestorationPolicy.None);
            }
            return new ProbeResult<DefenderBaseline>(new DefenderBaseline(baseline),
                ProbeStatus.Ready, RestorationPolicy.Manual);
        }

        private ProbeResult<DefenderBaseline> ProbeList(IPreferenceReader backend)
        {
            // Read surface only: list never depends on Add's metadata, so a provider whose Add interface
            // is unavailable can still be listed.
            backend.PrepareRead();
            // The read surface decides what can be listed: a type that Add's metadata omits but the
            // preference object still returns is a real, readable list.
            var supported = new List<string>();
            foreach (string type in ExclusionTypes)
            {
                if (backend.SupportsRead(type)) { supported.Add(type); }
            }
            ExclusionSnapshot snapshot = new ExclusionSnapshot();
            if (supported.Count > 0)
            {
                evidence.Stage = "List read";
                snapshot = ExclusionSnapshot.From(backend.Read(supported));
            }
            bool unreadable = false;
            ConsoleUi.Section("Exclusions");
            foreach (string type in ExclusionTypes)
            {
                if (!supported.Contains(type))
                {
                    ConsoleUi.Row(type, "UNSUPPORTED - not a readable field of the preference object");
                }
                else if (snapshot.Unreadable.Contains(type))
                {
                    ConsoleUi.Row(type, "UNREADABLE - contents withheld from this identity; not an empty list");
                    unreadable = true;
                }
                else
                {
                    List<string> values = snapshot.Values[type].FindAll(delegate(string value) { return value != null; });
                    values.Sort(StringComparer.OrdinalIgnoreCase);
                    if (values.Count == 0)
                    {
                        ConsoleUi.Row(type, "EMPTY - readable, no entries");
                        continue;
                    }
                    ConsoleUi.Row(type, values.Count + (values.Count == 1 ? " entry" : " entries"));
                    foreach (string value in values) { ConsoleUi.Text("    " + TelemetryEvidence.Safe(value)); }
                }
            }
            evidence.ListUnreadable = unreadable;
            evidence.Stage = "List complete";
            if (supported.Count == 0)
            {
                // Nothing was read at all, so nothing can be called a complete list.
                ConsoleUi.Status("WARN", "List incomplete: no exclusion type is readable on this provider, so nothing was listed. No settings were changed.");
                return new ProbeResult<DefenderBaseline>(new DefenderBaseline(snapshot),
                    ProbeStatus.ReadOnlyMismatch, RestorationPolicy.None);
            }
            if (unreadable)
            {
                ConsoleUi.Text(UnreadableExplanation);
                ConsoleUi.Status("WARN", "List incomplete: at least one type could not be read. No settings were changed.");
                return new ProbeResult<DefenderBaseline>(new DefenderBaseline(snapshot),
                    ProbeStatus.ReadOnlyMismatch, RestorationPolicy.None);
            }
            ConsoleUi.Status("OK", "Read-only list complete. No settings were changed.");
            return new ProbeResult<DefenderBaseline>(new DefenderBaseline(snapshot),
                ProbeStatus.ReadOnlyConfirmed, RestorationPolicy.None);
        }

        private ProbeResult<DefenderBaseline> ProbeRemove(IPreferenceReader backend)
        {
            // Read and Remove surfaces only; Add's metadata is neither needed nor consulted.
            backend.PrepareRead();
            foreach (string type in options.Exclusions.Keys)
            {
                string reason = null;
                bool supported = false;
                try { supported = backend.SupportsRead(type) && backend.SupportsRemove(type); }
                catch (ManagementException ex) { reason = ex.Message; }
                catch (COMException ex) { reason = ex.Message; }
                if (!supported)
                {
                    // A provider without a Remove method fails the metadata lookup instead of saying
                    // "false"; every transport reports it through this one refusal.
                    throw new InvalidOperationException("Unsupported exclusion type for remove: " + type +
                        (reason == null ? "" : " (" + reason + ")") + ". Nothing was removed.");
                }
            }
            evidence.Stage = "Baseline read";
            ExclusionSnapshot baseline = ExclusionSnapshot.From(backend.Read(options.Exclusions.Keys));
            if (baseline.Unreadable.Count != 0)
            {
                evidence.ListUnreadable = true;
                var names = new List<string>(baseline.Unreadable);
                names.Sort(StringComparer.OrdinalIgnoreCase);
                throw new InvalidOperationException("Refusing to remove: the " + string.Join(", ", names.ToArray()) +
                    " list cannot be read by this identity, so presence cannot be established. " +
                    "Re-run elevated. Nothing was changed.");
            }

            var scheduled = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            ConsoleUi.Section("Baseline");
            foreach (var exclusion in options.Exclusions)
            {
                foreach (string value in exclusion.Value)
                {
                    // Two spellings of one value (e.g. a trailing backslash) are one request.
                    if (!scheduled.Add(exclusion.Key + "|" + NormalizeValue(exclusion.Key, value))) { continue; }
                    var item = new RemoveItem(exclusion.Key, value);
                    foreach (string stored in baseline.Values[exclusion.Key])
                    {
                        if (EquivalentValues(exclusion.Key, stored, value) && !item.Stored.Contains(stored))
                        {
                            item.Stored.Add(stored);
                        }
                    }
                    bool present = item.Stored.Count != 0;
                    if (!present) { item.State = RemoveState.AlreadyAbsent; item.Detail = "not present in the baseline; no Remove was sent"; }
                    ConsoleUi.Status(present ? "SEEN" : "INFO", exclusion.Key + ": " + TelemetryEvidence.Safe(value) +
                        (present ? " [present]" : " [already absent]"));
                    evidence.RemoveItems.Add(item);
                }
            }
            if (!evidence.RemoveItems.Exists(delegate(RemoveItem item) { return item.State == RemoveState.Pending; }))
            {
                evidence.Stage = "Remove not needed";
                PrintRemoveResults(evidence);
                ConsoleUi.Status("OK", "Every requested value is already absent. No Remove was invoked; no settings were changed.");
                return new ProbeResult<DefenderBaseline>(new DefenderBaseline(baseline),
                    ProbeStatus.ReadOnlyConfirmed, RestorationPolicy.None);
            }
            return new ProbeResult<DefenderBaseline>(new DefenderBaseline(baseline),
                ProbeStatus.Ready, RestorationPolicy.Manual);
        }

        public MutationStatus Mutate(DefenderBaseline baseline, IPreferenceWriter backend)
        {
            if (options.Mode == ExclusionMode.Remove) { return MutateRemove(backend); }
            evidence.Stage = "Add invocation";
            ConsoleUi.Section("Apply & verify");
            evidence.AddAttempted = true;
            object returnValue = backend.Add();
            evidence.AddReturned = true;
            evidence.Stage = "Return status";
            uint status;
            if (!TryGetStatusCode(returnValue, out status))
            {
                ConsoleUi.Status("WARN", "No usable WMI return code; verifying configuration by readback.");
                return MutationStatus.ApiUnknown;
            }
            if (status != 0)
            {
                ConsoleUi.Status("FAIL", "Defender rejected the request. WMI return code: " + status +
                    " (0x" + status.ToString("X8") + ").", true);
                return MutationStatus.ApiFailed;
            }
            return MutationStatus.ApiSucceeded;
        }

        // One request per value, so a rejection or error is attributed to exactly that value and the
        // rest of the batch still runs. There is no rollback: a value already removed stays removed.
        private MutationStatus MutateRemove(IPreferenceWriter backend)
        {
            evidence.Stage = "Remove invocation";
            ConsoleUi.Section("Apply & verify");
            bool anyFailed = false;
            bool anyUnknown = false;
            foreach (RemoveItem item in evidence.RemoveItems)
            {
                if (item.State != RemoveState.Pending) { continue; }
                item.Invoked = true;
                evidence.RemoveInvoked++;
                try
                {
                    object returnValue = backend.Remove(item.Type, item.Stored);
                    evidence.RemoveReturned++;
                    uint status;
                    if (!TryGetStatusCode(returnValue, out status))
                    {
                        anyUnknown = true;
                        item.State = RemoveState.NotConfirmed;
                        item.Detail = "request returned no usable WMI return code; awaiting readback";
                    }
                    else if (status != 0)
                    {
                        anyFailed = true;
                        item.State = RemoveState.Error;
                        item.Detail = "Defender rejected the request. WMI return code: " + status +
                            " (0x" + status.ToString("X8") + ")";
                    }
                    else
                    {
                        item.State = RemoveState.NotConfirmed;
                        item.Detail = "request accepted; awaiting readback";
                    }
                }
                catch (Exception error)
                {
                    anyFailed = true;
                    item.State = RemoveState.Error;
                    item.Detail = error.Message;
                }
            }
            evidence.Stage = "Return status";
            if (anyUnknown)
            {
                ConsoleUi.Status("WARN", "No usable WMI return code for at least one request; verifying by readback.");
            }
            return anyFailed ? MutationStatus.ApiFailed :
                anyUnknown ? MutationStatus.ApiUnknown : MutationStatus.ApiSucceeded;
        }

        public VerificationStatus Verify(DefenderBaseline baseline, IPreferenceReader backend)
        {
            if (options.Mode == ExclusionMode.Remove) { return VerifyRemove(backend); }
            evidence.Stage = "Post-Add readback";
            ExclusionSnapshot after = ExclusionSnapshot.From(backend.Read(options.Exclusions.Keys));
            return VerifyExclusions(options.Exclusions, after.Values, after.Unreadable) ?
                VerificationStatus.Confirmed : VerificationStatus.Mismatch;
        }

        private VerificationStatus VerifyRemove(IPreferenceReader backend)
        {
            evidence.Stage = "Post-Remove readback";
            var types = new List<string>();
            foreach (RemoveItem item in evidence.RemoveItems)
            {
                if (item.Invoked && !types.Contains(item.Type)) { types.Add(item.Type); }
            }
            if (types.Count == 0)
            {
                // Nothing was sent, so there is nothing to read back or confirm.
                PrintRemoveResults(evidence);
                return VerificationStatus.Mismatch;
            }
            ExclusionSnapshot after;
            try { after = ExclusionSnapshot.From(backend.Read(types)); }
            catch
            {
                // Nothing can be confirmed; every invoked value keeps its unconfirmed/error state.
                foreach (RemoveItem item in evidence.RemoveItems)
                {
                    if (item.Invoked) { item.Detail += "; post-removal readback failed"; }
                }
                PrintRemoveResults(evidence);
                throw;
            }
            bool allConfirmed = true;
            foreach (RemoveItem item in evidence.RemoveItems)
            {
                if (!item.Invoked) { continue; }
                if (after.Unreadable.Contains(item.Type))
                {
                    if (item.State != RemoveState.Error) { item.State = RemoveState.NotConfirmed; }
                    item.Detail += "; the list is unreadable after the request, so removal cannot be confirmed";
                    allConfirmed = false;
                    continue;
                }
                bool still = ContainsExclusion(after.Values, item.Type, item.Requested);
                if (item.State == RemoveState.Error)
                {
                    item.Detail += still ? "; value still present in readback" :
                        "; value is no longer observed in readback, but this request failed, so the change is not attributed to it";
                    allConfirmed = false;
                }
                else if (still)
                {
                    item.State = RemoveState.NotConfirmed;
                    item.Detail = "value still present in readback after the request returned";
                    allConfirmed = false;
                }
                else
                {
                    item.State = RemoveState.Removed;
                    item.Detail = "value no longer observed in readback";
                }
            }
            PrintRemoveResults(evidence);
            return allConfirmed ? VerificationStatus.Confirmed : VerificationStatus.Mismatch;
        }

        public void Restore(DefenderBaseline baseline, IPreferenceWriter backend) { throw new NotSupportedException("Manual restoration selected."); }
        public VerificationStatus VerifyRestored(DefenderBaseline baseline, IPreferenceReader backend)
        { throw new NotSupportedException("Manual restoration selected."); }
    }

    private const string UnreadableExplanation =
        "UNREADABLE: Defender withheld the list contents from this identity (typically a non-administrator, " +
        "or a policy that hides exclusions). That is not an empty list and not proof a value is absent. " +
        "Re-run elevated to observe it.";

    // Prints one line per requested value, so a batch that partly succeeded states each outcome.
    internal static void PrintRemoveResults(RunEvidence evidence)
    {
        ConsoleUi.Section("Remove results");
        foreach (RemoveItem item in evidence.RemoveItems)
        {
            string tag = item.State == RemoveState.Removed ? "OK" :
                item.State == RemoveState.AlreadyAbsent ? "INFO" :
                item.State == RemoveState.Error ? "FAIL" : "WARN";
            string stored = item.Stored.Count != 0 && !item.Stored.Contains(item.Requested) ?
                " (stored as " + TelemetryEvidence.Safe(string.Join(" / ", item.Stored.ToArray())) + ")" : "";
            ConsoleUi.Status(tag, item.Label + "  " + item.Type + ": " + TelemetryEvidence.Safe(item.Requested) +
                stored + (string.IsNullOrEmpty(item.Detail) ? "" : " - " + item.Detail),
                item.State == RemoveState.Error || item.State == RemoveState.NotConfirmed);
        }
    }

    // WTF never marks exclusions, so this only restates the request: it lists the values a Remove
    // request was sent for (whatever their final state), not values WTF created or owned.
    private static string DescribeRemoveRestoration(Options options, RunEvidence evidence)
    {
        var command = new StringBuilder();
        foreach (string type in ExclusionTypes)
        {
            bool first = true;
            foreach (RemoveItem item in evidence.RemoveItems)
            {
                if (!item.Invoked || item.Type != type) { continue; }
                foreach (string value in item.Stored)
                {
                    command.Append(first ? " -" + type : "").Append(" \"").Append(TelemetryEvidence.Safe(value)).Append('"');
                    first = false;
                }
            }
        }
        return "No automatic rollback. These values were not created by WTF; if a removal was unintended, " +
            "re-add it: wtf.exe defender exclusion add --transport " + options.Transport + command;
    }

    internal interface IPreferenceBackend : IDisposable
    {
        void Connect();
        // Read/Remove surface only: loads the preference class metadata. Never touches Add's.
        void PrepareRead();
        void Prepare(Dictionary<string, List<string>> exclusions);
        bool Supports(string name);
        // Read-surface only: is the type a readable string-array field of the preference class?
        bool SupportsRead(string name);
        bool SupportsRemove(string name);
        object Add();
        // One Remove request for the given values of a single exclusion type.
        object Remove(string type, IList<string> values);
        Dictionary<string, List<string>> Read(ICollection<string> types);
    }

    internal interface IPreferenceReader
    {
        void Connect();
        void PrepareRead();
        void Prepare(Dictionary<string, List<string>> exclusions);
        bool Supports(string name);
        bool SupportsRead(string name);
        bool SupportsRemove(string name);
        Dictionary<string, List<string>> Read(ICollection<string> types);
    }

    internal interface IPreferenceWriter
    {
        object Add();
        object Remove(string type, IList<string> values);
    }

    private sealed class PreferenceReader : IPreferenceReader
    {
        private readonly IPreferenceBackend inner;
        internal PreferenceReader(IPreferenceBackend inner) { this.inner = inner; }
        public void Connect() { inner.Connect(); }
        public void PrepareRead() { inner.PrepareRead(); }
        public void Prepare(Dictionary<string, List<string>> exclusions) { inner.Prepare(exclusions); }
        public bool Supports(string name) { return inner.Supports(name); }
        public bool SupportsRead(string name) { return inner.SupportsRead(name); }
        public bool SupportsRemove(string name) { return inner.SupportsRemove(name); }
        public Dictionary<string, List<string>> Read(ICollection<string> types) { return inner.Read(types); }
    }

    private sealed class PreferenceWriter : IPreferenceWriter
    {
        private readonly IPreferenceBackend inner;
        internal PreferenceWriter(IPreferenceBackend inner) { this.inner = inner; }
        public object Add() { return inner.Add(); }
        public object Remove(string type, IList<string> values) { return inner.Remove(type, values); }
    }

    private sealed class NativeBackend : IPreferenceBackend
    {
        private IntPtr handle;

        public void Connect()
        {
            CheckNative(NativeMethods.NativeOpen(out handle), "IWbemLocator::ConnectServer / proxy security");
        }

        public void PrepareRead()
        {
            CheckNative(NativeMethods.NativePrepareRead(handle), "GetObject");
        }

        public void Prepare(Dictionary<string, List<string>> exclusions)
        {
            CheckNative(NativeMethods.NativePrepare(handle), "GetObject / GetMethod / SpawnInstance");
            foreach (var exclusion in exclusions)
            {
                if (!Supports(exclusion.Key))
                {
                    throw new InvalidOperationException("Unsupported exclusion type: " + exclusion.Key);
                }
                string[] values = exclusion.Value.ToArray();
                CheckNative(NativeMethods.NativeSetValues(handle, exclusion.Key, values, values.Length),
                    "IWbemClassObject::Put(" + exclusion.Key + ")");
            }
        }

        public bool Supports(string name)
        {
            bool supported;
            CheckNative(NativeMethods.NativeSupports(handle, name, out supported), "Get parameter metadata: " + name);
            return supported;
        }

        public bool SupportsRead(string name)
        {
            bool supported;
            CheckNative(NativeMethods.NativeSupportsRead(handle, name, out supported), "Get class property metadata: " + name);
            return supported;
        }

        public bool SupportsRemove(string name)
        {
            bool supported;
            CheckNative(NativeMethods.NativeSupportsRemove(handle, name, out supported),
                "Get Remove parameter metadata: " + name);
            return supported;
        }

        public object Add()
        {
            object returnValue;
            CheckNative(NativeMethods.NativeAdd(handle, out returnValue), "IWbemServices::ExecMethod(Add)");
            return returnValue;
        }

        public object Remove(string type, IList<string> values)
        {
            string[] array = new string[values.Count];
            values.CopyTo(array, 0);
            object returnValue;
            CheckNative(NativeMethods.NativeRemove(handle, type, array, array.Length, out returnValue),
                "IWbemServices::ExecMethod(Remove, " + type + ")");
            return returnValue;
        }

        public Dictionary<string, List<string>> Read(ICollection<string> types)
        {
            var configured = new Dictionary<string, List<string>>(StringComparer.OrdinalIgnoreCase);
            foreach (string type in types)
            {
                object raw;
                CheckNative(NativeMethods.NativeRead(handle, type, out raw), "ExecQuery / Get: " + type);
                configured.Add(type, DecodeStringArray(raw, type));
            }
            return configured;
        }

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
        internal static extern int NativePrepareRead(IntPtr handle);

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
        internal static extern int NativeSupportsRead(IntPtr handle, string name, [MarshalAs(UnmanagedType.Bool)] out bool supported);

        [DllImport(Library, CallingConvention = CallingConvention.Cdecl, ExactSpelling = true, CharSet = CharSet.Unicode)]
        [DefaultDllImportSearchPaths(DllImportSearchPath.AssemblyDirectory | DllImportSearchPath.System32)]
        internal static extern int NativeSupportsRemove(IntPtr handle, string name, [MarshalAs(UnmanagedType.Bool)] out bool supported);

        [DllImport(Library, CallingConvention = CallingConvention.Cdecl, ExactSpelling = true)]
        [DefaultDllImportSearchPaths(DllImportSearchPath.AssemblyDirectory | DllImportSearchPath.System32)]
        internal static extern int NativeAdd(IntPtr handle, [MarshalAs(UnmanagedType.Struct)] out object returnValue);

        [DllImport(Library, CallingConvention = CallingConvention.Cdecl, ExactSpelling = true, CharSet = CharSet.Unicode)]
        [DefaultDllImportSearchPaths(DllImportSearchPath.AssemblyDirectory | DllImportSearchPath.System32)]
        internal static extern int NativeRemove(IntPtr handle, string name,
            [In, MarshalAs(UnmanagedType.LPArray, ArraySubType = UnmanagedType.LPWStr, SizeParamIndex = 3)] string[] values, int count,
            [MarshalAs(UnmanagedType.Struct)] out object returnValue);

        [DllImport(Library, CallingConvention = CallingConvention.Cdecl, ExactSpelling = true, CharSet = CharSet.Unicode)]
        [DefaultDllImportSearchPaths(DllImportSearchPath.AssemblyDirectory | DllImportSearchPath.System32)]
        internal static extern int NativeRead(IntPtr handle, string name, [MarshalAs(UnmanagedType.Struct)] out object values);

        [DllImport(Library, CallingConvention = CallingConvention.Cdecl, ExactSpelling = true)]
        [DefaultDllImportSearchPaths(DllImportSearchPath.AssemblyDirectory | DllImportSearchPath.System32)]
        internal static extern void NativeClose(IntPtr handle);
    }

    private static List<string> DecodeStringArray(object raw, string name)
    {
        var decoded = new List<string>();
        if (raw == null || raw == DBNull.Value) { return decoded; }
        Array values = raw as Array;
        if (values == null || values.Rank != 1)
        {
            throw new InvalidOperationException("Unexpected readback type for " + name + ".");
        }
        foreach (object value in values)
        {
            if (value != null && !(value is string))
            {
                throw new InvalidOperationException("Unexpected array element for " + name + ".");
            }
            decoded.Add((string)value);
        }
        return decoded;
    }

    // Management and COM supply raw provider records and nothing else; this one non-virtual Read turns
    // them into lists through AssembleExclusions, so neither transport can bypass the singleton gate.
    private abstract class RecordReadBackend
    {
        public Dictionary<string, List<string>> Read(ICollection<string> types)
        {
            return AssembleExclusions(ReadRecords(types), types);
        }

        protected abstract IList<Dictionary<string, object>> ReadRecords(ICollection<string> types);
    }

    private sealed class ComBackend : RecordReadBackend, IPreferenceBackend
    {
        private readonly ComObjects objects = new ComObjects();
        private object services;
        private object preferenceClass;
        private object input;
        private Dictionary<string, object> inputProperties;
        private Dictionary<string, object> classProperties;
        private Dictionary<string, object> removeProperties;
        private object removeDefinition;

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

        public void PrepareRead()
        {
            preferenceClass = objects.Call(services, "Get", "MSFT_MpPreference", 0, new DispatchWrapper(null));
            classProperties = objects.Properties(preferenceClass);
        }

        public void Prepare(Dictionary<string, List<string>> exclusions)
        {
            PrepareRead();
            object methods = objects.Get(preferenceClass, "Methods_");
            object add = objects.Call(methods, "Item", "Add", 0);
            object definition = objects.Get(add, "InParameters");
            if (definition == null)
            {
                throw new InvalidOperationException("Defender COM Add parameter metadata is unavailable.");
            }
            input = objects.Call(definition, "SpawnInstance_", 0);
            inputProperties = objects.Properties(input);
            foreach (var exclusion in exclusions)
            {
                if (!Supports(exclusion.Key))
                {
                    throw new InvalidOperationException("Unsupported exclusion type: " + exclusion.Key);
                }
                objects.Set(inputProperties[exclusion.Key], "Value", exclusion.Value.ToArray());
            }
        }

        public bool Supports(string name)
        {
            return IsStringArray(inputProperties, name) && IsStringArray(classProperties, name);
        }

        private bool IsStringArray(Dictionary<string, object> properties, string name)
        {
            object property;
            return properties.TryGetValue(name, out property) &&
                Convert.ToInt32(objects.Get(property, "CIMType"), CultureInfo.InvariantCulture) == 8 &&
                Convert.ToBoolean(objects.Get(property, "IsArray"), CultureInfo.InvariantCulture);
        }

        public object Add()
        {
            return Execute("Add", input);
        }

        private object Execute(string method, object parameters)
        {
            object result = objects.Call(services, "ExecMethod", "MSFT_MpPreference", method, parameters, 0, new DispatchWrapper(null));
            if (result == null)
            {
                return null;
            }
            object property;
            return objects.Properties(result).TryGetValue("ReturnValue", out property) ?
                objects.Get(property, "Value") : null;
        }

        private object RemoveDefinition()
        {
            // Cached: every Methods_/Item/InParameters call adds RCWs that live until Dispose.
            if (removeDefinition != null) { return removeDefinition; }
            object methods = objects.Get(preferenceClass, "Methods_");
            object remove = objects.Call(methods, "Item", "Remove", 0);
            object definition = objects.Get(remove, "InParameters");
            if (definition == null)
            {
                throw new InvalidOperationException("Defender COM Remove parameter metadata is unavailable.");
            }
            removeDefinition = definition;
            return definition;
        }

        public bool SupportsRead(string name)
        {
            return IsStringArray(classProperties, name);
        }

        public bool SupportsRemove(string name)
        {
            if (removeProperties == null) { removeProperties = objects.Properties(RemoveDefinition()); }
            return IsStringArray(removeProperties, name);
        }

        public object Remove(string type, IList<string> values)
        {
            object parameters = objects.Call(RemoveDefinition(), "SpawnInstance_", 0);
            Dictionary<string, object> properties = objects.Properties(parameters);
            if (!IsStringArray(properties, type))
            {
                throw new InvalidOperationException("Defender COM Remove does not accept " + type + ".");
            }
            string[] array = new string[values.Count];
            values.CopyTo(array, 0);
            objects.Set(properties[type], "Value", array);
            return Execute("Remove", parameters);
        }

        protected override IList<Dictionary<string, object>> ReadRecords(ICollection<string> types)
        {
            object results = objects.Call(services, "ExecQuery",
                "SELECT " + string.Join(", ", types) + " FROM MSFT_MpPreference", "WQL", 0, new DispatchWrapper(null));
            int count = Convert.ToInt32(objects.Get(results, "Count"), CultureInfo.InvariantCulture);
            var records = new List<Dictionary<string, object>>();
            for (int i = 0; i < count; i++)
            {
                object record = objects.Call(results, "ItemIndex", i);
                Dictionary<string, object> properties = objects.Properties(record);
                var fields = new Dictionary<string, object>(StringComparer.OrdinalIgnoreCase);
                foreach (string type in types)
                {
                    object property;
                    if (!properties.TryGetValue(type, out property))
                    {
                        throw new InvalidOperationException("Missing COM readback field: " + type);
                    }
                    fields[type] = objects.Get(property, "Value");
                }
                records.Add(fields);
            }
            return records;
        }

        public void Dispose() { objects.Dispose(); }
    }

    // Internal (not private): reused by AsrModule's COM backend, which talks to the same
    // root\Microsoft\Windows\Defender namespace and needs the identical IDispatch bookkeeping.
    internal sealed class ComObjects : IDisposable
    {
        private readonly List<object> owned = new List<object>();

        internal object Own(object value)
        {
            if (value != null && Marshal.IsComObject(value) &&
                !owned.Exists(delegate(object existing) { return ReferenceEquals(existing, value); }))
            {
                owned.Add(value);
            }
            return value;
        }

        internal object Get(object target, string name)
        {
            return Invoke(target, name, BindingFlags.GetProperty, new object[0]);
        }

        internal object Call(object target, string name, params object[] arguments)
        {
            return Invoke(target, name, BindingFlags.InvokeMethod, arguments);
        }

        internal void Set(object target, string name, object value)
        {
            Invoke(target, name, BindingFlags.SetProperty, new object[] { value });
        }

        private object Invoke(object target, string name, BindingFlags flags, object[] arguments)
        {
            if (target == null)
            {
                throw new InvalidOperationException("Null COM target for " + name + ".");
            }
            try
            {
                return Own(target.GetType().InvokeMember(name, flags, null, target, arguments,
                    CultureInfo.InvariantCulture));
            }
            catch (TargetInvocationException ex)
            {
                if (ex.InnerException == null) { throw; }
                ExceptionDispatchInfo.Capture(ex.InnerException).Throw();
                throw;
            }
            catch (COMException ex)
            {
                throw new COMException("COM member " + name + ": " + ex.Message, ex.ErrorCode);
            }
        }

        internal Dictionary<string, object> Properties(object instance)
        {
            var properties = new Dictionary<string, object>(StringComparer.OrdinalIgnoreCase);
            object collection = Get(instance, "Properties_");
            IEnumerable enumerable = collection as IEnumerable;
            if (enumerable == null)
            {
                throw new InvalidOperationException("COM property collection is not enumerable.");
            }
            IEnumerator enumerator = enumerable.GetEnumerator();
            try
            {
                while (enumerator.MoveNext())
                {
                    object property = Own(enumerator.Current);
                    string name = Get(property, "Name") as string;
                    if (string.IsNullOrEmpty(name))
                    {
                        throw new InvalidOperationException("COM property has no valid name.");
                    }
                    properties.Add(name, property);
                }
            }
            finally
            {
                if (Marshal.IsComObject(enumerator))
                {
                    Marshal.FinalReleaseComObject(enumerator);
                }
                else
                {
                    IDisposable disposable = enumerator as IDisposable;
                    if (disposable != null) { disposable.Dispose(); }
                }
            }
            return properties;
        }

        public void Dispose()
        {
            // All tracked RCWs are private to this backend and never escape its lifetime.
            for (int i = owned.Count - 1; i >= 0; i--)
            {
                Marshal.FinalReleaseComObject(owned[i]);
            }
            owned.Clear();
        }
    }

    private sealed class ManagementBackend : RecordReadBackend, IPreferenceBackend
    {
        private readonly ManagementScope scope =
            new ManagementScope(@"\\.\root\Microsoft\Windows\Defender");
        private ManagementClass preferenceClass;
        private ManagementBaseObject input;

        public void Connect() { scope.Connect(); }

        public void PrepareRead()
        {
            preferenceClass = new ManagementClass(scope, new ManagementPath("MSFT_MpPreference"), null);
            preferenceClass.Get();
        }

        public void Prepare(Dictionary<string, List<string>> exclusions)
        {
            PrepareRead();
            input = preferenceClass.GetMethodParameters("Add");
            if (input == null)
            {
                throw new InvalidOperationException("Defender WMI Add parameter metadata is unavailable.");
            }
            foreach (var exclusion in exclusions)
            {
                if (!Supports(exclusion.Key))
                {
                    throw new InvalidOperationException("Unsupported exclusion type: " + exclusion.Key);
                }
                input[exclusion.Key] = exclusion.Value.ToArray();
            }
        }

        public bool Supports(string name)
        {
            return HasStringArrayProperty(input.Properties, name) &&
                HasStringArrayProperty(preferenceClass.Properties, name);
        }

        public object Add()
        {
            using (ManagementBaseObject result = preferenceClass.InvokeMethod("Add", input, null))
            {
                return ReturnValueOf(result);
            }
        }

        private static object ReturnValueOf(ManagementBaseObject result)
        {
            if (result != null)
            {
                foreach (PropertyData property in result.Properties)
                {
                    if (string.Equals(property.Name, "ReturnValue", StringComparison.OrdinalIgnoreCase))
                    {
                        return property.Value;
                    }
                }
            }
            return null;
        }

        public bool SupportsRead(string name)
        {
            return HasStringArrayProperty(preferenceClass.Properties, name);
        }

        public bool SupportsRemove(string name)
        {
            using (ManagementBaseObject parameters = preferenceClass.GetMethodParameters("Remove"))
            {
                return parameters != null && HasStringArrayProperty(parameters.Properties, name);
            }
        }

        public object Remove(string type, IList<string> values)
        {
            using (ManagementBaseObject parameters = preferenceClass.GetMethodParameters("Remove"))
            {
                if (parameters == null || !HasStringArrayProperty(parameters.Properties, type))
                {
                    throw new InvalidOperationException("Defender WMI Remove does not accept " + type + ".");
                }
                string[] array = new string[values.Count];
                values.CopyTo(array, 0);
                parameters[type] = array;
                using (ManagementBaseObject result = preferenceClass.InvokeMethod("Remove", parameters, null))
                {
                    return ReturnValueOf(result);
                }
            }
        }

        protected override IList<Dictionary<string, object>> ReadRecords(ICollection<string> types)
        {
            return ReadExclusionRecords(scope, types);
        }

        public void Dispose()
        {
            if (input != null) { input.Dispose(); }
            if (preferenceClass != null) { preferenceClass.Dispose(); }
        }

        private static bool HasStringArrayProperty(PropertyDataCollection properties, string name)
        {
            foreach (PropertyData property in properties)
            {
                if (string.Equals(property.Name, name, StringComparison.OrdinalIgnoreCase))
                {
                    return property.Type == CimType.String && property.IsArray;
                }
            }
            return false;
        }
    }

    // Shells to powershell.exe and drives the ConfigDefender module's own cmdlets
    // (Add-MpPreference/Get-MpPreference) instead of talking to WMI directly like the other three
    // transports. See PowerShellRunner's own remarks for the full set of hardening measures (absolute
    // executable path, restricted module path, -EncodedCommand instead of a temp script file,
    // Base64-encoded values). Add-MpPreference is a void cmdlet with no WMI ReturnValue to report, so
    // a successful Add always yields MutationStatus.ApiUnknown upstream; readback is the only
    // confirmation this transport can ever offer, which is an accurate description of what shelling
    // out to the cmdlet actually observes, not a degraded one.
    private sealed class PowerShellBackend : IPreferenceBackend
    {
        private Dictionary<string, bool> supportsCache;
        private string readError;
        private bool addAvailable;
        private string pendingAddScript;

        public void Connect()
        {
            PowerShellRunner.Result result = PowerShellRunner.RunScript(BuildConnectScript());
            string errorMessage = PowerShellRunner.FindMarkerMessage(result.Stdout, "WTF_CONNECT_ERROR:");
            if (errorMessage != null || !PowerShellRunner.ContainsMarker(result.Stdout, "WTF_CONNECT_OK"))
            {
                throw new NotSupportedException("PowerShell Defender module (Get-MpPreference) is unavailable. " +
                    (errorMessage ?? PowerShellRunner.DescribeFailure(result)));
            }
            ApplyConnectOutput(result.Stdout);
        }

        // Internal for tests. One launch discovers everything the later phases ask about: Add's and
        // Remove's parameter sets, and which exclusion fields the Get-MpPreference object really has
        // (the read surface). Discovering the read surface here keeps `list` at two launches (connect +
        // read) instead of three. A failure of that discovery does not fail connect: it is reported as
        // Read.ERROR and only surfaces if a caller asks for read support.
        internal static string BuildConnectScript()
        {
            var script = new StringBuilder();
            script.Append("$ErrorActionPreference = 'Stop'\r\n");
            script.Append("try {\r\n");
            // Get-MpPreference is the only mandatory cmdlet (every command reads). Add-MpPreference and
            // Remove-MpPreference are discovered, not required: list/remove must work without Add, and
            // add/check without Remove. A missing one is reported as AddCmdlet=False / Remove.*=False.
            script.Append("    Get-Command ConfigDefender\\Get-MpPreference | Out-Null\r\n");
            script.Append("    $cmd = Get-Command ConfigDefender\\Add-MpPreference -ErrorAction SilentlyContinue\r\n");
            script.Append("    Write-Output ('AddCmdlet=' + [bool]$cmd)\r\n");
            script.Append("    foreach ($n in @('ExclusionPath','ExclusionExtension','ExclusionProcess','ExclusionIpAddress')) {\r\n");
            script.Append("        Write-Output ($n + '=' + [bool]($cmd -and $cmd.Parameters.ContainsKey($n)))\r\n");
            script.Append("    }\r\n");
            // Remove-MpPreference is only needed by 'remove'; its absence must not break add/check/list.
            script.Append("    $rm = Get-Command ConfigDefender\\Remove-MpPreference -ErrorAction SilentlyContinue\r\n");
            script.Append("    foreach ($n in @('ExclusionPath','ExclusionExtension','ExclusionProcess','ExclusionIpAddress')) {\r\n");
            script.Append("        Write-Output ('Remove.' + $n + '=' + [bool]($rm -and $rm.Parameters.ContainsKey($n)))\r\n");
            script.Append("    }\r\n");
            script.Append("    try {\r\n");
            script.Append("        $instances = @(ConfigDefender\\Get-MpPreference)\r\n");
            script.Append("        if ($instances.Count -ne 1) { throw ('Expected exactly one instance, got ' + $instances.Count + '.') }\r\n");
            script.Append("        foreach ($n in @('ExclusionPath','ExclusionExtension','ExclusionProcess','ExclusionIpAddress')) {\r\n");
            script.Append("            Write-Output ('Read.' + $n + '=' + [bool]$instances[0].PSObject.Properties[$n])\r\n");
            script.Append("        }\r\n");
            script.Append("    } catch {\r\n");
            script.Append("        Write-Output ('Read.ERROR=' + [Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($_.Exception.Message)))\r\n");
            script.Append("    }\r\n");
            script.Append("    Write-Output 'WTF_CONNECT_OK'\r\n");
            script.Append("} catch {\r\n");
            script.Append(PowerShellRunner.EmitErrorMarkerStatement("WTF_CONNECT_ERROR:"));
            script.Append("    exit 1\r\n");
            script.Append("}\r\n");
            return script.ToString();
        }

        private static readonly string[] CapabilityTypes =
            { "ExclusionPath", "ExclusionExtension", "ExclusionProcess", "ExclusionIpAddress" };

        // Internal for tests: parses the connect script's name=True/False lines. A capability that never
        // arrived is unobserved, not "unsupported", so every row of every group must be present
        // (the Read group may instead be replaced by a Read.ERROR), or connect fails.
        internal void ApplyConnectOutput(string stdout)
        {
            var parsed = new Dictionary<string, bool>(StringComparer.OrdinalIgnoreCase);
            string error = null;
            foreach (string line in PowerShellRunner.SplitLines(stdout))
            {
                int equals = line.IndexOf('=');
                if (equals <= 0) { continue; }
                string key = line.Substring(0, equals);
                if (key == "Read.ERROR")
                {
                    try { error = PowerShellRunner.DecodeValue(line.Substring(equals + 1)); }
                    catch (FormatException) { error = line.Substring(equals + 1); }
                    continue;
                }
                parsed[key] = string.Equals(line.Substring(equals + 1), "True", StringComparison.OrdinalIgnoreCase);
            }
            var missing = new List<string>();
            if (!parsed.ContainsKey("AddCmdlet")) { missing.Add("AddCmdlet"); }
            foreach (string type in CapabilityTypes)
            {
                if (!parsed.ContainsKey(type)) { missing.Add(type); }
                if (!parsed.ContainsKey("Remove." + type)) { missing.Add("Remove." + type); }
                if (error == null && !parsed.ContainsKey("Read." + type)) { missing.Add("Read." + type); }
            }
            if (missing.Count != 0)
            {
                throw new InvalidOperationException("PowerShell connect output is incomplete (missing " +
                    string.Join(", ", missing.ToArray()) + "); capabilities are unobserved, not unsupported.");
            }
            supportsCache = parsed;
            readError = error;
            addAvailable = parsed["AddCmdlet"];
        }

        public void PrepareRead() { }

        public void Prepare(Dictionary<string, List<string>> exclusions)
        {
            // Built (and length-validated) before the Supports() checks below, not after: an
            // oversized request must fail here, during Probe, so the lifecycle reports
            // Mutation=NotAttempted rather than reaching Add() first and being misreported as
            // MutationStatus.ApiFailed (as if Defender itself had rejected a request that
            // powershell.exe never even got a chance to run).
            string script = BuildAddScript(exclusions);
            // Only after the length check, so an oversized request still fails the same way everywhere.
            if (!addAvailable)
            {
                throw new NotSupportedException("ConfigDefender\\Add-MpPreference is unavailable; add cannot run on this transport.");
            }
            foreach (var exclusion in exclusions)
            {
                if (!Supports(exclusion.Key))
                {
                    throw new InvalidOperationException("Unsupported exclusion type: " + exclusion.Key);
                }
            }
            pendingAddScript = script;
        }

        public bool Supports(string name)
        {
            bool supported;
            return supportsCache != null && supportsCache.TryGetValue(name, out supported) && supported;
        }

        // Read surface, as discovered by the connect script from the Get-MpPreference object itself
        // (not Add-MpPreference's parameter set). If that discovery failed, the caller learns why
        // instead of being told the type is unsupported.
        public bool SupportsRead(string name)
        {
            if (readError != null)
            {
                throw new InvalidOperationException("Get-MpPreference (PowerShell) field discovery failed: " + readError);
            }
            bool supported;
            return supportsCache != null && supportsCache.TryGetValue("Read." + name, out supported) && supported;
        }

        public bool SupportsRemove(string name)
        {
            bool supported;
            return supportsCache != null && supportsCache.TryGetValue("Remove." + name, out supported) && supported;
        }

        // Internal for tests: the script for one Remove request (a single type), length-validated.
        internal static string BuildRemoveScript(string type, IList<string> values)
        {
            var script = new StringBuilder();
            script.Append("$ErrorActionPreference = 'Stop'\r\n");
            script.Append("try {\r\n");
            script.Append("    ConfigDefender\\Remove-MpPreference -" + type + " " +
                PowerShellRunner.EncodeValuesExpression(values) + "\r\n");
            script.Append("    Write-Output 'WTF_REMOVE_OK'\r\n");
            script.Append("} catch {\r\n");
            script.Append(PowerShellRunner.EmitErrorMarkerStatement("WTF_REMOVE_ERROR:"));
            script.Append("    exit 1\r\n");
            script.Append("}\r\n");
            string result = script.ToString();
            PowerShellRunner.ValidateScriptLength(result);
            return result;
        }

        public object Remove(string type, IList<string> values)
        {
            if (!SupportsRemove(type))
            {
                throw new NotSupportedException("Remove-MpPreference -" + type + " is unavailable.");
            }
            PowerShellRunner.Result result = PowerShellRunner.RunScript(BuildRemoveScript(type, values));
            string errorMessage;
            PowerShellRunner.AddOutcome outcome = PowerShellRunner.ClassifyResult(
                result, "WTF_REMOVE_OK", "WTF_REMOVE_ERROR:", out errorMessage);
            if (outcome == PowerShellRunner.AddOutcome.Error)
            {
                throw new InvalidOperationException("Remove-MpPreference (PowerShell) failed: " + errorMessage);
            }
            if (outcome == PowerShellRunner.AddOutcome.Unknown)
            {
                // Same reasoning as Add(): no marker is not a known failure; readback decides.
                ConsoleUi.Status("WARN", "powershell.exe ended (exit code " + result.ExitCode +
                    ") without a clear success/failure marker; verifying configuration by readback.");
                ConsoleUi.Detail(PowerShellRunner.DescribeFailure(result));
            }
            // Remove-MpPreference is a void cmdlet: no WMI return code exists to report.
            return null;
        }

        private static string BuildAddScript(Dictionary<string, List<string>> exclusions)
        {
            var script = new StringBuilder();
            script.Append("$ErrorActionPreference = 'Stop'\r\n");
            script.Append("try {\r\n");
            script.Append("    ConfigDefender\\Add-MpPreference");
            foreach (var exclusion in exclusions)
            {
                script.Append(" -" + exclusion.Key + " " + PowerShellRunner.EncodeValuesExpression(exclusion.Value));
            }
            script.Append("\r\n");
            script.Append("    Write-Output 'WTF_ADD_OK'\r\n");
            script.Append("} catch {\r\n");
            script.Append(PowerShellRunner.EmitErrorMarkerStatement("WTF_ADD_ERROR:"));
            script.Append("    exit 1\r\n");
            script.Append("}\r\n");
            string result = script.ToString();
            PowerShellRunner.ValidateScriptLength(result);
            return result;
        }

        public object Add()
        {
            PowerShellRunner.Result result = PowerShellRunner.RunScript(pendingAddScript);
            string errorMessage;
            PowerShellRunner.AddOutcome outcome = PowerShellRunner.ClassifyAddResult(result, out errorMessage);
            if (outcome == PowerShellRunner.AddOutcome.Error)
            {
                throw new InvalidOperationException("Add-MpPreference (PowerShell) failed: " + errorMessage);
            }
            if (outcome == PowerShellRunner.AddOutcome.Unknown)
            {
                // See PowerShellRunner.ClassifyAddResult's remarks: a missing marker (crash, or the
                // process torn down externally after Add-MpPreference may already have run) is
                // genuinely unknown, not a known failure -- collapsing it into MutationStatus.ApiFailed
                // would falsely claim Defender rejected the request, so the caller must fall back to
                // readback instead, exactly as it already does for a WMI call that returns no usable
                // status code. Stderr is surfaced here (not just the exit code) since it is often the
                // only evidence of *why* -- an AMSI/execution-policy block, for example, writes its
                // reason there.
                ConsoleUi.Status("WARN", "powershell.exe ended (exit code " + result.ExitCode +
                    ") without a clear success/failure marker; verifying configuration by readback.");
                ConsoleUi.Detail(PowerShellRunner.DescribeFailure(result));
            }
            // No WMI ReturnValue exists for a PowerShell cmdlet call; the caller (DefenderOperation.Mutate)
            // treats null as MutationStatus.ApiUnknown and falls back to readback either way.
            return null;
        }

        public Dictionary<string, List<string>> Read(ICollection<string> types)
        {
            string marker = Guid.NewGuid().ToString("N");
            PowerShellRunner.Result result = PowerShellRunner.RunScript(
                PowerShellRunner.BuildReadScript("ConfigDefender\\Get-MpPreference", types, marker, null));
            string errorMessage = PowerShellRunner.FindMarkerMessage(result.Stdout, "WTF_READ_ERROR:");
            if (errorMessage != null)
            {
                throw new InvalidOperationException("Get-MpPreference (PowerShell) readback failed: " + errorMessage);
            }
            if (!PowerShellRunner.ContainsMarker(result.Stdout, "WTF_READ_OK"))
            {
                // Unlike Add(), a read has no "maybe it happened anyway" fallback: either the script
                // completed and every field is trustworthy, or it did not, and the caller must never
                // substitute an empty snapshot for "could not read" (the same invariant BuildSnapshot
                // and RequireSingleInstance enforce for every other ASR/Defender transport).
                throw new InvalidOperationException("Get-MpPreference (PowerShell) readback did not complete (exit " +
                    result.ExitCode + "): " + PowerShellRunner.DescribeFailure(result));
            }
            return PowerShellRunner.ParseFields(result.Stdout, marker, types);
        }

        public void Dispose() { }
    }

    // Shared by DefenderModule's and AsrModule's PowerShell transports (same rationale as
    // DefenderModule.ComObjects being reused by AsrModule's COM backend): builds and runs an ad hoc
    // script against the system's own powershell.exe. Hardening measures, each closing a distinct gap
    // a non-elevated process on the same host could otherwise exploit against an elevated Add:
    //   - PowerShellExecutablePath is an absolute path, not a bare "powershell.exe" name (closes a
    //     CreateProcess search-order hijack via a same-directory/cwd-planted executable).
    //   - TrustedModulePath pins PSModulePath to the system module directory for the child process
    //     (closes a same-named "ConfigDefender" module planted earlier on a user-writable
    //     PSModulePath entry being loaded instead of the real one -- module-qualifying a call, e.g.
    //     ConfigDefender\Add-MpPreference, only guards against a same-named function/alias, never
    //     against the module itself being shadowed).
    //   - The script is passed via -EncodedCommand (Base64 UTF-16LE), never written to a temp file
    //     first: there is nothing on disk for a same-user process to race and overwrite before
    //     powershell.exe reads it, and consequently no temp directory to create, clean up, or leak.
    // Every value that could ever contain caller-supplied or non-ASCII content -- exclusion values,
    // error messages, readback results -- is also Base64-encoded, immune to the OEM/ANSI/UTF-8
    // codepage mismatches that would otherwise corrupt non-ASCII text, and (for values embedded
    // directly in script text via EncodeValuesExpression) never needing any quoting/escaping at all,
    // since Base64's alphabet ([A-Za-z0-9+/=]) contains no quote character.
    internal static class PowerShellRunner
    {
        internal static readonly string PowerShellExecutablePath =
            Path.Combine(Environment.SystemDirectory, "WindowsPowerShell", "v1.0", "powershell.exe");

        internal static readonly string TrustedModulePath =
            Path.Combine(Environment.SystemDirectory, "WindowsPowerShell", "v1.0", "Modules");

        // -EncodedCommand's underlying CreateProcess command line is capped at 32,768 UTF-16
        // characters total (a Windows limit, not .NET's); this bounds the *script* side of that
        // budget (before UTF-16 + Base64 expansion) with a wide margin, so an oversized request fails
        // with a clear message here instead of a confusing OS-level "command line too long" failure.
        private const int MaxScriptLength = 8000;

        internal sealed class Result
        {
            internal readonly int ExitCode;
            internal readonly string Stdout;
            internal readonly string Stderr;
            internal Result(int exitCode, string stdout, string stderr)
            { ExitCode = exitCode; Stdout = stdout; Stderr = stderr; }
        }

        internal enum AddOutcome { Ok, Error, Unknown }

        // Split out so a caller building a script ahead of time (e.g. Prepare(), during Probe) can
        // fail fast on an oversized request before any mutation is even attempted, rather than only
        // discovering it inside Add() after evidence.AddAttempted is already true.
        internal static void ValidateScriptLength(string script)
        {
            if (script.Length > MaxScriptLength)
            {
                throw new InvalidOperationException("PowerShell script/value payload is too large for -EncodedCommand (" +
                    script.Length + " > " + MaxScriptLength + " characters); reduce the number or length of values.");
            }
        }

        // Split out so a test can inspect the constructed ProcessStartInfo (executable path, and that
        // -EncodedCommand -- never -File plus a temp script -- is used) without actually starting a
        // process. Deliberately never touches ProcessStartInfo.EnvironmentVariables: see RunScript's
        // remarks for why the PSModulePath restriction is applied a different way.
        internal static ProcessStartInfo BuildProcessStartInfo(string script)
        {
            ValidateScriptLength(script);
            string encodedCommand = Convert.ToBase64String(Encoding.Unicode.GetBytes(script));
            return new ProcessStartInfo(PowerShellExecutablePath,
                "-NoProfile -NonInteractive -ExecutionPolicy Bypass -EncodedCommand " + encodedCommand)
            {
                UseShellExecute = false,
                CreateNoWindow = true,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                StandardOutputEncoding = new UTF8Encoding(false),
                StandardErrorEncoding = new UTF8Encoding(false)
            };
        }

        // Deliberately does not throw on a nonzero exit code: every script emits its own explicit
        // WTF_..._OK / WTF_..._ERROR marker, and callers must decide from those (via
        // FindMarkerMessage/ContainsMarker/ClassifyAddResult) what a missing marker means for their
        // own operation -- a bare process exit code alone cannot distinguish "the script's try/catch
        // reported a real failure" from "something external tore down powershell.exe after the real
        // work already completed," and only some callers (Add) can safely treat that ambiguity as
        // anything but a hard failure.
        internal static Result RunScript(string script)
        {
            var start = BuildProcessStartInfo(script);

            // ProcessStartInfo.EnvironmentVariables' first access unconditionally copies the entire
            // current-process environment into a case-insensitive StringDictionary (lowercasing every
            // key before insertion) so callers can layer changes on top of inheritance. On a minority
            // of real hosts, the raw environment block already contains two case-variant entries for
            // the same variable (observed in practice for "Path"/"PATH", typically left behind by a
            // third-party PATH-manipulating tool or shell integration) -- Windows itself tolerates
            // this, since CreateProcess and GetEnvironmentVariableW are case-insensitive, but that
            // StringDictionary copy does not, and throws ArgumentException ("item with the same key
            // has already been added") on the very first touch of the property, before PSModulePath
            // is ever set. wtf.exe never even reaches powershell.exe on such a host, for both
            // defender exclusion and defender asr.
            //
            // Avoiding ProcessStartInfo.EnvironmentVariables entirely sidesteps this: with that
            // property never accessed, Process.Start passes CreateProcess a NULL environment block,
            // so the child simply inherits this process' real, current environment as-is. Temporarily
            // overriding this process' own PSModulePath immediately before Process.Start (and
            // restoring it immediately after -- the child only reads it once, at its own startup, not
            // continuously) achieves the same restriction without going anywhere near the buggy copy.
            // This is safe because RunScript is only ever called synchronously, never from multiple
            // threads at once.
            string previousPSModulePath = Environment.GetEnvironmentVariable("PSModulePath");
            Process process;
            try
            {
                Environment.SetEnvironmentVariable("PSModulePath", TrustedModulePath);
                try
                {
                    process = Process.Start(start);
                }
                catch (Win32Exception ex)
                {
                    throw new NotSupportedException("Could not start " + PowerShellExecutablePath + ": " + ex.Message);
                }
            }
            finally
            {
                Environment.SetEnvironmentVariable("PSModulePath", previousPSModulePath);
            }
            using (process)
            {
                // Reading one redirected stream fully before touching the other can deadlock once
                // the unread pipe's OS buffer fills and the child blocks writing to it; both are
                // drained concurrently instead.
                Task<string> stdoutTask = process.StandardOutput.ReadToEndAsync();
                Task<string> stderrTask = process.StandardError.ReadToEndAsync();
                Task.WaitAll(stdoutTask, stderrTask);
                process.WaitForExit();
                return new Result(process.ExitCode, stdoutTask.Result, stderrTask.Result);
            }
        }

        // Classifies an Add() script's result from its own explicit markers, never the bare process
        // exit code: only WTF_ADD_ERROR means the cmdlet itself actually rejected the request; a
        // missing marker (crash, external process kill) is Unknown, never conflated with a real
        // rejection.
        internal static AddOutcome ClassifyAddResult(Result result, out string errorMessage)
        {
            return ClassifyResult(result, "WTF_ADD_OK", "WTF_ADD_ERROR:", out errorMessage);
        }

        // General form of ClassifyAddResult, parameterized on the OK/ERROR: marker pair rather than
        // hard-coded to "WTF_ADD_*" -- reused by FirewallModule's PowerShellFirewallBackend for its
        // Remove() outcome (marker pair "WTF_REMOVE_OK"/"WTF_REMOVE_ERROR:"), which needs the identical
        // Ok/Error/Unknown classification but is not an Add. A pure function of its inputs (no process
        // I/O), so it can be unit-tested directly against a constructed Result rather than only through
        // a live script run or a fake-backend lifecycle test.
        internal static AddOutcome ClassifyResult(Result result, string okMarker, string errorPrefix, out string errorMessage)
        {
            errorMessage = FindMarkerMessage(result.Stdout, errorPrefix);
            if (errorMessage != null) { return AddOutcome.Error; }
            return ContainsMarker(result.Stdout, okMarker) ? AddOutcome.Ok : AddOutcome.Unknown;
        }

        // Builds a read script for one CIM-backed source expression (e.g. "ConfigDefender\Get-MpPreference";
        // in a test, a literal [pscustomobject] simulating one): asserts exactly one instance, then for
        // each field asserts it actually exists on that instance before emitting its values
        // (Base64-encoded, one line per value) between a WTF_BEGIN_<marker>:<field> / WTF_END_<marker>:<field>
        // pair, ending in a WTF_READ_OK marker only if every field was read.
        //
        // Deliberately does NOT guard "foreach ($v in $pref.<field>)" with "if ($pref.<field>) { ... }":
        // PowerShell's truthiness of a one-element array is the truthiness of that single element, so a
        // one-element array holding a falsy value (0, $false, an empty string) would vanish from the
        // output entirely -- exactly what a single ASR rule set to Disabled hits, since
        // AttackSurfaceReductionRules_Actions is a UInt8Array and Disabled's real value is 0. A bare
        // "foreach" over $null already iterates zero times (PSv3+); @($pref.<field>) must NOT be used
        // instead, since @($null) produces a one-element array containing $null, not an empty one.
        //
        // sourceExpression is never caller-supplied text -- it is always one of the two literal cmdlet
        // invocations this module constructs (ConfigDefender\Get-MpPreference), or, in a test, a literal
        // fixture -- never a runtime value assembled from user input.
        //
        // integerFields (may be null) names fields whose values must be cast via [int] before [string]
        // (i.e. [string][int]$v rather than the default [string]$v). This matters only for
        // AttackSurfaceReductionRules_Actions: it is documented as a UInt8Array, but if some Defender
        // build ever returns it as an enum-backed type instead of a plain byte, a bare [string]$v cast
        // would print that enum member's *name* (e.g. "Disabled"), not the numeric value
        // AsrModule.DecodeUInt32Array expects -- silently turning a real value into unparsable text. A
        // plain string-valued field like ExclusionPath must never be cast via [int] (it would throw).
        internal static string BuildReadScript(string sourceExpression, IEnumerable<string> fields, string marker,
            ICollection<string> integerFields)
        {
            var script = new StringBuilder();
            script.Append("$ErrorActionPreference = 'Stop'\r\n");
            script.Append("try {\r\n");
            script.Append("    $instances = @(" + sourceExpression + ")\r\n");
            script.Append("    if ($instances.Count -ne 1) { throw ('Expected exactly one instance, got ' + $instances.Count + '.') }\r\n");
            script.Append("    $pref = $instances[0]\r\n");
            foreach (string field in fields)
            {
                string cast = integerFields != null && integerFields.Contains(field) ? "[string][int]$v" : "[string]$v";
                script.Append("    if (-not $pref.PSObject.Properties['" + field + "']) { throw ('Missing readback field: " + field + "') }\r\n");
                script.Append("    Write-Output ('WTF_BEGIN_" + marker + ":" + field + "')\r\n");
                script.Append("    foreach ($v in $pref." + field +
                    ") { Write-Output ([Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes(" + cast + "))) }\r\n");
                script.Append("    Write-Output ('WTF_END_" + marker + ":" + field + "')\r\n");
            }
            script.Append("    Write-Output 'WTF_READ_OK'\r\n");
            script.Append("} catch {\r\n");
            script.Append(EmitErrorMarkerStatement("WTF_READ_ERROR:"));
            script.Append("    exit 1\r\n");
            script.Append("}\r\n");
            return script.ToString();
        }

        // Embeds every value as its own Base64 literal directly in script text, decoded inline -- e.g.
        // (@('<b64>','<b64>') | ForEach-Object { ... }) -- rather than through a side-channel file:
        // Base64's alphabet contains no quote character, so each value sits inside a single-quoted
        // literal with no escaping, and because the value never touches disk, there is nothing for
        // another process to race and overwrite (unlike a temp file written before -File reads it back).
        internal static string EncodeValuesExpression(IEnumerable<string> values)
        {
            var builder = new StringBuilder("(@(");
            bool first = true;
            foreach (string value in values)
            {
                if (!first) { builder.Append(","); }
                builder.Append("'" + EncodeValue(value) + "'");
                first = false;
            }
            builder.Append(") | ForEach-Object { [System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String($_)) })");
            return builder.ToString();
        }

        // The catch-block statement every script uses to report a caught exception's message: also
        // Base64-encoded, so an exception message containing non-ASCII text (a localized .NET message,
        // or one carrying user input) cannot be corrupted crossing the same stdout channel actual
        // configuration values cross.
        internal static string EmitErrorMarkerStatement(string prefix)
        {
            return "    Write-Output ('" + prefix + "' + [Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($_.Exception.Message)))\r\n";
        }

        // Scalar counterpart to EncodeValuesExpression, for a single parameter argument rather than an
        // array (e.g. -DisplayName ([...decode-expression...])) -- reused by FirewallModule's
        // PowerShellFirewallBackend, whose New-NetFirewallRule invocation takes scalar, not array,
        // string parameters. Same rationale: Base64's alphabet has no quote character, so the decoded
        // value never needs script-text escaping even when it may contain caller-supplied content
        // (e.g. an absolute --program path).
        internal static string EncodeValueExpression(string value)
        {
            return "([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String('" + EncodeValue(value) + "')))";
        }

        internal static string EncodeValue(string value)
        {
            return Convert.ToBase64String(Encoding.UTF8.GetBytes(value ?? string.Empty));
        }

        internal static string DecodeValue(string base64)
        {
            return Encoding.UTF8.GetString(Convert.FromBase64String(base64));
        }

        internal static IEnumerable<string> SplitLines(string text)
        {
            return text.Replace("\r\n", "\n").Split('\n');
        }

        // Returns the decoded message from the first "prefix<base64>" line found, or null if no line
        // starts with that prefix. A line that fails to decode as Base64 (should never happen from
        // our own scripts) falls back to its raw text rather than throwing, so a malformed marker
        // still surfaces as an error message instead of masking the failure it was reporting.
        internal static string FindMarkerMessage(string stdout, string prefix)
        {
            foreach (string line in SplitLines(stdout))
            {
                if (line.StartsWith(prefix, StringComparison.Ordinal))
                {
                    try { return DecodeValue(line.Substring(prefix.Length)); }
                    catch (FormatException) { return line.Substring(prefix.Length); }
                }
            }
            return null;
        }

        internal static bool ContainsMarker(string stdout, string marker)
        {
            foreach (string line in SplitLines(stdout))
            {
                if (string.Equals(line, marker, StringComparison.Ordinal)) { return true; }
            }
            return false;
        }

        internal static string DescribeFailure(Result result)
        {
            return result.Stderr.Trim().Length > 0 ? result.Stderr.Trim() : result.Stdout.Trim();
        }

        // Parses the "WTF_BEGIN_<marker>:<field>" / "WTF_END_<marker>:<field>" delimited text
        // protocol every PowerShell Read() script emits, Base64-decoding each value line found in
        // between. A fresh marker per call rules out a value colliding with the literal marker text.
        // A field appearing out of order, more than once, or a begin/end mismatch is a script/parsing
        // bug, not adversarial user input, so both fail loudly instead of silently keeping whatever
        // was last seen.
        internal static Dictionary<string, List<string>> ParseFields(string stdout, string marker, ICollection<string> fields)
        {
            var result = new Dictionary<string, List<string>>(StringComparer.OrdinalIgnoreCase);
            foreach (string field in fields) { result.Add(field, new List<string>()); }
            string beginPrefix = "WTF_BEGIN_" + marker + ":";
            string endPrefix = "WTF_END_" + marker + ":";
            string current = null;
            var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            foreach (string line in SplitLines(stdout))
            {
                if (line.StartsWith(beginPrefix, StringComparison.Ordinal))
                {
                    if (current != null)
                    {
                        throw new InvalidOperationException("PowerShell readback block for field " + current + " was not closed.");
                    }
                    current = line.Substring(beginPrefix.Length);
                    if (!result.ContainsKey(current))
                    {
                        throw new InvalidOperationException("Unexpected PowerShell readback field: " + current);
                    }
                    if (!seen.Add(current))
                    {
                        throw new InvalidOperationException("PowerShell readback returned field " + current + " more than once.");
                    }
                    continue;
                }
                if (line.StartsWith(endPrefix, StringComparison.Ordinal))
                {
                    if (current != line.Substring(endPrefix.Length))
                    {
                        throw new InvalidOperationException("PowerShell readback block mismatch for field: " + current);
                    }
                    current = null;
                    continue;
                }
                if (current != null && line.Length > 0) { result[current].Add(DecodeValue(line)); }
            }
            if (current != null)
            {
                throw new InvalidOperationException("PowerShell readback truncated for field: " + current);
            }
            // A field that never arrived is unobserved, not an empty list.
            foreach (string field in fields)
            {
                if (!seen.Contains(field))
                {
                    throw new InvalidOperationException("PowerShell readback is missing field: " + field);
                }
            }
            return result;
        }
    }

    internal static int EvaluateAddResult(object returnValue, Func<bool> readBack)
    {
        uint status;
        if (TryGetStatusCode(returnValue, out status))
        {
            if (status != 0)
            {
                return ReportError("Defender rejected the request. WMI return code: " +
                    status + " (0x" + status.ToString("X8") + ").");
            }
        }
        else
        {
            ConsoleUi.Status("WARN",
                "Warning: No usable WMI return code; verifying configuration by readback.", true);
            ConsoleUi.Detail("WMI return value: " +
                (returnValue == null ? "null or missing" :
                    returnValue == DBNull.Value ? "DBNull" :
                    returnValue.GetType().FullName + ": " +
                    Convert.ToString(returnValue, CultureInfo.InvariantCulture)));
        }

        if (readBack())
        {
            ConsoleUi.Status("OK", "Confirmed: all requested exclusions are visible in readback.");
            return 0;
        }

        ConsoleUi.Status("FAIL", "One or more exclusions could not be confirmed by readback.", true);
        ConsoleUi.Text("Check effective policy and visibility; partial changes are possible.");
        return 3;
    }

    private static bool TryGetStatusCode(object value, out uint status)
    {
        status = 0;
        if (value is int)
        {
            // A signed Int32 may contain the same HRESULT bits as a UInt32.
            status = unchecked((uint)(int)value);
            return true;
        }

        if (!(value is uint || value is long || value is ulong ||
              value is short || value is ushort || value is byte ||
              value is sbyte || value is string))
        {
            return false;
        }

        string text = Convert.ToString(value, CultureInfo.InvariantCulture);
        if (uint.TryParse(text, NumberStyles.Integer, CultureInfo.InvariantCulture, out status))
        {
            return true;
        }

        int signedStatus;
        if (int.TryParse(text, NumberStyles.Integer, CultureInfo.InvariantCulture, out signedStatus))
        {
            status = unchecked((uint)signedStatus);
            return true;
        }

        return false;
    }

    private static IList<Dictionary<string, object>> ReadExclusionRecords(
        ManagementScope scope, ICollection<string> types)
    {
        var records = new List<Dictionary<string, object>>();
        using (var searcher = new ManagementObjectSearcher(scope,
            new ObjectQuery("SELECT " + string.Join(", ", types) + " FROM MSFT_MpPreference")))
        using (ManagementObjectCollection results = searcher.Get())
        {
            foreach (ManagementObject preference in results)
            {
                using (preference)
                {
                    var fields = new Dictionary<string, object>(StringComparer.OrdinalIgnoreCase);
                    foreach (string type in types) { fields[type] = preference[type]; }
                    records.Add(fields);
                }
            }
        }
        return records;
    }

    // The one place the management and COM reads turn provider records into lists. MSFT_MpPreference
    // is a singleton: zero records means nothing was observed (provider degraded, service down) and
    // several mean the answer is ambiguous, so both fail rather than become an empty or merged list.
    // native and powershell enforce the same rule in their own readers. Each record maps a type name
    // to the raw property value.
    internal static Dictionary<string, List<string>> AssembleExclusions(
        IList<Dictionary<string, object>> records, ICollection<string> types)
    {
        AsrModule.RequireSingleInstance(records.Count, "Exclusion lists cannot be read.");
        var configured = new Dictionary<string, List<string>>(StringComparer.OrdinalIgnoreCase);
        foreach (string type in types)
        {
            object raw;
            if (!records[0].TryGetValue(type, out raw))
            {
                throw new InvalidOperationException("Missing readback field: " + type);
            }
            configured.Add(type, DecodeStringArray(raw, type));
        }
        return configured;
    }

    internal static bool VerifyExclusions(Dictionary<string, List<string>> requested,
        Dictionary<string, List<string>> configured)
    {
        return VerifyExclusions(requested, configured, null);
    }

    // unreadable (may be null) names types whose list Defender withheld: their values cannot be
    // confirmed, and are reported as such rather than as simply missing.
    internal static bool VerifyExclusions(Dictionary<string, List<string>> requested,
        Dictionary<string, List<string>> configured, ICollection<string> unreadable)
    {
        bool allConfirmed = true;
        foreach (var exclusion in requested)
        {
            foreach (string value in exclusion.Value)
            {
                if (unreadable != null && unreadable.Contains(exclusion.Key))
                {
                    ConsoleUi.Status("FAIL", "Not confirmed " + exclusion.Key + ": " + value +
                        " (list unreadable; cannot confirm)", true);
                    allConfirmed = false;
                    continue;
                }
                bool found = ContainsExclusion(configured, exclusion.Key, value);
                if (found)
                {
                    ConsoleUi.Status("OK", "Configured " + exclusion.Key + ": " + value);
                }
                else
                {
                    ConsoleUi.Status("FAIL", "Not confirmed " + exclusion.Key + ": " + value, true);
                    allConfirmed = false;
                }
            }
        }
        return allConfirmed;
    }

    private static bool ContainsExclusion(Dictionary<string, List<string>> configured,
        string type, string value)
    {
        List<string> values;
        if (!configured.TryGetValue(type, out values))
        {
            throw new InvalidOperationException("Missing readback field: " + type);
        }
        return values.Exists(delegate(string actual) { return EquivalentValues(type, actual, value); });
    }

    // Defender treats a path/process entry with and without a trailing backslash as the same entry.
    private static string NormalizeValue(string type, string value)
    {
        bool isPath = type == "ExclusionPath" || type == "ExclusionProcess";
        return isPath ? value.TrimEnd('\\') : value;
    }

    private static bool EquivalentValues(string type, string actual, string value)
    {
        return actual != null && string.Equals(NormalizeValue(type, actual),
            NormalizeValue(type, value), StringComparison.OrdinalIgnoreCase);
    }

    internal static void PrintAssessment(Options options, RunEvidence evidence, int exitCode)
    {
        ConsoleUi.Section("Result");
        string outcome = DescribeOutcome(options, evidence, exitCode);
        ConsoleUi.Status(exitCode == 0 ? "OK" : exitCode == 3 ? "WARN" : "FAIL", "Outcome: " + outcome);
        ConsoleUi.Row("Exit / stage", exitCode + " / " + evidence.Stage);
        if (options.Mode == ExclusionMode.Remove)
        {
            ConsoleUi.Text("Remove attempted: " + evidence.RemoveAttempted +
                "; requests sent: " + evidence.RemoveInvoked + "; returned: " + evidence.RemoveReturned);
            if (evidence.RemoveItems.Count != 0)
            {
                ConsoleUi.Text("Per value: " + CountItems(evidence, RemoveState.Removed) + " removed (confirmed), " +
                    CountItems(evidence, RemoveState.AlreadyAbsent) + " already absent, " +
                    CountItems(evidence, RemoveState.NotConfirmed) + " not confirmed, " +
                    CountItems(evidence, RemoveState.Error) + " error.");
            }
        }
        else if (options.ReadOnly)
        {
            ConsoleUi.Text("Add attempted: " + evidence.AddAttempted + "; Remove attempted: " + evidence.RemoveAttempted);
        }
        else
        {
            ConsoleUi.Text("Add attempted: " + evidence.AddAttempted +
                "; invocation returned: " + evidence.AddReturned);
        }
        if (evidence.Lifecycle != null)
        {
            ConsoleUi.Row("Lifecycle", "probe=" + evidence.Lifecycle.Probe +
                "; mutation=" + evidence.Lifecycle.Mutation +
                "; verification=" + evidence.Lifecycle.Verification +
                "; observation=" + evidence.Lifecycle.Observation +
                "; restoration=" + evidence.Lifecycle.Restoration);
        }
        if (options.Mode == ExclusionMode.Remove)
        {
            if (!evidence.RemoveAttempted && exitCode == 0)
            {
                ConsoleUi.Text("Every requested value was already absent; Defender was not asked to remove anything.");
            }
            else if (!evidence.RemoveAttempted)
            {
                ConsoleUi.Text("Preflight failed before Remove; this is not proof of a tamper-protection block.");
            }
            else if (exitCode == 0)
            {
                ConsoleUi.Text("Removal confirmed by readback for every value sent. WTF did not create these entries; protection state and EDR detection require separate evidence.");
                if (CountItems(evidence, RemoveState.AlreadyAbsent) != 0)
                {
                    ConsoleUi.Text("Values already absent are listed as such; no change was demonstrated for them.");
                }
            }
            else
            {
                ConsoleUi.Text("An error or missing readback does not prove a security-control block.");
                ConsoleUi.Text("The per-value results show which values changed; partial changes are possible and nothing was rolled back.");
            }
        }
        else if (options.ReadOnly)
        {
            ConsoleUi.Text(options.Mode == ExclusionMode.List ?
                "No Add or Remove was invoked. A list is a point-in-time read, not proof of effective policy." :
                "No Add was invoked. This does not test prevention of configuration changes.");
            if (evidence.ListUnreadable)
            {
                ConsoleUi.Text("At least one list was unreadable: it is not reported as empty, and no value is reported absent because of it.");
            }
        }
        else if (!evidence.AddAttempted)
        {
            ConsoleUi.Text("Preflight failed before Add; this is not proof of a tamper-protection block.");
        }
        else if (exitCode == 0)
        {
            ConsoleUi.Text("Configuration confirmed; antivirus enforcement and EDR detection require separate evidence.");
            if (evidence.AllPresentBefore == true)
            {
                ConsoleUi.Text("All values already existed; no new configuration transition was demonstrated.");
            }
            else if (evidence.AllPresentBefore == null)
            {
                ConsoleUi.Text("The baseline was unreadable, so whether the values already existed is unknown.");
            }
            else
            {
                ConsoleUi.Text("At least one value is newly observed; visibility or concurrent policy changes may affect attribution.");
            }
        }
        else
        {
            ConsoleUi.Text("An error or missing readback does not prove a security-control block.");
            ConsoleUi.Text("Inspect the error and effective policy; partial changes are possible.");
        }
        ConsoleUi.Text("Compliance: NOT_ASSESSED | Detection/response: NOT_MEASURED");
        ConsoleUi.Text(options.Mode == ExclusionMode.Remove ?
            "No automatic rollback; re-add a removed value only if the removal was unintended." :
            "No automatic cleanup; preserve pre-existing entries when restoring test changes.");
        if (!options.Verbose)
        {
            ConsoleUi.Text("Use --verbose for diagnostic detail and Detection & Response guidance.");
            return;
        }

        ConsoleUi.Section("Diagnostics");
        ConsoleUi.Row("Run ID", evidence.RunId);
        ConsoleUi.Row("End UTC", evidence.OperationEndUtc.ToString("O", CultureInfo.InvariantCulture));
        ConsoleUi.Text("Transport: " + options.Transport + "; last stage: " + evidence.Stage);
        ConsoleUi.Text("All clients share the same WMI provider and authorization boundary; none elevates privileges.");
        ConsoleUi.Text("Readback is a point-in-time configuration check, not a functional protection or persistence test.");
        ConsoleUi.Text("Compare results with approved policy, change authorization, scope and expected outcome.");
        ConsoleUi.Text("Local event evidence does not establish SIEM/EDR alerting or response.");
        ConsoleUi.Row("Telemetry mode", options.CollectEtw ? "etw (raw ETL capture; TDH evidence follows)" :
            options.CollectEventLog ? "eventlog (evidence follows; not raw ETW tracing)" : "none (no event logs read)");

        ConsoleUi.Section(options.Mode == ExclusionMode.Remove ? "Removal scope" : "Exclusion scope");
        if (options.Exclusions.ContainsKey("ExclusionPath"))
        {
            ConsoleUi.Row("Path", "Can reduce file/directory antivirus scanning; review breadth and writable locations.");
        }
        if (options.Exclusions.ContainsKey("ExclusionExtension"))
        {
            ConsoleUi.Row("Extension", "May affect matching files across locations, not just the test directory.");
        }
        if (options.Exclusions.ContainsKey("ExclusionProcess"))
        {
            ConsoleUi.Row("Process", "Concerns files opened by the process; not a blanket executable/EDR allowlist.");
        }
        if (options.Exclusions.ContainsKey("ExclusionIpAddress"))
        {
            ConsoleUi.Row("IP", "Applies to supported Defender inspection behavior; not a Windows Firewall allow rule.");
        }

        ConsoleUi.Section("Detection & Response");
        ConsoleUi.Text("Recommendations below are not observed detection results.");
        ConsoleUi.Row("1. Correlate", "Use UTC, host, identity, PID, image and requested values. Preserve the executable hash and console output. Run ID is local, not injected into events.");
        ConsoleUi.Row("2. Defender", "Event 5007: inspect old/new configuration. Event 5013: verify the blocked setting. Neither is guaranteed for every request or pre-existing value.");
        ConsoleUi.Row("3. Process", "Security 4688 (audit policy required), Sysmon 1, or EDR: correlate parent process, command line, identity, hash and signer.");
        ConsoleUi.Row("4. WMI", "WMI-Activity is not a complete successful-method audit trail. Only the powershell transport launches an actual PowerShell process (script-block logging, AMSI); the other three never do, so missing script logs on their own do not establish a detection gap.");
        ConsoleUi.Row("5. Validate", "Check collection, ingestion delay, sensor coverage, alert rules and triage latency separately.");
        ConsoleUi.Row("6. Restore", options.Mode == ExclusionMode.Remove ?
            "Removed entries were not created by WTF. Re-add only an unintended removal, via the approved channel; there is no automatic rollback. Verify policy and protection afterward." :
            "Remove only test-created entries via the approved channel; preserve pre-existing entries. No automatic cleanup. Verify policy and protection afterward.");
        ConsoleUi.Row("7. Respond", "For unauthorized changes, preserve evidence, follow the incident playbook and investigate the account/process and exposure. T1562.001 requires unauthorized impairment context.");
        ConsoleUi.Row("8. Govern", "Review least privilege, exclusion ownership/expiry, central policy and applicable tamper-protection coverage. Administrator access alone does not prove noncompliance.");
        ConsoleUi.Text("Reference: https://learn.microsoft.com/en-us/defender-endpoint/troubleshoot-microsoft-defender-antivirus");
    }

    private static int CountItems(RunEvidence evidence, RemoveState state)
    {
        return evidence.RemoveItems.FindAll(delegate(RemoveItem item) { return item.State == state; }).Count;
    }

    private static string DescribeOutcome(Options options, RunEvidence evidence, int exitCode)
    {
        if (options.Mode == ExclusionMode.Remove)
        {
            if (exitCode == 0) { return evidence.RemoveAttempted ? "REMOVAL_CONFIRMED" : "ALREADY_ABSENT"; }
            if (!evidence.RemoveAttempted) { return "NOT_ATTEMPTED"; }
            if (exitCode == 3)
            {
                return CountItems(evidence, RemoveState.Removed) != 0 ? "PARTIAL_REMOVAL_UNCONFIRMED" : "REMOVAL_UNCONFIRMED";
            }
            return CountItems(evidence, RemoveState.Removed) != 0 && CountItems(evidence, RemoveState.Error) != 0 ?
                "PARTIAL_REMOVAL" : "OPERATION_ERROR";
        }
        if (options.ReadOnly)
        {
            string name = options.Mode == ExclusionMode.List ? "LIST" : "CHECK";
            // Exit 4 means ETW setup stopped the run before the read; any other failure is a failed read.
            return exitCode == 0 ? name + "_ONLY" : exitCode == 3 ? name + "_INCOMPLETE" :
                exitCode == 4 ? "NOT_ATTEMPTED" : name + "_FAILED";
        }
        return exitCode == 0 ?
            (evidence.AllPresentBefore == true ? "CONFIGURATION_CONFIRMED_PREEXISTING" : "CONFIGURATION_CONFIRMED") :
            (!evidence.AddAttempted ? "NOT_ATTEMPTED" : exitCode == 3 ? "UNCONFIRMED" : "OPERATION_ERROR");
    }

    private static int ReportError(string message)
    {
        ConsoleUi.Status("FAIL", message, true);
        ConsoleUi.Text("Check permissions/policy. If a write was attempted, inspect settings for partial changes.");
        ConsoleUi.Detail("Organizational policy and tamper protection can restrict the requested change.");
        return 1;
    }
}
