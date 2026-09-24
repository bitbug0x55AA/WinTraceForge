// This Source Code Form is subject to the terms of the
// Mozilla Public License, v. 2.0.
// If a copy of the MPL was not distributed with this file, You can obtain one at https://mozilla.org/MPL/2.0/.

using System;
using System.Collections;
using System.Collections.Generic;
using System.Diagnostics;
using System.Globalization;
using System.Management;
using System.Reflection;
using System.Runtime.ExceptionServices;
using System.Runtime.InteropServices;
using System.Security;
using System.Security.Principal;
using System.Threading;

internal static class DefenderModule
{
    private static readonly string[] ExclusionTypes =
    {
        "ExclusionPath", "ExclusionExtension", "ExclusionProcess", "ExclusionIpAddress"
    };

    internal sealed class Options : ControlOptions
    {
        internal bool CheckOnly;
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
            throw new ArgumentException("Specify an exclusion, --check, or --help. There is no default exclusion.");
        }

        for (int i = 0; i < args.Length; i++)
        {
            string argument = args[i];
            if (CommonArguments.TryParse(args, ref i, options, commonSeen)) { continue; }

            if (string.Equals(argument, "--check", StringComparison.OrdinalIgnoreCase))
            {
                options.CheckOnly = true;
                continue;
            }

            if (string.Equals(argument, "--transport", StringComparison.OrdinalIgnoreCase))
            {
                if (transportSpecified || i + 1 >= args.Length)
                {
                    throw new ArgumentException("Specify --transport once, followed by management, com, or native.");
                }
                options.Transport = args[++i].ToLowerInvariant();
                if (options.Transport != "management" && options.Transport != "com" && options.Transport != "native")
                {
                    throw new ArgumentException("Unknown transport. Supported values: management, com, native.");
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
            if (options.CheckOnly || options.Exclusions.Count != 0 ||
                transportSpecified || commonSeen.Count != 0)
            {
                throw new ArgumentException("Use --help by itself, or with --verbose / --no-color.");
            }
            return options;
        }
        if (!options.CheckOnly && options.Exclusions.Count == 0)
        {
            throw new ArgumentException("Specify at least one exclusion for Add, or use --check.");
        }
        CommonArguments.Validate(options, commonSeen);
        return options;
    }

    private static void AddValue(Options options, string type, string value)
    {
        if (string.IsNullOrWhiteSpace(value))
        {
            throw new ArgumentException("-" + type + " does not accept empty or whitespace-only values.");
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
        ConsoleUi.Text("wtf.exe defender exclusion [options] -ExclusionTYPE VALUE [VALUE ...]");
        ConsoleUi.Section("Options");
        ConsoleUi.Row("--transport", "management|com|native  (default: management)");
        ConsoleUi.Row("--check", "Read-only: prepare inputs and read baseline; never invokes Add.");
        ConsoleUi.HelpOptions();
        ConsoleUi.Section("Exclusion types");
        ConsoleUi.Row("-ExclusionPath", "Files or directories");
        ConsoleUi.Row("-ExclusionExtension", "File extensions");
        ConsoleUi.Row("-ExclusionProcess", "Process names or executable paths (Defender semantics)");
        ConsoleUi.Row("-ExclusionIpAddress", "IP addresses (requires provider support)");
        ConsoleUi.Section("Routes");
        ConsoleUi.Row("management", "System.Management -> WMI");
        ConsoleUi.Row("com", "SWbemServices COM Automation -> WMI");
        ConsoleUi.Row("native", "C++ IWbemServices::ExecMethod -> WMI");
        ConsoleUi.Text("All routes target MSFT_MpPreference.Add; no fallback or privilege bypass.");
        ConsoleUi.Section("Quick start");
        ConsoleUi.Text("Read-only check:");
        ConsoleUi.Text("  .\\wtf.exe defender exclusion --check -ExclusionPath \"C:\\Lab Data\"");
        ConsoleUi.Text("Add an exclusion (administrator required):");
        ConsoleUi.Text("  .\\wtf.exe defender exclusion -ExclusionPath \"C:\\Lab Data\"");
        ConsoleUi.HelpTelemetry();
        ConsoleUi.Section("Before you run");
        ConsoleUi.Text("Quote paths with spaces; separate values with spaces, not commas.");
        ConsoleUi.Text("No arguments: usage error; no default exclusion is added.");
        ConsoleUi.Text("Native transport and ETW require WinTraceForge.Native.dll beside the EXE.");
        ConsoleUi.HelpExitCodes();
        ConsoleUi.Status("WARN", "Exclusions reduce protection. Authorized testing only; no automatic cleanup.");
        if (!ConsoleUi.Verbose) { return; }
        ConsoleUi.Section("Extended notes");
        ConsoleUi.Text("Parameter names are case-insensitive and may be combined or repeated.");
        ConsoleUi.Text("PowerShell array syntax and parameter abbreviations are not supported.");
        ConsoleUi.Text("For a value starting with '-', use -ExclusionTYPE=VALUE.");
        ConsoleUi.Text("--check alone reads metadata; with values it also prepares inputs and reads the baseline.");
        ConsoleUi.Text("--check does not validate provider acceptance, write permissions, or prevention policy.");
        ConsoleUi.Text("Existing exclusions are preserved. Every requested item is read back after Add.");
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
        ConsoleUi.Text("See README.md and docs\\technical-reference.md for evidence limits and restoration guidance.");
    }

    internal sealed class RunEvidence : ControlRunEvidence
    {
        internal bool AddAttempted;
        internal bool AddReturned;
        internal bool? AllPresentBefore;
        internal ControlLifecycleResult<DefenderBaseline> Lifecycle;
        internal override void RecordObservation(ObservationStatus status)
        { if (Lifecycle != null) { Lifecycle.SetObservation(status); } }
    }

    private static int Run(Options options, RunEvidence evidence)
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
        ConsoleUi.Detail("Route: " + (options.Transport == "native" ?
            "P/Invoke -> native C++ IWbemLocator/IWbemServices::ExecMethod -> WMI -> MSFT_MpPreference.Add" :
            options.Transport == "com" ?
            ".NET COM interop -> SWbemLocator/SWbemServices -> WMI -> MSFT_MpPreference.Add" :
            "System.Management -> WMI -> MSFT_MpPreference.Add"));
        ConsoleUi.Row("Mode", options.CheckOnly ? "CHECK ONLY - no changes" : "ADD exclusions");

        bool isAdministrator;
        using (WindowsIdentity identity = WindowsIdentity.GetCurrent())
        {
            isAdministrator = new WindowsPrincipal(identity)
                .IsInRole(WindowsBuiltInRole.Administrator);
            ConsoleUi.Row("Identity", identity.Name);
        }

        ConsoleUi.Row("Administrator", isAdministrator ? "Yes" : "No");
        ConsoleUi.Detail("Elevated administrator: " + isAdministrator);
        if (options.Exclusions.Count > 0) { ConsoleUi.Section("Requested exclusions"); }
        foreach (var exclusion in options.Exclusions)
        {
            foreach (string value in exclusion.Value)
            {
                ConsoleUi.Row(exclusion.Key, value);
            }
        }

        if (!options.CheckOnly && !isAdministrator)
        {
            return ReportError("Open a terminal with Run as administrator, then run this EXE again.");
        }

        evidence.Stage = "Connect";
        using (IPreferenceBackend backend = options.Transport == "native" ?
            (IPreferenceBackend)new NativeBackend() : options.Transport == "com" ?
            (IPreferenceBackend)new ComBackend() : new ManagementBackend())
        {
            return RunWithBackend(options, evidence, backend);
        }
    }

    internal static int RunWithBackend(Options options, RunEvidence evidence, IPreferenceBackend backend)
    {
        var gate = new ControlMutationGate();
        ControlLifecycleResult<DefenderBaseline> result = ControlLifecycle.Run(
            new DefenderOperation(options, evidence, new GuardedPreferenceBackend(backend, gate), gate),
            delegate(ControlLifecycleResult<DefenderBaseline> current) { return evidence.ObserveNow(); });
        evidence.Lifecycle = result;
        foreach (string error in result.Errors) { ConsoleUi.Status("FAIL", error, true); }
        if (result.Restoration == RestorationStatus.ManualRequired)
        { ConsoleUi.Row("Restoration", "MANUAL_REQUIRED - " + result.ManualRestoration); }
        return result.ExitCode;
    }

    internal sealed class DefenderBaseline
    {
        internal readonly Dictionary<string, List<string>> Values;
        internal DefenderBaseline(Dictionary<string, List<string>> values) { Values = values; }
    }

    private sealed class DefenderOperation : IControlOperation<DefenderBaseline>
    {
        private readonly Options options;
        private readonly RunEvidence evidence;
        private readonly IPreferenceBackend backend;
        private readonly ControlMutationGate gate;
        internal DefenderOperation(Options options, RunEvidence evidence, IPreferenceBackend backend,
            ControlMutationGate gate)
        { this.options = options; this.evidence = evidence; this.backend = backend; this.gate = gate; }
        public string Transport { get { return options.Transport; } }
        public ControlMutationGate WriteGate { get { return gate; } }
        public bool VerifyAfterApiFailure { get { return false; } }
        public string ManualRestoration { get { return "Remove only test-created exclusions; preserve the captured baseline."; } }

        public ProbeResult<DefenderBaseline> Probe()
        {
            evidence.Stage = "Connect";
            backend.Connect();
            evidence.Stage = "Prepare";
            backend.Prepare(options.Exclusions);
            if (options.CheckOnly && options.Exclusions.Count == 0) { ConsoleUi.Section("Capabilities"); }
            foreach (string type in ExclusionTypes)
            {
                if (options.CheckOnly && (options.Exclusions.Count == 0 || options.Exclusions.ContainsKey(type)) &&
                    (options.Exclusions.Count == 0 || options.Verbose))
                { ConsoleUi.Text(type + ": " + (backend.Supports(type) ? "supported (string[])" : "unsupported")); }
            }
            Dictionary<string, List<string>> baseline = null;
            if (options.Exclusions.Count > 0)
            {
                evidence.Stage = "Baseline read";
                baseline = backend.Read(options.Exclusions.Keys);
                bool allPresent = true;
                ConsoleUi.Section("Baseline");
                foreach (var exclusion in options.Exclusions)
                {
                    foreach (string value in exclusion.Value)
                    {
                        bool present = ContainsExclusion(baseline, exclusion.Key, value);
                        ConsoleUi.Status(present ? "SEEN" : "INFO", exclusion.Key + ": " + value +
                            (present ? " [present]" : " [not observed]"));
                        allPresent &= present;
                    }
                }
                evidence.AllPresentBefore = allPresent;
            }
            if (options.CheckOnly)
            {
                evidence.Stage = "Check complete";
                ConsoleUi.Status("OK", "Read-only check passed. No settings were changed.");
                return new ProbeResult<DefenderBaseline>(new DefenderBaseline(baseline),
                    ProbeStatus.ReadOnlyConfirmed, RestorationPolicy.None);
            }
            return new ProbeResult<DefenderBaseline>(new DefenderBaseline(baseline),
                ProbeStatus.Ready, RestorationPolicy.Manual);
        }

        public MutationStatus Mutate(DefenderBaseline baseline)
        {
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

        public VerificationStatus Verify(DefenderBaseline baseline)
        {
            evidence.Stage = "Post-Add readback";
            return VerifyExclusions(options.Exclusions, backend.Read(options.Exclusions.Keys)) ?
                VerificationStatus.Confirmed : VerificationStatus.Mismatch;
        }

        public void Restore(DefenderBaseline baseline) { throw new NotSupportedException("Manual restoration selected."); }
        public VerificationStatus VerifyRestored(DefenderBaseline baseline)
        { throw new NotSupportedException("Manual restoration selected."); }
    }

    internal interface IPreferenceBackend : IDisposable
    {
        void Connect();
        void Prepare(Dictionary<string, List<string>> exclusions);
        bool Supports(string name);
        object Add();
        Dictionary<string, List<string>> Read(ICollection<string> types);
    }

    private sealed class GuardedPreferenceBackend : IPreferenceBackend
    {
        private readonly IPreferenceBackend inner;
        private readonly ControlMutationGate gate;
        internal GuardedPreferenceBackend(IPreferenceBackend inner, ControlMutationGate gate)
        { this.inner = inner; this.gate = gate; }
        public void Connect() { inner.Connect(); }
        public void Prepare(Dictionary<string, List<string>> exclusions) { inner.Prepare(exclusions); }
        public bool Supports(string name) { return inner.Supports(name); }
        public Dictionary<string, List<string>> Read(ICollection<string> types) { return inner.Read(types); }
        public object Add() { gate.RequireWrite(); return inner.Add(); }
        public void Dispose() { inner.Dispose(); }
    }

    private sealed class NativeBackend : IPreferenceBackend
    {
        private IntPtr handle;

        public void Connect()
        {
            CheckNative(NativeMethods.NativeOpen(out handle), "IWbemLocator::ConnectServer / proxy security");
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

        public object Add()
        {
            object returnValue;
            CheckNative(NativeMethods.NativeAdd(handle, out returnValue), "IWbemServices::ExecMethod(Add)");
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
        internal static extern int NativePrepare(IntPtr handle);

        [DllImport(Library, CallingConvention = CallingConvention.Cdecl, ExactSpelling = true, CharSet = CharSet.Unicode)]
        [DefaultDllImportSearchPaths(DllImportSearchPath.AssemblyDirectory | DllImportSearchPath.System32)]
        internal static extern int NativeSupports(IntPtr handle, string name, [MarshalAs(UnmanagedType.Bool)] out bool supported);

        [DllImport(Library, CallingConvention = CallingConvention.Cdecl, ExactSpelling = true, CharSet = CharSet.Unicode)]
        [DefaultDllImportSearchPaths(DllImportSearchPath.AssemblyDirectory | DllImportSearchPath.System32)]
        internal static extern int NativeSetValues(IntPtr handle, string name,
            [In, MarshalAs(UnmanagedType.LPArray, ArraySubType = UnmanagedType.LPWStr, SizeParamIndex = 3)] string[] values, int count);

        [DllImport(Library, CallingConvention = CallingConvention.Cdecl, ExactSpelling = true)]
        [DefaultDllImportSearchPaths(DllImportSearchPath.AssemblyDirectory | DllImportSearchPath.System32)]
        internal static extern int NativeAdd(IntPtr handle, [MarshalAs(UnmanagedType.Struct)] out object returnValue);

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

    private sealed class ComBackend : IPreferenceBackend
    {
        private readonly ComObjects objects = new ComObjects();
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

        public void Prepare(Dictionary<string, List<string>> exclusions)
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
            object result = objects.Call(services, "ExecMethod", "MSFT_MpPreference", "Add", input, 0, new DispatchWrapper(null));
            if (result == null)
            {
                return null;
            }
            object property;
            return objects.Properties(result).TryGetValue("ReturnValue", out property) ?
                objects.Get(property, "Value") : null;
        }

        public Dictionary<string, List<string>> Read(ICollection<string> types)
        {
            var configured = new Dictionary<string, List<string>>(StringComparer.OrdinalIgnoreCase);
            foreach (string type in types) { configured.Add(type, new List<string>()); }
            object results = objects.Call(services, "ExecQuery",
                "SELECT " + string.Join(", ", types) + " FROM MSFT_MpPreference", "WQL", 0, new DispatchWrapper(null));
            int count = Convert.ToInt32(objects.Get(results, "Count"), CultureInfo.InvariantCulture);
            for (int i = 0; i < count; i++)
            {
                object record = objects.Call(results, "ItemIndex", i);
                Dictionary<string, object> properties = objects.Properties(record);
                foreach (string type in types)
                {
                    object property;
                    if (!properties.TryGetValue(type, out property))
                    {
                        throw new InvalidOperationException("Missing COM readback field: " + type);
                    }
                    object raw = objects.Get(property, "Value");
                    configured[type].AddRange(DecodeStringArray(raw, type));
                }
            }
            return configured;
        }

        public void Dispose() { objects.Dispose(); }
    }

    private sealed class ComObjects : IDisposable
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

    private sealed class ManagementBackend : IPreferenceBackend
    {
        private readonly ManagementScope scope =
            new ManagementScope(@"\\.\root\Microsoft\Windows\Defender");
        private ManagementClass preferenceClass;
        private ManagementBaseObject input;

        public void Connect() { scope.Connect(); }

        public void Prepare(Dictionary<string, List<string>> exclusions)
        {
            preferenceClass = new ManagementClass(scope, new ManagementPath("MSFT_MpPreference"), null);
            preferenceClass.Get();
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
            }
            return null;
        }

        public Dictionary<string, List<string>> Read(ICollection<string> types)
        {
            return ReadExclusions(scope, types);
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

    private static Dictionary<string, List<string>> ReadExclusions(
        ManagementScope scope, ICollection<string> types)
    {
        var configured = new Dictionary<string, List<string>>(StringComparer.OrdinalIgnoreCase);
        foreach (string type in types)
        {
            configured.Add(type, new List<string>());
        }

        using (var searcher = new ManagementObjectSearcher(scope,
            new ObjectQuery("SELECT " + string.Join(", ", types) + " FROM MSFT_MpPreference")))
        using (ManagementObjectCollection results = searcher.Get())
        {
            foreach (ManagementObject preference in results)
            {
                using (preference)
                {
                    foreach (string type in types)
                    {
                        object raw = preference[type];
                        if (raw == null || raw == DBNull.Value)
                        {
                            continue;
                        }
                        string[] values = raw as string[];
                        if (values == null)
                        {
                            throw new InvalidOperationException("Unexpected WMI readback type for " + type + ".");
                        }
                        configured[type].AddRange(values);
                    }
                }
            }
        }

        return configured;
    }

    internal static bool VerifyExclusions(Dictionary<string, List<string>> requested,
        Dictionary<string, List<string>> configured)
    {
        bool allConfirmed = true;
        foreach (var exclusion in requested)
        {
            foreach (string value in exclusion.Value)
            {
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
        return values.Exists(delegate(string actual)
        {
            if (actual == null) { return false; }
            bool isPath = type == "ExclusionPath" || type == "ExclusionProcess";
            return string.Equals(isPath ? actual.TrimEnd('\\') : actual,
                isPath ? value.TrimEnd('\\') : value, StringComparison.OrdinalIgnoreCase);
        });
    }

    internal static void PrintAssessment(Options options, RunEvidence evidence, int exitCode)
    {
        ConsoleUi.Section("Result");
        string outcome = exitCode == 0 ?
            (options.CheckOnly ? "CHECK_ONLY" :
                evidence.AllPresentBefore == true ? "CONFIGURATION_CONFIRMED_PREEXISTING" : "CONFIGURATION_CONFIRMED") :
            (!evidence.AddAttempted ? "NOT_ATTEMPTED" : exitCode == 3 ? "UNCONFIRMED" : "OPERATION_ERROR");
        ConsoleUi.Status(exitCode == 0 ? "OK" : exitCode == 3 ? "WARN" : "FAIL", "Outcome: " + outcome);
        ConsoleUi.Row("Exit / stage", exitCode + " / " + evidence.Stage);
        ConsoleUi.Text("Add attempted: " + evidence.AddAttempted +
            "; invocation returned: " + evidence.AddReturned);
        if (evidence.Lifecycle != null)
        {
            ConsoleUi.Row("Lifecycle", "probe=" + evidence.Lifecycle.Probe +
                "; mutation=" + evidence.Lifecycle.Mutation +
                "; verification=" + evidence.Lifecycle.Verification +
                "; observation=" + evidence.Lifecycle.Observation +
                "; restoration=" + evidence.Lifecycle.Restoration);
        }
        if (options.CheckOnly)
        {
            ConsoleUi.Text("No Add was invoked. This does not test prevention of configuration changes.");
        }
        else if (!evidence.AddAttempted)
        {
            ConsoleUi.Text("Preflight failed before Add; this is not proof of a tamper-protection block.");
        }
        else if (exitCode == 0)
        {
            ConsoleUi.Text("Configuration confirmed, not proof of antivirus/EDR bypass.");
            if (evidence.AllPresentBefore == true)
            {
                ConsoleUi.Text("All values already existed; no new configuration transition was demonstrated.");
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
        ConsoleUi.Text("No automatic cleanup; preserve pre-existing entries when restoring test changes.");
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

        ConsoleUi.Section("Exclusion scope");
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
        ConsoleUi.Row("4. WMI", "WMI-Activity is not a complete successful-method audit trail. No backend launches PowerShell; missing script logs do not establish a detection gap.");
        ConsoleUi.Row("5. Validate", "Check collection, ingestion delay, sensor coverage, alert rules and triage latency separately.");
        ConsoleUi.Row("6. Restore", "Remove only test-created entries via the approved channel; preserve pre-existing entries. No automatic cleanup. Verify policy and protection afterward.");
        ConsoleUi.Row("7. Respond", "For unauthorized changes, preserve evidence, follow the incident playbook and investigate the account/process and exposure. T1562.001 requires unauthorized impairment context.");
        ConsoleUi.Row("8. Govern", "Review least privilege, exclusion ownership/expiry, central policy and applicable tamper-protection coverage. Administrator access alone does not prove noncompliance.");
        ConsoleUi.Text("Reference: https://learn.microsoft.com/en-us/defender-endpoint/troubleshoot-microsoft-defender-antivirus");
    }

    private static int ReportError(string message)
    {
        ConsoleUi.Status("FAIL", message, true);
        ConsoleUi.Text("Check permissions/policy. If Add was attempted, inspect settings for partial changes.");
        ConsoleUi.Detail("This program does not disable or bypass organizational policy or tamper protection.");
        return 1;
    }
}
