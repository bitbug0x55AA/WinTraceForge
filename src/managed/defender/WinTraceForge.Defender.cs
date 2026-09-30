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
        ConsoleUi.Text("wtf.exe defender exclusion [options] -ExclusionTYPE VALUE [VALUE ...]");
        ConsoleUi.Section("Options");
        ConsoleUi.Row("--transport", "management|com|native|powershell  (default: management)");
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
        ConsoleUi.Row("powershell", "powershell.exe -> Add-MpPreference/Get-MpPreference");
        ConsoleUi.Text("All routes target Defender preferences directly or via Defender cmdlets; no fallback.");
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
        ConsoleUi.Text("powershell transport uses System32's own powershell.exe (no PATH lookup) and needs ConfigDefender.");
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
        ConsoleUi.Text("See docs\\user\\README.md for evidence limits and restoration guidance.");
    }

    internal sealed class RunEvidence : ControlRunEvidence
    {
        internal bool AddAttempted;
        internal bool AddReturned;
        internal bool? AllPresentBefore;
        internal ControlLifecycleResult<DefenderBaseline> Lifecycle;
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
        ConsoleUi.Detail("Route: " + DescribeRoute(options.Transport));
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
        using (IPreferenceBackend backend = CreateBackend(options.Transport))
        {
            return RunWithBackend(options, evidence, backend);
        }
    }

    private static string DescribeRoute(string transport)
    {
        switch (transport)
        {
            case "native": return "P/Invoke -> native C++ IWbemLocator/IWbemServices::ExecMethod -> WMI -> MSFT_MpPreference.Add";
            case "com": return ".NET COM interop -> SWbemLocator/SWbemServices -> WMI -> MSFT_MpPreference.Add";
            case "powershell": return "Process -> powershell.exe -> Add-MpPreference/Get-MpPreference (Defender PowerShell module) -> MSFT_MpPreference.Add";
            default: return "System.Management -> WMI -> MSFT_MpPreference.Add";
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
        internal readonly Dictionary<string, List<string>> Values;
        internal DefenderBaseline(Dictionary<string, List<string>> values) { Values = values; }
    }

    private sealed class DefenderOperation : IControlOperation<DefenderBaseline, IPreferenceReader, IPreferenceWriter>
    {
        private readonly Options options;
        private readonly RunEvidence evidence;
        internal DefenderOperation(Options options, RunEvidence evidence)
        { this.options = options; this.evidence = evidence; }
        public string Transport { get { return options.Transport; } }
        public bool VerifyAfterApiFailure { get { return false; } }
        public string ManualRestoration { get { return "Remove only test-created exclusions; preserve the captured baseline."; } }

        public ProbeResult<DefenderBaseline> Probe(IPreferenceReader backend)
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

        public MutationStatus Mutate(DefenderBaseline baseline, IPreferenceWriter backend)
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

        public VerificationStatus Verify(DefenderBaseline baseline, IPreferenceReader backend)
        {
            evidence.Stage = "Post-Add readback";
            return VerifyExclusions(options.Exclusions, backend.Read(options.Exclusions.Keys)) ?
                VerificationStatus.Confirmed : VerificationStatus.Mismatch;
        }

        public void Restore(DefenderBaseline baseline, IPreferenceWriter backend) { throw new NotSupportedException("Manual restoration selected."); }
        public VerificationStatus VerifyRestored(DefenderBaseline baseline, IPreferenceReader backend)
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

    internal interface IPreferenceReader
    {
        void Connect();
        void Prepare(Dictionary<string, List<string>> exclusions);
        bool Supports(string name);
        Dictionary<string, List<string>> Read(ICollection<string> types);
    }

    internal interface IPreferenceWriter { object Add(); }

    private sealed class PreferenceReader : IPreferenceReader
    {
        private readonly IPreferenceBackend inner;
        internal PreferenceReader(IPreferenceBackend inner) { this.inner = inner; }
        public void Connect() { inner.Connect(); }
        public void Prepare(Dictionary<string, List<string>> exclusions) { inner.Prepare(exclusions); }
        public bool Supports(string name) { return inner.Supports(name); }
        public Dictionary<string, List<string>> Read(ICollection<string> types) { return inner.Read(types); }
    }

    private sealed class PreferenceWriter : IPreferenceWriter
    {
        private readonly IPreferenceBackend inner;
        internal PreferenceWriter(IPreferenceBackend inner) { this.inner = inner; }
        public object Add() { return inner.Add(); }
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
        private string pendingAddScript;

        public void Connect()
        {
            var script = new StringBuilder();
            script.Append("$ErrorActionPreference = 'Stop'\r\n");
            script.Append("try {\r\n");
            script.Append("    Get-Command ConfigDefender\\Add-MpPreference | Out-Null\r\n");
            script.Append("    Get-Command ConfigDefender\\Get-MpPreference | Out-Null\r\n");
            script.Append("    $cmd = Get-Command ConfigDefender\\Add-MpPreference\r\n");
            script.Append("    foreach ($n in @('ExclusionPath','ExclusionExtension','ExclusionProcess','ExclusionIpAddress')) {\r\n");
            script.Append("        Write-Output ($n + '=' + $cmd.Parameters.ContainsKey($n))\r\n");
            script.Append("    }\r\n");
            script.Append("    Write-Output 'WTF_CONNECT_OK'\r\n");
            script.Append("} catch {\r\n");
            script.Append(PowerShellRunner.EmitErrorMarkerStatement("WTF_CONNECT_ERROR:"));
            script.Append("    exit 1\r\n");
            script.Append("}\r\n");

            PowerShellRunner.Result result = PowerShellRunner.RunScript(script.ToString());
            string errorMessage = PowerShellRunner.FindMarkerMessage(result.Stdout, "WTF_CONNECT_ERROR:");
            if (errorMessage != null || !PowerShellRunner.ContainsMarker(result.Stdout, "WTF_CONNECT_OK"))
            {
                throw new NotSupportedException("PowerShell Defender module (Add-MpPreference/Get-MpPreference) is unavailable. " +
                    (errorMessage ?? PowerShellRunner.DescribeFailure(result)));
            }
            supportsCache = new Dictionary<string, bool>(StringComparer.OrdinalIgnoreCase);
            foreach (string line in PowerShellRunner.SplitLines(result.Stdout))
            {
                int equals = line.IndexOf('=');
                if (equals <= 0) { continue; }
                supportsCache[line.Substring(0, equals)] =
                    string.Equals(line.Substring(equals + 1), "True", StringComparison.OrdinalIgnoreCase);
            }
        }

        public void Prepare(Dictionary<string, List<string>> exclusions)
        {
            // Built (and length-validated) before the Supports() checks below, not after: an
            // oversized request must fail here, during Probe, so the lifecycle reports
            // Mutation=NotAttempted rather than reaching Add() first and being misreported as
            // MutationStatus.ApiFailed (as if Defender itself had rejected a request that
            // powershell.exe never even got a chance to run).
            string script = BuildAddScript(exclusions);
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
            foreach (string line in SplitLines(stdout))
            {
                if (line.StartsWith(beginPrefix, StringComparison.Ordinal))
                {
                    current = line.Substring(beginPrefix.Length);
                    if (!result.ContainsKey(current))
                    {
                        throw new InvalidOperationException("Unexpected PowerShell readback field: " + current);
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
            ConsoleUi.Text("Configuration confirmed; antivirus enforcement and EDR detection require separate evidence.");
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
        ConsoleUi.Row("4. WMI", "WMI-Activity is not a complete successful-method audit trail. Only the powershell transport launches an actual PowerShell process (script-block logging, AMSI); the other three never do, so missing script logs on their own do not establish a detection gap.");
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
        ConsoleUi.Detail("Organizational policy and tamper protection can restrict the requested change.");
        return 1;
    }
}
