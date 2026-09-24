// This Source Code Form is subject to the terms of the
// Mozilla Public License, v. 2.0.
// If a copy of the MPL was not distributed with this file, You can obtain one at https://mozilla.org/MPL/2.0/.

using System;
using System.ComponentModel;
using System.Globalization;
using System.IO;
using System.Runtime.InteropServices;
using System.Security;
using System.Threading;
using System.Xml;

internal sealed class EtwCapture : IDisposable
{
    private const string Library = "WinTraceForge.Native.dll";
    private readonly ControlOptions options;
    private readonly ControlRunEvidence evidence;
    private readonly TelemetryProfile profile;
    private readonly Guid[] providerIds;
    private readonly object gate = new object();
    private readonly string name;
    private IntPtr handle;
    private string file;
    private CaptureStatus captureStatus;
    private uint stopStatus;
    private bool stopped;
    private bool interrupted;
    private bool expired;
    private bool stopFailed;
    private Timer deadline;
    private ConsoleCancelEventHandler cancelHandler;
    private uint candidates;
    private uint parseErrors;
    private uint shown;
    private uint decodeErrorsShown;
    private DateTime startRequestUtc;
    private DateTime stopCompletedUtc;

    [StructLayout(LayoutKind.Sequential)]
    internal struct CaptureStatus
    {
        internal uint ProviderCount;
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = TelemetryProfile.MaxEtwProviders)]
        internal uint[] EnableStatuses;
        internal uint EventsLost;
        internal uint LogBuffersLost;
        internal uint RealTimeBuffersLost;
        internal uint BuffersWritten;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct DecodeStatus
    {
        internal uint SelectedEvents;
        internal uint PartialEvents;
        internal uint DecodeFailures;
        internal uint LimitReached;
        internal uint CallbackFailures;
    }

    internal EtwCapture(ControlOptions options, ControlRunEvidence evidence)
    {
        this.options = options;
        this.evidence = evidence;
        profile = options.Telemetry;
        providerIds = profile.ProviderIds();
        name = "WinTraceForge-" + evidence.RunId;
    }

    internal bool TryStart()
    {
        ConsoleUi.Section("ETW capture setup");
        ConsoleUi.Row("Session", name);
        ConsoleUi.Text("Raw ETW file-mode capture starts before the operation; TDH decoding follows stop.");
        ConsoleUi.Row("Telemetry profile", profile.Name);
        foreach (EtwProvider provider in profile.EtwProviders)
        {
            ConsoleUi.Text("Provider: " + provider.Name + "; verbose level, all keywords.");
        }
        try
        {
            string root = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
            if (string.IsNullOrEmpty(root)) { throw new IOException("Local application data directory is unavailable."); }
            string directory = Path.Combine(root, "WinTraceForge", "Traces", evidence.RunId);
            if (Directory.Exists(directory)) { throw new IOException("Trace directory already exists; refusing to overwrite it."); }
            Directory.CreateDirectory(directory);
            file = Path.Combine(directory, "capture.etl");
            ConsoleUi.Row("ETL file", file);
            ConsoleUi.Text("ETL may contain unrelated provider activity. Protect it as sensitive test evidence.");
            startRequestUtc = DateTime.UtcNow;
            uint start = NativeEtwStartV2(providerIds, (uint)providerIds.Length, name, file, out handle, out captureStatus);
            if (start != 0) { return Fail("StartTrace", start); }
            if (captureStatus.ProviderCount != providerIds.Length || captureStatus.EnableStatuses == null)
            {
                Stop();
                return FailMessage("ETW native provider status does not match the requested telemetry profile.");
            }
            bool enabled = false;
            for (int i = 0; i < providerIds.Length; i++)
            {
                ShowProvider(profile.EtwProviders[i].Name, captureStatus.EnableStatuses[i]);
                enabled |= captureStatus.EnableStatuses[i] == 0;
            }
            if (!enabled)
            {
                ConsoleUi.Status("FAIL", "No ETW providers could be enabled; operation will not be attempted.");
                Stop();
                return false;
            }
            cancelHandler = delegate(object sender, ConsoleCancelEventArgs args)
            {
                args.Cancel = true;
                interrupted = true;
                ConsoleUi.Status("WARN", "Cancellation requested; stopping only this tool's ETW session.");
                Stop();
                Environment.Exit(130);
            };
            Console.CancelKeyPress += cancelHandler;
            deadline = new Timer(delegate
            {
                lock (gate)
                {
                    if (stopped || handle == IntPtr.Zero) { return; }
                    expired = true;
                    ConsoleUi.Status("WARN", "ETW 120-second safety limit reached; subsequent activity is not captured.");
                    Stop();
                }
            }, null, 120000, Timeout.Infinite);
            ConsoleUi.Status("OK", "ETW capture active (32 MB file cap, 120-second safety limit).");
            return true;
        }
        catch (UnauthorizedAccessException ex) { return FailMessage(ex.Message); }
        catch (SecurityException ex) { return FailMessage(ex.Message); }
        catch (IOException ex) { return FailMessage(ex.Message); }
        catch (DllNotFoundException ex) { return FailMessage("ETW native DLL is missing: " + ex.Message); }
        catch (BadImageFormatException ex) { return FailMessage("ETW native DLL architecture mismatch: " + ex.Message); }
        catch (EntryPointNotFoundException ex) { return FailMessage("ETW native DLL version mismatch: " + ex.Message); }
    }

    private static void ShowProvider(string provider, uint status)
    {
        ConsoleUi.Status(status == 0 ? "OK" : "WARN", provider + ": " +
            (status == 0 ? "EnableTraceEx2 succeeded (does not guarantee events)" : Error(status)));
    }

    private static string Error(uint status)
    {
        return "Win32=" + status + " (0x" + status.ToString("X8") + "): " +
            new Win32Exception(unchecked((int)status)).Message;
    }

    private bool Fail(string operation, uint status)
    {
        return FailMessage(operation + " failed: " + Error(status));
    }

    private bool FailMessage(string message)
    {
        ConsoleUi.Status("FAIL", message, true);
        ConsoleUi.Text("ETW setup failed; no test operation will run and there is no eventlog fallback.");
        ConsoleUi.Text("An elevated token or appropriate ETW permissions may be required. No privileges are changed.");
        return false;
    }

    internal void StopAfterWait()
    {
        bool wait;
        lock (gate) { wait = !stopped && handle != IntPtr.Zero; }
        if (wait && options.TelemetryWaitSeconds > 0)
        {
            ConsoleUi.Text("ETW capture tail: waiting " + options.TelemetryWaitSeconds + "s...");
            Thread.Sleep(options.TelemetryWaitSeconds * 1000);
        }
        Stop();
    }

    private void Stop()
    {
        lock (gate)
        {
            if (handle == IntPtr.Zero || stopped) { return; }
            stopStatus = NativeEtwStopV2(handle, out captureStatus);
            stopCompletedUtc = DateTime.UtcNow;
            stopped = stopStatus == 0 || stopStatus == 4201;
            if (stopStatus != 0)
            {
                stopFailed = true;
                ConsoleUi.Status("WARN", "ControlTrace(STOP): " + Error(stopStatus));
                ConsoleUi.Text("ETW completeness cannot be established.");
            }
        }
    }

    internal ObservationStatus Report()
    {
        lock (gate)
        {
            ConsoleUi.Section("Raw ETW evidence");
            ConsoleUi.Row("Session", name);
            ConsoleUi.Row("ETL file", file);
            ConsoleUi.Row("Start request UTC", startRequestUtc.ToString("O", CultureInfo.InvariantCulture));
            ConsoleUi.Row("Stop completed UTC", stopCompletedUtc.ToString("O", CultureInfo.InvariantCulture));
            ConsoleUi.Text("Capture mode: sequential ETL, not Windows Event Log and not live console streaming.");
            if (handle == IntPtr.Zero || !stopped || stopFailed)
            {
                ConsoleUi.Status("WARN", "ETW_STOP_INCOMPLETE; trace cannot be reliably decoded as a completed run.");
                return ObservationStatus.Incomplete;
            }
            ConsoleUi.Row("Events lost", captureStatus.EventsLost.ToString(CultureInfo.InvariantCulture));
            ConsoleUi.Row("File buffers lost", captureStatus.LogBuffersLost.ToString(CultureInfo.InvariantCulture));
            ConsoleUi.Row("Realtime buffers lost", captureStatus.RealTimeBuffersLost + " (file-mode session)");
            ConsoleUi.Row("Buffers written", captureStatus.BuffersWritten.ToString(CultureInfo.InvariantCulture));
            if (!File.Exists(file))
            {
                ConsoleUi.Status("WARN", "ETL_MISSING after session stop; no decoding attempted.");
                return ObservationStatus.Unavailable;
            }
            DecodedCallback callback = ReceiveEvent;
            DecodeStatus decoded;
            uint read = NativeEtwReadV2(providerIds, (uint)providerIds.Length, file, callback, IntPtr.Zero, out decoded);
            GC.KeepAlive(callback);
            ConsoleUi.Row("Selected events", decoded.SelectedEvents.ToString(CultureInfo.InvariantCulture));
            ConsoleUi.Row("Candidates / shown", candidates + " / " + shown);
            ConsoleUi.Row("TDH failures / partial", decoded.DecodeFailures + " / " + decoded.PartialEvents);
            ConsoleUi.Row("XML parse failures", parseErrors.ToString(CultureInfo.InvariantCulture));
            bool complete = captureStatus.ProviderCount == providerIds.Length &&
                IsComplete(captureStatus, decoded, read, parseErrors, expired || interrupted);
            ConsoleUi.Status(complete ? "OK" : "WARN", complete ?
                "ETW_CAPTURE_COMPLETE - no reported capture/decode loss within this session." :
                "ETW_CAPTURE_INCOMPLETE - inspect provider, loss, decode and duration diagnostics.");
            if (read != 0) { ConsoleUi.Status("WARN", "ProcessTrace: " + Error(read)); }
            if (decoded.LimitReached != 0) { ConsoleUi.Status("WARN", "Decode limit: only the first 10,000 selected events were considered."); }
            if (decoded.CallbackFailures != 0) { ConsoleUi.Status("WARN", "A managed evidence callback failed; decoding stopped early."); }
            if (candidates > shown) { ConsoleUi.Text((candidates - shown) + " candidate(s) not displayed; use --verbose to show all within the decode cap."); }
            ConsoleUi.Text("No matching events does NOT prove no detection. Provider success does not guarantee event emission.");
            ConsoleUi.Text("Header PID is the emitting process; ClientProcessId, when available, is a separate field.");
            ConsoleUi.Text("Activity IDs are reported, not invented. PID/value matches are candidates, not causal proof.");
            ConsoleUi.Text("ETW telemetry completeness does not change the operation exit code. ETL is not automatically deleted.");
            return complete ? (candidates > 0 ? ObservationStatus.Observed : ObservationStatus.NotObserved) :
                ObservationStatus.Incomplete;
        }
    }

    internal static bool IsComplete(CaptureStatus capture, DecodeStatus decoded, uint read,
        uint parseFailures, bool durationIncomplete)
    {
        if (capture.ProviderCount == 0 || capture.ProviderCount > TelemetryProfile.MaxEtwProviders ||
            capture.EnableStatuses == null || capture.EnableStatuses.Length < capture.ProviderCount) { return false; }
        for (int i = 0; i < capture.ProviderCount; i++)
        {
            if (capture.EnableStatuses[i] != 0) { return false; }
        }
        return
            capture.EventsLost == 0 && capture.LogBuffersLost == 0 && capture.RealTimeBuffersLost == 0 &&
            decoded.PartialEvents == 0 && decoded.DecodeFailures == 0 && decoded.LimitReached == 0 &&
            decoded.CallbackFailures == 0 && read == 0 && parseFailures == 0 && !durationIncomplete;
    }

    internal static string Correlate(TelemetryEvidence.ParsedEvent parsed, ControlOptions options, int pid)
    {
        if (!options.Telemetry.ContainsEtwProvider(parsed)) { return null; }
        options.Telemetry.ResolveEtwProviderName(parsed);
        string correlation = TelemetryEvidence.Correlate(parsed, options, pid);
        if (correlation != null) { return correlation; }
        return pid > 0 && parsed.HeaderProcessId == (uint)pid ?
            "HEADER_PID_MATCH: emitting process matches; inspect the payload for operation attribution." : null;
    }

    private int ReceiveEvent(uint sequence, string xml, IntPtr context)
    {
        try
        {
            TelemetryEvidence.ParsedEvent parsed = TelemetryEvidence.Parse(xml);
            if ((parsed.DecodeStatus != 0 || parsed.FieldErrors != 0) && (options.Verbose || decodeErrorsShown < 3))
            {
                decodeErrorsShown++;
                ConsoleUi.Status("WARN", "TDH sequence " + sequence + ": provider=" + parsed.Provider +
                    ", event=" + parsed.Id + ", status=" + parsed.DecodeStatus + ", field errors=" + parsed.FieldErrors);
            }
            string correlation = Correlate(parsed, options, evidence.ProcessId);
            if (correlation == null) { return 0; }
            candidates++;
            if (!options.Verbose && shown >= 3) { return 0; }
            shown++;
            ConsoleUi.Status("INFO", "ETW sequence " + sequence + " / Event " + parsed.Id + " / Version " + parsed.Version);
            ConsoleUi.Row("Provider", parsed.Provider);
            ConsoleUi.Row("Provider GUID", parsed.ProviderGuid);
            ConsoleUi.Row("Header PID / TID", parsed.HeaderProcessId + " / " + parsed.HeaderThreadId);
            ConsoleUi.Row("Activity ID", parsed.ActivityId);
            if (options.Verbose) { ConsoleUi.Row("Related activity ID", parsed.RelatedActivityId); }
            // ETW sequence numbers are not Windows Event Log Record IDs.
            TelemetryEvidence.PrintEvent(parsed, correlation, options.Verbose, false);
            return 0;
        }
        catch (XmlException ex)
        {
            parseErrors++;
            ConsoleUi.Status("WARN", "ETW XML parse error: " + TelemetryEvidence.Safe(ex.Message));
            return 0;
        }
        catch (FormatException ex)
        {
            parseErrors++;
            ConsoleUi.Status("WARN", "ETW metadata parse error: " + TelemetryEvidence.Safe(ex.Message));
            return 0;
        }
        catch (IOException)
        {
            // A closed output pipe cannot be reported there; return a callback failure to the controller.
            return 1;
        }
    }

    public void Dispose()
    {
        lock (gate)
        {
            if (cancelHandler != null) { Console.CancelKeyPress -= cancelHandler; }
            if (deadline != null) { deadline.Dispose(); }
            if (handle == IntPtr.Zero) { return; }
            uint close = NativeEtwClose(handle);
            handle = IntPtr.Zero;
            if (close != 0)
            {
                ConsoleUi.Status("WARN", "ETW cleanup failed: " + Error(close));
                ConsoleUi.Text("Check only this tool-owned session: " + name);
            }
        }
    }

    [UnmanagedFunctionPointer(CallingConvention.Cdecl, CharSet = CharSet.Unicode)]
    private delegate int DecodedCallback(uint sequence, [MarshalAs(UnmanagedType.LPWStr)] string xml, IntPtr context);

    [DllImport(Library, CallingConvention = CallingConvention.Cdecl, ExactSpelling = true, CharSet = CharSet.Unicode)]
    [DefaultDllImportSearchPaths(DllImportSearchPath.AssemblyDirectory | DllImportSearchPath.System32)]
    private static extern uint NativeEtwStartV2(
        [In, MarshalAs(UnmanagedType.LPArray, SizeParamIndex = 1)] Guid[] providers, uint count,
        string name, string file, out IntPtr handle, out CaptureStatus status);

    [DllImport(Library, CallingConvention = CallingConvention.Cdecl, ExactSpelling = true)]
    [DefaultDllImportSearchPaths(DllImportSearchPath.AssemblyDirectory | DllImportSearchPath.System32)]
    private static extern uint NativeEtwStopV2(IntPtr handle, out CaptureStatus status);

    [DllImport(Library, CallingConvention = CallingConvention.Cdecl, ExactSpelling = true)]
    [DefaultDllImportSearchPaths(DllImportSearchPath.AssemblyDirectory | DllImportSearchPath.System32)]
    private static extern uint NativeEtwClose(IntPtr handle);

    [DllImport(Library, CallingConvention = CallingConvention.Cdecl, ExactSpelling = true, CharSet = CharSet.Unicode)]
    [DefaultDllImportSearchPaths(DllImportSearchPath.AssemblyDirectory | DllImportSearchPath.System32)]
    private static extern uint NativeEtwReadV2(
        [In, MarshalAs(UnmanagedType.LPArray, SizeParamIndex = 1)] Guid[] providers, uint count,
        string file, DecodedCallback callback, IntPtr context, out DecodeStatus status);
}
