// This Source Code Form is subject to the terms of the Mozilla Public License, v. 2.0.
// If a copy of the MPL was not distributed with this file, You can obtain one at https://mozilla.org/MPL/2.0/.

using System;
using System.Collections.Generic;
using System.IO;
using System.Management;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Xml;
using System.Text.RegularExpressions;
using Microsoft.Win32.SafeHandles;

internal static class RegressionTests
{
    private static int passed;

    private static int Main(string[] args)
    {
        if (args.Length == 1 && args[0] == "--asr-read-only")
        {
            RunAsrReadOnlyIntegrationCheck();
            return 0;
        }
        CheckArguments();
        CheckReadback();
        CheckTransportsAndAssessment();
        CheckTelemetry();
        CheckRawEtw();
        CheckModuleTelemetry();
        CheckLifecycle();
        CheckArchitecture();
        CheckAsrArguments();
        CheckAsrLifecycle();
        CheckAsrPolicySourceAndCatalog();
        CheckAsrSnapshotDecoding();
        CheckNativeSetterTypeGate();
        CheckAsrTelemetry();
        CheckAsrArchitecture();
        CheckAsrBuiltInPrimitive();
        CheckAsrCleanupUnverifiableLabel();
        CheckConsoleLayout();
        object[] zeroStatuses = { (uint)0, 0, (long)0, (ulong)0, (short)0,
            (ushort)0, (byte)0, (sbyte)0, "0" };
        foreach (object status in zeroStatuses)
        {
            Check(status, true, 0, true, false);
            Check(status, false, 3, true, false);
        }

        object[] unknownStatuses = { null, DBNull.Value, "invalid", true,
            0.5, (ulong)uint.MaxValue + 1 };
        foreach (object status in unknownStatuses)
        {
            Check(status, true, 0, true, true);
            Check(status, false, 3, true, true);
        }

        object[] failures = { (uint)5, 5, "5", uint.MaxValue,
            unchecked((int)0x80070005), "-2147024891", (long)-2147024891 };
        foreach (object status in failures)
        {
            Check(status, true, 1, false, false);
            Check(status, false, 1, false, false);
        }

        bool propagated = false;
        try
        {
            DefenderModule.EvaluateAddResult((uint)0,
                delegate { throw new UnauthorizedAccessException("Readback denied"); });
        }
        catch (UnauthorizedAccessException)
        {
            propagated = true;
        }
        if (!propagated)
        {
            throw new Exception("Readback errors must not be swallowed.");
        }
        passed++;
        Console.WriteLine("PASS: " + passed + " regression cases; no Defender settings modified.");
        return 0;
    }

    private static void CheckArguments()
    {
        Assert(DefenderModule.ParseArguments(new[] { "--help" }).Help, "Help");
        Assert(DefenderModule.ParseArguments(new[] { "-HELP" }).Help, "Help alias");
        Assert(DefenderModule.ParseArguments(new[] { "-?" }).Help, "Help shorthand");
        DefenderModule.Options display = DefenderModule.ParseArguments(new[] { "--help", "--verbose", "--no-color" });
        Assert(display.Help && display.Verbose && display.NoColor, "Help display modifiers");
        Assert(!DefenderModule.ParseArguments(new[] { "--check" }).Verbose, "Concise by default");
        Assert(DefenderModule.ParseArguments(new[] { "--verbose", "--check", "--no-color" }).NoColor,
            "Runtime display flags");
        DefenderModule.Options check = DefenderModule.ParseArguments(new[] { "--CHECK" });
        Assert(check.CheckOnly && check.Exclusions.Count == 0, "Check without default");
        Assert(check.Transport == "management", "Default transport preserved");
        Assert(!check.CollectEventLog && !check.CollectEtw && check.TelemetryWaitSeconds == 3, "Telemetry opt-in only");
        DefenderModule.Options telemetry = DefenderModule.ParseArguments(new[] {
            "--check", "--telemetry", "EVENTLOG", "--telemetry-wait", "0"
        });
        Assert(telemetry.CollectEventLog && telemetry.TelemetryWaitSeconds == 0, "Eventlog telemetry selection");
        Assert(DefenderModule.ParseArguments(new[] { "--telemetry", "none", "--check" }).CollectEventLog == false,
            "Explicit telemetry none");
        Assert(DefenderModule.ParseArguments(new[] { "--telemetry-wait", "30", "--telemetry", "eventlog", "--check" })
            .TelemetryWaitSeconds == 30, "Wait before mode");
        DefenderModule.Options etw = DefenderModule.ParseArguments(new[] { "--check", "--telemetry", "ETW", "--telemetry-wait", "0" });
        Assert(etw.CollectEtw && !etw.CollectEventLog, "Raw ETW is a distinct backend");
        Assert(etw.TelemetryWaitSeconds == 0, "ETW tail can be disabled");
        foreach (string transport in new[] { "management", "com", "native" })
        {
            Assert(DefenderModule.ParseArguments(new[] { "--transport", transport, "--check" }).Transport == transport,
                "Select transport: " + transport);
            Assert(DefenderModule.ParseArguments(new[] { "-ExclusionPath", "C:\\Lab", "--transport", transport }).Transport == transport,
                "Select transport after values: " + transport);
        }
        Assert(DefenderModule.ParseArguments(new[] { "--TRANSPORT", "NATIVE", "--check" }).Transport == "native",
            "Transport case insensitive");

        DefenderModule.Options options = DefenderModule.ParseArguments(new[]
        {
            "-exclusionpath", @"C:\Lab Data", @"C:\Lab Logs",
            "-ExclusionExtension", ".lablog", ".labtmp",
            "-ExclusionProcess", "LabWorker.exe", @"C:\Lab Tools\Worker.exe",
            "-ExclusionIpAddress", "192.0.2.10", "2001:db8::1",
            "-ExclusionPath", @"c:\lab data", @"C:\Lab More", "--check"
        });
        Assert(options.CheckOnly && options.Exclusions.Count == 4, "Combined types");
        Assert(options.Exclusions["ExclusionPath"].Count == 3, "Repeated and duplicate values");
        Assert(options.Exclusions["ExclusionPath"][0] == @"C:\Lab Data", "Spaces preserved");
        Assert(options.Exclusions["ExclusionProcess"][1] == @"C:\Lab Tools\Worker.exe", "Process path");
        Assert(options.Exclusions["ExclusionExtension"].Count == 2, "Multiple extensions");
        Assert(options.Exclusions["ExclusionIpAddress"][1] == "2001:db8::1", "IPv6 preserved");
        Assert(!DefenderModule.ParseArguments(new[] { "-ExclusionPath", @"C:\Lab" }).CheckOnly,
            "Add mode");
        Assert(DefenderModule.ParseArguments(new[] { "-ExclusionExtension=-lab" })
            .Exclusions["ExclusionExtension"][0] == "-lab", "Leading dash inline");
        Assert(DefenderModule.ParseArguments(new[] { "-ExclusionPath=C:\\A=B" })
            .Exclusions["ExclusionPath"][0] == "C:\\A=B", "Embedded equals");
        Assert(DefenderModule.ParseArguments(new[] { "-ExclusionPath", @"C:\A,B" })
            .Exclusions["ExclusionPath"][0] == @"C:\A,B", "Comma remains literal");
        Assert(DefenderModule.ParseArguments(new[] { "-ExclusionPath", "C:\\\u6d4b\u8bd5\\\u8d44\u6599" })
            .Exclusions["ExclusionPath"][0] == "C:\\\u6d4b\u8bd5\\\u8d44\u6599", "Unicode preserved");
        Assert(DefenderModule.ParseArguments(new[] { "-ExclusionPath", @"C:\Lab\*" })
            .Exclusions["ExclusionPath"][0] == @"C:\Lab\*", "Wildcard preserved");
        Assert(DefenderModule.ParseArguments(new[] { "--check", "-ExclusionPath", @"C:\Lab" })
            .CheckOnly, "Check before parameters");

        string[][] invalid = {
            new string[0],
            new[] { "-ExclusionPath" },
            new[] { "-ExclusionExtension", "--check" },
            new[] { "-ExclusionProcess", "-ExclusionPath", @"C:\Lab" },
            new[] { "-ExclusionIpAddress=" },
            new[] { "-ExclusionPath", "" },
            new[] { "-ExclusionPath", "   " },
            new[] { "-ExclusionPath", @"C:\Lab", "--invalid" },
            new[] { "--check", "-ExclusionPath", @"C:\Lab", "--invalid" },
            new[] { "-Unknown", "value" },
            new[] { "C:\\Lab" },
            new[] { "--check", "C:\\Lab" },
            new[] { "-ExclusionPa", "C:\\Lab" },
            new[] { "--help", "-ExclusionPath", @"C:\Lab" },
            new[] { "-ExclusionPath", @"C:\Lab", "--help" },
            new[] { "--check", "--help" }
            ,new[] { "--transport" }
            ,new[] { "--transport", "unknown", "--check" }
            ,new[] { "--transport", "com", "--transport", "native", "--check" }
            ,new[] { "--transport", "com" }
            ,new[] { "--transport", "native", "--check", "stray-value" }
            ,new[] { "--transport", "--check" }
            ,new[] { "--telemetry" }
            ,new[] { "--telemetry", "raw", "--check" }
            ,new[] { "--telemetry", "eventlog", "--telemetry", "none", "--check" }
            ,new[] { "--telemetry-wait", "31", "--telemetry", "eventlog", "--check" }
            ,new[] { "--telemetry-wait", "-1", "--telemetry", "eventlog", "--check" }
            ,new[] { "--telemetry-wait", "oops", "--telemetry", "eventlog", "--check" }
            ,new[] { "--telemetry-wait", "0", "--check" }
            ,new[] { "--telemetry-wait", "0", "--telemetry", "none", "--check" }
            ,new[] { "--verbose" }
            ,new[] { "--no-color" }
            ,new[] { "--help", "--verbose", "--check" }
            ,new[] { "--check", "--telemetry", "etw", "--telemetry", "eventlog" }
            ,new[] { "--check", "--telemetry", "etw", "--telemetry-wait", "31" }
        };
        foreach (string[] arguments in invalid)
        {
            bool rejected = false;
            try { DefenderModule.ParseArguments(arguments); }
            catch (ArgumentException) { rejected = true; }
            Assert(rejected, "Reject invalid arguments: " + string.Join(" ", arguments));
        }
    }

    private static void CheckTelemetry()
    {
        DefenderModule.Options options = DefenderModule.ParseArguments(new[] { "-ExclusionPath", "C:\\Lab Data" });
        string defender = EventXml("Microsoft-Windows-Windows Defender", 5007,
            "<EventData><Data Name='Old Value'>Exclusions previous</Data>" +
            "<Data Name='New Value'>Exclusions\\Paths\\C:\\Lab Data = 0</Data></EventData>");
        TelemetryEvidence.ParsedEvent parsed = TelemetryEvidence.Parse(defender);
        Assert(parsed.Id == 5007 && parsed.RecordId == "42", "XML event identity");
        Assert(parsed.TimeUtc == "2026-09-24T01:00:00Z", "XML event timestamp");
        Assert(parsed.Fields["New Value"][0].Contains("C:\\Lab Data"), "XML named fields");
        Assert(TelemetryEvidence.Correlate(parsed, options, 1234).StartsWith("REQUEST_VALUE_MATCH"),
            "Value match takes precedence over generic setting match");
        parsed = TelemetryEvidence.Parse(EventXml("Microsoft-Windows-Windows Defender", 5013,
            "<EventData><Data Name='Setting'>Exclusions</Data></EventData>"));
        Assert(TelemetryEvidence.Correlate(parsed, options, 1234).StartsWith("SETTING_TIME_ONLY"),
            "Blocked-setting event is not causal attribution");
        parsed = TelemetryEvidence.Parse(EventXml("Microsoft-Windows-Windows Defender", 5007,
            "<EventData><Data Name='Setting'>Cloud protection</Data></EventData>"));
        Assert(TelemetryEvidence.Correlate(parsed, options, 1234) == null, "Unrelated setting excluded");

        parsed = TelemetryEvidence.Parse(EventXml("Microsoft-Windows-Security-Auditing", 4688,
            "<EventData><Data Name='NewProcessId'>0x4d2</Data>" +
            "<Data Name='NewProcessName'>C:\\Lab\\Tool.exe</Data></EventData>"));
        Assert(TelemetryEvidence.Correlate(parsed, options, 1234).StartsWith("PID_MATCH"), "Hex new-process PID");
        Assert(TelemetryEvidence.Correlate(parsed, options, 1235) == null, "Different PID excluded");
        Assert(TelemetryEvidence.Correlate(parsed, options, 0) == null, "Uninitialized PID excluded");
        parsed = TelemetryEvidence.Parse(EventXml("Microsoft-Windows-WMI-Activity", 5858,
            "<UserData><Operation xmlns='urn:wmi'><ClientProcessId>1234</ClientProcessId>" +
            "<Operation>ExecQuery</Operation><ResultCode>0x80041003</ResultCode></Operation></UserData>"));
        Assert(TelemetryEvidence.Correlate(parsed, options, 1234).StartsWith("PID_MATCH"), "WMI UserData client PID");
        Assert(parsed.Fields["ResultCode"][0] == "0x80041003", "WMI UserData fields");
        parsed = TelemetryEvidence.Parse(EventXml("Microsoft-Windows-WMI-Activity", 5858,
            "<EventData><Data Name='ProcessId'>1234</Data></EventData>"));
        Assert(TelemetryEvidence.Correlate(parsed, options, 1234) == null, "Provider PID is not WMI client PID");
        parsed = TelemetryEvidence.Parse(EventXml("Microsoft-Windows-Sysmon", 1,
            "<EventData><Data Name='ProcessId'>1234</Data><Data Name='Image'>Tool.exe</Data></EventData>"));
        Assert(TelemetryEvidence.Correlate(parsed, options, 1234).StartsWith("PID_MATCH"), "Sysmon decimal PID");
        parsed = TelemetryEvidence.Parse(EventXml("UnrelatedProvider", 5007,
            "<EventData><Data Name='Value'>C:\\Lab Data</Data></EventData>"));
        Assert(TelemetryEvidence.Correlate(parsed, options, 1234) == null, "Provider isolation");
        parsed = TelemetryEvidence.Parse(EventXml("Microsoft-Windows-Sysmon", 1,
            "<EventData><Data Name='ProcessId'>garbage</Data><Data Name='Image'>one</Data><Data Name='Image'>two</Data></EventData>"));
        Assert(parsed.Fields["Image"].Count == 2, "Repeated fields retained");
        Assert(TelemetryEvidence.Correlate(parsed, options, 1234) == null, "Malformed PID is not a match");
        Assert(TelemetryEvidence.Safe("text\r\n\u001b[31m").IndexOf('\u001b') < 0, "Terminal escapes sanitized");
        Assert(TelemetryEvidence.Safe(new string('x', 1300)).EndsWith("[truncated]"), "Explicit truncation");
        bool rejected = false;
        try { TelemetryEvidence.Parse("<!DOCTYPE Event [<!ENTITY e 'test'>]><Event>&e;</Event>"); }
        catch (XmlException) { rejected = true; }
        Assert(rejected, "DTD rejected");
        rejected = false;
        try { TelemetryEvidence.Parse("<Event/>"); }
        catch (FormatException) { rejected = true; }
        Assert(rejected, "Missing schema rejected explicitly");
    }

    private static string EventXml(string provider, int id, string payload)
    {
        return "<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'>" +
            "<System><Provider Name='" + provider + "'/><EventID>" + id + "</EventID>" +
            "<EventRecordID>42</EventRecordID><TimeCreated SystemTime='2026-09-24T01:00:00Z'/>" +
            "<Execution ProcessID='1234'/></System>" + payload + "</Event>";
    }

    private sealed class TestControlOptions : ControlOptions
    {
        internal TelemetryProfile Profile = TelemetryProfiles.Firewall;
        internal override TelemetryProfile Telemetry { get { return Profile; } }
        internal override IEnumerable<string> EvidenceValues
        {
            get
            {
                if (Kind == ControlKind.FirewallRule) { yield return "WCT-test-rule-123"; }
            }
        }
    }

    private static void CheckModuleTelemetry()
    {
        var firewall = new TestControlOptions { Kind = ControlKind.FirewallRule };
        var profiles = new TestControlOptions { Kind = ControlKind.FirewallProfiles };
        DefenderModule.Options defender = DefenderModule.ParseArguments(new[] { "--check", "-ExclusionPath", "WCT-test-rule-123" });
        foreach (int id in new[] { 2004, 2005, 2006, 4946, 4947, 4948 })
        {
            string provider = id < 4000 ? "Microsoft-Windows-Windows Firewall With Advanced Security" :
                "Microsoft-Windows-Security-Auditing";
            TelemetryEvidence.ParsedEvent parsed = TelemetryEvidence.Parse(EventXml(provider, id,
                "<EventData><Data Name='RuleName'>WCT-test-rule-123</Data></EventData>"));
            Assert(TelemetryEvidence.Correlate(parsed, firewall, 1234).StartsWith("RULE_NAME_MATCH"),
                "Firewall exact-name event correlation " + id);
            Assert(TelemetryEvidence.Correlate(parsed, defender, 1234) == null, "No Firewall events in Defender module");
            Assert(TelemetryEvidence.Correlate(parsed, profiles, 1234) == null, "Profile reads claim no rule mutation");
            parsed.Fields["RuleName"][0] = "WCT-test-rule-123-business";
            Assert(TelemetryEvidence.Correlate(parsed, firewall, 1234) == null, "Rule substrings are not ownership evidence");
        }
        var wrongEvent = TelemetryEvidence.Parse(EventXml("Microsoft-Windows-Windows Defender", 5007,
            "<EventData><Data Name='New Value'>WCT-test-rule-123</Data></EventData>"));
        Assert(TelemetryEvidence.Correlate(wrongEvent, firewall, 1234) == null, "Defender events excluded from Firewall");
        var process = TelemetryEvidence.Parse(EventXml("Microsoft-Windows-Sysmon", 1,
            "<EventData><Data Name='ProcessId'>1234</Data></EventData>"));
        Assert(TelemetryEvidence.Correlate(process, firewall, 1234).StartsWith("PID_MATCH"), "Shared process evidence");
        Assert(TelemetryProfiles.DefenderExclusion.EtwProviders.Count == 2, "Defender explicit ETW providers");
        Assert(TelemetryProfiles.Firewall.EtwProviders.Count == 1, "Firewall explicit ETW providers");
        Assert(TelemetryProfiles.Firewall.EventLogChannels.Count == 3, "Firewall channel list is profile-owned");
        var syntheticProvider = new EtwProvider("Synthetic.Profile", new Guid("8c462a3c-a463-44d9-b553-401a25999c22"));
        var third = new TelemetryProfile("Third test family",
            new[] { new EventLogChannel("Synthetic/Operational", "Synthetic.Profile", "(EventID=7)") },
            new[] { syntheticProvider }, delegate(ControlOptions o) { return new[] { "test-value" }; },
            delegate(TelemetryEvidence.ParsedEvent e, IEnumerable<string> values, int pid) {
                return e.Provider == "Synthetic.Profile" && new List<string>(values).Contains("test-value") ? "THIRD_MATCH" : null;
            }, TelemetryPresentation.Fields("SyntheticValue"),
            delegate(TelemetryEvidence.ParsedEvent e) { return "Synthetic event " + e.Id; });
        var thirdOptions = new TestControlOptions { Kind = (ControlKind)99, Profile = third };
        var thirdEvent = TelemetryEvidence.Parse(EventXml("Synthetic.Profile", 7, "<EventData/>"));
        thirdEvent.Fields["SyntheticValue"] = new List<string> { "profile-owned" };
        thirdEvent.Fields["RuleName"] = new List<string> { "must-not-display" };
        Assert(third.DisplayField("Synthetic Value") && !third.DisplayField("RuleName") &&
            third.Interpret(thirdEvent) == "Synthetic event 7", "Third profile owns fields and interpretation");
        TextWriter originalOutput = Console.Out;
        using (var presentation = new StringWriter())
        {
            try
            {
                Console.SetOut(presentation);
                TelemetryEvidence.PrintEvent(third, thirdEvent, "THIRD_MATCH", false);
                Assert(presentation.ToString().Contains("profile-owned") &&
                    presentation.ToString().Contains("Synthetic event 7") &&
                    !presentation.ToString().Contains("must-not-display"),
                    "Shared renderer honors third profile without family dispatch");
            }
            finally { Console.SetOut(originalOutput); }
        }
        Assert(TelemetryEvidence.Correlate(thirdEvent, thirdOptions, 1234) == "THIRD_MATCH", "Third profile works without core kind dispatch");
        ControlLifecycleResult<SyntheticBaseline> thirdRun = RunSynthetic(new SyntheticOperation(),
            delegate(IControlLifecycleSnapshot state)
            {
                Assert(state.Verification == VerificationStatus.Confirmed,
                    "Third family observation receives verified control state");
                return TelemetryEvidence.Correlate(thirdEvent, thirdOptions, 1234) == "THIRD_MATCH" ?
                    ObservationStatus.Observed : ObservationStatus.NotObserved;
            });
        Assert(thirdRun.Observation == ObservationStatus.Observed &&
            thirdRun.Restoration == RestorationStatus.Succeeded,
            "Third control and telemetry profile integrate through shared lifecycle");
        Assert(TelemetryEvidence.Correlate(thirdEvent, firewall, 1234) == null, "No synthetic events attributed to Firewall");
        Assert(EtwCapture.Correlate(thirdEvent, firewall, 1234) == null, "ETW emitter PID does not cross profile boundary");
        thirdEvent.Provider = "";
        thirdEvent.ProviderGuid = syntheticProvider.Id.ToString("D");
        Assert(EtwCapture.Correlate(thirdEvent, thirdOptions, 1234) == "THIRD_MATCH", "Profile resolves undecoded provider name by actual GUID");
        Guid[] ids = third.ProviderIds();
        ids[0] = Guid.Empty;
        Assert(third.ProviderIds()[0] == syntheticProvider.Id, "Caller cannot change profile provider IDs");
        foreach (EtwProvider[] providers in new[] { new EtwProvider[0],
            new[] { syntheticProvider, syntheticProvider }, new EtwProvider[17] })
        {
            bool rejected = false;
            try { new TelemetryProfile("Invalid", new[] { third.EventLogChannels[0] }, providers,
                third.EvidenceValues, TelemetryEvidence.CorrelateFirewall,
                third.DisplayField, third.Interpret); }
            catch (ArgumentException) { rejected = true; }
            Assert(rejected, "Invalid/duplicate/unbounded provider lists rejected");
        }
    }

    private static void CheckRawEtw()
    {
        var capture = new EtwCapture.CaptureStatus { ProviderCount = 2, EnableStatuses = new uint[16] };
        var decoded = new EtwCapture.DecodeStatus();
        Assert(EtwCapture.IsComplete(capture, decoded, 0, 0, false), "Empty successful trace is complete, not detection proof");
        capture.EnableStatuses[0] = 5;
        Assert(!EtwCapture.IsComplete(capture, decoded, 0, 0, false), "Provider denial marks ETW incomplete");
        capture.EnableStatuses[0] = 0;
        capture.EnableStatuses[1] = 5;
        Assert(!EtwCapture.IsComplete(capture, decoded, 0, 0, false), "Defender denial marks ETW incomplete");
        capture.EnableStatuses[1] = 0;
        Assert(!EtwCapture.IsComplete(new EtwCapture.CaptureStatus(), decoded, 0, 0, false), "Missing provider status is not complete");
        capture.ProviderCount = 3;
        capture.EnableStatuses[2] = 5;
        Assert(!EtwCapture.IsComplete(capture, decoded, 0, 0, false), "Third provider failure is not ignored");
        capture.EnableStatuses[2] = 0;
        Assert(EtwCapture.IsComplete(capture, decoded, 0, 0, false), "Generic third provider status supported");
        capture.ProviderCount = 2;
        capture.EventsLost = 1;
        Assert(!EtwCapture.IsComplete(capture, decoded, 0, 0, false), "Event loss preserved");
        capture.EventsLost = 0;
        capture.LogBuffersLost = 1;
        Assert(!EtwCapture.IsComplete(capture, decoded, 0, 0, false), "File buffer loss preserved");
        capture.LogBuffersLost = 0;
        capture.RealTimeBuffersLost = 1;
        Assert(!EtwCapture.IsComplete(capture, decoded, 0, 0, false), "Realtime buffer counter preserved");
        capture.RealTimeBuffersLost = 0;
        decoded.PartialEvents = 1;
        Assert(!EtwCapture.IsComplete(capture, decoded, 0, 0, false), "Partial schema decode is not full success");
        decoded.PartialEvents = 0;
        decoded.DecodeFailures = 1;
        Assert(!EtwCapture.IsComplete(capture, decoded, 0, 0, false), "TDH failure preserved");
        decoded.DecodeFailures = 0;
        decoded.LimitReached = 1;
        Assert(!EtwCapture.IsComplete(capture, decoded, 0, 0, false), "Decode cap reported incomplete");
        decoded.LimitReached = 0;
        decoded.CallbackFailures = 1;
        Assert(!EtwCapture.IsComplete(capture, decoded, 0, 0, false), "Callback failure preserved");
        decoded.CallbackFailures = 0;
        Assert(!EtwCapture.IsComplete(capture, decoded, 5, 0, false), "Trace read error preserved");
        Assert(!EtwCapture.IsComplete(capture, decoded, 0, 1, false), "XML parse failure preserved");
        Assert(!EtwCapture.IsComplete(capture, decoded, 0, 0, true), "Duration cutoff preserved");

        DefenderModule.Options options = DefenderModule.ParseArguments(new[] { "--telemetry", "etw", "--check", "-ExclusionPath", "C:\\Lab" });
        string xml = "<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'>" +
            "<System><Provider Name='Microsoft-Windows-WMI-Activity' Guid='{1418ef04-b0b4-4623-bf7e-d74ab47bbdaa}'/>" +
            "<EventID>5858</EventID><Version>2</Version><Execution ProcessID='99' ThreadID='100'/>" +
            "<Correlation ActivityID='{11111111-1111-1111-1111-111111111111}' RelatedActivityID=''/>" +
            "<TimeCreated SystemTime='2026-09-24T01:00:00Z'/></System>" +
            "<EventData><Data Name='ClientProcessId'>1234</Data></EventData>" +
            "<Decoding Win32Status='0' FieldErrors='1'/></Event>";
        TelemetryEvidence.ParsedEvent parsed = TelemetryEvidence.Parse(xml);
        Assert(parsed.HeaderProcessId == 99 && parsed.HeaderThreadId == 100, "ETW emitter metadata parsed");
        Assert(parsed.Version == "2" && parsed.ProviderGuid.Contains("1418ef04"), "ETW schema metadata parsed");
        Assert(parsed.FieldErrors == 1 && parsed.DecodeStatus == 0, "Partial decode retained");
        Assert(parsed.ActivityId == "{11111111-1111-1111-1111-111111111111}", "Actual activity ID retained");
        Assert(EtwCapture.Correlate(parsed, options, 1234).StartsWith("PID_MATCH"), "ETW client PID precedence");
        Assert(EtwCapture.Correlate(parsed, options, 99).StartsWith("HEADER_PID_MATCH"), "Emitter PID clearly labelled");
        Assert(EtwCapture.Correlate(parsed, options, 77) == null, "No fabricated ETW match");
        Assert(EtwCapture.Correlate(parsed, options, 0) == null, "ETW excludes uninitialized PID");
        TextWriter original = Console.Out;
        using (var output = new StringWriter())
        {
            try
            {
                Console.SetOut(output);
                TelemetryEvidence.PrintEvent(TelemetryProfiles.DefenderExclusion, parsed, "PID_MATCH: test", false, false);
                Assert(!output.ToString().Contains("Record "), "ETW sequence is not Event Log Record ID");
                var evidence = new DefenderModule.RunEvidence { Stage = "ETW setup" };
                DefenderModule.PrintAssessment(options, evidence, 4);
                Assert(output.ToString().Contains("NOT_ATTEMPTED"), "ETW setup failure has no operation");
                Assert(output.ToString().Contains("Add attempted: False"), "ETW failure never implies Add");
            }
            finally { Console.SetOut(original); }
        }
    }

    private sealed class FakeBackend : DefenderModule.IPreferenceBackend
    {
        internal readonly List<string> Calls = new List<string>();
        internal Dictionary<string, List<string>> Before;
        internal Dictionary<string, List<string>> After;
        internal object Status;
        internal string ThrowAt;
        private int readCount;

        private void Record(string operation)
        {
            Calls.Add(operation);
            if (ThrowAt == operation)
            {
                throw new UnauthorizedAccessException("Simulated " + operation + " failure");
            }
        }
        public void Connect() { Record("Connect"); }
        public void Prepare(Dictionary<string, List<string>> exclusions) { Record("Prepare"); }
        public bool Supports(string name) { Record("Supports"); return true; }
        public object Add() { Record("Add"); return Status; }
        public Dictionary<string, List<string>> Read(ICollection<string> types)
        {
            Record("Read");
            return readCount++ == 0 ? Before : After;
        }
        public void Dispose() { }
    }

    private sealed class FakeAsrBackend : IAsrBackend
    {
        internal readonly List<string> Calls = new List<string>();
        internal AsrSnapshot Snapshot;
        internal AsrSnapshot AfterSnapshot;
        internal object Status;
        internal readonly Dictionary<string, AsrPolicySourceKind> PolicySource =
            new Dictionary<string, AsrPolicySourceKind>(StringComparer.OrdinalIgnoreCase);
        internal bool NotepadRedirectionActive;
        private int readCount;

        public void Connect() { Calls.Add("Connect"); }
        public void Prepare(AsrMutationRequest request) { Calls.Add("Prepare"); }
        public bool Supports(string name) { Calls.Add("Supports"); return true; }
        public object Add() { Calls.Add("Add"); return Status; }
        public AsrSnapshot Read()
        {
            Calls.Add("Read");
            return readCount++ == 0 ? Snapshot : (AfterSnapshot ?? Snapshot);
        }
        public Dictionary<string, AsrPolicySourceKind> ReadPolicySource(IEnumerable<string> keys)
        {
            Calls.Add("ReadPolicySource");
            var result = new Dictionary<string, AsrPolicySourceKind>(StringComparer.OrdinalIgnoreCase);
            foreach (string key in keys)
            {
                AsrPolicySourceKind kind;
                result[key] = PolicySource.TryGetValue(key, out kind) ? kind : AsrPolicySourceKind.Unknown;
            }
            return result;
        }
        public bool IsNotepadRedirectionActive() { return NotepadRedirectionActive; }
        public void Dispose() { }
    }

    private static AsrSnapshot EmptyAsrSnapshot()
    {
        return new AsrSnapshot(new Dictionary<string, AsrAction>(StringComparer.OrdinalIgnoreCase), new List<string>(),
            new Dictionary<string, List<string>>(StringComparer.OrdinalIgnoreCase)
            {
                { "ExclusionPath", new List<string>() }, { "ExclusionExtension", new List<string>() },
                { "ExclusionProcess", new List<string>() }, { "ExclusionIpAddress", new List<string>() }
            });
    }

    // -Integration only: exercises every real ASR backend against live WMI to prove the CimType
    // gate (B1) actually accepts a real Prepare(RuleAction) call end to end on each transport. Add
    // is never invoked, so no Defender setting is touched; this only proves the request would be accepted.
    // Also reads a real baseline through all three and asserts the snapshots agree as sets (order-
    // and case-insensitive, not byte-for-byte), so a future BuildSnapshot/decoder regression that
    // only breaks com or native cannot pass silently.
    private static void RunAsrReadOnlyIntegrationCheck()
    {
        AsrSnapshot[] snapshots = new AsrSnapshot[3];
        string[] transports = { "management", "com", "native" };
        for (int i = 0; i < transports.Length; i++)
        {
            using (IAsrBackend backend = AsrModule.CreateBackend(transports[i]))
            {
                backend.Connect();
                backend.Prepare(new AsrMutationRequest
                {
                    Kind = AsrRequestKind.RuleAction,
                    RuleId = Guid.NewGuid().ToString("D"),
                    Action = AsrAction.Audit
                });
                Console.WriteLine("PASS: real " + transports[i] + " ASR backend Prepare(RuleAction) accepted the UInt8 " +
                    "Actions array against live WMI; Add was not called and no Defender setting was changed.");
                snapshots[i] = backend.Read();
            }
        }
        for (int i = 1; i < transports.Length; i++)
        {
            Assert(AsrSnapshotsEqual(snapshots[0], snapshots[i]),
                "ASR Read() snapshot equal across transports: management vs " + transports[i]);
        }
        Console.WriteLine("PASS: real management/com/native ASR Read() produced identical snapshots against live WMI.");

        RunNativeSetterTypeGateIntegrationCheck();
    }

    [DllImport("WinTraceForge.Native.dll", CallingConvention = CallingConvention.Cdecl, ExactSpelling = true)]
    private static extern int NativeOpen(out IntPtr handle);

    [DllImport("WinTraceForge.Native.dll", CallingConvention = CallingConvention.Cdecl, ExactSpelling = true)]
    private static extern int NativePrepare(IntPtr handle);

    [DllImport("WinTraceForge.Native.dll", CallingConvention = CallingConvention.Cdecl, ExactSpelling = true, CharSet = CharSet.Unicode)]
    private static extern int NativeSetValues(IntPtr handle, string name,
        [In, MarshalAs(UnmanagedType.LPArray, ArraySubType = UnmanagedType.LPWStr, SizeParamIndex = 3)] string[] values, int count);

    [DllImport("WinTraceForge.Native.dll", CallingConvention = CallingConvention.Cdecl, ExactSpelling = true, CharSet = CharSet.Unicode)]
    private static extern int NativeSetByteValues(IntPtr handle, string name,
        [In, MarshalAs(UnmanagedType.LPArray, ArraySubType = UnmanagedType.U1, SizeParamIndex = 3)] byte[] values, int count);

    [DllImport("WinTraceForge.Native.dll", CallingConvention = CallingConvention.Cdecl, ExactSpelling = true)]
    private static extern void NativeClose(IntPtr handle);

    // -Integration only: check the real prepared-session path as well as the deterministic
    // null-session gate check in the CI suite. No Add call is made.
    private static void RunNativeSetterTypeGateIntegrationCheck()
    {
        IntPtr handle;
        int hr = NativeOpen(out handle);
        if (hr < 0) { throw new InvalidOperationException("NativeOpen failed (0x" + hr.ToString("X8") + ")."); }
        try
        {
            hr = NativePrepare(handle);
            if (hr < 0) { throw new InvalidOperationException("NativePrepare failed (0x" + hr.ToString("X8") + ")."); }

            // "1" must stay a value WMI's own Put() coercion would otherwise accept for a UInt8
            // array: WBEM_E_TYPE_MISMATCH (0x80041005) is also what Put() itself returns for a
            // value it cannot convert, so an inconvertible test string here would pass this
            // assertion for the wrong reason even if the gate above it were deleted.
            int crossStringIntoByteField = NativeSetValues(handle, "AttackSurfaceReductionRules_Actions", new[] { "1" }, 1);
            Assert(crossStringIntoByteField == unchecked((int)0x80041005),
                "Native string setter rejects a convertible value for the UInt8-typed Actions property at its own gate");

            int crossByteIntoStringField = NativeSetByteValues(handle, "AttackSurfaceReductionRules_Ids", new byte[] { 1 }, 1);
            Assert(crossByteIntoStringField == unchecked((int)0x80041005),
                "Native byte setter rejects the string-typed Ids property at its own gate");

            Console.WriteLine("PASS: native NativeSetValues/NativeSetByteValues reject a cross-typed property " +
                "against a real prepared session; no Defender setting was changed (Add was never called).");
        }
        finally { NativeClose(handle); }
    }

    private static bool AsrSnapshotsEqual(AsrSnapshot a, AsrSnapshot b)
    {
        if (a.GlobalExclusionsRequireElevation != b.GlobalExclusionsRequireElevation) { return false; }
        if (a.AvExclusionsRequireElevation != b.AvExclusionsRequireElevation) { return false; }
        if (!StringSetsEqual(a.GlobalExclusions, b.GlobalExclusions)) { return false; }
        if (a.Rules.Count != b.Rules.Count) { return false; }
        foreach (var rule in a.Rules)
        {
            AsrAction otherAction;
            if (!b.Rules.TryGetValue(rule.Key, out otherAction) || otherAction != rule.Value) { return false; }
        }
        if (a.AvExclusions.Count != b.AvExclusions.Count) { return false; }
        foreach (var exclusion in a.AvExclusions)
        {
            List<string> otherValues;
            if (!b.AvExclusions.TryGetValue(exclusion.Key, out otherValues) ||
                !StringSetsEqual(exclusion.Value, otherValues)) { return false; }
        }
        return true;
    }

    private static bool StringSetsEqual(List<string> a, List<string> b)
    {
        if (a.Count != b.Count) { return false; }
        var sortedA = new List<string>(a); sortedA.Sort(StringComparer.OrdinalIgnoreCase);
        var sortedB = new List<string>(b); sortedB.Sort(StringComparer.OrdinalIgnoreCase);
        for (int i = 0; i < sortedA.Count; i++)
        {
            if (!string.Equals(sortedA[i], sortedB[i], StringComparison.OrdinalIgnoreCase)) { return false; }
        }
        return true;
    }

    private static void CheckAsrArguments()
    {
        Assert(AsrModule.Parse(new[] { "--help" }).Help, "ASR help");
        Assert(AsrModule.Parse(new[] { "status", "--help" }).Help, "ASR status help");
        AsrOptions status = AsrModule.Parse(new[] { "status" });
        Assert(status.Kind == ControlKind.DefenderAsrStatus && !status.CheckOnly, "ASR status kind");

        AsrOptions check = AsrModule.Parse(new[] { "exclusion", "--check", "-Path", @"C:\Lab" });
        Assert(check.Kind == ControlKind.DefenderAsrExclusion && check.CheckOnly && check.Paths.Count == 1,
            "ASR exclusion check parse");
        Assert(check.Transport == "management", "ASR default transport preserved");

        foreach (string transport in new[] { "management", "com", "native" })
        {
            Assert(AsrModule.Parse(new[] { "exclusion", "--transport", transport, "--check", "-Path", @"C:\Lab" }).Transport == transport,
                "ASR select transport: " + transport);
        }
        Assert(AsrModule.Parse(new[] { "exclusion", "--TRANSPORT", "NATIVE", "--check", "-Path", @"C:\Lab" }).Transport == "native",
            "ASR transport case insensitive");

        // Construction alone never connects to WMI, so this is safe to assert without -Integration:
        // catches a transposed case in CreateBackend's switch (e.g. "com" silently mapped to management).
        var expectedBackendTypes = new Dictionary<string, string>(StringComparer.Ordinal)
        {
            { "management", "ManagementAsrBackend" }, { "com", "ComAsrBackend" }, { "native", "NativeAsrBackend" }
        };
        foreach (var expected in expectedBackendTypes)
        {
            using (IAsrBackend backend = AsrModule.CreateBackend(expected.Key))
            {
                Assert(backend.GetType().Name == expected.Value, "ASR CreateBackend maps " + expected.Key + " to " + expected.Value);
            }
        }

        AsrOptions add = AsrModule.Parse(new[] { "exclusion", "-Path", @"C:\Lab", @"C:\Lab2" });
        Assert(!add.CheckOnly && add.Paths.Count == 2, "ASR exclusion add parse");

        Guid ruleId = Guid.NewGuid();
        AsrOptions ruleCheck = AsrModule.Parse(new[] { "rule", "--check", "-RuleId", ruleId.ToString("D") });
        Assert(ruleCheck.Kind == ControlKind.DefenderAsrRule && ruleCheck.CheckOnly && ruleCheck.RuleId == ruleId,
            "ASR rule check parse");

        AsrOptions ruleSet = AsrModule.Parse(new[] { "rule", "-RuleId", ruleId.ToString("D"), "-Action", "Block" });
        Assert(ruleSet.Action == AsrAction.Block, "ASR rule set parse");
        Assert(AsrModule.Parse(new[] { "rule", "-RuleId", ruleId.ToString("D"), "-Action", "NotConfigured" }).Action
            == AsrAction.NotConfigured, "ASR rule set accepts NotConfigured");

        AsrOptions verifyBuiltIn = AsrModule.Parse(new[] { "verify", "-RuleId", AsrRuleCatalog.JavaScriptOrVbScriptRuleId });
        Assert(verifyBuiltIn.TestCommand == null, "ASR verify built-in parse");

        AsrOptions verifyCustom = AsrModule.Parse(new[] {
            "verify", "-RuleId", ruleId.ToString("D"), "-TestCommand", "cmd.exe", "-TestArguments", "/c exit 0" });
        Assert(verifyCustom.TestCommand == "cmd.exe" && verifyCustom.TestArguments == "/c exit 0",
            "ASR verify custom command parse");

        string[][] invalid = {
            new string[0],
            new[] { "bogus" },
            new[] { "status", "--check" },
            new[] { "status", "-Path", @"C:\Lab" },
            new[] { "exclusion" },
            new[] { "exclusion", "--check" },
            new[] { "exclusion", "-Path" },
            new[] { "exclusion", "--check", "-Path" },
            new[] { "rule" },
            new[] { "rule", "-RuleId", "not-a-guid" },
            new[] { "rule", "-RuleId", ruleId.ToString("D") },
            new[] { "rule", "--check", "-RuleId", ruleId.ToString("D"), "-Action", "Block" },
            new[] { "rule", "-RuleId", ruleId.ToString("D"), "-Action", "Bogus" },
            new[] { "verify" },
            new[] { "verify", "-RuleId", ruleId.ToString("D") },
            new[] { "verify", "-RuleId", ruleId.ToString("D"), "-TestArguments", "/c exit 0" },
            new[] { "exclusion", "--transport", "unknown", "-Path", @"C:\Lab" },
            new[] { "exclusion", "--transport", "--check" }
        };
        foreach (string[] arguments in invalid)
        {
            bool rejected = false;
            try { AsrModule.Parse(arguments); }
            catch (ArgumentException) { rejected = true; }
            Assert(rejected, "Reject invalid ASR arguments: " + string.Join(" ", arguments));
        }
    }

    private static void CheckAsrLifecycle()
    {
        AsrOptions check = AsrModule.Parse(new[] { "exclusion", "--check", "-Path", @"C:\Lab" });
        var backend = new FakeAsrBackend { Snapshot = EmptyAsrSnapshot() };
        var evidence = new AsrRunEvidence();
        int exitCode = AsrModule.RunWithBackend(check, evidence, backend);
        Assert(exitCode == 0 && !backend.Calls.Contains("Add"), "ASR exclusion check never calls Add");

        AsrOptions add = AsrModule.Parse(new[] { "exclusion", "-Path", @"C:\Lab" });
        AsrSnapshot before = EmptyAsrSnapshot();
        var after = new AsrSnapshot(new Dictionary<string, AsrAction>(StringComparer.OrdinalIgnoreCase),
            new List<string> { @"C:\Lab" }, before.AvExclusions);
        backend = new FakeAsrBackend { Snapshot = before, AfterSnapshot = after, Status = (uint)0 };
        evidence = new AsrRunEvidence();
        exitCode = AsrModule.RunWithBackend(add, evidence, backend);
        Assert(exitCode == 0 && evidence.Lifecycle.Restoration == RestorationStatus.ManualRequired,
            "ASR exclusion add confirmed with manual restoration");
        Assert(string.Join(",", backend.Calls) == "Connect,Prepare,Read,Add,Read", "ASR exclusion call order");
        Assert(evidence.Lifecycle.ManualRestoration.Contains("C:\\Lab") &&
            evidence.Lifecycle.ManualRestoration.Contains("Remove-MpPreference"),
            "ASR exclusion restoration names the newly-added path with an executable command");

        // R1: a request that mixes an already-existing baseline path with a genuinely new one must
        // list ONLY the new path for removal -- never a pre-existing, possibly-organizational entry.
        AsrOptions mixedAdd = AsrModule.Parse(new[] { "exclusion", "-Path", @"C:\OrgExisting", @"C:\New" });
        var mixedBefore = new AsrSnapshot(new Dictionary<string, AsrAction>(StringComparer.OrdinalIgnoreCase),
            new List<string> { @"C:\OrgExisting" }, EmptyAsrSnapshot().AvExclusions);
        var mixedAfter = new AsrSnapshot(new Dictionary<string, AsrAction>(StringComparer.OrdinalIgnoreCase),
            new List<string> { @"C:\OrgExisting", @"C:\New" }, EmptyAsrSnapshot().AvExclusions);
        backend = new FakeAsrBackend { Snapshot = mixedBefore, AfterSnapshot = mixedAfter, Status = (uint)0 };
        evidence = new AsrRunEvidence();
        exitCode = AsrModule.RunWithBackend(mixedAdd, evidence, backend);
        Assert(exitCode == 0 && evidence.Lifecycle.ManualRestoration.Contains(@"C:\New") &&
            !evidence.Lifecycle.ManualRestoration.Contains(@"C:\OrgExisting"),
            "ASR exclusion restoration lists only the newly-added path, never a pre-existing baseline path");

        // R1: when every requested path already existed, there is nothing new to remove.
        AsrOptions allExisting = AsrModule.Parse(new[] { "exclusion", "-Path", @"C:\OrgExisting" });
        backend = new FakeAsrBackend { Snapshot = mixedBefore, AfterSnapshot = mixedBefore, Status = (uint)0 };
        evidence = new AsrRunEvidence();
        exitCode = AsrModule.RunWithBackend(allExisting, evidence, backend);
        Assert(exitCode == 0 && evidence.Lifecycle.ManualRestoration.Contains("nothing new to remove"),
            "ASR exclusion restoration says so when every requested path already existed");

        // T1: an unquoted path with a space would be parsed as a separate positional argument by
        // PowerShell, and one containing '$' would have that treated as a variable to expand -- e.g.
        // "C:\Temp$Lab" silently becomes "C:\Temp", which could be a real, unrelated, pre-existing
        // exclusion. Every path in the printed command must be single-quoted (with '' escaping).
        AsrOptions trickyAdd = AsrModule.Parse(new[] { "exclusion", "-Path", @"C:\Lab Data", @"C:\Temp$Lab" });
        var trickyAfter = new AsrSnapshot(new Dictionary<string, AsrAction>(StringComparer.OrdinalIgnoreCase),
            new List<string> { @"C:\Lab Data", @"C:\Temp$Lab" }, EmptyAsrSnapshot().AvExclusions);
        backend = new FakeAsrBackend { Snapshot = EmptyAsrSnapshot(), AfterSnapshot = trickyAfter, Status = (uint)0 };
        evidence = new AsrRunEvidence();
        exitCode = AsrModule.RunWithBackend(trickyAdd, evidence, backend);
        Assert(exitCode == 0 && evidence.Lifecycle.ManualRestoration.Contains("'C:\\Lab Data'") &&
            evidence.Lifecycle.ManualRestoration.Contains("'C:\\Temp$Lab'"),
            "ASR exclusion restoration single-quotes every path (spaces and '$' cannot be left bare)");
        Assert(string.Join(",", AsrModule.QuotePowerShellPaths(new[] { @"O'Brien's" })) == "'O''Brien''s'",
            "QuotePowerShellPaths escapes an embedded single quote by doubling it");
        // U1: PowerShell's tokenizer also treats the Unicode "smart quote" variants as quote
        // characters -- real in copy-pasted folder names (e.g. from Office) -- so each must be
        // doubled exactly like an ASCII ' or the generated command fails to parse at all.
        Assert(string.Join(",", AsrModule.QuotePowerShellPaths(new[] { "C:\\Bob\u2019s Lab" })) ==
            "'C:\\Bob\u2019\u2019s Lab'",
            "QuotePowerShellPaths escapes U+2019 (right single quotation mark) the same way as ASCII '");
        Assert(string.Join(",", AsrModule.QuotePowerShellPaths(new[] { "\u2018\u2019\u201A\u201B" })) ==
            "'\u2018\u2018\u2019\u2019\u201A\u201A\u201B\u201B'",
            "QuotePowerShellPaths escapes every recognized smart-quote variant (U+2018/2019/201A/201B)");

        backend = new FakeAsrBackend { Snapshot = before, AfterSnapshot = before, Status = (uint)5 };
        evidence = new AsrRunEvidence();
        exitCode = AsrModule.RunWithBackend(add, evidence, backend);
        Assert(exitCode == 1, "ASR exclusion add explicit failure status");

        Guid ruleId = Guid.NewGuid();
        AsrOptions ruleCheck = AsrModule.Parse(new[] { "rule", "--check", "-RuleId", ruleId.ToString("D") });
        backend = new FakeAsrBackend { Snapshot = EmptyAsrSnapshot() };
        evidence = new AsrRunEvidence();
        exitCode = AsrModule.RunWithBackend(ruleCheck, evidence, backend);
        Assert(exitCode == 0 && !backend.Calls.Contains("Add"), "ASR rule check never calls Add");

        AsrOptions ruleSet = AsrModule.Parse(new[] { "rule", "-RuleId", ruleId.ToString("D"), "-Action", "Block" });
        AsrSnapshot ruleBefore = EmptyAsrSnapshot();
        var ruleAfterRules = new Dictionary<string, AsrAction>(StringComparer.OrdinalIgnoreCase)
            { { ruleId.ToString("D"), AsrAction.Block } };
        var ruleAfter = new AsrSnapshot(ruleAfterRules, new List<string>(), ruleBefore.AvExclusions);
        backend = new FakeAsrBackend { Snapshot = ruleBefore, AfterSnapshot = ruleAfter, Status = (uint)0 };
        evidence = new AsrRunEvidence();
        exitCode = AsrModule.RunWithBackend(ruleSet, evidence, backend);
        Assert(exitCode == 0 && evidence.Lifecycle.Restoration == RestorationStatus.ManualRequired &&
            evidence.Lifecycle.ManualRestoration.Contains("-Action NotConfigured"),
            "ASR rule set from NotConfigured documents an exact NotConfigured restore command");

        var priorRules = new Dictionary<string, AsrAction>(StringComparer.OrdinalIgnoreCase)
            { { ruleId.ToString("D"), AsrAction.Audit } };
        var priorSnapshot = new AsrSnapshot(priorRules, new List<string>(), ruleBefore.AvExclusions);
        backend = new FakeAsrBackend { Snapshot = priorSnapshot, AfterSnapshot = ruleAfter, Status = (uint)0 };
        evidence = new AsrRunEvidence();
        exitCode = AsrModule.RunWithBackend(ruleSet, evidence, backend);
        Assert(exitCode == 0 && evidence.Lifecycle.ManualRestoration.Contains("-Action Audit"),
            "ASR rule set from a prior action documents the exact restore command");

        // T6 / R2: requesting NotConfigured(5) may leave Defender with an explicit (guid, 5) entry, or
        // it may remove the entry entirely -- unobserved either way, and Microsoft documents both as
        // functionally unconfigured -- so readback must accept BOTH representations as Confirmed.
        AsrOptions ruleClear = AsrModule.Parse(new[] { "rule", "-RuleId", ruleId.ToString("D"), "-Action", "NotConfigured" });
        backend = new FakeAsrBackend { Snapshot = ruleAfter, AfterSnapshot = EmptyAsrSnapshot(), Status = (uint)0 };
        evidence = new AsrRunEvidence();
        exitCode = AsrModule.RunWithBackend(ruleClear, evidence, backend);
        Assert(exitCode == 0 && evidence.Lifecycle.Verification == VerificationStatus.Confirmed,
            "ASR rule NotConfigured readback is Confirmed when Defender removes the entry entirely");
        var explicitNotConfigured = new Dictionary<string, AsrAction>(StringComparer.OrdinalIgnoreCase)
            { { ruleId.ToString("D"), AsrAction.NotConfigured } };
        backend = new FakeAsrBackend { Snapshot = ruleAfter,
            AfterSnapshot = new AsrSnapshot(explicitNotConfigured, new List<string>(), ruleBefore.AvExclusions), Status = (uint)0 };
        evidence = new AsrRunEvidence();
        exitCode = AsrModule.RunWithBackend(ruleClear, evidence, backend);
        Assert(exitCode == 0 && evidence.Lifecycle.Verification == VerificationStatus.Confirmed,
            "ASR rule NotConfigured readback is also Confirmed when Defender keeps an explicit (guid, 5) entry");

        AsrOptions verifyCheck = AsrModule.Parse(new[] { "verify", "-RuleId", AsrRuleCatalog.JavaScriptOrVbScriptRuleId, "--check" });
        backend = new FakeAsrBackend { Snapshot = EmptyAsrSnapshot() };
        evidence = new AsrRunEvidence();
        exitCode = AsrModule.RunWithBackend(verifyCheck, evidence, backend);
        Assert(exitCode == 0 && evidence.Lifecycle.Restoration == RestorationStatus.NotRequired,
            "ASR verify check is read-only");

        // The redirection check is wired through the backend (fakeable), not a hardcoded static
        // registry call; --check never launches anything, so this is safe to exercise for real.
        backend = new FakeAsrBackend { Snapshot = EmptyAsrSnapshot(), NotepadRedirectionActive = true };
        evidence = new AsrRunEvidence();
        TextWriter originalOutForRedirect = Console.Out;
        using (var redirectOutput = new StringWriter())
        {
            try { Console.SetOut(redirectOutput); exitCode = AsrModule.RunWithBackend(verifyCheck, evidence, backend); }
            finally { Console.SetOut(originalOutForRedirect); }
            Assert(exitCode == 0 && redirectOutput.ToString().Contains("redirects notepad.exe"),
                "ASR verify surfaces the backend's redirection signal through Probe's own output");
        }

        AsrOptions verifyCustom = AsrModule.Parse(new[] {
            "verify", "-RuleId", Guid.NewGuid().ToString("D"), "-TestCommand", "cmd.exe", "-TestArguments", "/c exit 0" });
        backend = new FakeAsrBackend { Snapshot = EmptyAsrSnapshot() };
        evidence = new AsrRunEvidence();
        exitCode = AsrModule.RunWithBackend(verifyCustom, evidence, backend);
        // The ASR backend here is fake, but the process cleanup this exercises always queries real
        // Win32_Process regardless: on a host where that WMI query is itself restricted, cleanup
        // correctly reports Unavailable (never crashes into Failed, never falsely claims Succeeded) --
        // both outcomes are accepted here so this suite runs the real code path without requiring a
        // specific host WMI posture; only Failed (a genuine, unhandled regression) would fail this.
        Assert(evidence.Lifecycle.Verification == VerificationStatus.Unavailable &&
            (evidence.Lifecycle.Restoration == RestorationStatus.Succeeded ||
                evidence.Lifecycle.Restoration == RestorationStatus.Unavailable) &&
            (exitCode == 1 || exitCode == 3),
            "ASR verify with a custom command and no known child signature is unavailable, and restoration is " +
            "either confirmed or honestly unavailable depending on host WMI access, but never falsely Succeeded");

        // A non-administrator sees Defender's elevation sentinel, not a genuine empty exclusion list.
        // --check must not silently claim success over content it could not actually observe.
        var elevationGated = new AsrSnapshot(new Dictionary<string, AsrAction>(StringComparer.OrdinalIgnoreCase),
            new List<string>(), EmptyAsrSnapshot().AvExclusions, globalExclusionsRequireElevation: true);
        backend = new FakeAsrBackend { Snapshot = elevationGated };
        evidence = new AsrRunEvidence();
        exitCode = AsrModule.RunWithBackend(check, evidence, backend);
        Assert(exitCode == 3 && evidence.Lifecycle.Probe == ProbeStatus.ReadOnlyMismatch,
            "ASR exclusion check cannot claim success when Defender hides exclusion content non-elevated");

        backend = new FakeAsrBackend { Snapshot = before, AfterSnapshot = elevationGated, Status = (uint)0 };
        evidence = new AsrRunEvidence();
        exitCode = AsrModule.RunWithBackend(add, evidence, backend);
        Assert(exitCode == 3 && evidence.Lifecycle.Verification == VerificationStatus.Unavailable,
            "ASR exclusion Add readback cannot claim confirmation when Defender hides exclusion content");
    }

    // Synthetic IAsrReader/IAsrWriter and operation, used only to drive a real
    // ControlLifecycleResult<AsrBaseline> through the shared runner without ever launching the real
    // built-in primitive (which would open a real notepad.exe window on the host running this suite).
    private sealed class NullAsrReader : IAsrReader
    {
        public void Connect() { }
        public void Prepare(AsrMutationRequest request) { }
        public bool Supports(string name) { return true; }
        public AsrSnapshot Read() { return EmptyAsrSnapshot(); }
        public Dictionary<string, AsrPolicySourceKind> ReadPolicySource(IEnumerable<string> keys)
        { return new Dictionary<string, AsrPolicySourceKind>(StringComparer.OrdinalIgnoreCase); }
        public bool IsNotepadRedirectionActive() { return false; }
    }

    private sealed class NullAsrWriter : IAsrWriter { public object Add() { return null; } }

    private sealed class FakeAsrLifecycleOperation : IControlOperation<AsrBaseline, IAsrReader, IAsrWriter>
    {
        internal VerificationStatus RestoreOutcome = VerificationStatus.Confirmed;
        public string Transport { get { return "fake"; } }
        public bool VerifyAfterApiFailure { get { return false; } }
        public string ManualRestoration { get { return "n/a"; } }
        public ProbeResult<AsrBaseline> Probe(IAsrReader reader)
        { return new ProbeResult<AsrBaseline>(new AsrBaseline(EmptyAsrSnapshot(), null), ProbeStatus.Ready, RestorationPolicy.Automatic); }
        public MutationStatus Mutate(AsrBaseline baseline, IAsrWriter writer) { return MutationStatus.ApiSucceeded; }
        public VerificationStatus Verify(AsrBaseline baseline, IAsrReader reader) { return VerificationStatus.Confirmed; }
        public void Restore(AsrBaseline baseline, IAsrWriter writer) { }
        public VerificationStatus VerifyRestored(AsrBaseline baseline, IAsrReader reader) { return RestoreOutcome; }
    }

    // T2: on a host where the built-in primitive's target is redirected (confirmed present on this
    // development machine via IFEO/AppExecutionAlias), 'verify' cannot confirm cleanup and reports
    // Restoration=Unavailable. That must be its own outcome label, not a generic OPERATION_ERROR.
    private static void CheckAsrCleanupUnverifiableLabel()
    {
        var operation = new FakeAsrLifecycleOperation { RestoreOutcome = VerificationStatus.Unavailable };
        ControlLifecycleResult<AsrBaseline> result = ControlLifecycle.Run(operation, new NullAsrReader(), new NullAsrWriter(), null);
        Assert(result.Restoration == RestorationStatus.Unavailable && result.ExitCode == 1,
            "Synthetic ASR lifecycle reaches Restoration=Unavailable with exit 1, matching a redirected host");

        AsrOptions verifyOptions = AsrModule.Parse(new[] { "verify", "-RuleId", AsrRuleCatalog.JavaScriptOrVbScriptRuleId, "--verbose" });
        var evidence = new AsrRunEvidence { Lifecycle = result };
        TextWriter original = Console.Out;
        using (var output = new StringWriter())
        {
            try
            {
                Console.SetOut(output);
                AsrModule.PrintAssessment(verifyOptions, evidence, result.ExitCode);
                Assert(output.ToString().Contains("CLEANUP_UNVERIFIABLE") && !output.ToString().Contains("OPERATION_ERROR"),
                    "Unconfirmable cleanup is labeled distinctly, not as a generic operation error");
            }
            finally { Console.SetOut(original); }
        }
    }

    private static void CheckAsrPolicySourceAndCatalog()
    {
        Assert(AsrRuleCatalog.NameOf(AsrRuleCatalog.JavaScriptOrVbScriptRuleId).Contains("JavaScript"),
            "ASR catalog resolves a known rule name");
        Assert(AsrRuleCatalog.NameOf(Guid.NewGuid().ToString("D")) == "(unrecognized rule; verify against Microsoft Learn)",
            "ASR catalog is safe for unknown GUIDs");

        string ruleKey = Guid.NewGuid().ToString("D");
        Dictionary<string, AsrPolicySourceKind> sources = AsrRegistry.ReadPolicySource(
            new[] { ruleKey, AsrRegistry.GlobalExclusionsSourceKey });
        Assert(sources.ContainsKey(ruleKey) && sources.ContainsKey(AsrRegistry.GlobalExclusionsSourceKey),
            "ASR registry policy-source lookup returns every requested key without throwing");
    }

    // Deterministic coverage for the snapshot assembly shared by all three ASR backends: every
    // transport's raw readback shape (management/native return string[]/byte[]; COM returns
    // object[] of boxed string/Byte through IDispatch) must decode to the identical AsrSnapshot,
    // and a length mismatch or a non-singleton instance count must fail loudly, never guess.
    private static void CheckAsrSnapshotDecoding()
    {
        string ruleId = Guid.NewGuid().ToString("D");

        // management/native shape: string[] and a real uint/byte-typed Array.
        Dictionary<string, AsrAction> viaTyped = AsrModule.BuildRuleActions(
            new[] { ruleId }, new byte[] { (byte)AsrAction.Block });
        Assert(viaTyped.Count == 1 && viaTyped[ruleId] == AsrAction.Block, "BuildRuleActions decodes string[]/byte[]");

        // COM shape: SWbem hands back Object[] holding boxed CLR values, not typed arrays.
        Dictionary<string, AsrAction> viaBoxed = AsrModule.BuildRuleActions(
            new object[] { ruleId }, new object[] { (byte)AsrAction.Audit });
        Assert(viaBoxed.Count == 1 && viaBoxed[ruleId] == AsrAction.Audit, "BuildRuleActions decodes boxed object[] (COM shape)");

        Assert(AsrModule.BuildRuleActions(null, null).Count == 0, "BuildRuleActions treats null as empty, not an error");
        Assert(AsrModule.BuildRuleActions(DBNull.Value, DBNull.Value).Count == 0, "BuildRuleActions treats DBNull as empty");

        bool mismatchRejected = false;
        try { AsrModule.BuildRuleActions(new[] { ruleId, Guid.NewGuid().ToString("D") }, new byte[] { (byte)AsrAction.Block }); }
        catch (InvalidOperationException) { mismatchRejected = true; }
        Assert(mismatchRejected, "BuildRuleActions rejects Ids/Actions length mismatch instead of defaulting to Disabled");

        Assert(AsrModule.IsElevationPlaceholder(new[] { "N/A: elevation required" }), "Elevation sentinel recognized");
        Assert(!AsrModule.IsElevationPlaceholder(new[] { @"C:\Lab" }), "A real single path is not mistaken for the sentinel");
        Assert(!AsrModule.IsElevationPlaceholder(new string[0]), "An empty array is not mistaken for the sentinel");

        Assert(string.Join(",", AsrModule.DecodeStringArray(new object[] { ruleId, null })) == ruleId + ",",
            "DecodeStringArray accepts boxed object[] with a null element");
        bool badElement = false;
        try { AsrModule.DecodeStringArray(new object[] { (byte)1 }); }
        catch (InvalidOperationException) { badElement = true; }
        Assert(badElement, "DecodeStringArray rejects a non-string element");

        // A field func closing over one fixed record: exercises the shared assembly path every
        // transport's Read() now goes through, including the elevation-hidden AV branch.
        var fieldsRead = new List<string>();
        Func<string, object> field = delegate(string name)
        {
            fieldsRead.Add(name);
            if (name == "AttackSurfaceReductionRules_Ids") { return new[] { ruleId }; }
            if (name == "AttackSurfaceReductionRules_Actions") { return new byte[] { (byte)AsrAction.Warn }; }
            if (name == "AttackSurfaceReductionOnlyExclusions") { return new[] { @"C:\Lab" }; }
            return new[] { "N/A: elevation required" };
        };
        AsrSnapshot snapshot = AsrModule.BuildSnapshot(field);
        Assert(snapshot.Rules[ruleId] == AsrAction.Warn, "BuildSnapshot assembles rule actions");
        Assert(snapshot.GlobalExclusions.Count == 1 && snapshot.GlobalExclusions[0] == @"C:\Lab" &&
            !snapshot.GlobalExclusionsRequireElevation, "BuildSnapshot assembles visible global exclusions");
        Assert(snapshot.AvExclusionsRequireElevation, "BuildSnapshot marks the AV exclusion sentinel as unobservable, not empty");
        foreach (string type in AsrModule.AvExclusionTypes)
        { Assert(snapshot.AvExclusions[type].Count == 0, "Elevation-hidden AV exclusion never surfaces the sentinel text: " + type); }

        Assert(!ThrowsInvalidOperation(delegate { AsrModule.RequireSingleInstance(1); }), "Exactly one instance is accepted");
        Assert(ThrowsInvalidOperation(delegate { AsrModule.RequireSingleInstance(0); }), "Zero instances must not read as absent");
        Assert(ThrowsInvalidOperation(delegate { AsrModule.RequireSingleInstance(2); }), "Multiple instances must not be silently merged");

        fieldsRead.Clear();
        bool zeroRejectedWithInstanceMessage = false;
        try { AsrModule.ReadSnapshot(new Func<string, object>[0]); }
        catch (InvalidOperationException ex)
        { zeroRejectedWithInstanceMessage = ex.Message.IndexOf("instance", StringComparison.OrdinalIgnoreCase) >= 0; }
        Assert(zeroRejectedWithInstanceMessage && fieldsRead.Count == 0,
            "ReadSnapshot rejects zero instances with a specific error before reading fields");

        AsrSnapshot guarded = AsrModule.ReadSnapshot(new[] { field });
        Assert(guarded.Rules[ruleId] == AsrAction.Warn && fieldsRead.Count == 3 + AsrModule.AvExclusionTypes.Length,
            "ReadSnapshot reads and assembles exactly one instance");

        fieldsRead.Clear();
        Assert(ThrowsInvalidOperation(delegate { AsrModule.ReadSnapshot(new[] { field, field }); }) && fieldsRead.Count == 0,
            "ReadSnapshot rejects multiple instances before reading any fields");
    }

    private static void CheckNativeSetterTypeGate()
    {
        // The type gate runs before session validation. A cross-typed property must return
        // WBEM_E_TYPE_MISMATCH; a correctly typed property with no session returns E_INVALIDARG.
        // Deleting either gate changes its result to E_INVALIDARG, so CI detects the regression.
        const int typeMismatch = unchecked((int)0x80041005);
        const int invalidArgument = unchecked((int)0x80070057);
        Assert(NativeSetValues(IntPtr.Zero, "AttackSurfaceReductionRules_Actions", new[] { "1" }, 1) == typeMismatch,
            "Native string setter rejects the byte array property before session validation");
        Assert(NativeSetByteValues(IntPtr.Zero, "AttackSurfaceReductionRules_Ids", new byte[] { 1 }, 1) == typeMismatch,
            "Native byte setter rejects the string array property before session validation");
        Assert(NativeSetValues(IntPtr.Zero, "AttackSurfaceReductionRules_Ids", new[] { "id" }, 1) == invalidArgument,
            "Native string setter accepts the Ids property type and then checks the session");
        Assert(NativeSetByteValues(IntPtr.Zero, "AttackSurfaceReductionRules_Actions", new byte[] { 1 }, 1) == invalidArgument,
            "Native byte setter accepts the Actions property type and then checks the session");
    }

    private static bool ThrowsInvalidOperation(Action action)
    {
        try { action(); return false; }
        catch (InvalidOperationException) { return true; }
    }

    private static void CheckAsrTelemetry()
    {
        string ruleId = Guid.NewGuid().ToString("D");
        AsrOptions options = AsrModule.Parse(new[] { "rule", "--check", "-RuleId", ruleId });
        TelemetryEvidence.ParsedEvent blocked = TelemetryEvidence.Parse(EventXml("Microsoft-Windows-Windows Defender", 1121,
            "<EventData><Data Name='ID'>" + ruleId + "</Data></EventData>"));
        Assert(TelemetryEvidence.Correlate(blocked, options, 1234).StartsWith("REQUEST_VALUE_MATCH"),
            "ASR block event correlates on rule GUID substring");
        TelemetryEvidence.ParsedEvent unrelatedBlocked = TelemetryEvidence.Parse(EventXml("Microsoft-Windows-Windows Defender", 1121,
            "<EventData><Data Name='ID'>" + Guid.NewGuid().ToString("D") + "</Data></EventData>"));
        Assert(TelemetryEvidence.Correlate(unrelatedBlocked, options, 1234) ==
            "ASR_EVENT_TIME_ONLY: an ASR block/audit event fired in the window; value not matched to this rule/path.",
            "Unrelated ASR block event is time-only, not a match");
        TelemetryEvidence.ParsedEvent wmi = TelemetryEvidence.Parse(EventXml("Microsoft-Windows-WMI-Activity", 5858,
            "<UserData><Operation xmlns='urn:wmi'><ClientProcessId>1234</ClientProcessId></Operation></UserData>"));
        Assert(TelemetryEvidence.Correlate(wmi, options, 1234).StartsWith("PID_MATCH"), "ASR WMI client PID correlates");
        Assert(TelemetryEvidence.Correlate(wmi, options, 4321) == null, "ASR WMI different PID excluded");
        var firewallOptions = new TestControlOptions { Kind = ControlKind.FirewallRule };
        Assert(TelemetryEvidence.Correlate(blocked, firewallOptions, 1234) == null, "No ASR events attributed to Firewall profile");
        Assert(AsrTelemetry.Profile.EventLogChannels.Count == 4, "ASR profile owns its channel list");
        Assert(AsrTelemetry.Profile.EtwProviders.Count == 2, "ASR profile owns its ETW providers");
        Assert(AsrTelemetry.Profile.DisplayField("Process Name") && AsrTelemetry.Profile.DisplayField("Path") &&
            AsrTelemetry.Profile.DisplayField("Target Commandline"),
            "ASR profile displays its own 1121/1122 template fields, not just generic Defender fields");
    }

    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    private static extern SafeFileHandle CreateFileW(string lpFileName, uint dwDesiredAccess, uint dwShareMode,
        IntPtr lpSecurityAttributes, uint dwCreationDisposition, uint dwFlagsAndAttributes, IntPtr hTemplateFile);

    // Managed File/FileInfo APIs go through the same legacy path validation that broke the
    // production ADS write (B2); reading the stream back must bypass it the same way Production does.
    private static bool AlternateStreamExists(string streamPath)
    {
        const uint GenericRead = 0x80000000;
        const uint FileShareRead = 1;
        const uint OpenExisting = 3;
        SafeFileHandle handle = CreateFileW(streamPath, GenericRead, FileShareRead, IntPtr.Zero, OpenExisting, 0, IntPtr.Zero);
        bool exists = !handle.IsInvalid;
        handle.Dispose();
        return exists;
    }

    private static void CheckAsrBuiltInPrimitive()
    {
        Assert(AsrPropertySchema.ExpectedType("AttackSurfaceReductionRules_Actions") == CimType.UInt8,
            "ASR Actions property is UInt8Array (Add-MpPreference's own action enum is byte-sized), not UInt32");
        Assert(AsrPropertySchema.ExpectedType("AttackSurfaceReductionRules_Ids") == CimType.String,
            "ASR Ids property is StringArray");
        Assert(AsrPropertySchema.ExpectedType("AttackSurfaceReductionOnlyExclusions") == CimType.String,
            "ASR OnlyExclusions property is StringArray");

        string directory = Path.Combine(Path.GetTempPath(), "WtfAsrArtifactTest-" + Guid.NewGuid().ToString("D"));
        string filePath = Path.Combine(directory, "test.js");
        try
        {
            AsrModule.CreateTestArtifact(directory, filePath);
            Assert(File.Exists(filePath), "ASR test artifact file was created");
            Assert(File.ReadAllText(filePath).Contains("notepad.exe"), "ASR test artifact contains the expected payload");
            Assert(AlternateStreamExists(filePath + ":Zone.Identifier"),
                "ASR test artifact has a real Zone.Identifier alternate data stream, not a silently-swallowed write");
        }
        finally { if (Directory.Exists(directory)) { Directory.Delete(directory, true); } }

        // Fault injection through the REAL path: run 'verify' with the built-in primitive end to end
        // via RunWithBackend (not a hand-rolled call to CreateTestArtifact), with the artifact file's
        // path pre-occupied by a directory so MutateVerify's write fails partway through. This is the
        // actual production sequence Mutate -> (throws) -> Restore -> VerifyRestored, so it fails if
        // 'createdArtifact' regresses back to being set only after both writes succeed.
        AsrOptions verifyBuiltIn = AsrModule.Parse(new[] { "verify", "-RuleId", AsrRuleCatalog.JavaScriptOrVbScriptRuleId });
        var faultEvidence = new AsrRunEvidence();
        string expectedDirectory = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
            "WinTraceForge", "AsrTests", faultEvidence.RunId);
        Directory.CreateDirectory(Path.Combine(expectedDirectory, "test.js"));
        var faultBackend = new FakeAsrBackend { Snapshot = EmptyAsrSnapshot() };
        int faultExitCode = AsrModule.RunWithBackend(verifyBuiltIn, faultEvidence, faultBackend);
        Assert(faultExitCode == 1 && faultEvidence.Lifecycle.Mutation == MutationStatus.ApiFailed,
            "ASR verify surfaces a partial artifact-creation failure as a real mutation failure, not silent success");
        Assert(faultEvidence.Lifecycle.Restoration == RestorationStatus.Succeeded,
            "ASR verify still restores cleanly after a partial artifact-creation failure");
        Assert(!Directory.Exists(expectedDirectory),
            "The partially created ASR artifact directory was actually removed by the real Restore path");

        var table = new[]
        {
            new { Action = AsrAction.Block, Observed = true, Expected = VerificationStatus.Mismatch },
            new { Action = AsrAction.Block, Observed = false, Expected = VerificationStatus.Unavailable },
            new { Action = AsrAction.Warn, Observed = true, Expected = VerificationStatus.Mismatch },
            new { Action = AsrAction.Warn, Observed = false, Expected = VerificationStatus.Unavailable },
            new { Action = AsrAction.Audit, Observed = true, Expected = VerificationStatus.Unavailable },
            new { Action = AsrAction.Audit, Observed = false, Expected = VerificationStatus.Unavailable },
            new { Action = AsrAction.Disabled, Observed = true, Expected = VerificationStatus.Unavailable },
            new { Action = AsrAction.NotConfigured, Observed = true, Expected = VerificationStatus.Unavailable }
        };
        foreach (var row in table)
        {
            VerificationStatus actual = AsrModule.EvaluateTestOutcome(row.Action, row.Observed);
            Assert(actual == row.Expected,
                "ASR outcome decision (" + row.Action + ", observed=" + row.Observed + ") -> " + row.Expected);
        }
        foreach (AsrAction action in (AsrAction[])Enum.GetValues(typeof(AsrAction)))
        {
            Assert(AsrModule.EvaluateTestOutcome(action, true) != VerificationStatus.Confirmed &&
                AsrModule.EvaluateTestOutcome(action, false) != VerificationStatus.Confirmed,
                "ASR outcome decision never returns Confirmed from local process observation alone: " + action);
        }

        // A same-named process that isn't a child of the exact launcher PID must never be selected
        // (this is what previously let an unrelated user notepad.exe get killed/miscounted), and a
        // same-PPID/same-name process created BEFORE the launcher started must also be excluded --
        // that combination can only occur when the launcher's PID was already reused by the OS.
        DateTime launcherStart = new DateTime(2026, 1, 1, 12, 0, 0);
        Assert(AsrModule.IsOwnedChildProcess(100, "notepad.exe", launcherStart.AddSeconds(1), 100, "notepad.exe", launcherStart),
            "Owned: correct parent PID, correct image, created after the launcher started");
        Assert(!AsrModule.IsOwnedChildProcess(999, "notepad.exe", launcherStart.AddSeconds(1), 100, "notepad.exe", launcherStart),
            "Not owned: different parent PID (an unrelated process with the same image name)");
        Assert(!AsrModule.IsOwnedChildProcess(100, "calc.exe", launcherStart.AddSeconds(1), 100, "notepad.exe", launcherStart),
            "Not owned: different image name");
        Assert(!AsrModule.IsOwnedChildProcess(100, "notepad.exe", launcherStart.AddSeconds(-1), 100, "notepad.exe", launcherStart),
            "Not owned: created before the launcher started (PID reuse of an already-exited launcher)");
        Assert(AsrModule.IsOwnedChildProcess(100, "NOTEPAD.EXE", launcherStart, 100, "notepad.exe", launcherStart),
            "Owned: image name comparison is case-insensitive");
        // Restore/VerifyRestored pass null for "any image name" (a custom -TestCommand's children
        // have no known expected name at all, and this also catches anything unexpected the built-in
        // primitive's launcher spawned); parent PID and creation-time ordering still must hold.
        Assert(AsrModule.IsOwnedChildProcess(100, "anything.exe", launcherStart.AddSeconds(1), 100, null, launcherStart),
            "Owned (any-name mode): correct parent PID and created after the launcher is sufficient");
        Assert(!AsrModule.IsOwnedChildProcess(999, "anything.exe", launcherStart.AddSeconds(1), 100, null, launcherStart),
            "Not owned (any-name mode): wrong parent PID is still excluded");

        // Killing by PID alone races with PID reuse: only a freshly-opened handle whose own StartTime
        // matches what WMI recorded at query time may actually be terminated.
        DateTime recorded = new DateTime(2026, 1, 1, 12, 0, 0, 123);
        Assert(AsrModule.IsSameProcessInstance(recorded, recorded), "Same instance: identical timestamps");
        Assert(AsrModule.IsSameProcessInstance(recorded, recorded.AddMilliseconds(1)),
            "Same instance: within WMI's microsecond-vs-FILETIME rounding tolerance");
        Assert(!AsrModule.IsSameProcessInstance(recorded, recorded.AddSeconds(5)),
            "Different instance: a PID reused by an unrelated process created seconds later is rejected");
        Assert(!AsrModule.IsSameProcessInstance(recorded, recorded.AddSeconds(-5)),
            "Different instance: a completely different creation time is rejected");
    }

    private static void CheckAsrArchitecture()
    {
        Type read = typeof(IAsrReader);
        Type write = typeof(IAsrWriter);
        Assert(read.GetMethod("Add") == null && write.GetMethod("Add") != null, "ASR read capability cannot Add");
        Type operation = typeof(AsrModule).GetNestedType("AsrOperation", BindingFlags.NonPublic);
        Assert(operation != null, "ASR operation exists");
        foreach (FieldInfo field in operation.GetFields(BindingFlags.Instance | BindingFlags.NonPublic))
        {
            Assert(!typeof(IAsrBackend).IsAssignableFrom(field.FieldType) && !write.IsAssignableFrom(field.FieldType),
                "ASR operation retains no mutable backend");
        }
        Assert(operation.GetMethod("Probe").GetParameters()[0].ParameterType == read &&
            operation.GetMethod("Verify").GetParameters()[1].ParameterType == read &&
            operation.GetMethod("Mutate").GetParameters()[1].ParameterType == write,
            "ASR phase signatures fence writes");
    }

    private sealed class SyntheticBaseline
    {
        internal readonly string Original = "original";
    }

    private interface ISyntheticReader { string Read(); }
    private interface ISyntheticWriter { void Write(); }
    private sealed class SyntheticReader : ISyntheticReader
    { public string Read() { return "original"; } }
    private sealed class SyntheticWriter : ISyntheticWriter
    { internal int Writes; public void Write() { Writes++; } }
    private sealed class CombinedSyntheticBackend : ISyntheticReader, ISyntheticWriter
    {
        public string Read() { return "original"; }
        public void Write() { }
    }

    private sealed class SyntheticOperation : IControlOperation<SyntheticBaseline, ISyntheticReader, ISyntheticWriter>
    {
        internal readonly List<string> Calls = new List<string>();
        internal ProbeStatus ProbeOutcome = ProbeStatus.Ready;
        internal RestorationPolicy Policy = RestorationPolicy.Automatic;
        internal MutationStatus ApiOutcome = MutationStatus.ApiSucceeded;
        internal VerificationStatus VerifyOutcome = VerificationStatus.Confirmed;
        internal VerificationStatus RestoreOutcome = VerificationStatus.Confirmed;
        internal bool FailProbe, FailMutation, FailVerification, FailRestore;
        internal bool ReadAfterFailure = true;
        public string Transport { get { return "synthetic"; } }
        public bool VerifyAfterApiFailure { get { return ReadAfterFailure; } }
        public string ManualRestoration { get { return "Restore synthetic baseline original."; } }
        public ProbeResult<SyntheticBaseline> Probe(ISyntheticReader reader)
        {
            Calls.Add("probe");
            Assert(reader.Read() == "original", "Probe receives read capability");
            if (FailProbe) { throw new InvalidOperationException("probe failed"); }
            return new ProbeResult<SyntheticBaseline>(new SyntheticBaseline(), ProbeOutcome,
                ProbeOutcome == ProbeStatus.Ready ? Policy : RestorationPolicy.None);
        }
        public MutationStatus Mutate(SyntheticBaseline baseline, ISyntheticWriter writer)
        {
            Calls.Add("mutate");
            Assert(baseline.Original == "original", "Typed baseline reaches mutation");
            writer.Write();
            if (FailMutation) { throw new InvalidOperationException("write failed"); }
            return ApiOutcome;
        }
        public VerificationStatus Verify(SyntheticBaseline baseline, ISyntheticReader reader)
        {
            Calls.Add("verify");
            Assert(reader.Read() == "original", "Verify receives read capability");
            if (FailVerification) { throw new InvalidOperationException("readback failed"); }
            return VerifyOutcome;
        }
        public void Restore(SyntheticBaseline baseline, ISyntheticWriter writer)
        {
            Calls.Add("restore");
            Assert(baseline.Original == "original", "Restoration uses captured baseline");
            writer.Write();
            if (FailRestore) { throw new InvalidOperationException("restore failed"); }
        }
        public VerificationStatus VerifyRestored(SyntheticBaseline baseline, ISyntheticReader reader)
        { Calls.Add("verify-restored"); Assert(reader.Read() == "original", "Restore verification receives read capability"); return RestoreOutcome; }
    }

    private static ControlLifecycleResult<SyntheticBaseline> RunSynthetic(SyntheticOperation operation,
        Func<IControlLifecycleSnapshot, ObservationStatus> observe)
    { return ControlLifecycle.Run(operation, new SyntheticReader(), new SyntheticWriter(), observe); }

    private static void CheckLifecycle()
    {
        var operation = new SyntheticOperation { FailProbe = true };
        ControlLifecycleResult<SyntheticBaseline> result = RunSynthetic(operation, null);
        Assert(result.ExitCode == 1 && result.Probe == ProbeStatus.Failed &&
            result.Mutation == MutationStatus.NotAttempted && string.Join(",", operation.Calls) == "probe",
            "Failed mandatory probe never mutates");

        operation = new SyntheticOperation { ProbeOutcome = ProbeStatus.ReadOnlyConfirmed };
        result = RunSynthetic(operation, null);
        Assert(result.ExitCode == 0 && result.Restoration == RestorationStatus.NotRequired &&
            string.Join(",", operation.Calls) == "probe", "Read-only probe never invokes a write");

        operation = new SyntheticOperation { ProbeOutcome = ProbeStatus.ReadOnlyMismatch };
        result = RunSynthetic(operation, null);
        Assert(result.ExitCode == 3 && result.Mutation == MutationStatus.NotAttempted,
            "Read-only expected-state mismatch is preserved");

        operation = new SyntheticOperation { VerifyOutcome = VerificationStatus.Mismatch };
        result = RunSynthetic(operation, null);
        Assert(result.ExitCode == 3 && result.Mutation == MutationStatus.ApiSucceeded &&
            result.Verification == VerificationStatus.Mismatch && result.Restoration == RestorationStatus.Succeeded,
            "API success cannot override verification mismatch");

        operation = new SyntheticOperation();
        result = RunSynthetic(operation, delegate(IControlLifecycleSnapshot current)
        {
            Assert(current.Verification == VerificationStatus.Confirmed, "Observation sees control result");
            Assert(!((object)current is ControlLifecycleResult<SyntheticBaseline>) &&
                current.GetType().GetProperty("Baseline", BindingFlags.Public | BindingFlags.NonPublic | BindingFlags.Instance) == null,
                "Observer has no baseline or mutable result");
            operation.Calls.Add("observe");
            throw new InvalidOperationException("collector crashed");
        });
        Assert(result.ExitCode == 0 && result.Observation == ObservationStatus.Failed &&
            result.Restoration == RestorationStatus.Succeeded &&
            string.Join(",", operation.Calls) == "probe,mutate,verify,observe,restore,verify-restored",
            "Telemetry failure preserves control truth and cannot prevent restoration");

        operation = new SyntheticOperation { FailRestore = true };
        result = RunSynthetic(operation, null);
        Assert(result.ExitCode == 1 && result.Verification == VerificationStatus.Confirmed &&
            result.Restoration == RestorationStatus.Failed, "Restoration failure remains separate and visible");

        operation = new SyntheticOperation { RestoreOutcome = VerificationStatus.Unavailable };
        result = RunSynthetic(operation, null);
        Assert(result.ExitCode == 1 && result.Restoration == RestorationStatus.Unavailable,
            "Restore API return is not restore verification");

        operation = new SyntheticOperation { RestoreOutcome = VerificationStatus.Mismatch };
        result = RunSynthetic(operation, null);
        Assert(result.ExitCode == 1 && result.Restoration == RestorationStatus.Failed,
            "Restore readback mismatch is a restoration failure");

        operation = new SyntheticOperation { FailVerification = true };
        result = RunSynthetic(operation, null);
        Assert(result.ExitCode == 3 && result.Verification == VerificationStatus.Unavailable &&
            result.Restoration == RestorationStatus.Succeeded, "Verification exception still restores");

        operation = new SyntheticOperation { FailMutation = true };
        result = RunSynthetic(operation, null);
        Assert(result.ExitCode == 1 && result.Mutation == MutationStatus.ApiFailed &&
            result.Verification == VerificationStatus.Confirmed && result.Restoration == RestorationStatus.Succeeded,
            "Ambiguous mutation failure can be read back and restored");

        operation = new SyntheticOperation { ApiOutcome = MutationStatus.ApiFailed, ReadAfterFailure = false,
            Policy = RestorationPolicy.Manual };
        result = RunSynthetic(operation, null);
        Assert(result.ExitCode == 1 && result.Verification == VerificationStatus.NotRun &&
            result.Restoration == RestorationStatus.ManualRequired,
            "Legacy failed API skips readback but preserves manual restoration requirement");

        operation = new SyntheticOperation();
        result = RunSynthetic(operation,
            delegate(IControlLifecycleSnapshot current) { return ObservationStatus.Incomplete; });
        Assert(result.ExitCode == 0 && result.Observation == ObservationStatus.Incomplete &&
            result.Restoration == RestorationStatus.Succeeded,
            "Incomplete telemetry is not a control failure");

        operation = new SyntheticOperation { Policy = RestorationPolicy.Manual, ApiOutcome = MutationStatus.ApiUnknown };
        result = RunSynthetic(operation, null);
        Assert(result.ExitCode == 0 && result.Mutation == MutationStatus.ApiUnknown &&
            result.Verification == VerificationStatus.Confirmed &&
            result.Restoration == RestorationStatus.ManualRequired &&
            !operation.Calls.Contains("restore"), "Unknown API status needs readback and explicit manual cleanup");

        operation = new SyntheticOperation { Policy = RestorationPolicy.None };
        result = RunSynthetic(operation, null);
        Assert(result.ExitCode == 1 && result.Mutation == MutationStatus.NotAttempted,
            "Mutating probe cannot omit restoration policy");

        operation = new SyntheticOperation();
        var writer = new SyntheticWriter();
        result = ControlLifecycle.Run(operation, new SyntheticReader(), writer, null);
        Assert(writer.Writes == 2 && result.Restoration == RestorationStatus.Succeeded,
            "Runner provides write capability for mutation and restoration");
        bool combinedRejected = false;
        try
        {
            var combined = new CombinedSyntheticBackend();
            ControlLifecycle.Run(operation, (ISyntheticReader)combined, (ISyntheticWriter)combined, null);
        }
        catch (ArgumentException) { combinedRejected = true; }
        Assert(combinedRejected, "Runner rejects a reader that also exposes writes");
    }

    private static void CheckArchitecture()
    {
        Type read = typeof(DefenderModule.IPreferenceReader);
        Type write = typeof(DefenderModule.IPreferenceWriter);
        Assert(read.GetMethod("Add") == null && write.GetMethod("Add") != null,
            "Defender read capability cannot Add");
        Assert(typeof(IFirewallReader).GetMethod("Add") == null &&
            typeof(IFirewallReader).GetMethod("Remove") == null &&
            typeof(IFirewallWriter).GetMethod("Add") != null &&
            typeof(IFirewallWriter).GetMethod("Remove") != null,
            "Firewall read capability cannot mutate");
        foreach (string name in new[] { "DefenderOperation" })
        {
            Type operation = typeof(DefenderModule).GetNestedType(name, BindingFlags.NonPublic);
            Assert(operation != null, "Defender operation exists");
            foreach (FieldInfo field in operation.GetFields(BindingFlags.Instance | BindingFlags.NonPublic))
            {
                Assert(!typeof(DefenderModule.IPreferenceBackend).IsAssignableFrom(field.FieldType) &&
                    !write.IsAssignableFrom(field.FieldType), "Defender operation retains no mutable backend");
            }
            Assert(operation.GetMethod("Probe").GetParameters()[0].ParameterType == read &&
                operation.GetMethod("Verify").GetParameters()[1].ParameterType == read &&
                operation.GetMethod("Mutate").GetParameters()[1].ParameterType == write,
                "Defender phase signatures fence writes");
        }
        Type firewall = typeof(FirewallModule).GetNestedType("FirewallOperation", BindingFlags.NonPublic);
        Assert(firewall != null, "Firewall operation exists");
        foreach (FieldInfo field in firewall.GetFields(BindingFlags.Instance | BindingFlags.NonPublic))
        {
            Assert(!typeof(IFirewallBackend).IsAssignableFrom(field.FieldType) &&
                !typeof(IFirewallWriter).IsAssignableFrom(field.FieldType),
                "Firewall operation retains no mutable backend");
        }
        Assert(firewall.GetMethod("Probe").GetParameters()[0].ParameterType == typeof(IFirewallReader) &&
            firewall.GetMethod("Verify").GetParameters()[1].ParameterType == typeof(IFirewallReader) &&
            firewall.GetMethod("Mutate").GetParameters()[1].ParameterType == typeof(IFirewallWriter),
            "Firewall phase signatures fence writes");
        foreach (PropertyInfo property in typeof(IControlLifecycleSnapshot).GetProperties())
        { Assert(property.GetSetMethod() == null, "Observation snapshot is read-only"); }
        foreach (PropertyInfo property in typeof(ControlLifecycleResult<SyntheticBaseline>).GetProperties(
            BindingFlags.Public | BindingFlags.NonPublic | BindingFlags.Instance))
        { Assert(property.GetSetMethod(true) == null || property.GetSetMethod(true).IsPrivate,
            "Lifecycle result has no externally callable setter"); }
        Assert(typeof(ControlLifecycleResult<SyntheticBaseline>).GetConstructors(
            BindingFlags.Public | BindingFlags.NonPublic | BindingFlags.Instance)[0].IsPrivate,
            "Only lifecycle result runtime can construct lifecycle truth");
    }

    private static void CheckTransportsAndAssessment()
    {
        TextWriter originalOut = Console.Out;
        TextWriter originalError = Console.Error;
        using (var output = new StringWriter())
        using (var error = new StringWriter())
        {
            try
            {
                Console.SetOut(output);
                Console.SetError(error);
                foreach (string transport in new[] { "management", "com", "native" })
                {
                    DefenderModule.Options options = DefenderModule.ParseArguments(new[]
                    {
                        "--transport", transport, "-ExclusionPath", "C:\\Lab",
                        "-ExclusionExtension", ".lablog"
                    });
                    var present = options.Exclusions;
                    var absent = new Dictionary<string, List<string>>(StringComparer.OrdinalIgnoreCase)
                    {
                        { "ExclusionPath", new List<string>() },
                        { "ExclusionExtension", new List<string>() }
                    };
                    var backend = new FakeBackend { Before = absent, After = present, Status = null };
                    var evidence = new DefenderModule.RunEvidence();
                    int exitCode = DefenderModule.RunWithBackend(options, evidence, backend);
                    Assert(exitCode == 0 && evidence.AddAttempted && evidence.AddReturned,
                        "Missing status still requires confirmed readback");
                    Assert(evidence.AllPresentBefore == false, "Baseline absence retained");
                    Assert(string.Join(",", backend.Calls) == "Connect,Prepare,Read,Add,Read",
                        "Baseline before exactly one Add and post-read");
                    CheckAssessment(output, options, evidence, exitCode, "CONFIGURATION_CONFIRMED");

                    backend = new FakeBackend { Before = present, After = present, Status = (uint)0 };
                    evidence = new DefenderModule.RunEvidence();
                    exitCode = DefenderModule.RunWithBackend(options, evidence, backend);
                    Assert(exitCode == 0 && evidence.AllPresentBefore == true, "Pre-existing baseline");
                    CheckAssessment(output, options, evidence, exitCode, "CONFIGURATION_CONFIRMED_PREEXISTING");
                    Assert(output.ToString().Contains("no new configuration transition"), "No new change claimed");

                    backend = new FakeBackend { Before = absent, After = absent, Status = (uint)0 };
                    evidence = new DefenderModule.RunEvidence();
                    exitCode = DefenderModule.RunWithBackend(options, evidence, backend);
                    Assert(exitCode == 3, "Accepted but not observed must be unconfirmed");
                    CheckAssessment(output, options, evidence, exitCode, "UNCONFIRMED");

                    backend = new FakeBackend { Before = absent, After = present, Status = (uint)5 };
                    evidence = new DefenderModule.RunEvidence();
                    exitCode = DefenderModule.RunWithBackend(options, evidence, backend);
                    Assert(exitCode == 1, "Explicit nonzero status must fail");
                    Assert(string.Join(",", backend.Calls) == "Connect,Prepare,Read,Add",
                        "Error must not fall back to another Add");
                    CheckAssessment(output, options, evidence, exitCode, "OPERATION_ERROR");

                    foreach (string failure in new[] { "Connect", "Prepare", "Read", "Add" })
                    {
                        backend = new FakeBackend { Before = absent, After = present, ThrowAt = failure };
                        evidence = new DefenderModule.RunEvidence();
                        int failedCode = DefenderModule.RunWithBackend(options, evidence, backend);
                        Assert(failedCode == 1 && evidence.Lifecycle.Errors.Count == 1,
                            "Failure is captured in the lifecycle result: " + failure);
                        Assert(evidence.AddAttempted == (failure == "Add"), "Accurate Add attempt evidence");
                        Assert(!evidence.AddReturned, "Failed operation cannot report returned Add");
                        Assert(backend.Calls.FindAll(delegate(string call) { return call == "Add"; }).Count <= 1,
                            "No retry or fallback");
                        CheckAssessment(output, options, evidence, 1,
                            failure == "Add" ? "OPERATION_ERROR" : "NOT_ATTEMPTED");
                    }

                    options.CheckOnly = true;
                    backend = new FakeBackend { Before = absent, After = present };
                    evidence = new DefenderModule.RunEvidence();
                    exitCode = DefenderModule.RunWithBackend(options, evidence, backend);
                    Assert(exitCode == 0 && !evidence.AddAttempted && !backend.Calls.Contains("Add"),
                        "Check must never invoke Add");
                    Assert(backend.Calls.Contains("Read"), "Parameterized check exercises readback");
                    CheckAssessment(output, options, evidence, exitCode, "CHECK_ONLY");

                    options = DefenderModule.ParseArguments(new[] { "--transport", transport, "--check" });
                    backend = new FakeBackend();
                    evidence = new DefenderModule.RunEvidence();
                    exitCode = DefenderModule.RunWithBackend(options, evidence, backend);
                    Assert(exitCode == 0 && !backend.Calls.Contains("Add") && !backend.Calls.Contains("Read"),
                        "Metadata-only check has no default query or Add");
                }
            }
            finally
            {
                Console.SetOut(originalOut);
                Console.SetError(originalError);
            }
        }
    }

    private static void CheckAssessment(StringWriter output, DefenderModule.Options options,
        DefenderModule.RunEvidence evidence, int exitCode, string outcome)
    {
        output.GetStringBuilder().Clear();
        options.Verbose = true;
        DefenderModule.PrintAssessment(options, evidence, exitCode);
        string report = Normalize(output.ToString());
        Assert(report.Contains("Outcome: " + outcome), "Assessment outcome: " + outcome);
        Assert(report.Contains("Compliance: NOT_ASSESSED"), "No invented compliance verdict");
        Assert(report.Contains("Detection/response: NOT_MEASURED"), "No invented detection result");
        Assert(report.Contains("Event 5007") && report.Contains("Event 5013"), "Defender event guidance");
        Assert(report.Contains("Security 4688") && report.Contains("Sysmon 1"), "Process correlation guidance");
        Assert(report.Contains("No automatic cleanup") && report.Contains("preserve pre-existing entries"),
            "Controlled cleanup guidance");
        Assert(report.Contains("not a complete successful-method audit trail"), "WMI telemetry limits");
        Assert(report.Contains("Transport: " + options.Transport) && report.Contains(evidence.RunId),
            "Transport and run correlation");
        options.Verbose = false;
    }

    private static string Normalize(string text)
    {
        return Regex.Replace(text, @"\s+", " ").Trim();
    }

    private static void CheckConsoleLayout()
    {
        foreach (int width in new[] { 40, 64, 100, 110 })
        {
            foreach (string text in new[] {
                "A normal sentence with spaces that should wrap without losing words.",
                "C:\\" + new string('x', 180), "", "Line one\r\nLine two\tTabbed"
            })
            {
                string reconstructed = "";
                foreach (string line in ConsoleUi.Wrap(text, "  ", "  ", width))
                {
                    Assert(line.Length <= width, "Wrapped line width " + width);
                    reconstructed += line.Substring(2);
                }
                Assert(Regex.Replace(reconstructed, @"\s+", "") == Regex.Replace(text, @"\s+", ""),
                    "Wrapping preserves content");
            }
        }

        TextWriter originalOut = Console.Out;
        using (var output = new StringWriter())
        {
            try
            {
                Console.SetOut(output);
                ConsoleUi.Configure(false, true);
                ConsoleUi.Width = 80;
                var options = DefenderModule.ParseArguments(new[] { "--check" });
                var evidence = new DefenderModule.RunEvidence { Stage = "Check complete" };
                DefenderModule.PrintAssessment(options, evidence, 0);
                string compact = output.ToString();
                Assert(compact.Contains("CHECK_ONLY"), "Compact outcome visible");
                Assert(compact.Contains("NOT_ASSESSED") && compact.Contains("NOT_MEASURED"), "Compact limits visible");
                Assert(!compact.Contains("Event 5007") && !compact.Contains("8. Govern"), "Guidance not dumped by default");
                Assert(compact.Contains("--verbose"), "Detail discoverable");
                Assert(compact.Split('\n').Length <= 16, "Compact result fits 16 lines");
                Assert(!compact.Contains("\u001b"), "No ANSI escapes in plain text");
                foreach (string line in compact.Split(new[] { Environment.NewLine }, StringSplitOptions.None))
                {
                    Assert(line.Length <= 80, "Assessment wraps to target width");
                }
                output.GetStringBuilder().Clear();
                options.Verbose = true;
                DefenderModule.PrintAssessment(options, evidence, 0);
                Assert(output.ToString().Length > compact.Length * 2, "Verbose expands diagnostics");

                output.GetStringBuilder().Clear();
                var parsed = TelemetryEvidence.Parse(EventXml("Microsoft-Windows-WMI-Activity", 5858,
                    "<EventData><Data Name='ClientProcessId'>1234</Data>" +
                    "<Data Name='Operation'>" + new string('x', 300) + "</Data></EventData>"));
                TelemetryEvidence.PrintEvent(TelemetryProfiles.DefenderExclusion, parsed, "PID_MATCH: client PID matched", false);
                Assert(output.ToString().Contains("shortened; --verbose"), "Compact evidence truncation explicit");
                Assert(Normalize(output.ToString()).Contains("does not by itself prove Add"), "Evidence meaning retained");
                output.GetStringBuilder().Clear();
                TelemetryEvidence.PrintEvent(TelemetryProfiles.DefenderExclusion, parsed, "PID_MATCH: client PID matched", true);
                Assert(!output.ToString().Contains("shortened; --verbose"), "Verbose evidence retains field data");
            }
            finally
            {
                Console.SetOut(originalOut);
                ConsoleUi.Configure(false, true);
            }
        }
    }

    private static void CheckReadback()
    {
        Dictionary<string, List<string>> requested = DefenderModule.ParseArguments(new[]
        {
            "-ExclusionPath", @"C:\Lab Data\", @"C:\Lab Logs",
            "-ExclusionExtension", ".lablog",
            "-ExclusionProcess", "Worker.exe",
            "-ExclusionIpAddress", "192.0.2.10"
        }).Exclusions;
        Dictionary<string, List<string>> configured = DefenderModule.ParseArguments(new[]
        {
            "-ExclusionPath", @"c:\lab data", @"C:\Lab Logs", @"C:\Existing",
            "-ExclusionExtension", ".LABLOG",
            "-ExclusionProcess", "WORKER.EXE",
            "-ExclusionIpAddress", "192.0.2.10"
        }).Exclusions;
        AssertReadback(requested, configured, true, 5);
        configured["ExclusionPath"].Remove(@"C:\Lab Logs");
        AssertReadback(requested, configured, false, 4);
        configured["ExclusionPath"].Add(null);
        AssertReadback(requested, configured, false, 4);
        configured["ExclusionPath"].Add(@"C:\Lab Logs");
        configured["ExclusionExtension"].Clear();
        AssertReadback(requested, configured, false, 4);

        configured.Remove("ExclusionPath");
        bool rejected = false;
        try { DefenderModule.VerifyExclusions(requested, configured); }
        catch (InvalidOperationException) { rejected = true; }
        Assert(rejected, "Missing readback field must fail");

        requested = DefenderModule.ParseArguments(new[] { "-ExclusionPath", @"C:\Lab" }).Exclusions;
        configured = DefenderModule.ParseArguments(new[] { "-ExclusionPath", @"C:\Lab\Child" }).Exclusions;
        AssertReadback(requested, configured, false, 0);
    }

    private static void AssertReadback(Dictionary<string, List<string>> requested,
        Dictionary<string, List<string>> configured, bool expected, int expectedConfigured)
    {
        TextWriter originalOut = Console.Out;
        TextWriter originalError = Console.Error;
        using (var output = new StringWriter())
        using (var error = new StringWriter())
        {
            try
            {
                Console.SetOut(output);
                Console.SetError(error);
                bool actual = DefenderModule.VerifyExclusions(requested, configured);
                int configuredCount = output.ToString().Split(
                    new[] { "Configured " }, StringSplitOptions.None).Length - 1;
                Assert(actual == expected, "All requested values must be confirmed");
                Assert(configuredCount == expectedConfigured, "Per-item confirmation count");
                Assert(error.ToString().Contains("Not confirmed ") == !expected, "Missing-item diagnostics");
            }
            finally
            {
                Console.SetOut(originalOut);
                Console.SetError(originalError);
            }
        }
    }

    private static void Assert(bool condition, string message)
    {
        if (!condition) { throw new Exception(message); }
        passed++;
    }

    private static void Check(object status, bool configured, int expectedExit,
        bool expectedRead, bool expectedWarning)
    {
        TextWriter originalOut = Console.Out;
        TextWriter originalError = Console.Error;
        using (var output = new StringWriter())
        using (var error = new StringWriter())
        {
            try
            {
                Console.SetOut(output);
                Console.SetError(error);
                bool read = false;
                int exitCode = DefenderModule.EvaluateAddResult(status, delegate
                {
                    read = true;
                    return configured;
                });
                if (exitCode != expectedExit || read != expectedRead ||
                    error.ToString().Contains("Warning:") != expectedWarning ||
                    output.ToString().Contains("Confirmed:") != (expectedExit == 0) ||
                    (expectedExit == 3 && !error.ToString().Contains("could not be confirmed")))
                {
                    throw new Exception("Regression failure for status " +
                        (status ?? "<null>") + ", configured=" + configured +
                        ", exit=" + exitCode + ", stderr=" + error);
                }
                passed++;
            }
            finally
            {
                Console.SetOut(originalOut);
                Console.SetError(originalError);
            }
        }
    }
}
