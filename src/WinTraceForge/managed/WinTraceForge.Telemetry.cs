// This Source Code Form is subject to the terms of the
// Mozilla Public License, v. 2.0.
// If a copy of the MPL was not distributed with this file, You can obtain one at https://mozilla.org/MPL/2.0/.

using System;
using System.Collections.Generic;
using System.Diagnostics.Eventing.Reader;
using System.Globalization;
using System.IO;
using System.Security;
using System.Xml;

internal static class TelemetryEvidence
{
    private const int EventLimit = 200;

    internal sealed class ParsedEvent
    {
        internal int Id;
        internal string Provider;
        internal string RecordId;
        internal string TimeUtc;
        internal uint HeaderProcessId;
        internal uint HeaderThreadId;
        internal string ProviderGuid;
        internal string Version;
        internal string ActivityId;
        internal string RelatedActivityId;
        internal uint DecodeStatus;
        internal uint FieldErrors;
        internal readonly Dictionary<string, List<string>> Fields =
            new Dictionary<string, List<string>>(StringComparer.OrdinalIgnoreCase);
    }

    internal static void Collect(ControlOptions options, ControlRunEvidence evidence, DateTime endUtc)
    {
        ConsoleUi.Section("Telemetry evidence");
        ConsoleUi.Text("Source: existing ETW-backed Windows event channels; not raw ETW tracing.");
        DateTime startUtc = evidence.StartUtc.AddSeconds(-2);
        ConsoleUi.Row("Window UTC", startUtc.ToString("yyyy-MM-dd HH:mm:ss.fff'Z'", CultureInfo.InvariantCulture) +
            " -> " + endUtc.ToString("yyyy-MM-dd HH:mm:ss.fff'Z'", CultureInfo.InvariantCulture));
        ConsoleUi.Detail("The 2s lookback permits process-start correlation. Events can predate the operation.");
        ConsoleUi.Detail("Run ID " + evidence.RunId + " is local, not an event correlation field.");

        ConsoleUi.Row("Telemetry profile", options.Telemetry.Name);
        int incomplete = 0;
        foreach (EventLogChannel channel in options.Telemetry.EventLogChannels)
        {
            if (!ReadChannel(channel, startUtc, endUtc, options, evidence)) { incomplete++; }
        }
        Console.WriteLine();
        ConsoleUi.Status(incomplete == 0 ? "OK" : "WARN", "Collection completeness: " + (incomplete == 0 ?
            "all channel queries completed within their caps." :
            incomplete + " channel(s) unavailable or incomplete."));
        ConsoleUi.Text("No matching evidence is NOT proof of no detection. Correlations are candidates, not causation.");
        ConsoleUi.Detail("Events may be delayed, dropped, disabled, cleared or not emitted; no ETW loss counter is available here.");
        ConsoleUi.Detail("PID can be reused. Channels/audit policies are never enabled or changed.");
        ConsoleUi.Detail("Telemetry status does not alter the operation exit code.");
    }

    private static bool ReadChannel(EventLogChannel channel, DateTime startUtc, DateTime endUtc,
        ControlOptions options, ControlRunEvidence evidence)
    {
        int scanned = 0;
        int candidates = 0;
        int parseErrors = 0;
        Console.WriteLine();
        ConsoleUi.Text("Channel: " + channel.Name);
        try
        {
            using (var configuration = new EventLogConfiguration(channel.Name))
            {
                if (!configuration.IsEnabled)
                {
                    ConsoleUi.Status("WARN", "DISABLED - not enabled by this tool");
                    return false;
                }
            }
            string filter = "*[System[Provider[@Name='" + channel.Provider + "'] and " +
                channel.Filter + " and TimeCreated[@SystemTime >= '" +
                startUtc.ToString("yyyy-MM-ddTHH:mm:ss.fffffffZ", CultureInfo.InvariantCulture) +
                "' and @SystemTime <= '" +
                endUtc.ToString("yyyy-MM-ddTHH:mm:ss.fffffffZ", CultureInfo.InvariantCulture) + "']]]";
            var query = new EventLogQuery(channel.Name, PathType.LogName, filter)
            {
                ReverseDirection = true,
                TolerateQueryErrors = false
            };
            using (var reader = new EventLogReader(query))
            {
                while (scanned < EventLimit)
                {
                    using (EventRecord record = reader.ReadEvent())
                    {
                        if (record == null) { break; }
                        scanned++;
                        ParsedEvent parsed;
                        try
                        {
                            parsed = Parse(record.ToXml());
                        }
                        catch (XmlException ex)
                        {
                            parseErrors++;
                            ConsoleUi.Status("WARN", "Parse error, record " + record.RecordId + ": " + Safe(ex.Message));
                            continue;
                        }
                        catch (FormatException ex)
                        {
                            parseErrors++;
                            ConsoleUi.Status("WARN", "Parse error, record " + record.RecordId + ": " + Safe(ex.Message));
                            continue;
                        }
                        string correlation = Correlate(parsed, options, evidence.ProcessId);
                        if (correlation == null) { continue; }
                        candidates++;
                        if (options.Verbose || candidates <= 3) { PrintEvent(parsed, correlation, options.Verbose); }
                    }
                }
            }
            bool complete = scanned < EventLimit && parseErrors == 0;
            ConsoleUi.Status(complete ? "OK" : "WARN", (complete ? "QUERY_COMPLETED" : "INCOMPLETE") +
                "; scanned=" + scanned + "; candidates=" + candidates + "; parseErrors=" + parseErrors);
            if (!options.Verbose && candidates > 3)
            {
                ConsoleUi.Text((candidates - 3) + " more candidate events not displayed; use --verbose for all.");
            }
            if (scanned == EventLimit)
            {
                ConsoleUi.Status("WARN", "Cap reached: newest " + EventLimit + " filtered events examined; earlier events may be omitted.");
            }
            return complete;
        }
        catch (EventLogNotFoundException ex)
        {
            ConsoleUi.Status("WARN", "UNAVAILABLE - " + Safe(ex.Message));
        }
        catch (UnauthorizedAccessException ex)
        {
            ConsoleUi.Status("WARN", "ACCESS_DENIED - " + Safe(ex.Message));
        }
        catch (SecurityException ex)
        {
            ConsoleUi.Status("WARN", "ACCESS_DENIED - " + Safe(ex.Message));
        }
        catch (EventLogException ex)
        {
            ConsoleUi.Status("WARN", "READ_ERROR - " + Safe(ex.Message));
        }
        ConsoleUi.Detail("Partial counts: scanned=" + scanned + "; candidates=" + candidates);
        return false;
    }

    internal static void PrintEvent(ParsedEvent parsed, string correlation, bool verbose, bool eventLogRecord = true)
    {
        string kind = correlation.Split(':')[0];
        ConsoleUi.Status("INFO", "Event " + parsed.Id +
            (eventLogRecord ? " / Record " + Safe(parsed.RecordId) : "") + " / " + kind);
        ConsoleUi.Row("Event UTC", Safe(parsed.TimeUtc));
        if (verbose)
        {
            ConsoleUi.Row("Provider", Safe(parsed.Provider));
            ConsoleUi.Row("Correlation", correlation);
        }
        if (parsed.Provider == "Microsoft-Windows-WMI-Activity")
        {
            ConsoleUi.Text("WMI activity may be a query; it does not by itself prove Add was invoked.");
        }
        else if (parsed.Provider == "Microsoft-Windows-Windows Defender")
        {
            ConsoleUi.Text(parsed.Id == 5007 ?
                "Configuration change: verify setting and authorization." :
                "Blocked setting change: verify the setting and attribution to this run.");
        }
        else if (parsed.Provider == "Microsoft-Windows-Windows Firewall With Advanced Security" ||
            (parsed.Provider == "Microsoft-Windows-Security-Auditing" && parsed.Id >= 4946 && parsed.Id <= 4948))
        {
            ConsoleUi.Text("Firewall rule-change evidence only; not proof of packet blocking/allowing.");
        }
        else
        {
            ConsoleUi.Text("Process-start evidence only; not proof of a WMI method invocation.");
        }
        foreach (var field in parsed.Fields)
        {
            if (!DisplayField(field.Key)) { continue; }
            foreach (string value in field.Value)
            {
                string display = Safe(value);
                if (!verbose && display.Length > 160)
                {
                    display = display.Substring(0, 160) + " [shortened; --verbose for detail]";
                }
                ConsoleUi.Row(Safe(field.Key), display);
            }
        }
    }

    internal static ParsedEvent Parse(string xml)
    {
        var settings = new XmlReaderSettings { DtdProcessing = DtdProcessing.Prohibit, XmlResolver = null };
        var document = new XmlDocument { XmlResolver = null };
        using (var text = new StringReader(xml))
        using (XmlReader reader = XmlReader.Create(text, settings))
        {
            document.Load(reader);
        }
        var namespaces = new XmlNamespaceManager(document.NameTable);
        namespaces.AddNamespace("e", "http://schemas.microsoft.com/win/2004/08/events/event");
        XmlNode system = document.SelectSingleNode("/e:Event/e:System", namespaces);
        if (system == null) { throw new FormatException("Event System element is missing."); }
        int id;
        XmlNode idNode = system.SelectSingleNode("e:EventID", namespaces);
        if (idNode == null || !int.TryParse(idNode.InnerText, NumberStyles.None, CultureInfo.InvariantCulture, out id))
        {
            throw new FormatException("EventID is missing or invalid.");
        }
        var parsed = new ParsedEvent
        {
            Id = id,
            Provider = NodeValue(system.SelectSingleNode("e:Provider/@Name", namespaces)),
            RecordId = NodeValue(system.SelectSingleNode("e:EventRecordID", namespaces)),
            TimeUtc = NodeValue(system.SelectSingleNode("e:TimeCreated/@SystemTime", namespaces))
        };
        parsed.HeaderProcessId = OptionalNumber(system.SelectSingleNode("e:Execution/@ProcessID", namespaces));
        parsed.HeaderThreadId = OptionalNumber(system.SelectSingleNode("e:Execution/@ThreadID", namespaces));
        parsed.ProviderGuid = NodeValue(system.SelectSingleNode("e:Provider/@Guid", namespaces));
        parsed.Version = NodeValue(system.SelectSingleNode("e:Version", namespaces));
        parsed.ActivityId = NodeValue(system.SelectSingleNode("e:Correlation/@ActivityID", namespaces));
        parsed.RelatedActivityId = NodeValue(system.SelectSingleNode("e:Correlation/@RelatedActivityID", namespaces));
        parsed.DecodeStatus = OptionalNumber(document.SelectSingleNode("/e:Event/e:Decoding/@Win32Status", namespaces));
        parsed.FieldErrors = OptionalNumber(document.SelectSingleNode("/e:Event/e:Decoding/@FieldErrors", namespaces));
        foreach (XmlNode data in document.SelectNodes("/e:Event/e:EventData/e:Data", namespaces))
        {
            XmlAttribute name = data.Attributes["Name"];
            AddField(parsed, name == null ? "UnnamedData" : name.Value, data.InnerText);
        }
        foreach (XmlNode data in document.SelectNodes("/e:Event/e:UserData//*[not(*)]", namespaces))
        {
            AddField(parsed, data.LocalName, data.InnerText);
        }
        return parsed;
    }

    private static string NodeValue(XmlNode node) { return node == null ? "(missing)" : node.InnerText; }

    private static uint OptionalNumber(XmlNode node)
    {
        if (node == null) { return 0; }
        uint value;
        if (!uint.TryParse(node.InnerText, NumberStyles.None, CultureInfo.InvariantCulture, out value))
        {
            throw new FormatException("Invalid event metadata number: " + node.InnerText);
        }
        return value;
    }

    private static void AddField(ParsedEvent parsed, string name, string value)
    {
        List<string> values;
        if (!parsed.Fields.TryGetValue(name, out values))
        {
            values = new List<string>();
            parsed.Fields.Add(name, values);
        }
        values.Add(value);
    }

    internal static string Correlate(ParsedEvent parsed, ControlOptions options, int processId)
    {
        return options.Telemetry.Correlate(parsed, options, processId);
    }

    private static string CorrelateProcess(ParsedEvent parsed, int processId)
    {
        if (parsed.Provider == "Microsoft-Windows-Security-Auditing" && parsed.Id == 4688)
        {
            return MatchesPid(parsed, "NewProcessId", processId) ? "PID_MATCH: Security NewProcessId matches this process." : null;
        }
        if (parsed.Provider == "Microsoft-Windows-Sysmon" && parsed.Id == 1)
        {
            return MatchesPid(parsed, "ProcessId", processId) ? "PID_MATCH: Sysmon ProcessId matches this process." : null;
        }
        return null;
    }

    internal static string CorrelateFirewall(ParsedEvent parsed, IEnumerable<string> evidenceValues, int processId)
    {
        string process = CorrelateProcess(parsed, processId);
        if (process != null) { return process; }
        bool firewallEvent =
            (parsed.Provider == "Microsoft-Windows-Windows Firewall With Advanced Security" &&
                (parsed.Id == 2004 || parsed.Id == 2005 || parsed.Id == 2006)) ||
            (parsed.Provider == "Microsoft-Windows-Security-Auditing" &&
                (parsed.Id == 4946 || parsed.Id == 4947 || parsed.Id == 4948));
        if (!firewallEvent) { return null; }
        foreach (var field in parsed.Fields)
        {
            string compact = field.Key.Replace(" ", "").Replace("_", "");
            if (!string.Equals(compact, "RuleName", StringComparison.OrdinalIgnoreCase)) { continue; }
            foreach (string actual in field.Value)
            {
                foreach (string expected in evidenceValues)
                {
                    if (string.Equals(actual.Trim(), expected, StringComparison.OrdinalIgnoreCase))
                    {
                        return "RULE_NAME_MATCH: exact test-rule name within the window; verify action and attribution.";
                    }
                }
            }
        }
        return null;
    }

    internal static string CorrelateDefender(ParsedEvent parsed, IEnumerable<string> evidenceValues, int processId)
    {
        string process = CorrelateProcess(parsed, processId);
        if (process != null) { return process; }
        if (parsed.Provider == "Microsoft-Windows-WMI-Activity")
        {
            return MatchesPid(parsed, "ClientProcessId", processId) ? "PID_MATCH: WMI ClientProcessId matches this process." : null;
        }
        if (parsed.Provider != "Microsoft-Windows-Windows Defender" || (parsed.Id != 5007 && parsed.Id != 5013))
        {
            return null;
        }
        bool settingMatch = false;
        foreach (var field in parsed.Fields)
        {
            foreach (string text in field.Value)
            {
                foreach (string requested in evidenceValues)
                {
                    if (text.IndexOf(requested, StringComparison.OrdinalIgnoreCase) >= 0)
                    {
                        return "REQUEST_VALUE_MATCH: value substring within the collection window; not causal proof.";
                    }
                }
                if (text.IndexOf("Exclusion", StringComparison.OrdinalIgnoreCase) >= 0)
                {
                    settingMatch = true;
                }
            }
        }
        return settingMatch ?
            "SETTING_TIME_ONLY: exclusion-related text in the time window; not attributed to this process." : null;
    }

    private static bool MatchesPid(ParsedEvent parsed, string field, int processId)
    {
        if (processId <= 0) { return false; }
        List<string> values;
        if (!parsed.Fields.TryGetValue(field, out values)) { return false; }
        foreach (string text in values)
        {
            string value = text.Trim();
            bool hex = value.StartsWith("0x", StringComparison.OrdinalIgnoreCase);
            uint pid;
            if (uint.TryParse(hex ? value.Substring(2) : value,
                hex ? NumberStyles.AllowHexSpecifier : NumberStyles.None,
                CultureInfo.InvariantCulture, out pid) && pid == (uint)processId)
            {
                return true;
            }
        }
        return false;
    }

    private static bool DisplayField(string name)
    {
        string compact = name.Replace(" ", "").Replace("_", "");
        foreach (string allowed in new[] { "OldValue", "NewValue", "Setting", "SettingName", "Value",
            "ClientProcessId", "ProcessId", "NewProcessId", "NewProcessName", "ParentProcessName",
            "Image", "ParentImage", "CommandLine", "User", "SubjectUserName", "SubjectDomainName",
            "Operation", "ResultCode", "PossibleCause", "ClientMachine", "ProcessGuid",
            "RuleName", "RuleId", "Action", "Direction", "Profiles", "Active", "ApplicationPath",
            "ModifyingApplication", "ModifyingUser", "RemoteAddresses", "RemotePorts", "LocalPorts", "Protocol",
            "LocalAddresses", "ServiceName", "EdgeTraversal", "SecurityOptions", "RuleStatus", "Origin" })
        {
            if (string.Equals(compact, allowed, StringComparison.OrdinalIgnoreCase)) { return true; }
        }
        return false;
    }

    internal static string Safe(string value)
    {
        if (value == null) { return "(null)"; }
        int length = Math.Min(value.Length, 1200);
        char[] output = value.Substring(0, length).ToCharArray();
        for (int i = 0; i < output.Length; i++)
        {
            if (char.IsControl(output[i])) { output[i] = ' '; }
        }
        return new string(output) + (value.Length > length ? " [truncated]" : "");
    }
}
