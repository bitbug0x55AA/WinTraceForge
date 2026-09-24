// This Source Code Form is subject to the terms of the
// Mozilla Public License, v. 2.0.
// If a copy of the MPL was not distributed with this file, You can obtain one at https://mozilla.org/MPL/2.0/.

using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Globalization;
using System.Threading;

internal enum ControlKind
{
    DefenderExclusion,
    FirewallRule,
    FirewallProfiles
}

internal abstract class ControlOptions
{
    internal bool Help;
    internal bool Verbose;
    internal bool NoColor;
    internal bool CollectEventLog;
    internal bool CollectEtw;
    internal int TelemetryWaitSeconds = 3;
    internal ControlKind Kind;
    internal abstract TelemetryProfile Telemetry { get; }
    internal abstract IEnumerable<string> EvidenceValues { get; }
}

internal class ControlRunEvidence
{
    internal readonly string RunId = Guid.NewGuid().ToString("D");
    internal readonly DateTime StartUtc = DateTime.UtcNow;
    internal DateTime OperationEndUtc = DateTime.UtcNow;
    internal int ProcessId;
    internal string Stage = "Identity";
}

internal static class CommonArguments
{
    internal static bool TryParse(string[] args, ref int index, ControlOptions options, HashSet<string> seen)
    {
        string argument = args[index].ToLowerInvariant();
        switch (argument)
        {
            case "--help": case "-help": case "-?": options.Help = true; return true;
            case "--verbose": options.Verbose = true; return true;
            case "--no-color": options.NoColor = true; return true;
            case "--telemetry":
                if (!seen.Add(argument) || index + 1 >= args.Length)
                {
                    throw new ArgumentException("Specify --telemetry once, followed by none, eventlog, or etw.");
                }
                string mode = args[++index].ToLowerInvariant();
                if (mode != "none" && mode != "eventlog" && mode != "etw")
                {
                    throw new ArgumentException("Telemetry modes: none, eventlog, etw.");
                }
                options.CollectEventLog = mode == "eventlog";
                options.CollectEtw = mode == "etw";
                return true;
            case "--telemetry-wait":
                int seconds;
                if (!seen.Add(argument) || index + 1 >= args.Length ||
                    !int.TryParse(args[++index], NumberStyles.None, CultureInfo.InvariantCulture, out seconds) ||
                    seconds < 0 || seconds > 30)
                {
                    throw new ArgumentException("--telemetry-wait requires one integer from 0 to 30 seconds.");
                }
                options.TelemetryWaitSeconds = seconds;
                return true;
            default: return false;
        }
    }

    internal static void Validate(ControlOptions options, HashSet<string> seen)
    {
        if (seen.Contains("--telemetry-wait") && !options.CollectEventLog && !options.CollectEtw)
        {
            throw new ArgumentException("--telemetry-wait requires --telemetry eventlog or etw.");
        }
    }
}

internal static class ControlRuntime
{
    internal static int Execute(ControlOptions options, ControlRunEvidence evidence,
        Func<int> operation, Action<int> assessment)
    {
        using (Process process = Process.GetCurrentProcess()) { evidence.ProcessId = process.Id; }
        if (options.CollectEtw)
        {
            using (var capture = new EtwCapture(options, evidence))
            {
                evidence.Stage = "ETW setup";
                if (!capture.TryStart())
                {
                    evidence.OperationEndUtc = DateTime.UtcNow;
                    assessment(4);
                    return 4;
                }
                int exitCode;
                try
                {
                    exitCode = operation();
                    evidence.OperationEndUtc = DateTime.UtcNow;
                }
                finally { capture.StopAfterWait(); }
                capture.Report();
                assessment(exitCode);
                return exitCode;
            }
        }
        int result = operation();
        evidence.OperationEndUtc = DateTime.UtcNow;
        if (options.CollectEventLog)
        {
            ConsoleUi.Text("Collecting event-log evidence; waiting " + options.TelemetryWaitSeconds + "s...");
            Thread.Sleep(options.TelemetryWaitSeconds * 1000);
            TelemetryEvidence.Collect(options, evidence, DateTime.UtcNow);
        }
        assessment(result);
        return result;
    }
}
