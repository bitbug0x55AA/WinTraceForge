// This Source Code Form is subject to the terms of the
// Mozilla Public License, v. 2.0.
// If a copy of the MPL was not distributed with this file, You can obtain one at https://mozilla.org/MPL/2.0/.

using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Globalization;
using System.IO;
using System.Management;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading;
using Microsoft.Win32.SafeHandles;

internal sealed class AsrBaseline
{
    internal readonly AsrSnapshot Snapshot;
    internal readonly Dictionary<string, AsrPolicySourceKind> PolicySource;
    internal AsrBaseline(AsrSnapshot snapshot, Dictionary<string, AsrPolicySourceKind> policySource)
    { Snapshot = snapshot; PolicySource = policySource; }
}

internal static partial class AsrModule
{
    private sealed class AsrOperation : IControlOperation<AsrBaseline, IAsrReader, IAsrWriter>
    {
        private readonly AsrOptions options;
        private readonly AsrRunEvidence evidence;

        // Set during Probe/Mutate for the 'rule' and 'verify' sub-commands; the same operation
        // instance is reused across every phase of one ControlLifecycle.Run call.
        private AsrAction? priorRuleAction;
        private string testDirectory;
        private string testFilePath;
        private string launchExecutable;
        private string launchArguments;
        private string expectedProcessName;
        // Requested exclusion paths that were NOT already in the baseline; null when that could not
        // be determined (elevation-gated read). Only these -- never a pre-existing, unrelated
        // organizational exclusion -- may ever be named in a cleanup instruction.
        private List<string> newExclusionPaths;
        private bool createdArtifact;
        private bool targetMayBeUntrackable;
        private Process launchedProcess;
        // Captured once, right after a successful launch: RestoreVerify disposes launchedProcess,
        // and phases that run after Restore (VerifyRestored) must not touch a disposed Process.
        private int launcherProcessId;
        private DateTime launcherStartTime;

        internal AsrOperation(AsrOptions options, AsrRunEvidence evidence)
        { this.options = options; this.evidence = evidence; }

        public string Transport { get { return options.Transport; } }
        public bool VerifyAfterApiFailure { get { return false; } }

        public string ManualRestoration
        {
            get
            {
                if (options.Kind == ControlKind.DefenderAsrExclusion)
                {
                    if (newExclusionPaths == null)
                    {
                        return "Baseline exclusion content was unobservable (non-elevated read); verify manually " +
                            "which of these paths pre-existed before removing any: " + string.Join(", ", options.Paths.ToArray());
                    }
                    if (newExclusionPaths.Count == 0)
                    { return "Every requested path already existed in the baseline; nothing new to remove."; }
                    return "Remove only these newly-added ASR-only exclusion(s), leaving every pre-existing baseline " +
                        "path untouched: Remove-MpPreference -AttackSurfaceReductionOnlyExclusions " +
                        string.Join(",", QuotePowerShellPaths(newExclusionPaths)) + " (PowerShell; WTF only calls Add, never Remove).";
                }
                if (options.Kind == ControlKind.DefenderAsrRule)
                {
                    string ruleId = options.RuleId.ToString("D");
                    AsrAction restoreTo = priorRuleAction ?? AsrAction.NotConfigured;
                    return "Restore rule " + ruleId + " to its pre-run state via: wtf.exe defender asr rule -RuleId " +
                        ruleId + " -Action " + restoreTo;
                }
                return "No manual restoration is required for this sub-command.";
            }
        }

        public ProbeResult<AsrBaseline> Probe(IAsrReader backend)
        {
            evidence.Stage = "Connect";
            backend.Connect();
            if (options.Kind == ControlKind.DefenderAsrStatus) { return RunStatusProbe(backend); }
            if (options.Kind == ControlKind.DefenderAsrExclusion) { return RunExclusionProbe(backend); }
            if (options.Kind == ControlKind.DefenderAsrRule) { return RunRuleProbe(backend); }
            return RunVerifyProbe(backend);
        }

        public MutationStatus Mutate(AsrBaseline baseline, IAsrWriter backend)
        {
            if (options.Kind == ControlKind.DefenderAsrVerify) { return MutateVerify(); }
            return MutateAdd(backend);
        }

        public VerificationStatus Verify(AsrBaseline baseline, IAsrReader backend)
        {
            if (options.Kind == ControlKind.DefenderAsrExclusion) { return VerifyExclusion(backend); }
            if (options.Kind == ControlKind.DefenderAsrRule) { return VerifyRule(baseline, backend); }
            return VerifyTestOutcome(baseline);
        }

        public void Restore(AsrBaseline baseline, IAsrWriter backend)
        {
            if (options.Kind == ControlKind.DefenderAsrVerify) { RestoreVerify(); return; }
            throw new NotSupportedException("Manual restoration selected.");
        }

        public VerificationStatus VerifyRestored(AsrBaseline baseline, IAsrReader backend)
        {
            if (options.Kind == ControlKind.DefenderAsrVerify) { return VerifyRestoredVerify(); }
            throw new NotSupportedException("Manual restoration selected.");
        }

        // ---- status ----

        private ProbeResult<AsrBaseline> RunStatusProbe(IAsrReader backend)
        {
            evidence.Stage = "ASR status read";
            ConsoleUi.Section("Attack Surface Reduction rules");
            AsrSnapshot snapshot = backend.Read();
            var allRuleIds = new List<string>(snapshot.Rules.Keys);
            foreach (string known in AsrRuleCatalog.KnownRuleIds)
            {
                if (!allRuleIds.Exists(delegate(string id)
                    { return string.Equals(id, known, StringComparison.OrdinalIgnoreCase); }))
                { allRuleIds.Add(known); }
            }
            var policyKeys = new List<string>(allRuleIds);
            policyKeys.Add(AsrRegistry.GlobalExclusionsSourceKey);
            Dictionary<string, AsrPolicySourceKind> sources = backend.ReadPolicySource(policyKeys);

            foreach (string ruleId in allRuleIds)
            {
                AsrAction action;
                bool configured = snapshot.Rules.TryGetValue(ruleId, out action);
                AsrPolicySourceKind source = sources.ContainsKey(ruleId) ? sources[ruleId] : AsrPolicySourceKind.Unknown;
                ConsoleUi.Row(ruleId, (configured ? action.ToString() : "NotConfigured") + "  source=" + source);
                ConsoleUi.Detail("  " + AsrRuleCatalog.NameOf(ruleId));
            }

            ConsoleUi.Section("ASR-only (global) exclusions");
            if (snapshot.GlobalExclusionsRequireElevation)
            {
                ConsoleUi.Status("WARN", "Defender hid ASR-only exclusion content from this non-administrator context; " +
                    "presence/absence could not be observed. Re-run elevated for a real reading.");
            }
            else
            {
                AsrPolicySourceKind exclusionSource = sources.ContainsKey(AsrRegistry.GlobalExclusionsSourceKey) ?
                    sources[AsrRegistry.GlobalExclusionsSourceKey] : AsrPolicySourceKind.Unknown;
                if (snapshot.GlobalExclusions.Count == 0) { ConsoleUi.Text("(none configured)"); }
                foreach (string exclusion in snapshot.GlobalExclusions)
                { ConsoleUi.Row(exclusion, "source=" + exclusionSource); }
            }

            ConsoleUi.Section("Exception-surface cross-reference");
            if (snapshot.AvExclusionsRequireElevation)
            {
                ConsoleUi.Status("WARN", "Defender hid antivirus exclusion content from this non-administrator context; " +
                    "the AV/ASR exception-surface overlap could not be observed. Re-run elevated for a real reading.");
            }
            else
            {
                int avExclusionCount = 0;
                foreach (var exclusion in snapshot.AvExclusions) { avExclusionCount += exclusion.Value.Count; }
                if (avExclusionCount == 0) { ConsoleUi.Text("No Defender antivirus exclusions configured."); }
                else
                {
                    ConsoleUi.Status("WARN", avExclusionCount + " Defender antivirus exclusion(s) configured; these can widen " +
                        "the effective ASR exception surface in addition to the ASR-only exclusion list above.");
                    foreach (var exclusion in snapshot.AvExclusions)
                    {
                        foreach (string value in exclusion.Value) { ConsoleUi.Detail("  " + exclusion.Key + ": " + value); }
                    }
                }
            }

            var baseline = new AsrBaseline(snapshot, sources);
            return new ProbeResult<AsrBaseline>(baseline, ProbeStatus.ReadOnlyConfirmed, RestorationPolicy.None);
        }

        // ---- exclusion ----

        private ProbeResult<AsrBaseline> RunExclusionProbe(IAsrReader backend)
        {
            evidence.Stage = "Prepare";
            backend.Prepare(new AsrMutationRequest { Kind = AsrRequestKind.GlobalExclusion, ExclusionPaths = options.Paths });
            evidence.Stage = "Baseline read";
            AsrSnapshot snapshot = backend.Read();
            ConsoleUi.Section("Baseline");
            if (snapshot.GlobalExclusionsRequireElevation)
            {
                ConsoleUi.Status("WARN", "Defender hid existing ASR-only exclusion content from this non-administrator " +
                    "context; baseline presence could not be observed for any requested path.");
                newExclusionPaths = null;
            }
            else
            {
                newExclusionPaths = new List<string>();
                foreach (string path in options.Paths)
                {
                    bool present = ContainsExclusion(snapshot.GlobalExclusions, path);
                    ConsoleUi.Status(present ? "SEEN" : "INFO", path +
                        (present ? " [present in baseline; will not be listed for removal]" : " [not observed]"));
                    if (!present) { newExclusionPaths.Add(path); }
                }
            }
            var baseline = new AsrBaseline(snapshot, null);
            if (options.CheckOnly)
            {
                if (snapshot.GlobalExclusionsRequireElevation)
                {
                    ConsoleUi.Status("WARN", "Check did not confirm anything: baseline presence is unobservable non-elevated.");
                    return new ProbeResult<AsrBaseline>(baseline, ProbeStatus.ReadOnlyMismatch, RestorationPolicy.None);
                }
                ConsoleUi.Status("OK", "Read-only check passed. No settings were changed.");
                return new ProbeResult<AsrBaseline>(baseline, ProbeStatus.ReadOnlyConfirmed, RestorationPolicy.None);
            }
            return new ProbeResult<AsrBaseline>(baseline, ProbeStatus.Ready, RestorationPolicy.Manual);
        }

        private VerificationStatus VerifyExclusion(IAsrReader backend)
        {
            evidence.Stage = "Post-Add readback";
            ConsoleUi.Section("Result / readback");
            AsrSnapshot snapshot = backend.Read();
            if (snapshot.GlobalExclusionsRequireElevation)
            {
                ConsoleUi.Status("WARN", "Defender hid ASR-only exclusion content on readback; the Add could not be verified.");
                return VerificationStatus.Unavailable;
            }
            bool allConfirmed = true;
            foreach (string path in options.Paths)
            {
                bool found = ContainsExclusion(snapshot.GlobalExclusions, path);
                ConsoleUi.Status(found ? "OK" : "FAIL", (found ? "Configured " : "Not confirmed ") + path, !found);
                allConfirmed &= found;
            }
            return allConfirmed ? VerificationStatus.Confirmed : VerificationStatus.Mismatch;
        }

        private static bool ContainsExclusion(List<string> values, string value)
        {
            return values.Exists(delegate(string actual)
            {
                return actual != null && string.Equals(actual.TrimEnd('\\'), value.TrimEnd('\\'), StringComparison.OrdinalIgnoreCase);
            });
        }

        // ---- rule ----

        private ProbeResult<AsrBaseline> RunRuleProbe(IAsrReader backend)
        {
            string ruleId = options.RuleId.ToString("D");
            evidence.Stage = "Baseline read";
            AsrSnapshot snapshot = backend.Read();
            Dictionary<string, AsrPolicySourceKind> sources = backend.ReadPolicySource(new[] { ruleId });
            AsrAction? prior = snapshot.Rules.ContainsKey(ruleId) ? snapshot.Rules[ruleId] : (AsrAction?)null;
            priorRuleAction = prior;

            ConsoleUi.Section("Rule");
            ConsoleUi.Row(ruleId, AsrRuleCatalog.NameOf(ruleId));
            ConsoleUi.Row("Current action", prior.HasValue ? prior.Value.ToString() : "NotConfigured");
            ConsoleUi.Row("Policy source", sources[ruleId].ToString());

            var baseline = new AsrBaseline(snapshot, sources);
            if (options.CheckOnly)
            { return new ProbeResult<AsrBaseline>(baseline, ProbeStatus.ReadOnlyConfirmed, RestorationPolicy.None); }

            if (sources[ruleId] == AsrPolicySourceKind.GroupPolicy)
            { ConsoleUi.Status("WARN", "This rule appears Group Policy-managed; a local Add may not persist or take effect."); }

            evidence.Stage = "Prepare";
            backend.Prepare(new AsrMutationRequest
            { Kind = AsrRequestKind.RuleAction, RuleId = ruleId, Action = options.Action.Value });
            return new ProbeResult<AsrBaseline>(baseline, ProbeStatus.Ready, RestorationPolicy.Manual);
        }

        private VerificationStatus VerifyRule(AsrBaseline baseline, IAsrReader backend)
        {
            evidence.Stage = "Post-Add readback";
            ConsoleUi.Section("Result / readback");
            string ruleId = options.RuleId.ToString("D");
            AsrSnapshot snapshot = backend.Read();
            AsrAction actual;
            bool configured = snapshot.Rules.TryGetValue(ruleId, out actual);
            // Requesting NotConfigured(5) may leave Defender with an explicit (guid, 5) entry, or it
            // may remove the entry entirely -- this tool has not observed which, and Microsoft treats
            // both as functionally unconfigured. Either outcome must count as Confirmed here.
            bool matches = options.Action.Value == AsrAction.NotConfigured ?
                (!configured || actual == AsrAction.NotConfigured) :
                (configured && actual == options.Action.Value);
            ConsoleUi.Status(matches ? "OK" : "FAIL",
                "Rule " + ruleId + " action: " + (configured ? actual.ToString() : "NotConfigured"), !matches);
            return matches ? VerificationStatus.Confirmed : VerificationStatus.Mismatch;
        }

        // ---- shared Add-based mutation (exclusion + rule) ----

        private MutationStatus MutateAdd(IAsrWriter backend)
        {
            evidence.Stage = "Add invocation";
            ConsoleUi.Section("Apply & verify");
            evidence.MutationAttempted = true;
            object returnValue = backend.Add();
            evidence.MutationReturned = true;
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

        private static bool TryGetStatusCode(object value, out uint status)
        {
            status = 0;
            if (value is int) { status = unchecked((uint)(int)value); return true; }
            if (!(value is uint || value is long || value is ulong || value is short || value is ushort ||
                  value is byte || value is sbyte || value is string)) { return false; }
            string text = Convert.ToString(value, CultureInfo.InvariantCulture);
            if (uint.TryParse(text, NumberStyles.Integer, CultureInfo.InvariantCulture, out status)) { return true; }
            int signedStatus;
            if (int.TryParse(text, NumberStyles.Integer, CultureInfo.InvariantCulture, out signedStatus))
            { status = unchecked((uint)signedStatus); return true; }
            return false;
        }

        // ---- verify (behavioral test primitive) ----

        private ProbeResult<AsrBaseline> RunVerifyProbe(IAsrReader backend)
        {
            string ruleId = options.RuleId.ToString("D");
            evidence.Stage = "Baseline read";
            AsrSnapshot snapshot = backend.Read();
            Dictionary<string, AsrPolicySourceKind> sources = backend.ReadPolicySource(new[] { ruleId });
            AsrAction? current = snapshot.Rules.ContainsKey(ruleId) ? snapshot.Rules[ruleId] : (AsrAction?)null;

            ConsoleUi.Section("Behavioral verification");
            ConsoleUi.Row(ruleId, AsrRuleCatalog.NameOf(ruleId));
            ConsoleUi.Row("Current action", current.HasValue ? current.Value.ToString() : "NotConfigured");
            ConsoleUi.Row("Policy source", sources[ruleId].ToString());

            bool builtIn = options.TestCommand == null;
            if (builtIn)
            {
                testDirectory = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
                    "WinTraceForge", "AsrTests", evidence.RunId);
                testFilePath = Path.Combine(testDirectory, "test.js");
                launchExecutable = "wscript.exe";
                launchArguments = "//B \"" + testFilePath + "\"";
                expectedProcessName = "notepad";
                ConsoleUi.Status("WARN", "EXPERIMENTAL primitive: benign .js marked Internet-zone (downloaded), run via " +
                    "wscript.exe, launches notepad.exe. Whether this rule actually intercepts it has not been confirmed " +
                    "in any environment (Block -> observed 1121); a Mismatch below may mean the rule didn't fire on this " +
                    "primitive at all, not that protection failed. Validate once in a disposable VM before relying on it.");
                ConsoleUi.Row("Test artifact", testFilePath);
                if (backend.IsNotepadRedirectionActive())
                {
                    targetMayBeUntrackable = true;
                    ConsoleUi.Status("WARN", "This host redirects notepad.exe via Image File Execution Options / " +
                        "AppExecutionAlias to a packaged app. The process actually launched may not appear as a child " +
                        "of the launcher at all, so enforcement observation and cleanup confirmation are unreliable " +
                        "here: a missing observation does not mean nothing opened, and reported cleanup does not " +
                        "guarantee no window remains. Check manually.");
                }
            }
            else
            {
                launchExecutable = options.TestCommand;
                launchArguments = options.TestArguments ?? "";
                expectedProcessName = null;
                ConsoleUi.Row("Test command", launchExecutable + " " + launchArguments);
                ConsoleUi.Status("WARN", "No known expected child process for a custom -TestCommand; " +
                    "enforcement outcome will be Unavailable. Rely on --telemetry evidence for this run.");
            }

            var baseline = new AsrBaseline(snapshot, sources);
            if (options.CheckOnly)
            {
                ConsoleUi.Status("OK", "Read-only check passed. No test artifact was created or executed.");
                return new ProbeResult<AsrBaseline>(baseline, ProbeStatus.ReadOnlyConfirmed, RestorationPolicy.None);
            }
            return new ProbeResult<AsrBaseline>(baseline, ProbeStatus.Ready, RestorationPolicy.Automatic);
        }

        private MutationStatus MutateVerify()
        {
            evidence.Stage = "Test primitive execution";
            ConsoleUi.Section("Execute test primitive");
            if (testDirectory != null)
            {
                // Ownership is recorded before either write that could still fail: Restore must
                // always be able to find and remove whatever got created, even a partial artifact.
                createdArtifact = true;
                CreateTestArtifact(testDirectory, testFilePath);
            }
            evidence.MutationAttempted = true;
            var start = new ProcessStartInfo(launchExecutable, launchArguments)
            { UseShellExecute = false, CreateNoWindow = true };
            launchedProcess = Process.Start(start);
            evidence.MutationReturned = true;
            if (launchedProcess != null)
            {
                launcherProcessId = launchedProcess.Id;
                launcherStartTime = launchedProcess.StartTime;
                launchedProcess.WaitForExit(5000);
            }
            else { Thread.Sleep(2000); }
            return MutationStatus.ApiSucceeded;
        }

        // Verify only observes: it must never terminate or delete anything, so that "Verify is
        // read-only" stays true even for a family whose target lives outside the WMI backend.
        // Ownership is via Windows' own ParentProcessId bookkeeping (not name+timestamp, which a
        // coincidental unrelated notepad.exe could satisfy), guarded against PID reuse by requiring
        // the candidate to have been created no earlier than the launcher itself (IsOwnedChildProcess).
        private VerificationStatus VerifyTestOutcome(AsrBaseline baseline)
        {
            evidence.Stage = "Enforcement observation";
            ConsoleUi.Section("Result / readback");
            if (expectedProcessName == null || launchedProcess == null)
            {
                ConsoleUi.Status("WARN", "No expected-process signature for a custom test command; enforcement outcome is unavailable.");
                return VerificationStatus.Unavailable;
            }
            Thread.Sleep(500);
            List<AsrOwnedProcess> found = FindChildProcesses(expectedProcessName + ".exe");
            if (found == null)
            {
                ConsoleUi.Status("WARN", "Could not query the process tree (WMI access restricted on this host); " +
                    "enforcement outcome is unavailable.");
                return VerificationStatus.Unavailable;
            }
            bool observed = found.Count != 0;
            string ruleId = options.RuleId.ToString("D");
            AsrAction action = baseline.Snapshot.Rules.ContainsKey(ruleId) ? baseline.Snapshot.Rules[ruleId] : AsrAction.Disabled;
            VerificationStatus status = EvaluateTestOutcome(action, observed);
            ConsoleUi.Row("Rule action at test time", action.ToString());
            ConsoleUi.Row("Expected child process observed (as a child of the launcher)", observed.ToString());
            if (status == VerificationStatus.Mismatch)
            {
                ConsoleUi.Status("FAIL", "The primitive ran despite an action (" + action + ") that should have stopped " +
                    "it by default. This is a local observation, not proof of a bypass: it may also mean this " +
                    "(experimental, unverified) primitive simply does not trigger this rule at all in this environment. " +
                    "Check for exclusions, RTP state, and corroborate with --telemetry evidence (1121/1122).", true);
            }
            else
            {
                ConsoleUi.Status("WARN", "Local process observation alone cannot confirm ASR enforcement (many other " +
                    "causes -- WSH disabled, AppLocker/WDAC, a script error, RTP state -- can also explain this result). " +
                    "Use --telemetry etw or eventlog and inspect the correlated 1121/1122 evidence for real confirmation.");
            }
            return status;
        }

        // Re-queried independently by both Verify (observation) and Restore (cleanup) rather than
        // sharing state between phases, so cleanup remains correct even if Verify never ran. Restore
        // and VerifyRestored pass null (any name): a custom -TestCommand's children are otherwise
        // never tracked at all, and a broader net also catches anything unexpected the launcher spawned.
        // Returns null (never an empty list) when the query itself could not be answered -- e.g. WMI
        // access is restricted on this host -- so callers never mistake "could not check" for "checked
        // and found none": that distinction is exactly the "unobserved is not absent" rule this module
        // applies everywhere else (the exclusion-visibility sentinel, elevation-gated reads, etc.).
        private List<AsrOwnedProcess> FindChildProcesses(string expectedImageNameOrNull)
        {
            var results = new List<AsrOwnedProcess>();
            try
            {
                string query = "SELECT ProcessId, ParentProcessId, Name, CreationDate FROM Win32_Process WHERE ParentProcessId = " +
                    launcherProcessId.ToString(CultureInfo.InvariantCulture) +
                    (expectedImageNameOrNull != null ? " AND Name = '" + expectedImageNameOrNull + "'" : "");
                using (var searcher = new ManagementObjectSearcher(query))
                using (ManagementObjectCollection matches = searcher.Get())
                {
                    foreach (ManagementObject item in matches)
                    {
                        using (item)
                        {
                            int parentProcessId = Convert.ToInt32(item["ParentProcessId"], CultureInfo.InvariantCulture);
                            string name = (string)item["Name"];
                            string rawCreated = item["CreationDate"] as string;
                            DateTime created = rawCreated != null ? ManagementDateTimeConverter.ToDateTime(rawCreated) : DateTime.MinValue;
                            if (IsOwnedChildProcess(parentProcessId, name, created, launcherProcessId, expectedImageNameOrNull, launcherStartTime))
                            {
                                int pid = Convert.ToInt32(item["ProcessId"], CultureInfo.InvariantCulture);
                                results.Add(new AsrOwnedProcess(pid, created));
                            }
                        }
                    }
                }
            }
            catch (ManagementException) { return null; }
            catch (UnauthorizedAccessException) { return null; }
            catch (COMException) { return null; }
            return results;
        }

        private void RestoreVerify()
        {
            evidence.Stage = "Test artifact cleanup";
            if (launchedProcess != null)
            {
                // Kill the launcher first, then enumerate and kill its children: if it were killed
                // last, it could still be alive (and spawn a new, unaccounted-for child) in the gap
                // between listing children and terminating it. Its own PID is safe to hold across this
                // -- this Process object still references it throughout, unlike the transient handles
                // used for each discovered child below.
                try
                {
                    if (!launchedProcess.HasExited) { launchedProcess.Kill(); launchedProcess.WaitForExit(3000); }
                }
                catch (Exception) { }
                finally { launchedProcess.Dispose(); }
                List<AsrOwnedProcess> children = FindChildProcesses(null);
                if (children == null)
                {
                    ConsoleUi.Status("WARN", "Could not query the process tree for cleanup (WMI access restricted on " +
                        "this host); manually verify no child process remains.");
                }
                else { foreach (AsrOwnedProcess candidate in children) { KillIfSameInstance(candidate); } }
            }
            if (createdArtifact && testDirectory != null && Directory.Exists(testDirectory))
            {
                try { Directory.Delete(testDirectory, true); }
                catch (IOException) { }
                catch (UnauthorizedAccessException) { }
            }
        }

        // Killing by PID alone races: if the queried process already exited, its PID can be reused by
        // an unrelated process before this runs, and Process.GetProcessById(pid) would then open THAT
        // process. Re-verifying the freshly opened handle's own StartTime against the CreationDate the
        // WMI query recorded (IsSameProcessInstance) confirms it is still the same process before Kill
        // -- but only once that handle is actually pinned: Process lazily opens a short-lived handle
        // per call (StartTime opens and closes its own), so without forcing one one open first, Kill()
        // would separately reopen by PID and could still land on a process that reused it in between.
        // Touching .Handle up front caches a single native handle that StartTime, Kill and WaitForExit
        // all then share, closing that gap rather than merely narrowing it.
        private static void KillIfSameInstance(AsrOwnedProcess candidate)
        {
            try
            {
                using (Process handle = Process.GetProcessById(candidate.ProcessId))
                {
                    if (handle.Handle == IntPtr.Zero) { return; }
                    if (IsSameProcessInstance(candidate.CreatedAt, handle.StartTime))
                    { handle.Kill(); handle.WaitForExit(3000); }
                }
            }
            catch (Exception) { }
        }

        private VerificationStatus VerifyRestoredVerify()
        {
            bool directoryClean = !createdArtifact || testDirectory == null || !Directory.Exists(testDirectory);
            if (!directoryClean) { return VerificationStatus.Mismatch; }
            if (launchedProcess == null) { return VerificationStatus.Confirmed; }
            if (targetMayBeUntrackable)
            {
                ConsoleUi.Status("WARN", "Process-based cleanup confirmation is unavailable on this host (see the " +
                    "earlier redirection warning); manually verify no window remains.");
                return VerificationStatus.Unavailable;
            }
            bool? launcherExited = IsLauncherConfirmedExited();
            if (launcherExited == false)
            {
                ConsoleUi.Status("FAIL", "The launcher process could not be confirmed terminated.", true);
                return VerificationStatus.Mismatch;
            }
            List<AsrOwnedProcess> remaining = FindChildProcesses(null);
            if (launcherExited == null || remaining == null)
            {
                ConsoleUi.Status("WARN", "Process-tree cleanup could not be fully confirmed (WMI access restricted on " +
                    "this host); manually verify no window remains.");
                return VerificationStatus.Unavailable;
            }
            return remaining.Count == 0 ? VerificationStatus.Confirmed : VerificationStatus.Mismatch;
        }

        // true: confirmed exited (no process with this PID and start time still exists). false:
        // confirmed still running as the exact same instance RestoreVerify was supposed to have killed.
        // null: could not be determined (e.g. access denied opening the handle) -- treated the same as
        // every other "cannot observe" case in this module, never silently folded into Confirmed.
        private bool? IsLauncherConfirmedExited()
        {
            try
            {
                using (Process check = Process.GetProcessById(launcherProcessId))
                { return !IsSameProcessInstance(launcherStartTime, check.StartTime); }
            }
            catch (ArgumentException) { return true; }
            catch (Exception) { return null; }
        }
    }

    // Single-quoted PowerShell string literals do not expand variables and need only one escape rule
    // (a literal quote character becomes two), so this alone is sufficient for a path that may
    // contain spaces (which would otherwise be parsed as separate positional arguments) or a $ (which
    // would otherwise expand as a variable reference inside an unquoted or double-quoted argument --
    // silently turning, say, "C:\Temp$Lab" into "C:\Temp", which could be a real, unrelated,
    // pre-existing exclusion). PowerShell's tokenizer also accepts the Unicode "smart quote" variants
    // (U+2018/2019/201A/201B) as quote characters -- real in copy-pasted folder names -- so an
    // unescaped one would still break the command's parse even though it isn't an ASCII '.
    private static readonly char[] PowerShellQuoteChars = { '\'', '\u2018', '\u2019', '\u201A', '\u201B' };

    internal static IEnumerable<string> QuotePowerShellPaths(IEnumerable<string> paths)
    {
        foreach (string path in paths)
        {
            var escaped = new StringBuilder("'");
            foreach (char c in path)
            {
                escaped.Append(c);
                if (Array.IndexOf(PowerShellQuoteChars, c) >= 0) { escaped.Append(c); }
            }
            escaped.Append('\'');
            yield return escaped.ToString();
        }
    }

    // A discovered candidate process plus the creation timestamp WMI reported for it at query time,
    // carried forward so the kill step can re-verify it is still the same process before terminating it.
    internal sealed class AsrOwnedProcess
    {
        internal readonly int ProcessId;
        internal readonly DateTime CreatedAt;
        internal AsrOwnedProcess(int processId, DateTime createdAt) { ProcessId = processId; CreatedAt = createdAt; }
    }

    // Pure ownership decision, independent of the WMI query that supplies its inputs: a process is
    // this run's child only if Windows itself recorded it as a child of the exact launcher PID (and,
    // when an image name is required, with that exact name), created no earlier than the launcher --
    // the last check excludes a candidate whose CreationDate cannot possibly belong to this run.
    internal static bool IsOwnedChildProcess(int candidateParentProcessId, string candidateImageName, DateTime candidateCreated,
        int expectedParentProcessId, string expectedImageNameOrNull, DateTime launcherStartTime)
    {
        return candidateParentProcessId == expectedParentProcessId &&
            (expectedImageNameOrNull == null ||
                string.Equals(candidateImageName, expectedImageNameOrNull, StringComparison.OrdinalIgnoreCase)) &&
            candidateCreated >= launcherStartTime;
    }

    // WMI's CIM datetime string has microsecond resolution while Process.StartTime reads the raw
    // 100ns FILETIME, so exact equality would spuriously reject the very same process; a couple of
    // milliseconds of tolerance absorbs that truncation while still rejecting a genuinely different
    // process (which, being a distinct creation event, differs by much more than rounding error).
    internal static bool IsSameProcessInstance(DateTime recordedCreationTime, DateTime handleStartTime)
    { return Math.Abs((recordedCreationTime - handleStartTime).TotalMilliseconds) <= 2; }

    // Split out so a deterministic test can call it directly against a temp directory and assert
    // both the file and its Zone.Identifier alternate data stream were actually written.
    internal static void CreateTestArtifact(string directory, string filePath)
    {
        Directory.CreateDirectory(directory);
        File.WriteAllText(filePath,
            "var shell = new ActiveXObject(\"WScript.Shell\"); shell.Run(\"notepad.exe\");", Encoding.ASCII);
        AlternateDataStream.WriteText(filePath + ":Zone.Identifier", "[ZoneTransfer]\r\nZoneId=3\r\n");
    }

    // Pure decision: local process-presence evidence can only ever support two conclusions.
    // Absence is ambiguous (many unrelated causes), so it is never enough for Confirmed.
    // Presence despite an action that should stop the primitive by default (Block, and Warn's
    // default-block-with-bypass-option behavior) is the one unambiguous signal this primitive
    // can produce, so that case alone is reported Mismatch. Every other combination -- including
    // Audit (real evidence is event 1122, not process presence) and Disabled/NotConfigured
    // (presence is simply expected and uninformative) -- is Unavailable.
    internal static VerificationStatus EvaluateTestOutcome(AsrAction action, bool childObserved)
    {
        if (childObserved && (action == AsrAction.Block || action == AsrAction.Warn))
        { return VerificationStatus.Mismatch; }
        return VerificationStatus.Unavailable;
    }

    // MSFT_MpPreference aside, writing a NTFS alternate data stream (":Zone.Identifier") through
    // File.WriteAllText fails with NotSupportedException under this build's legacy path handling
    // (no app.config / TargetFrameworkAttribute opts into the newer path normalizer). CreateFileW
    // takes the raw path directly, bypassing that managed validation entirely.
    private static class AlternateDataStream
    {
        private const uint GenericWrite = 0x40000000;
        private const uint CreateAlways = 2;
        private const uint FileAttributeNormal = 0x80;

        [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        private static extern SafeFileHandle CreateFileW(string lpFileName, uint dwDesiredAccess, uint dwShareMode,
            IntPtr lpSecurityAttributes, uint dwCreationDisposition, uint dwFlagsAndAttributes, IntPtr hTemplateFile);

        internal static void WriteText(string streamPath, string content)
        {
            SafeFileHandle handle = CreateFileW(streamPath, GenericWrite, 0, IntPtr.Zero,
                CreateAlways, FileAttributeNormal, IntPtr.Zero);
            if (handle.IsInvalid)
            {
                throw new System.ComponentModel.Win32Exception(Marshal.GetLastWin32Error(),
                    "CreateFileW failed for alternate data stream: " + streamPath);
            }
            using (handle)
            using (var stream = new FileStream(handle, FileAccess.Write))
            {
                byte[] bytes = Encoding.ASCII.GetBytes(content);
                stream.Write(bytes, 0, bytes.Length);
            }
        }
    }

    private sealed class AsrReader : IAsrReader
    {
        private readonly IAsrBackend inner;
        internal AsrReader(IAsrBackend inner) { this.inner = inner; }
        public void Connect() { inner.Connect(); }
        public void Prepare(AsrMutationRequest request) { inner.Prepare(request); }
        public bool Supports(string name) { return inner.Supports(name); }
        public AsrSnapshot Read() { return inner.Read(); }
        public Dictionary<string, AsrPolicySourceKind> ReadPolicySource(IEnumerable<string> keys)
        { return inner.ReadPolicySource(keys); }
        public bool IsNotepadRedirectionActive() { return inner.IsNotepadRedirectionActive(); }
    }

    private sealed class AsrWriter : IAsrWriter
    {
        private readonly IAsrBackend inner;
        internal AsrWriter(IAsrBackend inner) { this.inner = inner; }
        public object Add() { return inner.Add(); }
    }
}
