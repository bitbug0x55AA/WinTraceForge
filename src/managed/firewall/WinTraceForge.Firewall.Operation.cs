// This Source Code Form is subject to the terms of the
// Mozilla Public License, v. 2.0.
// If a copy of the MPL was not distributed with this file, You can obtain one at https://mozilla.org/MPL/2.0/.

using System;
using System.Collections.Generic;
using System.Globalization;

internal sealed class FirewallBaseline
{
    internal readonly IList<FirewallRuleData> Rules;
    internal readonly FirewallRuleData Expected;
    internal FirewallBaseline(IList<FirewallRuleData> rules, FirewallRuleData expected)
    { Rules = rules; Expected = expected; }
}

internal static partial class FirewallModule
{
    private sealed class FirewallOperation : IControlOperation<FirewallBaseline, IFirewallReader, IFirewallWriter>
    {
        private readonly FirewallOptions options;
        private readonly FirewallRunEvidence evidence;
        internal FirewallOperation(FirewallOptions options, FirewallRunEvidence evidence)
        { this.options = options; this.evidence = evidence; }
        public string Transport { get { return options.Transport; } }
        public bool VerifyAfterApiFailure { get { return false; } }
        public string ManualRestoration
        {
            get
            {
                return options.Operation == "add" ? CleanupCommand(options) :
                    "Inspect rule " + options.RuleName + " and the captured baseline before any restoration.";
            }
        }

        public ProbeResult<FirewallBaseline> Probe(IFirewallReader backend)
        {
            if (options.Kind == ControlKind.FirewallProfiles)
            {
                evidence.Stage = "Firewall profile read";
                int current = backend.CurrentProfiles;
                ConsoleUi.Section("Firewall profiles (read-only)");
                ConsoleUi.Row("Active profile mask", current.ToString(CultureInfo.InvariantCulture));
                ConsoleUi.Row("Local modify state", ModifyState(backend.LocalPolicyModifyState));
                foreach (FirewallProfileData profile in backend.ReadProfiles())
                {
                    ConsoleUi.Row(ProfileName(profile.Profile), "enabled=" + profile.Enabled +
                        "; block-all-inbound=" + profile.BlockAllInbound +
                        "; default inbound=" + ActionName(profile.DefaultInboundAction) +
                        "; default outbound=" + ActionName(profile.DefaultOutboundAction));
                    ConsoleUi.Row("Excluded interfaces", string.Join(", ", profile.ExcludedInterfaces));
                }
                ConsoleUi.Text("LocalPolicyModifyState describes current policy restrictions, not per-profile merge settings. " +
                    "INetFwPolicy2 does not expose all GPO/MDM local-rule merge limits; those are not established here.");
                evidence.ReadbackConfirmed = true;
                evidence.Outcome = "Profile settings read only; no settings changed.";
                return ReadOnly(null, ProbeStatus.ReadOnlyConfirmed);
            }

            ConsoleUi.Section("Firewall rule " + options.Operation);
            ConsoleUi.Row(options.GeneratedId ? "Generated ID" : "Rule ID", options.Id.ToString("D"));
            ConsoleUi.Row("Rule name", options.RuleName);
            ConsoleUi.Text("Cleanup: " + CleanupCommand(options));
            ConsoleUi.Text("Name-based COM operations are not atomic with enumeration: concurrent writers can race " +
                "ownership checks. Use a unique ID and avoid concurrent changes. Markers are not an authentication boundary.");
            evidence.Stage = "Firewall baseline";
            IList<FirewallRuleData> baseline = backend.FindByName(options.RuleName);
            evidence.BaselineRead = true;
            ConsoleUi.Section("Baseline");
            ConsoleUi.Status("INFO", baseline.Count == 0 ? "Rule not present." :
                baseline.Count + " matching rule name(s) found; ownership must be verified.");

            if (options.Operation == "add")
            {
                if (baseline.Count != 0) { throw new FirewallRefusalException("Add refused: this name already exists (including owned/duplicate rules). Choose another ID."); }
                int profiles = options.Profiles == 0 ? backend.CurrentProfiles : options.Profiles;
                if (profiles <= 0 || (profiles & ~7) != 0)
                { throw new FirewallRefusalException("Invalid/empty active profile mask; no fallback to all profiles and no mutation."); }
                evidence.FrozenProfiles = profiles;
                evidence.Stage = "Firewall local policy context";
                evidence.PolicyModifyState = backend.LocalPolicyModifyState;
                FirewallRuleData expected = ExpectedRule(options, profiles);
                ConsoleUi.Section("Request");
                ConsoleUi.Row("Local modify state", ModifyState(evidence.PolicyModifyState.Value));
                ConsoleUi.Text("Policy restriction indicator only; not complete resultant GPO/MDM policy or per-rule merge acceptance.");
                if (evidence.PolicyModifyState.Value != 0)
                { ConsoleUi.Status("WARN", "Local policy restrictions may affect enforcement even if this rule is persisted."); }
                ConsoleUi.Row("Direction / action", (options.Direction == 1 ? "in" : "out") + " / " + ActionName(options.Action));
                ConsoleUi.Row("Protocol / profiles", (options.Protocol == 6 ? "TCP" : "UDP") + " / " + profiles);
                ConsoleUi.Row("Remote address:port", expected.RemoteAddresses + " : " + expected.RemotePorts);
                ConsoleUi.Row("Local port / program", expected.LocalPorts + " / " +
                    (expected.ApplicationName.Length == 0 ? "(all programs)" : expected.ApplicationName));
                evidence.Stage = "Firewall detached rule preparation";
                backend.PrepareAdd(expected);
                evidence.Stage = "Firewall add name refresh";
                if (backend.FindByName(options.RuleName).Count != 0)
                { throw new FirewallRefusalException("Add refused: the rule name appeared during preflight."); }
                return new ProbeResult<FirewallBaseline>(new FirewallBaseline(baseline, expected),
                    ProbeStatus.Ready, RestorationPolicy.Manual);
            }
            if (baseline.Count == 0)
            {
                if (options.Operation == "remove")
                {
                    evidence.AlreadyAbsent = true;
                    evidence.ReadbackConfirmed = true;
                    evidence.Outcome = "Already absent at inspection; no Remove call made (idempotent).";
                    return ReadOnly(baseline, ProbeStatus.ReadOnlyConfirmed);
                }
                evidence.Outcome = "Check: expected test rule is absent; no mutation attempted.";
                return ReadOnly(baseline, ProbeStatus.ReadOnlyMismatch);
            }
            RequireOwnedUnique(options, baseline);
            if (options.Operation == "check")
            {
                ConsoleUi.Section("Result / readback");
                ShowRule(baseline[0]);
                evidence.ReadbackConfirmed = true;
                evidence.Outcome = "Check confirmed one matching ownership marker; properties shown, not compared to an original add request.";
                return ReadOnly(baseline, ProbeStatus.ReadOnlyConfirmed);
            }
            evidence.Stage = "Firewall remove ownership refresh";
            IList<FirewallRuleData> refreshed = backend.FindByName(options.RuleName);
            if (refreshed.Count == 0)
            {
                evidence.AlreadyAbsent = true;
                evidence.ReadbackConfirmed = true;
                evidence.Outcome = "Absent on immediate pre-remove refresh; no Remove call made.";
                return ReadOnly(baseline, ProbeStatus.ReadOnlyConfirmed);
            }
            RequireOwnedUnique(options, refreshed);
            return new ProbeResult<FirewallBaseline>(new FirewallBaseline(baseline, null),
                ProbeStatus.Ready, RestorationPolicy.Manual);
        }

        private static ProbeResult<FirewallBaseline> ReadOnly(IList<FirewallRuleData> rules, ProbeStatus status)
        { return new ProbeResult<FirewallBaseline>(new FirewallBaseline(rules, null), status, RestorationPolicy.None); }

        public MutationStatus Mutate(FirewallBaseline baseline, IFirewallWriter backend)
        {
            evidence.Stage = options.Operation == "add" ? "Firewall Add" : "Firewall Remove";
            evidence.MutationAttempted = true;
            if (options.Operation == "add") { backend.Add(); }
            else { backend.Remove(options.RuleName); }
            evidence.MutationReturned = true;
            return MutationStatus.ApiSucceeded;
        }

        public VerificationStatus Verify(FirewallBaseline baseline, IFirewallReader backend)
        {
            evidence.Stage = options.Operation == "add" ? "Firewall add readback" : "Firewall remove readback";
            ConsoleUi.Section("Result / readback");
            IList<FirewallRuleData> actual = backend.FindByName(options.RuleName);
            if (options.Operation == "remove")
            {
                if (actual.Count != 0)
                {
                    evidence.Outcome = "Remove returned, but the name is still present at readback; no further deletion attempted.";
                    return VerificationStatus.Mismatch;
                }
                evidence.ReadbackConfirmed = true;
                evidence.Outcome = "Remove confirmed: no matching rule name at readback.";
                return VerificationStatus.Confirmed;
            }
            if (actual.Count != 1)
            {
                evidence.Outcome = "Add returned, but readback did not find exactly one rule. No automatic cleanup attempted.";
                return VerificationStatus.Mismatch;
            }
            IList<string> mismatches = Mismatches(baseline.Expected, actual[0]);
            ShowRule(actual[0]);
            if (mismatches.Count != 0)
            {
                evidence.Outcome = "Add readback mismatch: " + string.Join(", ", mismatches) + ". No automatic cleanup attempted.";
                return VerificationStatus.Mismatch;
            }
            evidence.ReadbackConfirmed = true;
            evidence.Outcome = "Add confirmed: all constrained rule attributes match the frozen request.";
            return VerificationStatus.Confirmed;
        }

        public void Restore(FirewallBaseline baseline, IFirewallWriter backend) { throw new NotSupportedException("Manual restoration selected."); }
        public VerificationStatus VerifyRestored(FirewallBaseline baseline, IFirewallReader backend)
        { throw new NotSupportedException("Manual restoration selected."); }
    }

    private sealed class FirewallReader : IFirewallReader
    {
        private readonly IFirewallBackend inner;
        internal FirewallReader(IFirewallBackend inner) { this.inner = inner; }
        public int CurrentProfiles { get { return inner.CurrentProfiles; } }
        public int LocalPolicyModifyState { get { return inner.LocalPolicyModifyState; } }
        public IList<FirewallProfileData> ReadProfiles() { return inner.ReadProfiles(); }
        public IList<FirewallRuleData> FindByName(string name) { return inner.FindByName(name); }
        public void PrepareAdd(FirewallRuleData rule) { inner.PrepareAdd(rule); }
    }

    private sealed class FirewallWriter : IFirewallWriter
    {
        private readonly IFirewallBackend inner;
        internal FirewallWriter(IFirewallBackend inner) { this.inner = inner; }
        public void Add() { inner.Add(); }
        public void Remove(string name) { inner.Remove(name); }
    }
}
