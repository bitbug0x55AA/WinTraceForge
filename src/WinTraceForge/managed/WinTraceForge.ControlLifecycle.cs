// This Source Code Form is subject to the terms of the
// Mozilla Public License, v. 2.0.
// If a copy of the MPL was not distributed with this file, You can obtain one at https://mozilla.org/MPL/2.0/.

using System;
using System.Collections.Generic;

internal enum ProbeStatus { NotRun, Ready, ReadOnlyConfirmed, ReadOnlyMismatch, Failed }
internal enum MutationStatus { NotAttempted, Attempted, ApiSucceeded, ApiFailed, ApiUnknown }
internal enum VerificationStatus { NotRun, Confirmed, Mismatch, Unavailable }
internal enum ObservationStatus { NotRequested, Observed, NotObserved, Incomplete, Failed, Unavailable }
internal enum RestorationPolicy { None, Manual, Automatic }
internal enum RestorationStatus { NotRequired, Required, Attempted, Succeeded, Failed, Unavailable, ManualRequired }

// Use this gate in the family backend facade, so Probe/Verify/Observe have no write capability.
internal sealed class ControlMutationGate
{
    private bool writeAllowed;
    internal void Open() { writeAllowed = true; }
    internal void Close() { writeAllowed = false; }
    internal void RequireWrite()
    {
        if (!writeAllowed) { throw new InvalidOperationException("Persistent writes are forbidden outside mutation/restoration."); }
    }
}

internal sealed class ProbeResult<TBaseline> where TBaseline : class
{
    internal readonly TBaseline Baseline;
    internal readonly ProbeStatus Status;
    internal readonly RestorationPolicy Restoration;

    internal ProbeResult(TBaseline baseline, ProbeStatus status, RestorationPolicy restoration)
    {
        if (status != ProbeStatus.Ready && status != ProbeStatus.ReadOnlyConfirmed &&
            status != ProbeStatus.ReadOnlyMismatch) { throw new ArgumentException("Invalid successful probe status."); }
        if (status == ProbeStatus.Ready && baseline == null) { throw new ArgumentNullException("baseline"); }
        if (status == ProbeStatus.Ready && restoration == RestorationPolicy.None)
        { throw new ArgumentException("Mutating operations require an explicit restoration policy."); }
        if (status != ProbeStatus.Ready && restoration != RestorationPolicy.None)
        { throw new ArgumentException("Read-only probes cannot require restoration."); }
        Baseline = baseline;
        Status = status;
        Restoration = restoration;
    }
}

// A family implements one operation, with its Windows backend supplied by its own module.
// Probe must use only read methods. The runner is the only caller of Mutate and Restore.
internal interface IControlOperation<TBaseline> where TBaseline : class
{
    string Transport { get; }
    ControlMutationGate WriteGate { get; }
    ProbeResult<TBaseline> Probe();
    MutationStatus Mutate(TBaseline baseline);
    VerificationStatus Verify(TBaseline baseline);
    bool VerifyAfterApiFailure { get; }
    void Restore(TBaseline baseline);
    VerificationStatus VerifyRestored(TBaseline baseline);
    string ManualRestoration { get; }
}

internal sealed class ControlLifecycleResult<TBaseline> where TBaseline : class
{
    internal TBaseline Baseline { get; private set; }
    internal string Transport { get; private set; }
    internal ProbeStatus Probe { get; private set; }
    internal MutationStatus Mutation { get; private set; }
    internal VerificationStatus Verification { get; private set; }
    internal ObservationStatus Observation { get; private set; }
    internal RestorationStatus Restoration { get; private set; }
    internal string ManualRestoration { get; private set; }
    internal readonly List<string> Warnings = new List<string>();
    internal readonly List<string> Errors = new List<string>();

    internal ControlLifecycleResult(string transport)
    {
        if (string.IsNullOrWhiteSpace(transport)) { throw new ArgumentException("A selected transport is required."); }
        Transport = transport;
        Probe = ProbeStatus.NotRun;
        Mutation = MutationStatus.NotAttempted;
        Verification = VerificationStatus.NotRun;
        Observation = ObservationStatus.NotRequested;
        Restoration = RestorationStatus.NotRequired;
    }

    internal void SetProbe(ProbeResult<TBaseline> value)
    {
        if (Probe != ProbeStatus.NotRun) { throw new InvalidOperationException("Probe already completed."); }
        Baseline = value.Baseline;
        Probe = value.Status;
        if (value.Status == ProbeStatus.Ready && value.Restoration != RestorationPolicy.None)
        { Restoration = RestorationStatus.Required; }
    }

    private static string Describe(Exception error)
    { return error.Message + " (HRESULT 0x" + error.HResult.ToString("X8") + ")"; }
    internal void ProbeFailed(Exception error) { Probe = ProbeStatus.Failed; Errors.Add("Probe: " + Describe(error)); }
    internal void MutationAttempted() { Mutation = MutationStatus.Attempted; }
    internal void MutationReturned(MutationStatus status)
    {
        if (status != MutationStatus.ApiSucceeded && status != MutationStatus.ApiFailed &&
            status != MutationStatus.ApiUnknown) { throw new ArgumentException("Mutation must return an API status."); }
        Mutation = status;
    }
    internal void MutationFailed(Exception error) { Mutation = MutationStatus.ApiFailed; Errors.Add("Mutation: " + Describe(error)); }
    internal void SetVerification(VerificationStatus status) { Verification = status; }
    internal void VerificationFailed(Exception error)
    { Verification = VerificationStatus.Unavailable; Errors.Add("Verification: " + Describe(error)); }
    internal void SetObservation(ObservationStatus status) { Observation = status; }
    internal void ObservationFailed(Exception error)
    { Observation = ObservationStatus.Failed; Warnings.Add("Observation: " + error.Message); }
    internal void SetRestoration(RestorationStatus status) { Restoration = status; }
    internal void RestorationFailed(Exception error)
    { Restoration = RestorationStatus.Failed; Errors.Add("Restoration: " + Describe(error)); }
    internal void SetManualRestoration(string instruction)
    {
        if (string.IsNullOrWhiteSpace(instruction))
        { throw new InvalidOperationException("Manual restoration requires a cleanup instruction."); }
        ManualRestoration = instruction;
        Restoration = RestorationStatus.ManualRequired;
    }

    internal int ExitCode
    {
        get
        {
            if (Probe == ProbeStatus.Failed || Mutation == MutationStatus.ApiFailed ||
                Restoration == RestorationStatus.Failed || Restoration == RestorationStatus.Unavailable) { return 1; }
            if (Probe == ProbeStatus.ReadOnlyMismatch || Verification == VerificationStatus.Mismatch ||
                Verification == VerificationStatus.Unavailable) { return 3; }
            if (Probe == ProbeStatus.ReadOnlyConfirmed) { return 0; }
            return Probe == ProbeStatus.Ready && Verification == VerificationStatus.Confirmed ? 0 : 1;
        }
    }
}

internal static class ControlLifecycle
{
    // Observation runs even after a control error; automatic restoration always follows it.
    internal static ControlLifecycleResult<TBaseline> Run<TBaseline>(IControlOperation<TBaseline> operation,
        Func<ControlLifecycleResult<TBaseline>, ObservationStatus> observe) where TBaseline : class
    {
        if (operation == null) { throw new ArgumentNullException("operation"); }
        ControlMutationGate gate = operation.WriteGate;
        if (gate == null) { throw new InvalidOperationException("A lifecycle write gate is required."); }
        gate.Close();
        var result = new ControlLifecycleResult<TBaseline>(operation.Transport);
        ProbeResult<TBaseline> probe;
        try
        {
            probe = operation.Probe();
            if (probe == null) { throw new InvalidOperationException("Probe returned no result."); }
            result.SetProbe(probe);
        }
        catch (Exception error) { result.ProbeFailed(error); return result; }

        if (probe.Status == ProbeStatus.Ready)
        {
            try
            {
                result.MutationAttempted();
                gate.Open();
                result.MutationReturned(operation.Mutate(probe.Baseline));
            }
            catch (Exception error) { result.MutationFailed(error); }
            finally { gate.Close(); }

            if (result.Mutation != MutationStatus.ApiFailed || operation.VerifyAfterApiFailure)
            {
                try { result.SetVerification(operation.Verify(probe.Baseline)); }
                catch (Exception error) { result.VerificationFailed(error); }
            }
        }

        try
        {
            if (observe != null) { result.SetObservation(observe(result)); }
        }
        catch (Exception error) { result.ObservationFailed(error); }
        finally
        {
            if (result.Mutation != MutationStatus.NotAttempted && probe.Restoration == RestorationPolicy.Manual)
            {
                try { result.SetManualRestoration(operation.ManualRestoration); }
                catch (Exception error) { result.RestorationFailed(error); }
            }
            else if (result.Mutation != MutationStatus.NotAttempted && probe.Restoration == RestorationPolicy.Automatic)
            {
                result.SetRestoration(RestorationStatus.Attempted);
                try
                {
                    gate.Open();
                    operation.Restore(probe.Baseline);
                    gate.Close();
                    VerificationStatus restored = operation.VerifyRestored(probe.Baseline);
                    result.SetRestoration(restored == VerificationStatus.Confirmed ? RestorationStatus.Succeeded :
                        restored == VerificationStatus.Unavailable ? RestorationStatus.Unavailable : RestorationStatus.Failed);
                }
                catch (Exception error) { result.RestorationFailed(error); }
                finally { gate.Close(); }
            }
            else { result.SetRestoration(RestorationStatus.NotRequired); }
        }
        return result;
    }
}
