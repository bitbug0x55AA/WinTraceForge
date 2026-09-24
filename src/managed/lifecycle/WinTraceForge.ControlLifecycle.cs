// This Source Code Form is subject to the terms of the
// Mozilla Public License, v. 2.0.
// If a copy of the MPL was not distributed with this file, You can obtain one at https://mozilla.org/MPL/2.0/.

using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;

internal enum ProbeStatus { NotRun, Ready, ReadOnlyConfirmed, ReadOnlyMismatch, Failed }
internal enum MutationStatus { NotAttempted, Attempted, ApiSucceeded, ApiFailed, ApiUnknown }
internal enum VerificationStatus { NotRun, Confirmed, Mismatch, Unavailable }
internal enum ObservationStatus { NotRequested, Observed, NotObserved, Incomplete, Failed, Unavailable }
internal enum RestorationPolicy { None, Manual, Automatic }
internal enum RestorationStatus { NotRequired, Required, Attempted, Succeeded, Failed, Unavailable, ManualRequired }

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
        Baseline = baseline; Status = status; Restoration = restoration;
    }
}

// An operation owns decisions and phase outcomes, never a backend or a write gate.
// The runner supplies a read-only facade to read phases and a separate writer to write phases.
internal interface IControlOperation<TBaseline, TReader, TWriter> where TBaseline : class
{
    string Transport { get; }
    ProbeResult<TBaseline> Probe(TReader reader);
    MutationStatus Mutate(TBaseline baseline, TWriter writer);
    VerificationStatus Verify(TBaseline baseline, TReader reader);
    bool VerifyAfterApiFailure { get; }
    void Restore(TBaseline baseline, TWriter writer);
    VerificationStatus VerifyRestored(TBaseline baseline, TReader reader);
    string ManualRestoration { get; }
}

internal interface IControlLifecycleSnapshot
{
    ProbeStatus Probe { get; }
    MutationStatus Mutation { get; }
    VerificationStatus Verification { get; }
    ObservationStatus Observation { get; }
    RestorationStatus Restoration { get; }
}

// Immutable copy: even an observer that downcasts cannot rewrite lifecycle facts.
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
    internal ReadOnlyCollection<string> Warnings { get; private set; }
    internal ReadOnlyCollection<string> Errors { get; private set; }

    private ControlLifecycleResult(TBaseline baseline, string transport, ProbeStatus probe,
        MutationStatus mutation, VerificationStatus verification, ObservationStatus observation,
        RestorationStatus restoration, string manualRestoration, IList<string> warnings, IList<string> errors)
    {
        Baseline = baseline; Transport = transport; Probe = probe; Mutation = mutation;
        Verification = verification; Observation = observation; Restoration = restoration;
        ManualRestoration = manualRestoration;
        Warnings = Array.AsReadOnly(new List<string>(warnings).ToArray());
        Errors = Array.AsReadOnly(new List<string>(errors).ToArray());
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

    // This is the sole mutable lifecycle record. It never leaves the runner.
    private sealed class State
    {
        internal TBaseline Baseline;
        internal readonly string Transport;
        internal ProbeStatus Probe = ProbeStatus.NotRun;
        internal MutationStatus Mutation = MutationStatus.NotAttempted;
        internal VerificationStatus Verification = VerificationStatus.NotRun;
        internal ObservationStatus Observation = ObservationStatus.NotRequested;
        internal RestorationStatus Restoration = RestorationStatus.NotRequired;
        internal string ManualRestoration;
        internal readonly List<string> Warnings = new List<string>();
        internal readonly List<string> Errors = new List<string>();
        internal State(string transport)
        {
            if (string.IsNullOrWhiteSpace(transport)) { throw new ArgumentException("A selected transport is required."); }
            Transport = transport;
        }
        internal ControlLifecycleResult<TBaseline> Snapshot()
        {
            return new ControlLifecycleResult<TBaseline>(Baseline, Transport, Probe, Mutation,
                Verification, Observation, Restoration, ManualRestoration, Warnings, Errors);
        }
        internal IControlLifecycleSnapshot ObservationSnapshot()
        { return new ObservationView(Probe, Mutation, Verification, Observation, Restoration); }
        internal static string Describe(Exception error)
        { return error.Message + " (HRESULT 0x" + error.HResult.ToString("X8") + ")"; }
    }

    private sealed class ObservationView : IControlLifecycleSnapshot
    {
        public ProbeStatus Probe { get; private set; }
        public MutationStatus Mutation { get; private set; }
        public VerificationStatus Verification { get; private set; }
        public ObservationStatus Observation { get; private set; }
        public RestorationStatus Restoration { get; private set; }
        internal ObservationView(ProbeStatus probe, MutationStatus mutation, VerificationStatus verification,
            ObservationStatus observation, RestorationStatus restoration)
        { Probe = probe; Mutation = mutation; Verification = verification; Observation = observation; Restoration = restoration; }
    }

    // The only invocation site holding both capabilities is the shared runner.
    internal static ControlLifecycleResult<TBaseline> Run<TReader, TWriter>(
        IControlOperation<TBaseline, TReader, TWriter> operation, TReader reader, TWriter writer,
        Func<IControlLifecycleSnapshot, ObservationStatus> observe)
    {
        if (operation == null) { throw new ArgumentNullException("operation"); }
        if (reader == null || writer == null) { throw new ArgumentNullException("capability"); }
        if (((object)reader) is TWriter)
        { throw new ArgumentException("The read capability must not also expose the writer contract."); }
        var state = new State(operation.Transport);
        ProbeResult<TBaseline> probe;
        try
        {
            probe = operation.Probe(reader);
            if (probe == null) { throw new InvalidOperationException("Probe returned no result."); }
            state.Baseline = probe.Baseline;
            state.Probe = probe.Status;
            if (probe.Status == ProbeStatus.Ready) { state.Restoration = RestorationStatus.Required; }
        }
        catch (Exception error)
        {
            state.Probe = ProbeStatus.Failed;
            state.Errors.Add("Probe: " + State.Describe(error));
            return state.Snapshot();
        }

        if (probe.Status == ProbeStatus.Ready)
        {
            try
            {
                state.Mutation = MutationStatus.Attempted;
                MutationStatus returned = operation.Mutate(probe.Baseline, writer);
                if (returned != MutationStatus.ApiSucceeded && returned != MutationStatus.ApiFailed &&
                    returned != MutationStatus.ApiUnknown) { throw new ArgumentException("Mutation must return an API status."); }
                state.Mutation = returned;
            }
            catch (Exception error)
            {
                state.Mutation = MutationStatus.ApiFailed;
                state.Errors.Add("Mutation: " + State.Describe(error));
            }
            if (state.Mutation != MutationStatus.ApiFailed || operation.VerifyAfterApiFailure)
            {
                try { state.Verification = operation.Verify(probe.Baseline, reader); }
                catch (Exception error)
                {
                    state.Verification = VerificationStatus.Unavailable;
                    state.Errors.Add("Verification: " + State.Describe(error));
                }
            }
        }

        try
        {
            if (observe != null) { state.Observation = observe(state.ObservationSnapshot()); }
        }
        catch (Exception error)
        {
            state.Observation = ObservationStatus.Failed;
            state.Warnings.Add("Observation: " + error.Message);
        }
        finally
        {
            if (state.Mutation != MutationStatus.NotAttempted && probe.Restoration == RestorationPolicy.Manual)
            {
                try
                {
                    string instruction = operation.ManualRestoration;
                    if (string.IsNullOrWhiteSpace(instruction))
                    { throw new InvalidOperationException("Manual restoration requires a cleanup instruction."); }
                    state.ManualRestoration = instruction;
                    state.Restoration = RestorationStatus.ManualRequired;
                }
                catch (Exception error)
                {
                    state.Restoration = RestorationStatus.Failed;
                    state.Errors.Add("Restoration: " + State.Describe(error));
                }
            }
            else if (state.Mutation != MutationStatus.NotAttempted && probe.Restoration == RestorationPolicy.Automatic)
            {
                state.Restoration = RestorationStatus.Attempted;
                try
                {
                    operation.Restore(probe.Baseline, writer);
                    VerificationStatus restored = operation.VerifyRestored(probe.Baseline, reader);
                    state.Restoration = restored == VerificationStatus.Confirmed ? RestorationStatus.Succeeded :
                        restored == VerificationStatus.Unavailable ? RestorationStatus.Unavailable : RestorationStatus.Failed;
                }
                catch (Exception error)
                {
                    state.Restoration = RestorationStatus.Failed;
                    state.Errors.Add("Restoration: " + State.Describe(error));
                }
            }
            else { state.Restoration = RestorationStatus.NotRequired; }
        }
        return state.Snapshot();
    }
}

internal static class ControlLifecycle
{
    internal static ControlLifecycleResult<TBaseline> Run<TBaseline, TReader, TWriter>(
        IControlOperation<TBaseline, TReader, TWriter> operation, TReader reader, TWriter writer,
        Func<IControlLifecycleSnapshot, ObservationStatus> observe) where TBaseline : class
    { return ControlLifecycleResult<TBaseline>.Run(operation, reader, writer, observe); }
}
