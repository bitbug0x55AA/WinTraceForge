// This Source Code Form is subject to the terms of the Mozilla Public License, v. 2.0.
// If a copy of the MPL was not distributed with this file, You can obtain one at https://mozilla.org/MPL/2.0/.

using System;
using System.Collections.Generic;
using System.IO;
using System.Runtime.InteropServices;

// Compile with /main:FirewallRegressionTests alongside the firewall, Core and ConsoleUi sources.
// Define FIREWALL_TEST_STUBS to replace only telemetry dependencies when testing in isolation.
// The default test run never constructs the native backend or mutates Windows Firewall.
internal static class FirewallRegressionTests
{
    private const string Id = "a365896e-f623-440e-8c31-cb817b35d674";
    private static int assertions;

    private sealed class FakeBackend : IFirewallBackend
    {
        internal readonly List<FirewallRuleData> Rules = new List<FirewallRuleData>();
        internal readonly List<string> Calls = new List<string>();
        internal int Mask = 1;
        internal int ModifyStateValue;
        internal int Adds, Removes, Reads;
        internal bool Disposed, IgnoreRemove;
        internal Action<FakeBackend> BeforeRead;
        internal Action<FirewallRuleData> AfterAdd;
        internal COMException AddError;
        internal COMException PrepareError;
        internal COMException PolicyError;
        internal FirewallRuleData Prepared;
        public int CurrentProfiles { get { Calls.Add("profiles"); return Mask; } }
        public int LocalPolicyModifyState { get { Calls.Add("modify-state"); if (PolicyError != null) { throw PolicyError; } return ModifyStateValue; } }
        public IList<FirewallProfileData> ReadProfiles()
        {
            Calls.Add("readprofiles");
            return new List<FirewallProfileData>
            {
                new FirewallProfileData { Profile = 1, Enabled = true, ExcludedInterfaces = new string[0] }
            };
        }
        public IList<FirewallRuleData> FindByName(string name)
        {
            Calls.Add("read");
            Reads++;
            if (BeforeRead != null) { BeforeRead(this); }
            List<FirewallRuleData> result = new List<FirewallRuleData>();
            foreach (FirewallRuleData rule in Rules)
            {
                if (string.Equals(rule.Name, name, StringComparison.OrdinalIgnoreCase)) { result.Add(rule.Copy()); }
            }
            return result;
        }
        public void PrepareAdd(FirewallRuleData rule)
        {
            Calls.Add("prepare");
            if (PrepareError != null) { throw PrepareError; }
            Prepared = rule.Copy();
        }
        public void Add()
        {
            Calls.Add("add");
            Adds++;
            if (AddError != null) { throw AddError; }
            FirewallRuleData copy = Prepared.Copy();
            Rules.Add(copy);
            if (AfterAdd != null) { AfterAdd(copy); }
        }
        public void Remove(string name)
        {
            Calls.Add("remove");
            Removes++;
            if (!IgnoreRemove) { Rules.RemoveAll(delegate(FirewallRuleData r) { return r.Name == name; }); }
        }
        public void Dispose() { Calls.Add("dispose"); Disposed = true; }
    }

    private static int Main(string[] args)
    {
        if (args.Length == 1 && args[0] == "--native-detached-preflight")
        {
            foreach (int protocol in new int[] { 6, 17 })
            {
                FirewallOptions options = AddOptions();
                options.Id = Guid.NewGuid();
                options.Protocol = protocol;
                options.RemoteAddress = protocol == 6 ? "192.0.2.15" : "2001:db8::1";
                options.Direction = protocol == 6 ? 2 : 1;
                options.Action = protocol == 6 ? 0 : 1;
                options.LocalPort = protocol == 6 ? 0 : 12345;
                options.RemotePort = protocol == 6 ? 443 : 0;
                options.Program = protocol == 6 ? "" : @"C:\Windows\System32\notepad.exe";
                using (IFirewallBackend backend = new ComFirewallBackend())
                {
                    Assert(backend.FindByName(options.RuleName).Count == 0, "detached name initially absent");
                    backend.PrepareAdd(FirewallModule.ExpectedRule(options, 1));
                    Assert(backend.FindByName(options.RuleName).Count == 0, "detached preparation never persists");
                }
            }
            Console.WriteLine("Detached TCP/UDP rule preparation verified; Rules.Add/Remove were never called.");
            return 0;
        }
        if (args.Length == 1 && args[0] == "--native-read-only")
        {
            ConsoleUi.Configure(false, true);
            using (IFirewallBackend backend = new ComFirewallBackend())
            {
                Assert(backend.FindByName(FirewallModule.NameFor(Guid.NewGuid())).Count == 0, "native absent enumeration");
                string existingName = FirstNativeTcpUdpName();
                if (existingName != null)
                {
                    Assert(backend.FindByName(existingName).Count > 0, "native full restriction snapshot");
                    Console.WriteLine("Existing TCP/UDP rule: all restriction properties read successfully.");
                }
            }
            return FirewallModule.Main(new string[] { "profiles", "--no-color" });
        }

        TextWriter original = Console.Out;
        using (StringWriter output = new StringWriter())
        {
            Console.SetOut(output);
            try
            {
                ConsoleUi.Configure(false, true);
                Parsing();
                TransportSelection();
                DirectionalPorts();
                AddAndCleanup();
                Refusals();
                Readback();
                RemovalRaces();
                ReadOnly();
                Assessment();
#if FIREWALL_TEST_STUBS
                EtwFailure();
#endif
                Assert(output.ToString().IndexOf("Cleanup: wtf.exe firewall rule remove --id " + Id, StringComparison.Ordinal) >= 0, "exact cleanup command");
                Console.SetOut(original);
                Console.WriteLine("Firewall regression tests passed: " + assertions + " assertions; no native mutations.");
                return 0;
            }
            finally { Console.SetOut(original); }
        }
    }

    private static string FirstNativeTcpUdpName()
    {
        object policy = null, rules = null, enumeration = null;
        object[] item = new object[1];
        try
        {
            policy = Activator.CreateInstance(Type.GetTypeFromProgID("HNetCfg.FwPolicy2", true));
            rules = NativeGet(policy, "Rules");
            IntPtr pointer;
            int enumerationStatus = ((ComFirewallBackend.IFirewallRulesEnumerator)rules).GetNewEnum(out pointer);
            try
            {
                Marshal.ThrowExceptionForHR(enumerationStatus);
                enumeration = Marshal.GetTypedObjectForIUnknown(pointer, typeof(ComFirewallBackend.IFirewallEnumVariant));
            }
            finally { if (pointer != IntPtr.Zero) { Marshal.Release(pointer); } }
            ComFirewallBackend.IFirewallEnumVariant enumerator = (ComFirewallBackend.IFirewallEnumVariant)enumeration;
            int remaining = 1000;
            while (remaining-- > 0)
            {
                int status = enumerator.Next(1, item, IntPtr.Zero);
                try
                {
                    if (status == 1) { break; }
                    Marshal.ThrowExceptionForHR(status);
                    object rule = item[0];
                    int protocol = (int)NativeGet(rule, "Protocol");
                    if (protocol == 6 || protocol == 17) { return (string)NativeGet(rule, "Name"); }
                }
                finally
                {
                    if (item[0] != null && Marshal.IsComObject(item[0])) { Marshal.FinalReleaseComObject(item[0]); }
                    item[0] = null;
                }
            }
            Console.WriteLine("No TCP/UDP rule within 1000 entries; native full snapshot probe skipped.");
            return null;
        }
        finally
        {
            foreach (object value in new object[] { item[0], enumeration, rules, policy })
            {
                if (value != null && Marshal.IsComObject(value)) { Marshal.FinalReleaseComObject(value); }
            }
        }
    }

    private static object NativeGet(object target, string name)
    {
        return target.GetType().InvokeMember(name, System.Reflection.BindingFlags.GetProperty, null, target, new object[0]);
    }

    private static FirewallOptions AddOptions()
    {
        return FirewallModule.Parse(new string[] { "rule", "add", "--id", Id, "--remote-address", "192.0.2.15", "--remote-port", "443" });
    }
    private static FirewallOptions Options(string operation)
    {
        return FirewallModule.Parse(new string[] { "rule", operation, "--id", Id });
    }
    private static int Run(FirewallOptions options, FakeBackend backend, out FirewallRunEvidence evidence)
    {
        evidence = new FirewallRunEvidence();
        return FirewallModule.Execute(options, evidence, delegate { return backend; }, delegate { return true; });
    }
    private static void Assert(bool condition, string name)
    {
        assertions++;
        if (!condition) { throw new InvalidOperationException("FAILED: " + name); }
    }
    private static void Bad(params string[] args)
    {
        bool rejected = false;
        try { FirewallModule.Parse(args); }
        catch (ArgumentException) { rejected = true; }
        Assert(rejected, "invalid input rejected: " + string.Join(" ", args));
    }

    private static void Parsing()
    {
        FirewallOptions options = AddOptions();
        Assert(options.Transport == "com", "default transport preserves COM behavior");
        Assert(options.Direction == 2 && options.Action == 0 && options.Protocol == 6 && options.Profiles == 0, "safe defaults");
        Assert(options.Id.ToString("D") == Id && !options.GeneratedId, "explicit ID");
        Assert(new List<string>(options.EvidenceValues).Contains("WinTraceForge.Firewall." + Id), "exact deterministic name in telemetry evidence");
        Assert(new List<string>(options.EvidenceValues).Count == 1, "only exact rule name is correlation identity");
        options = FirewallModule.Parse(new string[] { "rule", "add", "--remote-address", "2001:0db8::1", "--remote-port", "65535",
            "--direction", "in", "--action", "allow", "--protocol", "udp", "--profiles", "domain,private", "--local-port", "1",
            "--program", @"C:\Tools\probe.exe", "--verbose", "--no-color", "--telemetry", "eventlog", "--telemetry-wait", "0" });
        Assert(options.GeneratedId && options.Id != Guid.Empty && options.RemoteAddress == "2001:db8::1", "generated ID and IPv6");
        Assert(new List<string>(options.EvidenceValues).Contains(options.RuleName), "generated name in telemetry evidence");
        Assert(options.Direction == 1 && options.Action == 1 && options.Protocol == 17 && options.Profiles == 3 &&
            options.LocalPort == 1 && options.CollectEventLog && options.Verbose && options.NoColor, "all add/common options");
        Assert(FirewallModule.Parse(new string[] { "profiles", "--help" }).Help, "profiles help");
        Assert(FirewallModule.Parse(new string[] { "--help" }).Help, "module help");
        Assert(FirewallModule.Parse(new string[] { "rule", "--help", "--no-color" }).Help, "rule-level help");
        Assert(FirewallModule.Parse(new string[] { "--help", "--verbose" }).Help, "module help with formatting");
        Bad();
        Bad("rule");
        Bad("rule", "off");
        Bad("rule", "add");
        Bad("rule", "check");
        Bad("rule", "remove", "--id", "invalid");
        Bad("rule", "check", "--id", Guid.Empty.ToString());
        Bad("rule", "check", "--id", Id, "--remote-port", "443");
        Bad("profiles", "--id", Id);
        Bad("profiles", "--verbose", "--verbose");
        Bad("profiles", "--help", "-?");
        Bad("profiles", "--telemetry-wait", "1");
        Bad("profiles", "--telemetry", "none", "--telemetry", "etw");
        Bad("profiles", "--telemetry", "etw", "--telemetry-wait", "31");
        Bad("profiles", "--unknown");
        Bad("profiles", "--transport");
        Bad("profiles", "--transport", "cim");
        Bad("profiles", "--transport", "management");
        Bad("profiles", "--transport", "wmi");
        Bad("profiles", "--transport", "native", "--TRANSPORT", "com");
        Bad("rule", "check", "--id", Id, "--transport", "invalid");
        string[] invalidAddresses = { "host.example", "*", "192.0.2.0/24", "127.1", "0x7f000001", "127.00.0.1", "[::1]", "fe80::1%2", "1.2.3.4,2.3.4.5" };
        foreach (string address in invalidAddresses)
        {
            Bad("rule", "add", "--remote-address", address, "--remote-port", "443");
        }
        foreach (string port in new string[] { "0", "65536", "-1", "80-81", "*", "abc" })
        {
            Bad("rule", "add", "--remote-address", "192.0.2.1", "--remote-port", port);
        }
        foreach (string profiles in new string[] { "", "all,domain", "domain,domain", "domain,", "8" })
        {
            Bad("rule", "add", "--remote-address", "192.0.2.1", "--remote-port", "443", "--profiles", profiles);
        }
        foreach (string path in new string[] { "probe.exe", @"C:probe.exe", @"\probe.exe", @"C:\probe.exe:stream.exe", @"\\?\C:\probe.exe", @"C:\*.exe", @"%SystemRoot%\probe.exe" })
        {
            Bad("rule", "add", "--remote-address", "192.0.2.1", "--remote-port", "443", "--program", path);
        }
        Bad("rule", "add", "--remote-address", "192.0.2.1", "--remote-port", "443", "--id", Id, "--ID", Id);
        Bad("rule", "add", "--remote-address", "192.0.2.1", "--remote-port", "443", "--direction", "both");
        Bad("rule", "add", "--remote-address", "192.0.2.1", "--remote-port", "443", "--protocol", "any");
    }

    private static void TransportSelection()
    {
        foreach (string transport in new[] { "com", "native" })
        {
            FirewallOptions options = FirewallModule.Parse(new[] { "profiles", "--transport", transport.ToUpperInvariant() });
            Assert(options.Transport == transport, "profile transport normalized");
            options = FirewallModule.Parse(new[] { "rule", "add", "--remote-address", "192.0.2.10",
                "--remote-port", "44443", "--id", Id, "--transport", transport });
            Assert(options.Transport == transport, "add transport parsed");
            Assert(FirewallModule.CleanupCommand(options).EndsWith("--transport " + transport, StringComparison.Ordinal),
                "cleanup preserves transport");
            FakeBackend backend = new FakeBackend();
            FirewallRunEvidence evidence;
            Assert(Run(options, backend, out evidence) == 0 && backend.Adds == 1, "selected transport add workflow");
            foreach (string operation in new[] { "check", "remove" })
            {
                options = FirewallModule.Parse(new[] { "rule", operation, "--id", Id, "--transport", transport });
                Assert(options.Transport == transport, operation + " transport parsed");
                Assert(Run(options, backend, out evidence) == 0, operation + " selected transport workflow");
            }
            Assert(backend.Removes == 1, "selected transport cleanup exactly once");
        }
        foreach (Exception failure in new Exception[] {
            new DllNotFoundException("missing"), new EntryPointNotFoundException("outdated"),
            new BadImageFormatException("wrong architecture") })
        {
            FirewallOptions options = FirewallModule.Parse(new[] { "profiles", "--transport", "native" });
            FirewallRunEvidence evidence = new FirewallRunEvidence();
            int attempts = 0;
            int code = FirewallModule.Execute(options, evidence, delegate {
                attempts++; throw failure;
            }, delegate { return true; });
            Assert(code == 1 && attempts == 1 && !evidence.MutationAttempted, "native loader error: no fallback");
            Assert(evidence.Outcome.Contains("matching x64") && evidence.Outcome.Contains("No fallback to com"),
                "native dependency diagnostics explicit");
        }
        bool refused = false;
        try { FirewallModule.CreateBackend("invalid"); }
        catch (FirewallRefusalException) { refused = true; }
        Assert(refused, "backend factory never defaults on unknown transport");
    }

    private static void DirectionalPorts()
    {
        foreach (string transport in new[] { "com", "native" })
        {
            foreach (string direction in new[] { "in", "out" })
            {
                string required = direction == "in" ? "--local-port" : "--remote-port";
                string optional = direction == "in" ? "--remote-port" : "--local-port";
                FirewallOptions options = FirewallModule.Parse(new[] { "rule", "add", "--direction", direction,
                    "--remote-address", "192.0.2.10", required, "443", "--transport", transport });
                FirewallRuleData expected = FirewallModule.ExpectedRule(options, 1);
                Assert(expected.LocalPorts == (direction == "in" ? "443" : "*"), "directional local port");
                Assert(expected.RemotePorts == (direction == "in" ? "*" : "443"), "directional remote port");
                FakeBackend backend = new FakeBackend { ModifyStateValue = 1 };
                FirewallRunEvidence evidence;
                Assert(Run(options, backend, out evidence) == 0, "restricted policy context is not readback failure");
                Assert(evidence.PolicyModifyState == 1 && backend.Calls.IndexOf("modify-state") < backend.Calls.IndexOf("add"),
                    "policy restriction read before add");
                Bad("rule", "add", "--direction", direction, "--remote-address", "192.0.2.10", optional, "12345");
                options = FirewallModule.Parse(new[] { "rule", "add", "--direction", direction,
                    "--remote-address", "192.0.2.10", required, "443", optional, "12345" });
                Assert(options.LocalPort != 0 && options.RemotePort != 0, "explicit both-side port restriction preserved");
            }
            var denied = new FakeBackend { PolicyError = new COMException("policy context denied", unchecked((int)0x80070005)) };
            FirewallRunEvidence failed;
            Assert(Run(AddOptions(), denied, out failed) == 1 && denied.Adds == 0 &&
                !failed.MutationAttempted, "policy context read failure explicit before mutation");
        }
    }

    private static void AddAndCleanup()
    {
        FakeBackend backend = new FakeBackend();
        FirewallRunEvidence evidence;
        int code = Run(AddOptions(), backend, out evidence);
        Assert(code == 0 && backend.Adds == 1 && backend.Removes == 0, "add confirmed once");
        Assert(evidence.BaselineRead && evidence.MutationAttempted && evidence.MutationReturned && evidence.ReadbackConfirmed, "add evidence");
        Assert(evidence.FrozenProfiles == 1 && backend.Rules[0].Profiles == 1, "active profiles frozen");
        Assert(string.Join(",", backend.Calls) == "read,profiles,modify-state,prepare,read,add,read,dispose",
            "baseline policy-context prepare mutation readback dispose order");
        Assert(backend.Disposed, "backend released");
        Assert(Run(Options("check"), backend, out evidence) == 0 && backend.Adds == 1 && backend.Removes == 0, "owned check read only");
        Assert(Run(Options("remove"), backend, out evidence) == 0 && backend.Removes == 1 && backend.Rules.Count == 0, "owned cleanup");
        Assert(evidence.MutationReturned && evidence.ReadbackConfirmed, "remove confirmed");
        Assert(Run(Options("remove"), backend, out evidence) == 0 && backend.Removes == 1 && evidence.AlreadyAbsent, "absent remove idempotent");
        Assert(!evidence.MutationAttempted, "absent no mutation flag");
        Assert(Run(Options("check"), backend, out evidence) == 3, "missing check is explicitly unconfirmed");
    }

    private static void Refusals()
    {
        FirewallRunEvidence evidence;
        foreach (int mask in new int[] { 0, -1, 8, int.MaxValue })
        {
            FakeBackend invalid = new FakeBackend { Mask = mask };
            Assert(Run(AddOptions(), invalid, out evidence) == 1 && invalid.Adds == 0 && invalid.Removes == 0, "invalid active mask refuses before mutation");
        }
        FakeBackend explicitProfiles = new FakeBackend { Mask = 0 };
        FirewallOptions options = AddOptions();
        options.Profiles = 7;
        Assert(Run(options, explicitProfiles, out evidence) == 0 && explicitProfiles.Rules[0].Profiles == 7, "explicit all does not need active mask");
        FakeBackend prepareFailure = new FakeBackend { PrepareError = new COMException("Detached rule preparation failed", unchecked((int)0x80070057)) };
        Assert(Run(AddOptions(), prepareFailure, out evidence) == 1 && prepareFailure.Adds == 0 &&
            !evidence.MutationAttempted && prepareFailure.Disposed, "detached preparation failure never attempts persistent mutation");
        foreach (string operation in new string[] { "add", "remove" })
        {
            int factories = 0;
            evidence = new FirewallRunEvidence();
            options = operation == "add" ? AddOptions() : Options(operation);
            Assert(FirewallModule.Execute(options, evidence, delegate { factories++; return new FakeBackend(); }, delegate { return false; }) == 1 &&
                factories == 0 && !evidence.MutationAttempted, "admin gate before backend");
        }
        foreach (string marker in new string[] { "Name", "Grouping", "Description" })
        {
            FakeBackend foreign = new FakeBackend();
            FirewallRuleData rule = FirewallModule.ExpectedRule(AddOptions(), 1);
            if (marker == "Name") { rule.Name = rule.Name.ToUpperInvariant(); }
            if (marker == "Grouping") { rule.Grouping = "foreign"; }
            if (marker == "Description") { rule.Description += ";extra=1"; }
            foreign.Rules.Add(rule);
            Assert(Run(Options("remove"), foreign, out evidence) == 1 && foreign.Removes == 0, "foreign marker refusal " + marker);
            Assert(Run(Options("check"), foreign, out evidence) == 1, "foreign check " + marker);
            Assert(Run(AddOptions(), foreign, out evidence) == 1 && foreign.Adds == 0, "existing foreign add refusal");
        }
        FakeBackend owned = new FakeBackend();
        owned.Rules.Add(FirewallModule.ExpectedRule(AddOptions(), 1));
        Assert(Run(AddOptions(), owned, out evidence) == 1 && owned.Adds == 0, "owned add not upsert");
        owned.Rules.Add(owned.Rules[0].Copy());
        foreach (string operation in new string[] { "add", "check", "remove" })
        {
            Assert(Run(operation == "add" ? AddOptions() : Options(operation), owned, out evidence) == 1 &&
                owned.Adds == 0 && owned.Removes == 0, "duplicate refusal " + operation);
        }
        FakeBackend race = new FakeBackend();
        race.BeforeRead = delegate(FakeBackend b) { if (b.Reads == 2) { b.Rules.Add(FirewallModule.ExpectedRule(AddOptions(), 1)); } };
        Assert(Run(AddOptions(), race, out evidence) == 1 && race.Adds == 0, "name appears before add");
    }

    private static void Readback()
    {
        FirewallRunEvidence evidence;
        string[] strings = { "Name", "Grouping", "Description", "ApplicationName", "ServiceName", "LocalAddresses", "RemoteAddresses",
            "LocalPorts", "RemotePorts", "InterfaceTypes", "LocalAppPackageId", "LocalUserOwner", "LocalUserAuthorizedList",
            "RemoteUserAuthorizedList", "RemoteMachineAuthorizedList" };
        foreach (string field in strings)
        {
            FakeBackend backend = new FakeBackend();
            string captured = field;
            backend.AfterAdd = delegate(FirewallRuleData rule)
            {
                typeof(FirewallRuleData).GetField(captured, System.Reflection.BindingFlags.Instance | System.Reflection.BindingFlags.NonPublic).SetValue(rule, "mismatch");
            };
            Assert(Run(AddOptions(), backend, out evidence) == 3 && backend.Removes == 0 && !evidence.ReadbackConfirmed, "string mismatch " + field);
        }
        foreach (string field in new string[] { "Direction", "Action", "Protocol", "Profiles", "EdgeTraversalOptions", "SecureFlags" })
        {
            FakeBackend backend = new FakeBackend();
            string captured = field;
            backend.AfterAdd = delegate(FirewallRuleData rule)
            {
                typeof(FirewallRuleData).GetField(captured, System.Reflection.BindingFlags.Instance | System.Reflection.BindingFlags.NonPublic).SetValue(rule, 999);
            };
            Assert(Run(AddOptions(), backend, out evidence) == 3 && backend.Removes == 0, "numeric mismatch " + field);
        }
        foreach (string field in new string[] { "Enabled", "EdgeTraversal", "Interfaces" })
        {
            FakeBackend backend = new FakeBackend();
            string captured = field;
            backend.AfterAdd = delegate(FirewallRuleData rule)
            {
                if (captured == "Enabled") { rule.Enabled = false; }
                if (captured == "EdgeTraversal") { rule.EdgeTraversal = true; }
                if (captured == "Interfaces") { rule.Interfaces = new string[] { "restricted interface" }; }
            };
            Assert(Run(AddOptions(), backend, out evidence) == 3, "restriction mismatch " + field);
        }
        FakeBackend duplicate = new FakeBackend();
        duplicate.AfterAdd = delegate(FirewallRuleData rule) { duplicate.Rules.Add(rule.Copy()); };
        Assert(Run(AddOptions(), duplicate, out evidence) == 3 && duplicate.Removes == 0, "duplicate add readback no cleanup");
        FakeBackend error = new FakeBackend();
        error.BeforeRead = delegate(FakeBackend b)
        {
            if (b.Reads == 3) { throw new COMException("Read failed", unchecked((int)0x80070005)); }
        };
        Assert(Run(AddOptions(), error, out evidence) == 3 && evidence.Outcome.Contains("80070005") && error.Disposed, "readback HRESULT and release");
        error = new FakeBackend { AddError = new COMException("Add failed", unchecked((int)0x80070005)) };
        Assert(Run(AddOptions(), error, out evidence) == 1 && evidence.MutationAttempted && !evidence.MutationReturned && error.Disposed, "mutation failure evidence");
        FirewallRuleData expected = FirewallModule.ExpectedRule(AddOptions(), 1);
        FirewallRuleData actual = expected.Copy();
        actual.RemoteAddresses += "/255.255.255.255";
        actual.RemotePorts = "0443";
        actual.InterfaceTypes = "all";
        actual.ApplicationName = null;
        actual.ServiceName = null;
        Assert(FirewallModule.Mismatches(expected, actual).Count == 0, "canonical host mask ports interface case null restrictions");
        actual.RemoteAddresses = "192.0.2.15/24";
        Assert(FirewallModule.Mismatches(expected, actual).Contains("RemoteAddresses"), "subnet broadening mismatch");
        expected.RemoteAddresses = "2001:db8::1";
        actual = expected.Copy();
        actual.RemoteAddresses = "2001:0db8:0:0:0:0:0:1/128";
        Assert(FirewallModule.Mismatches(expected, actual).Count == 0, "IPv6 canonical host");
        actual.RemoteAddresses = "2001:db8::1-2001:0db8:0:0:0:0:0:1";
        Assert(FirewallModule.Mismatches(expected, actual).Count == 0, "native IPv6 singleton range");
        actual.RemoteAddresses = "2001:db8::1-2001:db8::2";
        Assert(FirewallModule.Mismatches(expected, actual).Contains("RemoteAddresses"), "non-singleton range cannot broaden scope");
        FakeBackend frozen = new FakeBackend();
        frozen.BeforeRead = delegate(FakeBackend b) { if (b.Reads == 2) { b.Mask = 4; } };
        Assert(Run(AddOptions(), frozen, out evidence) == 0 && frozen.Rules[0].Profiles == 1, "active profile changes do not widen frozen rule");
    }

    private static void RemovalRaces()
    {
        FirewallRunEvidence evidence;
        foreach (string mode in new string[] { "foreign", "duplicate", "absent" })
        {
            FakeBackend backend = new FakeBackend();
            backend.Rules.Add(FirewallModule.ExpectedRule(AddOptions(), 1));
            string captured = mode;
            backend.BeforeRead = delegate(FakeBackend b)
            {
                if (b.Reads != 2) { return; }
                if (captured == "foreign") { b.Rules[0].Grouping = "foreign"; }
                if (captured == "duplicate") { b.Rules.Add(b.Rules[0].Copy()); }
                if (captured == "absent") { b.Rules.Clear(); }
            };
            int code = Run(Options("remove"), backend, out evidence);
            Assert(code == (mode == "absent" ? 0 : 1) && backend.Removes == 0, "immediate ownership refresh " + mode);
        }
        FakeBackend retained = new FakeBackend { IgnoreRemove = true };
        retained.Rules.Add(FirewallModule.ExpectedRule(AddOptions(), 1));
        Assert(Run(Options("remove"), retained, out evidence) == 3 && retained.Removes == 1, "remove unconfirmed no retry");
        FakeBackend readError = new FakeBackend();
        readError.BeforeRead = delegate(FakeBackend b) { throw new COMException("baseline denied", unchecked((int)0x80070005)); };
        Assert(Run(Options("remove"), readError, out evidence) == 1 && readError.Removes == 0 && readError.Disposed, "baseline failure no mutation");
    }

    private static void ReadOnly()
    {
        FirewallOptions profiles = FirewallModule.Parse(new string[] { "profiles" });
        FakeBackend backend = new FakeBackend();
        FirewallRunEvidence evidence = new FirewallRunEvidence();
        Assert(FirewallModule.Execute(profiles, evidence, delegate { return backend; },
            delegate { throw new InvalidOperationException("Read-only must not require admin."); }) == 0 &&
            backend.Adds == 0 && backend.Removes == 0 && evidence.ReadbackConfirmed, "profiles strictly read-only without admin");
        backend = new FakeBackend();
        backend.Rules.Add(FirewallModule.ExpectedRule(AddOptions(), 1));
        backend.Rules[0].Enabled = false;
        evidence = new FirewallRunEvidence();
        Assert(FirewallModule.Execute(Options("check"), evidence, delegate { return backend; },
            delegate { throw new InvalidOperationException("Check must not require admin."); }) == 0 &&
            evidence.Outcome.Contains("not compared"), "check ownership only not match assertion");
    }

    private static void Assessment()
    {
        FakeBackend backend = new FakeBackend();
        FirewallRunEvidence evidence = new FirewallRunEvidence();
        bool assessed = false;
        FirewallRunEvidence captured = evidence;
        int result = ControlRuntime.Execute(AddOptions(), evidence,
            delegate { return FirewallModule.Execute(AddOptions(), captured, delegate { return backend; }, delegate { return true; }); },
            delegate(int code)
            {
                assessed = true;
                Assert(code == 0 && captured.ReadbackConfirmed && backend.Disposed, "runtime assessment follows readback and release");
                FirewallModule.Assess(AddOptions(), captured, code);
            });
        Assert(result == 0 && assessed && evidence.ReadbackConfirmed, "shared runtime assessment confirmed");
        evidence = new FirewallRunEvidence();
        FirewallModule.Assess(AddOptions(), evidence, 4);
        Assert(!evidence.MutationAttempted && evidence.Outcome.Contains("ETW setup failed"), "ETW assessment no mutation");
    }

#if FIREWALL_TEST_STUBS
    private static void EtwFailure()
    {
        FirewallOptions options = AddOptions();
        options.CollectEtw = true;
        FirewallRunEvidence evidence = new FirewallRunEvidence();
        bool operated = false, assessed = false;
        int code = ControlRuntime.Execute(options, evidence, delegate { operated = true; return 0; },
            delegate(int result) { assessed = result == 4; FirewallModule.Assess(options, evidence, result); });
        Assert(code == 4 && !operated && assessed && !evidence.MutationAttempted, "shared runtime ETW failure before operation");
    }
#endif
}

#if FIREWALL_TEST_STUBS
internal sealed class EtwCapture : IDisposable
{
    internal EtwCapture(ControlOptions options, ControlRunEvidence evidence) { }
    internal bool TryStart() { return false; }
    internal void StopAfterWait() { }
    internal void Report() { }
    public void Dispose() { }
}
internal static class TelemetryEvidence
{
    internal static void Collect(ControlOptions options, ControlRunEvidence evidence, DateTime endUtc) { }
}
#endif
