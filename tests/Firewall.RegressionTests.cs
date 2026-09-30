// This Source Code Form is subject to the terms of the Mozilla Public License, v. 2.0.
// If a copy of the MPL was not distributed with this file, You can obtain one at https://mozilla.org/MPL/2.0/.

using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Management;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Text;

// Compile with /main:FirewallRegressionTests alongside the firewall, Core and ConsoleUi sources.
// Define FIREWALL_TEST_STUBS to replace only telemetry dependencies when testing in isolation.
// The default test run never constructs the native or management backend, or mutates Windows
// Firewall. --native-* and --management-read-only opt into real (never-mutating) construction and
// are only invoked under Build.ps1 -Integration, never the default -Test run or CI.
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
        internal MutationStatus AddOutcome = MutationStatus.ApiSucceeded;
        internal MutationStatus RemoveOutcome = MutationStatus.ApiSucceeded;
        internal bool AddPersists = true;
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
        public MutationStatus Add()
        {
            Calls.Add("add");
            Adds++;
            if (AddError != null) { throw AddError; }
            FirewallRuleData copy = Prepared.Copy();
            if (AddPersists) { Rules.Add(copy); }
            if (AfterAdd != null) { AfterAdd(copy); }
            return AddOutcome;
        }
        public MutationStatus Remove(string name)
        {
            Calls.Add("remove");
            Removes++;
            if (!IgnoreRemove) { Rules.RemoveAll(delegate(FirewallRuleData r) { return r.Name == name; }); }
            return RemoveOutcome;
        }
        public void Dispose() { Calls.Add("dispose"); Disposed = true; }
    }

    private static int Main(string[] args)
    {
        if (args.Length == 1 && args[0] == "--native-detached-preflight") { return RunGatedMode(NativeDetachedPreflight); }
        if (args.Length == 1 && args[0] == "--native-read-only") { return RunGatedMode(NativeReadOnly); }
        if (args.Length == 1 && args[0] == "--management-read-only") { return RunGatedMode(ManagementReadOnly); }
        if (args.Length == 1 && args[0] == "--powershell-read-only") { return RunGatedMode(PowerShellReadOnly); }
        if (args.Length == 1 && args[0] == "--cmd-read-only") { return RunGatedMode(CmdReadOnly); }

        TextWriter original = Console.Out;
        using (StringWriter output = new StringWriter())
        {
            Console.SetOut(output);
            try
            {
                ConsoleUi.Configure(false, true);
                Parsing();
                GroupingByTransport();
                CmdProfilesStoreLabel();
                CrossTransportOwnershipRefusal();
                AmbiguousMutationOutcome();
                TransportSelection();
                DirectionalPorts();
                AddAndCleanup();
                Refusals();
                Readback();
                RemovalRaces();
                ReadOnly();
                Assessment();
                NullVersusEmptyCodec();
                AddFailureAttribution();
                ManagementActionCodec();
                ManagementReadbackClassification();
                ManagementEscapeWql();
                CmdAddCommandOmitsProgramWhenUnset();
                CmdUnsafeCharactersRejected();
                CmdNetshOutputEncoding();
                CmdParseRulesFixtures();
                PowerShellParseRulesFixtures();
                PowerShellStrictModeCatchesMissingProperty();
                PowerShellScriptProloguesAreApplied();
                MutationClassification();
#if FIREWALL_TEST_STUBS
                EtwFailure();
#endif
                Assert(output.ToString().IndexOf("Cleanup: wtf.exe firewall rule remove --id " + Id, StringComparison.Ordinal) >= 0, "exact cleanup command");
                Console.SetOut(original);
                Console.WriteLine("Firewall regression tests passed: " + assertions + " assertions; no native mutations.");
                return 0;
            }
            catch (Exception error)
            {
                // Without this, a failing Assert's InvalidOperationException propagates out of Main
                // uncaught: the CLR prints only a raw exit code, and Build.ps1 reports just
                // "Test failed: Firewall.RegressionTests.exe (<code>)" with no assertion name -- the
                // same unreadable-crash problem RunGatedMode fixes for the -Integration-only modes,
                // but for the default -Test suite everyone actually runs. Print what was buffered
                // (this suite's own console output up to the failure point) plus the assertion name.
                Console.Error.WriteLine(output.ToString());
                Console.Error.WriteLine("FAILED (" + error.GetType().Name + "): " + error.Message);
                return 1;
            }
            finally { Console.SetOut(original); }
        }
    }

    // -Integration gated modes below construct a real com/native/management backend and can fail
    // for reasons other than a plain Assert (a genuine WMI/COM error, a thrown FirewallRefusalException,
    // etc.). Run them through this wrapper so a failure prints what actually went wrong instead of the
    // bare CLR crash dump ("Exception.ToString() failed", exit 0xE0434352, no diagnostic text) these
    // standalone-exe entry points would otherwise produce.
    private static int RunGatedMode(Func<int> mode)
    {
        try { return mode(); }
        catch (Exception error)
        {
            Console.Error.WriteLine("FAILED (" + error.GetType().Name + "): " + error.Message);
            return 1;
        }
    }

    private static int NativeDetachedPreflight()
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

    private static int NativeReadOnly()
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

    private static int ManagementReadOnly()
    {
        ConsoleUi.Configure(false, true);
        using (IFirewallBackend backend = new ManagementFirewallBackend())
        {
            Assert(backend.FindByName(FirewallModule.NameFor(Guid.NewGuid())).Count == 0, "management absent enumeration");
            bool verified = false;
            foreach (string existingName in CandidateRealRuleElementNames(25))
            {
                IList<FirewallRuleData> matches;
                try { matches = backend.FindByName(existingName); }
                catch (FirewallReadbackUnsupportedException)
                {
                    // A rule shape this transport's readback deliberately refuses to decode
                    // (e.g. an interface-alias/interface-type/action-value restriction) -- try
                    // the next candidate rather than letting enumeration order make this test
                    // flaky. Anything else (including a plain FirewallRefusalException) is not
                    // caught here and fails the test loudly.
                    continue;
                }
                // existingName was just read from this exact MSFT_NetFirewallRule.ElementName, so
                // a lookup by that same name returning zero rows can only mean the ElementName-
                // keyed lookup itself is broken (e.g. a regression back to querying by
                // InstanceID) -- this must never be treated as "try the next candidate".
                Assert(matches.Count > 0, "management full restriction snapshot via ElementName: " + existingName);
                Console.WriteLine("Existing rule: ElementName-keyed lookup and full filter-association readback succeeded.");
                verified = true;
                break;
            }
            if (!verified)
            {
                Console.WriteLine("No readable pre-existing rule found among the first candidates " +
                    "(all were unsupported shapes); management full snapshot probe skipped.");
            }
        }
        ManagementIdentityKey();
        return FirewallModule.Main(new string[] { "profiles", "--transport", "management", "--no-color" });
    }

    // Shared by --powershell-read-only and --cmd-read-only: both drive an entirely different process
    // (powershell.exe / cmd.exe+netsh.exe) than management's in-process WMI, but read the same
    // root\StandardCimv2 provider, so the same candidate-name probe strategy (and the same
    // FirewallReadbackUnsupportedException skip-past-unsupported-shapes reasoning) applies unchanged.
    private static int PowerShellReadOnly() { return TransportReadOnly("powershell"); }
    private static int CmdReadOnly() { return TransportReadOnly("cmd"); }

    private static int TransportReadOnly(string transport)
    {
        ConsoleUi.Configure(false, true);
        using (IFirewallBackend backend = FirewallModule.CreateBackend(transport))
        {
            Assert(backend.FindByName(FirewallModule.NameFor(Guid.NewGuid())).Count == 0, transport + " absent enumeration");
            bool verified = false;
            // powershell's own Get-NetFirewallRule.DisplayName is used as the candidate source here
            // (not the raw WMI ElementName CandidateRealRuleElementNames reads) specifically so this
            // integration mode exercises a real decode through the actual script-to-parser contract
            // (Emit's $i closure, @($null)-shaped values, whether $sec[0].LocalUser/$rule.Profile
            // etc. really exist on the live cmdlet objects) at least once, rather than being at the
            // mercy of the same raw-vs-resolved-name mismatch --cmd-read-only tolerates by skipping.
            // cmd keeps the WQL-based source: netsh's own dual raw/resolved-name matching (see
            // FindByName's remarks) already makes it round-trip reliably either way.
            bool strict = transport == "powershell";
            IList<string> candidates = strict ? CandidatePowerShellDisplayNames(25) : CandidateRealRuleElementNames(25);
            int considered = 0;
            int unsupported = 0;
            foreach (string existingName in candidates)
            {
                // Filtered here, not by widening the catch below to the FirewallRefusalException base
                // type: a real third-party rule name can contain a character
                // CmdFirewallBackend.RequireSafeForCmd refuses outright ('%'/'!', confirmed present
                // among real rule names on a development host), which this probe legitimately cannot
                // query -- but catching the base type would also swallow a plain FirewallRefusalException
                // from a genuine output-format drift (e.g. a Windows update changing "Enabled: Yes" to
                // "Enabled: True"), silently turning this integration mode's only defense against that
                // kind of drift into a report of "all were unsupported shapes; skipped." Only
                // FirewallReadbackUnsupportedException (a known, named, still-unsupported rule shape)
                // is caught below; anything else must fail the test loudly, exactly like
                // ManagementReadOnly's identical candidate loop already requires.
                if (HasUnsafeCmdCharacter(existingName)) { continue; }
                considered++;
                IList<FirewallRuleData> matches;
                try { matches = backend.FindByName(existingName); }
                catch (FirewallReadbackUnsupportedException)
                {
                    unsupported++;
                    continue;
                }
                if (matches.Count == 0)
                {
                    if (strict)
                    {
                        // Unlike cmd's raw-ElementName candidates, CandidatePowerShellDisplayNames
                        // queries the exact same NetSecurity\Get-NetFirewallRule.DisplayName property
                        // FindByName's own script filters by (-eq), so a candidate sourced this way can
                        // never legitimately round-trip to zero matches: it can only mean the
                        // DisplayName-keyed lookup itself is broken (e.g. a regression to filtering by
                        // Name instead of DisplayName). This must never be treated as "try the next
                        // candidate" -- fail loudly, exactly like ManagementReadOnly's ElementName-keyed
                        // assertion already does.
                        Assert(false, "powershell full restriction snapshot via DisplayName: " + existingName);
                    }
                    // cmd: CandidateRealRuleElementNames reads the raw WMI ElementName directly, which
                    // for many built-in rules is an unresolved MUI resource reference (e.g.
                    // "@FirewallAPI.dll,-32765"); confirmed live that netsh's "Rule Name:" shows the
                    // resolved text ("Network Discovery (UPnP-Out)") instead, so a raw-ElementName
                    // candidate can legitimately round-trip to zero matches even though the rule exists.
                    // This never affects this tool's own rules (their name is always a literal
                    // WinTraceForge.Firewall.<guid> string, never an MUI reference) -- only this probe's
                    // candidate selection. Try the next candidate rather than treating a resolution
                    // mismatch as a readback failure.
                    continue;
                }
                assertions++;
                Console.WriteLine("Existing rule: " + (strict ? "DisplayName-keyed" : "ElementName-keyed") +
                    " lookup and full filter-association readback succeeded (" + transport + ").");
                verified = true;
                break;
            }
            if (!verified)
            {
                // For powershell, a skip is only legitimate when every considered candidate was a known
                // unsupported rule shape (see the strict zero-match Assert above): if even one candidate
                // was considered and none were unsupported, matches.Count == 0 for all of them would have
                // already asserted false above, so reaching here with considered != unsupported can only
                // happen if the probe never actually found matches.Count > 0 for a rule that WAS
                // decodable but got skipped by some other path -- this defends against a future edit
                // quietly adding such a path without updating this invariant.
                if (strict && considered != 0)
                {
                    Assert(unsupported == considered,
                        "powershell full snapshot probe skipped without every considered candidate being an unsupported shape");
                }
                Console.WriteLine("No readable pre-existing rule found among the first candidates " +
                    "(all were unsupported shapes); " + transport + " full snapshot probe skipped.");
            }
        }
        return FirewallModule.Main(new string[] { "profiles", "--transport", transport, "--no-color" });
    }

    // Sources candidates from the same NetSecurity\Get-NetFirewallRule.DisplayName property
    // PowerShellFirewallBackend.FindByName itself queries by (-eq), so a candidate returned here is
    // guaranteed to round-trip through the real script rather than depending on the raw-WMI-vs-
    // resolved-name coincidence CandidateRealRuleElementNames leaves to chance.
    private static IList<string> CandidatePowerShellDisplayNames(int limit)
    {
        string script = "$ErrorActionPreference = 'Stop'\r\n" +
            "try {\r\n" +
            "    NetSecurity\\Get-NetFirewallRule | Select-Object -First " + limit.ToString(CultureInfo.InvariantCulture) +
            " -ExpandProperty DisplayName | ForEach-Object {\r\n" +
            "        Write-Output ([Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes([string]$_)))\r\n" +
            "    }\r\n" +
            "    Write-Output 'WTF_LIST_OK'\r\n" +
            "} catch {\r\n" +
            DefenderModule.PowerShellRunner.EmitErrorMarkerStatement("WTF_LIST_ERROR:") +
            "    exit 1\r\n" +
            "}\r\n";
        DefenderModule.PowerShellRunner.Result result = DefenderModule.PowerShellRunner.RunScript(script);
        string errorMessage = DefenderModule.PowerShellRunner.FindMarkerMessage(result.Stdout, "WTF_LIST_ERROR:");
        if (errorMessage != null) { throw new InvalidOperationException("Get-NetFirewallRule (candidate listing) failed: " + errorMessage); }
        // Without this, a powershell.exe that ends early (killed, crashed, torn down externally) before
        // emitting WTF_LIST_OK -- and without ever emitting WTF_LIST_ERROR: either -- would silently
        // decode as zero (or a truncated set of) candidates here. TransportReadOnly would then just
        // print "all were unsupported shapes; skipped" for an empty/short candidate list, reporting the
        // real-rule readback probe as a harmless skip when it never actually ran at all. Require the
        // completion marker exactly like every other script in this file does, rather than treating a
        // silently truncated stream the same as a script that legitimately listed zero rules.
        if (!DefenderModule.PowerShellRunner.ContainsMarker(result.Stdout, "WTF_LIST_OK"))
        {
            throw new InvalidOperationException("Get-NetFirewallRule (candidate listing) did not complete (exit " +
                result.ExitCode + "): " + DefenderModule.PowerShellRunner.DescribeFailure(result));
        }
        List<string> names = new List<string>();
        foreach (string line in DefenderModule.PowerShellRunner.SplitLines(result.Stdout))
        {
            if (line == "WTF_LIST_OK" || line.Length == 0) { continue; }
            string name = DefenderModule.PowerShellRunner.DecodeValue(line);
            if (!string.IsNullOrEmpty(name) && !names.Contains(name)) { names.Add(name); }
        }
        return names;
    }

    // Mirrors CmdFirewallBackend.RequireSafeForCmd's own character set (not calling it directly: that
    // method's job is to throw, this one's is to decide in advance whether to bother asking at all).
    private static bool HasUnsafeCmdCharacter(string value)
    {
        foreach (char c in value) { if (c == '"' || c == '%' || c == '!' || c < ' ') { return true; } }
        return false;
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

    // WQL enumeration order is not guaranteed stable across hosts/OS builds, and some pre-existing
    // rules (e.g. from third-party VPN/security software) can carry an interface-type or interface-
    // alias restriction ReadRule() deliberately refuses to decode (see its "Unsupported ... restriction"
    // refusals). Returns several candidate names rather than just the first, so the caller can skip
    // past rule shapes this transport doesn't support without the test becoming host-dependent.
    private static IList<string> CandidateRealRuleElementNames(int limit)
    {
        List<string> names = new List<string>();
        ManagementScope scope = new ManagementScope(@"\\.\root\StandardCimv2");
        scope.Connect();
        using (ManagementObjectSearcher searcher = new ManagementObjectSearcher(scope,
            new ObjectQuery("SELECT ElementName FROM MSFT_NetFirewallRule")))
        using (ManagementObjectCollection results = searcher.Get())
        {
            foreach (ManagementObject rule in results)
            {
                using (rule)
                {
                    string name = (string)rule["ElementName"];
                    if (!string.IsNullOrEmpty(name)) { names.Add(name); }
                }
                if (names.Count >= limit) { break; }
            }
        }
        return names;
    }

    // Pins the exact bug found in live cross-transport testing: a rule created outside management's
    // own Add() (e.g. com/native's HNetCfg.FWRule) gets an opaque provider-generated InstanceID, with
    // its real ownership name only ever in ElementName. ReadDirectProperties/ReadRule must key off
    // ElementName, never InstanceID -- otherwise FindByName/Remove silently miss such rules, and
    // Remove misreports "already absent" without ever deleting the live rule. Builds a detached
    // (never-Put) instance so this never touches persisted state.
    private static void ManagementIdentityKey()
    {
        ManagementScope scope = new ManagementScope(@"\\.\root\StandardCimv2");
        scope.Connect();
        using (ManagementClass ruleClass = new ManagementClass(scope, new ManagementPath("MSFT_NetFirewallRule"), null))
        using (ManagementObject detached = ruleClass.CreateInstance())
        {
            detached["InstanceID"] = "decoy-instance-id-must-never-be-read-as-name";
            detached["ElementName"] = "WinTraceForge.Firewall.identity-key-test";
            detached["Description"] = "";
            detached["RuleGroup"] = "";
            detached["Enabled"] = (ushort)1;
            detached["Direction"] = (ushort)2;
            detached["Action"] = (ushort)2;
            detached["Profiles"] = (ushort)1;
            FirewallRuleData read = (FirewallRuleData)ManagementPrivate("ReadDirectProperties", detached);
            Assert(read.Name == "WinTraceForge.Firewall.identity-key-test", "management identity keys off ElementName");
            Assert(read.Name != "decoy-instance-id-must-never-be-read-as-name", "management never reads InstanceID as Name");
        }
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

    // Pins netsh's one real, documented gap ("add rule" has no group=/grouping= parameter): only
    // --transport cmd may ever expect an empty Grouping; every other transport -- including
    // powershell, whose New-NetFirewallRule -Group sets the identical WMI property management writes
    // directly -- must keep expecting the real marker. A future change that widens this exemption to
    // another transport, or drops it for cmd, breaks cross-transport ownership silently; this test
    // does not.
    private static void GroupingByTransport()
    {
        foreach (string transport in new[] { "com", "native", "management", "powershell" })
        {
            FirewallOptions options = FirewallModule.Parse(new[] { "rule", "add", "--remote-address", "192.0.2.10",
                "--remote-port", "44443", "--transport", transport });
            Assert(FirewallModule.ExpectedRule(options, 1).Grouping == FirewallModule.Group,
                transport + " expects the real Grouping marker");
        }
        FirewallOptions cmdOptions = FirewallModule.Parse(new[] { "rule", "add", "--remote-address", "192.0.2.10",
            "--remote-port", "44443", "--transport", "cmd" });
        Assert(FirewallModule.ExpectedRule(cmdOptions, 1).Grouping == "",
            "cmd cannot stamp Grouping via netsh, so it expects an empty one");
    }

    // Pins that a backend reporting MutationStatus.ApiUnknown (powershell/cmd's "no clear
    // success/failure marker" case; see PowerShellFirewallBackend.Add and CmdFirewallBackend.Add)
    // flows straight through FirewallOperation.Mutate to the shared lifecycle, is never silently
    // upgraded to ApiSucceeded, and -- because VerifyAfterApiFailure is false and ApiUnknown is not
    // ApiFailed -- still lets Verify() run and settle the outcome via readback, exactly like a
    // genuinely successful mutation would.
    private static void AmbiguousMutationOutcome()
    {
        FakeBackend backend = new FakeBackend { AddOutcome = MutationStatus.ApiUnknown };
        FirewallRunEvidence evidence;
        int code = Run(AddOptions(), backend, out evidence);
        Assert(code == 0 && evidence.Lifecycle.Mutation == MutationStatus.ApiUnknown, "ambiguous add outcome reaches the lifecycle unchanged");
        Assert(evidence.Lifecycle.Verification == VerificationStatus.Confirmed, "ambiguous add outcome still runs Verify");
        Assert(evidence.MutationReturned && evidence.ReadbackConfirmed, "ambiguous add outcome is settled by readback");

        backend = new FakeBackend();
        backend.Rules.Add(FirewallModule.ExpectedRule(AddOptions(), 1));
        backend.RemoveOutcome = MutationStatus.ApiUnknown;
        code = Run(Options("remove"), backend, out evidence);
        Assert(code == 0 && evidence.Lifecycle.Mutation == MutationStatus.ApiUnknown, "ambiguous remove outcome reaches the lifecycle unchanged");
        Assert(evidence.Lifecycle.Verification == VerificationStatus.Confirmed, "ambiguous remove outcome still runs Verify");

        // The absent/still-present halves: an ApiUnknown outcome that readback shows was NOT applied
        // must say so plainly ("not applied"/"not removed"), not "Add returned"/wording that implies
        // the backend told us it succeeded when all that is really known is the process ended.
        backend = new FakeBackend { AddOutcome = MutationStatus.ApiUnknown, AddPersists = false };
        code = Run(AddOptions(), backend, out evidence);
        Assert(code == 3 && evidence.Lifecycle.Mutation == MutationStatus.ApiUnknown, "ambiguous add outcome with an absent rule is unconfirmed, not an error");
        Assert(evidence.Outcome.Contains("ambiguous") && evidence.Outcome.Contains("not applied"),
            "ambiguous absent add outcome is worded as unresolved, not as a claimed success");

        backend = new FakeBackend { IgnoreRemove = true, RemoveOutcome = MutationStatus.ApiUnknown };
        backend.Rules.Add(FirewallModule.ExpectedRule(AddOptions(), 1));
        code = Run(Options("remove"), backend, out evidence);
        Assert(code == 3 && evidence.Lifecycle.Mutation == MutationStatus.ApiUnknown, "ambiguous remove outcome with the rule still present is unconfirmed, not an error");
        Assert(evidence.Outcome.Contains("ambiguous") && evidence.Outcome.Contains("not removed"),
            "ambiguous still-present remove outcome is worded as unresolved, not as a claimed success");

        // The >=2-rules half: an ApiUnknown outcome whose readback finds more than one matching rule
        // must also say so plainly ("readback found N matching rules"), not "Add returned" -- the same
        // wording requirement as the absent case above, just for FirewallOperation.Verify's other
        // actual.Count != 1 branch.
        backend = new FakeBackend { AddOutcome = MutationStatus.ApiUnknown };
        backend.AfterAdd = delegate(FirewallRuleData rule) { backend.Rules.Add(rule.Copy()); };
        code = Run(AddOptions(), backend, out evidence);
        Assert(code == 3 && evidence.Lifecycle.Mutation == MutationStatus.ApiUnknown, "ambiguous add outcome with 2 rules found is unconfirmed, not an error");
        Assert(evidence.Outcome.Contains("ambiguous") && evidence.Outcome.Contains("found 2 matching rules"),
            "ambiguous multi-rule add outcome names the count, not 'Add returned'");
    }

    // A cmd-created rule (empty Grouping) is legitimately owned when checked/removed with
    // --transport cmd, and legitimately refused as a foreign/Grouping-mismatched rule by every other
    // transport -- and symmetrically, a rule carrying the real Grouping marker (as every non-cmd
    // transport creates) is refused by --transport cmd, since ExpectedGrouping("cmd") is "". Both
    // directions matter: this is the actual protection stopping one transport from touching a rule it
    // cannot prove it owns, not just a one-way check.
    private static void CrossTransportOwnershipRefusal()
    {
        FirewallOptions cmdAdd = FirewallModule.Parse(new[] { "rule", "add", "--remote-address", "192.0.2.10",
            "--remote-port", "44443", "--id", Id, "--transport", "cmd" });
        FakeBackend cmdOwned = new FakeBackend();
        cmdOwned.Rules.Add(FirewallModule.ExpectedRule(cmdAdd, 1));
        FirewallRunEvidence evidence;
        Assert(Run(FirewallModule.Parse(new[] { "rule", "check", "--id", Id, "--transport", "cmd" }), cmdOwned, out evidence) == 0,
            "cmd owns a rule with empty Grouping");
        Assert(Run(FirewallModule.Parse(new[] { "rule", "check", "--id", Id, "--transport", "management" }), cmdOwned, out evidence) == 1,
            "management refuses a cmd-created (empty-Grouping) rule as foreign");
        Assert(Run(FirewallModule.Parse(new[] { "rule", "check", "--id", Id, "--transport", "powershell" }), cmdOwned, out evidence) == 1,
            "powershell refuses a cmd-created (empty-Grouping) rule as foreign");

        FakeBackend comOwned = new FakeBackend();
        comOwned.Rules.Add(FirewallModule.ExpectedRule(AddOptions(), 1));
        Assert(Run(Options("check"), comOwned, out evidence) == 0, "com owns a rule with the real Grouping marker");
        Assert(Run(FirewallModule.Parse(new[] { "rule", "check", "--id", Id, "--transport", "cmd" }), comOwned, out evidence) == 1,
            "cmd refuses a com/native/management/powershell-created rule as foreign (it cannot prove the Grouping marker)");
    }

    // The Local-vs-effective distinction previously existed only in code comments and
    // docs\user\firewall.md; this pins that FirewallOperation.Probe's own console output states it
    // directly, so reading the output (or a saved log) alone is enough to avoid mistaking cmd's Local
    // store for the GPO-merged effective policy every other transport reads.
    private static void CmdProfilesStoreLabel()
    {
        Assert(CapturedProfilesOutput("cmd").Contains("Policy store") &&
            CapturedProfilesOutput("cmd").Contains("Local (not GPO-merged effective policy)"),
            "cmd profiles output states it read the Local policy store");
        foreach (string transport in new[] { "com", "native", "management", "powershell" })
        {
            Assert(CapturedProfilesOutput(transport).Contains("Policy store") &&
                CapturedProfilesOutput(transport).Contains("Effective (GPO-merged)"),
                transport + " profiles output states it read the effective policy");
        }
    }

    private static string CapturedProfilesOutput(string transport)
    {
        TextWriter outer = Console.Out;
        using (StringWriter captured = new StringWriter())
        {
            Console.SetOut(captured);
            try
            {
                FirewallOptions options = FirewallModule.Parse(new[] { "profiles", "--transport", transport });
                FirewallRunEvidence evidence;
                Run(options, new FakeBackend(), out evidence);
            }
            finally { Console.SetOut(outer); }
            return captured.ToString();
        }
    }

    private static void TransportSelection()
    {
        foreach (string transport in new[] { "com", "native", "management", "powershell", "cmd" })
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
        foreach (string transport in new[] { "com", "native", "management", "powershell", "cmd" })
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

    // Shared ABI contract with Firewall.Native.RegressionTests.cpp NullVersusEmpty: identical bytes.
    // NULL BSTR and allocated empty BSTR are distinct states; no helper may collapse them.
    private static readonly byte[] NullThenEmpty = { 0x4e, 0x57, 0x46, 0x31, 0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00 };

    private static object Private(string method, object target, params object[] arguments)
    {
        const BindingFlags flags = BindingFlags.Static | BindingFlags.Instance | BindingFlags.NonPublic;
        Type type = target == null ? typeof(NativeFirewallBackend) : target.GetType();
        try { return type.GetMethod(method, flags).Invoke(target, arguments); }
        catch (TargetInvocationException error) { throw error.InnerException; }
    }

    private static IDisposable NativeReader(byte[] packet)
    {
        Type reader = typeof(NativeFirewallBackend).GetNestedType("PacketReader", BindingFlags.NonPublic);
        try { return (IDisposable)Activator.CreateInstance(reader, BindingFlags.Instance | BindingFlags.NonPublic, null, new object[] { packet }, null); }
        catch (TargetInvocationException error) { throw error.InnerException; }
    }

    private static void NullVersusEmptyCodec()
    {
        using (MemoryStream stream = new MemoryStream())
        using (BinaryWriter writer = new BinaryWriter(stream))
        {
            writer.Write(BitConverter.ToUInt32(NullThenEmpty, 0));
            Private("WriteString", null, writer, null);
            Private("WriteString", null, writer, "");
            writer.Flush();
            byte[] encoded = stream.ToArray();
            Assert(encoded.Length == NullThenEmpty.Length, "managed NULL/empty packet length");
            for (int i = 0; i < encoded.Length; ++i) { Assert(encoded[i] == NullThenEmpty[i], "managed NULL -1 / empty 0 encoding byte " + i); }
        }
        using (IDisposable reader = NativeReader(NullThenEmpty))
        {
            Assert(Private("String", reader) == null, "native -1 decodes to managed null");
            Assert((string)Private("String", reader) == "", "native zero length decodes to managed empty, not null");
            Private("End", reader);
        }
        foreach (bool applicationNull in new bool[] { true, false })
        {
            FirewallRuleData rule = FirewallModule.ExpectedRule(AddOptions(), 1);
            rule.ApplicationName = applicationNull ? null : "";
            rule.ServiceName = applicationNull ? "" : null;
            rule.Description = null;
            rule.LocalUserOwner = "";
            using (IDisposable reader = NativeReader((byte[])Private("RulePacket", null, rule)))
            {
                FirewallRuleData copy = (FirewallRuleData)Private("Rule", reader);
                Private("End", reader);
                Assert(applicationNull ? copy.ApplicationName == null : copy.ApplicationName == "", "ApplicationName NULL/empty state survives codec");
                Assert(applicationNull ? copy.ServiceName == "" : copy.ServiceName == null, "ServiceName NULL/empty state survives codec");
                Assert(copy.Description == null && copy.LocalUserOwner == "", "other optional strings keep NULL/empty state");
            }
        }
    }

    private static void AddFailureAttribution()
    {
        const int invalidArgument = unchecked((int)0x80070057);
        Assert((string)Private("OperationName", null, (uint)7) == "INetFwRules::Add", "operation 7 failure names INetFwRules::Add");
        Assert(((string)Private("OperationName", null, (uint)5)).Contains("preparation"), "operation 5 failure names preparation");
        COMException thrown = null;
        try { Private("Throw", null, invalidArgument, "INetFwRules::Add"); }
        catch (COMException error) { thrown = error; }
        Assert(thrown != null && thrown.HResult == invalidArgument && thrown.Message.Contains("INetFwRules::Add"),
            "native Add status becomes COMException with the exact HRESULT");
        FakeBackend backend = new FakeBackend { AddError = thrown };
        FirewallRunEvidence evidence;
        Assert(Run(AddOptions(), backend, out evidence) == 1 && backend.Adds == 1 && backend.Removes == 0, "Add E_INVALIDARG is an operation error");
        Assert(string.Join(",", backend.Calls) == "read,profiles,modify-state,prepare,read,add,dispose", "no readback after failed Add");
        Assert(evidence.MutationAttempted && !evidence.MutationReturned && !evidence.ReadbackConfirmed, "Add failure mutation evidence");
        Assert(evidence.Outcome.StartsWith("Firewall Add: ", StringComparison.Ordinal) &&
            evidence.Outcome.Contains("HRESULT 0x80070057"), "Add failure keeps stage and exact HRESULT");
        Assert(evidence.Outcome.IndexOf("preparation", StringComparison.OrdinalIgnoreCase) < 0 &&
            evidence.Outcome.IndexOf("readback", StringComparison.OrdinalIgnoreCase) < 0, "Add failure not reported as preparation/readback");
    }

    private static object ManagementPrivate(string method, params object[] arguments)
    {
        const BindingFlags flags = BindingFlags.Static | BindingFlags.NonPublic;
        try { return typeof(ManagementFirewallBackend).GetMethod(method, flags).Invoke(null, arguments); }
        catch (TargetInvocationException error) { throw error.InnerException; }
    }

    private static string CmdBuildAddCommand(FirewallRuleData rule)
    {
        const BindingFlags flags = BindingFlags.Static | BindingFlags.NonPublic;
        try { return (string)typeof(CmdFirewallBackend).GetMethod("BuildAddCommand", flags).Invoke(null, new object[] { rule }); }
        catch (TargetInvocationException error) { throw error.InnerException; }
    }

    private static void CmdRequireSafeForCmd(string value)
    {
        const BindingFlags flags = BindingFlags.Static | BindingFlags.NonPublic;
        try { typeof(CmdFirewallBackend).GetMethod("RequireSafeForCmd", flags).Invoke(null, new object[] { value, "test value" }); }
        catch (TargetInvocationException error) { throw error.InnerException; }
    }

    // '"' would break netsh's own name="..."/program="..." quoting; '%' expands an environment
    // variable even inside a quoted cmd.exe region; '!' does too when delayed expansion happens to be
    // enabled (RunNetsh's own /V:OFF already disables it for this invocation, but RequireSafeForCmd is
    // a second, registry-independent layer -- see its own remarks); a control character has no safe
    // representation on a single command line. A plain printable path must pass through unrejected.
    // Pins that netsh output is decoded with the real system OEM codepage (Win32 GetOEMCP()), not
    // CultureInfo.CurrentCulture.TextInfo.OEMCodePage: confirmed live that these can genuinely differ
    // (a development host with CurrentCulture=zh-CN reported OEM 936 from that property while the real
    // system codepage, from GetOEMCP() directly, was 437) -- a regression back to the culture-based
    // property would silently corrupt non-ASCII --program readback on exactly this kind of host.
    [DllImport("kernel32.dll")]
    private static extern int GetOEMCP();

    // Calls GetOEMCP() independently here (not through CmdFirewallBackend.NetshOutputEncoding itself,
    // which is exactly what is under test) and asserts equality, not just "resolves to *some*
    // codepage" -- the latter would still pass after reverting to
    // CultureInfo.CurrentCulture.TextInfo.OEMCodePage, since that also returns a valid codepage, just
    // sometimes the wrong one (confirmed live: 936 vs the real 437 on a zh-CN-culture development
    // host). Honesty note: on a host where the culture-based and system codepages happen to coincide
    // (most en-US installs, likely including an en-US CI runner), this assertion cannot distinguish
    // the fix from the bug it fixes -- it only catches the regression on a host like the one that
    // exposed it.
    private static void CmdNetshOutputEncoding()
    {
        Encoding encoding = CmdFirewallBackend.NetshOutputEncoding();
        Assert(encoding != null && encoding.CodePage == GetOEMCP(), "cmd netsh output encoding matches the real system OEM codepage");
    }

    // Pins the return value of the pure classification functions directly, independent of any live
    // process spawn or fake-backend lifecycle plumbing: if CmdFirewallBackend.Add/Remove ever went
    // back to throwing on a nonzero exit instead of deferring to readback (or the powershell
    // equivalent stopped doing so), this fails without needing a real netsh.exe/powershell.exe call.
    private static void MutationClassification()
    {
        Assert(CmdFirewallBackend.ClassifyMutation(new CmdFirewallBackend.Result(0, "Ok.\r\n", "")) == MutationStatus.ApiSucceeded,
            "cmd exit 0 with Ok. trailer classifies as ApiSucceeded");
        Assert(CmdFirewallBackend.ClassifyMutation(new CmdFirewallBackend.Result(1, "The requested operation requires elevation.\r\n", "")) == MutationStatus.ApiUnknown,
            "cmd a definite-looking netsh rejection still classifies as ApiUnknown, not a hard failure");
        Assert(CmdFirewallBackend.ClassifyMutation(new CmdFirewallBackend.Result(0, "", "")) == MutationStatus.ApiUnknown,
            "cmd exit 0 without an Ok. trailer classifies as ApiUnknown");
        Assert(CmdFirewallBackend.ClassifyMutation(new CmdFirewallBackend.Result(-1, "", "terminated")) == MutationStatus.ApiUnknown,
            "cmd an externally-terminated-looking result classifies as ApiUnknown, never as a claimed success");

        Assert(PowerShellFirewallBackend.ClassifyMutation(PowerShellScriptResult("WTF_ADD_OK\r\n"), "WTF_ADD_OK", "WTF_ADD_ERROR:", "x: ") == MutationStatus.ApiSucceeded,
            "powershell OK marker classifies as ApiSucceeded");
        Assert(PowerShellFirewallBackend.ClassifyMutation(PowerShellScriptResult(""), "WTF_ADD_OK", "WTF_ADD_ERROR:", "x: ") == MutationStatus.ApiUnknown,
            "powershell no marker at all classifies as ApiUnknown");
        bool threw = false;
        try
        {
            PowerShellFirewallBackend.ClassifyMutation(
                PowerShellScriptResult("WTF_ADD_ERROR:" + DefenderModule.PowerShellRunner.EncodeValue("boom")), "WTF_ADD_OK", "WTF_ADD_ERROR:", "x: ");
        }
        catch (InvalidOperationException error) { threw = error.Message == "x: boom"; }
        Assert(threw, "powershell a confirmed ERROR marker throws with the decoded message, not ApiUnknown/ApiFailed");
    }

    private static DefenderModule.PowerShellRunner.Result PowerShellScriptResult(string stdout)
    {
        return new DefenderModule.PowerShellRunner.Result(0, stdout, "");
    }

    // Deterministic, CI-covered parser tests using real "netsh advfirewall firewall show rule ...
    // verbose" text captured live from a development host during development of this transport (not
    // paraphrased), so the label/value shapes are ground truth rather than assumed -- this is what
    // --cmd-read-only (host-dependent, and only exercises whatever rule shapes happen to exist on the
    // machine it runs on) cannot guarantee. The multi-value RemoteIP fixture is the one exception:
    // constructed, not captured, following the same "Domain,Private,Public"-style comma-joined
    // rendering netsh is independently confirmed to use for Profiles.
    private static void CmdParseRulesFixtures()
    {
        const string DnsRule =
            "Rule Name:                            Core Networking - DNS (UDP-Out)\r\n" +
            "----------------------------------------------------------------------\r\n" +
            "Description:                          Outbound rule to allow DNS requests.\r\n" +
            "Enabled:                              Yes\r\n" +
            "Direction:                            Out\r\n" +
            "Profiles:                             Domain,Private,Public\r\n" +
            "Grouping:                             Core Networking\r\n" +
            "LocalIP:                              Any\r\n" +
            "RemoteIP:                              Any\r\n" +
            "Protocol:                             UDP\r\n" +
            "LocalPort:                            Any\r\n" +
            "RemotePort:                           53\r\n" +
            "Edge traversal:                       No\r\n" +
            "Program:                              C:\\Windows\\system32\\svchost.exe\r\n" +
            "Service:                              dnscache\r\n" +
            "InterfaceTypes:                       Any\r\n" +
            "Security:                             NotRequired\r\n" +
            "Rule source:                          Local Setting\r\n" +
            "Action:                               Allow\r\n" +
            "Ok.\r\n";
        IList<FirewallRuleData> dns = CmdFirewallBackend.ParseRules(DnsRule);
        Assert(dns.Count == 1 && dns[0].ApplicationName == @"C:\Windows\system32\svchost.exe" && dns[0].ServiceName == "dnscache" &&
            dns[0].Protocol == 17 && dns[0].Direction == 2 && dns[0].Grouping == "Core Networking" && dns[0].RemotePorts == "53" &&
            dns[0].LocalPorts == "*" && dns[0].Description.StartsWith("Outbound rule", StringComparison.Ordinal),
            "cmd fixture: DNS rule (Program+Service present) decodes fully");

        // Pins that the two refusal exception types stay distinct for cmd, the same way
        // ManagementActionCodec/ManagementReadbackClassification pin it for management: an unrecognized
        // VALUE for a field this transport already understands (e.g. a hypothetical future Windows
        // build spelling "Enabled: Yes" as "Enabled: True") is real output-format drift that must fail
        // the test loudly as a plain FirewallRefusalException, never silently absorbed as the
        // known-and-skippable FirewallReadbackUnsupportedException an actually-unsupported rule shape
        // (a multi-value RemoteIP, an unrecognized label) produces below.
        const string UnrecognizedEnabledValueRule =
            "Rule Name:                            Future Enabled Spelling\r\n" +
            "----------------------------------------------------------------------\r\n" +
            "Description:                          future\r\n" +
            "Enabled:                              True\r\n" +
            "Direction:                            Out\r\n" +
            "Profiles:                             Domain,Private,Public\r\n" +
            "Grouping:                             \r\n" +
            "LocalIP:                              Any\r\n" +
            "RemoteIP:                             Any\r\n" +
            "Protocol:                             TCP\r\n" +
            "LocalPort:                            Any\r\n" +
            "RemotePort:                           Any\r\n" +
            "Edge traversal:                       No\r\n" +
            "InterfaceTypes:                       Any\r\n" +
            "Security:                             NotRequired\r\n" +
            "Rule source:                          Local Setting\r\n" +
            "Action:                               Allow\r\n" +
            "Ok.\r\n";
        AssertThrowsType(delegate { CmdFirewallBackend.ParseRules(UnrecognizedEnabledValueRule); }, typeof(FirewallRefusalException),
            "cmd fixture: an unrecognized Enabled value is a plain refusal (output-format drift), not the Unsupported-shape subtype");

        const string NoProgramNoGroupRule =
            "Rule Name:                            HNS Container Networking - DNS (UDP-In) - 0\r\n" +
            "----------------------------------------------------------------------\r\n" +
            "Description:                          HNS Container Networking - DNS (UDP-In) - 0\r\n" +
            "Enabled:                              Yes\r\n" +
            "Direction:                            In\r\n" +
            "Profiles:                             Domain,Private,Public\r\n" +
            "Grouping:                             \r\n" +
            "LocalIP:                              Any\r\n" +
            "RemoteIP:                             Any\r\n" +
            "Protocol:                             UDP\r\n" +
            "LocalPort:                            53\r\n" +
            "RemotePort:                           Any\r\n" +
            "Edge traversal:                       No\r\n" +
            "InterfaceTypes:                       Any\r\n" +
            "Security:                             NotRequired\r\n" +
            "Rule source:                          Local Setting\r\n" +
            "Action:                               Allow\r\n" +
            "Ok.\r\n";
        IList<FirewallRuleData> noProgram = CmdFirewallBackend.ParseRules(NoProgramNoGroupRule);
        Assert(noProgram.Count == 1 && noProgram[0].ApplicationName.Length == 0 && noProgram[0].ServiceName.Length == 0 &&
            noProgram[0].Grouping.Length == 0 && noProgram[0].LocalPorts == "53" && noProgram[0].RemotePorts == "*" &&
            noProgram[0].Direction == 1, "cmd fixture: no Program/Service line and empty Grouping value both decode as ''");

        const string NoDescriptionRule =
            "Rule Name:                            Smart Connect\r\n" +
            "----------------------------------------------------------------------\r\n" +
            "Enabled:                              Yes\r\n" +
            "Direction:                            In\r\n" +
            "Profiles:                             Public\r\n" +
            "Grouping:                             \r\n" +
            "LocalIP:                              Any\r\n" +
            "RemoteIP:                             Any\r\n" +
            "Protocol:                             TCP\r\n" +
            "LocalPort:                            8080\r\n" +
            "RemotePort:                           Any\r\n" +
            "Edge traversal:                       No\r\n" +
            "Program:                              C:\\Program Files\\Lenovo\\Ready For Assistant\\ScMcpServer.exe\r\n" +
            "InterfaceTypes:                       Any\r\n" +
            "Security:                             NotRequired\r\n" +
            "Rule source:                          Local Setting\r\n" +
            "Action:                               Block\r\n" +
            "Ok.\r\n";
        IList<FirewallRuleData> noDescription = CmdFirewallBackend.ParseRules(NoDescriptionRule);
        Assert(noDescription.Count == 1 && noDescription[0].Description.Length == 0 && noDescription[0].Action == 0,
            "cmd fixture: a rule with no 'Description:' line decodes as '', not a refusal (confirmed live shape: Smart Connect)");

        const string MultiValueRemoteIpRule =
            "Rule Name:                            codex_sandbox_offline_block_loopback_udp\r\n" +
            "----------------------------------------------------------------------\r\n" +
            "Description:                          codex sandbox\r\n" +
            "Enabled:                              Yes\r\n" +
            "Direction:                            Out\r\n" +
            "Profiles:                             Domain,Private,Public\r\n" +
            "Grouping:                             \r\n" +
            "LocalIP:                              Any\r\n" +
            "RemoteIP:                             127.0.0.0/8,::/127\r\n" +
            "Protocol:                             UDP\r\n" +
            "LocalPort:                            Any\r\n" +
            "RemotePort:                           Any\r\n" +
            "Edge traversal:                       No\r\n" +
            "InterfaceTypes:                       Any\r\n" +
            "Security:                             NotRequired\r\n" +
            "Rule source:                          Local Setting\r\n" +
            "Action:                               Block\r\n" +
            "Ok.\r\n";
        AssertThrowsType(delegate { CmdFirewallBackend.ParseRules(MultiValueRemoteIpRule); }, typeof(FirewallReadbackUnsupportedException),
            "cmd fixture: a comma-joined multi-value RemoteIP is refused, matching management/powershell's FirstOrAny");

        const string UnrecognizedLabelRule =
            "Rule Name:                            Future Windows Rule\r\n" +
            "----------------------------------------------------------------------\r\n" +
            "Description:                          future\r\n" +
            "Enabled:                              Yes\r\n" +
            "Direction:                            Out\r\n" +
            "Profiles:                             Domain,Private,Public\r\n" +
            "Grouping:                             \r\n" +
            "LocalIP:                              Any\r\n" +
            "RemoteIP:                             Any\r\n" +
            "Protocol:                             TCP\r\n" +
            "LocalPort:                            Any\r\n" +
            "RemotePort:                           Any\r\n" +
            "Edge traversal:                       No\r\n" +
            "NewFieldNoOneHasSeenYet:               Something\r\n" +
            "InterfaceTypes:                       Any\r\n" +
            "Security:                             NotRequired\r\n" +
            "Rule source:                          Local Setting\r\n" +
            "Action:                               Allow\r\n" +
            "Ok.\r\n";
        AssertThrowsType(delegate { CmdFirewallBackend.ParseRules(UnrecognizedLabelRule); }, typeof(FirewallReadbackUnsupportedException),
            "cmd fixture: an unrecognized label refuses outright rather than silently ignoring it");

        Assert(CmdFirewallBackend.ParseRules("").Count == 0, "cmd fixture: empty text parses to zero rules");

        const string AllProfilesFixture =
            "Domain Profile Settings: \r\n" +
            "----------------------------------------------------------------------\r\n" +
            "State                                 ON\r\n" +
            "Firewall Policy                       BlockInbound,AllowOutbound\r\n" +
            "\r\n" +
            "Private Profile Settings: \r\n" +
            "----------------------------------------------------------------------\r\n" +
            "State                                 ON\r\n" +
            "Firewall Policy                       BlockInboundAlways,BlockOutbound\r\n" +
            "\r\n" +
            "Public Profile Settings: \r\n" +
            "----------------------------------------------------------------------\r\n" +
            "State                                 OFF\r\n" +
            "Firewall Policy                       AllowInbound,AllowOutbound\r\n" +
            "\r\n" +
            "Ok.\r\n";
        IList<FirewallProfileData> profiles = CmdFirewallBackend.ParseAllProfiles(AllProfilesFixture);
        Assert(profiles.Count == 3 && profiles[0].Profile == 1 && profiles[0].Enabled && profiles[0].DefaultInboundAction == 0 &&
            !profiles[0].BlockAllInbound && profiles[0].DefaultOutboundAction == 1, "cmd fixture: Domain profile (BlockInbound,AllowOutbound)");
        Assert(profiles[1].Profile == 2 && profiles[1].BlockAllInbound && profiles[1].DefaultOutboundAction == 0,
            "cmd fixture: Private profile (BlockInboundAlways,BlockOutbound)");
        Assert(profiles[2].Profile == 4 && !profiles[2].Enabled && profiles[2].DefaultInboundAction == 1,
            "cmd fixture: Public profile (OFF; AllowInbound,AllowOutbound)");

        // The not-found path: confirmed live text/exit-code pair (netsh exits 1 with exactly this
        // message, never 0, when no rule matches). Tested against a constructed Result rather than
        // only via --cmd-read-only's live "absent enumeration" assertion, which proves the same
        // outcome but not deterministically on every run.
        Assert(CmdFirewallBackend.ParseFindByNameResult(new CmdFirewallBackend.Result(1, "No rules match the specified criteria.\r\n", "")).Count == 0,
            "cmd fixture: the not-found message with exit 1 parses to zero rules, not a thrown failure");
        AssertThrowsType(delegate { CmdFirewallBackend.ParseFindByNameResult(new CmdFirewallBackend.Result(1, "Some other netsh error.\r\n", "")); },
            typeof(InvalidOperationException), "cmd fixture: a nonzero exit that is NOT the not-found message still throws");

        // Multi-block splitting: two rule blocks back to back, separated by exactly one blank line and
        // no per-block "Ok." -- the real shape netsh produces for "show rule name=X verbose" when X
        // matches more than one rule (confirmed live shape, e.g. several real Windows rules each have
        // 2-6 instances sharing one DisplayName across profiles/ports). ParseShowRuleBlocks splits on
        // the "Rule Name" label itself (starting a new block each time that label recurs), not on the
        // "----" line -- that line is just skipped, like any other blank or unparseable line. These two
        // fixture blocks (DnsRule, NoProgramNoGroupRule) happen to carry different Rule Name values, but
        // splitting never compares names for equality, so this still exercises the same splitting logic
        // a true same-name duplicate would.
        string duplicateBlocks = DnsRule.Substring(0, DnsRule.Length - "Ok.\r\n".Length) + "\r\n" + NoProgramNoGroupRule;
        IList<FirewallRuleData> duplicates = CmdFirewallBackend.ParseRules(duplicateBlocks);
        Assert(duplicates.Count == 2 && duplicates[0].ApplicationName.Length != 0 && duplicates[1].ApplicationName.Length == 0,
            "cmd fixture: two back-to-back rule blocks both decode, in order");
    }

    // Deterministic, CI-covered tests for PowerShellFirewallBackend.ParseRules against a constructed
    // marker-delimited fixture (the exact protocol FindByName's own script emits), covering a
    // truncated stream, an out-of-range begin-marker index and a begin/end field-name mismatch --
    // none of which --powershell-read-only can guarantee exercising, since it depends on what rules
    // (if any) happen to be readable on whatever host it runs on.
    private static void PowerShellParseRulesFixtures()
    {
        const string marker = "abc123";
        string valid = BuildValidPowerShellRuleFixture(marker);
        IList<FirewallRuleData> rules = PowerShellFirewallBackend.ParseRules(valid, marker);
        Assert(rules.Count == 1 && rules[0].Name == "WinTraceForge.Firewall.test" && rules[0].Grouping == "WinTraceForge.Firewall.v1" &&
            rules[0].Enabled && rules[0].Direction == 2 && rules[0].Action == 1 && rules[0].Profiles == 7 &&
            rules[0].RemoteAddresses == "192.0.2.10" && rules[0].RemotePorts == "44443" && rules[0].LocalPorts == "*" &&
            rules[0].Protocol == 6, "powershell fixture: a well-formed marker stream decodes fully");

        int lastEnd = valid.LastIndexOf("WTF_END_" + marker, StringComparison.Ordinal);
        string truncated = valid.Substring(0, lastEnd);
        AssertThrowsType(delegate { PowerShellFirewallBackend.ParseRules(truncated, marker); }, typeof(InvalidOperationException),
            "powershell fixture: a stream missing its final WTF_END_ marker is reported as truncated");

        string outOfRangeIndex = "WTF_COUNT_" + marker + ":1\r\n" +
            "WTF_BEGIN_" + marker + ":5:ElementName\r\n" +
            DefenderModule.PowerShellRunner.EncodeValue("x") + "\r\n" +
            "WTF_END_" + marker + ":5:ElementName\r\n";
        AssertThrowsType(delegate { PowerShellFirewallBackend.ParseRules(outOfRangeIndex, marker); }, typeof(InvalidOperationException),
            "powershell fixture: a begin-marker index beyond the declared count is refused");

        string mismatchedEnd = "WTF_COUNT_" + marker + ":1\r\n" +
            "WTF_BEGIN_" + marker + ":0:ElementName\r\n" +
            DefenderModule.PowerShellRunner.EncodeValue("x") + "\r\n" +
            "WTF_END_" + marker + ":0:RuleGroup\r\n";
        AssertThrowsType(delegate { PowerShellFirewallBackend.ParseRules(mismatchedEnd, marker); }, typeof(InvalidOperationException),
            "powershell fixture: a begin/end field-name mismatch is refused");

        Assert(PowerShellFirewallBackend.ParseRules("WTF_COUNT_" + marker + ":0\r\n", marker).Count == 0,
            "powershell fixture: a declared count of zero parses to zero rules");
    }

    // Runs a real powershell.exe (the same DefenderModule.PowerShellRunner.RunScript path
    // PowerShellFirewallBackend itself uses, and the same "spawn a real process from the default -Test
    // run" pattern AddDefenderExclusion.RegressionTests.cs already establishes for BuildReadScript) to
    // verify the actual mechanism PowerShellFirewallBackend.RuleFields' remarks rely on: that
    // Set-StrictMode -Version Latest turns a read of a property that does not exist on an object into a
    // terminating error, rather than silently returning $null/0, on a plain strongly-typed object (not
    // just a PSCustomObject with dynamic members) -- confirmed live in this session before adding
    // Set-StrictMode to every script this backend runs. This proves the *platform* behaves as relied
    // upon; it does NOT prove any of this backend's own scripts actually still contain the line --
    // PowerShellScriptProloguesAreApplied below closes that gap (a mutation-tested one: deleting
    // Set-StrictMode from FindByName's own builder and re-running -Test was confirmed live to leave
    // this test, and the rest of the default suite, still passing).
    private static void PowerShellStrictModeCatchesMissingProperty()
    {
        string script = "$ErrorActionPreference = 'Stop'\r\n" +
            "Set-StrictMode -Version Latest\r\n" +
            "try {\r\n" +
            "    $p = Get-Process -Id $PID\r\n" +
            "    $x = [int]$p.WTF_Nonexistent_Property_Marker\r\n" +
            "    Write-Output 'WTF_GUARD_OK'\r\n" +
            "} catch {\r\n" +
            DefenderModule.PowerShellRunner.EmitErrorMarkerStatement("WTF_GUARD_ERROR:") +
            "    exit 1\r\n" +
            "}\r\n";
        DefenderModule.PowerShellRunner.Result result = DefenderModule.PowerShellRunner.RunScript(script);
        string errorMessage = DefenderModule.PowerShellRunner.FindMarkerMessage(result.Stdout, "WTF_GUARD_ERROR:");
        Assert(errorMessage != null && !DefenderModule.PowerShellRunner.ContainsMarker(result.Stdout, "WTF_GUARD_OK"),
            "Set-StrictMode -Version Latest converts a nonexistent-property read into a script-terminating error " +
            "(live powershell.exe), not a silent $null/0");
    }

    // Deterministic (no process spawn), CI-covered pin that every one of PowerShellFirewallBackend's six
    // script builders actually starts with PowerShellFirewallBackend.ScriptPrologue -- not merely that
    // the language feature works (PowerShellStrictModeCatchesMissingProperty, above) or that today's
    // property names happen to exist (--powershell-read-only, which cannot detect a deleted
    // Set-StrictMode line at all: verified live that removing it from FindByName's builder alone left
    // the default -Test suite, including PowerShellStrictModeCatchesMissingProperty, at a full pass).
    // Each builder is exercised with the minimal real arguments it needs; only the resulting script TEXT
    // is inspected, so this never spawns powershell.exe.
    private static void PowerShellScriptProloguesAreApplied()
    {
        string prologue = PowerShellFirewallBackend.ScriptPrologue;
        // The six StartsWith checks below read their expected value from the constant itself, so they
        // would pass just as happily if ScriptPrologue were quietly weakened (e.g. Set-StrictMode
        // trimmed back out of it) -- confirmed live by mutation testing that all 369 assertions still
        // passed with ScriptPrologue reduced to just "$ErrorActionPreference = 'Stop'\r\n". Pin the
        // constant's actual content against a literal written here, independent of the constant, so
        // that specific edit fails loudly instead of passing silently.
        Assert(prologue == "$ErrorActionPreference = 'Stop'\r\nSet-StrictMode -Version Latest\r\n",
            "powershell shared prologue pins ErrorActionPreference=Stop and StrictMode Latest verbatim");
        FirewallRuleData rule = FirewallModule.ExpectedRule(AddOptions(), 1);
        Assert(PowerShellFirewallBackend.BuildConnectScript().StartsWith(prologue, StringComparison.Ordinal),
            "powershell connect script starts with the shared prologue (Set-StrictMode included)");
        Assert(PowerShellFirewallBackend.BuildCurrentProfilesScript().StartsWith(prologue, StringComparison.Ordinal),
            "powershell CurrentProfiles script starts with the shared prologue (Set-StrictMode included)");
        Assert(PowerShellFirewallBackend.BuildReadProfilesScript("marker").StartsWith(prologue, StringComparison.Ordinal),
            "powershell ReadProfiles script starts with the shared prologue (Set-StrictMode included)");
        Assert(PowerShellFirewallBackend.BuildFindByNameScript("WinTraceForge.Firewall.test", "marker").StartsWith(prologue, StringComparison.Ordinal),
            "powershell FindByName script starts with the shared prologue (Set-StrictMode included)");
        Assert(PowerShellFirewallBackend.BuildAddScript(rule).StartsWith(prologue, StringComparison.Ordinal),
            "powershell Add script starts with the shared prologue (Set-StrictMode included)");
        Assert(PowerShellFirewallBackend.BuildRemoveScript("WinTraceForge.Firewall.test").StartsWith(prologue, StringComparison.Ordinal),
            "powershell Remove script starts with the shared prologue (Set-StrictMode included)");
    }

    private static string BuildValidPowerShellRuleFixture(string marker)
    {
        string[] fields = { "ElementName", "RuleGroup", "Description", "Enabled", "Direction", "Action", "Profiles",
            "EdgeTraversalPolicy", "PackageFamilyName", "Owner", "LocalAddress", "RemoteAddress",
            "LocalPort", "RemotePort", "Protocol", "AppPath", "ServiceName", "InterfaceType",
            "InterfaceAlias", "Authentication", "Encryption", "OverrideBlockRules", "LocalUsers",
            "RemoteUsers", "RemoteMachines" };
        Dictionary<string, string> values = new Dictionary<string, string>
        {
            { "ElementName", "WinTraceForge.Firewall.test" }, { "RuleGroup", "WinTraceForge.Firewall.v1" },
            { "Description", "WinTraceForge;kind=firewall-rule;schema=1;id=test" }, { "Enabled", "1" },
            { "Direction", "2" }, { "Action", "2" }, { "Profiles", "7" }, { "EdgeTraversalPolicy", "0" },
            { "PackageFamilyName", "" }, { "Owner", "" }, { "LocalAddress", "Any" }, { "RemoteAddress", "192.0.2.10" },
            { "LocalPort", "Any" }, { "RemotePort", "44443" }, { "Protocol", "TCP" }, { "AppPath", "Any" },
            { "ServiceName", "Any" }, { "InterfaceType", "0" }, { "InterfaceAlias", "Any" },
            { "Authentication", "0" }, { "Encryption", "0" }, { "OverrideBlockRules", "0" },
            { "LocalUsers", "Any" }, { "RemoteUsers", "Any" }, { "RemoteMachines", "Any" }
        };
        StringBuilder sb = new StringBuilder();
        sb.Append("WTF_COUNT_" + marker + ":1\r\n");
        foreach (string field in fields)
        {
            sb.Append("WTF_BEGIN_" + marker + ":0:" + field + "\r\n");
            sb.Append(DefenderModule.PowerShellRunner.EncodeValue(values[field]) + "\r\n");
            sb.Append("WTF_END_" + marker + ":0:" + field + "\r\n");
        }
        sb.Append("WTF_READ_OK\r\n");
        return sb.ToString();
    }

    private static void AssertThrowsType(Action action, Type expected, string name)
    {
        try { action(); }
        catch (Exception error)
        {
            Assert(error.GetType() == expected, name + " (was " + error.GetType().Name + ")");
            return;
        }
        Assert(false, name + " (nothing was thrown)");
    }

    private static void CmdUnsafeCharactersRejected()
    {
        foreach (char unsafeChar in new[] { '"', '%', '!', '\r', '\n', '\t', '\x01' })
        {
            bool rejected = false;
            try { CmdRequireSafeForCmd(@"C:\Tools\a" + unsafeChar + "b.exe"); }
            catch (FirewallRefusalException) { rejected = true; }
            Assert(rejected, "cmd rejects unsafe character 0x" + ((int)unsafeChar).ToString("X2"));
        }
        bool accepted = true;
        try { CmdRequireSafeForCmd(@"C:\Tools\Ordinary Path (2).exe"); }
        catch (FirewallRefusalException) { accepted = false; }
        Assert(accepted, "cmd accepts an ordinary path with spaces/parentheses");
    }

    // Pins the exact bug found in review: "add rule ?" documents program=<Application Path and File
    // Name> with no "any" keyword (unlike localport=/remoteport=, which do document "any"). What netsh
    // would actually have done with the literal text "any" as a path is undocumented and was never
    // verified live (it might have been rejected outright, silently ignored, or genuinely scoped the
    // rule to a program named "any" -- no evidence either way), which is exactly why it should never
    // have been sent: the fix omits program= entirely for an unrestricted rule instead, matching
    // com/management's own "preserve unspecified defaults" behavior, which IS confirmed live to mean
    // "no restriction" (see BuildAddCommand's own remarks). This snapshot test fails loudly if that
    // regresses.
    private static void CmdAddCommandOmitsProgramWhenUnset()
    {
        FirewallRuleData withoutProgram = FirewallModule.ExpectedRule(AddOptions(), 1);
        Assert(withoutProgram.ApplicationName.Length == 0, "test precondition: no --program given");
        string command = CmdBuildAddCommand(withoutProgram);
        Assert(command.IndexOf("program=", StringComparison.Ordinal) < 0, "cmd add omits program= entirely when unset");

        FirewallOptions withProgram = FirewallModule.Parse(new[] { "rule", "add", "--remote-address", "192.0.2.10",
            "--remote-port", "44443", "--program", @"C:\Tools\probe.exe" });
        string commandWithProgram = CmdBuildAddCommand(FirewallModule.ExpectedRule(withProgram, 1));
        Assert(commandWithProgram.Contains("program=\"C:\\Tools\\probe.exe\""), "cmd add quotes an explicit program path");
    }

    // Pins the exact accepted/rejected set for MSFT_NetFirewallRule.Action's live ValueMap {2, 3, 4}
    // (0 is a NetSecurity.Action value that applies only to profile-level default actions, not to a
    // rule's own Action) so a future edit to this mapping cannot silently regress without a test
    // noticing. Construction alone; never touches real Windows Firewall state.
    private static void ManagementActionCodec()
    {
        Assert((int)ManagementPrivate("RuleActionFromRaw", 2) == 1, "management Action 2 (Allow) decodes to 1");
        Assert((int)ManagementPrivate("RuleActionFromRaw", 4) == 0, "management Action 4 (Block) decodes to 0");
        Assert((int)ManagementPrivate("RuleActionToRaw", 1) == 2, "management Allow(1) encodes to Action 2");
        Assert((int)ManagementPrivate("RuleActionToRaw", 0) == 4, "management Block(0) encodes to Action 4");
        // Raw 3 is the one Action value the --management-read-only candidate loop is allowed to skip
        // past (see FirewallReadbackUnsupportedException; the loop also skips a few other rule shapes
        // -- interface type, interface alias, protocol, multi-value filters -- pinned separately below
        // in ManagementReadbackClassification). Pinning Action's exact type here means a future change
        // that reclassifies any of 0/1/5/999 the same way would be caught here, not silently by that
        // loop skipping a real rule it should have failed on.
        AssertThrowsExactType("RuleActionFromRaw", 3, typeof(FirewallReadbackUnsupportedException),
            "management Action 3 is the readback-unsupported subtype, not a plain refusal");
        foreach (int raw in new[] { 0, 1, 5, 999 })
        {
            AssertThrowsExactType("RuleActionFromRaw", raw, typeof(FirewallRefusalException),
                "management Action " + raw + " is a plain refusal, not the readback-unsupported subtype");
        }
    }

    // Extends the Action pinning above to the other refusal sites the --management-read-only
    // candidate loop treats as skip-worthy (RuleEnabledFromRaw, ProtocolNumber, FirstOrAny,
    // ReadStringArray), so a future change that moves a "must fail" refusal to the skippable
    // subtype -- or vice versa -- is caught here rather than only surfacing as that loop silently
    // skipping a readback it should have failed on. RequireOne's "Expected exactly one ..." refusal
    // (the invariant that a rule has exactly one of each MSFT_Net*Filter kind) is deliberately left
    // unpinned here: it takes a live ManagementObjectCollection with a contrived 0-or-2+-count shape
    // to exercise, which construction-only testing cannot produce; it must always stay a plain
    // FirewallRefusalException; never the readback-unsupported subtype, since finding zero or more
    // than one of a filter kind is a structural anomaly, not a merely-unsupported valid rule shape.
    private static void ManagementReadbackClassification()
    {
        AssertThrowsExactType("RuleEnabledFromRaw", 0, typeof(FirewallRefusalException),
            "management Enabled=0 is a plain refusal, not the readback-unsupported subtype");
        AssertThrowsExactType("ReadStringArray", 123, typeof(FirewallRefusalException),
            "management an unexpected filter array type is a plain refusal, not the readback-unsupported subtype");
        AssertThrowsExactType("ProtocolNumber", "ICMPv4", typeof(FirewallReadbackUnsupportedException),
            "management an unrecognized readback protocol is the readback-unsupported subtype");
        AssertThrowsExactType("FirstOrAny", new[] { "a", "b" }, typeof(FirewallReadbackUnsupportedException),
            "management a multi-value filter is the readback-unsupported subtype");
    }

    private static void AssertThrowsExactType(string method, object argument, Type expected, string name)
    {
        try { ManagementPrivate(method, argument); }
        catch (FirewallRefusalException error)
        {
            Assert(error.GetType() == expected, name + " (was " + error.GetType().Name + ")");
            return;
        }
        Assert(false, name + " (nothing was thrown)");
    }

    // Production rule names (WinTraceForge.Firewall.<guid>) never contain \ or ', so this never
    // affects user-visible behavior; it guards the general-purpose WQL escape --management-read-only's
    // real-rule candidate loop depends on (some pre-existing rule names, e.g. from firewallapi.dll,
    // contain \, which WQL treats as an escape character).
    private static void ManagementEscapeWql()
    {
        Assert((string)ManagementPrivate("EscapeWql", "a\\b'c") == "a\\\\b''c", "management WQL escaping handles backslash and quote");
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
