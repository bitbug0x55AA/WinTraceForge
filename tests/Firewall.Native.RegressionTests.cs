// This Source Code Form is subject to the terms of the Mozilla Public License, v. 2.0.
// If a copy of the MPL was not distributed with this file, You can obtain one at https://mozilla.org/MPL/2.0/.

using System;
using System.Collections.Generic;
using System.IO;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Threading;

// Compile alongside WinTraceForge*.cs with /main:FirewallNativeRegressionTests.
// The only write-like operations exercised are detached object setters. Never Add/Remove.
internal static class FirewallNativeRegressionTests
{
    private static int assertions;
    private static void Assert(bool value, string message)
    {
        ++assertions;
        if (!value) { throw new Exception(message); }
    }
    private static void Expect<T>(Action action, string message) where T : Exception
    {
        try { action(); }
        catch (T) { Assert(true, message); return; }
        throw new Exception("Expected " + typeof(T).Name + ": " + message);
    }
    private static FirewallRuleData Expected(int protocol)
    {
        FirewallOptions options = FirewallModule.Parse(new string[] { "rule", "add", "--id",
            Guid.NewGuid().ToString("D"), "--remote-address", protocol == 6 ? "192.0.2.15" : "2001:db8::1",
            "--remote-port", "443", "--protocol", protocol == 6 ? "tcp" : "udp", "--profiles", "private" });
        options.Direction = protocol == 6 ? 2 : 1;
        options.Action = protocol == 6 ? 0 : 1;
        options.LocalPort = protocol == 6 ? 0 : 12345;
        options.Program = protocol == 6 ? "" : @"C:\Windows\System32\notepad.exe";
        return FirewallModule.ExpectedRule(options, 2);
    }
    private static void CompareFields(object expected, object actual)
    {
        foreach (FieldInfo field in expected.GetType().GetFields(BindingFlags.Instance | BindingFlags.NonPublic))
        {
            object left = field.GetValue(expected), right = field.GetValue(actual);
            string[] strings = left as string[];
            if (strings != null)
            {
                string[] other = right as string[];
                Assert(other != null && strings.Length == other.Length, field.Name + " count");
                for (int i = 0; i < strings.Length; ++i) { Assert(strings[i] == other[i], field.Name + " element"); }
            }
            else { Assert(object.Equals(left, right), "Full field comparison: " + field.Name); }
        }
    }
    private static List<string> ExistingNames()
    {
        object policy = null, rules = null, enumeration = null;
        object[] item = new object[1];
        List<string> names = new List<string>();
        try
        {
            policy = Activator.CreateInstance(Type.GetTypeFromProgID("HNetCfg.FwPolicy2", true));
            rules = Get(policy, "Rules");
            IntPtr pointer;
            int status = ((ComFirewallBackend.IFirewallRulesEnumerator)rules).GetNewEnum(out pointer);
            try
            {
                Marshal.ThrowExceptionForHR(status);
                enumeration = Marshal.GetTypedObjectForIUnknown(pointer, typeof(ComFirewallBackend.IFirewallEnumVariant));
            }
            finally { if (pointer != IntPtr.Zero) { Marshal.Release(pointer); } }
            while (names.Count < 5)
            {
                status = ((ComFirewallBackend.IFirewallEnumVariant)enumeration).Next(1, item, IntPtr.Zero);
                try
                {
                    if (status == 1) { break; }
                    Marshal.ThrowExceptionForHR(status);
                    Assert(status == 0, "enumerator status");
                    int protocol = (int)Get(item[0], "Protocol");
                    if (protocol == 6 || protocol == 17)
                    {
                        string name = (string)Get(item[0], "Name");
                        if (!names.Contains(name)) { names.Add(name); }
                    }
                }
                finally { Release(item[0]); item[0] = null; }
            }
            return names;
        }
        finally { Release(item[0]); Release(enumeration); Release(rules); Release(policy); }
    }
    private static object Get(object target, string property)
    {
        return target.GetType().InvokeMember(property, BindingFlags.GetProperty, null, target, null);
    }
    private static void Release(object target)
    {
        if (target != null && Marshal.IsComObject(target)) { Marshal.FinalReleaseComObject(target); }
    }
    private static void ReadOnly()
    {
        using (IFirewallBackend com = new ComFirewallBackend())
        using (IFirewallBackend native = new NativeFirewallBackend())
        {
            Assert(com.CurrentProfiles == native.CurrentProfiles, "current profiles");
            Assert(com.LocalPolicyModifyState == native.LocalPolicyModifyState, "modify state");
            IList<FirewallProfileData> left = com.ReadProfiles(), right = native.ReadProfiles();
            Assert(left.Count == 3 && right.Count == 3, "all profiles");
            for (int i = 0; i < 3; ++i) { CompareFields(left[i], right[i]); }
            string missing = "WinTraceForge.Native.Absent." + Guid.NewGuid().ToString("D");
            Assert(com.FindByName(missing).Count == 0 && native.FindByName(missing).Count == 0, "absent lookup");
            List<string> names = ExistingNames();
            Assert(names.Count != 0, "at least one existing TCP/UDP rule available");
            foreach (string name in names)
            {
                IList<FirewallRuleData> comRules = com.FindByName(name), nativeRules = native.FindByName(name);
                Assert(comRules.Count > 0 && comRules.Count == nativeRules.Count, "existing rule count");
                for (int i = 0; i < comRules.Count; ++i) { CompareFields(comRules[i], nativeRules[i]); }
                Assert(native.FindByName(name.ToUpperInvariant()).Count == nativeRules.Count, "case insensitive collision lookup");
            }
            Console.WriteLine("Compared all DTO fields for {0} existing names and three profiles.", names.Count);
        }
    }
    private static void Detached()
    {
        FirewallOptions inbound = FirewallModule.Parse(new string[] { "rule", "add", "--id",
            Guid.NewGuid().ToString("D"), "--direction", "in", "--remote-address", "192.0.2.15",
            "--local-port", "443", "--profiles", "private" });
        FirewallRuleData inboundRule = FirewallModule.ExpectedRule(inbound, 2);
        Assert(inboundRule.Direction == 1 && inboundRule.LocalPorts == "443" && inboundRule.RemotePorts == "*",
            "inbound local443 with omitted source port maps to wildcard");
        using (IFirewallBackend com = new ComFirewallBackend())
        using (IFirewallBackend native = new NativeFirewallBackend())
        {
            Assert(com.FindByName(inboundRule.Name).Count == 0 && native.FindByName(inboundRule.Name).Count == 0,
                "inbound wildcard rule absent before preparation");
            com.PrepareAdd(inboundRule);
            native.PrepareAdd(inboundRule);
            Assert(com.FindByName(inboundRule.Name).Count == 0 && native.FindByName(inboundRule.Name).Count == 0,
                "inbound local443 remote wildcard detached readback succeeds without persistence");
        }
        foreach (int protocol in new int[] { 6, 17 })
        {
            FirewallRuleData rule = Expected(protocol);
            using (IFirewallBackend com = new ComFirewallBackend())
            using (IFirewallBackend native = new NativeFirewallBackend())
            {
                Assert(native.FindByName(rule.Name).Count == 0, "detached absent before");
                com.PrepareAdd(rule);
                native.PrepareAdd(rule);
                Assert(com.FindByName(rule.Name).Count == 0 && native.FindByName(rule.Name).Count == 0,
                    "detached setters never persisted");
                Expect<FirewallRefusalException>(delegate { native.PrepareAdd(rule); }, "duplicate preparation");
            }
        }
        using (IFirewallBackend native = new NativeFirewallBackend())
        {
            Expect<FirewallRefusalException>(delegate { native.Add(); }, "Add without prepare refused before COM call");
            FirewallRuleData invalid = Expected(6);
            invalid.Protocol = -1;
            Expect<COMException>(delegate { native.PrepareAdd(invalid); }, "invalid protocol HRESULT");
            invalid = Expected(6);
            invalid.RemoteAddresses = "not-an-ip-address";
            Expect<COMException>(delegate { native.PrepareAdd(invalid); }, "invalid address HRESULT");
            foreach (string property in new string[] { "LocalAppPackageId", "LocalUserOwner", "LocalUserAuthorizedList",
                "RemoteUserAuthorizedList", "RemoteMachineAuthorizedList" })
            {
                invalid = Expected(6);
                typeof(FirewallRuleData).GetField(property, BindingFlags.NonPublic | BindingFlags.Instance).SetValue(invalid, "must-not-be-lost");
                Expect<FirewallRefusalException>(delegate { native.PrepareAdd(invalid); }, property + " survives preflight");
            }
            invalid = Expected(6);
            invalid.Interfaces = new string[] { "restricted-interface" };
            Expect<FirewallRefusalException>(delegate { native.PrepareAdd(invalid); }, "interface restriction refusal");
            invalid = Expected(6);
            invalid.SecureFlags = 1;
            Expect<FirewallRefusalException>(delegate { native.PrepareAdd(invalid); }, "IPsec restriction refusal");
            invalid = Expected(6);
            invalid.EdgeTraversalOptions = 1;
            Expect<FirewallRefusalException>(delegate { native.PrepareAdd(invalid); }, "edge restriction refusal");
            invalid = Expected(6);
            invalid.EdgeTraversal = true;
            Expect<FirewallRefusalException>(delegate { native.PrepareAdd(invalid); }, "edge traversal refusal");
            native.PrepareAdd(Expected(6));
            Assert(true, "failed preparations leave session reusable");
        }
    }
    private static void Codec()
    {
        FirewallRuleData original = Expected(6);
        original.Name = "UTF16-\u00e9-\ud83d\ude80-\ud800";
        original.Interfaces = new string[] { "Ethernet", "\u7f51\u7edc", "", null };
        original.LocalAppPackageId = "package-SID";
        original.LocalUserOwner = null;
        original.LocalUserAuthorizedList = "D:(A;;CC;;;WD)";
        original.RemoteUserAuthorizedList = "remote-user";
        original.RemoteMachineAuthorizedList = "remote-machine";
        original.EdgeTraversalOptions = 2;
        original.SecureFlags = unchecked((int)0x80000001);
        original.EdgeTraversal = true;
        Type backend = typeof(NativeFirewallBackend);
        MethodInfo encode = backend.GetMethod("RulePacket", BindingFlags.Static | BindingFlags.NonPublic);
        byte[] packet = (byte[])encode.Invoke(null, new object[] { original });
        Type readerType = backend.GetNestedType("PacketReader", BindingFlags.NonPublic);
        using (IDisposable reader = (IDisposable)Activator.CreateInstance(readerType,
            BindingFlags.Instance | BindingFlags.NonPublic, null, new object[] { packet }, null))
        {
            FirewallRuleData copy = (FirewallRuleData)readerType.GetMethod("Rule", BindingFlags.Instance | BindingFlags.NonPublic).Invoke(reader, null);
            CompareFields(original, copy);
            readerType.GetMethod("End", BindingFlags.Instance | BindingFlags.NonPublic).Invoke(reader, null);
        }

        foreach (byte[] bad in new byte[][] { new byte[0], new byte[3], new byte[4] })
        {
            try
            {
                Activator.CreateInstance(readerType, BindingFlags.Instance | BindingFlags.NonPublic, null, new object[] { bad }, null);
                throw new Exception("Malformed packet was accepted.");
            }
            catch (TargetInvocationException error) { Assert(error.InnerException is FirewallRefusalException, "malformed packet rejected"); }
        }
    }

    private static void OptionalDefaults()
    {
        foreach (int protocol in new[] { 6, 17 })
        {
            FirewallRuleData expected = Expected(protocol);
            using (ComFirewallBackend com = new ComFirewallBackend())
            using (NativeFirewallBackend native = new NativeFirewallBackend())
            {
                com.PrepareAdd(expected);
                object comRule = typeof(ComFirewallBackend).GetField("preparedRule",
                    BindingFlags.Instance | BindingFlags.NonPublic).GetValue(com);
                Assert(Get(comRule, "ServiceName") == null, "COM unspecified service stays NULL, not empty");
                Assert(protocol == 6 ? Get(comRule, "ApplicationName") == null :
                    (string)Get(comRule, "ApplicationName") == expected.ApplicationName,
                    "COM omitted/explicit application preserved");
                Type backend = typeof(NativeFirewallBackend);
                byte[] packet = (byte[])backend.GetMethod("RulePacket", BindingFlags.Static | BindingFlags.NonPublic)
                    .Invoke(null, new object[] { expected });
                using (IDisposable reader = (IDisposable)backend.GetMethod("Invoke", BindingFlags.Instance | BindingFlags.NonPublic)
                    .Invoke(native, new object[] { (uint)5, packet }))
                {
                    FirewallRuleData actual = (FirewallRuleData)reader.GetType()
                        .GetMethod("Rule", BindingFlags.Instance | BindingFlags.NonPublic).Invoke(reader, null);
                    reader.GetType().GetMethod("End", BindingFlags.Instance | BindingFlags.NonPublic).Invoke(reader, null);
                    Assert(actual.ServiceName == null, "native unspecified service stays NULL, not empty");
                    Assert(protocol == 6 ? actual.ApplicationName == null : actual.ApplicationName == expected.ApplicationName,
                        "native omitted/explicit application preserved");
                    Assert(FirewallModule.Mismatches(expected, actual).Count == 0, "optional default change preserves all requested scope");
                }
                Assert(com.FindByName(expected.Name).Count == 0 && native.FindByName(expected.Name).Count == 0,
                    "optional-default checks never persist a rule");
            }
        }
        MethodInfo operation = typeof(NativeFirewallBackend).GetMethod("OperationName", BindingFlags.Static | BindingFlags.NonPublic);
        Assert((string)operation.Invoke(null, new object[] { (uint)7 }) == "INetFwRules::Add", "Add failure names actual API");
        Assert((string)operation.Invoke(null, new object[] { (uint)8 }) == "INetFwRules::Remove", "Remove failure names actual API");
        try
        {
            typeof(NativeFirewallBackend).GetMethod("Throw", BindingFlags.Static | BindingFlags.NonPublic)
                .Invoke(null, new object[] { unchecked((int)0x80070057), "INetFwRules::Add" });
            throw new Exception("Native error was swallowed.");
        }
        catch (TargetInvocationException error)
        {
            COMException failure = error.InnerException as COMException;
            Assert(failure != null && failure.HResult == unchecked((int)0x80070057),
                "named Add error preserves original HRESULT");
            Assert(failure.Message.Contains("INetFwRules::Add") && !failure.Message.Contains("0x80070057"),
                "HRESULT left for shared reporter, not duplicated in message");
        }
    }
    private static void Lifetime()
    {
        NativeFirewallBackend native = new NativeFirewallBackend();
        Exception failure = null;
        Thread thread = new Thread(delegate()
        {
            try { Assert(native.ReadProfiles().Count == 3, "cross-thread read"); }
            catch (Exception error) { failure = error; }
        });
        thread.Start();
        thread.Join();
        if (failure != null) { throw failure; }
        Expect<ArgumentException>(delegate { native.FindByName(""); }, "empty name");
        Expect<ArgumentException>(delegate { native.FindByName("prefix\0suffix"); }, "embedded NUL name");
        Expect<ArgumentException>(delegate { native.FindByName(new string('a', 1024 * 1024 + 1)); }, "oversized name");
        Expect<ArgumentNullException>(delegate { native.PrepareAdd(null); }, "null rule");
        native.Dispose();
        native.Dispose();
        Expect<ObjectDisposedException>(delegate { native.ReadProfiles(); }, "disposed access");
        Expect<ObjectDisposedException>(delegate { native.Add(); }, "disposed Add");
        for (int i = 0; i < 4; ++i) { using (NativeFirewallBackend value = new NativeFirewallBackend()) { Assert(value.CurrentProfiles > 0, "reopen"); } }
    }
    private static int Main()
    {
        try
        {
            Codec();
            ReadOnly();
            Detached();
            OptionalDefaults();
            Lifetime();
            Console.WriteLine("PASS: {0} assertions; no Rules.Add/Remove or policy setter invoked.", assertions);
            return 0;
        }
        catch (Exception error) { Console.Error.WriteLine(error); return 1; }
    }
}
