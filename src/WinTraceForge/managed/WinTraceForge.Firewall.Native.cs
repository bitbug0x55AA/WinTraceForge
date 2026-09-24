// This Source Code Form is subject to the terms of the
// Mozilla Public License, v. 2.0.
// If a copy of the MPL was not distributed with this file, You can obtain one at https://mozilla.org/MPL/2.0/.

using System;
using System.Collections.Generic;
using System.IO;
using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;

// Native ABI v1 is deliberately independent of CLR/COM layout and reflection.
// The native session owns an MTA worker; no COM interface crosses this boundary.
internal sealed class NativeFirewallBackend : IFirewallBackend
{
    private const uint Magic = 0x3146574e;
    private const int MaxPacket = 16 * 1024 * 1024;
    private const int MaxString = 1024 * 1024;
    private const int MaxCount = 65536;
    private readonly object gate = new object();
    private SessionHandle session;
    private bool prepared;

    internal NativeFirewallBackend()
    {
        IntPtr handle;
        Throw(NativeMethods.Open(out handle), "open");
        if (handle == IntPtr.Zero || handle == new IntPtr(-1))
        {
            throw new FirewallRefusalException("Native firewall returned an invalid session.");
        }
        session = new SessionHandle(handle);
    }

    public int CurrentProfiles { get { return ReadInt(1); } }
    public int LocalPolicyModifyState { get { return ReadInt(2); } }

    private int ReadInt(uint operation)
    {
        lock (gate)
        {
            using (PacketReader reader = Invoke(operation, Packet()))
            {
                int value = reader.Int();
                reader.End();
                return value;
            }
        }
    }

    public IList<FirewallProfileData> ReadProfiles()
    {
        lock (gate)
        {
            using (PacketReader reader = Invoke(3, Packet()))
            {
                int count = reader.Count();
                if (count != 3) { throw new FirewallRefusalException("Expected all three firewall profiles."); }
                List<FirewallProfileData> result = new List<FirewallProfileData>();
                for (int i = 0; i < count; ++i)
                {
                    FirewallProfileData profile = new FirewallProfileData
                    {
                        Profile = reader.Int(), DefaultInboundAction = reader.Int(),
                        DefaultOutboundAction = reader.Int(), Enabled = reader.Boolean(),
                        BlockAllInbound = reader.Boolean(), ExcludedInterfaces = reader.Strings()
                    };
                    if (profile.Profile != (1 << i)) { throw new FirewallRefusalException("Unexpected firewall profile order."); }
                    result.Add(profile);
                }
                reader.End();
                return result;
            }
        }
    }

    public IList<FirewallRuleData> FindByName(string name)
    {
        ValidateName(name);
        lock (gate)
        {
            using (PacketReader reader = Invoke(4, NamePacket(name)))
            {
                int count = reader.Count();
                List<FirewallRuleData> rules = new List<FirewallRuleData>();
                for (int i = 0; i < count; ++i) { rules.Add(reader.Rule()); }
                reader.End();
                return rules;
            }
        }
    }

    public void PrepareAdd(FirewallRuleData rule)
    {
        if (rule == null) { throw new ArgumentNullException("rule"); }
        ValidateName(rule.Name);
        if (rule.Interfaces == null || rule.Interfaces.Length != 0)
        { throw new FirewallRefusalException("Detached firewall rules must have no interface restrictions."); }
        lock (gate)
        {
            EnsureOpen();
            if (prepared) { throw new FirewallRefusalException("A detached rule is already prepared."); }
            bool accepted = false;
            try
            {
                FirewallRuleData detached;
                using (PacketReader reader = Invoke(5, RulePacket(rule)))
                {
                    detached = reader.Rule();
                    reader.End();
                }
                IList<string> differences = FirewallModule.Mismatches(rule, detached);
                if (differences.Count != 0)
                {
                    throw new FirewallRefusalException("New native rule has unexpected attributes before Rules.Add: " +
                        string.Join(", ", differences) + "; remote-address readback=" + detached.RemoteAddresses);
                }
                prepared = true;
                accepted = true;
            }
            finally
            {
                if (!accepted)
                {
                    // Discard is detached-only. If even cleanup fails, close the session
                    // so no subsequent Add can accidentally use an unverified object.
                    try { Empty(6); }
                    catch { session.Dispose(); session = null; }
                }
            }
        }
    }

    public void Add()
    {
        lock (gate)
        {
            EnsureOpen();
            if (!prepared) { throw new FirewallRefusalException("No detached rule was prepared."); }
            Empty(7);
        }
    }

    public void Remove(string name)
    {
        ValidateName(name);
        lock (gate)
        {
            using (PacketReader reader = Invoke(8, NamePacket(name))) { reader.End(); }
        }
    }

    private void Empty(uint operation)
    {
        using (PacketReader reader = Invoke(operation, Packet())) { reader.End(); }
    }

    private void EnsureOpen()
    {
        if (session == null || session.IsClosed) { throw new ObjectDisposedException("NativeFirewallBackend"); }
    }

    private PacketReader Invoke(uint operation, byte[] input)
    {
        EnsureOpen();
        IntPtr pointer = IntPtr.Zero;
        uint length;
        try
        {
            Throw(NativeMethods.Invoke(session, operation, input, checked((uint)input.Length), out pointer, out length),
                OperationName(operation));
            if (pointer == IntPtr.Zero || length < 4 || length > MaxPacket)
            { throw new FirewallRefusalException("Invalid native firewall packet size."); }
            byte[] bytes = new byte[checked((int)length)];
            Marshal.Copy(pointer, bytes, 0, bytes.Length);
            return new PacketReader(bytes);
        }
        finally { if (pointer != IntPtr.Zero) { NativeMethods.Free(pointer); } }
    }

    private static void Throw(int status, string operation)
    {
        if (status < 0) { throw new COMException("Native firewall " + operation + " failed.", status); }
        if (status != 0) { throw new COMException("Unexpected native firewall success status.", status); }
    }

    private static string OperationName(uint operation)
    {
        switch (operation)
        {
            case 1: return "INetFwPolicy2.CurrentProfileTypes";
            case 2: return "INetFwPolicy2.LocalPolicyModifyState";
            case 3: return "profile read";
            case 4: return "rule enumeration/readback";
            case 5: return "detached rule preparation/readback";
            case 6: return "detached rule discard";
            case 7: return "INetFwRules::Add";
            case 8: return "INetFwRules::Remove";
            default: return "unknown operation " + operation;
        }
    }

    private static void ValidateName(string name)
    {
        if (string.IsNullOrEmpty(name) || name.Length > MaxString || name.IndexOf('\0') >= 0)
        { throw new ArgumentException("A nonempty, bounded firewall name without NULs is required.", "name"); }
    }

    private static byte[] Packet() { return BitConverter.GetBytes(Magic); }

    private static byte[] NamePacket(string name)
    {
        using (MemoryStream stream = new MemoryStream())
        using (BinaryWriter writer = new BinaryWriter(stream))
        {
            writer.Write(Magic);
            WriteString(writer, name);
            return stream.ToArray();
        }
    }

    private static void WriteString(BinaryWriter writer, string text)
    {
        if (text == null) { writer.Write(-1); return; }
        if (text.Length > MaxString || text.IndexOf('\0') >= 0)
        { throw new ArgumentException("Firewall strings must be bounded and contain no NULs."); }
        writer.Write(text.Length);
        // Write UTF-16 code units, not an encoder that silently substitutes lone surrogates.
        foreach (char value in text) { writer.Write((ushort)value); }
        if (writer.BaseStream.Position > MaxPacket) { throw new ArgumentException("Firewall packet is too large."); }
    }

    private static byte[] RulePacket(FirewallRuleData rule)
    {
        using (MemoryStream stream = new MemoryStream())
        using (BinaryWriter writer = new BinaryWriter(stream))
        {
            writer.Write(Magic);
            foreach (string text in new string[] { rule.Name, rule.Grouping, rule.Description,
                rule.ApplicationName, rule.ServiceName, rule.LocalAddresses, rule.RemoteAddresses,
                rule.LocalPorts, rule.RemotePorts, rule.InterfaceTypes, rule.LocalAppPackageId,
                rule.LocalUserOwner, rule.LocalUserAuthorizedList, rule.RemoteUserAuthorizedList,
                rule.RemoteMachineAuthorizedList })
            { WriteString(writer, text); }
            if (rule.Interfaces == null || rule.Interfaces.Length > MaxCount)
            { throw new ArgumentException("Expected a bounded firewall interface list."); }
            writer.Write(rule.Interfaces.Length);
            foreach (string value in rule.Interfaces) { WriteString(writer, value); }
            writer.Write(rule.Protocol); writer.Write(rule.Direction); writer.Write(rule.Action);
            writer.Write(rule.Profiles); writer.Write(rule.EdgeTraversalOptions); writer.Write(rule.SecureFlags);
            writer.Write(rule.Enabled ? 1 : 0); writer.Write(rule.EdgeTraversal ? 1 : 0);
            if (stream.Length > MaxPacket) { throw new ArgumentException("Firewall packet is too large."); }
            return stream.ToArray();
        }
    }

    private sealed class PacketReader : IDisposable
    {
        private readonly MemoryStream stream;
        private readonly BinaryReader reader;
        internal PacketReader(byte[] bytes)
        {
            stream = new MemoryStream(bytes, false);
            reader = new BinaryReader(stream);
            if (unchecked((uint)Int()) != Magic) { Dispose(); throw new FirewallRefusalException("Unknown firewall packet version."); }
        }
        internal int Int()
        {
            if (stream.Length - stream.Position < 4) { throw new FirewallRefusalException("Truncated firewall integer."); }
            return reader.ReadInt32();
        }
        internal int Count()
        {
            int count = Int();
            if (count < 0 || count > MaxCount) { throw new FirewallRefusalException("Invalid firewall collection count."); }
            return count;
        }
        internal bool Boolean()
        {
            int value = Int();
            if (value != 0 && value != 1) { throw new FirewallRefusalException("Invalid firewall Boolean."); }
            return value == 1;
        }
        internal string String()
        {
            int length = Int();
            if (length == -1) { return null; }
            if (length < 0 || length > MaxString || length > (stream.Length - stream.Position) / 2)
            { throw new FirewallRefusalException("Invalid firewall string length."); }
            char[] text = new char[length];
            for (int i = 0; i < length; ++i) { text[i] = (char)reader.ReadUInt16(); }
            return new string(text);
        }
        internal string[] Strings()
        {
            string[] result = new string[Count()];
            for (int i = 0; i < result.Length; ++i) { result[i] = String(); }
            return result;
        }
        internal FirewallRuleData Rule()
        {
            return new FirewallRuleData
            {
                Name = String(), Grouping = String(), Description = String(),
                ApplicationName = String(), ServiceName = String(), LocalAddresses = String(),
                RemoteAddresses = String(), LocalPorts = String(), RemotePorts = String(),
                InterfaceTypes = String(), LocalAppPackageId = String(), LocalUserOwner = String(),
                LocalUserAuthorizedList = String(), RemoteUserAuthorizedList = String(),
                RemoteMachineAuthorizedList = String(), Interfaces = Strings(),
                Protocol = Int(), Direction = Int(), Action = Int(), Profiles = Int(),
                EdgeTraversalOptions = Int(), SecureFlags = Int(), Enabled = Boolean(), EdgeTraversal = Boolean()
            };
        }
        internal void End()
        {
            if (stream.Position != stream.Length) { throw new FirewallRefusalException("Trailing native firewall data."); }
        }
        public void Dispose() { reader.Dispose(); stream.Dispose(); }
    }

    private sealed class SessionHandle : SafeHandleZeroOrMinusOneIsInvalid
    {
        internal SessionHandle(IntPtr value) : base(true) { SetHandle(value); }
        protected override bool ReleaseHandle() { return NativeMethods.Close(handle) == 0; }
    }

    private static class NativeMethods
    {
        private const string Library = "WinTraceForge.Native.dll";
        private const DllImportSearchPath Search = DllImportSearchPath.AssemblyDirectory | DllImportSearchPath.System32;
        [DllImport(Library, EntryPoint = "FirewallNativeOpen", CallingConvention = CallingConvention.Cdecl, ExactSpelling = true)]
        [DefaultDllImportSearchPaths(Search)]
        internal static extern int Open(out IntPtr handle);
        [DllImport(Library, EntryPoint = "FirewallNativeInvoke", CallingConvention = CallingConvention.Cdecl, ExactSpelling = true)]
        [DefaultDllImportSearchPaths(Search)]
        internal static extern int Invoke(SessionHandle handle, uint operation,
            [In] byte[] input, uint inputLength, out IntPtr output, out uint outputLength);
        [DllImport(Library, EntryPoint = "FirewallNativeClose", CallingConvention = CallingConvention.Cdecl, ExactSpelling = true)]
        [DefaultDllImportSearchPaths(Search)]
        internal static extern int Close(IntPtr handle);
        [DllImport(Library, EntryPoint = "FirewallNativeFree", CallingConvention = CallingConvention.Cdecl, ExactSpelling = true)]
        [DefaultDllImportSearchPaths(Search)]
        internal static extern void Free(IntPtr pointer);
    }

    public void Dispose()
    {
        lock (gate)
        {
            if (session != null) { session.Dispose(); session = null; }
            prepared = false;
        }
    }
}
