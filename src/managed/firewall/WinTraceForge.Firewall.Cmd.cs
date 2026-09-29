// This Source Code Form is subject to the terms of the
// Mozilla Public License, v. 2.0.
// If a copy of the MPL was not distributed with this file, You can obtain one at https://mozilla.org/MPL/2.0/.

using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Diagnostics;
using System.Globalization;
using System.IO;
using System.Text;
using System.Threading.Tasks;

// Shells to cmd.exe and drives netsh.exe's "advfirewall firewall"/"advfirewall" context, instead of
// talking to WMI, netfw COM or a PowerShell cmdlet like the other four transports. netsh is the last
// of the classic, decades-old text-oriented Windows Firewall surfaces still shipped; it is included
// here purely for telemetry-comparison purposes (cmd.exe -> netsh.exe is a distinct process lineage
// and command-line shape from every other transport in this tool), not because it offers better
// fidelity -- it does not. Two real, load-bearing limits of netsh itself (verified against Microsoft's
// documented "add rule" parameter list and against this transport's own live output, not assumed):
//   - "netsh advfirewall firewall add rule" has no group=/grouping= parameter at all, so a rule this
//     transport creates can never carry this tool's Grouping ownership marker. See
//     FirewallModule.ExpectedGrouping and RequireOwnedUnique: for --transport cmd, ownership rests on
//     Name+Description alone; the other four transports will refuse a cmd-created rule as a Grouping
//     mismatch (working as intended, not a bug -- see docs\user\firewall.md).
//   - Readback comes from parsing the fixed-column text of "netsh advfirewall firewall show rule ...
//     verbose" and "netsh advfirewall show allprofiles/currentprofile", not a typed API. This is
//     inherently more fragile than the other transports (locale- and Windows-version-sensitive label
//     text) and refuses outright (FirewallRefusalException/FirewallReadbackUnsupportedException) on
//     any unrecognized label or value rather than guessing -- the same fail-loud posture
//     ManagementFirewallBackend already applies to its own WMI readback. ExcludedInterfaces is always
//     reported as "not available (cmd)": netsh exposes no such field via any show command.
// Hardening mirrors DefenderModule.PowerShellRunner's rationale: cmd.exe and netsh.exe are launched by
// absolute System32 path (never a bare name subject to PATH/CreateProcess search-order hijack), and
// /D disables AutoRun (the HKLM/HKCU "Command Processor\AutoRun" registry value cmd.exe would
// otherwise execute on every invocation) -- the cmd.exe analogue of -NoProfile/-ExecutionPolicy
// Bypass. /S is the documented modifier that makes cmd.exe strip only the single outer quote pair
// wrapping the whole netsh invocation, leaving the inner name="..."/program="..." quoting netsh's own
// argument parser expects untouched (the same nested-quoting pattern Build.ps1's own
// Invoke-VcCommand already uses to shell out through $env:ComSpec /d /s /c). Every value embedded in
// that command line is additionally checked by RequireSafeForCmd to contain no '"', no control
// character and no '%' (cmd.exe environment-variable expansion is active even inside a quoted region)
// before it is ever concatenated into the command text -- defense in depth on top of the CLI's own
// --program validation (FirewallModule.ParseProgram already forbids '"', '%', '*', '?').
internal sealed class CmdFirewallBackend : IFirewallBackend
{
    private static readonly string CmdExecutablePath = Path.Combine(Environment.SystemDirectory, "cmd.exe");
    private static readonly string NetshExecutablePath = Path.Combine(Environment.SystemDirectory, "netsh.exe");
    private const string NotFoundMessage = "No rules match the specified criteria.";
    private string pendingAddCommand;

    internal CmdFirewallBackend()
    {
        Result probe = RunNetsh("advfirewall show currentprofile");
        if (probe.ExitCode != 0 || !ContainsOkTrailer(probe.Stdout))
        {
            throw new NotSupportedException("netsh.exe advfirewall is unavailable. " + DescribeFailure(probe));
        }
    }

    public int CurrentProfiles
    {
        get
        {
            Result result = RunNetsh("advfirewall show currentprofile");
            if (result.ExitCode != 0 || !ContainsOkTrailer(result.Stdout))
            { throw new InvalidOperationException("netsh advfirewall show currentprofile failed: " + DescribeFailure(result)); }
            int mask = 0;
            if (result.Stdout.IndexOf("Domain Profile Settings", StringComparison.Ordinal) >= 0) { mask |= 1; }
            if (result.Stdout.IndexOf("Private Profile Settings", StringComparison.Ordinal) >= 0) { mask |= 2; }
            if (result.Stdout.IndexOf("Public Profile Settings", StringComparison.Ordinal) >= 0) { mask |= 4; }
            return mask;
        }
    }

    // A plain registry read (the same WindowsFirewall GPO keys ManagementFirewallBackend reads), not
    // a netsh property -- reused directly rather than parsed out of any netsh output.
    public int LocalPolicyModifyState { get { return FirewallGroupPolicy.ReadLocalPolicyModifyState(CurrentProfiles); } }

    // Confirmed live (this transport's own "netsh advfirewall show store" reports "Policy Store:
    // Local" by default, with no netsh command found to select an ActiveStore/GPO-merged equivalent):
    // unlike com/native (INetFwPolicy2 always effective) and management/powershell (both explicitly
    // request PolicyStore=ActiveStore), this reads the Local store only. On a GPO-managed host, the
    // returned Enabled/BlockAllInbound/DefaultInboundAction/DefaultOutboundAction values can therefore
    // differ from what the other four transports report for the identical live policy -- the same
    // failure mode ManagementFirewallBackend's own ActiveStore fix was written to avoid, but with no
    // netsh-level fix available here. This affects only the read-only `firewall profiles` command; it
    // does not affect add/check/remove (CurrentProfiles, used to freeze a new rule's profile mask,
    // reflects live network-category membership, not a GPO-overridable setting, and is unaffected).
    // See docs\user\firewall.md.
    public IList<FirewallProfileData> ReadProfiles()
    {
        Result result = RunNetsh("advfirewall show allprofiles");
        if (result.ExitCode != 0 || !ContainsOkTrailer(result.Stdout))
        { throw new InvalidOperationException("netsh advfirewall show allprofiles failed: " + DescribeFailure(result)); }

        Dictionary<string, FirewallProfileData> byName = new Dictionary<string, FirewallProfileData>(StringComparer.Ordinal);
        string currentHeader = null;
        foreach (string rawLine in SplitLines(result.Stdout))
        {
            string line = rawLine.TrimEnd();
            foreach (string headerName in new[] { "Domain", "Private", "Public" })
            {
                if (line.StartsWith(headerName + " Profile Settings", StringComparison.Ordinal)) { currentHeader = headerName; }
            }
            if (currentHeader == null) { continue; }
            if (line.StartsWith("State", StringComparison.Ordinal))
            {
                string value = line.Substring("State".Length).Trim();
                GetOrAdd(byName, currentHeader).Enabled = ParseOnOff(value);
            }
            else if (line.StartsWith("Firewall Policy", StringComparison.Ordinal))
            {
                string value = line.Substring("Firewall Policy".Length).Trim();
                string[] tokens = value.Split(',');
                if (tokens.Length != 2) { throw new FirewallRefusalException("Malformed netsh Firewall Policy readback: " + value); }
                FirewallProfileData profile = GetOrAdd(byName, currentHeader);
                if (string.Equals(tokens[0], "BlockInboundAlways", StringComparison.Ordinal))
                { profile.DefaultInboundAction = 0; profile.BlockAllInbound = true; }
                else if (string.Equals(tokens[0], "BlockInbound", StringComparison.Ordinal))
                { profile.DefaultInboundAction = 0; profile.BlockAllInbound = false; }
                else if (string.Equals(tokens[0], "AllowInbound", StringComparison.Ordinal))
                { profile.DefaultInboundAction = 1; profile.BlockAllInbound = false; }
                else { throw new FirewallRefusalException("Unrecognized netsh inbound firewall policy: " + tokens[0]); }
                if (string.Equals(tokens[1], "AllowOutbound", StringComparison.Ordinal)) { profile.DefaultOutboundAction = 1; }
                else if (string.Equals(tokens[1], "BlockOutbound", StringComparison.Ordinal)) { profile.DefaultOutboundAction = 0; }
                else { throw new FirewallRefusalException("Unrecognized netsh outbound firewall policy: " + tokens[1]); }
            }
        }
        List<FirewallProfileData> profiles = new List<FirewallProfileData>();
        foreach (KeyValuePair<string, int> entry in new[]
        {
            new KeyValuePair<string, int>("Domain", 1), new KeyValuePair<string, int>("Private", 2), new KeyValuePair<string, int>("Public", 4)
        })
        {
            FirewallProfileData profile;
            if (!byName.TryGetValue(entry.Key, out profile))
            { throw new FirewallRefusalException("Missing firewall profile in netsh readback: " + entry.Key); }
            profile.Profile = entry.Value;
            // netsh exposes no equivalent of DisabledInterfaceAliases via any show command; report
            // this plainly as unobserved rather than as an empty array indistinguishable from "really
            // none excluded" (ReadProfiles is purely diagnostic display, never compared against an
            // expected value, so this sentinel cannot affect ownership/verification correctness).
            profile.ExcludedInterfaces = new[] { "not available (cmd)" };
            profiles.Add(profile);
        }
        return profiles;
    }

    private static FirewallProfileData GetOrAdd(Dictionary<string, FirewallProfileData> byName, string header)
    {
        FirewallProfileData profile;
        if (!byName.TryGetValue(header, out profile)) { profile = new FirewallProfileData(); byName[header] = profile; }
        return profile;
    }

    private static bool ParseOnOff(string value)
    {
        if (string.Equals(value, "ON", StringComparison.Ordinal)) { return true; }
        if (string.Equals(value, "OFF", StringComparison.Ordinal)) { return false; }
        throw new FirewallRefusalException("Unrecognized netsh firewall profile State: " + value);
    }

    // name is matched by netsh against a rule's ElementName -- confirmed live that this also matches
    // (and, on a hit, returns the fully resolved "Rule Name:"/"Grouping:" text for) a built-in rule
    // whose raw WMI ElementName is an unresolved MUI reference (e.g. "@FirewallAPI.dll,-32765" both
    // matches and displays as "Network Discovery (UPnP-Out)"). Also confirmed live that a Program path
    // stored with an environment-variable macro (e.g. "%SystemRoot%\system32\svchost.exe") is shown
    // already expanded to an absolute path. Neither affects this tool's own rules (their Name is
    // always a literal WinTraceForge.Firewall.<guid> string with no MUI indirection, and --program is
    // already required to be an absolute, already-resolved path with no '%'), but both are genuine
    // fidelity differences from com/native/management/powershell when reading a third-party rule
    // through this transport specifically.
    public IList<FirewallRuleData> FindByName(string name)
    {
        RequireSafeForCmd(name, "rule name");
        Result result = RunNetsh("advfirewall firewall show rule name=\"" + name + "\" verbose");
        if (result.ExitCode != 0)
        {
            if (result.Stdout.Trim() == NotFoundMessage) { return new List<FirewallRuleData>(); }
            throw new InvalidOperationException("netsh advfirewall firewall show rule failed: " + DescribeFailure(result));
        }
        if (!ContainsOkTrailer(result.Stdout))
        { throw new InvalidOperationException("netsh advfirewall firewall show rule did not end with 'Ok.': " + DescribeFailure(result)); }

        List<FirewallRuleData> rules = new List<FirewallRuleData>();
        foreach (Dictionary<string, string> block in ParseShowRuleBlocks(result.Stdout)) { rules.Add(DecodeShowRuleBlock(block)); }
        return rules;
    }

    // Every label DecodeShowRuleBlock either reads (via Require/ContainsKey) or deliberately ignores.
    // "Rule source" is real, observed output (see the DNS/ChatGPT captures this transport was verified
    // against) that this tool has no corresponding FirewallRuleData field for and does not need; it is
    // the one label allowed through unread. Anything else appearing here means either a Windows/locale
    // version this transport was never verified against, or a rule shape it cannot faithfully
    // represent -- both cases must refuse rather than silently ignore a field that could be hiding a
    // real restriction (the same fail-loud posture as an unrecognized value for a field it does read).
    private static readonly HashSet<string> KnownRuleLabels = new HashSet<string>(StringComparer.Ordinal)
    {
        "Rule Name", "Description", "Enabled", "Direction", "Profiles", "Grouping", "LocalIP", "RemoteIP",
        "Protocol", "LocalPort", "RemotePort", "Edge traversal", "Program", "Service", "InterfaceTypes",
        "Security", "Action", "Rule source"
    };

    private static List<Dictionary<string, string>> ParseShowRuleBlocks(string stdout)
    {
        List<Dictionary<string, string>> blocks = new List<Dictionary<string, string>>();
        Dictionary<string, string> current = null;
        foreach (string rawLine in SplitLines(stdout))
        {
            string line = rawLine.TrimEnd();
            if (line.Length == 0 || IsDashLine(line) || line.Trim() == "Ok.") { continue; }
            int colon = line.IndexOf(':');
            if (colon < 0) { continue; }
            string label = line.Substring(0, colon).Trim();
            string value = line.Substring(colon + 1).Trim();
            if (label == "Rule Name")
            {
                if (current != null) { blocks.Add(current); }
                current = new Dictionary<string, string>(StringComparer.Ordinal);
            }
            if (current == null) { continue; }
            if (!KnownRuleLabels.Contains(label))
            { throw new FirewallReadbackUnsupportedException("Unrecognized netsh readback field on a cmd-transport rule: " + label); }
            if (current.ContainsKey(label))
            { throw new InvalidOperationException("Duplicate netsh readback field in one rule block: " + label); }
            current[label] = value;
        }
        if (current != null) { blocks.Add(current); }
        return blocks;
    }

    private static bool IsDashLine(string line)
    {
        string trimmed = line.Trim();
        if (trimmed.Length == 0) { return false; }
        foreach (char c in trimmed) { if (c != '-') { return false; } }
        return true;
    }

    private static FirewallRuleData DecodeShowRuleBlock(Dictionary<string, string> block)
    {
        FirewallRuleData result = new FirewallRuleData
        {
            Name = Require(block, "Rule Name"),
            Grouping = Require(block, "Grouping"),
            Description = Require(block, "Description"),
            Enabled = ParseYesNo(Require(block, "Enabled"), "Enabled"),
            Direction = ParseDirection(Require(block, "Direction")),
            Profiles = ParseProfileList(Require(block, "Profiles")),
            Protocol = ManagementFirewallBackend.ProtocolNumber(Require(block, "Protocol")),
            Action = ParseAction(Require(block, "Action")),
            ApplicationName = block.ContainsKey("Program") ? block["Program"] : "",
            ServiceName = block.ContainsKey("Service") ? block["Service"] : "",
            Interfaces = new string[0],
            // netsh's "show rule ... verbose" text has no equivalent of PackageFamilyName/Owner/
            // LocalUser/RemoteUser/RemoteMachine at all -- not merely an "Any" sentinel for these,
            // unlike LocalIP/RemoteIP/Program/Service. These are hard-coded to "" (matching this
            // tool's own rules, which never request such a restriction) rather than actually observed:
            // a foreign rule that DOES carry one of these restrictions would incorrectly read back as
            // unrestricted through this transport specifically. This is a genuine, structural netsh
            // limitation (there is no text field to parse), not a parsing gap; management and
            // powershell both actually read these values from the real MSFT_NetNetworkLayerSecurityFilter/
            // MSFT_NetFirewallRule properties. See docs\user\firewall.md.
            LocalAppPackageId = "", LocalUserOwner = "",
            LocalUserAuthorizedList = "", RemoteUserAuthorizedList = "", RemoteMachineAuthorizedList = "",
            SecureFlags = 0
        };

        string localIp = Require(block, "LocalIP");
        if (localIp != "Any")
        { throw new FirewallReadbackUnsupportedException("Unsupported LocalIP restriction on a cmd-transport rule readback: " + localIp); }
        result.LocalAddresses = "*";
        string remoteIp = Require(block, "RemoteIP");
        // A comma-separated list here (confirmed live, e.g. "127.0.0.0/8,::/127") is netsh's rendering
        // of a multi-value RemoteIP scope; management/powershell both refuse a multi-value address
        // filter outright (FirstOrAny) rather than reporting the raw joined text as a single value, and
        // this transport must be no more permissive for the sake of cross-transport comparability.
        if (remoteIp.IndexOf(',') >= 0)
        { throw new FirewallReadbackUnsupportedException("Unsupported multi-value RemoteIP on a cmd-transport rule readback: " + remoteIp); }
        result.RemoteAddresses = remoteIp == "Any" ? "*" : remoteIp;

        result.LocalPorts = NetshPort(Require(block, "LocalPort"));
        result.RemotePorts = NetshPort(Require(block, "RemotePort"));

        string edge = Require(block, "Edge traversal");
        if (edge != "No")
        { throw new FirewallReadbackUnsupportedException("Unsupported Edge traversal setting on a cmd-transport rule readback: " + edge); }
        result.EdgeTraversal = false; result.EdgeTraversalOptions = 0;

        string interfaceTypes = Require(block, "InterfaceTypes");
        if (interfaceTypes != "Any")
        { throw new FirewallReadbackUnsupportedException("Unsupported InterfaceTypes restriction on a cmd-transport rule readback: " + interfaceTypes); }
        result.InterfaceTypes = "All";

        string security = Require(block, "Security");
        if (security != "NotRequired")
        { throw new FirewallReadbackUnsupportedException("Unsupported Security setting on a cmd-transport rule readback: " + security); }

        return result;
    }

    private static string NetshPort(string value) { return value == "Any" ? "*" : value; }

    private static string Require(Dictionary<string, string> block, string label)
    {
        string value;
        if (!block.TryGetValue(label, out value))
        { throw new FirewallRefusalException("Missing netsh readback field: " + label); }
        return value;
    }

    private static bool ParseYesNo(string value, string field)
    {
        if (value == "Yes") { return true; }
        if (value == "No") { return false; }
        throw new FirewallRefusalException("Unrecognized netsh " + field + " value: " + value);
    }

    private static int ParseDirection(string value)
    {
        if (value == "In") { return 1; }
        if (value == "Out") { return 2; }
        throw new FirewallRefusalException("Unrecognized netsh Direction value: " + value);
    }

    private static int ParseAction(string value)
    {
        if (value == "Allow") { return 1; }
        if (value == "Block") { return 0; }
        throw new FirewallReadbackUnsupportedException("Unsupported netsh Action value on rule readback: " + value);
    }

    private static int ParseProfileList(string value)
    {
        int mask = 0;
        foreach (string token in value.Split(','))
        {
            string name = token.Trim();
            int bit;
            if (string.Equals(name, "Domain", StringComparison.Ordinal)) { bit = 1; }
            else if (string.Equals(name, "Private", StringComparison.Ordinal)) { bit = 2; }
            else if (string.Equals(name, "Public", StringComparison.Ordinal)) { bit = 4; }
            else { throw new FirewallRefusalException("Unrecognized netsh Profiles token: " + name); }
            if ((mask & bit) != 0) { throw new FirewallRefusalException("Duplicate netsh Profiles token: " + name); }
            mask |= bit;
        }
        if (mask == 0) { throw new FirewallRefusalException("Empty netsh Profiles readback."); }
        return mask;
    }

    public void PrepareAdd(FirewallRuleData rule)
    {
        if (rule == null) { throw new ArgumentNullException("rule"); }
        if (rule.Interfaces == null || rule.Interfaces.Length != 0)
        { throw new FirewallRefusalException("Detached firewall rules must have no interface restrictions."); }
        if (pendingAddCommand != null) { throw new FirewallRefusalException("A detached rule is already prepared."); }
        pendingAddCommand = BuildAddCommand(rule);
    }

    private static string BuildAddCommand(FirewallRuleData rule)
    {
        RequireSafeForCmd(rule.Name, "rule name");
        RequireSafeForCmd(rule.Description, "description");
        RequireSafeForCmd(rule.RemoteAddresses, "remote address");
        if (rule.ApplicationName.Length != 0) { RequireSafeForCmd(rule.ApplicationName, "program path"); }

        StringBuilder command = new StringBuilder("advfirewall firewall add rule");
        command.Append(" name=\"" + rule.Name + "\"");
        command.Append(" description=\"" + rule.Description + "\"");
        command.Append(" dir=" + (rule.Direction == 1 ? "in" : "out"));
        command.Append(" action=" + (rule.Action == 1 ? "allow" : "block"));
        command.Append(" protocol=" + ManagementFirewallBackend.ProtocolName(rule.Protocol));
        command.Append(" remoteip=" + rule.RemoteAddresses);
        command.Append(" localport=" + (rule.LocalPorts == "*" ? "any" : rule.LocalPorts));
        command.Append(" remoteport=" + (rule.RemotePorts == "*" ? "any" : rule.RemotePorts));
        // "add rule ?"'s documented program= syntax is [program=<Application Path and File Name>];
        // unlike localport=/remoteport=, it never documents "any" as an accepted keyword (only
        // service= does). Omit the parameter entirely for "all programs" instead of passing the
        // literal text "any" as a path -- matching com ("Preserve unspecified defaults instead of
        // writing empty BSTR scopes") and management (Program is only added to the WMI call context
        // when set). Confirmed live: netsh's own "show rule ... verbose" omits the "Program:" line
        // entirely for an unrestricted rule, which ShowRule's parser already treats as ApplicationName="".
        if (rule.ApplicationName.Length != 0) { command.Append(" program=\"" + rule.ApplicationName + "\""); }
        command.Append(" profile=" + FirewallModule.ProfileList(rule.Profiles).ToLowerInvariant());
        command.Append(" edge=no");
        command.Append(" security=notrequired");
        command.Append(" enable=yes");
        return command.ToString();
    }

    public MutationStatus Add()
    {
        if (pendingAddCommand == null) { throw new FirewallRefusalException("No detached rule was prepared."); }
        string command = pendingAddCommand;
        pendingAddCommand = null;
        Result result = RunNetsh(command);
        if (result.ExitCode == 0 && ContainsOkTrailer(result.Stdout)) { return MutationStatus.ApiSucceeded; }
        // netsh has no equivalent of a WMI ReturnValue, and unlike the powershell transport's own
        // script (whose WTF_ADD_ERROR marker is only ever written by our own try/catch, so it
        // unambiguously means netsh's cmdlet equivalent itself rejected the request), a nonzero exit
        // or missing "Ok." trailer from this opaque external process cannot be trusted as a definite
        // rejection: cmd.exe/netsh.exe being torn down externally after the rule was already written
        // would look identical. Defer to the shared post-mutation Verify() readback instead of
        // reporting a hard failure that skips it (see FirewallOperation.VerifyAfterApiFailure).
        ConsoleUi.Status("WARN", "netsh.exe ended without a clear success marker; verifying configuration by readback.");
        ConsoleUi.Detail(DescribeFailure(result));
        return MutationStatus.ApiUnknown;
    }

    public MutationStatus Remove(string name)
    {
        RequireSafeForCmd(name, "rule name");
        // Re-checked immediately before the name-based delete, mirroring management's own RequireOne-
        // then-Delete() and powershell's own count-check-then-Remove-NetFirewallRule: "netsh ...
        // delete rule name=..." has no per-object handle to target and deletes every match by name in
        // one call, so without this check it could remove more than the one rule
        // FirewallOperation.Probe's own immediate pre-remove refresh already confirmed, if a second
        // rule sharing the exact name appeared in between.
        IList<FirewallRuleData> refreshed = FindByName(name);
        if (refreshed.Count != 1)
        { throw new FirewallRefusalException("Refused: expected exactly one rule to remove, found " + refreshed.Count + "."); }
        Result result = RunNetsh("advfirewall firewall delete rule name=\"" + name + "\"");
        if (result.ExitCode == 0 && ContainsOkTrailer(result.Stdout)) { return MutationStatus.ApiSucceeded; }
        ConsoleUi.Status("WARN", "netsh.exe ended without a clear success marker; verifying configuration by readback.");
        ConsoleUi.Detail(DescribeFailure(result));
        return MutationStatus.ApiUnknown;
    }

    public void Dispose() { }

    // Defense in depth on top of FirewallModule.ParseProgram (which already forbids '"', '%', '*',
    // '?') and ParseAddress (digits/./:/hex letters only): every value this backend ever concatenates
    // into a netsh command line passes through here first. '"' would break out of the name="..."/
    // program="..." quoting netsh's own argument parser expects; '%' triggers cmd.exe environment-
    // variable expansion even inside a quoted region; '!' would too if delayed expansion is enabled
    // (RunNetsh's own /V:OFF already disables it for this invocation regardless of the machine/user
    // registry default, but this is a second, registry-independent layer); a control character has no
    // safe representation on a single command line. Our own generated Name/Description (GUID-based;
    // see FirewallModule.NameFor/DescriptionFor) and a --remote-address literal can never trip this,
    // so it only ever fires for --program, and only as a last-resort safety net.
    private static void RequireSafeForCmd(string value, string what)
    {
        if (value == null) { return; }
        foreach (char c in value)
        {
            if (c == '"' || c == '%' || c == '!' || c < ' ')
            { throw new FirewallRefusalException("Refused: " + what + " contains a character unsafe for the cmd transport."); }
        }
    }

    private static bool ContainsOkTrailer(string stdout)
    {
        foreach (string line in SplitLines(stdout)) { if (line.Trim() == "Ok.") { return true; } }
        return false;
    }

    private static string DescribeFailure(Result result)
    {
        string text = (result.Stderr ?? "").Trim();
        if (text.Length == 0) { text = (result.Stdout ?? "").Trim(); }
        return "(exit " + result.ExitCode + ") " + text;
    }

    private static IEnumerable<string> SplitLines(string text) { return (text ?? "").Replace("\r\n", "\n").Split('\n'); }

    internal sealed class Result
    {
        internal readonly int ExitCode;
        internal readonly string Stdout;
        internal readonly string Stderr;
        internal Result(int exitCode, string stdout, string stderr) { ExitCode = exitCode; Stdout = stdout; Stderr = stderr; }
    }

    // Builds "cmd.exe /d /v:off /s /c "<netsh.exe path> <netshArguments>"": /D disables AutoRun, /S is
    // the documented modifier that makes cmd.exe strip only the single outermost quote pair around the
    // whole command, leaving netsh's own inner name="..."/program="..." quoting untouched for its own
    // argument parser -- the identical nested-quoting shape Build.ps1's Invoke-VcCommand already uses
    // for $env:ComSpec /d /s /c. /V:OFF disables delayed variable expansion for this invocation
    // regardless of the machine/user default: /D only disables AutoRun, not the separate
    // HKLM/HKCU\Software\Microsoft\Command Processor\DelayedExpansion registry value, and with that
    // value set to 1, a caret-free '!' inside an otherwise-safe quoted value (e.g. a --program path
    // like "C:\a!b!.exe") would be rewritten by cmd.exe before netsh ever saw it -- RequireSafeForCmd
    // also rejects '!' outright as a second, registry-independent layer. netshArguments is always built
    // by BuildAddCommand/FindByName/Remove above, every embedded value already checked by
    // RequireSafeForCmd; it is never raw external input.
    private static Result RunNetsh(string netshArguments)
    {
        ProcessStartInfo start = new ProcessStartInfo(CmdExecutablePath,
            "/d /v:off /s /c \"" + NetshExecutablePath + " " + netshArguments + "\"")
        {
            UseShellExecute = false,
            CreateNoWindow = true,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            // netsh (like most console apps) writes redirected output in the OEM codepage, not the
            // ANSI codepage Encoding.Default represents in .NET Framework -- on many Western Windows
            // installs these are different codepages (e.g. 1252 vs 850), which would garble a
            // non-ASCII --program path on readback (our own fixed English label text and GUID-based
            // Name/Description are pure ASCII and unaffected either way).
            StandardOutputEncoding = Encoding.GetEncoding(CultureInfo.CurrentCulture.TextInfo.OEMCodePage),
            StandardErrorEncoding = Encoding.GetEncoding(CultureInfo.CurrentCulture.TextInfo.OEMCodePage)
        };
        Process process;
        try { process = Process.Start(start); }
        catch (Win32Exception error)
        { throw new NotSupportedException("Could not start " + CmdExecutablePath + ": " + error.Message); }
        using (process)
        {
            // Reading one redirected stream fully before touching the other can deadlock once the
            // unread pipe's OS buffer fills and the child blocks writing to it; both are drained
            // concurrently instead (same reasoning as DefenderModule.PowerShellRunner.RunScript).
            Task<string> stdoutTask = process.StandardOutput.ReadToEndAsync();
            Task<string> stderrTask = process.StandardError.ReadToEndAsync();
            Task.WaitAll(stdoutTask, stderrTask);
            process.WaitForExit();
            return new Result(process.ExitCode, stdoutTask.Result, stderrTask.Result);
        }
    }
}
