// This Source Code Form is subject to the terms of the
// Mozilla Public License, v. 2.0.
// If a copy of the MPL was not distributed with this file, You can obtain one at https://mozilla.org/MPL/2.0/.

using System;

internal static class WinTraceForge
{
    private static int Main(string[] args)
    {
        if (args.Length == 0 || IsRootHelp(args))
        {
            bool noColor = Array.Exists(args, delegate(string value)
                { return string.Equals(value, "--no-color", StringComparison.OrdinalIgnoreCase); });
            bool verbose = Array.Exists(args, delegate(string value)
                { return string.Equals(value, "--verbose", StringComparison.OrdinalIgnoreCase); });
            ConsoleUi.Configure(verbose, noColor);
            ConsoleUi.Banner();
            PrintHelp();
            return 0;
        }
        if (args.Length >= 2 && Same(args[0], "defender") && Same(args[1], "exclusion"))
        {
            return DefenderModule.Main(Slice(args, 2));
        }
        if (Same(args[0], "firewall")) { return FirewallModule.Main(Slice(args, 1)); }
        if (args.Length == 2 && Same(args[0], "defender") && Same(args[1], "--help"))
        {
            return DefenderModule.Main(new[] { "--help" });
        }
        ConsoleUi.Status("FAIL", "Unknown command. Use 'defender exclusion', 'firewall rule', or 'firewall profiles'.", true);
        ConsoleUi.Text("Run wtf.exe --help. No control operation was performed.");
        return 2;
    }

    private static bool Same(string left, string right)
    {
        return string.Equals(left, right, StringComparison.OrdinalIgnoreCase);
    }

    private static bool IsRootHelp(string[] args)
    {
        bool help = false;
        foreach (string argument in args)
        {
            if (Same(argument, "--help") || Same(argument, "-help") || argument == "-?") { help = true; }
            else if (!Same(argument, "--no-color") && !Same(argument, "--verbose")) { return false; }
        }
        return help;
    }

    private static string[] Slice(string[] args, int count)
    {
        var result = new string[args.Length - count];
        Array.Copy(args, count, result, 0, result.Length);
        return result;
    }

    private static void PrintHelp()
    {
        ConsoleUi.Section("Control modules");
        ConsoleUi.Row("defender exclusion", "Add/check Defender antivirus exclusions.");
        ConsoleUi.Row("firewall rule add", "Create a marked, narrowly scoped test rule; refuse existing names.");
        ConsoleUi.Row("firewall rule check", "Read a marked rule by its test ID.");
        ConsoleUi.Row("firewall rule remove", "Remove only a unique, correctly marked test rule.");
        ConsoleUi.Row("firewall profiles", "Read profile state and policy settings; never change them.");
        ConsoleUi.Section("Examples");
        ConsoleUi.Text("wtf.exe defender exclusion --help");
        ConsoleUi.Text("wtf.exe firewall rule --help");
        ConsoleUi.Text("wtf.exe firewall profiles");
        ConsoleUi.Section("Shared evidence");
        ConsoleUi.Row("--telemetry", "none | eventlog | etw  (provider selection follows the module)");
        ConsoleUi.Row("--telemetry-wait", "0..30 seconds  (default: 3)");
        ConsoleUi.Row("--verbose", "Expand diagnostics and Detection & Response guidance.");
        ConsoleUi.Row("--no-color", "Plain text; redirected output is always color-free.");
        ConsoleUi.Section("Boundaries");
        ConsoleUi.Text("Firewall uses INetFwPolicy2 / INetFwRule COM rule management, not WFP filters or callouts.");
        ConsoleUi.Text("No Firewall Off, no profile mutation, no automatic deletion of business rules.");
        ConsoleUi.Text("Configuration readback is not proof of packet blocking/allowing or EDR detection.");
        ConsoleUi.Text("Legacy exclusion arguments now belong after 'defender exclusion'.");
        if (ConsoleUi.Verbose)
        {
            ConsoleUi.Section("Operational notes");
            ConsoleUi.Text("WinTraceForge.Native.dll is required for raw ETW and both modules' native transports.");
            ConsoleUi.Text("Eventlog reads existing channels. ETW creates a bounded session and retains ETL evidence.");
            ConsoleUi.Text("Module-specific --help describes permissions, defaults, exit codes and cleanup.");
            ConsoleUi.Text("Ownership markers prevent accidental cleanup of foreign rules; they are not an authorization boundary.");
        }
    }
}
