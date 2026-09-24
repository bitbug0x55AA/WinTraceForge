// This Source Code Form is subject to the terms of the
// Mozilla Public License, v. 2.0.
// If a copy of the MPL was not distributed with this file, You can obtain one at https://mozilla.org/MPL/2.0/.

using System;
using System.Collections.Generic;
using System.IO;

internal static class ConsoleUi
{
    internal static bool Verbose { get; private set; }
    internal static int Width = 100;
    private static bool useColor;

    internal static void Configure(bool verbose, bool noColor)
    {
        Verbose = verbose;
        useColor = !noColor && Environment.GetEnvironmentVariable("NO_COLOR") == null &&
            !string.Equals(Environment.GetEnvironmentVariable("TERM"), "dumb", StringComparison.OrdinalIgnoreCase);
        Width = Console.IsOutputRedirected ? 100 : Math.Max(40, Math.Min(110, Console.WindowWidth - 1));
    }

    internal static void Banner()
    {
        Console.WriteLine();
        Write("WTF // WINTRACEFORGE", "  ", "  ", ConsoleColor.Cyan, false);
        Write("Same change. Different paths. Interesting silence.", "  ", "  ", ConsoleColor.Gray, false);
    }

    internal static void Section(string title)
    {
        Console.WriteLine();
        string label = "  " + title.ToUpperInvariant() + " ";
        Write(label + new string('-', Math.Max(0, Width - label.Length - 2)),
            "", "", ConsoleColor.Cyan, false);
    }

    internal static void Row(string label, string value)
    {
        string prefix = "  " + label.PadRight(20) + "  ";
        Write(value, prefix, new string(' ', prefix.Length), ConsoleColor.Gray, false);
    }

    internal static void Text(string text)
    {
        Write(text, "  ", "  ", ConsoleColor.Gray, false);
    }

    internal static void Detail(string text)
    {
        if (Verbose) { Text(text); }
    }

    internal static void HelpOptions()
    {
        Row("--telemetry", "none|eventlog|etw  (default: none)");
        Row("--telemetry-wait", "0..30 seconds for log publication / ETW tail  (default: 3)");
        Row("--verbose", "Full diagnostics and Detection & Response guidance.");
        Row("--no-color", "Plain text; also automatic when output is redirected.");
        Row("--help", "This help. Add --verbose for extended notes.");
    }

    internal static void HelpTelemetry()
    {
        Text("Append --telemetry eventlog to collect evidence; --verbose for full detail.");
        Text("Use --telemetry etw for raw ETW capture + ETL + TDH decoding (ETW permissions required).");
    }

    internal static void HelpExitCodes()
    {
        Text("Exit codes: 0 confirmed/read-only/help | 1 error/refusal | 2 usage | 3 unconfirmed | 4 ETW setup.");
    }

    internal static void Status(string tag, string text, bool error = false)
    {
        ConsoleColor color = tag == "OK" ? ConsoleColor.Green :
            tag == "WARN" ? ConsoleColor.Yellow : tag == "FAIL" ? ConsoleColor.Red : ConsoleColor.Gray;
        string prefix = "  [" + tag.PadLeft((4 + tag.Length) / 2).PadRight(4) + "] ";
        Write(text, prefix, new string(' ', prefix.Length), color, error);
    }

    private static void Write(string text, string firstPrefix, string continuationPrefix,
        ConsoleColor color, bool error)
    {
        TextWriter writer = error ? Console.Error : Console.Out;
        bool colored = useColor && !(error ? Console.IsErrorRedirected : Console.IsOutputRedirected);
        ConsoleColor original = colored ? Console.ForegroundColor : ConsoleColor.Gray;
        try
        {
            if (colored) { Console.ForegroundColor = color; }
            foreach (string line in Wrap(text, firstPrefix, continuationPrefix, Width))
            {
                writer.WriteLine(line);
            }
        }
        finally
        {
            if (colored) { Console.ForegroundColor = original; }
        }
    }

    internal static IEnumerable<string> Wrap(string text, string firstPrefix, string continuationPrefix, int width)
    {
        string remaining = (text ?? "").Replace('\r', ' ').Replace('\n', ' ').Replace('\t', ' ');
        string prefix = firstPrefix;
        do
        {
            int available = Math.Max(1, width - prefix.Length);
            if (remaining.Length <= available)
            {
                yield return prefix + remaining;
                yield break;
            }
            int cut = remaining.LastIndexOf(' ', available - 1, available);
            bool wordBoundary = cut > 0;
            if (!wordBoundary)
            {
                cut = available;
                if (cut > 1 && char.IsHighSurrogate(remaining[cut - 1])) { cut--; }
            }
            yield return prefix + remaining.Substring(0, cut);
            remaining = remaining.Substring(cut + (wordBoundary ? 1 : 0));
            prefix = continuationPrefix;
        } while (true);
    }
}
