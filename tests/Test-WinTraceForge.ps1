# This Source Code Form is subject to the terms of the Mozilla Public License, v. 2.0.
# If a copy of the MPL was not distributed with this file, You can obtain one at https://mozilla.org/MPL/2.0/.

param([Parameter(Mandatory = $true)][string] $Executable)

$ErrorActionPreference = 'Stop'
$passed = 0

function Test-Command {
    param([string] $Arguments, [int[]] $ExitCodes, [string[]] $Contains)
    $start = New-Object System.Diagnostics.ProcessStartInfo
    $start.FileName = $Executable
    $start.Arguments = $Arguments
    $start.UseShellExecute = $false
    $start.RedirectStandardOutput = $true
    $start.RedirectStandardError = $true
    $process = [System.Diagnostics.Process]::Start($start)
    try {
        $stdout = $process.StandardOutput.ReadToEndAsync()
        $stderr = $process.StandardError.ReadToEndAsync()
        if (-not $process.WaitForExit(60000)) {
            $process.Kill()
            throw "Command timed out: $Arguments"
        }
        $output = $stdout.GetAwaiter().GetResult() + $stderr.GetAwaiter().GetResult()
        if ($ExitCodes -notcontains $process.ExitCode) {
            throw "Unexpected exit $($process.ExitCode): $Arguments`n$output"
        }
        $normalized = $output -replace '\s+', ' '
        foreach ($text in $Contains) {
            if ($normalized.IndexOf($text, [StringComparison]::OrdinalIgnoreCase) -lt 0) {
                throw "Missing '$text': $Arguments`n$output"
            }
        }
        if ($output.Contains([string][char]27)) { throw 'Redirected output includes an ANSI escape.' }
        $script:passed++
        Write-Host "PASS [$($process.ExitCode)] $Arguments"
        return $output
    }
    finally { $process.Dispose() }
}

Test-Command '--help --no-color' 0 @('WTF // WINTRACEFORGE', 'Interesting silence.', 'defender exclusion', 'firewall rule', 'firewall profiles', 'not WFP') | Out-Null
Test-Command '' 0 @('CONTROL MODULES') | Out-Null
$defenderHelp = Test-Command 'defender exclusion --help --no-color' 0 @('ExclusionPath', 'transport')
$firewallHelp = Test-Command 'firewall rule --help --no-color' 0 @('add', 'check', 'remove', '--id')
foreach ($entry in @(
    @{ Command = 'defender exclusion'; Output = $defenderHelp; Specific = 'EXCLUSION TYPES'; Limit = 45 },
    @{ Command = 'firewall'; Output = $firewallHelp; Specific = 'COMMANDS'; Limit = 60 }
)) {
    $sections = @([regex]::Matches($entry.Output, '(?m)^  ([A-Z][A-Z /&]+) -+') |
        ForEach-Object { $_.Groups[1].Value })
    $expected = @('USAGE', 'OPTIONS', $entry.Specific, 'ROUTES', 'QUICK START', 'BEFORE YOU RUN')
    if (($sections -join '|') -ne ($expected -join '|')) { throw "Help section order mismatch: $($entry.Command)" }
    $lines = $entry.Output -split '\r?\n'
    if ($lines.Count -gt $entry.Limit) { throw "Default help exceeds $($entry.Limit) lines: $($entry.Command)" }
    foreach ($line in $lines) {
        if ($line.Length -gt 100) { throw "Help line exceeds 100 columns: $line" }
    }
    if ($entry.Output.Contains('EXTENDED NOTES') -or $entry.Output.Contains('schema=1')) {
        throw 'Extended details leaked into default help.'
    }
    $plain = Test-Command "$($entry.Command) --help" 0 @()
    if ($plain -ne $entry.Output) { throw 'Color flag changed redirected help text.' }
    $verbose = Test-Command "$($entry.Command) --help --verbose --no-color" 0 @('EXTENDED NOTES', 'ETW caps:')
    if (-not $verbose.StartsWith($entry.Output, [StringComparison]::Ordinal)) {
        throw 'Verbose help must extend, not replace, the default page.'
    }
    foreach ($line in ($verbose -split '\r?\n')) {
        if ($line.Length -gt 100) { throw "Verbose help line exceeds 100 columns: $line" }
    }
    if ($entry.Command -eq 'firewall' -and (-not $verbose.Contains('schema=1') -or
        -not $verbose.Contains("sender's source port") -or -not $verbose.Contains('Absent check returns 3'))) {
        throw 'Firewall extended help lost ownership, port or absence semantics.'
    }
}
foreach ($option in @('--telemetry', '--telemetry-wait', '--verbose', '--no-color', '--help')) {
    $pattern = '(?m)^  ' + [regex]::Escape($option) + ' +[^\r\n]+'
    $defenderRow = [regex]::Match($defenderHelp, $pattern).Value
    $firewallRow = [regex]::Match($firewallHelp, $pattern).Value
    if (-not $defenderRow -or $defenderRow -ne $firewallRow) { throw "Shared option text/layout mismatch: $option" }
    if ($defenderRow.Substring(24).StartsWith(' ')) { throw "Misaligned option description: $option" }
}
foreach ($arguments in @(
    'firewall --help --no-color', 'firewall -help --no-color', 'firewall -? --no-color',
    'firewall profiles --help --no-color', 'firewall rule add --help --no-color',
    'firewall rule check --help --no-color', 'firewall rule remove --help --no-color'
)) {
    $aliasHelp = Test-Command $arguments 0 @('USAGE', 'OPTIONS', 'QUICK START')
    if ($aliasHelp -ne $firewallHelp) { throw "Firewall help entrypoint mismatch: $arguments" }
}
Test-Command 'firewall profiles --no-color' 0 @('Domain', 'Private', 'Public') | Out-Null
Test-Command 'firewall profiles --verbose --no-color' 0 @(
    'FIREWALL_PROFILES_READ', 'FIREWALL DETECTION & RESPONSE', '4946/4947/4948',
    'Compliance: NOT_ASSESSED', 'Detection/response: NOT_MEASURED'
) | Out-Null
$evidenceOutput = Test-Command 'firewall profiles --telemetry eventlog --telemetry-wait 0 --no-color' 0 @(
    'Microsoft-Windows-Windows Firewall With Advanced Security/Firewall',
    'Collection completeness:', 'No matching evidence is NOT proof'
)
if ($evidenceOutput.IndexOf('TELEMETRY EVIDENCE') -gt $evidenceOutput.IndexOf('ASSESSMENT')) {
    throw 'Telemetry must precede final assessment.'
}
if ($evidenceOutput.Contains('Channel: Microsoft-Windows-Windows Defender/Operational') -or
    $evidenceOutput.Contains('Channel: Microsoft-Windows-WMI-Activity/Operational')) {
    throw 'Firewall telemetry queried a Defender-only channel.'
}
$id = [guid]::NewGuid().ToString('D')
Test-Command "firewall rule check --id $id --no-color" 3 @($id, 'BASELINE', 'FIREWALL_RULE_UNCONFIRMED', 'Mutation attempted False') | Out-Null
Test-Command '--transport native --check' 2 @('Unknown command', 'No control operation') | Out-Null
foreach ($command in @(
    'firewall off',
    'firewall rule remove',
    'firewall rule check --id not-a-guid',
    'firewall profiles --action block',
    'firewall rule add --remote-address 192.0.2.10 --remote-port 0',
    'firewall rule add --remote-address any --remote-port 443',
    'firewall rule add --remote-address 192.0.2.10 --remote-port 443 --action invalid',
    'firewall rule add --direction in --remote-address 192.0.2.10 --remote-port 443',
    'firewall rule check --id 11111111-1111-1111-1111-111111111111 --transport cim',
    'firewall profiles --transport',
    'firewall profiles --transport native --transport com'
)) {
    Test-Command $command 2 @() | Out-Null
}

$identity = [System.Security.Principal.WindowsIdentity]::GetCurrent()
try {
    $principal = New-Object System.Security.Principal.WindowsPrincipal($identity)
    $admin = $principal.IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)
}
finally { $identity.Dispose() }
if (-not $admin) {
    Test-Command "firewall rule add --id $id --remote-address 192.0.2.10 --remote-port 44443 --no-color" 1 @('administrator') | Out-Null
    Test-Command "firewall rule remove --id $id --no-color" 1 @('administrator') | Out-Null
}
else {
    Write-Host 'SKIP mutation guard tests: current token is elevated; no Add/Remove is permitted in validation.'
}
Test-Command 'firewall profiles --telemetry etw --telemetry-wait 0 --no-color' @(0,4) @(
    'ETW CAPTURE SETUP', 'Provider: Microsoft-Windows-Windows Firewall With Advanced Security'
) | Out-Null
$profileSnapshots = @{}
foreach ($transport in @('com', 'native')) {
    $result = Test-Command "firewall profiles --transport $transport --no-color" 0 @(
        "Transport $transport", 'FIREWALL_PROFILES_READ', 'Domain', 'Private', 'Public'
    )
    $start = $result.IndexOf('FIREWALL PROFILES (READ-ONLY)')
    $end = $result.IndexOf('ASSESSMENT', $start)
    $profileSnapshots[$transport] = $result.Substring($start, $end - $start)
    Test-Command "firewall rule check --id $id --transport $transport --no-color" 3 @(
        "Transport $transport", 'FIREWALL_RULE_UNCONFIRMED', "remove --id $id --transport $transport"
    ) | Out-Null
    Test-Command "firewall profiles --transport $transport --telemetry eventlog --telemetry-wait 0 --no-color" 0 @(
        'Microsoft-Windows-Windows Firewall With Advanced Security/Firewall'
    ) | Out-Null
    if (-not $admin) {
        Test-Command "firewall rule add --direction in --remote-address 192.0.2.10 --local-port 443 --transport $transport --no-color" 1 @(
            'administrator', 'Mutation attempted False'
        ) | Out-Null
        Test-Command "firewall rule add --id $id --remote-address 192.0.2.10 --remote-port 44443 --transport $transport --no-color" 1 @(
            'administrator', 'Mutation attempted False'
        ) | Out-Null
        Test-Command "firewall rule remove --id $id --transport $transport --no-color" 1 @(
            'administrator', 'Mutation attempted False'
        ) | Out-Null
    }
}
if ($profileSnapshots['com'] -ne $profileSnapshots['native']) {
    throw 'COM/native profile snapshots differ; investigate policy changes or backend mapping.'
}
Test-Command 'firewall profiles --transport native --telemetry etw --telemetry-wait 0 --no-color' @(0,4) @(
    'Provider: Microsoft-Windows-Windows Firewall With Advanced Security', 'Transport native'
) | Out-Null

$originalExecutable = $Executable
$dependencyFolder = Join-Path $PSScriptRoot 'firewall-native-dependency-test'
if (Test-Path -LiteralPath $dependencyFolder) { throw "Test folder already exists: $dependencyFolder" }
$copy = Join-Path $dependencyFolder 'wtf.exe'
$dll = Join-Path $dependencyFolder 'WinTraceForge.Native.dll'
New-Item -ItemType Directory -Path $dependencyFolder | Out-Null
try {
    Copy-Item -LiteralPath $Executable -Destination $copy
    $Executable = $copy
    Test-Command 'firewall --help --transport native --no-color' 0 @('com|native', 'no automatic fallback') | Out-Null
    Test-Command 'firewall profiles --transport com --no-color' 0 @('FIREWALL_PROFILES_READ') | Out-Null
    Test-Command 'firewall profiles --transport native --no-color' 1 @(
        'matching x64 WinTraceForge.Native.dll', 'No fallback to com', 'Mutation attempted False'
    ) | Out-Null
    Copy-Item -LiteralPath (Join-Path $env:WINDIR 'System32\version.dll') -Destination $dll
    Test-Command 'firewall profiles --transport native --no-color' 1 @(
        'matching x64 WinTraceForge.Native.dll', 'No fallback to com'
    ) | Out-Null
    Remove-Item -LiteralPath $dll
    [System.IO.File]::WriteAllBytes($dll, [byte[]]@(0x4d, 0x5a, 0, 0))
    Test-Command 'firewall profiles --transport native --no-color' 1 @(
        'matching x64 WinTraceForge.Native.dll', 'No fallback to com', 'Mutation attempted False'
    ) | Out-Null
}
finally {
    $Executable = $originalExecutable
    if (Test-Path -LiteralPath $dll) { Remove-Item -LiteralPath $dll }
    if (Test-Path -LiteralPath $copy) { Remove-Item -LiteralPath $copy }
    Remove-Item -LiteralPath $dependencyFolder
}
Write-Host "PASS: $script:passed root/Firewall integration checks; no Firewall mutation was permitted."
