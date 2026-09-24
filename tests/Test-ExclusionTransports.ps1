# This Source Code Form is subject to the terms of the Mozilla Public License, v. 2.0.
# If a copy of the MPL was not distributed with this file, You can obtain one at https://mozilla.org/MPL/2.0/.

param(
    [Parameter(Mandatory = $true)]
    [string] $Executable
)

$ErrorActionPreference = 'Stop'
$script:Passed = 0

function Invoke-Case {
    param(
        [string] $Image,
        [string] $Arguments,
        [int[]] $ExpectedExit,
        [string[]] $ExpectedText
    )
    $start = New-Object System.Diagnostics.ProcessStartInfo
    $start.FileName = $Image
    $start.Arguments = 'defender exclusion ' + $Arguments
    $start.UseShellExecute = $false
    $start.RedirectStandardOutput = $true
    $start.RedirectStandardError = $true
    $process = [System.Diagnostics.Process]::Start($start)
    try {
        $stdoutTask = $process.StandardOutput.ReadToEndAsync()
        $stderrTask = $process.StandardError.ReadToEndAsync()
        if (-not $process.WaitForExit(60000)) {
            $process.Kill()
            throw "Test timed out: $Arguments"
        }
        $output = $stdoutTask.GetAwaiter().GetResult() + $stderrTask.GetAwaiter().GetResult()
        $normalized = ($output -replace '\s+', ' ').Trim()
        if ($ExpectedExit -notcontains $process.ExitCode) {
            throw "Unexpected exit $($process.ExitCode) for $Arguments`n$output"
        }
        foreach ($text in $ExpectedText) {
            if (-not $normalized.Contains(($text -replace '\s+', ' ').Trim())) {
                throw "Missing '$text' for $Arguments`n$output"
            }
            if ($output.Contains([string][char]27)) { throw 'Redirected output must not contain ANSI escapes.' }
            foreach ($line in ($output -split '\r?\n')) {
                if ($line.Length -gt 100) { throw "Redirected line exceeds 100 columns: $line" }
            }
        }
        $script:Passed++
        Write-Host "PASS [$($process.ExitCode)] $Arguments"
        return $output
    }
    finally {
        $process.Dispose()
    }
}

$help = Invoke-Case $Executable '--help' 0 @(
    'WINTRACEFORGE', 'USAGE', 'OPTIONS', 'EXCLUSION TYPES', 'QUICK START',
    'management|com|native', 'Detection & Response', 'No arguments: usage error'
)
$plainHelp = Invoke-Case $Executable '--help --no-color' 0 @('--no-color', '--verbose')
if ($help -ne $plainHelp) { throw 'Color flag changed redirected help content.' }
if (($help -split '\r?\n').Count -gt 45) { throw 'Default help exceeds 45 lines.' }
Invoke-Case $Executable '--help --verbose --no-color' 0 @(
    'EXTENDED NOTES', 'PowerShell array syntax', 'Telemetry failures do not change the operation exit code.'
) | Out-Null
$etwOutput = Invoke-Case $Executable '--transport native --check -ExclusionPath "C:\Lab Data" --telemetry etw --telemetry-wait 0 --no-color' @(0, 4) @(
    'ETW CAPTURE SETUP', 'Raw ETW file-mode capture', 'Add attempted: False'
)
if ($etwOutput.Contains('Outcome: NOT_ATTEMPTED')) {
    if (-not $etwOutput.Contains('no eventlog fallback') -and -not $etwOutput.Contains('No ETW providers')) {
        throw 'ETW setup failure must explicitly prevent an unobserved operation.'
    }
}
elseif (-not $etwOutput.Contains('RAW ETW EVIDENCE')) {
    throw 'Successful ETW setup must produce an ETW evidence report.'
}
$match = [regex]::Match($etwOutput, 'Session\s+WinTraceForge-([0-9a-f-]{36})')
if ($match.Success) {
    $testTrace = Join-Path ([Environment]::GetFolderPath('LocalApplicationData')) ('WinTraceForge\Traces\' + $match.Groups[1].Value)
    if ((Test-Path -LiteralPath $testTrace) -and @(Get-ChildItem -LiteralPath $testTrace -Force).Count -eq 0) {
        Remove-Item -LiteralPath $testTrace
    }
}
$baselines = @{}
foreach ($transport in @('management', 'com', 'native')) {
    Invoke-Case $Executable "--transport $transport --check" 0 @(
        "Transport $transport", 'ExclusionPath: supported (string[])',
        'ExclusionExtension: supported (string[])', 'ExclusionProcess: supported (string[])',
        'ExclusionIpAddress: supported (string[])', 'Outcome: CHECK_ONLY',
        'Add attempted: False', 'Detection/response: NOT_MEASURED', 'Compliance: NOT_ASSESSED'
    ) | Out-Null
    $arguments = "--transport $transport --check " +
        '-ExclusionPath "C:\Lab Data" "C:\Temp\DefenderExclusionTest" ' +
        '-ExclusionExtension .lablog .labtmp -ExclusionProcess "C:\Lab Tools\Worker.exe" ' +
        '-ExclusionIpAddress 192.0.2.10 2001:db8::1 -ExclusionPath "C:\Lab Data"'
    $output = Invoke-Case $Executable $arguments 0 @(
        'Read-only check passed. No settings were changed.',
        'BASELINE', 'ExclusionPath: C:\Lab Data',
        'ExclusionExtension: .lablog',
        'ExclusionProcess: C:\Lab Tools\Worker.exe',
        'ExclusionIpAddress: 2001:db8::1',
        'Add attempted: False', 'Outcome: CHECK_ONLY'
    )
    $baselines[$transport] = (($output -split '\r?\n') | Where-Object {
        $_ -match '^\s+\[(SEEN|INFO)\]\s+Exclusion'
    }) -join "`n"
    if (@($output -split '\r?\n' | Where-Object { $_ -match '^\s+ExclusionPath\s+C:\\Lab Data$' }).Count -ne 1) {
        throw "Duplicate value was not deduplicated for $transport"
    }
    Invoke-Case $Executable "--transport $transport --check -ExclusionPath `"C:\Lab Data`" --verbose --no-color" 0 @(
        'DIAGNOSTICS', 'EXCLUSION SCOPE', 'DETECTION & RESPONSE',
        'Event 5007', 'Event 5013', 'Security 4688', 'Sysmon 1',
        'not a complete successful-method audit trail', 'Executable:', 'Route:'
    ) | Out-Null
    $compact = Invoke-Case $Executable "--transport $transport --check -ExclusionPath `"C:\Lab Data`" --no-color" 0 @(
        'RESULT', 'Outcome: CHECK_ONLY', 'No automatic cleanup', '--verbose'
    )
    if ($compact.Contains('DIAGNOSTICS') -or $compact.Contains('Event 5007')) {
        throw 'Default output must not dump verbose recommendations.'
    }
    if (($compact -split '\r?\n').Count -gt 40) { throw 'Default single-target check exceeds 40 lines.' }
    Invoke-Case $Executable "--transport $transport --check --telemetry eventlog --telemetry-wait 0" 0 @(
        'Source: existing ETW-backed Windows event channels',
        'Outcome: CHECK_ONLY', 'Add attempted: False',
        'Channel: Microsoft-Windows-Windows Defender/Operational',
        'Channel: Microsoft-Windows-WMI-Activity/Operational',
        'Channel: Security', 'Channel: Microsoft-Windows-Sysmon/Operational',
        'Collection completeness:', 'No matching evidence is NOT proof'
    ) | Out-Null
}
if ($baselines['management'] -ne $baselines['com'] -or $baselines['management'] -ne $baselines['native']) {
    throw 'Transport baseline results differ.'
}
$script:Passed++
Write-Host 'PASS equivalent requested-value baselines across all transports'

foreach ($arguments in @(
    '', '--transport', '--transport com', '--transport invalid --check',
    '--transport com --transport native --check', '-ExclusionPath',
    '--check -ExclusionPath "C:\Lab" --invalid', '--help --transport com'
    , '--check --telemetry raw'
    , '--check --telemetry-wait 0'
    , '--check --telemetry eventlog --telemetry-wait 31'
)) {
    Invoke-Case $Executable $arguments 2 @('Invalid arguments:', 'No settings were changed.') | Out-Null
}

$identity = [System.Security.Principal.WindowsIdentity]::GetCurrent()
try {
    $principal = New-Object System.Security.Principal.WindowsPrincipal($identity)
    $isAdministrator = $principal.IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)
}
finally {
    $identity.Dispose()
}
if (-not $isAdministrator) {
    foreach ($transport in @('management', 'com', 'native')) {
        Invoke-Case $Executable "--transport $transport -ExclusionPath `"C:\Lab Data`"" 1 @(
            'Administrator No', 'Outcome: NOT_ATTEMPTED',
            'Add attempted: False', 'Preflight failed before Add'
        ) | Out-Null
    }
}
else {
    Write-Host 'SKIP non-admin guard tests: current token is elevated; no Add will be attempted.'
}

$dependencyFolder = Join-Path $PSScriptRoot 'native-dependency-test'
if (Test-Path -LiteralPath $dependencyFolder) {
    throw "Refusing to overwrite existing test directory: $dependencyFolder"
}
$copy = Join-Path $dependencyFolder 'wtf.exe'
New-Item -ItemType Directory -Path $dependencyFolder | Out-Null
try {
    Copy-Item -LiteralPath $Executable -Destination $copy
    Invoke-Case $copy '--transport native --check' 1 @(
        'Native backend DLL is missing', 'Outcome: NOT_ATTEMPTED', 'Add attempted: False'
    ) | Out-Null
    Invoke-Case $copy '--transport management --check' 0 @('Outcome: CHECK_ONLY') | Out-Null
    Invoke-Case $copy '--transport com --check' 0 @('Outcome: CHECK_ONLY') | Out-Null
    Invoke-Case $copy '--check --telemetry etw --telemetry-wait 0' 4 @(
        'ETW native DLL is missing', 'Outcome: NOT_ATTEMPTED', 'Add attempted: False'
    ) | Out-Null
}
finally {
    if (Test-Path -LiteralPath $copy) { Remove-Item -LiteralPath $copy }
    Remove-Item -LiteralPath $dependencyFolder
}

Write-Host "PASS: $script:Passed integration checks; no Defender Add invocation was permitted."
