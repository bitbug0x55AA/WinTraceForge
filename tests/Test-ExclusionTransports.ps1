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

# Whether the exclusion lists are readable decides what a read-only command must report: an
# administrator sees the values; anyone else gets Defender's placeholder, which WTF must report as
# UNREADABLE (exit 3), never as an empty list or a missing value.
$identity = [System.Security.Principal.WindowsIdentity]::GetCurrent()
try {
    $principal = New-Object System.Security.Principal.WindowsPrincipal($identity)
    $isAdministrator = $principal.IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)
}
finally {
    $identity.Dispose()
}
$readExit = if ($isAdministrator) { 0 } else { 3 }

$help = Invoke-Case $Executable '--help' 0 @(
    'WTF // WINTRACEFORGE', 'Same action. Different paths. Different visibility.', 'USAGE', 'OPTIONS', 'COMMANDS', 'EXCLUSION TYPES', 'ROUTES', 'QUICK START',
    'add', 'check', 'list', 'remove', 'No remove-all',
    'management|com|native|powershell', 'Detection & Response', 'No command: usage error',
    'never shown as empty'
)
$plainHelp = Invoke-Case $Executable '--help --no-color' 0 @('--no-color', '--verbose')
if ($help -ne $plainHelp) { throw 'Color flag changed redirected help content.' }
if (($help -split '\r?\n').Count -gt 45) { throw 'Default help exceeds 45 lines.' }
foreach ($command in @('add', 'check', 'list', 'remove')) {
    $commandHelp = Invoke-Case $Executable "$command --help" 0 @('COMMANDS')
    if ($commandHelp -ne $help) { throw "'$command --help' must print the same help." }
}
Invoke-Case $Executable '--help --verbose --no-color' 0 @(
    'EXTENDED NOTES', 'PowerShell array syntax', 'UNREADABLE', 'ALREADY_ABSENT', 'REMOVED_CONFIRMED',
    'never claims a value was created by WTF', 'Telemetry failures do not change the operation exit code.'
) | Out-Null
$etwOutput = Invoke-Case $Executable 'check --transport native -ExclusionPath "C:\Lab Data" --telemetry etw --telemetry-wait 0 --no-color' @(0, 3, 4) @(
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

$checkBaselines = @{}
$listResults = @{}
foreach ($transport in @('management', 'com', 'native', 'powershell')) {
    # check without values: capability check only, unaffected by list readability.
    Invoke-Case $Executable "check --transport $transport" 0 @(
        "Transport $transport", 'ExclusionPath: supported (string[])',
        'ExclusionExtension: supported (string[])', 'ExclusionProcess: supported (string[])',
        'ExclusionIpAddress: supported (string[])', 'Outcome: CHECK_ONLY',
        'Add attempted: False', 'Detection/response: NOT_MEASURED', 'Compliance: NOT_ASSESSED'
    ) | Out-Null

    $arguments = "check --transport $transport " +
        '-ExclusionPath "C:\Lab Data" "C:\Temp\DefenderExclusionTest" ' +
        '-ExclusionExtension .lablog .labtmp -ExclusionProcess "C:\Lab Tools\Worker.exe" ' +
        '-ExclusionIpAddress 192.0.2.10 2001:db8::1 -ExclusionPath "C:\Lab Data"'
    if ($isAdministrator) {
        $expected = @('Read-only check passed. No settings were changed.', 'BASELINE', 'ExclusionPath: C:\Lab Data',
            'ExclusionExtension: .lablog', 'ExclusionProcess: C:\Lab Tools\Worker.exe',
            'ExclusionIpAddress: 2001:db8::1', 'Add attempted: False', 'Outcome: CHECK_ONLY')
    }
    else {
        $expected = @('BASELINE', 'ExclusionPath: C:\Lab Data [unknown - list unreadable]',
            'ExclusionIpAddress: 2001:db8::1 [unknown - list unreadable]', 'UNREADABLE',
            'Check incomplete', 'Add attempted: False', 'Outcome: CHECK_INCOMPLETE')
    }
    $output = Invoke-Case $Executable $arguments $readExit $expected
    if (-not $isAdministrator -and $output -match 'not observed') {
        throw "An unreadable list must never be reported as 'not observed' for $transport"
    }
    $checkBaselines[$transport] = (($output -split '\r?\n') | Where-Object {
        $_ -match '^\s+\[(SEEN|INFO|WARN)\]\s+Exclusion'
    }) -join "`n"
    if (@($output -split '\r?\n' | Where-Object { $_ -match '^\s+ExclusionPath\s+C:\\Lab Data$' }).Count -ne 1) {
        throw "Duplicate value was not deduplicated for $transport"
    }
    Invoke-Case $Executable "check --transport $transport -ExclusionPath `"C:\Lab Data`" --verbose --no-color" $readExit @(
        'DIAGNOSTICS', 'EXCLUSION SCOPE', 'DETECTION & RESPONSE',
        'Event 5007', 'Event 5013', 'Security 4688', 'Sysmon 1',
        'not a complete successful-method audit trail', 'Executable:', 'Route:'
    ) | Out-Null
    $compact = Invoke-Case $Executable "check --transport $transport -ExclusionPath `"C:\Lab Data`" --no-color" $readExit @(
        'RESULT', 'No automatic cleanup', '--verbose'
    )
    if ($compact.Contains('DIAGNOSTICS') -or $compact.Contains('Event 5007')) {
        throw 'Default output must not dump verbose recommendations.'
    }
    if (($compact -split '\r?\n').Count -gt 40) { throw 'Default single-target check exceeds 40 lines.' }
    Invoke-Case $Executable "check --transport $transport --telemetry eventlog --telemetry-wait 0" 0 @(
        'Source: existing ETW-backed Windows event channels',
        'Outcome: CHECK_ONLY', 'Add attempted: False',
        'Channel: Microsoft-Windows-Windows Defender/Operational',
        'Channel: Microsoft-Windows-WMI-Activity/Operational',
        'Channel: Security', 'Channel: Microsoft-Windows-Sysmon/Operational',
        'Collection completeness:', 'No matching evidence is NOT proof'
    ) | Out-Null

    # list: every readable exclusion per type, never writes, never calls an unreadable list empty.
    if ($isAdministrator) {
        $listExpected = @('EXCLUSIONS', 'Read-only list complete. No settings were changed.',
            'Outcome: LIST_ONLY', 'Add attempted: False; Remove attempted: False')
    }
    else {
        $listExpected = @('EXCLUSIONS', 'ExclusionPath UNREADABLE', 'ExclusionExtension UNREADABLE',
            'ExclusionProcess UNREADABLE', 'ExclusionIpAddress UNREADABLE', 'List incomplete',
            'Outcome: LIST_INCOMPLETE', 'Add attempted: False; Remove attempted: False')
    }
    $listOutput = Invoke-Case $Executable "list --transport $transport --no-color" $readExit $listExpected
    if (-not $isAdministrator -and ($listOutput -cmatch 'Exclusion\w+\s+EMPTY' -or $listOutput -cmatch 'N/A:')) {
        throw "An unreadable list must not be reported empty or show Defender's placeholder for $transport"
    }
    # The per-type rows and their entries, which must match exactly across transports.
    $listResults[$transport] = ((@($listOutput -split '\r?\n')) | Where-Object {
        $_ -match '^\s+Exclusion(Path|Extension|Process|IpAddress)\s' -or $_ -match '^\s{4}\S'
    }) -join "`n"
}
foreach ($transport in @('com', 'native', 'powershell')) {
    if ($checkBaselines['management'] -ne $checkBaselines[$transport]) { throw "Transport baseline results differ: $transport" }
    if ($listResults['management'] -ne $listResults[$transport]) { throw "Transport list results differ: $transport" }
}
$script:Passed++
Write-Host 'PASS equivalent check baselines and lists across all transports'

# Legacy spellings keep working during the migration period, with a pointer to the new command.
Invoke-Case $Executable '--transport management --check' 0 @(
    '--check', 'deprecated', 'defender exclusion check', 'Outcome: CHECK_ONLY'
) | Out-Null
Invoke-Case $Executable '--check -ExclusionPath "C:\Lab Data"' $readExit @('deprecated', 'defender exclusion check') | Out-Null

foreach ($arguments in @(
    '', 'add', 'remove', 'add --transport com', 'remove --transport com',
    'remove -ExclusionPath', 'remove -ExclusionPath ""', 'list -ExclusionPath "C:\Lab"',
    'check --check', 'add --check -ExclusionPath "C:\Lab"', 'list --check',
    '--transport com remove -ExclusionPath "C:\Lab"', 'delete -ExclusionPath "C:\Lab"',
    'remove --help -ExclusionPath "C:\Lab"', 'list --transport cmd',
    'add -ExclusionPath "C:\Lab" remove', 'check -ExclusionPath "C:\Lab" list',
    '-ExclusionPath "C:\Lab" remove', '--check -ExclusionPath "C:\Lab" list',
    '--transport', '--transport com', '--transport invalid --check', 'check --transport invalid',
    '--transport com --transport native --check', '-ExclusionPath',
    '--check -ExclusionPath "C:\Lab" --invalid', '--help --transport com'
    , '--check --telemetry raw', 'check --telemetry raw'
    , '--check --telemetry-wait 0', 'check --telemetry-wait 0'
    , '--check --telemetry eventlog --telemetry-wait 31'
)) {
    Invoke-Case $Executable $arguments 2 @('Invalid arguments:', 'No settings were changed.') | Out-Null
}

if (-not $isAdministrator) {
    foreach ($transport in @('management', 'com', 'native', 'powershell')) {
        Invoke-Case $Executable "add --transport $transport -ExclusionPath `"C:\Lab Data`"" 1 @(
            'Administrator No', 'Outcome: NOT_ATTEMPTED',
            'Add attempted: False', 'Preflight failed before Add'
        ) | Out-Null
        Invoke-Case $Executable "remove --transport $transport -ExclusionPath `"C:\Lab Data`"" 1 @(
            'Mode REMOVE exclusions', 'Administrator No', 'Outcome: NOT_ATTEMPTED',
            'Remove attempted: False', 'Preflight failed before Remove'
        ) | Out-Null
        Invoke-Case $Executable "--transport $transport -ExclusionPath `"C:\Lab Data`"" 1 @(
            'Implicit add is deprecated', 'defender exclusion add',
            'Administrator No', 'Outcome: NOT_ATTEMPTED', 'Add attempted: False', 'Preflight failed before Add'
        ) | Out-Null
    }
}
else {
    Write-Host 'SKIP non-admin guard tests: current token is elevated; no Add will be attempted.'
    # Values that cannot exist in any list: remove must find them absent in the baseline and never
    # send a Remove request, so this exercises the real baseline read on every transport without
    # changing Defender.
    $absent = [guid]::NewGuid().ToString('N')
    foreach ($transport in @('management', 'com', 'native', 'powershell')) {
        Invoke-Case $Executable ("remove --transport $transport -ExclusionPath `"C:\WTF-absent-$absent`" " +
            "-ExclusionExtension .wtf$($absent.Substring(0, 8)) -ExclusionProcess `"wtf-$absent.exe`" " +
            "-ExclusionIpAddress 198.51.100.77") 0 @(
            'Mode REMOVE exclusions', 'ALREADY_ABSENT ExclusionPath', 'ALREADY_ABSENT ExclusionExtension',
            'ALREADY_ABSENT ExclusionProcess', 'ALREADY_ABSENT ExclusionIpAddress',
            'Outcome: ALREADY_ABSENT', 'Remove attempted: False; requests sent: 0'
        ) | Out-Null
    }
}

$dependencyFolder = Join-Path $PSScriptRoot 'native-dependency-test'
if (Test-Path -LiteralPath $dependencyFolder) {
    throw "Refusing to overwrite existing test directory: $dependencyFolder"
}
$copy = Join-Path $dependencyFolder 'wtf.exe'
New-Item -ItemType Directory -Path $dependencyFolder | Out-Null
try {
    Copy-Item -LiteralPath $Executable -Destination $copy
    # The lifecycle reports the loader's own (localized) message, so only the DLL name is matched.
    Invoke-Case $copy 'check --transport native' 1 @(
        'WinTraceForge.Native.dll', 'Outcome: CHECK_FAILED', 'Add attempted: False'
    ) | Out-Null
    Invoke-Case $copy 'list --transport native' 1 @(
        'WinTraceForge.Native.dll', 'Outcome: LIST_FAILED', 'Add attempted: False'
    ) | Out-Null
    Invoke-Case $copy 'check --transport management' 0 @('Outcome: CHECK_ONLY') | Out-Null
    Invoke-Case $copy 'check --transport com' 0 @('Outcome: CHECK_ONLY') | Out-Null
    Invoke-Case $copy 'check --transport powershell' 0 @('Outcome: CHECK_ONLY') | Out-Null
    Invoke-Case $copy 'check --telemetry etw --telemetry-wait 0' 4 @(
        'ETW native DLL is missing', 'Outcome: NOT_ATTEMPTED', 'Add attempted: False'
    ) | Out-Null
}
finally {
    if (Test-Path -LiteralPath $copy) { Remove-Item -LiteralPath $copy }
    Remove-Item -LiteralPath $dependencyFolder
}

Write-Host "PASS: $script:Passed integration checks; no Defender Add or Remove invocation was permitted."
