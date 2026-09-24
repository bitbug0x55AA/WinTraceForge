# This Source Code Form is subject to the terms of the Mozilla Public License, v. 2.0.
# If a copy of the MPL was not distributed with this file, You can obtain one at https://mozilla.org/MPL/2.0/.

[CmdletBinding()]
param(
    [string] $OutputDirectory,
    [string] $VcVarsPath,
    [string] $Version = '0.1.0-dev',
    [switch] $Test,
    [switch] $Integration
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
if (-not $OutputDirectory) { $OutputDirectory = Join-Path $PSScriptRoot 'build' }
$versionMatch = [regex]::Match($Version,
    '^(?<major>0|[1-9][0-9]*)\.(?<minor>0|[1-9][0-9]*)\.(?<patch>0|[1-9][0-9]*)(?:-[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?(?:\+[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?$')
if (-not $versionMatch.Success) { throw "Version must be valid SemVer, for example 0.1.0 or 0.1.0-rc.1." }
$versionNumbers = @('major', 'minor', 'patch') | ForEach-Object {
    [int]::Parse($versionMatch.Groups[$_].Value, [Globalization.CultureInfo]::InvariantCulture)
}
if (@($versionNumbers | Where-Object { $_ -gt 65535 }).Count -ne 0) {
    throw 'Version major, minor and patch components must be 0..65535 for Windows file metadata.'
}
$assemblyVersion = '{0}.{1}.{2}.0' -f $versionNumbers
$csc = Join-Path $env:WINDIR 'Microsoft.NET\Framework64\v4.0.30319\csc.exe'
if (-not (Test-Path -LiteralPath $csc)) { throw '.NET Framework x64 C# compiler not found.' }
if (-not $VcVarsPath) {
    $vswhere = Join-Path ${env:ProgramFiles(x86)} 'Microsoft Visual Studio\Installer\vswhere.exe'
    if (-not (Test-Path -LiteralPath $vswhere)) { throw 'Install Visual Studio C++ Build Tools, or specify -VcVarsPath.' }
    $found = @(& $vswhere -latest -products '*' -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -find 'VC\Auxiliary\Build\vcvars64.bat')
    if ($LASTEXITCODE -ne 0 -or $found.Count -eq 0) { throw 'Visual Studio x64 C++ tools not found.' }
    $VcVarsPath = $found[0]
}
if (-not (Test-Path -LiteralPath $VcVarsPath -PathType Leaf)) { throw "Missing vcvars64: $VcVarsPath" }
$VcVarsPath = (Resolve-Path -LiteralPath $VcVarsPath).Path
$OutputDirectory = [IO.Path]::GetFullPath($OutputDirectory)
New-Item -ItemType Directory -Path $OutputDirectory -Force | Out-Null
$sourceDirectory = Join-Path $PSScriptRoot 'src\WinTraceForge'
$managedSourceDirectory = Join-Path $sourceDirectory 'managed'
$nativeSourceDirectory = Join-Path $sourceDirectory 'native'
$sources = @(Get-ChildItem -LiteralPath $managedSourceDirectory -Filter 'WinTraceForge*.cs' -File |
    Sort-Object Name | ForEach-Object { $_.FullName })
$testDirectory = Join-Path $PSScriptRoot 'tests'
$versionSource = Join-Path $OutputDirectory 'WinTraceForge.Version.g.cs'
$versionResourceSource = Join-Path $OutputDirectory 'WinTraceForge.Version.rc'
$versionResourceObject = Join-Path $OutputDirectory 'WinTraceForge.Version.res'

@"
using System.Reflection;

[assembly: AssemblyTitle("WinTraceForge")]
[assembly: AssemblyProduct("WinTraceForge")]
[assembly: AssemblyDescription("Windows-native defense-control path and telemetry test harness")]
[assembly: AssemblyVersion("$assemblyVersion")]
[assembly: AssemblyFileVersion("$assemblyVersion")]
[assembly: AssemblyInformationalVersion("$Version")]

internal static class WinTraceForgeBuildInfo
{
    internal const string Version = "$Version";
}
"@ | Set-Content -LiteralPath $versionSource -Encoding UTF8

$versionComma = $versionNumbers -join ','
@"
#include <windows.h>

1 VERSIONINFO
 FILEVERSION $versionComma,0
 PRODUCTVERSION $versionComma,0
 FILEFLAGSMASK VS_FFI_FILEFLAGSMASK
 FILEFLAGS 0x0L
 FILEOS VOS_NT_WINDOWS32
 FILETYPE VFT_DLL
 FILESUBTYPE 0x0L
BEGIN
    BLOCK "StringFileInfo"
    BEGIN
        BLOCK "040904b0"
        BEGIN
            VALUE "CompanyName", "WinTraceForge contributors\0"
            VALUE "FileDescription", "WinTraceForge native transports\0"
            VALUE "FileVersion", "$assemblyVersion\0"
            VALUE "InternalName", "WinTraceForge.Native\0"
            VALUE "LegalCopyright", "Licensed under MPL-2.0\0"
            VALUE "OriginalFilename", "WinTraceForge.Native.dll\0"
            VALUE "ProductName", "WinTraceForge\0"
            VALUE "ProductVersion", "$Version\0"
        END
    END
    BLOCK "VarFileInfo"
    BEGIN
        VALUE "Translation", 0x0409, 1200
    END
END
"@ | Set-Content -LiteralPath $versionResourceSource -Encoding ASCII

function Invoke-VcCommand([string] $Command) {
    $installer = Join-Path ${env:ProgramFiles(x86)} 'Microsoft Visual Studio\Installer'
    & $env:ComSpec /d /s /c ('set "PATH=' + $installer + ';%PATH%" && call "' +
        $VcVarsPath + '" >nul && ' + $Command)
    if ($LASTEXITCODE -ne 0) { throw "Visual C++ command failed ($LASTEXITCODE): $Command" }
}

function Invoke-NativeBuild([string] $Arguments) {
    Invoke-VcCommand ('cl /nologo /O2 /MT /W4 /WX /EHsc /std:c++17 ' + $Arguments)
    if ($LASTEXITCODE -ne 0) { throw "Native build failed ($LASTEXITCODE)." }
}

function Invoke-ManagedBuild([string] $EntryPoint, [string] $OutputName, [string] $TestSource) {
    $inputs = @($sources) + $versionSource
    if ($TestSource) { $inputs += Join-Path $testDirectory $TestSource }
    & $csc /nologo /target:exe /platform:x64 /optimize+ /warn:4 /warnaserror+ /reference:System.Management.dll "/main:$EntryPoint" "/out:$OutputName" $inputs
    if ($LASTEXITCODE -ne 0) { throw "Managed build failed: $EntryPoint ($LASTEXITCODE)." }
}

function Invoke-TestBinary([string] $Name, [string[]] $Arguments = @()) {
    & (Join-Path $OutputDirectory $Name) @Arguments
    if ($LASTEXITCODE -ne 0) { throw "Test failed: $Name ($LASTEXITCODE)." }
}

Push-Location -LiteralPath $OutputDirectory
try {
    Invoke-VcCommand ('rc /nologo /fo"' + $versionResourceObject + '" "' + $versionResourceSource + '"')
    $nativeSources = @('WinTraceForge.Native.cpp', 'WinTraceForge.Etw.cpp', 'WinTraceForge.Firewall.Native.cpp') |
        ForEach-Object { '"' + (Join-Path $nativeSourceDirectory $_) + '"' }
    Invoke-NativeBuild ('/LD ' + ($nativeSources -join ' ') + ' "' + $versionResourceObject + '"' +
        ' /link /OUT:WinTraceForge.Native.dll wbemuuid.lib ole32.lib oleaut32.lib advapi32.lib tdh.lib')
    Invoke-ManagedBuild 'WinTraceForge' 'wtf.exe' ''
    if ($Test -or $Integration) {
        Invoke-ManagedBuild 'RegressionTests' 'Control.RegressionTests.exe' 'AddDefenderExclusion.RegressionTests.cs'
        Invoke-ManagedBuild 'FirewallRegressionTests' 'Firewall.RegressionTests.exe' 'Firewall.RegressionTests.cs'
        Invoke-TestBinary 'Control.RegressionTests.exe'
        Invoke-TestBinary 'Firewall.RegressionTests.exe'
    }
    if ($Integration) {
        Write-Host 'Windows integration: read-only policy checks, detached rule preparation and bounded private ETW only.'
        Invoke-ManagedBuild 'FirewallNativeRegressionTests' 'Firewall.Native.RegressionTests.exe' 'Firewall.Native.RegressionTests.cs'
        Invoke-TestBinary 'Firewall.Native.RegressionTests.exe'
        Invoke-NativeBuild ('/I"' + $nativeSourceDirectory + '" "' +
            (Join-Path $testDirectory 'Firewall.Native.RegressionTests.cpp') +
            '" /Fe:Firewall.Native.CppTests.exe /link ole32.lib oleaut32.lib advapi32.lib')
        Invoke-TestBinary 'Firewall.Native.CppTests.exe'
        Invoke-TestBinary 'Firewall.RegressionTests.exe' @('--native-read-only')
        Invoke-TestBinary 'Firewall.RegressionTests.exe' @('--native-detached-preflight')
        Invoke-NativeBuild ('/I"' + $nativeSourceDirectory + '" "' +
            (Join-Path $testDirectory 'Etw.RegressionTests.cpp') + '" /Fe:Etw.RegressionTests.exe /link advapi32.lib tdh.lib ole32.lib')
        $etl = Join-Path $OutputDirectory ('PrivateSelfTest-' + [guid]::NewGuid().ToString('D') + '.etl')
        try { Invoke-TestBinary 'Etw.RegressionTests.exe' @($etl) }
        finally { if (Test-Path -LiteralPath $etl) { Remove-Item -LiteralPath $etl } }
        & (Join-Path $testDirectory 'Test-ExclusionTransports.ps1') -Executable (Join-Path $OutputDirectory 'wtf.exe')
        & (Join-Path $testDirectory 'Test-WinTraceForge.ps1') `
            -Executable (Join-Path $OutputDirectory 'wtf.exe') -ExpectedVersion $Version
    }
    Write-Host "PASS: WinTraceForge $Version build/selected checks finished. Output: $OutputDirectory"
}
finally { Pop-Location }
