# Installation and verification

[User docs](README.md)

## Requirements

- Windows x64 and .NET Framework 4.8 or later.
- The Windows Defender Antivirus / Windows Firewall services relevant to the command.
- Administrator rights for Defender and ASR policy writes and firewall rule add/remove. Read-only commands do not require elevation, but some exclusion content may be hidden.
- Suitable tracing permissions for ETW, commonly an elevated PowerShell session.

No installation service is created. Keep `wtf.exe` and the matching x64 `WinTraceForge.Native.dll` in the same directory. Native transports and raw ETW require that DLL. A missing, incompatible, or outdated DLL fails explicitly without transport fallback.

## Download and verify

Download `WinTraceForge-<tag>-win-x64.zip` and its `.sha256` file from the corresponding [GitHub Release](https://github.com/bitbug0x55AA/WinTraceForge/releases). Generated binaries are not committed to the source branch.

From the download directory, check the ZIP's SHA-256 hash. This example uses `v0.1.0`; substitute the tag you downloaded:

```powershell
Get-FileHash .\WinTraceForge-v0.1.0-win-x64.zip -Algorithm SHA256
Get-Content .\WinTraceForge-v0.1.0-win-x64.sha256
```

The hash must match the release checksum. If GitHub CLI is installed, also verify build provenance:

```powershell
gh attestation verify .\WinTraceForge-v0.1.0-win-x64.zip `
  --repo bitbug0x55AA/WinTraceForge
```

The attestation binds the artifact digest to the repository, workflow, and source commit that built it. Extract the ZIP after verification.

## Confirm the version and start

In the extracted directory:

```powershell
.\wtf.exe --version
(Get-Item .\wtf.exe).VersionInfo | Select-Object FileVersion, ProductVersion
(Get-Item .\WinTraceForge.Native.dll).VersionInfo | Select-Object FileVersion, ProductVersion
.\wtf.exe --help
.\wtf.exe defender asr status
.\wtf.exe firewall profiles
```

Use the docs bundled with your release for its available commands. To build the current checkout instead, follow the [developer build guide](../dev/build-and-test.md).
