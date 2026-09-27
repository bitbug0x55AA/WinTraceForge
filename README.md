# WinTraceForge (WTF)

> **Same change. Different paths. Interesting silence.**

WinTraceForge is a Windows x64 defense-control test harness. It checks or makes narrowly scoped Microsoft Defender Antivirus, Attack Surface Reduction (ASR), and Windows Firewall changes through different execution paths, captures local evidence, and gives you a repeatable window to compare with your EDR/SIEM telemetry and alerts.

| Control | What you can do |
| --- | --- |
| Defender Antivirus | Check or add exclusions. |
| Attack Surface Reduction | Inspect posture, check or change exclusions and rule actions, and run an experimental behavioral test. |
| Windows Firewall | Inspect profiles and add, check, or remove uniquely marked test rules. |

Select managed WMI, COM, or native execution paths and collect existing Event Log records or raw ETW traces. WinTraceForge collects host-side evidence; a missing alert is an observation, not a bypass claim. It does not query your EDR/SIEM, generate test traffic, or disable the firewall.

> [!WARNING]
> Use only in an authorized test environment. Defender and ASR policy changes persist until manually restored. Firewall test rules require removal using the printed cleanup command and test ID. ASR behavioral verification is experimental and cannot confirm enforcement from local process observation alone.

## Install

Requires Windows x64, .NET Framework 4.8+, and the relevant Defender Antivirus / Windows Firewall services. Policy writes require administrator rights; read-only checks can run without elevation, though some data may be hidden. ETW capture commonly requires elevation.

Download the Windows x64 ZIP and accompanying SHA-256 file from [GitHub Releases](https://github.com/bitbug0x55AA/WinTraceForge/releases), verify the checksum, and extract it. Keep `wtf.exe` and the matching `WinTraceForge.Native.dll` together. See [installation and verification](docs/user/installation.md) for the exact verification steps.

## Quick start

Open PowerShell in the extracted directory and start with read-only checks:

```powershell
.\wtf.exe --version
.\wtf.exe --help
.\wtf.exe defender exclusion --check -ExclusionPath "C:\Lab Data"
.\wtf.exe defender asr status
.\wtf.exe firewall profiles
```

Compare execution paths and collect local evidence without changing policy:

```powershell
.\wtf.exe firewall profiles --transport native --telemetry eventlog
```

For an authorized firewall test, add a narrowly scoped rule, retain the printed ID, and use the exact printed cleanup command afterward:

```powershell
.\wtf.exe firewall rule add --remote-address 192.0.2.10 --remote-port 44443
# Replace the placeholder with the ID printed by add:
.\wtf.exe firewall rule remove --id <GUID>
```

`192.0.2.10` is an example address; choose an approved endpoint for your test. Rule readback confirms configuration, not packet enforcement.

## Documentation

- [User docs](docs/user/README.md): installation, command examples, telemetry, result interpretation, and cleanup.
- [Developer docs](docs/dev/README.md): source layout, lifecycle contract, backend details, build/test, and releases.
- [Documentation index](docs/README.md), [changelog](CHANGELOG.md), and [security policy](SECURITY.md).

## License

[Mozilla Public License 2.0](LICENSE).
