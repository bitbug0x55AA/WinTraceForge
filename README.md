# WinTraceForge (WTF)

> **Same action. Different paths. Different visibility.**

WinTraceForge is a Windows x64 security telemetry differential testing harness / lab focused on **path-dependent security visibility**: when the same security-relevant operation or an equivalent outcome is reached through different Windows implementation paths, do Windows telemetry, EDR/SIEM telemetry, and detection response differ?

The research direction is **same operation / equivalent outcome → different implementation paths → compare observable security evidence**. Implementation paths concern how an operation is carried out, not only how a defense setting is changed. The current implementation centers on security-control / configuration experiments with Defender Antivirus, ASR, and Windows Firewall; it does not provide a general execution-experiment framework or additional behavior families.

The existing control modules share an operation lifecycle, verification and restoration contracts, and local evidence collection. Operators compare individual runs and correlate their evidence with their own detection stack; WTF does not automatically compare runs or query EDR/SIEM backends. Its value is in investigating visibility differences, rather than the number of controls it can modify.

Currently implemented modules:

| Current control experiment | What you can do |
| --- | --- |
| Defender Antivirus | Check or add exclusions. |
| Attack Surface Reduction | Inspect posture, check or change exclusions and rule actions, and run an experimental behavioral test. |
| Windows Firewall | Inspect profiles and add, check, or remove uniquely marked test rules. |

Available implementation paths include managed WMI, COM, native interfaces, and a PowerShell child process for Defender/ASR preferences, depending on the module. These are the paths supported by today's control experiments, not a definition of the project's ultimate research boundary. Collect existing Event Log records or raw ETW traces to investigate observable evidence, including on read-only checks. A missing alert is **an observation under tested conditions, not a bypass claim**; configuration readback alone does not prove enforcement or detection.

> [!WARNING]
> Run only on systems where you are authorized to test and modify security controls. Tests can change protection settings, affect system behavior, and leave persistent changes or artifacts, including after a failed or interrupted run. Review the selected module's effects and limitations, capture the baseline, and establish a restoration plan before making changes. Do not assume automatic rollback: follow the module's cleanup guidance and verify the resulting state. Treat collected telemetry as sensitive evidence.

## Install

Requires Windows x64, .NET Framework 4.8+, and the Windows services/providers used by the selected module. Current policy writes require administrator rights; read-only checks can run without elevation, though some data may be hidden. ETW capture commonly requires elevation. See the [user docs](docs/user/README.md) for module-specific requirements and limitations.

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

Collect evidence for a read-only operation through different supported paths:

```powershell
.\wtf.exe firewall profiles --transport com --telemetry eventlog
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
