# Developer docs

These guides are for contributors and maintainers changing WinTraceForge's security telemetry differential testing harness. Start with architecture and the existing control lifecycle contract when changing the implemented Defender Antivirus, ASR, or Firewall experiments. These contracts describe today's code; they do not define a general execution-experiment architecture.

| Guide | Covers |
| --- | --- |
| [Architecture](architecture.md) | Source layout, operation flow, transport boundaries, and extension workflow. |
| [Control lifecycle contract](control-lifecycle.md) | Phase interfaces, typed results, restoration policies, existing families, and regression requirements. |
| [Backend and interop reference](backend-reference.md) | ASR schemas/process cleanup, Firewall WMI/COM behavior, native NULL semantics, and telemetry ABI. |
| [Build and test](build-and-test.md) | Toolchain, local build options, deterministic checks, integration checks, and validation limits. |
| [Release maintenance](releases.md) | Version metadata, workflows, package contents, provenance, and documentation maintenance. |

Command syntax, operator-visible results, and cleanup guidance belong in the [user docs](../user/README.md). Release history remains in [CHANGELOG](../../CHANGELOG.md); vulnerability reporting remains in [SECURITY](../../SECURITY.md).

[All documentation](../README.md) | [Repository overview](../../README.md)
