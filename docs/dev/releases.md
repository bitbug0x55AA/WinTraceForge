# Release maintenance

[Developer docs](README.md) | [Build and test](build-and-test.md)

## Version and publish

`Build.ps1 -Version` accepts SemVer and generates metadata for both the EXE and native DLL. Local builds default to `0.1.0-dev`; CI injects a version containing its run number and commit. Numeric major/minor/patch components must fit Windows file metadata (`0..65535`).

After reviewing the intended commit, updating the changelog, and validating it, create and push a release tag. Example only; choose the intended unused version:

```powershell
git tag v0.1.0
git push origin v0.1.0
```

The [release workflow](https://github.com/bitbug0x55AA/WinTraceForge/blob/main/.github/workflows/release.yml) triggers on `v*.*.*` tags. It also supports manual dispatch from the default branch with a `vX.Y.Z` input and optional prerelease flag. Dispatch creates a missing tag or requires an existing tag to match the workflow commit.

The workflow builds/tests on a GitHub-hosted Windows runner, injects the tag version, packages the release, computes SHA-256, creates signed build-provenance attestations, and publishes assets. It attests the ZIP, checksum, EXE, and native DLL. Rerunning the same tag replaces its release assets; dispatch's prerelease flag is applied when creating a release.

## Package contents

`WinTraceForge-<tag>-win-x64.zip` contains:

- `wtf.exe` and `WinTraceForge.Native.dll` together.
- `README.md`, `CHANGELOG.md`, `SECURITY.md`, and `LICENSE`.
- The `docs/` tree, preserving relative paths for offline navigation.

The sibling `.sha256` asset records the ZIP digest. Users follow the [installation guide](../user/installation.md) for verification. Generated executables, DLLs, symbols, ETLs, and build directories remain excluded from source control; publish compiled outputs as release assets.

## Maintain documentation

Keep the root README focused on path-dependent security visibility, currently implemented experiments, requirements, installation, a short quick start, and links. Describe WTF as a Windows security telemetry differential testing harness / lab, while clearly identifying Defender Antivirus, ASR, and Firewall as today's security-control / configuration experiments. Put command usage, results, evidence limits, and cleanup under `docs/user/`; put current architecture, implementation contracts, toolchain/test details, and release procedures under `docs/dev/`.

Keep release and documentation wording vendor-neutral. Do not describe planned execution experiments, behavior families, or new lifecycles as implemented. Missing alerts are an observation under tested conditions, not a bypass claim. The existing control lifecycle describes current code, not the ultimate research boundary; adding more control families is not itself the research objective. Preserve historical release descriptions as history, and record positioning changes under the corresponding unreleased/released changes.

When moving or renaming pages, update indexes, relative links, CLI help references, and release packaging together. Preserve documentation paths inside the ZIP. Keep important limitations near the user-facing command, especially persistent policy changes, ownership-based removal, and experimental ASR verification.

Check that examples match the current parser and transport defaults, that links resolve in both the checkout and release package, and that documentation describes the corresponding source/release version. Update [CHANGELOG](../../CHANGELOG.md) for notable user-visible behavior changes.
