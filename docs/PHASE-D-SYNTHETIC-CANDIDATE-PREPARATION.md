# Phase D synthetic candidate preparation

**Status:** prepared for owner review only, 2026-10-18. No release authorization is implied.

## Verified sandbox state

The repository is `oangsa/RoLauncher-release-sandbox` (ID `1423257712`), owned by account ID `71574088`. Current `main` is `b19226ccc5a28fe2632bf6d3c4d6f4b2eb9ab230`; current `dev` is `ba09c98ee602f9da76ccdf935a6bf1f70125fc80`.

PR #18 and PR #19 are merged. Read-only GitHub API checks found zero tags and zero Releases. Production `oangsa/RoLauncher` was not accessed.

## Candidate identity and inert proposal

The requested version is `0.0.900`, proposed tag `v0.0.900`, channel `stable`, and application payload an inert sandbox fixture. A fresh canonical UUIDv4 was generated: `0db2788e-d5f3-478f-9f77-6d6d0dd064f4`.

The schema-1 proposal is saved at [`intent.proposed.json`](../phase-d/candidates/v0.0.900/intent.proposed.json) under this inert candidate directory. It is not in `.github/release-intents/`; it grants no authority and must only be copied to its final path in a separately approved intent-only PR.

The version metadata checks pass: `Cargo.toml` and the root `Cargo.lock` package are `0.0.900`; README and release notes begin with `# RoLauncher 0.0.900`; release notes are 388 characters after trimming, exceed the 120-character minimum, and contain no current placeholder. No production launcher binary or Premium, payment, or licensing feature was added.

## Locally measured inert fixtures

Two clean generations from source SHA `ba09c98ee602f9da76ccdf935a6bf1f70125fc80`, using `scripts/sandbox_fixtures.py`, produced byte-identical files. The source ZIP contains 68 tracked entries and passes file-backed Git blob verification against that source tree. Its inventory contains no `.exe`, `.dll`, `.msi`, or `.appx` source entries.

| File | Bytes | SHA-256 |
| --- | ---: | --- |
| `rolauncher-v0.0.900-setup-x64.exe` | 86 | `2fa3c13e4b3bac686b5c5362e50de46cd8755cd49212a60d7e93b904ff139291` |
| `rolauncher-v0.0.900-windows-x64.zip` | 43,764 | `24b4524c642255224b62d91b2c5527e20be7a342f4c45396f3eeffc2de8830b5` |
| `rolauncher-v0.0.900-source.zip` | 581,869 | `74c5cb1124512b26047cbfaf4cfb57488fdd898d87d119b7846410cfedbbf6e3` |
| `rolauncher-v0.0.900-SHA256SUMS.txt` | 299 | `8f678b975be0cc52cccc534f2917c5a51c5a2091d0a6117ccdc7ee198659104f` |
| `rolauncher-v0.0.900-linux-x64.tar.gz` | 15,767 | `c93eb47c50afd61a069ae5e4e0919c92c78233da8bccfcd241a998d719ac82dc` |
| `rolauncher-v0.0.900-linux-SHA256SUMS.txt` | 103 | `0d36d27967c52f0153bbe73ec73acd1a4ef037fe17731e2669888e0a0f22f718` |

The setup file is 86 bytes, starts without a PE header, and contains the builder's `NOT-A-PE-EXECUTABLE` marker. Windows ZIP and Linux TAR inventories both contain only `AGENTS.md`, `LICENSE`, `THIRD_PARTY_NOTICES.md`, and `SANDBOX-ONLY.txt`. No private-key or token markers were found in fixture payloads.

These are measured local hashes for the verified `dev` source only. They are not hashes for the future candidate merge, Actions artifacts, or a Release. The future source SHA, artifact IDs, run attempts, artifact digests, receipt, and resulting package hashes remain pending until actual owner-approved main-push workflows run. Generated fixture binaries were temporary and are not committed.

## Capacity and authorization boundary

Operational publisher limits remain 256 MiB per archive, 256 MiB per entry, 512 MiB aggregate expansion, and 1 MiB buffers. The separate local 2× stress profile remains test-only. This small smoke fixture does not satisfy 2× live transfer or publication acceptance.

The Publisher workflow remains hard-disabled by `false &&` in `.github/workflows/release-promotion.yml`. No intent, tag, Release, repository variable, key, Ruleset, or security setting was changed. No live signing, workflow dispatch, owner evidence post, or publication was performed.

See [admission requirements](PHASE-D-SYNTHETIC-CANDIDATE-ADMISSION.md) and [first-run sequencing](PHASE-D-FIRST-LIVE-RUN-SEQUENCING.md). Candidate state is `SYNTHETIC_CANDIDATE_READY_FOR_OWNER_REVIEW`; live publication remains unauthorized.
