# Phase D live validation

Status on 2026-10-18: **read-only baseline PASS; operational acceptance BLOCKED**.
No readiness dispatch, owner signature, public evidence, release mutation, fault probe or cleanup was executed.
The [original lifecycle contract](SANDBOX-RELEASE-LIFECYCLE.md) remains authoritative.

## Current protected baseline

- Sandbox `oangsa/RoLauncher-release-sandbox`, repository ID `1423257712`, owner ID `71574088`.
- Owner merged [PR #9](https://github.com/oangsa/RoLauncher-release-sandbox/pull/9) into dev as `797e74ee3e644644c7b09cffe07cde236919f080`.
- Owner merged official dev into main through [PR #10](https://github.com/oangsa/RoLauncher-release-sandbox/pull/10), commit `4df5c0b6a83374aa6f8b4d4e5c24ef384a585c70`.
- Main parents: `b010f87fdefe1283e8e0fc417341a6fb96e9ccee`, `797e74ee3e644644c7b09cffe07cde236919f080`; exact Git tree agrees with API.
- Main [CI 39093592497](https://github.com/oangsa/RoLauncher-release-sandbox/actions/runs/39093592497) and [Linux 39093592484](https://github.com/oangsa/RoLauncher-release-sandbox/actions/runs/39093592484): attempt 1, push, success, actual main checkout.
- All five required contexts succeeded; Windows, Ubuntu 24.04, Ubuntu and Arch each ran 111 tests. Skipped jobs do not count.

## Real baseline artifacts

Both current-main Actions ZIPs were downloaded independently; GitHub SHA256, exact inventories, all checksums and 57 source Git blobs pass.
Installer is inert, portable/Linux payloads contain only reviewed notices, and two exact-source reproductions match every payload byte.
These are small baseline fixtures; they do not prove production-sized hosted throughput.

| Artifact | ID | Bytes | SHA256 |
|---|---:|---:|---|
| release-files-attempt-1 | 12123672333 | 131964 | `ed220b9d3644e8a7ec9b191b42a9ab41f2de180bed4fa378dac3a4c92739108b` |
| release-linux-files-attempt-1 | 12123259583 | 16224 | `1442611085a392e1ce9fc54f383c6fab6f33a3c2186eafcd7be5b06a065a980b` |

## Controls and isolation

Complete owner GET collections match the 7,264-byte canonical digest `c48b4ebe3972abe2d5fe75b2ef7e5a0f70065c3b7e5c71a7bc9cd8a18d09c368`.
All seven Rulesets are active; all bypass arrays are explicit; effective main/dev protections and native immutability pass.
The enrolled key, fingerprint and Issue #5 remain unchanged; Issue #5 has zero evidence comments and stale enrollment wording remains proposed-only.

Publisher, Beta and historical PoC retain literal `false &&`; main readiness is also held.
Publisher/PoC wakeups are skipped with zero steps; Beta/readiness have zero runs.
Variables, release intents, tags, drafts and Releases are absent.

Production was queried read-only: main `193c465e4d5999506f8c406ac45ff3e88d1a1a94`, PR #29 open at `dc2494876a7bd4a29f0da91cf27ffe1bdd2798be`.
No Production source, credential or configuration change is part of this proposal.

## Readiness proposal and checklist

The dedicated codex branch proposes only removing `false &&` from readiness, plus boundary regressions and these reports.
This unmerged proposal does not activate protected main; review exact PR HEAD and its five contexts before authorizing an owner merge.
Use feature to dev, then a separately reviewed official dev-to-main PR; no direct protected-branch write.

| Requirement | Evidence class | Status / next evidence |
|---|---|---|
| Exact owner merges, source, main checks and artifacts | Read-only live | PASS |
| Complete controls, native setting, identity, isolation | Read-only live | PASS |
| Readiness activation YAML and GET-only source audit | Source/offline | PASS; activation/dispatch BLOCKED |
| Publisher-equivalent token visibility | Live Actions | NOT RUN; separate dispatch approval |
| Independent readiness artifact review | Live Actions | NOT RUN; require run/attempt/trusted SHA/digest |
| Both Windows-to-Ubuntu attended gates | Mutating live/public evidence | NOT RUN; exact signing/disclosure approval |
| Stable, beta, feature and hotfix source contracts | Offline/simulated | PASS; actual publication NOT RUN |
| Immutable release/source/receipt/download identity | Mutating live plus GET | NOT RUN |
| Interrupted/expired/cancelled recovery and consumed retry | Offline/simulated | PASS; live NOT RUN |
| Native immutability outside tag Rulesets | Mutating live | NOT RUN; separate permanent control approval |
| Actual rejected HTTP mutations and unchanged readback | Mutating live | NOT RUN |
| Large within-limit parser fixtures | Prior local measurements | PASS locally; large hosted transport NOT RUN |
| Positive 2x minimum capacity | Contract/capacity | BLOCKED; separate owner/security decision |
| Final audit and cleanup | Preparation | Reports prepared; cleanup NOT RUN |

## Next exact approvals

1. Review the dedicated readiness PR's exact HEAD and owner-authorize only its merge into dev; review/approve official dev-to-main separately.
2. Once resulting main and all checks are verified, authorize one manual readiness dispatch at that exact main SHA, attempt 1.
3. The readiness token declares contents-write, Actions-read, PR-read and Issues-read; no Administration. Script calls only GET; Actions artifact upload is an expected write.
4. Approve real signing/public responses, publisher variables/activation, named permanent fixtures, live fault/denied scenarios and cleanup separately.

No future run ID, challenge, response, Release ID, mutating HTTP outcome or mutation ledger is invented here.
Record those exact values only after the relevant authorized operation, in the [security](PHASE-D-LIVE-SECURITY-AUDIT.md) and [recovery](PHASE-D-LIVE-RECOVERY-RESULTS.md) reports.
