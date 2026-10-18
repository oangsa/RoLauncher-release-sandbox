# Phase D live recovery results

Status: **offline/simulated coverage PASS; mutating live matrix NOT RUN**.
No synthetic tag, draft, Release, fault, denied mutation or cleanup was executed.
Original [recovery matrix](PHASE-D-RECOVERY-MATRIX.md) remains mandatory.

## Prepared fault matrix

| Scenario | Required observed invariant | Live result |
|---|---|---|
| Before tag creation | Zero committed release mutations | NOT RUN |
| After tag creation | Preserve exact tag; no rewrite/duplicate | NOT RUN |
| After draft creation | Resume only exact matching unpublished draft | NOT RUN |
| Interrupted asset POST before acceptance | GET reconcile; upload only missing name | NOT RUN |
| Accepted upload response lost | Preserve existing ID/bytes; no duplicate successful upload | NOT RUN |
| Evidence expiry before first upload | Zero asset POSTs | NOT RUN |
| Evidence expiry between uploads | No subsequent mutation with stale evidence | NOT RUN |
| Evidence expires during admitted in-flight upload | Only admitted request may finish; no later stale write | NOT RUN |
| Canceled/timed-out preflight attendance | Zero release mutations | NOT RUN |
| Canceled/timed-out final attendance | Matching unpublished draft/assets only | NOT RUN |
| All uploads complete, before PATCH interruption | No publication without fresh final gate | NOT RUN |
| Publication PATCH committed, response lost | Independent immutable GET; consumed retry has zero writes | NOT RUN |
| Interrupted recovery with identical assets | Preserve all existing IDs/sizes/hashes; upload missing only | NOT RUN |
| Conflicting source/tag/asset/receipt | Stop/quarantine; no repair, overwrite or deletion | NOT RUN |
| Completed publication replay | Byte-identical state; zero mutations | NOT RUN |
| Wrong source/run/attempt/key/phase/replay/nonce | Fail closed; zero preflight writes | NOT RUN |
| Missing Ruleset/bypass/native/disclosure evidence | BLOCKED; never infer security controls | NOT RUN |
| Tag rewrite/delete and asset rename/delete/add | Actual GitHub denial plus unchanged readback | NOT RUN |
| Native immutable control outside tag Rulesets | Independent native protection proof | NOT RUN |

## Audit and execution preparation

1. Before each live scenario obtain exact approval naming sandbox, trusted/source SHA, run/attempt, fixture/tag, credential, fault point and permanent effects.
2. Record exact before-state, canonical receipt, source/artifact provenance, tag target, numeric Release/asset IDs and downloaded byte hashes.
3. Use existing `AuditedTransport`; append-only exclusive JSONL ledgers have a 2,000-event ceiling, start/end timestamps, sanitized route/method, mutation ordinal and actual HTTP outcomes.
4. Preserve no-retry behavior. A lost response is ambiguous until an independent GET proves server state; never replay a POST automatically.
5. Recovery needs fresh run/attempt and fresh owner evidence. Existing exact bytes must remain; mismatches require quarantine rather than replacement.
6. Independently GET immutable Release by numeric ID, resolve exact tag/source, download every asset and compare checksums/receipt before acceptance.
7. Retain both challenge/response references, collection/expiry times, admission timestamps and final state hashes. Never log tokens, passphrases, private keys or authenticated storage URLs.

Live mutation ledger: **NOT RUN**. Live mutating HTTP outcomes: **NOT RUN**.
Prior local simulated ledgers are distinct evidence; their fake statuses and resource states cannot satisfy GitHub operational acceptance.

## Capacity review

Current parser permits 268,435,456 bytes per entry/archive and 536,870,912 bytes aggregate expansion across platform archives.
Windows 256 MiB plus Linux 128 MiB fits capacity before bounded packaging overhead; real small main archives pass current parser.
The parser buffers bounded complete payloads and uses a 120-second transport timeout; no streaming-throughput or timeout guarantee is inferred.

Doubling minima requires Windows 536,870,912 bytes and Linux 268,435,456 bytes, totaling 805,306,368 before overhead.
Windows alone exceeds entry cap; combined payload exceeds aggregate cap. Oversized-negative rejection PASS is separate from positive stress acceptance BLOCKED.
No security limit or evidence TTL has been increased.

Owner acceptance options, none adopted:

1. Approve repeated within-limit and high-entropy cases as an explicit revised acceptance contract, retaining oversized rejection tests and documenting lost doubled-minimum coverage.
2. Resolve whether 2x refers to a verified production-size baseline; review exact current compressed inventory and preserve the separate 256/128 MiB minima. Do not infer this interpretation automatically.
3. Retain exact doubled-minimum requirement and request a separate security-reviewed streaming/resource-contract redesign before any changed positive capacity claim.

Prior local 256/128 MiB parser proof and near-limit entropy measurements remain local evidence only; large real Actions transfers and fault recovery are NOT RUN.
Capacity acceptance remains BLOCKED until owner explicitly resolves the contract after security review.

## Cleanup proposal; NOT AUTHORIZED

1. Restore readiness or other separately activated workflow's `false &&` through reviewed feature/dev/main PRs.
2. Unset only individually approved activation variables; revoke only approved temporary sandbox credentials after preserving evidence.
3. Preserve immutable fixtures, receipts, run identities, downloaded hashes and sanitized ledgers; never promise immutable-resource deletion.
4. Recollect complete controls and Production read-only state; verify all Publisher/Beta/PoC guards remain held.
5. Do not delete tags/releases/assets, edit Issue #5, alter Rulesets/bypasses/native immutability, invoke the operational key or change Production without distinct authorization.

No cleanup action executed; present variables and synthetic resources are absent.
Final Phase D operational acceptance remains **BLOCKED**, including attendance, runtime visibility, real fault recovery, immutability denial and capacity requirements.
