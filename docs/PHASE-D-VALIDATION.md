# Phase D validation

Implementation status: offline lifecycle, fault/audit interfaces and held automation prepared.
**Live lifecycle status: NOT RUN / BLOCKED by separate owner approval and attendance.**
The [original lifecycle specification](SANDBOX-RELEASE-LIFECYCLE.md) remains authoritative; no requirement is waived.

| Requirement | Implemented evidence | Actual live result |
|---|---|---|
| D0 baseline, policy, controls, source artifacts | [Exact main evidence](PHASE-D-READINESS.md) | PASS, read-only GitHub evidence |
| D1 canonical evidence, both independent gates and negatives | Disposable-key regressions; strict integration preserves pinned verifier | BLOCKED: real Windows attendance needed |
| D2 stable/schema-1, beta and schema-2 hotfix | Existing admission plus both cryptographic gates; independent immutable download auditor | NOT RUN: publication needs exact fixture approval |
| D3 interruption, expiry, cancellation, lost response and consumed retry | [Recovery matrix](PHASE-D-RECOVERY-MATRIX.md), audited transport and retained simulated state | NOT RUN against real mutating API |
| D3 256/128 MiB and near-limit entropy fixtures | Local real parser, source blobs, CRC/SHA256 and memory measurements | PASS locally; hosted transport/recovery NOT RUN |
| D3 requested 512/256 MiB positive 2x minimum | Explicit unchanged-limit rejection | BLOCKED: entry/aggregate incompatibility |
| D4 independent audit, denial plans and cleanup | Download verifier, exact-approval probe driver and nonexecuting cleanup plan | Native GitHub denial/cleanup NOT RUN |

## Reproduce safely

1. Use Python 3.13+, Git and OpenSSH supporting `ssh-keygen -Y`.
2. Run `python scripts/offline_tests.py`; this blocks sockets, remote Git, inherited credentials/agents and shell subprocesses.
3. To retain nonsecret simulated ledgers/state, set `PHASE_D_TEST_AUDIT_DIR` to a new local evidence directory before running tests.
4. Run Actionlint against every workflow; all Actions remain SHA-pinned.
5. Generate local size fixtures into a new directory with `python scripts/phase_d_fixtures.py --output <new-directory>`.

Automated tests generate disposable test-only keys. They never read or invoke the operational owner private key.
Hosted branch/PR jobs run offline regressions and small inert fixtures; they do not run live publisher/probes or upload large fixtures.
Local Windows/Python 3.13.10 validation: 111 tests PASS, retaining all 84 existing regressions.
Exact final source/PR SHAs, platform logs, workflow IDs/attempts and results belong in the implementation PR and accompanying evidence bundle.

## Local capacity evidence

| Case | Windows asset | Linux asset | Parser peak bytes | Result |
|---|---:|---:|---:|---|
| Zero padding | 268435456 | 134239598 | 428744704 | PASS |
| Deterministic high entropy | 267386880 | 134239598 | 829001728 | PASS |

Generator, archive writes and checksums stream in bounded chunks; original publisher parser retains complete bounded payload bytes.
Measured memory is not a claim of constant-memory publisher parsing or measured Actions network throughput.
High-entropy outer Windows ZIP is 267,573,282 bytes, below unchanged 268,435,456-byte archive limit; Linux ZIP is 134,273,134 bytes.

Production latest-stable metadata was read only: v1.7.0 installer 65,658,398 bytes, portable 94,579,670 bytes, source 4,110,123 bytes, Linux 64,747,868 bytes.
Generated large individual Windows/Linux assets exceed twice the largest respective individual baseline assets; this does not prove a complete 2x production bundle or 2x the mandated minimum fixture.
No Production artifact/source/credential was copied into these inert fixtures.

Doubling mandated minima requires a 512 MiB Windows entry and at least 768 MiB combined Windows/Linux payload.
Those exceed 256 MiB entry and 512 MiB aggregate limits before ZIP/source/checksum overhead.
Capacity-versus-acceptance remains an explicit owner decision; oversized negatives pass by rejecting, never by raising limits.
