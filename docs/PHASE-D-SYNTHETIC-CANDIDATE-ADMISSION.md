# Phase D synthetic candidate admission

This document follows the current source in `scripts/release_promotion.py`, `scripts/phase_d_publisher.py`, `scripts/hotfix_policy.py`, `scripts/owner_evidence.py`, and the three release workflows. A valid intent or green CI alone never grants publication authority.

## Stable intent and governance contract

The stable schema-1 intent has exactly four fields:

```json
{
  "schema": 1,
  "id": "<canonical lowercase UUIDv4>",
  "version": "0.0.900",
  "channel": "stable"
}
```

Its eventual path is `.github/release-intents/<id>.json`. On the source commit admitted by the main-push CI, `authorize()` requires exactly one newly added intent path, rejects edits/reuse and noncanonical UUIDs, and checks the stable version and channel.

The matching GitHub PR must be merged into `main`, come from the exact `dev` branch and sandbox repository, have `merge_commit_sha` equal to the admitted source SHA, and identify repository owner ID `71574088` as merger. Foreign repository IDs, missing/ambiguous PR evidence, wrong branch, wrong merge SHA, missing intent, and stale `main` fail closed.

## Required main-push evidence

The admitted source is a successful `push` run of `.github/workflows/ci-release.yml` on `main`. The current attempt must be completed and successful. Its jobs must each appear exactly once, succeed, and report the same `head_sha`:

- `Branch flow`
- `Windows checks`
- `Linux checks and package (Ubuntu 24.04)`

Exactly one matching `push` run of `.github/workflows/linux.yml` must exist for that SHA. Its `Linux checks (Ubuntu)` and `Linux checks (Arch)` jobs must also succeed at the selected run attempt and source SHA. The publisher re-reads both run records, and stable promotion requires current `main` to equal the admitted source SHA.

The CI branch-flow and owner-merged PR records depend on actual GitHub commit IDs, PR metadata, owner identity, and workflow-run records. Offline tests can validate simulated records only; they cannot establish these final admission facts.

## Artifact names and exact contents

The main-push CI workflow uploads two attempt-named artifact groups:

| Group | Exact entries |
| --- | --- |
| `release-files-attempt-N` | `rolauncher-v0.0.900-setup-x64.exe`, `rolauncher-v0.0.900-windows-x64.zip`, `rolauncher-v0.0.900-source.zip`, `rolauncher-v0.0.900-SHA256SUMS.txt` |
| `release-linux-files-attempt-N` | `rolauncher-v0.0.900-linux-x64.tar.gz`, `rolauncher-v0.0.900-linux-SHA256SUMS.txt` |

`N` is the admitted CI run's `run_attempt`. The parser selects one exact group for that attempt, checks artifact source run ID and head SHA, expiry, declared size, downloaded size, and GitHub's archive digest. Each selected ZIP must have the exact expected entry set and count. Duplicate or case-fold-colliding names, extra/missing entries, paths, symlinks, encryption, unsupported compression, oversized entries, invalid directory metadata, and ZIP64/split archives are rejected.

Names are compared case-sensitively against the exact expected filenames. Checksum records accept only expected filenames, lowercase 64-hex SHA-256 values, no duplicates, and the complete expected set; each file's bytes are rehashed. The publisher constructs the final combined `SHA256SUMS.txt` from the Windows and Linux package digests. Previous attempt artifacts may remain attached to a run, but only the current attempt-specific groups are selected.

The receipt binds the intent UUID, channel, version, source SHA, CI run ID and attempt, artifact IDs/names/digests, and final asset hashes. The Windows builder's source ZIP is checked against the admitted Git tree before either attended gate. File-backed verification requires a complete tree below 5,000 entries, regular Git blobs only (`100644` or `100755`), an exact path inventory, and each ZIP entry's Git blob SHA-1. Missing/extra/duplicate source entries, unsupported symlink/submodule entries, wrong source SHA, and modified blob bytes fail closed.

## Publisher and owner evidence gates

The activation patch is inert in `phase-d/release-promotion.activation.patch`. Current `main` still contains literal `false &&`; this candidate PR does not apply the patch or change runtime variables.

After separate activation, `phase_d_publisher.authorize_plan()` requires the exact sandbox repository/owner IDs, workflow-run environment, trusted/source SHAs, candidate tag/channel, and fault approval fields. `run_id` and `attempt` are filled from the actual Publisher workflow's `GITHUB_RUN_ID` and `GITHUB_RUN_ATTEMPT` when omitted from the proposed scope. This is the Publisher run identity, distinct from the admitted CI and Linux source run IDs.

The attended preflight and final gates use the existing enrolled Ed25519 public-key policy and bind signatures to the canonical challenge digest, source/CI/Linux runs and attempts, trusted SHA, receipt, fresh nonce, policy digest, and phase. Evidence expires after 120 seconds; collection and confirmation are limited to 45 seconds; owner attendance waits at most 1,200 seconds. Replay, wrong key/owner, edited or duplicate response, changed source/run/attempt, stale policy, and expired evidence are rejected before the applicable mutation. The original enrollment and private key are not changed or copied.

Native immutability and visibility are read at both gates. `OWNER_ATTESTED` and `RUNNER_VISIBLE` remain distinct observations in the audit ledger. An ambiguous HTTP 403 is classified as permission-limited only under the documented response contract; it never substitutes for a valid owner signature. TOCTOU checks, audited file-backed transfers, immutable readback, and no unauthorized mutation retries remain in the existing publisher path.

## Offline regression evidence

The offline suite uses fake GitHub transports and disposable signing keys. Relevant coverage includes valid and malformed intents, owner/branch/merge evidence, changed main, failed/skipped/missing required jobs, mismatched Linux source, stale artifact attempt, expiry/digest/source errors, exact ZIP and source-tree inventories, denied admission with zero writes, wrong operation plan, unexpected publisher events, ambiguous HTTP 403, signature rejection, nonce replay, and evidence expiry.

Candidate-preparation additions exercise a Linux-run rerun at the same source SHA with the incremented attempt, artifact ID substitution, unapproved archive members, canonical UUID/path/intent count, owner-merge evidence, and file-backed source ZIP failures for wrong source SHA, wrong Git blob, missing/extra/duplicate entries, and unsupported Git symlink entries. These are offline contract tests; they are not GitHub admission or live Publisher evidence.
