# Phase D Publisher activation review

**PREPARED — NOT AUTHORIZED FOR ACTIVATION**

This review prepares a guarded workflow proposal for `oangsa/RoLauncher-release-sandbox` only. It does not authorize merging, enabling variables, signing, rerunning Publisher, or publishing a release.

## Baseline and dependency

Read-only GitHub refresh on 2026-10-18 confirmed:

- Main: `b19226ccc5a28fe2632bf6d3c4d6f4b2eb9ab230`.
- Dev: `ba09c98ee602f9da76ccdf935a6bf1f70125fc80`.
- PR #18 (capacity remediation) is merged to dev; PR #19 promoted it to main.
- PR #20 (synthetic candidate preparation) remains open at `67f7bff270329090104b8d14c3bc37f6ec689dc0`, targeting dev. It was not modified or superseded.
- No remote activation branch, tag, or Release exists. `phase-d/candidates/v0.0.900/` and `.github/release-intents/` are absent from this reviewed dev snapshot.

The activation proposal is based on current dev while PR #20 is open. Rebase and rerun all checks after PR #20 is owner-merged or dev otherwise advances.

## Proposed changes

The workflow patch changes only the `promote` job in `.github/workflows/release-promotion.yml`:

- Remove the literal `false &&` from that job guard.
- Require both `RELEASE_PROMOTION_ENABLED == 'true'` and `PHASE_D_LIVE_AUTHORIZED == 'true'`.
- Pass `PHASE_D_OPERATION_PLAN` and both flags to `prepare`, `stage`, and `finish`.
- Route all three stages through `scripts/phase_d_publisher.py`.

The repo and numeric ID, successful same-repository push, main/Beta branch gate, trusted checkout at `github.sha`, SHA-pinned checkout/upload actions, concurrency group, no-cancel setting, token permissions, attendance steps, and Beta/PoC hard-disables remain in place. The workflow introduces no dispatch path, administrator permission, owner PAT, private signing key, dynamic candidate shell, or new release mutation route.

This Draft PR targets dev; it does not replace the workflow file on default-branch main. GitHub only triggers `workflow_run` when the workflow file exists on the default branch, so this proposal itself does not make the main Publisher eligible. A separate owner-approved promotion to main remains the activation boundary. [GitHub `workflow_run` trigger rules](https://docs.github.com/en/actions/reference/workflows-and-actions/events-that-trigger-workflows).

The publisher code now binds the reviewed operation plan to the admitted release before owner attendance. The live entry passes the plan channel into `promote_event`; `LifecycleEvidence` rejects a channel/tag mismatch with the admitted intent or a source SHA mismatch before source verification and before either owner gate. This closes a scope gap where a mismatched plan could otherwise reach the preflight challenge before the mutation wrapper rejected it.

## Execution and authorization trace

`workflow_run.completed` → two-variable job guard → trusted `github.sha` checkout → exact operation-plan parse → fresh source-run reconciliation → intent/owner/CI admission → artifact provenance and checksum/source-ZIP verification → signed Preflight → audited staging → signed Final → freshness and state re-reads → scoped publication.

All three workflow stages execute the Phase D entry point. Its `main()` returns before constructing a GitHub transport unless both activation variables equal `true`. With both enabled, an absent or malformed plan fails before creating the API transport. Plan validation pins repository ID `1423257712`, owner ID `71574088`, trusted workflow SHA, triggering source SHA, publisher run/attempt, synthetic tag/channel, and bounded fault approval. Publisher run identity remains separate from candidate CI and Linux identities. If both publisher run fields are omitted in the plan, the entry binds them to its current runtime values; a partially supplied pair is rejected.

For an official Linux main-push completion, `promote_event` checks the event against the current run, requires the same source SHA and run attempt, then requires exactly one matching successful CI run for that SHA. The candidate receipt and source artifacts remain bound to the CI run; signed evidence also binds the Linux run ID/attempt and the separate Publisher run ID/attempt. Stable admission rechecks that main still points to the source SHA before and after attendance and before publication.

The workflow listens for `completed`; unsuccessful completions fail the job guard and the code independently checks current API status. Once the plan channel is passed into `promote_event`, unrelated workflow paths and a Beta completion under a stable plan fail before candidate admission. PR #20 has no active intent in this dev snapshot, so it cannot by itself authorize a publication.

### Rerun boundary

GitHub documents that workflow reruns use the original `GITHUB_SHA` and `GITHUB_REF`, and exposes `github.run_attempt` as the attempt number for a particular workflow run. The publisher compares the delivered run attempt and SHA with the current API run, and the Linux source query must resolve one unique CI run on the same SHA. The current code supports the requested identity binding if GitHub delivers the intended completed event.

No operational Linux rerun was issued. Offline fixtures cannot prove that GitHub will deliver a real `workflow_run.completed` event for the proposed rerun or establish its payload timing. Treat that behavior as unverified; the owner must review the actual run ID, incremented attempt, unchanged candidate SHA, event, and unique CI match before proceeding. [GitHub event documentation](https://docs.github.com/en/actions/reference/workflows-and-actions/events-that-trigger-workflows), [rerun behavior](https://docs.github.com/en/actions/how-tos/manage-workflow-runs/re-run-workflows-and-jobs), and [run-attempt context](https://docs.github.com/en/actions/reference/workflows-and-actions/contexts#github-context).

## Plan scope and reachable mutations

`phase-d/operation-scope.example.json` is an inert example with SHA placeholders. It is not configured as a repository variable. No future source or trusted SHA was invented. The first proposed stable fixture remains `v0.0.900`, `channel: stable`, `fault: null`, and `faults_approved: false`; an exact candidate and trusted main SHA are still required.

If both flags and an exact plan are enabled, an admitted release can reach only these release mutations through `scoped_call`:

1. `POST /git/refs` to create the plan’s exact tag at its source SHA.
2. `POST /releases` to create the matching draft.
3. `POST` uploads for missing verified setup, Windows archive, source archive, Linux archive, checksum, and `release-promotion.json` receipt assets.
4. `PATCH /releases/{id}` to publish after final attendance and fresh readbacks.

The wrapper rejects other write methods/routes, mismatched tag/release IDs/assets, and plans for another source/channel. It has no release deletion path. The workflow also uploads challenge and audit artifacts through the pinned Actions artifact action; those are workflow evidence artifacts, not release assets. No GitHub mutation was performed for this review.

## Signed evidence, HTTP 403, and audit

Both gates require fresh challenges and distinct nonces, an enrolled Ed25519 signature, canonical controls/disclosure digests, exact repository/source/trusted-SHA/run/attempt binding, replay protection, strict Ruleset checks, and native immutability evidence. Evidence collection is limited to 45 seconds, signature TTL is 120 seconds, and owner attendance is limited to 1,200 seconds per gate. Final publication follows a separate final signature after complete staging, receipt and asset inventory checks, live security rereads, and evidence freshness checks.

The transport path is `FrozenArtifacts → AuditedTransport → GitHub API`. Immutable visibility observations are forwarded to the append-only audit ledger as `OWNER_ATTESTED` or `RUNNER_VISIBLE`; a missing observer fails closed. The synthetic end-to-end regression exercises both visibility values, checks the actual ledger, and verifies that token/body/header material is absent. HTTP 403 is treated as an owner-attested permission limit only for the exact documented integration denial, endpoint, accepted permission, positive rate-limit remainder, and no `Retry-After`; ambiguous 403 responses do not approve the observation. No owner key or public evidence was used.

## Artifact limits and lifecycle

Operational Publisher capacity remains fixed at 256 MiB per archive, 256 MiB per entry, 512 MiB aggregate expanded data, and a 1 MiB streaming buffer. The 2× benchmark profile is a test-only constant; `promote()` rejects a workspace whose policy differs from the operational policy. Downloads, decompression, uploads, checksum/source verification, time limits, temporary disk use, and cleanup are file-backed and bounded. The local 2× stress profile is not a live GitHub capacity result.

## Preconditions and open items

- `VARIABLE_STATE_NOT_VERIFIED`: GitHub’s approved read connector rejected the Actions variables endpoint. No variable was changed and no value is assumed. Before any future promotion into main, the owner must independently verify both activation flags are false/unset and `PHASE_D_OPERATION_PLAN` has no executable plan. Until then, main promotion is **BLOCKED**.
- Source/intent readiness: **NOT READY**. PR #20 is open; there is no active candidate intent, reviewed candidate source SHA, trusted activation-main SHA, artifact run identity, or operation plan.
- The Draft PR body records exact head, base, test-merge SHA, and hosted context results; owner approval must verify all five contexts still match the current PR revision.
- Live event delivery, owner signatures, artifact uploads, capacity at production-sized files, mutation denial, native immutability, and recovery behavior against GitHub: **NOT RUN**.
- Published tags/Releases may be permanent or immutable. The owner must explicitly accept the exact `v0.0.900` fixture risk before any live fixture operation.

## Validation record

| Check | Result |
| --- | --- |
| Activation patch `git apply --check` | PASS |
| Focused simulated publisher plan-mismatch and successful lifecycle | PASS |
| Audit ledger visibility and secret-redaction regression | PASS |
| Actionlint v1.7.12, all six workflows | PASS |
| Full `python scripts/offline_tests.py` | PASS — 135 tests |
| Python AST syntax | PASS — 22 scripts |
| Source artifact parser/tree verification | PASS — offline integration regressions |
| Whitespace and workflow guard/permissions diff review | PASS |
| Hosted PR contexts and exact test-merge SHA | See PR body; verify all five required contexts against the current PR head, base, and test-merge SHA before owner approval |

## Required default-branch warning

Promoting this workflow into the default branch removes the literal hard-disable. Before such promotion, the owner must verify both activation flags are disabled or unset, verify no executable operation plan is configured, and approve the exact revision. No operational publication is authorized by this PR.
