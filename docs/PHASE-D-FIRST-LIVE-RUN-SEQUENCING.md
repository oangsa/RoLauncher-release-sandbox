# Phase D first live run sequencing

**Status:** sequencing is viable at the source-contract level with one owner-controlled Linux rerun after SHA and artifact verification. This is not approval to activate or run the Publisher.

## Keep activation ahead of the candidate source

1. Review and merge the candidate-preparation PR to `dev` through normal governance. It contains no active intent.
2. Separately review the Publisher activation patch. Bring that change to `dev`, then use an owner-approved `dev` → `main` PR to install it on the default branch. Keep `RELEASE_PROMOTION_ENABLED` and `PHASE_D_LIVE_AUTHORIZED` false or unset, and leave the operation plan unconfigured. Activation advances `main`, so it must happen before the final candidate source is created.
3. Separately approve an intent-only PR that adds the proposed schema-1 record at `.github/release-intents/0db2788e-d5f3-478f-9f77-6d6d0dd064f4.json` to `dev`. The final official `dev` → `main` PR must be merged by the repository owner. Record the actual `merge_commit_sha` as candidate source SHA `C` only after GitHub creates it.
4. Let the main-push CI and Linux workflows for `C` finish. Verify PR/source identity, all five required job contexts, exact run IDs and attempts, artifact group names, artifact IDs/digests, source ZIP/Git tree match, and current `main == C`.

## First-event race and guarded recovery

The current Publisher workflow has literal `false &&`. The activation patch removes that hard stop but adds two explicit variable checks. With both variables held false, the CI and Linux completion events cannot start Publisher jobs while their records are being collected and reviewed.

After the initial `workflow_run` events have completed with their Publisher jobs skipped, obtain owner approval for the exact candidate scope. Set `trusted_sha=C` and `source_sha=C` only if the default-branch SHA seen by the Publisher is still `C` and the triggering source run also has head SHA `C`. Then set the approved operation plan and activation variables. Do not merge or otherwise advance `main` during this run.

Re-run the existing `linux.yml` run for `C` as the explicit wake-up. GitHub documents that workflow reruns retain the original `GITHUB_SHA` and `GITHUB_REF`, keep the same run ID, and increment `GITHUB_RUN_ATTEMPT`. The `workflow_run` event uses the last commit on the default branch for its own `GITHUB_SHA`, and the Publisher listens for completed CI/Linux runs. Its code re-fetches the triggering run and requires the event attempt and SHA to match. For a Linux wake-up, `promote_event()` selects the unique CI run for the same SHA; `promote()` then verifies its own required jobs and attempt-bound artifacts.

The Linux rerun leaves the original CI artifact attempt unchanged, so the Publisher still selects `release-files-attempt-1` and `release-linux-files-attempt-1` from the verified CI run. An offline event fixture confirms that the rerun attempt can wake promotion while the receipt remains bound to the original CI source run and artifacts. The docs distinguish the webhook `completed` event from `requested`, which GitHub says is not emitted for a rerun. No live rerun was performed; the first separately authorized smoke must confirm the real completion event before any owner signature is posted.

## SHA availability and stale-source stop

The future source SHA becomes known when the owner-approved `dev` → `main` merge creates its commit. The trusted SHA is the actual default-branch `GITHUB_SHA` of the Publisher's `workflow_run` execution. Both must be verified from GitHub; for this main-push candidate they should equal `C` while `main` remains unchanged. The inert scope in [`operation-scope.proposed.json`](../phase-d/candidates/v0.0.900/operation-scope.proposed.json) leaves both as `null` and omits Publisher run ID/attempt.

`phase_d_publisher.main()` binds the Publisher's own `run_id` and `attempt` from its runtime environment when both are omitted from the plan. That binding is separate from the source CI run and Linux validation run. The source run attempt controls artifact names; the Publisher run attempt controls owner challenges, audit files, and attendance.

If `main` advances after `C`, `authorize_plan()` rejects a trusted SHA that differs from Publisher `GITHUB_SHA`, and stable promotion rejects a source SHA that no longer equals current `main`. Stop and prepare a newly reviewed source/intent plan; do not relax run/source binding or reuse an already admitted intent path.

## Owner approvals still required

- Owner review and merge of this inert candidate-preparation PR to `dev`.
- Separate security approval of the activation workflow diff and the official owner-merged promotion to `main`.
- Explicit approval of the permanent synthetic tag/release name `v0.0.900`, including possible immutable or undeletable Release consequences.
- Separate approval to add the proposed UUID at the active intent path through an intent-only PR and to merge the official `dev` → `main` candidate PR as owner.
- Separate approval of the exact GitHub-derived SHA, source runs/attempts, artifact IDs/digests, operation plan, activation variables, and Linux rerun that wakes the Publisher.
- Owner attendance and local signing for both fresh challenge phases, plus explicit approval of the exact public evidence disclosure. No key or signing action is part of this preparation.
- Separate authorization for any larger 2× GitHub artifact transport or live capacity acceptance. The small smoke case does not cover it.

## Current decision and limits

No activation patch, variables, active intent, workflow rerun, tag, Release, signed evidence, HTTP mutation, or Production access occurred. The sequence is `PASS` for contract-level planning, `NOT RUN` for actual GitHub workflow rerun delivery, and `BLOCKED` for live Publisher/publication until the approvals above and actual source identities exist.

GitHub references: [workflow events and `workflow_run`](https://docs.github.com/en/actions/reference/workflows-and-actions/events-that-trigger-workflows), [re-running workflows and jobs](https://docs.github.com/en/actions/how-tos/manage-workflow-runs/re-run-workflows-and-jobs), and [workflow variables including run ID and attempt](https://docs.github.com/en/actions/reference/workflows-and-actions/variables).
