# Phase D first-live activation checklist

**PREPARED — NOT AUTHORIZED FOR ACTIVATION**

Every item is a separate owner approval. Bind each approval to the exact revision, run/attempt, plan digest, and proposed action. A checked item does not approve later items. Stop if any identity, evidence, variable value, or source readback differs.

Current review state: PR #20 is open at `67f7bff270329090104b8d14c3bc37f6ec689dc0`; activation proposal is not merged; `VARIABLE_STATE_NOT_VERIFIED`; no candidate intent, source SHA, trusted activation SHA, or executable plan is ready. This checklist authorizes nothing by itself.

## Approval ladder

1. [ ] **Candidate-preparation PR merge.** Owner reviews and separately merges PR #20 into dev. Record its exact merge SHA and revalidate this activation proposal against the resulting dev head. Do not merge or close PR #20 as part of activation preparation.
2. [ ] **Activation PR merge into dev.** Owner reviews the guarded workflow diff, plan-binding fix, tests, docs, exact-head CI results, and PR #20 dependency. This merge only updates dev and does not authorize activation.
3. [ ] **Activation PR promotion into main.** Owner separately approves the exact source/head SHA and proposed dev-to-main promotion after all promotion checks pass. The Publisher remains guarded by both runtime variables.
4. [ ] **Activation-variable verification.** Before the main workflow is installed, owner independently verifies `RELEASE_PROMOTION_ENABLED` and `PHASE_D_LIVE_AUTHORIZED` are false or unset and `PHASE_D_OPERATION_PLAN` contains no executable plan. Current state is `VARIABLE_STATE_NOT_VERIFIED`; do not proceed until verified.
5. [ ] **Intent-only candidate PR merge.** Owner reviews a new intent-only candidate change through dev and into main. Confirm the intent contains no application/code changes beyond the reviewed release intent and identify the exact main commit SHA `C`.
6. [ ] **Exact operation-plan authorization.** Owner approves canonical plan bytes/digest binding repository ID `1423257712`, owner ID `71574088`, trusted workflow SHA, candidate source SHA `C`, publisher run/attempt policy, `v0.0.900`, stable channel, `fault: null`, and `faults_approved: false`. Do not guess SHAs or configure a plan in advance of the exact revisions.
7. [ ] **Runtime variable activation.** Owner separately enables both flags and installs only the approved plan after verifying the actual main workflow SHA and current candidate source. This is the first authorization that makes a matching Publisher job eligible.
8. [ ] **Linux rerun authorization.** Owner separately authorizes the exact successful Linux main-push run ID and a controlled rerun. Verify the run ID, incremented attempt, unchanged source SHA `C`, delivered `workflow_run.completed` event, and unique matching CI run. No offline test proves GitHub event delivery.
9. [ ] **Preflight owner signing and public evidence.** Owner reviews the exact preflight challenge and live control snapshot, independently authorizes signing/posting, confirms enrolled Ed25519 key and disclosure digest, and approves the 120-second evidence TTL and 45-second collection window.
10. [ ] **Final signing and publication.** After exact staging, receipt, source, artifact inventory, and fresh security rereads, owner separately signs the distinct final challenge. Publication may proceed only with fresh accepted evidence and an exact scoped publish PATCH.
11. [ ] **Live capacity and mutation-denial probes.** Owner separately approves each exact inert asset size, API request, HTTP expected result, and before/after hash plan. Do not infer native immutability from offline tests, Ruleset rejection, or an ambiguous 403.
12. [ ] **Cleanup or guard restoration.** Owner reviews retained immutable fixture IDs, evidence/audit artifacts, and exact cleanup actions. Restore the literal hard-disable or disable only separately approved variables through reviewed changes; do not assume immutable tags/releases can be deleted.

## Stop conditions

- Any check is pending, skipped, attached to another head/base/test-merge SHA, or failed.
- Either activation flag or operation-plan state is unknown before main installation.
- Source, trusted SHA, run ID/attempt, intent, Linux/CI relationship, artifact digest, owner identity, channel, or tag differs from the approved scope.
- A rerun event is absent, ambiguous, unsuccessful, stale, duplicated, or not bound to the expected candidate SHA.
- A signature is invalid, expired, replayed, edited, or bound to another challenge/run/attempt.
- Native immutability evidence is missing, contradictory, or classified from an ambiguous 403.
- A mutation is outside the exact tag, draft, asset, receipt, or final publish scope.
- Capacity limits, asset integrity, freshness, or workspace cleanup cannot be demonstrated.

## Required evidence to retain

- Main/dev/PR merge SHAs; exact activation PR head, base, and test-merge SHA.
- All five required CI context names, conclusions, workflow run IDs, attempts, and run URLs.
- Candidate intent digest, source SHA, CI/Linux run IDs and attempts, artifact IDs/sizes/digests, and source ZIP/Git-tree verification.
- Exact operation-plan digest and the owner approval for each stage.
- Distinct preflight/final challenge, response references, policy/control digest, and sanitized append-only route ledger.
- Tag, draft/release ID, asset list/hashes, receipt digest, final HTTP result, immutable readback, and independent downloaded-byte audit.
- Any live denied-probe plan and exact before/after resource hashes. Never retain tokens, authenticated upload URLs, session cookies, or private key material in the ledger.
