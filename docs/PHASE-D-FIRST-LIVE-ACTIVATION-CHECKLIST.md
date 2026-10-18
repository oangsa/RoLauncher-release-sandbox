# Phase D first-live activation checklist

**PREPARED — NOT AUTHORIZED FOR ACTIVATION**

Every item is a separate owner approval. Bind it to the exact revision, run/attempt, plan digest, and proposed action. Completing one item does not approve later items.

Current verified state (2026-10-18): `main` is `b19226ccc5a28fe2632bf6d3c4d6f4b2eb9ab230`; PR #20 merged into `dev` as `f5c36daca15d569e53eac651be9a795dd71fb9e6`. PR #21 remains open and Draft after a transparent merge of updated `dev` into its branch. The refreshed HEAD, base, and test-merge SHA are recorded in the live PR metadata and body for owner review. The inert candidate proposal is on `dev`, but `.github/release-intents/` is absent. Variable state remains `VARIABLE_STATE_NOT_VERIFIED`.

## Approval ladder

1. [x] **Candidate-preparation PR #20 merged and verified.** It merged at `f5c36daca15d569e53eac651be9a795dd71fb9e6`, with parent `ba09c98ee602f9da76ccdf935a6bf1f70125fc80` and approved head `67f7bff270329090104b8d14c3bc37f6ec689dc0`. All five required post-merge contexts passed on the merge SHA. The proposal remains inert.
2. [x] **Synchronize activation PR #21.** A transparent merge brought current `dev` into its existing branch history without rewriting commits. The candidate proposal is present and `.github/release-intents/` remains absent. PR #21 stays Draft; local validation passed 140 offline tests, Actionlint v1.7.12 across all six workflows, and Python syntax parsing. Review the exact hosted contexts on the refreshed HEAD before owner approval.
3. [ ] **Review and separately approve PR #21's exact HEAD for merge into `dev`.** Record its current HEAD, base, test-merge SHA, security diff, all five hosted contexts, and source identities. Approval for an earlier HEAD does not apply.
4. [ ] **Merge PR #21 into `dev` through the protected PR path.** Verify the actual merger, merge SHA and parents, unchanged main, and all five successful post-merge contexts. This does not authorize main promotion or Publisher operation.
5. [ ] **Verify activation variables before any promotion to `main`.** Using an authorized authenticated owner interface, independently confirm `RELEASE_PROMOTION_ENABLED` and `PHASE_D_LIVE_AUTHORIZED` are false or unset, and `PHASE_D_OPERATION_PLAN` is absent, unset, or demonstrably non-executable. If any value is unreadable, record `VARIABLE_STATE_NOT_VERIFIED` and keep main promotion `BLOCKED`. If a flag is true or the plan is executable, stop.
6. [ ] **Approve the exact `dev`-to-`main` activation promotion.** Review the precise source and test-merge SHAs, required checks, branch rules, and the verified variable-state evidence. This is a separate owner decision.
7. [ ] **Install the activation workflow on `main` through a protected, owner-approved PR.** Do not use direct pushes, bypasses, or a stale reviewed revision.
8. [ ] **Immediately re-read main and variable state after installation.** Record the resulting main SHA and verify the expected Publisher workflow is present, both flags remain false or unset, and no executable operation plan is configured. No candidate run is operationally authorized until this authenticated readback succeeds.
9. [ ] **Prepare and merge a separate intent-only candidate PR.** Promote the reviewed intent through `dev` and the protected owner-approved path into `main`; include no application or unrelated workflow changes. PR #20's `intent.proposed.json` is inert and is not an active intent.
10. [ ] **Verify the final candidate source.** Record source SHA `C`, confirm `main == C`, require all five source checks, and verify run IDs/attempts, artifact IDs, digests, inventory, provenance, and source ZIP/Git-tree match.
11. [ ] **Approve the exact operation plan.** Bind canonical plan bytes and digest to repository ID `1423257712`, owner ID `71574088`, trusted workflow SHA, source SHA `C`, exact run/attempt policy, tag `v0.0.900`, stable channel, `fault: null`, and `faults_approved: false`. Do not configure it before the exact identities exist.
12. [ ] **Separately authorize runtime activation.** Only after exact-plan approval, the owner may enable both flags and configure that exact plan. Record the authenticated values and approved revision.
13. [ ] **Separately authorize the Linux rerun.** Identify the successful Linux main-push run and approve its controlled rerun. Verify the same run ID, incremented attempt, unchanged source SHA `C`, delivered `workflow_run.completed` event, and unique matching CI run.
14. [ ] **Separately authorize Preflight signing and evidence posting.** Review the live challenge, controls snapshot, key enrollment, disclosure digest, exact evidence, 120-second TTL, and 45-second collection window before local owner signing.
15. [ ] **Separately authorize Final signing and publication.** Require exact staging, receipt, source and asset inventories, fresh security readbacks, a distinct final challenge, and fresh accepted evidence before the scoped publish request.
16. [ ] **Separately authorize live capacity and immutable-resource denial probes.** Approve each exact inert asset size, API request, expected response, and before/after resource hash plan. Offline tests and ambiguous 403 responses do not prove native immutability.
17. [ ] **Separately authorize cleanup or guard restoration.** Review retained fixture IDs, evidence and audit artifacts, and each cleanup action. Restore the hard-disable or change approved variables only through separately reviewed actions; do not assume immutable tags or Releases can be deleted.

## Mandatory stop gate

Before the activation workflow is promoted to `main`:

- An authorized authenticated owner interface must show both activation flags false or unset.
- The operation plan must be absent, unset, or demonstrably non-executable.
- If any state cannot be read, record `VARIABLE_STATE_NOT_VERIFIED` and keep promotion `BLOCKED`.
- If either flag is true or an executable plan exists, stop.
- Merging into `dev` is not evidence that this gate passed.
- Repeat the authenticated variable and plan readback immediately after the workflow is installed on `main`, before any candidate run is operationally authorized.

## Stop conditions

- A required check is pending, skipped, stale, failed, attached to another revision, or attached to another base or test-merge SHA.
- An owner approval does not name the exact revision and intended action.
- A variable or plan value is unknown, changed, true, or executable at a stop gate.
- Source, trusted SHA, run ID/attempt, intent, Linux/CI relationship, artifact digest, owner identity, channel, or tag differs from approved scope.
- A rerun event is absent, ambiguous, unsuccessful, stale, duplicated, or not bound to the expected candidate SHA.
- A signature is invalid, expired, replayed, edited, or bound to another challenge/run/attempt.
- Native immutability evidence is missing or contradictory, or an ambiguous 403 is used as proof.
- A mutation is outside the exact tag, draft, asset, receipt, or final publish scope.
- Capacity limits, asset integrity, freshness, or workspace cleanup cannot be demonstrated.

## Required evidence to retain

- Main/dev and PR merge SHAs, merge parents, merger identities, timestamps, and Git trees.
- Exact PR #21 HEAD, base, test-merge SHA, five required context conclusions, workflow run IDs/attempts, and run URLs.
- Candidate intent digest, source SHA, CI/Linux run IDs and attempts, artifact IDs/sizes/digests, and source ZIP/Git-tree verification.
- Authenticated variable-state readbacks before and immediately after main installation.
- Exact operation-plan digest and separate owner approval for each stage.
- Distinct Preflight/Final challenges, response references, policy/control digest, and sanitized append-only route ledger.
- Tag, draft/Release ID, asset list/hashes, receipt digest, final HTTP result, immutable readback, and independent downloaded-byte audit.
- Any denied-probe plan and exact before/after resource hashes. Never retain tokens, authenticated upload URLs, session cookies, or private key material in the ledger.
