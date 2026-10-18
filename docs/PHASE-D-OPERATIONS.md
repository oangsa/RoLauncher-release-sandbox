# Phase D operations and cleanup

This is an operator runbook, not authority to execute. Existing [lifecycle acceptance](SANDBOX-RELEASE-LIFECYCLE.md) still applies.
Implementation PR merges, activations, attendance, public signed posts, exact fixtures, real mutation/fault probes and cleanup require separate approval.

## Review and integration

1. Review feature branch into dev; require all five exact contexts and owner-approved merge commit.
2. Promote official dev to main; require exact test-merge checks and separate owner merge approval.
3. Verify resulting main, policy, all five checks, artifact/source integrity and unchanged complete controls digest.
4. Review readiness activation and Publisher activation as separate proposals; readiness dispatch is GET-only and does not authorize publication.
5. After approved dispatch, record run/attempt/source, exact declarations and visibility results; missing bypass/immutability privilege is BLOCKED.

This branch proposes the Publisher guard behind two explicit runtime variables; it is not authority to merge or enable them. Historical PoC and Beta workflows stay hard-disabled.

## Publication approval sequence

1. Owner approves exact permanent fixture names: proposed first stable `v0.0.900`, beta `beta-v0.0.900`, hotfix `v0.0.901`, and independent native control `sandbox-native-immutable-0.0.900`.
2. Use minimum fixtures; each candidate requires its own source/intent/CI authority and both attended gates. These proposals are not created by development.
3. Review the separate publisher activation patch and exact operation scope; obtain owner approval before changing guards or variables.
4. Authorize only sandbox publisher credentials and explicitly approved faults/probes. Never use Production credentials or move the operational private key.
5. Keep stable Publisher/Beta/PoC activation independent; beta source/tag workflow needs its own reviewed authorization.
6. Before any live run, set approved scope only after exact trusted/source commits are known; stale scope must fail closed.

For large live cases, separately review `phase-d/large-builders.activation.patch` before producing the exact candidate's main-push artifacts.
It changes only inert package generation; source run admission, named inventories, action pins and upload guards remain intact.
Choose exact dataset, source and version before publication; never change accepted artifact bytes under an already published tag.

No repository variables are changed by this proposal. Their live state is `VARIABLE_STATE_NOT_VERIFIED`; before any default-branch promotion, the owner must independently verify both flags are false/unset and no executable operation plan is configured.
The operation-scope example is inert and rejected until placeholders become exact reviewed 40-hex source/trusted SHAs.
Runtime binds its actual publisher run/attempt; this configuration grants no signature authority and cannot replace either owner-attended gate.

## Windows owner attendance

1. Verify current complete controls match enrolled digest, policy/inbox and actual trusted publisher workflow/run/attempt/source.
2. Owner separately authorizes signing and public evidence, then runs existing `scripts/owner_evidence.py` locally with exact `--run-id`, `--trusted-sha`, `--source-sha`, synthetic `--version`, dedicated local `--key` and `--approve-public-evidence`.
3. Enter passphrase only in local Windows OpenSSH; never in chat, Actions, a container or artifact.
4. Review each distinct challenge and live snapshot; existing helper requires explicit local confirmations before each of preflight and final.
5. Preserve 45-second collection/confirmation limit, 120-second TTL and 20-minute attendance wait. Never retry a possibly committed public POST blindly.

This implementation does not invoke that command or sign/post anything using the owner's key.

## Audit and recovery

1. Preserve source/main/PR/run/attempt identities, two challenge/response references and exact controls/policy digest.
2. Retain `owner-evidence/` stage ledgers and acceptance state as existing publisher audit artifacts; do not expose credentials or private key material.
3. On interruption, use a new attempt and fresh attendance. Existing identical assets/receipt/tag remain; only missing verified assets may upload.
4. After publication, run `phase_d_audit.verify_release` through existing sandbox GET transport; download all bytes and separately GET immutable Release.
5. For denied probes, owner approves exact `denied_probe_plan` digest and permanent target IDs first; wrap same sandbox credential in `AuditedTransport`, explicitly allow only `PHASE-D-DENIED.txt`, then invoke `phase_d_probes.run`.
6. Generate `native_control_proposal` from the enrolled complete snapshot; owner separately approves/provisions that exact permanent control fixture. `verify_native_control` audits its numeric Release GET, downloaded inert asset and exclusion from every active tag Ruleset.
7. Feed that independently verified native baseline into the same exact-plan denied-probe driver. Stop on any accepted mutation or changed resource; do not repair automatically.

Plans/probe functions have no automatic live entry point. Do not count local route rejection, missing HTTP status or tag Ruleset denial as native immutability proof.
Live download/transport recovery, real large-asset throughput and all acceptance scenarios need actual separately approved GitHub evidence.

## Cleanup approval

1. Propose restoring literal `false &&` for any separately activated workflow through protected PRs.
2. Propose unsetting only approved activation variables and revoking only temporary credentials; do not change bypasses, Rulesets or immutability without separate approval.
3. Preserve ledgers, receipts, IDs and downloaded hashes. Immutable fixtures may be permanent; never promise deletion or replace published bytes.
4. Recheck sandbox controls and Production read-only identity; document every retained fixture and unexecuted cleanup action.

`phase_d_audit.cleanup_plan` emits proposals only; it executes no cleanup or security-setting mutation.
Production enrollment/activation and v1.7.1 publication remain outside Phase D.
