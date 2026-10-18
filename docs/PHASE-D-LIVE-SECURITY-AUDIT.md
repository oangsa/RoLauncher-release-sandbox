# Phase D live security audit

Status: **source/offline and owner read-only checks PASS; live operational acceptance BLOCKED**.
Scope: sandbox ID `1423257712`; trusted inspected main `4df5c0b6a83374aa6f8b4d4e5c24ef384a585c70`; owner `71574088`.
No Ruleset, policy, security limit or operational owner key was changed.

## Readiness execution path

The smallest useful change reuses `phase_d_readiness.main`; no new credential, service or signing mechanism is needed.
`workflow_dispatch` is the sole event; job guards pin sandbox name, numeric ID and `refs/heads/main`.
Checkout uses exact `github.sha`, with persisted credentials disabled; all Actions remain SHA-pinned.

The script independently checks repository/event/ref/workflow-ref before constructing transport.
It GETs repository identity and current main SHA, then collects complete Ruleset/effective branch/native immutability evidence.
Its transport wrapper always supplies method GET; no publisher, signing helper, shell, private-key path or mutation method is reachable from this entry.

Missing bypass arrays or native privilege produce `privileged_controls: BLOCKED`; complete matching disclosure and strict branch checks are required for PASS.
A successful job alone cannot establish privileged visibility: independently inspect artifact content, expected 7 Rulesets, trusted SHA, run/attempt and digest.
Transport/API failure without a complete artifact is BLOCKED, never permission success; do not add owner PAT or Administration as a workaround.

## Permission review

| Declaration | Purpose in experiment | Limitation |
|---|---|---|
| contents: write | Reproduce Publisher's exact token context | GETs need only read; write is intentional experimental excess |
| actions: read | Match Publisher declarations | Does not authorize dispatch, rerun or publication |
| pull-requests: read | Match Publisher declarations | No PR merge/write capability requested |
| issues: read | Match Publisher declarations | No evidence comment write authorized |
| Administration absent | Preserve existing architecture | Missing bypass/immutability privilege must remain BLOCKED |

Reducing contents-write would be safer for a generic reader but would test a different permission context.
This proposal preserves exact declarations only for the manual trusted-main visibility experiment; owner approval must explicitly cover that token risk.
The script's GET-only behavior is not a server-enforced read-only token guarantee.

Expected workflow writes: one Actions run/log stream and `phase-d-readiness-<run>-<attempt>` artifact, 14-day retention.
Artifact contains visibility status/counts, approved digest and run identity, not raw privileged controls, signatures or secrets.
A revert through protected PR can restore `false &&`; it cannot erase previously disclosed logs/artifact contents or undo historical execution.

## Enrolled identity and public disclosure

- Inbox [Issue #5](https://github.com/oangsa/RoLauncher-release-sandbox/issues/5); namespace `rolauncher-sandbox-lifecycle-controls-v1`; principal `github-user-71574088`.
- Public key `ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIJPXo+4JhA/+CwDnDNJYnUctFyayOVMwOMZLG1hMGhfX`.
- Fingerprint `SHA256:jG13DdI7llxXe3kfcJ2xnu8kftf2xe41QMv8hYkuuiQ`.
- Complete controls SHA256 `c48b4ebe3972abe2d5fe75b2ef7e5a0f70065c3b7e5c71a7bc9cd8a18d09c368`; 7,264 bytes, including all seven active Rulesets and complete bypass arrays.
- Five Rulesets have explicit empty bypasses; canary 25300842 and beta-creation 25310363 each contain only RepositoryRole 5 / always.
- Effective main/dev protections, strict five checks and Actions App 15368 retained; native immutability enabled.

## Prepared owner signing procedure; NOT AUTHORIZED

1. After exact publisher activation/source/run approval, use the existing reviewed Windows helper from the trusted revision; verify the public fingerprint locally.
2. Record exact publisher run ID, run attempt, trusted/source SHAs and synthetic version from independent GitHub GETs. No publisher run exists for this proposal.
3. Only after separate signing and public-post approval, invoke `python scripts/owner_evidence.py --run-id <approved-id> --trusted-sha <approved-trusted-sha> --source-sha <approved-source-sha> --version <approved-synthetic-version> --key C:/Users/sukru/.ssh/rolauncher-sandbox-architecture-c-20261018 --approve-public-evidence` locally.
4. Inspect preflight challenge, type its exact APPROVE phrase, collect fresh complete controls, then type SIGN. Enter passphrase only in local OpenSSH.
5. Repeat independently for final after complete staging; never reuse a signature/nonce or copy the private key into GitHub, CI, containers, repository or chat.
6. Preserve 120-second TTL, 45-second collection/confirmation and 1,200-second attendance per gate. Abort changed source/policy/run/attempt, expiry, duplicate/edited/conflicting responses or canceled run.
7. On ambiguous POST, inspect Issue #5 and publisher independently; never blindly repost. Capture exact challenge/response references and acceptance state, without secrets.

The command above is a non-runnable template pending exact IDs and approval; it has not been executed.
Readiness dispatch cannot generate publisher challenges or validate real Windows-to-Ubuntu signing.
Operational challenge/response references: **NOT RUN**.

## Publication and denied-probe review

The publisher activation and large-builder patches remain unapplied; all three runtime variables remain unset.
Existing source admission, explicit scope, two gates, numeric Release ID pinning, cached artifact/source blobs, deterministic receipt and no-delete/no-overwrite behavior remain unchanged.
Original pinned security contracts, timeouts and limits remain intact; Beta and PoC stay independently held.

Proposed permanent identities are `v0.0.900`, `beta-v0.0.900`, `v0.0.901` and `sandbox-native-immutable-0.0.900`; none exists or is authorized.
For each denied-probe plan, approve exact digest, credential scope, numeric resource IDs, rewrite target and inert added/renamed asset before requests.
Actual HTTP 403/422 plus identical independent tag/assets/source readback is required; local rejection or tag Ruleset denial alone is insufficient native proof.

Unexpected mutation acceptance requires stop/quarantine, never automatic deletion/repair.
Final Release immutable readback, all-asset hashes, real HTTP denials and public owner evidence remain **NOT RUN**.
Readiness dispatch, protected merges, publishing and cleanup are separate owner gates.
