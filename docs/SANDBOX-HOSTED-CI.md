# Sandbox Hosted CI bootstrap

Status: proposed; merge and runner activation require owner approval.
Scope: `oangsa/RoLauncher-release-sandbox` (`1423257712`) only.
Reviewed bootstrap main: `07d57c252022fe648f089045412d79e336263a80` (PR #2).

## Changes

- Remove literal `false &&` only from Branch flow, Windows checks, Ubuntu packaging and the Ubuntu/Arch matrix.
- Keep sandbox name/ID guards, pinned Actions, permissions, dependencies and main-push upload conditions unchanged.
- Keep protected promotion, beta and historical owner-evidence PoC jobs hard-disabled.
- Retain unenrolled owner policy, absent release intents and unchanged publisher limits.
- Run the offline regression suite on Windows, Ubuntu and Arch; package deterministic inert fixtures without application builds.

## Approval sequence

1. Recheck sandbox main and the absent `dev` ref before creating anything; stop if either differs from the reviewed snapshot.
2. Obtain owner authorization to create `dev` at the reviewed main, without changing settings or controls.
3. Push `codex/sandbox-hosted-ci` with `[skip ci]` in its HEAD commit and open a draft PR targeting `dev`.
4. Keep that PR unmerged and undispatched until owner authorization for hosted runner execution.
5. After runner approval, add an empty commit without a skip marker; record its SHA and wait for push and PR checks.
6. Require all five contexts to succeed on the exact applicable revision before requesting the owner merge into `dev`.
7. Open the separate `dev` to `main` PR; verify its exact five contexts and obtain owner approval before merging.
8. Verify the resulting main push runs both suites and uploads both expected artifact groups; independently inspect downloaded bytes.

`[skip ci]` is a preparation hold using [GitHub's native skip mechanism](https://docs.github.com/en/actions/how-tos/manage-workflow-runs/skip-workflow-runs).
It leaves checks pending; it supplies no admission, test success or merge authority.
Do not remove the hold through a dispatch, new commit or merge before runner approval.

No branch-policy exception is needed: existing admission accepts `codex/*` to `dev`, then official `dev` to `main`.
Direct `codex/sandbox-hosted-ci` to `main` remains rejected.
No stable release, synthetic release intent or governance bypass is needed to bootstrap this flow.

## Exact check contexts

- `Branch flow`
- `Windows checks`
- `Linux checks and package (Ubuntu 24.04)`
- `Linux checks (Ubuntu)`
- `Linux checks (Arch)`

Keep source SHA, PR merge revision, run ID, attempt, job outcomes and workflow URLs together.
Skipped, pending and local results do not establish hosted success.
Strict required-check Rulesets belong to the separately approved governance phase; do not install them before bootstrap checks are available.

## Artifact boundary

Only `push` to `refs/heads/main` uploads `release-files-attempt-N` and `release-linux-files-attempt-N`.
PR, feature, dev and manual runs do not upload those groups.
Windows setup bytes are an invalid non-PE placeholder; ZIP/TAR payloads are inert and source ZIP matches exact Git blobs.

Main-push artifact verification must check inventories, source SHA, byte hashes and deterministic metadata.
Publisher and beta remain hard-disabled even when CI succeeds.
No tag, Release, signer enrollment, inbox, production change or mutation probe is authorized here.

## Local validation

1. Run `python scripts/offline_tests.py` with Python 3.13+, Git and OpenSSH supporting `ssh-keygen -Y`.
2. Run Actionlint against `.github/workflows/*.yml` and inspect the exact diff.
3. Generate both fixture groups twice from the committed source and compare bytes and source ZIP Git blob hashes.

Retain local logs separately from public owner evidence.
Local disposable cryptographic test keys are never enrolled and are removed after tests.
Hosted execution and main artifact validation remain blocked until their approvals and real GitHub evidence exist.
