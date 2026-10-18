# Sandbox owner evidence enrollment

Enrolled in sandbox main by owner-merged PR #8, commit `b010f87fdefe1283e8e0fc417341a6fb96e9ccee`.
Enrollment permits verification of the named public identity; it grants no operational signature or publication authority.

## Exact identities

- Repository: `oangsa/RoLauncher-release-sandbox`, ID `1423257712`; owner ID `71574088`.
- Inbox: [Issue #5](https://github.com/oangsa/RoLauncher-release-sandbox/issues/5), dedicated evidence only.
- Public key: `ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIJPXo+4JhA/+CwDnDNJYnUctFyayOVMwOMZLG1hMGhfX`.
- Fingerprint: `SHA256:jG13DdI7llxXe3kfcJ2xnu8kftf2xe41QMv8hYkuuiQ`.
- SSH namespace: `rolauncher-sandbox-lifecycle-controls-v1`; principal: `github-user-71574088`.
- Reviewed canonical controls SHA256: `c48b4ebe3972abe2d5fe75b2ef7e5a0f70065c3b7e5c71a7bc9cd8a18d09c368` (7,264 bytes).

The digest covers all seven complete Rulesets and bypass arrays, effective main/dev rules and native immutability.
Any changed snapshot requires renewed disclosure review; missing privileged metadata fails closed.
Explicit owner approval of this exact digest and signer is required before enrollment into main.

## Local Windows signing boundary

1. Keep the existing encrypted dedicated private key on the owner's Windows machine; never place it in GitHub, CI, containers, artifacts or this repository.
2. Use local OpenSSH supporting `ssh-keygen -Y`; enter the passphrase only in the owner's local terminal.
3. Obtain separate authorization before running the existing attended helper or posting any preflight/final response.

Phase C performs no operational signing or Issue comments; regressions use disposable test-only keys.
Fresh evidence remains bound to source, workflow run, attempt, phase and challenge, with 120-second TTL and 45-second collection limit.

## Phase D prerequisites

- Owner-authorized enrollment merges, passing exact main CI, and live policy/control readback.
- Separate review and authorization for publisher activation, operational attendance, synthetic intents/tags/releases and mutation/fault tests.
- Demonstrated Windows-to-Ubuntu signing acceptance, real runner metadata visibility, large-upload recovery and native immutable release behavior.

The Publisher workflow requires both `RELEASE_PROMOTION_ENABLED` and `PHASE_D_LIVE_AUTHORIZED`. Live repository variable and operation-plan state is `VARIABLE_STATE_NOT_VERIFIED`; do not infer that the workflow is operationally disabled or authorized.
The v0.0.900 intent and two unpublished same-tag drafts exist in the sandbox, but enrollment did not authorize their publication. No signed evidence or Release publication is authorized by enrollment; Production remains read-only.
The [lifecycle validation plan](SANDBOX-RELEASE-LIFECYCLE.md) remains future work under separate approval.
