# RoLauncher 0.0.901

**SANDBOX ONLY — inert lifecycle fixtures, no application binaries.**
This is the Architecture C sandbox port for oangsa/RoLauncher-release-sandbox (1423257712).
Hosted builders are active. Publisher execution is gated by `RELEASE_PROMOTION_ENABLED` and `PHASE_D_LIVE_AUTHORIZED`; their live values are not verified. Beta and historical PoC workflows remain hard-disabled.
Phase C signer, inbox and disclosure policy are described in [Owner evidence enrollment](docs/OWNER-EVIDENCE.md).
The v0.0.900 candidate remains unpublished and has two same-tag draft Releases; do not resume or mutate them.
The upcoming v0.0.901 fixture tests corrected draft recovery and is not a usable application.
Live signing and publication require separate owner approval.

## Offline checks

1. Use Python 3.13+, Git and OpenSSH supporting ssh-keygen -Y.
2. Run python scripts/offline_tests.py.
3. Inspect the complete diff and [Hosted CI approval sequence](docs/SANDBOX-HOSTED-CI.md) before remote execution.

Tests block Python network connections and use only disposable temporary test keys.
All simulated publication state lives in memory; no GitHub publishing test runs.
The old non-publishing PoC remains historical and is locally guarded false.

## Hosted builders

1. Hold CI execution until owner approval; follow the feature/codex to dev to main PR flow.
2. Builder CI creates deterministic inert Windows/Linux fixtures from exact Git objects.
3. Source CI must be a real push/main run after an owner-authorized merge.
4. Publisher requires complete strict controls, fresh owner signatures at both gates and native immutable readback.

The v0.0.900 release intent is checked in, but its duplicate drafts make that candidate ambiguous. The upcoming v0.0.901 fixture exercises bounded draft recovery and Release-ID admission.
Small M2 fixtures do not prove large-upload, expiry or native GitHub behavior.

See docs/SANDBOX-PORT.md for identity pins and remaining gates.
Current Phase D implementation and live-approval gates are recorded in [Phase D validation](docs/PHASE-D-VALIDATION.md).
The current duplicate-draft recovery decision and owner gates are recorded in [draft recovery remediation](docs/PHASE-D-DRAFT-RECOVERY-REMEDIATION.md).
The authoritative docs/SANDBOX-RELEASE-LIFECYCLE.md is copied from the production merge.
Historical PoC instructions are archived in docs/POC-README.md and grant no M2 publishing authorization.
