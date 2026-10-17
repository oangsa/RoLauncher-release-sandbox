# RoLauncher 0.0.900

**SANDBOX ONLY — inert lifecycle fixtures, no application binaries.**
This is the Architecture C sandbox port for oangsa/RoLauncher-release-sandbox (1423257712).
Hosted CI activation is proposed; publisher, beta and historical PoC remain hard-disabled.
No signer, inbox or release intent is enrolled.

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

No release intent is checked in.
The synthetic version metadata and notes exercise the unchanged publisher data contract.
Small M2 fixtures do not prove large-upload, expiry or native GitHub behavior.

See docs/SANDBOX-PORT.md for identity pins and remaining gates.
The authoritative docs/SANDBOX-RELEASE-LIFECYCLE.md is copied from the production merge.
Historical PoC instructions are archived in docs/POC-README.md and grant no M2 publishing authorization.
