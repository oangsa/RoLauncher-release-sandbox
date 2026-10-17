# Architecture C non-publishing sandbox

This repository is a test only. No release intent, tag, GitHub Release, production mutation, or publishing credential is used.
Production `protected_branches(strict=True)` is unchanged; this PoC validates exact sandbox fixture evidence, not production release authorization.

## Protocol

- Trusted `main` workflow generates separate random preflight/final challenges.
- Pinned upload-artifact action exposes each challenge during the active job.
- Windows owner helper fetches both live canaries using existing GitHub CLI authentication, signs locally with the approved test-only key, and posts to issue #1.
- Ubuntu verifies owner comment identity, OpenSSH namespace/key, exact source/workflow/run/attempt/phase/nonce binding, collection window, expiry, and full expected fixture projections.
- Each gate tests nine signed negative vectors, a valid response, and same-challenge replay; final additionally rejects preflight replay.
- Both fixture definitions remain unchanged. Their doubled `refs/tags/` patterns do not establish real tag protection; only field visibility and protocol behavior are tested.

## Windows owner commands

Requirements: Python 3.13+, GitHub CLI logged in as `oangsa`, OpenSSH with `ssh-keygen -Y`, and the approved local test key corresponding to `allowed_signers`.
No private key is stored in this repository. Do not reuse this key for production.

1. Obtain this trusted sandbox checkout and current commit SHA. Run `python -m unittest -v test_poc`.
2. Start a fresh dry run from Actions > Owner evidence sandbox dry run > Run workflow (main).
3. Use its publisher/test workflow run ID and exact commit SHA:

```powershell
python .\poc.py attend --run-id RUN_ID --expected-sha COMMIT_SHA --key 'C:\local-private\owner_test_ed25519' --approve-public-evidence
```

4. Helper posts clearly marked synthetic negative test cases plus real canary evidence for each gate. It requires explicit public-posting flag.
5. Open Actions run and inspect both gate results and `dry-run-results-RUN_ID-ATTEMPT` artifact. Helper posting success alone is not Ubuntu acceptance.

The job waits at most ten minutes per gate, with a 30-minute total job timeout; evidence lifetime remains 60 seconds from collection start.
No environment approval gate is provisioned by this minimal test. Production timeout/approval policy requires separate review.

## Boundaries and limitations

- The only owner-side mutation implemented is posting JSON comments to this sandbox's issue #1.
- Runner client implements fixed GET routes only. Workflow grants Contents/Actions/Pull requests read; no secrets are supplied.
- Runtime records whether its own token sees bypass arrays; owner evidence never substitutes an absent array with an empty list.
- Fixture projections bind every configured ID, source, target, enforcement, conditions, rule, and bypass actor.
- Test negative payloads are deliberately altered copies and do not change live Rulesets.
- `test-vector.json` contains public signed synthetic vectors, not a private key or a release intent.
- Private-key revocation, production authority, live release immutability, actual publication/retry, public-data policy, and full hostile-input hardening still need production work and independent review.
- Owner helper captures GitHub CLI responses before applying size limits; production requires streaming bounds. No claim of full publisher hardening is made here.

Cancel the run to stop; a failed/expired challenge needs a new run/attempt and new evidence. Never extend an old signature's expiry.
