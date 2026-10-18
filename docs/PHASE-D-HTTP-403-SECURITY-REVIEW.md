# Phase D HTTP 403 security review

## Status

This is a code remediation review, not Phase D operational acceptance. Prior request context reports readiness run `39099161592` attempt 1 as `BLOCKED`, with seven Rulesets, 7,264 canonical control bytes, immutability enabled, `enforced_by_owner: false`, and digest `c48b4ebe3972abe2d5fe75b2ef7e5a0f70065c3b7e5c71a7bc9cd8a18d09c368`. These live facts were supplied with the request; this change did not re-run or independently verify them. No operational signing, readiness dispatch, publication, or release mutation was performed.

| Status | Meaning |
|---|---|
| `RUNNER_VISIBILITY_BLOCKED` | The runner cannot independently read a required privileged setting. Keep readiness blocked unless the narrowly documented owner-attestation path is separately accepted. |
| `OWNER_CONTROLS_VERIFIED` | The owner-authenticated control snapshot passed canonical disclosure validation. This does not establish runner visibility or authorize a release. |
| `OWNER_SIGNED_EVIDENCE_ACCEPTED` | A fresh, valid owner signature passed both bound authorization gates. This establishes the evidence contract only. |
| `PUBLICATION_AUTHORIZED` | Separate publisher authorization and operational controls permit a publication. This status was not reached. |

## Root cause and affected path

`release_promotion.github_api()` previously discarded HTTP response headers and body, then raised the same status-only `RuntimeError` for every HTTP 403. `PhaseDEvidence.fresh()` matched that exact string for `GET /immutable-releases` and treated the result as expected visibility denial. Rate limiting, secondary throttling, abuse controls, and other 403 causes therefore looked identical to a permission restriction.

The path is `github_api()` → HTTP exception handler → `PhaseDEvidence.gate()` / `fresh()` → `LifecycleEvidence` freshness checks → `AuditedTransport` → publisher mutation forwarding. The fix preserves a bounded typed error through this path. No mutation retry was added.

## GitHub response evidence and classification

GitHub documents that `Resource not accessible by integration` can indicate insufficient GitHub App or token permissions, and documents the accepted-permissions response header. The immutable-release endpoint requires repository Administration read permission. GitHub documents primary rate-limit responses, secondary rate-limit responses, and `Retry-After` handling separately. See [immutable release settings](https://docs.github.com/en/rest/repos/repos#check-if-immutable-releases-are-enabled-for-a-repository), [REST API troubleshooting](https://docs.github.com/en/rest/using-the-rest-api/troubleshooting-the-rest-api), [rate limits](https://docs.github.com/en/rest/using-the-rest-api/rate-limits-for-the-rest-api), and [GitHub App permissions](https://docs.github.com/en/apps/creating-github-apps/registering-a-github-app/choosing-permissions-for-a-github-app).

The code accepts an owner-attested visibility result only for the exact HTTPS `api.github.com` `GET /repos/oangsa/RoLauncher-release-sandbox/immutable-releases` response when all of these hold:

- HTTP status is 403.
- The JSON `message` exactly matches GitHub's documented integration-permission response; duplicate or malformed JSON is rejected.
- `X-Accepted-GitHub-Permissions` exactly identifies `administration=read`.
- `X-RateLimit-Remaining` is a valid positive integer and `Retry-After` is absent.
- Fresh, cryptographically valid owner evidence already matches the challenge, disclosure digest, repository/source, run, attempt, phase, and expiry bindings enforced by the existing gates.

The error message is documented evidence, not a generic substring heuristic. The positive quota value and accepted-permissions header are additional required checks; absence of rate-limit headers alone is never interpreted as permission denial. Primary-rate-limit, secondary-rate-limit, abuse-protection, ambiguous, incomplete, inconsistent, or unrecognized responses remain blocked. This classification is limited to this endpoint and grants no release authority.

## Direct and owner-attested observations

A successful immutable-settings response must be an object with boolean `enabled: true` and boolean `enforced_by_owner`; both required fields must canonically match the fresh signed owner snapshot. Disabled, changed, missing, null, or malformed values reject the gate.

On the explicit permission response, only immutable-settings visibility is marked `OWNER_ATTESTED`. Ruleset inventories and visible bypass arrays continue to be fetched and compared independently by the runner. The audit ledger records `RUNNER_VISIBLE` or `OWNER_ATTESTED` without changing existing readiness status fields.

The live publisher passes `FrozenArtifacts(AuditedTransport(...))` into the evidence gate. `FrozenArtifacts` explicitly forwards visibility observations, and fails closed if its underlying transport cannot record them. An end-to-end offline regression verifies both ledger values through this wrapper and checks that the ledger contains no token, headers, or request body.

HTTP diagnostics expose only method, status, endpoint path, validated accepted-permission text, validated rate-limit remaining, and Retry-After presence. Error bodies are read with a 16 KiB cap for exact classification, then discarded; they are not included in errors or logs. API redirects are rejected for JSON responses. Timeouts, resets, malformed JSON, 401, 404, 429, and 5xx errors fail closed.

## Freshness and remaining risk

The existing 120-second evidence TTL, 45-second collection limit, 1,200-second owner-attendance window, two-gate signature verification, replay protection, and fresh checks before release mutations remain in force. No read-only retries extend evidence freshness.

A runner cannot detect a hidden immutable-settings change while GitHub denies that setting's visibility. The owner-attested branch therefore relies on the signed snapshot's short freshness window and the documented endpoint-specific permission response; it does not claim independent observation. Any response that fails the exact contract stays blocked. A change after the last fresh observation and before GitHub applies a mutation remains a narrow TOCTOU window inherent to remote API operations.

## Validation

TDD reproduced both the generic-403 classification defect and the missing ledger forwarding through the publisher wrapper. Regressions cover matching and contradictory HTTP 200 responses; rate limits; `Retry-After`; ambiguous and documented permission 403s; other HTTP failures; timeouts, resets, malformed JSON, and redirects; both signed-evidence gates; and changes immediately before staging or publication. Rejection tests verify no release mutation crosses the boundary.

- Offline suite: **PASS**, 125 tests.
- Python syntax and trailing-whitespace/final-newline scans: **PASS**.
- `actionlint` v1.7.12: **PASS**, all six workflows; SHA-256 matched the official release digest.
- Hosted CI: the PR description records the five required contexts for its current HEAD.
- `git diff --check`: **NOT RUN**; the materialized copy reports it is not a work tree for diff operations. The equivalent whitespace scan passed.
## Unresolved operational blockers

The original positive 2× capacity blocker remains unresolved, and the prior live readiness result remains `BLOCKED`. No live owner signing, signed evidence posting, synthetic publication, recovery exercise, or immutable-resource enforcement test was performed. This code review does not satisfy those operational acceptance steps.
## Contract changes and next authorization

The existing authorization contract is preserved: this permission classification permits only an owner-attested setting observation after the existing signed evidence checks. It does not relax source admission, expand publication scope, change credentials, or activate Publisher, Beta, readiness, or historical PoC workflows. There is no new proposed contract change.

Before live signing or publication, an owner/security reviewer must approve the remediation PR and separately authorize any live readiness work. Operational owner signing, signed evidence posting, publication, fault injection, and protected-branch promotion require their own scoped authorization. The eventual `dev` to `main` promotion also requires separate approval.
