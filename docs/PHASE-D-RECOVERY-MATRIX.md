# Phase D recovery matrix

All rows below are automated local simulations through existing publisher authority and disposable SSH signatures.
Live API execution is NOT RUN; no simulated result is counted as native GitHub proof.

| Scenario | Observable invariant | Coverage |
|---|---|---|
| Wrong key/revoked key/namespace/principal | Reject; no preflight writes | Owner evidence suite and Phase D principal lookup |
| Wrong source/owner/repository/workflow/run/attempt/policy/phase | Reject exact binding; no writes | Original authority/owner suites retained |
| Noncanonical payload or comment wrapper | Reject even with valid signature; nonce not consumed | Phase D strict gate tests |
| Missing bypass/inventory/immutability/disclosure mismatch | Reject or BLOCKED; never infer empty arrays | Owner suite and readiness visibility test |
| Duplicate/edited/conflicting response, replay and timeout | Reject; preserve permitted draft at final gate | Original owner suite plus cancelled final wait |
| Interrupted artifact download | No challenge or mutations; fresh retry verifies full bytes | Phase D download recovery |
| Before tag, after tag, after draft | No duplicate committed writes; fresh attempt reconciles exact state | Phase D interruption matrix |
| First upload before/after acceptance, between uploads | Existing IDs/sizes/hashes retained; only missing names uploaded | Phase D interruption matrix |
| Complete staging, final wait cancelled or denied | Only matching authorized draft/assets remain | Phase D final gate test |
| Final authorization then pre-publication interruption | No PATCH publication; fresh attempt required | Before-publication fault |
| Server-committed publication response lost | Immutable readback, fresh gates, consumed with zero mutation | After-publication fault and consumed retry |
| Expiry before first/between/in-flight uploads | Delays before forward recheck freshness; admitted in-flight may finish, no later write | Three-case upload expiry test |
| Conflicting source/tag/asset/receipt or stale attempt | Quarantine; never repair, replace or delete | Original publisher/owner/hotfix suites retained |
| Beta and schema-2 hotfix | Both cryptographic gates; independent source admission | Phase D positive integration tests |
| Immutable asset/tag operations | Actual HTTP denial plus unchanged independent readback required | Driver simulated HTTP 403; live proof BLOCKED |

## Ledger semantics

`AuditedTransport` appends start/end nanosecond timestamps, sanitized route, method, mutation ordinal, duplicate-attempt flag, actual HTTP status when available and outcome.
It records no token, authenticated query string, headers, raw request/response body, signature, passphrase or private key.
Ledger opens exclusively, flushes each event, permits at most 2,000 events and never automatically retries a mutation.

Before-acceptance retries may repeat an attempt; tests independently reject duplicate successful mutations and compare server asset identities/bytes.
Lost-response-after-return injection proves caller-visible interruption after backend return; real server commit must still be reconciled through independent GETs.
Faults bind one stage and mutation ordinal; delays are bounded to 130 seconds and do not extend the 120-second evidence TTL.

## Live audit procedure

1. Obtain separate approval for exact source, fixture/tag, operation scope, credential, fault point and permanent immutable artifacts.
2. Capture independent baseline with `phase_d_audit.verify_release`; hash the exact denied-probe proposal if relevant.
3. Use existing sandbox-only HTTP transport wrapped by audit instrumentation; retain actual statuses and independent before/after state.
4. On any unexpected accepted mutation, mismatched state, missing privilege or ambiguous response, stop and quarantine; never issue automatic repair/deletion.
5. Require fresh run/attempt and both fresh owner signatures for interrupted publication recovery; completed identical publication must consume without mutation.
