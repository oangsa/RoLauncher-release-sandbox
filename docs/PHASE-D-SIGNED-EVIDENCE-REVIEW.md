# Phase D signed evidence integration review

Review date: 2026-10-18. Scope: `oangsa/RoLauncher-release-sandbox` only.
Verdict: safe integration hardening prepared; full operational acceptance **BLOCKED**.
No operational signing, inbox post, activation, release intent, tag, draft, Release, probe or security-setting mutation is authorized by this review.

## Verified baseline and evidence classes

- Repository ID: `1423257712`; numeric owner: `71574088`; default branch: `main`.
- Main: `db9fa19f60554e02dda1e3c4e2332088f238773b`, matching the requested baseline.
- Dev and initial review HEAD: `9ee6ad9209312ad5622243c97571f7406e1c616d`.
- Both baseline branches have tree `9150c0c67a8da08acea349f2894b1ee94ee8108f`.
- Review lane: `codex/phase-d-signed-evidence-review` to `dev`; merge requires owner review, then separate dev-to-main approval.
- Production checkout was inspected only for identity and clean status; all implementation work uses an isolated sandbox clone.

| Claim | Status | Evidence and limit |
|---|---|---|
| Runner privileged visibility | BLOCKED | [Readiness run 39099161592](https://github.com/oangsa/RoLauncher-release-sandbox/actions/runs/39099161592), attempt 1, exact main SHA; failure and successful diagnostic upload independently confirmed through API |
| Seven missing bypass arrays; immutable visibility false | BLOCKED | Owner-supplied retained diagnostic; never inferred empty or relabeled PASS |
| Owner privileged readback | PASS | Owner-supplied independent CLI result: seven complete Rulesets, enabled native setting, 7,264 canonical bytes, enrolled digest |
| Fresh owner-signed acceptance | NOT RUN | Actual operational key, comments and Actions acceptance deliberately untouched; disposable-key simulations are separate |
| Publication authorization and lifecycle | BLOCKED | No live attended gates, publication, recovery, denial or positive 2x-capacity evidence |

Owner readback matches `c48b4ebe3972abe2d5fe75b2ef7e5a0f70065c3b7e5c71a7bc9cd8a18d09c368`.
Expected nonempty arrays are Rulesets `25300842` and `25310363`, each RepositoryRole 5 / always; other five arrays are explicitly empty.
This supplied observation proves disclosure integrity at collection, not continued state or release authority.

## Findings and smallest remediation

1. **Visible privileged contradictions were ignored.** `owner_evidence.controls_call` (line 141) projects away bypass arrays when comparing live metadata and does not query immutable settings.
   A valid approved signature could therefore coexist with newly visible contradictory bypass or `enabled: false` settings.
   New both-gate tests reproduced acceptance before the fix and reject it afterward with no new release mutations.
2. **Controls were not refreshed at write boundaries.** `StagedEvidence.fresh` (line 288) checks expiry and owner-comment integrity, but not live Ruleset metadata.
   A metadata change after gate acceptance could reach the next mutation.
   New audited delay-before tests reproduce this at first staging write and publication PATCH; both now reject before forwarding.
3. **No redundant privileged Ruleset blocker was found.** Strict branch verification already obtains complete Ruleset details through the signed adapter.
   Adding a second signer, owner token or replacement authority is unnecessary.

Remediation is confined to `PhaseDEvidence.gate` and `PhaseDEvidence.fresh` in `scripts/phase_d.py`.
Only after the original gate has verified the signature, challenge, disclosure and strict protections does it retain the accepted controls for rechecking.
Every subsequent freshness check recollects observable metadata, compares any visible bypass array, reruns strict protections and checks expiry after those reads.

Native settings are compared whenever their GET succeeds; missing fields, null responses, disabled settings and changed owner enforcement fail closed.
Only the exact HTTP 403 error emitted by the existing sandbox transport permits reliance on the already verified owner observation for that setting.
HTTP 404 is fatal because GitHub documents it for disabled immutability; 401, 5xx, timeout and other errors also remain fatal.

The pinned Architecture C functions, production AST assertions, enrolled key/digest, release state machine, limits and workflow guards are unchanged.
The held workflow still calls the original entry; the existing separately reviewed activation patch selects `phase_d_publisher.py` and its hardened subclass.
Do not activate the old entry directly or count these Phase D extensions as changes to pinned production code.

## Exact authorization call flow

1. Held integration entry: `phase_d_publisher.main` (line 129) checks both activation flags, exact operation scope and trusted environment.
   `authorize_plan` pins sandbox IDs, trusted/source SHAs, publisher run/attempt, channel, approved synthetic tag and fault scope.
   `scoped_call` restricts mutation endpoints, resource IDs and bodies; `AuditedTransport` checks freshness immediately before forwarding each mutation.
2. `promote_event` (`release_promotion.py:448`) rereads triggering run and checks event/run attempt/source.
   `promote` (line 247) runs `authorize`, successful source/Linux jobs, main/source authority, versions, notes, artifacts, deterministic receipt and existing tag/Release checks.
   `FrozenArtifacts` bounds repeated artifact observations within a stage; candidate code is never executed.
3. `LifecycleEvidence.gate` (`phase_d_publisher.py:63`) verifies exact source ZIP against Git blobs for every channel before either challenge or acceptance.
   It calls `PhaseDEvidence.gate`, which enforces canonical wrapper, payload JSON and Base64, then delegates to `StagedEvidence.gate` (`owner_evidence.py:310`).
4. Prepare/preflight creates a fresh challenge artifact and exits via `ChallengeReady`, without release mutation.
   Stage/preflight rereads the challenge and exact context, checks previously consumed nonces, polls the owner inbox, independently rereads the comment and invokes `verify` (line 214).
   `verify` validates the real OpenSSH signature before payload contract, exact challenge binding, collection times, expiry, replay and approved disclosure checks.
5. `controls_call` compares complete projected live inventory/details/effective branches to signed data, then serves signed Ruleset detail objects.
   `protected_branches(strict=True)` (`release_promotion.py:123`) requires active workflow, main/dev protection, all five strict Actions-bound checks, empty branch bypasses and stable/beta tag contracts.
   Phase D then retains verified controls and calls its hardened `fresh` before returning acceptance.
6. Publisher repeats intent/main/source/Linux/run/resource checks after attendance.
   Tag creation, draft creation and each missing exact asset upload require fresh preflight evidence; audited forwarding repeats the freshness check after any injected delay.
   Complete staged inventory, hashes, tag and main are checked before requesting the distinct final challenge.
7. Finish calls `resume` (`owner_evidence.py:299`) to bind trusted local preflight bookkeeping to the same publisher run/attempt/source/receipt.
   Resume does not revive preflight signing authority; finish requires existing staged resources and cannot create/upload replacements.
   Final acceptance repeats the real signature/controls path using a different phase and nonce after complete staging.
8. After final attendance, intent/main/source/Linux jobs, tag, assets, Release identity and latest stable are independently reread.
   Fresh final evidence precedes the sole publication PATCH; failure leaves an authorized matching draft only.
   Separate Release GET must prove native `immutable: true`; consumed recovery requires matching immutable resources and zero writes.

The final gate cannot reuse a preflight signature: the complete challenge differs in phase and fresh nonce.
The source binding includes intent, source/Linux run identities and SHA256 of the deterministic receipt.
The public wrapper separately carries SHA256 of the exact challenge.

## Endpoint and permission boundaries

Paths below are relative to `/repos/oangsa/RoLauncher-release-sandbox` unless stated otherwise.
Runner means the existing contents-write, Actions-read, PR-read and Issues-read publisher token, without Administration.
Signed controls substitute only privileged observations; all other rows require independent live success.

| Required GET family | Runner/owner visibility | Signed substitution | Failure despite valid signature |
|---|---|---|---|
| Repository root; `/branches/main` | Runner observable; no owner privilege needed | None | Wrong IDs/default branch/owner; advanced main |
| `/actions/runs/{id}`, workflow run listings, attempt jobs | Runner Actions-read | None | Failed/skipped/missing checks; source/path/event/attempt mismatch |
| `/actions/workflows/release-promotion.yml` | Runner Actions-read | None | Workflow disabled |
| `/commits/{sha}`, path history, associated PRs, `/pulls/{number}` | Runner contents/PR-read | None | Reused intent, wrong merge lane/merger/repository; hotfix governance failure |
| `/compare/{sha}...dev` and hotfix comparisons/check runs | Runner contents/check metadata | None | Beta outside dev history; hotfix ancestry, governance or CI mismatch |
| `/contents/{path}?ref={sha}`, `/git/trees/{sha}?recursive=1` | Runner contents-read | None | Version/notes/source ZIP differs; incomplete tree |
| `/actions/runs/{id}/artifacts`, `/actions/artifacts/{id}/zip` | Runner Actions-read, stripped credentials on external download redirect | None | Missing/expired/ambiguous artifact, wrong digest, ZIP inventory or resource limits |
| `/rulesets?includes_parents=true&per_page=100` | Runner sees inventory including inactive/inherited sources | Signed inventory must equal live inventory | Missing fields, pagination ceiling, changed/repeated IDs |
| `/rulesets/{id}` ordinary `FIELDS` | Runner metadata-read; owner sees full object | Signed projection compared exactly to live fields | Source/target/enforcement/conditions/rules contradict snapshot |
| `/rulesets/{id}` bypass arrays | Owner with Ruleset write privilege sees arrays; runner observed all seven omitted | Yes, after real signature, digest, binding and freshness; visible arrays must agree | Missing signed array, unexpected actor, contradictory live array |
| `/rules/branches/main`, `/rules/branches/dev` | Runner directly observes effective Rulesets | Never replace live effective branch rules | Missing strict checks, changed source Ruleset, incomplete list |
| `/immutable-releases` | Administration-read required; runner visibility reported false | Verified owner setting only on exact 403; successful live response must agree | Disabled/missing/malformed/changed setting, ambiguous 404 or transport failure |
| `/issues/{inbox}/comments`, `/issues/comments/{id}` | Runner Issues-read; numeric owner supplies public response | Signature authenticates response, never replaces comment readback | Edited/duplicate/conflicting response, wrong owner, timeout/cancellation |
| `/git/ref/tags/{tag}`, `/git/tags/{sha}` | Runner contents-read | None | Missing/moved/incorrect tag target |
| `/releases/tags/{tag}`, `/releases/latest`, `/releases/{id}`, assets | Runner contents-read | None | Receipt/body/source/channel/assets/latest changed; published resource not immutable |
| `/releases/assets/{id}` raw download | Independent audit contents-read | None | Downloaded bytes/size/hash differ from canonical receipt |
| Owner CLI `GET /user`, challenge artifacts and publisher run | Local authenticated owner only; not sent to runner | None | Wrong owner, stale trusted publisher/source/version/attempt or altered artifact |

Strict branch protection here means the effective Ruleset contract, not a legacy `/branches/{branch}/protection` call.
No such legacy endpoint is called by either authorization gate; adding it would introduce an unrelated Administration-dependent blocker.
The optional independent immutability probe is the only new privileged read, and never grants authority from an error alone.

## GitHub limitation and threat model

GitHub explicitly returns `bypass_actors` only to callers with write access to the Ruleset, even when ordinary Ruleset metadata is readable.
Contents-write is not Ruleset administration privilege; the observed runner/owner difference is consistent with that documented boundary.
See [Ruleset GET documentation](https://docs.github.com/en/rest/repos/rules#get-a-repository-ruleset).

Native setting GET requires Administration-read; its documented 404 may mean immutability is disabled.
See [native setting documentation](https://docs.github.com/en/rest/repos/repos#check-if-immutable-releases-are-enabled-for-a-repository).
The readiness artifact does not expose its precise HTTP failure, so actual runner status must be confirmed during separately authorized live validation; do not assume 403.

Independent GitHub reads establish source provenance, run status, effective protections, observable control definitions, comments and resource state.
The enrolled owner attests only complete privileged observations collected for the exact challenge; signatures establish attribution/integrity, not GitHub's continued state.
Compromised owner key/workstation, malicious owner administrator or hidden setting changes can invalidate those observations despite a mathematically valid signature.

TOCTOU cannot be eliminated: GitHub has no atomic transaction binding control settings, owner comments, source readbacks and release writes.
The 45-second collection/confirmation limit, 120-second TTL, two independent attended gates and immediate live rechecks bound exposure; they cannot independently detect a hidden privileged change after collection.
An upload admitted fresh can finish after expiry; all later mutations require fresh evidence, and publication still requires a separate final signature.

The architecture is sufficient for bounded owner-attested authorization under that explicit trust model, without placing owner credentials in Actions.
It cannot satisfy a stronger requirement of independently proving hidden settings at the exact write instant; that requirement remains BLOCKED without additional trusted observation or server-side enforcement.
Missing required public metadata and ambiguous immutable settings remain blockers, never inferred safe.

## Cryptographic and recovery invariants

- Exact namespace: `rolauncher-sandbox-lifecycle-controls-v1`; allowed signer principal: `github-user-71574088`.
- Existing enrolled Ed25519 public key, policy digest, numeric identities, approved disclosure and revocation checks are unchanged.
- Canonical JSON/Base64/wrapper checks remain Phase D requirements; pinned `verify` alone decodes strictly but does not enforce canonical byte representation.
- OpenSSH signatures do not encode an application principal; the allowed-signers lookup binds the public key to the exact verification principal and namespace.
- Evidence TTL stays 120 seconds; collection/confirmation stays 45 seconds; each owner attendance deadline stays 1,200 seconds.
- Challenge SHA256, trusted/source SHA, workflow/run/attempt, phase/nonce, exact receipt and policy remain bound.
- Consumed-nonce state, edited/duplicate comment rejection and local same-attempt resume remain fail closed.
- Final rejection permits existing authorized draft resources only; no DELETE, repair, replacement or automatic mutation retry is added.
- Post-publication numeric Release immutability, downloaded hashes and native-control denial proofs remain independently required.

## Validation and experiment ledger

1. Initial restricted Windows run could not use temporary files: environment failure, not product failure.
   Reran the network-denying suite with working local temporary-file permissions: all 112 baseline tests PASS.
2. Added live immutable contradiction test first: preflight proceeded and final published in simulation; test FAIL before remediation, PASS after guard.
3. Exact 403 restricted-runner positive test initially FAIL after adding mandatory GET; narrowed fallback to exact transport permission denial; PASS afterward.
4. Added visible bypass and delay-before metadata race tests first: both demonstrated missing rejection; PASS after immediate live control rechecks.
5. Added both-gate denial matrix through real disposable-key signatures and publisher seam, asserting unchanged mutation history for every rejected case.
   Separate tests retain wrong-principal OpenSSH lookup, preflight-for-final replay, stable/beta/hotfix authorization, expiry, interruption and immutable readback coverage.

The matrix covers wrong/revoked key, wrong namespace, payload modification, malformed/noncanonical Base64, wrong digest, missing bypass/native evidence, wrong repository/owner/trusted/source/workflow/run/attempt/phase, expiry/replay, edited/duplicate comments, cancellation, advanced main, missing artifacts and receipt/resource conflicts.
Additional cases cover visible disabled/changed native settings, missing/null settings, 404/401/500/timeouts and changes immediately before staging/publication forwarding.
All use disposable test-only keys; no operational private key is accessed.

Local checks: `python scripts/offline_tests.py`: **PASS**, 118 tests, including unchanged pinned contracts and six new integration tests with both-gate subcases.
`actionlint -color=false` with every `.github/workflows/*.yml` explicitly supplied: **PASS**.
Hosted check outcomes are recorded in the delivery PR and final assessment, tied to its HEAD.
Offline PASS is never operational PASS; all five named hosted contexts must succeed before owner merge review.

## Remaining owner approvals and blockers

1. Review this exact PR HEAD and all five hosted contexts; authorize merge into dev, then separately approve protected dev-to-main promotion.
2. Resolve the positive 2x capacity blocker under the original lifecycle contract; unchanged 256 MiB entry and 512 MiB aggregate ceilings cannot satisfy the mandated doubled minimum case.
   Do not waive it or extend TTL in this PR.
3. Separately approve exact trusted/source/run/attempt scope, held publisher activation patch and variables; verify immutable GET's actual HTTP status without logging credentials.
   An actual 404 remains BLOCKED, not an approved hidden-setting fallback.
4. Separately authorize local Windows owner attendance and public signed evidence for both gates, exact approved permanent synthetic fixture names and candidate source/intent/CI authority.
   Never run the helper or post to Issue #5 as part of implementation review.
5. Separately authorize real stable/beta/hotfix publication, expired/interrupted recovery, canceled waits, lost committed responses and zero-write consumed retry.
6. Require independent immutable numeric Release readback and downloaded receipt/asset/source verification; separately approve exact denied mutation plans and native control outside version-tag Rulesets.
7. Approve any later cleanup/variable changes or key revocation separately, retaining immutable resources and audit evidence; production remains unchanged.

Current operational verdict: **BLOCKED**. No live signing, GitHub signed-evidence acceptance, synthetic publication, recovery or native-resource probe result is claimed.
