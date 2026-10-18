# Phase D draft recovery remediation

**Decision:** prepare a code and metadata PR for `v0.0.901`. Do not resume the ambiguous `v0.0.900` drafts. This report authorizes no Publisher run, signature, tag, Release mutation, or publication.

## Current read-only state

Read from GitHub on 2026-10-18:

- `main` is `c8b8dc8a017420d4717adb9724162a7146ea9d34`; `dev` is `eea0f2e281506a6909adcaa77ea1e915725731d1`.
- Both branches have tree `dd307e82d875600669fe700dc9398154bca95ad9`; `dev` is an ancestor of `main`.
- No open pull request was present at the time of readback. Seven repository rulesets were active, including main/dev and stable/beta tag protections.
- `v0.0.900` points to `c8b8dc8a017420d4717adb9724162a7146ea9d34`.
- CI run `39130305101` succeeded on that SHA. Linux run `39130305086`, attempt 2, succeeded on that SHA.
- Publisher run `39138668137`, attempt 3, failed. It did not publish a Release.
- No stable GitHub Release exists. Two draft Releases with tag `v0.0.900` remain unpublished; neither was changed by this remediation.

| Draft ID | State | Assets |
|---:|---|---|
| `416523601` | Draft, unpublished | `release-promotion.json` only |
| `416558034` | Draft, unpublished | Receipt plus the five expected package/source/checksum assets |

GitHub's Release API metadata reports the same receipt digest for both drafts. Asset digests and sizes were read from GitHub metadata; the original asset bytes were not independently downloaded in this environment. The two same-tag drafts are ambiguous and must not be deleted, replaced, resumed, or published under this plan.

Repository variable and operation-plan values are **NOT VERIFIED**. No configured operation-plan bytes were available to calculate or validate a plan digest. Do not treat the workflow's variable gates as proof that the Publisher is disabled.

## Failure and remediation

The interrupted `v0.0.900` attempt left a receipt-only draft and a separate complete draft for the same tag. The prior recovery path queried `/releases/tags/{tag}`; a draft was not reliably discoverable there, so a retry could treat it as absent and attempt duplicate creation. A simulated end-to-end test reproduces this failure mode through the Publisher wrapper and audit transport.

The proposed fix enumerates Releases with bounded pagination, repeats the inventory to detect unstable reads, rejects multiple same-tag candidates, validates exact source/channel/receipt/assets, and performs a numeric Release-ID readback before admitting that ID to the mutation scope. Only missing identical assets may be uploaded to one admitted draft; unexpected state fails closed. Audit rows record the admitted numeric ID and sanitized identity fields without tokens or request bodies.

`v0.0.900` is not reused because its tag already points at the old candidate and two drafts conflict. The code and version metadata target `v0.0.901`, leaving both old drafts intact as historical unpublished state. The `.901` notes describe only the inert sandbox fixture; it contains no runnable application.

## Validation provenance

- **Local agent run:** 151 offline tests passed on the remediation worktree. Tests use simulated GitHub transport and disposable keys; they do not call GitHub publishing APIs.
- **Local agent run:** `git diff-files --check` passed.
- **Actionlint:** not run; the executable and Go toolchain are unavailable in this environment. Hosted CI does not substitute for this local lint result.
- **GitHub readback:** branch SHAs, active ruleset names, tag, workflow runs, Release IDs and asset metadata listed above. These are API observations, not downloaded-byte verification.
- **Owner/API state:** repository variables and configured plan value remain unverified. No Owner-Signed Preflight or Final evidence was created or accepted.

The proposed PR must be checked against its exact HEAD. The five hosted contexts are `Branch flow`, `Windows checks`, `Linux checks and package (Ubuntu 24.04)`, `Linux checks (Ubuntu)`, and `Linux checks (Arch)`. Reconfirm their exact PR names and conclusions after the run completes. A passing PR does not authorize merge or live operation.

## Phase D first-live-smoke acceptance matrix

| Gate | Current status | Evidence needed |
|---|---|---|
| Draft-recovery source fix | Prepared locally | Review exact PR diff and passing hosted checks on its current HEAD |
| `v0.0.900` ambiguity | Confirmed; quarantined | Preserve both drafts unchanged; no resume or deletion |
| `v0.0.901` source target | Proposed | Owner-approved code PR through `dev`, then protected `dev` → `main` promotion and final main SHA `C` |
| Candidate intent | Not prepared | After activation review, create a separate intent-only PR with a fresh UUID and bind it to `C` |
| Source CI and Linux artifacts | Not run for `.901` | Verify all five source contexts, run IDs/attempts, artifact IDs/digests, inventories and Source ZIP/Git-tree match on `C` |
| Variables and operation plan | Not verified; digest unavailable | Owner readback of both flags and exact plan bytes; verify the canonical plan digest without activating it |
| Native immutability readback | Prior owner-provided readback: `enabled=true`, `enforced_by_owner=false`; not a fresh signed check | Fresh owner-authorized readback bound to `C` and the approved run; keep mutation-denial separate |
| Owner-signed Preflight | Not run | Complete the enrolled signing protocol for a fresh challenge; verify source, run/attempt, controls digest, nonce, expiry, and evidence acceptance |
| Linux rerun | Not run | Separately approve and verify same run ID, incremented attempt, unchanged SHA `C`, and matching delivered `workflow_run.completed` event |
| Owner-signed Final | Not run | Fresh distinct challenge and accepted final evidence after exact staging and receipt readback |
| Live Publisher smoke | Not run | Explicit owner authorization for exact plan, tag, assets, expected mutations, and retained audit |
| Native immutability mutation-denial | Not run | Separately approved inert denial probe and before/after resource verification |
| Release publication | Not authorized | Separate final owner decision after all preceding gates; not implied by artifact admission or this PR |

## Owner actions remaining

1. Review the remediation PR's exact head, source diff, local test record, and all hosted CI contexts. Merge to `dev` only through the protected owner-approved PR path.
2. Review the protected `dev` → `main` promotion and verify the resulting main SHA and source CI. Keep both activation flags false or unset and the plan non-executable until the owner completes a separate live-operation approval.
3. Re-read repository variables and the actual plan through an authorized owner interface. If either value is unavailable, changed, or outside approval, stop; the agent cannot infer it from workflow code.
4. Prepare a separate intent-only PR for fresh candidate `v0.0.901` only after source SHA `C` is final. Merge it through the protected path and collect fresh main-push CI/Linux evidence for that exact SHA.
5. Build and independently review the canonical operation plan for `C`, its exact runs and artifacts, stable channel, `v0.0.901`, and no fault injection. Record its digest without enabling variables or running the Publisher.
6. Obtain separate owner authorization for activation, Linux rerun, Preflight signing, Final signing, live smoke, mutation-denial probe, and any publication. Each signature and permission is bound to its own exact challenge and evidence.

## Actions not taken

No repository variables were changed. No workflow was rerun. No operational signature, tag, Release, upload, deletion, or publication was performed. The existing `.900` tag and both drafts remain unchanged; Production was not accessed.
