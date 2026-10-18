# Phase D security audit

Status: implementation/offline checks PASS; operational security acceptance remains BLOCKED until separately approved live evidence.
Production remains read-only. No Ruleset, policy digest, owner key or resource bound changed.

## Retained boundaries

- All pinned production AST/security-contract assertions remain intact; no expected digest was changed to accommodate implementation.
- Existing source authorization, strict controls, signature verification, deterministic receipts and promotion state machine remain authoritative.
- `github_api` gains only an optional status observer; existing endpoint pinning, credential stripping on redirects, limits and no-retry behavior remain unchanged.
- New Phase D entry requires both activation flags, exact reviewed operation scope and trusted main workflow/repository/source/run/attempt identity before constructing a transport.
- Its source gate verifies exact cached Windows artifact source ZIP against Git blobs for every channel before either challenge.
- Its strict evidence integration rejects noncanonical signed payload/base64/comment wrapper before existing signature/phase/TTL/replay checks.
- Publication scope never permits DELETE, arbitrary tags or other repositories; denied probes are a separate exact-plan approval path.
- Upload and publication PATCH are pinned to the numeric Release ID read/created for the exact approved tag/source.
- Independent audit downloads every asset and verifies inventory, sizes, hashes, canonical receipt, exact tag/source and separate immutable Release GET.
- Native-control exclusion checks the complete enrolled snapshot; tag-rule denial alone cannot establish native immutable-release behavior.

## Secrets and permissions

Only the already-enrolled public identity is in source. Operational owner key is never invoked by automated tests, copied or uploaded.
Windows signing remains the existing owner-attended helper with local passphrase entry; CI receives only separately authorized public responses.
Builders retain contents-read. New readiness workflow declares publisher-equivalent permissions but is hard-disabled, manual-only, trusted-main-only and calls a GET-only probe.

Readiness output contains visibility flags, counts and approved digest, not full privileged values or raw error bodies.
Missing privileged fields remain BLOCKED even when public metadata is otherwise complete.
Both new and existing publication/probe workflows remain held; activation patch files are inert review artifacts.

## Known limitations and gates

- Actual Windows-to-Ubuntu owner attendance, runner permission visibility and signed public comments: NOT RUN.
- Real publication, immutable native denial, interrupted HTTP recovery, large Actions transfers and no-write consumed retry: NOT RUN.
- Two-times mandated minimum fixture is incompatible with unchanged entry/aggregate limits; no silent waiver.
- Publisher parser is bounded but buffers full payloads; high-entropy local peak was 829,001,728 bytes, not a constant-memory streaming claim.
- Issue #5 enrollment wording is stale; correction awaits owner approval.
- Exact owner authorization is still required for protected merges, variables, activations, named permanent fixtures, live faults and cleanup.

Do not mark live Phase D PASS from green offline suites, skipped workflows, approval flags or unenforced textual plans.
