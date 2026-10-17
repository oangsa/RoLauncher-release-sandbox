# Sandbox publisher port — local M2

Status: historical M2 bootstrap; all jobs were hard-disabled when PR #2 merged.
Hosted CI activation is proposed separately in [Sandbox Hosted CI bootstrap](SANDBOX-HOSTED-CI.md).
Production reference: 193c465e4d5999506f8c406ac45ff3e88d1a1a94.
Target: oangsa/RoLauncher-release-sandbox, repository ID 1423257712, owner ID 71574088.

## Scope

- Port the merged Architecture C publisher, owner helper, hotfix policy and original three regression suites.
- Preserve source/intent/CI checks, deterministic receipts, strict explicit bypass verification and separate immutable Release readback.
- Use SSH namespace rolauncher-sandbox-lifecycle-controls-v1; production signatures cannot satisfy this namespace.
- Add numeric source/PR/event identity checks and reject foreign API/upload redirects before forwarding credentials.
- Keep old PoC files as historical data and guard its workflow false.
- Route both stable/beta CLIs through the common gate; omit the legacy beta upload/delete library seam.

## Original M2 disabled controls

1. All eight job definitions across five workflows begin with literal false && and pin sandbox name/ID.
2. The publisher still also requires RELEASE_PROMOTION_ENABLED=true; this port sets no repository variable.
3. The new policy has no inbox, no keys, no disclosure approval and no snapshot digest.
4. No release-intent directory or deployment fixture is added.

Workflow path, source event and exact required job names match the merged publisher.
Main/dev builders use read-only credentials; the disabled publisher declares only Contents-write, Actions/PR/Issues-read.
Owner Administration authority and private signing keys never enter Actions.

## Offline validation

1. Use Python 3.13+, Git and OpenSSH supporting ssh-keygen -Y on Windows.
2. Run python scripts/offline_tests.py.
3. Inspect test results and the complete local diff before any remote installation.

The runner blocks Python sockets and remote Git commands, removes credential/agent variables and disables inherited Git configuration.
Only local Git, Python and ssh-keygen subprocesses are admitted.
Temporary test keys are generated for cryptographic regressions, never enrolled, and removed by TemporaryDirectory cleanup.

The original suites retain all 69 tests, with 12 additional sandbox/offline-runner tests.
Sandbox checks compare 41 unchanged function/class ASTs against the pinned production source and test identity, redirects, disabled workflows and deterministic packages.
The explicit production namespace is also rejected using an ephemeral test key.

## Synthetic packages

Builders never invoke Cargo, dotnet, installers, WebView or application code.
They read exact Git objects and create an invalid non-PE setup placeholder, inert portable ZIP, source ZIP and inert Linux TAR.GZ.
Packages carry AGENTS.md, applicable notices and a SANDBOX-ONLY disclaimer.

ZIP inventory, timestamps, ordering and modes are fixed; gzip/tar metadata is fixed.
Source ZIP contains the complete tracked source tree, with no extraction or execution.
Checksums retain the merged input/output contract; the Linux checksum fragment is consumed, not published separately.

Versions are restricted to the reviewed sandbox registry: 0.0.900, 0.0.901 and 0.1.0 through 0.20.0.
The checked-in 0.0.900 metadata is synthetic contract data, not an application build or a published release.
No v1.7.1 production release data is used.

## Limits and remaining gates

- TTL stays 120 seconds, collection/confirmation 45 seconds, each attendance wait 20 minutes.
- Archive and entry ceilings stay 256 MiB; aggregate expansion stays 512 MiB.
- These small offline fixtures do not establish the plan's production-size or positive 2x stress requirement.
- Real token visibility, owner settings, signing attendance, native immutability and HTTP lost-response behavior remain untested.
- A bounded live HTTP fault adapter/ledger is still required and must be reviewed before M7; this local port does not simulate live GitHub success.
- Hosted Ubuntu/Windows/Arch workflow runs remain unauthorized; local platform results belong in the M2 report.

## Next authorization boundary

The next request is only to publish this reviewed disabled source snapshot to sandbox branch codex/sandbox-release-lifecycle and open a draft PR against sandbox main.
Do not merge it, enable jobs, change Rulesets/settings/variables, enroll a key/inbox or run publishing tests under that approval.
An automatic all-skipped workflow record may be created by the branch push/PR; no job may execute.

Before a future sandbox bootstrap merge, separately approve that merge and read-only builder activation.
Controls, disclosure enrollment, attended publishing and M7 probes retain their separate approvals.
Production and PR #29 stay unchanged throughout.
