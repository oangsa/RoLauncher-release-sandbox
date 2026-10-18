# Phase D readiness — D0

Status: **PASS for Phase C main readback; live Phase D remains BLOCKED by operational approvals.**
Repository: `oangsa/RoLauncher-release-sandbox`, ID `1423257712`, owner `71574088`.

## Deployed baseline

- Owner merged PR #8 using merge commit `b010f87fdefe1283e8e0fc417341a6fb96e9ccee`.
- Parents: `01e17f49ebbdd14f84c5b7d0ca0cbb8b7e99f992`, `b9922ddc3d860984efa2bd04b76f07a3167775be`.
- Tree: `f8c5c0e44eb530ad5a1a42d46064c619a3d87777`; enrolled source equals reviewed Phase C tree.
- Main [CI 39061813271](https://github.com/oangsa/RoLauncher-release-sandbox/actions/runs/39061813271) and [Linux 39061813408](https://github.com/oangsa/RoLauncher-release-sandbox/actions/runs/39061813408): attempt 1, push, success, exact baseline checkout.
- All five required contexts passed; Windows, Ubuntu 24.04, Ubuntu and Arch jobs each ran 84 tests.

## Actual retained artifacts

Both GitHub artifact archives downloaded; independent SHA256 equals GitHub metadata.
All checksum inventories, 38 source Git blob hashes, inert payloads and two deterministic reproductions passed.

| Artifact | ID | ZIP bytes | SHA256 |
|---|---|---|---|
| release-files-attempt-1 | 12111249287 | 104920 | `af2e71918ea67c69a4751f4887071be98dd4861a6c455cf4478c8d00cb36d4fd` |
| release-linux-files-attempt-1 | 12111194412 | 16220 | `a3546dd08418ea39d1e9c68a9309bb200f0290f8e3661fd3c4dd5496cbae41a3` |

## Complete controls and policy

- Seven active Rulesets: `25300842`, `25300914`, `25310153`, `25310237`, `25310336`, `25310351`, `25310363`.
- Full privileged bypass arrays and effective main/dev rules read through owner CLI, never inferred from public omission.
- Canonical snapshot: 7,264 bytes; SHA256 `c48b4ebe3972abe2d5fe75b2ef7e5a0f70065c3b7e5c71a7bc9cd8a18d09c368`.
- Native immutability enabled; branch required checks strict, Actions App `15368`, merge-commit-only, no branch bypasses.
- Exact enrolled policy, Issue #5 and fingerprint verified; see [owner identity](OWNER-EVIDENCE.md).
- Existing Windows helper raw binary GET reproduced exact real archive digest without signing or posting.
- Publisher wakeups [39061853476](https://github.com/oangsa/RoLauncher-release-sandbox/actions/runs/39061853476), [39061867008](https://github.com/oangsa/RoLauncher-release-sandbox/actions/runs/39061867008) skipped with zero steps; historical PoC also skipped with zero steps.
- Publisher/Beta/PoC retain literal `false &&`; activation variables and release intents absent; tags/Releases empty.
- Production main remains `193c465e4d5999506f8c406ac45ff3e88d1a1a94`; held PR #29 unchanged/open.

## Discrepancies and gates

Issue #5 still says **Not yet enrolled**. The [precise correction](PHASE-D-ISSUE5-CORRECTION.md) is proposed only; no Issue edit or evidence comment made.
Older sandbox-port/hosted-CI documents describe historical bootstrap state; current phase status is this report and [validation](PHASE-D-VALIDATION.md).
Original lifecycle document remains the acceptance specification, including all live and capacity requirements.

Readiness dispatch, real owner attendance, publisher activation, exact permanent fixtures, live faults/denials and cleanup each need separate operational approval.
Missing privileged runtime fields mean BLOCKED; actual Windows-to-Ubuntu operational signing has not occurred.
