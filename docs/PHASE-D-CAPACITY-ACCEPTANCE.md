# Phase D Capacity Acceptance

## Acceptance matrix

| Gate | Status | Evidence |
| --- | --- | --- |
| Source path and capacity contract review | PASS | `PHASE-D-CAPACITY-ARCHITECTURE.md` |
| File-backed 512/256 MiB stress fixture | PASS — final-tree run r4 | `PHASE-D-CAPACITY-BENCHMARKS.md` and `PHASE-D-CAPACITY-BENCHMARK-RESULTS.json` |
| Offline regression suite | PASS — 131 tests | `python scripts/offline_tests.py`, Windows Python 3.13.10 |
| Actionlint | PASS — 6 workflow files | Actionlint 1.7.12, locally checksum-verified binary |
| Python syntax and whitespace | PASS | `py_compile` for 11 scripts; trailing whitespace and JSON checks for 15 files |
| Hosted CI contexts | Pending | Record the exact PR HEAD SHA, run IDs, attempts and all five contexts |
| GitHub artifact service transfer | NOT RUN | Requires a separately authorized live workflow run |
| Owner-attested Publisher gates | NOT RUN | No live activation or signing was performed |
| Production repository or release | NOT RUN | Production remains untouched |
| Merge to `dev` | Pending | Review the sandbox PR; do not merge from this task |

The final-tree benchmark successfully parsed the complete 512 MiB Windows and 256 MiB Linux payloads through the file-backed parser. An earlier attempt stopped before fixture creation because available memory was below the preflight requirement; the successful run used 1,364,807,680 bytes of available physical memory against a 1,342,177,280-byte requirement.

## Rollout

1. Review the sandbox PR and confirm the workflow activation guard remains false.
2. Require offline tests, Actionlint, and all five hosted CI contexts on the same PR head.
3. Keep the operational 256/256/512 MiB limits until hosted runner and service measurements support an explicit capacity change.
4. Run any live Publisher or owner evidence exercise only through the existing separate owner-authorization process.

## Recovery

If local fixture generation or parsing fails, discard its temporary output and retain the JSON diagnostics. A live staged release must use the existing attempt-bound recovery path and exact asset digest checks; do not replace or delete immutable releases. This remediation does not create tags, releases, credentials, or signing material.
