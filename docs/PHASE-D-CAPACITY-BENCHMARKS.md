# Phase D Capacity Benchmarks

## Reproduce

Use a fresh local output folder with at least 7 GiB free disk and 1 GiB of available physical memory beyond the benchmark's streaming working allowance. Keep additional disk and memory reserves for other applications.

```powershell
python scripts/phase_d_capacity_bench.py `
  --profile 2x-test `
  --confirm-heavy-local-only `
  --reserve-disk-mib 2048 `
  --reserve-memory-mib 1024 `
  --output C:\temp\phase-d-capacity-run
```

The command generates deterministic, inert fixtures, then uses a local file-backed transport. It makes no GitHub request and never invokes the Publisher. Output must be a new directory. The report records resource preflight, fixture file hashes and sizes, archive digests, parser throughput, maximum read chunk, peak working set and elapsed/CPU time. Large temporary fixture trees are deleted after the run; `benchmark.json` retains their manifest and measurements.

The benchmark compares the streamed parser with a simulation of the previous in-memory path using a 192/96 MiB representative workload under operational limits. The full-limit 256 MiB entry cannot fit in a 256 MiB outer ZIP after package sidecars are included. The legacy simulation requires an additional 2 GiB memory budget beyond the requested reserve. When that budget is unavailable it is marked `NOT RUN`, and the representative operational and 2× streamed measurements still run if their own preflight passes.

## Results

The final-tree run came from a Windows host with Python 3.13.10. Preflight reported 14.25 GiB free disk and 1.27 GiB available physical memory, with a configured 1 GiB reserve. The machine-readable measurements and fixture hashes are in `PHASE-D-CAPACITY-BENCHMARK-RESULTS.json`. A local simulation is not a GitHub Actions service or live publication test.

| Workload | Status | Wall time | Peak working set | Expanded / peak temp disk |
| --- | --- | ---: | ---: | ---: |
| Representative 192/96 MiB legacy simulation | NOT RUN: required 3 GiB available | — | — | — |
| Representative 192/96 MiB streamed parser | PASS | 9.339 s | 30.9 MiB | 288.5 / 576.7 MiB |
| 512/256 MiB streamed stress | PASS | 11.989 s | 31.2 MiB | 768.3 / 1,536.7 MiB |

Both streaming runs used at most 1 MiB per read. Measured input throughput was 30.86 MiB/s for the representative workload and 64.09 MiB/s for the 2× workload. CPU time was 3.500 s and 9.234 s. The stress parser verified 805,727,033 archive bytes, 805,866,504 expanded bytes, two archive digests and five release file digests; Windows and Linux payloads were exactly 512 MiB and 256 MiB.

The deterministic stress payload SHA-256 values were `a869793082211c7ae8681d0f090822bf202f98a4e1bd4308cde4a2081d97aa37` (Windows) and `96ed5af5a7165d7ceb24ada37abeafef335a1a91ff4d8e5f2a90c1256d90db28` (Linux). The fixture used synthetic source commit `b5737bfb8a19d78a85ab3aad24997bd1b01a77b9`; it is a local test identity, not a GitHub commit.

An earlier rerun stopped before fixture creation when available physical memory was 1,169,326,080 bytes against a 1,342,177,280-byte preflight requirement. After memory recovered, the final-tree run passed the same preflight and completed both workloads. The report records both attempts; the blocked attempt made no GitHub requests or Publisher calls.

GitHub artifact downloads, release uploads, owner gates, and live Publisher operations: **NOT RUN**.
