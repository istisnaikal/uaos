# ADR-0003 appendix: spike H1 results

> Promoted from branch `spike/h1-journal-ack` (commit `445ff71`), which is deleted after this lands
> (plan v2 PD-03). The spike measured a stand-in writer, not the production `Journal`; the
> production journal is benched per OS by the nightly lane (PD-01) and recorded in ADR-0003.

**Hypothesis (plan §10.3, H1):** handing a critical record to the OS before acknowledging it
is cheap (p99 ≤ 1 ms) and loses nothing under process kill; power-loss durability via group
fsync fits the overhead budget.

## Machine 1 — Windows (founder workstation), 2026-10-12

AMD Ryzen 5 5600X · WD Green SN350 500 GB NVMe (DRAM-less, entry-level) · Windows 10 Pro · NTFS ·
rustc 1.98.1 (MSVC) · release build · ~600-byte JSON lines · SHA-256 via `sha2` 0.11.

| Measurement | n | p50 | p95 | p99 | p99.9 | max |
|---|---|---|---|---|---|---|
| SHA-256 per line | 100,000 | 2.3 µs | 2.8 µs | 3.9 µs | 5.4 µs | 198 µs |
| write-ack (build + hash + `write_all`) | 100,000 | 5.2 µs | 8.3 µs | **41 µs** | 65 µs | 228 µs |
| group fsync (`FlushFileBuffers`, every 64 records) | 1,562 | 349 µs | 482 µs | 781 µs | 5.9 ms | 9.9 ms |
| strict mode: fsync before every ack | 3,000 | 324 µs | 429 µs | 637 µs | 1.2 ms | 9.3 ms |

Throughput: 79,697 records/s balanced; 2,809 records/s strict.

**Kill test:** 500 `TerminateProcess` kills at pseudo-random acknowledgement counts (1–3,000),
alternating writers without fsync and with 50 ms group fsync:
**746,250 acknowledged records, 0 lost, 0 torn tails, chain verified every time.**

## Verdict on Windows

- H1 holds with large margin: write-ack p99 41 µs ≈ 4% of the 1 ms slice.
- Even **strict** mode (fsync before every critical ack) costs p99 0.64 ms / max 9.3 ms on this
  entry-level NVMe — within the 25 ms p95 overhead budget. Balanced remains the default
  (ADR-0003) because strict caps throughput at ~2.8k critical records/s on this disk.
- Proposed power-loss window **W = 50 ms** for balanced mode (group fsync p99.9 5.9 ms leaves
  ample room); to be confirmed on Linux and macOS before ADR-0003 is finalized.

## Limitations of this spike (carried into the P1 harness)

- Kill points are chosen by acknowledgement count, so the writer is often blocked on its ack
  pipe when killed. The P1 harness must also kill on random timers to hit mid-`write` states.
- Process kill ≠ power loss. Power-loss behaviour is tested with LazyFS on Linux (RC-2).
- One machine, one OS. Linux and macOS numbers come from CI runners and a macOS device;
  `F_FULLFSYNC` on macOS is expected to be markedly slower.
- 500 iterations, not the 10,000 per OS required by the `journal-durability` gate.
