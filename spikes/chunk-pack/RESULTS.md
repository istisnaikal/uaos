# Spike 0c: one file per chunk against pack files, results (2026-10-20)

**Question** (plan "Spine to RC-1", Stage 0c; open decision D-32). ADR-0018's balanced chunk put
budget is p99 ≤ 0.5 ms. With one data file and one key file per chunk, CI measured p99 6.85 ms on
macOS and 0.87 ms on Windows (run 38869000900), and the reference machine 1.55 ms. Does an
append-only pack per pocket meet the budget, and in which shape?

**Run:** `cargo run --release --manifest-path spikes/chunk-pack/Cargo.toml -- <scratch dir> 5000 64`.
5,000 puts, sizes log-uniform from 256 B to 64 KiB, flushed in groups of 64, file-system work
only. Workflow `spike-chunk-pack` on pushes to this branch, three runs per runner.

**Fidelity check.** The spike's "today" row reproduces the product: on the reference machine its
put p99 is 1.42–1.48 ms against `ChunkStore`'s measured 1.55 ms (ADR-0018 appendix, `fc4b5a8`), and
its CI macOS p99 with background flushes (2.1–6.2 ms) brackets the product's 6.85 ms.

## Verdict

**Pack segments meet the budget on macOS and Linux, and cut the Windows CI tail by about 2.7
times without meeting it.** Measured with a flush always running, which is harsher than ADR-0018's
cadence of one flush per 50 ms window; the product's cadence is not measured here.

| Runner | Today | Prepared segments | Meets 0.5 ms |
|---|---|---|---|
| macos-latest | 2.14–6.18 ms | 0.18–0.29 ms | yes, segments only |
| ubuntu-latest | 0.43–0.56 ms | 0.02 ms | segments yes; today in 1 run of 3 |
| windows-latest | 1.35–1.83 ms | 0.48–0.69 ms | no: segments in 1 run of 3, today in none |
| Reference machine (Windows, NVMe) | 1.46 ms | 0.13 ms | yes, segments only |

- **On Windows CI the remaining tail is the volume, not the layout.** With flushes between groups
  the same segments measure 0.21–0.32 ms; with a flush of another file running at the same time,
  about 1 put in 100 waits 20–27 ms (p99.9). Preparing the next segment ahead of time did not
  change that.
- **Recommendation for D-32 (yours: an on-disk format change before the RC-1 freeze):** adopt
  prepared pack segments per pocket, through an ADR-0018 amendment with an ADR-0007 note, built
  before the runtime spine, whose coordinator would prepare the segments. Windows CI stays stated
  as over budget until the product's own cadence is measured in WP3.8; nothing is claimed for it.
- **The alternative** is to keep one file per chunk for RC-1 and state the miss on every platform
  but Linux: 4 to 12 times over on macOS, 3 times on Windows.

## Balanced put p99, flushes on a second thread (the durability coordinator's shape)

Three runs per runner per round; the budget is 0.5 ms. Today's and the single pack's rows are
round 1 (run 39322162391); the segment rows span rounds 1 and 2 (run 39325957920); prepared
segments are round 2 only.

| Layout | ubuntu-latest | macos-latest | windows-latest | Reference machine |
|---|---|---|---|---|
| One file per chunk (today) | 0.43–0.56 ms | 2.14–6.18 ms | 1.35–1.83 ms | 1.46 ms |
| One pack per pocket | 0.02 ms | 0.61–0.71 ms | 0.84–0.86 ms | 1.10 ms |
| A pack segment per group | 0.02 ms | **0.18–0.45 ms** | 0.48–0.70 ms | 0.29–0.33 ms |
| Prepared segments | **0.02 ms** | **0.18–0.29 ms** | 0.48–0.69 ms | **0.13 ms** |

**What this shows.**
- **One file per chunk cannot meet the budget off Linux.** Creating files is the cost: two per
  chunk, plus two renames.
- **A single pack misses it too, because of the flush.** Appending to a file while another thread
  flushes that same file stalls the append (p99 0.6–1.1 ms on macOS and Windows), and the
  coordinator flushes while puts continue.
- **A segment per group** lets the next group append to a fresh pair while the closed pair is
  flushed. That meets the budget on macOS and Linux, but on Windows the first write to a file
  created moments before lands on the put path (p99.9 23–27 ms).
- **Prepared segments** create the next pair, with a header, one group ahead and off the put path.
  That helps on the reference machine (0.29 → 0.13 ms) and macOS, and not on Windows CI.

## Group flush and reads

| Runner | Group flush p50, today | Group flush p50, segments | Read p50, today | Read p50, segments |
|---|---|---|---|---|
| ubuntu-latest | 46–56 ms | 1.2–1.5 ms | 0.010 ms | 0.003 ms |
| macos-latest | 71–124 ms | 2.3–4.0 ms | 0.03–0.35 ms | 0.009 ms |
| windows-latest | 32–49 ms | 1.1–1.6 ms | 0.058 ms | 0.018 ms |

A group flush falls from tens of milliseconds to one or two, because it flushes two files instead
of 128 plus two directories. That shortens how long a balanced record waits to become durable.

## What a pack format would cost (not measured here)

- **An index.** Today the directory is the index: a chunk's file name is its reference. A pack
  needs a reference → (segment, offset) index, rebuilt at open by reading record headers or
  stored per sealed segment. This is the largest piece of work and an on-disk format change in
  the RC-1 freeze set.
- **Torn tails.** A crash can leave a partial record at a segment's end. Records are
  length-prefixed and AEAD-authenticated, so recovery truncates at the first record that does not
  authenticate, and payload losses are journaled exactly as today (ADR-0018 §3).
- **Shred keeps its guarantee.** Per-chunk data keys stay; a shred still rotates the pocket's KEK,
  re-wraps every other key (into a new key segment instead of new key files) and destroys the old
  version, so the shredded key cannot be unwrapped from any copy (ADR-0007 §4). The shredded
  ciphertext stays in its data segment until compaction, which crypto-shredding permits.
- **Compaction.** Dead records accumulate and are reclaimed by rewriting segments: P4's compaction
  work, not RC-1's.
- **Dedup.** A put of content already stored becomes an index lookup instead of a file probe.

## Not measured

The AEAD seal and the keyed reference (the same in both layouts), recovery of a torn segment,
compaction, shred re-wraps, and the index. Power-loss behaviour is ADR-0018's statement, unchanged
by layout.
