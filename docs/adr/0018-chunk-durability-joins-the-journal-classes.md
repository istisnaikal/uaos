# ADR-0018: Chunk durability joins the journal's durability classes

**Status:** Accepted by the maintainer on 2026-10-15, at the end of its 48 h window (opened 2026-10-13) · **Plan refs:** v2 PD-18, I-02, §2.4 per-stage budget, B-06 · **Amends:** ADR-0003 §5 (chunked payloads) · **Evidence:** [ack-latency appendix](appendix/0003-ack-latency-2026-10-13.md)

## Context

ADR-0003 gives journal records two durability classes:
- **kill -9:** a record is handed to the OS before it is acknowledged;
- **power loss:** records are group-fsynced within a window W (50 ms), or in strict mode
  fsynced before every acknowledgement.

The chunk store, which holds every message body, never adopted those classes.
`ChunkStore::put` writes two files per new chunk, the AES-GCM data and the wrapped data key. Each
goes through `Fs::write_atomic`, which does `sync_data` on a temporary file, a rename and a
directory sync, so every new chunk costs four synchronous flushes before it is acknowledged.

Measured on 2026-10-13 (`journal-ack-bench`, new 4 KiB chunk):

| Machine | p50 | p99 | p99.9 |
|---|---|---|---|
| macOS runner | 5.1 ms | **28.5 ms** | 74.7 ms |
| Linux runner | 0.9 ms | 3.8 ms | 21.0 ms |
| Windows runner | 1.0 ms | 1.7 ms | 10.0 ms |
| Reference Windows NVMe | 2.4 ms | 3.5 ms | 11.9 ms |

A request usually carries several new chunks: the new user turn, tool results, and the assistant
turn on settlement. On macOS one chunk alone exceeds the 25 ms p95 local-overhead SLO. The
journal record that references those chunks costs about 10 µs.

## Decision

1. **Chunks follow the class of the record that references them.**
   - **Balanced (default):** chunk files are written to the OS (create, write, rename) with **no
     per-file flush**, *before* the intent record that references them is appended. A process
     kill therefore never leaves an acknowledged intent pointing at a chunk the OS does not
     hold.
   - **Strict:** chunk files are flushed before the intent is acknowledged, exactly as today.
2. **One flush schedule for both stores.**
   - A `DurabilityCoordinator` in `uaos-state` owns the window W.
   - When a flush is due, it first syncs every chunk file and chunk directory written since the
     last flush, then syncs the journal segment. Only then does it advance `flushed_through`.
   - A record is **durable** only once its chunks are. The journal never reports durable records
     whose payloads might not be.
3. **The power-loss window is honest about payloads.**
   - Unsynced writes have no ordering guarantee across files. After a power loss, a record
     written after the last durable flush may therefore survive while one of its chunks did not.
   - Chunks are content-addressed and AES-GCM authenticated, so a missing, empty or torn chunk
     file is **detected**, never misread.
   - Recovery checks the chunks of every record after `flushed_through`. A record whose chunk is
     unreadable marks its Operation's payload as **lost in the power-loss window**: an event plus
     the operation state, reported, never silent. Records at or before `flushed_through` keep
     ADR-0003's guarantee unchanged.
4. **Fewer files per chunk is a measured follow-up, not part of this decision.** Moving wrapped
   data keys from one file per chunk into an append-only per-pocket keystore log would halve the
   file count. It changes how shredding works (ADR-0007), so it needs its own ADR if the P3
   overhead bench shows the remaining cost matters.

## Alternatives rejected

- **Keep flushing per chunk:** measured above to exceed the SLO on macOS by itself.
- **Store chunk bodies inside the journal:** that undoes ADR-0003 §5. History would be stored
  quadratically, and crypto-shredding of individual chunks would be lost.
- **Skip the payload check on recovery:** that turns a lost payload into a silent hole (red line
  3, honest outcomes).

## Consequences

- The power-loss window W now covers payloads as well as records, and the docs say so.
- `uaos-state` gains a coordinator that both stores report unsynced writes to, and the runtime
  appends intents only after the chunks are written.
- Recovery reads the chunks referenced after `flushed_through`. That set is bounded by what one
  window can produce.

## Threat and privacy note

No new data flows. Durability is weakened only for content inside the power-loss window, and that
loss is detected and reported. Chunk authenticity (AEAD) is unchanged, and shred semantics
(ADR-0007) are untouched.

## Verification (before P3 runtime code depends on it)

- **Kill harness:** extended to chunk writes. Every chunk referenced by an acknowledged intent
  must survive a process kill.
- **Simulation:** `SimFs` power-loss scenarios cover chunk files plus journal records. Records at
  or before `flushed_through` must have readable chunks; later records with missing chunks must
  be reported as lost, never misread.
- **Bench, measured on all three CI runners and recorded in ADR-0003's appendix:** chunk-put p99
  ≤ 0.5 ms in balanced mode.
- **Negative case for the gate self-test:** a coordinator that advances `flushed_through` before
  syncing chunks must fail the simulation.
