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

## Implementation and evidence (P3 Move 1, PR-1, 2026-10-15; revised 2026-10-16 after review)

The V1 review of the first implementation ([WP3.A1](../reviews/WP3.A1-chunk-durability.md))
found four High findings, each a payload loss ending with a durable record and no `chunk.lost`
record. What follows describes the code after those fixes.

**How each decision is built.**
- **Decision 1.** `ChunkStore::open_with(…, ChunkDurability::Balanced)` hands both chunk files to
  the OS through a uniquely named temporary and a rename, with no flush. Strict mode is unchanged.
  A pair already on disk from an earlier process is replaced only by a flushed write that keeps
  its data key. To know which names those are without a file-system call per put, the store
  indexes the key files present when it opens (one store per data directory, enforced by its own
  lock).
- **Decision 2.** There is no separate `DurabilityCoordinator` type: `Journal::open_with_payloads`
  plays that role.
  - `Journal::sync` first flushes the store's pending chunks (files, then pocket directories),
    then the segment, and only then advances `flushed_through`.
  - **A failed flush is sticky.** A failed flush of pending content, inside or outside
    `Journal::sync`, poisons the store, and in balanced mode so does any failed flushed write or
    chunk-directory flush (a directory flush also covers pending chunks' entries). Then `put`,
    `is_stored` and `sync_pending` refuse, and the writer stops
    (`JournalHealth::PayloadFlushFailed`). A store poisoned before the journal attached is
    recovered when the journal opens, and `Journal::recover` recovers a store poisoned while the
    writer stayed healthy. Recovery clears only the failures it saw when it began, so a flush
    that fails while it runs keeps the store poisoned. A put that joins the pending set while
    the store is poisoned is refused, and so is a put whose write overlapped a failed flush,
    which poisons the store again so that the next recovery rewrites it even if one already
    ran. A journal flush is not acknowledged if the store was poisoned while it ran: every
    flushed write or directory flush that can poison, the store's own flush of pending chunks
    included, holds a flush window until it has, and the flush takes that window before it
    acknowledges its batch.
  - **Recovery rewrites; it never re-flushes.** `recover` reads each pending chunk back. A
    readable one is rewritten to new files and flushed, because after a writeback error a second
    flush of the same file can report success without writing anything. An unreadable one is
    quarantined (kept, not deleted) and journaled as `chunk.lost` with its cause (`missing`,
    `short`, `unauthentic`).
  - **The flush still runs inline.** When the window is due, the `append` that finds it due pays
    for the flush. Moving it to its own thread is runtime work (WP3.3, the state actor).
- **Decision 3.**
  - **Losses are journaled before their records are durable.** The `chunk.lost` records are
    appended before the flush that makes the records they report durable, so one flush covers
    both. While a found loss is not yet journaled, the writer refuses records and flushes.
  - **Durable point.** A one-line marker (`journal/FLUSHED`), written atomically at open and
    then at most once per second, names the last flushed record. Every journal keeps one, with
    or without a store. A separate flag file (`journal/PAYLOADS`) records that the journal
    coordinates a store, so it cannot be opened without one (`JournalError::PayloadsRequired`).
    For a journal that coordinates a store, every payload up to the marker is durable or its
    loss journaled, and the marker never moves while a loss is unreported or the store is
    poisoned. A plain journal's marker says nothing about payloads, so the first open with a
    store invalidates it before writing the flag; no later open, even after that one fails, reads
    it as vouching for payloads.
  - **Recovery on open.** `open_with_payloads` reads back, rewrites and flushes the payloads of
    every record after the marker. Without a valid marker (a store attached for the first time,
    whose plain marker was invalidated, or a removed marker) it checks the **whole journal**, not
    the last segment, so the work is bounded by the marker's lag (about a second of records)
    only when a marker exists. Losses found here, and losses the store set aside earlier, are
    reported for every record in the journal that references them. The records after the
    durable point are then **copied**, unflushed, to a fresh active segment, the `chunk.lost`
    records for them are appended after them, and one flush makes both durable. Only then is the
    manifest stored that stops naming the old copies, so a failed or interrupted open loses
    nothing the previous run had flushed. When the copy replaces the old segment whole, the old
    file is removed once that manifest is durable, so restarts do not grow the journal. Open
    never flushes the previous run's segment file again, for the same reason recovery never
    re-flushes a chunk.
  - **The event exists; the operation state does not yet.** Each loss is a `chunk.lost` record
    and is listed by `Journal::lost_payloads`. The operation-state projection that Decision 3
    names arrives with the runtime (WP3.3).
  - **Keys that are gone are not a loss.** A keychain that no longer holds a pocket's KEKs (a
    reset, a moved data directory) makes recovery fail closed and touches no chunk. A put in
    such a pocket fails closed too: it never creates a fresh KEK version under which the existing
    key files would look tampered with.
  - **Shredded chunks.** A chunk shredded after the record that references it is not a loss when
    a `chunk.shredded` record for it follows. A coordinated store shreds only through
    `Journal::shred`, which appends that record, flushes it, rotates the KEK and removes the
    chunk while no other record can be appended. The re-wrap of the pocket's other keys runs
    after the writer is free, through the returned `PendingRewrap` (finished explicitly or when
    dropped); until then the old KEK lives. The store marks the chunk before the record is
    appended, and until a put of the content succeeds or the shred completes, it neither vouches
    for the chunk nor serves it: a record appended afterwards that references it is refused,
    whichever step of the shred failed, its own flush included. If `append` refuses the record or
    fails to write it, no record exists (a line it did not write whole is never read back) and
    the mark is lifted; if the record was written and a flush failed, inside `append` (a window
    that fell due, or strict mode) or after it, the chunk is marked again, even if a put lifted
    the mark meanwhile, since `recover` can still make the record durable. At most
    `MAX_UNFINISHED_SHREDS` (4,096) failed shreds stay marked; past that, a shred is refused
    before its record until earlier ones are retried. A direct `ChunkStore::shred` on a
    coordinated store is refused. A shred whose record is durable but which a crash interrupted is completed when the
    journal opens, once its record is durable again after the open's flush, and it counts as
    unfinished while a file of the pair or an older KEK version remains; the store's own startup
    would otherwise re-wrap the leftover key and leave the content readable. Both `chunk.lost` and
    `chunk.shredded` name the chunk in metadata, never as `payload_ref`, and `append` enforces
    it.
- **Added beyond the decision (I-02, S-6).**
  - **Payload before record.** With a store attached, the journal refuses a record whose
    `payload_ref` is not stored (`JournalError::PayloadNotStored`).
  - **One writer per chunk.** Every operation on a chunk (put, flush, recovery, verification,
    shred) holds that chunk's slot, and every atomic write uses its own temporary. A rotation
    lock per stripe of pockets (64 stripes) keeps a shred from destroying the KEK a concurrent
    put is wrapping under or a read is unwrapping with (a put's, a check's or recovery's read-back
    of stored content included); only puts, reads and flushes in the same
    stripe wait while a shred re-wraps its pocket (two flushed writes per key file). The journal
    writer is released before the re-wrap, but its flush still waits while a re-wrap holds the
    stripe of a pocket in which a chunk is pending, and so does an append that has to read back
    content from an earlier run in that stripe.
  - **A pair a shred leaves on disk is never overwritten with the journal.** A shred forgets its
    chunk before removing the files; if the removal fails, the chunk is indexed as possibly on
    disk, so a later put of the same content rewrites the pair flushed with its own data key.
  - **Rotation re-wraps are always flushed.** The old KEK is destroyed right after, so an
    unflushed re-wrap lost to power would leave a key file only the destroyed KEK can open. For
    the same reason every readable key file of the pocket is written again, as a fresh flushed
    file, before old versions are destroyed, also one already at the current version: a re-wrap
    whose directory flush failed leaves its new file visible but not durable.
  - **Quarantine is durable.** The quarantine folder is flushed before any later flush of the
    chunk folders can make the removal there durable.

**Verification as built.**
- **Kill harness.** The real-OS writer stores a distinct payload before each intent. Every
  acknowledged record's payload must read back after the kill.
  - Windows, local: 60 kills, 0 lost.
  - CI: 40 kills per OS per merge, 10,000 nightly.
- **Simulation (`uaos-state/tests/durability.rs`).** It runs under two disk models: a failed
  flush either drops the unflushed bytes, or keeps serving them without ever making them durable.
  - **Flush-ordering scenario.** A flush fails at every possible step, then the power goes. A
    record at or before `flushed_through` must have a readable payload.
  - **Regression tests.** One for each finding of the seven review rounds fixed in code, and
    one for each defect the extended schedules found afterwards. Each round-four test was
    checked to fail with its fix reverted. These are fixed by construction, with no test that
    fails when they are reverted: second round L3 (losses set aside before quarantine) and L4 (a
    concurrent put between two recovery steps); third round M3 (the stripe count), the marker
    half of M1 (restarts are also held flat by removing the replaced segment), the data-file
    half of L3, and two parts of L4 (recovery clears only what it saw; `prepare` poisons);
    fifth round, the flush window, which closes the microseconds between a concurrent write's
    failure and its poisoning (the generation check it completes is tested).
  - **Random crash schedules.** Under three flush policies (flushes only when asked, strict,
    and a window that falls due, so appends flush on their own as in production): writes,
    repeated payloads, write-ahead shreds (their re-wraps
    left pending across later operations, finished later, or lost to a crash), flushes, failed
    flushes, failed appends, clock advances, process crashes, power losses and recoveries, with
    faults still armed during the next open, followed by a crash or a power loss. 64 cases per
    merge; 12,000 run locally on the final code. Every acknowledged record survives a process crash (except records that existed only
    in memory after a flush and its rewrite both failed, ADR-0003). Every flushed record's
    payload survives a power loss unless its loss was journaled first. No surviving record's
    payload is unreadable without a `chunk.lost` record.
- **Gate self-test.** The `journal-durability` gate lists thirty seeded violations in
  `gates.toml`: twenty-nine for this ADR, one per silent-loss class the seven reviews and the
  schedules found (one of them, `chunk-put-shared-temp`, checks temporary naming only), and P1's
  `journal-ack-without-write`.
- **Not modelled, stated plainly.** `SimFs` cannot model a failed directory flush that drops
  entries, so the poisoning that rule triggers is tested only for being triggered. Open reads
  every `chunk.shredded` record in the journal to find unfinished shreds: the cost grows with
  history until compaction (P4). It asks the keychain once per pocket, not once per record.
- **Bench: the target is not met on the reference machine.** The details are in
  [the appendix](appendix/0018-chunk-put-2026-10-15.md).
  - Balanced chunk put, 4 KiB, after the fixes: p99 is 1.55 ms on Windows 10 (solid-state drive)
    against the 0.5 ms target. The fixes did not make this path slower in the one A/B session
    (`2cf78f8`, run once, measured 1.93 ms p99).
  - Without the flush, the cost is the creation of two files per chunk.
  - Creating chunk files in place, with no temporary or rename, was also measured: it halved
    p50 but tripled p99, so the rename stays.
  - Linux and macOS numbers come from the nightly `ack-latency` job.
  - This is the condition Decision 4 names for its follow-up: one key file per chunk is now the
    measured cost. A per-pocket keystore log would halve the file count, but it changes shred
    semantics (ADR-0007). It therefore needs its own ADR and the maintainer's decision; it does
    not ride in with this change.
