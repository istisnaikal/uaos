# ADR-0003: Journal as source of truth; durability classes; pending gates

**Status:** Accepted (2026-10-12). Windows spike numbers recorded; Linux and macOS numbers are owed (plan v2 PD-01)
**Plan refs:** D3, D4, D5, D20, §4.2 · **Deviates from:** CLAUDE.md §3 Storage ("Transactional state: SQLite WAL") and §4 merge-blocker wording

## Context

CLAUDE.md requires "kill -9 critical event loss 0", tamper evidence, export/delete, and local
overhead p95 ≤ 25 ms. Two stores (journal + SQLite) written independently drift apart on crash.

## Decision

1. **The journal is the truth; SQLite holds projections** that can be deleted and rebuilt
   (`uaos journal rebuild`). Deviation from CLAUDE.md's storage line: SQLite stays the
   transactional *projection* store; it is no longer an independent source of truth.
2. **Chain over exact bytes.** `hash_i = SHA-256(stored bytes of line i)`; line `i+1` carries
   `prev_hash`. No canonicalization (JCS rejected: an unmaintained implementation and IEEE-double
   number semantics). 64-bit integers are decimal strings.
3. **Durability classes:**
   - `critical` — the record is handed to the OS (`write`/`WriteFile` completed) **before the
     acknowledgement**. This is exactly what "kill -9 loss 0" requires: process death does not
     discard OS buffers.
   - Power-loss durability: **balanced** mode (default) group-commits fsync within a documented
     window **W**; **strict** mode fsyncs before every critical acknowledgement (`F_FULLFSYNC` on
     macOS, slow, documented).
   - **An fsync error is fatal for that segment:** the writer stops, events since the last good
     fsync are retained in memory and rewritten to a new segment, the old segment is marked
     suspect. Re-reading the page cache proves nothing and is never used as verification.
   - **If that rewrite also fails** (e.g. no space), the acknowledged records after the last
     flush exist only in the process's memory — the OS has already dropped its copy. The writer
     enters `FlushFailed`, refuses new records, and `recover()` retries the rewrite. A crash in
     this state loses those records; this is reported (S2), never hidden. The crash-durability
     guarantee is therefore stated precisely: *every acknowledged record survives a process
     crash, except records acknowledged after the last flush while the writer is in
     `FlushFailed`.*
   - **Recovery flushes before it seals.** On open, records the previous process left in the
     OS (acknowledged, not yet flushed) are flushed *before* the manifest seals the segment
     around them; a durable manifest never claims records a power loss could still remove.
     (Found by the deterministic simulation in WP1.2.)
     *Amended 2026-10-16 by ADR-0018:* open no longer flushes the previous run's segment in
     place, since a second flush of a file whose flush may have failed proves nothing. It copies
     the records after the durable point (the `journal/FLUSHED` marker) to a fresh segment,
     unflushed, journals any payload loss among them, and one flush then covers both; the
     manifest stops naming the old copies only after that flush. The rule above still holds: a
     durable manifest never claims records a power loss could still remove (WP3.A1 N4, H1).
4. **One combined `reserve+intent` record per Operation** before egress.
5. **Chunked, content-addressed payloads** (`hmac-sha256:` refs with a per-pocket key). A long
   session stores each message once (linear, not quadratic, growth). *Amended 2026-10-16 by
   ADR-0018:* payloads join the durability classes; a record's payload is stored before the
   record and made durable before it, and a payload found unreadable is journaled as
   `chunk.lost`.
6. **Crypto-shredding**: random per-chunk data keys wrapped by the pocket key; shredding deletes
   the wrapped key and rotates the pocket key. The chain stays verifiable through tombstones.
7. **Pending gates (deviation from CLAUDE.md §4 wording).** CLAUDE.md lists all merge blockers
   from day one. A gate whose subject does not exist yet is registered as `pending(phase)` in
   `gates.toml`: it blocks a **release** and is visible on every run, instead of passing a merge
   vacuously. Removing a gate requires an ADR.

## Alternatives rejected

- *SQLite-first with an outbox:* two sources of truth during recovery.
- *fsync before every acknowledgement by default:* pays power-loss cost for a guarantee the norm
  does not ask for; heavy on macOS and Windows.
- *Re-journaling full histories per turn:* ~0.2 GB per long session; disk exhaustion then fails
  closed for everything.

## Measured numbers

The P1 gate required critical-ack p50/p99 and the window W per OS before P1 closed. P1 closed with
only the Windows spike row; the rest is phase debt PD-01, recorded here rather than hidden.

| OS / disk | Source | write-ack p50 / p99 | group fsync p99 / p99.9 | strict fsync-per-ack p99 / max |
|---|---|---|---|---|
| Windows 10, entry-level NVMe (WD SN350), 2026-10-12 | spike H1, stand-in writer ([appendix](appendix/0003-h1-spike-results.md)) | 5.2 µs / 41 µs | 0.78 ms / 5.9 ms | 0.64 ms / 9.3 ms |
| Windows, Linux, macOS | production `Journal`, nightly `ack-latency` bench (PD-01) | owed | owed | owed |

The default power-loss window `W = 50 ms` (`uaos_contracts::limits::DEFAULT_FLUSH_WINDOW`) rests on
the Windows group-fsync p99.9 of 5.9 ms. It is re-confirmed or changed once Linux and macOS
(`F_FULLFSYNC`) rows exist. CI-runner numbers are labelled as such, because shared virtual disks
are not reference hardware.

## Production-journal kill results (WP1.6)

The `journal-durability` gate kills the real `Journal` (`OsFs`, system clock, OS randomness) in a
separate process, alternating kills after *k* acknowledgements and after random delays, and
checks every acknowledged record by sequence number **and hash**. 40 kills per OS run on every
merge; 10,000 per OS run nightly.

| OS | Kills | Acknowledged records lost |
|---|---|---|
| Windows 10, entry-level NVMe (local, 2026-10-13) | 1,000 | 0 |
| Linux, macOS, Windows (CI) | 40 per merge, 10,000 nightly | reported by CI |

## Verification

From P1 (`journal-durability` gate): 10,000 randomized kill -9 / `TerminateProcess` runs per OS
with zero lost acknowledged critical events; rebuild equivalence; fsync-error injection; disk-full
fail-closed (`disk-full` behavior); linear storage over 500 turns.
