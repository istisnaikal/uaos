# ADR-0003: Journal as source of truth; durability classes; pending gates

**Status:** Accepted (2026-10-12) — durability numbers to be filled from the P0/P1 spike
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
4. **One combined `reserve+intent` record per Operation** before egress.
5. **Chunked, content-addressed payloads** (`hmac-sha256:` refs with a per-pocket key). A long
   session stores each message once (linear, not quadratic, growth).
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

## Open numbers (spike, P0/P1)

Critical-ack p50/p99 and the window W per OS are measured and recorded here before the P1 gate.

## Verification

From P1 (`journal-durability` gate): 10,000 randomized kill -9 / `TerminateProcess` runs per OS
with zero lost acknowledged critical events; rebuild equivalence; fsync-error injection; disk-full
fail-closed (`disk-full` behavior); linear storage over 500 turns.
