# Adversarial review: WP3.A1 chunk durability (P3 Move 1, PR-1, ADR-0018)

**Reviewer:** a fresh-context review agent with the fixed V1 checklist (plan v2 §4.2), read-only,
probing a scratchpad export of the branch. **Reviewed:** `2cf78f8` (`p3/a1-chunk-durability`),
2026-10-15.
**Result:** 0 Critical · 4 High · 7 Medium · 7 Low. Each High finding was a payload loss that ended
with a durable record and no `chunk.lost` record; three reproduced inside `SimFs` with a single
process. The High findings blocked merge.
**Resolution:** every High and Medium finding fixed with a regression test; Low findings fixed or
accepted with a reason. The property test, extended as M6 asked, then found four more defects
(N1–N4), all fixed and pinned. One item needs a maintainer decision (L7). A second V1 review of
the fixes is pending; the PR stays draft until it is clean.

## Findings as reported

### High

**H1. `open()` moved the durable point past lost records before it journaled the loss.** The
previous segment was sealed and the `FLUSHED` marker written naming the previous run's last record;
only then were `chunk.lost` records appended, after `verify_and_sync` had already deleted the
unreadable pairs. If that append failed, or the process died in between, the next open saw a valid
marker past the record and never reported it. Without a marker, the fallback started at the new,
empty segment.

**H2. `recover()` made records durable before their losses were journaled, and most recover arms
dropped the losses.** `take_lost` emptied the store's set, `sync` made the records durable and moved
the marker, and only then were the losses appended. If that failed, the loss lived only in memory,
and the `Healthy`, `DiskFull`/`WriteFailed` and `FlushFailed` arms returned healthy without
reporting it.

**H3. A failed payload flush outside `Journal::sync` was invisible to the journal.** The inline
flush at the pending cap (or any public `sync_pending` call) could fail, after which the next
journal flush succeeded on the now-truncated file and marked the records durable, and `known` kept
vouching for the chunk.

**H4. Recovery after a failed flush trusted the page cache ("fsyncgate").** It read each pending
chunk back and flushed the same file again. After a writeback error the OS may serve cached bytes
it will never write, and the second flush reports success. `SimFs` dropped failed pages, so the
simulation could only show the case where the read-back detected the loss.

### Medium

- **M1.** A second put of the same chunk could return before the chunk was in `pending`, so a
  flush taken in between missed it.
- **M2.** `recover_pending` (and `verify_and_sync`, `shred`) removed a pair without the chunk's
  slot, so a concurrent put's fresh pair could be deleted underneath it.
- **M3.** A put racing a shred in the same pocket could wrap its key under a KEK the shred then
  destroyed. The race predates this change.
- **M4.** `is_stored` trusted a never-flushed chunk left by an earlier process.
- **M5.** Unreadable chunks were deleted, not quarantined, including when the keychain lost the
  key (a moved data directory, a reset) or the file failed authentication (S1). Error texts and
  codes did not fit the new failures.
- **M6.** The property test could not reach the failure classes it was cited for: no faults
  during open, one sync fault at a time, no append faults, a clock that never advanced, no shreds,
  and a disk model that made H4 correct by construction.
- **M7.** Claims and docs were stronger than the evidence (`claims.md`, ADR-0018, CHANGELOG, the
  bench appendix).

### Low

- **L1.** A panic while writing leaked the chunk's in-flight slot.
- **L2.** The chunk store started without a lock of its own; legacy `*.uaos-tmp` names were never
  swept; on Windows a shred during a flush could cause a spurious flush failure.
- **L3.** `Journal::open` without the store silently sealed an unverified tail.
- **L4.** Unbounded `lost` list and `pending` set past the cap; the shred lookup was quadratic in
  the tail; two sequential flushes per verified chunk.
- **L5.** The `chunk.lost`/`chunk.shredded` conventions were unenforced, and a loss could be
  reported twice.
- **L6.** `chunk-put-shared-temp` bites only a name-level test; the S-6 test always slept 2 s.
- **L7.** ADR-0018 was still Proposed, its p99 ≤ 0.5 ms bar is unmet, and it still named a
  `DurabilityCoordinator` folded into `Journal`.

## Resolution

Tests are in `crates/uaos-state/tests/durability.rs` unless named otherwise. Negatives run with
`cargo xtask negative <id>` and are listed under the `journal-durability` gate in `gates.toml`.

| Finding | What changed | Proof |
|---|---|---|
| H1 | Open appends the losses it found after the previous run's records, and one flush covers both **before** the marker moves; if reporting fails, open fails and the next open checks the same tail. No flush runs and the marker never moves while a loss is unreported, set aside, or the store is poisoned. Without a valid marker the **whole journal** is checked | `h1_open_reports_a_loss_before_its_marker_moves`, `h1_a_failed_open_leaves_no_record_durable_before_its_loss_record`; negative `marker-before-loss-report` (removes all three defences) **PROVEN** |
| H2 | `chunk.lost` records are appended without rotating or flushing, then one flush covers them with the records they report. Every recover arm ends by reporting what is still unreported. While a loss waits, `append` and `sync` refuse and `health()` reports it; recovery moves the unflushed records to a fresh segment without flushing them first | `h2_a_loss_survives_a_failed_report_and_other_recover_branches`, `n3_…`; negative `loss-flushed-before-report` **PROVEN** |
| H3 | Any failed store flush poisons the store: `put`, `is_stored` and `sync_pending` refuse until `recover_pending`, and the journal's flush sees it. The inline flush at the cap is gone: a put past `MAX_PENDING` is refused (`PendingFull`) | `h3_a_store_flush_failure_stops_the_journal`; negative `store-flush-failure-forgotten` **PROVEN** |
| H4 | Recovery **rewrites** each readable pending chunk to new files, flushed, keeping its data key; it never re-flushes the failed file. `SimFs::set_failed_sync_keeps_cache` models the writeback error (cached bytes served, never durable), and the property test runs in both modes | `h4_recovery_rewrites_content_instead_of_reflushing_the_failed_file`; negative `recovery-reflushes-same-file` **PROVEN** |
| M1 | The chunk is remembered and enrolled in `pending` before its slot opens | Structural; no hook exists between the two steps any more |
| M2 | Recovery, verification at open and shred hold the chunk's slot. A pending file missing at flush time is a failure, never success | `m2_a_quarantine_and_a_concurrent_put_of_the_same_chunk_never_lose_it` (the race at open; during runtime recovery a poisoned store refuses puts outright) |
| M3 | A rotation lock: puts wrap under the current KEK holding it shared; a shred's rotation holds it exclusively. Order is always slot, then rotation | `m3_a_put_racing_a_shred_in_the_same_pocket_stays_readable`, both modes |
| M4 | A chunk found on disk from an earlier process is rewritten, flushed, before `is_stored` or `put` vouches for it | `n1_…` covers the put path |
| M5 | Unreadable chunks are quarantined under the pocket's `quarantine/` folder. `chunk.lost` metadata names the cause (`missing`, `short`, `unauthentic`). A pocket whose KEKs are gone fails closed and touches nothing: the store no longer creates a fresh version 1 at open. `get` keeps S1 `Corrupt` for authentication failures. New codes `STORE_PAYLOAD_LOST`, `STORE_PAYLOAD_FLUSH_FAILED`, `JOURNAL_PAYLOAD_NOT_STORED` (a caller error) | `m5_keyring_failures_fail_closed_without_touching_chunks`, `a_failed_payload_flush_stops_the_writer_until_recovery_reports_the_loss` |
| M6 | Schedules now include failed segment appends, faults still armed during the next open, clock advances that move the marker, write-ahead shreds and re-puts, and the cache-keeping disk model. 64 cases per merge; 12,000 run locally on the final code. **Accepted:** size-based rotation is not reached (the 64 MiB segment target is a contract constant); rotation shares `sync`, and the disk-full path exercises `rotate` | `payload_durability_under_random_crash_schedules`; it found N1–N4 below |
| M7 | `claims.md` row narrowed to simulation and to what the tests prove, citing this gate's negatives. ADR-0018's implementation section rewritten (no separate coordinator type, whole-journal fallback, inline flush, the projection still to come). Appendix: the flush runs inline today, and the 2026-10-15 rows are marked suspect. CHANGELOG corrected | review of the text |
| L1 | The slot is an RAII guard, released on drop | Structural |
| L2 | The store takes `chunks/chunks.lock` (`InstanceLocked`). Legacy `*.uaos-tmp` names are swept. A shred can no longer run during that chunk's flush (both hold its slot) | `l2_one_chunk_store_per_data_directory`; platform `temp_names_*` tests |
| L3 | A journal whose `FLUSHED` marker exists refuses to open without its store (`PayloadsRequired`). The marker is written at the first open even with no record | `l3_a_coordinated_journal_refuses_to_open_without_its_store` |
| L4 | `lost_payloads` keeps the latest `MAX_LOST_LISTED`; puts past `MAX_PENDING` are refused; shreds and earlier reports are indexed once at open. **Accepted:** verification at open flushes each rewritten chunk separately; the tail is bounded by the marker's lag (about a second of records) while the marker is valid | — |
| L5 | `append` refuses `chunk.lost` and `chunk.shredded` records with `payload_ref` set or without the `chunk` metadata key. A loss leaves the unreported list once its record reached the OS, and records already named by a `chunk.lost` record are not reported again | `l5_chunk_records_name_their_chunk_and_a_shred_is_not_a_loss` |
| L6 | **Partly accepted.** `chunk-put-shared-temp` stays name-level: with one writer per chunk, no remaining behaviour depends on shared temporaries alone. The S-6 test now waits at most 0.5 s | — |
| L7 | The implementation section no longer implies a separate coordinator. Status: the maintainer accepted ADR-0018 on 2026-10-15; the status line lands with the decision record (PR #24). **Open:** the p99 ≤ 0.5 ms target is unmet (1.55 ms on the reference machine). The maintainer decides whether to amend the target or open the keystore-log ADR that Decision 4 names | appendix, 2026-10-16 section |

## Found after the fixes (N1–N4)

The extended property test found four more defects in the fixed code. N4 is latent since P1.

| ID | Defect | Fix | Proof |
|---|---|---|---|
| N1 | A put of content already on disk from an earlier process rewrote it **unflushed**. Once that process died, the next directory flush made the durable copy empty, under a record that was durable before | Such pairs are replaced only by a flushed write. The store indexes the key files present at open (8 bytes each, at most 2^20; past that, or once `known` is cleared, every put reads back), so a new put needs no file-system call to tell | `n1_a_rewrite_of_a_chunk_from_an_earlier_process_is_flushed`; negative `chunk-rewrite-unflushed` **PROVEN** |
| N2 | A rewrite generated a fresh data key. A failure between the data-file and key-file writes left new data that no key file opened | Rewrites keep the pair's data key, so every intermediate state opens | `n2_a_rewrite_that_fails_between_its_two_files_leaves_a_readable_pair`; negative `chunk-rewrite-new-data-key` **PROVEN** |
| N3 | A `sync` while a found loss waited to be journaled (the disk filled while it was reported) made its record durable before the loss record | `sync` and `append` refuse while a loss is unreported; recovery moves the unflushed records to a fresh segment unflushed | `n3_a_loss_waiting_to_be_journaled_holds_back_every_flush`; negative `loss-flushed-before-report` **PROVEN** |
| N4 | Open flushed the previous run's active segment in place. After a failed flush, a second flush of the same file can report success without writing, and the manifest then sealed records a power loss took away; a failing flush dropped what the OS held | Open copies the records after the durable point, unflushed, to a fresh active segment and keeps the old file as suspect up to that point. Its `chunk.lost` records follow them, and one flush covers both, so a failed open never leaves a record durable ahead of its loss record | `n4_open_copies_the_previous_runs_records_instead_of_flushing_their_file_again`, every fault position in both disk models; `h1_a_failed_open_leaves_no_record_durable_before_its_loss_record`; negative `open-trusts-previous-segment` **PROVEN** |

Also fixed: a shred now forgets the chunk before removing its files, so a partial failure cannot
leave a put vouching for it from memory. The property test models shreds the way the kernel must
perform them: the `chunk.shredded` record is written and flushed first.

## Bench

The fixes cost nothing measurable on the balanced put path: p50 1.14 ms, p95 1.34 ms, p99 1.55 ms
on the reference machine, against 1.20/1.69/1.93 ms for `2cf78f8` in the same session
(`docs/adr/appendix/0018-chunk-put-2026-10-15.md`). One measurement lesson is recorded there: builds
in the target directory shared by several worktrees produced byte-different binaries of the same
code that ran about 0.5 ms slower, so bench numbers now come only from a dedicated target.
