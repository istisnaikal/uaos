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
the fixes found 1 High, 1 Medium and 6 Low findings, one of them introduced by an N4 follow-up,
a third found 1 High, 3 Medium and 5 Low, a fourth 2 Medium and 4 Low, a fifth 2 Medium and
3 Low, a sixth 4 Low, a seventh 1 Medium and 2 Low, an eighth 1 Low, a ninth 4 Low, a tenth
4 Low, an eleventh 1 High and 3 Low, and a twelfth 3 Low; all are fixed below.
The PR stays a draft until a review comes back clean.

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

The fixes did not make the balanced put path slower: p50 1.14 ms, p95 1.34 ms, p99 1.55 ms on
the reference machine, against 1.20/1.69/1.93 ms for `2cf78f8` in the same session (run once, so
one comparison, not a measured improvement)
(`docs/adr/appendix/0018-chunk-put-2026-10-15.md`). One measurement lesson is recorded there: builds
in the target directory shared by several worktrees produced byte-different binaries of the same
code that ran about 0.5 ms slower, so bench numbers now come only from a dedicated target.

## Second review (2026-10-16)

**Reviewed:** `35895c7`, `fc4b5a8`, `9865502` by a fresh-context agent with the same checklist,
in a scratch export. **Result:** 1 High · 1 Medium · 6 Low, plus two pre-existing defects.

| Finding | What it was | What changed | Proof |
|---|---|---|---|
| H1 | **Introduced by the fixes.** Open stored the manifest that marked the old segment suspect at the marker *before* the copied records were flushed. The marker lags by up to a second, so records the previous run had flushed and acknowledged after it existed only in the unflushed copy; a power loss right after the manifest write, or a failed open's flush and rewrite, lost them | The manifest is stored only after the copied records and their `chunk.lost` records are flushed; until then the old manifest names the old file, and the marker cannot move while the manifest is unstored | `r2_h1_a_power_loss_during_open_keeps_what_the_previous_run_flushed` (a filesystem that dies right after the manifest write), `r2_h1_a_failed_open_keeps_what_the_previous_run_flushed` (every fault position, both disk models, crash or power loss); negative `open-stores-manifest-before-flush` **PROVEN**; the property test now follows a failed open with a power loss too |
| M1 | Several fixes were pinned by no test: (1) disk-full recovery with an unreported loss flushing; (2) the same after a failed relocation; (3) the marker guard alone; (4) `is_stored` trusting an earlier process's pair; (5) a vanished pending file treated as flushed; (6) a loss set aside only after its quarantine | One deterministic test for each of (1), (2), (4), (5), (6), each checked to fail with its fix reverted. **Accepted for (3):** the marker guard is now defence in depth; the states it blocks are refused earlier (`sync` refuses with an unreported loss, a poisoned store fails the payload flush, and open recovers a poisoned store) | `r2_m1_*` (five tests); negatives `is-stored-trusts-earlier-pair`, `flush-skips-missing-pending-file`, `loss-set-aside-after-quarantine` **PROVEN** for the three that can lose content silently |
| L1 | Open ignored a store poisoned, or holding set-aside losses, before the journal attached, wrote no marker, and so allowed a later plain open | Open recovers a poisoned store first. Losses the store set aside are reported for every record in the journal that references them; with no journal yet, none can be referenced | `r2_l1_a_store_poisoned_before_the_journal_attached_is_recovered_at_open` |
| L2 | Only `sync_pending` poisoned the store; failed directory flushes elsewhere did not | In balanced mode, any failed flushed write or chunk-directory flush poisons the store. The docs say so | `r2_l2_a_failed_directory_flush_poisons_a_balanced_store` |
| L3 | `verify_and_sync` dropped the losses it had found when it failed midway | It sets each loss aside in the store before quarantining it; open takes them | By construction; no test fails `verify_and_sync` midway (corrected in the third round) |
| L4 | A loss could be reported twice when a chunk was lost again after its first report was appended but not flushed | Records an unflushed `chunk.lost` already names are skipped | Fixed by construction; no deterministic test (it needs a concurrent put between two recovery steps) |
| L5 | `PendingFull` had no test and its contract was unstated | `put` documents that the caller flushes the journal and retries | `r2_l5_pending_full_is_refused_and_cleared_by_a_flush` (16,384 puts; the simulated filesystem no longer collects garbage on every rename, which made this quadratic) |
| L6 | The appendix said "within run-to-run noise" although `2cf78f8` measured slower and was run once | The text states the measured difference and that it is one comparison | review of the text |
| Pre-existing | A shred that rotated the KEK and then crashed before removing the files: the store's startup re-wrapped the leftover key, and the content stayed readable | The journal completes, at open, every shred it recorded whose pair is still on disk, **after** the open's flush. Completing it earlier was found by the crash schedules to act on a shred record a power loss could still take away | `a_shred_interrupted_after_its_record_is_completed_at_open`, `r2_a_shred_is_completed_only_once_its_record_is_durable`; negative `shred-not-completed-at-open` **PROVEN** |
| Pre-existing | `get` racing a shred of another chunk could report existing content as unavailable | `get` holds the rotation lock shared | By construction (lock order unchanged: rotation only) |

## Third review (2026-10-16)

**Reviewed:** `135f327..08ba4fb` (rebased onto `e5b0ec8`) by a fresh-context agent, in a scratch
export. **Result:** 1 High · 3 Medium · 5 Low.

| Finding | What it was | What changed | Proof |
|---|---|---|---|
| H1 | A request that stored the same content between the write-ahead shred record and the shred got `Ok` from memory and appended a record; the shred then removed the content, and once the marker passed that record, nothing explained it | `Journal::shred` appends the record, flushes it and shreds while holding the writer, so nothing can be appended in between; the store forgets the chunk first, so a later record is refused until the content is stored again. A coordinated store refuses a direct `ChunkStore::shred` (`ShredThroughJournal`) | `r3_h1_after_a_shred_a_record_needs_its_content_stored_again`; negative `shred-bypasses-journal` **PROVEN** |
| M1 | Every open of a journal without a marker copied its whole active segment and kept the old file, so restarts grew the journal | Every journal keeps a marker; the store-coordination flag moved to its own file (`PAYLOADS`). A copy that replaces the old segment whole removes it once the manifest is durable | `r3_m1_restarts_do_not_grow_the_journal` |
| M2 | "Complete shreds only after the manifest is stored" was pinned by no test | A test whose manifest write fails at open, then the power goes | `r3_m2_shreds_at_open_wait_for_the_manifest`; negative `shreds-before-manifest-at-open` **PROVEN** |
| M3 | One store-wide rotation lock: a shred stalled every read, put and flush | 64 lock stripes by pocket; only the same stripe waits. The stall that remains is stated | By construction (lock order unchanged) |
| L1 | Quarantined files were never made durable | The quarantine folder is flushed right after the renames | `r3_l1_quarantined_files_survive_a_power_loss` |
| L2 | After a keychain reset, one put created a fresh KEK version 1 and the next open quarantined the old chunks as lost | A pocket that had key files and has no KEK refuses puts (fail closed) | `r3_l2_a_put_after_a_keychain_reset_fails_closed` |
| L3 | A shred completed at open that failed after its key file was removed was never finished by a same-process retry | A shred counts as unfinished while a file of the pair or an older KEK version remains | `r3_l3_a_shred_failing_midway_at_open_is_finished_by_the_next`; negative `shred-incomplete-key-only` **PROVEN** |
| L4 | The poison flag was cleared by recovery even for failures during it; `prepare`'s directory flushes did not poison | A generation counter: recovery clears only what it saw when it began; a put that joins the pending set while poisoned is refused; `prepare` poisons. **Accepted:** `SimFs` cannot model dropped directory entries; stated in the ADR | By construction |
| L5 | Open scans every shred record; doc counts were inconsistent | The cost is stated (until compaction, P4); the counts are corrected | review of the text |

The crash schedules also found, after these fixes, that a store open can fail while it finishes an
interrupted rotation under an armed fault; the harness now retries a failed store open the way it
retries a failed journal open.

## Fourth review (2026-10-16)

**Reviewed:** `a6e8255` (on `555494b`) by a fresh-context agent, in a scratch export.
**Result:** 0 High · 2 Medium · 4 Low. No failure, crash or power-loss order through
`finish_open` and `Journal::shred` dropped a flushed record, made a record durable before its loss
record, removed a segment file the durable manifest still named, or left shredded content
readable or an old KEK alive; 6,000 crash schedules and the 42 tests passed in the export.

| Finding | What it was | What changed | Proof |
|---|---|---|---|
| M1 | Since every journal keeps a marker (third round, M1), a plain journal's marker was trusted by the first open with a store as "payloads checked up to here", so a record whose payload was never stored stayed unreadable with no `chunk.lost` | The marker is the payload check's starting point only if `PAYLOADS` existed when the journal opened; otherwise the whole journal is checked and the marker bounds only the copy. Three docs corrected | `r4_m1_a_plain_journals_marker_does_not_skip_the_payload_check`; negative `plain-marker-trusted` **PROVEN** |
| M2 | `Journal::shred` re-wrapped the whole pocket (one flushed write per key file) while holding the journal writer: shredding one chunk in a pocket of 10,000 blocked every append and flush for seconds | Under the writer: append, flush, rotate the KEK, remove the chunk and flush its directories. The re-wrap and the destruction of the old KEK run after, holding only the stripe, through the returned `PendingRewrap` (`finish`, or on drop); an unfinished one is completed by the next shred in the pocket or the store's next open | `r4_m2_the_rewrap_runs_after_the_writer_is_free` (the writer takes a record while the old KEK still lives; 19 re-wraps after; a dropped remainder finishes) |
| L1 | A put whose data file entered `data/` before a failed directory flush, and which joined the pending set after a recovery cleared the poisoning, got `Ok` and was never rewritten | A put reads the poisoning generation before it writes; if it changed by the time the chunk joins the pending set, the store is poisoned again and the put refused, so the next recovery includes it. **Found while fixing it:** `Journal::recover` was a no-op when the store was poisoned but the writer healthy (also reachable through `prepare`'s directory flush), so the refusals outlasted every recovery; it now recovers such a store | `r4_l1_a_put_spanning_a_failed_directory_flush_is_recovered_with_it` (bites with either fix reverted); negative `put-overlapping-failed-flush` **PROVEN** |
| L2 | A shred whose KEK rotation failed left the chunk remembered, so a later record referenced it without the content being stored again, and that record cancelled the shred at every later open | Reordering `forget` alone was not enough: the store re-reads the pair from disk and vouches for it. A shred now marks its chunk before anything else, under the chunk's slot so a concurrent put cannot undo the mark (by construction; no deterministic test reaches that window); until the content is stored again or the shred completes, the store neither vouches for it nor serves it. Tested on both the rotation-failure and the removal-failure path. **Found while fixing it:** after a failed removal the forgotten pair was no longer indexed as on disk, so a put of the same content would have written a fresh pair with the journal over it, against the store's own rule; it is now indexed | `r4_l2_a_failed_shred_never_vouches_for_its_content`, `r4_l2_storing_the_content_again_lifts_the_refusal`; negative `failed-shred-vouched` **PROVEN** |
| L3 | Open made one uncached keychain query per recorded shred | Asked once per pocket; completing a shred finishes its pocket's rotation | `r4_l3_open_asks_the_keychain_once_per_pocket` |
| L4 | ADR-0018 claimed every review fix was pinned by a test that fails with it reverted; `claims.md` said "two review rounds" | The ADR lists the fixes held by construction (second round L3, L4; third round M3, the marker half of M1, the data-file half of L3, two parts of L4); `claims.md` says four rounds | review of the text |

Each round-four test was checked to fail with its fix reverted (eleven mutations, all bite).

## Fifth review (2026-10-16)

**Reviewed:** `f4f90f1` (on `555494b`) by a fresh-context agent, in a scratch export.
**Result:** 0 High · 2 Medium · 3 Low. Every round-four change it reverted failed its test; 6,000
crash schedules passed; no deadlock was found (a slot is never taken while a stripe is held).

| Finding | What it was | What changed | Proof |
|---|---|---|---|
| M1 | Round four's M1 fix held only while the first open with a store succeeded: if it failed after writing `PAYLOADS` (a crash during the whole-journal check, a refused keychain, a full disk), the next open trusted the plain journal's marker and never checked the earlier records | The first open with a store invalidates the plain marker (writes `none`) before it writes `PAYLOADS`, so no open, in the same process or after a crash, reads it as vouching for payloads. This replaces round four's check of the flag, which it makes redundant | `r5_m1_a_failed_first_open_with_a_store_does_not_trust_the_plain_marker` (with and without a crash between the opens), `r4_m1_*`; negative `plain-marker-trusted` re-anchored, **PROVEN** |
| M2 | A journal flush was acknowledged even when a flushed write elsewhere in the store failed and poisoned it while the flush ran; round four's `PendingRewrap` made that overlap designed (a re-wrap's `keys/` flush on another thread), so recovery would never rewrite the pending chunk whose entry the failed flush may have dropped | The flush reads the poisoning generation before its batch and refuses to acknowledge it if the generation changed, keeping the batch pending. Every flushed write or directory flush that poisons now holds a store-wide flush window until it has poisoned, and the flush takes the window before its check, so a failure that overlaps it is always seen (by construction: the microseconds between a failure and its poisoning cannot be reached by a deterministic test) | `r5_m2_a_flush_is_not_acknowledged_across_a_failed_rewrap` (the reviewer's repro: the flush now fails, the chunk stays pending, recovery rewrites it); negative `flush-acked-across-poisoning` **PROVEN** |
| L1 | The shred mark came too late and went too early: a put that failed had already lifted it, and a shred whose own flush failed never set it; either way, once the record was durable, a later record cancelled the shred | The journal marks the chunk before it appends the record (mark only: forgetting it there would drop a pending chunk before the flush, which the reviewer found loses payloads); a put lifts the mark only once it has succeeded | `r5_l1_a_failed_put_keeps_a_failed_shred_refused`, `r5_l1_a_shred_whose_flush_failed_stays_refused`; negatives `failed-put-lifts-shred-mark`, `shred-marked-after-record` **PROVEN** |
| L2 | "The journal writer does not wait for the re-wrap" was false: the journal's flush waits for a re-wrap holding the stripe of a pocket with a pending chunk | The ADR, the `PendingRewrap` docs and the CHANGELOG say what holds: the writer is released before the re-wrap; its flush can still wait | review of the text |
| L3 | The crash schedules dropped each `PendingRewrap` at once, and the set of marked chunks had no bound | The schedules keep re-wraps pending across later operations, finish them later, or lose them to a crash (no `Drop` runs). At most 4,096 failed shreds stay marked; past that a shred is refused (`ShredBacklog`) before its record | `r5_l3_unfinished_shreds_are_bounded`; the property test |

**Found by the extended schedules after these fixes.** With re-wraps left pending, the crash
schedules found a defect that predates this PR: a re-wrap whose `keys/` flush failed left its new
key file visible but not durable; a later re-wrap skipped that file as already current and
destroyed the old KEK, so after a power loss the only durable key file needed the destroyed KEK
(open then failed closed with `Retired`; in a longer schedule the payload was silently
unreadable). A rotation now writes every readable key file of the pocket again, as a fresh
flushed file, before it destroys old versions. Proof: `r5_a_failed_rewrap_never_leaves_a_key_only_a_retired_kek_opens`,
the shrunk schedule kept in `durability.proptest-regressions`, and negative
`rotation-skips-current-key` **PROVEN**.

Each round-five test was checked to fail with its fix reverted (seven mutations, all bite).

## Sixth review (2026-10-16)

**Reviewed:** `2712e8b` (on `555494b`) by a fresh-context agent, in a scratch export.
**Result:** 0 High · 0 Medium · 4 Low. No failure, crash or power-loss order lost a flushed
record, left a reference to removed content unexplained, left shredded content readable or
destroyed a KEK a durable key file still needed; 12,000 crash schedules passed, and every
round-five fix reversal bit.

| Finding | What it was | What changed | Proof |
|---|---|---|---|
| L1 | The store's own flush of pending chunks (`sync_pending`, public) poisoned after its failing directory flush returned, outside the flush window, so a concurrent journal flush could acknowledge its batch in between | Every file and directory flush in the batch goes through the same `flushed` helper, poisoning inside the window | `r6_l1_a_failed_direct_store_flush_is_seen_by_a_concurrent_journal_flush`; negative `store-flush-poisons-outside-window` **PROVEN** |
| L2 | A put of the same content while `Journal::shred` ran lifted the mark; if the shred's flush then failed, `recover` made the record durable and a later record referencing the content cancelled the shred | When the record's flush fails, the chunk is marked again (beyond the bound), since the record can still become durable. Round five's negative `shred-marked-after-record` now removes both marks, since either one keeps that test passing | `r6_l2_a_put_during_a_shred_whose_flush_fails_does_not_lift_the_refusal`; negatives `shred-mark-not-restored` and the re-seeded `shred-marked-after-record` **PROVEN** |
| L3 | A shred refused before its record was written (a malformed record, a stopped writer) still marked its chunk, and a full-disk episode could fill the backlog with shreds that never had a record | When the append fails no record exists (a failed append is never acknowledged, and recovery excludes its bytes), so the mark this attempt set is lifted; an earlier shred's mark stays. **Corrected in the seventh round:** an append can write the record and then fail in its own flush | `r6_l3_a_shred_refused_before_its_record_leaves_the_content_alone`, `r6_l3_a_disk_full_episode_leaves_no_shred_backlog` |
| L4 | A read-back of stored content (by a put, a check or recovery) unwrapped its key file without the stripe, so a re-wrap finishing meanwhile failed it with a misleading keyring error | The read-back holds the stripe shared, in the existing lock order (slot, then stripe) | `r6_l4_a_put_reading_back_content_is_not_failed_by_a_finishing_rewrap` |

Each round-six test was checked to fail with its fix reverted (five mutations, all bite). The
reviewer noted that the crash schedules check neither old-KEK retirement nor that shredded content
is unreadable; the deterministic tests `r3_l3`, `r4_l2`, `r4_l3` and `r4_m2` pin those.

## Seventh review (2026-10-16)

**Reviewed:** `63ec5fc` (on `555494b`) by a fresh-context agent, in a scratch export.
**Result:** 0 High · 1 Medium · 2 Low. The Medium was a regression the sixth round introduced.
No deadlock was found: the lock order slot, `prepared`, stripe, window is acyclic, and a 20 s
stress run of puts, reads, direct and journal flushes, shreds and threaded re-wraps under
injected faults kept progressing.

| Finding | What it was | What changed | Proof |
|---|---|---|---|
| M1 | Round six lifted a shred's mark on any `append` error, but `append` can write the record and then fail in the flush it runs itself (a window that fell due, the default; or strict mode). `recover` then made the record durable while the content was vouched for again, and a later record cancelled the shred | The journal compares the next sequence number before and after: if the record was written, the chunk is marked again; only when no record exists is the mark lifted. The claim "a failed append is never acknowledged" is corrected in the code, the ADR and this record | `r7_m1_a_shred_whose_flush_inside_append_fails_stays_refused` (default policy), `r7_m1_a_shred_whose_payload_flush_inside_append_fails_stays_refused` (strict); negative `shred-unmarked-after-written-record` **PROVEN** |
| L1 | Every test and every crash schedule used a window that never falls due, so no append ever flushed on its own; that is how M1 survived | The crash schedules also run under the strict policy and under a one-second window that a tick makes due; the two M1 tests use the default and strict policies | the property test (12,000 schedules across the three policies) |
| L2 | An append that reads back content from an earlier run in a stripe waits for a re-wrap of that stripe, which the docs did not say (it predates round six) | ADR-0018 and the `PendingRewrap` docs say so | review of the text |

Two round-six negatives (`shred-mark-not-restored`, `shred-marked-after-record`) named the line
the sixth-round fix added; the seventh-round fix added a second such line, so both were re-anchored
to the flush-failure site and re-run (**PROVEN**).

## Eighth review (2026-10-16)

**Reviewed:** `91cf50f` (on `555494b`) by a fresh-context agent, in a scratch export.
**Result:** 0 High · 0 Medium · 1 Low. The seventh round's fix is correct: `next_seq` advances only
after a line is written whole, every error after that leaves a record `recover` or the next open
can make durable, and a torn line is never read back. Every negative's anchor occurs exactly once
at its intended site; 20,000 schedules passed, and stronger oracles 15,000 more.

| Finding | What it was | What changed | Proof |
|---|---|---|---|
| L1 | The crash schedules could not see the seventh round's M1 class: every record was preceded by a put, which lifts a shred's mark, and no check looked at shred refusal or completion; yet the seventh round cited them as proof | A second property test, `shred_refusal_and_completion_under_random_crash_schedules`, adds records that reference earlier content without storing it again, checks in each run that no such record is written after a written shred record without a put since, and checks after every reopen that a durable shred no later record uses leaves the content unreadable and one KEK version alive | With the seventh round's fix reverted it fails within seconds (shrunk schedule kept in `durability.proptest-regressions`); 12,000 schedules pass on the final code |

## Ninth review (2026-10-16)

**Reviewed:** `452360c` (on `555494b`) by a fresh-context agent, in a scratch export.
**Result:** 0 High · 0 Medium · 4 Low.

| Finding | What it was | What changed | Proof |
|---|---|---|---|
| L1 | `Journal::append` accepted the kernel's own records from callers on a coordinated journal. A `chunk.shredded` appended directly recorded a shred that never marked or removed the content: it stayed served, a later record referencing it needed no put, and the next open shredded it anyway. A `chunk.lost` from a caller exempted a healthy record from every later payload check | With a store attached, `append` refuses both: `chunk.shredded` goes through `Journal::shred`, and only the journal's own loss reporting writes `chunk.lost`. Three tests that appended a shred record directly to stage a crash before the shred now reach the same state through `Journal::shred` with a fault (a failing store flush, or a failing key removal) | `r9_l1_kernel_records_cannot_be_appended_directly` (each half checked to fail when reverted on its own); the rebuilt `r2_…` test checked to fail with the second round's defect reverted; negative `kernel-record-appended-directly` **PROVEN** |
| L2 | CI ran 64 cases of each durability property, far fewer than the local runs the docs cited | The nightly lane runs both properties at 20,000 schedules each on all three operating systems; ADR-0018 states what the 64 merge cases can and cannot catch | `nightly.yml`; 20,000 of each take about a minute in release locally |
| L3 | `claims.md` overstated two things: "one regression test per finding" (ADR-0018 lists findings fixed by construction, with no test), and shredded content being unrecoverable before its `PendingRewrap` has finished (the old KEK lives until then) | Both rows now say so | review of the text |
| L4 | The CHANGELOG and `claims.md` attributed the negatives to eight review rounds (the eighth added none); ADR-0018 attributed all twenty-nine to reviews and schedules (four come from its own verification plan); the eighth section's heading carried the wrong date; the bench appendix's "as shipped" row measured `fc4b5a8`, the first round's code | Attribution corrected everywhere; the heading carries the commit date; the row and ADR-0018 name `fc4b5a8` and say later rounds were not re-measured | review of the text |

**Found while verifying.** `tampering_is_detected` (P1) failed once in about 400 runs: the AEAD
nonce is OS-random, so the last tag byte the test overwrote with 0 was already 0 one run in 256,
and the "tampering" changed nothing. It now flips the byte; 600 runs passed.

**Verified locally (Windows, dedicated target directory):** 63 durability tests and the rest of
`uaos-state`, `uaos-testkit` and `uaos-ledger`; workspace clippy with warnings denied; 3 × 4,000
and 2 × 20,000 schedules of each property, in release; the 31 `journal-durability` negatives.

## Tenth review (2026-10-16)

**Reviewed:** `fcd2393` (on `555494b`) by a fresh-context agent, in a scratch export.
**Result:** 0 High · 0 Medium · 4 Low. No order of failures through the journal's own paths lost
a flushed record; the ninth round's refusal holds, and the three rebuilt tests still reach their
states and fail with their defects restored.

| Finding | What it was | What changed | Proof |
|---|---|---|---|
| L1 | The chunk store's public loss API worked on a coordinated store. A caller that called `recover_pending` and `take_lost` after a failed payload flush took the loss away from the journal: `recover` reported nothing and the record became durable with an unreadable payload and no `chunk.lost`. A caller's own failed `sync_pending` followed by its own `recover_pending` let `sync` make the record durable before its loss record | With a store attached, `recover_pending`, `take_lost` (now returning a `Result`) and `verify_and_sync` refuse callers with `LossesThroughJournal`; the journal uses crate-internal versions. A flush also refuses while the store holds a loss the journal has not taken | `r10_l1_a_coordinated_stores_losses_go_through_its_journal` (both of the reviewer's scenarios); negative `store-losses-taken-by-caller` **PROVEN** |
| L2 | Reporting losses at open removed from the front of a `Vec`: quadratic in the records that reference one lost chunk (27 s at 40,000 records in release) | The unreported list is a `VecDeque`, taken from the front in O(1). The `chunk.lost` records written at open without rotating are stated in ADR-0018's "Not modelled" | `r10_l2_every_loss_at_open_is_journaled_and_the_list_is_bounded` (1,124 records referencing one lost chunk: every one journaled, the latest `MAX_LOST_LISTED` listed); linear time by construction |
| L3 | The property tests' oracles accepted a store that loses every payload, as long as each loss is reported: after a crash they checked only that records survived, and nothing checked progress | After a process crash, every acknowledged record that survived must keep a readable payload unless a flush failure was armed after it was acknowledged (tracked per record) or a later shred removed it. After a power loss, only a `chunk.lost` record that survived the power loss excuses a flushed record's payload. A recovery with no fault armed must succeed and leave neither journal nor store refusing work | The reviewer's never-writes store now fails both properties (it passed 4,000 of each before); 52,000 schedules of each pass on the final code |
| L4 | `claims.md` says "except those ADR-0018 lists", but the list missed findings fixed by construction: the first round's M1, L1 and part of L4, the second round's pre-existing `get` race, and the fourth round's L2 slot part | Added to ADR-0018's list, with this round's L2; the first round's L4 list bound now has a test (above) | review of the text |

**Found by the stronger schedules.** On their first run the new oracles found that `recover`
treated a poisoned store only while the writer was healthy (the fourth round's L1 fix). With the
writer out of space and the store poisoned by a failed flush of its own, `recover` rotated the
segment, returned `Ok`, and left the store refusing every put until a later flush failed and a
second recovery ran. No record lost its payload; work stopped. `recover` now recovers the store
first, whatever state the writer is in, and takes its losses before any branch could flush the
records that reference them. Pinned by `r10_a_recovery_out_of_space_also_recovers_a_poisoned_store`
and the negative `recovery-leaves-store-poisoned` **PROVEN**; with the persisted seeds removed,
both properties find the old behaviour within 4,000 schedules.

**Found while verifying.** The negative `shred-bypasses-journal` stopped biting: its seed anchor, `if self.attached.load(Ordering::SeqCst) {`, now also matched the new refusal above it, and the runner replaced the first match. The anchor names its own site again, and the runner now refuses an anchor that occurs more than once in its file, so a seed can no longer land on the wrong site silently; every anchor in the file is unique.

**Verified locally (Windows, dedicated target directory):** 66 durability tests and the rest of
`uaos-state`, `uaos-testkit` and `uaos-ledger`; workspace clippy with warnings denied; 3 × 4,000
and 2 × 20,000 schedules of each property, in release; the 33 `journal-durability` negatives.

## Eleventh review (2026-10-16)

**Reviewed:** `8a33981` (on `555494b`) by a fresh-context agent, in a scratch export.
**Result:** 1 High · 0 Medium · 3 Low. The High finding blocked merge. The tenth round's store-first
recovery loses no loss and cannot loop; the caller paths to a coordinated store's losses are
closed; the power-loss excuse and the pruned exposure set are sound.

| Finding | What it was | What changed | Proof |
|---|---|---|---|
| H1 | An append that runs out of space leaves part of its line in the segment (`write_all` on ENOSPC) and the writer `DiskFull`. A payload flush failure then set `PayloadFlushFailed` over it (from a caller's `sync`, or from the payload flush inside `recover`'s own rotation), and `recover` turned that into `Healthy` without leaving the torn segment. Later records, the loss record among them, were appended after the torn bytes and flushed; the next open failed with `ChainBroken`, so acknowledged, flushed records became unreadable after a recovery that returned `Ok`. Present since the first round's fixes. The schedules could not reach it: their failed append wrote nothing | Only a healthy writer becomes `PayloadFlushFailed`; `DiskFull` and `WriteFailed` stay until `recover`'s rotation or rewrite leaves the segment, and `recover` handles the poisoned store first. The harness's failed append now writes half its line first, and the clean-recovery oracle appends a record, flushes it and reads the journal back | `r11_h1_a_payload_failure_never_hides_a_torn_segment` (both ways in); negative `payload-failure-hides-torn-segment` **PROVEN**; with the fix reverted and the persisted seeds removed, both properties fail within 4,000 schedules ("the journal no longer reads back after a clean recovery: ChainBroken") |
| L1 | The tenth round's store-first recovery could queue one loss twice: a loss waiting in `unreported` (its report's append failed) whose content was stored and lost again was queued a second time, and the record got two `chunk.lost` records (the first round's L5 class) | A record whose loss is already queued is not queued again | `r11_l1_a_loss_is_queued_once`, checked to fail with the check removed |
| L2 | The crash oracle exposed every acknowledged record when a fault was armed, records already flushed included, and also in the disk model where a failed flush keeps the bytes; a store that discarded readable content after any failed flush and reported it passed 20,000 schedules of each property | Only records not yet flushed are exposed, and none when a failed flush keeps the bytes | with that mutation, both properties now fail within 4,000 schedules |
| L3 | The tenth round cited `r10_l1` and its negative for the flush refusal on untaken losses, but no public path reaches that state with a live journal, and removing the clause broke nothing | Stated in ADR-0018 as defence in depth | review of the text |

**Verified locally (Windows, dedicated target directory):** 68 durability tests and the rest of
`uaos-state`, `uaos-testkit` and `uaos-ledger`; workspace clippy with warnings denied; 3 × 4,000
and 2 × 20,000 schedules of each property, in release; the 34 `journal-durability` negatives.

## Twelfth review (2026-10-16)

**Reviewed:** `dae8763` (on `555494b`) by a fresh-context agent, in a scratch export, with the
writer's health state machine reviewed transition by transition. **Result:** 0 High · 0 Medium ·
3 Low, all in docs and messages; no durability, loss-ordering, open, shred or KEK defect. The
reviewer's own probes passed 40,000 schedules of each property extended with full-disk episodes
and two more append-fault shapes, 20,000 + 60,000 more with two stricter oracles, and 1,560
iterations of a concurrent stress (puts, reads and direct flushes on one thread, re-wraps on
another, the journal with faults on a third).

| Finding | What it was | What changed | Proof |
|---|---|---|---|
| L1 | ADR-0003 still said open flushes the previous run's records before it seals the segment, the mechanism N4 replaced; ADR-0018 said it amends only ADR-0003 §5 | ADR-0003 §3 and §5 carry dated amendment notes pointing to ADR-0018, and ADR-0018 lists both | review of the text |
| L2 | `PayloadsRequired`'s doc said `journal/FLUSHED` forces the store, and the layout comment said `FLUSHED` exists only with a store; since the third round's M1, `journal/PAYLOADS` does that and every journal keeps `FLUSHED` | Both comments corrected; `journal/PAYLOADS` added to the layout | review of the text |
| L3 | Content whose loss was journaled read back as `Unavailable`, whose message says never stored or shredded and points at `chunk.shredded`; the registered `STORE_PAYLOAD_LOST` was never produced | `get` returns `ChunkError::Lost` (`STORE_PAYLOAD_LOST`) when the chunk's files sit in the pocket's quarantine; content stored again reads back | `r12_l3_lost_content_reads_back_as_lost` (also after a restart); negative `lost-content-reads-as-unavailable` **PROVEN** |

**Adopted from the reviewer's probes.** Two stricter oracles in both properties: an open with no
fault armed must succeed (the harness used to fall back to a power loss), and a record whose
payload an open verified (it reads back and no `chunk.lost` names it) no longer counts as exposed
to a later failed flush. ADR-0018's "Not modelled" now states that `SimFs` drops a failed flush's
bytes back to the durable prefix, while Linux can leave a hole of dropped pages (pre-existing
since P1).

**Verified locally (Windows, dedicated target directory):** 69 durability tests and the rest of
`uaos-state`; workspace clippy with warnings denied; 3 × 4,000 and 2 × 20,000 schedules of each
property, in release, with the stricter oracles; the 35 `journal-durability` negatives.
