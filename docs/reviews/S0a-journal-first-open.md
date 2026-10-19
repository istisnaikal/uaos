# Adversarial review: a crash during the journal's first open (PR #29, plan "Spine to RC-1" 0a)

**Reviewer:** a fresh-context review agent (plan v2 §4.2, V1), read-only on the branch, probing a
scratchpad copy with its own cut harness. **Reviewed:** `629a377` (`debt/kill-harness-cost`),
2026-10-20.
**Result:** 0 High · 1 Medium · 4 Low. No reachable permanent failure to open and no silent loss
was found.
**Resolution:** the Medium and every Low fixed; the reviewer's cut harness kept as a merge-lane
test. The fixes have not been reviewed again.

## The defect under review

Nightly 39330543607 (macOS, kill harness, seed `0x5b92d4afa7`, iteration 176) failed with `open
failed: journal is corrupt: segment files exist but the manifest is missing; refusing to start a
new history over them`. A writer killed during a directory's first open, after `start_segment`
created and flushed the first segment but before the manifest was stored, left an empty segment
and no manifest. Every later open refused it, so the directory could never be opened again. It
was found by the harness's new kills during boot; no acknowledged record was at risk. The fix at
`629a377` sets segment files aside as orphans when all of them are empty.

## What the reviewer checked

A harness that cuts a boot before each of its filesystem steps, including the steps inside atomic
writes, then crashes or loses power and reopens twice:

- first open, plain: 14 cut points;
- first open with a chunk store: 26 cut points;
- an existing journal with a carried tail: 18 plain, 75 with a store;
- a first open killed twice: about 680 combinations;
- reopens that journal a lost payload, or complete a shred cut at each of 17 points: about 55
  cut points each.

Zero failures to reopen, and every acknowledged (crash) or flushed (power loss) record present.
With the old refusal seeded back, 5 cut points per first-open scenario failed with the nightly's
exact message.

## Findings and resolution

| Finding | What was wrong | What changed | Proof |
|---|---|---|---|
| M1 | The refusal was untested on a real history's usual shape: opened once before any record (the first segment sealed empty), records in the next. A check of the first segment only passed all 119 tests and would have started a new history over records | Test for that shape, which also asserts a refused open renames nothing | `a_lost_manifest_behind_an_empty_first_segment_is_refused`; negative `journal-new-history-checks-first-segment-only` **PROVEN** |
| L1 | The safety argument said "nothing is written to a segment before its manifest is stored", which later opens contradict (a carried tail and a rewrite append first) | Stated as it holds: a directory's first manifest is stored before any segment is written, and is then only ever replaced atomically, never removed | `new_manifest`'s and the module's docs |
| L2 | "Kept for forensics like every orphan": a first open killed twice leaves a second empty `.orphan-g0` that replaces the first | The doc says only the last is kept, and that every one is empty | Doc |
| L3 | Emptiness was checked by reading the whole file, so a stray large segment file was read into memory to be refused | The file's length is checked instead (`open_append`, `os_len`); errors still fail closed | Existing refusal tests |
| L4 | The added directory flush cannot be observed (creating the first segment flushes the directory too); and a `FLUSHED` marker naming a record, which proves a history existed, was not used as a witness | The flush is kept and commented as belt and braces. Without a manifest, a marker that names a record is refused, whatever the segments hold | `a_missing_manifest_with_a_recorded_durable_point_is_refused`; negative `journal-new-history-over-a-marker` **PROVEN** |

**The cut harness is kept** as `crates/uaos-state/tests/boot_cuts.rs`: every cut of a first open
and of an existing journal's open (plain and with a store, crash and power loss), first opens cut
twice, and reopens that complete a shred or journal a lost payload. It runs in the merge lane in
about 6 s, so a boot that can leave a directory unopenable fails a merge rather than waiting for
the right nightly timing.
