# Adversarial review: WP3.A6b, the runtime's boot recovery (P3 Move 1, PR-6b, #44)

**Reviewer:** a fresh-context review agent (D-31, V1). It was read-only on the branch: no cargo
run, and one script to count the seed anchors.
**Reviewed:** `d503a43` (`p3/a6b-boot-recovery`, base `91288c9`), 2026-10-21. That covers the
contract `docs/adr/appendix/0013-runtime-boot-recovery.md`, `uaos_runtime::boot`, its tests,
seeds and bench, and the PR-6b/6c/6d reference renames.
**Result:** 0 High · 7 Medium · 9 Low. Nothing breaks an invariant or a red line: no money is
released at boot, `Indeterminate` is reached only from an open intent, and a crash at any append
converges.

**Verified clean by the reviewer:**
- **The drift check:**
  - the highest `config_version` is the right "last" one, because pinned snapshots interleave;
  - recovery records reuse the configured version;
  - an empty journal passes;
  - the check runs before any append.
- **The stop:** a journaled stop boots stopped, is not journaled again, and recovery still runs.
- **Recovery:**
  - it accepts the system actor and never releases an open reservation;
  - it closes each item with one entry;
  - when items stay stuck, boot still succeeds and the ledger keeps refusing work.
- **Intents:**
  - the outcome list matches the projection's;
  - the state machine allows `CrashRecovered` from `Reserved`.
- **The convergence property:**
  - it covers every n, its crash model is faithful, and `draft_of` copies every field.
- **Seeds:** every anchor occurs once, every seeded build compiles, and each test fails first
  with its message. `boot-intents-follow-ledger` fails in the property only.
- **The bench:**
  - each round uses a fresh copy, and the phases are timed apart;
  - the counts are asserted.
- **The renames:** they are consistent, and the D-37 row changes only its "needed by" cell.

**Resolution:** every finding is fixed in this PR, each with a test or a seed, or with contract
text and an owner (M5, L7, L8). The D-31 scoped round over the fixes follows, then a final fresh
full review before the PR leaves draft.

## Findings and what was done

### Medium

| | Finding | Fix | Proof |
|---|---|---|---|
| M1 | `BootError::Ledger(String)` erased the ledger's error. A full disk during recovery reported `BUDGET_LEDGER_INCONSISTENT`; the same failure one record later reported `JOURNAL_WRITE_FAILED`. | `Ledger(LedgerError)` delegates to `LedgerError::code()`, and `Journal(JournalError)` to `JournalError::code()`. A malformed entry is `LedgerEntries`. | `a_journal_failure_during_recovery_keeps_its_code`; negative `boot-ledger-error-erased` |
| M2 | §5 promised a denied Operation is left alone, and no fixture had one. Dropping `OP_DENIED` from the outcomes would pass. | `Fate::Denied`: the reservation is released, then `op.denied`. It is in the fixtures and in the property's strategy. | `open_intents_become_indeterminate_once`; negative `boot-denied-reopened` |
| M3 | T11 claimed boot's memory grows only with open items and the journal is read once. It holds every record and every Operation, and the journal is read twice. | T11 now states what boot holds. The second read and a streaming start are PR-6c's startup sequence (§1). | Contract §1, §6 |
| M4 | §7 said `boot` is "about a tenth of the total at every size"; the table gives 2.0% to 10.4%. | §7 gives the four shares. | Contract §7 |
| M5 | The bench does not measure what ADR-0018's appendix owes: records after the `FLUSHED` marker, after an interrupted shred, on `open_with_payloads`. | §5 and §7 say so, and name PR-6c, which brings that open. | Contract §1, §5, §7 |
| M6 | The relay contract says the explanation of a boot after a lost stop says so. The rename left that without an owner. | `kernel.booted` and the report carry `stop_may_be_lost`. It is set when the kernel boots running with work left open, the only evidence of a crash boot has. A crash with nothing open looks like a clean exit until PR-6c journals one. | `a_boot_after_a_crash_says_a_stop_may_be_lost`; negative `boot-stop-loss-unexplained` |
| M7 | `op.indeterminate` carried only `{"reason":"crash_recovery"}`, and claimed `side_effect_class: None` whatever the intent declared. That hides the @devam warning (red line 3). | The record carries the intent's side-effect class, is not compensable, and its payload says `"may_have_taken_effect": true`. | `open_intents_become_indeterminate_once`; negative `boot-intent-effect-dropped` |

### Low

| | Finding | What was done |
|---|---|---|
| L1 | A later intent reopened an Operation boot treats as terminal. | Once closed, an Operation stays closed for boot. |
| L2 | Nothing tied `records` to `journal`, so a retry with the same slice repeated its writes. | §2 step 0: the records must end where the journal goes on, or boot refuses with the new code `RUNTIME_BOOT_RECORDS_STALE`. Test `records_that_are_not_the_journals_are_refused_before_anything_is_written`; negative `boot-stale-records-accepted`. An empty slice is not checked, and §2 says why. |
| L3 | The convergence check could not see duplicate identical ledger entries or the estimated flag. Its journals were narrow, and two tests compared the report with itself. | Each ledger key is counted, at most once. The settle entry is checked for `estimated`. The boot record is checked against the fixture. Denials join the journals. Partial settles, transfers and a stop are cut by PR-6d's DST, and §5 says so. |
| L4 | `kernel.booted` wrote 64-bit counters as JSON numbers, against the wire rule. | Every count, and the version, is a canonical decimal string. |
| L5 | The reasons for stuck items were thrown away, and §2 named S2 where the ledger then returns S3. | `BootReport::stuck` keeps the reasons, in memory only. §2 names `BUDGET_RECOVERY_REQUIRED` as what the ledger then returns. |
| L6 | §3 described a `kernel.booted` of an interrupted boot, which cannot exist. | §3 is reworded: the interrupted boot's records stand with their reasons. |
| L7 | An equal version with different content boots silently. | A conscious assumption in §2 step 1. The digest is M3's write side. |
| L8 | Boot depends on today's two-record intent without saying so. | Named in §1, owned by PR-6c. |
| L9 | The `else Recovery::default()` branch was dead. A historical review names "PR-6b's DST". | A replayed ledger always recovers. The historical record is left as written. |
