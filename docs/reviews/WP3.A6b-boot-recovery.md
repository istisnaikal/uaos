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

## D-31 scoped round (over `eceab95`)

**Reviewer:** a fresh-context agent, read-only. It covered the fix diff and every invariant and
caller it touches.
**Result:** 0 High · 2 Medium · 4 Low. With a correct caller, nothing breaks an invariant.

**Verified clean:**
- **Step 0's normal path:** it runs before any write, and records read after open end at
  `next_seq`, even when open journals `chunk.lost`.
- **The new code:** `RUNTIME_BOOT_RECORDS_STALE` follows the registry's conventions.
- **Intents:** `open_intents` keeps the first intent's position and effect, and closes for good.
- **Payloads:** the `op.indeterminate` envelope and payload, and the nine `kernel.booted` fields,
  match the contract.
- **The fixtures:** `Fate::Denied` is valid ledger use. The disk-full test fails at the ledger's
  first append.
- **Seeds and docs:** every seed bites, and the docs' counts are right.

| | Finding | What was done |
|---|---|---|
| M1 | Step 0 skipped an empty slice on a false premise: a journal never drops a verified record. An empty slice, a suffix, or another journal's records of the same length passed. A journaled stop would then boot running, and the ledger would be rebuilt wrong. | The records must start at the genesis (sequence 0) and end at the head (next sequence and chain hash). An empty slice must mean an empty journal. The test covers a retry, an empty slice, a suffix and another journal's records. Negatives `boot-stale-records-accepted` (retargeted) and `boot-partial-records-accepted`. |
| M2 | V1's M1 was not resolved. `JournalSink` turns the journal's error into text, so a full disk read `JOURNAL_WRITE_FAILED` during recovery and `JOURNAL_DISK_FULL` at boot's own records. The test asserted the erased code. | The ledger's `JournalSink` keeps the journal's error (`take_refusal`, additive), and boot reports it as `BootError::Journal`. `a_full_disk_reads_the_same_wherever_boot_meets_it` checks both places. Negative `boot-ledger-error-erased` (retargeted). |
| L1 | Replay errors lost `BUDGET_LEDGER_INCONSISTENT` and read as user-class codes. | Anything the ledger reports, other than a journal failure, is `BUDGET_LEDGER_INCONSISTENT`. |
| L2 | `stop_may_be_lost` repeated while a stuck item stayed, and was lost after a crash during boot. | Stuck items are no evidence. An interrupted boot's `op.indeterminate` with no `kernel.booted` after it is. The property checks the flag for every cut before the boot record. Negative `boot-interrupted-boot-unseen`. The one residual, a boot interrupted after closing only a reservation that no intent named, is stated. |
| L3 | §2 called stuck S2 "until a later recovery closes them", while the code is S3 and retryable, and a stuck item is deterministic. | §2 states the mismatch. The repair and surfacing stuck items are a conscious assumption owned by PR-6c. |
| L4 | The CHANGELOG and the crate docs lagged the contract, and §7 named no commit. | Both follow the contract, and §7 names `d503a43`. |

## D-31 final fresh full review (`51b0f78`)

**Reviewer:** a fresh-context agent, read-only, over the whole five-commit diff.
**Result:** 0 High · 2 Medium · 7 Low. Nothing breaks an invariant or a red line. Another fresh
full review follows these fixes, within D-31's five rounds.

**Verified clean:**
- **Step 0** refuses no legitimate journal.
- **Drift and the stop** behave as specified.
- **`take_refusal`** can never return a stale refusal within boot.
- **The codes, the payload fields, and the crash model of the convergence property** match the
  contract.
- **All 13 seeds** bite.
- **Every earlier fix** is real.

| | Finding | What was done |
|---|---|---|
| M1 | The relay contract said, without condition, that the explanation of a boot after a lost stop says so. Boot says so only when a crash shows. | The sentence names the evidence rule, and the clean shutdown PR-6c journals. |
| M2 | Removing the ledger term from the crash evidence passed everything. No fixture had a reservation without an intent. | `Fate::ReservedOnly` (a crash between the reserve and the intent), in the fixtures and the property. The property encodes the one stated residual exactly. Negative `boot-ledger-evidence-ignored`. A stuck-only crash is a third stated residual. |
| L1 | Step 0 checked only the ends, so a gap or a doubled record passed. | The records must follow one another, by sequence and chain link. Gap and doubled cases are tested; negative `boot-gapped-records-accepted`. |
| L2 | Several mutants survived: `or_insert` → `insert`, the first intent's effect, `rposition` → `position`, compensable, durability, `"stopped"`, recovery's principal. | `a_closed_operation_stays_closed_and_its_first_intent_speaks`, `a_boot_after_complete_boots_claims_no_lost_stop`, `recovery_records_carry_the_operations_ids_and_honest_flags`, and the stopped payload check. Negatives `boot-closed-reopened`, `boot-evidence-from-first-boot`. |
| L3 | A crash between a denied Operation's release and `op.denied` is journaled as `may_have_taken_effect`. | A conscious assumption in §2 step 4: it overstates, never hides; PR-6c's one-record transitions close it. |
| L4 | Recovery records dropped the Operation's ids, correlation and a parent link. `kernel.booted` was MAX on every clean boot. | `op.indeterminate` carries the intent's ids and correlation and links to it. `kernel.booted` is MAX only when it recovered, and `RiskTier::MIN` when clean (new constant). The ledger's entries' attribution is PR-6c's (§1). |
| L5 | Error texts lagged the checks. | The stale-records message and Display describe the whole-journal check. `CONFIG_DRIFT`'s approval path is named as M3's in §2 step 1. |
| L6 | §7 said the procedure changed "only in checks". | §7 says what changed, and that the appends are the same. |
| L7 | Doc drift: ADR-0018's appendix owner, "every boot", step 4's first bullet, the CHANGELOG's review line. | Fixed. |

## D-31 round 4: a second final fresh full review (`030d22f`)

**Reviewer:** a fresh-context agent, read-only, over the whole six-commit diff.
**Result:** 0 High · 0 Medium · 5 Low. Nothing forces a split.

**Verified clean:**
- **Copying the intent's ids, correlation and parent:** no journal rule forbids it. The stop,
  the evidence scan and the projection read none of them. There is precedent in `chunk.lost`.
- **`RiskTier::MIN`:** valid at every layer.
- **Step 0:** refuses no legitimate journal. Its contiguity check is O(n).
- **`take_refusal`:** never stale.
- **The residual guard:** it hides no other failure.
- **All 17 seeds:** each bites first.

| | Finding | What was done |
|---|---|---|
| L1 | The copied ids were untested: every fixture intent had none. | `the_indeterminate_record_carries_the_intents_ids`, with all four ids and a risk tier. Negative `boot-intent-ids-dropped`. |
| L2 | No boot fixture left an item stuck. The stuck count and its tier were untested, and §2 did not say a stuck-only boot surfaces. | A unit test of the boot record, `a_boot_that_leaves_an_item_stuck_counts_it_and_surfaces`. Negative `boot-stuck-not-surfaced`. §2 step 5 says it. |
| L3 | §5 overstated the property. Its residual guard skipped more cuts than needed, and an already-indeterminate fixture modelled an interrupted boot. | The guard skips only cuts after the last ledger append. The fixture journals its earlier boot's record. §5 says both. |
| L4 | §4, the CHANGELOG and two docs lagged the new surface. | §4 and the CHANGELOG list the code, `RiskTier::MIN` and `take_refusal`. The report's doc and §7 are corrected. |
| L5 | `op.indeterminate` claimed to be the Operation's record but was written at `MAX`, not the Operation's tier. | It carries the intent's tier, as the envelope defines the field. It surfaces by its type and the boot record's tier (§2 step 4). |

**Outside the PR:** the projection takes an Operation's side effect from its first record. That
is now a PR-6c duty in §1.
