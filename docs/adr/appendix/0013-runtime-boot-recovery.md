# ADR-0013 contract: the runtime's boot recovery

**Status:** normative for `uaos_runtime::boot` as far as P3 Move 1 PR-6b (WP3.A6b) builds it. It
was written before the code. A change to anything below changes the contract, so it lands in the
same pull request as the code and is recorded in the CHANGELOG. Draft until RC-1, like every
kernel contract.

**Builds on:**
- **ADR-0003:** the journal is the truth, and a record acknowledged critical survives `kill -9`.
- **ADR-0002 and the ledger:** reservations are taken before execution, and
  `Ledger::recover` settles what a crash left open at full cost, estimated, never released.
- **I-09:** `Indeterminate` only through crash recovery.
- **D-6:** balanced recovery settles as estimated; it never guesses "never sent".
- **The runtime contract `0013-runtime-relay-and-stop.md` §3 and §5:** the stop and the
  configuration snapshot.
- **Red lines:**
  - 3: no rollback is claimed;
  - 9: nothing changes invisibly;
  - 10: unknowns are marked.

## 1. What PR-6b builds, and what it does not

**Built:** `uaos_runtime::boot`. After the journal itself has opened and repaired its tail
(`Journal::open`), boot recovery rebuilds what the runtime holds in memory from the verified
records, closes what a crash left open, and explains the boot in one record.

**Not built here:**
- **PR-6c:** the state actor and the durability coordinator (D-5). The actor, not boot, journals
  a stop the running kernel engages, through `Stop::unrecorded` and `Stop::recorded`, once D-37 is
  accepted.
- **PR-6d:** the bus (D-9), the CPU pool and simulated executor (D-7), and the DST harness.
- **PR-8:** loading grants at boot. #39 states the duty: a journal that holds one grant id twice
  keeps the first entry and raises an alarm.
- **PR-7, once it journals `op.executing`:** strict mode's release of provably unsent
  reservations (D-6).
- **PR-6c, the one-record intent (D-6, ADR-0003 rule 4).** Today an intent is two records, a
  `budget.entry` reserve and `op.reserved_intent`, and boot reads both. A crash between them
  charges a reservation whose Operation journaled no intent, which T6 accepts. PR-6c's single
  record changes both of boot's inputs, and amends this contract (V1 review L8).
- **PR-6c, the startup sequence.** `Journal::open` verifies the whole journal and drops the
  records, then the caller reads them again for boot: about a third of the measured boot at
  50,000 records (§7). The state actor opens the journal and keeps what it verified once.
  PR-6c also brings the payload-coordinated open (`Journal::open_with_payloads`) whose cost
  ADR-0018's appendix owes (§5).
- **PR-6c, a clean shutdown record.** Until one exists, a crash with nothing open looks like a
  clean exit (§2 step 5).

These are a reversible split of the approved PR-6 row (Move 1 plan §7) into units small enough to
review (D-31).

## 2. The procedure

`boot(journal, records, config, correlation)` takes the open journal, its verified records (oldest
first), the configuration snapshot the process starts with, and the correlation id its records
carry. It runs these steps in this order:

0. **The records are the journal's, before anything is written.** Their last record must be the
   journal's last: the next sequence number after it is the journal's next. Otherwise boot
   refuses with `RUNTIME_BOOT_RECORDS_STALE`. A retry with the records of an earlier attempt
   would repeat its writes (V1 review L2). An empty slice is not checked: a journal whose
   verified records are all shredded can be empty while its sequence goes on.
1. **Configuration drift, before anything is written.**
   - The highest `config_version` any record carries is the last configuration the kernel used.
   - A configured version below it means the configuration went back without a record of it, so
     boot refuses: `CONFIG_DRIFT`, and nothing is journaled.
   - `[CONSCIOUS ASSUMPTION]` Refusal is the default. The way forward is a configuration
     published with a higher version. An explicit downgrade with an approval is M3's (the
     write side).
   - `[CONSCIOUS ASSUMPTION]` An equal version with different content is not detected: no
     snapshot digest is journaled yet (V1 review L7). The write side, M3, publishes every change
     under a new version and journals its digest.
2. **The stop.** `boot_state(records)` decides it (runtime contract §3 rule 4), and
   `Stop::booted` holds it. A stopped kernel boots stopped: recovery still runs, so the
   journal is closed honestly, but admission refuses everything until a human resumes it (M3).
3. **The ledger.** The `budget.entry` records replay into a `Ledger` (`entries_from_journal`,
   `Ledger::replay`). A replayed ledger always runs `Ledger::recover`, which closes what is open,
   journaling its entries through the ledger's `JournalSink` with actor `system`:
   - an open reservation settles at its full amount, estimated, and is never released: its
     Operation may have spent it;
   - a partly settled one is completed;
   - a half-recorded transfer is completed.

   What it cannot close is stuck, an S2 condition for the operator. The boot record counts the
   stuck items, the report keeps why each stayed open (in memory only), and the ledger refuses
   new work with `BUDGET_RECOVERY_REQUIRED` until a later recovery closes them. A journal
   failure while recovering keeps its own code (`JOURNAL_WRITE_FAILED`), not
   `BUDGET_LEDGER_INCONSISTENT` (V1 review M1).
4. **Open intents.**
   - An Operation whose last journaled state is `Reserved` has an intent and no outcome.
   - Boot moves it to `Indeterminate` (`Transition::CrashRecovered`) and journals
     `op.indeterminate` for it: critical, with the reason `crash_recovery`.
   - The record carries the side-effect class the intent declared, not compensable, and the
     payload `{"reason": "crash_recovery", "may_have_taken_effect": true}` (V1 review M7).
     Neither success nor failure is assumed (red line 3): the request may have reached the
     provider.
   - Once an Operation has an outcome, a later intent does not reopen it. Only an inconsistent
     journal holds one, and reopening would make a committed Operation indeterminate (V1 review
     L1).
5. **The boot record.** One `kernel.booted` record, critical. Its inline payload counts, each
   count a canonical decimal string (the wire rule for 64-bit counters):
   - the records read;
   - the Operations made indeterminate;
   - the reservations settled as estimated;
   - the partly settled reservations completed;
   - the transfers completed;
   - the items left stuck;
   - whether the kernel booted stopped;
   - whether a stop may have been lost (`stop_may_be_lost`). The kernel boots running, and work
     left open shows a crash, so a stop engaged just before it may not have been journaled
     (runtime contract §3 rule 3). A crash with nothing open looks like a clean exit until
     PR-6c journals one;
   - the configuration version.

   Every complete boot is explained.

`boot` returns the `Stop`, the `Ledger` and a `BootReport` of the same counts.

## 3. Idempotence under a crash

A crash can stop boot between any two of its appends, and the next boot must converge without
duplicating anything:
- An Operation already `Indeterminate` is terminal for boot, so `op.indeterminate` is journaled
  once per Operation.
- The ledger's recovery entries make the reservations they close settled, so a second replay
  finds nothing open.
- `kernel.booted` is boot's last append, so an interrupted boot writes none. Its recovery records
  stand, each with its reason, and the next complete boot writes its own record, counting only
  what it closed itself (V1 review L6).

The property in §5 proves convergence over crashes at every append.

## 4. Contract changes (additive)

- **Event type** `kernel.booted`, with the inline payload of §2 step 5. `types::ALL` grows by one.
- **No schema change:** event types are strings in `uaos.event/1`.

## 5. Proof obligations

**Tests:**
- **The records:** records that are not the journal's are refused with
  `RUNTIME_BOOT_RECORDS_STALE`, and nothing is appended.
- **Drift:** a configured version below the journal's is refused with `CONFIG_DRIFT`, and
  nothing is appended. An equal or higher one boots.
- **Error codes:** a journal failure during the ledger's recovery is `JOURNAL_WRITE_FAILED`.
- **The stop:** a journaled stop boots stopped, and recovery still closes the ledger and the
  intents. A boot after a crash with work open says a stop may have been lost; one with
  nothing open does not.
- **The ledger:** an open reservation settles at its full amount, with an estimated settle
  entry, and no money is released.
- **Intents:**
  - every open intent becomes `Indeterminate` exactly once;
  - an Operation that committed, failed, was denied or is already `Indeterminate` is left
    alone;
  - the record carries the intent's side-effect class and says the effect may have happened.
- **The boot record:** it is journaled once per boot, with counts checked against the fixture.
- **Convergence (property):** for random journals, a boot cut after its n-th append, for every
  n, then a full boot, leaves what a boot with no cut leaves:
  - the same ledger state, with nothing stuck;
  - the same set of indeterminate Operations;
  - no Operation with two `op.indeterminate`;
  - no ledger entry journaled twice under one key.

  The random journals hold open, committed, failed, denied and already indeterminate
  Operations. Partial settles, transfers and a stop are tested by the ledger's and the stop's
  own suites, not cut at boot level. PR-6d's DST owns that. The cut journal holds exactly the first n records a real boot appended, which is what a crash
  between two appends leaves: an acknowledged append survives a crash, and open cuts a torn one.

**Seeded violations:** recorded in §7 by the commit that adds them, each with its catching test.

**Bench:** boot time against the number of records after a crash (1,000 to 50,000), recorded in
§7, on the plain `Journal::open`. ADR-0018's appendix owes two more dimensions, and this bench
does not pay them: boot time against the records after the `FLUSHED` marker, and after an
interrupted shred, both on `Journal::open_with_payloads`. PR-6c brings that open (§1) and
measures them (V1 review M5).

## 6. Threat and privacy note

- **T6:** money that may be spent is never released at boot.
- **Red line 3:** an interrupted Operation is never called done or undone.
- **Red line 9:** every boot is explained in the journal.
- **T11:** boot's memory grows with the journal, not only with the open items. The caller
  holds every verified record, boot decodes every budget entry, and it keeps one small entry
  per Operation the journal names, so a closed Operation is never reopened. Holding the
  journal in memory is the caller's choice today; PR-6c's startup sequence reads it once and
  streams it (§1, V1 review M3).
- **Privacy:** the boot record carries counts and versions only.

## 7. Measured, seeded

**Bench** (`cargo bench -p uaos-runtime --bench boot`, 2026-10-21):
- **Machine:** the reference machine, Windows 10, environment label `reference-win10-local` (D-33).
- **Method:** 3 rounds per size, each on a fresh copy of a journal that a crash left. Every
  Operation reserved, journaled its intent, settled and committed, except one in a hundred,
  which the crash left open. The journal was written under the default flush policy.
- **Results:** medians, with the maximum in brackets, in ms:

| Records | Open Operations | Journal open | Read of the records | `boot` | Total |
|---:|---:|---:|---:|---:|---:|
| 997 | 2 | 34.5 (38.0) | 28.0 (29.8) | 1.3 (1.4) | 63.9 (69.2) |
| 4,977 | 12 | 126.1 (137.2) | 107.4 (111.6) | 7.7 (8.4) | 240.9 (257.2) |
| 9,951 | 25 | 174.4 (177.9) | 151.2 (153.7) | 17.5 (19.2) | 343.8 (345.4) |
| 49,751 | 125 | 458.0 (464.8) | 311.7 (340.0) | 90.5 (93.3) | 867.0 (889.4) |

- **Where the time goes:** `boot` itself (drift, stop, ledger replay and recovery, intents, the
  record) is 2.0% of the total at 997 records, 3.2% at 4,977, 5.1% at 9,951 and 10.4% at
  49,751. The rest is the journal's own open and the second read of its verified records,
  which PR-6c removes (§1).
- **Not measured here:** the payload-coordinated open and the dimensions ADR-0018's appendix
  owes (§5).
- **Against ADR-0018's figure:** ADR-0018's appendix measured 10.8 s on Windows CI for about
  5,000 records, inside the kill harness. This bench reproduces neither that machine nor
  that harness's directories, so it does not explain the gap. The CI runners are measured
  once the bench joins the nightly lane (WP3.8).

**Seeded violations** (`cargo xtask negative`, gate `test`):

| id | Seed | Caught by |
|---|---|---|
| `boot-config-drift-unchecked` | an older configuration boots | `an_older_configuration_is_refused_before_anything_is_written` |
| `boot-recovery-skipped` | open reservations are left open | `an_open_reservation_settles_in_full_and_is_never_released` |
| `boot-indeterminate-twice` | an Operation already `Indeterminate` is made so again | `open_intents_become_indeterminate_once` |
| `boot-intents-follow-ledger` | intents are closed only when the ledger had something to close, which only a crash shows | `a_crash_during_boot_converges` |
| `boot-ignores-journaled-stop` | a journaled stop boots running | `a_journaled_stop_boots_stopped_and_recovery_still_runs` |
| `boot-unexplained` | no `kernel.booted` record | `every_boot_is_explained_once` |
| `boot-denied-reopened` | a denied Operation is made `Indeterminate` (V1 review M2) | `open_intents_become_indeterminate_once` |
| `boot-ledger-error-erased` | a journal failure in recovery reads as an inconsistent ledger (M1) | `a_journal_failure_during_recovery_keeps_its_code` |
| `boot-intent-effect-dropped` | the record says the Operation had no external effect (M7) | `open_intents_become_indeterminate_once` |
| `boot-stop-loss-unexplained` | a boot after a crash does not say a stop may be lost (M6) | `a_boot_after_a_crash_says_a_stop_may_be_lost` |
| `boot-stale-records-accepted` | records that are not the journal's are booted from (L2) | `records_that_are_not_the_journals_are_refused_before_anything_is_written` |
