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

These are a reversible split of the approved PR-6 row (Move 1 plan §7) into units small enough to
review (D-31).

## 2. The procedure

`boot(journal, records, config, correlation)` takes the open journal, its verified records (oldest
first), the configuration snapshot the process starts with, and the correlation id its records
carry. It runs these steps in this order:

1. **Configuration drift, before anything is written.**
   - The highest `config_version` any record carries is the last configuration the kernel used.
   - A configured version below it means the configuration went back without a record of it, so
     boot refuses: `CONFIG_DRIFT`, and nothing is journaled.
   - `[CONSCIOUS ASSUMPTION]` Refusal is the default. The way forward is a configuration
     published with a higher version. An explicit downgrade with an approval is M3's (the
     write side).
2. **The stop.** `boot_state(records)` decides it (runtime contract §3 rule 4), and
   `Stop::booted` holds it. A stopped kernel boots stopped: recovery still runs, so the
   journal is closed honestly, but admission refuses everything until a human resumes it (M3).
3. **The ledger.** The `budget.entry` records replay into a `Ledger` (`entries_from_journal`,
   `Ledger::replay`). If it needs recovery, `Ledger::recover` closes it, journaling its entries
   through the ledger's `JournalSink` with actor `system`:
   - an open reservation settles at its full amount, estimated, and is never released: its
     Operation may have spent it;
   - a partly settled one is completed;
   - a half-recorded transfer is completed.

   What it cannot close is counted as stuck (S2), and the ledger then keeps refusing new work.
4. **Open intents.**
   - An Operation whose last journaled state is `Reserved` has an intent and no outcome.
   - Boot moves it to `Indeterminate` (`Transition::CrashRecovered`) and journals
     `op.indeterminate` for it: critical, with the reason `crash_recovery`.
   - Neither success nor failure is assumed (red line 3). The explanation says the request may
     have reached the provider.
5. **The boot record.** One `kernel.booted` record, critical. Its inline payload counts:
   - the records read;
   - the Operations made indeterminate;
   - the reservations settled as estimated;
   - the partly settled reservations completed;
   - the transfers completed;
   - the items left stuck;
   - whether the kernel booted stopped;
   - the configuration version.

   A boot therefore never goes unexplained.

`boot` returns the `Stop`, the `Ledger` and a `BootReport` of the same counts.

## 3. Idempotence under a crash

A crash can stop boot between any two of its appends, and the next boot must converge without
duplicating anything:
- An Operation already `Indeterminate` is terminal for boot, so `op.indeterminate` is journaled
  once per Operation.
- The ledger's recovery entries make the reservations they close settled, so a second replay
  finds nothing open.
- A `kernel.booted` from an interrupted boot is not repeated; the next complete boot writes its
  own.

The property in §5 proves convergence over crashes at every append.

## 4. Contract changes (additive)

- **Event type** `kernel.booted`, with the inline payload of §2 step 5. `types::ALL` grows by one.
- **No schema change:** event types are strings in `uaos.event/1`.

## 5. Proof obligations

**Tests:**
- **Drift:** a configured version below the journal's is refused with `CONFIG_DRIFT`, and
  nothing is appended. An equal or higher one boots.
- **The stop:** a journaled stop boots stopped, and recovery still closes the ledger and the
  intents.
- **The ledger:** an open reservation settles at its full amount, estimated, and no money is
  released.
- **Intents:**
  - every open intent becomes `Indeterminate` exactly once;
  - an Operation that committed, failed, was denied or is already `Indeterminate` is left
    alone.
- **The boot record:** it is journaled once per boot, with the counts.
- **Convergence (property):** for random journals, a boot cut after its n-th append, for every
  n, then a full boot, leaves what a boot with no cut leaves:
  - the same ledger state, with nothing stuck;
  - the same set of indeterminate Operations;
  - no Operation with two `op.indeterminate`.

  The cut journal holds exactly the first n records a real boot appended, which is what a crash
  between two appends leaves: an acknowledged append survives a crash, and open cuts a torn one.

**Seeded violations:** recorded in §7 by the commit that adds them, each with its catching test.

**Bench:** boot time against the number of records after a crash (1,000 to 50,000), recorded in
§7. ADR-0018's appendix owes this product number: 10.8 s was measured on Windows CI for about
5,000 records, most of it in the journal's own open.

## 6. Threat and privacy note

- **T6:** money that may be spent is never released at boot.
- **Red line 3:** an interrupted Operation is never called done or undone.
- **Red line 9:** every boot is explained in the journal.
- **T11:** boot reads the journal once, and its memory grows with the open items, not with
  history beyond what the ledger already keeps (its own stated limit).
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
  record) is about a tenth of the total at every size. The rest is the journal's own open and
  the read of its verified records.
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
