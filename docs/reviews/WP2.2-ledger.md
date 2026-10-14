# Retroactive adversarial review: WP2.2 uaos-ledger

**Why retroactive:** WP2.2 merged without the V1 review that plan v2 now requires (PD-16).
**Reviewer:** a fresh-context review agent with the fixed checklist, read-only; probes and mutants
on a scratchpad copy. **Reviewed:** `main` at `3ed983f`, 2026-10-13.
**Result:** 2 High · 6 Medium · 4 Low.
**Verdict as reported:** the code records every entry before applying it within one running
process. The hard cap failed after a rebuild, after a mid-run `recover()`, and when caller keys
collided with derived keys.

## Findings as reported

### High

- **H1. After a replay, a reservation can be granted against money already spent.**
  - A `Settle` above the reserved amount did not debit `available`; only the closing `Adjust`
    did.
  - `Ledger::replay` returned a ledger that accepted reservations before `recover()` ran.
  - Probe: fund 100, reserve 30, settle 80 with the `Adjust` write failing, then replay. A new
    reservation of 70 was accepted. After recovery the pool read −50 available and 150 spent.
- **H2. Derived keys share a namespace with caller keys.**
  - Derived keys are `{rsv}:reserve`, `:release`, `:settle`, `:overrun`, and `<key>:in` for a
    transfer's second half.
  - A caller key colliding with one of them left a transfer or settlement half-applied, and
    `recover()` then failed permanently on the `KeyConflict`.

### Medium

- **M1. `recover()` could force-settle reservations whose tokens were still live in the
  process,** and `settle` consumed the token even on errors raised before anything was recorded.
- **M2. The in-flight state existed only in memory.** Replay accepted a `Release` after
  execution had begun.
- **M3. `BudgetTx::validate()` was too permissive.** It accepted a `Reserve` below zero, fields on
  kinds that do not use them, a `Release` without `settled`, and a zero `Adjust`.
- **M4. The tests did not reach the replay rules.** 4 of 7 seeded mutants survived the suite:
  - a second `Settle` on a partly settled reservation;
  - a `Settle` against another pool;
  - a `TransferIn` with a different amount, which creates money on replay;
  - a `Release` without `settled`.
- **M5. Error codes were misclassified.** Most errors mapped to the S1 overrun code, while a real
  overrun raised no signal and was journaled at risk tier 0.
- **M6. Claim wording overstated the behaviour.**
  - "Structural hard cap": overruns are unbounded.
  - "Model-checked": the simulation is randomized property testing.
  - "Recorded durably": entries can be lost inside the power-loss window W.

### Low

- **L1. Unpruned indexes, and a lock held across the journal append.**
- **L2. Transfers created pools silently.**
- **L3. Replay accepted refunds and adjustments that nothing produces.** A probe created
  1,000,000 this way.
- **L4. Retries ignored principal, reason, `settled` and `estimated`.** The journal sink stamped
  its own actor on the event.

## Resolution

| Finding | What changed | Proof |
|---|---|---|
| H1 | A rebuilt ledger refuses allocate, reserve and transfer until `recover()` has run (`LedgerError::RecoveryRequired`, `UAOS-BUDGET-0007`). The cap check subtracts any overrun not yet closed. The contract refuses any hold that would take the balance below zero | `a_rebuilt_ledger_refuses_new_work_until_recovered` (the reviewer's probe, now refused); `a_hold_can_never_take_the_balance_below_zero` (contract) |
| H2 | Caller keys that start with `rsv_` or end in `:in`, `:reserve`, `:release`, `:settle` or `:overrun` are refused (`KeyReserved`). A transfer checks both keys before its first entry. Recovery reports an item it cannot close in `Recovery::stuck` (S2) and still closes the rest; the ledger then keeps refusing new work | `caller_keys_cannot_collide_with_derived_keys`, `recovery_reports_a_stuck_item_and_still_closes_the_rest` |
| M1 | `recover()` is boot-only (`NotReplayed` on a live ledger with open items). `release` and `settle` return `CloseError::Rejected` with the token when refused before recording | `recovery_is_boot_only_and_rejected_closes_hand_the_token_back` |
| M2 | **Accepted.** The journal cannot mark the start of execution until the runtime exists. Recovery never releases an open reservation, so no money that may have been spent is ever returned. The runtime journals the start of execution in WP3.3 (ADR-0010), and replay then refuses `Release` after it. Stated in the crate docs | — |
| M3 | Per-entry rules in `BudgetTx::validate()`: the reservation id only on reserve, settle, release and adjust; the counterparty only on transfers and never the entry's own pool; `settled` only where it means something; `estimated` only on `Settle`; a release must close; an adjust is never zero; holds never go below zero | `fields_are_only_allowed_where_they_mean_something`, `a_hold_can_never_take_the_balance_below_zero` |
| M4 | Targeted replay tests kill each surviving mutant. The nightly mutation lane (V4) tracks the rest. Comparing live and replayed state on poison is **not yet** added to the simulation; that is recorded as follow-up | `replay_enforces_every_reservation_and_transfer_rule` |
| M5 | Distinct codes: `UAOS-BUDGET-0005` key conflict (User), `-0006` ledger inconsistent (S2), `-0007` recovery required. The overrun is returned in `Settlement::overrun` for the runtime to raise as S1, and journaled at `RiskTier::MAX` | `a_retry_must_match_every_field_and_errors_have_their_own_codes`, `an_overrun_is_journaled_at_the_highest_risk_tier` |
| M6 | Crate docs and CHANGELOG restated. The cap covers reservations and outgoing transfers; spend above a reservation is recorded truthfully as an S1 overrun. The simulation is called "randomized simulation against a reference model". Durability is stated as "survives a process kill; within W it can be lost" | review of the text |
| L1 | **Accepted, scheduled.** Index growth is PD-12 (before the RC-1 build exit). The lock held across the append is measured in the P3 overhead bench | — |
| L2 | Only an allocation creates a pool; a transfer to an unknown pool is refused | `transfer_rules` |
| L3 | Replay refuses refunds and adjustments outside an overrun until a producer exists | `replay_refuses_money_without_a_producer` |
| L4 | A retry must match every field except the balances. The journal event's actor is the entry's own principal | `a_retry_must_match_every_field_and_errors_have_their_own_codes` |
