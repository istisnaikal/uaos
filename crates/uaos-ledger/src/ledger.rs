// SPDX-License-Identifier: Apache-2.0

//! The ledger writer: turns budget operations into recorded entries.
//!
//! Every entry is recorded through a [`LedgerSink`] (normally the journal) **before** the
//! in-memory state changes, so a reservation is durable before the Operation it pays for can
//! execute. If recording fails, the ledger refuses further work until it is rebuilt from the
//! journal: the entry may or may not have reached the journal, and guessing would let memory and
//! truth diverge.
//!
//! Reservations are typestate tokens. A [`Reservation<Held>`] may be released; once execution
//! starts, [`Reservation::begin`] turns it into a [`Reservation<InFlight>`], which can only be
//! settled — money that may already have been spent can never be released. Tokens are not
//! `Clone`, so a reservation cannot be settled twice in-process, and the state refuses a second
//! closing entry anyway. A token that is dropped (or a process that crashes) leaves the
//! reservation open; [`Ledger::recover`] settles open reservations conservatively, at the full
//! reserved amount marked `estimated`, and never releases them.

use std::marker::PhantomData;

use uaos_contracts::budget::{BudgetTx, BudgetTxKind, BudgetTxSchema, IdempotencyKey, ReasonCode};
use uaos_contracts::event::Actor;
use uaos_contracts::id::{PoolId, ReservationId};
use uaos_contracts::money::NanoUsd;

use crate::state::{LedgerError, LedgerState, transfer_in_key};

/// Where entries are recorded durably.
pub trait LedgerSink {
    /// Records one entry; returns only once it is durable to the sink's standard.
    ///
    /// # Errors
    /// A description of the failure; the entry may or may not have been recorded.
    fn record(&mut self, tx: &BudgetTx) -> Result<(), String>;
}

/// An in-memory sink for tests and simulation.
#[derive(Debug, Default)]
pub struct MemorySink {
    /// Entries in recording order.
    pub entries: Vec<BudgetTx>,
    /// When set, the next `record` fails with this message.
    pub fail_next: Option<String>,
}

impl LedgerSink for MemorySink {
    fn record(&mut self, tx: &BudgetTx) -> Result<(), String> {
        if let Some(message) = self.fail_next.take() {
            return Err(message);
        }
        self.entries.push(tx.clone());
        Ok(())
    }
}

/// Marker: reserved, execution not started; may be released.
#[derive(Debug)]
pub struct Held;
/// Marker: execution started; can only be settled.
#[derive(Debug)]
pub struct InFlight;

/// A reservation token. Not `Clone`: it is consumed by exactly one closing operation.
#[must_use = "an unclosed reservation is settled conservatively at full cost by recovery"]
#[derive(Debug)]
pub struct Reservation<S> {
    id: ReservationId,
    pool: PoolId,
    amount: NanoUsd,
    state: PhantomData<S>,
}

impl<S> Reservation<S> {
    /// The reservation identifier.
    #[must_use]
    pub fn id(&self) -> ReservationId {
        self.id
    }

    /// The reserved amount.
    #[must_use]
    pub fn amount(&self) -> NanoUsd {
        self.amount
    }
}

impl Reservation<Held> {
    /// Marks execution as started. From here on the reservation can only be settled.
    pub fn begin(self) -> Reservation<InFlight> {
        Reservation {
            id: self.id,
            pool: self.pool,
            amount: self.amount,
            state: PhantomData,
        }
    }
}

/// What the provider (or tool) reported as the actual cost.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Usage {
    /// Actual cost is known.
    Reported(NanoUsd),
    /// No usage was reported (aborted stream, crash): settle at the reserved amount, estimated.
    Unknown,
}

/// The result of settling.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Settlement {
    /// Amount recorded as spent.
    pub spent: NanoUsd,
    /// Amount returned to the pool.
    pub released: NanoUsd,
    /// Amount charged beyond the reservation (an S1 condition: the estimate was too low).
    pub overrun: NanoUsd,
    /// Whether the spend is an estimate.
    pub estimated: bool,
}

/// What [`Ledger::recover`] did.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Recovery {
    /// Open reservations settled at their full reserved amount (estimated).
    pub settled_estimated: usize,
    /// Partially settled reservations completed (remainder released or overrun charged).
    pub completed: usize,
    /// Transfers whose second half was recorded.
    pub transfers_completed: usize,
}

/// The ledger: state plus the rules for producing entries.
#[derive(Debug, Default)]
pub struct Ledger {
    state: LedgerState,
    poisoned: bool,
}

fn key(text: String) -> Result<IdempotencyKey, LedgerError> {
    IdempotencyKey::new(text).map_err(LedgerError::Invalid)
}

fn reason(code: &str) -> Result<ReasonCode, LedgerError> {
    ReasonCode::new(code).map_err(LedgerError::Invalid)
}

/// Fields of an entry that vary by operation.
struct Draft {
    key: IdempotencyKey,
    pool: PoolId,
    kind: BudgetTxKind,
    amount: NanoUsd,
    reason: &'static str,
    reservation: Option<ReservationId>,
    counterparty: Option<PoolId>,
    settled: bool,
    estimated: bool,
}

impl Ledger {
    /// Rebuilds a ledger from recorded entries (the journal's `budget.entry` records).
    ///
    /// # Errors
    /// The first entry that does not apply; the history is inconsistent at that point.
    pub fn replay<'a>(entries: impl IntoIterator<Item = &'a BudgetTx>) -> Result<Self, LedgerError> {
        let mut state = LedgerState::default();
        for tx in entries {
            state.apply(tx)?;
        }
        Ok(Self { state, poisoned: false })
    }

    /// The current state.
    #[must_use]
    pub fn state(&self) -> &LedgerState {
        &self.state
    }

    /// Whether a recording failure has stopped the ledger until it is rebuilt.
    #[must_use]
    pub fn is_poisoned(&self) -> bool {
        self.poisoned
    }

    fn record(&mut self, sink: &mut dyn LedgerSink, principal: &Actor, d: Draft) -> Result<BudgetTx, LedgerError> {
        if self.poisoned {
            return Err(LedgerError::Poisoned);
        }
        if let Some(previous) = self.state.entry_for(&d.key) {
            // Idempotent retry: return what was recorded, record nothing new. The same key for a
            // different movement of money is a caller bug, never silently absorbed.
            let same = previous.kind == d.kind
                && previous.pool_id == d.pool
                && previous.amount == d.amount
                && previous.reservation_id == d.reservation
                && previous.counterparty_pool == d.counterparty;
            return if same {
                Ok(previous.clone())
            } else {
                Err(LedgerError::KeyConflict(d.key.as_str().to_owned()))
            };
        }
        let before = self.state.pool(d.pool).map_or(NanoUsd::ZERO, |p| p.available);
        let mut tx = BudgetTx {
            schema: BudgetTxSchema::V1,
            idempotency_key: d.key,
            pool_id: d.pool,
            principal: principal.clone(),
            session_id: None,
            kind: d.kind,
            amount: d.amount,
            balance_before: before,
            balance_after: before,
            reason_code: reason(d.reason)?,
            related_event: None,
            reservation_id: d.reservation,
            counterparty_pool: d.counterparty,
            settled: d.settled,
            estimated: d.estimated,
        };
        tx.balance_after = before.checked_add(tx.effect()?).ok_or(LedgerError::Overflow)?;
        self.state.check(&tx)?;
        if let Err(e) = sink.record(&tx) {
            self.poisoned = true;
            return Err(LedgerError::Sink(e));
        }
        if let Err(e) = self.state.apply(&tx) {
            // Unreachable while `check` and `apply` share one rule set; if they ever diverge,
            // memory no longer matches what was recorded.
            self.poisoned = true;
            return Err(e);
        }
        Ok(tx)
    }

    /// Adds money to a pool (creating it on first use).
    ///
    /// # Errors
    /// Recording or consistency failures.
    pub fn allocate(
        &mut self,
        sink: &mut dyn LedgerSink,
        pool: PoolId,
        amount: NanoUsd,
        principal: &Actor,
        idempotency: IdempotencyKey,
    ) -> Result<(), LedgerError> {
        let d = Draft {
            key: idempotency,
            pool,
            kind: BudgetTxKind::Allocate,
            amount,
            reason: "allocate",
            reservation: None,
            counterparty: None,
            settled: false,
            estimated: false,
        };
        self.record(sink, principal, d).map(|_| ())
    }

    /// Reserves `amount` before an Operation executes. The hard cap: refused with
    /// [`LedgerError::Insufficient`] if the pool cannot cover it.
    ///
    /// A reservation identifier is single-use: reserving it again is refused with
    /// [`LedgerError::ReservationReused`], so at most one token ever exists per reservation and a
    /// duplicate `Held` token can never release money an `InFlight` one may have spent.
    ///
    /// # Errors
    /// `Insufficient`, `UnknownPool`, `ReservationReused`, recording or consistency failures.
    pub fn reserve(
        &mut self,
        sink: &mut dyn LedgerSink,
        pool: PoolId,
        id: ReservationId,
        amount: NanoUsd,
        principal: &Actor,
    ) -> Result<Reservation<Held>, LedgerError> {
        if self.poisoned {
            return Err(LedgerError::Poisoned);
        }
        if self.state.knows_reservation(id) {
            return Err(LedgerError::ReservationReused(id));
        }
        let d = Draft {
            key: key(format!("{id}:reserve"))?,
            pool,
            kind: BudgetTxKind::Reserve,
            amount,
            reason: "reserve",
            reservation: Some(id),
            counterparty: None,
            settled: false,
            estimated: false,
        };
        let tx = self.record(sink, principal, d)?;
        Ok(Reservation {
            id,
            pool: tx.pool_id,
            amount: tx.amount,
            state: PhantomData,
        })
    }

    /// Returns a reservation whose execution never started.
    ///
    /// ```
    /// # use uaos_contracts::{event::Actor, id::{PoolId, ReservationId, TypedId}, money::NanoUsd, budget::IdempotencyKey};
    /// # use uaos_ledger::{Ledger, MemorySink};
    /// # fn main() -> Result<(), Box<dyn std::error::Error>> {
    /// let (mut ledger, mut sink) = (Ledger::default(), MemorySink::default());
    /// let pool = PoolId::from_parts(1, [1; 10]);
    /// ledger.allocate(&mut sink, pool, NanoUsd::new(10), &Actor::System, IdempotencyKey::new("fund")?)?;
    /// let held = ledger.reserve(&mut sink, pool, ReservationId::from_parts(1, [2; 10]), NanoUsd::new(5), &Actor::System)?;
    /// ledger.release(&mut sink, held, &Actor::System)?;
    /// # Ok(()) }
    /// ```
    ///
    /// Once execution has begun, the reservation can only be settled; releasing it does not
    /// compile:
    ///
    /// ```compile_fail
    /// # use uaos_contracts::{event::Actor, id::{PoolId, ReservationId, TypedId}, money::NanoUsd, budget::IdempotencyKey};
    /// # use uaos_ledger::{Ledger, MemorySink};
    /// # fn main() -> Result<(), Box<dyn std::error::Error>> {
    /// let (mut ledger, mut sink) = (Ledger::default(), MemorySink::default());
    /// let pool = PoolId::from_parts(1, [1; 10]);
    /// ledger.allocate(&mut sink, pool, NanoUsd::new(10), &Actor::System, IdempotencyKey::new("fund")?)?;
    /// let held = ledger.reserve(&mut sink, pool, ReservationId::from_parts(1, [2; 10]), NanoUsd::new(5), &Actor::System)?;
    /// ledger.release(&mut sink, held.begin(), &Actor::System)?;
    /// # Ok(()) }
    /// ```
    ///
    /// # Errors
    /// Recording or consistency failures.
    #[allow(
        clippy::needless_pass_by_value,
        reason = "taking the token by value is the point: the caller cannot use it again"
    )]
    pub fn release(
        &mut self,
        sink: &mut dyn LedgerSink,
        reservation: Reservation<Held>,
        principal: &Actor,
    ) -> Result<(), LedgerError> {
        // The token was moved in: it can never be released or settled again.
        let Reservation { id, pool, amount, .. } = reservation;
        let d = Draft {
            key: key(format!("{id}:release"))?,
            pool,
            kind: BudgetTxKind::Release,
            amount,
            reason: "release",
            reservation: Some(id),
            counterparty: None,
            settled: true,
            estimated: false,
        };
        self.record(sink, principal, d).map(|_| ())
    }

    /// Settles a reservation whose execution started: records the spend, then returns the
    /// unused remainder or charges an overrun.
    ///
    /// # Errors
    /// Recording or consistency failures.
    #[allow(
        clippy::needless_pass_by_value,
        reason = "taking the token by value is the point: the caller cannot use it again"
    )]
    pub fn settle(
        &mut self,
        sink: &mut dyn LedgerSink,
        reservation: Reservation<InFlight>,
        usage: Usage,
        principal: &Actor,
    ) -> Result<Settlement, LedgerError> {
        // The token was moved in: it can never be settled again.
        let Reservation { id, pool, amount, .. } = reservation;
        self.settle_open(sink, id, pool, amount, None, usage, principal)
    }

    #[allow(clippy::too_many_arguments, reason = "internal: one call site per recovery path")]
    fn settle_open(
        &mut self,
        sink: &mut dyn LedgerSink,
        id: ReservationId,
        pool: PoolId,
        reserved: NanoUsd,
        already_settled: Option<NanoUsd>,
        usage: Usage,
        principal: &Actor,
    ) -> Result<Settlement, LedgerError> {
        let (actual, estimated) = match (already_settled, usage) {
            (Some(actual), _) | (None, Usage::Reported(actual)) => (actual, false),
            (None, Usage::Unknown) => (reserved, true),
        };
        if already_settled.is_none() {
            let d = Draft {
                key: key(format!("{id}:settle"))?,
                pool,
                kind: BudgetTxKind::Settle,
                amount: actual,
                reason: if estimated { "settle_estimated" } else { "settle" },
                reservation: Some(id),
                counterparty: None,
                settled: actual == reserved,
                estimated,
            };
            self.record(sink, principal, d)?;
        }
        let mut out = Settlement {
            spent: actual,
            released: NanoUsd::ZERO,
            overrun: NanoUsd::ZERO,
            estimated,
        };
        if actual < reserved {
            let remainder = reserved.checked_sub(actual).ok_or(LedgerError::Overflow)?;
            let d = Draft {
                key: key(format!("{id}:release"))?,
                pool,
                kind: BudgetTxKind::Release,
                amount: remainder,
                reason: "release_remainder",
                reservation: Some(id),
                counterparty: None,
                settled: true,
                estimated: false,
            };
            self.record(sink, principal, d)?;
            out.released = remainder;
        } else if actual > reserved {
            let overrun = actual.checked_sub(reserved).ok_or(LedgerError::Overflow)?;
            let d = Draft {
                key: key(format!("{id}:overrun"))?,
                pool,
                kind: BudgetTxKind::Adjust,
                amount: NanoUsd::ZERO.checked_sub(overrun).ok_or(LedgerError::Overflow)?,
                reason: "overrun",
                reservation: Some(id),
                counterparty: None,
                settled: true,
                estimated: false,
            };
            self.record(sink, principal, d)?;
            out.overrun = overrun;
        }
        Ok(out)
    }

    /// Moves money between pools: a `TransferOut` then its paired `TransferIn`. If the process
    /// dies in between, [`Ledger::recover`] records the missing half.
    ///
    /// # Errors
    /// `Insufficient` on the source pool, recording or consistency failures.
    pub fn transfer(
        &mut self,
        sink: &mut dyn LedgerSink,
        from: PoolId,
        to: PoolId,
        amount: NanoUsd,
        principal: &Actor,
        idempotency: IdempotencyKey,
    ) -> Result<(), LedgerError> {
        let in_key = transfer_in_key(&idempotency)?;
        let out = Draft {
            key: idempotency,
            pool: from,
            kind: BudgetTxKind::TransferOut,
            amount,
            reason: "transfer",
            reservation: None,
            counterparty: Some(to),
            settled: false,
            estimated: false,
        };
        self.record(sink, principal, out)?;
        let incoming = Draft {
            key: in_key,
            pool: to,
            kind: BudgetTxKind::TransferIn,
            amount,
            reason: "transfer",
            reservation: None,
            counterparty: Some(from),
            settled: false,
            estimated: false,
        };
        self.record(sink, principal, incoming).map(|_| ())
    }

    /// Closes everything a crash (or a dropped token) left open: unsettled reservations are
    /// settled at their full reserved amount, marked estimated, and never released; partially
    /// settled reservations get their closing entry; half-recorded transfers are completed.
    ///
    /// # Errors
    /// Recording or consistency failures.
    pub fn recover(&mut self, sink: &mut dyn LedgerSink, principal: &Actor) -> Result<Recovery, LedgerError> {
        let mut report = Recovery::default();
        let open: Vec<_> = self.state.open.iter().map(|(id, o)| (*id, *o)).collect();
        for (id, o) in open {
            if o.settled.is_some() {
                report.completed += 1;
            } else {
                report.settled_estimated += 1;
            }
            self.settle_open(sink, id, o.pool, o.reserved, o.settled, Usage::Unknown, principal)?;
        }
        let pending: Vec<_> = self.state.pending.iter().map(|(k, p)| (k.clone(), *p)).collect();
        for (out_key, p) in pending {
            let d = Draft {
                key: transfer_in_key(&out_key)?,
                pool: p.to,
                kind: BudgetTxKind::TransferIn,
                amount: p.amount,
                reason: "transfer_recovered",
                reservation: None,
                counterparty: Some(p.from),
                settled: false,
                estimated: false,
            };
            self.record(sink, principal, d)?;
            report.transfers_completed += 1;
        }
        Ok(report)
    }
}
