// SPDX-License-Identifier: Apache-2.0

//! # UAOS budget ledger
//!
//! Pools of money, reservations taken before an Operation executes, settlement against actual
//! usage, transfers, and a hard cap that is structural rather than advisory (plan D12, C-25,
//! C-28, C-29):
//!
//! * money is integer nano-USD; floats are banned in this crate;
//! * a reservation that exceeds the available balance is refused before anything happens;
//! * every entry is recorded durably before it takes effect, and the ledger is a pure replay of
//!   its entries (the journal's `budget.entry` records);
//! * money that may already be spent is never released: in-flight reservations can only settle,
//!   and recovery settles open reservations at full cost, marked estimated.
//!
//! Limitation stated plainly: the idempotency index grows with the number of entries until
//! journal compaction (P4) introduces snapshots.

#![deny(missing_docs)]
#![deny(clippy::float_arithmetic)]

mod journal_sink;
mod ledger;
mod state;

pub use journal_sink::{JournalSink, entries_from_journal};
pub use ledger::{Held, InFlight, Ledger, LedgerSink, MemorySink, Recovery, Reservation, Settlement, Usage};
pub use state::{LedgerError, LedgerState, PoolState};
