// SPDX-License-Identifier: Apache-2.0

//! # UAOS identity: scoped credentials
//!
//! Agents never hold provider keys. They authenticate with credentials that UAOS issues
//! (ADR-0004, ADR-0011; cells C-07, C-08, C-09):
//!
//! * **recognisable:** `uaos_sk_` + base32 + a CRC-32 checksum, so secret scanners can find a
//!   leaked key;
//! * **stored as digests only:** HMAC-SHA-256 under an identity key held in the OS keychain.
//!   The secret is shown once and never journaled;
//! * **hierarchical:** master → sub → child, at most
//!   [`uaos_contracts::limits::MAX_CREDENTIAL_DEPTH`] long. A child's scope must be within its
//!   parent's, checked at issuance and again on every verification;
//! * **revocable:** directly, or for a whole subtree by bumping an epoch. Every revocation is a
//!   critical journal record before it returns;
//! * **restore-safe:** a counter in the OS keychain detects a data directory restored from
//!   before a revocation, and verification then fails closed.
//!
//! Like the ledger, the identity is a pure replay of its journal entries (`identity.entry`).

#![deny(missing_docs)]
#![deny(clippy::indexing_slicing)]

mod identity;
mod journal_sink;
pub mod scope;
mod secret;
mod state;

pub use identity::{Identity, IdentityKeys, IdentitySink, IssueRequest, Issued, MemorySink};
pub use journal_sink::{JournalSink, entries_from_journal};
pub use secret::{MalformedCredential, PREFIX, Secret, TEXT_LEN};
pub use state::{IdentityError, IdentityState, Node, Verified};
