// SPDX-License-Identifier: Apache-2.0

//! # UAOS test harnesses (dev-only)
//!
//! Never part of a release build. Holds harnesses that need real processes and real disks,
//! starting with the kill harness behind the `journal-durability` gate (ADR-0003):
//!
//! * `journal-crash-writer` (binary) appends records to a real journal with the production
//!   stack (`OsFs`, system clock, OS randomness) and prints `seq hash` for each acknowledged
//!   record, flushing stdout after every line;
//! * `tests/kill.rs` kills that writer at random acknowledgement counts and random times
//!   (`TerminateProcess` on Windows, `SIGKILL` on Unix), reopens the journal, and checks that every
//!   acknowledged record is present with exactly the acknowledged hash.

#![deny(missing_docs)]

use uaos_contracts::event::{Actor, Durability, Metadata, types};
use uaos_contracts::id::{CorrelationId, TypedId};
use uaos_contracts::operation::{RiskTier, SideEffectClass};
use uaos_contracts::wire::ConfigVersion;
use uaos_state::journal::EventDraft;

/// A representative critical record (write-ahead intent of an external operation).
#[must_use]
pub fn intent_draft(n: u64) -> EventDraft {
    let mut random = [0u8; 10];
    random[..8].copy_from_slice(&n.to_le_bytes());
    EventDraft {
        session_id: None,
        pocket_id: None,
        operation_id: None,
        request_id: None,
        correlation_id: CorrelationId::from_parts(n, random),
        parent_id: None,
        actor: Actor::System,
        event_type: types::OP_RESERVED_INTENT,
        payload_ref: None,
        payload_inline: None,
        cost_estimate: None,
        compensable: false,
        side_effect_class: SideEffectClass::External,
        risk_tier: RiskTier::MAX,
        durability: Durability::Critical,
        config_version: ConfigVersion(1),
        metadata: Metadata::default(),
    }
}
