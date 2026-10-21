// SPDX-License-Identifier: Apache-2.0

//! Boot recovery (contract `0013-runtime-boot-recovery.md`).
//!
//! After the journal has opened and repaired its tail, [`boot`] rebuilds what the runtime holds in
//! memory from the verified records, closes what a crash left open, and explains the boot in one
//! `kernel.booted` record:
//! 1. a configuration older than the journal's last is refused, before anything is written;
//! 2. the stop is restored;
//! 3. the ledger is replayed and recovered: money that may be spent is settled, never released;
//! 4. every open intent becomes `Indeterminate`, once: neither success nor failure is assumed;
//! 5. the boot is journaled with its counts.
//!
//! A crash between any two appends converges on the next boot without duplicates (§3).

use std::collections::BTreeMap;

use uaos_contracts::error::{ErrorCode, codes};
use uaos_contracts::event::{Actor, Durability, EnvelopeError, EventType, InlinePayload, Metadata, types};
use uaos_contracts::id::{CorrelationId, OperationId};
use uaos_contracts::operation::{RiskTier, SideEffectClass};
use uaos_contracts::wire::ConfigVersion;
use uaos_ledger::{JournalSink, Ledger, Recovery, entries_from_journal};
use uaos_state::journal::{EventDraft, Journal, JournalError, VerifiedRecord};

use crate::config::ConfigSnapshot;
use crate::stop::{BootState, Stop, boot_state};

/// The reason an intent with no outcome is made indeterminate.
pub const CRASH_RECOVERY: &str = "crash_recovery";

/// What a boot did: counts and versions only, as the `kernel.booted` record carries them.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BootReport {
    /// Verified records read.
    pub records: u64,
    /// The stop as the journal left it.
    pub stop: BootState,
    /// Operations whose intent had no outcome, now `Indeterminate`, in journal order.
    pub indeterminate: Vec<OperationId>,
    /// Open reservations settled at their full amount, estimated.
    pub settled_estimated: usize,
    /// Partly settled reservations completed.
    pub completed: usize,
    /// Transfers whose second half was recorded.
    pub transfers_completed: usize,
    /// Ledger items recovery could not close (S2); while any remain, the ledger refuses work.
    pub stuck: usize,
    /// The configuration version the kernel boots with.
    pub config_version: ConfigVersion,
}

/// A booted kernel's state.
#[derive(Debug)]
pub struct Booted {
    /// The stop, as the journal left it.
    pub stop: Stop,
    /// The ledger, replayed and recovered.
    pub ledger: Ledger,
    /// What the boot did.
    pub report: BootReport,
}

/// Why boot refused or failed.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum BootError {
    /// The configuration is older than the last one the journal records (§2 step 1). Nothing was
    /// written.
    #[error("the configuration (version {configured}) is older than the journal's last ({journaled})")]
    ConfigDrift {
        /// The highest version a record carries.
        journaled: ConfigVersion,
        /// The version the process starts with.
        configured: ConfigVersion,
    },
    /// The ledger's entries do not replay, or recovery could not record its entries.
    #[error("the budget ledger could not be rebuilt: {0}")]
    Ledger(String),
    /// The journal refused a recovery record. The next boot resumes where this one stopped.
    #[error("the journal refused a recovery record: {0}")]
    Journal(#[from] JournalError),
    /// A recovery record does not fit the envelope's bounds.
    #[error("a recovery record does not fit the envelope: {0}")]
    Envelope(#[from] EnvelopeError),
}

impl BootError {
    /// The registered error code.
    #[must_use]
    pub const fn code(&self) -> ErrorCode {
        match self {
            Self::ConfigDrift { .. } => codes::CONFIG_DRIFT,
            Self::Ledger(_) => codes::BUDGET_LEDGER_INCONSISTENT,
            Self::Journal(_) | Self::Envelope(_) => codes::JOURNAL_WRITE_FAILED,
        }
    }
}

/// Recovers a kernel from its journal (contract §2). `records` are the journal's verified records,
/// oldest first; `config` is the snapshot the process starts with; the recovery records carry
/// `correlation`.
///
/// # Errors
/// [`BootError::ConfigDrift`] before anything is written; otherwise a ledger or journal failure,
/// after which the next boot resumes (§3).
pub fn boot(
    journal: &mut Journal,
    records: &[VerifiedRecord],
    config: &ConfigSnapshot,
    correlation: CorrelationId,
) -> Result<Booted, BootError> {
    // 1. Drift, before anything is written.
    if let Some(journaled) = records.iter().map(|r| r.envelope.config_version).max()
        && journaled > config.version()
    {
        return Err(BootError::ConfigDrift {
            journaled,
            configured: config.version(),
        });
    }

    // 2. The stop. A stopped kernel boots stopped; recovery still closes the journal honestly.
    let stop_state = boot_state(records.iter().map(|r| &r.envelope));
    let stop = Stop::booted(stop_state);

    // 3. The ledger: replayed, then recovered. Open reservations settle at their full amount,
    // estimated, and are never released: their Operations may have spent them.
    let entries = entries_from_journal(records).map_err(BootError::Ledger)?;
    let mut ledger = Ledger::replay(&entries).map_err(|e| BootError::Ledger(e.to_string()))?;
    let recovery = if ledger.needs_recovery() {
        let mut sink = JournalSink::new(journal, correlation, None, config.version());
        ledger
            .recover(&mut sink, &Actor::System)
            .map_err(|e| BootError::Ledger(e.to_string()))?
    } else {
        Recovery::default()
    };

    // 4. Every intent with no outcome becomes indeterminate, once.
    let indeterminate = open_intents(records);
    for operation in &indeterminate {
        journal.append(indeterminate_draft(*operation, correlation, config.version())?)?;
    }

    // 5. The boot, explained.
    let report = BootReport {
        records: u64::try_from(records.len()).unwrap_or(u64::MAX),
        stop: stop_state,
        indeterminate,
        settled_estimated: recovery.settled_estimated,
        completed: recovery.completed,
        transfers_completed: recovery.transfers_completed,
        stuck: recovery.stuck.len(),
        config_version: config.version(),
    };
    journal.append(booted_draft(&report, correlation)?)?;
    Ok(Booted { stop, ledger, report })
}

/// The event types after which an Operation has an outcome, or needs a human: terminal for boot.
const OUTCOMES: [&EventType; 5] = [
    &types::OP_COMMITTED,
    &types::OP_FAILED,
    &types::OP_DENIED,
    &types::OP_APPROVAL_REQUIRED,
    &types::OP_INDETERMINATE,
];

/// Operations whose last journaled state is `Reserved`: an intent with no outcome, in the order
/// their intents were journaled.
fn open_intents(records: &[VerifiedRecord]) -> Vec<OperationId> {
    // Per Operation: the position of its first intent, and whether it is still open.
    let mut state: BTreeMap<OperationId, (usize, bool)> = BTreeMap::new();
    for (at, record) in records.iter().enumerate() {
        let Some(operation) = record.envelope.operation_id else {
            continue;
        };
        let event_type = &record.envelope.event_type;
        if *event_type == types::OP_RESERVED_INTENT {
            state.entry(operation).or_insert((at, true)).1 = true;
        } else if OUTCOMES.contains(&event_type) {
            state.entry(operation).or_insert((at, false)).1 = false;
        }
    }
    let mut open: Vec<(usize, OperationId)> = state
        .into_iter()
        .filter_map(|(operation, (at, is_open))| is_open.then_some((at, operation)))
        .collect();
    open.sort_unstable();
    open.into_iter().map(|(_, operation)| operation).collect()
}

fn draft(
    event_type: EventType,
    operation: Option<OperationId>,
    correlation: CorrelationId,
    config_version: ConfigVersion,
    payload: serde_json::Value,
) -> Result<EventDraft, EnvelopeError> {
    Ok(EventDraft {
        session_id: None,
        pocket_id: None,
        operation_id: operation,
        request_id: None,
        agent_id: None,
        correlation_id: correlation,
        parent_id: None,
        actor: Actor::System,
        event_type,
        payload_ref: None,
        payload_inline: Some(InlinePayload::new(payload)?),
        cost_estimate: None,
        compensable: false,
        side_effect_class: SideEffectClass::None,
        // Recovery surfaces: an interrupted Operation is never routine bookkeeping.
        risk_tier: RiskTier::MAX,
        durability: Durability::Critical,
        config_version,
        metadata: Metadata::default(),
    })
}

/// `op.indeterminate` for an intent with no outcome (`Transition::CrashRecovered`): the request may
/// have reached the provider, and neither success nor failure is assumed (red line 3).
fn indeterminate_draft(
    operation: OperationId,
    correlation: CorrelationId,
    config_version: ConfigVersion,
) -> Result<EventDraft, EnvelopeError> {
    draft(
        types::OP_INDETERMINATE,
        Some(operation),
        correlation,
        config_version,
        serde_json::json!({ "reason": CRASH_RECOVERY }),
    )
}

/// `kernel.booted`, with the boot's counts.
fn booted_draft(report: &BootReport, correlation: CorrelationId) -> Result<EventDraft, EnvelopeError> {
    draft(
        types::KERNEL_BOOTED,
        None,
        correlation,
        report.config_version,
        serde_json::json!({
            "records": report.records,
            "indeterminate": report.indeterminate.len(),
            "settled_estimated": report.settled_estimated,
            "completed": report.completed,
            "transfers_completed": report.transfers_completed,
            "stuck": report.stuck,
            "stopped": report.stop != BootState::Running,
            "config_version": report.config_version.0,
        }),
    )
}
