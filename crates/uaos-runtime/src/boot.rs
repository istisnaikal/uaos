// SPDX-License-Identifier: Apache-2.0

//! Boot recovery (contract `0013-runtime-boot-recovery.md`).
//!
//! After the journal has opened and repaired its tail, [`boot`] rebuilds what the runtime holds in
//! memory from the verified records, closes what a crash left open, and explains the boot in one
//! `kernel.booted` record:
//! 1. records that are not the journal's, or a configuration older than the journal's last, are
//!    refused, before anything is written;
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
use uaos_contracts::wire::{ConfigVersion, Seq};
use uaos_ledger::{JournalSink, Ledger, LedgerError, entries_from_journal};
use uaos_state::journal::{EventDraft, Journal, JournalError, VerifiedRecord};

use crate::config::ConfigSnapshot;
use crate::stop::{BootState, Stop, boot_state};

/// The reason an intent with no outcome is made indeterminate.
pub const CRASH_RECOVERY: &str = "crash_recovery";

/// What a boot did: counts and versions, as the `kernel.booted` record carries them, and in
/// memory only, why ledger items stayed stuck.
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
    /// Why each ledger item recovery could not close stayed open (S2). While any remain, the
    /// ledger refuses new work (`BUDGET_RECOVERY_REQUIRED`). Not journaled: the record counts
    /// them.
    pub stuck: Vec<String>,
    /// The kernel boots running after a crash, which work left open shows: a stop engaged just
    /// before the crash may not have been journaled (runtime contract §3 rule 3). A crash with
    /// nothing open looks like a clean exit until PR-6c journals one.
    pub stop_may_be_lost: bool,
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
    /// The records do not end where the journal does: boot would journal against records that are
    /// not the journal's, and a retry with the same records would repeat its writes (§2 step 0).
    /// Nothing was written.
    #[error("the records end before {records_end}, but the journal's next record is {journal_next}")]
    StaleRecords {
        /// The sequence number after the last record handed to boot.
        records_end: Seq,
        /// The journal's next sequence number.
        journal_next: Seq,
    },
    /// The configuration is older than the last one the journal records (§2 step 1). Nothing was
    /// written.
    #[error("the configuration (version {configured}) is older than the journal's last ({journaled})")]
    ConfigDrift {
        /// The highest version a record carries.
        journaled: ConfigVersion,
        /// The version the process starts with.
        configured: ConfigVersion,
    },
    /// A ledger entry in the journal does not decode. Nothing was written.
    #[error("a budget entry in the journal does not decode: {0}")]
    LedgerEntries(String),
    /// The ledger's entries do not replay, or recovery could not record its entries.
    #[error("the budget ledger could not be rebuilt: {0}")]
    Ledger(#[source] LedgerError),
    /// The journal refused a recovery record. The next boot resumes where this one stopped.
    #[error("the journal refused a recovery record: {0}")]
    Journal(#[from] JournalError),
    /// A recovery record does not fit the envelope's bounds.
    #[error("a recovery record does not fit the envelope: {0}")]
    Envelope(#[from] EnvelopeError),
}

impl BootError {
    /// The registered error code. A journal failure keeps its own code wherever it lands, in the
    /// ledger's recovery or in boot's own records.
    #[must_use]
    pub fn code(&self) -> ErrorCode {
        match self {
            Self::StaleRecords { .. } => codes::RUNTIME_BOOT_RECORDS_STALE,
            Self::ConfigDrift { .. } => codes::CONFIG_DRIFT,
            Self::LedgerEntries(_) => codes::BUDGET_LEDGER_INCONSISTENT,
            Self::Ledger(error) => error.code(),
            Self::Journal(error) => error.code(),
            Self::Envelope(_) => codes::JOURNAL_WRITE_FAILED,
        }
    }
}

/// Recovers a kernel from its journal (contract §2). `records` are the journal's verified records,
/// oldest first, read after it opened; `config` is the snapshot the process starts with; the
/// recovery records carry `correlation`.
///
/// # Errors
/// [`BootError::StaleRecords`] and [`BootError::ConfigDrift`] before anything is written;
/// otherwise a ledger or journal failure, after which the next boot resumes (§3).
pub fn boot(
    journal: &mut Journal,
    records: &[VerifiedRecord],
    config: &ConfigSnapshot,
    correlation: CorrelationId,
) -> Result<Booted, BootError> {
    // 0. The records are the journal's: they end where it goes on.
    let tip = records.last().map(|r| Seq(r.envelope.seq.0.saturating_add(1)));
    if let Some(records_end) = tip
        && records_end != journal.next_seq()
    {
        return Err(BootError::StaleRecords {
            records_end,
            journal_next: journal.next_seq(),
        });
    }

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

    // 3. The ledger: replayed, then recovered (a replayed ledger always runs its recovery). Open
    // reservations settle at their full amount, estimated, and are never released: their
    // Operations may have spent them.
    let entries = entries_from_journal(records).map_err(BootError::LedgerEntries)?;
    let mut ledger = Ledger::replay(&entries).map_err(BootError::Ledger)?;
    let recovery = {
        let mut sink = JournalSink::new(journal, correlation, None, config.version());
        ledger.recover(&mut sink, &Actor::System).map_err(BootError::Ledger)?
    };

    // 4. Every intent with no outcome becomes indeterminate, once, with the effect it declared.
    let intents = open_intents(records);
    for (operation, effect) in &intents {
        journal.append(indeterminate_draft(*operation, *effect, correlation, config.version())?)?;
    }

    // 5. The boot, explained.
    let crashed = !intents.is_empty()
        || recovery.settled_estimated + recovery.completed + recovery.transfers_completed + recovery.stuck.len() > 0;
    let stop_may_be_lost = stop_state == BootState::Running && crashed;
    let report = BootReport {
        records: u64::try_from(records.len()).unwrap_or(u64::MAX),
        stop: stop_state,
        indeterminate: intents.into_iter().map(|(operation, _)| operation).collect(),
        settled_estimated: recovery.settled_estimated,
        completed: recovery.completed,
        transfers_completed: recovery.transfers_completed,
        stuck: recovery.stuck,
        stop_may_be_lost,
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

/// What the records say of one Operation.
enum Seen {
    /// An intent with no outcome yet: where it was first journaled, and the effect it declared.
    Open { at: usize, effect: SideEffectClass },
    /// An outcome or a human's decision: terminal for boot, whatever a later record says.
    Closed,
}

/// Operations whose intent has no outcome, with the effect each intent declared, in the order
/// their intents were journaled. Once an Operation is closed, a later intent does not reopen it:
/// only an inconsistent journal holds one, and reopening would make a committed Operation
/// indeterminate.
fn open_intents(records: &[VerifiedRecord]) -> Vec<(OperationId, SideEffectClass)> {
    let mut seen: BTreeMap<OperationId, Seen> = BTreeMap::new();
    for (at, record) in records.iter().enumerate() {
        let envelope = &record.envelope;
        let Some(operation) = envelope.operation_id else {
            continue;
        };
        if envelope.event_type == types::OP_RESERVED_INTENT {
            seen.entry(operation).or_insert(Seen::Open {
                at,
                effect: envelope.side_effect_class,
            });
        } else if OUTCOMES.contains(&&envelope.event_type) {
            seen.insert(operation, Seen::Closed);
        }
    }
    let mut open: Vec<(usize, OperationId, SideEffectClass)> = seen
        .into_iter()
        .filter_map(|(operation, seen)| match seen {
            Seen::Open { at, effect } => Some((at, operation, effect)),
            Seen::Closed => None,
        })
        .collect();
    open.sort_unstable_by_key(|(at, ..)| *at);
    open.into_iter()
        .map(|(_, operation, effect)| (operation, effect))
        .collect()
}

fn draft(
    event_type: EventType,
    operation: Option<OperationId>,
    side_effect_class: SideEffectClass,
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
        side_effect_class,
        // Recovery surfaces: an interrupted Operation is never routine bookkeeping.
        risk_tier: RiskTier::MAX,
        durability: Durability::Critical,
        config_version,
        metadata: Metadata::default(),
    })
}

/// `op.indeterminate` for an intent with no outcome (`Transition::CrashRecovered`). It carries the
/// effect the intent declared, and says the effect may have happened: the request may have reached
/// the provider, and neither success nor failure is assumed (red line 3).
fn indeterminate_draft(
    operation: OperationId,
    effect: SideEffectClass,
    correlation: CorrelationId,
    config_version: ConfigVersion,
) -> Result<EventDraft, EnvelopeError> {
    draft(
        types::OP_INDETERMINATE,
        Some(operation),
        effect,
        correlation,
        config_version,
        serde_json::json!({ "reason": CRASH_RECOVERY, "may_have_taken_effect": true }),
    )
}

/// `kernel.booted`, with the boot's counts as canonical decimal strings (`wire`'s rule).
fn booted_draft(report: &BootReport, correlation: CorrelationId) -> Result<EventDraft, EnvelopeError> {
    draft(
        types::KERNEL_BOOTED,
        None,
        SideEffectClass::None,
        correlation,
        report.config_version,
        serde_json::json!({
            "records": report.records.to_string(),
            "indeterminate": report.indeterminate.len().to_string(),
            "settled_estimated": report.settled_estimated.to_string(),
            "completed": report.completed.to_string(),
            "transfers_completed": report.transfers_completed.to_string(),
            "stuck": report.stuck.len().to_string(),
            "stopped": report.stop != BootState::Running,
            "stop_may_be_lost": report.stop_may_be_lost,
            "config_version": report.config_version.0.to_string(),
        }),
    )
}
