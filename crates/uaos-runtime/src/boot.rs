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
use uaos_contracts::event::{
    Actor, Durability, EnvelopeError, EventEnvelope, EventType, InlinePayload, Metadata, types,
};
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
    /// The records are not the whole journal, from its genesis to its head: boot would journal
    /// against records that are not the journal's, and a retry with the same records would repeat
    /// its writes (§2 step 0). Nothing was written.
    #[error(
        "the records are not the whole journal from its genesis to its head, one record after \
         another (they end before {records_end}; the journal's next is {journal_next})"
    )]
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
    /// The ledger's entries do not replay, or its recovery failed other than at the journal.
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
    /// The registered error code. A journal failure keeps the journal's own code wherever it lands,
    /// in the ledger's recovery or in boot's own records; anything else the ledger reports is an
    /// inconsistent ledger.
    #[must_use]
    pub fn code(&self) -> ErrorCode {
        match self {
            Self::StaleRecords { .. } => codes::RUNTIME_BOOT_RECORDS_STALE,
            Self::ConfigDrift { .. } => codes::CONFIG_DRIFT,
            Self::LedgerEntries(_) | Self::Ledger(_) => codes::BUDGET_LEDGER_INCONSISTENT,
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
    // 0. The records are the whole journal: from its genesis to its head. A journal never drops
    // a verified record, so an empty slice means an empty journal.
    let records_end = records
        .last()
        .map_or(Seq(0), |last| Seq(last.envelope.seq.0.saturating_add(1)));
    let ends_at_head = records.last().map_or(journal.next_seq() == Seq(0), |last| {
        records_end == journal.next_seq() && last.hash == journal.head()
    });
    let from_genesis = records.first().is_none_or(|first| first.envelope.seq == Seq(0));
    // One after another, by sequence and chain link: no gap, no record twice (final review L1).
    let contiguous = records
        .iter()
        .zip(records.iter().skip(1))
        .all(|(a, b)| b.envelope.seq.0 == a.envelope.seq.0.saturating_add(1) && b.envelope.prev_hash == a.hash);
    if !(ends_at_head && from_genesis && contiguous) {
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
        match ledger.recover(&mut sink, &Actor::System) {
            Ok(recovery) => recovery,
            // A journal failure keeps the journal's own code, as it does at boot's own records.
            Err(error) => return Err(sink.take_refusal().map_or(BootError::Ledger(error), BootError::Journal)),
        }
    };

    // 4. Every intent with no outcome becomes indeterminate, once, with the effect it declared.
    let intents = open_intents(records);
    for intent in &intents {
        journal.append(indeterminate_draft(intent, config.version())?)?;
    }

    // 5. The boot, explained.
    // Evidence of a crash: work left open, or an interrupted boot's `op.indeterminate` with no
    // `kernel.booted` after it. A stuck item is not: it stays from boot to boot.
    let last_boot = records
        .iter()
        .rposition(|r| r.envelope.event_type == types::KERNEL_BOOTED);
    let interrupted = records
        .iter()
        .skip(last_boot.map_or(0, |at| at + 1))
        .any(|r| r.envelope.event_type == types::OP_INDETERMINATE);
    let crashed = interrupted
        || !intents.is_empty()
        || recovery.settled_estimated + recovery.completed + recovery.transfers_completed > 0;
    let stop_may_be_lost = stop_state == BootState::Running && crashed;
    let report = BootReport {
        records: u64::try_from(records.len()).unwrap_or(u64::MAX),
        stop: stop_state,
        indeterminate: intents.iter().filter_map(|intent| intent.operation_id).collect(),
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
enum Seen<'r> {
    /// An intent with no outcome yet: where it was first journaled, and that first intent.
    Open { at: usize, intent: &'r EventEnvelope },
    /// An outcome or a human's decision: terminal for boot, whatever a later record says.
    Closed,
}

/// The first intent of each Operation that has no outcome, in the order those intents were
/// journaled. Once an Operation is closed, a later intent does not reopen it:
/// only an inconsistent journal holds one, and reopening would make a committed Operation
/// indeterminate.
fn open_intents(records: &[VerifiedRecord]) -> Vec<&EventEnvelope> {
    let mut seen: BTreeMap<OperationId, Seen<'_>> = BTreeMap::new();
    for (at, record) in records.iter().enumerate() {
        let envelope = &record.envelope;
        let Some(operation) = envelope.operation_id else {
            continue;
        };
        if envelope.event_type == types::OP_RESERVED_INTENT {
            seen.entry(operation).or_insert(Seen::Open { at, intent: envelope });
        } else if OUTCOMES.contains(&&envelope.event_type) {
            seen.insert(operation, Seen::Closed);
        }
    }
    let mut open: Vec<(usize, &EventEnvelope)> = seen
        .into_values()
        .filter_map(|seen| match seen {
            Seen::Open { at, intent } => Some((at, intent)),
            Seen::Closed => None,
        })
        .collect();
    open.sort_unstable_by_key(|(at, _)| *at);
    open.into_iter().map(|(_, intent)| intent).collect()
}

/// `op.indeterminate` for an intent with no outcome (`Transition::CrashRecovered`). It is the
/// Operation's record: it carries the intent's ids and correlation, links to the intent, keeps the
/// effect the intent declared, and says the effect may have happened. The request may have reached
/// the provider, and neither success nor failure is assumed (red line 3; final review L4).
fn indeterminate_draft(intent: &EventEnvelope, config_version: ConfigVersion) -> Result<EventDraft, EnvelopeError> {
    Ok(EventDraft {
        session_id: intent.session_id,
        pocket_id: intent.pocket_id,
        operation_id: intent.operation_id,
        request_id: intent.request_id,
        agent_id: intent.agent_id,
        correlation_id: intent.correlation_id,
        parent_id: Some(intent.id),
        actor: Actor::System,
        event_type: types::OP_INDETERMINATE,
        payload_ref: None,
        payload_inline: Some(InlinePayload::new(serde_json::json!({
            "reason": CRASH_RECOVERY,
            "may_have_taken_effect": true,
        }))?),
        cost_estimate: None,
        compensable: false,
        side_effect_class: intent.side_effect_class,
        // Recovery surfaces: an interrupted Operation is never routine bookkeeping.
        risk_tier: RiskTier::MAX,
        durability: Durability::Critical,
        config_version,
        metadata: Metadata::default(),
    })
}

/// `kernel.booted`, with the boot's counts as canonical decimal strings (`wire`'s rule). A boot
/// that closed anything, or says a stop may have been lost, surfaces at the highest risk tier; a
/// clean boot is routine (final review L4).
fn booted_draft(report: &BootReport, correlation: CorrelationId) -> Result<EventDraft, EnvelopeError> {
    let recovered = !report.indeterminate.is_empty()
        || report.settled_estimated + report.completed + report.transfers_completed + report.stuck.len() > 0
        || report.stop_may_be_lost;
    let payload = serde_json::json!({
            "records": report.records.to_string(),
            "indeterminate": report.indeterminate.len().to_string(),
            "settled_estimated": report.settled_estimated.to_string(),
            "completed": report.completed.to_string(),
            "transfers_completed": report.transfers_completed.to_string(),
            "stuck": report.stuck.len().to_string(),
            "stopped": report.stop != BootState::Running,
            "stop_may_be_lost": report.stop_may_be_lost,
            "config_version": report.config_version.0.to_string(),
    });
    Ok(EventDraft {
        session_id: None,
        pocket_id: None,
        operation_id: None,
        request_id: None,
        agent_id: None,
        correlation_id: correlation,
        parent_id: None,
        actor: Actor::System,
        event_type: types::KERNEL_BOOTED,
        payload_ref: None,
        payload_inline: Some(InlinePayload::new(payload)?),
        cost_estimate: None,
        compensable: false,
        side_effect_class: SideEffectClass::None,
        risk_tier: if recovered { RiskTier::MAX } else { RiskTier::MIN },
        durability: Durability::Critical,
        config_version: report.config_version,
        metadata: Metadata::default(),
    })
}
