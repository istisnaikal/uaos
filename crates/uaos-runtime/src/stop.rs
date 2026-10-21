// SPDX-License-Identifier: Apache-2.0

//! The kernel stop, the kill switch (contract §3).
//!
//! One atomic flag, set before anything else. Admission reads it first, and every admitted
//! Operation holds a [`StopWatch`], so a live relay cuts at its next poll. The stop restricts,
//! so it acts before its record is written and never waits on the state actor; the record
//! ([`Engaged::draft`]) is journaled after, and [`boot_state`] honours it at the next start.

use std::fmt;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use tokio::sync::watch;
use uaos_contracts::event::{Actor, Durability, EnvelopeError, EventEnvelope, InlinePayload, Metadata, types};
use uaos_contracts::id::CorrelationId;
use uaos_contracts::operation::{RiskTier, SideEffectClass};
use uaos_contracts::wire::ConfigVersion;
use uaos_state::journal::EventDraft;

/// Why the kernel stopped. The code is what the journal records.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum StopReason {
    /// A human stopped it.
    Operator,
    /// A response's usage passed its reservation mid-stream (contract §7.4).
    BudgetOverrun,
    /// The chunk store could not flush the journal's payloads (ADR-0018).
    PayloadFlushFailed,
    /// The disk is full.
    DiskFull,
    /// A secret canary appeared where it must never be (S1).
    CanaryHit,
    /// A journaled stop whose reason this build does not know. It still boots stopped.
    Unrecognized,
}

impl StopReason {
    /// Every reason a stop can be engaged with.
    pub const ENGAGEABLE: [Self; 5] = [
        Self::Operator,
        Self::BudgetOverrun,
        Self::PayloadFlushFailed,
        Self::DiskFull,
        Self::CanaryHit,
    ];

    /// The journaled code.
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::Operator => "operator",
            Self::BudgetOverrun => "budget_overrun",
            Self::PayloadFlushFailed => "payload_flush_failed",
            Self::DiskFull => "disk_full",
            Self::CanaryHit => "canary_hit",
            Self::Unrecognized => "unrecognized",
        }
    }

    /// The reason a journaled code names; an unknown code is [`StopReason::Unrecognized`].
    #[must_use]
    pub fn from_code(code: &str) -> Self {
        Self::ENGAGEABLE
            .into_iter()
            .find(|r| r.code() == code)
            .unwrap_or(Self::Unrecognized)
    }
}

struct Inner {
    engaged: AtomicBool,
    /// The engaged stop's record is in the journal ([`Stop::recorded`]).
    recorded: AtomicBool,
    reason: watch::Sender<Option<StopReason>>,
}

/// The kernel stop. Clones share one stop.
#[derive(Clone)]
pub struct Stop {
    inner: Arc<Inner>,
}

impl fmt::Debug for Stop {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Stop").field("reason", &self.reason()).finish()
    }
}

impl Default for Stop {
    fn default() -> Self {
        Self::running()
    }
}

impl Stop {
    /// A kernel that is running.
    #[must_use]
    pub fn running() -> Self {
        Self {
            inner: Arc::new(Inner {
                engaged: AtomicBool::new(false),
                recorded: AtomicBool::new(false),
                reason: watch::Sender::new(None),
            }),
        }
    }

    /// The stop as the journal left it ([`boot_state`]): a kernel stopped before a restart boots
    /// stopped (rule 4).
    #[must_use]
    pub fn booted(state: BootState) -> Self {
        let stop = Self::running();
        if let BootState::Stopped(reason) = state {
            // Its record is the one boot read.
            stop.inner.recorded.store(true, Ordering::SeqCst);
            let _engaged = stop.engage(reason);
        }
        stop
    }

    /// Engages the stop. The flag is set before any watcher is woken, so admission refuses from
    /// this instant, and every live relay cuts at its next poll. The first reason wins; engaging
    /// again changes nothing ([`Engaged::first`] is false).
    #[must_use = "journal the stop through `Stop::unrecorded`"]
    pub fn engage(&self, reason: StopReason) -> Engaged {
        let mut kept = reason;
        let first = self.inner.reason.send_if_modified(|current| {
            if let Some(held) = *current {
                kept = held;
                false
            } else {
                // The flag first: admission reads it before anything else (rule 1).
                self.inner.engaged.store(true, Ordering::SeqCst);
                *current = Some(reason);
                true
            }
        });
        Engaged { reason: kept, first }
    }

    /// Whether the stop is engaged.
    #[must_use]
    pub fn is_engaged(&self) -> bool {
        self.inner.engaged.load(Ordering::SeqCst)
    }

    /// The reason the stop holds, if engaged.
    #[must_use]
    pub fn reason(&self) -> Option<StopReason> {
        *self.inner.reason.borrow()
    }

    /// The engaged stop, while its record is not in the journal yet. The state actor (PR-6b)
    /// journals [`Engaged::draft`] and then calls [`Stop::recorded`]; until it does, this keeps
    /// returning the stop, so while the process runs a failed write is retried (review L12). A
    /// restart before the record is durable boots running: that is the window rule 3 accepts,
    /// by acting before the record, and PR-6b's DST bounds it. `None` while running, or once
    /// recorded. Whoever engaged the stop need not journal it, so a relay engages without a
    /// journal.
    #[must_use]
    pub fn unrecorded(&self) -> Option<Engaged> {
        let reason = self.reason()?;
        (!self.inner.recorded.load(Ordering::SeqCst)).then_some(Engaged { reason, first: true })
    }

    /// The stop's record is in the journal. A no-op while running.
    pub fn recorded(&self) {
        if self.is_engaged() {
            self.inner.recorded.store(true, Ordering::SeqCst);
        }
    }

    /// A watch on the stop. Subscribe before checking [`Stop::is_engaged`], and a stop engaged
    /// later is never missed (rule 2).
    #[must_use]
    pub fn watch(&self) -> StopWatch {
        StopWatch {
            rx: self.inner.reason.subscribe(),
        }
    }
}

/// What [`Stop::engage`] did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Engaged {
    reason: StopReason,
    first: bool,
}

impl Engaged {
    /// The reason the stop holds: the first one engaged.
    #[must_use]
    pub const fn reason(&self) -> StopReason {
        self.reason
    }

    /// Whether this call engaged the stop. Only the first is journaled.
    #[must_use]
    pub const fn first(&self) -> bool {
        self.first
    }

    /// The `kernel.stopped` record to journal after the stop took effect (rule 3): critical,
    /// with the reason as its inline payload.
    ///
    /// # Errors
    /// [`EnvelopeError`] if the inline payload does not fit the envelope's bound (it always
    /// fits: one short code).
    pub fn draft(
        &self,
        actor: Actor,
        correlation_id: CorrelationId,
        config_version: ConfigVersion,
    ) -> Result<EventDraft, EnvelopeError> {
        Ok(EventDraft {
            session_id: None,
            pocket_id: None,
            operation_id: None,
            request_id: None,
            agent_id: None,
            correlation_id,
            parent_id: None,
            actor,
            event_type: types::KERNEL_STOPPED,
            payload_ref: None,
            payload_inline: Some(InlinePayload::new(serde_json::json!({ "reason": self.reason.code() }))?),
            cost_estimate: None,
            compensable: false,
            side_effect_class: SideEffectClass::None,
            risk_tier: RiskTier::MAX,
            durability: Durability::Critical,
            config_version,
            metadata: Metadata::default(),
        })
    }
}

/// A watch on the stop, held by every admitted Operation.
#[derive(Debug, Clone)]
pub struct StopWatch {
    rx: watch::Receiver<Option<StopReason>>,
}

impl StopWatch {
    /// The reason, if the stop is engaged.
    #[must_use]
    pub fn engaged(&self) -> Option<StopReason> {
        *self.rx.borrow()
    }

    /// Resolves once the stop is engaged, at once if it already is. If every [`Stop`] handle is
    /// gone, the kernel is gone too, and it never resolves.
    pub async fn stopped(mut self) -> StopReason {
        loop {
            if let Some(reason) = *self.rx.borrow_and_update() {
                return reason;
            }
            if self.rx.changed().await.is_err() {
                return std::future::pending().await;
            }
        }
    }
}

/// How the journal left the stop.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BootState {
    /// No stop, or a resume after the last one.
    Running,
    /// The last record was a stop with this reason.
    Stopped(StopReason),
}

/// Reads the stop from verified journal records, oldest first: the last `kernel.stopped` or
/// `kernel.resumed` decides (rule 4). A stop whose reason is missing or unknown still stops,
/// and only a human resumes: a `kernel.resumed` from any other actor is ignored (review L12;
/// presence is M3's, ADR-0012).
pub fn boot_state<'a>(records: impl IntoIterator<Item = &'a EventEnvelope>) -> BootState {
    let mut state = BootState::Running;
    for record in records {
        if record.event_type == types::KERNEL_STOPPED {
            let code = record
                .payload_inline
                .as_ref()
                .and_then(|p| p.as_value().get("reason"))
                .and_then(serde_json::Value::as_str)
                .unwrap_or_default();
            state = BootState::Stopped(StopReason::from_code(code));
        } else if record.event_type == types::KERNEL_RESUMED && record.actor == Actor::Human {
            state = BootState::Running;
        }
    }
    state
}
