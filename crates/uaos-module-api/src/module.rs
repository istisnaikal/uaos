// SPDX-License-Identifier: Apache-2.0

//! The `Module` trait and what a hook sees (contract §2, §4): read-only borrows that end with the
//! call, and a collector for declarations.

use uaos_contracts::event::EventType;
use uaos_contracts::id::{AgentId, OperationId, PocketId};
use uaos_contracts::operation::{OperationKind, RiskTier};
use uaos_contracts::wire::Seq;

use crate::codec::SseEvent;
use crate::decl::{CandidateId, Decls};
use crate::grant_ref::GrantRef;
use crate::manifest::{HookPoint, Manifest};
use crate::state::StateMut;
use crate::view::StructuralView;

/// What a hook may know about its Operation: identifiers and metadata, never content. Built by
/// the host; `#[non_exhaustive]` so it grows additively (contract §9).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub struct OpMeta {
    /// The Operation.
    pub operation: OperationId,
    /// Its kind.
    pub kind: OperationKind,
    /// Its pocket: the only pocket this call's state belongs to.
    pub pocket: PocketId,
    /// Its risk tier.
    pub risk_tier: RiskTier,
    /// The agent that asked, if known.
    pub agent: Option<AgentId>,
}

impl OpMeta {
    /// The metadata of an Operation, with no agent known.
    #[must_use]
    pub const fn new(operation: OperationId, kind: OperationKind, pocket: PocketId, risk_tier: RiskTier) -> Self {
        Self {
            operation,
            kind,
            pocket,
            risk_tier,
            agent: None,
        }
    }

    /// Names the agent that asked.
    #[must_use]
    pub const fn with_agent(mut self, agent: AgentId) -> Self {
        self.agent = Some(agent);
        self
    }
}

/// A route candidate's breaker state, so a module can prefer a healthy upstream (C-52).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[non_exhaustive]
pub enum CircuitState {
    /// Accepting requests.
    Closed,
    /// Refusing requests until a cooldown ends.
    Open,
    /// Letting one probe through.
    Probing,
}

/// One candidate route `route.decide` offers: already permitted by policy and pinned to the
/// Session's account (I-16).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub struct Candidate {
    /// Its position in the offer.
    pub id: CandidateId,
    /// Its upstream's breaker.
    pub circuit: CircuitState,
}

impl Candidate {
    /// A candidate.
    #[must_use]
    pub const fn new(id: CandidateId, circuit: CircuitState) -> Self {
        Self { id, circuit }
    }
}

/// What one hook call sees. Built by the host; every field is a borrow that ends with the call.
#[derive(Debug, Clone, Copy)]
pub struct HookCx<'c> {
    point: HookPoint,
    op: OpMeta,
    view: Option<StructuralView<'c, 'c>>,
    frame: Option<SseEvent<'c>>,
    candidates: &'c [Candidate],
    grants: &'c [GrantRef],
}

impl<'c> HookCx<'c> {
    /// A context for `point` on `op`, with nothing else visible.
    #[must_use]
    pub const fn new(point: HookPoint, op: OpMeta) -> Self {
        Self {
            point,
            op,
            view: None,
            frame: None,
            candidates: &[],
            grants: &[],
        }
    }

    /// Shows the redacted structural view.
    #[must_use]
    pub const fn with_view(mut self, view: StructuralView<'c, 'c>) -> Self {
        self.view = Some(view);
        self
    }

    /// Shows one stream frame.
    #[must_use]
    pub const fn with_frame(mut self, frame: SseEvent<'c>) -> Self {
        self.frame = Some(frame);
        self
    }

    /// Offers route candidates.
    #[must_use]
    pub const fn with_candidates(mut self, candidates: &'c [Candidate]) -> Self {
        self.candidates = candidates;
        self
    }

    /// Hands over the live grants the manifest declared for this pocket.
    #[must_use]
    pub const fn with_grants(mut self, grants: &'c [GrantRef]) -> Self {
        self.grants = grants;
        self
    }

    /// The point.
    #[must_use]
    pub const fn point(&self) -> HookPoint {
        self.point
    }

    /// The Operation's metadata.
    #[must_use]
    pub const fn op(&self) -> &OpMeta {
        &self.op
    }

    /// The redacted view, at points that show one.
    #[must_use]
    pub const fn view(&self) -> Option<&StructuralView<'c, 'c>> {
        self.view.as_ref()
    }

    /// The frame, at stream points.
    #[must_use]
    pub const fn frame(&self) -> Option<&SseEvent<'c>> {
        self.frame.as_ref()
    }

    /// The candidates, at `route.decide`.
    #[must_use]
    pub const fn candidates(&self) -> &[Candidate] {
        self.candidates
    }

    /// The grants it may carry into child Operations.
    #[must_use]
    pub const fn grants(&self) -> &[GrantRef] {
        self.grants
    }
}

/// One journaled event of a pocket, delivered in journal order (contract §5). Built by the host;
/// `#[non_exhaustive]`, so what replay needs (a module event's values, a child outcome's
/// correlation tag) is added without a break when the host defines it (PR-8).
#[derive(Debug, Clone, Copy)]
#[non_exhaustive]
pub struct EventView<'e> {
    /// Its pocket.
    pub pocket: PocketId,
    /// Its sequence number.
    pub seq: Seq,
    /// Its type.
    pub event_type: &'e EventType,
    /// The Operation it belongs to, if any.
    pub operation: Option<OperationId>,
}

impl<'e> EventView<'e> {
    /// An event of `pocket` at `seq`.
    #[must_use]
    pub const fn new(pocket: PocketId, seq: Seq, event_type: &'e EventType, operation: Option<OperationId>) -> Self {
        Self {
            pocket,
            seq,
            event_type,
            operation,
        }
    }
}

/// A module (`uaos.module/1`): trusted code with minimized authority. It describes; the kernel
/// acts.
pub trait Module: Send + Sync + 'static {
    /// Its manifest.
    fn manifest(&self) -> &Manifest;

    /// Called at each point it hooked, within the point's deadline. Pure and bounded: it reads the
    /// context, may change its state for the Operation's pocket, and declares.
    fn on_hook(&self, cx: &HookCx<'_>, state: StateMut<'_>, out: &mut Decls);

    /// Called, off the hot path, for each journaled event of a pocket it touches, in journal
    /// order. The default declares nothing.
    fn on_event(&self, event: &EventView<'_>, state: StateMut<'_>, out: &mut Decls) {
        let _ = (event, state, out);
    }
}
