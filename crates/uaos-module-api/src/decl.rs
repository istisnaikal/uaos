// SPDX-License-Identifier: Apache-2.0

//! Declarations (contract §4): what a module may ask the kernel to do. A module never performs an
//! effect; the kernel checks every declaration against the manifest and the point, then acts.

use std::fmt;

use uaos_contracts::id::{OperationId, PocketId};

use crate::code::Code;
use crate::grant_ref::GrantRef;
use crate::manifest::{ChildKind, HookMode, HookPoint, KernelFeature, Manifest};
use crate::selector::Selector;

/// The longest text a module may add, in bytes.
pub const MAX_MODULE_TEXT: usize = 8 * 1024;
/// The most values one module event may carry.
pub const MAX_EVENT_VALUES: usize = 8;

/// Text that does not fit [`ModuleText`].
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum TextError {
    /// Longer than [`MAX_MODULE_TEXT`].
    #[error("module text is at most {MAX_MODULE_TEXT} bytes")]
    TooLong,
    /// A control character other than a newline or a tab.
    #[error("module text holds a control character other than a newline or a tab")]
    Control,
    /// An explicit bidirectional embedding, override or isolate (ADR-0020 rule 5).
    #[error("module text holds an explicit bidirectional control (U+202A-U+202E, U+2066-U+2069)")]
    Bidi,
}

/// Whether `c` is an explicit bidirectional embedding, override or isolate: U+202A to U+202E and
/// U+2066 to U+2069. A model gains nothing from one, and a person reading the text can be misled
/// by one (Trojan Source). The implicit marks U+200E, U+200F and U+061C are not among them.
#[must_use]
pub const fn is_explicit_bidi(c: char) -> bool {
    matches!(c, '\u{202A}'..='\u{202E}' | '\u{2066}'..='\u{2069}')
}

/// Text a module adds to a request: bounded, in any language and kept byte for byte (ADR-0020
/// rule 2), without control characters but newlines and tabs and without explicit bidirectional
/// controls. Like every outbound byte, it is detected and final-scanned by the kernel (contract
/// §2 rule 4).
#[derive(Clone, PartialEq, Eq)]
pub struct ModuleText(String);

impl ModuleText {
    /// Checks and wraps `text`, unchanged: no normalization, no case folding.
    ///
    /// # Errors
    /// [`TextError`] if it is too long, holds a control character, or holds an explicit
    /// bidirectional control.
    pub fn new(text: impl Into<String>) -> Result<Self, TextError> {
        let text = text.into();
        if text.len() > MAX_MODULE_TEXT {
            return Err(TextError::TooLong);
        }
        if text.chars().any(|c| c.is_control() && c != '\n' && c != '\t') {
            return Err(TextError::Control);
        }
        if text.chars().any(is_explicit_bidi) {
            return Err(TextError::Bidi);
        }
        Ok(Self(text))
    }

    /// The text.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for ModuleText {
    // Its length only: the text is outbound content (I-11).
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ModuleText").field("len", &self.0.len()).finish()
    }
}

/// Where an appended text goes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[non_exhaustive]
pub enum AppendSlot {
    /// The end of the newest human turn: the only place injections land (ADR-0014).
    NewestHumanTurn,
}

/// A route candidate, as `route.decide` offers it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct CandidateId(u16);

impl CandidateId {
    /// The candidate at position `n` of the offer.
    #[must_use]
    pub const fn new(n: u16) -> Self {
        Self(n)
    }

    /// Its position.
    #[must_use]
    pub const fn get(self) -> u16 {
        self.0
    }
}

/// An event a module emits: a declared code and at most [`MAX_EVENT_VALUES`] bounded numbers.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ModuleEvent {
    code: Code,
    values: Vec<(Code, i64)>,
}

impl ModuleEvent {
    /// An event with no values.
    #[must_use]
    pub const fn new(code: Code) -> Self {
        Self {
            code,
            values: Vec::new(),
        }
    }

    /// Adds a named value.
    ///
    /// # Errors
    /// The event, unchanged, once it holds [`MAX_EVENT_VALUES`] values.
    pub fn value(mut self, name: Code, value: i64) -> Result<Self, Self> {
        if self.values.len() >= MAX_EVENT_VALUES {
            return Err(self);
        }
        self.values.push((name, value));
        Ok(self)
    }

    /// Its code.
    #[must_use]
    pub const fn code(&self) -> &Code {
        &self.code
    }

    /// Its values.
    #[must_use]
    pub fn values(&self) -> &[(Code, i64)] {
        &self.values
    }
}

/// What a child Operation carries.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum ChildBody {
    /// A prompt, for a model call or a token count.
    Prompt(ModuleText),
    /// A query of another pocket's memory.
    MemoryQuery {
        /// The pocket to read.
        source: PocketId,
        /// What to look for.
        query: ModuleText,
    },
    /// A configuration change to request (policy answers with an approval).
    ConfigChange {
        /// The key.
        key: Code,
        /// The new value, as text.
        value: ModuleText,
    },
    /// A tool call.
    ToolCall {
        /// The tool.
        tool: Code,
        /// Its input.
        input: ModuleText,
    },
}

impl ChildBody {
    const fn fits(&self, kind: ChildKind) -> bool {
        matches!(
            (kind, self),
            (ChildKind::ModelCall | ChildKind::CountTokens, Self::Prompt(_))
                | (ChildKind::MemoryRead, Self::MemoryQuery { .. })
                | (ChildKind::ConfigChange, Self::ConfigChange { .. })
                | (ChildKind::ToolCall, Self::ToolCall { .. })
        )
    }
}

/// A request for one child Operation (contract §6).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChildOpRequest {
    kind: ChildKind,
    body: ChildBody,
    grant: Option<GrantRef>,
    correlate: Code,
}

impl ChildOpRequest {
    /// A request of `kind` carrying `body`, tagged `correlate` so the outcome can be matched.
    ///
    /// # Errors
    /// The body back if it does not fit the kind.
    pub fn new(kind: ChildKind, body: ChildBody, correlate: Code) -> Result<Self, ChildBody> {
        if !body.fits(kind) {
            return Err(body);
        }
        Ok(Self {
            kind,
            body,
            grant: None,
            correlate,
        })
    }

    /// Carries a grant.
    #[must_use]
    pub const fn with_grant(mut self, grant: GrantRef) -> Self {
        self.grant = Some(grant);
        self
    }

    /// Its kind.
    #[must_use]
    pub const fn kind(&self) -> ChildKind {
        self.kind
    }

    /// Its body.
    #[must_use]
    pub const fn body(&self) -> &ChildBody {
        &self.body
    }

    /// The grant it carries, if any.
    #[must_use]
    pub const fn grant(&self) -> Option<GrantRef> {
        self.grant
    }

    /// Its correlation code.
    #[must_use]
    pub const fn correlate(&self) -> &Code {
        &self.correlate
    }
}

/// One thing a module asks the kernel to do (contract §4).
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum Decl {
    /// Removes what the selector selects, outside every forbidden role.
    Strip(Selector),
    /// Appends text.
    Append {
        /// Where.
        slot: AppendSlot,
        /// What.
        text: ModuleText,
    },
    /// Denies the Operation.
    Veto(Code),
    /// Cancels the stream from the next frame.
    Cancel(Code),
    /// Adds a label; risk only rises.
    Label(Code),
    /// Ranks, or narrows, the route candidates offered.
    Rank(Vec<CandidateId>),
    /// Emits an event.
    Emit(ModuleEvent),
    /// Requests a child Operation.
    Request(ChildOpRequest),
    /// Cancels one of the module's own child Operations.
    CancelOp(OperationId),
    /// Persists the module's state for this pocket.
    Checkpoint,
}

impl Decl {
    /// Whether this declaration is allowed at `point` (contract §4), or from `on_event` when
    /// `point` is `None`.
    #[must_use]
    pub const fn allowed_at(&self, point: Option<HookPoint>) -> bool {
        use HookPoint as P;
        matches!(
            (self, point),
            (Self::Emit(_) | Self::Request(_) | Self::CancelOp(_), _)
                | (Self::Checkpoint, None | Some(P::ContextAssemble | P::ResponsePost))
                | (Self::Strip(_), Some(P::IngressParsed | P::ToolResult))
                | (Self::Append { .. }, Some(P::IngressParsed | P::ContextAssemble))
                | (Self::Veto(_), Some(P::ToolResult))
                | (Self::Cancel(_), Some(P::StreamAssert))
                | (Self::Label(_), Some(P::Classify))
                | (Self::Rank(_), Some(P::RouteDecide))
        )
    }

    /// Whether an observe-mode hook may return it.
    #[must_use]
    pub const fn observes(&self) -> bool {
        matches!(
            self,
            Self::Emit(_) | Self::Request(_) | Self::CancelOp(_) | Self::Checkpoint
        )
    }
}

/// Why one hook call's declarations are refused; the module gets a strike and none of them apply.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum Strike {
    /// More declarations than the manifest's `max_decls`.
    #[error("more declarations than the manifest allows")]
    TooMany,
    /// A declaration the point, or the hook's mode, does not allow.
    #[error("a declaration this point or mode does not allow")]
    NotAllowedHere,
    /// A reason, label or event code the manifest does not declare.
    #[error("a code the manifest does not declare")]
    UndeclaredCode,
    /// A child Operation of a kind the manifest does not declare.
    #[error("a child Operation the manifest does not declare")]
    UndeclaredAction,
    /// A declaration that needs a feature the manifest does not require.
    #[error("a declaration that needs `{}`, which the manifest does not require", .0.code())]
    FeatureNotRequired(KernelFeature),
}

impl Strike {
    /// A stable label for the kernel's explanation.
    #[must_use]
    pub const fn code(&self) -> &'static str {
        match self {
            Self::TooMany => "too_many",
            Self::NotAllowedHere => "not_allowed_here",
            Self::UndeclaredCode => "undeclared_code",
            Self::UndeclaredAction => "undeclared_action",
            Self::FeatureNotRequired(_) => "feature_not_required",
        }
    }
}

/// Checks one call's declarations against the manifest and the point (`None` for `on_event`).
/// All or nothing: the first refusal refuses the whole call.
///
/// # Errors
/// The [`Strike`].
pub fn check_decls(manifest: &Manifest, point: Option<HookPoint>, decls: &[Decl]) -> Result<(), Strike> {
    if decls.len() > usize::from(manifest.max_decls()) {
        return Err(Strike::TooMany);
    }
    let observing = point
        .and_then(|p| manifest.hook(p))
        .is_none_or(|hook| hook.mode() == HookMode::Observe);
    for decl in decls {
        if !decl.allowed_at(point) || (observing && !decl.observes()) {
            return Err(Strike::NotAllowedHere);
        }
        match decl {
            Decl::Veto(code) | Decl::Cancel(code) if !manifest.declares_reason(code) => {
                return Err(Strike::UndeclaredCode);
            }
            Decl::Label(code) if !manifest.declares_label(code) => return Err(Strike::UndeclaredCode),
            Decl::Emit(event) if manifest.event_class(event.code()).is_none() => {
                return Err(Strike::UndeclaredCode);
            }
            Decl::Request(request) => {
                if !manifest.actions().contains(&request.kind()) {
                    return Err(Strike::UndeclaredAction);
                }
                if let Some(feature) = request
                    .kind()
                    .required_features()
                    .into_iter()
                    .find(|f| !manifest.requires().contains(f))
                {
                    return Err(Strike::FeatureNotRequired(feature));
                }
            }
            Decl::Checkpoint if !manifest.requires().contains(&KernelFeature::StateCheckpoints) => {
                return Err(Strike::FeatureNotRequired(KernelFeature::StateCheckpoints));
            }
            _ => {}
        }
    }
    Ok(())
}

/// Collects one call's declarations, up to the manifest's bound.
#[derive(Clone, PartialEq, Eq)]
pub struct Decls {
    items: Vec<Decl>,
    max: u16,
}

/// A declaration past the call's bound.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("this call already holds its maximum of {max} declarations")]
pub struct DeclError {
    /// The bound.
    pub max: u16,
}

impl Decls {
    /// An empty collector for at most `max` declarations. The host builds it from the manifest.
    #[must_use]
    pub const fn new(max: u16) -> Self {
        Self { items: Vec::new(), max }
    }

    /// Adds a declaration.
    ///
    /// # Errors
    /// [`DeclError`] once the bound is reached; the collector is unchanged.
    pub fn push(&mut self, decl: Decl) -> Result<(), DeclError> {
        if self.items.len() >= usize::from(self.max) {
            return Err(DeclError { max: self.max });
        }
        self.items.push(decl);
        Ok(())
    }

    /// The declarations so far.
    #[must_use]
    pub fn as_slice(&self) -> &[Decl] {
        &self.items
    }

    /// Takes the declarations out.
    #[must_use]
    pub fn into_inner(self) -> Vec<Decl> {
        self.items
    }

    /// Whether there are none.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.items.is_empty()
    }
}

impl fmt::Debug for Decls {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Decls")
            .field("len", &self.items.len())
            .field("max", &self.max)
            .finish()
    }
}
