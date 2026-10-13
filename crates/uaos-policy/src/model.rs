// SPDX-License-Identifier: Apache-2.0

//! Typed requests, decisions and grants. Everything that becomes Cedar text or a Cedar entity
//! identifier is validated here first, so caller-supplied strings can never alter a policy.

use std::collections::BTreeSet;
use std::fmt;

use uaos_contracts::event::ModuleName;
use uaos_contracts::id::{CredentialId, GrantId, PocketId, PoolId};
use uaos_contracts::operation::{OperationKind, RiskTier};

/// Error for a name that cannot be used as a resource or data-class identifier.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("names are 1..=128 characters of [A-Za-z0-9._:/-]")]
pub struct NameError;

/// A resource or data-class name, restricted to characters that need no escaping anywhere.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Name(String);

/// Maximum length of a [`Name`].
const MAX_NAME: usize = 128;

impl Name {
    /// Validates and wraps a name.
    ///
    /// # Errors
    /// [`NameError`] if empty, too long, or containing other characters.
    pub fn new(value: impl Into<String>) -> Result<Self, NameError> {
        let value = value.into();
        let ok = !value.is_empty()
            && value.len() <= MAX_NAME
            && value
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b':' | b'/' | b'-'));
        if ok { Ok(Self(value)) } else { Err(NameError) }
    }

    /// The name.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for Name {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// Actions known to the authorization schema.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Action {
    /// A billable model call.
    ModelCall,
    /// A token-count call (non-billable, but carries the full prompt).
    CountTokens,
    /// A tool invocation.
    ToolCall,
    /// A process execution.
    Exec,
    /// A budget transfer between pools.
    BudgetTransfer,
    /// A configuration change.
    ConfigChange,
}

impl Action {
    /// Every action, in schema order.
    pub const ALL: [Self; 6] = [
        Self::ModelCall,
        Self::CountTokens,
        Self::ToolCall,
        Self::Exec,
        Self::BudgetTransfer,
        Self::ConfigChange,
    ];

    /// Cedar action identifier.
    #[must_use]
    pub const fn cedar_id(self) -> &'static str {
        match self {
            Self::ModelCall => "model.call",
            Self::CountTokens => "model.count_tokens",
            Self::ToolCall => "tool.call",
            Self::Exec => "exec",
            Self::BudgetTransfer => "budget.transfer",
            Self::ConfigChange => "config.change",
        }
    }

    /// The action that authorizes an Operation of `kind`.
    #[must_use]
    pub const fn for_operation(kind: OperationKind) -> Self {
        match kind {
            OperationKind::ModelCall => Self::ModelCall,
            OperationKind::CountTokens => Self::CountTokens,
            OperationKind::ToolCall => Self::ToolCall,
            OperationKind::Exec => Self::Exec,
            OperationKind::BudgetTransfer => Self::BudgetTransfer,
            OperationKind::ConfigChange => Self::ConfigChange,
        }
    }
}

/// Who is asking.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Principal {
    /// An agent authenticated with a UAOS credential.
    Agent(CredentialId),
    /// A human through a user-present channel.
    Human,
    /// A module.
    Module(ModuleName),
    /// The kernel itself.
    System,
}

/// What is being acted on.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Resource {
    /// A model of a provider.
    Model {
        /// Provider name, e.g. `anthropic`.
        provider: Name,
        /// Model name, e.g. `claude-sonnet-5-5`.
        model: Name,
    },
    /// A tool.
    Tool(Name),
    /// A budget pool.
    Pool(PoolId),
    /// A configuration key.
    ConfigKey(Name),
}

/// One authorization question.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Request {
    /// Who asks.
    pub principal: Principal,
    /// What they want to do.
    pub action: Action,
    /// On what.
    pub resource: Resource,
    /// In which pocket.
    pub pocket: PocketId,
    /// Risk tier of the Operation.
    pub risk_tier: RiskTier,
    /// Data classes detected in the content (e.g. `secret.aws`, `pii.email`).
    pub data_classes: BTreeSet<Name>,
    /// Evaluation time, Unix milliseconds, from the caller's clock.
    pub now_ms: u64,
}

/// Outcome, by precedence: `Deny` > `Ask` > `Allow`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Effect {
    /// Proceed.
    Allow,
    /// A human must approve first.
    Ask,
    /// Refused.
    Deny,
}

/// Why the decision came out as it did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Basis {
    /// At least one permit matched and nothing forbade or asked.
    Permitted,
    /// A matching permit requires approval.
    ApprovalRequired,
    /// A forbid matched.
    Forbidden,
    /// No permit matched: default deny.
    NoMatchingPermit,
    /// A policy failed to evaluate, or the request was malformed: fail closed.
    EvaluationError,
}

/// An explained decision.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Decision {
    /// The effect.
    pub effect: Effect,
    /// Why.
    pub basis: Basis,
    /// `@id`s of the policies that determined the decision (grant policies are `grant:<id>`).
    pub policies: Vec<String>,
    /// Evaluation errors, if any (they always force `Deny`).
    pub errors: Vec<String>,
}

impl Decision {
    pub(crate) fn deny_error(error: impl Into<String>) -> Self {
        Self {
            effect: Effect::Deny,
            basis: Basis::EvaluationError,
            policies: Vec::new(),
            errors: vec![error.into()],
        }
    }

    /// One-line explanation for `uaos policy explain`.
    #[must_use]
    pub fn explain(&self) -> String {
        let by = if self.policies.is_empty() {
            String::new()
        } else {
            format!(" by {}", self.policies.join(", "))
        };
        match self.basis {
            Basis::Permitted => format!("allowed{by}"),
            Basis::ApprovalRequired => format!("approval required{by}"),
            Basis::Forbidden => format!("denied{by}"),
            Basis::NoMatchingPermit => "denied: no policy permits this (default deny)".to_owned(),
            Basis::EvaluationError => format!(
                "denied: evaluation failed, so UAOS fails closed ({})",
                self.errors.join("; ")
            ),
        }
    }
}

/// A time-bounded capability: compiled into a Cedar permit that matches only this principal,
/// action, resource and pocket, and only before `expires_at_ms`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Grant {
    /// Identifier, shown in explanations as `grant:<id>`.
    pub id: GrantId,
    /// Who receives it.
    pub principal: Principal,
    /// What it allows.
    pub action: Action,
    /// On what.
    pub resource: Resource,
    /// Where.
    pub pocket: PocketId,
    /// Unix milliseconds after which it no longer applies.
    pub expires_at_ms: u64,
}
