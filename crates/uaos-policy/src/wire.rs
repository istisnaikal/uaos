// SPDX-License-Identifier: Apache-2.0

//! `uaos.grant/1` and the engine's [`Grant`] (ADR-0008 appendix §3). A grant journaled when it is
//! issued reloads into the engine at boot exactly. The engine holds no approval, issue time or
//! injection policy, so building a record takes them from the caller.

use uaos_contracts::credential::ActionName;
use uaos_contracts::grant::{
    DataClass, GrantError, GrantName, GrantPrincipal, GrantRecord, GrantResource, InjectionPolicy, PolicyId,
};
use uaos_contracts::id::ApprovalId;
use uaos_contracts::time::WallTime;

use crate::model::{Action, Grant, Name, Principal, Resource};

/// A grant that does not convert between the wire and the engine.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum WireError {
    /// An action the engine does not know.
    #[error("the action `{0}` is not one the engine knows")]
    UnknownAction(String),
    /// A name that does not fit the engine's grammar, or a policy identifier the wire refuses.
    #[error("a name or policy identifier does not fit both grammars")]
    Name,
    /// An expiry outside the wire's time range.
    #[error("the expiry is outside the wire's time range")]
    Expiry,
    /// A record that fails `uaos.grant/1`'s own validation.
    #[error(transparent)]
    Invalid(#[from] GrantError),
}

fn engine_name(name: &str) -> Result<Name, WireError> {
    Name::new(name).map_err(|_| WireError::Name)
}

fn wire_name(name: &Name) -> Result<GrantName, WireError> {
    GrantName::new(name.as_str()).map_err(|_| WireError::Name)
}

impl TryFrom<&GrantRecord> for Grant {
    type Error = WireError;

    /// Reloads a journaled grant. An expiry finer than a millisecond floors, so the reloaded
    /// grant ends early, never late.
    fn try_from(record: &GrantRecord) -> Result<Self, WireError> {
        record.validate()?;
        let action = Action::ALL
            .into_iter()
            .find(|a| a.cedar_id() == record.action.as_str())
            .ok_or_else(|| WireError::UnknownAction(record.action.as_str().to_owned()))?;
        let principal = match &record.principal {
            GrantPrincipal::Agent { credential } => Principal::Agent(*credential),
            GrantPrincipal::Module { name } => Principal::Module(name.clone()),
            GrantPrincipal::Human => Principal::Human,
            GrantPrincipal::System => Principal::System,
        };
        let resource = match &record.resource {
            GrantResource::Model { provider, name } => Resource::Model {
                provider: engine_name(provider.as_str())?,
                model: engine_name(name.as_str())?,
            },
            GrantResource::Tool { name } => Resource::Tool(engine_name(name.as_str())?),
            GrantResource::Pool { id } => Resource::Pool(*id),
            GrantResource::ConfigKey { name } => Resource::ConfigKey(engine_name(name.as_str())?),
            GrantResource::Pocket { id } => Resource::Pocket(*id),
        };
        Ok(Self {
            id: record.id,
            principal,
            action,
            resource,
            pocket: record.pocket,
            expires_at_ms: record.expires_at.unix_millis_saturating(),
            max_risk_tier: record.max_risk_tier,
            data_classes: record
                .data_classes
                .iter()
                .map(|c| engine_name(c.as_str()))
                .collect::<Result<_, _>>()?,
            approves: record.approves.iter().map(|id| id.as_str().to_owned()).collect(),
        })
    }
}

/// The record that journals `grant`, issued through `approval` at `issued_at`, with `injection`
/// for a `memory.read` grant on a pocket.
///
/// # Errors
/// [`WireError`] if a field does not fit the wire, or the record fails its own validation (for
/// example an expiry at or before `issued_at`, or an injection policy on any other grant).
pub fn grant_record(
    grant: &Grant,
    approval: ApprovalId,
    issued_at: WallTime,
    injection: Option<InjectionPolicy>,
) -> Result<GrantRecord, WireError> {
    let principal = match &grant.principal {
        Principal::Agent(credential) => GrantPrincipal::Agent {
            credential: *credential,
        },
        Principal::Module(name) => GrantPrincipal::Module { name: name.clone() },
        Principal::Human => GrantPrincipal::Human,
        Principal::System => GrantPrincipal::System,
    };
    let resource = match &grant.resource {
        Resource::Model { provider, model } => GrantResource::Model {
            provider: wire_name(provider)?,
            name: wire_name(model)?,
        },
        Resource::Tool(name) => GrantResource::Tool { name: wire_name(name)? },
        Resource::Pool(id) => GrantResource::Pool { id: *id },
        Resource::ConfigKey(name) => GrantResource::ConfigKey { name: wire_name(name)? },
        Resource::Pocket(id) => GrantResource::Pocket { id: *id },
    };
    let expires_at = i128::from(grant.expires_at_ms)
        .checked_mul(1_000_000)
        .and_then(|nanos| WallTime::from_unix_nanos(nanos).ok())
        .ok_or(WireError::Expiry)?;
    let record = GrantRecord {
        id: grant.id,
        principal,
        action: ActionName::new(grant.action.cedar_id())
            .map_err(|_| WireError::UnknownAction(grant.action.cedar_id().to_owned()))?,
        resource,
        pocket: grant.pocket,
        approval,
        issued_at,
        expires_at,
        max_risk_tier: grant.max_risk_tier,
        data_classes: grant
            .data_classes
            .iter()
            .map(|c| DataClass::new(c.as_str()).map_err(|_| WireError::Name))
            .collect::<Result<_, _>>()?,
        approves: grant
            .approves
            .iter()
            .map(|id| PolicyId::new(id.as_str()).map_err(|_| WireError::Name))
            .collect::<Result<_, _>>()?,
        injection,
    };
    record.validate()?;
    Ok(record)
}
