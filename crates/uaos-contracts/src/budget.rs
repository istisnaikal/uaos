// SPDX-License-Identifier: Apache-2.0

//! Budget ledger entries, `uaos.budget_tx/1` (plan §2.7, D12).
//!
//! The ledger tracks one balance per pool: **available** money. Every entry records the
//! balance before and after, so the ledger can be audited entry by entry without replaying
//! anything else, and a single [`BudgetTx::validate`] call checks conservation.
//!
//! | kind          | effect on available | notes                                              |
//! |---------------|---------------------|----------------------------------------------------|
//! | `allocate`    | `+ amount`          | money entering the pool                            |
//! | `refund`      | `+ amount`          | provider credit / correction in the user's favour  |
//! | `transfer_in` | `+ amount`          | paired with a `transfer_out` in another pool       |
//! | `release`     | `+ amount`          | unused part of a reservation returned              |
//! | `reserve`     | `- amount`          | hold taken before an Operation executes            |
//! | `transfer_out`| `- amount`          |                                                    |
//! | `settle`      | `0`                 | records actual spend against a reservation         |
//! | `adjust`      | `± amount`          | the only kind allowed a negative amount; S1-audited|
//!
//! **Draft until RC-1:** this contract freezes with the journal format at Kernel RC-1
//! (ADR-0003). Until then a breaking change requires a major bump through the schema gate
//! like any other.

use std::borrow::Cow;

use schemars::{JsonSchema, Schema, SchemaGenerator, json_schema};
use serde::{Deserialize, Deserializer, Serialize, Serializer};

use crate::event::Actor;
use crate::id::{EventId, PoolId, ReservationId, SessionId};
use crate::limits;
use crate::money::NanoUsd;

/// Error returned when a ledger entry is internally inconsistent.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum BudgetTxError {
    /// The amount is negative for a kind that only accepts non-negative amounts.
    #[error("amount must be non-negative for {0:?}")]
    NegativeAmount(BudgetTxKind),
    /// `balance_after` does not equal `balance_before` plus the kind's effect.
    #[error("balance_after does not match balance_before plus the entry's effect")]
    Conservation,
    /// A reservation-related entry has no reservation identifier.
    #[error("{0:?} entries must reference a reservation")]
    MissingReservation(BudgetTxKind),
    /// An idempotency key or reason code is malformed.
    #[error("idempotency keys are 1..=128 bytes of [A-Za-z0-9_.:-]; reason codes 1..=64 bytes of [a-z0-9_]")]
    MalformedToken,
}

/// The kind of ledger entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum BudgetTxKind {
    /// Money entering the pool.
    Allocate,
    /// Hold taken before an Operation executes.
    Reserve,
    /// Actual spend recorded against a reservation.
    Settle,
    /// Unused part of a reservation returned to the pool.
    Release,
    /// Correction in the user's favour.
    Refund,
    /// Money leaving to another pool.
    TransferOut,
    /// Money arriving from another pool.
    TransferIn,
    /// Signed manual correction; always audited.
    Adjust,
}

impl BudgetTxKind {
    const fn requires_reservation(self) -> bool {
        matches!(self, Self::Reserve | Self::Settle | Self::Release)
    }
}

/// Client- or module-supplied key that makes a ledger write retry-safe.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct IdempotencyKey(String);

impl IdempotencyKey {
    /// Validates and wraps a key.
    ///
    /// # Errors
    /// Returns [`BudgetTxError::MalformedToken`] if the key is empty, too long, or contains
    /// characters outside `[A-Za-z0-9_.:-]`.
    pub fn new(key: impl Into<String>) -> Result<Self, BudgetTxError> {
        let key = key.into();
        let ok = !key.is_empty()
            && limits::MAX_IDEMPOTENCY_KEY.admits(key.len())
            && key
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'.' | b':' | b'-'));
        if ok {
            Ok(Self(key))
        } else {
            Err(BudgetTxError::MalformedToken)
        }
    }

    /// Returns the key.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Machine-readable reason such as `hard_cap_reached`.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ReasonCode(String);

impl ReasonCode {
    /// Validates and wraps a reason code.
    ///
    /// # Errors
    /// Returns [`BudgetTxError::MalformedToken`] if the code is not 1..=64 bytes of `[a-z0-9_]`.
    pub fn new(code: impl Into<String>) -> Result<Self, BudgetTxError> {
        let code = code.into();
        let ok = !code.is_empty()
            && limits::MAX_REASON_CODE.admits(code.len())
            && code
                .bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_');
        if ok {
            Ok(Self(code))
        } else {
            Err(BudgetTxError::MalformedToken)
        }
    }

    /// Returns the code.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

macro_rules! string_token_serde {
    ($name:ident, $pattern:literal) => {
        impl Serialize for $name {
            fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
                serializer.serialize_str(&self.0)
            }
        }
        impl<'de> Deserialize<'de> for $name {
            fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
                Self::new(String::deserialize(deserializer)?).map_err(serde::de::Error::custom)
            }
        }
        impl JsonSchema for $name {
            fn schema_name() -> Cow<'static, str> {
                stringify!($name).into()
            }
            fn json_schema(_: &mut SchemaGenerator) -> Schema {
                json_schema!({ "type": "string", "pattern": $pattern })
            }
        }
    };
}

string_token_serde!(IdempotencyKey, "^[A-Za-z0-9_.:-]{1,128}$");
string_token_serde!(ReasonCode, "^[a-z0-9_]{1,64}$");

/// Schema tag of the ledger entry contract.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
pub enum BudgetTxSchema {
    /// Version 1.
    #[serde(rename = "uaos.budget_tx/1")]
    V1,
}

/// One ledger entry, `uaos.budget_tx/1`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[schemars(
    title = "uaos.budget_tx/1",
    description = "One budget ledger entry with before/after balances."
)]
pub struct BudgetTx {
    /// Schema tag, always `uaos.budget_tx/1`.
    pub schema: BudgetTxSchema,
    /// Makes the write retry-safe: a replay returns the original entry.
    pub idempotency_key: IdempotencyKey,
    /// Pool whose available balance changes.
    pub pool_id: PoolId,
    /// Who caused the entry.
    pub principal: Actor,
    /// Session, if the entry belongs to one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub session_id: Option<SessionId>,
    /// Kind of entry.
    pub kind: BudgetTxKind,
    /// Amount (non-negative except for `adjust`).
    pub amount: NanoUsd,
    /// Available balance before the entry.
    pub balance_before: NanoUsd,
    /// Available balance after the entry.
    pub balance_after: NanoUsd,
    /// Why the entry exists.
    pub reason_code: ReasonCode,
    /// Journal event recording the entry.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub related_event: Option<EventId>,
    /// Reservation this entry belongs to (required for reserve/settle/release).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reservation_id: Option<ReservationId>,
    /// Whether the reservation this entry belongs to is fully settled.
    pub settled: bool,
    /// Whether the amount is an estimate (no provider-reported usage was available).
    pub estimated: bool,
}

impl BudgetTx {
    /// Signed effect of this entry on the available balance.
    ///
    /// # Errors
    /// Returns [`BudgetTxError::NegativeAmount`] for a negative amount on a kind that does
    /// not allow it, or [`BudgetTxError::Conservation`] on arithmetic overflow.
    pub fn effect(&self) -> Result<NanoUsd, BudgetTxError> {
        use BudgetTxKind as K;
        if self.kind != K::Adjust && self.amount.is_negative() {
            return Err(BudgetTxError::NegativeAmount(self.kind));
        }
        match self.kind {
            K::Allocate | K::Refund | K::TransferIn | K::Release | K::Adjust => Ok(self.amount),
            K::Reserve | K::TransferOut => self.amount.checked_neg().ok_or(BudgetTxError::Conservation),
            K::Settle => Ok(NanoUsd::ZERO),
        }
    }

    /// Checks the entry's internal invariants: amount sign, reservation reference, and
    /// conservation (`balance_after == balance_before + effect`).
    ///
    /// # Errors
    /// Returns the first violated invariant.
    pub fn validate(&self) -> Result<(), BudgetTxError> {
        if self.kind.requires_reservation() && self.reservation_id.is_none() {
            return Err(BudgetTxError::MissingReservation(self.kind));
        }
        let expected = self
            .balance_before
            .checked_add(self.effect()?)
            .ok_or(BudgetTxError::Conservation)?;
        if expected == self.balance_after {
            Ok(())
        } else {
            Err(BudgetTxError::Conservation)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::id::TypedId;
    use proptest::prelude::*;

    fn entry(kind: BudgetTxKind, amount: i64, before: i64, after: i64) -> BudgetTx {
        BudgetTx {
            schema: BudgetTxSchema::V1,
            idempotency_key: IdempotencyKey::new("op_1:reserve").unwrap(),
            pool_id: PoolId::from_parts(1, [1; 10]),
            principal: Actor::System,
            session_id: None,
            kind,
            amount: NanoUsd::new(amount),
            balance_before: NanoUsd::new(before),
            balance_after: NanoUsd::new(after),
            reason_code: ReasonCode::new("model_call").unwrap(),
            related_event: None,
            reservation_id: Some(ReservationId::from_parts(1, [2; 10])),
            settled: false,
            estimated: false,
        }
    }

    #[test]
    fn conservation_examples() {
        assert!(entry(BudgetTxKind::Reserve, 30, 100, 70).validate().is_ok());
        assert!(entry(BudgetTxKind::Settle, 25, 70, 70).validate().is_ok());
        assert!(entry(BudgetTxKind::Release, 5, 70, 75).validate().is_ok());
        assert_eq!(
            entry(BudgetTxKind::Reserve, 30, 100, 80).validate(),
            Err(BudgetTxError::Conservation)
        );
        assert_eq!(
            entry(BudgetTxKind::Reserve, -30, 100, 130).validate(),
            Err(BudgetTxError::NegativeAmount(BudgetTxKind::Reserve))
        );
        let mut no_rsv = entry(BudgetTxKind::Settle, 1, 1, 1);
        no_rsv.reservation_id = None;
        assert_eq!(
            no_rsv.validate(),
            Err(BudgetTxError::MissingReservation(BudgetTxKind::Settle))
        );
    }

    #[test]
    fn tokens_reject_malformed_input() {
        assert!(IdempotencyKey::new("").is_err());
        assert!(IdempotencyKey::new("a b").is_err());
        assert!(IdempotencyKey::new("k".repeat(129)).is_err());
        assert!(ReasonCode::new("Hard_Cap").is_err());
    }

    proptest! {
        #[test]
        fn wire_round_trip_preserves_validity(amount in 0i64..1_000_000_000, before in 0i64..1_000_000_000) {
            let e = entry(BudgetTxKind::Reserve, amount, before, before - amount);
            prop_assert!(e.validate().is_ok());
            let back: BudgetTx = serde_json::from_str(&serde_json::to_string(&e).unwrap()).unwrap();
            prop_assert_eq!(back, e);
        }
    }
}
