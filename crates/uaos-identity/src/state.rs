// SPDX-License-Identifier: Apache-2.0

//! The identity state: a pure replay of `uaos.credential/1` entries (ADR-0011).
//!
//! [`IdentityState::check`] decides whether an entry may be applied; [`IdentityState::apply`]
//! applies it. Verification walks a credential's ancestor chain and fails on the first
//! revoked, expired, epoch-stale or scope-escaping link. The walk is bounded by
//! [`limits::MAX_CREDENTIAL_DEPTH`].

use std::collections::BTreeMap;

use uaos_contracts::credential::{
    CredentialEntry, CredentialError, CredentialKind, CredentialOp, CredentialRecord, Scope,
};
use uaos_contracts::digest::CredentialDigest;
use uaos_contracts::error::{ErrorCode, codes};
use uaos_contracts::id::CredentialId;
use uaos_contracts::limits;
use uaos_contracts::time::WallTime;
use uaos_contracts::wire::{Epoch, RevocationSeq};

use crate::scope::scope_within;

/// Identity failure. Each variant maps to one registered error code.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum IdentityError {
    /// The presented text is not a well-formed credential.
    #[error("not a well-formed UAOS credential")]
    Malformed,
    /// No credential has this digest.
    #[error("unknown credential")]
    Unknown,
    /// The credential, or an ancestor, is revoked (directly or by an epoch bump).
    #[error("credential {0} is revoked")]
    Revoked(CredentialId),
    /// The credential, or an ancestor, has expired.
    #[error("credential {0} has expired")]
    Expired(CredentialId),
    /// A scope is not within its parent's.
    #[error("the scope of {0} exceeds its parent's")]
    ScopeExceedsParent(CredentialId),
    /// The chain would be, or is, longer than allowed.
    #[error("credential chain longer than {max}")]
    DepthExceeded {
        /// The bound.
        max: usize,
    },
    /// The data directory is older than the latest revocation (restore guard).
    #[error("the data directory predates revocation {keychain}; the journal has only {journal}")]
    StaleDataDirectory {
        /// Count in the OS keychain.
        keychain: RevocationSeq,
        /// Count in the journal.
        journal: RevocationSeq,
    },
    /// The serialized entry would not fit an inline journal payload.
    #[error("the credential record is too large for one journal entry")]
    RecordTooLarge,
    /// The OS keychain holding the identity key failed.
    #[error("identity keys unavailable: {0}")]
    KeysUnavailable(String),
    /// A recording failed; the identity refuses work until rebuilt from the journal.
    #[error("identity state unavailable: {0}")]
    Unavailable(String),
    /// An entry is inconsistent with the current state.
    #[error("invalid identity entry: {0}")]
    Invalid(String),
}

impl IdentityError {
    /// The registered error code.
    #[must_use]
    pub fn code(&self) -> ErrorCode {
        match self {
            Self::Malformed => codes::IDENTITY_MALFORMED,
            Self::Unknown => codes::IDENTITY_UNKNOWN,
            Self::Revoked(_) => codes::IDENTITY_REVOKED,
            Self::Expired(_) => codes::IDENTITY_EXPIRED,
            Self::ScopeExceedsParent(_) => codes::IDENTITY_SCOPE_EXCEEDS_PARENT,
            Self::DepthExceeded { .. } => codes::IDENTITY_DEPTH_EXCEEDED,
            Self::StaleDataDirectory { .. } => codes::IDENTITY_STALE_DATA_DIR,
            Self::RecordTooLarge => codes::IDENTITY_RECORD_TOO_LARGE,
            Self::KeysUnavailable(_) => codes::IDENTITY_KEYS_UNAVAILABLE,
            Self::Unavailable(_) | Self::Invalid(_) => codes::IDENTITY_UNAVAILABLE,
        }
    }
}

impl From<CredentialError> for IdentityError {
    fn from(e: CredentialError) -> Self {
        Self::Invalid(e.to_string())
    }
}

/// A credential and its live status.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Node {
    /// The record as issued.
    pub record: CredentialRecord,
    /// Revoked directly.
    pub revoked: bool,
    /// Current epoch; descendants issued under an older one no longer verify.
    pub epoch: Epoch,
}

/// A credential that verified, with the scope it may use.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Verified {
    /// The credential.
    pub credential: CredentialId,
    /// Its kind.
    pub kind: CredentialKind,
    /// Its scope: within every ancestor's, re-checked on this verification.
    pub scope: Scope,
    /// The chain from the credential up to its master.
    pub chain: Vec<CredentialId>,
}

/// The replayed identity state.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct IdentityState {
    nodes: BTreeMap<CredentialId, Node>,
    by_digest: BTreeMap<CredentialDigest, CredentialId>,
    revocation_seq: RevocationSeq,
}

impl IdentityState {
    /// The highest revocation count recorded in the journal.
    #[must_use]
    pub fn revocation_seq(&self) -> RevocationSeq {
        self.revocation_seq
    }

    /// A credential and its status.
    #[must_use]
    pub fn node(&self, id: CredentialId) -> Option<&Node> {
        self.nodes.get(&id)
    }

    /// All credentials, in identifier order.
    pub fn nodes(&self) -> impl Iterator<Item = &Node> {
        self.nodes.values()
    }

    /// Number of credentials in the chain ending at `id` (1 for a master).
    fn chain_len(&self, id: CredentialId) -> Result<usize, IdentityError> {
        let mut len = 0usize;
        let mut current = Some(id);
        while let Some(cur) = current {
            len += 1;
            if len > limits::MAX_CREDENTIAL_DEPTH {
                return Err(IdentityError::DepthExceeded {
                    max: limits::MAX_CREDENTIAL_DEPTH,
                });
            }
            current = self.nodes.get(&cur).ok_or(IdentityError::Unknown)?.record.parent;
        }
        Ok(len)
    }

    /// Whether `entry` may be applied to this state.
    ///
    /// # Errors
    /// [`IdentityError`] naming the first rule the entry breaks.
    pub fn check(&self, entry: &CredentialEntry) -> Result<(), IdentityError> {
        entry.validate()?;
        match &entry.op {
            CredentialOp::Issued { record } => self.check_issue(record),
            CredentialOp::Revoked {
                credential,
                revocation_seq,
            } => {
                let node = self.nodes.get(credential).ok_or(IdentityError::Unknown)?;
                if node.revoked {
                    return Err(IdentityError::Invalid(format!("{credential} is already revoked")));
                }
                self.check_seq(*revocation_seq)
            }
            CredentialOp::EpochBumped {
                credential,
                epoch,
                revocation_seq,
            } => {
                let node = self.nodes.get(credential).ok_or(IdentityError::Unknown)?;
                if epoch.0 != node.epoch.0.saturating_add(1) {
                    return Err(IdentityError::Invalid(format!(
                        "epoch of {credential} must advance by one (now {})",
                        node.epoch
                    )));
                }
                self.check_seq(*revocation_seq)
            }
            CredentialOp::RestoreRecovered { revocation_seq } => {
                if self
                    .nodes
                    .values()
                    .any(|n| n.record.kind == CredentialKind::Master && !n.revoked)
                {
                    return Err(IdentityError::Invalid(
                        "restore recovery requires every master to be revoked first".to_owned(),
                    ));
                }
                self.check_seq(*revocation_seq)
            }
        }
    }

    fn check_seq(&self, seq: RevocationSeq) -> Result<(), IdentityError> {
        // Strictly increasing; gaps are allowed so that recovery after a restore can catch the
        // journal up with the keychain (ADR-0011 §7).
        if seq > self.revocation_seq {
            Ok(())
        } else {
            Err(IdentityError::Invalid(format!(
                "revocation_seq {seq} must exceed {}",
                self.revocation_seq
            )))
        }
    }

    fn check_issue(&self, record: &CredentialRecord) -> Result<(), IdentityError> {
        if self.nodes.contains_key(&record.id) {
            return Err(IdentityError::Invalid(format!("{} already exists", record.id)));
        }
        if self.by_digest.contains_key(&record.digest) {
            return Err(IdentityError::Invalid("digest already in use".to_owned()));
        }
        if record.epoch != Epoch(0) {
            return Err(IdentityError::Invalid("a new credential starts at epoch 0".to_owned()));
        }
        let Some(parent_id) = record.parent else {
            return if record.parent_epoch == Epoch(0) {
                Ok(())
            } else {
                Err(IdentityError::Invalid("a master has no parent epoch".to_owned()))
            };
        };
        let parent = self.nodes.get(&parent_id).ok_or(IdentityError::Unknown)?;
        if parent.revoked {
            return Err(IdentityError::Revoked(parent_id));
        }
        if record.parent_epoch != parent.epoch {
            return Err(IdentityError::Invalid(format!(
                "parent_epoch {} does not match {parent_id}'s epoch {}",
                record.parent_epoch, parent.epoch
            )));
        }
        let expected_kind = if parent.record.kind == CredentialKind::Master {
            CredentialKind::Sub
        } else {
            CredentialKind::Child
        };
        if record.kind != expected_kind {
            return Err(IdentityError::Invalid(format!(
                "a credential issued by a {:?} is a {expected_kind:?}",
                parent.record.kind
            )));
        }
        if self.chain_len(parent_id)? >= limits::MAX_CREDENTIAL_DEPTH {
            return Err(IdentityError::DepthExceeded {
                max: limits::MAX_CREDENTIAL_DEPTH,
            });
        }
        if !scope_within(&record.scope, &parent.record.scope) {
            return Err(IdentityError::ScopeExceedsParent(record.id));
        }
        Ok(())
    }

    /// Checks and applies `entry`.
    ///
    /// # Errors
    /// As [`IdentityState::check`]; the state is unchanged on error.
    pub fn apply(&mut self, entry: &CredentialEntry) -> Result<(), IdentityError> {
        self.check(entry)?;
        match &entry.op {
            CredentialOp::Issued { record } => {
                self.by_digest.insert(record.digest, record.id);
                self.nodes.insert(
                    record.id,
                    Node {
                        record: record.as_ref().clone(),
                        revoked: false,
                        epoch: record.epoch,
                    },
                );
            }
            CredentialOp::Revoked {
                credential,
                revocation_seq,
            } => {
                if let Some(node) = self.nodes.get_mut(credential) {
                    node.revoked = true;
                }
                self.revocation_seq = *revocation_seq;
            }
            CredentialOp::EpochBumped {
                credential,
                epoch,
                revocation_seq,
            } => {
                if let Some(node) = self.nodes.get_mut(credential) {
                    node.epoch = *epoch;
                }
                self.revocation_seq = *revocation_seq;
            }
            CredentialOp::RestoreRecovered { revocation_seq } => {
                self.revocation_seq = *revocation_seq;
            }
        }
        Ok(())
    }

    /// Verifies the credential with `digest` at `now`, given the revocation count held in the
    /// OS keychain.
    ///
    /// # Errors
    /// The first failing rule, checked from the credential up to its master.
    pub fn verify(
        &self,
        digest: &CredentialDigest,
        now: WallTime,
        keychain_seq: RevocationSeq,
    ) -> Result<Verified, IdentityError> {
        if keychain_seq > self.revocation_seq {
            return Err(IdentityError::StaleDataDirectory {
                keychain: keychain_seq,
                journal: self.revocation_seq,
            });
        }
        let id = *self.by_digest.get(digest).ok_or(IdentityError::Unknown)?;
        let mut chain = Vec::new();
        let mut current = id;
        loop {
            if chain.len() >= limits::MAX_CREDENTIAL_DEPTH {
                return Err(IdentityError::DepthExceeded {
                    max: limits::MAX_CREDENTIAL_DEPTH,
                });
            }
            chain.push(current);
            let node = self.nodes.get(&current).ok_or(IdentityError::Unknown)?;
            if node.revoked {
                return Err(IdentityError::Revoked(current));
            }
            if node.record.scope.expires_at.is_some_and(|expiry| now >= expiry) {
                return Err(IdentityError::Expired(current));
            }
            let Some(parent_id) = node.record.parent else {
                break;
            };
            let parent = self.nodes.get(&parent_id).ok_or(IdentityError::Unknown)?;
            if node.record.parent_epoch != parent.epoch {
                return Err(IdentityError::Revoked(current));
            }
            if !scope_within(&node.record.scope, &parent.record.scope) {
                return Err(IdentityError::ScopeExceedsParent(current));
            }
            current = parent_id;
        }
        let node = self.nodes.get(&id).ok_or(IdentityError::Unknown)?;
        Ok(Verified {
            credential: id,
            kind: node.record.kind,
            scope: node.record.scope.clone(),
            chain,
        })
    }
}
