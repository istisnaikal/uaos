// SPDX-License-Identifier: Apache-2.0

//! The identity writer: turns credential operations into recorded entries (ADR-0011).
//!
//! As in the ledger, every entry is recorded through an [`IdentitySink`] (normally the journal,
//! as a critical record) **before** the in-memory state changes. A failed recording poisons the
//! writer until it is rebuilt from the journal: the entry may or may not have been recorded, and
//! guessing would let memory and truth diverge.
//!
//! Revocations and epoch bumps advance a counter in the OS keychain *before* they are journaled
//! (the restore guard, ADR-0011 §7). A crash between the two leaves the keychain ahead of the
//! journal, which is the safe direction: verification fails closed until
//! [`Identity::recover_after_restore`] runs.

use std::fmt;
use std::sync::Arc;

use uaos_contracts::credential::{
    CredentialEntry, CredentialKind, CredentialOp, CredentialRecord, CredentialSchema, Label, Scope,
};
use uaos_contracts::digest::CredentialDigest;
use uaos_contracts::id::CredentialId;
use uaos_contracts::limits;
use uaos_contracts::time::WallTime;
use uaos_contracts::wire::{Epoch, RevocationSeq};
use uaos_platform::Rng;
use uaos_platform::crypto::{SecretKey, hmac_sha256};
use uaos_platform::keychain::Keychain;
use zeroize::Zeroizing;

use crate::secret::Secret;
use crate::state::{IdentityError, IdentityState, Verified};

/// Where identity entries are recorded durably.
pub trait IdentitySink {
    /// Records one entry; returns only once it is durable to the sink's standard.
    ///
    /// # Errors
    /// A description of the failure; the entry may or may not have been recorded.
    fn record(&mut self, entry: &CredentialEntry) -> Result<(), String>;
}

/// An in-memory sink for tests and simulation.
#[derive(Debug, Default)]
pub struct MemorySink {
    /// Entries in recording order.
    pub entries: Vec<CredentialEntry>,
    /// When set, the next `record` fails with this message.
    pub fail_next: Option<String>,
}

impl IdentitySink for MemorySink {
    fn record(&mut self, entry: &CredentialEntry) -> Result<(), String> {
        if let Some(message) = self.fail_next.take() {
            return Err(message);
        }
        self.entries.push(entry.clone());
        Ok(())
    }
}

/// The keychain-held material: the identity key that digests secrets, and the restore-guard
/// counter.
pub struct IdentityKeys {
    hmac: SecretKey,
    keychain: Arc<dyn Keychain>,
    guard_account: String,
    guard: RevocationSeq,
}

impl fmt::Debug for IdentityKeys {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("IdentityKeys")
            .field("keychain", &self.keychain.backend())
            .field("guard", &self.guard)
            .finish_non_exhaustive()
    }
}

const KEY_LEN: usize = 32;
const GUARD_LEN: usize = 8;

fn keys_error(e: impl fmt::Display) -> IdentityError {
    IdentityError::KeysUnavailable(e.to_string())
}

impl IdentityKeys {
    /// Loads the identity key and the restore-guard counter, creating the key on first use.
    ///
    /// # Errors
    /// [`IdentityError::KeysUnavailable`] if the keychain fails or holds malformed entries.
    pub fn open(keychain: Arc<dyn Keychain>, rng: &dyn Rng, installation: &str) -> Result<Self, IdentityError> {
        let key_account = format!("{installation}/identity/hmac");
        let guard_account = format!("{installation}/identity/revocation-seq");
        let hmac = if let Some(bytes) = keychain.get(&key_account).map_err(keys_error)? {
            let array: [u8; KEY_LEN] = bytes
                .as_slice()
                .try_into()
                .map_err(|_| keys_error("identity key has the wrong length"))?;
            SecretKey::from_bytes(array)
        } else {
            let fresh = SecretKey::generate(rng).map_err(keys_error)?;
            keychain.set(&key_account, fresh.expose_secret()).map_err(keys_error)?;
            fresh
        };
        let guard = match keychain.get(&guard_account).map_err(keys_error)? {
            None => RevocationSeq(0),
            Some(bytes) => {
                let array: [u8; GUARD_LEN] = bytes
                    .as_slice()
                    .try_into()
                    .map_err(|_| keys_error("revocation counter has the wrong length"))?;
                RevocationSeq(u64::from_be_bytes(array))
            }
        };
        Ok(Self {
            hmac,
            keychain,
            guard_account,
            guard,
        })
    }

    /// The revocation count held in the keychain.
    #[must_use]
    pub fn guard(&self) -> RevocationSeq {
        self.guard
    }

    fn digest(&self, secret: &Secret) -> CredentialDigest {
        CredentialDigest::from_bytes(hmac_sha256(&self.hmac, secret.as_bytes()))
    }

    fn advance_guard(&mut self, to: RevocationSeq) -> Result<(), IdentityError> {
        self.keychain
            .set(&self.guard_account, &to.0.to_be_bytes())
            .map_err(keys_error)?;
        self.guard = to;
        Ok(())
    }
}

/// What to issue.
#[derive(Debug, Clone)]
pub struct IssueRequest {
    /// Identifier for the new credential (from the caller's identifier source).
    pub id: CredentialId,
    /// The issuing credential; `None` issues a master.
    pub parent: Option<CredentialId>,
    /// Optional human-readable label.
    pub label: Option<Label>,
    /// Requested scope; must be within the parent's.
    pub scope: Scope,
}

/// A freshly issued credential. The text is shown to its holder once and never again.
pub struct Issued {
    /// The text form to hand over.
    pub text: Zeroizing<String>,
    /// The record as journaled.
    pub record: CredentialRecord,
}

impl fmt::Debug for Issued {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Issued")
            .field("record", &self.record)
            .finish_non_exhaustive()
    }
}

/// The identity: replayed state plus the rules for producing entries.
#[derive(Debug, Default)]
pub struct Identity {
    state: IdentityState,
    poisoned: bool,
}

impl Identity {
    /// Rebuilds the identity from its journaled entries, in order.
    ///
    /// # Errors
    /// [`IdentityError::Invalid`] if an entry does not apply (a corrupt or reordered journal).
    pub fn replay(entries: &[CredentialEntry]) -> Result<Self, IdentityError> {
        let mut state = IdentityState::default();
        for entry in entries {
            state.apply(entry)?;
        }
        Ok(Self { state, poisoned: false })
    }

    /// The replayed state.
    #[must_use]
    pub fn state(&self) -> &IdentityState {
        &self.state
    }

    /// Whether a recording failure stopped this writer.
    #[must_use]
    pub fn is_poisoned(&self) -> bool {
        self.poisoned
    }

    fn ensure_usable(&self) -> Result<(), IdentityError> {
        if self.poisoned {
            Err(IdentityError::Unavailable(
                "an identity recording failed; rebuild from the journal".to_owned(),
            ))
        } else {
            Ok(())
        }
    }

    /// Records `entry` and applies it. The state is checked first, so a refused entry is never
    /// recorded; a recording failure poisons the writer.
    fn commit(&mut self, sink: &mut dyn IdentitySink, entry: &CredentialEntry) -> Result<(), IdentityError> {
        self.state.check(entry)?;
        let size = serde_json::to_vec(entry)
            .map_err(|e| IdentityError::Invalid(e.to_string()))?
            .len();
        if !limits::MAX_INLINE_PAYLOAD.admits(size) {
            return Err(IdentityError::RecordTooLarge);
        }
        if let Err(message) = sink.record(entry) {
            self.poisoned = true;
            return Err(IdentityError::Unavailable(message));
        }
        self.state.apply(entry)
    }

    /// Issues a credential under `request.parent` (or a master) at `now`.
    ///
    /// # Errors
    /// [`IdentityError`] if the request breaks a rule (scope, depth, revoked or unknown parent,
    /// size), randomness fails, or recording fails.
    pub fn issue(
        &mut self,
        sink: &mut dyn IdentitySink,
        keys: &IdentityKeys,
        rng: &dyn Rng,
        request: IssueRequest,
        now: WallTime,
    ) -> Result<Issued, IdentityError> {
        self.ensure_usable()?;
        let (kind, parent_epoch) = match request.parent {
            None => (CredentialKind::Master, Epoch(0)),
            Some(parent) => {
                let node = self.state.node(parent).ok_or(IdentityError::Unknown)?;
                let kind = if node.record.kind == CredentialKind::Master {
                    CredentialKind::Sub
                } else {
                    CredentialKind::Child
                };
                (kind, node.epoch)
            }
        };
        let secret = Secret::generate(rng).map_err(|e| IdentityError::Unavailable(e.to_string()))?;
        let record = CredentialRecord {
            id: request.id,
            kind,
            parent: request.parent,
            digest: keys.digest(&secret),
            label: request.label,
            scope: request.scope,
            issued_at: now,
            parent_epoch,
            epoch: Epoch(0),
        };
        let entry = CredentialEntry {
            schema: CredentialSchema::V1,
            op: CredentialOp::Issued {
                record: Box::new(record.clone()),
            },
        };
        self.commit(sink, &entry)?;
        Ok(Issued {
            text: secret.encode(),
            record,
        })
    }

    /// Verifies a presented credential at `now`.
    ///
    /// # Errors
    /// [`IdentityError`]: malformed, unknown, revoked, expired, scope escape, or a data
    /// directory older than the latest revocation.
    pub fn verify(&self, keys: &IdentityKeys, presented: &str, now: WallTime) -> Result<Verified, IdentityError> {
        self.ensure_usable()?;
        let secret = Secret::parse(presented).map_err(|_| IdentityError::Malformed)?;
        self.state.verify(&keys.digest(&secret), now, keys.guard())
    }

    fn next_seq(&self, keys: &IdentityKeys) -> RevocationSeq {
        RevocationSeq(self.state.revocation_seq().0.max(keys.guard().0).saturating_add(1))
    }

    /// Revokes one credential. Its descendants stop verifying with it.
    ///
    /// # Errors
    /// [`IdentityError`] if the credential is unknown or already revoked, the keychain fails, or
    /// recording fails.
    pub fn revoke(
        &mut self,
        sink: &mut dyn IdentitySink,
        keys: &mut IdentityKeys,
        credential: CredentialId,
    ) -> Result<(), IdentityError> {
        self.ensure_usable()?;
        let seq = self.next_seq(keys);
        let entry = CredentialEntry {
            schema: CredentialSchema::V1,
            op: CredentialOp::Revoked {
                credential,
                revocation_seq: seq,
            },
        };
        self.state.check(&entry)?;
        keys.advance_guard(seq)?;
        self.commit(sink, &entry)
    }

    /// Bumps a credential's epoch: every descendant issued under the previous epoch stops
    /// verifying, while the credential itself stays valid.
    ///
    /// # Errors
    /// As [`Identity::revoke`].
    pub fn bump_epoch(
        &mut self,
        sink: &mut dyn IdentitySink,
        keys: &mut IdentityKeys,
        credential: CredentialId,
    ) -> Result<Epoch, IdentityError> {
        self.ensure_usable()?;
        let node = self.state.node(credential).ok_or(IdentityError::Unknown)?;
        let epoch = Epoch(node.epoch.0.saturating_add(1));
        let seq = self.next_seq(keys);
        let entry = CredentialEntry {
            schema: CredentialSchema::V1,
            op: CredentialOp::EpochBumped {
                credential,
                epoch,
                revocation_seq: seq,
            },
        };
        self.state.check(&entry)?;
        keys.advance_guard(seq)?;
        self.commit(sink, &entry)?;
        Ok(epoch)
    }

    /// After a data directory older than the latest revocation was detected: revokes every
    /// master that is still live, catching the journal up with the keychain. Every credential
    /// then fails to verify until the maintainer issues a new master and new keys (ADR-0011 §7).
    /// Returns the number of masters revoked.
    ///
    /// # Errors
    /// As [`Identity::revoke`].
    pub fn recover_after_restore(
        &mut self,
        sink: &mut dyn IdentitySink,
        keys: &mut IdentityKeys,
    ) -> Result<usize, IdentityError> {
        self.ensure_usable()?;
        let masters: Vec<CredentialId> = self
            .state
            .nodes()
            .filter(|n| n.record.kind == CredentialKind::Master && !n.revoked)
            .map(|n| n.record.id)
            .collect();
        for &master in &masters {
            self.revoke(sink, keys, master)?;
        }
        let seq = self.next_seq(keys);
        let entry = CredentialEntry {
            schema: CredentialSchema::V1,
            op: CredentialOp::RestoreRecovered { revocation_seq: seq },
        };
        self.state.check(&entry)?;
        keys.advance_guard(seq)?;
        self.commit(sink, &entry)?;
        Ok(masters.len())
    }
}
