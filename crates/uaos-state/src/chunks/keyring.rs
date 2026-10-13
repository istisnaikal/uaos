// SPDX-License-Identifier: Apache-2.0

//! Pocket key management interface.
//!
//! Each pocket has two kinds of key:
//! * a **content-addressing key** (stable): chunk references are `HMAC(cas_key, plaintext)`,
//!   so equal content in different pockets is unlinkable and, once a pocket's keys are gone,
//!   nobody can confirm guesses about its former content;
//! * versioned **key-encryption keys (KEKs)** that wrap every chunk's random data key.
//!   Shredding a chunk rotates the KEK: survivors are re-wrapped under the new version and the
//!   old versions are destroyed, so a stale copy of the shredded chunk's wrapped key (a backup,
//!   an SSD remnant) can no longer be unwrapped.
//!
//! The production keyring (OS keychain, WP1.5) implements this trait; [`MemoryKeyring`] is the
//! deterministic double used by tests and simulation.

use std::collections::BTreeMap;
use std::fmt;
use std::sync::{Arc, Mutex, PoisonError};

use uaos_contracts::id::PocketId;
use uaos_platform::crypto::SecretKey;
use uaos_platform::{PlatformError, Rng};

/// Version number of a pocket's key-encryption key.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct KekVersion(pub u32);

/// Keyring failure.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum KeyringError {
    /// The requested KEK version no longer exists (retired after a shred).
    #[error("key version retired")]
    Retired,
    /// The keyring backend is unreachable or refused access.
    #[error("keyring unavailable: {0}")]
    Unavailable(String),
    /// Key generation failed.
    #[error("key generation failed: {0}")]
    Platform(PlatformError),
}

/// Per-pocket key storage used by the chunk store.
pub trait PocketKeyring: Send + Sync + fmt::Debug {
    /// The pocket's content-addressing key, created on first use.
    ///
    /// # Errors
    /// [`KeyringError`] if the backend fails.
    fn cas_key(&self, pocket: PocketId) -> Result<Arc<SecretKey>, KeyringError>;

    /// The pocket's current KEK, created on first use.
    ///
    /// # Errors
    /// [`KeyringError`] if the backend fails.
    fn current_kek(&self, pocket: PocketId) -> Result<(KekVersion, Arc<SecretKey>), KeyringError>;

    /// A specific KEK version.
    ///
    /// # Errors
    /// [`KeyringError::Retired`] if that version was destroyed.
    fn kek(&self, pocket: PocketId, version: KekVersion) -> Result<Arc<SecretKey>, KeyringError>;

    /// Creates a new current KEK version; older versions stay usable until retired.
    ///
    /// # Errors
    /// [`KeyringError`] if the backend fails.
    fn rotate_kek(&self, pocket: PocketId) -> Result<KekVersion, KeyringError>;

    /// Destroys every KEK version older than `keep_from`.
    ///
    /// # Errors
    /// [`KeyringError`] if the backend fails.
    fn retire_keks_before(&self, pocket: PocketId, keep_from: KekVersion) -> Result<(), KeyringError>;

    /// Live KEK versions, ascending. More than one means a rotation is unfinished.
    ///
    /// # Errors
    /// [`KeyringError`] if the backend fails.
    fn kek_versions(&self, pocket: PocketId) -> Result<Vec<KekVersion>, KeyringError>;
}

#[derive(Debug, Default)]
struct PocketKeys {
    cas: Option<Arc<SecretKey>>,
    keks: BTreeMap<KekVersion, Arc<SecretKey>>,
}

/// In-memory keyring for tests and deterministic simulation. Survives simulated process
/// crashes when the same instance is kept, like an OS keychain. Never injected in production.
#[derive(Debug)]
pub struct MemoryKeyring {
    rng: Arc<dyn Rng>,
    pockets: Mutex<BTreeMap<PocketId, PocketKeys>>,
}

impl MemoryKeyring {
    /// Creates an empty keyring drawing key material from `rng`.
    #[must_use]
    pub fn new(rng: Arc<dyn Rng>) -> Self {
        Self {
            rng,
            pockets: Mutex::new(BTreeMap::new()),
        }
    }

    fn with<T>(
        &self,
        pocket: PocketId,
        f: impl FnOnce(&mut PocketKeys, &dyn Rng) -> Result<T, KeyringError>,
    ) -> Result<T, KeyringError> {
        let mut pockets = self.pockets.lock().unwrap_or_else(PoisonError::into_inner);
        f(pockets.entry(pocket).or_default(), self.rng.as_ref())
    }
}

fn fresh(rng: &dyn Rng) -> Result<Arc<SecretKey>, KeyringError> {
    SecretKey::generate(rng).map(Arc::new).map_err(KeyringError::Platform)
}

impl PocketKeyring for MemoryKeyring {
    fn cas_key(&self, pocket: PocketId) -> Result<Arc<SecretKey>, KeyringError> {
        self.with(pocket, |p, rng| {
            if let Some(k) = &p.cas {
                return Ok(Arc::clone(k));
            }
            let k = fresh(rng)?;
            p.cas = Some(Arc::clone(&k));
            Ok(k)
        })
    }

    fn current_kek(&self, pocket: PocketId) -> Result<(KekVersion, Arc<SecretKey>), KeyringError> {
        self.with(pocket, |p, rng| {
            if let Some((v, k)) = p.keks.iter().next_back() {
                return Ok((*v, Arc::clone(k)));
            }
            let k = fresh(rng)?;
            p.keks.insert(KekVersion(1), Arc::clone(&k));
            Ok((KekVersion(1), k))
        })
    }

    fn kek(&self, pocket: PocketId, version: KekVersion) -> Result<Arc<SecretKey>, KeyringError> {
        self.with(pocket, |p, _| {
            p.keks.get(&version).map(Arc::clone).ok_or(KeyringError::Retired)
        })
    }

    fn rotate_kek(&self, pocket: PocketId) -> Result<KekVersion, KeyringError> {
        self.with(pocket, |p, rng| {
            let next = KekVersion(p.keks.keys().next_back().map_or(1, |v| v.0.saturating_add(1)));
            p.keks.insert(next, fresh(rng)?);
            Ok(next)
        })
    }

    fn retire_keks_before(&self, pocket: PocketId, keep_from: KekVersion) -> Result<(), KeyringError> {
        self.with(pocket, |p, _| {
            p.keks.retain(|v, _| *v >= keep_from);
            Ok(())
        })
    }

    fn kek_versions(&self, pocket: PocketId) -> Result<Vec<KekVersion>, KeyringError> {
        self.with(pocket, |p, _| Ok(p.keks.keys().copied().collect()))
    }
}
