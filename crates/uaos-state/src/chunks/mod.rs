// SPDX-License-Identifier: Apache-2.0

//! Encrypted, content-addressed chunk store with crypto-shredding (ADR-0003 §5–6).
//!
//! Content (prompts, outputs, tool payloads) never sits in the journal: journal records carry a
//! [`ChunkRef`], and the bytes live here, encrypted.
//!
//! * **Addressing:** `ref = HMAC-SHA-256(pocket content key, plaintext)`. Equal content in one
//!   pocket is stored once; equal content in two pockets is unlinkable.
//! * **Encryption:** every chunk gets a fresh random 256-bit data key (AES-256-GCM, context bound
//!   to pocket and reference). The data key is wrapped by the pocket's current KEK and stored
//!   in a small separate key file.
//! * **Durability:** the chunk file, then the key file, are written atomically and durably
//!   before [`ChunkStore::put`] returns, so a journal record written afterwards never refers to
//!   content a power loss could remove.
//! * **Shredding:** delete the key file (content becomes unreadable), delete the chunk, then
//!   rotate the pocket KEK: re-wrap every surviving data key under a new version and destroy the
//!   old versions. A stale copy of the shredded key file — a backup, an SSD remnant — can then
//!   no longer be unwrapped. A crash mid-rotation is finished by [`ChunkStore::open`].
//!
//! Honest limit: copies of key material held by the OS keychain's own backups are outside UAOS's
//! control (stated in `docs/privacy/data-flow.md`).

mod format;
pub mod keyring;

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, PoisonError};

use uaos_contracts::digest::ChunkRef;
use uaos_contracts::error::{ErrorCode, codes};
use uaos_contracts::id::PocketId;
use uaos_contracts::limits;
use uaos_platform::crypto::{CryptoError, KEY_LEN, SecretKey, hmac_sha256, open, seal};
use uaos_platform::fs::{Fs, FsError};
use uaos_platform::{PlatformError, Rng};

use keyring::{KekVersion, KeyringError, PocketKeyring};

/// Name of the chunk-store directory inside the data directory.
pub const CHUNKS_DIR: &str = "chunks";

/// Chunk-store failure, mapped to registered codes by [`ChunkError::code`].
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ChunkError {
    /// Never stored in this pocket, or deliberately shredded.
    #[error("chunk unavailable (never stored here, or shredded)")]
    Unavailable,
    /// Authentication failed or the file is malformed: altered or damaged outside UAOS.
    #[error("chunk failed authentication or is malformed")]
    Corrupt,
    /// The content exceeds the maximum chunk size.
    #[error("content exceeds the maximum chunk size")]
    TooLarge,
    /// The device is full; nothing was acknowledged.
    #[error("no space left for content")]
    DiskFull,
    /// Filesystem failure.
    #[error("chunk storage error: {0}")]
    Storage(FsError),
    /// The pocket's keys could not be used.
    #[error("{0}")]
    Keyring(KeyringError),
    /// Randomness unavailable.
    #[error("platform failure: {0}")]
    Platform(PlatformError),
}

impl ChunkError {
    /// Registered error code.
    #[must_use]
    pub fn code(&self) -> ErrorCode {
        match self {
            Self::Unavailable => codes::STORE_CHUNK_UNAVAILABLE,
            Self::Corrupt => codes::STORE_CHUNK_CORRUPT,
            Self::Keyring(_) => codes::STORE_KEYRING_UNAVAILABLE,
            Self::DiskFull => codes::JOURNAL_DISK_FULL,
            Self::TooLarge | Self::Storage(_) | Self::Platform(_) => codes::JOURNAL_WRITE_FAILED,
        }
    }
}

fn storage(e: FsError) -> ChunkError {
    match e {
        FsError::NoSpace { .. } => ChunkError::DiskFull,
        other => ChunkError::Storage(other),
    }
}

/// What a shred did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ShredReport {
    /// Whether the chunk existed (a repeated shred is a no-op that still completes rotation).
    pub removed: bool,
    /// Number of surviving data keys re-wrapped under the new KEK.
    pub rewrapped: usize,
    /// KEK version now in force; every older version has been destroyed.
    pub kek_version: KekVersion,
}

/// The chunk store of one data directory.
#[derive(Debug)]
pub struct ChunkStore {
    fs: Arc<dyn Fs>,
    rng: Arc<dyn Rng>,
    keys: Arc<dyn PocketKeyring>,
    root: PathBuf,
    prepared: Mutex<BTreeSet<PocketId>>,
}

fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    bytes.iter().fold(String::with_capacity(bytes.len() * 2), |mut s, b| {
        // Writing to a String cannot fail.
        let _infallible = write!(s, "{b:02x}");
        s
    })
}

impl ChunkStore {
    /// Opens the store in `data_dir`, finishing any key rotation a crash interrupted.
    ///
    /// # Errors
    /// Storage or keyring failures.
    pub fn open(
        fs: Arc<dyn Fs>,
        rng: Arc<dyn Rng>,
        keys: Arc<dyn PocketKeyring>,
        data_dir: &Path,
    ) -> Result<Self, ChunkError> {
        let root = data_dir.join(CHUNKS_DIR);
        fs.create_dir_all(&root).map_err(storage)?;
        let store = Self {
            fs,
            rng,
            keys,
            root,
            prepared: Mutex::new(BTreeSet::new()),
        };
        for pocket in store.pockets()? {
            store.finish_rotation(pocket)?;
        }
        Ok(store)
    }

    /// Pockets that have stored content.
    ///
    /// # Errors
    /// Storage failures.
    pub fn pockets(&self) -> Result<Vec<PocketId>, ChunkError> {
        Ok(self
            .fs
            .list_dir(&self.root)
            .map_err(storage)?
            .iter()
            .filter_map(|p| p.file_name()?.to_str()?.parse().ok())
            .collect())
    }

    fn data_dir(&self, pocket: PocketId) -> PathBuf {
        self.root.join(pocket.to_string()).join("data")
    }

    fn key_dir(&self, pocket: PocketId) -> PathBuf {
        self.root.join(pocket.to_string()).join("keys")
    }

    fn chunk_path(&self, pocket: PocketId, chunk: ChunkRef) -> PathBuf {
        self.data_dir(pocket).join(format!("{}.chunk", hex(chunk.as_bytes())))
    }

    fn key_path(&self, pocket: PocketId, chunk: ChunkRef) -> PathBuf {
        self.key_dir(pocket).join(format!("{}.key", hex(chunk.as_bytes())))
    }

    /// Creates the pocket's directories and makes their entries durable, once per process.
    fn prepare(&self, pocket: PocketId) -> Result<(), ChunkError> {
        let mut prepared = self.prepared.lock().unwrap_or_else(PoisonError::into_inner);
        if prepared.contains(&pocket) {
            return Ok(());
        }
        let pocket_dir = self.root.join(pocket.to_string());
        self.fs.create_dir_all(&self.data_dir(pocket)).map_err(storage)?;
        self.fs.create_dir_all(&self.key_dir(pocket)).map_err(storage)?;
        self.fs.sync_dir(&self.root).map_err(storage)?;
        self.fs.sync_dir(&pocket_dir).map_err(storage)?;
        prepared.insert(pocket);
        Ok(())
    }

    /// The reference `content` has (or would have) in `pocket`.
    ///
    /// # Errors
    /// Keyring failures.
    pub fn reference(&self, pocket: PocketId, content: &[u8]) -> Result<ChunkRef, ChunkError> {
        let cas = self.keys.cas_key(pocket).map_err(ChunkError::Keyring)?;
        Ok(ChunkRef::from_bytes(hmac_sha256(&cas, content)))
    }

    /// Stores `content` durably and returns its reference. Storing the same content again in
    /// the same pocket is a cheap no-op.
    ///
    /// # Errors
    /// `TooLarge`, `DiskFull`, storage, keyring or platform failures. On error nothing is
    /// acknowledged; partially written files are unreferenced and harmless.
    pub fn put(&self, pocket: PocketId, content: &[u8]) -> Result<ChunkRef, ChunkError> {
        if !limits::MAX_CHUNK.admits(content.len()) {
            return Err(ChunkError::TooLarge);
        }
        let chunk = self.reference(pocket, content)?;
        self.prepare(pocket)?;
        let key_path = self.key_path(pocket, chunk);
        match self.fs.read(&key_path) {
            Ok(_) => return Ok(chunk),
            Err(FsError::NotFound { .. }) => {}
            Err(e) => return Err(storage(e)),
        }

        let data_key = SecretKey::generate(self.rng.as_ref()).map_err(ChunkError::Platform)?;
        let sealed = seal(&data_key, &format::chunk_aad(pocket, chunk), content).map_err(|_| ChunkError::Corrupt)?;
        self.fs
            .write_atomic(
                &self.chunk_path(pocket, chunk),
                &format::encode_chunk(sealed.nonce, &sealed.ciphertext),
            )
            .map_err(storage)?;

        let (version, kek) = self.keys.current_kek(pocket).map_err(ChunkError::Keyring)?;
        self.write_key(pocket, chunk, &data_key, version, &kek)?;
        Ok(chunk)
    }

    fn write_key(
        &self,
        pocket: PocketId,
        chunk: ChunkRef,
        data_key: &SecretKey,
        version: KekVersion,
        kek: &SecretKey,
    ) -> Result<(), ChunkError> {
        let wrapped = seal(kek, &format::key_aad(pocket, chunk, version), data_key.expose_secret())
            .map_err(|_| ChunkError::Corrupt)?;
        self.fs
            .write_atomic(
                &self.key_path(pocket, chunk),
                &format::encode_key(version, wrapped.nonce, &wrapped.ciphertext),
            )
            .map_err(storage)
    }

    /// Unwraps a chunk's data key.
    fn data_key(&self, pocket: PocketId, chunk: ChunkRef) -> Result<(SecretKey, KekVersion), ChunkError> {
        let bytes = match self.fs.read(&self.key_path(pocket, chunk)) {
            Ok(b) => b,
            Err(FsError::NotFound { .. }) => return Err(ChunkError::Unavailable),
            Err(e) => return Err(storage(e)),
        };
        let (version, nonce, wrapped) = format::decode_key(&bytes).ok_or(ChunkError::Corrupt)?;
        let kek = match self.keys.kek(pocket, version) {
            Ok(k) => k,
            Err(KeyringError::Retired) => return Err(ChunkError::Unavailable),
            Err(e) => return Err(ChunkError::Keyring(e)),
        };
        let raw = open(&kek, &nonce, &format::key_aad(pocket, chunk, version), wrapped)
            .map_err(|_: CryptoError| ChunkError::Corrupt)?;
        let raw: [u8; KEY_LEN] = raw.as_slice().try_into().map_err(|_| ChunkError::Corrupt)?;
        Ok((SecretKey::from_bytes(raw), version))
    }

    /// Reads and authenticates a chunk.
    ///
    /// # Errors
    /// `Unavailable` if never stored or shredded; `Corrupt` if anything fails authentication,
    /// including the end-to-end check that the content still matches its reference.
    pub fn get(&self, pocket: PocketId, chunk: ChunkRef) -> Result<Vec<u8>, ChunkError> {
        let (data_key, _) = self.data_key(pocket, chunk)?;
        let bytes = match self.fs.read(&self.chunk_path(pocket, chunk)) {
            Ok(b) => b,
            Err(FsError::NotFound { .. }) => return Err(ChunkError::Corrupt),
            Err(e) => return Err(storage(e)),
        };
        let (nonce, sealed) = format::decode_chunk(&bytes).ok_or(ChunkError::Corrupt)?;
        let content =
            open(&data_key, &nonce, &format::chunk_aad(pocket, chunk), sealed).map_err(|_| ChunkError::Corrupt)?;
        if self.reference(pocket, &content)? != chunk {
            return Err(ChunkError::Corrupt);
        }
        Ok(content)
    }

    /// Crypto-shreds a chunk (see module docs). Idempotent: shredding twice is safe.
    ///
    /// Order matters. The KEK is rotated **first**: from then on an unfinished rotation is the
    /// durable marker of an unfinished shred, and [`ChunkStore::open`] completes it after any
    /// crash. Deleting first would let a crash leave the files gone but the old KEK alive, so a
    /// backup of the key file would still unwrap.
    ///
    /// # Errors
    /// Storage or keyring failures. The shred is acknowledged only by `Ok`; after an error the
    /// caller retries, and a crash is completed on the next open.
    pub fn shred(&self, pocket: PocketId, chunk: ChunkRef) -> Result<ShredReport, ChunkError> {
        self.prepare(pocket)?;
        self.keys.rotate_kek(pocket).map_err(ChunkError::Keyring)?;
        let mut removed = false;
        for path in [self.key_path(pocket, chunk), self.chunk_path(pocket, chunk)] {
            match self.fs.remove_file(&path) {
                Ok(()) => removed = true,
                Err(FsError::NotFound { .. }) => {}
                Err(e) => return Err(storage(e)),
            }
        }
        self.fs.sync_dir(&self.key_dir(pocket)).map_err(storage)?;
        self.fs.sync_dir(&self.data_dir(pocket)).map_err(storage)?;
        let (rewrapped, kek_version) = self.finish_rotation(pocket)?;
        Ok(ShredReport {
            removed,
            rewrapped,
            kek_version,
        })
    }

    /// Re-wraps every data key still under an older KEK version, then destroys the older
    /// versions. No-op when only one version exists.
    fn finish_rotation(&self, pocket: PocketId) -> Result<(usize, KekVersion), ChunkError> {
        let (current, kek) = self.keys.current_kek(pocket).map_err(ChunkError::Keyring)?;
        let versions = self.keys.kek_versions(pocket).map_err(ChunkError::Keyring)?;
        if versions.len() <= 1 {
            return Ok((0, current));
        }
        let mut rewrapped = 0usize;
        let key_dir = self.key_dir(pocket);
        let entries = match self.fs.list_dir(&key_dir) {
            Ok(e) => e,
            Err(FsError::NotFound { .. }) => Vec::new(),
            Err(e) => return Err(storage(e)),
        };
        for path in entries {
            let Some(chunk) = path
                .file_name()
                .and_then(|n| n.to_str())
                .and_then(|n| n.strip_suffix(".key"))
                .and_then(|h| format!("hmac-sha256:{h}").parse::<ChunkRef>().ok())
            else {
                continue;
            };
            match self.data_key(pocket, chunk) {
                Ok((data_key, version)) if version < current => {
                    self.write_key(pocket, chunk, &data_key, current, &kek)?;
                    rewrapped += 1;
                }
                Ok(_) | Err(ChunkError::Unavailable) => {}
                Err(e) => return Err(e),
            }
        }
        self.keys
            .retire_keks_before(pocket, current)
            .map_err(ChunkError::Keyring)?;
        Ok((rewrapped, current))
    }
}
