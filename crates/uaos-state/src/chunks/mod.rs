// SPDX-License-Identifier: Apache-2.0

//! Encrypted, content-addressed chunk store with crypto-shredding (ADR-0003 §5–6, ADR-0018).
//!
//! Content (prompts, outputs, tool payloads) never sits in the journal: journal records carry a
//! [`ChunkRef`], and the bytes live here, encrypted.
//!
//! * **Addressing:** `ref = HMAC-SHA-256(pocket content key, plaintext)`. Equal content in one
//!   pocket is stored once; equal content in two pockets is unlinkable.
//! * **Encryption:** every chunk gets a fresh random 256-bit data key (AES-256-GCM, context bound
//!   to pocket and reference). The data key is wrapped by the pocket's current KEK and stored
//!   in a small separate key file.
//! * **Durability (ADR-0018):** chunks follow the class of the records that reference them.
//!   - [`ChunkDurability::Strict`]: the chunk file, then the key file, are written atomically
//!     and flushed before [`ChunkStore::put`] returns.
//!   - [`ChunkDurability::Balanced`]: both files are handed to the OS (they survive a process
//!     crash) before `put` returns, and the journal's flush makes them durable **before** the
//!     records that reference them ([`ChunkStore::sync_pending`], called by
//!     [`crate::journal::Journal::sync`]). A record is durable only once its payload is.
//! * **One writer per chunk (S-6):** concurrent puts of the same content wait for one another,
//!   so a data file can never be paired with another writer's key. A chunk found on disk from
//!   an earlier process is read back once before it is trusted, because a power loss can leave
//!   it empty or torn.
//! * **Shredding:** delete the key file (content becomes unreadable), delete the chunk, then
//!   rotate the pocket KEK: re-wrap every surviving data key under a new version and destroy the
//!   old versions. A stale copy of the shredded key file — a backup, an SSD remnant — can then
//!   no longer be unwrapped. A crash mid-rotation is finished by [`ChunkStore::open`]. Re-wraps
//!   are always flushed, in either mode, because the old KEK is destroyed right after.
//!
//! Honest limit: copies of key material held by the OS keychain's own backups are outside UAOS's
//! control (stated in `docs/privacy/data-flow.md`).

mod format;
pub mod keyring;

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Condvar, Mutex, MutexGuard, PoisonError};

use uaos_contracts::digest::ChunkRef;
use uaos_contracts::error::{ErrorCode, codes};
use uaos_contracts::id::PocketId;
use uaos_contracts::limits;
use uaos_platform::crypto::{CryptoError, KEY_LEN, SecretKey, hmac_sha256, open, seal};
use uaos_platform::fs::{Fs, FsError, is_temp_file_name};
use uaos_platform::{PlatformError, Rng};

use keyring::{KekVersion, KeyringError, PocketKeyring};

/// Name of the chunk-store directory inside the data directory.
pub const CHUNKS_DIR: &str = "chunks";

/// Unflushed chunk writes held at once in balanced mode. Reaching it flushes them in place, so
/// a store whose journal never flushes still stays bounded (I-08).
pub const MAX_PENDING: usize = 16_384;

/// Chunks remembered as written or verified by this process. Past it the memory is cleared;
/// later puts then read chunks back once more, which costs time, never correctness (I-08).
pub const MAX_KNOWN: usize = 262_144;

/// When chunk writes become durable against power loss (ADR-0018).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChunkDurability {
    /// Flushed before `put` returns. For stores without a journal, and the journal's strict mode.
    Strict,
    /// Handed to the OS before `put` returns; flushed by the journal before the records that
    /// reference them.
    Balanced,
}

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

    /// Whether the chunk itself is unreadable (as opposed to the store failing to look).
    fn is_unreadable(&self) -> bool {
        matches!(self, Self::Unavailable | Self::Corrupt)
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

type Key = (PocketId, ChunkRef);

/// The chunk store of one data directory.
#[derive(Debug)]
pub struct ChunkStore {
    fs: Arc<dyn Fs>,
    rng: Arc<dyn Rng>,
    keys: Arc<dyn PocketKeyring>,
    root: PathBuf,
    durability: ChunkDurability,
    prepared: Mutex<BTreeSet<PocketId>>,
    /// Written in balanced mode and not yet flushed.
    pending: Mutex<BTreeSet<Key>>,
    /// Puts in progress; a second put of the same chunk waits on `inflight_done`.
    inflight: Mutex<BTreeSet<Key>>,
    inflight_done: Condvar,
    /// Written or read back by this process.
    known: Mutex<BTreeSet<Key>>,
    /// Pending chunks found unreadable after a failed flush and not yet taken by the journal.
    /// Kept across failed recoveries, so a loss can never be dropped unreported.
    lost: Mutex<BTreeSet<Key>>,
}

fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    bytes.iter().fold(String::with_capacity(bytes.len() * 2), |mut s, b| {
        // Writing to a String cannot fail.
        let _infallible = write!(s, "{b:02x}");
        s
    })
}

fn locked<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    // Every update of a guarded set is a single insert, remove or clear, so a panicking holder
    // cannot leave one half-updated.
    m.lock().unwrap_or_else(PoisonError::into_inner)
}

/// Whether a write must be flushed before it returns.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Flush {
    Now,
    WithJournal,
}

impl ChunkStore {
    /// Opens the store in `data_dir` in [`ChunkDurability::Strict`] mode, finishing any key
    /// rotation a crash interrupted.
    ///
    /// # Errors
    /// Storage or keyring failures.
    pub fn open(
        fs: Arc<dyn Fs>,
        rng: Arc<dyn Rng>,
        keys: Arc<dyn PocketKeyring>,
        data_dir: &Path,
    ) -> Result<Self, ChunkError> {
        Self::open_with(fs, rng, keys, data_dir, ChunkDurability::Strict)
    }

    /// Opens the store with the given durability. A [`ChunkDurability::Balanced`] store must be
    /// attached to the journal that references its chunks
    /// ([`crate::journal::Journal::open_with_payloads`]); that journal flushes it.
    ///
    /// # Errors
    /// Storage or keyring failures.
    pub fn open_with(
        fs: Arc<dyn Fs>,
        rng: Arc<dyn Rng>,
        keys: Arc<dyn PocketKeyring>,
        data_dir: &Path,
        durability: ChunkDurability,
    ) -> Result<Self, ChunkError> {
        let root = data_dir.join(CHUNKS_DIR);
        fs.create_dir_all(&root).map_err(storage)?;
        let store = Self {
            fs,
            rng,
            keys,
            root,
            durability,
            prepared: Mutex::new(BTreeSet::new()),
            pending: Mutex::new(BTreeSet::new()),
            inflight: Mutex::new(BTreeSet::new()),
            inflight_done: Condvar::new(),
            known: Mutex::new(BTreeSet::new()),
            lost: Mutex::new(BTreeSet::new()),
        };
        for pocket in store.pockets()? {
            store.sweep_temporaries(pocket)?;
            store.finish_rotation(pocket)?;
        }
        Ok(store)
    }

    /// The store's durability mode.
    #[must_use]
    pub fn durability(&self) -> ChunkDurability {
        self.durability
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
        let mut prepared = locked(&self.prepared);
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

    /// Removes temporaries left by writes a crash interrupted. They are never referenced.
    fn sweep_temporaries(&self, pocket: PocketId) -> Result<(), ChunkError> {
        for dir in [self.data_dir(pocket), self.key_dir(pocket)] {
            let entries = match self.fs.list_dir(&dir) {
                Ok(e) => e,
                Err(FsError::NotFound { .. }) => continue,
                Err(e) => return Err(storage(e)),
            };
            for path in entries {
                if path.file_name().and_then(|n| n.to_str()).is_some_and(is_temp_file_name) {
                    match self.fs.remove_file(&path) {
                        Ok(()) | Err(FsError::NotFound { .. }) => {}
                        Err(e) => return Err(storage(e)),
                    }
                }
            }
        }
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

    /// Stores `content` and returns its reference once both files are with the OS (strict mode:
    /// once they are flushed). Storing the same content again in the same pocket is a cheap
    /// no-op; concurrent puts of the same content wait for one another.
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
        let key = (pocket, chunk);
        {
            let mut inflight = locked(&self.inflight);
            while inflight.contains(&key) {
                inflight = self
                    .inflight_done
                    .wait(inflight)
                    .unwrap_or_else(PoisonError::into_inner);
            }
            if locked(&self.known).contains(&key) {
                return Ok(chunk);
            }
            inflight.insert(key);
        }
        let result = self.store(pocket, chunk, content);
        {
            let mut inflight = locked(&self.inflight);
            if result.is_ok() {
                // Before the slot opens, so a waiting put of the same chunk sees it as written.
                self.remember(key);
            }
            inflight.remove(&key);
            self.inflight_done.notify_all();
        }
        result?;
        if self.durability == ChunkDurability::Balanced {
            let full = {
                let mut pending = locked(&self.pending);
                pending.insert(key);
                pending.len() >= MAX_PENDING
            };
            if full {
                self.sync_pending()?;
            }
        }
        Ok(chunk)
    }

    /// Writes one chunk; the caller holds its in-flight slot.
    fn store(&self, pocket: PocketId, chunk: ChunkRef, content: &[u8]) -> Result<(), ChunkError> {
        match self.fs.read(&self.key_path(pocket, chunk)) {
            Ok(_) => {
                // Stored by an earlier process. A power loss can leave the pair empty or torn,
                // so it is read back once before it is trusted (ADR-0018 §3).
                match self.get(pocket, chunk) {
                    Ok(_) => return Ok(()),
                    Err(e) if e.is_unreadable() => self.remove_pair(pocket, chunk)?,
                    Err(e) => return Err(e),
                }
            }
            Err(FsError::NotFound { .. }) => {}
            Err(e) => return Err(storage(e)),
        }

        let flush = match self.durability {
            ChunkDurability::Strict => Flush::Now,
            ChunkDurability::Balanced => Flush::WithJournal,
        };
        let data_key = SecretKey::generate(self.rng.as_ref()).map_err(ChunkError::Platform)?;
        let sealed = seal(&data_key, &format::chunk_aad(pocket, chunk), content).map_err(|_| ChunkError::Corrupt)?;
        self.write(
            &self.chunk_path(pocket, chunk),
            &format::encode_chunk(sealed.nonce, &sealed.ciphertext),
            flush,
        )?;
        let (version, kek) = self.keys.current_kek(pocket).map_err(ChunkError::Keyring)?;
        self.write_key(pocket, chunk, &data_key, version, &kek, flush)
    }

    /// Writes one chunk file. Strict: atomic replace, flushed. Balanced: atomic replace through
    /// a unique temporary, unflushed.
    ///
    /// Creating the file in place under its final name (no temporary, no rename) was measured
    /// on the reference machine (Windows 10, solid-state drive, 2026-10-15). It halved p50 put latency
    /// (0.89 ms against 1.64 ms) but tripled p99 (7.5 ms against 2.1 ms) with flushes
    /// interleaved. The overhead SLO is judged at p95 and p99, so the rename stays until other
    /// platforms' numbers say otherwise.
    fn write(&self, path: &Path, bytes: &[u8], flush: Flush) -> Result<(), ChunkError> {
        match flush {
            Flush::Now => self.fs.write_atomic(path, bytes),
            Flush::WithJournal => self.fs.write_unsynced(path, bytes),
        }
        .map_err(storage)
    }

    fn write_key(
        &self,
        pocket: PocketId,
        chunk: ChunkRef,
        data_key: &SecretKey,
        version: KekVersion,
        kek: &SecretKey,
        flush: Flush,
    ) -> Result<(), ChunkError> {
        let wrapped = seal(kek, &format::key_aad(pocket, chunk, version), data_key.expose_secret())
            .map_err(|_| ChunkError::Corrupt)?;
        self.write(
            &self.key_path(pocket, chunk),
            &format::encode_key(version, wrapped.nonce, &wrapped.ciphertext),
            flush,
        )
    }

    fn remove_pair(&self, pocket: PocketId, chunk: ChunkRef) -> Result<(), ChunkError> {
        for path in [self.key_path(pocket, chunk), self.chunk_path(pocket, chunk)] {
            match self.fs.remove_file(&path) {
                Ok(()) | Err(FsError::NotFound { .. }) => {}
                Err(e) => return Err(storage(e)),
            }
        }
        Ok(())
    }

    fn remember(&self, key: Key) {
        let mut known = locked(&self.known);
        if known.len() >= MAX_KNOWN {
            known.clear();
        }
        known.insert(key);
    }

    fn forget(&self, key: Key) {
        locked(&self.known).remove(&key);
        locked(&self.pending).remove(&key);
    }

    /// Whether `chunk` is stored in `pocket` and readable. A chunk this process wrote is
    /// answered from memory; any other is read back once. The journal asks this before it
    /// accepts a record that references the chunk (payload before record, I-02).
    ///
    /// # Errors
    /// Storage or keyring failures (an unreadable chunk is `Ok(false)`).
    pub fn is_stored(&self, pocket: PocketId, chunk: ChunkRef) -> Result<bool, ChunkError> {
        let key = (pocket, chunk);
        if locked(&self.known).contains(&key) {
            return Ok(true);
        }
        match self.get(pocket, chunk) {
            Ok(_) => {
                self.remember(key);
                Ok(true)
            }
            Err(e) if e.is_unreadable() => Ok(false),
            Err(e) => Err(e),
        }
    }

    /// Number of chunks written in balanced mode and not yet flushed.
    #[must_use]
    pub fn pending_len(&self) -> usize {
        locked(&self.pending).len()
    }

    /// Makes every chunk written since the last successful call durable: both files, then the
    /// pocket directories (ADR-0018). The journal calls this before it flushes its own records.
    ///
    /// # Errors
    /// Storage failures. Nothing new is then durable, and the chunks stay pending; after a
    /// failed flush their content must be considered lost until [`ChunkStore::recover_pending`]
    /// has read them back.
    pub fn sync_pending(&self) -> Result<(), ChunkError> {
        let batch: Vec<Key> = locked(&self.pending).iter().copied().collect();
        if batch.is_empty() {
            return Ok(());
        }
        let mut pockets = BTreeSet::new();
        for &(pocket, chunk) in &batch {
            for path in [self.chunk_path(pocket, chunk), self.key_path(pocket, chunk)] {
                match self.fs.sync_file(&path) {
                    // Shredded since it was written: nothing left to make durable.
                    Ok(()) | Err(FsError::NotFound { .. }) => {}
                    Err(e) => return Err(storage(e)),
                }
            }
            pockets.insert(pocket);
        }
        for pocket in pockets {
            self.fs.sync_dir(&self.data_dir(pocket)).map_err(storage)?;
            self.fs.sync_dir(&self.key_dir(pocket)).map_err(storage)?;
        }
        let mut pending = locked(&self.pending);
        for key in &batch {
            pending.remove(key);
        }
        Ok(())
    }

    /// After a failed [`ChunkStore::sync_pending`]: reads every pending chunk back. The OS may
    /// have dropped the unflushed pages, so readable chunks are flushed again and unreadable
    /// ones are removed and set aside for [`ChunkStore::take_lost`] (ADR-0018 §3). What was set
    /// aside survives a failure of this call, so a retry still reports it.
    ///
    /// # Errors
    /// Storage or keyring failures.
    pub fn recover_pending(&self) -> Result<(), ChunkError> {
        let batch: Vec<Key> = locked(&self.pending).iter().copied().collect();
        for (pocket, chunk) in batch {
            match self.get(pocket, chunk) {
                Ok(_) => {}
                Err(e) if e.is_unreadable() => {
                    // Set aside first: from here on the loss is remembered whatever fails next.
                    locked(&self.lost).insert((pocket, chunk));
                    self.forget((pocket, chunk));
                    self.remove_pair(pocket, chunk)?;
                }
                Err(e) => return Err(e),
            }
        }
        self.sync_pending()
    }

    /// Takes the chunks [`ChunkStore::recover_pending`] found lost. The caller must report each
    /// (the journal writes a `chunk.lost` record).
    #[must_use]
    pub fn take_lost(&self) -> Vec<(PocketId, ChunkRef)> {
        std::mem::take(&mut *locked(&self.lost)).into_iter().collect()
    }

    /// At startup, before the journal makes a previous run's records durable: reads each
    /// referenced chunk back, flushes the readable ones and removes and returns the unreadable
    /// ones (ADR-0018 §3). `refs` may contain duplicates.
    ///
    /// # Errors
    /// Storage or keyring failures.
    pub fn verify_and_sync(&self, refs: &[(PocketId, ChunkRef)]) -> Result<Vec<(PocketId, ChunkRef)>, ChunkError> {
        let unique: BTreeSet<Key> = refs.iter().copied().collect();
        let mut lost = Vec::new();
        let mut pockets = BTreeSet::new();
        for (pocket, chunk) in unique {
            match self.get(pocket, chunk) {
                Ok(_) => {
                    self.fs.sync_file(&self.chunk_path(pocket, chunk)).map_err(storage)?;
                    self.fs.sync_file(&self.key_path(pocket, chunk)).map_err(storage)?;
                    pockets.insert(pocket);
                    self.remember((pocket, chunk));
                }
                Err(e) if e.is_unreadable() => {
                    self.remove_pair(pocket, chunk)?;
                    self.forget((pocket, chunk));
                    lost.push((pocket, chunk));
                }
                Err(e) => return Err(e),
            }
        }
        for pocket in pockets {
            self.fs.sync_dir(&self.data_dir(pocket)).map_err(storage)?;
            self.fs.sync_dir(&self.key_dir(pocket)).map_err(storage)?;
        }
        Ok(lost)
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
        self.forget((pocket, chunk));
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
    /// versions. No-op when only one version exists. Re-wraps are flushed in either durability
    /// mode: the old versions are destroyed right after, so an unflushed re-wrap lost to a power
    /// loss would leave a key file only a destroyed KEK can open.
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
                    self.write_key(pocket, chunk, &data_key, current, &kek, Flush::Now)?;
                    rewrapped += 1;
                }
                // Unreadable key files (shredded, or torn by a power loss in balanced mode)
                // cannot be re-wrapped; they are reported when a record that references them is
                // checked, and must not stop the store from opening.
                Ok(_) | Err(ChunkError::Unavailable | ChunkError::Corrupt) => {}
                Err(e) => return Err(e),
            }
        }
        self.keys
            .retire_keks_before(pocket, current)
            .map_err(ChunkError::Keyring)?;
        Ok((rewrapped, current))
    }
}
