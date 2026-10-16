// SPDX-License-Identifier: Apache-2.0

//! Encrypted, content-addressed chunk store with crypto-shredding (ADR-0003 §5–6, ADR-0018).
//!
//! Content (prompts, outputs, tool payloads) never sits in the journal: journal records carry a
//! [`ChunkRef`], and the bytes live here, encrypted.
//!
//! * **Addressing:** `ref = HMAC-SHA-256(pocket content key, plaintext)`. Equal content in one
//!   pocket is stored once; equal content in two pockets is unlinkable.
//! * **Encryption:** every chunk gets a fresh random 256-bit data key (AES-256-GCM, context bound
//!   to pocket and reference), kept when an existing pair is rewritten. The data key is wrapped by the pocket's current KEK and stored
//!   in a small separate key file, written after the data file: a pair counts as stored once
//!   its key file is complete.
//! * **Durability (ADR-0018):** chunks follow the class of the records that reference them.
//!   - [`ChunkDurability::Strict`]: both files are written atomically and flushed before
//!     [`ChunkStore::put`] returns.
//!   - [`ChunkDurability::Balanced`]: both files are handed to the OS (they survive a process
//!     crash) before `put` returns, and the journal makes them durable **before** the records
//!     that reference them ([`ChunkStore::sync_pending`], called by
//!     [`crate::journal::Journal::sync`]).
//! * **A failed flush is sticky.** A failed flush of pending content poisons the store, and in
//!   balanced mode so does any failed flushed write or chunk-directory flush, because a directory
//!   flush also covers the entries of pending chunks. Then `put`, `is_stored` and
//!   `sync_pending` refuse until [`ChunkStore::recover_pending`] has read every pending chunk
//!   back. Recovery **rewrites** each readable chunk to a new file and flushes it;
//!   it never trusts a second flush of the file whose flush failed, because after a writeback
//!   error the OS may serve cached bytes it will never write (ADR-0018 §3, review WP3.A1 H4).
//!   Unreadable chunks are quarantined, not deleted, and handed to the journal to report.
//! * **One writer per chunk (S-6):** every operation on a chunk (put, flush, recovery, adoption,
//!   shred) holds that chunk's slot. A chunk found on disk from an earlier process is rewritten
//!   once before it is trusted, so its durability never depends on that process's flushes. That
//!   rewrite is always flushed before it replaces the old pair: the old pair may be the durable
//!   copy a flushed record relies on, and an unflushed replacement whose pending entry died with
//!   its process would be made durable empty by the next directory flush. It also keeps the
//!   pair's data key, so a failure between the data-file and key-file writes leaves a pair that
//!   still opens.
//! * **Shredding:** delete the key file (content becomes unreadable), delete the chunk, then
//!   rotate the pocket KEK: re-wrap every surviving data key under a new version and destroy the
//!   old versions. A stale copy of the shredded key file — a backup, an SSD remnant — can then
//!   no longer be unwrapped. A crash after the rotation began but before the files went leaves
//!   them in place: [`ChunkStore::open`] finishes the rotation (re-wrapping them too), and the
//!   journal, which recorded the shred first, completes it when it opens
//!   ([`crate::journal::Journal::open_with_payloads`]). A store a journal coordinates shreds only
//!   through [`crate::journal::Journal::shred`]. Rotation excludes concurrent puts, reads and
//!   flushes in the same stripe of pockets from a version it is about to destroy, and its
//!   re-wraps are always flushed.
//!
//! Honest limit: copies of key material held by the OS keychain's own backups are outside UAOS's
//! control (stated in `docs/privacy/data-flow.md`).

mod format;
pub mod keyring;

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Condvar, Mutex, MutexGuard, PoisonError, RwLock, RwLockReadGuard, RwLockWriteGuard};

use uaos_contracts::digest::ChunkRef;
use uaos_contracts::error::{ErrorCode, codes};
use uaos_contracts::id::PocketId;
use uaos_contracts::limits;
use uaos_platform::crypto::{CryptoError, KEY_LEN, SecretKey, hmac_sha256, open, seal};
use uaos_platform::fs::{Fs, FsError, LockGuard, is_temp_file_name};
use uaos_platform::{PlatformError, Rng};

use keyring::{KekVersion, KeyringError, PocketKeyring};

/// Name of the chunk-store directory inside the data directory.
pub const CHUNKS_DIR: &str = "chunks";
/// The chunk store's own lock file: one store per data directory (review WP3.A1 L2).
pub const CHUNKS_LOCK: &str = "chunks.lock";
/// Per-pocket folder that keeps unreadable chunk files for inspection instead of deleting them.
pub const QUARANTINE_DIR: &str = "quarantine";

/// Unflushed chunk writes held at once in balanced mode. A put beyond it is refused (the
/// caller retries after the next flush), so the set stays bounded (I-08).
pub const MAX_PENDING: usize = 16_384;

/// Chunks remembered as written or verified by this process. Past it the memory is cleared;
/// later puts then rewrite chunks once more, which costs time, never correctness (I-08).
pub const MAX_KNOWN: usize = 262_144;

/// Rotation locks, one per stripe of pockets: a shred re-wraps and destroys KEKs while holding
/// its pocket's stripe exclusively, and only puts, reads and flushes in the same stripe wait for
/// it (review WP3.A1, third round, M3).
const ROTATION_STRIPES: usize = 64;

/// Key files indexed when the store opens (8 bytes each). Past it, or once the memory of
/// written chunks has been cleared, every put of content this process has not written reads
/// its name back first, which costs time, never correctness (I-08).
pub const MAX_INDEXED: usize = 1 << 20;

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
    /// A flush of pending content failed; nothing is trusted until recovery has read it back.
    #[error("a flush of stored content failed; the store refuses work until recovery")]
    FlushFailed,
    /// Too many unflushed chunks; retry after the journal's next flush.
    #[error("too many unflushed chunks; retry after the next flush")]
    PendingFull,
    /// Another chunk store owns this data directory.
    #[error("another chunk store owns this data directory")]
    InstanceLocked,
    /// A journal coordinates this store; a shred must go through
    /// [`crate::journal::Journal::shred`], which records it first.
    #[error("this store is coordinated by a journal; shred through the journal")]
    ShredThroughJournal,
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
            Self::FlushFailed => codes::STORE_PAYLOAD_FLUSH_FAILED,
            Self::PendingFull => codes::RUNTIME_OVERLOAD,
            Self::InstanceLocked => codes::JOURNAL_INSTANCE_LOCKED,
            Self::ShredThroughJournal => codes::CONFIG_INVALID,
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

/// Why a chunk could not be read back. Recorded with every loss; never guessed beyond what the
/// bytes show.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LossCause {
    /// The key file or the data file is absent.
    Missing,
    /// A file is too short to parse: a write cut off by a crash or a power loss.
    Short,
    /// A file parses but fails authentication: a torn write of full length, or tampering.
    Unauthentic,
}

impl LossCause {
    /// Stable name for journal metadata.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Missing => "missing",
            Self::Short => "short",
            Self::Unauthentic => "unauthentic",
        }
    }
}

/// A chunk found unreadable by recovery. Its files are quarantined, and the journal reports it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LostChunk {
    /// Pocket.
    pub pocket: PocketId,
    /// Chunk.
    pub chunk: ChunkRef,
    /// What the bytes showed.
    pub cause: LossCause,
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

/// The result of reading a chunk back.
enum Probe {
    /// No key file: nothing is stored under this name.
    Absent,
    Readable {
        content: Vec<u8>,
        data_key: SecretKey,
    },
    Lost(LossCause),
    /// The store could not look (storage or keyring failure). Never a reason to touch the files.
    Failed(ChunkError),
}

/// The chunk store of one data directory.
#[derive(Debug)]
pub struct ChunkStore {
    fs: Arc<dyn Fs>,
    rng: Arc<dyn Rng>,
    keys: Arc<dyn PocketKeyring>,
    root: PathBuf,
    durability: ChunkDurability,
    /// Held for the store's lifetime; in a `Mutex` only so the store stays `Sync`.
    _lock: Mutex<Box<dyn LockGuard>>,
    prepared: Mutex<BTreeSet<PocketId>>,
    /// Written in balanced mode and not yet flushed.
    pending: Mutex<BTreeSet<Key>>,
    /// Chunks with an operation in progress; see [`Slot`].
    inflight: Mutex<BTreeSet<Key>>,
    inflight_done: Condvar,
    /// Written or rewritten by this process.
    known: Mutex<BTreeSet<Key>>,
    /// Fingerprints (first 8 bytes of the reference) of the key files present when the store
    /// opened, sorted. Only one store owns the directory, so every pair an earlier process left
    /// is in it, and a put of content absent from it and from `known` writes without reading the
    /// name back, which saves a file-system call per new chunk. A fingerprint two chunks share costs
    /// a read-back, never correctness. `None` once too many to index, or once `known` has been
    /// cleared (chunks this process wrote would look new): then every such put reads back.
    earlier: Mutex<Option<Vec<u64>>>,
    /// Found unreadable by recovery and not yet taken by the journal.
    lost: Mutex<Vec<LostChunk>>,
    /// Per stripe of pockets: puts wrap under the current KEK, reads unwrap and flushes sync
    /// holding it shared; rotation holds it exclusively.
    rotation: Vec<RwLock<()>>,
    /// Counts poisonings (failed flushes). The store is poisoned while it is ahead of `cleared`.
    poison: AtomicU64,
    /// The poisoning a successful recovery cleared through. A flush that fails while recovery
    /// runs stays visible: recovery clears only what it saw when it began (third round, L4).
    cleared: AtomicU64,
    /// Pockets that had key files when the store opened.
    keyed_pockets: Mutex<BTreeSet<PocketId>>,
    /// Set when a journal coordinates the store; direct shreds are then refused.
    attached: AtomicBool,
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
    // Every update of a guarded value is a single insert, remove, push or clear, so a panicking
    // holder cannot leave one half-updated.
    m.lock().unwrap_or_else(PoisonError::into_inner)
}

/// Exclusive use of one chunk for the slot's lifetime, released on drop even by a panic.
struct Slot<'a> {
    store: &'a ChunkStore,
    key: Key,
}

impl Drop for Slot<'_> {
    fn drop(&mut self) {
        locked(&self.store.inflight).remove(&self.key);
        self.store.inflight_done.notify_all();
    }
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
    /// `InstanceLocked`, storage or keyring failures.
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
    /// `InstanceLocked` if another store owns the directory; storage or keyring failures.
    pub fn open_with(
        fs: Arc<dyn Fs>,
        rng: Arc<dyn Rng>,
        keys: Arc<dyn PocketKeyring>,
        data_dir: &Path,
        durability: ChunkDurability,
    ) -> Result<Self, ChunkError> {
        let root = data_dir.join(CHUNKS_DIR);
        fs.create_dir_all(&root).map_err(storage)?;
        let lock = fs.try_lock_exclusive(&root.join(CHUNKS_LOCK)).map_err(|e| match e {
            FsError::Locked { .. } => ChunkError::InstanceLocked,
            other => storage(other),
        })?;
        let store = Self {
            fs,
            rng,
            keys,
            root,
            durability,
            _lock: Mutex::new(lock),
            prepared: Mutex::new(BTreeSet::new()),
            pending: Mutex::new(BTreeSet::new()),
            inflight: Mutex::new(BTreeSet::new()),
            inflight_done: Condvar::new(),
            known: Mutex::new(BTreeSet::new()),
            earlier: Mutex::new(Some(Vec::new())),
            lost: Mutex::new(Vec::new()),
            rotation: (0..ROTATION_STRIPES).map(|_| RwLock::new(())).collect(),
            poison: AtomicU64::new(0),
            cleared: AtomicU64::new(0),
            keyed_pockets: Mutex::new(BTreeSet::new()),
            attached: AtomicBool::new(false),
        };
        for pocket in store.pockets()? {
            store.sweep_temporaries(pocket)?;
            store.finish_rotation(pocket)?;
            store.index_key_files(pocket)?;
        }
        if let Some(index) = locked(&store.earlier).as_mut() {
            index.sort_unstable();
            index.dedup();
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

    fn pocket_dir(&self, pocket: PocketId) -> PathBuf {
        self.root.join(pocket.to_string())
    }

    fn data_dir(&self, pocket: PocketId) -> PathBuf {
        self.pocket_dir(pocket).join("data")
    }

    fn key_dir(&self, pocket: PocketId) -> PathBuf {
        self.pocket_dir(pocket).join("keys")
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
        // A pocket with key files whose KEKs are gone from the keychain (a reset, a moved data
        // directory) must not get a fresh version 1: every existing key file would then look
        // tampered with, and the next check would quarantine it (third round, L2).
        if locked(&self.keyed_pockets).contains(&pocket)
            && self.keys.kek_versions(pocket).map_err(ChunkError::Keyring)?.is_empty()
        {
            return Err(ChunkError::Keyring(KeyringError::Unavailable(
                "the pocket's keys are missing from the keychain".to_owned(),
            )));
        }
        self.fs.create_dir_all(&self.data_dir(pocket)).map_err(storage)?;
        self.fs.create_dir_all(&self.key_dir(pocket)).map_err(storage)?;
        self.fs
            .create_dir_all(&self.pocket_dir(pocket).join(QUARANTINE_DIR))
            .map_err(storage)?;
        for dir in [self.root.clone(), self.pocket_dir(pocket)] {
            if let Err(e) = self.fs.sync_dir(&dir) {
                self.poison_if_balanced();
                return Err(storage(e));
            }
        }
        prepared.insert(pocket);
        Ok(())
    }

    /// Marks the store as coordinated by a journal (called by
    /// [`crate::journal::Journal::open_with_payloads`]).
    pub(crate) fn attach(&self) {
        self.attached.store(true, Ordering::SeqCst);
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

    /// Adds the pocket's key files to the index of pairs left by earlier processes.
    fn index_key_files(&self, pocket: PocketId) -> Result<(), ChunkError> {
        let entries = match self.fs.list_dir(&self.key_dir(pocket)) {
            Ok(e) => e,
            Err(FsError::NotFound { .. }) => return Ok(()),
            Err(e) => return Err(storage(e)),
        };
        if entries
            .iter()
            .any(|p| p.extension().and_then(|e| e.to_str()) == Some("key"))
        {
            locked(&self.keyed_pockets).insert(pocket);
        }
        let mut earlier = locked(&self.earlier);
        for path in entries {
            let Some(index) = earlier.as_mut() else {
                return Ok(());
            };
            let Some(fingerprint) = path
                .file_name()
                .and_then(|n| n.to_str())
                .and_then(|n| n.strip_suffix(".key"))
                .and_then(|h| h.get(..16))
                .and_then(|h| u64::from_str_radix(h, 16).ok())
            else {
                continue;
            };
            if index.len() >= MAX_INDEXED {
                *earlier = None;
            } else {
                index.push(fingerprint);
            }
        }
        Ok(())
    }

    /// Whether a pair for `chunk` may be on disk from an earlier process (see `earlier`).
    fn may_be_on_disk(&self, chunk: ChunkRef) -> bool {
        let bytes = chunk.as_bytes();
        let mut head = [0u8; 8];
        head.copy_from_slice(&bytes[..8]);
        let fingerprint = u64::from_be_bytes(head);
        locked(&self.earlier)
            .as_ref()
            .is_none_or(|index| index.binary_search(&fingerprint).is_ok())
    }

    /// Waits for, then takes, exclusive use of one chunk.
    fn slot(&self, key: Key) -> Slot<'_> {
        let mut inflight = locked(&self.inflight);
        while inflight.contains(&key) {
            inflight = self
                .inflight_done
                .wait(inflight)
                .unwrap_or_else(PoisonError::into_inner);
        }
        inflight.insert(key);
        Slot { store: self, key }
    }

    fn stripe(&self, pocket: PocketId) -> &RwLock<()> {
        use std::hash::{Hash as _, Hasher as _};
        let mut hasher = std::hash::DefaultHasher::new();
        pocket.hash(&mut hasher);
        let stripes = u64::try_from(self.rotation.len()).unwrap_or(1);
        let index = usize::try_from(hasher.finish() % stripes).unwrap_or(0);
        &self.rotation[index]
    }

    fn rotation_shared(&self, pocket: PocketId) -> RwLockReadGuard<'_, ()> {
        self.stripe(pocket).read().unwrap_or_else(PoisonError::into_inner)
    }

    fn rotation_exclusive(&self, pocket: PocketId) -> RwLockWriteGuard<'_, ()> {
        self.stripe(pocket).write().unwrap_or_else(PoisonError::into_inner)
    }

    fn poison(&self) {
        self.poison.fetch_add(1, Ordering::SeqCst);
    }

    fn check_poison(&self) -> Result<(), ChunkError> {
        if self.is_poisoned() {
            Err(ChunkError::FlushFailed)
        } else {
            Ok(())
        }
    }

    fn flush_mode(&self) -> Flush {
        match self.durability {
            ChunkDurability::Strict => Flush::Now,
            ChunkDurability::Balanced => Flush::WithJournal,
        }
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
    /// no-op for content this process wrote; concurrent puts of the same content wait for one
    /// another, and a chunk left by an earlier process is rewritten once.
    ///
    /// # Errors
    /// `TooLarge`, `FlushFailed` while the store is poisoned, `PendingFull` (the caller flushes
    /// the journal with [`crate::journal::Journal::sync`] and retries), `DiskFull`, storage,
    /// keyring or platform failures. On error nothing is acknowledged; partially written files
    /// are unreferenced and harmless.
    pub fn put(&self, pocket: PocketId, content: &[u8]) -> Result<ChunkRef, ChunkError> {
        if !limits::MAX_CHUNK.admits(content.len()) {
            return Err(ChunkError::TooLarge);
        }
        let chunk = self.reference(pocket, content)?;
        self.prepare(pocket)?;
        let key = (pocket, chunk);
        let _slot = self.slot(key);
        // Under the slot: a flush that failed while this put waited is seen here.
        self.check_poison()?;
        if locked(&self.known).contains(&key) {
            // Written by this process and, in balanced mode, still pending or already flushed.
            return Ok(chunk);
        }
        // A pair already on disk is replaced only by a flushed write that keeps its data key
        // (see the module docs); only a name with no key file is written with the journal.
        let found = if self.may_be_on_disk(chunk) {
            self.probe(pocket, chunk)
        } else {
            Probe::Absent
        };
        match found {
            Probe::Absent => self.adopt(key, content, None, self.flush_mode())?,
            Probe::Readable { data_key, .. } => self.adopt(key, content, Some(data_key), Flush::Now)?,
            Probe::Lost(_) => self.adopt(key, content, None, Flush::Now)?,
            Probe::Failed(e) => return Err(e),
        }
        Ok(chunk)
    }

    /// Writes a pair for `key` and tracks it. The caller holds the chunk's slot.
    fn adopt(&self, key: Key, content: &[u8], data_key: Option<SecretKey>, flush: Flush) -> Result<(), ChunkError> {
        let with_journal = flush == Flush::WithJournal;
        if with_journal && locked(&self.pending).len() >= MAX_PENDING {
            return Err(ChunkError::PendingFull);
        }
        self.write_pair(key.0, key.1, content, data_key, flush)?;
        // Both before the slot opens: a waiting put of the same chunk then sees it written and
        // already pending (review WP3.A1 M1).
        self.remember(key);
        if with_journal {
            locked(&self.pending).insert(key);
            // A flush that failed while this pair was written may have missed it; the caller
            // must not reference it until recovery has run (third round, L4).
            self.check_poison()?;
        } else {
            locked(&self.pending).remove(&key);
        }
        Ok(())
    }

    /// Writes the data file, then the key file under the current KEK. A concurrent rotation
    /// cannot destroy that KEK before the key file exists (review WP3.A1 M3).
    ///
    /// `existing` is the pair's data key when a readable pair is rewritten: a failure between
    /// the two writes then leaves the old key file, which opens the new data file too. A fresh
    /// key would leave new data that only the unwritten key file could open.
    fn write_pair(
        &self,
        pocket: PocketId,
        chunk: ChunkRef,
        content: &[u8],
        existing: Option<SecretKey>,
        flush: Flush,
    ) -> Result<(), ChunkError> {
        let data_key = match existing {
            Some(k) => k,
            None => SecretKey::generate(self.rng.as_ref()).map_err(ChunkError::Platform)?,
        };
        let sealed = seal(&data_key, &format::chunk_aad(pocket, chunk), content).map_err(|_| ChunkError::Corrupt)?;
        self.write(
            &self.chunk_path(pocket, chunk),
            &format::encode_chunk(sealed.nonce, &sealed.ciphertext),
            flush,
        )?;
        let _shared = self.rotation_shared(pocket);
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
        let result = match flush {
            Flush::Now => self.fs.write_atomic(path, bytes),
            Flush::WithJournal => self.fs.write_unsynced(path, bytes),
        };
        if result.is_err() && flush == Flush::Now {
            self.poison_if_balanced();
        }
        result.map_err(storage)
    }

    /// In balanced mode, a failed flush of a chunk file or directory may have covered pending
    /// chunks' directory entries, and a later flush of the same directory proves nothing about
    /// them: the store is poisoned until recovery rewrites them (review WP3.A1, second round, L2).
    fn poison_if_balanced(&self) {
        if self.durability == ChunkDurability::Balanced {
            self.poison();
        }
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

    /// Moves a chunk's files into the pocket's quarantine folder. Unreadable content is kept
    /// for inspection, never deleted (review WP3.A1 M5); the chunk's name is then free for a
    /// fresh write.
    fn quarantine_pair(&self, pocket: PocketId, chunk: ChunkRef) -> Result<(), ChunkError> {
        let _shared = self.rotation_shared(pocket);
        let dir = self.pocket_dir(pocket).join(QUARANTINE_DIR);
        self.fs.create_dir_all(&dir).map_err(storage)?;
        let mut tag = [0u8; 8];
        self.rng.fill(&mut tag).map_err(ChunkError::Platform)?;
        let tag = hex(&tag);
        let name = hex(chunk.as_bytes());
        for (path, ext) in [
            (self.key_path(pocket, chunk), "key"),
            (self.chunk_path(pocket, chunk), "chunk"),
        ] {
            match self.fs.rename(&path, &dir.join(format!("{name}.{tag}.{ext}"))) {
                Ok(()) | Err(FsError::NotFound { .. }) => {}
                Err(e) => return Err(storage(e)),
            }
        }
        // The new entries are made durable now, before any later flush of `data/` or `keys/`
        // can make their removal there durable (third round, L1).
        if let Err(e) = self.fs.sync_dir(&dir) {
            self.poison_if_balanced();
            return Err(storage(e));
        }
        Ok(())
    }

    fn remember(&self, key: Key) {
        let mut known = locked(&self.known);
        if known.len() >= MAX_KNOWN {
            known.clear();
            // Chunks this process wrote now look new to `put`: every put reads back from now on.
            *locked(&self.earlier) = None;
        }
        known.insert(key);
    }

    fn forget(&self, key: Key) {
        locked(&self.known).remove(&key);
        locked(&self.pending).remove(&key);
    }

    /// Reads a chunk back and classifies the result. Keyring and storage failures are reported
    /// as such: they are never evidence that the content is lost.
    fn probe(&self, pocket: PocketId, chunk: ChunkRef) -> Probe {
        let key_bytes = match self.fs.read(&self.key_path(pocket, chunk)) {
            Ok(b) => b,
            Err(FsError::NotFound { .. }) => return Probe::Absent,
            Err(e) => return Probe::Failed(storage(e)),
        };
        let Some((version, nonce, wrapped)) = format::decode_key(&key_bytes) else {
            return Probe::Lost(LossCause::Short);
        };
        let kek = match self.keys.kek(pocket, version) {
            Ok(k) => k,
            Err(e) => return Probe::Failed(ChunkError::Keyring(e)),
        };
        let Ok(raw) = open(&kek, &nonce, &format::key_aad(pocket, chunk, version), wrapped) else {
            return Probe::Lost(LossCause::Unauthentic);
        };
        let Ok(raw) = <[u8; KEY_LEN]>::try_from(raw.as_slice()) else {
            return Probe::Lost(LossCause::Unauthentic);
        };
        let data_key = SecretKey::from_bytes(raw);
        let bytes = match self.fs.read(&self.chunk_path(pocket, chunk)) {
            Ok(b) => b,
            Err(FsError::NotFound { .. }) => return Probe::Lost(LossCause::Missing),
            Err(e) => return Probe::Failed(storage(e)),
        };
        let Some((nonce, sealed)) = format::decode_chunk(&bytes) else {
            return Probe::Lost(LossCause::Short);
        };
        let Ok(content) = open(&data_key, &nonce, &format::chunk_aad(pocket, chunk), sealed) else {
            return Probe::Lost(LossCause::Unauthentic);
        };
        match self.reference(pocket, &content) {
            Ok(r) if r == chunk => Probe::Readable { content, data_key },
            Ok(_) => Probe::Lost(LossCause::Unauthentic),
            Err(e) => Probe::Failed(e),
        }
    }

    /// Whether `chunk` is stored in `pocket` and readable. A chunk this process wrote is
    /// answered from memory. Any other is read back and, if readable, rewritten (flushed) and
    /// remembered, so its durability never rests on an earlier process's flushes (review WP3.A1
    /// M4). The journal asks this before it accepts a record that references the chunk (payload
    /// before record, I-02).
    ///
    /// # Errors
    /// `FlushFailed` while poisoned, `PendingFull`, storage or keyring failures. An unreadable
    /// chunk is `Ok(false)`.
    pub fn is_stored(&self, pocket: PocketId, chunk: ChunkRef) -> Result<bool, ChunkError> {
        let key = (pocket, chunk);
        let _slot = self.slot(key);
        self.check_poison()?;
        if locked(&self.known).contains(&key) {
            return Ok(true);
        }
        match self.probe(pocket, chunk) {
            Probe::Readable { content, data_key } => {
                self.prepare(pocket)?;
                self.adopt(key, &content, Some(data_key), Flush::Now)?;
                Ok(true)
            }
            Probe::Absent | Probe::Lost(_) => Ok(false),
            Probe::Failed(e) => Err(e),
        }
    }

    /// Number of chunks written in balanced mode and not yet flushed.
    #[must_use]
    pub fn pending_len(&self) -> usize {
        locked(&self.pending).len()
    }

    /// Whether the store is poisoned by a failed flush.
    #[must_use]
    pub fn is_poisoned(&self) -> bool {
        self.poison.load(Ordering::SeqCst) > self.cleared.load(Ordering::SeqCst)
    }

    /// Whether recovery has set aside lost chunks the journal has not taken yet.
    #[must_use]
    pub fn has_untaken_losses(&self) -> bool {
        !locked(&self.lost).is_empty()
    }

    /// Makes every chunk written since the last successful call durable: both files, then the
    /// pocket directories (ADR-0018). The journal calls this before it flushes its own records.
    ///
    /// # Errors
    /// `FlushFailed` if the store is already poisoned. Any storage failure poisons it: the OS
    /// may have dropped the unflushed content, so nothing is trusted until
    /// [`ChunkStore::recover_pending`] has read it back.
    pub fn sync_pending(&self) -> Result<(), ChunkError> {
        self.check_poison()?;
        let batch: Vec<Key> = locked(&self.pending).iter().copied().collect();
        if batch.is_empty() {
            return Ok(());
        }
        let result = self.flush_batch(&batch);
        if result.is_err() {
            self.poison();
        }
        result
    }

    fn flush_batch(&self, batch: &[Key]) -> Result<(), ChunkError> {
        let mut pockets = BTreeSet::new();
        let mut flushed = Vec::with_capacity(batch.len());
        for &key in batch {
            // Slot, then rotation shared: the order every chunk operation uses, so a rotation's
            // re-wraps never overlap this flush and no lock cycle is possible.
            let _slot = self.slot(key);
            let _shared = self.rotation_shared(key.0);
            if !locked(&self.pending).contains(&key) {
                // Shredded or quarantined since the batch was taken, under the same slot.
                continue;
            }
            for path in [self.chunk_path(key.0, key.1), self.key_path(key.0, key.1)] {
                // A pending chunk's files are removed only under its slot, which also removes
                // it from `pending`: a missing file here is a failure, never success.
                self.fs.sync_file(&path).map_err(storage)?;
            }
            pockets.insert(key.0);
            flushed.push(key);
        }
        for pocket in pockets {
            self.fs.sync_dir(&self.data_dir(pocket)).map_err(storage)?;
            self.fs.sync_dir(&self.key_dir(pocket)).map_err(storage)?;
        }
        let mut pending = locked(&self.pending);
        for key in &flushed {
            pending.remove(key);
        }
        Ok(())
    }

    /// After a failed flush: reads every pending chunk back. A readable chunk is **rewritten**
    /// to a new file and flushed, because a second flush of the file whose flush failed proves
    /// nothing (review WP3.A1 H4). An unreadable chunk is quarantined and set aside for
    /// [`ChunkStore::take_lost`]; what is set aside survives a failure of this call. On success
    /// the store is no longer poisoned.
    ///
    /// # Errors
    /// Storage or keyring failures; the store then stays poisoned.
    pub fn recover_pending(&self) -> Result<(), ChunkError> {
        let seen = self.poison.load(Ordering::SeqCst);
        let batch: Vec<Key> = locked(&self.pending).iter().copied().collect();
        for key in batch {
            let _slot = self.slot(key);
            if !locked(&self.pending).contains(&key) {
                continue;
            }
            let cause = match self.probe(key.0, key.1) {
                Probe::Readable { content, data_key } => {
                    self.write_pair(key.0, key.1, &content, Some(data_key), Flush::Now)?;
                    locked(&self.pending).remove(&key);
                    continue;
                }
                Probe::Absent => LossCause::Missing,
                Probe::Lost(cause) => cause,
                Probe::Failed(e) => return Err(e),
            };
            // Set aside first: from here on the loss is remembered whatever fails next.
            locked(&self.lost).push(LostChunk {
                pocket: key.0,
                chunk: key.1,
                cause,
            });
            self.forget(key);
            self.quarantine_pair(key.0, key.1)?;
        }
        self.cleared.fetch_max(seen, Ordering::SeqCst);
        Ok(())
    }

    /// Takes the chunks recovery found lost. The caller must report each (the journal writes a
    /// `chunk.lost` record, and holds its durable point back until it has).
    #[must_use]
    pub fn take_lost(&self) -> Vec<LostChunk> {
        std::mem::take(&mut *locked(&self.lost))
    }

    /// At startup, before the journal makes a previous run's records durable: reads each
    /// referenced chunk back. Readable chunks are rewritten to new files and flushed, so their
    /// durability never rests on the previous run's flushes; unreadable ones are set aside for
    /// [`ChunkStore::take_lost`], then quarantined (ADR-0018 §3). What is set aside survives a
    /// failure of this call. `refs` may contain duplicates.
    ///
    /// # Errors
    /// Storage or keyring failures. A chunk whose KEK cannot be loaded is a failure, never a
    /// loss: its files are left untouched.
    pub fn verify_and_sync(&self, refs: &[(PocketId, ChunkRef)]) -> Result<(), ChunkError> {
        let unique: BTreeSet<Key> = refs.iter().copied().collect();
        for key in unique {
            let _slot = self.slot(key);
            let cause = match self.probe(key.0, key.1) {
                Probe::Readable { content, data_key } => {
                    self.prepare(key.0)?;
                    self.write_pair(key.0, key.1, &content, Some(data_key), Flush::Now)?;
                    locked(&self.pending).remove(&key);
                    self.remember(key);
                    continue;
                }
                Probe::Absent => LossCause::Missing,
                Probe::Lost(cause) => cause,
                Probe::Failed(e) => return Err(e),
            };
            // Set aside first: from here on the loss is remembered whatever fails next (review
            // WP3.A1, second round, L3).
            locked(&self.lost).push(LostChunk {
                pocket: key.0,
                chunk: key.1,
                cause,
            });
            self.forget(key);
            self.quarantine_pair(key.0, key.1)?;
        }
        Ok(())
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
        // Held shared, so a rotation cannot destroy the KEK between reading the key file and
        // unwrapping it, which would report existing content as unavailable.
        let _shared = self.rotation_shared(pocket);
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
    /// durable marker of an unfinished shred. After a crash, [`ChunkStore::open`] finishes the
    /// rotation and the journal completes the shred it recorded. Deleting first would let a crash
    /// leave the files gone but the old KEK alive, so a backup of the key file would still
    /// unwrap.
    ///
    /// The caller journals a `chunk.shredded` record naming the chunk in metadata key `chunk`
    /// (never in `payload_ref`: the content is gone), so recovery does not report a record that
    /// referenced it as lost. It writes and flushes that record **before** calling `shred`
    /// (write-ahead): a record written after could be lost to power while the shred is not, and
    /// the references to the removed content would then be unexplained. A shred that fails after
    /// its record is retried; the record already covers whatever it removed.
    ///
    /// A store that a journal coordinates refuses this call: the shred must go through
    /// [`crate::journal::Journal::shred`], which records it, flushes the record and shreds while
    /// no other record can be appended (review WP3.A1, third round, H1).
    ///
    /// # Errors
    /// `ShredThroughJournal` if a journal coordinates the store; storage or keyring failures. The
    /// shred is acknowledged only by `Ok`; after an error the caller retries, and a crash is
    /// completed on the next open.
    pub fn shred(&self, pocket: PocketId, chunk: ChunkRef) -> Result<ShredReport, ChunkError> {
        if self.attached.load(Ordering::SeqCst) {
            return Err(ChunkError::ShredThroughJournal);
        }
        self.shred_now(pocket, chunk)
    }

    /// Whether a shred of `chunk` may be unfinished: a file of the pair remains, or the pocket
    /// has more than one KEK version (a rotation that did not finish).
    ///
    /// # Errors
    /// Storage or keyring failures.
    pub fn shred_incomplete(&self, pocket: PocketId, chunk: ChunkRef) -> Result<bool, ChunkError> {
        for path in [self.key_path(pocket, chunk), self.chunk_path(pocket, chunk)] {
            match self.fs.read(&path) {
                Ok(_) => return Ok(true),
                Err(FsError::NotFound { .. }) => {}
                Err(e) => return Err(storage(e)),
            }
        }
        Ok(self.keys.kek_versions(pocket).map_err(ChunkError::Keyring)?.len() > 1)
    }

    /// The shred itself (see [`ChunkStore::shred`]); the journal calls it once the record is
    /// durable.
    pub(crate) fn shred_now(&self, pocket: PocketId, chunk: ChunkRef) -> Result<ShredReport, ChunkError> {
        self.prepare(pocket)?;
        let key = (pocket, chunk);
        // Slot first, then rotation: the same order as a put, so the two never deadlock.
        let _slot = self.slot(key);
        let _exclusive = self.rotation_exclusive(pocket);
        self.keys.rotate_kek(pocket).map_err(ChunkError::Keyring)?;
        // Forgotten before any file goes: if a removal then fails, a later put rewrites the
        // chunk instead of vouching for it from memory.
        self.forget(key);
        let mut removed = false;
        for path in [self.key_path(pocket, chunk), self.chunk_path(pocket, chunk)] {
            match self.fs.remove_file(&path) {
                Ok(()) => removed = true,
                Err(FsError::NotFound { .. }) => {}
                Err(e) => return Err(storage(e)),
            }
        }
        for dir in [self.key_dir(pocket), self.data_dir(pocket)] {
            if let Err(e) = self.fs.sync_dir(&dir) {
                self.poison_if_balanced();
                return Err(storage(e));
            }
        }
        let rewrapped = self.finish_rotation(pocket)?;
        let (kek_version, _) = self.keys.current_kek(pocket).map_err(ChunkError::Keyring)?;
        Ok(ShredReport {
            removed,
            rewrapped,
            kek_version,
        })
    }

    /// Re-wraps every data key still under an older KEK version, then destroys the older
    /// versions. No-op when only one version exists. Re-wraps are flushed in either durability
    /// mode: the old versions are destroyed right after, so an unflushed re-wrap lost to a power
    /// loss would leave a key file only a destroyed KEK can open. Runs at open (no other user
    /// yet) or inside [`ChunkStore::shred`] (holding rotation exclusively). Returns the number
    /// of re-wrapped keys.
    ///
    /// It never creates a KEK: a pocket whose keys are gone from the keychain (a reset, a moved
    /// data directory) must fail closed when its chunks are read, not get a fresh version 1
    /// under which every existing key file looks tampered with (review WP3.A1 M5).
    fn finish_rotation(&self, pocket: PocketId) -> Result<usize, ChunkError> {
        let versions = self.keys.kek_versions(pocket).map_err(ChunkError::Keyring)?;
        if versions.len() <= 1 {
            return Ok(0);
        }
        let (current, kek) = self.keys.current_kek(pocket).map_err(ChunkError::Keyring)?;
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
        Ok(rewrapped)
    }
}
