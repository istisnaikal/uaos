// SPDX-License-Identifier: Apache-2.0

//! The single journal writer.
//!
//! Durability (ADR-0003):
//! * [`Journal::append`] returns after the record's bytes are **handed to the OS**: it survives
//!   a process crash (kill -9). This is the `critical` acknowledgement point.
//! * Power-loss durability follows [`FlushPolicy`]: `Balanced` flushes once the window has
//!   elapsed since the last flush (and on [`Journal::sync`]); `Strict` flushes before every
//!   acknowledgement.
//! * A failed flush is never retried in place (the OS may have dropped the unflushed pages
//!   while reporting later flushes as successful). The writer seals the segment at its last
//!   flushed record, rewrites every unflushed record to a fresh segment, flushes it and
//!   records the switch in the manifest. If any step fails, the writer stops.
//! * Disk full: the segment may end in a torn record, so the writer refuses all appends until
//!   [`Journal::recover`] has moved to a fresh segment.
//!
//! Recovery on [`Journal::open`] verifies the whole chain, seals the previously active segment
//! at its last complete record, quarantines segment files the manifest does not list, and
//! starts a new segment. It never appends after a possibly torn tail.

use std::path::{Path, PathBuf};
use std::sync::Arc;

use uaos_contracts::digest::{ChunkRef, Sha256Digest};
use uaos_contracts::event::{Actor, Durability, EventEnvelope, EventSchema, EventType, InlinePayload, Metadata};
use uaos_contracts::id::{CorrelationId, EventId, OperationId, PocketId, RequestId, SessionId, TypedId};
use uaos_contracts::limits;
use uaos_contracts::money::NanoUsd;
use uaos_contracts::operation::{RiskTier, SideEffectClass};
use uaos_contracts::time::EventTime;
use uaos_contracts::wire::{ConfigVersion, Seq};
use uaos_platform::crypto::sha256;
use uaos_platform::fs::{AppendFile, Fs, FsError, LockGuard};
use uaos_platform::{Clock, Rng};

use super::JournalError;
use super::manifest::{
    Manifest, ManifestSchema, READER_VERSION, SegmentEntry, SegmentStatus, is_segment_file_name, segment_file_name,
};
use super::scan::{genesis_hash, read_verified};

/// Name of the data-directory lock file.
pub const LOCK_FILE: &str = "uaos.lock";
/// Name of the journal directory inside the data directory.
pub const JOURNAL_DIR: &str = "journal";

/// When acknowledged records are flushed to stable storage.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FlushPolicy {
    /// Flush when at least `window` has passed since the last flush (default W = 50 ms).
    Balanced {
        /// Maximum power-loss window.
        window: limits::Millis,
    },
    /// Flush before every acknowledgement.
    Strict,
}

impl Default for FlushPolicy {
    fn default() -> Self {
        Self::Balanced {
            window: limits::DEFAULT_FLUSH_WINDOW,
        }
    }
}

/// Everything about a record except what the journal itself assigns (identifier, sequence
/// number, timestamp and chain link), so callers cannot forge the chain.
#[derive(Debug, Clone, PartialEq)]
pub struct EventDraft {
    /// Session, if any.
    pub session_id: Option<SessionId>,
    /// Pocket, if any.
    pub pocket_id: Option<PocketId>,
    /// Operation, if any.
    pub operation_id: Option<OperationId>,
    /// Ingress request, if any.
    pub request_id: Option<RequestId>,
    /// Correlation identifier.
    pub correlation_id: CorrelationId,
    /// Causing event, if any.
    pub parent_id: Option<EventId>,
    /// Who caused it.
    pub actor: Actor,
    /// Namespaced type.
    pub event_type: EventType,
    /// Encrypted content chunk, if any.
    pub payload_ref: Option<ChunkRef>,
    /// Small metadata-only payload.
    pub payload_inline: Option<InlinePayload>,
    /// Estimated cost, if any.
    pub cost_estimate: Option<NanoUsd>,
    /// Whether the related effect is compensable.
    pub compensable: bool,
    /// Reach of the related effect.
    pub side_effect_class: SideEffectClass,
    /// Risk tier.
    pub risk_tier: RiskTier,
    /// Durability class requested by the caller.
    pub durability: Durability,
    /// Configuration snapshot in force.
    pub config_version: ConfigVersion,
    /// Bounded labels.
    pub metadata: Metadata,
}

/// Acknowledgement of an appended record.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Appended {
    /// Assigned sequence number.
    pub seq: Seq,
    /// Assigned identifier.
    pub id: EventId,
    /// Chain hash of the stored line.
    pub hash: Sha256Digest,
}

/// Writer state. Anything but `Healthy` refuses new records (fail closed) until
/// [`Journal::recover`] succeeds.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum JournalHealth {
    /// Accepting records.
    Healthy,
    /// The device filled up; the active segment may end in a torn record.
    DiskFull,
    /// A write failed for another reason; the active segment may end in a torn record.
    WriteFailed,
    /// A flush failed and rewriting the unflushed records also failed. Records after
    /// [`Journal::flushed_through`] now exist **only in this process's memory** (the OS dropped
    /// its copy): `recover` retries the rewrite; a crash before it succeeds loses them. This is
    /// reported, never hidden (S2).
    FlushFailed,
}

/// The journal writer. Exactly one exists per data directory (enforced by an OS lock).
#[derive(Debug)]
pub struct Journal {
    fs: Arc<dyn Fs>,
    clock: Arc<dyn Clock>,
    rng: Arc<dyn Rng>,
    dir: PathBuf,
    _lock: Box<dyn LockGuard>,
    manifest: Manifest,
    active: Box<dyn AppendFile>,
    active_bytes: u64,
    next_seq: u64,
    head: Sha256Digest,
    /// Lines appended since the last successful flush, in order, starting at `unflushed_first`.
    unflushed: Vec<Vec<u8>>,
    unflushed_first: u64,
    /// Last record known durable (seq, hash), if any.
    last_flushed: Option<(u64, Sha256Digest)>,
    last_flush_mono: u64,
    flush: FlushPolicy,
    health: JournalHealth,
}

fn storage(e: FsError) -> JournalError {
    match e {
        FsError::NoSpace { .. } => JournalError::DiskFull,
        other => JournalError::Storage(other),
    }
}

impl Journal {
    /// Opens (or creates) the journal in `data_dir`, taking the data-directory lock and
    /// recovering from any previous crash.
    ///
    /// # Errors
    /// `InstanceLocked` if another daemon owns the directory; `Corrupt`/`ChainBroken` if the
    /// existing journal does not verify (nothing is modified in that case); storage errors.
    pub fn open(
        fs: Arc<dyn Fs>,
        clock: Arc<dyn Clock>,
        rng: Arc<dyn Rng>,
        data_dir: &Path,
        flush: FlushPolicy,
    ) -> Result<Self, JournalError> {
        let dir = data_dir.join(JOURNAL_DIR);
        fs.create_dir_all(&dir).map_err(storage)?;
        let lock = fs.try_lock_exclusive(&data_dir.join(LOCK_FILE)).map_err(|e| match e {
            FsError::Locked { .. } => JournalError::InstanceLocked,
            other => storage(other),
        })?;

        let manifest_exists = match fs.read(&Manifest::path(&dir)) {
            Ok(_) => true,
            Err(FsError::NotFound { .. }) => false,
            Err(e) => return Err(storage(e)),
        };

        let (mut manifest, next_seq, head, last_flushed) = if manifest_exists {
            let (_, report) = read_verified(fs.as_ref(), &dir)?;
            let mut manifest = Manifest::load(fs.as_ref(), &dir)?;
            quarantine_orphans(fs.as_ref(), &dir, &manifest)?;
            // The previous process may have acknowledged records the OS holds but never
            // flushed. Flush them BEFORE the manifest seals the segment around them: a durable
            // manifest must never claim records a power loss could still take away.
            if let Some(active) = manifest.active() {
                let mut previous = fs.open_append(&dir.join(&active.file)).map_err(storage)?;
                previous.sync_data().map_err(|_| JournalError::Stopped)?;
            }
            // Seal the previously active segment at its last complete, verified record.
            if let Some(active) = manifest.segments.last_mut() {
                active.status = SegmentStatus::Sealed;
                if report.next_seq > active.first_seq.0 {
                    active.last_seq = Some(Seq(report.next_seq - 1));
                    active.last_hash = Some(report.head);
                }
            }
            let last = report.next_seq.checked_sub(1).map(|s| (s, report.head));
            (manifest, report.next_seq, report.head, last)
        } else {
            if fs
                .list_dir(&dir)
                .map_err(storage)?
                .iter()
                .any(|p| p.file_name().and_then(|n| n.to_str()).is_some_and(is_segment_file_name))
            {
                return Err(JournalError::Corrupt(
                    "segment files exist but the manifest is missing; refusing to start a new history over them"
                        .to_owned(),
                ));
            }
            let mut id = [0u8; 16];
            rng.fill(&mut id).map_err(JournalError::Platform)?;
            let journal_id = id.iter().fold(String::with_capacity(32), |mut acc, b| {
                use std::fmt::Write as _;
                // Writing to a String cannot fail.
                let _infallible = write!(acc, "{b:02x}");
                acc
            });
            let head = genesis_hash(&journal_id);
            let manifest = Manifest {
                schema: ManifestSchema::V1,
                journal_id,
                min_reader_version: READER_VERSION,
                generation: 0,
                segments: Vec::new(),
            };
            (manifest, 0, head, None)
        };

        let active = start_segment(fs.as_ref(), &dir, &mut manifest, next_seq)?;
        let last_flush_mono = clock.mono().0;
        Ok(Self {
            fs,
            clock,
            rng,
            dir,
            _lock: lock,
            manifest,
            active,
            active_bytes: 0,
            next_seq,
            head,
            unflushed: Vec::new(),
            unflushed_first: next_seq,
            last_flushed,
            last_flush_mono,
            flush,
            health: JournalHealth::Healthy,
        })
    }

    /// Next sequence number to be assigned.
    #[must_use]
    pub fn next_seq(&self) -> Seq {
        Seq(self.next_seq)
    }

    /// The last record known to be durable against power loss, if any.
    #[must_use]
    pub fn flushed_through(&self) -> Option<Seq> {
        self.last_flushed.map(|(seq, _)| Seq(seq))
    }

    /// Chain hash of the last appended record.
    #[must_use]
    pub fn head(&self) -> Sha256Digest {
        self.head
    }

    /// Appends a record and returns once the OS holds it (see the module docs for the
    /// durability contract and the meaning of an error).
    ///
    /// # Errors
    /// `DiskFull`, `Stopped`, `Write`, `LineTooLarge`, `Platform`, `Encoding`.
    pub fn append(&mut self, draft: EventDraft) -> Result<Appended, JournalError> {
        match self.health {
            JournalHealth::Healthy => {}
            JournalHealth::DiskFull => return Err(JournalError::DiskFull),
            JournalHealth::WriteFailed | JournalHealth::FlushFailed => return Err(JournalError::Stopped),
        }
        let wall = self.clock.wall().map_err(JournalError::Platform)?;
        let mut random = [0u8; 10];
        self.rng.fill(&mut random).map_err(JournalError::Platform)?;
        let id = EventId::from_parts(wall.unix_millis_saturating(), random);
        let envelope = EventEnvelope {
            schema: EventSchema::V1,
            id,
            seq: Seq(self.next_seq),
            ts: EventTime {
                wall,
                mono_ns: self.clock.mono(),
            },
            session_id: draft.session_id,
            pocket_id: draft.pocket_id,
            operation_id: draft.operation_id,
            request_id: draft.request_id,
            correlation_id: draft.correlation_id,
            parent_id: draft.parent_id,
            actor: draft.actor,
            event_type: draft.event_type,
            payload_ref: draft.payload_ref,
            payload_inline: draft.payload_inline,
            cost_estimate: draft.cost_estimate,
            compensable: draft.compensable,
            side_effect_class: draft.side_effect_class,
            risk_tier: draft.risk_tier,
            durability: draft.durability,
            config_version: draft.config_version,
            prev_hash: self.head,
            metadata: draft.metadata,
        };
        let mut line = serde_json::to_vec(&envelope).map_err(|e| JournalError::Encoding(e.to_string()))?;
        line.push(b'\n');
        if !limits::MAX_JOURNAL_LINE.admits(line.len()) {
            return Err(JournalError::LineTooLarge);
        }
        let line_len = u64::try_from(line.len()).unwrap_or(u64::MAX);
        if self.active_bytes > 0 && self.active_bytes.saturating_add(line_len) > limits::JOURNAL_SEGMENT_TARGET.0 {
            self.rotate()?;
        }

        match self.active.append(&line) {
            Ok(()) => {}
            Err(FsError::NoSpace { .. }) => {
                self.health = JournalHealth::DiskFull;
                return Err(JournalError::DiskFull);
            }
            Err(e) => {
                self.health = JournalHealth::WriteFailed;
                return Err(JournalError::Write(e));
            }
        }
        let hash = sha256(&line);
        let seq = self.next_seq;
        self.head = hash;
        self.next_seq += 1;
        self.active_bytes = self.active_bytes.saturating_add(line_len);
        if self.unflushed.is_empty() {
            self.unflushed_first = seq;
        }
        self.unflushed.push(line);

        let due = match self.flush {
            FlushPolicy::Strict => true,
            FlushPolicy::Balanced { window } => {
                self.clock.mono().0.saturating_sub(self.last_flush_mono) >= window.as_nanos()
            }
        };
        if due {
            self.sync()?;
        }
        Ok(Appended {
            seq: Seq(seq),
            id,
            hash,
        })
    }

    /// Flushes every acknowledged record to stable storage. On a failed flush, rewrites the
    /// unflushed records to a fresh segment; if that fails too, the writer enters
    /// [`JournalHealth::FlushFailed`].
    ///
    /// # Errors
    /// `Stopped` if the flush and its recovery both failed (or already had); `DiskFull` if the
    /// recovery ran out of space.
    pub fn sync(&mut self) -> Result<(), JournalError> {
        if self.health == JournalHealth::FlushFailed {
            return Err(JournalError::Stopped);
        }
        if self.unflushed.is_empty() {
            return Ok(());
        }
        match self.active.sync_data() {
            Ok(()) => {
                self.mark_flushed();
                Ok(())
            }
            Err(_) => self.rewrite_unflushed(),
        }
    }

    /// Current writer state.
    #[must_use]
    pub fn health(&self) -> JournalHealth {
        self.health
    }

    /// Returns the writer to `Healthy` once the cause is gone: after a disk-full or write
    /// failure it flushes what was acknowledged, seals the segment (excluding any torn tail)
    /// and continues in a fresh one; after a flush failure it retries rewriting the
    /// memory-only records to a fresh segment.
    ///
    /// # Errors
    /// `DiskFull` if there is still no space; `Stopped` if a flush still cannot be recovered.
    pub fn recover(&mut self) -> Result<(), JournalError> {
        match self.health {
            JournalHealth::Healthy => Ok(()),
            JournalHealth::DiskFull | JournalHealth::WriteFailed => {
                self.rotate()?;
                self.health = JournalHealth::Healthy;
                Ok(())
            }
            JournalHealth::FlushFailed => {
                self.rewrite_unflushed()?;
                self.health = JournalHealth::Healthy;
                Ok(())
            }
        }
    }

    fn mark_flushed(&mut self) {
        if self.next_seq > 0 && !self.unflushed.is_empty() {
            self.last_flushed = Some((self.next_seq - 1, self.head));
        }
        self.unflushed.clear();
        self.unflushed_first = self.next_seq;
        self.last_flush_mono = self.clock.mono().0;
    }

    /// Normal rotation: flush, seal at the last appended record, continue in a new segment.
    fn rotate(&mut self) -> Result<(), JournalError> {
        self.sync()?;
        let saved = self.manifest.clone();
        let last = self.next_seq.checked_sub(1).map(|s| (s, self.head));
        self.seal_active(SegmentStatus::Sealed, last);
        match start_segment(self.fs.as_ref(), &self.dir, &mut self.manifest, self.next_seq) {
            Ok(file) => {
                self.active = file;
                self.active_bytes = 0;
                Ok(())
            }
            Err(e) => {
                // The manifest on disk still lists the old segment as active, so memory must too.
                self.restore_manifest(saved);
                if self.health == JournalHealth::Healthy {
                    self.health = if e == JournalError::DiskFull {
                        JournalHealth::DiskFull
                    } else {
                        JournalHealth::WriteFailed
                    };
                }
                Err(e)
            }
        }
    }

    /// Rolls the in-memory manifest back to `saved` while keeping the generation counter, so a
    /// retry never reuses the name of a file created by the failed attempt (that file is
    /// quarantined as an orphan on the next open).
    fn restore_manifest(&mut self, saved: Manifest) {
        let generation = self.manifest.generation;
        self.manifest = saved;
        self.manifest.generation = generation;
    }

    /// Records the active segment's final range in the in-memory manifest.
    fn seal_active(&mut self, status: SegmentStatus, last: Option<(u64, Sha256Digest)>) {
        if let Some(active) = self.manifest.segments.last_mut() {
            active.status = status;
            if let Some((seq, hash)) = last.filter(|(seq, _)| *seq >= active.first_seq.0) {
                active.last_seq = Some(Seq(seq));
                active.last_hash = Some(hash);
            } else {
                active.last_seq = None;
                active.last_hash = None;
            }
        }
    }

    /// Recovery from a failed flush (see module docs).
    fn rewrite_unflushed(&mut self) -> Result<(), JournalError> {
        let saved = self.manifest.clone();
        let result: Result<(Box<dyn AppendFile>, u64), JournalError> = (|| {
            self.seal_active(SegmentStatus::Suspect, self.last_flushed);
            let mut fresh = start_segment_file(self.fs.as_ref(), &self.dir, &mut self.manifest, self.unflushed_first)?;
            for line in &self.unflushed {
                fresh.append(line).map_err(storage)?;
            }
            fresh.sync_data().map_err(|_| JournalError::Stopped)?;
            self.fs.sync_dir(&self.dir).map_err(|_| JournalError::Stopped)?;
            self.manifest.store(self.fs.as_ref(), &self.dir)?;
            let bytes: u64 = self
                .unflushed
                .iter()
                .map(|l| u64::try_from(l.len()).unwrap_or(u64::MAX))
                .sum();
            Ok((fresh, bytes))
        })();
        match result {
            Ok((fresh, bytes)) => {
                self.active = fresh;
                self.active_bytes = bytes;
                self.mark_flushed();
                Ok(())
            }
            Err(e) => {
                self.restore_manifest(saved);
                self.health = JournalHealth::FlushFailed;
                Err(if e == JournalError::DiskFull {
                    JournalError::DiskFull
                } else {
                    JournalError::Stopped
                })
            }
        }
    }
}

/// Creates a segment file starting at `first_seq`, makes its directory entry durable and
/// records it in the in-memory manifest (not yet stored).
fn start_segment_file(
    fs: &dyn Fs,
    dir: &Path,
    manifest: &mut Manifest,
    first_seq: u64,
) -> Result<Box<dyn AppendFile>, JournalError> {
    manifest.generation += 1;
    let name = segment_file_name(first_seq, manifest.generation);
    let file = fs.open_append(&dir.join(&name)).map_err(storage)?;
    fs.sync_dir(dir).map_err(storage)?;
    manifest.segments.push(SegmentEntry {
        file: name,
        first_seq: Seq(first_seq),
        last_seq: None,
        last_hash: None,
        status: SegmentStatus::Active,
    });
    Ok(file)
}

/// Creates a new active segment and stores the manifest.
fn start_segment(
    fs: &dyn Fs,
    dir: &Path,
    manifest: &mut Manifest,
    first_seq: u64,
) -> Result<Box<dyn AppendFile>, JournalError> {
    let file = start_segment_file(fs, dir, manifest, first_seq)?;
    manifest.store(fs, dir)?;
    Ok(file)
}

/// Renames segment files the manifest does not list (left by a crash between creating a
/// segment and recording it) so they can never be mistaken for, or collide with, live ones.
/// Their records were never acknowledged. They are kept, not deleted, for forensics.
fn quarantine_orphans(fs: &dyn Fs, dir: &Path, manifest: &Manifest) -> Result<(), JournalError> {
    let listed: std::collections::BTreeSet<&str> = manifest.segments.iter().map(|s| s.file.as_str()).collect();
    for path in fs.list_dir(dir).map_err(storage)? {
        let Some(name) = path.file_name().and_then(|n| n.to_str()) else {
            continue;
        };
        if is_segment_file_name(name) && !listed.contains(name) {
            let target = dir.join(format!("{name}.orphan-g{}", manifest.generation));
            fs.rename(&path, &target).map_err(storage)?;
        }
    }
    fs.sync_dir(dir).map_err(storage)
}
