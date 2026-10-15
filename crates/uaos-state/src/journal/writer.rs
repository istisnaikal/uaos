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
//!
//! **Payloads (ADR-0018).** A journal opened with [`Journal::open_with_payloads`] coordinates
//! the chunk store's durability with its own:
//! * a record that references a chunk is accepted only once the chunk is stored (I-02);
//! * every flush makes the store's pending chunks durable **before** the segment, so a record
//!   is durable only once its payload is; a failed payload flush stops the writer
//!   ([`JournalHealth::PayloadFlushFailed`]) until [`Journal::recover`] has read the pending
//!   chunks back;
//! * after each flush a small marker (`FLUSHED`) records the durable point, itself made durable
//!   at most once per second. On open, the payloads of every record after the durable point are
//!   read back and flushed before the previous run's records are made durable. An unreadable
//!   one is reported by a `chunk.lost` record, never silently ([`Journal::lost_payloads`]).

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use uaos_contracts::digest::{ChunkRef, Sha256Digest};
use uaos_contracts::event::{Actor, Durability, EventEnvelope, EventSchema, EventType, InlinePayload, Metadata, types};
use uaos_contracts::id::{CorrelationId, EventId, OperationId, PocketId, RequestId, SessionId, TypedId};
use uaos_contracts::limits;
use uaos_contracts::money::NanoUsd;
use uaos_contracts::operation::{RiskTier, SideEffectClass};
use uaos_contracts::time::EventTime;
use uaos_contracts::wire::{ConfigVersion, Seq};
use uaos_platform::crypto::sha256;
use uaos_platform::fs::{AppendFile, Fs, FsError, LockGuard, is_temp_file_name};
use uaos_platform::{Clock, Rng};

use super::JournalError;
use super::manifest::{
    Manifest, ManifestSchema, READER_VERSION, SegmentEntry, SegmentStatus, is_segment_file_name, segment_file_name,
};
use super::scan::{VerifiedRecord, genesis_hash, read_verified};
use crate::chunks::ChunkStore;

/// Name of the data-directory lock file.
pub const LOCK_FILE: &str = "uaos.lock";
/// Name of the journal directory inside the data directory.
pub const JOURNAL_DIR: &str = "journal";
/// Name of the durable-point marker inside the journal directory (ADR-0018).
pub const FLUSH_MARKER: &str = "FLUSHED";
/// First word of the marker's single line: `uaos.flushed/1 <seq> <hash>`.
const MARKER_PREFIX: &str = "uaos.flushed/1";
/// How often the marker itself is made durable. It bounds how much of the tail recovery reads
/// back, never what recovery reports.
const MARKER_SYNC_INTERVAL: limits::Millis = limits::Millis(1_000);
/// Metadata key that names the chunk a `chunk.lost` or `chunk.shredded` record is about. Such
/// records never set `payload_ref`: the payload is gone.
pub const CHUNK_METADATA_KEY: &str = "chunk";

/// A payload that a record references and that could not be read back (ADR-0018 §3). The
/// record stands; the loss is journaled as a `chunk.lost` record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LostPayload {
    /// The record that references the payload.
    pub record_seq: Seq,
    /// Its Operation, if any.
    pub operation_id: Option<OperationId>,
    /// The pocket the chunk belonged to.
    pub pocket: PocketId,
    /// The lost chunk.
    pub chunk: ChunkRef,
}

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
    /// Flushing the attached chunk store failed. Records after [`Journal::flushed_through`] are
    /// not durable, and the OS may have dropped some of their payloads. `recover` reads the
    /// pending chunks back, reports the unreadable ones and flushes (ADR-0018).
    PayloadFlushFailed,
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
    /// The chunk store whose durability this journal coordinates (ADR-0018), if any.
    payloads: Option<Arc<ChunkStore>>,
    /// A newer marker was written and is not yet durable.
    marker_dirty: bool,
    last_marker_sync_mono: u64,
    /// Payloads reported lost since this journal was opened.
    lost: Vec<LostPayload>,
    /// Losses found but not yet journaled; kept across failures until their records are written.
    unreported: Vec<(LostPayload, EventEnvelope)>,
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
        Self::open_inner(fs, clock, rng, data_dir, flush, None)
    }

    /// Like [`Journal::open`], with the chunk store whose durability this journal coordinates
    /// (ADR-0018; see the module docs). Before the previous run's records are made durable,
    /// the payloads of every record after the last durable point are read back and flushed; an
    /// unreadable one is journaled as `chunk.lost` and listed by [`Journal::lost_payloads`].
    ///
    /// # Errors
    /// As [`Journal::open`], plus `Payload` if the store fails while it is checked.
    pub fn open_with_payloads(
        fs: Arc<dyn Fs>,
        clock: Arc<dyn Clock>,
        rng: Arc<dyn Rng>,
        data_dir: &Path,
        flush: FlushPolicy,
        payloads: Arc<ChunkStore>,
    ) -> Result<Self, JournalError> {
        Self::open_inner(fs, clock, rng, data_dir, flush, Some(payloads))
    }

    fn open_inner(
        fs: Arc<dyn Fs>,
        clock: Arc<dyn Clock>,
        rng: Arc<dyn Rng>,
        data_dir: &Path,
        flush: FlushPolicy,
        payloads: Option<Arc<ChunkStore>>,
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

        let mut lost_in_tail = Vec::new();
        let (mut manifest, next_seq, head, last_flushed) = if manifest_exists {
            let (records, report) = read_verified(fs.as_ref(), &dir)?;
            let mut manifest = Manifest::load(fs.as_ref(), &dir)?;
            quarantine_orphans(fs.as_ref(), &dir, &manifest)?;
            sweep_temporaries(fs.as_ref(), &dir)?;
            // ADR-0018 §3: the payloads of records after the last durable point must be durable
            // (or reported lost) before those records are made durable below.
            if let Some(store) = &payloads {
                lost_in_tail = recover_tail_payloads(fs.as_ref(), &dir, &manifest, &records, store)?;
            }
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
        let mut journal = Self {
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
            payloads,
            marker_dirty: false,
            last_marker_sync_mono: last_flush_mono,
            lost: Vec::new(),
            unreported: lost_in_tail,
        };
        // Everything that survived is durable now (the previous segment was flushed above).
        journal.update_marker();
        journal.report_lost()?;
        Ok(journal)
    }

    /// Payloads reported lost since this journal was opened (each also journaled as a
    /// `chunk.lost` record).
    #[must_use]
    pub fn lost_payloads(&self) -> &[LostPayload] {
        &self.lost
    }

    /// Journals one `chunk.lost` record per unreported loss, then flushes them. A loss leaves
    /// the unreported list only once its record is appended; on failure the rest stay for the
    /// next [`Journal::recover`].
    fn report_lost(&mut self) -> Result<(), JournalError> {
        if self.unreported.is_empty() {
            return Ok(());
        }
        while let Some((payload, referencing)) = self.unreported.first().cloned() {
            let metadata = Metadata::new(
                [
                    (CHUNK_METADATA_KEY.to_owned(), payload.chunk.to_string()),
                    ("record_seq".to_owned(), payload.record_seq.0.to_string()),
                ]
                .into_iter()
                .collect(),
            )
            .map_err(|e| JournalError::Encoding(e.to_string()))?;
            self.append(EventDraft {
                session_id: referencing.session_id,
                pocket_id: Some(payload.pocket),
                operation_id: referencing.operation_id,
                request_id: referencing.request_id,
                correlation_id: referencing.correlation_id,
                parent_id: Some(referencing.id),
                actor: Actor::System,
                event_type: types::CHUNK_LOST,
                payload_ref: None,
                payload_inline: None,
                cost_estimate: None,
                compensable: false,
                side_effect_class: SideEffectClass::None,
                risk_tier: referencing.risk_tier,
                durability: Durability::Critical,
                config_version: referencing.config_version,
                metadata,
            })?;
            self.unreported.remove(0);
            self.lost.push(payload);
        }
        self.sync()
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
            JournalHealth::WriteFailed | JournalHealth::FlushFailed | JournalHealth::PayloadFlushFailed => {
                return Err(JournalError::Stopped);
            }
        }
        // Payload before record (I-02, ADR-0018): a record may reference only a chunk that is
        // already with the OS, so no acknowledged record can point at content a crash removes.
        if let (Some(store), Some(chunk)) = (&self.payloads, draft.payload_ref) {
            let pocket = draft.pocket_id.ok_or(JournalError::PayloadNotStored)?;
            if !store.is_stored(pocket, chunk).map_err(JournalError::Payload)? {
                return Err(JournalError::PayloadNotStored);
            }
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
        if matches!(
            self.health,
            JournalHealth::FlushFailed | JournalHealth::PayloadFlushFailed
        ) {
            return Err(JournalError::Stopped);
        }
        if self.unflushed.is_empty() {
            return Ok(());
        }
        // ADR-0018: payloads first. A record is durable only once the payloads it references are.
        self.sync_payloads()?;
        match self.active.sync_data() {
            Ok(()) => {
                self.mark_flushed();
                self.update_marker();
                Ok(())
            }
            Err(_) => self.rewrite_unflushed(),
        }
    }

    /// Flushes the attached chunk store's pending writes. On failure the writer stops: the
    /// unflushed records' payloads may be gone, and only [`Journal::recover`] can tell.
    fn sync_payloads(&mut self) -> Result<(), JournalError> {
        if let Some(store) = &self.payloads
            && store.sync_pending().is_err()
        {
            self.health = JournalHealth::PayloadFlushFailed;
            return Err(JournalError::Stopped);
        }
        Ok(())
    }

    /// Records the durable point after a flush (journals with payloads only). The marker is
    /// written without a flush; the previous marker is made durable first, at most once per
    /// [`MARKER_SYNC_INTERVAL`]. A durable marker therefore never names a record beyond the
    /// true durable point; a missing or stale one only makes recovery read back more.
    fn update_marker(&mut self) {
        if self.payloads.is_none() {
            return;
        }
        let Some((seq, hash)) = self.last_flushed else {
            return;
        };
        let path = self.dir.join(FLUSH_MARKER);
        let now = self.clock.mono().0;
        if self.marker_dirty && now.saturating_sub(self.last_marker_sync_mono) >= MARKER_SYNC_INTERVAL.as_nanos() {
            // Best effort: a failure leaves an older durable marker, which is still correct.
            if self.fs.sync_file(&path).is_ok() && self.fs.sync_dir(&self.dir).is_ok() {
                self.last_marker_sync_mono = now;
            }
        }
        let line = format!("{MARKER_PREFIX} {seq} {hash}\n");
        if self.fs.write_unsynced(&path, line.as_bytes()).is_ok() {
            self.marker_dirty = true;
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
            JournalHealth::PayloadFlushFailed => {
                let Some(store) = self.payloads.clone() else {
                    return Err(JournalError::Stopped);
                };
                store.recover_pending().map_err(JournalError::Payload)?;
                let lost = store.take_lost();
                let referencing = self.unflushed_referencing(&lost);
                self.unreported.extend(referencing);
                self.health = JournalHealth::Healthy;
                self.sync()?;
                self.report_lost()
            }
        }
    }

    /// The unflushed records that reference any of `lost`.
    fn unflushed_referencing(&self, lost: &[(PocketId, ChunkRef)]) -> Vec<(LostPayload, EventEnvelope)> {
        let lost: BTreeSet<&(PocketId, ChunkRef)> = lost.iter().collect();
        self.unflushed
            .iter()
            .filter_map(|line| serde_json::from_slice::<EventEnvelope>(line).ok())
            .filter_map(|e| {
                let key = (e.pocket_id?, e.payload_ref?);
                if !lost.contains(&key) {
                    return None;
                }
                let payload = LostPayload {
                    record_seq: e.seq,
                    operation_id: e.operation_id,
                    pocket: key.0,
                    chunk: key.1,
                };
                Some((payload, e))
            })
            .collect()
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

/// Removes temporaries left by manifest or marker writes a crash interrupted.
fn sweep_temporaries(fs: &dyn Fs, dir: &Path) -> Result<(), JournalError> {
    for path in fs.list_dir(dir).map_err(storage)? {
        if path.file_name().and_then(|n| n.to_str()).is_some_and(is_temp_file_name) {
            match fs.remove_file(&path) {
                Ok(()) | Err(FsError::NotFound { .. }) => {}
                Err(e) => return Err(storage(e)),
            }
        }
    }
    Ok(())
}

/// The durable point named by the marker, if the marker parses and names a record that exists
/// with exactly that hash. Anything else (missing, torn, stale beyond the journal) is ignored.
fn read_marker(fs: &dyn Fs, dir: &Path, records: &[VerifiedRecord]) -> Option<u64> {
    let bytes = fs.read(&dir.join(FLUSH_MARKER)).ok()?;
    let text = std::str::from_utf8(&bytes).ok()?;
    let mut words = text.strip_suffix('\n')?.split(' ');
    if words.next()? != MARKER_PREFIX {
        return None;
    }
    let seq: u64 = words.next()?.parse().ok()?;
    let hash: Sha256Digest = words.next()?.parse().ok()?;
    if words.next().is_some() {
        return None;
    }
    records
        .iter()
        .any(|r| r.envelope.seq.0 == seq && r.hash == hash)
        .then_some(seq)
}

/// ADR-0018 §3 at startup: reads back and flushes the payloads of every record after the last
/// durable point, and returns the records whose payload is unreadable.
///
/// The durable point is the marker if it is valid; otherwise the start of the previously
/// active segment (every earlier segment was flushed, payloads first, when it was sealed). A
/// chunk shredded after the record that references it is not a loss: it is skipped when a
/// `chunk.shredded` record for it follows.
fn recover_tail_payloads(
    fs: &dyn Fs,
    dir: &Path,
    manifest: &Manifest,
    records: &[VerifiedRecord],
    store: &ChunkStore,
) -> Result<Vec<(LostPayload, EventEnvelope)>, JournalError> {
    let first_unproven = match read_marker(fs, dir, records) {
        Some(seq) => seq + 1,
        None => manifest.active().map_or(0, |a| a.first_seq.0),
    };
    let tail: Vec<&EventEnvelope> = records
        .iter()
        .map(|r| &r.envelope)
        .filter(|e| e.seq.0 >= first_unproven)
        .collect();
    let shredded_after = |pocket: PocketId, chunk: ChunkRef, seq: Seq| {
        let name = chunk.to_string();
        tail.iter().any(|e| {
            e.seq > seq
                && e.event_type == types::CHUNK_SHREDDED
                && e.pocket_id == Some(pocket)
                && e.metadata.as_map().get(CHUNK_METADATA_KEY) == Some(&name)
        })
    };
    let referencing: Vec<(PocketId, ChunkRef, &EventEnvelope)> = tail
        .iter()
        .filter_map(|e| Some((e.pocket_id?, e.payload_ref?, *e)))
        .filter(|(pocket, chunk, e)| !shredded_after(*pocket, *chunk, e.seq))
        .collect();
    let refs: Vec<(PocketId, ChunkRef)> = referencing.iter().map(|(p, c, _)| (*p, *c)).collect();
    let lost: BTreeSet<(PocketId, ChunkRef)> = store
        .verify_and_sync(&refs)
        .map_err(JournalError::Payload)?
        .into_iter()
        .collect();
    Ok(referencing
        .into_iter()
        .filter(|(p, c, _)| lost.contains(&(*p, *c)))
        .map(|(pocket, chunk, e)| {
            (
                LostPayload {
                    record_seq: e.seq,
                    operation_id: e.operation_id,
                    pocket,
                    chunk,
                },
                e.clone(),
            )
        })
        .collect())
}
