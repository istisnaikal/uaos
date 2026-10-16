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
//! Recovery on [`Journal::open`] verifies the whole chain, quarantines segment files the
//! manifest does not list, and starts a new segment. It never appends after a possibly torn
//! tail, and it never flushes the previous run's segment again: after a failed flush (in that
//! run, or in an open that failed since) a new flush of the same file can report success
//! without writing anything, and a failing one drops what the OS held. The records after the
//! last durable point are copied to a fresh active segment, followed by any `chunk.lost`
//! records open appends for them, and flushed together. Only then is the manifest stored that
//! keeps the old file as suspect up to that point: until the copies are durable, the old
//! manifest still names the old file, and a failed or interrupted open loses nothing (review
//! WP3.A1, second round, H1). Shreds the journal recorded but a crash interrupted are completed.
//!
//! **Payloads (ADR-0018).** A journal opened with [`Journal::open_with_payloads`] coordinates
//! the chunk store's durability with its own:
//! * a record that references a chunk is accepted only once the chunk is stored (I-02);
//! * every flush makes the store's pending chunks durable **before** the segment, so a record
//!   is durable only once its payload is. A failed payload flush, here or anywhere in the store,
//!   stops the writer ([`JournalHealth::PayloadFlushFailed`]) until [`Journal::recover`] has
//!   read the pending chunks back, rewritten the readable ones and journaled the rest;
//! * a marker (`FLUSHED`), written atomically at open and then at most once per second, records
//!   a durable point up to which every payload is durable or its loss journaled. It **never
//!   moves while a loss is unreported**. Its presence also records that the journal coordinates
//!   a store, so it cannot be opened without one ([`JournalError::PayloadsRequired`]);
//! * while a loss is found but not yet journaled, the writer refuses records and flushes: no
//!   record may become durable before the record that reports its payload lost. On open, the payloads of every record after it are read back, rewritten
//!   and flushed before the previous run's records are made durable; an unreadable one is
//!   quarantined and journaled as `chunk.lost` ([`Journal::lost_payloads`]), and only then does
//!   the marker move. Without a valid marker the whole journal is checked.

use std::collections::{BTreeMap, BTreeSet};
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
use crate::chunks::{ChunkStore, LossCause, LostChunk};

/// Name of the data-directory lock file.
pub const LOCK_FILE: &str = "uaos.lock";
/// Name of the journal directory inside the data directory.
pub const JOURNAL_DIR: &str = "journal";
/// Name of the durable-point marker inside the journal directory (ADR-0018).
pub const FLUSH_MARKER: &str = "FLUSHED";
/// First word of the marker's single line: `uaos.flushed/1 <seq> <hash>`, or
/// `uaos.flushed/1 none` while no record is durable.
const MARKER_PREFIX: &str = "uaos.flushed/1";
/// Second word of the marker while no record is durable.
const MARKER_NONE: &str = "none";
/// How often the marker is rewritten. It bounds how much of the tail recovery reads back,
/// never what recovery reports.
const MARKER_INTERVAL: limits::Millis = limits::Millis(1_000);
/// Losses listed by [`Journal::lost_payloads`]; older ones remain in the journal (I-08).
pub const MAX_LOST_LISTED: usize = 1_024;
/// Metadata key that names the chunk a `chunk.lost` or `chunk.shredded` record is about. Such
/// records never set `payload_ref`: the payload is gone.
pub const CHUNK_METADATA_KEY: &str = "chunk";
/// Metadata key of a `chunk.lost` record that names the record whose payload was lost.
pub const RECORD_SEQ_METADATA_KEY: &str = "record_seq";
/// Metadata key of a `chunk.lost` record that names what the bytes showed.
pub const CAUSE_METADATA_KEY: &str = "cause";

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
    /// What the bytes showed.
    pub cause: LossCause,
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
    /// When the marker was last written.
    last_marker_mono: u64,
    /// Payloads reported lost since this journal was opened (the latest [`MAX_LOST_LISTED`]).
    lost: Vec<LostPayload>,
    /// Losses found but not yet journaled; kept across failures until their records are written.
    unreported: Vec<(LostPayload, EventEnvelope)>,
    /// The in-memory manifest disowns segment contents that are not yet flushed; it is stored,
    /// and the marker may move, only after the next flush (open's carried tail).
    manifest_unstored: bool,
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
        // A journal that has coordinated a chunk store must not be opened without it: the
        // previous run's tail would be made durable over payloads nobody checked (WP3.A1 L3).
        if payloads.is_none() {
            match fs.read(&dir.join(FLUSH_MARKER)) {
                Ok(_) => return Err(JournalError::PayloadsRequired),
                Err(FsError::NotFound { .. }) => {}
                Err(e) => return Err(storage(e)),
            }
        }

        let manifest_exists = match fs.read(&Manifest::path(&dir)) {
            Ok(_) => true,
            Err(FsError::NotFound { .. }) => false,
            Err(e) => return Err(storage(e)),
        };

        // A store whose flush failed before this journal attached is recovered first: its
        // pending content is rewritten or set aside, and whatever it set aside is reported below
        // (review WP3.A1, second round, L1).
        if let Some(store) = &payloads
            && store.is_poisoned()
        {
            store.recover_pending().map_err(JournalError::Payload)?;
        }
        let mut lost_in_tail = Vec::new();
        let mut shreds_to_complete = Vec::new();
        let mut carried = None;
        let (mut manifest, next_seq, head, last_flushed) = if manifest_exists {
            let (records, report) = read_verified(fs.as_ref(), &dir)?;
            let mut manifest = Manifest::load(fs.as_ref(), &dir)?;
            quarantine_orphans(fs.as_ref(), &dir, &manifest)?;
            sweep_temporaries(fs.as_ref(), &dir)?;
            let durable = read_marker(fs.as_ref(), &dir, &records);
            // ADR-0018 §3: the payloads of records after the last durable point must be durable
            // (or reported lost) before those records are made durable below.
            if let Some(store) = &payloads {
                shreds_to_complete = journaled_shreds(&records);
                lost_in_tail = recover_tail_payloads(&records, durable, store)?;
            }
            // The previous process may have acknowledged records the OS holds but never
            // flushed. They move to the new active segment unflushed, so a durable manifest
            // never claims them before they are durable, and the flush below covers them with
            // their loss records (review WP3.A1 H1, N4).
            carried = carry_previous_tail(fs.as_ref(), &dir, &mut manifest, &records, durable, &report)?;
            let last = match &carried {
                Some(tail) => tail.durable,
                None => report.next_seq.checked_sub(1).map(|s| (s, report.head)),
            };
            (manifest, report.next_seq, report.head, last)
        } else {
            // No record exists yet, so no loss the store set aside can be referenced by one.
            if let Some(store) = &payloads {
                let _unreferenced = store.take_lost();
            }
            let manifest = new_manifest(fs.as_ref(), &dir, rng.as_ref())?;
            let head = genesis_hash(&manifest.journal_id);
            (manifest, 0, head, None)
        };

        let carried_tail = carried.is_some();
        let (active, active_bytes, unflushed, unflushed_first) = match carried {
            Some(tail) => (tail.file, tail.bytes, tail.lines, tail.first),
            None => (
                start_segment(fs.as_ref(), &dir, &mut manifest, next_seq)?,
                0,
                Vec::new(),
                next_seq,
            ),
        };
        let last_flush_mono = clock.mono().0;
        let mut journal = Self {
            fs,
            clock,
            rng,
            dir,
            _lock: lock,
            manifest,
            active,
            active_bytes,
            next_seq,
            head,
            unflushed,
            unflushed_first,
            last_flushed,
            last_flush_mono,
            flush,
            health: JournalHealth::Healthy,
            payloads,
            last_marker_mono: last_flush_mono,
            lost: Vec::new(),
            unreported: lost_in_tail,
            manifest_unstored: carried_tail,
        };
        // Losses are journaled first, then one flush makes the previous run's records durable
        // together with them; then the manifest that stops naming the old copies is stored;
        // only then may the marker name the previous run's last record (review WP3.A1 H1, and
        // H1 of the second round). If any step fails, open fails, the durable manifest still
        // names the old copies, and the next open checks the same tail again. The marker must
        // exist before any record is accepted: it is also what makes the journal refuse to open
        // without its store (WP3.A1 L3).
        journal.report_lost()?;
        journal.sync()?;
        journal.store_manifest_if_unstored()?;
        // Only now are the shred records durable: completing a shred whose record a power loss
        // could still take away would leave references to removed content unexplained.
        if let Some(store) = &journal.payloads {
            for (pocket, chunk) in shreds_to_complete {
                if store.has_pair(pocket, chunk).map_err(JournalError::Payload)? {
                    store.shred(pocket, chunk).map_err(JournalError::Payload)?;
                }
            }
        }
        journal.update_marker(true).map_err(storage)?;
        Ok(journal)
    }

    /// Stores the in-memory manifest if it disowned contents that were not yet flushed.
    fn store_manifest_if_unstored(&mut self) -> Result<(), JournalError> {
        if self.manifest_unstored {
            self.manifest.store(self.fs.as_ref(), &self.dir)?;
            self.manifest_unstored = false;
        }
        Ok(())
    }

    /// Payloads reported lost since this journal was opened (each also journaled as a
    /// `chunk.lost` record).
    #[must_use]
    pub fn lost_payloads(&self) -> &[LostPayload] {
        &self.lost
    }

    /// Journals one `chunk.lost` record per unreported loss, then flushes them. A loss leaves
    /// the unreported list once its record has reached the OS (even if a flush after it then
    /// failed), so a retry never reports it twice; on failure the rest stay for the next
    /// [`Journal::recover`], and the marker stays where it was.
    fn report_lost(&mut self) -> Result<(), JournalError> {
        if self.unreported.is_empty() {
            return Ok(());
        }
        while let Some((payload, referencing)) = self.unreported.first().cloned() {
            let metadata = Metadata::new(
                [
                    (CHUNK_METADATA_KEY.to_owned(), payload.chunk.to_string()),
                    (RECORD_SEQ_METADATA_KEY.to_owned(), payload.record_seq.0.to_string()),
                    (CAUSE_METADATA_KEY.to_owned(), payload.cause.as_str().to_owned()),
                ]
                .into_iter()
                .collect(),
            )
            .map_err(|e| JournalError::Encoding(e.to_string()))?;
            let before = self.next_seq;
            let appended = self.append_inner(
                EventDraft {
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
                },
                true,
            );
            if self.next_seq > before {
                self.unreported.remove(0);
                if self.lost.len() >= MAX_LOST_LISTED {
                    self.lost.remove(0);
                }
                self.lost.push(payload);
            }
            appended?;
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
    /// `DiskFull`, `Stopped`, `PayloadFlushFailed`, `Write`, `LineTooLarge`, `Platform`,
    /// `Encoding`, `PayloadNotStored`, `Payload`, `InvalidRecord`.
    pub fn append(&mut self, draft: EventDraft) -> Result<Appended, JournalError> {
        self.append_inner(draft, false)
    }

    /// Appends one record. `reporting` is set only by [`Journal::report_lost`]: its records are
    /// accepted while losses are unreported, and never rotate or flush on their own, so the one
    /// flush after them covers them together with the records whose payloads they report.
    fn append_inner(&mut self, draft: EventDraft, reporting: bool) -> Result<Appended, JournalError> {
        match self.health {
            JournalHealth::Healthy => {}
            JournalHealth::DiskFull => return Err(JournalError::DiskFull),
            JournalHealth::PayloadFlushFailed => return Err(JournalError::PayloadFlushFailed),
            JournalHealth::WriteFailed | JournalHealth::FlushFailed => return Err(JournalError::Stopped),
        }
        if !reporting && !self.unreported.is_empty() {
            return Err(self.unreported_error());
        }
        // A record about a chunk that is gone names it in metadata, never as its payload: the
        // payload check below would refuse it, and recovery would report it lost (WP3.A1 L5).
        if (draft.event_type == types::CHUNK_LOST || draft.event_type == types::CHUNK_SHREDDED)
            && (draft.payload_ref.is_some() || !draft.metadata.as_map().contains_key(CHUNK_METADATA_KEY))
        {
            return Err(JournalError::InvalidRecord(
                "chunk.lost and chunk.shredded name their chunk in metadata key `chunk`, never in payload_ref",
            ));
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
        // A loss record may overshoot the segment target: rotating would flush the records it
        // reports before it exists.
        if !reporting
            && self.active_bytes > 0
            && self.active_bytes.saturating_add(line_len) > limits::JOURNAL_SEGMENT_TARGET.0
        {
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
        if due && !reporting {
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
    /// recovery ran out of space; `PayloadFlushFailed` if the attached chunk store could not be
    /// flushed (or had already failed to).
    pub fn sync(&mut self) -> Result<(), JournalError> {
        match self.health {
            JournalHealth::FlushFailed => return Err(JournalError::Stopped),
            JournalHealth::PayloadFlushFailed => return Err(JournalError::PayloadFlushFailed),
            JournalHealth::Healthy | JournalHealth::DiskFull | JournalHealth::WriteFailed => {}
        }
        if !self.unreported.is_empty() {
            return Err(self.unreported_error());
        }
        if self.unflushed.is_empty() {
            return Ok(());
        }
        // ADR-0018: payloads first. A record is durable only once the payloads it references are.
        self.sync_payloads()?;
        match self.active.sync_data() {
            Ok(()) => {
                self.mark_flushed();
                // A failed marker write is harmless here: the previous marker is still true,
                // only further behind.
                let _behind = self.update_marker(false);
                Ok(())
            }
            Err(_) => self.rewrite_unflushed(true),
        }
    }

    /// Flushes the attached chunk store's pending writes. On failure, or if the store is already
    /// poisoned by a failure elsewhere (review WP3.A1 H3), the writer stops: the unflushed
    /// records' payloads may be gone, and only [`Journal::recover`] can tell.
    fn sync_payloads(&mut self) -> Result<(), JournalError> {
        if let Some(store) = &self.payloads
            && store.sync_pending().is_err()
        {
            self.health = JournalHealth::PayloadFlushFailed;
            return Err(JournalError::PayloadFlushFailed);
        }
        Ok(())
    }

    /// Records the durable point (journals with payloads only), at most once per
    /// [`MARKER_INTERVAL`] unless `force`. The marker names the last flushed record, and every
    /// payload up to it is durable or its loss journaled:
    /// * it **never moves while a loss is unreported**, set aside by the store, or possibly
    ///   undetected because the store is poisoned (review WP3.A1 H1, H2);
    /// * it is written atomically and flushed, so a power loss leaves the previous or the new
    ///   marker, never an empty or torn one that would cost a whole-journal check.
    ///
    /// # Errors
    /// The marker write failed; the previous marker, if any, is still true.
    fn update_marker(&mut self, force: bool) -> Result<(), FsError> {
        let Some(store) = &self.payloads else {
            return Ok(());
        };
        if !self.unreported.is_empty() || store.has_untaken_losses() || store.is_poisoned() || self.manifest_unstored {
            return Ok(());
        }
        let now = self.clock.mono().0;
        if !force && now.saturating_sub(self.last_marker_mono) < MARKER_INTERVAL.as_nanos() {
            return Ok(());
        }
        let line = match self.last_flushed {
            Some((seq, hash)) => format!("{MARKER_PREFIX} {seq} {hash}\n"),
            None => format!("{MARKER_PREFIX} {MARKER_NONE}\n"),
        };
        self.fs.write_atomic(&self.dir.join(FLUSH_MARKER), line.as_bytes())?;
        self.last_marker_mono = now;
        Ok(())
    }

    /// Current writer state.
    #[must_use]
    pub fn health(&self) -> JournalHealth {
        if self.health == JournalHealth::Healthy && !self.unreported.is_empty() {
            // A loss waits to be journaled; records are refused until `recover` has done so.
            return JournalHealth::PayloadFlushFailed;
        }
        self.health
    }

    /// The refusal for a writer holding a loss it has not journaled: nothing may become durable
    /// before that loss record (ADR-0018), so [`Journal::recover`] must journal it first.
    fn unreported_error(&self) -> JournalError {
        match self.health {
            JournalHealth::DiskFull => JournalError::DiskFull,
            JournalHealth::WriteFailed | JournalHealth::FlushFailed => JournalError::Stopped,
            JournalHealth::Healthy | JournalHealth::PayloadFlushFailed => JournalError::PayloadFlushFailed,
        }
    }

    /// Returns the writer to `Healthy` once the cause is gone: after a disk-full or write
    /// failure it flushes what was acknowledged, seals the segment (excluding any torn tail)
    /// and continues in a fresh one; after a flush failure it retries rewriting the
    /// memory-only records to a fresh segment.
    ///
    /// After a payload flush failure it reads the pending chunks back (the store rewrites the
    /// readable ones to new files) and journals each loss **before** the flush that makes the
    /// referencing records durable. Every path ends by journaling any loss still unreported.
    ///
    /// # Errors
    /// `DiskFull` if there is still no space; `Stopped` if a flush still cannot be recovered;
    /// `Payload` if the chunk store cannot be read back.
    pub fn recover(&mut self) -> Result<(), JournalError> {
        match self.health {
            JournalHealth::Healthy => {}
            // While a loss waits to be journaled, the unflushed records move to a fresh segment
            // unflushed instead: flushing them first would make them durable before their loss
            // record. The flush after `report_lost` below covers them together.
            JournalHealth::DiskFull | JournalHealth::WriteFailed if !self.unreported.is_empty() => {
                self.rewrite_unflushed(false)?;
                self.health = JournalHealth::Healthy;
            }
            JournalHealth::DiskFull | JournalHealth::WriteFailed => {
                self.rotate()?;
                self.health = JournalHealth::Healthy;
            }
            JournalHealth::FlushFailed => {
                let flush = self.unreported.is_empty();
                self.rewrite_unflushed(flush)?;
                self.health = JournalHealth::Healthy;
            }
            JournalHealth::PayloadFlushFailed => {
                let Some(store) = self.payloads.clone() else {
                    return Err(JournalError::Stopped);
                };
                store.recover_pending().map_err(JournalError::Payload)?;
                // Moved into `unreported` at once: from here on the marker cannot pass them,
                // whatever fails next (review WP3.A1 H2).
                let lost = store.take_lost();
                let referencing = self.unflushed_referencing(&lost);
                self.unreported.extend(referencing);
                self.health = JournalHealth::Healthy;
            }
        }
        // Appends the `chunk.lost` records, then one flush covers them together with the records
        // whose payloads they report; with nothing to report, it completes the flush that failed.
        self.report_lost()?;
        self.sync()
    }

    /// The unflushed records that reference any of `lost`, except records an unflushed
    /// `chunk.lost` record already names (review WP3.A1, second round, L4).
    fn unflushed_referencing(&self, lost: &[LostChunk]) -> Vec<(LostPayload, EventEnvelope)> {
        let envelopes: Vec<EventEnvelope> = self
            .unflushed
            .iter()
            .filter_map(|line| serde_json::from_slice::<EventEnvelope>(line).ok())
            .collect();
        let reported: BTreeSet<u64> = envelopes
            .iter()
            .filter(|e| e.event_type == types::CHUNK_LOST)
            .filter_map(|e| e.metadata.as_map().get(RECORD_SEQ_METADATA_KEY)?.parse().ok())
            .collect();
        envelopes
            .into_iter()
            .filter(|e| !reported.contains(&e.seq.0))
            .filter_map(|e| {
                let (pocket, chunk) = (e.pocket_id?, e.payload_ref?);
                let found = lost.iter().find(|l| l.pocket == pocket && l.chunk == chunk)?;
                let payload = LostPayload {
                    record_seq: e.seq,
                    operation_id: e.operation_id,
                    pocket,
                    chunk,
                    cause: found.cause,
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
                self.manifest_unstored = false;
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

    /// Recovery from a failed flush (see module docs): seals the segment at its last flushed
    /// record and rewrites every unflushed record to a fresh segment. With `flush` the fresh
    /// segment is flushed before the manifest names it; without, its records stay unflushed for a
    /// later flush (the manifest then claims none of them).
    fn rewrite_unflushed(&mut self, flush: bool) -> Result<(), JournalError> {
        let saved = self.manifest.clone();
        let result: Result<(Box<dyn AppendFile>, u64), JournalError> = (|| {
            self.seal_active(SegmentStatus::Suspect, self.last_flushed);
            let mut fresh = start_segment_file(self.fs.as_ref(), &self.dir, &mut self.manifest, self.unflushed_first)?;
            for line in &self.unflushed {
                fresh.append(line).map_err(storage)?;
            }
            if flush {
                fresh.sync_data().map_err(|_| JournalError::Stopped)?;
            }
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
                self.manifest_unstored = false;
                if flush {
                    self.mark_flushed();
                }
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

/// The previous run's records after its durable point, moved to a fresh active segment.
struct CarriedTail {
    file: Box<dyn AppendFile>,
    /// The copied lines, in order, not yet flushed.
    lines: Vec<Vec<u8>>,
    bytes: u64,
    /// Sequence number of the first copied line.
    first: u64,
    /// The last record known durable before them, if any.
    durable: Option<(u64, Sha256Digest)>,
}

/// The manifest of a journal that does not exist yet, with a fresh random identifier. Refuses
/// to start a new history over segment files whose manifest is missing.
fn new_manifest(fs: &dyn Fs, dir: &Path, rng: &dyn Rng) -> Result<Manifest, JournalError> {
    if fs
        .list_dir(dir)
        .map_err(storage)?
        .iter()
        .any(|p| p.file_name().and_then(|n| n.to_str()).is_some_and(is_segment_file_name))
    {
        return Err(JournalError::Corrupt(
            "segment files exist but the manifest is missing; refusing to start a new history over them".to_owned(),
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
    Ok(Manifest {
        schema: ManifestSchema::V1,
        journal_id,
        min_reader_version: READER_VERSION,
        generation: 0,
        segments: Vec::new(),
    })
}

/// Seals the previous run's active segment without flushing it again (see the module docs).
///
/// If every record in it is durable already (or it has none), it is sealed in place and `None`
/// is returned; the caller starts a new segment. Otherwise the records up to `durable` stay in
/// the old file, recorded as suspect up to them, and the records after it are copied, unflushed,
/// to a fresh segment that becomes the active one. The manifest is **not** stored here: it
/// disowns the old copies, so the caller stores it only after the copied records are flushed.
fn carry_previous_tail(
    fs: &dyn Fs,
    dir: &Path,
    manifest: &mut Manifest,
    records: &[VerifiedRecord],
    durable: Option<u64>,
    report: &super::scan::VerifyReport,
) -> Result<Option<CarriedTail>, JournalError> {
    let Some(active) = manifest.active().cloned() else {
        return Ok(None);
    };
    let first = active.first_seq.0;
    let end = report.next_seq;
    // One past the last record known durable inside this segment.
    let proven_end = durable.map_or(first, |d| d.saturating_add(1).clamp(first, end));
    if proven_end == end {
        if let Some(old) = manifest.segments.last_mut() {
            old.status = SegmentStatus::Sealed;
            old.last_seq = end.checked_sub(1).filter(|l| *l >= first).map(Seq);
            old.last_hash = old.last_seq.map(|_| report.head);
        }
        return Ok(None);
    }
    let hash_of = |seq: u64| records.iter().find(|r| r.envelope.seq.0 == seq).map(|r| r.hash);
    let bytes = fs.read(&dir.join(&active.file)).map_err(storage)?;
    let (Some(from), Some(to)) = (
        line_offset(&bytes, proven_end - first),
        line_offset(&bytes, end - first),
    ) else {
        return Err(JournalError::Corrupt(
            "the active segment changed while it was recovered".to_owned(),
        ));
    };
    let tail = &bytes[from..to];
    if let Some(old) = manifest.segments.last_mut() {
        old.status = SegmentStatus::Suspect;
        old.last_seq = proven_end.checked_sub(1).filter(|l| *l >= first).map(Seq);
        old.last_hash = old.last_seq.and_then(|l| hash_of(l.0));
    }
    let mut file = start_segment_file(fs, dir, manifest, proven_end)?;
    file.append(tail).map_err(storage)?;
    let lines = tail.split_inclusive(|b| *b == b'\n').map(<[u8]>::to_vec).collect();
    let durable = proven_end
        .checked_sub(1)
        .and_then(|seq| hash_of(seq).map(|hash| (seq, hash)));
    Ok(Some(CarriedTail {
        file,
        lines,
        bytes: u64::try_from(tail.len()).unwrap_or(u64::MAX),
        first: proven_end,
        durable,
    }))
}

/// The byte offset just after the `n`th line of `bytes` (0 for `n == 0`), if it has that many.
fn line_offset(bytes: &[u8], n: u64) -> Option<usize> {
    if n == 0 {
        return Some(0);
    }
    let n = usize::try_from(n).ok()?;
    bytes
        .iter()
        .enumerate()
        .filter(|(_, b)| **b == b'\n')
        .nth(n - 1)
        .map(|(i, _)| i + 1)
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
/// with exactly that hash. Anything else (missing, torn, stale beyond the journal, or `none`) is
/// ignored, and the whole journal is checked.
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

/// The shreds the journal recorded (write-ahead, see [`ChunkStore::shred`]) that open must make
/// sure are complete: one per `chunk.shredded` record not followed by a record that references
/// the chunk again. Open shreds any of them whose pair is still on disk, once the records are
/// durable. Without this, the store's own startup would re-wrap a leftover key under the new
/// KEK and the content would stay readable (pre-existing, found by the second WP3.A1 review).
fn journaled_shreds(records: &[VerifiedRecord]) -> Vec<(PocketId, ChunkRef)> {
    let mut last_shred: BTreeMap<(PocketId, String), Seq> = BTreeMap::new();
    let mut last_use: BTreeMap<(PocketId, String), Seq> = BTreeMap::new();
    for e in records.iter().map(|r| &r.envelope) {
        if e.event_type == types::CHUNK_SHREDDED
            && let (Some(pocket), Some(chunk)) = (e.pocket_id, e.metadata.as_map().get(CHUNK_METADATA_KEY))
        {
            last_shred.insert((pocket, chunk.clone()), e.seq);
        } else if let (Some(pocket), Some(chunk)) = (e.pocket_id, e.payload_ref) {
            last_use.insert((pocket, chunk.to_string()), e.seq);
        }
    }
    last_shred
        .into_iter()
        .filter(|((pocket, name), shred)| last_use.get(&(*pocket, name.clone())).is_none_or(|used| *used < *shred))
        .filter_map(|((pocket, name), _)| Some((pocket, name.parse::<ChunkRef>().ok()?)))
        .collect()
}

/// ADR-0018 §3 at startup: reads back, rewrites and flushes the payloads of every record after
/// the durable point, and returns the records whose payload is unreadable. Losses the store set
/// aside before (a recovery at open, an earlier failed open in this process) are included, and
/// every record in the journal that references a lost chunk is reported, not only the tail's.
///
/// The durable point is the marker (`durable`) if it is valid. Without one (a store attached
/// for the first time, or a removed marker) the whole journal is checked: a narrower fallback could skip a
/// record whose loss was never journaled (review WP3.A1 H1). A record already named by a
/// `chunk.lost` record is not reported again, and a record whose chunk a later `chunk.shredded`
/// record names is not a loss. Both are looked up in indexes built once (review WP3.A1 L4).
fn recover_tail_payloads(
    records: &[VerifiedRecord],
    durable: Option<u64>,
    store: &ChunkStore,
) -> Result<Vec<(LostPayload, EventEnvelope)>, JournalError> {
    let first_unproven = durable.map_or(0, |seq| seq + 1);
    let mut last_shred: BTreeMap<(PocketId, &str), Seq> = BTreeMap::new();
    let mut reported: BTreeSet<u64> = BTreeSet::new();
    for e in records.iter().map(|r| &r.envelope) {
        let named = e.metadata.as_map();
        if e.event_type == types::CHUNK_SHREDDED
            && let (Some(pocket), Some(chunk)) = (e.pocket_id, named.get(CHUNK_METADATA_KEY))
        {
            let latest = last_shred.entry((pocket, chunk.as_str())).or_insert(e.seq);
            *latest = (*latest).max(e.seq);
        } else if e.event_type == types::CHUNK_LOST
            && let Some(seq) = named.get(RECORD_SEQ_METADATA_KEY).and_then(|v| v.parse().ok())
        {
            reported.insert(seq);
        }
    }
    let names: Vec<(PocketId, ChunkRef, String, &EventEnvelope)> = records
        .iter()
        .map(|r| &r.envelope)
        .filter(|e| e.seq.0 >= first_unproven && !reported.contains(&e.seq.0))
        .filter_map(|e| Some((e.pocket_id?, e.payload_ref?, e)))
        .map(|(pocket, chunk, e)| (pocket, chunk, chunk.to_string(), e))
        .collect();
    let referencing: Vec<(PocketId, ChunkRef, &EventEnvelope)> = names
        .iter()
        .filter(|(pocket, _, name, e)| {
            last_shred
                .get(&(*pocket, name.as_str()))
                .is_none_or(|shred| *shred < e.seq)
        })
        .map(|(pocket, chunk, _, e)| (*pocket, *chunk, *e))
        .collect();
    let refs: Vec<(PocketId, ChunkRef)> = referencing.iter().map(|(p, c, _)| (*p, *c)).collect();
    store.verify_and_sync(&refs).map_err(JournalError::Payload)?;
    let lost = store.take_lost();
    if lost.is_empty() {
        return Ok(Vec::new());
    }
    let every: Vec<(PocketId, ChunkRef, &EventEnvelope)> = records
        .iter()
        .map(|r| &r.envelope)
        .filter(|e| !reported.contains(&e.seq.0))
        .filter_map(|e| Some((e.pocket_id?, e.payload_ref?, e)))
        .filter(|(pocket, chunk, e)| {
            last_shred
                .get(&(*pocket, chunk.to_string().as_str()))
                .is_none_or(|shred| *shred < e.seq)
        })
        .collect();
    Ok(every
        .into_iter()
        .filter_map(|(pocket, chunk, e)| {
            let found = lost.iter().find(|l| l.pocket == pocket && l.chunk == chunk)?;
            Some((
                LostPayload {
                    record_seq: e.seq,
                    operation_id: e.operation_id,
                    pocket,
                    chunk,
                    cause: found.cause,
                },
                e.clone(),
            ))
        })
        .collect())
}
