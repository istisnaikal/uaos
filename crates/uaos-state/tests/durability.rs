// SPDX-License-Identifier: Apache-2.0

//! ADR-0018: chunk payloads join the journal's durability classes, under deterministic crash
//! simulation, plus the S-6 chunk race and every finding of the WP3.A1 review
//! (`docs/reviews/WP3.A1-chunk-durability.md`) as a regression test.
//!
//! Guarantees checked:
//! * **payload before record:** a record that references a chunk not yet stored is refused;
//! * after a **process crash**, every acknowledged record is present and its payload readable,
//!   unless a failed flush dropped it and the loss was journaled;
//! * after a **power loss**, every record up to the flushed boundary is present and its payload
//!   readable, unless that loss was already journaled;
//! * **never silent:** a surviving record whose payload is unreadable has a `chunk.lost` record,
//!   or a later `chunk.shredded` record names its chunk.
//!
//! The simulated disk runs in two modes: a failed flush either drops the unflushed bytes, or
//! (`set_failed_sync_keeps_cache`) keeps serving them while never making them durable, as Linux
//! does after a writeback error.

#![allow(
    clippy::unwrap_used,
    clippy::panic,
    clippy::disallowed_methods,
    reason = "test harness: fixtures and checks abort on failure; race tests need real threads and time"
)]

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Condvar, Mutex};
use std::time::Duration;

use proptest::prelude::*;
use uaos_contracts::digest::ChunkRef;
use uaos_contracts::event::{Actor, Durability, Metadata, types};
use uaos_contracts::id::{CorrelationId, PocketId, TypedId};
use uaos_contracts::limits::Millis;
use uaos_contracts::operation::{RiskTier, SideEffectClass};
use uaos_contracts::time::WallTime;
use uaos_contracts::wire::ConfigVersion;
use uaos_platform::fs::{AppendFile, Fs, FsError, LockGuard};
use uaos_platform::sim::fs::SimFs;
use uaos_platform::sim::{SimClock, SimRng};
use uaos_platform::{Clock, Rng};
use uaos_state::chunks::keyring::{KekVersion, MemoryKeyring, PocketKeyring};
use uaos_state::chunks::{CHUNKS_DIR, ChunkDurability, ChunkError, ChunkStore, MAX_PENDING, QUARANTINE_DIR};
use uaos_state::journal::{
    CHUNK_METADATA_KEY, EventDraft, FlushPolicy, JOURNAL_DIR, Journal, JournalError, JournalHealth,
    RECORD_SEQ_METADATA_KEY, read_verified,
};

const DATA: &str = "/data";
/// A window longer than any test, so only explicit `sync` calls flush.
const NEVER: FlushPolicy = FlushPolicy::Balanced {
    window: Millis(u64::MAX / 2),
};

// ── A simulated disk with switches ─────────────────────────────────────────────────────────

/// Holds the first matching operation until released.
#[derive(Debug, Default)]
struct Gate {
    armed: AtomicBool,
    held: AtomicBool,
    open: Mutex<bool>,
    opened: Condvar,
}

impl Gate {
    fn arm(&self) {
        self.armed.store(true, Ordering::SeqCst);
    }
    fn hold_if_armed(&self) {
        if self.armed.swap(false, Ordering::SeqCst) {
            self.held.store(true, Ordering::SeqCst);
            let mut open = self.open.lock().unwrap();
            while !*open {
                open = self.opened.wait(open).unwrap();
            }
        }
    }
    /// Waits until the gated operation is held; panics if it never runs, so a test cannot hang.
    fn wait_held(&self) {
        for _ in 0..10_000 {
            if self.held.load(Ordering::SeqCst) {
                return;
            }
            std::thread::sleep(Duration::from_millis(1));
        }
        panic!("the gated operation never ran");
    }
    fn release(&self) {
        *self.open.lock().unwrap() = true;
        self.opened.notify_all();
    }
    /// Releases after `ms` from another thread, so a test cannot deadlock on its own gate.
    fn release_after(self: &Arc<Self>, ms: u64) -> std::thread::JoinHandle<()> {
        let gate = Arc::clone(self);
        std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(ms));
            gate.release();
        })
    }
}

#[derive(Debug, Clone)]
struct FaultFs {
    sim: SimFs,
    /// Segment appends let through before the next one fails with `NoSpace`, once.
    segment_append_fault: Arc<Mutex<Option<u32>>>,
    /// The first key-file write.
    key_write: Arc<Gate>,
    /// The first key-file rename (quarantine).
    key_rename: Arc<Gate>,
    /// The next key-file rename fails, once.
    fail_key_rename: Arc<AtomicBool>,
    /// The next key-file removal fails, once.
    fail_key_remove: Arc<AtomicBool>,
}

#[derive(Debug)]
struct FaultAppend {
    inner: Box<dyn AppendFile>,
    segment: bool,
    fault: Arc<Mutex<Option<u32>>>,
}

impl AppendFile for FaultAppend {
    fn append(&mut self, bytes: &[u8]) -> Result<(), FsError> {
        if self.segment {
            let mut fault = self.fault.lock().unwrap();
            match *fault {
                Some(0) => {
                    *fault = None;
                    return Err(FsError::NoSpace { op: "append" });
                }
                Some(n) => *fault = Some(n - 1),
                None => {}
            }
        }
        self.inner.append(bytes)
    }
    fn sync_data(&mut self) -> Result<(), FsError> {
        self.inner.sync_data()
    }
    fn os_len(&self) -> Result<u64, FsError> {
        self.inner.os_len()
    }
}

fn injected(op: &'static str) -> FsError {
    FsError::Io {
        op,
        kind: "injected".to_owned(),
    }
}

fn is_key(path: &Path) -> bool {
    path.extension().and_then(|e| e.to_str()) == Some("key")
}

impl FaultFs {
    /// Lets `n` segment appends through, then fails the next with `NoSpace`.
    fn fail_segment_append_after(&self, n: u32) {
        *self.segment_append_fault.lock().unwrap() = Some(n);
    }

    fn clear_append_fault(&self) {
        *self.segment_append_fault.lock().unwrap() = None;
    }
}

impl Fs for FaultFs {
    fn create_dir_all(&self, path: &Path) -> Result<(), FsError> {
        self.sim.create_dir_all(path)
    }
    fn open_append(&self, path: &Path) -> Result<Box<dyn AppendFile>, FsError> {
        Ok(Box::new(FaultAppend {
            inner: self.sim.open_append(path)?,
            segment: path.extension().and_then(|e| e.to_str()) == Some("jsonl"),
            fault: Arc::clone(&self.segment_append_fault),
        }))
    }
    fn read(&self, path: &Path) -> Result<Vec<u8>, FsError> {
        self.sim.read(path)
    }
    fn list_dir(&self, path: &Path) -> Result<Vec<PathBuf>, FsError> {
        self.sim.list_dir(path)
    }
    fn rename(&self, from: &Path, to: &Path) -> Result<(), FsError> {
        if is_key(from) {
            self.key_rename.hold_if_armed();
            if self.fail_key_rename.swap(false, Ordering::SeqCst) {
                return Err(injected("rename"));
            }
        }
        self.sim.rename(from, to)
    }
    fn remove_file(&self, path: &Path) -> Result<(), FsError> {
        if is_key(path) && self.fail_key_remove.swap(false, Ordering::SeqCst) {
            return Err(injected("remove"));
        }
        self.sim.remove_file(path)
    }
    fn sync_dir(&self, path: &Path) -> Result<(), FsError> {
        self.sim.sync_dir(path)
    }
    fn write_atomic(&self, path: &Path, bytes: &[u8]) -> Result<(), FsError> {
        if is_key(path) {
            self.key_write.hold_if_armed();
        }
        self.sim.write_atomic(path, bytes)
    }
    fn write_unsynced(&self, path: &Path, bytes: &[u8]) -> Result<(), FsError> {
        if is_key(path) {
            self.key_write.hold_if_armed();
        }
        self.sim.write_unsynced(path, bytes)
    }
    fn sync_file(&self, path: &Path) -> Result<(), FsError> {
        self.sim.sync_file(path)
    }
    fn try_lock_exclusive(&self, path: &Path) -> Result<Box<dyn LockGuard>, FsError> {
        self.sim.try_lock_exclusive(path)
    }
}

/// What a journal shows: see [`World::survey`].
type Survey = (
    Vec<(u64, PocketId, ChunkRef)>,
    BTreeSet<u64>,
    Vec<(PocketId, String, u64)>,
);

struct World {
    sim: SimFs,
    fs: FaultFs,
    clock: Arc<SimClock>,
    rng: Arc<SimRng>,
    /// Survives simulated crashes, like an OS keychain.
    keys: Arc<MemoryKeyring>,
    data: PathBuf,
}

impl World {
    fn new(seed: u64) -> Self {
        let sim = SimFs::new();
        sim.create_dir_all(Path::new(DATA)).unwrap();
        let rng = Arc::new(SimRng::new(seed));
        Self {
            fs: FaultFs {
                sim: sim.clone(),
                segment_append_fault: Arc::new(Mutex::new(None)),
                key_write: Arc::new(Gate::default()),
                key_rename: Arc::new(Gate::default()),
                fail_key_rename: Arc::new(AtomicBool::new(false)),
                fail_key_remove: Arc::new(AtomicBool::new(false)),
            },
            sim,
            clock: Arc::new(SimClock::new(
                WallTime::from_unix_nanos(1_760_000_000_000_000_000).unwrap(),
            )),
            keys: Arc::new(MemoryKeyring::new(rng.clone())),
            rng,
            data: PathBuf::from(DATA),
        }
    }

    fn try_store(&self, durability: ChunkDurability) -> Result<Arc<ChunkStore>, ChunkError> {
        let rng: Arc<dyn Rng> = self.rng.clone();
        let keys: Arc<dyn PocketKeyring> = self.keys.clone();
        ChunkStore::open_with(Arc::new(self.fs.clone()), rng, keys, &self.data, durability).map(Arc::new)
    }

    fn store(&self) -> Arc<ChunkStore> {
        self.try_store(ChunkDurability::Balanced).unwrap()
    }

    fn open(&self, store: &Arc<ChunkStore>) -> Result<Journal, JournalError> {
        let clock: Arc<dyn Clock> = self.clock.clone();
        let rng: Arc<dyn Rng> = self.rng.clone();
        Journal::open_with_payloads(
            Arc::new(self.fs.clone()),
            clock,
            rng,
            &self.data,
            NEVER,
            Arc::clone(store),
        )
    }

    /// Simulates the process dying and starting again: a crash, then a fresh store and journal.
    fn restart(&self, power: bool) -> (Arc<ChunkStore>, Journal) {
        self.sim.fail_sync_after(u32::MAX);
        if power {
            self.sim.power_loss();
        } else {
            self.sim.crash();
        }
        let store = self.store();
        let journal = self.open(&store).unwrap();
        (store, journal)
    }

    /// Records with a payload, record seqs named by `chunk.lost`, and (pocket, chunk, seq) of
    /// every `chunk.shredded` record.
    fn survey(&self) -> Survey {
        let (records, _) = read_verified(&self.sim, &self.data.join(JOURNAL_DIR)).unwrap();
        let (mut with_payload, mut reported, mut shreds) = (Vec::new(), BTreeSet::new(), Vec::new());
        for r in records {
            let e = r.envelope;
            if e.event_type == types::CHUNK_LOST {
                reported.insert(e.metadata.as_map()[RECORD_SEQ_METADATA_KEY].parse::<u64>().unwrap());
            } else if e.event_type == types::CHUNK_SHREDDED {
                shreds.push((
                    e.pocket_id.unwrap(),
                    e.metadata.as_map()[CHUNK_METADATA_KEY].clone(),
                    e.seq.0,
                ));
            } else if let (Some(p), Some(c)) = (e.pocket_id, e.payload_ref) {
                with_payload.push((e.seq.0, p, c));
            }
        }
        (with_payload, reported, shreds)
    }

    /// Every surviving record's payload is readable, reported lost, or shredded after it.
    fn assert_never_silent(&self, store: &ChunkStore, what: &str) {
        let (records, reported, shreds) = self.survey();
        for (seq, p, c) in &records {
            let shredded = shreds
                .iter()
                .any(|(sp, sc, ss)| sp == p && *sc == c.to_string() && ss > seq);
            assert!(
                store.get(*p, *c).is_ok() || reported.contains(seq) || shredded,
                "{what}: record {seq} has an unreadable payload and no chunk.lost record"
            );
        }
    }

    fn quarantined(&self) -> usize {
        self.sim
            .list_dir(
                &self
                    .data
                    .join(CHUNKS_DIR)
                    .join(pocket().to_string())
                    .join(QUARANTINE_DIR),
            )
            .map_or(0, |v| v.len())
    }
}

fn pocket() -> PocketId {
    PocketId::from_parts(7, [7; 10])
}

fn draft(pocket: Option<PocketId>, chunk: Option<ChunkRef>, n: u64) -> EventDraft {
    let mut random = [0u8; 10];
    random[..8].copy_from_slice(&n.to_le_bytes());
    EventDraft {
        session_id: None,
        pocket_id: pocket,
        operation_id: None,
        request_id: None,
        correlation_id: CorrelationId::from_parts(n, random),
        parent_id: None,
        actor: Actor::System,
        event_type: types::OP_RESERVED_INTENT,
        payload_ref: chunk,
        payload_inline: None,
        cost_estimate: None,
        compensable: false,
        side_effect_class: SideEffectClass::External,
        risk_tier: RiskTier::MAX,
        durability: Durability::Critical,
        config_version: ConfigVersion(1),
        metadata: Metadata::default(),
    }
}

fn shredded_record(chunk: ChunkRef, n: u64) -> EventDraft {
    let mut d = draft(Some(pocket()), None, n);
    d.event_type = types::CHUNK_SHREDDED;
    d.side_effect_class = SideEffectClass::LocalIrreversible;
    d.metadata = Metadata::new(
        [(CHUNK_METADATA_KEY.to_owned(), chunk.to_string())]
            .into_iter()
            .collect(),
    )
    .unwrap();
    d
}

fn content(n: u64) -> Vec<u8> {
    format!("payload {n} ").repeat(32).into_bytes()
}

/// Stores a payload and appends a record that references it.
fn write(store: &ChunkStore, journal: &mut Journal, n: u64) -> (u64, ChunkRef) {
    let chunk = store.put(pocket(), &content(n)).unwrap();
    let seq = journal.append(draft(Some(pocket()), Some(chunk), n)).unwrap().seq.0;
    (seq, chunk)
}

// ── Scenarios ──────────────────────────────────────────────────────────────────────────────

#[test]
fn a_record_cannot_reference_a_chunk_that_is_not_stored() {
    let w = World::new(1);
    let store = w.store();
    let mut journal = w.open(&store).unwrap();
    let body = content(1);
    let chunk = store.reference(pocket(), &body).unwrap();

    assert_eq!(
        journal.append(draft(Some(pocket()), Some(chunk), 1)),
        Err(JournalError::PayloadNotStored),
        "payload before record: a record referencing an unwritten chunk was acknowledged"
    );
    assert_eq!(
        journal.append(draft(None, Some(chunk), 1)),
        Err(JournalError::PayloadNotStored),
        "a payload without its pocket cannot be checked and must be refused"
    );
    store.put(pocket(), &body).unwrap();
    journal.append(draft(Some(pocket()), Some(chunk), 1)).unwrap();
}

#[test]
fn balanced_chunks_become_durable_with_the_records_that_reference_them() {
    let w = World::new(2);
    let store = w.store();
    let mut journal = w.open(&store).unwrap();
    let (seq, chunk) = write(&store, &mut journal, 1);
    assert_eq!(store.pending_len(), 1, "a balanced put is not flushed by itself");
    journal.sync().unwrap();
    assert_eq!(store.pending_len(), 0, "the journal's flush flushes the payloads first");
    assert_eq!(journal.flushed_through().unwrap().0, seq);
    drop(journal);
    drop(store);

    let (store, journal) = w.restart(true);
    assert!(journal.lost_payloads().is_empty());
    assert!(w.survey().0.iter().any(|(s, _, _)| *s == seq));
    assert_eq!(store.get(pocket(), chunk).unwrap(), content(1));
}

#[test]
fn unflushed_payloads_lost_to_power_are_never_silent() {
    let w = World::new(3);
    let store = w.store();
    let mut journal = w.open(&store).unwrap();
    write(&store, &mut journal, 1);
    journal.sync().unwrap();
    write(&store, &mut journal, 2); // with the OS only
    drop(journal);
    drop(store);
    let (store, _journal) = w.restart(true);
    w.assert_never_silent(&store, "power loss");
}

/// The deterministic form of the ADR-0018 ordering rule: whatever flush fails, in either cache
/// mode, and whenever the power goes, a record at or before the flushed boundary has a readable
/// payload.
#[test]
fn a_flushed_record_never_references_an_unreadable_payload() {
    for keep_cache in [false, true] {
        for k in 0..14 {
            let w = World::new(100 + u64::from(k));
            w.sim.set_failed_sync_keeps_cache(keep_cache);
            let store = w.store();
            let mut journal = w.open(&store).unwrap();
            for n in 0..3 {
                write(&store, &mut journal, n);
            }
            w.sim.fail_sync_after(k);
            // Whether this flush fails depends on `k`; the guarantee must hold either way.
            let _outcome = journal.sync();
            let flushed = journal.flushed_through().map(|s| s.0);
            drop(journal);
            drop(store);
            let (store, _journal) = w.restart(true);
            let (records, reported, _) = w.survey();
            for (seq, p, c) in records {
                let readable = store.get(p, c).is_ok();
                if flushed.is_some_and(|f| seq <= f) {
                    assert!(
                        readable,
                        "fault after {k} flushes (cache kept: {keep_cache}): flushed record {seq} lost its payload"
                    );
                }
                assert!(
                    readable || reported.contains(&seq),
                    "record {seq} lost its payload silently"
                );
            }
        }
    }
}

#[test]
fn a_failed_payload_flush_stops_the_writer_until_recovery_reports_the_loss() {
    let w = World::new(4);
    let store = w.store();
    let mut journal = w.open(&store).unwrap();
    let (seq, _) = write(&store, &mut journal, 1);
    w.sim.fail_next_sync(); // the chunk's data file: the OS drops its unflushed pages
    assert_eq!(journal.sync(), Err(JournalError::PayloadFlushFailed));
    assert_eq!(journal.health(), JournalHealth::PayloadFlushFailed);
    assert_eq!(
        journal.append(draft(None, None, 2)),
        Err(JournalError::PayloadFlushFailed)
    );
    assert_eq!(
        store.put(pocket(), &content(3)),
        Err(ChunkError::FlushFailed),
        "the store is poisoned"
    );

    journal.recover().unwrap();
    assert_eq!(journal.health(), JournalHealth::Healthy);
    assert_eq!(journal.lost_payloads().len(), 1);
    assert_eq!(journal.lost_payloads()[0].record_seq.0, seq);
    assert!(
        w.quarantined() > 0,
        "the unreadable chunk is kept in quarantine, not deleted"
    );
    drop(journal);
    assert!(w.survey().1.contains(&seq), "the loss is journaled as chunk.lost");
}

#[test]
fn rotation_rewraps_are_durable_in_balanced_mode() {
    let w = World::new(5);
    let store = w.store();
    let keep = store.put(pocket(), &content(1)).unwrap();
    let doomed = store.put(pocket(), &content(2)).unwrap();
    store.sync_pending().unwrap();
    store.shred(pocket(), doomed).unwrap(); // rotates the KEK, re-wraps `keep`, retires the old KEK
    drop(store);
    w.sim.power_loss();
    let store = w.store();
    assert_eq!(
        store.get(pocket(), keep).unwrap(),
        content(1),
        "an unflushed re-wrap would leave a key only the destroyed KEK opens"
    );
}

#[test]
fn a_chunk_left_torn_by_a_power_loss_is_rewritten_not_trusted() {
    let w = World::new(6);
    let store = w.store();
    let chunk = store.put(pocket(), &content(1)).unwrap();
    // Make the directory entries durable but not the file contents: both files come back empty.
    w.sim
        .sync_dir(&w.data.join(CHUNKS_DIR).join(pocket().to_string()).join("data"))
        .unwrap();
    w.sim
        .sync_dir(&w.data.join(CHUNKS_DIR).join(pocket().to_string()).join("keys"))
        .unwrap();
    drop(store);
    w.sim.power_loss();
    let store = w.store();
    assert!(store.get(pocket(), chunk).is_err());
    assert!(!store.is_stored(pocket(), chunk).unwrap());
    assert_eq!(store.put(pocket(), &content(1)).unwrap(), chunk);
    assert_eq!(store.get(pocket(), chunk).unwrap(), content(1));
}

// ── Regressions from the WP3.A1 review ─────────────────────────────────────────────────────

/// H1: if reporting a loss fails during open, the marker has not moved, so the next open
/// checks the same tail and reports it.
#[test]
fn h1_open_reports_a_loss_before_its_marker_moves() {
    let w = World::new(11);
    let store = w.store();
    let mut j = w.open(&store).unwrap();
    write(&store, &mut j, 1);
    w.sim.fail_next_sync();
    assert_eq!(j.sync(), Err(JournalError::PayloadFlushFailed));
    drop(j);
    drop(store);
    w.sim.crash();

    // The open copies the previous run's record to a fresh segment, then appends chunk.lost:
    // the second segment append fails.
    w.fs.fail_segment_append_after(1);
    let store = w.store();
    let first = w.open(&store);
    assert!(first.is_err(), "the chunk.lost append failed, so open fails: {first:?}");
    drop(first);
    drop(store);

    let (store, _j) = w.restart(false);
    w.assert_never_silent(&store, "h1");
}

/// H1: an open that found a loss and failed to journal it leaves no record durable ahead of its
/// loss record, even if the power goes before the next open.
#[test]
fn h1_a_failed_open_leaves_no_record_durable_before_its_loss_record() {
    let w = World::new(25);
    let store = w.store();
    let mut j = w.open(&store).unwrap();
    let (seq, _) = write(&store, &mut j, 1);
    w.sim.fail_next_sync(); // the chunk's data file: the OS drops its unflushed pages
    assert_eq!(j.sync(), Err(JournalError::PayloadFlushFailed));
    drop(j);
    drop(store);
    w.sim.crash();
    // The open finds the loss, copies the record, and fails to append its chunk.lost record.
    w.fs.fail_segment_append_after(1);
    let store = w.store();
    assert!(w.open(&store).is_err());
    drop(store);
    w.sim.power_loss();
    let (records, reported, _) = w.survey();
    assert!(
        !records.iter().any(|(s, _, _)| *s == seq) || reported.contains(&seq),
        "the record became durable before its loss record"
    );
}

/// H2: a loss found by recovery survives a failed report and every other recovery branch.
#[test]
fn h2_a_loss_survives_a_failed_report_and_other_recover_branches() {
    let w = World::new(12);
    let store = w.store();
    let mut j = w.open(&store).unwrap();
    write(&store, &mut j, 1);
    w.sim.fail_next_sync();
    assert_eq!(j.sync(), Err(JournalError::PayloadFlushFailed));

    w.fs.fail_segment_append_after(0);
    assert!(j.recover().is_err(), "the chunk.lost append fails");
    assert_eq!(j.health(), JournalHealth::DiskFull);
    j.recover().unwrap(); // the disk-full branch must report what is still unreported
    assert_eq!(j.lost_payloads().len(), 1);
    write(&store, &mut j, 2);
    j.sync().unwrap();
    drop(j);
    drop(store);
    let (store, _j) = w.restart(true);
    w.assert_never_silent(&store, "h2");
}

/// H3: a flush that fails in the store, outside the journal, poisons the store, so the next
/// journal flush stops instead of marking records durable over dropped content.
#[test]
fn h3_a_store_flush_failure_stops_the_journal() {
    let w = World::new(13);
    let store = w.store();
    let mut j = w.open(&store).unwrap();
    let (seq, chunk) = write(&store, &mut j, 1);
    w.sim.fail_next_sync();
    assert!(store.sync_pending().is_err());
    assert_eq!(
        j.sync(),
        Err(JournalError::PayloadFlushFailed),
        "the journal saw the store's failure"
    );
    assert!(j.flushed_through().is_none_or(|f| f.0 < seq));
    assert!(
        store.is_stored(pocket(), chunk).is_err(),
        "a poisoned store does not vouch from memory"
    );
    j.recover().unwrap();
    drop(j);
    drop(store);
    let (store, _j) = w.restart(true);
    w.assert_never_silent(&store, "h3");
}

/// H4: after a writeback error the cache still serves the bytes and a second flush of the same
/// file "succeeds" without making them durable. Recovery must rewrite, not re-flush.
#[test]
fn h4_recovery_rewrites_content_instead_of_reflushing_the_failed_file() {
    let w = World::new(16);
    w.sim.set_failed_sync_keeps_cache(true);
    let store = w.store();
    let mut j = w.open(&store).unwrap();
    let (seq, chunk) = write(&store, &mut j, 1);
    w.sim.fail_next_sync();
    assert_eq!(j.sync(), Err(JournalError::PayloadFlushFailed));
    j.recover().unwrap();
    assert!(
        j.lost_payloads().is_empty(),
        "the cached bytes were readable, so nothing is lost"
    );
    assert!(j.flushed_through().is_some_and(|f| f.0 >= seq));
    drop(j);
    drop(store);
    let (store, _j) = w.restart(true);
    assert_eq!(
        store.get(pocket(), chunk).ok(),
        Some(content(1)),
        "a flushed record's payload was re-flushed in place and lost to the power cut"
    );
}

/// M2: a lost chunk is quarantined under its slot, so a concurrent put of the same content
/// cannot have its fresh pair moved away underneath it. The race is reachable at open, while
/// the previous run's tail is checked; during runtime recovery the store is poisoned and refuses
/// puts outright (`a_failed_payload_flush_stops_the_writer_until_recovery_reports_the_loss`).
#[test]
fn m2_a_quarantine_and_a_concurrent_put_of_the_same_chunk_never_lose_it() {
    let w = World::new(14);
    let store = w.store();
    let mut j = w.open(&store).unwrap();
    let (_, x) = write(&store, &mut j, 1);
    w.sim.fail_next_sync(); // the chunk's data file: the OS drops its unflushed pages
    assert_eq!(j.sync(), Err(JournalError::PayloadFlushFailed));
    drop(j);
    drop(store);
    w.sim.crash(); // the record is still with the OS; its payload is not

    let store = w.store();
    w.fs.key_rename.arm(); // the quarantine of the lost chunk stops at its key file
    let rename = Arc::clone(&w.fs.key_rename);
    let b = {
        let store = Arc::clone(&store);
        std::thread::spawn(move || {
            rename.wait_held();
            store.put(pocket(), &content(1))
        })
    };
    let releaser = w.fs.key_rename.release_after(300);
    let mut j = w.open(&store).unwrap();
    releaser.join().unwrap();
    assert_eq!(
        b.join().unwrap().unwrap(),
        x,
        "the put waited for the quarantine, then wrote a fresh pair"
    );
    assert_eq!(
        j.lost_payloads().len(),
        1,
        "the earlier record's payload was lost and is reported"
    );
    j.append(draft(Some(pocket()), Some(x), 2)).unwrap();
    j.sync().unwrap();
    drop(j);
    drop(store);
    let (store, _j) = w.restart(true);
    w.assert_never_silent(&store, "m2");
    assert_eq!(
        store.get(pocket(), x).ok(),
        Some(content(1)),
        "the fresh pair was moved into quarantine"
    );
}

/// M3: a put that is wrapping its key cannot race a shred into wrapping under a KEK the
/// shred destroys.
#[test]
fn m3_a_put_racing_a_shred_in_the_same_pocket_stays_readable() {
    for durability in [ChunkDurability::Balanced, ChunkDurability::Strict] {
        let w = World::new(15);
        let store = w.try_store(durability).unwrap();
        let other = store.put(pocket(), &content(9)).unwrap();
        store.sync_pending().unwrap();
        w.fs.key_write.arm();
        let a = {
            let store = Arc::clone(&store);
            std::thread::spawn(move || store.put(pocket(), &content(1)))
        };
        w.fs.key_write.wait_held(); // A holds the current KEK and has not written its key file
        let s = {
            let store = Arc::clone(&store);
            std::thread::spawn(move || store.shred(pocket(), other))
        };
        std::thread::sleep(Duration::from_millis(200));
        w.fs.key_write.release();
        let z = a.join().unwrap().unwrap();
        s.join().unwrap().unwrap();
        assert!(store.is_stored(pocket(), z).unwrap());
        assert_eq!(
            store.get(pocket(), z).ok(),
            Some(content(1)),
            "{durability:?}: the put's key file was wrapped under a destroyed KEK"
        );
    }
}

/// M5: recovery quarantines unreadable chunks instead of deleting them, and a keyring that
/// cannot produce a KEK is a failure that touches nothing.
#[test]
fn m5_keyring_failures_fail_closed_without_touching_chunks() {
    let w = World::new(17);
    let store = w.store();
    let mut j = w.open(&store).unwrap();
    let (_, chunk) = write(&store, &mut j, 1);
    drop(j);
    drop(store);
    w.sim.crash();
    // The keychain lost every KEK version (a reset, or a moved data directory).
    w.keys.retire_keks_before(pocket(), KekVersion(1_000)).unwrap();
    let store = w.store();
    let opened = w.open(&store);
    assert!(
        matches!(opened, Err(JournalError::Payload(ChunkError::Keyring(_)))),
        "missing keys are not a payload loss: {opened:?}"
    );
    assert_eq!(w.quarantined(), 0, "nothing was moved or deleted");
    let name = chunk.to_string();
    let key_file = format!("{}.key", name.strip_prefix("hmac-sha256:").unwrap());
    let key_files = w
        .sim
        .list_dir(&w.data.join(CHUNKS_DIR).join(pocket().to_string()).join("keys"))
        .unwrap();
    assert!(
        key_files
            .iter()
            .any(|p| p.file_name().unwrap().to_string_lossy() == key_file),
        "the key file is where it was"
    );
}

/// L2: one chunk store per data directory.
#[test]
fn l2_one_chunk_store_per_data_directory() {
    let w = World::new(18);
    let _first = w.store();
    assert_eq!(
        w.try_store(ChunkDurability::Balanced).err(),
        Some(ChunkError::InstanceLocked)
    );
}

/// L3: a journal that has coordinated a chunk store cannot be opened without it.
#[test]
fn l3_a_coordinated_journal_refuses_to_open_without_its_store() {
    let w = World::new(19);
    let store = w.store();
    let j = w.open(&store).unwrap();
    drop(j);
    w.sim.crash();
    let clock: Arc<dyn Clock> = w.clock.clone();
    let rng: Arc<dyn Rng> = w.rng.clone();
    let plain = Journal::open(Arc::new(w.fs.clone()), clock, rng, &w.data, NEVER);
    assert_eq!(
        plain.err(),
        Some(JournalError::PayloadsRequired),
        "a coordinated journal opened without its store"
    );
}

/// L5: chunk records name their chunk in metadata, and a shred after a record is not a loss.
#[test]
fn l5_chunk_records_name_their_chunk_and_a_shred_is_not_a_loss() {
    let w = World::new(20);
    let store = w.store();
    let mut j = w.open(&store).unwrap();
    let (_, chunk) = write(&store, &mut j, 1);
    let mut wrong = shredded_record(chunk, 2);
    wrong.payload_ref = Some(chunk);
    assert!(matches!(j.append(wrong), Err(JournalError::InvalidRecord(_))));
    // Write-ahead, as the kernel shreds: the record is durable before the content goes.
    j.append(shredded_record(chunk, 3)).unwrap();
    j.sync().unwrap();
    store.shred(pocket(), chunk).unwrap();
    drop(j);
    drop(store);
    let (store, j) = w.restart(true);
    assert!(j.lost_payloads().is_empty(), "a shredded payload was reported lost");
    w.assert_never_silent(&store, "l5");
}

// ── Found by the crash schedules after the review fixes (WP3.A1 N1–N4) ───────────────────

/// N1: a chunk already on disk from an earlier process is replaced only by a flushed write. An
/// unflushed replacement, once its process died, would be made durable empty by the next
/// directory flush, under a record that was durable before.
#[test]
fn n1_a_rewrite_of_a_chunk_from_an_earlier_process_is_flushed() {
    let w = World::new(21);
    let store = w.store();
    let mut j = w.open(&store).unwrap();
    let (seq, x) = write(&store, &mut j, 1);
    w.clock.advance(1_100_000_000);
    j.sync().unwrap(); // the marker now names the record: no later open checks its payload
    drop(j);
    drop(store);
    w.sim.crash();
    // A process that did not write the content stores it again, then dies before any flush.
    let store = w.store();
    assert_eq!(store.put(pocket(), &content(1)).unwrap(), x);
    drop(store);
    // The next process flushes the pocket's directories, then the power goes.
    let (store, mut j) = w.restart(false);
    write(&store, &mut j, 2);
    j.sync().unwrap();
    drop(j);
    drop(store);
    let (store, _j) = w.restart(true);
    assert!(w.survey().0.iter().any(|(s, _, _)| *s == seq));
    assert_eq!(
        store.get(pocket(), x).ok(),
        Some(content(1)),
        "a durable payload was replaced by an unflushed copy"
    );
}

/// N2: a rewrite keeps the pair's data key, so a failure between the data-file and key-file
/// writes leaves the old key file opening the new data file.
#[test]
fn n2_a_rewrite_that_fails_between_its_two_files_leaves_a_readable_pair() {
    let w = World::new(22);
    let store = w.store();
    let x = store.put(pocket(), &content(1)).unwrap();
    store.sync_pending().unwrap();
    drop(store);
    w.sim.crash();
    let store = w.store();
    store.put(pocket(), &content(2)).unwrap(); // the pocket's directories are prepared
    // A flushed write is two flushes (file, directory): the data file's succeed, the key
    // file's first one fails.
    w.sim.fail_sync_after(2);
    assert!(store.put(pocket(), &content(1)).is_err());
    w.sim.fail_sync_after(u32::MAX);
    assert_eq!(
        store.get(pocket(), x).ok(),
        Some(content(1)),
        "new data was left paired with a key file that was never written"
    );
    drop(store);
    w.sim.power_loss();
    let store = w.store();
    assert_eq!(
        store.get(pocket(), x).ok(),
        Some(content(1)),
        "new data was left paired with a key file that was never written"
    );
}

/// N3: while a found loss waits to be journaled (the disk filled while it was reported), the
/// writer refuses records and flushes, so no record becomes durable before its loss record.
#[test]
fn n3_a_loss_waiting_to_be_journaled_holds_back_every_flush() {
    let w = World::new(23);
    let store = w.store();
    let mut j = w.open(&store).unwrap();
    let (seq, _) = write(&store, &mut j, 1);
    w.sim.fail_next_sync(); // the chunk's data file: the OS drops its unflushed pages
    assert_eq!(j.sync(), Err(JournalError::PayloadFlushFailed));
    w.fs.fail_segment_append_after(0);
    assert!(
        j.recover().is_err(),
        "the loss was found; its record could not be appended"
    );
    assert_eq!(
        j.sync(),
        Err(JournalError::DiskFull),
        "a flush ran while a loss waited to be journaled"
    );
    assert!(
        j.flushed_through().is_none_or(|f| f.0 < seq),
        "the record became durable before its loss record"
    );
    assert_eq!(j.append(draft(None, None, 2)), Err(JournalError::DiskFull));
    j.recover().unwrap();
    assert!(j.flushed_through().is_some_and(|f| f.0 > seq));
    drop(j);
    drop(store);
    let (_store, _j) = w.restart(true);
    assert!(w.survey().1.contains(&seq), "the loss is journaled and durable");
}

/// N4: open never flushes the previous run's segment again. After a failed flush, a second
/// flush of the same file can report success without writing anything (cache kept), and a
/// failing one drops what the OS held (cache dropped). Whatever flush fails during an open,
/// the previous run's records survive the next open and a power loss after it.
#[test]
fn n4_open_copies_the_previous_runs_records_instead_of_flushing_their_file_again() {
    for keep_cache in [false, true] {
        for k in 0..6 {
            let w = World::new(24);
            w.sim.set_failed_sync_keeps_cache(keep_cache);
            let plain = || {
                let clock: Arc<dyn Clock> = w.clock.clone();
                let rng: Arc<dyn Rng> = w.rng.clone();
                Journal::open(Arc::new(w.fs.clone()), clock, rng, &w.data, NEVER)
            };
            let mut j = plain().unwrap();
            for n in 0..3 {
                j.append(draft(None, None, n)).unwrap(); // with the OS only
            }
            drop(j);
            w.sim.crash();
            w.sim.fail_sync_after(k);
            // Whether this open fails depends on `k`; the records must survive either way.
            drop(plain());
            w.sim.fail_sync_after(u32::MAX);
            w.sim.crash();
            drop(plain().unwrap());
            w.sim.power_loss();
            let records = read_verified(&w.sim, &w.data.join(JOURNAL_DIR))
                .unwrap_or_else(|e| panic!("cache kept: {keep_cache}, fault after {k}: {e}"))
                .0;
            assert_eq!(
                records.len(),
                3,
                "cache kept: {keep_cache}, fault after {k}: the previous run's records were lost"
            );
        }
    }
}

// ── Second review of the fixes (WP3.A1, second round) ──────────────────────────────────────

/// Stops all I/O right after the `n`th successful MANIFEST write: the machine dies at that
/// instant. Used to cut an open between its manifest write and whatever follows.
#[derive(Debug, Clone)]
struct DieFs {
    inner: FaultFs,
    manifests_left: Arc<Mutex<u32>>,
    dead: Arc<AtomicBool>,
}

#[derive(Debug)]
struct DieAppend {
    inner: Box<dyn AppendFile>,
    dead: Arc<AtomicBool>,
}

impl AppendFile for DieAppend {
    fn append(&mut self, bytes: &[u8]) -> Result<(), FsError> {
        if self.dead.load(Ordering::SeqCst) {
            return Err(injected("dead"));
        }
        self.inner.append(bytes)
    }
    fn sync_data(&mut self) -> Result<(), FsError> {
        if self.dead.load(Ordering::SeqCst) {
            return Err(injected("dead"));
        }
        self.inner.sync_data()
    }
    fn os_len(&self) -> Result<u64, FsError> {
        self.inner.os_len()
    }
}

impl DieFs {
    fn new(inner: FaultFs, manifests: u32) -> Self {
        Self {
            inner,
            manifests_left: Arc::new(Mutex::new(manifests)),
            dead: Arc::new(AtomicBool::new(false)),
        }
    }
    fn alive(&self) -> Result<(), FsError> {
        if self.dead.load(Ordering::SeqCst) {
            Err(injected("dead"))
        } else {
            Ok(())
        }
    }
}

impl Fs for DieFs {
    fn create_dir_all(&self, p: &Path) -> Result<(), FsError> {
        self.alive()?;
        self.inner.create_dir_all(p)
    }
    fn open_append(&self, p: &Path) -> Result<Box<dyn AppendFile>, FsError> {
        self.alive()?;
        Ok(Box::new(DieAppend {
            inner: self.inner.open_append(p)?,
            dead: Arc::clone(&self.dead),
        }))
    }
    fn read(&self, p: &Path) -> Result<Vec<u8>, FsError> {
        self.alive()?;
        self.inner.read(p)
    }
    fn list_dir(&self, p: &Path) -> Result<Vec<PathBuf>, FsError> {
        self.alive()?;
        self.inner.list_dir(p)
    }
    fn rename(&self, a: &Path, b: &Path) -> Result<(), FsError> {
        self.alive()?;
        self.inner.rename(a, b)
    }
    fn remove_file(&self, p: &Path) -> Result<(), FsError> {
        self.alive()?;
        self.inner.remove_file(p)
    }
    fn sync_dir(&self, p: &Path) -> Result<(), FsError> {
        self.alive()?;
        self.inner.sync_dir(p)
    }
    fn write_atomic(&self, p: &Path, b: &[u8]) -> Result<(), FsError> {
        self.alive()?;
        let written = self.inner.write_atomic(p, b);
        if written.is_ok() && p.file_name().and_then(|n| n.to_str()) == Some("MANIFEST") {
            let mut left = self.manifests_left.lock().unwrap();
            if *left == 0 {
                self.dead.store(true, Ordering::SeqCst);
            } else {
                *left -= 1;
            }
        }
        written
    }
    fn write_unsynced(&self, p: &Path, b: &[u8]) -> Result<(), FsError> {
        self.alive()?;
        self.inner.write_unsynced(p, b)
    }
    fn sync_file(&self, p: &Path) -> Result<(), FsError> {
        self.alive()?;
        self.inner.sync_file(p)
    }
    fn try_lock_exclusive(&self, p: &Path) -> Result<Box<dyn LockGuard>, FsError> {
        self.alive()?;
        self.inner.try_lock_exclusive(p)
    }
}

/// Second-round H1: the previous run flushed three records with its marker lagging, then
/// crashed. The next open dies right after its first manifest write and the power goes: the
/// records it had acknowledged as durable must survive.
#[test]
fn r2_h1_a_power_loss_during_open_keeps_what_the_previous_run_flushed() {
    let w = World::new(900);
    let store = w.store();
    let mut j = w.open(&store).unwrap();
    for n in 0..3 {
        write(&store, &mut j, n);
    }
    j.sync().unwrap();
    let flushed = j.flushed_through().unwrap().0;
    drop(j);
    drop(store);
    w.sim.crash();

    let store = w.store();
    let die = DieFs::new(w.fs.clone(), 0);
    let clock: Arc<dyn Clock> = w.clock.clone();
    let rng: Arc<dyn Rng> = w.rng.clone();
    let opened = Journal::open_with_payloads(Arc::new(die.clone()), clock, rng, &w.data, NEVER, Arc::clone(&store));
    assert!(die.dead.load(Ordering::SeqCst), "the open stored a manifest");
    assert!(opened.is_err());
    drop(opened);
    drop(store);
    w.sim.power_loss();
    let (_store, _j) = w.restart(false);
    let present: BTreeSet<u64> = w.survey().0.iter().map(|r| r.0).collect();
    assert!(
        (0..=flushed).all(|s| present.contains(&s)),
        "records flushed and acknowledged by the previous run vanished: present {present:?}"
    );
}

/// Second-round H1, with faults: whatever flush or append fails during the open, and whether a
/// crash or a power loss follows, the records the previous run flushed survive.
#[test]
fn r2_h1_a_failed_open_keeps_what_the_previous_run_flushed() {
    let mut failures = Vec::new();
    for power in [false, true] {
        for keep_cache in [false, true] {
            for k in 0..30u32 {
                let w = World::new(901);
                w.sim.set_failed_sync_keeps_cache(keep_cache);
                let store = w.store();
                let mut j = w.open(&store).unwrap();
                for n in 0..3 {
                    write(&store, &mut j, n);
                }
                j.sync().unwrap();
                let flushed = j.flushed_through().unwrap().0;
                drop(j);
                drop(store);
                w.sim.crash();
                w.fs.fail_segment_append_after(1);
                w.sim.fail_sync_after(k);
                let store = w.store();
                let first = w.open(&store);
                let failed = first.is_err();
                drop(first);
                drop(store);
                w.fs.clear_append_fault();
                let (_s, _j) = w.restart(power);
                let present: BTreeSet<u64> = w.survey().0.iter().map(|r| r.0).collect();
                if !(0..=flushed).all(|s| present.contains(&s)) {
                    failures.push(format!(
                        "power {power}, cache kept {keep_cache}, fault after {k}, open failed {failed}: present {present:?}"
                    ));
                }
            }
        }
    }
    assert!(failures.is_empty(), "flushed records lost:\n{}", failures.join("\n"));
}

/// Second-round L1: a store poisoned before the journal attached is recovered at open, and the
/// marker is still written, so the journal cannot then be opened without its store.
#[test]
fn r2_l1_a_store_poisoned_before_the_journal_attached_is_recovered_at_open() {
    let w = World::new(902);
    let store = w.store();
    store.put(pocket(), &content(1)).unwrap();
    w.sim.fail_next_sync();
    assert!(store.sync_pending().is_err());
    let j = w.open(&store).unwrap();
    assert_eq!(j.health(), JournalHealth::Healthy);
    assert!(!store.is_poisoned(), "open left the store poisoned");
    drop(j);
    drop(store);
    w.sim.crash();
    let clock: Arc<dyn Clock> = w.clock.clone();
    let rng: Arc<dyn Rng> = w.rng.clone();
    let plain = Journal::open(Arc::new(w.fs.clone()), clock, rng, &w.data, NEVER);
    assert_eq!(
        plain.err(),
        Some(JournalError::PayloadsRequired),
        "a coordinated journal opened without its store"
    );
}

/// Second-round M1 (1): recovery from a full disk while a loss waits to be journaled moves the
/// unflushed records without flushing them, so a power loss cannot leave a record durable
/// ahead of its loss record.
#[test]
fn r2_m1_disk_full_recovery_never_flushes_a_record_before_its_loss_record() {
    let w = World::new(903);
    let store = w.store();
    let mut j = w.open(&store).unwrap();
    let (seq, _) = write(&store, &mut j, 1);
    w.sim.fail_next_sync(); // the chunk's data file: the OS drops its unflushed pages
    assert_eq!(j.sync(), Err(JournalError::PayloadFlushFailed));
    w.fs.fail_segment_append_after(0);
    assert!(j.recover().is_err(), "the loss record could not be appended");
    // The next recovery moves the records, then its loss-record append fails again.
    w.fs.fail_segment_append_after(1);
    assert!(j.recover().is_err());
    drop(j);
    drop(store);
    w.sim.power_loss();
    let (records, reported, _) = w.survey();
    assert!(
        !records.iter().any(|(s, _, _)| *s == seq) || reported.contains(&seq),
        "the record became durable before its loss record"
    );
}

/// Second-round M1 (2): the same after a failed relocation (`FlushFailed`): retrying it does not
/// flush the records ahead of their loss record either.
#[test]
fn r2_m1_a_failed_relocation_never_flushes_a_record_before_its_loss_record() {
    let w = World::new(904);
    let store = w.store();
    let mut j = w.open(&store).unwrap();
    let (seq, _) = write(&store, &mut j, 1);
    w.sim.fail_next_sync();
    assert_eq!(j.sync(), Err(JournalError::PayloadFlushFailed));
    w.fs.fail_segment_append_after(0);
    assert!(j.recover().is_err(), "the loss record could not be appended");
    w.fs.fail_segment_append_after(0); // the relocation's own append fails
    assert!(j.recover().is_err());
    assert_eq!(j.health(), JournalHealth::FlushFailed);
    w.fs.fail_segment_append_after(1); // the relocation succeeds, the loss record fails again
    assert!(j.recover().is_err());
    drop(j);
    drop(store);
    w.sim.power_loss();
    let (records, reported, _) = w.survey();
    assert!(
        !records.iter().any(|(s, _, _)| *s == seq) || reported.contains(&seq),
        "the record became durable before its loss record"
    );
}

/// Second-round M1 (4): a pair left unflushed by an earlier process is rewritten, flushed,
/// before a record may reference it, so a power loss after the marker passed the record
/// cannot take the payload.
#[test]
fn r2_m1_is_stored_rewrites_an_earlier_processs_unflushed_pair() {
    let w = World::new(905);
    let store = w.store();
    let x = store.put(pocket(), &content(1)).unwrap(); // never flushed, no record
    drop(store);
    w.sim.crash();
    let (store, mut j) = w.restart(false);
    j.append(draft(Some(pocket()), Some(x), 1)).unwrap();
    w.clock.advance(1_100_000_000);
    j.sync().unwrap(); // the marker now passes the record
    drop(j);
    drop(store);
    let (store, _j) = w.restart(true);
    assert!(
        store.get(pocket(), x).is_ok() || w.survey().1.contains(&0),
        "a record became durable over a payload only an earlier process had written"
    );
}

/// Second-round M1 (5): a pending chunk whose files vanished is a flush failure, never success.
#[test]
fn r2_m1_a_pending_file_removed_underneath_is_a_flush_failure() {
    let w = World::new(906);
    let store = w.store();
    let mut j = w.open(&store).unwrap();
    let (seq, x) = write(&store, &mut j, 1);
    let name = x.to_string();
    let key_file = w
        .data
        .join(CHUNKS_DIR)
        .join(pocket().to_string())
        .join("keys")
        .join(format!("{}.key", name.strip_prefix("hmac-sha256:").unwrap()));
    w.sim.remove_file(&key_file).unwrap();
    assert_eq!(
        j.sync(),
        Err(JournalError::PayloadFlushFailed),
        "a flush succeeded although a pending payload's file was gone"
    );
    j.recover().unwrap();
    assert_eq!(j.lost_payloads().len(), 1);
    assert_eq!(j.lost_payloads()[0].record_seq.0, seq);
}

/// Second-round M1 (6): a loss found by recovery survives a failed quarantine and is reported
/// by the next recovery.
#[test]
fn r2_m1_a_failed_quarantine_never_drops_a_loss() {
    let w = World::new(907);
    let store = w.store();
    let mut j = w.open(&store).unwrap();
    let (seq, _) = write(&store, &mut j, 1);
    w.sim.fail_next_sync();
    assert_eq!(j.sync(), Err(JournalError::PayloadFlushFailed));
    w.fs.fail_key_rename.store(true, Ordering::SeqCst); // the quarantine fails
    assert!(j.recover().is_err());
    j.recover().unwrap();
    assert_eq!(
        j.lost_payloads().iter().map(|l| l.record_seq.0).collect::<Vec<_>>(),
        vec![seq],
        "the loss was dropped by the failed quarantine"
    );
}

/// Second-round L2: in balanced mode a failed directory flush poisons the store.
#[test]
fn r2_l2_a_failed_directory_flush_poisons_a_balanced_store() {
    let w = World::new(908);
    let store = w.store();
    let keep = store.put(pocket(), &content(1)).unwrap();
    let doomed = store.put(pocket(), &content(2)).unwrap();
    store.sync_pending().unwrap();
    let _pending = store.put(pocket(), &content(3)).unwrap();
    w.sim.fail_next_sync(); // the shred's first directory flush
    assert!(store.shred(pocket(), doomed).is_err());
    assert!(store.is_poisoned(), "a failed directory flush did not poison the store");
    assert_eq!(store.put(pocket(), &content(4)), Err(ChunkError::FlushFailed));
    assert!(store.get(pocket(), keep).is_ok());
}

/// Second-round L5: puts past the pending bound are refused, and a journal flush clears it.
#[test]
fn r2_l5_pending_full_is_refused_and_cleared_by_a_flush() {
    let w = World::new(909);
    let store = w.store();
    let mut j = w.open(&store).unwrap();
    let base = 1_000_000u64;
    for n in 0..u64::try_from(MAX_PENDING).unwrap() {
        store.put(pocket(), &content(base + n)).unwrap();
    }
    assert_eq!(store.put(pocket(), &content(1)), Err(ChunkError::PendingFull));
    j.append(draft(None, None, 1)).unwrap();
    j.sync().unwrap();
    assert_eq!(store.pending_len(), 0);
    store.put(pocket(), &content(1)).unwrap();
}

/// A shred whose record is durable but whose files a crash left behind is completed when the
/// journal opens; without that, the store's startup re-wraps the leftover key and the content
/// stays readable (pre-existing, found by the second review).
#[test]
fn a_shred_interrupted_after_its_record_is_completed_at_open() {
    let w = World::new(910);
    let store = w.store();
    let mut j = w.open(&store).unwrap();
    let (_, x) = write(&store, &mut j, 1);
    let (_, y) = write(&store, &mut j, 2);
    j.sync().unwrap();
    j.append(shredded_record(x, 3)).unwrap();
    j.sync().unwrap(); // write-ahead: the shred's record is durable first
    w.fs.fail_key_remove.store(true, Ordering::SeqCst);
    assert!(
        store.shred(pocket(), x).is_err(),
        "the KEK rotated, then the removal failed"
    );
    drop(j);
    drop(store);
    let (store, _j) = w.restart(true);
    assert_eq!(
        store.get(pocket(), x).err(),
        Some(ChunkError::Unavailable),
        "content whose shred was journaled is still readable"
    );
    assert_eq!(store.get(pocket(), y).ok(), Some(content(2)));
    w.assert_never_silent(&store, "interrupted shred");
}

/// A shred is completed at open only once its record is durable. Here the record was with the
/// OS only, the open fails before its flush, and the power goes: the record is gone, so the
/// content it named must still be there (found by the crash schedules in the second round).
#[test]
fn r2_a_shred_is_completed_only_once_its_record_is_durable() {
    let w = World::new(911);
    let store = w.store();
    let mut j = w.open(&store).unwrap();
    let (_, x) = write(&store, &mut j, 1);
    j.sync().unwrap();
    j.append(shredded_record(x, 2)).unwrap(); // with the OS only; the shred never ran
    drop(j);
    drop(store);
    w.sim.crash();
    w.fs.fail_segment_append_after(0); // the open's copy of the shred record fails
    let store = w.store();
    assert!(w.open(&store).is_err());
    drop(store);
    w.sim.power_loss(); // the shred record is gone
    let store = w.store();
    assert_eq!(
        store.get(pocket(), x).ok(),
        Some(content(1)),
        "a shred ran on a record a power loss took away"
    );
}

// ── Random crash schedules ─────────────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
enum Op {
    /// Store a new payload and append a record that references it.
    Write,
    /// Append a record that references an earlier payload again.
    Repeat(usize),
    /// Shred an earlier payload and journal it.
    Shred(usize),
    Sync,
    /// Let `n` flushes succeed, then fail the next.
    FailSyncAfter(u32),
    /// The next segment append fails with `NoSpace`.
    FailAppend,
    /// Advance the clock past the marker interval.
    Tick,
    Crash,
    PowerLoss,
    Recover,
}

fn op() -> impl Strategy<Value = Op> {
    prop_oneof![
        6 => Just(Op::Write),
        2 => (0usize..64).prop_map(Op::Repeat),
        1 => (0usize..64).prop_map(Op::Shred),
        3 => Just(Op::Sync),
        2 => (0u32..4).prop_map(Op::FailSyncAfter),
        1 => Just(Op::FailAppend),
        1 => Just(Op::Tick),
        1 => Just(Op::Crash),
        1 => Just(Op::PowerLoss),
        2 => Just(Op::Recover),
    ]
}

/// `os_holds_unflushed`: whether records after the flushed boundary were with the OS when the
/// process died; not after a failed segment flush whose rewrite also failed (`FlushFailed`: those
/// records lived only in memory, ADR-0003). `reported_before`: losses already journaled.
fn check(
    w: &World,
    store: &ChunkStore,
    acked: &BTreeMap<u64, u64>,
    flushed: Option<u64>,
    power: bool,
    os_holds_unflushed: bool,
    reported_before: &BTreeSet<u64>,
) {
    w.assert_never_silent(store, "schedule");
    let (records, _, shreds) = w.survey();
    let present: BTreeMap<u64, ChunkRef> = records.iter().map(|(s, _, c)| (*s, *c)).collect();
    for seq in acked.keys() {
        let flushed_here = flushed.is_some_and(|f| *seq <= f);
        if !(flushed_here || (!power && os_holds_unflushed)) {
            continue;
        }
        let chunk = present
            .get(seq)
            .unwrap_or_else(|| panic!("acknowledged record {seq} is gone"));
        let shredded = shreds.iter().any(|(_, sc, ss)| *sc == chunk.to_string() && ss > seq);
        if power && !reported_before.contains(seq) && !shredded {
            assert!(
                store.get(pocket(), *chunk).is_ok(),
                "flushed record {seq} lost its payload"
            );
        }
    }
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(64))]

    #[test]
    fn payload_durability_under_random_crash_schedules(
        seed in any::<u64>(),
        keep_cache in any::<bool>(),
        ops in prop::collection::vec(op(), 1..80),
    ) {
        let w = World::new(seed);
        w.sim.set_failed_sync_keeps_cache(keep_cache);
        let mut store = w.store();
        let mut journal = w.open(&store).unwrap();
        let mut contents: Vec<u64> = Vec::new();
        let mut acked: BTreeMap<u64, u64> = BTreeMap::new();
        let mut next = 0u64;
        for op in ops {
            match op {
                Op::Write | Op::Repeat(_) => {
                    let n = match op {
                        Op::Repeat(i) if !contents.is_empty() => contents[i % contents.len()],
                        _ => { next += 1; contents.push(next); next }
                    };
                    let Ok(chunk) = store.put(pocket(), &content(n)) else { continue };
                    if let Ok(a) = journal.append(draft(Some(pocket()), Some(chunk), n)) {
                        acked.insert(a.seq.0, n);
                    }
                }
                Op::Shred(i) if !contents.is_empty() => {
                    let n = contents[i % contents.len()];
                    let Ok(chunk) = store.reference(pocket(), &content(n)) else { continue };
                    // Write-ahead: the shred runs only once its record is durable, so a power
                    // loss can never leave references to removed content unexplained. A failed
                    // shred is retried once; the record already covers whatever it removed.
                    if journal.append(shredded_record(chunk, n)).is_ok() && journal.sync().is_ok()
                        && store.shred(pocket(), chunk).is_err()
                    {
                        let _outcome = store.shred(pocket(), chunk);
                    }
                }
                Op::Shred(_) => {}
                // Failures are part of the schedule; the checks after each crash judge the outcome.
                Op::Sync => { let _outcome = journal.sync(); }
                Op::FailSyncAfter(n) => w.sim.fail_sync_after(n),
                Op::FailAppend => w.fs.fail_segment_append_after(0),
                Op::Tick => w.clock.advance(1_100_000_000),
                Op::Recover => { let _outcome = journal.recover(); }
                Op::Crash | Op::PowerLoss => {
                    let power = matches!(op, Op::PowerLoss);
                    let flushed = journal.flushed_through().map(|s| s.0);
                    let os_holds_unflushed = journal.health() != JournalHealth::FlushFailed;
                    let (_, reported_before, _) = w.survey();
                    drop(journal);
                    drop(store);
                    if power { w.sim.power_loss() } else { w.sim.crash() }
                    // Faults armed before the crash may still hit this open; then open again.
                    // A failed open must not cost anything the OS held (it copies the previous
                    // run's records instead of flushing their file again).
                    store = w.store();
                    // After a failed open, the machine either crashes or loses power (alternating
                    // by schedule); after a power loss only flushed records are owed.
                    let mut lost_power = power;
                    journal = if let Ok(j) = w.open(&store) {
                        j
                    } else {
                        w.sim.fail_sync_after(u32::MAX);
                        w.fs.clear_append_fault();
                        drop(store);
                        if acked.len().is_multiple_of(2) {
                            w.sim.power_loss();
                            lost_power = true;
                        } else {
                            w.sim.crash();
                        }
                        store = w.store();
                        w.open(&store).unwrap()
                    };
                    check(&w, &store, &acked, flushed, lost_power, os_holds_unflushed, &reported_before);
                    let (records, _, _) = w.survey();
                    let present: BTreeSet<u64> = records.iter().map(|(s, _, _)| *s).collect();
                    acked.retain(|s, _| present.contains(s));
                }
            }
        }
    }
}

// ── S-6: two writers of one chunk ──────────────────────────────────────────────────────────

#[test]
fn concurrent_puts_of_one_chunk_never_pair_data_with_the_wrong_key() {
    for durability in [ChunkDurability::Balanced, ChunkDurability::Strict] {
        let w = World::new(9);
        let store = w.try_store(durability).unwrap();
        let body = content(42);
        w.fs.key_write.arm();

        // Writer A stores its data file, then is held before its key file.
        let a = {
            let (store, body) = (Arc::clone(&store), body.clone());
            std::thread::spawn(move || store.put(pocket(), &body))
        };
        w.fs.key_write.wait_held();
        // Writer B arrives for the same content. Without one writer per chunk it would replace
        // A's data file and write its own key, and A's late key would then open nothing.
        let b = {
            let (store, body) = (Arc::clone(&store), body.clone());
            std::thread::spawn(move || store.put(pocket(), &body))
        };
        for _ in 0..50 {
            if b.is_finished() {
                break;
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        w.fs.key_write.release();
        let chunk = a.join().unwrap().unwrap();
        assert_eq!(b.join().unwrap().unwrap(), chunk);
        assert_eq!(
            store.get(pocket(), chunk).ok(),
            Some(body),
            "{durability:?}: two writers of one chunk left a data file paired with the other's key"
        );
    }
}
