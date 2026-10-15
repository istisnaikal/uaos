// SPDX-License-Identifier: Apache-2.0

//! ADR-0018: chunk payloads join the journal's durability classes, under deterministic crash
//! simulation, plus the S-6 chunk race (two writers of one chunk).
//!
//! Guarantees checked:
//! * **payload before record:** a record that references a chunk not yet stored is refused;
//! * after a **process crash**, every acknowledged record is present and its payload readable,
//!   unless an earlier failed flush dropped it and the loss was reported;
//! * after a **power loss**, every record up to the flushed boundary is present and its payload
//!   readable;
//! * **never silent:** a surviving record whose payload is unreadable has a `chunk.lost` record.

#![allow(
    clippy::unwrap_used,
    clippy::panic,
    clippy::disallowed_methods,
    reason = "test harness: fixtures and checks abort on failure; the race test needs real threads and time"
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
use uaos_state::chunks::keyring::{MemoryKeyring, PocketKeyring};
use uaos_state::chunks::{ChunkDurability, ChunkStore};
use uaos_state::journal::{EventDraft, FlushPolicy, JOURNAL_DIR, Journal, JournalError, JournalHealth, read_verified};

const DATA: &str = "/data";
/// A window longer than any test, so only explicit `sync` calls flush.
const NEVER: FlushPolicy = FlushPolicy::Balanced {
    window: Millis(u64::MAX / 2),
};

struct World {
    fs: SimFs,
    clock: Arc<SimClock>,
    rng: Arc<SimRng>,
    /// Survives simulated crashes, like an OS keychain.
    keys: Arc<MemoryKeyring>,
    data: PathBuf,
}

impl World {
    fn new(seed: u64) -> Self {
        let fs = SimFs::new();
        fs.create_dir_all(Path::new(DATA)).unwrap();
        let rng = Arc::new(SimRng::new(seed));
        Self {
            fs,
            clock: Arc::new(SimClock::new(
                WallTime::from_unix_nanos(1_760_000_000_000_000_000).unwrap(),
            )),
            keys: Arc::new(MemoryKeyring::new(rng.clone())),
            rng,
            data: PathBuf::from(DATA),
        }
    }

    fn store(&self) -> Arc<ChunkStore> {
        let rng: Arc<dyn Rng> = self.rng.clone();
        let keys: Arc<dyn PocketKeyring> = self.keys.clone();
        Arc::new(
            ChunkStore::open_with(
                Arc::new(self.fs.clone()),
                rng,
                keys,
                &self.data,
                ChunkDurability::Balanced,
            )
            .unwrap(),
        )
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

    /// (seq, pocket, payload) of every record with a payload, and the record seqs reported lost.
    fn survey(&self) -> (Vec<(u64, PocketId, ChunkRef)>, BTreeSet<u64>) {
        let (records, _) = read_verified(&self.fs, &self.data.join(JOURNAL_DIR)).unwrap();
        let mut with_payload = Vec::new();
        let mut reported = BTreeSet::new();
        for r in records {
            let e = r.envelope;
            if e.event_type == types::CHUNK_LOST {
                reported.insert(e.metadata.as_map()["record_seq"].parse::<u64>().unwrap());
            } else if let (Some(p), Some(c)) = (e.pocket_id, e.payload_ref) {
                with_payload.push((e.seq.0, p, c));
            }
        }
        (with_payload, reported)
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

fn content(n: u64) -> Vec<u8> {
    format!("payload {n} ").repeat(32).into_bytes()
}

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
    let chunk = store.put(pocket(), &content(1)).unwrap();
    assert_eq!(store.pending_len(), 1, "a balanced put is not flushed by itself");
    journal.append(draft(Some(pocket()), Some(chunk), 1)).unwrap();
    journal.sync().unwrap();
    assert_eq!(store.pending_len(), 0, "the journal's flush flushes the payloads first");
    let flushed = journal.flushed_through().unwrap().0;
    drop(journal);

    w.fs.power_loss();
    let store = w.store();
    let journal = w.open(&store).unwrap();
    assert!(journal.lost_payloads().is_empty());
    let (records, _) = w.survey();
    assert!(records.iter().any(|(seq, _, _)| *seq == flushed));
    assert_eq!(store.get(pocket(), chunk).unwrap(), content(1));
}

#[test]
fn unflushed_payloads_lost_to_power_are_never_silent() {
    let w = World::new(3);
    let store = w.store();
    let mut journal = w.open(&store).unwrap();
    let a = store.put(pocket(), &content(1)).unwrap();
    journal.append(draft(Some(pocket()), Some(a), 1)).unwrap();
    journal.sync().unwrap();
    // Unflushed: the record's bytes and its chunk are with the OS only.
    let b = store.put(pocket(), &content(2)).unwrap();
    journal.append(draft(Some(pocket()), Some(b), 2)).unwrap();
    drop(journal);
    w.fs.power_loss();

    let store = w.store();
    let journal = w.open(&store).unwrap();
    let (records, reported) = w.survey();
    for (seq, p, c) in &records {
        assert!(
            store.get(*p, *c).is_ok() || reported.contains(seq),
            "record {seq} survived with an unreadable payload and no chunk.lost record"
        );
    }
    drop(journal);
}

/// The deterministic form of the ADR-0018 ordering rule: whatever flush fails, and whenever the
/// power goes, a record at or before the flushed boundary has a readable payload.
#[test]
fn a_flushed_record_never_references_an_unreadable_payload() {
    for k in 0..12 {
        let w = World::new(100 + u64::from(k));
        let store = w.store();
        let mut journal = w.open(&store).unwrap();
        for n in 0..3 {
            let chunk = store.put(pocket(), &content(n)).unwrap();
            journal.append(draft(Some(pocket()), Some(chunk), n)).unwrap();
        }
        w.fs.fail_sync_after(k);
        // Whether this flush fails depends on `k`; the guarantee must hold either way.
        let _outcome = journal.sync();
        let flushed = journal.flushed_through().map(|s| s.0);
        drop(journal);
        w.fs.fail_sync_after(u32::MAX);
        w.fs.power_loss();

        let store = w.store();
        let _journal = w.open(&store).unwrap();
        let (records, reported) = w.survey();
        for (seq, p, c) in records {
            let readable = store.get(p, c).is_ok();
            if flushed.is_some_and(|f| seq <= f) {
                assert!(
                    readable,
                    "fault after {k} flushes: flushed record {seq} lost its payload"
                );
            }
            assert!(
                readable || reported.contains(&seq),
                "record {seq} lost its payload silently"
            );
        }
    }
}

#[test]
fn a_failed_payload_flush_stops_the_writer_until_recovery_reports_the_loss() {
    let w = World::new(4);
    let store = w.store();
    let mut journal = w.open(&store).unwrap();
    let chunk = store.put(pocket(), &content(1)).unwrap();
    let acked = journal.append(draft(Some(pocket()), Some(chunk), 1)).unwrap();
    w.fs.fail_next_sync(); // the chunk's data file: the OS drops its unflushed pages
    assert_eq!(journal.sync(), Err(JournalError::Stopped));
    assert_eq!(journal.health(), JournalHealth::PayloadFlushFailed);
    assert_eq!(journal.append(draft(None, None, 2)), Err(JournalError::Stopped));

    journal.recover().unwrap();
    assert_eq!(journal.health(), JournalHealth::Healthy);
    assert_eq!(journal.lost_payloads().len(), 1);
    assert_eq!(journal.lost_payloads()[0].record_seq, acked.seq);
    drop(journal);
    let (_, reported) = w.survey();
    assert!(reported.contains(&acked.seq.0), "the loss is journaled as chunk.lost");
}

#[test]
fn rotation_rewraps_are_durable_in_balanced_mode() {
    let w = World::new(5);
    let store = w.store();
    let keep = store.put(pocket(), &content(1)).unwrap();
    let doomed = store.put(pocket(), &content(2)).unwrap();
    store.sync_pending().unwrap();
    store.shred(pocket(), doomed).unwrap(); // rotates the KEK, re-wraps `keep`, retires the old KEK
    w.fs.power_loss();
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
    w.fs.sync_dir(&w.data.join("chunks").join(pocket().to_string()).join("data"))
        .unwrap();
    w.fs.sync_dir(&w.data.join("chunks").join(pocket().to_string()).join("keys"))
        .unwrap();
    w.fs.power_loss();
    let store = w.store();
    assert!(store.get(pocket(), chunk).is_err());
    assert!(!store.is_stored(pocket(), chunk).unwrap());
    assert_eq!(store.put(pocket(), &content(1)).unwrap(), chunk);
    assert_eq!(store.get(pocket(), chunk).unwrap(), content(1));
}

// ── Random crash schedules ──────────────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
enum Op {
    /// Store a new payload and append a record that references it.
    Write,
    /// Append a record that references an earlier payload again.
    Repeat(usize),
    Sync,
    FailNextSync,
    Crash,
    PowerLoss,
    Recover,
}

fn op() -> impl Strategy<Value = Op> {
    prop_oneof![
        6 => Just(Op::Write),
        2 => (0usize..64).prop_map(Op::Repeat),
        3 => Just(Op::Sync),
        1 => Just(Op::FailNextSync),
        1 => Just(Op::Crash),
        1 => Just(Op::PowerLoss),
        1 => Just(Op::Recover),
    ]
}

/// `os_holds_unflushed`: whether records after the flushed boundary were with the OS when the
/// process died. They are not after a failed segment flush whose rewrite also failed
/// ([`JournalHealth::FlushFailed`]: those records lived only in memory, ADR-0003).
/// `reported_before`: records whose payload loss was already journaled before this crash (a
/// failed flush can drop a payload; the record then stands with a `chunk.lost` record).
fn check(
    w: &World,
    store: &ChunkStore,
    acked: &BTreeMap<u64, u64>,
    flushed: Option<u64>,
    power: bool,
    os_holds_unflushed: bool,
    reported_before: &BTreeSet<u64>,
) {
    let (records, reported) = w.survey();
    let present: BTreeMap<u64, ChunkRef> = records.iter().map(|(s, _, c)| (*s, *c)).collect();
    for (seq, p, c) in &records {
        assert!(
            store.get(*p, *c).is_ok() || reported.contains(seq),
            "record {seq} lost its payload silently"
        );
    }
    for seq in acked.keys() {
        let flushed_here = flushed.is_some_and(|f| *seq <= f);
        let must_survive = flushed_here || (!power && os_holds_unflushed);
        if must_survive {
            let chunk = present
                .get(seq)
                .unwrap_or_else(|| panic!("acknowledged record {seq} is gone"));
            if power && !reported_before.contains(seq) {
                assert!(
                    store.get(pocket(), *chunk).is_ok(),
                    "flushed record {seq} lost its payload"
                );
            }
        }
    }
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(64))]

    #[test]
    fn payload_durability_under_random_crash_schedules(seed in any::<u64>(), ops in prop::collection::vec(op(), 1..60)) {
        let w = World::new(seed);
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
                // Failures are part of the schedule; the checks after each crash judge the outcome.
                Op::Sync => { let _outcome = journal.sync(); }
                Op::FailNextSync => w.fs.fail_next_sync(),
                Op::Recover => { let _outcome = journal.recover(); }
                Op::Crash | Op::PowerLoss => {
                    let power = matches!(op, Op::PowerLoss);
                    let flushed = journal.flushed_through().map(|s| s.0);
                    let os_holds_unflushed = journal.health() != JournalHealth::FlushFailed;
                    let (_, reported_before) = w.survey();
                    drop(journal);
                    w.fs.fail_sync_after(u32::MAX);
                    if power { w.fs.power_loss() } else { w.fs.crash() }
                    store = w.store();
                    journal = w.open(&store).unwrap();
                    check(&w, &store, &acked, flushed, power, os_holds_unflushed, &reported_before);
                    // What survives is the new truth; the model follows it.
                    let (records, _) = w.survey();
                    let present: BTreeSet<u64> = records.iter().map(|(s, _, _)| *s).collect();
                    acked.retain(|s, _| present.contains(s));
                }
            }
        }
    }
}

// ── S-6: two writers of one chunk ───────────────────────────────────────────────────────────

/// A filesystem that holds the first key-file write until released, so a test can place a
/// second writer exactly between another writer's data file and its key file.
#[derive(Debug, Clone)]
struct GateFs {
    inner: SimFs,
    gate: Arc<Gate>,
}

#[derive(Debug, Default)]
struct Gate {
    armed: AtomicBool,
    held: AtomicBool,
    open: Mutex<bool>,
    opened: Condvar,
}

impl GateFs {
    fn hold_first_key_write(&self, path: &Path) {
        let is_key = path.extension().and_then(|e| e.to_str()) == Some("key");
        if is_key && self.gate.armed.swap(false, Ordering::SeqCst) {
            self.gate.held.store(true, Ordering::SeqCst);
            let mut open = self.gate.open.lock().unwrap();
            while !*open {
                open = self.gate.opened.wait(open).unwrap();
            }
        }
    }

    fn release(&self) {
        *self.gate.open.lock().unwrap() = true;
        self.gate.opened.notify_all();
    }
}

impl Fs for GateFs {
    fn create_dir_all(&self, path: &Path) -> Result<(), FsError> {
        self.inner.create_dir_all(path)
    }
    fn open_append(&self, path: &Path) -> Result<Box<dyn AppendFile>, FsError> {
        self.inner.open_append(path)
    }
    fn read(&self, path: &Path) -> Result<Vec<u8>, FsError> {
        self.inner.read(path)
    }
    fn list_dir(&self, path: &Path) -> Result<Vec<PathBuf>, FsError> {
        self.inner.list_dir(path)
    }
    fn rename(&self, from: &Path, to: &Path) -> Result<(), FsError> {
        self.inner.rename(from, to)
    }
    fn remove_file(&self, path: &Path) -> Result<(), FsError> {
        self.inner.remove_file(path)
    }
    fn sync_dir(&self, path: &Path) -> Result<(), FsError> {
        self.inner.sync_dir(path)
    }
    fn write_atomic(&self, path: &Path, bytes: &[u8]) -> Result<(), FsError> {
        self.hold_first_key_write(path);
        self.inner.write_atomic(path, bytes)
    }
    fn write_unsynced(&self, path: &Path, bytes: &[u8]) -> Result<(), FsError> {
        self.hold_first_key_write(path);
        self.inner.write_unsynced(path, bytes)
    }
    fn sync_file(&self, path: &Path) -> Result<(), FsError> {
        self.inner.sync_file(path)
    }
    fn try_lock_exclusive(&self, path: &Path) -> Result<Box<dyn LockGuard>, FsError> {
        self.inner.try_lock_exclusive(path)
    }
}

#[test]
fn concurrent_puts_of_one_chunk_never_pair_data_with_the_wrong_key() {
    for durability in [ChunkDurability::Balanced, ChunkDurability::Strict] {
        let sim = SimFs::new();
        sim.create_dir_all(Path::new(DATA)).unwrap();
        let fs = GateFs {
            inner: sim,
            gate: Arc::new(Gate::default()),
        };
        let rng: Arc<dyn Rng> = Arc::new(SimRng::new(9));
        let keys: Arc<dyn PocketKeyring> = Arc::new(MemoryKeyring::new(Arc::clone(&rng)));
        let store =
            Arc::new(ChunkStore::open_with(Arc::new(fs.clone()), rng, keys, Path::new(DATA), durability).unwrap());
        let body = content(42);
        fs.gate.armed.store(true, Ordering::SeqCst);

        // Writer A stores its data file, then is held before its key file.
        let a = {
            let (store, body) = (Arc::clone(&store), body.clone());
            std::thread::spawn(move || store.put(pocket(), &body))
        };
        while !fs.gate.held.load(Ordering::SeqCst) {
            std::thread::sleep(Duration::from_millis(1));
        }
        // Writer B arrives for the same content. Without one writer per chunk it would replace
        // A's data file and write its own key, and A's late key would then open nothing.
        let b = {
            let (store, body) = (Arc::clone(&store), body.clone());
            std::thread::spawn(move || store.put(pocket(), &body))
        };
        for _ in 0..200 {
            if b.is_finished() {
                break;
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        fs.release();
        let chunk = a.join().unwrap().unwrap();
        assert_eq!(b.join().unwrap().unwrap(), chunk);
        assert_eq!(
            store.get(pocket(), chunk).ok(),
            Some(body),
            "{durability:?}: two writers of one chunk left a data file paired with the other's key"
        );
    }
}
