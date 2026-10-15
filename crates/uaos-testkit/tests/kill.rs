// SPDX-License-Identifier: Apache-2.0

//! The `journal-durability` gate (CLAUDE.md §4, ADR-0003, ADR-0018): kill a real writer process
//! at random points and prove that every acknowledged record survives, unchanged, on the real
//! filesystem, **and so does the payload it references**: in balanced mode chunks are only
//! handed to the OS, never flushed, before the record that references them is acknowledged.
//!
//! Kill points alternate between "after k acknowledgements" and "after a random delay", so the
//! writer is caught both blocked on its output and in the middle of journal I/O. Iterations:
//! `UAOS_CRASH_ITERATIONS` (default 40 per merge; nightly runs use 10,000). Seed:
//! `UAOS_CRASH_SEED` (printed on failure for replay).

#![allow(
    clippy::unwrap_used,
    clippy::print_stderr,
    clippy::disallowed_methods,
    reason = "process-level test harness: real processes, real files, a real clock"
)]

use std::collections::BTreeMap;
use std::io::{BufRead, BufReader};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::Duration;

use std::sync::Arc;

use uaos_contracts::digest::{ChunkRef, Sha256Digest};
use uaos_platform::Rng;
use uaos_platform::real::OsRng;
use uaos_platform::real::fs::OsFs;
use uaos_platform::sim::SimRng;
use uaos_state::chunks::ChunkStore;
use uaos_state::journal::{JOURNAL_DIR, read_verified};
use uaos_testkit::{kill_keyring, kill_payload, kill_pocket};

const WRITER: &str = env!("CARGO_BIN_EXE_journal-crash-writer");
/// Start a fresh data directory this often, so long nightly runs stay bounded in size.
const ITERATIONS_PER_DIRECTORY: u32 = 25;

fn env_u64(name: &str, default: u64) -> u64 {
    std::env::var(name).ok().and_then(|v| v.parse().ok()).unwrap_or(default)
}

fn random_below(rng: &SimRng, bound: u64) -> u64 {
    let mut b = [0u8; 8];
    rng.fill(&mut b).unwrap();
    u64::from_le_bytes(b) % bound.max(1)
}

fn scratch_root() -> PathBuf {
    let dir = std::env::temp_dir().join(format!("uaos-kill-{}", std::process::id()));
    let _stale = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

fn spawn(data: &Path, mode: &str) -> Child {
    Command::new(WRITER)
        .arg(data)
        .arg(mode)
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .spawn()
        .unwrap()
}

/// Parses `<seq> <hash> <chunk>` acknowledgement lines; ignores a torn final line.
fn parse_ack(line: &str) -> Option<(u64, (Sha256Digest, ChunkRef))> {
    if !line.ends_with('\n') {
        return None;
    }
    let mut words = line.trim_end_matches(['\r', '\n']).split(' ');
    let seq = words.next()?.parse().ok()?;
    let hash = words.next()?.parse().ok()?;
    let chunk = words.next()?.parse().ok()?;
    Some((seq, (hash, chunk)))
}

#[test]
fn kill_minus_nine_loses_no_acknowledged_record() {
    let iterations = u32::try_from(env_u64("UAOS_CRASH_ITERATIONS", 40)).unwrap();
    let seed = env_u64("UAOS_CRASH_SEED", 0x005E_ED0F_CA5E);
    let rng = SimRng::new(seed);
    let root = scratch_root();
    let mut data = root.join("gen-0");
    let mut acked: BTreeMap<u64, (Sha256Digest, ChunkRef)> = BTreeMap::new();
    let mut total_acked = 0u64;

    for i in 0..iterations {
        if i > 0 && i % ITERATIONS_PER_DIRECTORY == 0 {
            data = root.join(format!("gen-{}", i / ITERATIONS_PER_DIRECTORY));
            acked.clear();
        }
        let mode = if i % 2 == 0 { "balanced" } else { "strict" };
        let mut child = spawn(&data, mode);
        let mut reader = BufReader::new(child.stdout.take().unwrap());

        let mut first = String::new();
        reader.read_line(&mut first).unwrap();
        let start: u64 = first
            .trim()
            .strip_prefix("start ")
            .and_then(|s| s.parse().ok())
            .unwrap_or_else(|| panic!("seed {seed:#x}, iteration {i}: writer did not start: {first:?}"));
        assert!(
            start >= acked.keys().next_back().map_or(0, |s| s + 1),
            "seed {seed:#x}, iteration {i}: journal restarted at {start}, before an acknowledged record"
        );

        // Kill strategy: after k acknowledgements, or after a random delay.
        if i % 3 == 0 {
            std::thread::sleep(Duration::from_millis(random_below(&rng, 40)));
        } else {
            let k = 1 + random_below(&rng, 400);
            let mut line = String::new();
            for _ in 0..k {
                line.clear();
                if reader.read_line(&mut line).unwrap() == 0 {
                    break;
                }
                if let Some((seq, hash)) = parse_ack(&line) {
                    acked.insert(seq, hash);
                }
            }
        }
        child.kill().unwrap(); // TerminateProcess on Windows, SIGKILL on Unix
        child.wait().unwrap();
        // Everything the writer printed before dying was acknowledged.
        let mut line = String::new();
        while reader.read_line(&mut line).unwrap() > 0 {
            if let Some((seq, hash)) = parse_ack(&line) {
                acked.insert(seq, hash);
            }
            line.clear();
        }

        let (records, report) = read_verified(&OsFs, &data.join(JOURNAL_DIR))
            .unwrap_or_else(|e| panic!("seed {seed:#x}, iteration {i}: journal does not verify: {e}"));
        let present: BTreeMap<u64, Sha256Digest> = records.iter().map(|r| (r.envelope.seq.0, r.hash)).collect();
        for (seq, (hash, _)) in &acked {
            assert_eq!(
                present.get(seq),
                Some(hash),
                "seed {seed:#x}, iteration {i}: acknowledged record {seq} lost or changed"
            );
        }
        // Every acknowledged record's payload is with the OS too (ADR-0018, I-02).
        let store = ChunkStore::open(Arc::new(OsFs), Arc::new(OsRng), kill_keyring().unwrap(), &data).unwrap();
        for (seq, (_, chunk)) in &acked {
            assert_eq!(
                store.get(kill_pocket(), *chunk).ok(),
                Some(kill_payload(*seq)),
                "seed {seed:#x}, iteration {i}: acknowledged record {seq} lost its payload"
            );
        }
        total_acked = total_acked.max(report.records);
    }
    eprintln!("kill harness: {iterations} kills, seed {seed:#x}, up to {total_acked} records per directory, 0 lost");
    let _cleanup = std::fs::remove_dir_all(&root);
}
