// SPDX-License-Identifier: Apache-2.0

//! Stores a payload and appends a record that references it, on a real journal and chunk store,
//! until killed, acknowledging each record on stdout.
//!
//! Usage: `journal-crash-writer <data-dir> <strict|balanced>`
//!
//! Output: `start <next seq>` once, then `<seq> <hash> <chunk>` per acknowledged record. A line
//! is printed only after `Journal::append` returned, i.e. after the record reached the OS, and
//! the record is appended only after its payload is stored (ADR-0018: chunks before the record
//! that references them). The harness treats every complete line it reads as a promise: the
//! record and its payload must both survive the kill.

#![allow(
    clippy::print_stdout,
    clippy::print_stderr,
    reason = "a harness binary whose protocol is its stdout"
)]

use std::io::Write as _;
use std::path::PathBuf;
use std::process::ExitCode;
use std::sync::Arc;

use uaos_platform::fs::Fs;
use uaos_platform::real::fs::OsFs;
use uaos_platform::real::{OsRng, SystemClock};
use uaos_platform::{Clock, Rng};
use uaos_state::chunks::{ChunkDurability, ChunkStore};
use uaos_state::journal::{FlushPolicy, Journal};
use uaos_testkit::{intent_draft, kill_keyring, kill_payload, kill_pocket};

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let (Some(dir), Some(mode)) = (args.first(), args.get(1)) else {
        eprintln!("usage: journal-crash-writer <data-dir> <strict|balanced>");
        return ExitCode::from(2);
    };
    let (policy, durability) = if mode == "strict" {
        (FlushPolicy::Strict, ChunkDurability::Strict)
    } else {
        (FlushPolicy::default(), ChunkDurability::Balanced)
    };
    let data = PathBuf::from(dir);
    let fs: Arc<dyn Fs> = Arc::new(OsFs);
    let clock: Arc<dyn Clock> = Arc::new(SystemClock::new());
    let rng: Arc<dyn Rng> = Arc::new(OsRng);
    let keys = match kill_keyring() {
        Ok(k) => k,
        Err(e) => {
            eprintln!("keyring failed: {e}");
            return ExitCode::FAILURE;
        }
    };
    if let Err(e) = fs.create_dir_all(&data) {
        eprintln!("data directory: {e}");
        return ExitCode::FAILURE;
    }
    let store = match ChunkStore::open_with(Arc::clone(&fs), Arc::clone(&rng), keys, &data, durability) {
        Ok(s) => Arc::new(s),
        Err(e) => {
            eprintln!("chunk store open failed: {e}");
            return ExitCode::FAILURE;
        }
    };
    let mut journal = match Journal::open_with_payloads(fs, clock, rng, &data, policy, Arc::clone(&store)) {
        Ok(j) => j,
        Err(e) => {
            eprintln!("open failed: {e}");
            return ExitCode::FAILURE;
        }
    };
    let mut out = std::io::stdout().lock();
    if writeln!(out, "start {}", journal.next_seq())
        .and_then(|()| out.flush())
        .is_err()
    {
        return ExitCode::FAILURE;
    }
    for n in 0u64.. {
        let seq = journal.next_seq().0;
        let chunk = match store.put(kill_pocket(), &kill_payload(seq)) {
            Ok(c) => c,
            Err(e) => {
                eprintln!("put failed: {e}");
                return ExitCode::FAILURE;
            }
        };
        let mut draft = intent_draft(n);
        draft.pocket_id = Some(kill_pocket());
        draft.payload_ref = Some(chunk);
        let acked = match journal.append(draft) {
            Ok(a) => a,
            Err(e) => {
                eprintln!("append failed: {e}");
                return ExitCode::FAILURE;
            }
        };
        if writeln!(out, "{} {} {}", acked.seq, acked.hash, chunk)
            .and_then(|()| out.flush())
            .is_err()
        {
            // The reader is gone (the harness is killing us); stop quietly.
            return ExitCode::SUCCESS;
        }
    }
    ExitCode::SUCCESS
}
