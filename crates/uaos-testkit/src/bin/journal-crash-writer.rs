// SPDX-License-Identifier: Apache-2.0

//! Appends records to a real journal until killed, acknowledging each on stdout.
//!
//! Usage: `journal-crash-writer <data-dir> <strict|balanced>`
//!
//! Output: `start <next seq>` once, then `<seq> <hash>` per acknowledged record. A line is
//! printed only after `Journal::append` returned, i.e. after the record reached the OS; the
//! harness treats every complete line it reads as a promise the journal must keep.

#![allow(
    clippy::print_stdout,
    clippy::print_stderr,
    reason = "a harness binary whose protocol is its stdout"
)]

use std::io::Write as _;
use std::path::PathBuf;
use std::process::ExitCode;
use std::sync::Arc;

use uaos_platform::real::fs::OsFs;
use uaos_platform::real::{OsRng, SystemClock};
use uaos_platform::{Clock, Rng};
use uaos_state::journal::{FlushPolicy, Journal};
use uaos_testkit::intent_draft;

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let (Some(dir), Some(mode)) = (args.first(), args.get(1)) else {
        eprintln!("usage: journal-crash-writer <data-dir> <strict|balanced>");
        return ExitCode::from(2);
    };
    let policy = if mode == "strict" {
        FlushPolicy::Strict
    } else {
        FlushPolicy::default()
    };
    let clock: Arc<dyn Clock> = Arc::new(SystemClock::new());
    let rng: Arc<dyn Rng> = Arc::new(OsRng);
    let mut journal = match Journal::open(Arc::new(OsFs), clock, rng, &PathBuf::from(dir), policy) {
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
        let acked = match journal.append(intent_draft(n)) {
            Ok(a) => a,
            Err(e) => {
                eprintln!("append failed: {e}");
                return ExitCode::FAILURE;
            }
        };
        if writeln!(out, "{} {}", acked.seq, acked.hash)
            .and_then(|()| out.flush())
            .is_err()
        {
            // The reader is gone (the harness is killing us); stop quietly.
            return ExitCode::SUCCESS;
        }
    }
    ExitCode::SUCCESS
}
