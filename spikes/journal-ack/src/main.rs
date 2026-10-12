// SPDX-License-Identifier: Apache-2.0

//! SPIKE H1: is "critical = handed to the OS before the ack" cheap, and does it survive kill -9?
//!
//! Subcommands:
//!   bench <dir> <records> <line_bytes> <fsync_every>   latency of write-ack and group fsync
//!   writer <file> <fsync_ms>                           append chained records, ack each on stdout
//!   crashtest <dir> <iterations>                       kill writers at random points, verify acks
//!
//! Measurement code only; deliberately simple and std-only apart from SHA-256.

use std::fs::{File, OpenOptions};
use std::io::{BufRead, BufReader, Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use sha2::{Digest, Sha256};

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// One journal-like line: a realistic ~0.6 KB metadata envelope chained to its predecessor.
fn line(seq: u64, prev: &str, pad: usize) -> Vec<u8> {
    format!(
        "{{\"schema\":\"uaos.event/1\",\"seq\":\"{seq}\",\"type\":\"op.reserved_intent\",\"prev_hash\":\"sha256:{prev}\",\"pad\":\"{}\"}}\n",
        "x".repeat(pad)
    )
    .into_bytes()
}

fn percentile(sorted: &[Duration], p: f64) -> Duration {
    if sorted.is_empty() {
        return Duration::ZERO;
    }
    let idx = ((sorted.len() as f64 - 1.0) * p).round() as usize;
    sorted[idx]
}

fn report(name: &str, mut v: Vec<Duration>) {
    v.sort();
    println!(
        "{name:<14} n={:<7} p50={:>10.1?} p95={:>10.1?} p99={:>10.1?} p99.9={:>10.1?} max={:>10.1?}",
        v.len(),
        percentile(&v, 0.50),
        percentile(&v, 0.95),
        percentile(&v, 0.99),
        percentile(&v, 0.999),
        v.last().copied().unwrap_or_default()
    );
}

fn bench(dir: &Path, records: u64, line_bytes: usize, fsync_every: u64) {
    std::fs::create_dir_all(dir).unwrap();
    let path = dir.join("bench.jsonl");
    let _ = std::fs::remove_file(&path);
    let mut f = OpenOptions::new().create(true).append(true).open(&path).unwrap();
    let pad = line_bytes.saturating_sub(160);
    let mut prev = "0".repeat(64);
    let mut ack = Vec::with_capacity(records as usize);
    let mut hash = Vec::with_capacity(records as usize);
    let mut fsync = Vec::new();
    let start = Instant::now();
    for seq in 0..records {
        let t0 = Instant::now();
        let bytes = line(seq, &prev, pad);
        let t1 = Instant::now();
        prev = hex(&Sha256::digest(&bytes));
        let t2 = Instant::now();
        f.write_all(&bytes).unwrap(); // handed to the OS: the "critical" ack point
        let t3 = Instant::now();
        hash.push(t2 - t1);
        ack.push(t3 - t0);
        if fsync_every > 0 && (seq + 1) % fsync_every == 0 {
            let t4 = Instant::now();
            f.sync_data().unwrap(); // power-loss durability (group commit)
            fsync.push(t4.elapsed());
        }
    }
    let total = start.elapsed();
    println!("bench: {records} records of ~{line_bytes} B, fsync every {fsync_every} records, file {}", path.display());
    report("sha256", hash);
    report("write-ack", ack);
    report("group-fsync", fsync);
    println!("throughput     {:.0} records/s ({:.1?} total)", records as f64 / total.as_secs_f64(), total);
}

fn writer(path: &Path, fsync_ms: u64) {
    let mut f = OpenOptions::new().create(true).append(true).open(path).unwrap();
    let mut out = std::io::stdout().lock();
    let mut prev = "0".repeat(64);
    let mut last_sync = Instant::now();
    for seq in 0u64.. {
        let bytes = line(seq, &prev, 440);
        prev = hex(&Sha256::digest(&bytes));
        f.write_all(&bytes).unwrap();
        // Ack only after the OS has the bytes.
        writeln!(out, "{seq}").unwrap();
        out.flush().unwrap();
        if fsync_ms > 0 && last_sync.elapsed() >= Duration::from_millis(fsync_ms) {
            f.sync_data().unwrap();
            last_sync = Instant::now();
        }
    }
}

/// Verifies the chain and returns the highest contiguous seq. A torn final line (no trailing
/// newline) is allowed: it was never acknowledged.
fn verify(path: &Path) -> Result<Option<u64>, String> {
    let mut data = Vec::new();
    File::open(path)
        .map_err(|e| e.to_string())?
        .read_to_end(&mut data)
        .map_err(|e| e.to_string())?;
    let mut prev = "0".repeat(64);
    let mut last: Option<u64> = None;
    let mut rest = &data[..];
    while let Some(nl) = rest.iter().position(|&b| b == b'\n') {
        let (l, tail) = rest.split_at(nl + 1);
        rest = tail;
        let text = std::str::from_utf8(l).map_err(|e| format!("utf8: {e}"))?;
        let want_prev = format!("\"prev_hash\":\"sha256:{prev}\"");
        if !text.contains(&want_prev) {
            return Err(format!("chain broken after seq {last:?}"));
        }
        let seq_field = text
            .split("\"seq\":\"")
            .nth(1)
            .and_then(|s| s.split('"').next())
            .ok_or("no seq")?;
        let seq: u64 = seq_field.parse().map_err(|_| "bad seq")?;
        let expected = last.map_or(0, |s| s + 1);
        if seq != expected {
            return Err(format!("seq gap: {seq} after {last:?}"));
        }
        prev = hex(&Sha256::digest(l));
        last = Some(seq);
    }
    Ok(last)
}

fn crashtest(dir: &Path, iterations: u32) {
    std::fs::create_dir_all(dir).unwrap();
    let exe = std::env::current_exe().unwrap();
    let mut lost_total = 0u64;
    let mut acked_total = 0u64;
    let mut torn_tails = 0u32;
    // Deterministic pseudo-random kill points (xorshift64).
    let mut state: u64 = 0x9E37_79B9_7F4A_7C15;
    for i in 0..iterations {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        let kill_after_acks = 1 + (state % 3000);
        let file: PathBuf = dir.join(format!("crash-{i}.jsonl"));
        let _ = std::fs::remove_file(&file);
        let fsync_ms = if i % 2 == 0 { 0 } else { 50 };
        let mut child = Command::new(&exe)
            .args(["writer", file.to_str().unwrap(), &fsync_ms.to_string()])
            .stdout(Stdio::piped())
            .spawn()
            .unwrap();
        let mut reader = BufReader::new(child.stdout.take().unwrap());
        let mut last_ack: Option<u64> = None;
        let mut buf = String::new();
        while last_ack.map_or(0, |a| a + 1) < kill_after_acks {
            buf.clear();
            if reader.read_line(&mut buf).unwrap() == 0 {
                break;
            }
            last_ack = buf.trim().parse().ok();
        }
        child.kill().unwrap(); // TerminateProcess on Windows, SIGKILL on Unix
        child.wait().unwrap();
        let data = std::fs::read(&file).unwrap();
        if data.last().is_some_and(|&b| b != b'\n') {
            torn_tails += 1;
        }
        let acked = last_ack.map_or(0, |a| a + 1);
        acked_total += acked;
        match verify(&file) {
            Ok(last_on_disk) => {
                let durable = last_on_disk.map_or(0, |s| s + 1);
                if durable < acked {
                    lost_total += acked - durable;
                    println!("iteration {i}: LOST {} acknowledged records", acked - durable);
                }
            }
            Err(e) => {
                println!("iteration {i}: VERIFY FAILED: {e}");
                lost_total += 1;
            }
        }
        let _ = std::fs::remove_file(&file);
    }
    println!(
        "crashtest: {iterations} kills, {acked_total} acknowledged records, lost = {lost_total}, torn unacked tails = {torn_tails}"
    );
    if lost_total > 0 {
        std::process::exit(1);
    }
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    match args.get(1).map(String::as_str) {
        Some("bench") => bench(
            Path::new(&args[2]),
            args[3].parse().unwrap(),
            args[4].parse().unwrap(),
            args[5].parse().unwrap(),
        ),
        Some("writer") => writer(Path::new(&args[2]), args[3].parse().unwrap()),
        Some("crashtest") => crashtest(Path::new(&args[2]), args[3].parse().unwrap()),
        _ => eprintln!("usage: bench|writer|crashtest (see source)"),
    }
}
