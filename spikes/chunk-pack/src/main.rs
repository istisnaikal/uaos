// SPDX-License-Identifier: Apache-2.0

//! SPIKE (D-32): one file per chunk against an append-only pack per pocket, file-system work only.
//!
//! Usage: `spike-chunk-pack <scratch dir> [puts] [group]` (defaults 5,000 puts, groups of 64).
//!
//! Workload, the same for both layouts: `puts` chunks with sizes drawn log-uniformly from
//! 256 B to 64 KiB (fixed seed), each with an 80-byte wrapped-key record, flushed in groups of
//! `group` as ADR-0018's balanced mode does. Each layout runs twice: flushes on the putting
//! thread between groups, and flushes on a second thread while the next group is being put (the
//! durability coordinator's shape, PR-6), where interference shows in the put tail.
//!
//! * **files**: what `ChunkStore` does today. A put writes the data file and the key file, each
//!   through a unique temporary renamed into place, unflushed. A group flush opens and flushes
//!   every file of the group, then flushes both directories (a no-op on Windows, as in `OsFs`).
//! * **pack**: a put appends a length-prefixed record to `data.pack` and one to `keys.pack`,
//!   both already open. A group flush flushes the two packs.
//! * **segmented pack**: as `pack`, but each group goes to a fresh pair of segment files; a
//!   group flush flushes the pair just closed while the next group appends to the new pair, so
//!   appends never wait on a flush of the file they write. Two files per group.
//! * **prepared segments**: as `segmented pack`, but the next pair is created, and a 16-byte
//!   header written to each, one group ahead and off the put path, as a coordinator would; a put
//!   never writes first to a file created moments before.
//!
//! Not measured: the AEAD seal and the keyed reference (the same work in both layouts), torn-tail
//! recovery of a pack, compaction, and shred re-wraps. RESULTS.md states what each would cost.

use std::fs::{self, File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::sync::mpsc;
use std::thread;
use std::time::{Duration, Instant};

const KEY_RECORD: usize = 80;

struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        // xorshift64*
        self.0 ^= self.0 >> 12;
        self.0 ^= self.0 << 25;
        self.0 ^= self.0 >> 27;
        self.0.wrapping_mul(0x2545_F491_4F6C_DD1D)
    }

    /// Log-uniform between 256 B and 64 KiB.
    fn size(&mut self) -> usize {
        let bits = 8.0 + (self.next() % 1_000_000) as f64 / 1_000_000.0 * 8.0;
        bits.exp2() as usize
    }

    fn fill(&mut self, buf: &mut [u8]) {
        for chunk in buf.chunks_mut(8) {
            let word = self.next().to_le_bytes();
            chunk.copy_from_slice(&word[..chunk.len()]);
        }
    }
}

fn percentile(sorted: &[Duration], p: f64) -> Duration {
    if sorted.is_empty() {
        return Duration::ZERO;
    }
    let rank = ((sorted.len() as f64) * p).ceil() as usize;
    sorted[rank.clamp(1, sorted.len()) - 1]
}

fn ms(d: Duration) -> String {
    format!("{:.3}", d.as_secs_f64() * 1000.0)
}

#[derive(Clone, Copy, PartialEq)]
enum Layout {
    Files,
    Pack,
    Segmented,
    Prepared,
}

#[derive(Clone, Copy, PartialEq)]
enum Flusher {
    Inline,
    Background,
}

/// What one group flush has to make durable.
enum FlushJob {
    Files(Vec<PathBuf>, [PathBuf; 2]),
    Pack(File, File),
    Stop,
}

fn sync_dir(dir: &Path) {
    #[cfg(unix)]
    File::open(dir).and_then(|d| d.sync_all()).expect("sync_dir");
    #[cfg(not(unix))]
    fs::metadata(dir).map(|_| ()).expect("sync_dir");
}

fn flush(job: FlushJob) -> Duration {
    let started = Instant::now();
    match job {
        FlushJob::Files(paths, dirs) => {
            for path in paths {
                OpenOptions::new().write(true).open(&path).and_then(|f| f.sync_data()).expect("sync_file");
            }
            for dir in dirs {
                sync_dir(&dir);
            }
        }
        FlushJob::Pack(data, keys) => {
            data.sync_data().expect("sync data pack");
            keys.sync_data().expect("sync key pack");
        }
        FlushJob::Stop => {}
    }
    started.elapsed()
}

/// `ChunkStore`'s balanced write: a unique temporary, renamed into place, unflushed.
fn write_unsynced(path: &Path, bytes: &[u8], n: u64) {
    let tmp = path.with_extension(format!("uaos-tmp-{n:016x}"));
    let mut file = File::create(&tmp).expect("create");
    file.write_all(bytes).expect("write");
    drop(file);
    fs::rename(&tmp, path).expect("rename");
}

struct Run {
    puts: Vec<Duration>,
    flushes: Vec<Duration>,
    reads: Vec<Duration>,
    files_created: u64,
}

fn run(root: &Path, layout: Layout, flusher: Flusher, puts: usize, group: usize) -> Run {
    let _fresh = fs::remove_dir_all(root);
    let data_dir = root.join("data");
    let key_dir = root.join("keys");
    fs::create_dir_all(&data_dir).expect("mkdir");
    fs::create_dir_all(&key_dir).expect("mkdir");
    let mut rng = Rng(0x5EED_C4A0_C0DE_0019);
    let mut buf = vec![0_u8; 1 << 16];
    let mut key = [0_u8; KEY_RECORD];

    let open = |p: PathBuf| OpenOptions::new().create(true).read(true).append(true).open(p).expect("pack");
    let (data_pack, key_pack) = if layout == Layout::Files {
        (None, None)
    } else {
        (Some(open(data_dir.join("data-0.pack"))), Some(open(key_dir.join("keys-0.pack"))))
    };
    let mut segment = 0_u64;
    let header = |mut f: File| {
        f.write_all(b"uaos.pack/0\0\0\0\0\0").expect("header");
        f
    };
    // Prepared layout: the pair for the next group, created and headed ahead of time.
    let mut ready = (layout == Layout::Prepared).then(|| {
        (
            header(open(data_dir.join("data-1.pack"))),
            header(open(key_dir.join("keys-1.pack"))),
        )
    });
    // (segment, offset, size) of every chunk, for reads.
    let mut located: Vec<(u64, u64, usize)> = Vec::with_capacity(puts);
    let mut data_pack = data_pack;
    let mut key_pack = key_pack;
    let mut pack_len = 0_u64;

    let (tx, rx) = mpsc::channel::<FlushJob>();
    let (done_tx, done_rx) = mpsc::channel::<Duration>();
    let worker = (flusher == Flusher::Background).then(|| {
        thread::spawn(move || {
            while let Ok(job) = rx.recv() {
                if matches!(job, FlushJob::Stop) {
                    break;
                }
                done_tx.send(flush(job)).expect("report");
            }
        })
    });

    let mut put_times = Vec::with_capacity(puts);
    let mut flush_times = Vec::new();
    let mut group_paths = Vec::with_capacity(2 * group);
    let mut files_created = if layout == Layout::Files { 0 } else { 2 };
    for n in 0..puts {
        let size = rng.size();
        rng.fill(&mut buf[..size]);
        rng.fill(&mut key);
        let started = Instant::now();
        match layout {
            Layout::Files => {
                let name = format!("{:016x}{:016x}", rng.next(), n);
                let data_path = data_dir.join(format!("{name}.chunk"));
                let key_path = key_dir.join(format!("{name}.key"));
                write_unsynced(&data_path, &buf[..size], 2 * n as u64);
                write_unsynced(&key_path, &key, 2 * n as u64 + 1);
                files_created += 2;
                group_paths.push(data_path);
                group_paths.push(key_path);
            }
            Layout::Pack | Layout::Segmented | Layout::Prepared => {
                let data = data_pack.as_mut().expect("pack");
                data.write_all(&(size as u32).to_le_bytes()).expect("append");
                data.write_all(&buf[..size]).expect("append");
                key_pack.as_mut().expect("pack").write_all(&key).expect("append");
                located.push((segment, pack_len + 4, size));
                pack_len += 4 + size as u64;
            }
        }
        put_times.push(started.elapsed());
        if (n + 1) % group == 0 || n + 1 == puts {
            let job = match layout {
                Layout::Files => FlushJob::Files(std::mem::take(&mut group_paths), [data_dir.clone(), key_dir.clone()]),
                Layout::Pack => FlushJob::Pack(
                    data_pack.as_ref().expect("pack").try_clone().expect("clone"),
                    key_pack.as_ref().expect("pack").try_clone().expect("clone"),
                ),
                Layout::Prepared => {
                    // Switch to the pair made ready one group ago, and make the next one ready.
                    segment += 1;
                    pack_len = 16;
                    files_created += 2;
                    let (next_data, next_keys) = ready.take().expect("ready pair");
                    ready = Some((
                        header(open(data_dir.join(format!("data-{}.pack", segment + 1)))),
                        header(open(key_dir.join(format!("keys-{}.pack", segment + 1)))),
                    ));
                    FlushJob::Pack(
                        data_pack.replace(next_data).expect("pack"),
                        key_pack.replace(next_keys).expect("pack"),
                    )
                }
                Layout::Segmented => {
                    // Seal this pair, open the next: the flush never touches a file being appended.
                    segment += 1;
                    pack_len = 0;
                    files_created += 2;
                    let next_data = open(data_dir.join(format!("data-{segment}.pack")));
                    let next_keys = open(key_dir.join(format!("keys-{segment}.pack")));
                    FlushJob::Pack(
                        data_pack.replace(next_data).expect("pack"),
                        key_pack.replace(next_keys).expect("pack"),
                    )
                }
            };
            match flusher {
                Flusher::Inline => flush_times.push(flush(job)),
                Flusher::Background => tx.send(job).expect("queue"),
            }
        }
    }
    if let Some(worker) = worker {
        tx.send(FlushJob::Stop).expect("stop");
        worker.join().expect("flusher");
        flush_times.extend(done_rx.try_iter());
    }

    // Read back 1,000 chunks at random, as the kill harness and recovery do.
    let mut reads = Vec::with_capacity(1000);
    let names: Vec<PathBuf> = if layout == Layout::Files {
        let mut v: Vec<PathBuf> = fs::read_dir(&data_dir).expect("list").map(|e| e.expect("entry").path()).collect();
        v.sort();
        v
    } else {
        Vec::new()
    };
    for _ in 0..1000.min(puts) {
        let pick = (rng.next() % puts as u64) as usize;
        let started = Instant::now();
        match layout {
            Layout::Files => {
                let data = &names[pick % names.len()];
                let key_path = key_dir.join(data.file_stem().expect("stem")).with_extension("key");
                let mut out = Vec::new();
                File::open(&key_path).and_then(|mut f| f.read_to_end(&mut out)).expect("read key");
                File::open(data).and_then(|mut f| f.read_to_end(&mut out)).expect("read data");
            }
            Layout::Pack | Layout::Segmented | Layout::Prepared => {
                // A cold open, as a reader in another process would: the honest upper bound.
                let (seg, offset, size) = located[pick];
                let name = if layout == Layout::Pack { 0 } else { seg };
                let mut f = File::open(data_dir.join(format!("data-{name}.pack"))).expect("open pack");
                f.seek(SeekFrom::Start(offset)).expect("seek");
                f.read_exact(&mut buf[..size]).expect("read");
            }
        }
        reads.push(started.elapsed());
    }
    put_times.sort();
    flush_times.sort();
    reads.sort();
    let _cleanup = fs::remove_dir_all(root);
    Run { puts: put_times, flushes: flush_times, reads, files_created }
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let root = PathBuf::from(args.first().expect("usage: spike-chunk-pack <scratch dir> [puts] [group]"));
    let puts: usize = args.get(1).and_then(|s| s.parse().ok()).unwrap_or(5_000);
    let group: usize = args.get(2).and_then(|s| s.parse().ok()).unwrap_or(64);
    println!("{puts} puts, 256 B to 64 KiB log-uniform, groups of {group}; file-system work only\n");
    println!("| Layout | Flushes | put p50 ms | p95 | p99 | p99.9 | max | group flush p50 ms | p99 | read p50 ms | p99 | files created |");
    println!("|---|---|---|---|---|---|---|---|---|---|---|---|");
    for (layout, name) in [
        (Layout::Files, "one file per chunk (today)"),
        (Layout::Pack, "one pack per pocket"),
        (Layout::Segmented, "a pack segment per group"),
        (Layout::Prepared, "prepared segments"),
    ] {
        for (flusher, how) in [(Flusher::Inline, "between groups"), (Flusher::Background, "on a second thread")] {
            let r = run(&root, layout, flusher, puts, group);
            println!(
                "| {name} | {how} | {} | {} | {} | {} | {} | {} | {} | {} | {} | {} |",
                ms(percentile(&r.puts, 0.50)),
                ms(percentile(&r.puts, 0.95)),
                ms(percentile(&r.puts, 0.99)),
                ms(percentile(&r.puts, 0.999)),
                ms(*r.puts.last().unwrap_or(&Duration::ZERO)),
                ms(percentile(&r.flushes, 0.50)),
                ms(percentile(&r.flushes, 0.99)),
                ms(percentile(&r.reads, 0.50)),
                ms(percentile(&r.reads, 0.99)),
                r.files_created,
            );
        }
    }
    println!("\nBudget (ADR-0018): balanced put p99 <= 0.5 ms.");
}
