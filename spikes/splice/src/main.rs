// SPDX-License-Identifier: Apache-2.0

//! WP3.0c splice kill-spike driver. Prints a verdict per criterion and exits non-zero if any
//! criterion fails. Usage: `cargo run --release -- [seeds] [turns]`.

mod kernel;
mod roles;
mod sim;
mod tape;

use std::time::Instant;

use kernel::{Config, Edit, EditClass, Kernel, KernelError};
use serde_json::Value;
use sim::{Client, Provider, Rng, Style};
use tape::{Limits, Tape, TapeError};

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let seeds: u64 = args.get(1).and_then(|s| s.parse().ok()).unwrap_or(200);
    let turns: usize = args.get(2).and_then(|s| s.parse().ok()).unwrap_or(50);
    let mut failed = false;

    let on = ON;
    let off = Config { detect: false, strip_tags: false, inject: false, ..ON };

    // A. Value-prefix stability with transforms on, client reformatting every turn.
    let (ok, report) = stability(seeds, turns, on);
    println!("A  value-prefix stability ({seeds} seeds x {turns} turns, transforms on): {report}");
    failed |= !ok;

    // B. Identity: no transforms means byte-identical forwarding.
    let (ok, report) = identity(seeds / 2, turns, off);
    println!("B  identity (transforms off): {report}");
    failed |= !ok;

    // A'. Design negatives: each load-bearing element switched off must break stability.
    for (name, cfg) in [
        ("no per-chunk pinning", Config { pin: false, ..ON }),
        ("digest includes the volatile cache_control", Config { volatile_aware: false, ..ON }),
    ] {
        let (ok, report) = stability(seeds.min(50), turns, cfg);
        let bites = !ok;
        println!(
            "A' design negative ({name}): {}",
            if bites { "breaks stability as expected" } else { "DID NOT BREAK: the element is not load-bearing" }
        );
        if !bites {
            println!("     {report}");
        }
        failed |= !bites;
    }

    // C. Role violations are refused, never forwarded.
    let (ok, report) = negatives();
    println!("C  role negatives: {report}");
    failed |= !ok;

    // D. Differential acceptance and decoding against serde_json.
    let (ok, report) = differential(20_000);
    println!("D  differential vs serde_json: {report}");
    failed |= !ok;

    // E. Throughput at about 1.7 MB.
    println!("E  throughput: {}", throughput());

    if failed {
        println!("VERDICT: FAIL");
        std::process::exit(1);
    }
    println!("VERDICT: PASS");
}

const ON: Config = Config { detect: true, strip_tags: true, inject: true, pin: true, volatile_aware: true };

fn stability(seeds: u64, turns: usize, cfg: Config) -> (bool, String) {
    let mut total = 0usize;
    let mut failures = Vec::new();
    let mut edited_turns = 0usize;
    let mut stats = kernel::Stats::default();
    for seed in 1..=seeds {
        let mut rng = Rng::new(seed);
        let mut client = Client::new(&mut rng);
        let mut provider = Provider::new();
        let mut k = Kernel::new(cfg);
        for turn in 0..turns {
            client.take_turn(&mut rng, 0);
            let style = Style::random(&mut rng);
            let bytes = sim::serialize(&client.request(), style, &mut rng);
            let edits_before = k.stats.edits;
            let out = match k.process(&bytes) {
                Ok(o) => o,
                Err(e) => {
                    failures.push(format!("seed {seed} turn {turn}: kernel error {e:?} ({style:?})"));
                    break;
                }
            };
            if k.stats.edits > edits_before {
                edited_turns += 1;
            }
            if let Err(e) = provider.check(&out) {
                failures.push(format!("seed {seed} turn {turn}: {e} ({style:?})"));
                break;
            }
            if sim::leaks_secret(&out) {
                failures.push(format!("seed {seed} turn {turn}: canary secret reached the provider"));
                break;
            }
            let a = sim::assistant_turn(&mut rng, turn);
            provider.produced(&a);
            client.receive(a);
            total += 1;
        }
        stats.chunks_new += k.stats.chunks_new;
        stats.chunks_replayed += k.stats.chunks_replayed;
        stats.edits += k.stats.edits;
    }
    let ok = failures.is_empty();
    let mut report = format!(
        "{} turns ok, {} with edits, {} edits, {} new chunks, {} replayed chunks; {} failure(s)",
        total,
        edited_turns,
        stats.edits,
        stats.chunks_new,
        stats.chunks_replayed,
        failures.len()
    );
    for f in failures.iter().take(5) {
        report.push_str(&format!("\n     - {f}"));
    }
    (ok, report)
}

fn identity(seeds: u64, turns: usize, cfg: Config) -> (bool, String) {
    let mut checked = 0usize;
    let mut diffs = 0usize;
    for seed in 1..=seeds {
        let mut rng = Rng::new(10_000 + seed);
        let mut client = Client::new(&mut rng);
        let mut k = Kernel::new(cfg);
        for turn in 0..turns {
            client.take_turn(&mut rng, 0);
            let bytes = sim::serialize(&client.request(), Style::random(&mut rng), &mut rng);
            match k.process(&bytes) {
                Ok(out) if out == bytes => checked += 1,
                _ => diffs += 1,
            }
            client.receive(sim::assistant_turn(&mut rng, turn));
        }
    }
    (diffs == 0, format!("{checked} requests byte-identical, {diffs} differed"))
}

fn sample_request() -> Vec<u8> {
    let mut rng = Rng::new(77);
    let mut client = Client::new(&mut rng);
    for turn in 0..4 {
        client.take_turn(&mut rng, 0);
        client.receive(sim::assistant_turn(&mut rng, turn));
    }
    client.take_turn(&mut rng, 0);
    let mut v = client.request();
    // Make sure there is an older human message and a system message to aim at.
    v["messages"].as_array_mut().map(|m| {
        m.insert(0, serde_json::json!({"role": "user", "content": [{"type": "text", "text": "@notal an old turn"}]}));
        m.insert(1, serde_json::json!({"role": "system", "content": "a mid-conversation system message"}));
    });
    sim::serialize(&v, Style::compact(), &mut rng)
}

fn negatives() -> (bool, String) {
    let raw = sample_request();
    let t = Tape::parse(&raw, Limits::default()).expect("sample parses");
    let roles = roles::messages_roles(&t);
    let inside = |n: usize| {
        let (s, e) = t.span(n);
        (s + 1, e - 1)
    };
    let edit = |n: usize, class: EditClass| {
        let (s, e) = inside(n);
        Edit { start: s, end: e, bytes: b"x".to_vec(), class }
    };
    let first_user = t.children(t.get(0, "messages").unwrap_or(0)).next().unwrap_or(0);
    let cases: Vec<(&str, Edit)> = vec![
        ("secret splice inside a thinking block", edit(roles.signed[0], EditClass::SecretSplice)),
        ("secret splice inside system[0]", edit(roles.system_entries[0], EditClass::SecretSplice)),
        ("tag strip inside system[1]", edit(roles.system_entries[1], EditClass::TagStrip)),
        ("tag strip inside a system message", edit(roles.system_messages[0], EditClass::TagStrip)),
        ("edit inside metadata (opaque)", edit(roles.opaque[0], EditClass::SecretSplice)),
        ("edit inside an assistant turn", edit(roles.provider_produced[0], EditClass::SecretSplice)),
        ("tag strip in an older user turn", edit(first_user, EditClass::TagStrip)),
        ("append in an older user turn", {
            let (_, e) = t.span(first_user);
            Edit { start: e - 1, end: e - 1, bytes: b",{}".to_vec(), class: EditClass::Append }
        }),
    ];
    let mut refused = 0;
    let mut wrong = Vec::new();
    for (name, e) in cases.iter() {
        match kernel::check_edit(&raw, e.clone()) {
            Err(KernelError::Forbidden(..)) => refused += 1,
            other => wrong.push(format!("{name}: {other:?}")),
        }
    }
    // Parser negatives.
    let bs = '\\';
    let parser_cases: Vec<(&str, String, fn(&TapeError) -> bool)> = vec![
        ("duplicate key", r#"{"a":1,"a":2}"#.into(), |e| matches!(e, TapeError::DuplicateKey(_))),
        ("duplicate key after decoding", format!("{{\"a\":1,\"{bs}u0061\":2}}"), |e| matches!(e, TapeError::DuplicateKey(_))),
        ("lone high surrogate", format!("[\"{bs}ud800x\"]"), |e| matches!(e, TapeError::Syntax(..))),
        ("lone low surrogate", format!("[\"{bs}udc00\"]"), |e| matches!(e, TapeError::Syntax(..))),
        ("depth 129", format!("{}{}", "[".repeat(129), "]".repeat(129)), |e| matches!(e, TapeError::Depth)),
        ("trailing data", "{} {}".into(), |e| matches!(e, TapeError::Syntax(..))),
        ("leading zero", "[01]".into(), |e| matches!(e, TapeError::Syntax(..))),
        ("raw control char", "[\"a\u{1}b\"]".into(), |e| matches!(e, TapeError::Syntax(..))),
    ];
    let mut parser_ok = 0;
    for (name, doc, want) in &parser_cases {
        match Tape::parse(doc.as_bytes(), Limits::default()) {
            Err(e) if want(&e) => parser_ok += 1,
            other => wrong.push(format!("parser {name}: {:?}", other.map(|_| "accepted"))),
        }
    }
    let depth_ok = Tape::parse(format!("{}{}", "[".repeat(128), "]".repeat(128)).as_bytes(), Limits::default()).is_ok();
    if !depth_ok {
        wrong.push("depth 128 should be accepted".into());
    }
    let ok = wrong.is_empty();
    let mut report = format!(
        "{refused}/{} role violations refused, {parser_ok}/{} parser violations rejected",
        cases.len(),
        parser_cases.len()
    );
    for w in wrong {
        report.push_str(&format!("\n     - {w}"));
    }
    (ok, report)
}

/// Builds a serde_json value from the tape, for comparison with serde_json's own parse.
fn to_value(t: &Tape<'_>, n: usize) -> Value {
    let node = &t.nodes[n];
    match node.kind {
        tape::Kind::Obj => Value::Object(t.children(n).map(|c| (t.key(c).unwrap_or_default().into_owned(), to_value(t, c))).collect()),
        tape::Kind::Arr => Value::Array(t.children(n).map(|c| to_value(t, c)).collect()),
        tape::Kind::Str => Value::String(t.str_value(n).unwrap_or_default().into_owned()),
        tape::Kind::Num | tape::Kind::Lit => serde_json::from_slice(&t.raw[node.start..node.end]).unwrap_or(Value::Null),
    }
}

fn random_value(rng: &mut Rng, depth: usize) -> Value {
    match rng.below(if depth > 4 { 4 } else { 7 }) {
        0 => Value::Null,
        1 => Value::Bool(rng.chance(50)),
        2 => serde_json::json!((rng.next() % 1_000_000) as i64 - 500_000),
        3 => {
            let words = 1 + rng.below(4) as usize;
            let mut s = rng.sentence(words);
            if rng.chance(20) {
                s.push_str("/\"\\\t\n😀");
            }
            Value::String(s)
        }
        4 | 5 => Value::Array((0..rng.below(5)).map(|_| random_value(rng, depth + 1)).collect()),
        _ => Value::Object((0..rng.below(5)).map(|i| (format!("{}{i}", rng.word()), random_value(rng, depth + 1))).collect()),
    }
}

fn differential(n: usize) -> (bool, String) {
    let mut rng = Rng::new(4242);
    let (mut both_ok, mut both_err, mut value_mismatch, mut dup_only, mut unexplained) = (0, 0, 0, 0, Vec::new());
    // RFC 8259 sets no numeric range; serde_json refuses numbers that overflow f64. The tape
    // forwards number text unchanged and never interprets it (fields the kernel must read, such
    // as max_tokens, are parsed with explicit range checks), so this is an explained category.
    let mut range_only = 0;
    let specials = b"{}[]\",:\\u0123456789abcdefE+-. \n\x01";
    for i in 0..n {
        let v = random_value(&mut rng, 0);
        let mut bytes = sim::serialize(&v, Style::random(&mut rng), &mut rng);
        if i % 2 == 1 {
            for _ in 0..=rng.below(3) {
                if bytes.is_empty() {
                    break;
                }
                let at = rng.below(bytes.len() as u64) as usize;
                match rng.below(4) {
                    0 => bytes[at] = specials[rng.below(specials.len() as u64) as usize],
                    1 => {
                        bytes.remove(at);
                    }
                    2 => bytes.insert(at, specials[rng.below(specials.len() as u64) as usize]),
                    _ => bytes.truncate(at),
                }
            }
        }
        let ours = Tape::parse(&bytes, Limits::default());
        let theirs = serde_json::from_slice::<Value>(&bytes);
        match (&ours, &theirs) {
            (Ok(t), Ok(v)) => {
                if &to_value(t, 0) == v {
                    both_ok += 1;
                } else {
                    value_mismatch += 1;
                    if unexplained.len() < 5 {
                        unexplained.push(format!("value mismatch on {:?}", String::from_utf8_lossy(&bytes)));
                    }
                }
            }
            (Err(_), Err(_)) => both_err += 1,
            (Err(TapeError::DuplicateKey(_)), Ok(_)) => dup_only += 1,
            (Ok(_), Err(e)) if e.to_string().contains("number out of range") => range_only += 1,
            (a, b) => {
                if unexplained.len() < 5 {
                    unexplained.push(format!(
                        "tape {:?} vs serde {:?} on {:?}",
                        a.as_ref().map(|_| "ok"),
                        b.as_ref().map(|_| "ok").map_err(|e| e.to_string()),
                        String::from_utf8_lossy(&bytes)
                    ));
                }
                value_mismatch += 0;
            }
        }
    }
    let disagreements = n - both_ok - both_err - dup_only - range_only - value_mismatch;
    let ok = value_mismatch == 0 && disagreements == 0;
    let mut report = format!(
        "{n} documents: {both_ok} accepted by both with equal values, {both_err} rejected by both, {dup_only} rejected only by the tape (duplicate keys, intended), {range_only} accepted only by the tape (numbers beyond f64, grammar-valid, explained), {value_mismatch} value mismatches, {disagreements} unexplained disagreements"
    );
    for u in unexplained {
        report.push_str(&format!("\n     - {u}"));
    }
    (ok, report)
}

fn quantiles(mut v: Vec<f64>) -> (f64, f64) {
    v.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
    let q = |p: f64| v[((v.len() - 1) as f64 * p).round() as usize];
    (q(0.5), q(0.95))
}

fn throughput() -> String {
    let mut rng = Rng::new(9);
    let mut client = Client::new(&mut rng);
    let mut k_warm = Kernel::new(ON);
    let mut turn = 0;
    let mut last = Vec::new();
    let mut prev = Vec::new();
    while last.len() < 1_700_000 {
        client.take_turn(&mut rng, 600);
        prev = last;
        last = sim::serialize(&client.request(), Style::compact(), &mut rng);
        // Warm the kernel turn by turn, like a real session.
        let _ = k_warm.process(&last);
        client.receive(sim::assistant_turn(&mut rng, turn));
        turn += 1;
    }
    let _ = prev;
    let iters = 100;
    let mb = last.len() as f64 / 1e6;
    let mut parse = Vec::new();
    let mut utf8 = Vec::new();
    let mut roles_t = Vec::new();
    let mut digests = Vec::new();
    let mut cold = Vec::new();
    let mut warm = Vec::new();
    let mut sink = 0u64;
    for _ in 0..iters {
        let s = Instant::now();
        sink ^= std::str::from_utf8(&last).map_or(0, |s| s.len() as u64);
        utf8.push(s.elapsed().as_secs_f64() * 1e3);
        let s = Instant::now();
        let t = Tape::parse(&last, Limits::default()).expect("parses");
        parse.push(s.elapsed().as_secs_f64() * 1e3);
        let s = Instant::now();
        let r = roles::messages_roles(&t);
        roles_t.push(s.elapsed().as_secs_f64() * 1e3);
        let mut volatile = vec![false; t.nodes.len()];
        for &v in &r.volatile {
            volatile[v] = true;
        }
        let s = Instant::now();
        for &c in &r.chunks {
            sink ^= kernel::value_digest(&t, c, &volatile);
        }
        digests.push(s.elapsed().as_secs_f64() * 1e3);
        let mut k = Kernel::new(ON);
        let s = Instant::now();
        let _ = k.process(&last);
        cold.push(s.elapsed().as_secs_f64() * 1e3);
        let s = Instant::now();
        let _ = k.process(&last);
        warm.push(s.elapsed().as_secs_f64() * 1e3);
    }
    let (p50, p95) = quantiles(parse.clone());
    let (u50, u95) = quantiles(utf8);
    let (r50, r95) = quantiles(roles_t);
    let (d50, d95) = quantiles(digests);
    let (c50, c95) = quantiles(cold);
    let (w50, w95) = quantiles(warm);
    format!(
        "{mb:.2} MB request after {turn} turns ({} nodes; sink {})\n     - utf-8 check  p50 {u50:.2} ms, p95 {u95:.2} ms (part of the parse)\n     - tape parse   p50 {p50:.2} ms, p95 {p95:.2} ms ({:.0} MB/s at p50)\n     - roles        p50 {r50:.2} ms, p95 {r95:.2} ms\n     - digests      p50 {d50:.2} ms, p95 {d95:.2} ms (every chunk, volatile excluded; SipHash stand-in)\n     - full, cold   p50 {c50:.2} ms, p95 {c95:.2} ms (parse, roles, digest, detect, strip, pin, validate, splice)\n     - full, warm   p50 {w50:.2} ms, p95 {w95:.2} ms (parse, roles, digest, replay, validate, splice)",
        Tape::parse(&last, Limits::default()).map(|t| t.nodes.len()).unwrap_or(0),
        sink % 2,
        mb / (p50 / 1e3),
    )
}
