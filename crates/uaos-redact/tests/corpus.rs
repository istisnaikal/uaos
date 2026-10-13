// SPDX-License-Identifier: Apache-2.0

//! Gate `redaction-corpus` (CLAUDE.md §4; plan §3 P2; C-53): detector set v1 measured against
//! synthetic corpus v1.
//!
//! For every claimed class, 3,000 positives are embedded in realistic contexts. Each positive
//! counts as detected only if all three paths hold:
//!
//! 1. text redaction removes the secret;
//! 2. JSON redaction removes it everywhere: in a chat message and inside an unknown nested
//!    field, with the output still valid JSON and passing the final scan;
//! 3. the final scan blocks the unredacted body, naming the class.
//!
//! In addition, 100,000 hard negatives are checked. Thresholds come from CLAUDE.md §4: recall
//! ≥ 99.9 % and false positives ≤ 0.5 %, both per class. With 3,000 positives, zero misses
//! bounds recall above 99.9 % at 95 % confidence (the rule of three).

#![allow(
    clippy::unwrap_used,
    clippy::print_stdout,
    reason = "test harness: fixtures abort on failure, and the corpus report is printed"
)]

mod common;

use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Write as _;

use common::{CORPUS_V1_SEED, Prng, embed, negative, secret};
use serde_json::{Value, json};
use uaos_platform::crypto::SecretKey;
use uaos_redact::{DataClass, DetectorVersion, FinalScanner, Redactor};

const POSITIVES_PER_CLASS: usize = 3_000;
const NEGATIVES: usize = 100_000;

#[derive(Debug, Default)]
struct Tally {
    positives: usize,
    missed: usize,
    leaked_text: usize,
    leaked_json: usize,
    not_blocked: usize,
    wrong_class: usize,
    false_positives: usize,
}

/// Corpus v1 on merge runs; nightly runs explore other seeds via `UAOS_CORPUS_SEED`.
#[allow(clippy::disallowed_methods, reason = "test configuration knob, read once")]
fn corpus_seed() -> u64 {
    std::env::var("UAOS_CORPUS_SEED")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(CORPUS_V1_SEED)
}

fn strings(v: &Value, out: &mut Vec<String>) {
    match v {
        Value::String(s) => out.push(s.clone()),
        Value::Array(items) => items.iter().for_each(|i| strings(i, out)),
        Value::Object(map) => {
            for (k, v) in map {
                out.push(k.clone());
                strings(v, out);
            }
        }
        _ => {}
    }
}

/// `part / whole` as a percentage with three decimals, in integer arithmetic.
fn percent(part: usize, whole: usize) -> String {
    let milli = part * 100_000 / whole.max(1);
    format!("{}.{:03}%", milli / 1000, milli % 1000)
}

#[test]
fn corpus_v1() {
    let seed = corpus_seed();
    let redactor = Redactor::new(DetectorVersion::V1, SecretKey::from_bytes([0x42; 32])).unwrap();
    let scanner = FinalScanner::new(DetectorVersion::V1, std::iter::empty()).unwrap();
    let mut tally: BTreeMap<DataClass, Tally> = DataClass::ALL.iter().map(|&c| (c, Tally::default())).collect();
    let mut rng = Prng::new(seed);

    for class in DataClass::ALL {
        for _ in 0..POSITIVES_PER_CLASS {
            let sample = secret(&mut rng, class);
            let context = embed(&mut rng, &sample.text);
            let t = tally.get_mut(&class).unwrap();
            t.positives += 1;

            let text = redactor.redact_text(&context).unwrap();
            let leaked_text = text.output().contains(sample.secret.as_str());
            if !text.classes().contains(&class) {
                t.wrong_class += 1;
            }

            let body = serde_json::to_vec(&json!({
                "model": "m",
                "messages": [{ "role": "user", "content": context }],
                "x_unknown": { "nested": [{ "deep": context }] },
            }))
            .unwrap();
            let redacted = redactor.redact_json(&body).unwrap();
            let mut out = Vec::new();
            strings(&serde_json::from_slice(redacted.output()).unwrap(), &mut out);
            let leaked_json = out.iter().any(|s| s.contains(sample.secret.as_str()))
                || scanner.check_json(redacted.output()).is_err();

            let not_blocked = !matches!(scanner.check_json(&body), Err(b) if b.classes.contains(&class));

            t.leaked_text += usize::from(leaked_text);
            t.leaked_json += usize::from(leaked_json);
            t.not_blocked += usize::from(not_blocked);
            t.missed += usize::from(leaked_text || leaked_json || not_blocked);
        }
    }

    for _ in 0..NEGATIVES {
        let text = negative(&mut rng);
        let classes: BTreeSet<DataClass> = redactor.detect(&text).unwrap().into_iter().map(|f| f.class).collect();
        for class in classes {
            tally.get_mut(&class).unwrap().false_positives += 1;
        }
    }

    let mut report = format!(
        "redaction corpus v1 (seed {seed:#018x}), detector set v1, {NEGATIVES} negatives\n\
         {:<18} {:>9} {:>7} {:>13} {:>11} {:>9} {:>10} {:>8}\n",
        "class", "positives", "missed", "text/json/fs", "wrong-class", "recall", "false-pos", "fp-rate"
    );
    let mut failures = Vec::new();
    for (class, t) in &tally {
        let _infallible = writeln!(
            report,
            "{:<18} {:>9} {:>7} {:>13} {:>11} {:>9} {:>10} {:>8}",
            class.as_str(),
            t.positives,
            t.missed,
            format!("{}/{}/{}", t.leaked_text, t.leaked_json, t.not_blocked),
            t.wrong_class,
            percent(t.positives - t.missed, t.positives),
            t.false_positives,
            percent(t.false_positives, NEGATIVES),
        );
        // recall >= 99.9 %  <=>  missed * 1000 <= positives
        if t.missed * 1000 > t.positives {
            failures.push(format!(
                "class {class}: recall below 99.9% ({} of {} missed)",
                t.missed, t.positives
            ));
        }
        if t.wrong_class * 1000 > t.positives {
            failures.push(format!(
                "class {class}: labelled as another class too often ({} of {})",
                t.wrong_class, t.positives
            ));
        }
        // false positives <= 0.5 %  <=>  fp * 200 <= negatives
        if t.false_positives * 200 > NEGATIVES {
            failures.push(format!(
                "class {class}: false-positive rate above 0.5% ({} of {NEGATIVES})",
                t.false_positives
            ));
        }
    }
    println!("{report}");
    assert!(failures.is_empty(), "{}\n{report}", failures.join("\n"));
}
