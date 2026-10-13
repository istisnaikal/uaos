// SPDX-License-Identifier: Apache-2.0

//! Redaction behavior (plan §3 P2 acceptance, C-53). Covered here: stable per-pocket
//! placeholders, byte preservation, schema-agnostic JSON at any depth (keys and unknown fields
//! included), escape evasion, fail-closed errors, the final scan, idempotence and no secrets in
//! `Debug` output.

#![allow(
    clippy::unwrap_used,
    reason = "test harness helpers outside #[test] fns: a failed fixture must abort the test"
)]

mod common;

use std::borrow::Cow;
use std::collections::BTreeSet;
use std::fmt::Write as _;

use common::{Prng, Sample, embed, prose, secret};
use proptest::prelude::*;
use serde_json::{Map, Value, json};
use uaos_contracts::error::codes;
use uaos_platform::crypto::SecretKey;
use uaos_redact::{DataClass, DetectorVersion, FinalScanner, RedactError, Redactor};

const POCKET_KEY: [u8; 32] = [7; 32];

fn redactor() -> Redactor {
    Redactor::new(DetectorVersion::V1, SecretKey::from_bytes(POCKET_KEY)).unwrap()
}

fn scanner(known: &[&[u8]]) -> FinalScanner {
    FinalScanner::new(DetectorVersion::V1, known.iter().copied()).unwrap()
}

fn sample(class: DataClass, seed: u64) -> Sample {
    secret(&mut Prng::new(seed), class)
}

/// JSON-escapes every character as a `\u` escape: an attempt to slip a secret past a scanner
/// that only looks at raw bytes.
fn fully_escaped(s: &str) -> String {
    s.chars().fold(String::new(), |mut out, c| {
        let _infallible = write!(out, "\\u{:04x}", u32::from(c));
        out
    })
}

#[test]
fn placeholders_are_stable_per_pocket_and_differ_between_pockets() {
    let token = sample(DataClass::GithubToken, 1);
    let first = redactor().redact_text(&token.text).unwrap().output().to_owned();
    let after_restart = redactor().redact_text(&token.text).unwrap().output().to_owned();
    let other_pocket = Redactor::new(DetectorVersion::V1, SecretKey::from_bytes([8; 32]))
        .unwrap()
        .redact_text(&token.text)
        .unwrap()
        .output()
        .to_owned();
    assert_eq!(
        first, after_restart,
        "same pocket key: same placeholder after a restart"
    );
    assert_ne!(
        first, other_pocket,
        "placeholders do not correlate secrets across pockets"
    );
    let tag = first
        .strip_prefix("[REDACTED:github_token:")
        .and_then(|s| s.strip_suffix(']'))
        .unwrap();
    assert!(tag.len() == 16 && tag.bytes().all(|b| b.is_ascii_hexdigit()));
    let other = sample(DataClass::GithubToken, 2);
    assert_ne!(redactor().redact_text(&other.text).unwrap().output(), first);
}

#[test]
fn clean_json_is_returned_borrowed_byte_for_byte() {
    let body = format!(
        r#"{{"model":"m","messages":[{{"role":"user","content":"a \"quoted\" \/ path\n caf{}"}}],"n":1.50}}"#,
        fully_escaped("é")
    );
    let r = redactor().redact_json(body.as_bytes()).unwrap();
    assert!(r.is_clean());
    assert!(matches!(r.into_output(), Cow::Borrowed(b) if b == body.as_bytes()));
}

#[test]
fn json_redaction_changes_only_the_secret_bytes() {
    let key = sample(DataClass::AwsAccessKeyId, 3);
    let body = format!(
        r#"{{"a":"x\ty","b":{{"unknown":["id={}"]}},"c":"{}"}}"#,
        key.text,
        fully_escaped("é")
    );
    let r = redactor().redact_json(body.as_bytes()).unwrap();
    let placeholder = redactor().placeholder(DataClass::AwsAccessKeyId, &key.secret);
    assert_eq!(
        std::str::from_utf8(r.output()).unwrap(),
        body.replace(&key.secret, &placeholder)
    );
    assert_eq!(r.classes(), BTreeSet::from([DataClass::AwsAccessKeyId]));
}

#[test]
fn escaped_secrets_are_found_and_replaced_whole() {
    let key = sample(DataClass::AnthropicApiKey, 4);
    let body = format!(r#"{{"content":"key: {}"}}"#, fully_escaped(&key.secret));
    // The raw bytes alone do not show the key; the decoded string does.
    assert!(scanner(&[]).check_bytes(body.as_bytes()).is_ok());
    let blocked = scanner(&[]).check_json(body.as_bytes()).unwrap_err();
    assert!(blocked.classes.contains(&DataClass::AnthropicApiKey));
    let r = redactor().redact_json(body.as_bytes()).unwrap();
    let out: Value = serde_json::from_slice(r.output()).unwrap();
    let expected = format!(
        "key: {}",
        redactor().placeholder(DataClass::AnthropicApiKey, &key.secret)
    );
    assert_eq!(out["content"], expected);
    assert!(scanner(&[]).check_json(r.output()).is_ok());
}

#[test]
fn private_keys_with_escaped_newlines_are_redacted_whole() {
    let key = sample(DataClass::PrivateKey, 5);
    let body = serde_json::to_vec(&json!({ "files": { "id_rsa": key.secret } })).unwrap();
    let r = redactor().redact_json(&body).unwrap();
    let out: Value = serde_json::from_slice(r.output()).unwrap();
    assert_eq!(
        out["files"]["id_rsa"],
        redactor().placeholder(DataClass::PrivateKey, &key.secret)
    );
}

fn object(key: String, value: Value) -> Value {
    let mut map = Map::new();
    map.insert(key, value);
    Value::Object(map)
}

#[test]
fn keys_unknown_fields_and_any_depth_are_scanned() {
    let token = sample(DataClass::StripeKey, 6);
    let mut deep = Value::String(format!("charge with {}", token.text));
    // 100 nesting levels: deeper than most parsers allow by default (serde_json stops at 128).
    for i in 0..50 {
        deep = object(format!("level{i}"), Value::Array(vec![deep]));
    }
    let mut doc = Map::new();
    doc.insert(token.text.clone(), Value::from(1));
    doc.insert("x_vendor_extension".to_owned(), deep);
    let body = serde_json::to_vec(&Value::Object(doc)).unwrap();
    let r = redactor().redact_json(&body).unwrap();
    let out = std::str::from_utf8(r.output()).unwrap();
    assert!(!out.contains(&token.secret));
    assert_eq!(out.matches("[REDACTED:stripe_key:").count(), 2);
    serde_json::from_slice::<Value>(r.output()).unwrap();
}

#[test]
fn malformed_input_fails_closed() {
    let lone_surrogate = format!(r#"{{"a":"{}"}}"#, "\\ud83d");
    let cases: [&[u8]; 4] = [
        br#"{"a":"open"#,
        br#"{"a":"\x"}"#,
        b"{\"a\":\"\xff\"}",
        lone_surrogate.as_bytes(),
    ];
    for bad in cases {
        assert_eq!(
            redactor().redact_json(bad).unwrap_err().code(),
            codes::REDACT_DETECTOR_FAILURE
        );
        let blocked = scanner(&[]).check_json(bad).unwrap_err();
        assert!(blocked.scanner_failure);
        assert_eq!(blocked.code(), codes::REDACT_DETECTOR_FAILURE);
    }
}

#[test]
fn final_scan_blocks_known_secrets_and_detections_but_passes_redacted_output() {
    let vault_key = b"custom-provider-secret-0123456789";
    let s = scanner(&[vault_key]);
    let body = format!(r#"{{"note":"my key is {}"}}"#, std::str::from_utf8(vault_key).unwrap());
    let blocked = s.check_json(body.as_bytes()).unwrap_err();
    assert!(blocked.known_secret && blocked.classes.is_empty());
    assert_eq!(blocked.code(), codes::REDACT_BLOCKED);
    assert!(!blocked.to_string().contains("custom-provider"), "never echoes content");
    assert!(s.check_bytes(body.as_bytes()).is_err());

    let token = sample(DataClass::GoogleApiKey, 7);
    let body = serde_json::to_vec(&json!({ "content": format!("use {}", token.text) })).unwrap();
    assert!(s.check_json(&body).is_err());
    let redacted = redactor().redact_json(&body).unwrap();
    assert!(s.check_json(redacted.output()).is_ok());

    // Content outside any string (a malformed body) is checked raw.
    let unquoted = format!(r#"{{"a": {} }}"#, sample(DataClass::AwsAccessKeyId, 10).text);
    assert!(
        s.check_json(unquoted.as_bytes())
            .unwrap_err()
            .classes
            .contains(&DataClass::AwsAccessKeyId)
    );

    assert_eq!(
        FinalScanner::new(DetectorVersion::V1, [b"short".as_slice()]).unwrap_err(),
        RedactError::KnownSecretTooShort
    );
}

#[test]
fn pinned_versions_are_enforced() {
    assert_eq!(
        Redactor::new(DetectorVersion(9), SecretKey::from_bytes(POCKET_KEY)).unwrap_err(),
        RedactError::UnknownDetectorVersion(9)
    );
    assert!(FinalScanner::new(DetectorVersion(9), std::iter::empty()).is_err());
    assert_eq!(redactor().version(), DetectorVersion::CURRENT);
}

#[test]
fn debug_output_never_contains_secrets() {
    let token = sample(DataClass::OpenaiApiKey, 8);
    let r = redactor().redact_text(&token.text).unwrap();
    let debug = format!("{r:?} {:?} {:?}", r.replacements(), redactor());
    assert!(!debug.contains(&token.secret));
    assert_eq!(r.replacements()[0].expose_secret(), token.secret);
}

#[test]
fn every_class_is_reported_for_policy() {
    let mut rng = Prng::new(9);
    let mut parts = Vec::new();
    for class in DataClass::ALL {
        let s = secret(&mut rng, class);
        parts.push(embed(&mut rng, &s.text));
    }
    let (red, text) = (redactor(), parts.join("\n"));
    let r = red.redact_text(&text).unwrap();
    assert_eq!(r.classes(), DataClass::ALL.into_iter().collect());
}

/// Prose with `count` secrets of random classes between it; returns the text and the secrets.
fn text_with_secrets(seed: u64, count: usize) -> (String, Vec<String>) {
    let mut rng = Prng::new(seed);
    let mut parts = vec![prose(&mut rng)];
    let mut secrets = Vec::new();
    for _ in 0..count {
        let class = rng.pick(&DataClass::ALL);
        let s = secret(&mut rng, class);
        parts.push(s.text);
        secrets.push(s.secret);
        parts.push(prose(&mut rng));
    }
    let separator = rng.pick(&[" ", "\n", ", ", "\t"]);
    (parts.join(separator), secrets)
}

fn json_value() -> impl Strategy<Value = Value> {
    let leaf = prop_oneof![
        (any::<u64>(), 0..3_usize).prop_map(|(seed, n)| Value::String(text_with_secrets(seed, n).0)),
        any::<i64>().prop_map(Value::from),
        any::<bool>().prop_map(Value::Bool),
        Just(Value::Null),
    ];
    leaf.prop_recursive(4, 48, 6, |inner| {
        prop_oneof![
            prop::collection::vec(inner.clone(), 0..6).prop_map(Value::Array),
            prop::collection::vec(((any::<u64>(), 0..2_usize), inner), 0..6).prop_map(|entries| {
                Value::Object(
                    entries
                        .into_iter()
                        .map(|((seed, n), v)| (text_with_secrets(seed, n).0, v))
                        .collect(),
                )
            }),
        ]
    })
}

fn map_strings(v: &Value, f: &dyn Fn(&str) -> String) -> Value {
    match v {
        Value::String(s) => Value::String(f(s)),
        Value::Array(items) => Value::Array(items.iter().map(|i| map_strings(i, f)).collect()),
        Value::Object(map) => Value::Object(map.iter().map(|(k, v)| (f(k), map_strings(v, f))).collect()),
        other => other.clone(),
    }
}

proptest! {
    #[test]
    fn text_redaction_removes_every_secret_and_is_a_fixpoint(seed in any::<u64>(), count in 0..5_usize) {
        let (text, secrets) = text_with_secrets(seed, count);
        let r = redactor().redact_text(&text).unwrap();
        for s in &secrets {
            prop_assert!(!r.output().contains(s.as_str()), "a secret survived redaction");
        }
        prop_assert_eq!(r.is_clean(), secrets.is_empty());
        prop_assert!(redactor().redact_text(r.output()).unwrap().is_clean(), "redact(redact(x)) != redact(x)");
        prop_assert!(scanner(&[]).check_bytes(r.output().as_bytes()).is_ok());
    }

    #[test]
    fn json_redaction_is_schema_agnostic(doc in json_value(), pretty in any::<bool>()) {
        let body = if pretty { serde_json::to_vec_pretty(&doc) } else { serde_json::to_vec(&doc) }.unwrap();
        let red = redactor();
        let r = red.redact_json(&body).unwrap();
        let out: Value = serde_json::from_slice(r.output()).unwrap();
        let expected = map_strings(&doc, &|s| red.redact_text(s).unwrap().into_output().into_owned());
        prop_assert_eq!(out, expected, "JSON redaction must equal text redaction of every string");
        prop_assert!(scanner(&[]).check_json(r.output()).is_ok());
        prop_assert!(red.redact_json(r.output()).unwrap().is_clean());
        if r.is_clean() {
            prop_assert_eq!(r.output(), body.as_slice(), "clean bodies pass byte for byte");
        }
    }

    #[test]
    fn arbitrary_bytes_never_panic_and_errors_block(
        bytes in prop::collection::vec(prop::sample::select(b"u\"\\0123456789abcdefABCDEF{}[]:,dD8 \xff".to_vec()), 0..256)
    ) {
        let red = redactor();
        let redacted = red.redact_json(&bytes);
        let checked = scanner(&[]).check_json(&bytes);
        if redacted.is_err() {
            prop_assert!(checked.is_err(), "content redaction refuses must not pass the final scan");
        }
        if let Ok(r) = redacted {
            prop_assert!(scanner(&[]).check_json(r.output()).is_ok());
        }
    }
}

/// Review WP2.3 H1: a derived `Debug` printed the known-secret automaton, from which a probe
/// reconstructed the vault secret. Nothing secret-derived may reach `Debug` output.
#[test]
fn debug_output_carries_no_secret_material() {
    let canary = b"vault-provider-key-ZQXJ0123456789";
    let scanner = FinalScanner::new(DetectorVersion::V1, [canary.as_slice()]).unwrap();
    let shown = format!("{scanner:?} {scanner:#?}");
    assert!(
        shown.len() < 200,
        "Debug output is unexpectedly large: {} bytes",
        shown.len()
    );
    // No 4-byte window of the canary, in any form, appears in the output.
    let text = String::from_utf8_lossy(canary);
    for window in text.as_bytes().windows(4) {
        let w = String::from_utf8_lossy(window);
        assert!(!shown.contains(w.as_ref()), "Debug output contains {w:?}");
    }
    assert!(shown.contains("known_secrets: 1"));
}
