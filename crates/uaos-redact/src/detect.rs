// SPDX-License-Identifier: Apache-2.0

//! Detector sets: high-confidence secret formats.
//!
//! One Aho–Corasick pass finds every anchor literal (`sk-ant-`, `AKIA`, `-----BEGIN `, …); a
//! per-format validator then confirms the candidate, with boundary checks on **both** sides so a
//! format embedded in a longer token is not reported. Overlapping detections merge into one
//! span carrying the most specific class. Scanning is linear in the input and allocation-free
//! unless something is found.
//!
//! A detector set is versioned as a whole and pinned per session: the bytes a session sends must
//! not change under it (plan §2.5). Changing any rule below requires a new version.

use std::fmt;
use std::ops::Range;

use aho_corasick::{AhoCorasick, MatchKind};

use crate::RedactError;
use crate::class::DataClass;

/// A pinned detector set version.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct DetectorVersion(pub u16);

impl DetectorVersion {
    /// Detector set v1: 11 classes, measured by synthetic corpus v1.
    pub const V1: Self = Self(1);
    /// The version new sessions pin.
    pub const CURRENT: Self = Self::V1;
}

/// A detected secret: its class and byte range in the scanned text.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Finding {
    /// The class.
    pub class: DataClass,
    /// Byte range in the scanned text.
    pub range: Range<usize>,
}

/// Placeholders start with this; no detector may match a placeholder (redaction is idempotent).
pub(crate) const PLACEHOLDER_PREFIX: &[u8] = b"[REDACTED:";

pub(crate) fn is_placeholder(bytes: &[u8]) -> bool {
    bytes.starts_with(PLACEHOLDER_PREFIX) && bytes.ends_with(b"]")
}

// Byte sets.
fn alnum(b: u8) -> bool {
    b.is_ascii_alphanumeric()
}
fn word(b: u8) -> bool {
    alnum(b) || b == b'_'
}
fn token(b: u8) -> bool {
    word(b) || b == b'-'
}
fn upper_digit(b: u8) -> bool {
    b.is_ascii_uppercase() || b.is_ascii_digit()
}
fn alnum_dash(b: u8) -> bool {
    alnum(b) || b == b'-'
}
fn path(b: u8) -> bool {
    alnum(b) || b == b'/'
}
fn nothing(_: u8) -> bool {
    false
}

/// How a candidate after an anchor is confirmed.
#[derive(Debug, Clone, Copy)]
enum Rule {
    /// A maximal run of `chars` after the anchor (single dots between runs allowed when `dots`)
    /// of `min..=max` bytes, containing `marker` if set. The finding includes the anchor.
    Run {
        chars: fn(u8) -> bool,
        min: usize,
        max: usize,
        dots: bool,
        marker: Option<&'static [u8]>,
    },
    /// Exactly `len` bytes of `chars` after the anchor, not followed by a byte of `stop`.
    Exact {
        chars: fn(u8) -> bool,
        len: usize,
        stop: fn(u8) -> bool,
    },
    /// A run of `chars` after a public anchor; only the run is secret.
    RunAfter {
        chars: fn(u8) -> bool,
        min: usize,
        max: usize,
    },
    /// A PEM block whose label ends in `PRIVATE KEY` (or `PRIVATE KEY BLOCK`).
    PemPrivateKey,
    /// `header.payload.signature`, header and payload both JSON objects in base64url.
    Jwt,
    /// The password in `scheme://user:password@host`.
    UrlPassword,
}

/// An anchor literal, the class it signals, and how to confirm it.
#[derive(Debug, Clone, Copy)]
struct Anchor {
    literal: &'static str,
    class: DataClass,
    /// A byte of this set right before the anchor means the anchor sits inside a longer token.
    left: fn(u8) -> bool,
    rule: Rule,
}

const fn anchor(literal: &'static str, class: DataClass, left: fn(u8) -> bool, rule: Rule) -> Anchor {
    Anchor {
        literal,
        class,
        left,
        rule,
    }
}

const fn run(chars: fn(u8) -> bool, min: usize, max: usize) -> Rule {
    Rule::Run {
        chars,
        min,
        max,
        dots: false,
        marker: None,
    }
}

const ANTHROPIC: Rule = run(token, 32, 300);
const OPENAI_MARKED: Rule = Rule::Run {
    chars: token,
    min: 40,
    max: 400,
    dots: false,
    marker: Some(b"T3BlbkFJ"),
};
const OPENAI_SCOPED: Rule = run(token, 40, 400);
const GITHUB_CLASSIC: Rule = Rule::Exact {
    chars: alnum,
    len: 36,
    stop: word,
};
const GITHUB_FINE_GRAINED: Rule = run(word, 70, 120);
const GITLAB: Rule = Rule::Run {
    chars: token,
    min: 20,
    max: 120,
    dots: true,
    marker: None,
};
const SLACK: Rule = run(alnum_dash, 20, 300);
const SLACK_WEBHOOK: Rule = Rule::RunAfter {
    chars: path,
    min: 20,
    max: 200,
};
const STRIPE: Rule = run(alnum, 24, 247);
const GOOGLE: Rule = Rule::Exact {
    chars: token,
    len: 35,
    stop: token,
};
const AWS: Rule = Rule::Exact {
    chars: upper_digit,
    len: 16,
    stop: alnum,
};

/// Detector set v1. A longer anchor must precede any anchor that is its prefix (leftmost-first);
/// merge priority between classes comes from [`DataClass`].
fn v1() -> Vec<Anchor> {
    use DataClass as C;
    vec![
        anchor("-----BEGIN ", C::PrivateKey, nothing, Rule::PemPrivateKey),
        anchor("eyJ", C::Jwt, token, Rule::Jwt),
        anchor("sk-ant-", C::AnthropicApiKey, token, ANTHROPIC),
        anchor("sk-proj-", C::OpenaiApiKey, token, OPENAI_SCOPED),
        anchor("sk-svcacct-", C::OpenaiApiKey, token, OPENAI_SCOPED),
        anchor("sk-admin-", C::OpenaiApiKey, token, OPENAI_SCOPED),
        anchor("sk-", C::OpenaiApiKey, token, OPENAI_MARKED),
        anchor("ghp_", C::GithubToken, word, GITHUB_CLASSIC),
        anchor("gho_", C::GithubToken, word, GITHUB_CLASSIC),
        anchor("ghu_", C::GithubToken, word, GITHUB_CLASSIC),
        anchor("ghs_", C::GithubToken, word, GITHUB_CLASSIC),
        anchor("ghr_", C::GithubToken, word, GITHUB_CLASSIC),
        anchor("github_pat_", C::GithubToken, word, GITHUB_FINE_GRAINED),
        anchor("glpat-", C::GitlabToken, token, GITLAB),
        anchor("glrt-", C::GitlabToken, token, GITLAB),
        anchor("gldt-", C::GitlabToken, token, GITLAB),
        anchor("xoxb-", C::SlackToken, token, SLACK),
        anchor("xoxp-", C::SlackToken, token, SLACK),
        anchor("xoxa-", C::SlackToken, token, SLACK),
        anchor("xoxr-", C::SlackToken, token, SLACK),
        anchor("xoxs-", C::SlackToken, token, SLACK),
        anchor("xoxe-", C::SlackToken, token, SLACK),
        anchor("hooks.slack.com/services/", C::SlackToken, nothing, SLACK_WEBHOOK),
        anchor("sk_live_", C::StripeKey, word, STRIPE),
        anchor("sk_test_", C::StripeKey, word, STRIPE),
        anchor("rk_live_", C::StripeKey, word, STRIPE),
        anchor("rk_test_", C::StripeKey, word, STRIPE),
        anchor("AIza", C::GoogleApiKey, token, GOOGLE),
        anchor("AKIA", C::AwsAccessKeyId, alnum, AWS),
        anchor("ASIA", C::AwsAccessKeyId, alnum, AWS),
        anchor("ABIA", C::AwsAccessKeyId, alnum, AWS),
        anchor("ACCA", C::AwsAccessKeyId, alnum, AWS),
        anchor("://", C::UrlCredentials, nothing, Rule::UrlPassword),
    ]
}

/// A compiled detector set. `Debug` shows the version and the number of anchors only.
pub struct DetectorSet {
    version: DetectorVersion,
    anchors: Vec<Anchor>,
    automaton: AhoCorasick,
}

impl fmt::Debug for DetectorSet {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DetectorSet")
            .field("version", &self.version)
            .field("anchors", &self.anchors.len())
            .finish_non_exhaustive()
    }
}

impl DetectorSet {
    /// Compiles detector set `version`.
    ///
    /// # Errors
    /// [`RedactError::UnknownDetectorVersion`] for a version this build does not have (the
    /// session must not silently switch rules); [`RedactError::DetectorFailure`] if compiling
    /// fails.
    pub fn new(version: DetectorVersion) -> Result<Self, RedactError> {
        let anchors = match version {
            DetectorVersion::V1 => v1(),
            DetectorVersion(other) => return Err(RedactError::UnknownDetectorVersion(other)),
        };
        // Leftmost-first, non-overlapping: lets the search use its SIMD prefilter (several times
        // faster on prose). Longer anchors are listed before their prefixes (`sk-ant-` before
        // `sk-`), so the most specific rule is tried. An anchor can only start inside another
        // anchor's match by being glued to it, which its left-boundary check rejects anyway.
        let automaton = AhoCorasick::builder()
            .match_kind(MatchKind::LeftmostFirst)
            .build(anchors.iter().map(|a| a.literal))
            .map_err(|_| RedactError::DetectorFailure("anchor automaton could not be built"))?;
        Ok(Self {
            version,
            anchors,
            automaton,
        })
    }

    /// The version.
    #[must_use]
    pub fn version(&self) -> DetectorVersion {
        self.version
    }

    /// Every secret in `text`, as non-overlapping findings in order.
    ///
    /// # Errors
    /// [`RedactError::DetectorFailure`]: the caller must block, never pass content unscanned.
    pub fn scan(&self, text: &[u8]) -> Result<Vec<Finding>, RedactError> {
        let mut found = Vec::new();
        let matches = self
            .automaton
            .try_find_iter(text)
            .map_err(|_| RedactError::DetectorFailure("anchor search failed"))?;
        for m in matches {
            let Some(anchor) = self.anchors.get(m.pattern().as_usize()) else {
                return Err(RedactError::DetectorFailure("unknown anchor"));
            };
            let glued = m
                .start()
                .checked_sub(1)
                .and_then(|i| text.get(i))
                .is_some_and(|&b| (anchor.left)(b));
            if glued {
                continue;
            }
            if let Some(range) = anchor.rule.confirm(text, m.start(), m.end()) {
                found.push(Finding {
                    class: anchor.class,
                    range,
                });
            }
        }
        Ok(merge(found))
    }
}

impl Rule {
    /// The secret's range, given an anchor at `start..after`; `None` if this is not one.
    fn confirm(self, text: &[u8], start: usize, after: usize) -> Option<Range<usize>> {
        match self {
            Self::Run {
                chars,
                min,
                max,
                dots,
                marker,
            } => {
                let end = run_end(text, after, chars, dots);
                let body = text.get(after..end)?;
                let ok = (min..=max).contains(&body.len()) && marker.is_none_or(|m| find(body, m).is_some());
                ok.then_some(start..end)
            }
            Self::Exact { chars, len, stop } => {
                let end = after.checked_add(len)?;
                let body = text.get(after..end)?;
                let ok = body.iter().all(|&b| chars(b)) && !text.get(end).is_some_and(|&b| stop(b));
                ok.then_some(start..end)
            }
            Self::RunAfter { chars, min, max } => {
                let end = run_end(text, after, chars, false);
                (min..=max).contains(&end.saturating_sub(after)).then_some(after..end)
            }
            Self::PemPrivateKey => pem_private_key(text, start, after),
            Self::Jwt => jwt(text, start),
            Self::UrlPassword => url_password(text, start, after),
        }
    }
}

/// End of the maximal run of `chars` from `from`; with `dots`, a single `.` between two runs
/// continues it (`a.b`), a trailing `.` (end of sentence) does not.
fn run_end(text: &[u8], from: usize, chars: fn(u8) -> bool, dots: bool) -> usize {
    let mut end = from;
    loop {
        while text.get(end).is_some_and(|&b| chars(b)) {
            end += 1;
        }
        let continues =
            dots && end > from && text.get(end) == Some(&b'.') && text.get(end + 1).is_some_and(|&b| chars(b));
        if !continues {
            return end;
        }
        end += 1;
    }
}

fn find(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack.windows(needle.len()).position(|w| w == needle)
}

/// Longest label we accept between `-----BEGIN ` and `-----`.
const PEM_LABEL_MAX: usize = 48;
/// How far we look for the matching `-----END` line.
const PEM_BODY_MAX: usize = 64 * 1024;

fn pem_private_key(text: &[u8], start: usize, after: usize) -> Option<Range<usize>> {
    let window = text.get(after..text.len().min(after + PEM_LABEL_MAX + 5))?;
    let label_len = find(window, b"-----")?;
    let label = window.get(..label_len)?;
    let well_formed = label.iter().all(|&b| upper_digit(b) || b == b' ');
    if !well_formed || !(label.ends_with(b"PRIVATE KEY") || label.ends_with(b"PRIVATE KEY BLOCK")) {
        return None;
    }
    let header_end = after + label_len + 5;
    let body = text.get(header_end..text.len().min(header_end.saturating_add(PEM_BODY_MAX)))?;
    // Without its END line (truncated, or too far away), everything after BEGIN is treated as
    // key material: fail closed.
    let end = find(body, b"-----END ")
        .and_then(|i| {
            let label_from = header_end + i + 9;
            let tail = text.get(label_from..text.len().min(label_from + PEM_LABEL_MAX + 5))?;
            find(tail, b"-----").map(|j| label_from + j + 5)
        })
        .unwrap_or(text.len());
    Some(start..end)
}

/// Minimum header and payload lengths (base64url of `{"alg":…}` and of a claims object).
const JWT_PART_MIN: usize = 10;
/// Minimum signature length: shorter ones are not credentials (an `alg: none` token has none).
const JWT_SIGNATURE_MIN: usize = 16;

fn jwt(text: &[u8], start: usize) -> Option<Range<usize>> {
    let header_end = run_end(text, start, token, false);
    if header_end - start < JWT_PART_MIN || text.get(header_end) != Some(&b'.') {
        return None;
    }
    let payload = header_end + 1;
    if text.get(payload..payload + 3) != Some(b"eyJ".as_slice()) {
        return None;
    }
    let payload_end = run_end(text, payload, token, false);
    if payload_end - payload < JWT_PART_MIN || text.get(payload_end) != Some(&b'.') {
        return None;
    }
    let signature = payload_end + 1;
    let end = run_end(text, signature, token, false);
    (end - signature >= JWT_SIGNATURE_MIN).then_some(start..end)
}

/// Longest authority we inspect for userinfo.
const USERINFO_MAX: usize = 512;

/// The password of `scheme://user:password@host`. Userinfo ends at the **last** `@` before the
/// authority ends (as URL parsers do), so an unencoded `@` inside a password is still covered.
fn url_password(text: &[u8], start: usize, after: usize) -> Option<Range<usize>> {
    let has_scheme = start
        .checked_sub(1)
        .and_then(|i| text.get(i))
        .is_some_and(|&b| alnum(b));
    if !has_scheme {
        return None;
    }
    let mut last_at = None;
    for i in after..text.len().min(after + USERINFO_MAX) {
        let b = *text.get(i)?;
        if matches!(b, b'/' | b'?' | b'#' | b'"' | b'\'' | b'<' | b'>' | b'\\' | b'`')
            || b.is_ascii_whitespace()
            || b.is_ascii_control()
        {
            break;
        }
        if b == b'@' {
            last_at = Some(i);
        }
    }
    let at = last_at?;
    let colon = after + find(text.get(after..at)?, b":")?;
    let password = colon + 1..at;
    if password.is_empty() || is_placeholder(text.get(password.clone())?) {
        return None;
    }
    let host_follows = text.get(at + 1).is_some_and(|&b| alnum(b) || b == b'[');
    host_follows.then_some(password)
}

/// Sorts findings and merges overlaps into one span with the most specific class.
fn merge(mut found: Vec<Finding>) -> Vec<Finding> {
    found.sort_by(|a, b| a.range.start.cmp(&b.range.start).then(b.range.end.cmp(&a.range.end)));
    let mut out: Vec<Finding> = Vec::with_capacity(found.len());
    for f in found {
        match out.last_mut() {
            Some(last) if f.range.start < last.range.end => {
                last.range.end = last.range.end.max(f.range.end);
                last.class = last.class.min(f.class);
            }
            _ => out.push(f),
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn classes(text: &str) -> Vec<(DataClass, &str)> {
        let set = DetectorSet::new(DetectorVersion::V1).unwrap();
        set.scan(text.as_bytes())
            .unwrap()
            .into_iter()
            .map(|f| (f.class, &text[f.range]))
            .collect()
    }

    #[test]
    fn boundaries_on_both_sides() {
        let key = format!("AKIA{}", "Q".repeat(16));
        assert_eq!(
            classes(&format!("id={key};")),
            [(DataClass::AwsAccessKeyId, key.as_str())]
        );
        assert!(classes(&format!("x{key}")).is_empty(), "inside a longer token");
        assert!(classes(&format!("{key}Z")).is_empty(), "longer than the format");
    }

    #[test]
    fn overlapping_detections_merge_to_the_specific_class() {
        let token = format!("ghp_{}", "a".repeat(36));
        let text = format!("https://user:{token}@github.com/org/repo");
        assert_eq!(classes(&text), [(DataClass::GithubToken, token.as_str())]);
    }

    #[test]
    fn url_password_ends_at_the_last_at_sign() {
        assert_eq!(
            classes("redis://:p@ss@cache.local:6379"),
            [(DataClass::UrlCredentials, "p@ss")]
        );
        assert!(classes("http://localhost:3000/@user").is_empty());
        assert!(classes("https://user@example.com").is_empty());
        assert!(classes("postgres://user:@db").is_empty());
    }

    #[test]
    fn pem_without_end_is_redacted_to_the_end() {
        // Split so the source never holds a full PEM header (secret scanning stays meaningful).
        let text = concat!("x -----BEGIN RSA PRIVATE", " KEY-----\nMIIabc");
        assert_eq!(classes(text), [(DataClass::PrivateKey, &text[2..])]);
        assert!(classes("-----BEGIN PUBLIC KEY-----\nMIIabc\n-----END PUBLIC KEY-----").is_empty());
    }

    #[test]
    fn unknown_versions_are_refused() {
        assert_eq!(
            DetectorSet::new(DetectorVersion(2)).unwrap_err(),
            RedactError::UnknownDetectorVersion(2)
        );
    }
}
