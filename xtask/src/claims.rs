// SPDX-License-Identifier: Apache-2.0

//! Forbidden-claims lint over public documents (CLAUDE.md red line 6; plan v2 V6, B-11).
//!
//! Claims are carried by metrics, baselines and tests. Words that promise more than any test can
//! show ("perfect", "zero loss", "tamper-proof", ...) fail the merge when they appear as a claim.
//! Three uses are not claims and pass:
//!
//! * **quoted** mentions: the term sits inside `"..."`, `“...”` or backticks on that line,
//!   e.g. we say "tamper-evident", not "tamper-proof";
//! * **negated** statements: a negation appears shortly before the term on the same line,
//!   e.g. "not tamper-proof", "do not claim the key is unobtainable";
//! * lines carrying an explicit, reasoned exemption comment:
//!   `<!-- claims-lint: allow (reason) -->`.
//!
//! `CLAUDE.md` defines the list and `CODE_OF_CONDUCT.md` is third-party text; both are skipped.

use std::path::Path;

use crate::util::{rel, walk_files};

const FORBIDDEN: &[&str] = &[
    "perfect",
    "faultless",
    "flawless",
    "zero loss",
    "zero-loss",
    "tamper-proof",
    "tamperproof",
    "unobtainable",
    "quota-bending",
    "quota bending",
    "rewind time",
    "rewinds time",
    "rewound time",
    "bulletproof",
    "unhackable",
    "100% secure",
    "military-grade",
];

const NEGATIONS: &[&str] = &["not", "never", "no", "nor", "without", "cannot"];
/// How far before a term (in characters) a negation still applies.
const NEGATION_WINDOW: usize = 40;
const EXEMPTION_MARKER: &str = "<!-- claims-lint: allow";
const SKIPPED: &[&str] = &["CLAUDE.md", "CODE_OF_CONDUCT.md"];

pub(crate) fn check(root: &Path) -> Result<(), String> {
    let mut violations = Vec::new();
    let mut scanned = 0usize;
    for path in walk_files(root)? {
        if path.extension().and_then(|e| e.to_str()) != Some("md") {
            continue;
        }
        let relative = rel(root, &path);
        let top_level = !relative.contains('/');
        if !(top_level || relative.starts_with("docs/")) || SKIPPED.contains(&relative.as_str()) {
            continue;
        }
        scanned += 1;
        let text = std::fs::read_to_string(&path).map_err(|e| format!("{relative}: {e}"))?;
        for (n, line) in text.lines().enumerate() {
            if let Some(term) = claim_in(line) {
                violations.push(format!("{relative}:{}: \"{term}\" used as a claim", n + 1));
            }
        }
    }
    if violations.is_empty() {
        println!("xtask claims: {scanned} document(s) free of forbidden claims");
        Ok(())
    } else {
        Err(format!(
            "{} forbidden claim(s) (CLAUDE.md red line 6). Quote it, negate it, or back it with a \
             measured statement:\n  {}",
            violations.len(),
            violations.join("\n  ")
        ))
    }
}

/// The first forbidden term used as a claim on `line`, if any.
fn claim_in(line: &str) -> Option<&'static str> {
    if line.contains(EXEMPTION_MARKER) {
        return None;
    }
    let lower = line.to_lowercase();
    for term in FORBIDDEN {
        for (at, _) in lower.match_indices(term) {
            let before = lower.get(..at).unwrap_or_default();
            let after = lower.get(at + term.len()..).unwrap_or_default();
            let word_start = !before.chars().next_back().is_some_and(char::is_alphanumeric);
            let word_end = !after.chars().next().is_some_and(char::is_alphanumeric);
            if !(word_start && word_end) {
                continue;
            }
            if quoted(before) || negated(before) {
                continue;
            }
            return Some(term);
        }
    }
    None
}

/// The text before the term leaves an open quote or backtick.
fn quoted(before: &str) -> bool {
    let straight = before.matches('"').count() % 2 == 1;
    let backtick = before.matches('`').count() % 2 == 1;
    let curly = before.matches('“').count() > before.matches('”').count();
    straight || backtick || curly
}

/// A negation word appears within [`NEGATION_WINDOW`] characters before the term.
fn negated(before: &str) -> bool {
    let window: String = before
        .chars()
        .rev()
        .take(NEGATION_WINDOW)
        .collect::<Vec<_>>()
        .into_iter()
        .rev()
        .collect();
    window
        .split(|c: char| !(c.is_alphanumeric() || c == '\'' || c == '’'))
        .any(|word| NEGATIONS.contains(&word) || word.ends_with("n't") || word.ends_with("n’t"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn claims_fail_mentions_pass() {
        assert_eq!(claim_in("UAOS is tamper-proof."), Some("tamper-proof"));
        assert_eq!(claim_in("Recovery with zero loss."), Some("zero loss"));
        assert_eq!(claim_in("We say \"tamper-evident\", not \"tamper-proof\"."), None);
        assert_eq!(claim_in("The chain is tamper-evident, not tamper-proof."), None);
        assert_eq!(claim_in("We do not claim the key is unobtainable."), None);
        assert_eq!(claim_in("the `perfect` word is banned"), None);
        assert_eq!(claim_in("perfectly ordinary"), None);
        assert_eq!(
            claim_in("it becomes unobtainable <!-- claims-lint: allow (hardened mode) -->"),
            None
        );
        assert_eq!(claim_in("It is 100% secure."), Some("100% secure"));
    }
}
