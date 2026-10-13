// SPDX-License-Identifier: Apache-2.0

//! Where guarded lints may be switched off (plan v2 §2.1, PD-19, ADR-0010).
//!
//! The workspace denies `unsafe_code`, and `clippy.toml` bans ambient clocks, randomness,
//! filesystem, process and thread APIs outside their owning crates. Both can be undone by a
//! single `#[allow(...)]` anywhere, and that would make every other gate decorative. This check
//! finds every `#[allow(...)]` / `#[expect(...)]` (inner or outer, including inside `cfg_attr`)
//! that names a guarded lint, and fails unless the file sits under one of that lint's owner
//! paths in `arch.toml` `[allow_audit]`.

use std::collections::BTreeMap;
use std::path::Path;

use serde::Deserialize;

use crate::util::{rel, walk_files};

#[derive(Debug, Deserialize)]
struct ArchFile {
    allow_audit: BTreeMap<String, Vec<String>>,
}

pub(crate) fn check(root: &Path) -> Result<(), String> {
    let text = std::fs::read_to_string(root.join("arch.toml")).map_err(|e| format!("arch.toml: {e}"))?;
    let arch: ArchFile = toml::from_str(&text).map_err(|e| format!("arch.toml [allow_audit]: {e}"))?;
    let owners = arch.allow_audit;

    let mut violations = Vec::new();
    let mut found = 0usize;
    for path in walk_files(root)? {
        if path.extension().and_then(|e| e.to_str()) != Some("rs") {
            continue;
        }
        let relative = rel(root, &path);
        let source = std::fs::read_to_string(&path).map_err(|e| format!("{relative}: {e}"))?;
        for (line, body) in attributes(&source) {
            if !(contains_word(&body, "allow") || contains_word(&body, "expect")) {
                continue;
            }
            for (lint, patterns) in &owners {
                if !contains_word(&body, short_name(lint)) {
                    continue;
                }
                found += 1;
                if !patterns.iter().any(|p| path_matches(p, &relative)) {
                    violations.push(format!(
                        "{relative}:{line}: allows `{lint}` outside its owners ({})",
                        patterns.join(", ")
                    ));
                }
            }
        }
    }
    if violations.is_empty() {
        println!("xtask allow-audit: {found} guarded-lint allow(s), all inside their owners");
        Ok(())
    } else {
        Err(format!(
            "{} guarded-lint allow(s) outside its owners (arch.toml [allow_audit]):\n  {}",
            violations.len(),
            violations.join("\n  ")
        ))
    }
}

/// `clippy::disallowed_methods` → `disallowed_methods`; `unsafe_code` stays as is.
fn short_name(lint: &str) -> &str {
    lint.rsplit("::").next().unwrap_or(lint)
}

/// Every attribute (`#[...]` or `#![...]`) in code as `(1-based line, text between the
/// brackets)`. String, raw-string and char literals and comments are skipped, so attribute-like
/// text in fixtures, seed strings and documentation is not mistaken for code.
fn attributes(source: &str) -> Vec<(usize, String)> {
    let chars: Vec<char> = source.chars().collect();
    let at = |i: usize| chars.get(i).copied();
    let mut out = Vec::new();
    let mut line = 1usize;
    let mut i = 0usize;
    // Inside an attribute: (start line, bracket depth, collected body).
    let mut attr: Option<(usize, usize, String)> = None;
    while let Some(c) = at(i) {
        let skipped = skip_literal_or_comment(&chars, i);
        if skipped > i {
            let text: String = chars.get(i..skipped).map(|s| s.iter().collect()).unwrap_or_default();
            line += text.matches('\n').count();
            if let Some((_, _, body)) = attr.as_mut() {
                body.push_str(&text);
            }
            i = skipped;
            continue;
        }
        if c == '\n' {
            line += 1;
        }
        match attr.as_mut() {
            None => {
                let bang = at(i + 1) == Some('!');
                let open = if bang { i + 2 } else { i + 1 };
                if c == '#' && at(open) == Some('[') {
                    attr = Some((line, 1, String::new()));
                    i = open + 1;
                    continue;
                }
            }
            Some((start, depth, body)) => match c {
                '[' => {
                    *depth += 1;
                    body.push(c);
                }
                ']' => {
                    *depth -= 1;
                    if *depth == 0 {
                        out.push((*start, std::mem::take(body)));
                        attr = None;
                    } else {
                        body.push(c);
                    }
                }
                _ => body.push(c),
            },
        }
        i += 1;
    }
    out
}

/// If a string, raw string, char literal or comment starts at `i`, returns the index just past
/// it; otherwise returns `i`. Lifetimes (`'a`) are not literals.
fn skip_literal_or_comment(chars: &[char], i: usize) -> usize {
    let at = |k: usize| chars.get(k).copied();
    match (at(i), at(i + 1)) {
        (Some('/'), Some('/')) => (i..chars.len()).find(|&k| at(k) == Some('\n')).unwrap_or(chars.len()),
        (Some('/'), Some('*')) => {
            let mut depth = 0usize;
            let mut k = i;
            while k < chars.len() {
                match (at(k), at(k + 1)) {
                    (Some('/'), Some('*')) => {
                        depth += 1;
                        k += 2;
                    }
                    (Some('*'), Some('/')) => {
                        depth -= 1;
                        k += 2;
                        if depth == 0 {
                            return k;
                        }
                    }
                    _ => k += 1,
                }
            }
            chars.len()
        }
        (Some('"'), _) => end_of_quoted(chars, i + 1),
        (Some('b'), Some('"')) => end_of_quoted(chars, i + 2),
        (Some('r' | 'b'), _) if !is_ident_char(i.checked_sub(1).and_then(at)) => {
            // r"..", r#".."#, br"..", br#".."#
            let mut k = i + 1;
            if at(i) == Some('b') {
                if at(k) != Some('r') {
                    return i;
                }
                k += 1;
            }
            let hashes = (k..chars.len()).take_while(|&p| at(p) == Some('#')).count();
            k += hashes;
            if at(k) != Some('"') {
                return i;
            }
            k += 1;
            while k < chars.len() {
                if at(k) == Some('"') && (1..=hashes).all(|h| at(k + h) == Some('#')) {
                    return k + 1 + hashes;
                }
                k += 1;
            }
            chars.len()
        }
        (Some('\''), Some('\\')) => (i + 2..chars.len())
            .find(|&k| at(k) == Some('\''))
            .map_or(chars.len(), |k| k + 1),
        (Some('\''), Some(_)) if at(i + 2) == Some('\'') => i + 3,
        _ => i,
    }
}

fn end_of_quoted(chars: &[char], mut k: usize) -> usize {
    while let Some(c) = chars.get(k) {
        match c {
            '\\' => k += 2,
            '"' => return k + 1,
            _ => k += 1,
        }
    }
    chars.len()
}

fn is_ident_char(c: Option<char>) -> bool {
    c.is_some_and(|c| c.is_ascii_alphanumeric() || c == '_')
}

/// `word` occurs in `text` delimited by non-identifier characters.
fn contains_word(text: &str, word: &str) -> bool {
    let is_ident = |c: char| c.is_ascii_alphanumeric() || c == '_';
    text.match_indices(word).any(|(at, _)| {
        let before = text.get(..at).and_then(|s| s.chars().next_back());
        let after = text.get(at + word.len()..).and_then(|s| s.chars().next());
        !before.is_some_and(is_ident) && !after.is_some_and(is_ident)
    })
}

/// Owner patterns are path prefixes; a `*` segment matches exactly one path segment.
fn path_matches(pattern: &str, path: &str) -> bool {
    let mut pattern_parts = pattern.split('/').peekable();
    let mut path_parts = path.split('/');
    while let Some(p) = pattern_parts.next() {
        let last = pattern_parts.peek().is_none();
        if last && p.is_empty() {
            // Trailing slash: a directory prefix; everything below it matches.
            return true;
        }
        let Some(segment) = path_parts.next() else {
            return false;
        };
        let ok = if p == "*" {
            true
        } else if last {
            // Final pattern segment without a trailing slash: an exact file, or a file-name
            // prefix such as `real` matching `real.rs` and the `real/` directory.
            segment == p || segment.starts_with(p)
        } else {
            segment == p
        };
        if !ok {
            return false;
        }
        if last {
            return true;
        }
    }
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn finds_single_and_multi_line_attributes() {
        let src = "#![allow(\n    clippy::print_stdout,\n    clippy::disallowed_methods,\n)]\nfn f() {}\n#[cfg_attr(test, allow(unsafe_code))]\nfn g() {}\n";
        let attrs = attributes(src);
        assert_eq!(attrs.len(), 2);
        assert_eq!(attrs[0].0, 1);
        assert!(contains_word(&attrs[0].1, "disallowed_methods"));
        assert_eq!(attrs[1].0, 6);
        assert!(contains_word(&attrs[1].1, "unsafe_code"));
    }

    #[test]
    fn literals_and_comments_are_not_code() {
        let src = concat!(
            "let s = \"#[allow(unsafe_code)]\";\n",
            "let r = r#\"#![allow(unsafe_code)]\"#;\n",
            "// #[allow(unsafe_code)]\n",
            "/* #[allow(unsafe_code)] */\n",
            "let c = '#'; fn f<'a>(x: &'a u8) {}\n",
            "#[allow(clippy::disallowed_methods)]\n",
        );
        let attrs = attributes(src);
        assert_eq!(attrs.len(), 1, "{attrs:?}");
        assert_eq!(attrs[0].0, 6);
        assert!(contains_word(&attrs[0].1, "disallowed_methods"));
    }

    #[test]
    fn word_boundaries() {
        assert!(contains_word("allow(unsafe_code)", "unsafe_code"));
        assert!(!contains_word("forbid(unsafe_code_x)", "unsafe_code"));
        assert!(!contains_word("disallowed_methods_extra", "disallowed_methods"));
    }

    #[test]
    fn owner_patterns() {
        assert!(path_matches(
            "crates/uaos-platform/src/real",
            "crates/uaos-platform/src/real.rs"
        ));
        assert!(path_matches(
            "crates/uaos-platform/src/real",
            "crates/uaos-platform/src/real/fs.rs"
        ));
        assert!(!path_matches(
            "crates/uaos-platform/src/real",
            "crates/uaos-platform/src/sim.rs"
        ));
        assert!(path_matches("crates/*/tests/", "crates/uaos-ledger/tests/ledger.rs"));
        assert!(!path_matches("crates/*/tests/", "crates/uaos-ledger/src/lib.rs"));
        assert!(path_matches("xtask/", "xtask/src/main.rs"));
        assert!(!path_matches(
            "crates/uaos-platform/src/os/",
            "crates/uaos-policy/src/os/x.rs"
        ));
    }
}
