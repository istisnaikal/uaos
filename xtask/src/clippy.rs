// SPDX-License-Identifier: Apache-2.0

//! `cargo xtask clippy`: clippy over the workspace with warnings denied, failing also on a
//! `clippy.toml` ban whose path resolves to nothing. Clippy reports such a path only as a warning
//! that `-D warnings` does not make fatal, so a typo, or an item moving upstream, would quietly
//! switch a ban off (review WP3.A5, round 4, M1). Cargo is asked for plain text and colour codes
//! are removed anyway: CI colours output, and a coloured header never starts with `warning:`
//! (round 5, M1). A note with no warning above it fails the gate too. Paths that draw no warning
//! at all are caught by the canaries in `crates/uaos-egress/tests/bans.rs`.

use std::path::Path;
use std::process::Command;

/// The note clippy attaches to every `clippy.toml` path it cannot resolve.
const UNRESOLVED: &str = "add `allow-invalid = true` to the entry to suppress this warning";

const ARGS: &[&str] = &[
    "clippy",
    "--color",
    "never",
    "--workspace",
    "--all-targets",
    "--locked",
    "--",
    "-D",
    "warnings",
];

pub(crate) fn check(root: &Path) -> Result<(), String> {
    let set = overriding_env(std::env::vars_os().filter_map(|(k, _)| k.into_string().ok()));
    if !set.is_empty() {
        return Err(format!(
            "[clippy] refusing to run: {} can change lint levels, compiler flags or clippy's configuration outside the workspace lint table; unset them (review WP3.A5, round 7, M1)",
            set.join(", ")
        ));
    }
    println!("xtask: [clippy] cargo {}", ARGS.join(" "));
    let out = Command::new("cargo")
        .args(ARGS)
        .current_dir(root)
        .output()
        .map_err(|e| format!("[clippy] could not start `cargo`: {e}"))?;
    let stderr = String::from_utf8_lossy(&out.stderr);
    print!("{}", String::from_utf8_lossy(&out.stdout));
    eprint!("{stderr}");
    // Reported first, also when clippy fails too: a ban that resolves to nothing usually also
    // leaves its canary unfulfilled, and the cause matters more than the symptom.
    let unresolved = unresolved_bans(&stderr);
    if !unresolved.is_empty() {
        return Err(format!(
            "[clippy] clippy.toml bans paths that resolve to nothing, so those bans are off:\n  {}",
            unresolved.join("\n  ")
        ));
    }
    if out.status.success() {
        Ok(())
    } else {
        Err(format!("[clippy] failed ({})", out.status))
    }
}

/// The variables among `names` that change lint levels, compiler flags or clippy's
/// configuration: compiler flags in any form, compiler wrappers, clippy's arguments and
/// configuration directory.
fn overriding_env(names: impl IntoIterator<Item = String>) -> Vec<String> {
    let mut set: Vec<String> = names
        .into_iter()
        .filter(|k| crate::allow_audit::OVERRIDING_ENV_WORDS.iter().any(|w| k.contains(w)))
        .collect();
    set.sort();
    set
}

/// The warnings clippy printed for `clippy.toml` paths it could not resolve: for each note, the
/// nearest `warning:` line above it, or the note itself if there is none (fail closed).
fn unresolved_bans(stderr: &str) -> Vec<String> {
    let lines: Vec<String> = stderr.lines().map(strip_ansi).collect();
    let mut found: Vec<String> = lines
        .iter()
        .enumerate()
        .filter(|(_, line)| line.contains(UNRESOLVED))
        .map(|(i, note)| {
            lines
                .iter()
                .take(i)
                .rev()
                .find(|l| l.starts_with("warning:"))
                .unwrap_or(note)
                .trim()
                .to_owned()
        })
        .collect();
    found.sort_unstable();
    found.dedup();
    found
}

/// `line` without ANSI escape sequences (`ESC [ ... final byte`).
fn strip_ansi(line: &str) -> String {
    let mut out = String::with_capacity(line.len());
    let mut chars = line.chars();
    while let Some(c) = chars.next() {
        if c == '\u{1b}' {
            if chars.next() == Some('[') {
                for c in chars.by_ref() {
                    if ('@'..='~').contains(&c) {
                        break;
                    }
                }
            }
        } else {
            out.push(c);
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_unresolved_ban_is_found_and_reported_once() {
        let stderr = "warning: `a::b` does not refer to a reachable function\n  --> clippy.toml:3:5\n  = note: add `allow-invalid = true` to the entry to suppress this warning\nwarning: `a::b` does not refer to a reachable function\n  = note: add `allow-invalid = true` to the entry to suppress this warning\n    Finished `dev` profile\n";
        assert_eq!(
            unresolved_bans(stderr),
            vec!["warning: `a::b` does not refer to a reachable function".to_owned()]
        );
        assert!(unresolved_bans("warning: unused variable `x`\n    Finished\n").is_empty());
    }

    /// Round 5, M1: CI colours cargo's output; the coloured header must still be found.
    #[test]
    fn a_coloured_unresolved_ban_is_found() {
        let stderr = "\x1b[1m\x1b[93mwarning\x1b[0m\x1b[1m\x1b[97m: `a::b` does not refer to a reachable function\x1b[0m\n   \x1b[1m\x1b[96m|\x1b[0m\n   \x1b[1m\x1b[96m= \x1b[0m\x1b[1m\x1b[97mhelp\x1b[0m: add `allow-invalid = true` to the entry to suppress this warning\n";
        assert_eq!(
            unresolved_bans(stderr),
            vec!["warning: `a::b` does not refer to a reachable function".to_owned()]
        );
    }

    /// Round 7, M1: flags, wrappers and clippy's own arguments in the environment are refused.
    #[test]
    fn an_overriding_environment_is_refused() {
        let names = [
            "PATH",
            "RUSTFLAGS",
            "CARGO_ENCODED_RUSTFLAGS",
            "CARGO_TARGET_X86_64_PC_WINDOWS_MSVC_RUSTFLAGS",
            "RUSTC_WRAPPER",
            "CLIPPY_ARGS",
            "CLIPPY_CONF_DIR",
            "CARGO_TERM_COLOR",
        ]
        .map(str::to_owned);
        assert_eq!(overriding_env(names).len(), 6);
    }

    /// A note with no warning above it still fails the gate.
    #[test]
    fn a_note_without_its_warning_fails_closed() {
        let stderr = "  = help: add `allow-invalid = true` to the entry to suppress this warning\n";
        assert_eq!(unresolved_bans(stderr).len(), 1);
    }
}
