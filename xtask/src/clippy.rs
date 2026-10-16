// SPDX-License-Identifier: Apache-2.0

//! `cargo xtask clippy`: clippy over the workspace with warnings denied, failing also on a
//! `clippy.toml` ban whose path resolves to nothing. Clippy reports such a path only as a warning
//! that `-D warnings` does not make fatal, so a typo, or an item moving upstream, would quietly
//! switch a ban off (review WP3.A5, round 4, M1).

use std::path::Path;
use std::process::Command;

/// The note clippy attaches to every `clippy.toml` path it cannot resolve.
const UNRESOLVED: &str = "add `allow-invalid = true` to the entry to suppress this warning";

const ARGS: &[&str] = &[
    "clippy",
    "--workspace",
    "--all-targets",
    "--locked",
    "--",
    "-D",
    "warnings",
];

pub(crate) fn check(root: &Path) -> Result<(), String> {
    println!("xtask: [clippy] cargo {}", ARGS.join(" "));
    let out = Command::new("cargo")
        .args(ARGS)
        .current_dir(root)
        .output()
        .map_err(|e| format!("[clippy] could not start `cargo`: {e}"))?;
    let stderr = String::from_utf8_lossy(&out.stderr);
    print!("{}", String::from_utf8_lossy(&out.stdout));
    eprint!("{stderr}");
    if !out.status.success() {
        return Err(format!("[clippy] failed ({})", out.status));
    }
    let unresolved = unresolved_bans(&stderr);
    if unresolved.is_empty() {
        Ok(())
    } else {
        Err(format!(
            "[clippy] clippy.toml bans paths that resolve to nothing, so those bans are off:\n  {}",
            unresolved.join("\n  ")
        ))
    }
}

/// The warnings clippy printed for `clippy.toml` paths it could not resolve: for each note, the
/// nearest `warning:` line above it.
fn unresolved_bans(stderr: &str) -> Vec<String> {
    let lines: Vec<&str> = stderr.lines().collect();
    let mut found: Vec<String> = lines
        .iter()
        .enumerate()
        .filter(|(_, line)| line.contains(UNRESOLVED))
        .filter_map(|(i, _)| {
            lines
                .iter()
                .take(i)
                .rev()
                .find(|l| l.starts_with("warning:"))
                .map(|w| w.trim().to_owned())
        })
        .collect();
    found.sort_unstable();
    found.dedup();
    found
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
}
