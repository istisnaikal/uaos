// SPDX-License-Identifier: Apache-2.0

//! Gate self-tests: every active merge gate must be shown to **fail** on a seeded violation
//! (plan P0 acceptance, §4.2). A gate that has never been seen failing is not a gate.
//!
//! For each case the workspace is copied to `target/xtask-negative/<case>`, the gate command
//! is run once on the clean copy (it must pass: this proves the failure below is caused by
//! the seed, not by an unrelated break), the violation is applied, and the gate is run again
//! (it must fail, and its output must name the violation).

use std::path::{Path, PathBuf};
use std::process::Command;

use crate::util::{rel, walk_files, workspace_root};

/// How a gate is invoked.
enum Runner {
    /// An external program run in the copy.
    Program {
        program: &'static str,
        args: &'static [&'static str],
    },
    /// An xtask subcommand run in the copy (built into the shared target directory).
    Xtask(&'static [&'static str]),
    /// A git-history gate exercised in a scratch repository: `(clean, violating)` commits.
    History(
        fn(&Path, &str) -> Result<(), String>,
        fn(&Path) -> Result<(String, String), String>,
    ),
}

/// Applies a seeded violation to a workspace copy.
type Seed = Box<dyn Fn(&Path) -> Result<(), String>>;

pub(crate) struct Case {
    pub(crate) id: &'static str,
    pub(crate) gate: &'static str,
    tool: Option<&'static str>,
    seed: Seed,
    runner: Runner,
    expect: &'static str,
}

const CLIPPY: Runner = Runner::Program {
    program: "cargo",
    args: &[
        "clippy",
        "--workspace",
        "--all-targets",
        "--locked",
        "--",
        "-D",
        "warnings",
    ],
};
const LIB: &str = "crates/uaos-contracts/src/limits.rs";

fn append(path: &'static str, text: &'static str) -> Seed {
    Box::new(move |ws| {
        let p = ws.join(path);
        let mut s = std::fs::read_to_string(&p).map_err(|e| format!("{path}: {e}"))?;
        s.push_str(text);
        std::fs::write(&p, s).map_err(|e| format!("{path}: {e}"))
    })
}

/// Like [`append`], for text built at run time. Seeds that spell out a guarded attribute are
/// assembled from parts, so this file never contains the attribute `allow-audit` looks for.
fn append_owned(path: &'static str, text: String) -> Seed {
    Box::new(move |ws| {
        let p = ws.join(path);
        let mut s = std::fs::read_to_string(&p).map_err(|e| format!("{path}: {e}"))?;
        s.push_str(&text);
        std::fs::write(&p, s).map_err(|e| format!("{path}: {e}"))
    })
}

fn replace(path: &'static str, old: &'static str, new: &'static str) -> Seed {
    Box::new(move |ws| {
        let p = ws.join(path);
        let s = std::fs::read_to_string(&p).map_err(|e| format!("{path}: {e}"))?;
        // Exactly once: an anchor that also matches elsewhere would seed the first match, which
        // may not be the site the case is about, and the case would then prove nothing.
        match s.matches(old).count() {
            0 => {
                return Err(format!(
                    "seed anchor not found in {path} (update the negative case): {old:?}"
                ));
            }
            1 => {}
            n => {
                return Err(format!(
                    "seed anchor occurs {n} times in {path} (make it unique to its site): {old:?}"
                ));
            }
        }
        std::fs::write(&p, s.replacen(old, new, 1)).map_err(|e| format!("{path}: {e}"))
    })
}

fn write(path: &'static str, text: String) -> Seed {
    Box::new(move |ws| {
        let p = ws.join(path);
        if let Some(parent) = p.parent() {
            std::fs::create_dir_all(parent).map_err(|e| format!("{path}: {e}"))?;
        }
        std::fs::write(&p, &text).map_err(|e| format!("{path}: {e}"))
    })
}

fn both(a: Seed, b: Seed) -> Seed {
    Box::new(move |ws| {
        a(ws)?;
        b(ws)
    })
}

#[allow(
    clippy::too_many_lines,
    reason = "a flat table of cases reads better than indirection"
)]
pub(crate) fn cases() -> Vec<Case> {
    vec![
        Case {
            id: "fmt-unformatted",
            gate: "fmt",
            tool: None,
            seed: append(LIB, "\nconst   SEEDED_VIOLATION :u8=1;\n"),
            runner: Runner::Program { program: "cargo", args: &["fmt", "--all", "--", "--check"] },
            expect: "Diff in",
        },
        Case {
            id: "clippy-unwrap",
            gate: "clippy",
            tool: None,
            seed: append(LIB, "\n/// Seeded.\n#[must_use]\npub fn seeded_violation() -> u8 {\n    Some(1_u8).unwrap()\n}\n"),
            runner: CLIPPY,
            expect: "unwrap",
        },
        Case {
            id: "clippy-unsafe",
            gate: "clippy",
            tool: None,
            seed: append(LIB, "\n/// Seeded.\n#[must_use]\npub fn seeded_violation(p: &u8) -> u8 {\n    unsafe { *core::ptr::from_ref(p) }\n}\n"),
            runner: CLIPPY,
            expect: "unsafe",
        },
        Case {
            id: "clippy-ambient-clock",
            gate: "clippy",
            tool: None,
            seed: append(LIB, "\n/// Seeded.\n#[must_use]\npub fn seeded_violation() -> std::time::SystemTime {\n    std::time::SystemTime::now()\n}\n"),
            runner: CLIPPY,
            expect: "disallowed method",
        },
        Case {
            id: "clippy-nondeterministic-map",
            gate: "clippy",
            tool: None,
            seed: append(LIB, "\n/// Seeded.\n#[must_use]\npub fn seeded_violation() -> std::collections::HashMap<u8, u8> {\n    std::collections::HashMap::new()\n}\n"),
            runner: CLIPPY,
            expect: "disallowed type",
        },
        Case {
            id: "test-failure",
            gate: "test",
            tool: None,
            seed: append(LIB, "\n#[cfg(test)]\nmod seeded_violation {\n    #[test]\n    fn fails() {\n        assert_eq!(1 + 1, 3);\n    }\n}\n"),
            runner: Runner::Program { program: "cargo", args: &["test", "--workspace", "--locked"] },
            expect: "seeded_violation",
        },
        Case {
            id: "arch-forbidden-edge",
            gate: "arch-check",
            tool: None,
            seed: replace("arch.toml", "[crate.uaos-platform]\nring = 0\nallow = [\"uaos-contracts\"]", "[crate.uaos-platform]\nring = 0\nallow = []"),
            runner: Runner::Xtask(&["arch-check"]),
            expect: "edge not allowed",
        },
        Case {
            id: "arch-ring1-reaches-kernel",
            gate: "arch-check",
            tool: None,
            seed: both(
                replace("Cargo.toml", "members = [\"crates/*\", \"xtask\"]", "members = [\"crates/*\", \"modules/*\", \"xtask\"]"),
                both(
                write(
                    "modules/mod-seeded/Cargo.toml",
                    "# SPDX-License-Identifier: Apache-2.0\n[package]\nname = \"mod-seeded\"\nversion = \"0.0.0\"\nedition = \"2024\"\nlicense = \"Apache-2.0\"\npublish = false\n\n[dependencies]\nuaos-platform = { path = \"../../crates/uaos-platform\" }\n".to_owned(),
                ),
                write("modules/mod-seeded/src/lib.rs", "// SPDX-License-Identifier: Apache-2.0\n//! Seeded.\n".to_owned()),
                ),
            ),
            runner: Runner::Xtask(&["arch-check"]),
            expect: "Ring 1",
        },
        Case {
            id: "schema-breaking-change",
            gate: "schema-compat",
            tool: None,
            // A retyped reference. (The seed must still compile: `settled` is read by validation.)
            seed: replace(
                "crates/uaos-contracts/src/budget.rs",
                "    pub related_event: Option<EventId>,",
                "    pub related_event: Option<SessionId>,",
            ),
            runner: Runner::Xtask(&["schema-check"]),
            expect: "BREAKING",
        },
        Case {
            id: "schema-drift",
            gate: "schema-compat",
            tool: None,
            seed: replace(
                "crates/uaos-contracts/src/budget.rs",
                "    pub estimated: bool,\n}",
                "    pub estimated: bool,\n    /// Seeded.\n    #[serde(default, skip_serializing_if = \"Option::is_none\")]\n    pub seeded: Option<String>,\n}",
            ),
            runner: Runner::Xtask(&["schema-check"]),
            expect: "out of date",
        },
        Case {
            id: "spdx-header-missing",
            gate: "spdx-headers",
            tool: None,
            seed: replace("crates/uaos-platform/src/real.rs", "// SPDX-License-Identifier: Apache-2.0\n", ""),
            runner: Runner::Xtask(&["headers"]),
            expect: "SPDX header",
        },
        Case {
            id: "gate-registry-incomplete",
            gate: "gate-registry",
            tool: None,
            seed: replace("gates.toml", "id = \"secret-scan\"", "id = \"secret-scan-renamed\""),
            runner: Runner::Xtask(&["gates"]),
            expect: "missing required gate",
        },
        Case {
            // The README's public phase line drifts from the registry (plan v2 PD-08).
            id: "docs-phase-line-stale",
            gate: "gate-registry",
            tool: None,
            seed: replace("README.md", "## Status: P3 ", "## Status: P2 "),
            runner: Runner::Xtask(&["gates"]),
            expect: "phase line: README.md names `P2`",
        },
        Case {
            // A merge-lane job left out of the aggregated required check (ADR-0019 Amendment 1).
            id: "merge-gate-missing-job",
            gate: "gate-registry",
            tool: None,
            seed: replace(".github/workflows/ci.yml", ", paths, negative]", ", paths]"),
            runner: Runner::Xtask(&["gates"]),
            expect: "job `negative` is not in `merge-gate` needs",
        },
        Case {
            id: "secret-committed",
            gate: "secret-scan",
            tool: Some("gitleaks"),
            // Assembled at runtime so this source file never contains a scannable key.
            seed: write(
                "crates/uaos-contracts/src/seeded.txt",
                format!("aws_access_key_id = {}{}\n", "AKIA", "Q3VZ7XKL2M4N6P5R"),
            ),
            runner: Runner::Program { program: "gitleaks", args: &["dir", "--no-banner", "--redact", "."] },
            expect: "leaks found",
        },
        Case {
            id: "license-not-allowed",
            gate: "cargo-deny",
            tool: Some("cargo-deny"),
            seed: both(
                write(
                    "crates/seeded-gpl/Cargo.toml",
                    "# SPDX-License-Identifier: Apache-2.0\n[package]\nname = \"seeded-gpl\"\nversion = \"0.0.0\"\nedition = \"2024\"\nlicense = \"GPL-3.0-only\"\n".to_owned(),
                ),
                write("crates/seeded-gpl/src/lib.rs", "// SPDX-License-Identifier: Apache-2.0\n//! Seeded.\n".to_owned()),
            ),
            runner: Runner::Program { program: "cargo", args: &["deny", "check", "licenses"] },
            expect: "GPL-3.0",
        },
        Case {
            id: "unaudited-dependency",
            gate: "cargo-vet",
            tool: Some("cargo-vet"),
            seed: both(
                replace(
                    "crates/uaos-contracts/Cargo.toml",
                    "[dependencies]\n",
                    // A crate no imported auditor (Mozilla, Google, Bytecode Alliance, ISRG,
                    // Zcash) has reviewed; widely used crates like `hex` are already vetted.
                    "[dependencies]\nleft-pad = \"1.0.1\"\n",
                ),
                // cargo-vet reads metadata with --locked, so the lockfile must already include
                // the new crate; `cargo fetch` adds it minimally.
                Box::new(|ws| crate::util::capture(ws, "cargo", &["fetch"]).map(|_| ())),
            ),
            runner: Runner::Program { program: "cargo", args: &["vet"] },
            expect: "unvetted",
        },
        Case {
            id: "journal-ack-without-write",
            gate: "journal-durability",
            tool: None,
            // A journal that acknowledges a record without handing it to the OS.
            seed: replace(
                "crates/uaos-state/src/journal/writer.rs",
                "match self.active.append(&line) {",
                "match Ok::<(), FsError>(()) {",
            ),
            runner: Runner::Program { program: "cargo", args: &["test", "-p", "uaos-testkit", "--test", "kill"] },
            expect: "lost or changed",
        },
        Case {
            id: "chunk-flushed-before-sync",
            gate: "journal-durability",
            tool: None,
            // ADR-0018: a journal that declares records durable before their payloads are.
            seed: replace(
                "crates/uaos-state/src/journal/writer.rs",
                "        self.sync_payloads()?;\n        match self.active.sync_data() {\n            Ok(()) => {\n                self.mark_flushed();\n",
                "        match self.active.sync_data() {\n            Ok(()) => {\n                self.mark_flushed();\n                self.sync_payloads()?;\n",
            ),
            runner: Runner::Program {
                program: "cargo",
                args: &[
                    "test",
                    "-p",
                    "uaos-state",
                    "--test",
                    "durability",
                    "a_flushed_record_never_references_an_unreadable_payload",
                ],
            },
            expect: "lost its payload",
        },
        Case {
            id: "intent-before-chunk-write",
            gate: "journal-durability",
            tool: None,
            // I-02: a journal that acknowledges a record whose payload is not stored yet.
            seed: replace(
                "crates/uaos-state/src/journal/writer.rs",
                "if !store.is_stored(pocket, chunk).map_err(JournalError::Payload)? {",
                "if false && !store.is_stored(pocket, chunk).map_err(JournalError::Payload)? {",
            ),
            runner: Runner::Program {
                program: "cargo",
                args: &[
                    "test",
                    "-p",
                    "uaos-state",
                    "--test",
                    "durability",
                    "a_record_cannot_reference_a_chunk_that_is_not_stored",
                ],
            },
            expect: "payload before record",
        },
        Case {
            id: "chunk-put-pair-race",
            gate: "journal-durability",
            tool: None,
            // S-6: a chunk store that lets two writers of one chunk interleave.
            seed: replace(
                "crates/uaos-state/src/chunks/mod.rs",
                "while inflight.contains(&key) {",
                "while false && inflight.contains(&key) {",
            ),
            runner: Runner::Program {
                program: "cargo",
                args: &[
                    "test",
                    "-p",
                    "uaos-state",
                    "--test",
                    "durability",
                    "concurrent_puts_of_one_chunk_never_pair_data_with_the_wrong_key",
                ],
            },
            expect: "paired with the other's key",
        },
        Case {
            id: "chunk-put-shared-temp",
            gate: "journal-durability",
            tool: None,
            // S-6: atomic writes that share one temporary name per target.
            seed: replace(
                "crates/uaos-platform/src/fs.rs",
                "name.push(format!(\"{TEMP_MARKER}{}-{n}\", std::process::id()));",
                "name.push(format!(\"{TEMP_MARKER}{}-{}\", std::process::id(), n * 0));",
            ),
            runner: Runner::Program {
                program: "cargo",
                args: &["test", "-p", "uaos-platform", "--lib", "temp_names_are_unique"],
            },
            expect: "never share a temporary",
        },
        Case {
            id: "marker-before-loss-report",
            gate: "journal-durability",
            tool: None,
            // WP3.A1 H1: an open that makes the previous run's records durable and moves the
            // durable point before it journals the losses it found. Three defences stop it
            // (report first; no flush while a loss is unreported; the marker refuses to pass
            // one), so all three go.
            seed: both(
                replace(
                    "crates/uaos-state/src/journal/writer.rs",
                    "        self.report_lost()?;\n        self.sync()?;\n        self.store_manifest_if_unstored()?;\n",
                    "        self.sync()?;\n        self.store_manifest_if_unstored()?;\n        self.update_marker(true).map_err(storage)?;\n        self.report_lost()?;\n",
                ),
                both(
                    replace(
                        "crates/uaos-state/src/journal/writer.rs",
                        "        if !self.unreported.is_empty() || store_holds_back || self.manifest_unstored {",
                        "        let _ = store_holds_back;\n        if self.manifest_unstored {",
                    ),
                    replace(
                        "crates/uaos-state/src/journal/writer.rs",
                        "        if !self.unreported.is_empty() {
            return Err(self.unreported_error());
        }
        if self.unflushed.is_empty() {",
                        "        if self.unflushed.is_empty() {",
                    ),
                ),
            ),
            runner: Runner::Program {
                program: "cargo",
                args: &[
                    "test",
                    "-p",
                    "uaos-state",
                    "--test",
                    "durability",
                    "h1_open_reports_a_loss_before_its_marker_moves",
                ],
            },
            expect: "has an unreadable payload and no chunk.lost record",
        },
        Case {
            id: "open-stores-manifest-before-flush",
            gate: "journal-durability",
            tool: None,
            // WP3.A1 second round H1: an open that disowns the old copies before the new ones are durable.
            seed: replace(
                "crates/uaos-state/src/journal/writer.rs",
                "    file.append(tail).map_err(storage)?;\n    let lines",
                "    file.append(tail).map_err(storage)?;\n    manifest.store(fs, dir)?;\n    let lines",
            ),
            runner: Runner::Program {
                program: "cargo",
                args: &[
                    "test",
                    "-p",
                    "uaos-state",
                    "--test",
                    "durability",
                    "r2_h1_a_power_loss_during_open_keeps_what_the_previous_run_flushed",
                ],
            },
            expect: "vanished",
        },
        Case {
            id: "is-stored-trusts-earlier-pair",
            gate: "journal-durability",
            tool: None,
            // WP3.A1 second round M1: a store that vouches for an earlier process's pair without rewriting it.
            seed: replace(
                "crates/uaos-state/src/chunks/mod.rs",
                "                self.adopt(key, &content, Some(data_key), Flush::Now)?;\n                Ok(true)",
                "                drop((content, data_key));\n                self.remember(key);\n                Ok(true)",
            ),
            runner: Runner::Program {
                program: "cargo",
                args: &[
                    "test",
                    "-p",
                    "uaos-state",
                    "--test",
                    "durability",
                    "r2_m1_is_stored_rewrites_an_earlier_processs_unflushed_pair",
                ],
            },
            expect: "only an earlier process had written",
        },
        Case {
            id: "flush-skips-missing-pending-file",
            gate: "journal-durability",
            tool: None,
            // WP3.A1 second round M1: a flush that treats a vanished pending file as flushed.
            seed: replace(
                "crates/uaos-state/src/chunks/mod.rs",
                "                self.flushed(|| self.fs.sync_file(&path))?;",
                "                match self.fs.sync_file(&path) {\n                    Ok(()) | Err(FsError::NotFound { .. }) => {}\n                    Err(e) => return Err(storage(e)),\n                }",
            ),
            runner: Runner::Program {
                program: "cargo",
                args: &[
                    "test",
                    "-p",
                    "uaos-state",
                    "--test",
                    "durability",
                    "r2_m1_a_pending_file_removed_underneath_is_a_flush_failure",
                ],
            },
            expect: "pending payload's file was gone",
        },
        Case {
            id: "loss-set-aside-after-quarantine",
            gate: "journal-durability",
            tool: None,
            // WP3.A1 second round M1: recovery that remembers a loss only once its quarantine succeeded.
            seed: replace(
                "crates/uaos-state/src/chunks/mod.rs",
                "            // Set aside first: from here on the loss is remembered whatever fails next.\n            locked(&self.lost).push(LostChunk {\n                pocket: key.0,\n                chunk: key.1,\n                cause,\n            });\n            self.forget(key);\n            self.quarantine_pair(key.0, key.1)?;",
                "            self.forget(key);\n            self.quarantine_pair(key.0, key.1)?;\n            locked(&self.lost).push(LostChunk {\n                pocket: key.0,\n                chunk: key.1,\n                cause,\n            });",
            ),
            runner: Runner::Program {
                program: "cargo",
                args: &[
                    "test",
                    "-p",
                    "uaos-state",
                    "--test",
                    "durability",
                    "r2_m1_a_failed_quarantine_never_drops_a_loss",
                ],
            },
            expect: "dropped by the failed quarantine",
        },
        Case {
            id: "shred-not-completed-at-open",
            gate: "journal-durability",
            tool: None,
            // WP3.A1 second round: a journaled shred a crash interrupted, left readable.
            seed: replace(
                "crates/uaos-state/src/journal/writer.rs",
                "                if unrotated || store.pair_remains(pocket, chunk).map_err(JournalError::Payload)? {",
                "                if false && (unrotated || store.pair_remains(pocket, chunk).map_err(JournalError::Payload)?) {",
            ),
            runner: Runner::Program {
                program: "cargo",
                args: &[
                    "test",
                    "-p",
                    "uaos-state",
                    "--test",
                    "durability",
                    "a_shred_interrupted_after_its_record_is_completed_at_open",
                ],
            },
            expect: "is still readable",
        },
        Case {
            id: "shred-bypasses-journal",
            gate: "journal-durability",
            tool: None,
            // WP3.A1 third round H1: a coordinated store that shreds without its journal's record.
            seed: replace(
                "crates/uaos-state/src/chunks/mod.rs",
                "        if self.attached.load(Ordering::SeqCst) {\n            return Err(ChunkError::ShredThroughJournal);",
                "        if false && self.attached.load(Ordering::SeqCst) {\n            return Err(ChunkError::ShredThroughJournal);",
            ),
            runner: Runner::Program {
                program: "cargo",
                args: &["test", "-p", "uaos-state", "--test", "durability", "r3_h1_after_a_shred_a_record_needs_its_content_stored_again"],
            },
            expect: "a coordinated store shredded without its journal",
        },
        Case {
            id: "shreds-before-manifest-at-open",
            gate: "journal-durability",
            tool: None,
            // WP3.A1 third round M2: an open that completes shreds before the manifest naming
            // their records is durable.
            seed: both(
                replace(
                    "crates/uaos-state/src/journal/writer.rs",
                    "        self.sync()?;\n        self.store_manifest_if_unstored()?;\n",
                    "        self.sync()?;\n",
                ),
                replace(
                    "crates/uaos-state/src/journal/writer.rs",
                    "        self.update_marker(true).map_err(storage)?;\n        Ok(())\n    }",
                    "        self.store_manifest_if_unstored()?;\n        self.update_marker(true).map_err(storage)?;\n        Ok(())\n    }",
                ),
            ),
            runner: Runner::Program {
                program: "cargo",
                args: &["test", "-p", "uaos-state", "--test", "durability", "r3_m2_shreds_at_open_wait_for_the_manifest"],
            },
            expect: "r3 m2: record",
        },
        Case {
            id: "plain-marker-trusted",
            gate: "journal-durability",
            tool: None,
            // WP3.A1 fourth round M1: the first open with a store trusts a plain journal's marker.
            seed: replace(
                "crates/uaos-state/src/journal/writer.rs",
                "fs.write_atomic(&dir.join(FLUSH_MARKER), none.as_bytes())",
                "Ok::<(), FsError>(drop(none))",
            ),
            runner: Runner::Program {
                program: "cargo",
                args: &["test", "-p", "uaos-state", "--test", "durability", "r4_m1_a_plain_journals_marker_does_not_skip_the_payload_check"],
            },
            expect: "trusted a plain journal's marker",
        },
        Case {
            id: "put-overlapping-failed-flush",
            gate: "journal-durability",
            tool: None,
            // WP3.A1 fourth round L1: a put whose write overlapped a failed directory flush is
            // acknowledged after a recovery that missed it.
            seed: replace(
                "crates/uaos-state/src/chunks/mod.rs",
                "            if self.poison.load(Ordering::SeqCst) != started {",
                "            if false && self.poison.load(Ordering::SeqCst) != started {",
            ),
            runner: Runner::Program {
                program: "cargo",
                args: &["test", "-p", "uaos-state", "--test", "durability", "r4_l1_a_put_spanning_a_failed_directory_flush_is_recovered_with_it"],
            },
            expect: "acknowledged after recovery missed it",
        },
        Case {
            id: "failed-shred-vouched",
            gate: "journal-durability",
            tool: None,
            // WP3.A1 fourth round L2: after a shred fails midway, the store vouches for the content
            // from disk, so a later record cancels the journaled shred.
            seed: replace(
                "crates/uaos-state/src/chunks/mod.rs",
                "        if locked(&self.shredding).contains(&key) {\n            return Ok(false);",
                "        if false && locked(&self.shredding).contains(&key) {\n            return Ok(false);",
            ),
            runner: Runner::Program {
                program: "cargo",
                args: &["test", "-p", "uaos-state", "--test", "durability", "r4_l2_a_failed_shred_never_vouches_for_its_content"],
            },
            expect: "a record referenced content whose shred is recorded",
        },
        Case {
            id: "flush-acked-across-poisoning",
            gate: "journal-durability",
            tool: None,
            // WP3.A1 fifth round M2: a journal flush acknowledged although a flushed write elsewhere
            // failed while it ran and may have dropped the batch's directory entries.
            seed: replace(
                "crates/uaos-state/src/chunks/mod.rs",
                "        drop(self.flush_window.write().unwrap_or_else(PoisonError::into_inner));\n        if self.poison.load(Ordering::SeqCst) != started {",
                "        drop(self.flush_window.write().unwrap_or_else(PoisonError::into_inner));\n        if false && self.poison.load(Ordering::SeqCst) != started {",
            ),
            runner: Runner::Program {
                program: "cargo",
                args: &["test", "-p", "uaos-state", "--test", "durability", "r5_m2_a_flush_is_not_acknowledged_across_a_failed_rewrap"],
            },
            expect: "acknowledged across a failed flush",
        },
        Case {
            id: "shred-marked-after-record",
            gate: "journal-durability",
            tool: None,
            // WP3.A1 fifth round L1: a shred whose own flush fails leaves its chunk unmarked, so
            // once the record is durable a later record cancels the shred.
            // Since the sixth round a failed flush also marks the chunk again, so the seed removes
            // both marks.
            seed: both(
                replace(
                    "crates/uaos-state/src/journal/writer.rs",
                    "        let marked = store.begin_shred(pocket, chunk).map_err(JournalError::Payload)?;\n",
                    "        let marked = false;\n",
                ),
                replace(
                    "crates/uaos-state/src/journal/writer.rs",
                    "(sixth round, L2).\n            store.keep_refused(pocket, chunk);\n",
                    "(sixth round, L2).\n",
                ),
            ),
            runner: Runner::Program {
                program: "cargo",
                args: &["test", "-p", "uaos-state", "--test", "durability", "r5_l1_a_shred_whose_flush_failed_stays_refused"],
            },
            expect: "whose shred record is durable",
        },
        Case {
            id: "failed-put-lifts-shred-mark",
            gate: "journal-durability",
            tool: None,
            // WP3.A1 fifth round L1: a put lifts a failed shred's mark before its own write fails.
            seed: both(
                replace(
                    "crates/uaos-state/src/chunks/mod.rs",
                    "        self.stored_again(key);\n        Ok(chunk)\n    }",
                    "        Ok(chunk)\n    }",
                ),
                replace(
                    "crates/uaos-state/src/chunks/mod.rs",
                    "        self.check_poison()?;\n        if locked(&self.known).contains(&key) {\n            // Written by this process",
                    "        self.check_poison()?;\n        self.stored_again(key);\n        if locked(&self.known).contains(&key) {\n            // Written by this process",
                ),
            ),
            runner: Runner::Program {
                program: "cargo",
                args: &["test", "-p", "uaos-state", "--test", "durability", "r5_l1_a_failed_put_keeps_a_failed_shred_refused"],
            },
            expect: "a failed put lifted the refusal",
        },
        Case {
            id: "rotation-skips-current-key",
            gate: "journal-durability",
            tool: None,
            // Found by the fifth WP3.A1 round's crash schedules: a re-wrap that skips a key file
            // already at the current version retires the KEK the durable copy still needs.
            seed: both(
                replace(
                    "crates/uaos-state/src/chunks/mod.rs",
                    "                Ok((data_key, _)) => {\n                    self.write_key(pocket, chunk, &data_key, current, &kek, Flush::Now)?;",
                    "                Ok((data_key, version)) if version < current => {\n                    self.write_key(pocket, chunk, &data_key, current, &kek, Flush::Now)?;",
                ),
                replace(
                    "crates/uaos-state/src/chunks/mod.rs",
                    "                Err(ChunkError::Unavailable | ChunkError::Corrupt) => {}\n                Err(e) => return Err(e),",
                    "                Ok(_) | Err(ChunkError::Unavailable | ChunkError::Corrupt) => {}\n                Err(e) => return Err(e),",
                ),
            ),
            runner: Runner::Program {
                program: "cargo",
                args: &["test", "-p", "uaos-state", "--test", "durability", "r5_a_failed_rewrap_never_leaves_a_key_only_a_retired_kek_opens"],
            },
            expect: "retired a KEK a durable key file still needed",
        },
        Case {
            id: "store-flush-poisons-outside-window",
            gate: "journal-durability",
            tool: None,
            // WP3.A1 sixth round L1: a store flush whose own directory flush fails poisons after
            // the window, so a concurrent journal flush acknowledges its batch in between.
            seed: replace(
                "crates/uaos-state/src/chunks/mod.rs",
                "            self.flushed(|| self.fs.sync_dir(&self.data_dir(pocket)))?;",
                "            self.fs.sync_dir(&self.data_dir(pocket)).map_err(storage)?;",
            ),
            runner: Runner::Program {
                program: "cargo",
                args: &["test", "-p", "uaos-state", "--test", "durability", "r6_l1_a_failed_direct_store_flush_is_seen_by_a_concurrent_journal_flush"],
            },
            expect: "acknowledged across a failed flush",
        },
        Case {
            id: "shred-mark-not-restored",
            gate: "journal-durability",
            tool: None,
            // WP3.A1 sixth round L2: a put during a shred lifts the mark, and a failed flush of
            // the shred record does not restore it.
            seed: replace(
                "crates/uaos-state/src/journal/writer.rs",
                "(sixth round, L2).\n            store.keep_refused(pocket, chunk);\n",
                "(sixth round, L2).\n",
            ),
            runner: Runner::Program {
                program: "cargo",
                args: &["test", "-p", "uaos-state", "--test", "durability", "r6_l2_a_put_during_a_shred_whose_flush_fails_does_not_lift_the_refusal"],
            },
            expect: "whose shred record is durable",
        },
        Case {
            id: "shred-unmarked-after-written-record",
            gate: "journal-durability",
            tool: None,
            // WP3.A1 seventh round M1: a shred whose record was written, and whose flush inside
            // `append` failed, lifts its mark as if no record existed.
            seed: replace(
                "crates/uaos-state/src/journal/writer.rs",
                "            if self.next_seq > before {\n                // The record was written and only the flush inside `append` failed",
                "            if false && self.next_seq > before {\n                // The record was written and only the flush inside `append` failed",
            ),
            runner: Runner::Program {
                program: "cargo",
                args: &["test", "-p", "uaos-state", "--test", "durability", "r7_m1_a_shred_whose_flush_inside_append_fails_stays_refused"],
            },
            expect: "whose shred record is durable",
        },
        Case {
            id: "kernel-record-appended-directly",
            gate: "journal-durability",
            tool: None,
            // WP3.A1 ninth round L1: `append` takes a caller's chunk.shredded or chunk.lost on a
            // coordinated journal.
            seed: replace(
                "crates/uaos-state/src/journal/writer.rs",
                "        if origin == Origin::Caller\n            && self.payloads.is_some()",
                "        if origin == Origin::Caller\n            && self.payloads.is_none()",
            ),
            runner: Runner::Program {
                program: "cargo",
                args: &["test", "-p", "uaos-state", "--test", "durability", "r9_l1_kernel_records_cannot_be_appended_directly"],
            },
            expect: "a chunk.shredded record was appended directly",
        },
        Case {
            id: "store-losses-taken-by-caller",
            gate: "journal-durability",
            tool: None,
            // WP3.A1 tenth round L1: a coordinated store lets a caller recover it or take its
            // losses, so the journal never reports them.
            seed: replace(
                "crates/uaos-state/src/chunks/mod.rs",
                "        if self.attached.load(Ordering::SeqCst) {\n            return Err(ChunkError::LossesThroughJournal);",
                "        if false && self.attached.load(Ordering::SeqCst) {\n            return Err(ChunkError::LossesThroughJournal);",
            ),
            runner: Runner::Program {
                program: "cargo",
                args: &["test", "-p", "uaos-state", "--test", "durability", "r10_l1_a_coordinated_stores_losses_go_through_its_journal"],
            },
            expect: "a caller recovered a coordinated store",
        },
        Case {
            id: "recovery-leaves-store-poisoned",
            gate: "journal-durability",
            tool: None,
            // Found by the tenth WP3.A1 round's stronger schedules: `recover` treats a poisoned
            // store only while the writer is healthy.
            seed: replace(
                "crates/uaos-state/src/journal/writer.rs",
                "            && (self.health == JournalHealth::PayloadFlushFailed || store.is_poisoned() || store.has_untaken_losses())",
                "            && (self.health == JournalHealth::PayloadFlushFailed\n                || (self.health == JournalHealth::Healthy && store.is_poisoned())\n                || store.has_untaken_losses())",
            ),
            runner: Runner::Program {
                program: "cargo",
                args: &["test", "-p", "uaos-state", "--test", "durability", "r10_a_recovery_out_of_space_also_recovers_a_poisoned_store"],
            },
            expect: "the store stayed poisoned after an Ok recovery",
        },
        Case {
            id: "shred-incomplete-key-only",
            gate: "journal-durability",
            tool: None,
            // WP3.A1 third round L3: an open that judges a shred finished once its key file is gone.
            seed: both(
                replace(
                    "crates/uaos-state/src/chunks/mod.rs",
                    "        for path in [self.key_path(pocket, chunk), self.chunk_path(pocket, chunk)] {\n            match self.fs.read(&path) {",
                    "        for path in [self.key_path(pocket, chunk)] {\n            match self.fs.read(&path) {",
                ),
                replace(
                    "crates/uaos-state/src/chunks/mod.rs",
                    "        Ok(self.keys.kek_versions(pocket).map_err(ChunkError::Keyring)?.len() > 1)",
                    "        Ok(false)",
                ),
            ),
            runner: Runner::Program {
                program: "cargo",
                args: &["test", "-p", "uaos-state", "--test", "durability", "r3_l3_a_shred_failing_midway_at_open_is_finished_by_the_next"],
            },
            expect: "a retried open left a shred unfinished",
        },
        Case {
            id: "store-flush-failure-forgotten",
            gate: "journal-durability",
            tool: None,
            // WP3.A1 H3: a chunk store that forgets a failed flush and vouches for its chunks again.
            seed: replace(
                "crates/uaos-state/src/chunks/mod.rs",
                "        if self.is_poisoned() {\n            Err(ChunkError::FlushFailed)",
                "        if false && self.is_poisoned() {\n            Err(ChunkError::FlushFailed)",
            ),
            runner: Runner::Program {
                program: "cargo",
                args: &[
                    "test",
                    "-p",
                    "uaos-state",
                    "--test",
                    "durability",
                    "h3_a_store_flush_failure_stops_the_journal",
                ],
            },
            expect: "saw the store's failure",
        },
        Case {
            id: "recovery-reflushes-same-file",
            gate: "journal-durability",
            tool: None,
            // WP3.A1 H4: recovery that flushes the file whose flush failed instead of rewriting it.
            seed: replace(
                "crates/uaos-state/src/chunks/mod.rs",
                "                Probe::Readable { content, data_key } => {\n                    self.write_pair(key.0, key.1, &content, Some(data_key), Flush::Now)?;\n                    locked(&self.pending).remove(&key);\n                    continue;",
                "                Probe::Readable { .. } => {\n                    for path in [self.chunk_path(key.0, key.1), self.key_path(key.0, key.1)] {\n                        self.fs.sync_file(&path).map_err(storage)?;\n                    }\n                    locked(&self.pending).remove(&key);\n                    continue;",
            ),
            runner: Runner::Program {
                program: "cargo",
                args: &[
                    "test",
                    "-p",
                    "uaos-state",
                    "--test",
                    "durability",
                    "h4_recovery_rewrites_content_instead_of_reflushing_the_failed_file",
                ],
            },
            expect: "re-flushed in place",
        },
        Case {
            id: "chunk-rewrite-unflushed",
            gate: "journal-durability",
            tool: None,
            // WP3.A1 N1: a chunk from an earlier process replaced by a write that is not flushed.
            seed: replace(
                "crates/uaos-state/src/chunks/mod.rs",
                "Probe::Readable { data_key, .. } => self.adopt(key, content, Some(data_key), Flush::Now)?",
                "Probe::Readable { data_key, .. } => self.adopt(key, content, Some(data_key), self.flush_mode())?",
            ),
            runner: Runner::Program {
                program: "cargo",
                args: &[
                    "test",
                    "-p",
                    "uaos-state",
                    "--test",
                    "durability",
                    "n1_a_rewrite_of_a_chunk_from_an_earlier_process_is_flushed",
                ],
            },
            expect: "replaced by an unflushed copy",
        },
        Case {
            id: "chunk-rewrite-new-data-key",
            gate: "journal-durability",
            tool: None,
            // WP3.A1 N2: a rewrite under a fresh data key, so a failure between its two files breaks the pair.
            seed: replace(
                "crates/uaos-state/src/chunks/mod.rs",
                "            Some(k) => k,\n            None => SecretKey::generate",
                "            Some(_) | None => SecretKey::generate",
            ),
            runner: Runner::Program {
                program: "cargo",
                args: &[
                    "test",
                    "-p",
                    "uaos-state",
                    "--test",
                    "durability",
                    "n2_a_rewrite_that_fails_between_its_two_files_leaves_a_readable_pair",
                ],
            },
            expect: "never written",
        },
        Case {
            id: "loss-flushed-before-report",
            gate: "journal-durability",
            tool: None,
            // WP3.A1 N3: a flush while a found loss waits to be journaled.
            seed: replace(
                "crates/uaos-state/src/journal/writer.rs",
                "        if !self.unreported.is_empty() {\n            return Err(self.unreported_error());\n        }\n",
                "",
            ),
            runner: Runner::Program {
                program: "cargo",
                args: &[
                    "test",
                    "-p",
                    "uaos-state",
                    "--test",
                    "durability",
                    "n3_a_loss_waiting_to_be_journaled_holds_back_every_flush",
                ],
            },
            expect: "while a loss waited to be journaled",
        },
        Case {
            id: "open-trusts-previous-segment",
            gate: "journal-durability",
            tool: None,
            // WP3.A1 N4: an open that seals the previous run's segment in place instead of copying it.
            seed: replace(
                "crates/uaos-state/src/journal/writer.rs",
                "    if proven_end == end {\n",
                "    if true {\n",
            ),
            runner: Runner::Program {
                program: "cargo",
                args: &[
                    "test",
                    "-p",
                    "uaos-state",
                    "--test",
                    "durability",
                    "n4_open_copies_the_previous_runs_records_instead_of_flushing_their_file_again",
                ],
            },
            expect: "cache kept:",
        },
        Case {
            id: "ledger-reserve-beyond-available",
            gate: "budget-concurrency",
            tool: None,
            // A ledger that accepts any reservation while the pool is not already in debt. The cap
            // is enforced twice (ledger state and the contract's per-entry rule), so both go.
            seed: both(
                replace(
                    "crates/uaos-ledger/src/state.rs",
                    "if usable < amount {",
                    "if usable < NanoUsd::ZERO {",
                ),
                replace(
                    "crates/uaos-contracts/src/budget.rs",
                    "if matches!(self.kind, K::Reserve | K::TransferOut) && self.balance_after.is_negative() {",
                    "if matches!(self.kind, K::Reserve | K::TransferOut) && self.balance_after < NanoUsd::new(i64::MIN) {",
                ),
            ),
            runner: Runner::Program { program: "cargo", args: &["test", "-p", "uaos-ledger", "--test", "ledger"] },
            expect: "hard cap breached",
        },
        Case {
            id: "redact-detector-drops-a-format",
            gate: "redaction-corpus",
            tool: None,
            // A detector set that no longer recognises one AWS key prefix.
            seed: replace(
                "crates/uaos-redact/src/detect.rs",
                "        anchor(\"ASIA\", C::AwsAccessKeyId, true, AWS),\n",
                "",
            ),
            runner: Runner::Program { program: "cargo", args: &["test", "-p", "uaos-redact", "--test", "corpus"] },
            expect: "recall below",
        },
        Case {
            id: "redact-url-password-stops-at-slash",
            gate: "redaction-corpus",
            tool: None,
            // Review WP2.3 H2, one byte wide: a URL password ends at its first `/` again.
            seed: replace(
                "crates/uaos-redact/src/detect.rs",
                r#"matches!(b, b'"' | b'<' | b'>' | b'`')"#,
                r#"matches!(b, b'"' | b'<' | b'>' | b'`' | b'/')"#,
            ),
            runner: Runner::Program { program: "cargo", args: &["test", "-p", "uaos-redact", "--test", "corpus"] },
            expect: "recall below",
        },
        Case {
            id: "policy-slicing-drops-unconstrained",
            gate: "policy-semantics",
            tool: None,
            // Review WP2.1 H1: slicing that loses action-unconstrained policies, so a forbid
            // without an action constraint stops applying.
            seed: replace(
                "crates/uaos-policy/src/engine.rs",
                "ActionConstraint::Any => true,",
                "ActionConstraint::Any => false,",
            ),
            runner: Runner::Program { program: "cargo", args: &["test", "-p", "uaos-policy", "--test", "policy"] },
            expect: "unconstrained forbid skipped",
        },
        Case {
            id: "policy-error-fails-open",
            gate: "policy-semantics",
            tool: None,
            // Review WP2.1 M1: an engine that, like plain Cedar, skips an erroring policy.
            seed: replace(
                "crates/uaos-policy/src/engine.rs",
                "if !errors.is_empty() {",
                "if errors.is_empty() && !errors.is_empty() {",
            ),
            runner: Runner::Program { program: "cargo", args: &["test", "-p", "uaos-policy", "--test", "policy"] },
            expect: "an erroring policy failed open",
        },
        Case {
            id: "policy-grant-overrides-forbid",
            gate: "policy-semantics",
            tool: None,
            // ADR-0008 Amendment 1: a grant is an approval and must never beat a forbid.
            seed: replace(
                "crates/uaos-policy/src/engine.rs",
                "CedarDecision::Deny if !matched.is_empty() =>",
                "CedarDecision::Deny if !matched.is_empty() && grants.is_empty() =>",
            ),
            runner: Runner::Program { program: "cargo", args: &["test", "-p", "uaos-policy", "--test", "policy"] },
            expect: "a grant must never override a forbid",
        },
        Case {
            id: "dco-missing-signoff",
            gate: "dco",
            tool: Some("git"),
            seed: Box::new(|_| Ok(())),
            runner: Runner::History(crate::dco::check, dco_history),
            expect: "lack a matching DCO",
        },
        Case {
            id: "dco-unsigned-content-merge",
            gate: "dco",
            tool: Some("git"),
            seed: Box::new(|_| Ok(())),
            // Clean: an unsigned conflict-free merge (exempt). Violating: an unsigned merge
            // that resolves a conflict with new content.
            runner: Runner::History(crate::dco::check, dco_merge_history),
            expect: "lack a matching DCO",
        },
        Case {

            id: "allow-audit-guarded-lint-outside-owner",
            gate: "allow-audit",
            tool: None,
            // An ambient-clock ban switched off in a crate that does not own the clock.
            seed: append_owned(
                LIB,
                format!(
                    "
/// Seeded.
#[{}({}, reason = \"seeded\")]
#[must_use]
pub fn seeded_violation() -> u8 {{
    1
}}
",
                    "allow", "clippy::disallowed_methods"
                ),
            ),
            runner: Runner::Xtask(&["allow-audit"]),
            expect: "outside its owners",
        },
        Case {
            id: "allow-audit-unsafe-outside-owner",
            gate: "allow-audit",
            tool: None,
            // `unsafe_code` re-enabled for one item outside any owner path. The workspace only
            // denies it, so a local allow would compile; uaos-contracts forbids it outright.
            seed: append_owned(
                "crates/uaos-ledger/src/lib.rs",
                format!(
                    "
/// Seeded.
#[{}({})]
#[must_use]
pub fn seeded_violation() -> u8 {{
    1
}}
",
                    "allow", "unsafe_code"
                ),
            ),
            runner: Runner::Xtask(&["allow-audit"]),
            expect: "outside its owners",
        },
        Case {
            id: "vet-ratchet-unnoted-exemption",
            gate: "vet-ratchet",
            tool: None,
            // A new exemption without a `notes` reason.
            seed: append(
                "supply-chain/config.toml",
                "
[[exemptions.seeded-unaudited-crate]]
version = \"1.0.0\"
criteria = \"safe-to-deploy\"
",
            ),
            runner: Runner::Xtask(&["vet-ratchet"]),
            expect: "without notes",
        },
        Case {
            id: "claims-forbidden-word",
            gate: "claims-lint",
            tool: None,
            seed: append("README.md", "
The journal is tamper-proof.
"),
            runner: Runner::Xtask(&["claims"]),
            expect: "used as a claim",
        },
        Case {
            id: "identity-epoch-check-skipped",
            gate: "test",
            tool: None,
            // Verification that ignores an ancestor's epoch bump (ADR-0011 §6).
            seed: replace(
                "crates/uaos-identity/src/state.rs",
                "if node.record.parent_epoch != parent.epoch {",
                "if node.record.parent_epoch != parent.epoch && node.revoked {",
            ),
            runner: Runner::Program {
                program: "cargo",
                args: &["test", "-p", "uaos-identity", "--test", "identity", "derivations_match_the_model"],
            },
            expect: "verification disagrees with the model",
        },
        Case {
            id: "contract-without-changelog",
            gate: "docs-contract-sync",
            tool: Some("git"),
            seed: Box::new(|_| Ok(())),
            runner: Runner::History(crate::docs_sync::check, docs_sync_history),
            expect: "CHANGELOG",
        },
    ]
}

/// Outcome of one case.
enum Outcome {
    Proven,
    Skipped(String),
    Broken(String),
}

pub(crate) fn run(args: &[String]) -> Result<(), String> {
    let require_all = args.iter().any(|a| a == "--require-all-tools");
    let selected: Vec<&String> = args.iter().filter(|a| !a.starts_with("--")).collect();
    let root = workspace_root();
    let base = root.join("target").join("xtask-negative");
    let shared_target = base.join("target");

    let mut failures = Vec::new();
    let mut skipped = Vec::new();
    for case in cases() {
        if !selected.is_empty() && !selected.iter().any(|s| s.as_str() == case.id) {
            continue;
        }
        let outcome = run_case(&case, &root, &base, &shared_target);
        match outcome {
            Outcome::Proven => println!(
                "  PROVEN   {:<30} gate `{}` fails on its seeded violation",
                case.id, case.gate
            ),
            Outcome::Skipped(why) => {
                println!("  SKIPPED  {:<30} {why}", case.id);
                skipped.push(case.id);
            }
            Outcome::Broken(why) => {
                println!("  BROKEN   {:<30} {why}", case.id);
                failures.push(format!("{}: {why}", case.id));
            }
        }
    }
    if require_all && !skipped.is_empty() {
        failures.push(format!("skipped with --require-all-tools: {}", skipped.join(", ")));
    }
    if failures.is_empty() {
        println!(
            "xtask negative: every exercised gate bites ({} skipped for missing tools)",
            skipped.len()
        );
        Ok(())
    } else {
        Err(format!("gate self-test failed:\n  {}", failures.join("\n  ")))
    }
}

fn run_case(case: &Case, root: &Path, base: &Path, shared_target: &Path) -> Outcome {
    if let Some(tool) = case.tool
        && !tool_available(tool)
    {
        return Outcome::Skipped(format!("`{tool}` not installed"));
    }
    if let Runner::History(gate, make_history) = &case.runner {
        let repo = base.join(case.id);
        return match history_case(&repo, *gate, *make_history, case.expect) {
            Ok(()) => Outcome::Proven,
            Err(e) => Outcome::Broken(e),
        };
    }
    let ws = base.join(case.id);
    let attempt = || -> Result<(), String> {
        copy_workspace(root, &ws)?;
        let (clean_ok, clean_out) = invoke(&case.runner, &ws, shared_target)?;
        if !clean_ok {
            return Err(format!(
                "gate fails on the CLEAN copy, so the seeded failure proves nothing:\n{}",
                tail(&clean_out)
            ));
        }
        (case.seed)(&ws)?;
        let (seeded_ok, seeded_out) = invoke(&case.runner, &ws, shared_target)?;
        if seeded_ok {
            return Err("gate PASSED on the seeded violation — it does not bite".to_owned());
        }
        if !seeded_out.contains(case.expect) {
            return Err(format!(
                "gate failed, but its output does not mention `{}` — it may have failed for another reason:\n{}",
                case.expect,
                tail(&seeded_out)
            ));
        }
        Ok(())
    };
    match attempt() {
        Ok(()) => Outcome::Proven,
        Err(e) => Outcome::Broken(e),
    }
}

fn invoke(runner: &Runner, ws: &Path, shared_target: &Path) -> Result<(bool, String), String> {
    let mut cmd = match runner {
        Runner::Program { program, args } => {
            let mut c = Command::new(program);
            c.args(*args);
            c
        }
        Runner::Xtask(args) => {
            let mut c = Command::new("cargo");
            c.args(["run", "--quiet", "-p", "xtask", "--"]).args(*args);
            c
        }
        Runner::History(..) => return Err("history cases are not invoked in a workspace copy".to_owned()),
    };
    let out = cmd
        .current_dir(ws)
        .env("CARGO_TARGET_DIR", shared_target)
        .output()
        .map_err(|e| format!("could not start gate: {e}"))?;
    let mut text = String::from_utf8_lossy(&out.stdout).into_owned();
    text.push_str(&String::from_utf8_lossy(&out.stderr));
    Ok((out.status.success(), text))
}

fn tail(s: &str) -> String {
    let lines: Vec<&str> = s.lines().collect();
    lines[lines.len().saturating_sub(25)..].join("\n")
}

fn tool_available(tool: &str) -> bool {
    let (program, args): (&str, &[&str]) = match tool {
        "cargo-deny" => ("cargo", &["deny", "--version"]),
        "cargo-vet" => ("cargo", &["vet", "--version"]),
        other => (other, &["--version"]),
    };
    Command::new(program)
        .args(args)
        .output()
        .is_ok_and(|o| o.status.success())
}

fn copy_workspace(root: &Path, dest: &Path) -> Result<(), String> {
    if dest.exists() {
        std::fs::remove_dir_all(dest).map_err(|e| format!("clean {}: {e}", dest.display()))?;
    }
    for file in walk_files(root)? {
        let relative = rel(root, &file);
        let target: PathBuf = dest.join(&relative);
        if let Some(parent) = target.parent() {
            std::fs::create_dir_all(parent).map_err(|e| format!("{}: {e}", parent.display()))?;
        }
        std::fs::copy(&file, &target).map_err(|e| format!("copy {relative}: {e}"))?;
        // Copies keep the source's modification time on some platforms (Windows CopyFile).
        // Cargo would then consider the copy unchanged and reuse artifacts built from a
        // previous, seeded copy in the shared target directory. Stamp every file as new.
        std::fs::File::options()
            .write(true)
            .open(&target)
            .and_then(|f| f.set_modified(std::time::SystemTime::now()))
            .map_err(|e| format!("touch {relative}: {e}"))?;
    }
    Ok(())
}

fn git(repo: &Path, args: &[&str]) -> Result<String, String> {
    crate::util::capture(repo, "git", args).map(|s| s.trim().to_owned())
}

fn scratch_repo(repo: &Path) -> Result<(), String> {
    if repo.exists() {
        std::fs::remove_dir_all(repo).map_err(|e| format!("clean {}: {e}", repo.display()))?;
    }
    std::fs::create_dir_all(repo).map_err(|e| format!("{}: {e}", repo.display()))?;
    git(repo, &["init", "-q"])?;
    git(repo, &["config", "user.name", "Gate Selftest"])?;
    git(repo, &["config", "user.email", "selftest@invalid.example"])?;
    git(repo, &["commit", "-q", "--allow-empty", "-s", "-m", "root"])?;
    Ok(())
}

/// Returns `(clean_range, violating_range)`.
fn dco_history(repo: &Path) -> Result<(String, String), String> {
    scratch_repo(repo)?;
    git(repo, &["commit", "-q", "--allow-empty", "-s", "-m", "signed"])?;
    git(repo, &["commit", "-q", "--allow-empty", "-m", "unsigned"])?;
    Ok(("HEAD~2..HEAD~1".to_owned(), "HEAD~1..HEAD".to_owned()))
}

/// Returns `(clean_range, violating_range)`, each spanning one unsigned merge and the signed
/// commit it brings in: first a content-free merge, then one that resolves a conflict.
fn dco_merge_history(repo: &Path) -> Result<(String, String), String> {
    scratch_repo(repo)?;
    let write = |file: &str, text: &str| std::fs::write(repo.join(file), text).map_err(|e| e.to_string());
    let trunk = git(repo, &["rev-parse", "--abbrev-ref", "HEAD"])?;
    write("a.txt", "base\n")?;
    git(repo, &["add", "-A"])?;
    git(repo, &["commit", "-q", "-s", "-m", "base"])?;

    git(repo, &["checkout", "-q", "-b", "side"])?;
    write("a.txt", "side\n")?;
    git(repo, &["commit", "-q", "-s", "-am", "side"])?;
    git(repo, &["checkout", "-q", &trunk])?;
    write("b.txt", "trunk\n")?;
    git(repo, &["add", "-A"])?;
    git(repo, &["commit", "-q", "-s", "-m", "trunk"])?;
    git(repo, &["merge", "-q", "--no-ff", "--no-edit", "side"])?;
    let content_free = git(repo, &["rev-parse", "HEAD"])?;

    git(repo, &["checkout", "-q", "-b", "side2"])?;
    write("a.txt", "side2\n")?;
    git(repo, &["commit", "-q", "-s", "-am", "side2"])?;
    git(repo, &["checkout", "-q", &trunk])?;
    write("a.txt", "trunk2\n")?;
    git(repo, &["commit", "-q", "-s", "-am", "trunk2"])?;
    if git(repo, &["merge", "-q", "--no-edit", "side2"]).is_ok() {
        return Err("expected a merge conflict in the seeded history".to_owned());
    }
    write("a.txt", "resolved by hand\n")?;
    git(repo, &["add", "a.txt"])?;
    git(repo, &["commit", "-q", "--no-edit"])?;
    let resolved = git(repo, &["rev-parse", "HEAD"])?;

    Ok((
        format!("{content_free}^1..{content_free}"),
        format!("{resolved}^1..{resolved}"),
    ))
}

fn docs_sync_history(repo: &Path) -> Result<(String, String), String> {
    scratch_repo(repo)?;
    let schemas = repo.join("schemas");
    std::fs::create_dir_all(&schemas).map_err(|e| e.to_string())?;
    std::fs::write(schemas.join("event.v1.json"), "{}\n").map_err(|e| e.to_string())?;
    std::fs::write(repo.join("CHANGELOG.md"), "# Changelog\n- event v1\n").map_err(|e| e.to_string())?;
    git(repo, &["add", "-A"])?;
    git(repo, &["commit", "-q", "-s", "-m", "contract with changelog"])?;
    std::fs::write(schemas.join("event.v1.json"), "{\"changed\":true}\n").map_err(|e| e.to_string())?;
    git(repo, &["add", "-A"])?;
    git(repo, &["commit", "-q", "-s", "-m", "contract without changelog"])?;
    Ok(("HEAD~2..HEAD~1".to_owned(), "HEAD~1..HEAD".to_owned()))
}

fn history_case(
    repo: &Path,
    gate: fn(&Path, &str) -> Result<(), String>,
    make_history: fn(&Path) -> Result<(String, String), String>,
    expect: &str,
) -> Result<(), String> {
    let (clean, violating) = make_history(repo)?;
    gate(repo, &clean).map_err(|e| format!("gate fails on the CLEAN history: {e}"))?;
    match gate(repo, &violating) {
        Ok(()) => Err("gate PASSED on the seeded violation — it does not bite".to_owned()),
        Err(e) if e.contains(expect) => Ok(()),
        Err(e) => Err(format!("gate failed without mentioning `{expect}`: {e}")),
    }
}
