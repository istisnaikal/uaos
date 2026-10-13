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

fn replace(path: &'static str, old: &'static str, new: &'static str) -> Seed {
    Box::new(move |ws| {
        let p = ws.join(path);
        let s = std::fs::read_to_string(&p).map_err(|e| format!("{path}: {e}"))?;
        if !s.contains(old) {
            return Err(format!(
                "seed anchor not found in {path} (update the negative case): {old:?}"
            ));
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
            seed: replace("crates/uaos-contracts/src/budget.rs", "    pub settled: bool,", "    pub settled: Option<bool>,"),
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
            id: "ledger-reserve-beyond-available",
            gate: "budget-concurrency",
            tool: None,
            // A ledger that accepts any reservation while the pool is not already in debt.
            seed: replace(
                "crates/uaos-ledger/src/state.rs",
                "if pool.available < amount {",
                "if pool.available < NanoUsd::ZERO {",
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
                "        anchor(\"ASIA\", C::AwsAccessKeyId, alnum, AWS),\n",
                "",
            ),
            runner: Runner::Program { program: "cargo", args: &["test", "-p", "uaos-redact", "--test", "corpus"] },
            expect: "recall below",
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
