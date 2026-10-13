// SPDX-License-Identifier: Apache-2.0

//! UAOS developer automation. Every merge gate that is not a third-party tool lives here, so
//! CI and a contributor's machine run exactly the same checks (`cargo xtask ci`).

#![allow(
    clippy::disallowed_methods,
    clippy::print_stdout,
    clippy::print_stderr,
    reason = "xtask is developer tooling: it reads files, spawns cargo/git and reports to the terminal"
)]

mod allow_audit;
mod arch;
mod claims;
mod dco;
mod decisions;
mod docs_sync;
mod gates;
mod headers;
mod negative;
mod schemas;
mod util;
mod vet_ratchet;

use std::process::ExitCode;

const USAGE: &str = "\
usage: cargo xtask <command>

  ci                     run the local merge fast lane (fmt, clippy, tests, all xtask checks)
  arch-check             enforce dependency direction (arch.toml)
  allow-audit            fail if a guarded lint is allowed outside its owner paths (arch.toml)
  vet-ratchet            fail if cargo-vet exemptions without notes grow (or shrink unrecorded)
  claims                 fail on forbidden claims in public documents (red line 6)
  schemas                regenerate schemas/ from uaos-contracts
  schema-check           fail on schema drift or unversioned breaking changes
  headers                fail on files missing an SPDX license header
  gates [--release]      validate gates.toml; --release also fails on pending gates
  decisions [--release]  list PENDING-DECISION markers; --release fails if any exist
  dco <rev-range>        fail if a commit in the range lacks a matching Signed-off-by
  docs-sync <rev-range>  fail if schemas/ changed in the range without a CHANGELOG.md entry
  negative [--require-all-tools] [case...]
                         prove each gate fails on a seeded violation
";

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let Some((command, rest)) = args.split_first() else {
        eprint!("{USAGE}");
        return ExitCode::from(2);
    };
    let result = match command.as_str() {
        "ci" => ci(),
        "arch-check" => arch::check(&util::workspace_root()),
        "allow-audit" => allow_audit::check(&util::workspace_root()),
        "vet-ratchet" => vet_ratchet::check(&util::workspace_root()),
        "claims" => claims::check(&util::workspace_root()),
        "schemas" => schemas::write(&util::workspace_root()),
        "schema-check" => schemas::check(&util::workspace_root()),
        "headers" => headers::check(&util::workspace_root()),
        "gates" => gates::check(&util::workspace_root(), rest.iter().any(|a| a == "--release")),
        "decisions" => decisions::check(&util::workspace_root(), rest.iter().any(|a| a == "--release")),
        "dco" => match rest.first() {
            Some(range) => dco::check(&util::workspace_root(), range),
            None => Err("usage: cargo xtask dco <rev-range>".to_owned()),
        },
        "docs-sync" => match rest.first() {
            Some(range) => docs_sync::check(&util::workspace_root(), range),
            None => Err("usage: cargo xtask docs-sync <rev-range>".to_owned()),
        },
        "negative" => negative::run(rest),
        "-h" | "--help" | "help" => {
            print!("{USAGE}");
            Ok(())
        }
        other => Err(format!("unknown command `{other}`\n\n{USAGE}")),
    };
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(message) => {
            eprintln!("xtask: {message}");
            ExitCode::FAILURE
        }
    }
}

/// The merge fast lane, in the same order CI runs it.
fn ci() -> Result<(), String> {
    let root = util::workspace_root();
    util::run_step(&root, "fmt", "cargo", &["fmt", "--all", "--", "--check"])?;
    util::run_step(
        &root,
        "clippy",
        "cargo",
        &[
            "clippy",
            "--workspace",
            "--all-targets",
            "--locked",
            "--",
            "-D",
            "warnings",
        ],
    )?;
    util::run_step(&root, "test", "cargo", &["test", "--workspace", "--locked"])?;
    arch::check(&root)?;
    allow_audit::check(&root)?;
    schemas::check(&root)?;
    headers::check(&root)?;
    claims::check(&root)?;
    vet_ratchet::check(&root)?;
    gates::check(&root, false)?;
    decisions::check(&root, false)?;
    println!("xtask ci: all local gates passed");
    Ok(())
}
