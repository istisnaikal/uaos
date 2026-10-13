// SPDX-License-Identifier: Apache-2.0

//! The gate registry (`gates.toml`, plan §4.2).
//!
//! Every CLAUDE.md merge blocker and required behavior is listed with its status. An
//! **active** gate names the CI job that runs it and the negative case that proves it bites.
//! A **pending** gate names the phase that brings its subject into existence; pending gates
//! block a *release*, never silently pass a merge. The required sets below are copied from
//! CLAUDE.md §4 and may only shrink through an ADR.

use std::collections::BTreeSet;
use std::path::Path;

use serde::Deserialize;

/// CLAUDE.md §4 "CI merge blocker" list, plus plan-mandated gates.
const REQUIRED_GATES: &[&str] = &[
    "fmt",
    "clippy",
    "test",
    "secret-scan",
    "cargo-deny",
    "adapter-conformance",
    "journal-durability",
    "budget-concurrency",
    "redaction-corpus",
    "sandbox-escape",
    "panel-auth-csrf",
    "profile-migration",
    "a11y-critical-flows",
    "perf-smoke",
    "docs-contract-sync",
    // Plan §4.2 additions.
    "arch-check",
    "schema-compat",
    "spdx-headers",
    "dco",
    "cargo-vet",
    "gate-registry",
    "gate-selftest",
    "path-spaces-unicode",
    "empty-kernel",
    "prefix-stability",
    "pricing-reconciliation",
    "kernel-tokens",
    "codeql",
    // Plan v2 additions (PD-06, PD-19, V6).
    "allow-audit",
    "vet-ratchet",
    "claims-lint",
];

/// CLAUDE.md §4 "Required behaviors".
const REQUIRED_BEHAVIORS: &[&str] = &[
    "devam-side-effect-honesty",
    "yenipen-diff-restore",
    "budget-double-spend",
    "prompt-injection-tool-hook-skill",
    "cross-project-consent",
    "hap-dry-run-requires-coverage",
    "malicious-package",
    "disk-full",
    "pricing-reconciliation",
    "fuzzy-dangerous-tag",
    "sync-conflict",
    "benchmark-privacy",
];

const PHASES: &[&str] = &[
    "P0", "P1", "P2", "P3", "RC-2", "P4", "P5", "P6A", "P6B", "P6C", "P7", "P8",
];

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Registry {
    gate: Vec<Gate>,
    behavior: Vec<Behavior>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Gate {
    id: String,
    source: String,
    lane: String,
    status: String,
    #[serde(default)]
    phase: Option<String>,
    #[serde(default)]
    job: Option<String>,
    #[serde(default)]
    negative: Vec<String>,
    #[serde(default)]
    negative_exempt: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Behavior {
    id: String,
    source: String,
    status: String,
    phase: String,
    #[serde(default)]
    gate: Option<String>,
}

pub(crate) fn check(root: &Path, release: bool) -> Result<(), String> {
    let text = std::fs::read_to_string(root.join("gates.toml")).map_err(|e| format!("gates.toml: {e}"))?;
    let registry: Registry = toml::from_str(&text).map_err(|e| format!("gates.toml: {e}"))?;
    let workflows = workflow_jobs(root)?;
    let negative_ids: BTreeSet<&str> = crate::negative::cases().iter().map(|c| c.id).collect();
    let negative_gates: BTreeSet<&str> = crate::negative::cases().iter().map(|c| c.gate).collect();

    let mut problems = Vec::new();
    let mut ids = BTreeSet::new();
    let mut pending = Vec::new();

    for g in &registry.gate {
        if !ids.insert(g.id.as_str()) {
            problems.push(format!("gate `{}` is listed twice", g.id));
        }
        if g.source.trim().is_empty() {
            problems.push(format!("gate `{}` has no source", g.id));
        }
        if !matches!(g.lane.as_str(), "merge" | "nightly" | "release") {
            problems.push(format!("gate `{}`: lane must be merge, nightly or release", g.id));
        }
        match g.status.as_str() {
            "active" => {
                match &g.job {
                    Some(job) if workflows.contains(job) => {}
                    Some(job) => problems.push(format!("gate `{}`: job `{job}` not found in .github/workflows", g.id)),
                    None => problems.push(format!("gate `{}`: active gates must name their CI job", g.id)),
                }
                match (&g.negative[..], &g.negative_exempt) {
                    ([], None) => problems.push(format!(
                        "gate `{}`: active gates must list a negative case or a `negative_exempt` reason",
                        g.id
                    )),
                    (cases, _) => {
                        for c in cases {
                            if !negative_ids.contains(c.as_str()) {
                                problems.push(format!("gate `{}`: negative case `{c}` does not exist", g.id));
                            }
                        }
                    }
                }
            }
            "pending" => match &g.phase {
                Some(p) if PHASES.contains(&p.as_str()) => pending.push(format!("{} ({p})", g.id)),
                Some(p) => problems.push(format!("gate `{}`: unknown phase `{p}`", g.id)),
                None => problems.push(format!(
                    "gate `{}`: pending gates must name the phase that activates them",
                    g.id
                )),
            },
            other => problems.push(format!("gate `{}`: status `{other}` must be active or pending", g.id)),
        }
    }
    for required in REQUIRED_GATES {
        if !ids.contains(required) {
            problems.push(format!("missing required gate `{required}` (CLAUDE.md §4 / plan §4.2)"));
        }
    }
    for case_gate in &negative_gates {
        if !ids.contains(case_gate) {
            problems.push(format!("negative case targets unknown gate `{case_gate}`"));
        }
    }

    check_behaviors(&registry.behavior, &ids, &mut problems, &mut pending);

    if release && !pending.is_empty() {
        problems.push(format!(
            "release requires zero pending gates; pending: {}",
            pending.join(", ")
        ));
    }
    if problems.is_empty() {
        println!(
            "xtask gates: {} gates, {} behaviors registered; {} pending (allowed before release)",
            registry.gate.len(),
            registry.behavior.len(),
            pending.len()
        );
        Ok(())
    } else {
        Err(format!("gate registry problems:\n  {}", problems.join("\n  ")))
    }
}

fn check_behaviors(
    behaviors: &[Behavior],
    gate_ids: &BTreeSet<&str>,
    problems: &mut Vec<String>,
    pending: &mut Vec<String>,
) {
    let mut behavior_ids = BTreeSet::new();
    for b in behaviors {
        behavior_ids.insert(b.id.as_str());
        if b.source.trim().is_empty() || !PHASES.contains(&b.phase.as_str()) {
            problems.push(format!("behavior `{}`: needs a source and a known phase", b.id));
        }
        match b.status.as_str() {
            "pending" => pending.push(format!("behavior {} ({})", b.id, b.phase)),
            "active" if b.gate.as_deref().is_some_and(|g| gate_ids.contains(g)) => {}
            "active" => problems.push(format!(
                "behavior `{}`: active behaviors must name an existing gate",
                b.id
            )),
            other => problems.push(format!(
                "behavior `{}`: status `{other}` must be active or pending",
                b.id
            )),
        }
    }
    for required in REQUIRED_BEHAVIORS {
        if !behavior_ids.contains(required) {
            problems.push(format!("missing required behavior `{required}` (CLAUDE.md §4)"));
        }
    }
}

/// Job IDs declared in `.github/workflows/*.yml` (two-space-indented keys under `jobs:`).
fn workflow_jobs(root: &Path) -> Result<BTreeSet<String>, String> {
    let dir = root.join(".github").join("workflows");
    let mut jobs = BTreeSet::new();
    let entries = std::fs::read_dir(&dir).map_err(|e| format!("{}: {e}", dir.display()))?;
    for entry in entries.flatten() {
        let path = entry.path();
        if path.extension().and_then(|e| e.to_str()) != Some("yml") {
            continue;
        }
        let text = std::fs::read_to_string(&path).map_err(|e| format!("{}: {e}", path.display()))?;
        let mut in_jobs = false;
        for line in text.lines() {
            if line.starts_with("jobs:") {
                in_jobs = true;
                continue;
            }
            if in_jobs && !line.starts_with(' ') && !line.trim().is_empty() && !line.starts_with('#') {
                in_jobs = false;
            }
            if in_jobs
                && let Some(key) = line.strip_prefix("  ").and_then(|l| l.strip_suffix(':'))
                && !key.starts_with(' ')
                && !key.starts_with('#')
            {
                jobs.insert(key.to_owned());
            }
        }
    }
    Ok(jobs)
}
