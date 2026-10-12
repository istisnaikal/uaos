// SPDX-License-Identifier: Apache-2.0

//! Dependency-direction enforcement (ADR-0001). See arch.toml for the rules.

use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

use cargo_metadata::{DependencyKind, MetadataCommand, PackageId};
use serde::Deserialize;

#[derive(Debug, Deserialize)]
struct ArchFile {
    ring1: Ring1,
    #[serde(rename = "crate")]
    crates: BTreeMap<String, CrateRule>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Ring1 {
    allow: Vec<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct CrateRule {
    #[allow(dead_code, reason = "documents the ring; validated by deserialization only")]
    ring: toml::Value,
    allow: Vec<String>,
    ban: Vec<String>,
}

pub(crate) fn check(root: &Path) -> Result<(), String> {
    let arch_text = std::fs::read_to_string(root.join("arch.toml")).map_err(|e| format!("arch.toml: {e}"))?;
    let arch: ArchFile = toml::from_str(&arch_text).map_err(|e| format!("arch.toml: {e}"))?;

    let metadata = MetadataCommand::new()
        .current_dir(root)
        .exec()
        .map_err(|e| format!("cargo metadata: {e}"))?;
    let resolve = metadata
        .resolve
        .as_ref()
        .ok_or("cargo metadata returned no resolve graph")?;

    let workspace: BTreeMap<&PackageId, &cargo_metadata::Package> =
        metadata.workspace_packages().into_iter().map(|p| (&p.id, p)).collect();
    let names: BTreeMap<&PackageId, &str> = metadata.packages.iter().map(|p| (&p.id, p.name.as_str())).collect();
    let nodes: BTreeMap<&PackageId, &cargo_metadata::Node> = resolve.nodes.iter().map(|n| (&n.id, n)).collect();

    let mut violations = Vec::new();
    for (id, package) in &workspace {
        let name = package.name.as_str();
        let rel_manifest = crate::util::rel(root, package.manifest_path.as_std_path());
        let is_ring1 = rel_manifest.starts_with("modules/");
        let rule = arch.crates.get(name);
        if rule.is_none() && !is_ring1 {
            violations.push(format!(
                "{name}: not declared in arch.toml (every crate declares its edges)"
            ));
            continue;
        }
        let allowed: BTreeSet<&str> = if is_ring1 {
            arch.ring1.allow.iter().map(String::as_str).collect()
        } else {
            rule.map(|r| r.allow.iter().map(String::as_str).collect())
                .unwrap_or_default()
        };
        let Some(node) = nodes.get(id) else {
            violations.push(format!("{name}: missing from resolve graph"));
            continue;
        };

        // Direct product edges (normal + build) to workspace crates.
        for dep in &node.deps {
            let is_product_edge = dep
                .dep_kinds
                .iter()
                .any(|k| matches!(k.kind, DependencyKind::Normal | DependencyKind::Build));
            if !is_product_edge || !workspace.contains_key(&dep.pkg) {
                continue;
            }
            let dep_name = names.get(&dep.pkg).copied().unwrap_or("?");
            if !(allowed.contains("*") || allowed.contains(dep_name)) {
                let ring = if is_ring1 {
                    " (Ring 1 may only use uaos-contracts and uaos-module-api)"
                } else {
                    ""
                };
                violations.push(format!("{name} -> {dep_name}: edge not allowed by arch.toml{ring}"));
            }
        }

        // Transitive closure over product edges, for bans.
        if let Some(rule) = rule.filter(|r| !r.ban.is_empty()) {
            let closure = product_closure(id, &nodes);
            for banned in &rule.ban {
                if closure.iter().any(|p| names.get(*p).copied() == Some(banned.as_str())) {
                    violations.push(format!("{name}: transitively depends on banned crate `{banned}`"));
                }
            }
        }
    }

    if violations.is_empty() {
        println!(
            "xtask arch-check: {} workspace crates conform to arch.toml",
            workspace.len()
        );
        Ok(())
    } else {
        Err(format!("architecture violations:\n  {}", violations.join("\n  ")))
    }
}

fn product_closure<'a>(
    start: &'a PackageId,
    nodes: &BTreeMap<&'a PackageId, &'a cargo_metadata::Node>,
) -> BTreeSet<&'a PackageId> {
    let mut seen = BTreeSet::new();
    let mut stack = vec![start];
    while let Some(id) = stack.pop() {
        let Some(node) = nodes.get(id) else { continue };
        for dep in &node.deps {
            let product = dep
                .dep_kinds
                .iter()
                .any(|k| matches!(k.kind, DependencyKind::Normal | DependencyKind::Build));
            if product && seen.insert(&dep.pkg) {
                stack.push(&dep.pkg);
            }
        }
    }
    seen
}
