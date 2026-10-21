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
/// A case's `tool` when its seed only compiles on Unix. Elsewhere it does not run and does not
/// count as skipped; the CI negative job, which runs on Linux with `--require-all-tools`, runs it.
const UNIX_ONLY: &str = "unix";
/// Likewise for Windows. The CI negative job never runs these: they are proven by running the
/// negatives on Windows (review WP3.A5, round 4, M1).
const WINDOWS_ONLY: &str = "windows";

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
            id: "journal-first-open-bricks",
            gate: "journal-durability",
            tool: None,
            // A first open killed before its manifest is stored leaves an empty segment; refusing
            // it makes the directory unopenable forever (kill harness, nightly 39330543607).
            seed: replace(
                "crates/uaos-state/src/journal/writer.rs",
                "        if len != 0 {\n",
                "        if len != u64::MAX {\n",
            ),
            runner: Runner::Program {
                program: "cargo",
                args: &["test", "-p", "uaos-state", "--test", "journal", "a_first_open_killed_before_its_manifest_is_stored_starts_cleanly"],
            },
            expect: "left the journal unopenable",
        },
        Case {
            id: "journal-new-history-over-records",
            gate: "journal-durability",
            tool: None,
            // Segments of a real history, whose manifest is gone, taken for a crashed first open:
            // a new history would hide that the old one is lost (T12).
            seed: replace(
                "crates/uaos-state/src/journal/writer.rs",
                "        if len != 0 {\n",
                "        if len != 0 && false {\n",
            ),
            runner: Runner::Program {
                program: "cargo",
                args: &["test", "-p", "uaos-state", "--test", "journal", "manifest"],
            },
            expect: "a new history started over",
        },
        Case {
            id: "journal-new-history-checks-first-segment-only",
            gate: "journal-durability",
            tool: None,
            // Only the first segment checked: a real history whose first segment is empty would
            // be renamed away and a new history started over its records (V1 review, M1).
            seed: replace(
                "crates/uaos-state/src/journal/writer.rs",
                "    for path in &segments {\n        // The length, not the content",
                "    for path in segments.iter().take(1) {\n        // The length, not the content",
            ),
            runner: Runner::Program {
                program: "cargo",
                args: &["test", "-p", "uaos-state", "--test", "journal", "a_lost_manifest_behind_an_empty_first_segment_is_refused"],
            },
            expect: "a new history started over records behind an empty first segment",
        },
        Case {
            id: "journal-new-history-over-a-marker",
            gate: "journal-durability",
            tool: None,
            // A marker naming a record ignored without a manifest (V1 review, L4).
            seed: replace(
                "crates/uaos-state/src/journal/writer.rs",
                "        Ok(bytes) if bytes.as_slice() != none.as_bytes() => {\n",
                "        Ok(bytes) if false && bytes.as_slice() != none.as_bytes() => {\n",
            ),
            runner: Runner::Program {
                program: "cargo",
                args: &["test", "-p", "uaos-state", "--test", "journal", "a_missing_manifest_with_a_recorded_durable_point_is_refused"],
            },
            expect: "a new history started over a recorded durable point",
        },
        Case {
            id: "recovery-drops-old-payload",
            gate: "journal-durability",
            tool: None,
            // A recovery that loses a payload acknowledged several runs earlier, outside the
            // per-kill window the nightly lane reads back. The harness runs in its nightly
            // configuration (sweep before retiring a directory only), so this proves that the
            // sweep the 10,000-kill lane relies on still catches an old loss.
            seed: both(
                both(
                    replace(
                        "crates/uaos-state/src/chunks/mod.rs",
                        "    pub(crate) fn shred_now(",
                        "    pub(crate) fn drop_data(&self, pocket: PocketId, chunk: ChunkRef) {\n        let _gone = self.fs.remove_file(&self.chunk_path(pocket, chunk));\n    }\n\n    pub(crate) fn shred_now(",
                    ),
                    replace(
                        "crates/uaos-state/src/journal/writer.rs",
                        "    let first_unproven = durable.map_or(0, |seq| seq + 1);\n",
                        // The journal's first payload, once it is both 1,500 records and 5
                        // seconds behind the newest record: several runs back on any machine.
                        "    let first_unproven = durable.map_or(0, |seq| seq + 1);\n    if let (Some(first), Some(last)) = (records.first(), records.last())\n        && records.len() > 1500\n        && last.envelope.ts.wall.unix_millis_saturating() > first.envelope.ts.wall.unix_millis_saturating() + 5000\n        && let (Some(pocket), Some(chunk)) = (first.envelope.pocket_id, first.envelope.payload_ref)\n    {\n        store.drop_data(pocket, chunk);\n    }\n",
                    ),
                ),
                replace(
                    "crates/uaos-testkit/tests/kill.rs",
                    "        Some(\"rotation\") => Some(Sweep::Rotation),\n        Some(\"every-kill\") | None => Some(Sweep::EveryKill),\n",
                    "        Some(\"rotation\") | None => Some(Sweep::Rotation),\n        Some(\"every-kill\") => Some(Sweep::EveryKill),\n",
                ),
            ),
            runner: Runner::Program { program: "cargo", args: &["test", "-p", "uaos-testkit", "--test", "kill"] },
            expect: "sweep before retiring",
        },
        Case {
            id: "egress-dials-private-range",
            gate: "test",
            tool: None,
            // T5: a door whose classification lets the loopback range through.
            seed: replace(
                "crates/uaos-egress/src/addr.rs",
                "([127, 0, 0, 0], 8, Blocked::Loopback),",
                "([127, 0, 0, 0], 32, Blocked::Loopback),",
            ),
            runner: Runner::Program {
                program: "cargo",
                args: &[
                    "test",
                    "-p",
                    "uaos-egress",
                    "--test",
                    "door",
                    "private_answers_are_refused_unless_the_upstream_is_declared_private",
                ],
            },
            expect: "the door dialled a private range",
        },
        Case {
            id: "egress-numeric-host",
            gate: "test",
            tool: None,
            // T5: an upstream named by an address literal in disguise (`2130706433`).
            seed: replace(
                "crates/uaos-egress/src/host.rs",
                "if name.rsplit('.').next().is_some_and(is_numeric_label) {",
                "if false && name.rsplit('.').next().is_some_and(is_numeric_label) {",
            ),
            runner: Runner::Program {
                program: "cargo",
                args: &["test", "-p", "uaos-egress", "--lib", "address_literals_are_refused"],
            },
            expect: "was accepted as a host name",
        },
        Case {
            id: "egress-ctor-outside-root",
            gate: "clippy",
            tool: None,
            // ADR-0010: code other than the composition root building an egress door.
            seed: append(
                "crates/uaos-egress/src/lib.rs",
                "\n/// Seeded.\n///\n/// # Errors\n/// Never.\npub fn seeded_violation() -> Result<Door, EgressError> {\n    Door::new(\n        Vec::new(),\n        std::sync::Arc::new(SystemResolver),\n        std::sync::Arc::new(uaos_platform::real::SystemClock::new()),\n        hyper_util::rt::TokioExecutor::new(),\n        DoorLimits::default(),\n    )\n}\n",
            ),
            runner: CLIPPY,
            expect: "uaos_egress::Door::new",
        },
        Case {
            id: "egress-private-reaches-link-local",
            gate: "test",
            tool: None,
            // Review WP3.A5 H2: a private upstream admitted to every special-purpose range, metadata included.
            seed: replace(
                "crates/uaos-egress/src/upstream.rs",
                "Reach::Blocked(_) if self.allow_private && is_local_network(ip) => Ok(()),",
                "Reach::Blocked(_) if self.allow_private => Ok(()),",
            ),
            runner: Runner::Program {
                program: "cargo",
                args: &["test", "-p", "uaos-egress", "--test", "door", "a_private_upstream_never_reaches_link_local_or_special_ranges"],
            },
            expect: "dialled the metadata range",
        },
        Case {
            id: "egress-plaintext-resolved",
            gate: "test",
            tool: None,
            // Review WP3.A5 H2: plain HTTP that depends on name resolution.
            seed: replace(
                "crates/uaos-egress/src/upstream.rs",
                "            if self.pinned.is_empty() {\n                return Err(UpstreamError::PlaintextNeedsPinned);\n            }\n",
                "",
            ),
            runner: Runner::Program {
                program: "cargo",
                args: &["test", "-p", "uaos-egress", "--test", "door", "plain_http_is_declared_only_toward_pinned_local_addresses"],
            },
            expect: "would be resolved",
        },
        Case {
            id: "egress-breaker-admits-after-cooldown",
            gate: "test",
            tool: None,
            // Review WP3.A5 M4: a breaker with no half-open state.
            seed: replace(
                "crates/uaos-egress/src/door.rs",
                "Breaker::Probing { .. } => Err(PROBE_RECHECK.min(cooldown)),",
                "Breaker::Probing { generation } => Ok(Ticket::Probe { generation }),",
            ),
            runner: Runner::Program {
                program: "cargo",
                args: &["test", "-p", "uaos-egress", "--test", "door", "after_the_cooldown_exactly_one_probe_goes_through"],
            },
            expect: "more than one probe",
        },
        Case {
            id: "net-dns-outside-egress",
            gate: "clippy",
            tool: None,
            // Review WP3.A5 M2: DNS through std, which needs no dependency at all.
            seed: append(
                "crates/uaos-state/src/lib.rs",
                "\n/// Seeded.\n#[must_use]\npub fn seeded_violation() -> bool {\n    use std::net::ToSocketAddrs as _;\n    (\"exfil.example\", 80).to_socket_addrs().is_ok()\n}\n",
            ),
            runner: CLIPPY,
            expect: "std::net::ToSocketAddrs::to_socket_addrs",
        },
        Case {
            id: "net-connect-outside-egress",
            gate: "clippy",
            tool: None,
            // Review WP3.A5 M2: an outbound TCP connection outside the connector.
            seed: append(
                "crates/uaos-egress/src/lib.rs",
                "\n/// Seeded.\n///\n/// # Errors\n/// Never.\npub async fn seeded_violation(addr: std::net::SocketAddr) -> std::io::Result<tokio::net::TcpStream> {\n    tokio::net::TcpSocket::new_v4()?.connect(addr).await\n}\n",
            ),
            runner: CLIPPY,
            expect: "tokio::net::TcpSocket::connect",
        },
        Case {
            id: "net-udp-outside-egress",
            gate: "clippy",
            tool: None,
            // Review WP3.A5 M2: a UDP socket.
            seed: append(
                "crates/uaos-egress/src/lib.rs",
                "\n/// Seeded.\n///\n/// # Errors\n/// Never.\npub async fn seeded_violation() -> std::io::Result<tokio::net::UdpSocket> {\n    tokio::net::UdpSocket::bind((std::net::Ipv4Addr::UNSPECIFIED, 0)).await\n}\n",
            ),
            runner: CLIPPY,
            expect: "tokio::net::UdpSocket::bind",
        },
        Case {
            id: "spawn-outside-supervisor",
            gate: "clippy",
            tool: None,
            // Review WP3.A5 M2: a task spawned on a runtime handle, outside the supervisor.
            seed: append(
                "crates/uaos-egress/src/lib.rs",
                "\n/// Seeded.\npub fn seeded_violation() {\n    drop(tokio::runtime::Handle::current().spawn(async {}));\n}\n",
            ),
            runner: CLIPPY,
            expect: "tokio::runtime::Handle::spawn",
        },
        Case {
            id: "egress-probe-stuck-on-cancel",
            gate: "test",
            tool: None,
            // Review WP3.A5 round 2, H1: a breaker probe whose caller drops the future is never settled.
            seed: replace(
                "crates/uaos-egress/src/door.rs",
                "            self.door
                .breaker_record(self.upstream, self.ticket, Outcome::NotAttempted);",
                "            let _ = (self.door, self.upstream, self.ticket);",
            ),
            runner: Runner::Program {
                program: "cargo",
                args: &["test", "-p", "uaos-egress", "--test", "door", "a_cancelled_probe_lets_the_next_attempt_probe"],
            },
            expect: "a cancelled probe left the circuit refusing",
        },
        Case {
            id: "egress-embedded-local",
            gate: "test",
            tool: None,
            // Review WP3.A5 round 2, M1: an IPv6 form that only embeds a loopback address counted as local.
            seed: replace(
                "crates/uaos-egress/src/addr.rs",
                "    if let IpAddr::V6(v6) = ip\n        && embeds_ipv4(v6)\n    {\n        return false;\n    }\n",
                "    let _ = embeds_ipv4;\n",
            ),
            runner: Runner::Program {
                program: "cargo",
                args: &["test", "-p", "uaos-egress", "--lib", "plaintext_is_refused_toward_embedded_forms"],
            },
            expect: "2002:7f00:1::1",
        },
        Case {
            id: "egress-forwards-switching-protocols",
            gate: "test",
            tool: None,
            // Review WP3.A5 round 13, L1: a 101 answer handed to the caller as final.
            seed: replace(
                "crates/uaos-egress/src/door.rs",
                "        if parts.status.is_informational() {",
                "        if parts.status.is_informational() && parts.status.as_u16() == 0 {",
            ),
            runner: Runner::Program {
                program: "cargo",
                args: &["test", "-p", "uaos-egress", "--test", "door", "a_switching_protocols_answer_is_an_error"],
            },
            expect: "a 101 reached the caller",
        },
        Case {
            id: "egress-forwards-contradicting-length",
            gate: "test",
            tool: None,
            // Review WP3.A5 round 13, L2: a content-length beside transfer-encoding forwarded.
            seed: replace(
                "crates/uaos-egress/src/door.rs",
                "        }\n        headers.remove(header::CONTENT_LENGTH);\n        return Ok(());",
                "        }\n        return Ok(());",
            ),
            runner: Runner::Program {
                program: "cargo",
                args: &["test", "-p", "uaos-egress", "--test", "door", "a_content_length_beside_transfer_encoding_is_dropped"],
            },
            expect: "a content-length contradicting the decoded body was forwarded",
        },
        Case {
            id: "osfs-doubled-separator-unc",
            gate: "test",
            tool: Some(WINDOWS_ONLY),
            // Review WP3.A5 round 13, M1: a UNC path spelled with doubled separators, which std
            // does not parse as UNC and Windows does.
            seed: replace(
                "crates/uaos-platform/src/real/fs.rs",
                "            .is_some_and(|start| start.iter().all(|b| *b == b'\\\\' || *b == b'/'));",
                "            .is_some_and(|_| false);",
            ),
            runner: Runner::Program {
                program: "cargo",
                args: &["test", "-p", "uaos-platform", "--lib", "network_and_device_paths_are_refused"],
            },
            expect: "uaos-canary.invalid",
        },
        Case {
            id: "egress-forwards-unknown-transfer-coding",
            gate: "test",
            tool: None,
            // Review WP3.A5 round 14, L2: a body coded with something other than `chunked` passed on
            // unmarked.
            seed: replace("crates/uaos-egress/src/door.rs", "        if !chunked_only {", "        if !chunked_only && false {"),
            runner: Runner::Program {
                program: "cargo",
                args: &["test", "-p", "uaos-egress", "--test", "door", "a_transfer_coding_other_than_chunked_is_an_error"],
            },
            expect: "a coded body reached the caller unmarked",
        },
        Case {
            id: "egress-forwards-repeated-length",
            gate: "test",
            tool: None,
            // Review WP3.A5 round 14, L2: a repeated content-length passed on as is.
            seed: replace(
                "crates/uaos-egress/src/door.rs",
                "            headers.insert(header::CONTENT_LENGTH, single);",
                "            let _ = single;",
            ),
            runner: Runner::Program {
                program: "cargo",
                args: &["test", "-p", "uaos-egress", "--test", "door", "a_repeated_content_length_is_forwarded_once"],
            },
            expect: "a repeated content-length was forwarded",
        },
        Case {
            id: "egress-forwards-bodiless-length",
            gate: "test",
            tool: None,
            // Review WP3.A5 round 15, L2: a 204 forwarded with the content-length it should not
            // carry.
            seed: replace(
                "crates/uaos-egress/src/door.rs",
                "    if status == StatusCode::NO_CONTENT {",
                "    if status == StatusCode::NO_CONTENT && status.as_u16() == 0 {",
            ),
            runner: Runner::Program {
                program: "cargo",
                args: &["test", "-p", "uaos-egress", "--test", "door", "content_length_on_answers_without_a_body"],
            },
            expect: "a 204 kept its content-length",
        },
        Case {
            id: "egress-delivered-reported-unsent",
            gate: "test",
            tool: None,
            // Review WP3.A5 round 16, M1: a request cut off after it was sent reported as never
            // sent, and retryable.
            seed: replace(
                "crates/uaos-egress/src/lib.rs",
                "            Self::Interrupted(\"the connection failed after the request was sent\")",
                "            Self::Unreachable(\"the connection failed before a response arrived\")",
            ),
            runner: Runner::Program {
                program: "cargo",
                args: &["test", "-p", "uaos-egress", "--test", "door", "errors_say_whether_the_request_may_have_reached_the_provider"],
            },
            expect: "a request the provider received was reported as never sent",
        },
        Case {
            id: "egress-timeout-reported-unsent",
            gate: "test",
            tool: None,
            // Review WP3.A5 round 17, L3: no answer within the response timeout reported as
            // nothing sent, retryable.
            seed: replace(
                "crates/uaos-egress/src/door.rs",
                "                return Err(EgressError::Interrupted(\"no answer within the response timeout\"));",
                "                return Err(EgressError::Timeout);",
            ),
            runner: Runner::Program {
                program: "cargo",
                args: &["test", "-p", "uaos-egress", "--test", "door", "no_answer_within_the_response_timeout_is_interrupted"],
            },
            expect: "an unanswered request was reported as never sent",
        },
        Case {
            id: "egress-unsent-reported-delivered",
            gate: "test",
            tool: None,
            // Review WP3.A5 round 17, L1: a connection lost before hyper took the request reported
            // as possibly received.
            seed: replace(
                "crates/uaos-egress/src/lib.rs",
                "        let mut unsent = e.is_connect() || e.connect_info().is_none();",
                "        let mut unsent = e.is_connect();",
            ),
            runner: Runner::Program {
                program: "cargo",
                args: &["test", "-p", "uaos-egress", "--test", "door", "a_connection_lost_before_the_request_left_is_unreachable"],
            },
            expect: "nothing was sent, but the door reported",
        },
        Case {
            id: "egress-unassigned-timeout-reported-delivered",
            gate: "test",
            tool: None,
            // Review WP3.A5 round 18, L1: a response timeout before hyper handed the request to a
            // connection reported as possibly received.
            seed: replace(
                "crates/uaos-egress/src/door.rs",
                "                if handed_over.connection_metadata().is_none() {",
                "                if handed_over.connection_metadata().is_none() && false {",
            ),
            runner: Runner::Program {
                program: "cargo",
                args: &["test", "-p", "uaos-egress", "--test", "door", "a_timeout_before_the_request_was_handed_over_is_not_interrupted"],
            },
            expect: "a request that never left was reported as possibly received",
        },
        Case {
            id: "egress-canceled-reported-delivered",
            gate: "test",
            tool: None,
            // Review WP3.A5 round 18, L3: a request hyper handed back unsent reported as possibly
            // received.
            seed: replace(
                "crates/uaos-egress/src/lib.rs",
                "                unsent |= h.is_canceled();",
                "                let _ = h.is_canceled();",
            ),
            runner: Runner::Program {
                program: "cargo",
                args: &["test", "-p", "uaos-egress", "--test", "door", "a_queued_request_handed_back_is_unreachable"],
            },
            expect: "a request handed back unsent was reported as",
        },
        Case {
            id: "json-duplicate-key-unchecked",
            gate: "test",
            tool: None,
            // ADR-0014 contract §4: an object closes without its duplicate-key check.
            seed: replace("crates/uaos-json/src/tape.rs", "self.check_duplicate_keys()?;", ""),
            runner: Runner::Program {
                program: "cargo",
                args: &["test", "-p", "uaos-json", "--test", "grammar", "plain_duplicate_keys_are_rejected"],
            },
            expect: "duplicate key accepted",
        },
        Case {
            id: "json-escaped-duplicate-compared-raw",
            gate: "test",
            tool: None,
            // Contract §4: an escaped key compared by its raw bytes in a run, so `"a"` and its
            // escaped spelling differ.
            seed: replace(
                "crates/uaos-json/src/tape.rs",
                "        if member.flags & KEY_ESCAPED == 0 {",
                "        if true {",
            ),
            runner: Runner::Program {
                program: "cargo",
                args: &["test", "-p", "uaos-json", "--test", "grammar", "escaped_duplicate_keys_are_rejected"],
            },
            expect: "escaped duplicate key accepted",
        },
        Case {
            id: "json-fingerprint-raw-bytes",
            gate: "test",
            tool: None,
            // Contract §6: escaped keys fingerprinted over their raw bytes, so `"a"` and its
            // escaped spelling land on different fingerprints and are never compared.
            seed: replace("crates/uaos-json/src/tape.rs", "let fingerprint = if escaped {", "let fingerprint = if false {"),
            runner: Runner::Program {
                program: "cargo",
                args: &["test", "-p", "uaos-json", "--test", "grammar", "escaped_duplicate_keys_are_rejected"],
            },
            expect: "escaped duplicate key accepted",
        },
        Case {
            id: "json-fingerprint-collision-accepts",
            gate: "test",
            tool: None,
            // Contract §6: members that share a fingerprint are never compared exactly, so a
            // shared fingerprint, a real repeat included, passes.
            seed: replace("crates/uaos-json/src/tape.rs", "        if run.len() < 2 {", "        if run.len() >= 2 {"),
            runner: Runner::Program {
                program: "cargo",
                args: &["test", "-p", "uaos-json", "--test", "grammar", "plain_duplicate_keys_are_rejected"],
            },
            expect: "duplicate key accepted",
        },
        Case {
            id: "json-fingerprint-collision-rejects",
            gate: "test",
            tool: None,
            // Contract §6: a shared fingerprint taken for a repeat, so two distinct keys that
            // collide refuse the object.
            seed: replace(
                "crates/uaos-json/src/tape.rs",
                "            && key(*a) == key(*b)\n",
                "            && (key(*a) == key(*b) || key_start(*a) != key_start(*b))\n",
            ),
            runner: Runner::Program {
                program: "cargo",
                args: &["test", "-p", "uaos-json", "--test", "grammar", "distinct_keys_sharing_a_fingerprint_are_accepted"],
            },
            expect: "colliding keys rejected",
        },
        Case {
            id: "json-fingerprint-word-order",
            gate: "test",
            tool: None,
            // Contract §6: raw keys fingerprinted a word at a time in the wrong byte order, so a
            // raw key of eight bytes or more and its escaped spelling get different fingerprints
            // and are never compared (review WP3.A2 M2).
            seed: replace(
                "crates/uaos-json/src/tape.rs",
                "fp.word = u64::from_le_bytes(word);",
                "fp.word = u64::from_be_bytes(word);",
            ),
            runner: Runner::Program {
                program: "cargo",
                args: &["test", "-p", "uaos-json", "--lib", "the_word_path_equals_the_byte_path"],
            },
            expect: "word path differs",
        },
        Case {
            id: "json-run-scratch-doubles",
            gate: "test",
            tool: None,
            // Contract §6: the run scratch reserved per key instead of once per run, so it grows
            // by doubling past its bound (review WP3.A2, second round, M1).
            seed: both(
                replace(
                    "crates/uaos-json/src/tape.rs",
                    "    decoded.try_reserve_exact(escaped).map_err(|_| oom(first_key))?;\n",
                    "    let _ = escaped;\n",
                ),
                replace(
                    "crates/uaos-json/src/tape.rs",
                    "            let start = decoded.len();\n",
                    "            let start = decoded.len();\n            decoded.try_reserve(content.len()).map_err(|_| oom(member.key_start))?;\n",
                ),
            ),
            runner: Runner::Program {
                program: "cargo",
                args: &["test", "-p", "uaos-json", "--lib", "the_run_scratch_stays_within_its_bound"],
            },
            expect: "run scratch",
        },
        Case {
            id: "json-pairwise-skips-shared-fingerprint",
            gate: "test",
            tool: None,
            // Contract §6: the small-object path that skips sorting also skips a shared
            // fingerprint, so a small object's repeat passes.
            seed: replace("crates/uaos-json/src/tape.rs", "!any_shared_fingerprint(members)", "true"),
            runner: Runner::Program {
                program: "cargo",
                args: &["test", "-p", "uaos-json", "--test", "grammar", "plain_duplicate_keys_are_rejected"],
            },
            expect: "duplicate key accepted",
        },
        Case {
            id: "json-depth-off-by-one",
            gate: "test",
            tool: None,
            // Contract §3: one level more than the limit gets through.
            seed: replace(
                "crates/uaos-json/src/tape.rs",
                "if self.stack.len() >= usize::from(self.limits.max_depth()) {",
                "if self.stack.len() > usize::from(self.limits.max_depth()) {",
            ),
            runner: Runner::Program {
                program: "cargo",
                args: &["test", "-p", "uaos-json", "--test", "grammar", "depth_limit_is_exact"],
            },
            expect: "depth 129 accepted",
        },
        Case {
            id: "json-lone-surrogate-accepted",
            gate: "test",
            tool: None,
            // Contract §4 (T19): a surrogate escape outside a pair passes as a character.
            seed: replace("crates/uaos-json/src/tape.rs", "if lone {", "if false {"),
            runner: Runner::Program {
                program: "cargo",
                args: &["test", "-p", "uaos-json", "--test", "grammar", "lone_surrogates_are_rejected"],
            },
            expect: "lone surrogate accepted",
        },
        Case {
            id: "json-trailing-data-accepted",
            gate: "test",
            tool: None,
            // Contract §4: bytes after the root value are ignored instead of refused.
            seed: replace(
                "crates/uaos-json/src/tape.rs",
                "if skip_ws(self.bytes, at) != self.bytes.len() {",
                "if false {",
            ),
            runner: Runner::Program {
                program: "cargo",
                args: &["test", "-p", "uaos-json", "--test", "grammar", "trailing_data_is_rejected"],
            },
            expect: "trailing data accepted",
        },
        Case {
            id: "json-bom-stripped",
            gate: "test",
            tool: None,
            // Contract §4: a byte-order mark stripped, so every span would sit three bytes off
            // the forwarded body.
            seed: replace(
                "crates/uaos-json/src/tape.rs",
                "reject_bom(raw)?;",
                "let raw = raw.strip_prefix(BOM).unwrap_or(raw);",
            ),
            runner: Runner::Program {
                program: "cargo",
                args: &["test", "-p", "uaos-json", "--test", "grammar", "bom_is_rejected"],
            },
            expect: "BOM accepted",
        },
        Case {
            id: "json-leading-zero-accepted",
            gate: "test",
            tool: None,
            // Contract §4 (T19): `01` read as a number, which another parser may refuse or read
            // as octal.
            seed: replace(
                "crates/uaos-json/src/tape.rs",
                "Some(b'0') => j += 1,",
                "Some(b'0') => j = skip_digits(bytes, j),",
            ),
            runner: Runner::Program {
                program: "cargo",
                args: &["test", "-p", "uaos-json", "--test", "grammar", "leading_zeros_are_rejected"],
            },
            expect: "leading zero accepted",
        },
        Case {
            id: "json-decode-escape-wrong",
            gate: "test",
            tool: None,
            // Contract §9 (T14): the independent oracle bites: one escape decoded wrongly makes
            // the tape disagree with serde_json.
            seed: replace("crates/uaos-json/src/decode.rs", "b'/' => '/',", "b'/' => '\\\\',"),
            runner: Runner::Program {
                program: "cargo",
                args: &["test", "-p", "uaos-json", "--test", "differential"],
            },
            expect: "differs from serde_json",
        },
        Case {
            id: "osfs-bare-volume",
            gate: "test",
            tool: Some(WINDOWS_ONLY),
            // Review WP3.A5 round 14, L1: `\\?\C:` alone, the raw volume, admitted as a disk path.
            seed: replace(
                "crates/uaos-platform/src/real/fs.rs",
                "Prefix::VerbatimDisk(_) => parts.next() != Some(Component::RootDir),",
                "Prefix::VerbatimDisk(_) => false,",
            ),
            runner: Runner::Program {
                program: "cargo",
                args: &["test", "-p", "uaos-platform", "--lib", "network_and_device_paths_are_refused"],
            },
            expect: r"create_dir_all \\?\C:",
        },
        Case {
            id: "egress-sends-trace",
            gate: "test",
            tool: None,
            // Review WP3.A5 round 9, L1: TRACE echoes the request, credential included, back.
            seed: replace(
                "crates/uaos-egress/src/door.rs",
                "        if !SENT_METHODS.contains(&request.method) {",
                "        if SENT_METHODS.is_empty() {",
            ),
            runner: Runner::Program {
                program: "cargo",
                args: &["test", "-p", "uaos-egress", "--test", "door", "methods_the_door_does_not_send_are_refused_before_contact"],
            },
            expect: "TRACE was not refused before contact",
        },
        Case {
            id: "net-listen-outside-api",
            gate: "clippy",
            tool: None,
            // Review WP3.A5 round 2, M2: a listener, whose bind also resolves names, outside the API crate.
            seed: append(
                "crates/uaos-state/src/lib.rs",
                "\n/// Seeded.\n///\n/// # Errors\n/// Never.\npub fn seeded_violation() -> std::io::Result<std::net::TcpListener> {\n    std::net::TcpListener::bind(\"localhost:0\")\n}\n",
            ),
            runner: CLIPPY,
            expect: "std::net::TcpListener::bind",
        },
        Case {
            id: "net-resolver-outside-egress",
            gate: "clippy",
            tool: None,
            // Review WP3.A5 round 3, M1: hyper-util's own resolver, a DNS lookup outside the door.
            seed: append(
                "crates/uaos-egress/src/lib.rs",
                "\n/// Seeded.\n#[must_use]\npub fn seeded_violation() -> hyper_util::client::legacy::connect::dns::GaiResolver {\n    hyper_util::client::legacy::connect::dns::GaiResolver::new()\n}\n",
            ),
            runner: CLIPPY,
            expect: "GaiResolver::new",
        },
        Case {
            id: "net-socket-listen-outside-api",
            gate: "clippy",
            tool: None,
            // Review WP3.A5 round 3, M1: a raw socket turned into a listener outside the API crate.
            seed: append(
                "crates/uaos-egress/src/lib.rs",
                "\n/// Seeded.\n///\n/// # Errors\n/// Never.\npub fn seeded_violation() -> std::io::Result<tokio::net::TcpListener> {\n    tokio::net::TcpSocket::new_v4()?.listen(1)\n}\n",
            ),
            runner: CLIPPY,
            expect: "tokio::net::TcpSocket::listen",
        },
        Case {
            id: "net-unix-connect-addr-outside-egress",
            gate: "clippy",
            tool: Some(UNIX_ONLY),
            // Review WP3.A5 round 4, M1: each `allow-invalid` ban is proven where it exists.
            seed: append(
                "crates/uaos-egress/src/lib.rs",
                "\n/// Seeded.\n///\n/// # Errors\n/// Never.\n#[cfg(unix)]\npub fn seeded_violation() -> std::io::Result<std::os::unix::net::UnixStream> {\n    std::os::unix::net::UnixStream::connect_addr(&std::os::unix::net::SocketAddr::from_pathname(\"/run/seeded.sock\")?)\n}\n",
            ),
            runner: CLIPPY,
            expect: "std::os::unix::net::UnixStream::connect_addr",
        },
        Case {
            id: "net-tokio-unix-connect-outside-egress",
            gate: "clippy",
            tool: Some(UNIX_ONLY),
            // Review WP3.A5 round 4, M1.
            seed: append(
                "crates/uaos-egress/src/lib.rs",
                "\n/// Seeded.\n///\n/// # Errors\n/// Never.\n#[cfg(unix)]\npub async fn seeded_violation() -> std::io::Result<tokio::net::UnixStream> {\n    tokio::net::UnixStream::connect(\"/run/seeded.sock\").await\n}\n",
            ),
            runner: CLIPPY,
            expect: "tokio::net::UnixStream::connect",
        },
        Case {
            id: "net-unix-socket-connect-outside-egress",
            gate: "clippy",
            tool: Some(UNIX_ONLY),
            // Review WP3.A5 round 4, M1.
            seed: append(
                "crates/uaos-egress/src/lib.rs",
                "\n/// Seeded.\n///\n/// # Errors\n/// Never.\n#[cfg(unix)]\npub async fn seeded_violation() -> std::io::Result<tokio::net::UnixStream> {\n    tokio::net::UnixSocket::new_stream()?.connect(\"/run/seeded.sock\").await\n}\n",
            ),
            runner: CLIPPY,
            expect: "tokio::net::UnixSocket::connect",
        },
        Case {
            id: "net-named-pipe-outside-egress",
            gate: "clippy",
            tool: Some(WINDOWS_ONLY),
            // Review WP3.A5 round 4, M1: the Windows counterpart of the Unix-socket bans.
            seed: append(
                "crates/uaos-egress/src/lib.rs",
                "\n/// Seeded.\n///\n/// # Errors\n/// Never.\n#[cfg(windows)]\npub fn seeded_violation() -> std::io::Result<tokio::net::windows::named_pipe::NamedPipeClient> {\n    tokio::net::windows::named_pipe::ClientOptions::new().open(\"seeded\")\n}\n",
            ),
            runner: CLIPPY,
            expect: "named_pipe::ClientOptions::open",
        },
        Case {
            id: "spawn-through-tokio-executor",
            gate: "clippy",
            tool: None,
            // Review WP3.A5 round 4, L1: hyper-util's executor spawns with `tokio::spawn`.
            seed: append(
                "crates/uaos-egress/src/lib.rs",
                "\n/// Seeded.\n#[must_use]\npub fn seeded_violation() -> hyper_util::rt::TokioExecutor {\n    hyper_util::rt::TokioExecutor::new()\n}\n",
            ),
            runner: CLIPPY,
            expect: "hyper_util::rt::TokioExecutor",
        },
        Case {
            id: "clippy-ban-path-unresolved",
            gate: "clippy",
            tool: None,
            // Review WP3.A5 round 4, M1: a ban whose path resolves to nothing is off, and clippy
            // only warns about it.
            seed: replace(
                "clippy.toml",
                "\"tokio::task::JoinSet::spawn_local_on\"",
                "\"tokio::task::JoinSet::spawn_local_onx\"",
            ),
            runner: Runner::Xtask(&["clippy"]),
            expect: "resolve to nothing",
        },
        Case {
            id: "clippy-ban-silenced",
            gate: "clippy",
            tool: None,
            // Review WP3.A5 round 5, L2: a ban that stops firing (here, removed) leaves its
            // canary's expectation unfulfilled, which fails clippy.
            seed: replace(
                "clippy.toml",
                "  { path = \"tokio::net::TcpSocket::listen\", reason = \"only the API crate listens, on loopback (owner: uaos-api)\" },\n",
                "",
            ),
            runner: CLIPPY,
            expect: "unfulfilled",
        },
        Case {
            id: "clippy-config-nested",
            gate: "allow-audit",
            tool: None,
            // Review WP3.A5 round 6, M2: a crate-local clippy.toml replaces every ban for its crate.
            seed: write("crates/uaos-state/clippy.toml", "allow-unwrap-in-tests = true\n".to_owned()),
            runner: Runner::Xtask(&["allow-audit"]),
            expect: "a clippy.toml below the root",
        },
        Case {
            id: "lints-not-inherited",
            gate: "allow-audit",
            tool: None,
            // Review WP3.A5 round 6, M2: a member's own [lints] replaces the workspace's.
            seed: replace(
                "crates/uaos-state/Cargo.toml",
                "[lints]\nworkspace = true",
                "[lints.clippy]\ndisallowed_methods = \"allow\"",
            ),
            runner: Runner::Xtask(&["allow-audit"]),
            expect: "must be exactly `workspace = true`",
        },
        Case {
            id: "cargo-config-clippy-override",
            gate: "allow-audit",
            tool: None,
            // Review WP3.A5 round 6, M2: Cargo configuration pointing clippy at another config.
            seed: append(".cargo/config.toml", "\n[env]\nCLIPPY_CONF_DIR = \"crates/uaos-state\"\n"),
            runner: Runner::Xtask(&["allow-audit"]),
            expect: "`env` is not allowed",
        },
        Case {
            id: "clippy-ban-without-canary",
            gate: "allow-audit",
            tool: None,
            // Review WP3.A5 round 6, L2: a ban added without a canary, in a compact layout.
            seed: replace(
                "clippy.toml",
                "disallowed-methods = [",
                "disallowed-methods = [\n  { path=\"std::process::abort\", reason=\"seeded\" },",
            ),
            runner: Runner::Xtask(&["allow-audit"]),
            expect: "`std::process::abort` has no canary",
        },
        Case {
            id: "allow-audit-lint-group",
            gate: "allow-audit",
            tool: None,
            // Review WP3.A5 round 7, H1: a lint group that contains a guarded lint switches it off.
            seed: append_owned(
                LIB,
                format!(
                    "\n/// Seeded.\n#[{}({}, reason = \"seeded\")]\n#[must_use]\npub fn seeded_violation() -> u8 {{\n    1\n}}\n",
                    "allow", "clippy::style"
                ),
            ),
            runner: Runner::Xtask(&["allow-audit"]),
            expect: "names `clippy::style`",
        },
        Case {
            id: "allow-audit-macro-attribute",
            gate: "allow-audit",
            tool: None,
            // Review WP3.A5 round 7, H1: an attribute a macro builds from its arguments.
            seed: append_owned(
                LIB,
                format!(
                    "\nmacro_rules! seeded {{\n    ($a:meta) => {{\n        #[$a]\n        /// Seeded.\n        pub fn seeded_violation() {{}}\n    }};\n}}\nseeded!({}({}, reason = \"seeded\"));\n",
                    "allow", "clippy::disallowed_methods"
                ),
            ),
            runner: Runner::Xtask(&["allow-audit"]),
            expect: "names `disallowed_methods`",
        },
        Case {
            id: "allow-audit-path-module",
            gate: "allow-audit",
            tool: None,
            // Review WP3.A5 round 7, H1: library code compiled from a file under an owner path.
            seed: both(
                append(LIB, "\n#[path = \"../tests/seeded.rs\"]\nmod seeded;\n"),
                write("crates/uaos-contracts/tests/seeded.rs", "//! Seeded.\n".to_owned()),
            ),
            runner: Runner::Xtask(&["allow-audit"]),
            expect: "a `#[path]` module",
        },
        Case {
            id: "allow-audit-nested-target",
            gate: "allow-audit",
            tool: None,
            // Review WP3.A5 round 7, H1: a nested folder named like the root's skipped build folder.
            seed: write(
                "crates/uaos-redact/src/target/seeded.rs",
                format!("#[{}({}, reason = \"seeded\")]\nfn seeded() {{}}\n", "allow", "clippy::disallowed_methods"),
            ),
            runner: Runner::Xtask(&["allow-audit"]),
            expect: "src/target/seeded.rs",
        },
        Case {
            id: "workspace-lints-group-allowed",
            gate: "allow-audit",
            tool: None,
            // Review WP3.A5 round 7, M1: a group allowed in the workspace lint table.
            seed: replace(
                "Cargo.toml",
                "disallowed_methods = \"deny\"",
                "disallowed_methods = \"deny\"\nstyle = { level = \"allow\", priority = 1 }",
            ),
            runner: Runner::Xtask(&["allow-audit"]),
            expect: "`style` set to `allow`",
        },
        Case {
            id: "clippy-config-case",
            gate: "allow-audit",
            tool: None,
            // Review WP3.A5 round 7, M1: a clippy.toml named in another case, which Windows and
            // macOS read.
            seed: write("crates/uaos-state/CLIPPY.TOML", "allow-unwrap-in-tests = true\n".to_owned()),
            runner: Runner::Xtask(&["allow-audit"]),
            expect: "replaces the root's bans",
        },
        Case {
            id: "cargo-config-not-alias",
            gate: "allow-audit",
            tool: None,
            // Review WP3.A5 round 7, M1: compiler flags in Cargo configuration.
            seed: append(".cargo/config.toml", "\n[build]\nrustflags = [\"-Aclippy::disallowed_methods\"]\n"),
            runner: Runner::Xtask(&["allow-audit"]),
            expect: "`build` is not allowed",
        },
        Case {
            id: "build-script-clippy-env",
            gate: "allow-audit",
            tool: None,
            // Review WP3.A5 rounds 8 and 10 (L5, L2): a build script that could set clippy's
            // environment, here through a helper that builds the line.
            seed: write(
                "crates/uaos-state/build.rs",
                "fn emit(key: &str, value: &str) {\n    println!(\"cargo:rustc-env={key}={value}\");\n}\n\nfn main() {\n    emit(\"clippy_args\", \"-Aclippy::disallowed_methods\");\n}\n".to_owned(),
            ),
            runner: Runner::Xtask(&["allow-audit"]),
            expect: "names one of clippy's variables",
        },
        Case {
            id: "canary-malformed",
            gate: "allow-audit",
            tool: None,
            // Review WP3.A5 round 7, L1: a marker that is not a canary.
            seed: both(
                replace(
                    "clippy.toml",
                    "disallowed-methods = [",
                    "disallowed-methods = [\n  { path = \"std::process::abort\", reason = \"seeded\" },",
                ),
                append("crates/uaos-egress/tests/bans.rs", "\n// canary: `std::process::abort`\n"),
            ),
            runner: Runner::Xtask(&["allow-audit"]),
            expect: "is not one banned call",
        },
        Case {
            id: "canary-calls-another-item",
            gate: "allow-audit",
            tool: None,
            // Review WP3.A5 rounds 9 and 10 (L2, L1): a canary that calls the ban of the same
            // type and method in another crate.
            seed: replace(
                "crates/uaos-egress/tests/bans.rs",
                "let _canary = tokio::net::TcpStream::connect(\"canary.invalid:1\");",
                "let _canary = std::net::TcpStream::connect(\"canary.invalid:1\");",
            ),
            runner: Runner::Xtask(&["allow-audit"]),
            expect: "the canary for `tokio::net::TcpStream::connect`",
        },
        Case {
            id: "canary-setup-calls-another-ban",
            gate: "allow-audit",
            tool: None,
            // Review WP3.A5 round 11, L1: a canary whose setup line calls another ban of the same
            // lint, which keeps the expectation fulfilled when its own ban is dead.
            seed: replace(
                "crates/uaos-egress/tests/bans.rs",
                "        fn std_datagram_connect(socket: &std::os::unix::net::UnixDatagram) {\n            // canary: `std::os::unix::net::UnixDatagram::connect`\n            let _canary = socket.connect(\"/canary\");",
                "        fn std_datagram_connect() {\n            // canary: `std::os::unix::net::UnixDatagram::connect`\n            let socket = std::os::unix::net::UnixDatagram::unbound().ok();\n            let _canary = socket.map(|s| s.connect(\"/canary\"));",
            ),
            runner: Runner::Xtask(&["allow-audit"]),
            expect: "also uses `std::os::unix::net::UnixDatagram::unbound`",
        },
        Case {
            id: "build-script-module",
            gate: "allow-audit",
            tool: None,
            // Review WP3.A5 round 11, L2: a build script that keeps its code in another file.
            seed: both(
                write(
                    "crates/uaos-state/build.rs",
                    "mod build_env;\n\nfn main() {\n    build_env::emit();\n}\n".to_owned(),
                ),
                write(
                    "crates/uaos-state/build_env.rs",
                    "pub fn emit() {\n    println!(\"cargo:rustc-env=clippy_args=-Aclippy::disallowed_methods\");\n}\n".to_owned(),
                ),
            ),
            runner: Runner::Xtask(&["allow-audit"]),
            expect: "uses another file",
        },
        Case {
            id: "build-script-include-in-owner",
            gate: "allow-audit",
            tool: None,
            // Review WP3.A5 round 12, L1: a build script in an owner crate, where `include!` is
            // otherwise allowed, that includes the helper setting clippy's arguments.
            seed: both(
                write(
                    "crates/uaos-testkit/build.rs",
                    "include!(\"build_env.rs\");\n\nfn main() {\n    emit_env();\n}\n".to_owned(),
                ),
                write(
                    "crates/uaos-testkit/build_env.rs",
                    "fn emit_env() {\n    println!(\"cargo:rustc-env={}=-Aclippy::disallowed_types\", \"clippy_args\".to_ascii_uppercase());\n}\n".to_owned(),
                ),
            ),
            runner: Runner::Xtask(&["allow-audit"]),
            expect: "crates/uaos-testkit/build.rs: a build script uses another file",
        },
        Case {
            id: "build-dependency-path",
            gate: "allow-audit",
            tool: None,
            // Review WP3.A5 round 11, L2: a path build dependency, whose code runs in the build
            // script.
            seed: both(
                write("crates/uaos-state/build.rs", "fn main() {}\n".to_owned()),
                append("crates/uaos-state/Cargo.toml", "\n[build-dependencies]\nuaos-contracts = { path = \"../uaos-contracts\" }\n"),
            ),
            runner: Runner::Xtask(&["allow-audit"]),
            expect: "build dependency `uaos-contracts` is a path dependency",
        },
        Case {
            id: "canary-copied-from-sibling",
            gate: "allow-audit",
            tool: None,
            // Review WP3.A5 round 10, L1: a canary copied from a sibling in the same module, whose
            // own ban fulfils the expectation.
            seed: replace(
                "crates/uaos-egress/tests/bans.rs",
                "    #[expect(clippy::disallowed_methods, reason = \"canary\")]\n    fn task_spawn_blocking() {\n        // canary: `tokio::task::spawn_blocking`\n        let _canary = tokio::task::spawn_blocking(|| ());",
                "    #[expect(clippy::disallowed_types, clippy::disallowed_methods, reason = \"canary\")]\n    fn task_spawn_blocking(set: &mut tokio::task::JoinSet<()>) {\n        // canary: `tokio::task::spawn_blocking`\n        let _canary = set.spawn_blocking(|| ());",
            ),
            runner: Runner::Xtask(&["allow-audit"]),
            expect: "the canary for `tokio::task::spawn_blocking`",
        },
        Case {
            id: "build-script-declared-path",
            gate: "allow-audit",
            tool: None,
            // Review WP3.A5 round 9, L3: a build script at the path `build = "..."` names.
            seed: both(
                write(
                    "crates/uaos-state/build/main.rs",
                    "fn main() {\n    println!(\"cargo:rustc-env=CLIPPY_CONF_DIR=crates\");\n}\n".to_owned(),
                ),
                replace(
                    "crates/uaos-state/Cargo.toml",
                    "name = \"uaos-state\"\n",
                    "name = \"uaos-state\"\nbuild = \"build/main.rs\"\n",
                ),
            ),
            runner: Runner::Xtask(&["allow-audit"]),
            expect: "main.rs: a build script names one of clippy's variables",
        },
        Case {
            id: "net-unix-connect-outside-egress",
            gate: "clippy",
            tool: Some(UNIX_ONLY),
            // Review WP3.A5 round 3, L3: the Unix-socket bans are `allow-invalid`, so a wrong path
            // would go silent; this proves they resolve where they exist.
            seed: append(
                "crates/uaos-egress/src/lib.rs",
                "\n/// Seeded.\n///\n/// # Errors\n/// Never.\n#[cfg(unix)]\npub fn seeded_violation() -> std::io::Result<std::os::unix::net::UnixStream> {\n    std::os::unix::net::UnixStream::connect(\"/run/seeded.sock\")\n}\n",
            ),
            runner: CLIPPY,
            expect: "std::os::unix::net::UnixStream::connect",
        },
        Case {
            id: "arch-ring1-depends-on-hyper",
            gate: "arch-check",
            tool: None,
            // ADR-0010: a Ring 1 module that reaches a network crate.
            seed: both(
                both(
                    write(
                        "modules/mod-seeded/Cargo.toml",
                        "[package]\nname = \"mod-seeded\"\nversion = \"0.0.0\"\nedition = \"2024\"\nlicense = \"Apache-2.0\"\npublish = false\n\n[dependencies]\nhyper.workspace = true\n".to_owned(),
                    ),
                    write("modules/mod-seeded/src/lib.rs", "// SPDX-License-Identifier: Apache-2.0\n".to_owned()),
                ),
                replace("Cargo.toml", "members = [\"crates/*\", \"xtask\"]", "members = [\"crates/*\", \"modules/*\", \"xtask\"]"),
            ),
            runner: Runner::Xtask(&["arch-check"]),
            expect: "transitively depends on banned crate `hyper`",
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
            id: "payload-failure-hides-torn-segment",
            gate: "journal-durability",
            tool: None,
            // WP3.A1 eleventh round H1: a payload flush failure replaces `DiskFull`, so recovery
            // appends after a torn line and the journal no longer opens.
            seed: replace(
                "crates/uaos-state/src/journal/writer.rs",
                "            if self.health == JournalHealth::Healthy {\n                self.health = JournalHealth::PayloadFlushFailed;\n            }",
                "            self.health = JournalHealth::PayloadFlushFailed;",
            ),
            runner: Runner::Program {
                program: "cargo",
                args: &["test", "-p", "uaos-state", "--test", "durability", "r11_h1_a_payload_failure_never_hides_a_torn_segment"],
            },
            expect: "a payload failure hid the torn segment",
        },
        Case {
            id: "lost-content-reads-as-unavailable",
            gate: "journal-durability",
            tool: None,
            // WP3.A1 twelfth round L3: content whose loss was journaled reads back as never stored
            // or shredded.
            seed: replace(
                "crates/uaos-state/src/chunks/mod.rs",
                "                    Ok(_) => Err(ChunkError::Lost),",
                "                    Ok(_) => Err(ChunkError::Unavailable),",
            ),
            runner: Runner::Program {
                program: "cargo",
                args: &["test", "-p", "uaos-state", "--test", "durability", "r12_l3_lost_content_reads_back_as_lost"],
            },
            expect: "lost content read back as never stored or shredded",
        },
        Case {
            id: "unauthentic-loss-skipped-at-open",
            gate: "journal-durability",
            tool: None,
            // WP3.A1 thirteenth round L1: an open that skips an unauthentic payload, so its record
            // becomes durable with no chunk.lost record.
            seed: replace(
                "crates/uaos-state/src/chunks/mod.rs",
                "                    self.remember(key);\n                    continue;\n                }\n                Probe::Absent => LossCause::Missing,",
                "                    self.remember(key);\n                    continue;\n                }\n                Probe::Lost(LossCause::Unauthentic) => continue,\n                Probe::Absent => LossCause::Missing,",
            ),
            runner: Runner::Program {
                program: "cargo",
                args: &["test", "-p", "uaos-state", "--test", "durability", "r13_l1_an_unauthentic_payload_found_at_open_is_journaled"],
            },
            expect: "survived without its payload and with no chunk.lost record",
        },
        Case {
            id: "unauthentic-loss-skipped-in-recovery",
            gate: "journal-durability",
            tool: None,
            // WP3.A1 thirteenth round L1: a recovery that skips an unauthentic payload.
            seed: replace(
                "crates/uaos-state/src/chunks/mod.rs",
                "                    locked(&self.pending).remove(&key);\n                    continue;\n                }\n                Probe::Absent => LossCause::Missing,",
                "                    locked(&self.pending).remove(&key);\n                    continue;\n                }\n                Probe::Lost(LossCause::Unauthentic) => continue,\n                Probe::Absent => LossCause::Missing,",
            ),
            runner: Runner::Program {
                program: "cargo",
                args: &["test", "-p", "uaos-state", "--test", "durability", "r13_l1_an_unauthentic_payload_found_in_recovery_is_journaled"],
            },
            expect: "became durable without its payload and with no chunk.lost record",
        },
        Case {
            id: "missing-loss-reads-as-unavailable",
            gate: "journal-durability",
            tool: None,
            // WP3.A1 thirteenth round L2: a loss with no file to set aside leaves no marker.
            seed: replace(
                "crates/uaos-state/src/chunks/mod.rs",
                "        self.fs\n            .write_unsynced(&self.lost_marker(pocket, chunk), b\"\")\n            .map_err(storage)?;",
                "",
            ),
            runner: Runner::Program {
                program: "cargo",
                args: &["test", "-p", "uaos-state", "--test", "durability", "r13_l2_a_missing_payload_reads_back_as_lost"],
            },
            expect: "a journaled loss reads back as never stored or shredded",
        },
        Case {
            id: "shredded-content-reads-as-lost",
            gate: "journal-durability",
            tool: None,
            // WP3.A1 thirteenth round L3: a shred that leaves an earlier loss's marker.
            seed: replace(
                "crates/uaos-state/src/chunks/mod.rs",
                "        match self.fs.remove_file(&self.lost_marker(pocket, chunk)) {",
                "        match Err::<(), FsError>(FsError::NotFound { op: \"seeded\" }) {",
            ),
            runner: Runner::Program {
                program: "cargo",
                args: &["test", "-p", "uaos-state", "--test", "durability", "r13_l3_lost_then_shredded_reads_back_as_shredded"],
            },
            expect: "deliberately shredded content reads back as lost",
        },
        Case {
            id: "shred-of-quarantined-payload-skipped",
            gate: "journal-durability",
            tool: None,
            // WP3.A1 fourteenth round M1: an open that ignores a loss marker when it decides
            // whether a journaled shred finished, so the KEK is never rotated.
            seed: replace(
                "crates/uaos-state/src/chunks/mod.rs",
                "        for path in [self.key_path(pocket, chunk), self.chunk_path(pocket, chunk), lost] {",
                "        let _ = lost;\n        for path in [self.key_path(pocket, chunk), self.chunk_path(pocket, chunk)] {",
            ),
            runner: Runner::Program {
                program: "cargo",
                args: &["test", "-p", "uaos-state", "--test", "durability", "r14_m1_a_shred_whose_payload_was_quarantined_is_completed"],
            },
            expect: "was never rotated",
        },
        Case {
            id: "loss-cause-overwritten",
            gate: "journal-durability",
            tool: None,
            // WP3.A1 fourteenth round L2: a chunk set aside twice reported with its later cause.
            seed: replace(
                "crates/uaos-state/src/journal/writer.rs",
                "        causes.entry((l.pocket, l.chunk)).or_insert(l.cause);",
                "        causes.insert((l.pocket, l.chunk), l.cause);",
            ),
            runner: Runner::Program {
                program: "cargo",
                args: &["test", "-p", "uaos-state", "--test", "durability", "r14_l2_the_cause_the_bytes_showed_is_the_cause_reported"],
            },
            expect: "cause reported for record",
        },
        Case {
            id: "shred-incomplete-key-only",
            gate: "journal-durability",
            tool: None,
            // WP3.A1 third round L3: an open that judges a shred finished once its key file is gone.
            seed: both(
                replace(
                    "crates/uaos-state/src/chunks/mod.rs",
                    "        for path in [self.key_path(pocket, chunk), self.chunk_path(pocket, chunk), lost] {\n            match self.fs.read(&path) {",
                    "        let _ = lost;\n        for path in [self.key_path(pocket, chunk)] {\n            match self.fs.read(&path) {",
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
            id: "arch-json-io-dependency",
            gate: "arch-check",
            tool: None,
            // ADR-0014 Decision 1: the tokenizer stays pure; an async runtime in its graph fails.
            seed: replace(
                "crates/uaos-json/Cargo.toml",
                "[dependencies]\nmemchr.workspace = true\n",
                "[dependencies]\nmemchr.workspace = true\ntokio.workspace = true\n",
            ),
            runner: Runner::Xtask(&["arch-check"]),
            expect: "transitively depends on banned crate `tokio`",
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
        Case {
            id: "module-unknown-feature-loaded",
            gate: "test",
            tool: None,
            // Contract §3: admission compares every required feature with the kernel's offer.
            seed: replace("crates/uaos-module-api/src/manifest.rs", "match manifest.requires().iter().find(|f| !self.features.contains(f)) {", "match manifest.requires().iter().find(|_| false) {"),
            runner: Runner::Program {
                program: "cargo",
                args: &["test", "-p", "uaos-module-api", "--test", "socket", "admission_compares_every_required_feature"],
            },
            expect: "a missing feature was admitted",
        },
        Case {
            id: "module-act-at-observe-point",
            gate: "test",
            tool: None,
            // Contract §2 rule 7: an acting hook at a point that only observes is refused at load.
            seed: replace("crates/uaos-module-api/src/manifest.rs", "if hook.mode == HookMode::Act && !hook.point.acts() {", "if false && hook.mode == HookMode::Act && !hook.point.acts() {"),
            runner: Runner::Program {
                program: "cargo",
                args: &["test", "-p", "uaos-module-api", "--test", "socket", "a_manifest_is_refused_whole_for_each_reason"],
            },
            expect: "was not refused",
        },
        Case {
            id: "module-state-unbounded",
            gate: "test",
            tool: None,
            // Contract §5: module state never grows past its bound.
            seed: replace("crates/uaos-module-api/src/state.rs", "if u32::try_from(wanted).is_ok_and(|n| n <= self.limit) {", "if u32::try_from(wanted).is_ok() {"),
            runner: Runner::Program {
                program: "cargo",
                args: &["test", "-p", "uaos-module-api", "--test", "socket", "state_is_bounded_and_unchanged_on_refusal"],
            },
            expect: "state grew past its bound",
        },
        Case {
            id: "module-state-call-kept",
            gate: "test",
            tool: None,
            // Contract §5: a call that outgrew its state is struck whole, not kept in part.
            seed: replace("crates/uaos-module-api/src/state.rs", "self.exceeded = true;", ""),
            runner: Runner::Program {
                program: "cargo",
                args: &["test", "-p", "uaos-module-api", "--test", "socket", "a_call_that_outgrows_its_state_is_struck_whole"],
            },
            expect: "an outgrown call was kept",
        },
        Case {
            id: "module-decls-at-unhooked-point",
            gate: "test",
            tool: None,
            // V1 review M2: a point the manifest does not hook takes no declaration.
            seed: replace("crates/uaos-module-api/src/decl.rs", "Some(p) => manifest.hook(p).ok_or(Strike::NotHooked)?.mode() == HookMode::Observe,", "Some(p) => manifest.hook(p).is_none_or(|h| h.mode() == HookMode::Observe),"),
            runner: Runner::Program {
                program: "cargo",
                args: &["test", "-p", "uaos-module-api", "--test", "socket", "nothing_is_declared_at_a_point_the_module_did_not_hook"],
            },
            expect: "declarations accepted at an unhooked point",
        },
        Case {
            id: "module-event-value-undeclared",
            gate: "test",
            tool: None,
            // V1 review H2: a module event carries only the value names its manifest declares.
            seed: replace("crates/uaos-module-api/src/decl.rs", "declared.fields.contains(name)", "declared.fields.contains(name) || name.as_str().is_ascii()"),
            runner: Runner::Program {
                program: "cargo",
                args: &["test", "-p", "uaos-module-api", "--test", "socket", "an_event_carries_only_declared_value_names"],
            },
            expect: "an undeclared value name was emitted",
        },
        Case {
            id: "module-text-accepts-bidi-override",
            gate: "language-neutrality",
            tool: None,
            // ADR-0020 rule 5: module text refuses explicit bidirectional controls.
            seed: replace("crates/uaos-module-api/src/decl.rs", "if text.chars().any(is_explicit_bidi) {", "if text.chars().any(|_| false) {"),
            runner: Runner::Program {
                program: "cargo",
                args: &["test", "-p", "uaos-module-api", "--test", "language_neutrality", "module_text_refuses_explicit_bidi_controls"],
            },
            expect: "explicit bidi accepted",
        },
        Case {
            id: "view-masked-key-readable",
            gate: "test",
            tool: None,
            // V1 review H1: a key detection flagged reads as masked.
            seed: replace("crates/uaos-module-api/src/view.rs", "let masked = self.key_masked();", "let masked = false;"),
            runner: Runner::Program {
                program: "cargo",
                args: &["test", "-p", "uaos-module-api", "--test", "view", "masked_keys_and_numbers_read_as_masked"],
            },
            expect: "a masked key was readable",
        },
        Case {
            id: "view-masked-key-found-by-name",
            gate: "test",
            tool: None,
            // V1 review H1: a member whose key is masked is never found by name.
            seed: replace("crates/uaos-module-api/src/view.rs", ".filter(|n| !self.wrap(*n).key_masked())", ".filter(|_| true)"),
            runner: Runner::Program {
                program: "cargo",
                args: &["test", "-p", "uaos-module-api", "--test", "view", "masked_keys_and_numbers_read_as_masked"],
            },
            expect: "a masked key was found by name",
        },
        Case {
            id: "selector-predicate-unbounded",
            gate: "test",
            tool: None,
            // V1 review M5: a predicate lists a bounded number of values.
            seed: replace("crates/uaos-module-api/src/selector.rs", "if values.len() > MAX_PREDICATE_VALUES {", "if values.len() > usize::MAX - 1 {"),
            runner: Runner::Program {
                program: "cargo",
                args: &["test", "-p", "uaos-module-api", "--test", "view", "a_selector_is_bounded"],
            },
            expect: "an unbounded predicate was accepted",
        },
        Case {
            id: "selector-folds-case",
            gate: "language-neutrality",
            tool: None,
            // ADR-0020 rule 2: selectors compare bytes and never fold case.
            seed: replace("crates/uaos-module-api/src/selector.rs", "Some(ViewText::Plain(text)) => Ok(values.contains(text.as_ref())),", "Some(ViewText::Plain(text)) => Ok(values.iter().any(|v| v.to_lowercase() == text.to_lowercase())),"),
            runner: Runner::Program {
                program: "cargo",
                args: &["test", "-p", "uaos-module-api", "--test", "language_neutrality", "selectors_never_fold_case"],
            },
            expect: "folded case",
        },
        Case {
            id: "path-pattern-crosses-segment",
            gate: "test",
            tool: None,
            // V1 review M6: a prefix pattern matches by whole segments.
            seed: replace("crates/uaos-module-api/src/codec.rs", ".is_some_and(|rest| rest.is_empty() || prefix.ends_with('/') || rest.starts_with('/')),", ".is_some(),"),
            runner: Runner::Program {
                program: "cargo",
                args: &["test", "-p", "uaos-module-api", "--test", "view", "path_patterns_match_canonical_paths_by_segment"],
            },
            expect: "matched a pattern it should not",
        },
        Case {
            id: "path-not-canonical",
            gate: "test",
            tool: None,
            // V1 review M6: a path that is not canonical never matches.
            seed: replace(
                "crates/uaos-module-api/src/codec.rs",
                "if !canonical(path) {\n            return false;",
                "if false && !canonical(path) {\n            return false;",
            ),
            runner: Runner::Program {
                program: "cargo",
                args: &["test", "-p", "uaos-module-api", "--test", "view", "path_patterns_match_canonical_paths_by_segment"],
            },
            expect: "matched a pattern it should not",
        },
        Case {
            id: "agent-id-serialized-when-absent",
            gate: "test",
            tool: None,
            // Contract §8: an envelope without an agent keeps its exact bytes (the journal hashes them).
            seed: replace("crates/uaos-contracts/src/event.rs", "#[serde(default, skip_serializing_if = \"Option::is_none\")]\n    pub agent_id: Option<AgentId>,", "#[serde(default)]\n    pub agent_id: Option<AgentId>,"),
            runner: Runner::Program {
                program: "cargo",
                args: &["test", "-p", "uaos-contracts", "--lib", "an_absent_agent_id_is_not_written"],
            },
            expect: "an absent agent_id was written",
        },
        Case {
            id: "endpoint-unmatched-not-denied",
            gate: "test",
            tool: None,
            // PR-4 scoped review F2: a path no endpoint matches is denied, never forwarded.
            seed: replace("crates/uaos-module-api/src/codec.rs", ".unwrap_or(EndpointClass::Denied)", ".unwrap_or(EndpointClass::Metadata)"),
            runner: Runner::Program {
                program: "cargo",
                args: &["test", "-p", "uaos-module-api", "--test", "view", "an_endpoint_s_class_is_the_strictest_match_and_unknown_paths_are_denied"],
            },
            expect: "an endpoint got a weaker class",
        },
        Case {
            id: "module-rank-empty-accepted",
            gate: "test",
            tool: None,
            // PR-4 scoped review F5: an empty ranking is a strike, not a silent veto.
            seed: replace("crates/uaos-module-api/src/decl.rs", "if ranked.is_empty() || ranked.len() > MAX_RANK", "if ranked.len() > MAX_RANK"),
            runner: Runner::Program {
                program: "cargo",
                args: &["test", "-p", "uaos-module-api", "--test", "socket", "an_empty_ranking_is_a_strike"],
            },
            expect: "an empty ranking vetoed the route without a reason",
        },
        Case {
            id: "view-masked-container-leaks",
            gate: "test",
            tool: None,
            // Final review L12: masking a container masks everything inside it.
            seed: replace("crates/uaos-module-api/src/view.rs", "self.node.ancestors().any(|a| self.mask.masks_value(a.id()))", "self.node.ancestors().any(|_| false)"),
            runner: Runner::Program {
                program: "cargo",
                args: &["test", "-p", "uaos-module-api", "--test", "view", "a_masked_container_masks_everything_inside"],
            },
            expect: "inside a masked container was",
        },
        Case {
            id: "role-check-ancestors-only",
            gate: "test",
            tool: None,
            // Final review M2: an edit's role check covers the node's whole subtree, not only its ancestors.
            seed: replace("crates/uaos-module-api/src/codec.rs", "for (_, inside) in self.roles.range(id..node.subtree_end()) {", "for (_, inside) in self.roles.range(id..id) {"),
            runner: Runner::Program {
                program: "cargo",
                args: &["test", "-p", "uaos-module-api", "--test", "view", "a_strip_never_encloses_a_forbidden_role"],
            },
            expect: "an edit's roles missed its subtree",
        },
        Case {
            id: "replay-declares-again",
            gate: "test",
            tool: None,
            // Final review H2: an event delivered by a replay is marked, so its declarations are discarded.
            seed: replace("crates/uaos-module-api/src/module.rs", "self.replay = true;", "self.replay = false;"),
            runner: Runner::Program {
                program: "cargo",
                args: &["test", "-p", "uaos-module-api", "--test", "socket", "a_replay_rebuilds_state_and_declares_nothing"],
            },
            expect: "a replay requested a child Operation again",
        },
        Case {
            id: "module-text-accepts-tag",
            gate: "language-neutrality",
            tool: None,
            // Final review L10: module text refuses Unicode tag characters.
            seed: replace("crates/uaos-module-api/src/decl.rs", "if text.chars().any(is_tag) {", "if text.chars().any(|_| false) {"),
            runner: Runner::Program {
                program: "cargo",
                args: &["test", "-p", "uaos-module-api", "--test", "language_neutrality", "module_text_takes_crlf_and_refuses_tag_characters"],
            },
            expect: "a tag character was accepted",
        },
        Case {
            id: "path-parameter-canonical",
            gate: "test",
            tool: None,
            // Final review L11: a path parameter (`;`) is not canonical.
            seed: replace("crates/uaos-module-api/src/codec.rs", "['?', '#', '%', ';', '\\\\']", "['?', '#', '%', '\\\\']"),
            runner: Runner::Program {
                program: "cargo",
                args: &["test", "-p", "uaos-module-api", "--test", "view", "path_patterns_match_canonical_paths_by_segment"],
            },
            expect: "matched a pattern it should not",
        },
        Case {
            id: "module-cancel-without-feature",
            gate: "test",
            tool: None,
            // Final review L3: cancelling a child Operation needs child_operations.
            seed: replace("crates/uaos-module-api/src/decl.rs", "Decl::CancelOp(_) if !manifest.requires().contains(&KernelFeature::ChildOperations) => {", "Decl::CancelOp(_) if false => {"),
            runner: Runner::Program {
                program: "cargo",
                args: &["test", "-p", "uaos-module-api", "--test", "socket", "cancelling_a_child_needs_child_operations"],
            },
            expect: "a cancellation was accepted without child_operations",
        },
        Case {
            id: "chunk-lost-drops-agent",
            gate: "test",
            tool: None,
            // Contract §8: a chunk.lost record carries the agent of the record it reports.
            seed: replace("crates/uaos-state/src/journal/writer.rs", "agent_id: referencing.agent_id,", "agent_id: None,"),
            runner: Runner::Program {
                program: "cargo",
                args: &["test", "-p", "uaos-state", "--test", "durability", "a_lost_payload_record_names_the_agent_of_the_record_it_reports"],
            },
            expect: "a lost-payload record dropped the agent",
        },
        Case {
            id: "module-manifest-reread",
            gate: "test",
            tool: None,
            // Fresh full review M1: every call is checked against the manifest admitted, not a later one.
            seed: replace("crates/uaos-module-api/src/module.rs", "    pub const fn manifest(&self) -> &Manifest {\n        &self.manifest\n    }", "    pub fn manifest(&self) -> &Manifest {\n        self.module.manifest()\n    }"),
            runner: Runner::Program {
                program: "cargo",
                args: &["test", "-p", "uaos-module-api", "--test", "socket", "a_module_is_checked_against_its_admitted_manifest"],
            },
            expect: "a module grew its manifest after admission",
        },
        Case {
            id: "view-sealed-mask-drifts",
            gate: "test",
            tool: None,
            // Fresh full review M2: a sealed mask answers exactly as an unsealed one.
            seed: replace("crates/uaos-module-api/src/view.rs", "covered.push((*id, node.subtree_end()));", "covered.push((*id, *id));"),
            runner: Runner::Program {
                program: "cargo",
                args: &["test", "-p", "uaos-module-api", "--test", "view", "sealed_and_unsealed_views_agree"],
            },
            expect: "a sealed view disagreed with an unsealed one",
        },
        Case {
            id: "strip-removes-anchor",
            gate: "test",
            tool: None,
            // Fresh full review L1: a strip removes what is inside its anchor, never the anchor.
            seed: replace("crates/uaos-module-api/src/codec.rs", "            .and_then(|n| n.parent())\n", ""),
            runner: Runner::Program {
                program: "cargo",
                args: &["test", "-p", "uaos-module-api", "--test", "view", "a_strip_keeps_its_anchor_and_masked_content"],
            },
            expect: "a strip removed its own anchor",
        },
        Case {
            id: "strip-touches-masked",
            gate: "test",
            tool: None,
            // Fresh full review L3: roles come from the masked view, so a strip never touches masked content.
            seed: replace("crates/uaos-module-api/src/codec.rs", "            && !view.touches_masked(id)\n", ""),
            runner: Runner::Program {
                program: "cargo",
                args: &["test", "-p", "uaos-module-api", "--test", "view", "a_strip_keeps_its_anchor_and_masked_content"],
            },
            expect: "a strip touched masked content",
        },
        Case {
            id: "selector-unbudgeted",
            gate: "test",
            tool: None,
            // Fresh full review M2: resolution spends a visit budget and stops when it is spent.
            seed: replace("crates/uaos-module-api/src/selector.rs", "self.0 = self.0.checked_sub(n).ok_or(SelectorError::Budget)?;", "self.0 = self.0.saturating_sub(n);"),
            runner: Runner::Program {
                program: "cargo",
                args: &["test", "-p", "uaos-module-api", "--test", "view", "a_selector_stops_at_its_budget"],
            },
            expect: "a selector ran past its budget",
        },
        Case {
            id: "usage-undeclared-dimension",
            gate: "test",
            tool: None,
            // Fresh full review M3: usage names only the dimensions its codec declares.
            seed: replace("crates/uaos-module-api/src/codec.rs", "if self.dims.iter().all(|(name, _)| declared.contains(name)) {", "if true || self.dims.iter().all(|(name, _)| declared.contains(name)) {"),
            runner: Runner::Program {
                program: "cargo",
                args: &["test", "-p", "uaos-module-api", "--test", "view", "usage_reports_name_declared_dimensions_once"],
            },
            expect: "an undeclared billing dimension was accepted",
        },
        Case {
            id: "module-text-accepts-variation-run",
            gate: "language-neutrality",
            tool: None,
            // Fresh full review L4: runs of variation selectors carry invisible bytes; module text refuses them.
            seed: replace("crates/uaos-module-api/src/decl.rs", "            if selector && !after_base {\n", "            if false && selector && !after_base {\n"),
            runner: Runner::Program {
                program: "cargo",
                args: &["test", "-p", "uaos-module-api", "--test", "language_neutrality", "module_text_refuses_variation_runs"],
            },
            expect: "a variation-selector run was accepted",
        },
        Case {
            id: "failure-deny-after-the-fact",
            gate: "test",
            tool: None,
            // Fresh full review L5: a failure after forwarding cannot deny, so `Deny` there is refused at load.
            seed: replace("crates/uaos-module-api/src/manifest.rs", "if hook.on_failure == OnFailure::Deny && !hook.point.denies() {", "if false && hook.on_failure == OnFailure::Deny && !hook.point.denies() {"),
            runner: Runner::Program {
                program: "cargo",
                args: &["test", "-p", "uaos-module-api", "--test", "socket", "a_failure_cannot_deny_after_the_fact"],
            },
            expect: "a failure policy that cannot deny was loaded",
        },
        Case {
            id: "grant-memory-read-off-a-pocket",
            gate: "test",
            tool: None,
            // V1 review L4: a memory.read grant is on a pocket, and only memory.read grants are.
            seed: replace("crates/uaos-contracts/src/grant.rs", "if memory_read != source.is_some() {", "if false && memory_read != source.is_some() {"),
            runner: Runner::Program {
                program: "cargo",
                args: &["test", "-p", "uaos-contracts", "--lib", "memory_reads_and_pockets_go_together"],
            },
            expect: "a memory.read grant off a pocket validated",
        },
        Case {
            id: "cedar-cross-pocket-without-grant",
            gate: "test",
            tool: None,
            // V1 review M1, contract §6.2: only a grant, which carries consent, allows a cross-pocket read.
            seed: replace("crates/uaos-policy/src/engine.rs", "if asking.is_empty() && cross_pocket {", "if false && asking.is_empty() && cross_pocket {"),
            runner: Runner::Program {
                program: "cargo",
                args: &["test", "-p", "uaos-policy", "--test", "policy", "a_permit_alone_only_asks_for_a_cross_pocket_read"],
            },
            expect: "a permit allowed a cross-pocket read without consent",
        },
        Case {
            id: "cedar-own-pocket-read-asks",
            gate: "test",
            tool: None,
            // PR-4 scoped review F3: a read of the requesting pocket follows policy; no consent loop.
            seed: replace("crates/uaos-policy/src/model.rs", "self.action == Action::MemoryRead && self.resource != Resource::Pocket(self.pocket)", "self.action == Action::MemoryRead"),
            runner: Runner::Program {
                program: "cargo",
                args: &["test", "-p", "uaos-policy", "--test", "policy", "a_permit_alone_only_asks_for_a_cross_pocket_read"],
            },
            expect: "a read of the own pocket asked for consent",
        },
        Case {
            id: "grant-carried-ignored",
            gate: "test",
            tool: None,
            // ADR-0008 appendix §2 rule 4 (M4): only the grant a request carries can satisfy it.
            seed: replace("crates/uaos-policy/src/engine.rs", "                            && request.grant.is_none_or(|carried| g.id == carried)
", ""),
            runner: Runner::Program {
                program: "cargo",
                args: &["test", "-p", "uaos-policy", "--test", "policy", "only_the_carried_grant_allows_a_cross_pocket_read"],
            },
            expect: "the decision cited a grant the request did not carry",
        },
        Case {
            id: "grant-wire-drops-provider",
            gate: "test",
            tool: None,
            // ADR-0008 appendix §3 (M5): every grant goes to the wire and back unchanged. The
            // valid-by-construction property catches it: a fifth of its grants are model grants.
            seed: replace("crates/uaos-policy/src/wire.rs", "provider: wire_name(provider)?,", "provider: wire_name(model)?,"),
            runner: Runner::Program {
                program: "cargo",
                args: &["test", "-p", "uaos-policy", "--test", "policy", "every_valid_grant_loads_and_round_trips"],
            },
            expect: "a grant changed through the wire",
        },
        Case {
            id: "grant-unnamed-cross-pocket-allowed",
            gate: "test",
            tool: None,
            // ADR-0008 appendix §2 rule 4: a cross-pocket read that names no grant has none.
            seed: replace("crates/uaos-policy/src/engine.rs", "        if request.crosses_pockets() && request.grant.is_none() {\n            return Ok(Vec::new());\n        }\n", ""),
            runner: Runner::Program {
                program: "cargo",
                args: &["test", "-p", "uaos-policy", "--test", "policy", "only_the_carried_grant_allows_a_cross_pocket_read"],
            },
            expect: "a cross-pocket read naming no grant was allowed",
        },
        Case {
            id: "grant-own-pocket-unjournalable",
            gate: "test",
            tool: None,
            // PR-4b V1 review M1: only a cross-pocket grant carries an injection policy, so an own-pocket one can be journaled.
            seed: replace("crates/uaos-contracts/src/grant.rs", "let cross_pocket = memory_read && source != Some(self.pocket);", "let cross_pocket = memory_read;"),
            runner: Runner::Program {
                program: "cargo",
                args: &["test", "-p", "uaos-contracts", "--lib", "an_own_pocket_read_grant_carries_no_injection_policy"],
            },
            expect: "an own-pocket grant took an injection policy",
        },
        Case {
            id: "engine-loads-unjournalable-grant",
            gate: "test",
            tool: None,
            // PR-4b V1 review M2: the engine loads no grant the wire cannot journal.
            seed: replace("crates/uaos-policy/src/engine.rs", "        check_grant(grant).map_err(|e| PolicyError::Rule {", "        Ok::<(), crate::WireError>(()).map_err(|e| PolicyError::Rule {"),
            runner: Runner::Program {
                program: "cargo",
                args: &["test", "-p", "uaos-policy", "--test", "policy", "every_engine_grant_round_trips_through_the_wire"],
            },
            expect: "the engine loaded a grant the wire cannot hold",
        },
        Case {
            id: "grant-id-twice-loaded",
            gate: "test",
            tool: None,
            // PR-4b's V1 review L2: the engine refuses a grant id twice.
            seed: replace("crates/uaos-policy/src/engine.rs", "        if !ids.insert(grant.id) {\n", "        if !ids.insert(grant.id) && false {\n"),
            runner: Runner::Program {
                program: "cargo",
                args: &["test", "-p", "uaos-policy", "--test", "policy", "a_grant_id_twice_is_refused"],
            },
            expect: "a grant id was loaded twice",
        },
        Case {
            id: "grant-principal-ignores-fields",
            gate: "test",
            tool: None,
            // PR-4b's final review L1: a principal with no fields refuses any field.
            seed: replace("crates/uaos-contracts/src/grant.rs", "    Human {},\n", "    Human,\n"),
            runner: Runner::Program {
                program: "cargo",
                args: &["test", "-p", "uaos-contracts", "--lib", "humans_and_the_kernel_can_hold_grants"],
            },
            expect: "a principal took a field it does not have",
        },
        Case {
            id: "stop-admits-new-op",
            gate: "test",
            tool: None,
            // Runtime contract §3 rule 1: admission checks the stop first.
            seed: replace("crates/uaos-runtime/src/admission.rs", "        let watch = self.inner.stop.watch();\n        if let Some(refusal) = self.inner.stopped() {\n            return Err(refusal);\n        }\n", "        let watch = self.inner.stop.watch();\n"),
            runner: Runner::Program {
                program: "cargo",
                args: &["test", "-p", "uaos-runtime", "--test", "stop", "a_stopped_kernel_admits_nothing"],
            },
            expect: "a stopped kernel admitted an Operation",
        },
        Case {
            id: "stop-not-persisted",
            gate: "test",
            tool: None,
            // Runtime contract §3 rule 4: a journaled stop is honoured at boot.
            seed: replace("crates/uaos-runtime/src/stop.rs", "            state = BootState::Stopped(StopReason::from_code(code));\n", "            let _ignored = code;\n"),
            runner: Runner::Program {
                program: "cargo",
                args: &["test", "-p", "uaos-runtime", "--test", "stop", "a_journaled_stop_survives_a_restart"],
            },
            expect: "a journaled stop did not survive a restart",
        },
        Case {
            id: "admission-counts-requests",
            gate: "test",
            tool: None,
            // Runtime contract §4: admission counts bytes in flight, not only requests.
            seed: replace("crates/uaos-runtime/src/admission.rs", "            Some(total) if total <= self.inner.limits.max_bytes => {\n                used.operations += 1;\n", "            Some(total) if total <= u64::MAX => {\n                used.operations += 1;\n"),
            runner: Runner::Program {
                program: "cargo",
                args: &["test", "-p", "uaos-runtime", "--test", "stop", "admission_counts_bytes_in_flight"],
            },
            expect: "admission counted requests, not bytes",
        },
        Case {
            id: "relay-forwards-over-ceiling",
            gate: "test",
            tool: None,
            // Runtime contract §7.3: one unit over the reservation cuts.
            seed: replace("crates/uaos-runtime/src/relay.rs", "        if cost > self.ceiling {\n", "        if cost.get() > self.ceiling.get() + 1_000 {\n"),
            runner: Runner::Program {
                program: "cargo",
                args: &["test", "-p", "uaos-runtime", "--test", "relay", "one_unit_over_the_ceiling_is_never_forwarded"],
            },
            expect: "a usage report over the ceiling was forwarded",
        },
        Case {
            id: "relay-overrun-keeps-kernel-running",
            gate: "test",
            tool: None,
            // Runtime contract §7.4: an overrun engages the kernel stop.
            seed: replace("crates/uaos-runtime/src/relay.rs", "            let _engaged = self.stop.engage(StopReason::BudgetOverrun);\n", "            let _engaged = StopReason::BudgetOverrun;\n"),
            runner: Runner::Program {
                program: "cargo",
                args: &["test", "-p", "uaos-runtime", "--test", "relay", "an_overrun_stops_the_kernel"],
            },
            expect: "an overrun left the kernel running",
        },
        Case {
            id: "relay-ignores-stop",
            gate: "test",
            tool: None,
            // Runtime contract §3 rule 2: a live relay cuts at its next poll.
            seed: replace("crates/uaos-runtime/src/relay.rs", "    fn poll_stop(&mut self, cx: &mut Context<'_>) -> Option<StopReason> {\n", "    fn poll_stop(&mut self, cx: &mut Context<'_>) -> Option<StopReason> {\n        if cx.waker().will_wake(cx.waker()) {\n            return None;\n        }\n"),
            runner: Runner::Program {
                program: "cargo",
                args: &["test", "-p", "uaos-runtime", "--test", "relay", "a_stop_cuts_a_waiting_stream"],
            },
            expect: "a stop did not cut a waiting stream",
        },
        Case {
            id: "relay-keeps-upstream-after-cut",
            gate: "test",
            tool: None,
            // Runtime contract §7.4 rule 2: a cut drops the upstream before the body yields again.
            seed: replace("crates/uaos-runtime/src/relay.rs", "        self.ready.clear();\n        self.upstream = None;\n", "        self.ready.clear();\n"),
            runner: Runner::Program {
                program: "cargo",
                args: &["test", "-p", "uaos-runtime", "--test", "relay", "a_cut_drops_the_upstream_at_once"],
            },
            expect: "a cut kept the upstream",
        },
        Case {
            id: "relay-cut-ends-clean",
            gate: "test",
            tool: None,
            // Runtime contract §7.4 rule 3: without a terminal frame a cut ends in an error (red line 9).
            seed: replace("crates/uaos-runtime/src/relay.rs", "                    return Poll::Ready(Some(Err(RelayError::Cut(reason))));\n", "                    let _reason = reason;\n                    return Poll::Ready(None);\n"),
            runner: Runner::Program {
                program: "cargo",
                args: &["test", "-p", "uaos-runtime", "--test", "relay", "a_cut_without_a_terminal_frame_ends_in_an_error"],
            },
            expect: "a cut ended cleanly, as if the answer were complete",
        },
        Case {
            id: "relay-event-unbounded",
            gate: "test",
            tool: None,
            // Runtime contract §7.1: an event past its bound cuts (T11).
            seed: replace("crates/uaos-runtime/src/sse.rs", "            max_event,\n        }\n", "            max_event: usize::MAX,\n        }\n"),
            runner: Runner::Program {
                program: "cargo",
                args: &["test", "-p", "uaos-runtime", "--test", "relay", "an_event_past_its_bound_cuts"],
            },
            expect: "an event past its bound was forwarded",
        },
        Case {
            id: "sse-split-crlf-twice",
            gate: "test",
            tool: None,
            // Runtime contract §7.2: a CRLF split across two pieces is one line ending.
            seed: replace("crates/uaos-runtime/src/sse.rs", "            if next == b'\\n' {\n                i += 1;\n            }\n", ""),
            runner: Runner::Program {
                program: "cargo",
                args: &["test", "-p", "uaos-runtime", "--test", "relay", "any_chunking_relays_the_same_bytes_and_events"],
            },
            expect: "the relay saw different events than an event-stream parser",
        },
        Case {
            id: "unbounded-channel",
            gate: "clippy",
            tool: None,
            // Runtime contract §8, PD-19: every channel is bounded.
            seed: append(
                "crates/uaos-runtime/src/lib.rs",
                "\n/// Seeded.\npub fn seeded_violation() {\n    drop(tokio::sync::mpsc::unbounded_channel::<()>());\n}\n",
            ),
            runner: CLIPPY,
            expect: "tokio::sync::mpsc::unbounded_channel",
        },
    ]
}

/// Outcome of one case.
enum Outcome {
    Proven,
    Skipped(String),
    /// The case is for another operating system.
    Elsewhere(&'static str),
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
    let mut elsewhere = 0usize;
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
            Outcome::Elsewhere(os) => {
                println!("  NOT HERE {:<30} runs on {os} only", case.id);
                elsewhere += 1;
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
            "xtask negative: every exercised gate bites ({} skipped for missing tools, {elsewhere} for another system)",
            skipped.len()
        );
        Ok(())
    } else {
        Err(format!("gate self-test failed:\n  {}", failures.join("\n  ")))
    }
}

fn run_case(case: &Case, root: &Path, base: &Path, shared_target: &Path) -> Outcome {
    match case.tool {
        Some(UNIX_ONLY) if !cfg!(unix) => return Outcome::Elsewhere("Unix"),
        Some(WINDOWS_ONLY) if !cfg!(windows) => return Outcome::Elsewhere("Windows"),
        Some(tool) if tool != UNIX_ONLY && tool != WINDOWS_ONLY && !tool_available(tool) => {
            return Outcome::Skipped(format!("`{tool}` not installed"));
        }
        _ => {}
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

#[cfg(test)]
mod tests {
    use super::replace;

    /// A seed anchor names exactly one site: one that also matched elsewhere would seed the first
    /// match, which may not be the case's site (review WP3.A1, round 10; WP3.A5, round 12).
    #[test]
    fn a_seed_anchor_must_occur_exactly_once() {
        let dir = std::env::temp_dir().join(format!("uaos-xtask-seed-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("f.rs"), "a\nb\na\n").unwrap();
        assert!(replace("f.rs", "b\n", "c\n")(&dir).is_ok());
        let twice = replace("f.rs", "a\n", "x\n")(&dir).unwrap_err();
        assert!(twice.contains("occurs 2 times"), "{twice}");
        let missing = replace("f.rs", "zzz", "y")(&dir).unwrap_err();
        assert!(missing.contains("not found"), "{missing}");
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
