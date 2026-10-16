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
                "        if self.attached.load(Ordering::SeqCst) {",
                "        if false && self.attached.load(Ordering::SeqCst) {",
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
                    "            store.keep_refused(pocket, chunk);\n",
                    "",
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
                "            store.keep_refused(pocket, chunk);\n",
                "",
            ),
            runner: Runner::Program {
                program: "cargo",
                args: &["test", "-p", "uaos-state", "--test", "durability", "r6_l2_a_put_during_a_shred_whose_flush_fails_does_not_lift_the_refusal"],
            },
            expect: "whose shred record is durable",
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
