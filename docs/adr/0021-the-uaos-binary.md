# ADR-0021: The `uaos` binary: composition root and command surface

**Status:** Proposed (opened 2026-10-22; earliest decision 2026-10-24, 48 h; D-41). Three of its choices were decided by the maintainer on 2026-10-22: D-38, D-39 and D-40 (§7) · **Refs:** CLAUDE.md §3 (single async binary), §4 (single binary, commands, `uaos doctor`), C-01, C-02, C-06, C-60; plan v2 WP3.6, WP3.7 · **Builds on:** ADR-0010, ADR-0012, ADR-0013, ADR-0019

## Context

RC-1 promises that unmodified coding agents point at UAOS with a base URL, or run under
`uaos run --` (roadmap, "What RC-1 means"). Nothing yet assembles the kernel crates into a
program. `arch.toml` declares `crates/uaos` as the composition root and `uaos-api` beneath it, but
neither crate exists. This ADR fixes the binary's boundary, process model, command surface,
configuration, security boundary, build and proof, so that WP3.6 and WP3.7 build against one
contract.

## Decision

1. **Boundary.** One executable, `crates/uaos`, in Ring 0. It is the only crate that wires the
   kernel together, within its `arch.toml` allow list: the kernel crates, `uaos-api`, and the
   Ring 1 dialect modules (`mod-anthropic`, `mod-openai`, `mod-mock`), linked in-process.
   - The list leaves out `uaos-egress`, so the binary never names the network door. Network use
     from the CLI, such as `doctor --online`, is a runtime Operation (review WP3.A5 M1).
   - The binary holds no `unsafe`; OS-specific code stays behind `uaos-platform` (ADR-0012).
2. **Process model.** One tokio runtime; the supervisor is the only spawner (ADR-0010).
   - `serve` runs the kernel, with `uaos-api` bound to loopback.
   - Other commands reach a running kernel through the control API. Without one, only read-only
     commands open the data directory.
   - One kernel per data directory, held by a lock.
   - Ctrl-C or SIGTERM triggers the kernel stop: admission closes, in-flight Operations settle,
     and the journal flushes. `kill -9` is covered by the journal and boot recovery.
3. **Commands.**

   | Command | Purpose | Needs | Slice |
   |---|---|---|---|
   | `init` | Data directory, pocket keys in the OS keychain, a default config without secrets | — | B1 |
   | `doctor [--online]`, `status`, `journal verify\|export`, `key add\|list\|revoke\|rotate` | Health, diagnostics, provider keys into the keychain | — or a running kernel | B1 |
   | `serve` | The kernel: Anthropic Messages and OpenAI Responses ingress, the `/v1` control API | — | B2 |
   | `run -- <cmd…>` | Launch an agent with the base-URL variables and a scoped sub-key that lives as long as the child; pass back the child's exit code. Master keys never reach the child | a running kernel | B3 |
   | `approvals …`, `stop`, `resume` | Approvals and resume need presence (ADR-0012) | a running kernel, presence | B3 |
   | `trace <op>`, `pricing`, `budget explain`, `policy explain` | Explanations | a running kernel | B4 |

   - Every read command has `--json` output with a versioned schema.
   - Exit codes follow the unified error classes, with distinct codes for denied, blocked and
     unreachable.
   - The default pocket for `uaos run` is D-27's.
4. **Configuration.**
   - A per-OS data directory (XDG base directories, `%LOCALAPPDATA%`, Application Support),
     readable only by its user.
   - A TOML config with a `config_version`. Precedence: flags, then `UAOS_*` environment
     variables, then the file, then defaults.
   - One config snapshot is pinned per Operation, and boot checks for drift.
   - The config holds keychain references, never secrets.
5. **Security boundary.**
   - Loopback bind only, a per-install token kept in the keychain, and Host and Origin checks
     (DNS rebinding, CSRF).
   - Peer credentials and presence for approvals (ADR-0012).
   - No tool execution and no telemetry at RC-1. Zero egress in the default configuration,
     counted by the door.
   - Panics unwind through a redacting hook; logs are structured and redacted.
6. **Build.**
   - `cargo build -p uaos --release --locked`.
   - Release profile: `panic = "unwind"` (module panic containment, PR-9), LTO,
     `codegen-units = 1`, stripped symbols with debug info kept separately.
   - Targets: Linux x86_64 and aarch64, Windows MSVC, macOS x86_64 and arm64.
   - `cargo auditable`, a CycloneDX SBOM, checksums and `SOURCE_DATE_EPOCH` (WP3.9). Signing once
     D-19 is done; attestations once D-22 is done. RC-1 ships a tarball and `cargo install`;
     installers come in P8.
   - `[CONSCIOUS ASSUMPTION]` Budgets, measured in B1 and then fixed here: at most 30 MB
     stripped, cold start to ready within 300 ms, idle memory at most 50 MB. Install to first
     value within 3 minutes is an RC-1 bar.
7. **Placement and order** (decided by the maintainer on 2026-10-22):
   - **D-38.** The binary is P3·M3 (WP3.7), part of Kernel RC-1. The roadmap keeps its
     numbering: P4 is Surface.
   - **D-39.** B1, the skeleton, is built early, with PR-7. B2 to B4 follow WP3.6 (`uaos-api` and
     presence).
   - **D-40.** `uaos shell-init` is deferred to P4. At RC-1, shell integration is `uaos run --`.

## Alternatives rejected

- **A daemon and a separate CLI:** two artifacts to sign, version and install, against the
  single-binary rule (CLAUDE.md §4).
- **The binary depending on `uaos-egress` directly:** the door would gain a second owner, which
  ADR-0013 and the allow list rule out.
- **Building every slice now:** without PR-7's pipeline and M2's dialects, the binary has no
  request path to serve.

## Consequences

- `arch.toml` already lists the crate. B1 creates it with the commands that need no request path.
- `empty-kernel`, `surface` and `kernel-tokens` must hold with the binary in the workspace.
- The CLI's text, exit codes and `--json` output become a contract (`cli-contract`), so changes
  to them are reviewed like schema changes.

## Threat and privacy note

- **Local API takeover:** a loopback bind, a token, and Host and Origin checks. Approvals need
  presence and the peer's credentials.
- **Keys reaching a child process:** `run --` passes a scoped sub-key, revoked when the child
  exits. Master keys never enter the child's environment.
- **The data directory:** created readable only by its user; `doctor` reports wider permissions.
- **The binary itself:** checksums and an SBOM at RC-1, and signing once D-19 is done.
- **Privacy:** no telemetry and zero egress by default. `doctor --online` contacts a provider only
  when asked, as an Operation.

## Verification

- **Gates:** `empty-kernel`, `surface` and `kernel-tokens` active; `arch` keeps
  `arch-bin-depends-on-egress`. New: `cli-contract` (snapshots of the help text, exit codes and
  `--json` output), `bin-budget`, and `install-time` on a fresh VM (WP3.8).
- **Seeded negatives:** `serve-binds-non-loopback`, `api-accepts-missing-token`,
  `api-accepts-foreign-origin`, `run-passes-master-key`, `run-key-outlives-child`,
  `resume-without-presence`, `doctor-online-bypasses-door`, `config-holds-secret`.
- **End to end:** `uaos run --` with a mock agent, through the pipeline to the loopback mock, on
  three systems; `kill -9` during `serve`, then a restart that recovers.
