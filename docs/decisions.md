# Decision register

Open decisions, their class, their default and their deadline. A decision that the next release
depends on carries a pending-decision marker, the token `cargo xtask decisions` searches for. That
command lists the markers on every merge, and `--release` makes it fail while any remain.
Decisions due in later phases are listed without a marker; it is added when their phase starts.

**Classes**
- **R, reversible:** decided within 24 hours. If unanswered by its deadline, it takes the recorded
  default, which is logged as a conscious assumption with a way back.
- **E, expensive:** 48 hours, an ADR, a threat/privacy note and a test plan. Never defaults.
- **RL, red line, money, external identity or external contact:** the maintainer's alone. Never
  defaults, and nothing is bought, created, moved or spent without an explicit decision.

Merges, publishing, spending and repository-setting changes never default, whatever the class.

## Due before the RC-1 release

| ID | Class | Decision | Recommended default | Deadline | Marker |
|---|---|---|---|---|---|
| D-08 | RL | Dedicated conduct address | A project mailbox once a legal entity or organisation exists | overdue (week 1) | in `GOVERNANCE.md` |
| D-06 | E | Ingress from containers and WSL | Off; a Unix socket or named pipe first | P3 | PENDING-DECISION(D-06) |
| D-15 | R | Pricing updates | Manual; automatic updates opt-in | P3 (WP3.5) | PENDING-DECISION(D-15) |
| D-24 | E | Final-scan caching | Scan every byte; caching only with an equivalence proof and under budget pressure | WP3.8 | PENDING-DECISION(D-24) |
| D-27 | R | Default pocket for `uaos run` | Project root; budget pools bound explicitly, never by pocket inference | WP3.7 | PENDING-DECISION(D-27) |
| D-28 | E | Endpoint handling | Three classes, governed / metadata / denied, from a captured inventory | 72 h gate | PENDING-DECISION(D-28) |
| D-31 | E | Review convergence (proposed 2026-10-19 after 14 and 18 review rounds on two PRs): one fresh full review, fixes, one scoped round over the fix diff and every invariant and caller it touches, then a final fresh full review before a PR leaves draft. A PR still holding a High or a Medium after round 5 is split. A Low is fixed, or accepted one at a time into its review's debt table with an owner and a phase | Adopt; the maintainer records it in `GOVERNANCE.md` | Before the next PR leaves draft | PENDING-DECISION(D-31) |
| D-32 | E | Chunk storage format before the RC-1 freeze: one file per chunk, or pack files if they are what brings macOS balanced-put p99 (6.85 ms) under ADR-0018's 0.5 ms | Keep one file per chunk unless a spike proves the pack format meets 0.5 ms with per-pocket shred intact; then an ADR-0018 and ADR-0007 amendment | Before the runtime spine (PR-6) | PENDING-DECISION(D-32) |
| D-33 | E | Which machine judges per-stage budgets and `perf-smoke`: the reference machine, the CI runners, or a dedicated runner | The reference machine judges stage budgets; CI runners are reported, labelled by environment, until a dedicated runner exists | WP3.8 | PENDING-DECISION(D-33) |
| D-34 | RL | Book the external security audit and the legal review (provider terms of service, licensing, user data, community funding) for the RC-1 evidence window, and start the search for a second reviewer | Start contacts now; lead times run to weeks | Now | PENDING-DECISION(D-34) |
| D-29 | E | Compressed streams | Relay compressed bytes untouched when nothing must be observed; request `accept-encoding: identity` upstream only when the stream must be observed or rewritten (rehydration, the binding-mismatch SLI, loop detection). From the Claude Code capture, CAP-9 | WP3.4 | PENDING-DECISION(D-29) |
| D-30 | E | Coverage-guided fuzzing of `uaos-json` (and later the journal reader) | cargo-fuzz in an isolated `fuzz/` workspace: not a member, never shipped, its own lockfile; a pinned nightly toolchain in the nightly lane only (Linux); NCSA allowed for `libfuzzer-sys` alone through a scoped `deny.toml` exception; property fuzzing on every merge stays. Contract: `docs/adr/appendix/0014-uaos-json-tape.md` §9 | WP3.A2 | PENDING-DECISION(D-30) |

## Later phases (no marker yet)

| ID | Class | Decision | Recommended default | Phase |
|---|---|---|---|---|
| D-17′ | RL | Subscription pass-through: the client keeps its own login and UAOS only forwards it | Off and legal-gated. A focused terms-of-service review runs in the RC-1 evidence window. RC-1 ships with it off, so RC-1 does not depend on it | ToS review |
| D-05 | R | Panel framework | Svelte + TypeScript, re-checked against the dependency-audit burden | P4 |
| D-11 | R | Telemetry | Opt-in, with a preview of the exact payload | P4 |
| D-04 | E | Windows exec before its sandbox backend is proven | Human-approved with user presence, never autonomous; WSL2 documented | P5 |
| D-02 | E | Encrypted search for notes and Obsidian | A bounded in-memory index rebuilt at unlock | P6A |
| D-10 | R | Tag identifiers | ASCII canonical IDs with Turkish and English aliases | P6 |
| D-07 | RL | Commercial modules at GA | They trail GA | before P7 |
| D-16 | E | Default trust mode | Same-user with honest claims; hardened mode as a GA option | P7 |
| D-13 | RL | Several keys of one provider | Rejected for evading limits; it would also break account-bound reasoning | GA legal gate |

## Decided

| ID | Decision | Where |
|---|---|---|
| D-01 | RC-1 dialects: Anthropic Messages and OpenAI Responses (stateless); Chat Completions in RC-2 | ADR-0005 |
| D-03 | Pipeline order: detect, route over permitted candidates, authorize, reserve, transform, final scan | ADR-0002 |
| D-09 | The private vision document stays out of the public repository; the traceability matrix is public | `docs/traceability.md` |
| D-12 | The repository path keeps its space; CI builds from a path with spaces and non-ASCII characters | `paths` gate |
| D-14 | Policy engine: Cedar with evaluation errors denied | ADR-0008 |
| D-18 | Default durability mode: balanced, W = 50 ms | ADR-0003 |
| D-25 | `kernel-tokens` gate moves from P2 to P3 | ADR-0002 amendment, ADR-0010 |
| D-19 | Code signing as an individual: an OV/EV certificate and an Apple Developer ID. The maintainer registers and buys; until then RC-1 ships with attestations and checksums | `docs/release/signing-and-identity.md` (2026-10-13, reaffirmed 2026-10-14) |
| D-20 | Merge review rule with one maintainer: platform-enforced merges (a ruleset with no bypass), an adversarial review per work package, a selective 24 h cool-off | ADR-0019 (accepted by the maintainer 2026-10-15; ruleset id 25183857 applied the same day) |
| D-26 | HTTP stack: tokio, hyper 1 directly and rustls on aws-lc-rs; no reqwest or axum at RC-1 | ADR-0013 (accepted by the maintainer 2026-10-15) |
| D-21 | Live-provider lane: both providers, CI-only keys with spend caps, a protected `live-providers` environment that only `main` reaches | `docs/release/signing-and-identity.md`, `.github/workflows/live.yml` (2026-10-13, reaffirmed 2026-10-14) |
| D-22 | Repository identity frozen as `uaos-project/uaos`, moved before WP3.9 | `docs/release/signing-and-identity.md` (2026-10-13, reaffirmed 2026-10-14) |
| — | Grants satisfy ask policies and never override a forbid | ADR-0008 Amendment 1 (2026-10-14) |
