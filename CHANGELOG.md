# Changelog

All notable changes are recorded here. Format: [Keep a Changelog](https://keepachangelog.com/en/1.1.0/);
versions follow [Semantic Versioning](https://semver.org). Contract (schema) changes must appear
here in the same change that alters `schemas/` (docs-with-contract gate).

## [Unreleased]

### Changed

- `dco` gate: merge commits whose combined diff is empty (GitHub's "Update branch", conflict-free
  `git merge`) add no content and are exempt. A merge that resolves a conflict with new content
  still needs a sign-off. This is proven by the new negative case `dco-unsigned-content-merge`.
  The rule was missing; that is why PR #10 failed on an "Update branch" commit.
- CI: `dco` and `docs-sync` now run on pushes to `main` and on merge queues as well as on pull
  requests. Before this, a direct push skipped both (plan v2 PD-17). A missing base commit fails
  the job instead of guessing a range.

- Phase-debt records sweep (plan v2 PD-03, -04, -07, -08, -09, -15, -23):
  - **ADR-0003** now records the measured Windows spike numbers. It states that the Linux, macOS
    and production-journal numbers are owed (PD-01). The spike report moved to
    `docs/adr/appendix/`.
  - **ADR-0002** is amended: the `kernel-tokens` gate activates in P3, not P2, because the tokens
    bind policy, ledger and egress, which first meet in the runtime. `gates.toml` follows.
  - **CODEOWNERS** now covers every Ring 0 crate, the build inputs (`Cargo.toml`/`.lock`,
    toolchain, `.cargo/`), the ADRs, the threat model, the privacy docs and CODEOWNERS itself.
  - **README** describes the real state (P2) and names the gate behind each claim.

### Security

- `uaos-redact`: `FinalScanner`'s derived `Debug` printed its known-secret automaton, from which
  a vault secret could be reconstructed exactly. This was found by the retroactive review
  (`docs/reviews/WP2.3-redact.md`, H1) and breaks red line 2. `FinalScanner`, `DetectorSet` and
  the crate-private JSON scanners now have manual `Debug` implementations that show only the
  version, counts and lengths. A canary test proves no 4-byte window of a vault secret reaches
  `{:?}` or `{:#?}`; against the old code it fails on a 7,741-byte dump. The review's other
  findings (URL passwords with `/#?'`, fail-open glue and length bounds, nested JSON, encodings,
  a PEM slowdown) are open and come in the next change.

### Added

- `docs/decisions.md`: a register of open decisions with class, default and deadline. Decisions
  the next release depends on carry markers, so `xtask decisions --release` sees them.
- `docs/roadmap.md` (public roadmap), `docs/rfcs/` (process and template), `MAINTAINERS.md` (with
  the single-maintainer risk stated), `docs/research/name-check.md`.

<<<<<<< HEAD
<<<<<<< HEAD
<<<<<<< HEAD
- Proposed ADRs (48 h review windows open):
  - **ADR-0011:** scoped credentials (`uaos_sk_`), a hierarchy with decidable scope containment,
    epoch revocation and a guard against restoring an older data directory.
  - **ADR-0012:** approvals need an OS presence ceremony; peer-credential and containment checks
    are defence in depth; the first `unsafe` code comes with obligations.
  - **ADR-0019:** merge integrity with one maintainer: a ruleset with no bypass, an adversarial
    review per work package, and a selective 24 h cool-off.

- `journal-ack-bench` (uaos-testkit) and a nightly `ack-latency` job on Linux, macOS and Windows.
  They measure the production journal's acknowledgement latency (balanced, strict, group flush)
  and the chunk store's per-chunk write (plan v2 PD-01), and the table goes to the run summary.
  First local run (Windows 10, entry-level NVMe):

  | Series | p99 | Other |
  |---|---|---|
  | Balanced ack | 29 µs | |
  | Strict ack | 0.91 ms | |
  | Group flush | 0.68 ms | |
  | New 4 KiB chunk | 3.5 ms | p99.9 11.9 ms |

  The chunk path is the evidence behind PD-18 / ADR-0018: per-chunk flushes do not fit the
  overhead budget. First CI run on all three OSes, recorded in
  `docs/adr/appendix/0003-ack-latency-2026-10-13.md`:
  - balanced-ack p99 is 7.2 µs on Linux, 12.2 µs on macOS and 13.8 µs on Windows (H1 holds);
  - the slowest group flush is 29.5 ms (p99.9), so W = 50 ms stands;
  - a new chunk costs **28.5 ms at p99 on macOS**, more than the entire 25 ms overhead SLO.

||||||| parent of e8f2691 (Gate hardening I: allow-audit, vet-ratchet and claims-lint)
=======
- Three merge gates, each proven to bite by seeded violations (plan v2 PD-06, PD-19, V6):
  - **`allow-audit`** finds every `#[allow]`/`#[expect]` of `unsafe_code`,
    `clippy::disallowed_methods` or `clippy::disallowed_types`, including multi-line and
    `cfg_attr` forms, and skipping literals and comments. It fails unless the file is under an
    owner path in `arch.toml [allow_audit]`. Today 17 allows exist, all owned; `unsafe_code` has
    no owner.
  - **`vet-ratchet`**: cargo-vet exemptions without a `notes` reason may not grow past the
    baseline (233). When the count drops, the baseline must be lowered in the same change.
  - **`claims-lint`**: forbidden claim words ("perfect", "zero loss", "tamper-proof",
    "unobtainable", ...) fail in public documents unless quoted, negated or explicitly exempted
    with a reason.
- `docs/claims.md`: the registry of public claims and the gates behind them.

>>>>>>> e8f2691 (Gate hardening I: allow-audit, vet-ratchet and claims-lint)
||||||| parent of bf7e3b2 (Propose P3 ADRs 0010, 0013, 0014, 0017, 0018)
=======
- Proposed ADRs for P3 (48 h review windows open):
  - **ADR-0010:** kernel tokens: a pipeline typestate in a private runtime module, plus
    reachability enforced by `arch.toml`, a `surface` check and a Ring 1 closure ban.
  - **ADR-0013:** tokio with hyper and rustls directly; no reqwest or axum; egress owns name
    resolution.
  - **ADR-0014:** codecs describe structure with declarative selectors over a kernel-owned
    view, and the kernel performs every edit; new Ring 0 crate `uaos-json`.
  - **ADR-0017:** rehydration is a policy-gated action with a recorded round trip and a
    per-session known-secret matcher.
  - **ADR-0018:** chunks join the journal's durability classes. One new chunk costs 28.5 ms
    at p99 on a macOS runner today.

>>>>>>> bf7e3b2 (Propose P3 ADRs 0010, 0013, 0014, 0017, 0018)
||||||| parent of ead8d14 (Gate hardening II: evidence freshness, xtask quick, nightly mutants)
=======
- `cargo xtask evidence [--candidate <rev>] [--streak N] [--max-age-hours H]` (plan v2 V5). It
  checks the nightly runs on `main`. The newest must be green, at most 48 h old, and ran on
  code identical to the candidate in `crates/`, `xtask/`, the manifests and the toolchain file.
  `--streak N` requires N consecutive such nights (counted by date, not by run). No evidence
  is an error, never a pass. It is listed in RELEASING.md with `--streak 7`.
- `cargo xtask quick` (PD-22): fmt, clippy, unit tests (`--lib --bins`, without the long
  simulations) and the local structural checks; about 10 s on a warm cache.
- Nightly `mutants` job (V4): cargo-mutants 27.1.0 on uaos-policy, uaos-ledger, uaos-redact and
  uaos-state, with caught, missed and timed-out counts and the missed list in the run summary.
  It is report-only until a per-crate baseline exists; a failing unmutated baseline still fails
  the job.

>>>>>>> ead8d14 (Gate hardening II: evidence freshness, xtask quick, nightly mutants)
- P2 WP2.3 — `uaos-redact` (ADR-0009): schema-agnostic secret detection and redaction with a
  fail-closed final scan. Detector set v1 covers 11 high-risk classes:
  - private keys, JWTs;
  - Anthropic, OpenAI, Google and AWS keys;
  - GitHub, GitLab and Slack tokens, Slack webhooks;
  - Stripe keys;
  - URL passwords.

  Detector sets are versioned and pinned per session. Every JSON string (keys, unknown fields,
  any depth) is scanned after decoding escapes, and placeholders are spliced into the original
  bytes; clean content passes byte for byte. Placeholders `[REDACTED:<class>:<hmac tag>]` are
  stable per pocket across turns and restarts. Redaction is a fixpoint (`redact∘redact = redact`).
  `FinalScanner` blocks on any detection, any known vault secret or any scanner failure.
  `redaction-corpus` gate **active**: synthetic corpus v1 (3,000 positives per class, 100,000 hard
  negatives, generated at test time) shows 0 misses and 0 false positives. Recall is bound to the
  claimed formats and this corpus; it is not a real-world rate. The gate is proven to bite by a
  detector set that drops one AWS prefix. Measured on 1.7 MB (about 400k tokens): full-body
  redaction p50 4.7 ms, final scan p50 4.7 ms.
- P2 WP2.2 — `uaos-ledger`: pools, reservations, settlement, transfers and a structural hard cap
  in integer nano-USD (float arithmetic denied). A reservation beyond the available balance is
  refused before anything is recorded. Reservations are typestate tokens: `Held` can be released;
  once `begin` makes it `InFlight` it can only be settled (releasing it does not compile). A
  reservation id is single-use, so no duplicate token can exist. Every entry is recorded (journal
  `budget.entry`, critical) before it takes effect. A recording failure poisons the ledger until it
  is replayed from the journal. Recovery settles open reservations at full cost, marked estimated,
  and never releases them; it also completes partial settlements and half-recorded transfers.
  `budget-concurrency` gate **active**: a model-checked simulation runs 256 schedules per merge and
  100,000 nightly (16.7 s locally), covering crashes and recording failures before and after the
  write. Contended threads and the journal round trip are also tested. A seeded ledger that skips
  the cap check proves the gate bites. Required behavior `budget-double-spend` is active.
- Contract (non-breaking): `uaos.budget_tx/1` gains optional `counterparty_pool`, required by
  `validate()` for `transfer_out`/`transfer_in` (`BudgetTxError::MissingCounterparty`), so recovery
  can complete a half-recorded transfer. New kernel event type `budget.entry`.
- P2 WP2.1 — `uaos-policy`: the reference monitor over Cedar (ADR-0008). Default deny; fail
  closed on any evaluation, request or entity validation error (Cedar alone would skip an erroring
  forbid); `Deny > Ask > Allow` via a validated `@effect("ask")`; strict loading (unique `@id`,
  known annotations only, strict schema validation against `uaos.cedarschema`); time-bounded
  grants compiled into scoped permits; per-action slicing proven decision-preserving; explanations
  for every decision. 1,000 policies: p99 662 µs.
- P1 WP1.6 — `journal-durability` gate **active**: `uaos-testkit` (dev-only) kills the production
  journal in a real process at random acknowledgement counts and random times, and verifies every
  acknowledged record by sequence and hash. 40 kills per OS per merge, 10,000 per OS nightly
  (new `nightly` workflow, which also runs the 20,000-scenario crash simulation). The gate is
  proven to bite by a seeded journal that acknowledges without writing. Required behavior
  `disk-full` is active.
- P1 WP1.5 — OS keychain (ADR-0007): `uaos-platform::keychain` (`OsKeychain` over keyring-core with
  an explicitly passed native store — Windows Credential Manager, macOS Keychain, Secret Service
  over pure-Rust zbus — and a fault-injecting `SimKeychain`); `KeychainKeyring`, the production
  `PocketKeyring`, with crash-safe rotation/retirement ordering and an in-memory key cache.
  Conformance suites run against simulated and (on Windows/macOS CI) real keychains.
  **Not yet implemented:** the headless passphrase vault of ADR-0007 §3; until it lands, hosts
  without a keychain fail loudly with `UAOS-STORE-0003`.
- P1 WP1.4 — `uaos-state::projection`: SQLite (bundled, WAL) projections of the journal —
  event index, operation states, cursor — holding metadata only. `catch_up` continues from the
  cursor and rebuilds automatically when the cursor no longer matches the journal (another
  journal, rewritten history, damaged cache). Queries: operation state, correlation trace,
  open intents (the input of crash recovery). Property test: incremental maintenance across
  journal crashes equals a rebuild from scratch, compared by canonical dump.
- P1 WP1.3 — `uaos-state::chunks`: encrypted, content-addressed chunk store. References are
  `HMAC-SHA-256(pocket key, content)` (deduplicated per pocket, unlinkable across pockets);
  every chunk has a random AES-256-GCM data key, context-bound to pocket and reference, wrapped
  by a versioned pocket KEK. Writes are atomic and durable before acknowledgement. Shredding
  rotates the KEK first, deletes, re-wraps survivors and destroys old versions, so restored
  backups of a shredded key are useless; an interrupted rotation is finished on open.
  `PocketKeyring` interface with an in-memory double (OS keychain in WP1.5).
- `uaos-platform::crypto`: `SecretKey` (zeroized, never printed), HMAC-SHA-256, AES-256-GCM.
- Error registry: `STORE` domain (`UAOS-STORE-0001..0003`).
- `SimFs::fail_sync_after(n)` to aim a flush fault at a specific step.
- P1 WP1.2 — `uaos-state` journal core: append-only `uaos.event/1` segments chained over exact
  line bytes from a per-journal genesis; atomic manifest with sealed/suspect/active segments;
  one-daemon-per-data-directory lock; crash recovery that verifies the whole chain, flushes
  before sealing, quarantines orphan segments and never appends after a torn tail; balanced
  (W = 50 ms) and strict flush policies; failed flushes rewritten to a fresh segment, never
  retried in place; disk-full and write failures fail closed until `recover()`; explicit
  `JournalHealth`. Deterministic simulation (crash, power loss, failed flush, disk full) runs
  256 scenarios per merge and 20,000 per policy in a deep sweep, all passing.
- `uaos-platform::crypto`: SHA-256 via aws-lc-rs (ADR-0006: prebuilt NASM objects on Windows).
- P1 WP1.1 — `uaos-platform::fs`: the filesystem boundary for durable stores (append-only
  files, atomic replace, rename, remove, directory sync, exclusive lock). `OsFs` wraps `std::fs`
  (lock via `File::try_lock`, released by the OS if the holder dies); `SimFs` models process
  crash vs power loss, torn writes on disk-full, and failed flushes that drop unflushed bytes.
  One conformance scenario runs against both.
- P0 Bedrock: workspace, pinned toolchain (1.98.1), lint policy (clippy pedantic + restriction
  set, architecture bans in `clippy.toml`), supply-chain policy (`deny.toml`, cargo-vet with
  imported audit sets).
- `uaos-contracts`: typed UUIDv7 identifiers with entity prefixes; canonical decimal-string
  64-bit wire integers; integer nano-USD money; RFC 3339 UTC time; algorithm-tagged digests
  (`sha256:`, `hmac-sha256:`); the Operation lifecycle state machine (non-compensable effects can
  never be reported as compensated; `Indeterminate` only via crash recovery); the unified error
  registry; bounded event envelope.
- Contract schemas: `uaos.event/1`, `uaos.error/1`, `uaos.budget_tx/1` (draft until RC-1),
  `uaos.operation/1`.
- `uaos-platform`: `Clock`, `Rng` and `IdSource` with real and deterministic-simulation
  implementations.
- `xtask`: `ci`, `arch-check`, `schemas`, `schema-check` (drift and breaking-change detection),
  `headers`, `gates`, `decisions`, `dco`, `docs-sync`, and `negative` (gate self-test).
- Governance: LICENSE (Apache-2.0), NOTICE, README, CONTRIBUTING, SECURITY, CODE_OF_CONDUCT
  (Contributor Covenant 2.1), GOVERNANCE, RELEASING, ADR-0001–0005, threat model v0, privacy
  data flow v0, vision traceability matrix.

