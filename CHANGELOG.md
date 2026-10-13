# Changelog

All notable changes are recorded here. Format: [Keep a Changelog](https://keepachangelog.com/en/1.1.0/);
versions follow [Semantic Versioning](https://semver.org). Contract (schema) changes must appear
here in the same change that alters `schemas/` (docs-with-contract gate).

## [Unreleased]

### Added

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
