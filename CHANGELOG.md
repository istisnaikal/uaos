# Changelog

All notable changes are recorded here. Format: [Keep a Changelog](https://keepachangelog.com/en/1.1.0/);
versions follow [Semantic Versioning](https://semver.org). Contract (schema) changes must appear
here in the same change that alters `schemas/` (docs-with-contract gate).

## [Unreleased]

### Added

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
