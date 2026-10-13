# ADR-0007: Where keys live, and what "shredded" honestly means

**Status:** Accepted (2026-10-13) · **Plan refs:** D6, D11, D18, T2, T12 · **Builds on:** ADR-0003 §5–6

## Context

WP1.3 made content deletable by crypto-shredding: a chunk's data key is wrapped by a versioned
pocket KEK, and shredding destroys the old KEK versions. That guarantee is only as strong as the
place the KEKs live. If a destroyed KEK can be reconstructed from anything that survives on disk
(a remnant of a rewritten file, a backup), the shred was cosmetic.

Two designs were considered:

- **A. Pocket keys directly in the OS keychain**: one keychain entry per pocket content key and
  per KEK version; retiring a version deletes its entry.
- **B. One master key in the keychain, pocket keys wrapped by it in a data-directory file.**
  Retiring a version rewrites the file. A disk image holding an old copy of that file, plus the
  still-live master key, would recover the "destroyed" KEK. Closing that hole means rotating the
  master key on every shred, which is more code for the same assumptions as A.

## Decision

1. **A: pocket keys live in the OS keychain.** Entries are named
   `service = "uaos"`, `account = "<installation id>/pocket/<pocket id>/cas"` and
   `".../kek/<version>"`. Retiring deletes the entry. Keys are cached in process memory as
   zeroizing `SecretKey`s after first use, so the keychain is not hit per chunk.
2. **Backends**, chosen per target, through `keyring-core` 1.x with explicit stores: Windows
   Credential Manager, Apple Keychain, and Secret Service over pure-Rust zbus on Linux. The store is
   **passed explicitly** to the keyring, never installed as keyring-core's process-global default
   (no hidden state).
3. **Headless fallback** (no Secret Service, e.g. servers and CI): an encrypted file vault keyed by
   Argon2id from a user passphrase, explicitly opted into and shown with a banner. **Its shred
   guarantee is weaker and is stated as such:** anyone who later learns the passphrase and holds an
   old copy of the vault file can recover retired KEKs. UAOS reports the active backend and its
   guarantee in `uaos doctor`.
4. **What "shredded" claims** (documentation and UI must use exactly this):
   - *Keychain backends:* after a shred completes, the content cannot be decrypted by UAOS or from
     any copy of the data directory, provided the OS keychain does not retain deleted entries.
     Keychain backups and synchronization (e.g. iCloud Keychain) are outside UAOS's control.
   - *Passphrase vault:* the content is deleted from the active vault; old vault copies remain
     decryptable with the passphrase.
5. **Provider API keys** (BYOK) use the same keychain mechanism under `".../provider/<name>"`, and
   are read only by the egress path at request time (plan D11; never sent to agents).

## Alternatives rejected

- **B (master key + wrapped file):** equal assumptions, more moving parts, plus a remnant hole
  unless the master is rotated on every shred.
- **Global default store:** convenient, but process-global mutable state that tests cannot
  isolate and that clippy's hidden-state rules forbid.

## Consequences

- Keychain entry count grows with pockets × live KEK versions (normally 1–2 per pocket).
- A user who denies keychain access gets `UAOS-STORE-0003`; nothing falls back silently.
- CI: Linux runners have no Secret Service, so the real Linux backend is exercised only where a
  session bus exists. The keychain contract is tested against the simulated keychain everywhere,
  and against the real Windows and macOS backends on those runners.

## Verification

WP1.5: a keychain conformance suite (set / get / overwrite / delete / not-found, binary secrets,
non-ASCII account names) runs against the simulated keychain on every OS and against the native
backend on Windows and macOS; the chunk-store shred tests run unchanged over the keychain-backed
keyring.
