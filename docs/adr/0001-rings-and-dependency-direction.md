# ADR-0001: Rings, crate boundaries and dependency direction

**Status:** Accepted (2026-10-12) · **Plan refs:** §1, §2.1, §2.2, D10, D13

## Context

UAOS must carry 61 product cells without the kernel warping under them. The usual failure mode
of infrastructure projects is gradual leakage: a feature reaches into kernel internals "just
this once", until the kernel can no longer change without breaking features and features can
no longer be removed without breaking the kernel.

## Decision

1. **Four rings.** Ring 0 kernel (`crates/`), Ring 1 standard modules (`modules/`, Apache-2.0,
   each disableable), Ring 2 commercial modules (separate repository, published contracts
   only), Ring 3 services (separate repositories).
2. **The line test.** If deleting a thing would change what UAOS *is*, it is kernel; if it only
   changes what UAOS *offers*, it is a module. If two modules would have to implement it
   identically for safety, it is kernel.
3. **Twelve Ring 0 crates for RC-1**, each an audit unit with one invariant owner (plan §2.2).
   Crates are added only in the phase that first needs them.
4. **Dependency direction is data, not convention.** `arch.toml` lists every crate's allowed
   workspace edges and banned transitive dependencies; `cargo xtask arch-check` enforces it on
   every merge. Ring 1 crates may depend only on `uaos-contracts` and `uaos-module-api`. The
   runtime *implements* `uaos-module-api` (host), so modules never see runtime internals.
5. **Architecture bans in `clippy.toml`.** Clocks, randomness, filesystem, process spawning,
   thread spawning and ambient environment reads are disallowed outside their owning crate.
6. **Paid functionality only as separate Ring 2 modules** (D13). No license checks in open code.

## Alternatives rejected

- *One big crate with modules:* boundaries become advisory; nothing stops an import.
- *Dynamic Rust plugins (dylibs):* unstable ABI, requires `unsafe`, defeats signing.
- *Feature-flagged paid code in the open core:* crippleware; erodes trust; forks strip it; needs a CLA.

## Consequences

- More crates than a minimal project; compile parallelism improves, edges are capped.
- Every new crate needs an `arch.toml` entry before it can merge.
- `modules/*` joins the workspace member list with the first module (P3); until then the
  Ring 1 rule is exercised by the gate self-test, which creates a module in a scratch copy.

## Verification

- `cargo xtask arch-check` (merge gate `arch-check`), proven by negative cases
  `arch-forbidden-edge` and `arch-ring1-reaches-kernel`.
- Clippy bans proven by `clippy-ambient-clock` and `clippy-nondeterministic-map`.
- From P3: the `empty-kernel` job boots and serves with zero product modules.
