# ADR-0010: Kernel tokens and reachability

**Status:** Proposed (opened 2026-10-13; earliest decision 2026-10-15, 48 h) · **Plan refs:** v2 I-01, I-07, I-10, §2.1, PD-04, PD-13 · **Builds on:** ADR-0001, ADR-0002 (amended)

## Context

ADR-0002 promised that egress cannot be called without kernel-issued `Authorized`,
`Reservation` and `EgressReady` values, and planned a `kernel-tokens` gate. The plan v2 review
found that "the secure path is the only one that compiles" is false under today's architecture
rules unless five holes are closed:

1. **The bin can reach egress.** The `uaos` bin may depend on every crate (`allow = ["*"]`), so
   CLI code (`doctor --online`, warm-up, pricing) could call egress without an Operation.
2. **Re-exports go unchecked.** `arch-check` looks at direct Cargo edges only. A `pub use` or a
   public signature in `uaos-runtime` could hand egress or process types to `uaos-api`.
3. **The spawner is reachable.** `Spawn` belongs in `uaos-platform`, which most kernel crates
   depend on.
4. **Ring 1 can do its own I/O.** Ring 1 has no ban list, and neither `std::net` nor tokio's net
   and process APIs are banned.
5. **Tokens are visible inside the runtime.** Rust visibility cannot restrict a constructor to
   another crate, and `pub(crate)` is visible to the whole runtime crate (supervisor, hooks, bus).

## Decision

1. **Pipeline typestate in a private module.**
   - `uaos-runtime::pipeline` (a private module) defines `Operation<S>` with the states
     `Detected → Authorized → Reserved → Scanned → Ready`. Each transition is a function in that
     module that takes the previous state by value and performs exactly one mandatory stage.
   - Constructors are private to `pipeline`; the rest of the runtime receives only the final
     `Ready` value.
   - `Ready` carries the `op_id`, the authorized route and the scanned bytes. The egress client
     checks the `op_id` binding at the door, which turns a misuse inside the runtime into a test
     failure if it ever compiles.
2. **Reachability is enforced by `arch.toml` and checked.**
   - Only `uaos-runtime` may depend on `uaos-egress`. The bin's allow list becomes explicit and
     excludes `uaos-egress`.
   - The real process spawner (`OsSpawn`) and the egress client constructor are
     `disallowed-methods` outside the composition root. The root passes them **only** to the
     runtime. `allow-audit` (active) enforces where those bans may be lifted.
3. **A `surface` check (`cargo xtask surface`, P3).** A `syn`-based scan of the public items of
   `uaos-runtime` and `uaos-api` fails if any of them names an egress or spawn type, including
   through `pub use`, return types, fields or trait items. It has seeded negatives.
4. **Ring 1 closure ban.**
   - `arch.toml [ring1]` gains a ban list: hyper, reqwest, tokio's `net`/`process` features,
     `socket2`, `mio`.
   - Ring 1 also gets a third-party **allowlist**; a module crate may use only listed crates.
   - `clippy.toml` bans `std::net`, `std::process` and `tokio::{net, process, spawn}` paths
     outside their owners.
5. **The claim is stated exactly:** "compile-time inside the runtime pipeline; enforced by the
   architecture checks and lints across crates". This is the wording for docs and `claims.md`.

## Alternatives rejected

- **Cross-crate `pub(crate)`:** Rust has no such visibility.
- **`#[doc(hidden)]` constructors with a lint:** anyone can call a hidden function.
- **One large kernel crate:** it would merge policy, ledger, egress and runtime into a single
  audit unit and erase the ring map that `arch-check` proves.
- **Capability objects minted at boot and passed around by convention:** they enforce nothing
  without the reachability rules, and with those rules they add nothing.

## Consequences

- CLI commands that need the network (for example `doctor --online`) become runtime Operations.
  They are therefore policy-checked, journaled and explained like any other external contact.
- Adding an extension point that needs I/O means adding a capability handle to `ModuleContext`,
  never a dependency edge.

## Threat and privacy note

- **I-01:** no egress without an Operation. **I-07:** one door each. **I-10:** no ambient
  authority for modules.
- **T5 (exfiltration):** closed for code that compiles against the kernel. A malicious in-process
  module is still trusted Ring 1 code, which is why P5 moves untrusted code into sidecars.

## Verification (P3)

- `kernel-tokens` gate: trybuild compile-fail tests show that outside `pipeline` a `Ready` cannot
  be constructed, a stage cannot be skipped, and a token cannot be reused for another `op_id`.
  Runtime binding tests cover the door check.
- `surface`: negatives for a `pub use uaos_egress::*` in runtime and an egress type in an api
  signature.
- `arch-check`: negatives for a bin → egress edge and a Ring 1 crate depending on hyper.
- `allow-audit`: a seeded `disallowed_methods` allow outside the composition root.
