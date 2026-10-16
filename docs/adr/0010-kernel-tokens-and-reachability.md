# ADR-0010: Kernel tokens and reachability

**Status:** Accepted by the maintainer on 2026-10-15, as revised (Revision 1), at the end of its 48 h window (opened 2026-10-13) · **Plan refs:** v2 I-01, I-07, I-10, §2.1, PD-04, PD-13 · **Builds on:** ADR-0001, ADR-0002 (amended)

**Revision 1 (2026-10-15, before the decision).** The P3 Move 1 design review found four gaps, and this text closes them before acceptance:
- **The typestate lacked stages.** It omitted the hook, route and splice stages that ADR-0002's order requires (Decision 1).
- **Effects through handles.** Plan v2 §1.3 hands modules effect-capable handles. Each such handle would be a second door, so module effects become child Operations (Decision 6).
- **Hooks on async workers.** A synchronous hook on a tokio worker can stall the runtime (Decision 7).
- **The panic boundary had no owner** (Decision 8).

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
   - `uaos-runtime::pipeline` (a private module) defines `Operation<S>`. Its states follow
     ADR-0002's order exactly (Revision 1):
     `Received → Parsed → Detected → Hooked → Routed → Authorized → Reserved → Spliced → Scanned → Ready`.
     Each transition is a function in that module that takes the previous state by value and
     performs exactly one mandatory stage.
   - **Terminal exits.**
     - `Authorized` may instead end as `op.denied` or `op.approval_required`.
     - `Scanned` may instead end as `op.denied`, after releasing the held reservation.
   - **Record before effect.** `Reserved` is reached only after the chunks the intent references
     are with the OS and the single critical `op.reserved_intent` record, with the budget entry
     inline, has been acknowledged (ADR-0002 item 3, ADR-0018).
   - **Execution starts at the door, not before.**
     - `Ready` is handed to the egress client, which first connects. A connection failure
       releases the reservation, because no byte left.
     - Only after the connection is up does the runtime move the reservation to `InFlight`,
       journal `op.executing` (critical), and send.
   - **Recovery is honest about that marker.** In balanced durability mode a power loss can
     lose `op.executing` after bytes left. Recovery therefore settles an open reservation at
     full cost, marked estimated. It uses `op.executing` only to explain "maybe sent" versus
     "never sent". Only strict mode, where every record is flushed before it is acknowledged,
     may release a reservation that has no `op.executing`.
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
6. **Module effects are child Operations (Revision 1).**
   - A module never receives a handle that performs I/O: no file, socket, process or pool
     handle.
   - Hooks return declarations. One of them requests a **child Operation** that carries an
     unforgeable `GrantRef`. The child then passes the same pipeline: policy, reservation,
     journal, final scan and the one door.
   - **Limits on children.**
     - Depth is at most 2.
     - A module's hooks never run on its own children.
     - Each module has a quota of children.
     - A child bills the parent's pool unless its grant names another.
   - This realises plan v2 §1.3's "capability" mechanism without a second door. Read-only
     inputs are the module's own configuration snapshot and its view of the Operation:
     redacted content and metadata.
7. **CPU stages never run on async workers (Revision 1).**
   - Decode, detection, hooks, splice and the final scan run on a bounded CPU pool owned by the
     supervisor, and are awaited with a `Clock` deadline.
   - `tokio::task::spawn_blocking` joins the spawn ban outside the supervisor.
   - Deadlines cannot preempt a thread. A late result is therefore discarded and counted, and
     the lost thread is counted too. When at least half the pool is lost, the runtime degrades
     to modules-off, the state `empty-kernel` proves safe.
8. **The panic boundary has owners (Revision 1).**
   - `std::panic::catch_unwind` is a disallowed method outside `uaos-runtime`'s module host and
     the bin, and so is `std::panic::set_hook`.
   - A module that panics loses its state and is disabled. No kernel lock is held while a module
     runs.
   - The bin installs a panic hook that never prints the panic message, because a message could
     carry payload (I-11).
   - An abort (double panic, stack overflow, out of memory) behaves like `kill -9`: recovery
     marks open Operations `Indeterminate`.

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
- Adding an extension point that needs I/O means adding a child-Operation kind that a `GrantRef`
  authorizes. It never means an I/O handle, and never a dependency edge (Revision 1; this
  replaces "a capability handle on `ModuleContext`").
- An in-process module is still trusted code. These rules minimise its authority; they do not
  contain a hostile module. Untrusted code waits for P5 sidecars.

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
- **Revision 1 negatives:**
  - `stage-skipped` (trybuild) and `ready-outside-pipeline`;
  - `door-op-id-mismatch`;
  - `runtime-requires-module` (the kernel must build and pass with zero modules);
  - `child-op-depth-exceeded`;
  - `hook-panic-escapes`;
  - `panic-message-logged`.
- `surface` is registered as an active gate in the change that implements it. It is never
  pending, so the pending count still only falls.
