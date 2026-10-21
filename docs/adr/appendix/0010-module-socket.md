# ADR-0010 appendix: the module socket — `uaos.module/1` and `uaos.adapter/1` (draft), and the kernel contract additions of PR-4

**Status:** draft contract, written before code (P3 Move 1, Train A PR-4; plan "Spine to RC-1"
Stage 1). The contracts named here freeze at RC-1 (plan v2 §2.6). Until then they are `draft`; a
change after this appendix is accepted is recorded in the CHANGELOG and in this file.
**Builds on:** ADR-0010 (Decision 6: effects are child Operations; 7: the CPU pool; 8: the panic
boundary), ADR-0014 (structural view, roles, selectors), ADR-0008 (authorization over Cedar),
ADR-0011 (scoped credentials), ADR-0007 (pocket keys and shred), ADR-0002 (pipeline order),
plan Move 1 D-1, D-2, D-9, D-10 and D-15.
**Invariants it carries:** I-01 (no side effect without an Operation), I-06 (value-level prefix
stability), I-07 (one door), I-10 (no ambient authority for modules), I-11 (no payload in logs),
I-12 (the kernel runs with zero modules), I-16 (session–account affinity).

## 1. What PR-4 builds, and what it does not

**Builds:**
- **`uaos-module-api`**, a Ring 0 crate with no I/O (`arch.toml`: it may depend on
  `uaos-contracts` and `uaos-json` only). It holds the types of §3–§7: the `Module` and
  `DialectCodec` traits, the manifest, hook points, the read-only views, selectors, roles,
  declarations, module state and `GrantRef`. It runs nothing: the host that calls modules is
  PR-8, the runtime that owns the CPU pool is PR-6.
- **`uaos-contracts` additions** (§8): `AgentId`, an optional `agent_id` on the event envelope,
  and the event-naming rule.
- **Moved to PR-4b (branch `p3/a4b-grant-path`):** `uaos.grant/1`, the Cedar `Pocket` entity, the `memory.read` action and
  its consent rule (§6.2), with the final review's M4 (match the grant a request carries) and
  M5 (`uaos.grant/1` as the exact wire form of the engine's grant). This contract still states
  the rules they implement; PR-4b proves them.

**Does not build** (and where it lands): the module host, ordering, deadlines, strikes and
quarantine (PR-8); panic containment (PR-9); paper modules (PR-10); real dialect codecs (M2,
WP3.4); the presence ceremony and `uaos.approval/1` (M3, WP3.6, with ADR-0012); any module that
ships.

## 2. Zero-trust rules the types encode

A module is **trusted code with minimized authority** (ADR-0010, threat T18): it runs in-process
and could be wrong, so the socket gives it nothing it could misuse by being wrong. Untrusted code
waits for P5 sidecars.

1. **Nothing ambient.** No type in `uaos-module-api` performs I/O or holds a handle that does:
   no file, socket, process, clock, randomness, pool or channel. Every value a hook receives is
   a read-only borrow that ends with the call.
2. **Modules describe; the kernel acts** (D-1). A hook returns declarations (§4). Every effect a
   module wants is a child Operation (§6) that passes the same pipeline as any request: policy,
   reservation, journal, final scan, the one door.
3. **A grant reference is not authority.** `GrantRef` only names a grant, and anyone can build
   one. Authority is the live grant: at every use, the host checks the grant behind it for
   holder, pocket, action, expiry and revocation. A reference that a module built, kept or
   copied therefore grants nothing that policy does not grant at that moment. A missing, stale
   or revoked grant fails closed.
4. **No free text** (D-2). Reasons, labels, module event value names, and the tools and
   configuration keys a child Operation names are manifest-declared codes. Event values are
   bounded numbers, and a child Operation's correlation tag is a number. A `Strip` selector
   may name keys and values a module copied from content, so the host never journals or
   explains a selector's keys or values, only their counts. The host never formats a struck
   call's declarations either: its explanation names the strike code only. Identifiers a
   module builds (a `GrantRef`, a source pocket, a `CancelOp` target) are checked against
   what the host knows before any of them is journaled or explained. Text a module adds
   (`ModuleText`) is bounded, detected and final-scanned like any outbound byte. It refuses
   control characters other than newline, carriage return and tab; the explicit
   bidirectional controls U+202A–U+202E and U+2066–U+2069 (ADR-0020 rule 5); and the Unicode
   tag characters U+E0000–U+E007F, which a model reads and a person cannot see; and a
   variation selector (U+FE00–U+FE0F, U+E0100–U+E01EF, and the Mongolian U+180B–U+180D and
   U+180F since the PR-4c V1 review) that follows no base character (a run of them encodes bytes nobody
   sees). A base is a visible character: not whitespace, not a control, and not a
   default-ignorable code point (PR-4c). An ideographic variation selector, U+E0100–U+E01EF,
   follows only a CJK unified ideograph. Declarations reach the host through a `DeclsMut`
   handle, by value, so a module
   cannot swap the collector for a larger one.
5. **Redacted by default.** A module sees the redacted structural view. Detection scans keys
   as well as values, so the mask covers strings, numbers and object keys. A masked value or
   key reads as masked, equals no value, matches no name and is never found by name, so no
   predicate's answer depends on masked text. Masking a container masks everything inside
   it, so a finding placed on the wrong node fails closed. Structure stays visible: kinds,
   counts and nesting, inside a masked container too; findings are strings, numbers and keys.
   A finding the host cannot place on a value or a key refuses the view, and so does one that
   names a node off the tape, or a key finding on a node that has no key (`Mask::seal`). A seal
   holds the tape it was sealed against and the mask, and builds the view itself
   (`Sealed::view`), so it is never used over another tape and the mask cannot change under it
   (PR-4c; its V1 review M2 found a fingerprint of the tape matched a refilled buffer). An
   unsealed view (`StructuralView::new`) cannot refuse: a finding off its tape, or a key finding
   on a node with no key, masks nothing in it. So the host hands a module or a codec only the
   view of a seal. `HookCx::with_view` takes a `Sealed` (PR-4c final review M2), and PR-8's host
   does the same for `roles()` and `usage()` (§12). A module's `Strip` selector is
   resolved over the masked
   view, never over the raw tape. **Frames and errors** reach a hook as the provider sent
   them: before rehydration (ADR-0017), never rehydrated. A secret masked on the way out
   therefore never comes back to a module on the way in. No raw view exists at RC-1.
   **Admission is a snapshot.** The host admits a module whole (`KernelOffer::admit_module`)
   and checks every call against the manifest it admitted (`Admitted::manifest`), never a
   later `Module::manifest`, so a module cannot grow its manifest after admission.
6. **Pocket isolation, for what the socket holds.** A module's state, events and grants are
   per pocket (§5), and nothing the socket holds crosses pockets except through a
   cross-pocket grant (§6.2). A module's own fields are outside this guarantee. A module
   that keeps data across calls in its own fields (interior mutability, statics) escapes the
   state bound and the pocket's shred. The module-author rules (PR-10) forbid it, and an
   architecture rule for Ring 1 crates will refuse interior mutability and statics (owner
   PR-10). Until then this rests on the trust model: trusted code with minimized authority.
   Untrusted code waits for P5 sidecars.
7. **Fail closed at load.** A manifest the host cannot fully honour is refused, never loaded in
   part. The causes: an unknown `requires` feature; a hook point or mode the kernel does not
   offer, including an acting hook at a point that only observes; a bound above its ceiling;
   an undeclared code, including a grant whose reason is not a declared reason.
8. **Language-neutral** (ADR-0020 rule 2). No type names a locale. Content in any language
   crosses the view, the selectors, `ModuleText` and `ModuleState` byte for byte: nothing
   normalizes it, case-folds it or reorders it. Codes are ASCII keys that a surface
   translates.

## 3. The manifest (`uaos.module/1`)

Built only through `Manifest::builder`; fields are private and read through accessors (D-15).

| Field | Type | Rule |
|---|---|---|
| `name` | `ModuleName` (`uaos-contracts`) | `[a-z][a-z0-9-]*`, at most 64 bytes; unique in the process. The envelope's module actor already uses it |
| `version` | `semver` | shown in explanations and events |
| `api` | `ModuleApiVersion { major, minor }` | the host refuses another major; a higher minor than the kernel's is refused |
| `requires` | `BTreeSet<KernelFeature>` | every feature the module needs (below); the host refuses the module if one is missing |
| `hooks` | `Vec<HookDecl>` | one per point at most: `point`, `mode` (`act` only where the point acts), `priority` (`u16`), `deadline_us`, `on_failure`. The view is the point's (§4) |
| `actions` | `BTreeSet<ChildKind>` | the child Operation kinds it may request; each kind names its Cedar action and the features it needs |
| `grants` | `Vec<GrantDecl>` | the grants it may hold, at most 64: the child kind, and why (one of its declared reasons) |
| `reasons`, `labels` | `Vec<Code>` | every code it may emit: `[a-z][a-z0-9_]{1,31}`, at most 64 each |
| `events` | `Vec<EventDecl>` | module event codes, each `ephemeral` or `journaled` (D-9), with the value names it may carry (at most 8) |
| `targets` | `BTreeSet<Code>` | the tools and configuration keys its child Operations may name, at most 64 |
| `config_schema` | JSON Schema, bounded | its configuration namespace; validated before the module sees it |
| `state_bytes` | `u32` | per-pocket state bound, at most `MAX_STATE_BYTES` (64 KiB) |
| `max_decls` | `u16` | declarations per hook call, at most 64 |
| `default_enabled` | `bool` | default **off** for anything that reaches outside the request (CLAUDE.md: "default off" is policy-gated, not absent) |

**`KernelFeature`** is a closed, `#[non_exhaustive]` enum: what the running kernel offers a
module beyond the base hook points. A module lists every feature it uses; the host compares the
set with its own and refuses the module, with an explained `module.refused` event (reason
`feature_missing`), when any is absent. An unknown feature in a manifest is refused the same way:
the comparison is by set membership, so a module built against a newer kernel never loads half
of itself into an older one. Features at RC-1:

| Feature | Grants the use of |
|---|---|
| `stream_observe` | the `stream.observe` point |
| `stream_assert` | the `stream.assert` point (cancel from the next frame) |
| `child_operations` | `Decl::Request` |
| `cross_pocket_read` | child Operations that read another pocket under a grant (§6.2) |
| `state_checkpoints` | `Decl::Checkpoint` (§5) |
| `config_change_requests` | child Operations of kind config change (C-61) |

Known additive extensions, not features yet: `suspend` (C-35 inline), `branch` (C-14 new
Session).

**Kill switches.** `modules.<id>.enabled` in configuration, the manifest's `default_enabled`, and
a global modules-off boot (the `empty-kernel` configuration, I-12). The automatic degradation of
ADR-0010 Decision 7 uses the same path.

## 4. Hook points and declarations

**Points** (D-1, plan Move 1 §6). Deadlines are ceilings; a manifest may ask for less.

| Point | Mode | View | Deadline | On failure |
|---|---|---|---|---|
| `ingress.parsed` | observe; strip or append only in the newest `user` turn | redacted | 300 µs | skip and explain |
| `classify` | label, monotone (only raises risk, only adds classes) | redacted | 200 µs | assume tier 3 |
| `context.assemble` | append-only | redacted + own state | 400 µs | skip and explain |
| `tool.result` | veto or transform the newest-turn `tool_result` | redacted | 300 µs | risk ≥ 2: deny |
| `route.decide` | rank or subset permitted, account-pinned candidates (I-16), seeing breaker state | metadata | 100 µs | kernel default route |
| `stream.observe` | observe after forwarding, lossy | frame (as the provider sent it, before rehydration) + stream state | 50 µs per frame, off the relay path | detach and count |
| `stream.assert` | `Cancel` from the next frame; frames held only at high risk; pings never held | frame (as the provider sent it, before rehydration) | 100 µs per frame | high risk: cancel |
| `response.post` | observe after settle | metadata | 5 ms, off the hot path | ignore and count |
| `error.translate` | additive annotation; upstream bytes stay identical. **Observe only in this draft:** the annotation's declaration is added with the host (PR-8) | error + metadata | 200 µs | kernel default |

The "On failure" column is the kernel's floor: a manifest's `OnFailure::Deny` can make a
pre-egress point stricter, and is refused at load where nothing is left to deny
(`stream.observe`, `response.post`, `error.translate`; `point_unavailable`). The pre-egress ceilings sum to 1.3 ms, inside the 2 ms hook budget. **Kernel rule:** at risk tier
2 or more, any veto that fails or times out denies, whatever the manifest says.

**Declarations** (`Decl`, closed, `#[non_exhaustive]`, at most `max_decls` per call):

| Declaration | Allowed at | Effect, performed by the kernel |
|---|---|---|
| `Strip(Selection)` | `ingress.parsed`, `tool.result` | removes nodes inside the point's anchor (the newest human turn at `ingress.parsed`, the newest tool result at `tool.result`) whose ancestors and whole subtree carry no role that forbids edits (`RoleMap::may_strip`; ADR-0014 §3) |
| `Append { slot, text: ModuleText }` | `ingress.parsed`, `context.assemble` | an append in the newest human turn; the text is detected and final-scanned |
| `Veto(ReasonCode)` | `tool.result` | the Operation is denied and explained |
| `Cancel(ReasonCode)` | `stream.assert` | the stream is cancelled from the next frame |
| `Label(Label)` | `classify` | a label added; risk only rises |
| `Rank(Vec<CandidateId>)` | `route.decide` | a ranking or subset of the candidates offered: 1 to 64, none twice; an id outside the offer is a strike (`unknown_candidate`) |
| `Emit(ModuleEvent)` | every hooked point | an event with a declared code and declared value names, each with a number; journaled ones rate-limited per module per Operation |
| `Request(ChildOpRequest)` | every point, with `child_operations` | a child Operation (§6) |
| `CancelOp(OperationId)` | every point, with `child_operations` | cancels one of the module's own child Operations; any other id is a strike (`not_own_child`) |
| `Checkpoint` | `context.assemble`, `response.post`, `on_event` | persists the module's state for this pocket (§5), with `state_checkpoints` |

A declaration a point does not allow, a declaration at a point the manifest does not hook, a
code the manifest does not declare, or more than `max_decls` is a strike against the module,
and none of that call's declarations apply.

## 5. Pocket-scoped module state, and how it stays in step

A module that remembers (notes, reminders, loop counters) keeps **state per (module, pocket)**,
never shared between pockets (C-18).

- **`ModuleState`** is an opaque byte buffer of at most the manifest's `state_bytes`. A hook gets
  a `StateMut` handle, by value and for one call, on the Operation's pocket's state only. The
  handle offers the bounded changes and nothing else, so a module can neither swap the state
  for another (which would clear the mark below and raise its bound) nor keep the handle. Each
  change is atomic, and a refused one marks the state `exceeded`. The host runs every call on a copy and keeps the copy only if
  it is not exceeded and its declarations pass. The procedure is the crate's own
  (`Admitted::call_hook`, `Admitted::call_event`, PR-4c), so every host gets the same one. A
  module's own entry points stay public for tests, and PR-8's host calls only these (§12);
  the host adds only the strikes it alone can make. A call that outgrew its state is a strike
  (`state_exceeded`), and the state is left as it was before the call. **Every strike refuses
  all of the call's declarations.** A static strike (from `check_decls`) and `state_exceeded`
  also discard the call's state changes. A host-side strike keeps them: one the host makes on
  what only it knows (`not_own_child`, `unknown_candidate`, `budget_exceeded`, a quota, a rate
  limit). So `on_event` stays a function of the state, the event and the manifest, and a
  replay rebuilds what the live run kept. The host runs at most
  one call of a module for one pocket at a time, so no two calls work on copies of the same
  state and none of their changes is lost. A cursor advances only on its own pocket's
  events.
- **Events in order.** `on_event` delivers the pocket's **journaled** events (D-9), the module's
  own and the kernel's it subscribed to, in journal order, with their sequence number. A
  module's state for a pocket reflects its events up to a `PocketCursor { pocket, through: Seq }`.
- **Checkpoints.** `Decl::Checkpoint` asks the host to persist the state with its cursor. The host
  stores the bytes as an encrypted chunk under the **pocket's** key and journals
  `module.state_checkpoint` naming the module, the pocket, the cursor and the chunk. Shredding a
  pocket therefore shreds its module states with it (ADR-0007), and a checkpoint never names
  another pocket.
- **Resume.** After a restart, a quarantine or a re-enable, the host restores the latest
  checkpoint for each pocket the module touches and replays the pocket's journaled events after
  its cursor through `on_event`. **A replay rebuilds state and declares nothing.** Each
  replayed event is marked (`EventView::replay`). The host applies the call's state changes,
  under the same all-or-nothing rule, and discards every declaration, so a replay never
  requests, emits or cancels anything a second time. No checkpoint means an empty state and a
  replay from the start of the pocket's journal, bounded by the projection's retention.
  Changes a hook made after the latest checkpoint are not journaled and do not survive a
  restart. A module that must not lose a change makes it in `on_event`, which replay
  repeats, or checkpoints after it.
- **Not synchronized:** ephemeral events (frames, metrics), which are lossy by design (D-9), and
  anything between pockets.

## 6. Child Operations and `GrantRef`

### 6.1 The rule

`Decl::Request(ChildOpRequest)` asks for one child Operation: a kind from the manifest's
`actions`, a `GrantRef` when the action needs one, a body (redacted inputs only; `ModuleText`
for new text) and a correlation tag (a `u16`, never a word). The kernel builds the child under the parent's correlation
id with `parent_operation`, and it passes the full pipeline. Limits (ADR-0010 Decision 6): depth
at most 2; a module's hooks never run on its own children; a per-module quota of children; the
child bills the parent's pool. The outcome reaches the module as
journaled events through `on_event`, never as a return value.

### 6.2 Cross-project memory (C-44)

Reading another pocket's memory (notes, Obsidian index, a project's decision log) is a child
Operation authorized by Cedar action `memory.read` on resource `Pocket::"<source>"`, with the
requesting pocket in `context.pocket` (§8). Default deny: without a grant, it is denied and
explained. A read of the requesting pocket itself crosses nothing and follows policy as any
action does. For a read of another pocket, a permit alone, however broad, never allows it: it at most turns the answer into
an approval request, whose approval issues the grant. Only a live grant, which carries the
injection policy, allows the read.

- **Consent is a grant** (`uaos.grant/1`, §8), issued only through a human, user-present
  approval (ADR-0004, ADR-0012), scoped to one source pocket, one requesting pocket and an
  expiry, and carrying an **injection policy**: `auto`, `ask` or `never` (CLAUDE.md main flow 5).
- **`GrantRef`** is how a module carries that consent into the request: the host hands the module
  the refs for the grants its manifest declared that are live for the Operation's pocket. The
  reference is unforgeable in effect, as ADR-0010 requires, though not as a type: building
  or keeping one confers nothing, because the host checks the live grant behind it at every
  use (§2 rule 3).
- **What comes back** is redacted, labelled with its provenance (source pocket, record, grant)
  and, with injection `ask`, held for the human before it may be appended at
  `context.assemble`. With `never`, it may inform ranking but never enter a prompt.

## 7. `uaos.adapter/1`: the dialect codec

A dialect module implements `DialectCodec` (ADR-0014 Decision 2). It describes; the kernel
splices.

| Method | Returns | Rule |
|---|---|---|
| `endpoints()` | `&[EndpointDecl]` | method, path pattern (path only, never the query; a final `*` matches whole segments), class `governed`, `metadata` or `denied` (D-28). A path that is not canonical (percent-encoding, a backslash, an empty or dot segment) matches no pattern. `classify` gives a request its class: `denied` when the path is not canonical or no endpoint matches, and the most restrictive class (`denied`, then `governed`, then `metadata`) when several match |
| `roles(&StructuralView, &mut RoleMap)` | `Result<(), CodecError>` | assigns the roles of ADR-0014 through selectors only; a codec never computes a byte offset |
| `frame(&SseEvent)` | `FrameKind` | classifies a stream frame: content, usage, ping, error, end. A frame whose data holds the dialect's usage object, even beside content, is usage, end or error: the runtime reads those strictly, content and other only best effort, and never a ping (runtime contract `0013-runtime-relay-and-stop.md` §7.3) |
| `dimensions()` | `&[Code]` | the billing dimensions its usage reports may name: a fixed set, never read from a response |
| `usage(&StructuralView)` | `Option<UsageReport>` | the billing dimensions the response reports (ADR-0016, M2), each declared and named once; the host refuses a report naming another (`UsageReport::check`) |

**`StructuralView`** is a read-only view over the `uaos-json` tape of the request, with the
detection overlay (`Mask`): values and keys holding a finding read as `Masked` (§2 rule 5).
**`Selector`** is ADR-0014 §6's language and no more: `key`, `each element`, `any-depth key`; the
predicates "member is one of", "member is not one of" and "string, or an array with an element
matching"; a `last` modifier. Growing it needs ADR-0014 amended. A selector resolves to node ids
on the tape. Roles are kept by node id. An edit's role check covers the node's ancestors and
its whole subtree, a contiguous range of ids (`RoleMap::touching`), so an edit that encloses a
forbidden role is refused. A strip may remove what lies inside its anchor, never the anchor
itself, and never anything that touches masked content: a codec assigns roles through the
masked view, so masked content may hide a forbidding role (`RoleMap::may_strip`).

**Cost (PR-4c).** Each step selects a node at most once, and every node a step or a predicate
examines spends one visit from a `Visits` budget, each member a lookup examines included, so a
node examined twice in one step spends twice: the budget counts examinations, not nodes.
No comparison decodes more than six times `MAX_SELECTOR_TEXT` bytes:
- a key is compared with the selector's key as it decodes, and stops at the first difference;
- a string whose raw text is longer than six times `MAX_SELECTOR_TEXT` is equal to no value,
  without decoding: an escape shrinks at most six bytes to one, so it decodes to more than
  `MAX_SELECTOR_TEXT` bytes, longer than any value a selector names. A masked string is
  equal to no value either, so the shortcut reveals nothing about masked text.

Each visit also costs O(log ranges) against a sealed mask; the host builds the view from the
seal (`Sealed::view`). One call's selectors share one budget of `MAX_VISITS`, and running out is a host-side
strike (`budget_exceeded`). **So one call costs at most `MAX_VISITS` visits, each
O(`MAX_SELECTOR_TEXT` + log ranges).** A codec's `roles()` is bounded the same way, for a host
that hands it one `RoleMap` per call: the map carries one budget for all the selectors it
assigns. `Visits` is not `Copy`, so a budget is not duplicated by copying. The bound holds
for a host that follows §5's procedure. `Visits::new`, `Visits::per_call` and
`RoleMap::default` are public for hosts and tests, and `Selector::resolve` starts its own
budget, so a codec that builds its own budgets is outside it (trusted code with minimized
authority, §12). Two maps with the same roles are equal whatever they spent.

## 8. Kernel contract additions (all additive)

| Contract | Addition | Why | Compatibility |
|---|---|---|---|
| `uaos-contracts::id` | `AgentId`, prefix `agt` | one agent instance (a main agent or one subagent) under a credential; subagents often share one key, so a credential alone cannot tell them apart | new type |
| `uaos.event/1` | optional `agent_id` on `EventEnvelope` and `EventDraft`, omitted when absent | CLAUDE.md §4: every request carries its agent id; per-agent spend and the task ledger (C-45, C-30) | a new optional property: non-breaking under `schema-compat` |
| `uaos.grant/1` (new, PR-4b (branch `p3/a4b-grant-path`)) | `Grant`: id, principal, action, resource, the pocket it applies in, expiry, highest risk tier, data classes, the ask policies it satisfies, for `memory.read` the injection policy, the approval that issued it, and when | the wire form of `uaos_policy::model::Grant`, journaled when issued and when revoked | a new contract |
| Cedar schema (PR-4b (branch `p3/a4b-grant-path`)) | `entity Pocket;` and `action "memory.read" appliesTo { principal: [Agent, Human, Module, System], resource: [Pocket], context: Ctx }` | cross-pocket reads are authorized like every other action, default deny (ADR-0008) | additive; existing policies unchanged |
| Event naming | `<domain>.<event>`, lowercase, `[a-z_]` words, no `uaos.` prefix, as in the code (`op.committed`, `chunk.lost`). Reserved domains: `op`, `budget`, `chunk`, `redact`, `identity`, `kernel`, `module`, `admission`, `egress`, `bus`, `config`, `grant` | Move 1's text used `uaos.module.*`; the code never did. Constants are added by the PR that first emits them. **Module events** are not types of their own: the host journals each as `module.event`, with the module's name and the declared code as fields, so a module name with hyphens never has to fit an event type | rule only |

**Who fills `agent_id`:** session inference (ADR-0015, M2) from the client's own agent markers;
until then the field is absent and nothing claims per-agent attribution.

**Deferred, with reason:** `uaos.approval/1` lands with the presence ceremony in M3 (WP3.6),
because what an approval must prove depends on ADR-0012, still proposed. M3 precedes the RC-1
freeze, so the contract still freezes with the rest.

## 9. Freeze discipline (D-15)

- Inputs a module receives are `#[non_exhaustive]` and built by the host through
  constructors: `OpMeta`, `Candidate`, `EventView`, `SseEvent`.
- Types a module builds are built through builders or constructors and are
  `#[non_exhaustive]` where they carry fields: `Manifest`, `ChildOpRequest`, `ModuleText`,
  `EventDecl`, `GrantDecl`, `EndpointDecl`, `ModuleVersion`. Handles a hook receives
  (`StateMut`, `DeclsMut`) come by value and end with the call. `OnFailure` is
  `#[non_exhaustive]`.
- Output enums (`Decl`, `KernelFeature`, `FrameKind`) are `#[non_exhaustive]` and grow additively.
- Paper modules (PR-10, test-only) prove that C-14, C-16, C-24, C-35, C-44, C-45, C-49, C-50, C-51,
  C-52 and C-61 fit `module/1` without a breaking change.

## 10. Observability

The crate is pure: no logging, counters or clock. It defines the codes the host reports with:
the `ModuleName`, the reason and label codes, and two code sets:

- **`module.refused` reasons:** `feature_missing`, `api_major`, `api_minor_ahead`,
  `bound_exceeded`, `undeclared_code`, `point_unavailable`, `duplicate_hook`,
  `feature_not_required`, `duplicate_event`, `grant_without_action`,
  `default_on_reaches_outside`, `config_schema`;
- **strike codes:** `too_many`, `not_hooked`, `not_allowed_here`, `undeclared_code`,
  `undeclared_action`, `feature_not_required`, `bound_exceeded`, `state_exceeded`, and the
  three the host checks against what only it knows: `not_own_child`, `unknown_candidate` and
  `budget_exceeded`.

`Debug` output shows identifiers, lengths and counts only, never a view's content, a
selector's keys and values, a frame, state bytes or `ModuleText` (I-11).

## 11. Proof obligations (PR-4)

**Tests:**
- manifest validation refuses each case of §2 rule 7, one case per refusal reason, and every
  refusal code is one §10 lists;
- `requires` is compared by set: an unknown feature, and a feature the kernel lacks, are refused;
- `ModuleState` refuses growth past its bound and leaves the state unchanged, and a call that
  outgrew it is struck whole through the crate's own procedure of §5 (`Admitted::call_hook`,
  `Admitted::call_event`, PR-4c);
- declarations: a strike for each reason in §10, including an unhooked point, an undeclared
  event value name, an undeclared tool or configuration key, and a ranking past its bound;
- the view: a masked key reads as masked, matches no name and is not found by name; a masked
  number reads as masked; every predicate answers the same whatever the masked text is;
- path patterns match canonical paths by whole segments;
- **the per-call cost bound (PR-4c):**
  - a `Key` step and a predicate's lookup spend a visit per member examined;
  - an escaped string at exactly six times `MAX_SELECTOR_TEXT` raw bytes still matches the
    value it decodes to, and one byte past the bound matches none and is never decoded;
  - one `RoleMap` exhausts one budget across its assignments;
- **seals (PR-4c):** a sealed view is over its own tape and says it is sealed, and a key
  finding on a keyless node refuses the seal;
- **`ModuleText` bases (PR-4c):** whitespace, a control and a default-ignorable code point are
  no base, and an ideographic selector follows a CJK ideograph only;
- a `GrantRef` is checked against the live grant at every use (the host's test, PR-8). Building
  one confers nothing (§2 rule 3);
- `AgentId` round-trips; an envelope without `agent_id` serializes to the exact bytes main
  writes (a golden string), because the journal's hash chain covers exact bytes;
- `uaos.grant/1` and the Cedar `memory.read` rules: PR-4b (branch `p3/a4b-grant-path`)'s proof obligations;
- selectors resolve to the expected node ids, and on generated tapes they name only nodes of
  the view, in document order, without repeats; a role map names only the nodes it was given,
  and the roles of a node outside the view are unknown (`None`), never empty;
- **language neutrality** (`tests/language_neutrality.rs`, gate `language-neutrality`): a
  seven-locale corpus crosses five stages with 0 byte differences: parse, the view, selectors,
  `ModuleText`, and `ModuleState` checkpoint and restore. Two properties hold over arbitrary
  strings. Selectors never fold case (Turkish i, German `ß`). NFC and NFD stay distinct.
  `ModuleText` refuses explicit bidi controls and keeps the implicit marks.

**Seeded violations** (`cargo xtask negative`): gate `test`, except the six language cases
(`selector-folds-case`, `module-text-accepts-bidi-override`, `module-text-accepts-tag`,
`module-text-accepts-variation-run`, `module-text-invisible-base`,
`module-text-ideographic-any-base`), which keep the `language-neutrality` gate active
(ADR-0020):

| id | Seed | Caught by |
|---|---|---|
| `module-unknown-feature-loaded` | admission skips the feature comparison | `admission_compares_every_required_feature` |
| `module-act-at-observe-point` | an acting hook at an observe-only point loads | `a_manifest_is_refused_whole_for_each_reason` |
| `module-state-unbounded` | the state bound check skipped | `state_is_bounded_and_unchanged_on_refusal` |
| `module-state-call-kept` | a refused change no longer marks the state | `a_call_that_outgrows_its_state_is_struck_whole` |
| `module-decls-at-unhooked-point` | an unhooked point treated as observe | `nothing_is_declared_at_a_point_the_module_did_not_hook` |
| `module-event-value-undeclared` | any value name accepted | `an_event_carries_only_declared_value_names` |
| `view-masked-key-readable` | a masked key reads plain | `masked_keys_and_numbers_read_as_masked` |
| `view-masked-key-found-by-name` | `member` finds a masked key | `masked_keys_and_numbers_read_as_masked` |
| `selector-predicate-unbounded` | the predicate value bound skipped | `a_selector_is_bounded` |
| `path-pattern-crosses-segment` | a prefix pattern matches mid-segment | `path_patterns_match_canonical_paths_by_segment` |
| `path-not-canonical` | non-canonical paths are matched | `path_patterns_match_canonical_paths_by_segment` |
| `agent-id-serialized-when-absent` | `skip_serializing_if` removed | `an_absent_agent_id_is_not_written` |
| `selector-folds-case` | predicate values compared lower-cased | `selectors_never_fold_case` |
| `module-text-accepts-bidi-override` | the explicit bidi check skipped | `module_text_refuses_explicit_bidi_controls` |
| `endpoint-unmatched-not-denied` | an unmatched path falls back to `metadata` | `an_endpoint_s_class_is_the_strictest_match_and_unknown_paths_are_denied` |
| `module-rank-empty-accepted` | an empty ranking passes | `an_empty_ranking_is_a_strike` |
| `view-masked-container-leaks` | a masked container no longer masks its inside | `a_masked_container_masks_everything_inside` |
| `role-check-ancestors-only` | the role check skips the subtree | `a_strip_never_encloses_a_forbidden_role` |
| `replay-declares-again` | a replayed event is not marked | `a_replay_rebuilds_state_and_declares_nothing` |
| `module-text-accepts-tag` | the tag-character check skipped | `module_text_takes_crlf_and_refuses_tag_characters` |
| `path-parameter-canonical` | `;` counts as canonical | `path_patterns_match_canonical_paths_by_segment` |
| `module-cancel-without-feature` | `CancelOp` without `child_operations` passes | `cancelling_a_child_needs_child_operations` |
| `chunk-lost-drops-agent` | a `chunk.lost` record drops the agent | `a_lost_payload_record_names_the_agent_of_the_record_it_reports` |
| `module-manifest-reread` | the host re-reads `manifest()` | `a_module_is_checked_against_its_admitted_manifest` |
| `view-sealed-mask-drifts` | sealing drops masked containers | `sealed_and_unsealed_views_agree` |
| `strip-removes-anchor` | a strip may remove its anchor | `a_strip_keeps_its_anchor_and_masked_content` |
| `strip-touches-masked` | a strip may touch masked content | `a_strip_keeps_its_anchor_and_masked_content` |
| `selector-unbudgeted` | the visit budget never runs out | `a_selector_stops_at_its_budget` |
| `usage-undeclared-dimension` | undeclared dimensions pass | `usage_reports_name_declared_dimensions_once` |
| `module-text-accepts-variation-run` | variation-selector runs pass | `module_text_refuses_variation_runs` |
| `failure-deny-after-the-fact` | `Deny` loads at an observe-after point | `a_failure_cannot_deny_after_the_fact` |
| `selector-member-scan-uncharged` | a lookup's member scan spends no visits (PR-4c) | `a_lookup_spends_a_visit_per_member` |
| `selector-raw-bound-too-tight` | the raw-length shortcut refuses a string that decodes to a value (PR-4c) | `a_string_that_decodes_short_enough_still_matches` |
| `module-text-invisible-base` | any character is a variation selector's base (PR-4c) | `module_text_needs_a_visible_base` |
| `module-text-ideographic-any-base` | an ideographic selector follows any base (PR-4c) | `module_text_needs_a_visible_base` |
| `selector-raw-bound-too-loose` | a string past the raw bound is decoded (PR-4c V1 review M3) | `a_string_past_the_raw_bound_is_never_decoded` |
| `call-event-manifest-reread` | an event is checked against a manifest grown after admission (PR-4c scoped round L-b) | `a_module_is_checked_against_its_admitted_manifest` |
| `call-event-keeps-outgrown-state` | the event procedure keeps an event that outgrew its state (PR-4c final review M1) | `an_event_that_outgrows_its_state_is_struck_whole` |
| `view-masked-key-matched-by-name` | a masked key matches its name in the selectors' key check (PR-4c final review L3) | `masked_keys_and_numbers_read_as_masked` |
| `mask-seal-keyless-key` | a key finding on a keyless node seals (PR-4c) | `a_key_finding_on_a_keyless_node_refuses_the_seal` |
| `rolemap-fresh-budget-per-assign` | each assignment gets a fresh budget (PR-4c) | `a_codecs_roles_share_one_budget` |
| `host-procedure-keeps-outgrown-state` | the crate's procedure keeps a call that outgrew its state (PR-4c) | `a_call_that_outgrows_its_state_is_struck_whole` |

`schema-breaking-change` is re-proven over the new schemas.

## 12. Open questions and conscious assumptions

- **Q1 (yours, class E): closed enums in draft contracts.** `schema-compat` treats any change to
  a JSON-schema `enum` as breaking and asks for a major version. The plan says a break before
  RC-1 is a minor bump recorded in the CHANGELOG. They disagree, and the module host (PR-8) will
  need `OperationKind` values for cross-pocket reads and network calls. Options: (a) keep the gate
  and issue `uaos.operation/2` when PR-8 adds them; (b) let draft contracts take added enum values
  as a minor bump, with readers that refuse unknown values. PR-4 adds no enum value either way.
  **Decided 2026-10-20 (D-35): option (b).** `schema-compat` learns which contracts are draft
  before PR-8.
- `[CONSCIOUS ASSUMPTION]` `MAX_STATE_BYTES` = 64 KiB per module per pocket. **Open:** no
  declaration or child kind writes a pocket chunk yet, so a module that needs more than 64 KiB
  (note bodies) has nowhere to put it. The paper modules (PR-10) decide whether one is added.
- `[CONSCIOUS ASSUMPTION]` Replay without a checkpoint is bounded by the projection's retention,
  which P4's compaction will set; a module that needs more must checkpoint.
- **Owned by the host (PR-8), from the V1 review:**
  - what `EventView` carries for replay: a module event's values, a child outcome's
    correlation tag, and a manifest subscription set. `EventView` is `#[non_exhaustive]`, so
    these are additive (M8);
  - the `error.translate` annotation's declaration (L8);
  - configuration keys with dots and hyphens (`modules.<name>.enabled`), which `Code` cannot
    spell, for the C-61 paper module (L8);
  - binding a `ModuleState` to its pocket in the host's store; this crate only checks the
    cursor (L5).
- **Split to PR-4c under D-31 (round 5), owed before PR-8; built by PR-4c:**
  - M1: the visit budget charges one visit per member a lookup examines, and string
    comparisons stop past `MAX_SELECTOR_TEXT` without decoding the whole value. That gives
    the per-call cost bound §7 does not claim yet, with tests for `Key`, `Each` and `Where` on
    wide objects and long strings;
  - L1: a variation selector's base must be a visible character, not whitespace, a control or
    a default-ignorable code point, and U+E0100–U+E01EF only after a CJK ideograph;
  - L3: a seal holds its tape and builds the view (its V1 review M2), and a key finding on a
    node with no key refuses the seal;
  - L4: `Visits` becomes move-only; a `RoleMap` carries one budget for a codec's `roles()`;
    the host procedure moves into the crate.
- **Owned by PR-8:** the codec's `dimensions()`, snapshot at admission like a module's
  manifest (round 5, L4).
- **PR-8 proof obligations, from the final review:**
  - a hook at `stream.observe`, `stream.assert` or `error.translate` receives the frame or
    error from before rehydration, with a seeded violation that hands it the rehydrated one;
  - a replay discards every declaration, as `a_replay_rebuilds_state_and_declares_nothing`
    shows for the procedure;
  - calls of one module for one pocket never overlap;
  - a host-side refusal keeps the call's state (§5), so replay rebuilds the live state;
  - every call is checked against the admitted manifest snapshot;
  - the host calls a module only through `Admitted::call_hook` and `Admitted::call_event`,
    never its `on_hook` or `on_event` directly (PR-4c V1 review L5);
  - a host builds every view it hands a module or a codec (`roles()`, `usage()`) from a seal
    (`Sealed::view`). The seal refuses a finding it cannot place, where an unsealed view would
    mask nothing for it, and every visit is O(log ranges) (PR-4c final review M2);
  - the Messages codec's `roles()` is measured at the parser's node limit. The `RoleMap` budget,
    `MAX_VISITS`, equals that limit (2^20), so one any-depth role selector on a node-dense
    request near it spends the whole budget, and the request is refused. That fails closed,
    but it would refuse a request the parser accepted, so such selectors are avoided or
    budgeted (PR-4c final review L2);
  - one `Visits` budget per call, a strike (`budget_exceeded`) when spent;
  - `not_own_child` and `unknown_candidate` strike what they name.
- `[CONSCIOUS ASSUMPTION]` (PR-4c V1 review L6) `ModuleText` refuses a variation selector
  that follows no visible base, and nothing else invisible beyond the controls, explicit bidi
  controls and tags of rule 4. Every other default-ignorable code point is accepted, alone or
  in runs, assigned or not: for example U+00AD, U+034F, U+180E, U+200B–U+200D, U+2060–U+2065,
  U+206A–U+206F, U+FEFF and the Hangul fillers. The bidi isolates U+2066–U+2069 are refused by
  rule 4. A format code point that is not default-ignorable, a private-use code point or a
  noncharacter counts as a visible base. ZWJ and ZWNJ are needed in emoji sequences and in scripts such as Persian and the
  Indic scripts, so which others to refuse belongs to ADR-0020 (D-36). The kernel's final scan
  stays the backstop. Owner: ADR-0020's PR, before PR-8.
- `[CONSCIOUS ASSUMPTION]` (PR-4c final review L6) One variation selector after each visible
  base is allowed. So hidden text can still ride on visible text: about 4.3 bits per letter
  (the 16 standard selectors), around 1.1 KB in 8 KiB of text, or about 7.9 bits per CJK
  ideograph (240 ideographic selectors). The rule closes runs, not single selectors. The final
  scan stays the backstop. Owner: ADR-0020's PR, with the rest of L6.
- `[CONSCIOUS ASSUMPTION]` (PR-4c final review L7) The RGI subdivision-flag emoji (England,
  Scotland, Wales) are written with tag characters, which rule 4 refuses, so `ModuleText`
  cannot hold them. Owner: ADR-0020's PR.
- **Debt (PR-4c final review L4):** that comparing a key stops at the first difference is
  `uaos-json`'s `Node::key_is`, and nothing proves it. A full decode would pass every test here.
  Owner: a `uaos-json` work counter, before PR-8.
- **Debt (PR-4c V1 review L7):** the Unicode tables in `decl.rs` and in the test oracle name
  their Unicode 16.0 sources, but nothing checks them against an independent copy of the UCD.
  Owner: WP3.9, before RC-1.
- `[CONSCIOUS ASSUMPTION]` Event values are `i64`. A module that is wrong could still encode
  data in numbers. The trust model is trusted code with minimized authority, not hostile
  code: hostile code waits for P5 sidecars. Declared value names close the realistic leak, a
  word from a prompt used as a name.
