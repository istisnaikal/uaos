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
  `uaos.grant/1`, and the event-naming rule.
- **`uaos-policy` additions** (§8): the Cedar `Pocket` entity and the `memory.read` action.

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
   explains a selector's keys or values, only their counts. Text a module adds (`ModuleText`) is bounded, detected and final-scanned
   like any outbound byte. It refuses control characters other than newline and tab, and the
   explicit bidirectional controls U+202A–U+202E and U+2066–U+2069 (ADR-0020 rule 5).
5. **Redacted by default.** A module sees the redacted structural view. Detection scans keys
   as well as values, so the mask covers strings, numbers and object keys. A masked value or
   key reads as masked, equals no value, matches no name and is never found by name, so no
   predicate's answer depends on masked text. A finding the host cannot place on a value or a
   key refuses the view. No raw view exists at RC-1.
6. **Pocket isolation.** A module's state, events and grants are per pocket (§5). Nothing
   crosses pockets except through a cross-pocket grant (§6.2).
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
| `stream.observe` | observe after forwarding, lossy | frame + stream state | 50 µs per frame, off the relay path | detach and count |
| `stream.assert` | `Cancel` from the next frame; frames held only at high risk; pings never held | frame | 100 µs per frame | high risk: cancel |
| `response.post` | observe after settle | metadata | 5 ms, off the hot path | ignore and count |
| `error.translate` | additive annotation; upstream bytes stay identical. **Observe only in this draft:** the annotation's declaration is added with the host (PR-8) | error + metadata | 200 µs | kernel default |

The pre-egress ceilings sum to 1.3 ms, inside the 2 ms hook budget. **Kernel rule:** at risk tier
2 or more, any veto that fails or times out denies, whatever the manifest says.

**Declarations** (`Decl`, closed, `#[non_exhaustive]`, at most `max_decls` per call):

| Declaration | Allowed at | Effect, performed by the kernel |
|---|---|---|
| `Strip(Selection)` | `ingress.parsed`, `tool.result` | a span splice outside every forbidden role (ADR-0014 §3) |
| `Append { slot, text: ModuleText }` | `ingress.parsed`, `context.assemble` | an append in the newest human turn; the text is detected and final-scanned |
| `Veto(ReasonCode)` | `tool.result` | the Operation is denied and explained |
| `Cancel(ReasonCode)` | `stream.assert` | the stream is cancelled from the next frame |
| `Label(Label)` | `classify` | a label added; risk only rises |
| `Rank(Vec<CandidateId>)` | `route.decide` | a ranking or subset of the candidates offered: 1 to 64, none twice; the host strikes an id outside the offer |
| `Emit(ModuleEvent)` | every hooked point | an event with a declared code and declared value names, each with a number; journaled ones rate-limited per module per Operation |
| `Request(ChildOpRequest)` | every point, with `child_operations` | a child Operation (§6) |
| `CancelOp(OperationId)` | every point | cancels one of the module's own child Operations |
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
  it is not exceeded and its declarations pass. Otherwise the call is a strike
  (`state_exceeded`), and the state is left as it was before the call. A cursor advances only
  on its own pocket's events.
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
  its cursor through `on_event`, so the state is the same as if the module had never stopped. No
  checkpoint means an empty state and a replay from the start of the pocket's journal, bounded
  by the projection's retention.
- **Not synchronized:** ephemeral events (frames, metrics), which are lossy by design (D-9), and
  anything between pockets.

## 6. Child Operations and `GrantRef`

### 6.1 The rule

`Decl::Request(ChildOpRequest)` asks for one child Operation: a kind from the manifest's
`actions`, a `GrantRef` when the action needs one, a body (redacted inputs only; `ModuleText`
for new text) and a correlation tag (a `u16`, never a word). The kernel builds the child under the parent's correlation
id with `parent_operation`, and it passes the full pipeline. Limits (ADR-0010 Decision 6): depth
at most 2; a module's hooks never run on its own children; a per-module quota of children; the
child bills the parent's pool unless its grant names another. The outcome reaches the module as
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
| `frame(&SseEvent)` | `FrameKind` | classifies a stream frame: content, usage, ping, error, end |
| `usage(&StructuralView)` | `Option<UsageReport>` | the billing dimensions the response reports (ADR-0016, M2) |

**`StructuralView`** is a read-only view over the `uaos-json` tape of the request, with the
detection overlay (`Mask`): values and keys holding a finding read as `Masked` (§2 rule 5).
**`Selector`** is ADR-0014 §6's language and no more: `key`, `each element`, `any-depth key`; the
predicates "member is one of", "member is not one of" and "string, or an array with an element
matching"; a `last` modifier. Growing it needs ADR-0014 amended. A selector resolves to node ids
on the tape; roles are kept by node id, so a later edit's role check is O(depth) through `parent`.

## 8. Kernel contract additions (all additive)

| Contract | Addition | Why | Compatibility |
|---|---|---|---|
| `uaos-contracts::id` | `AgentId`, prefix `agt` | one agent instance (a main agent or one subagent) under a credential; subagents often share one key, so a credential alone cannot tell them apart | new type |
| `uaos.event/1` | optional `agent_id` on `EventEnvelope` and `EventDraft`, omitted when absent | CLAUDE.md §4: every request carries its agent id; per-agent spend and the task ledger (C-45, C-30) | a new optional property: non-breaking under `schema-compat` |
| `uaos.grant/1` (new) | `Grant`: id, principal, action, resource, the pocket it applies in, expiry, highest risk tier, data classes, the ask policies it satisfies, for `memory.read` the injection policy, the approval that issued it, and when | the wire form of `uaos_policy::model::Grant`, journaled when issued and when revoked | a new contract |
| Cedar schema | `entity Pocket;` and `action "memory.read" appliesTo { principal: [Agent, Human, Module, System], resource: [Pocket], context: Ctx }` | cross-pocket reads are authorized like every other action, default deny (ADR-0008) | additive; existing policies unchanged |
| Event naming | `<domain>.<event>`, lowercase, `[a-z_]` words, no `uaos.` prefix, as in the code (`op.committed`, `chunk.lost`). Reserved domains: `op`, `budget`, `chunk`, `redact`, `identity`, `kernel`, `module`, `admission`, `egress`, `bus`, `config`, `grant` | Move 1's text used `uaos.module.*`; the code never did. Constants are added by the PR that first emits them | rule only |

**Who fills `agent_id`:** session inference (ADR-0015, M2) from the client's own agent markers;
until then the field is absent and nothing claims per-agent attribution.

**Deferred, with reason:** `uaos.approval/1` lands with the presence ceremony in M3 (WP3.6),
because what an approval must prove depends on ADR-0012, still proposed. M3 precedes the RC-1
freeze, so the contract still freezes with the rest.

## 9. Freeze discipline (D-15)

- Inputs a module receives are `#[non_exhaustive]` and built by the host through
  constructors: `OpMeta`, `Candidate`, `EventView`, `SseEvent`.
- Types a module builds (`Manifest`, `ChildOpRequest`, `ModuleText`) are built through builders.
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
  `undeclared_action`, `feature_not_required`, `bound_exceeded`, `state_exceeded`.

`Debug` output shows identifiers, lengths and counts only, never a view's content, a
selector's keys and values, a frame, state bytes or `ModuleText` (I-11).

## 11. Proof obligations (PR-4)

**Tests:**
- manifest validation refuses each case of §2 rule 7, one case per refusal reason, and every
  refusal code is one §10 lists;
- `requires` is compared by set: an unknown feature, and a feature the kernel lacks, are refused;
- `ModuleState` refuses growth past its bound and leaves the state unchanged, and a call that
  outgrew it is struck whole through the host procedure of §5;
- declarations: a strike for each reason in §10, including an unhooked point, an undeclared
  event value name, an undeclared tool or configuration key, and a ranking past its bound;
- the view: a masked key reads as masked, matches no name and is not found by name; a masked
  number reads as masked; every predicate answers the same whatever the masked text is;
- path patterns match canonical paths by whole segments;
- a `GrantRef` is checked against the live grant at every use (the host's test, PR-8). Building
  one confers nothing (§2 rule 3);
- `AgentId` round-trips; an envelope without `agent_id` serializes to the exact bytes main
  writes (a golden string), because the journal's hash chain covers exact bytes;
- `uaos.grant/1` round-trips and its schema is exported;
- Cedar: `memory.read` across pockets is denied with no grant, allowed with a matching grant,
  denied when the grant names another source pocket, another requesting pocket, or has expired;
  a forbid still wins (ADR-0008 Amendment 1); a permit, named or blanket, only asks;
- `uaos.grant/1`: a `memory.read` grant is on a pocket, and only `memory.read` grants are;
- selectors resolve to the expected node ids, and on generated tapes they name only nodes of
  the view, in document order, without repeats; a role map names only the nodes it was given,
  and the roles of a node outside the view are unknown (`None`), never empty;
- **language neutrality** (`tests/language_neutrality.rs`, gate `language-neutrality`): a
  seven-locale corpus crosses five stages with 0 byte differences: parse, the view, selectors,
  `ModuleText`, and `ModuleState` checkpoint and restore. Two properties hold over arbitrary
  strings. Selectors never fold case (Turkish i, German `ß`). NFC and NFD stay distinct.
  `ModuleText` refuses explicit bidi controls and keeps the implicit marks.

**Seeded violations** (`cargo xtask negative`, gate `test`; the two language cases move to
the `language-neutrality` gate once ADR-0020's PR registers it):

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
| `grant-memory-read-off-a-pocket` | the action and resource pairing skipped | `memory_reads_and_pockets_go_together` |
| `cedar-cross-pocket-without-grant` | a permit allows `memory.read` without a grant | `a_permit_alone_only_asks_for_a_cross_pocket_read` |
| `selector-folds-case` | predicate values compared lower-cased | `selectors_never_fold_case` |
| `module-text-accepts-bidi-override` | the explicit bidi check skipped | `module_text_refuses_explicit_bidi_controls` |

`schema-breaking-change` is re-proven over the new schemas.

## 12. Open questions and conscious assumptions

- **Q1 (yours, class E): closed enums in draft contracts.** `schema-compat` treats any change to
  a JSON-schema `enum` as breaking and asks for a major version. The plan says a break before
  RC-1 is a minor bump recorded in the CHANGELOG. They disagree, and the module host (PR-8) will
  need `OperationKind` values for cross-pocket reads and network calls. Options: (a) keep the gate
  and issue `uaos.operation/2` when PR-8 adds them; (b) let draft contracts take added enum values
  as a minor bump, with readers that refuse unknown values. PR-4 adds no enum value either way.
- `[CONSCIOUS ASSUMPTION]` `MAX_STATE_BYTES` = 64 KiB per module per pocket. Notes and reminders
  keep their bodies in pocket chunks and their index in state; revisit with paper modules.
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
- `[CONSCIOUS ASSUMPTION]` Event values are `i64`. A module that is wrong could still encode
  data in numbers. The trust model is trusted code with minimized authority, not hostile
  code: hostile code waits for P5 sidecars. Declared value names close the realistic leak, a
  word from a prompt used as a name.
