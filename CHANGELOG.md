# Changelog

All notable changes are recorded here. Format: [Keep a Changelog](https://keepachangelog.com/en/1.1.0/);
versions follow [Semantic Versioning](https://semver.org). Contract (schema) changes must appear
here in the same change that alters `schemas/` (docs-with-contract gate).

## [Unreleased]

### Security

- **RUSTSEC-2026-0382: `rustls-webpki` 0.103.15 → 0.103.16.** The affected version could accept
  certificate paths through distrusted emSign intermediates whose private keys are now known.
  `uaos-egress` (the network door) verifies TLS with it. 0.103.16 rejects any path that holds one
  of those keys, the trust anchor included. `cargo-vet` has no imported audit for the delta yet,
  so the new version is exempted with notes on what the delta contains (PD-06). `cargo deny`
  failed on every branch until this update.
- `deny.toml` takes its first advisory exceptions: RUSTSEC-2026-0370, -0371 and -0372
  (`zvariant`, `zbus_names`, `zvariant_derive` unmaintained, merged into zbus 6.0.0). They reach
  the build only through the Linux keyring store (`zbus-secret-service-keyring-store` 1.0.1 →
  `secret-service` 5.2.0 → zbus 5), which has no zbus 6 release yet. They are not
  vulnerabilities; the exceptions end when the keyring store moves to zbus 6.

- P3 Move 1, PR-1: chunk durability joins the journal's durability classes (ADR-0018), and a
  latent chunk race (S-6) in P1 code is fixed.
  - **Race (S-6).** Two concurrent puts of the same content could tear one shared temporary file
    or pair one writer's data file with the other's key, which reads back as `Corrupt`. It was
    harmless while single-threaded, but parallel subagents sharing `system` and `tools` content
    would make it the common case.
  - **The fix:**
    - every atomic write now uses its own temporary;
    - every operation on a chunk (put, flush, recovery, shred) holds that chunk's slot;
    - a shred cannot destroy the key a concurrent put is wrapping under;
    - a chunk left by an earlier process is read back and rewritten, flushed, before it is
      trusted, and a rewrite keeps the chunk's data key.
  - **Proof:** deterministic interleaving tests and seeded violations.
- Payload before record (I-02). A journal opened with its chunk store refuses a record whose
  `payload_ref` is not stored (`JournalError::PayloadNotStored`, new code
  `JOURNAL_PAYLOAD_NOT_STORED`).
- Payload losses are journaled before the records they affect become durable, in simulation
  (`docs/claims.md` gives the exact conditions).
  - **On open:** the journal reads back the payloads of every record after its durable point
    (the whole journal if the marker is missing), rewrites the readable ones, and journals each
    unreadable one as `chunk.lost` before the durable point moves. Unreadable chunks are
    quarantined, never deleted. A keychain that lost the pocket's keys fails closed instead.
  - **After a failed payload flush,** anywhere in the store: the store refuses work and the
    writer stops until `recover` has rewritten what it can read and journaled the rest. Nothing
    is flushed in place a second time, because after a writeback error a second flush can report
    success without writing anything.
  - **A journal that coordinates a store cannot be opened without it.**
  - **Open no longer flushes the previous run's journal segment again.** It moves the records
    after the durable point to a fresh segment, and one flush covers them together with any loss
    records open appends for them. This also closes a latent P1 gap: a failed flush during open
    could drop records the OS still held.
  - **A shred the journal recorded but a crash interrupted is completed when the journal
    opens**; before, the store's startup re-wrapped the leftover key and the content stayed
    readable (pre-existing).
  - **`Journal::shred`** records a shred, flushes the record, rotates the KEK and removes the
    chunk while no other record can be appended, and returns a `PendingRewrap` that re-wraps the
    pocket's other keys once the writer is free (or when dropped); a store a journal coordinates
    refuses a direct shred. The store marks the chunk before the record is appended and neither
    vouches for it nor serves it until a put of the content succeeds or the shred completes; at
    most 4,096 failed shreds stay marked (`ChunkError::ShredBacklog` beyond).
  - **A journal flush is not acknowledged across a poisoning** of the store while it ran, and the
    first open with a store invalidates a plain journal's marker before it records the store.
  - **A KEK rotation writes every readable key file again before destroying old versions**, so a
    re-wrap whose directory flush failed cannot leave a key file only a destroyed KEK opens
    (found by the extended crash schedules; it predates this PR).
  - **Every journal keeps a durable-point marker**, so restarts copy only the records after it;
    a `PAYLOADS` flag file now records that a journal coordinates a store.
  - **Review:** `docs/reviews/WP3.A1-chunk-durability.md` (4 High, 7 Medium, 7 Low, four defects
    found by the extended property test after the fixes, a second round: 1 High, 1 Medium,
    6 Low, a third: 1 High, 3 Medium, 5 Low, a fourth: 2 Medium, 4 Low, a fifth: 2 Medium,
    3 Low, a sixth: 4 Low, a seventh: 1 Medium, 2 Low, an eighth: 1 Low, a ninth: 4 Low, a
    tenth: 4 Low, an eleventh: 1 High, 3 Low, a twelfth: 3 Low, a thirteenth: 4 Low, and a
    fourteenth: 1 Medium, 4 Low).
    New codes `STORE_PAYLOAD_LOST` (lost content reads back as lost, `ChunkError::Lost`, through
    a marker every loss leaves in the pocket's quarantine and a shred removes) and
    `STORE_PAYLOAD_FLUSH_FAILED`. ADR-0003 §3 and §5 carry amendment
    notes pointing to ADR-0018.

- `uaos-policy` hardening after the retroactive review (`docs/reviews/WP2.1-policy.md`; ADR-0008
  Amendment 1):
  - **Crafted policy text aborted the process** (about 80 nested parentheses overflowed Cedar's
    parser). Text is now bounded before Cedar sees it: 8 nested brackets, 16 `if`s, 256 operators
    (brackets included) and 16 KiB per policy, and 4 MiB in all. The scanner skips comments
    exactly as Cedar's lexer does. The bounds were measured against the actual overflow
    points.
  - **Approvals could never complete.** A grant is now the approval:
    - it satisfies the `@effect("ask")` policies it lists, and allows on its own;
    - it covers nothing riskier than approved (risk tier, data classes);
    - a forbid still wins over it.

    Grants are matched natively, and a property proves this equals compiling them to permits.
  - **The proofs behind the slicing and fail-closed claims did not hold.** Slicing is now
    checked against the complete loaded set. The fail-closed property always has an erroring
    forbid and a permit both apply.
  - **Also:**
    - action groups are honoured by slicing;
    - `@id`s are plain (they cannot pose as explanations);
    - templates are refused;
    - a provider name with `/` fails closed;
    - a request clock running more than 5 s backwards is refused;
    - `@reason` texts are returned.

- Ledger hardening after the retroactive adversarial review (`docs/reviews/WP2.2-ledger.md`),
  which found two overspend paths in merged code:
  - **H1:** a ledger rebuilt from the journal accepted reservations before recovery had charged
    an unclosed overrun. A rebuilt ledger now refuses all new work until `recover()` has run, and
    the cap subtracts any overrun not yet closed.
  - **H2:** caller idempotency keys could collide with keys the ledger derives itself, leaving a
    transfer half-applied and recovery failing permanently. Reserved key forms are refused, a
    transfer checks both keys before its first entry, and recovery reports a stuck item (S2)
    while still closing the rest.
  - **Also:**
    - `recover()` is boot-only;
    - `release` and `settle` hand the token back when refused before recording;
    - stricter per-entry validation in `uaos.budget_tx/1` (fields only where they mean something,
      no hold below zero, releases close);
    - transfers cannot create pools;
    - replay refuses refunds and unattached adjustments, which have no producer;
    - a retry must match every field;
    - distinct error codes `UAOS-BUDGET-0005` to `0007`;
    - overruns are journaled at the highest risk tier.
  - **Accepted, with a reason:** the journal does not yet mark when execution began. That
    arrives with the runtime (WP3.3).

- `uaos-redact`: `FinalScanner`'s derived `Debug` printed its known-secret automaton, from which
  a vault secret could be reconstructed exactly. This was found by the retroactive review
  (`docs/reviews/WP2.3-redact.md`, H1) and breaks red line 2. `FinalScanner`, `DetectorSet` and
  the crate-private JSON scanners now have manual `Debug` implementations that show only the
  version, counts and lengths. A canary test proves no 4-byte window of a vault secret reaches
  `{:?}` or `{:#?}`; against the old code it fails on a 7,741-byte dump.
- `uaos-redact` hardening II closes the rest of the retroactive review (ADR-0009 Amendment 1;
  detector set v1 corrected in place, because no release has shipped it):
  - **URL passwords** containing `/`, `#`, `?`, `'` or `@` were not redacted (H2). The password
    now ends at the last `@` that a host follows, before a hard stop.
  - **Keys glued to separators** (`${KEY:-sk-ant-…}`, `_ghp_…`, `KEY_sk_live_…`), keys followed by
    more word characters, and runs longer than a format allowed all leaked (H3). They are now
    covered whole.
  - **Nested encodings** (M1, M2): JSON inside a JSON string (tool arguments, `partial_json`) and
    percent-encoded text are scanned in three views by redaction, by `check_json` and by
    `check_bytes`.
  - **Smaller fixes:** overlapping anchors are found (L2), scanning is linear, with a test bound
    on adversarial inputs (M3), and placeholders follow an exact grammar (L3).
  - **Gate `redaction-corpus` now measures corpus v2** (M4): six evasion forms, every printable
    URL password byte, an independent oracle, and false positives per family (40 families). It
    reports 0 misses and 0 false positives. The pre-fix detectors scored 24.8–64.7 % recall per
    class on it. The new negative case `redact-url-password-stops-at-slash` proves the gate
    catches a one-byte regression.
  - **A second fresh-context review of these fixes** found 2 High, 3 Medium and 3 Low findings.
    All are fixed:
    - JWT scanning went quadratic;
    - a redacted user hid its password;
    - form-encoded keys passed;
    - service URLs and templated passwords were flagged;
    - an escaped left neighbour hid keys;
    - a crafted cascade wedged the session (such content is now replaced whole).
  - **Cost** on a 1.8 MB history where every message is a tool call's JSON arguments: final scan
    p50 8.3 ms. That is above the plan's 6 ms per-stage hypothesis, and is recorded as a WP3.8
    input.

### Added

- P3 Move 1, PR-6a (WP3.A6a): the crate `uaos-runtime`, first half of the runtime spine: the
  kernel stop, admission, the pinned configuration snapshot, declared pricing, the metered relay
  and the supervisor. Contract: `docs/adr/appendix/0013-runtime-relay-and-stop.md`, written before
  the code. The relay core comes forward from PR-7; the state actor, bus and boot recovery are
  PR-6b's.
  - **The stop, the kill switch:**
    - an atomic flag, set before any watcher wakes;
    - admission checks it first (`RUNTIME_STOPPED`, `retry-after` 120 s);
    - every admitted Operation watches it, and every live relay cuts at its next poll;
    - it acts before its record. `Stop::unrecorded` offers the `kernel.stopped` record until
      `Stop::recorded` says it is journaled, and `boot_state` honours it at the next start;
    - only a human's `kernel.resumed` resumes;
    - resume needs presence (M3); the ADR-0010 amendment is open as D-37.
  - **Admission** counts bytes in flight as well as Operations. A permit grows as copies are
    made, and dropping it releases both. A request or a charge that alone exceeds the bytes
    bound can never fit, so it gets `INGRESS_TOO_LARGE`, not retryable.
  - **The relay** is a hyper body the client's connection pulls:
    - no task and no channel;
    - at most one incomplete event held;
    - each event's exact bytes forwarded, zero-copy inside one upstream frame;
    - every frame but a ping read for usage: usage, end and error frames strictly, parsed by
      `uaos-json` (duplicate keys refused, object-shaped data must parse, at most 2^20
      nodes). Content and other frames are read best effort: a report found on one is
      metered, and a parse failure never cuts it, so neither a lone surrogate nor a whole
      fetched document cuts a stream. A report is checked against the codec's dimensions
      and priced against the Operation's reservation. A report naming no dimension is no
      report;
    - the codec's duty, now in `FrameKind`'s doc: a frame holding a usage object is usage,
      end or error;
    - an idle timeout over a year disables the idle cut;
    - one upstream frame forwarded in at most two pieces, with nothing kept per event, and
      an event bound of 32 MiB, the door's request bound. Charging the relay's held bytes to
      the Operation's permit is owed by PR-7.
  - **Settlement:** `RelayReport::settlement`.
    - A cost settles as reported only when it is final: the stream completed, and the
      dialect's end came at or after its last report.
    - A cost past the reservation settles as reported, a lower bound, and records the overrun.
    - Anything else settles the full reservation, estimated: tokens generated after the last
      report are billed but uncounted.
  - **A cut.** The first report one nano-USD over the reservation cuts the stream and engages
    the kernel stop (`BUDGET_STREAM_OVERRUN`, S1); so does a cost past nano-USD's range. These
    cut the stream without stopping the kernel:
    - an unreadable or unpriced report;
    - a malformed or oversized event;
    - an oversized body;
    - an idle or failed upstream;
    - a stop, which says `RUNTIME_STOPPED` whatever engaged it.

    A cut:
    - forwards nothing more;
    - drops the upstream at once;
    - ends in the dialect's terminal frame or in an error, never in a clean end.

    A compressed event stream is refused before any byte (D-29).
  - **Not claimed:**
    - tokens between provider reports are not counted;
    - bytes already forwarded cannot be recalled;
    - tokens generated before the disconnect are billed, which is why an unfinished stream
      settles the full reservation.

    The hard cap stays the pre-request reservation at the clamped `max_tokens` (WP3.5).
  - **Locales:** the configuration snapshot pins an opaque `LocaleTag` per Operation. A publish
    reaches the next pin only, and no Ring 0 type names a locale.
  - **The supervisor** is the runtime's only spawner. Its tasks are bounded, and it is hyper's
    executor for the door. `tokio::sync::mpsc::unbounded_channel` and `std::sync::mpsc::channel`
    are banned workspace-wide (PD-19), each with a canary.
  - **Contract additions:**
    - event types `kernel.stopped` and `kernel.resumed`;
    - error codes `RUNTIME_STOPPED` and `BUDGET_STREAM_OVERRUN`.

    No schema change: types and codes are strings.
  - **Tests:** 60.
    - A property over random events, line endings and chunking (CRLF and the byte-order mark
      split across chunks, the seven-locale corpus): the bytes received are the bytes sent, and
      the events the codec sees are the ones a whole-body event-stream parser reads. 256 cases
      per merge; 20,000 once locally.
    - A journaled stop survives a restart on a real journal.
  - **Measured:** per event on the reference machine: p95 0.7 µs for content and 0.8–0.9 µs for
    a usage report (the budget is 1 ms). About 220 MB/s.
  - **Reviews** (`docs/reviews/WP3.A6a-runtime-relay.md`):
    - V1: 1 High, 2 Medium and 13 Low, all resolved apart from one Low owed to PR-9;
    - the D-31 scoped round: 0 High, 2 Medium and 8 Low, all resolved. An empty usage report
      is no report, and the stop's restart window is stated;
    - the final full review: 0 High, 2 Medium and 7 Low, all resolved. Two parts are owed
      by PR-7, which owns the permit and the response: charging the relay's memory to the
      permit, and a close-delimited client.
    - round 4, scoped: 0 High, 2 Medium and 6 Low, all resolved. Content frames are read best
      effort, so a usage frame mislabelled as content or other is metered when it parses;
      the codec's duty is stated.
    - round 5, scoped: 0 High, 0 Medium and 5 Low, all resolved: a content-labelled usage
      test, the joined data copy sized once, both read bounds pinned from below, and wording.
  - **Negatives:** 26 seeded violations.
- P3 Move 1, PR-4c: the module socket's selector cost and the round-5 Lows split from PR-4 under
  D-31 (`docs/adr/appendix/0010-module-socket.md` §2, §5, §7, §11, §12), written before the
  code.
  Owed before PR-8.
  - **A per-call cost bound:** every member a lookup examines spends a visit, and no
    comparison decodes more than six times `MAX_SELECTOR_TEXT` bytes. One call costs at most
    `MAX_VISITS` visits, each O(`MAX_SELECTOR_TEXT` + log ranges).
  - **`ModuleText`:** a variation selector's base is visible, and an ideographic one follows
    a CJK ideograph. The Mongolian free variation selectors U+180B–U+180D and U+180F now count
    as variation selectors, so a run of them is refused too.
  - **Seals:** `Mask::seal` returns a `Sealed` (`#[must_use]`) that holds its tape and builds the
    view, so a seal is never used over another tape; the runtime relay reads through it, and
    `HookCx::with_view` takes one. A key finding on a node with no key refuses the seal.
  - **Procedure:** `Visits` is not `Copy`; a `RoleMap` carries one budget; the call procedure
    is the crate's own (`Admitted::call_hook`, `Admitted::call_event`).
  - **Tests:** a member scan charged per member; the raw bound at exactly six times
    `MAX_SELECTOR_TEXT`, past which nothing is decoded; one `RoleMap` budget exhausted; a sealed
    view over its own tape; keyless key findings refused; visible bases, ideographic bases and
    the Mongolian free variation selectors.
  - **Negatives:** thirteen seeded violations, and PR-4's variation-run seed retargeted to the new
    rule; one seed of the first draft, `mask-seal-ignores-tape`, was retired with the check it
    seeded.
- P3 Move 1, PR-4 (spec first): the module socket's contract,
  `docs/adr/appendix/0010-module-socket.md`, before any code.
  - **`uaos.module/1` (draft):** a manifest built through a builder, with `requires`, a closed set
    of kernel features compared by set so that a module needing anything the kernel lacks is
    refused at load, never loaded in part. Nine hook points with their modes, ceilings and
    failure policies. Closed declarations; codes, never free text.
  - **Pocket-scoped module state:** bounded per module and pocket, kept in step by an ordered
    cursor over the pocket's journaled events, checkpointed as chunks under the pocket's key, so
    shredding a pocket shreds its module states.
  - **Child Operations and `GrantRef`:** every module effect is a child Operation through the full
    pipeline, carrying a grant reference that confers nothing by itself: the host checks the
    live grant behind it at each use. Cross-project memory is a `memory.read` child Operation
    on a Cedar `Pocket`, default deny, with an injection policy (`auto`, `ask`, `never`) and
    provenance labels.
  - **`uaos.adapter/1` (draft):** the dialect codec's endpoints, roles through ADR-0014's
    selectors only, frames and usage.
  - **Kernel additions, all additive:** `AgentId` and an optional `agent_id` on the envelope,
    and the event-naming rule. `uaos.grant/1`, the Cedar `Pocket` entity and the `memory.read`
    action are specified here and built in PR-4b (`p3/a4b-grant-path`).
    `uaos.approval/1` moves to M3 with the presence ceremony (ADR-0012).
  - D-35, how closed enums grow in draft contracts: option (b), decided by the maintainer on
    2026-10-20. An added value is a minor bump until RC-1, and readers refuse unknown values;
    `schema-compat` learns draft contracts before PR-8.
  - **Built: the contract additions.** `AgentId` (`agt_…`) and an optional `agent_id` on the
    envelope and the journal's draft (absent, it is not written, so existing records keep their
    exact bytes; a lost-payload record inherits the agent of the record it reports).
    `schemas/event.v1.json` gains the optional `agent_id`, a non-breaking change.
  - **Built: the socket crate, `uaos-module-api` (Ring 0, no I/O, `forbid(unsafe_code)`).**
    - The manifest and its builder, validated whole: one refusal per reason, each with a stable
      code.
    - `KernelOffer::admit`, which compares the module API version and every required feature as
      a set.
    - The nine hook points with their deadline ceilings.
    - Declarations checked against the manifest and the point (`check_decls`, one strike per
      reason). Nothing is declared at a point the module did not hook. Event value names,
      tools and configuration keys must be declared, and a child Operation's correlation tag
      is a number, so no word from content reaches journal metadata through a code or an
      event. Selector keys and values may come from content, so the host journals only their
      counts.
    - Pocket-scoped `ModuleState`, bounded at 64 KiB, reached by a hook only through a
      `StateMut` handle it cannot swap. A refused change marks the state `exceeded`, so the
      host keeps a call whole or strikes it whole. The `PocketCursor` moves
      forward and only on its own pocket's events.
    - The redacted structural view and ADR-0014's selectors, with bounded predicates.
      Detection's mask covers keys and numbers as well as strings. Masked text is unknown: it
      equals no value and matches no name, so no predicate's answer depends on it.
    - Endpoint path patterns match canonical paths by whole segments. `classify` denies a path
      that is not canonical or matches no endpoint, and picks the most restrictive class on
      overlap.
    - Role maps, and the `uaos.adapter/1` codec trait.
    - Every `Debug` shows sizes and identifiers only, selectors and stream frames included.
    - The inputs a module receives (`OpMeta`, `Candidate`, `EventView`) are `#[non_exhaustive]`
      with constructors, so they grow without a break.
    - V1 review (`docs/reviews/WP3.A4-module-socket.md`): 2 High, 8 Medium and 8 Low,
      resolved or assigned to the host (PR-8). A scoped second round (0 High, 2 Medium, 6 Low)
      and the final review (2 High, 6 Medium, 12 Low) are resolved; that review's M4 and M5 moved
      with the grant path to PR-4b. A fresh full review (1 High, 5 Medium, 7 Low) is resolved
      too. 31 seeded violations.
    - A replayed event is marked (`EventView::replay`), so the host can rebuild state and
      discard the declarations. Two further rules are contract text and PR-8 proof obligations,
      not code here: hooks see frames and errors from before rehydration, and one call of a
      module per pocket runs at a time.
    - A module is checked against the manifest it was admitted under (`Admitted`).
    - Masks seal against their tape, and every selector resolution spends a visit budget. No
      per-call cost bound is claimed yet: member scans and string decodes are not charged, and
      that is PR-4c's, split under D-31, before PR-8.
    - Codecs declare their billing dimensions.
    - A strip keeps its anchor and never touches masked content.
    - A strip may not enclose a forbidden role (`RoleMap::touching`, `RoleMap::may_strip`), and
      a masked container masks everything inside it.
    - `ModuleText` refuses Unicode tag characters and accepts CRLF.
    - The `language-neutrality` merge gate (ADR-0020) is active: the seven-locale corpus runs in
      the `test` job, and three seeded violations prove it bites (a case fold in selectors, an
      accepted bidi override, an accepted tag character).
    - **Language-neutral (ADR-0020).** No type names a locale. `ModuleText` keeps any language
      byte for byte and refuses explicit bidi controls (U+202A–U+202E, U+2066–U+2069). A
      seven-locale corpus (EN, TR, DE, FR, ES, IT, AR) crosses five stages with 0 byte
      differences: parse, the view, selectors, `ModuleText`, and state restore. Selectors never
      fold case, and NFC and NFD stay distinct.

- P3 Move 1, PR-4b (spec first): grants on the wire and cross-pocket consent,
  `docs/adr/appendix/0008-grants-on-the-wire-and-cross-pocket-consent.md`. Split from PR-4 (#32)
  at the maintainer's choice, with PR-4's final review findings M4 and M5.
  - **Moved from PR-4 unchanged:**
    - `uaos.grant/1`;
    - the Cedar `Pocket` entity and the `memory.read` action;
    - the consent rule: only a live grant allows a read of another pocket, and a permit at most
      asks.
  - **M4:** a request names the grant it carries, only that grant can satisfy it, and the
    decision cites it.
  - **M5:** `uaos.grant/1` becomes the exact wire form of the engine's grant, with conversions both
    ways.
  - **Built (moved from PR-4 unchanged):**
    - `uaos.grant/1` (`schemas/grant.v1.json`): a grant entry, issued or revoked. Its record
      validates its expiry and its bounds, and that `memory.read` and a pocket resource go
      together. As amended under M5, an injection policy appears exactly on the cross-pocket
      ones, and a grant on the reading pocket itself carries none.
    - The Cedar schema gains `entity Pocket` and the action `memory.read`; the model gains
      `Action::MemoryRead` and `Resource::Pocket`.
    - A read of another pocket is allowed only by a grant. A permit alone only asks, a read of
      the own pocket follows policy, and a forbid still wins over a grant
      (`cross_pocket_memory_reads_need_a_grant`, `a_permit_alone_only_asks_for_a_cross_pocket_read`).
  - **Built: the carried grant (M4).** `Request` names the grant it carries (`grant`). When it
    does, only that grant can satisfy the request. A cross-pocket read naming none is never
    allowed, and the decision cites the grant that allowed it, so with two live grants for one
    read, the carried one decides.
    - Tests: `only_the_carried_grant_allows_a_cross_pocket_read`, and a property over random
      grants, permits and named grants.
  - **Built: the exact wire form (M5).**
    - Model resources carry their provider.
    - Names and data classes take the engine's `Name` grammar (`GrantName`, `DataClass`), and
      `approves` takes its policy-identifier grammar (`PolicyId`).
    - Humans and the kernel can hold grants.
    - `uaos-policy::wire` converts both ways: `Grant::try_from(&GrantRecord)` and
      `grant_record`.
    - The engine loads only grants the wire can hold (`check_grant`, at load and when
      journaling) and no grant id twice. Properties show that every grant it loads round-trips
      and that the name and policy-identifier grammars agree.
    - A `memory.read` grant on the requesting pocket itself is valid, carrying no injection
      policy, so an ask on an own-pocket read can be approved and journaled.
    - Reviews (`docs/reviews/WP3.A4b-grant-path.md`), all findings resolved:
      - V1: 0 High, 2 Medium, 5 Low;
      - the D-31 scoped round: 0 High, 1 Medium, 5 Low;
      - the final full review: 0 High, 1 Medium, 4 Low.
    - 10 seeded violations.
    - `schemas/grant.v1.json` follows; the contract is new on main, so no reader is broken.
- P3 Move 1, PR-2 (WP3.A2): `uaos-json`, the one structural tokenizer (ADR-0014). Nothing calls
  it yet; `uaos-redact` and its final scan are untouched.
  - **The crate:**
    - one forward pass over a complete buffered body, with no recursion, into a flat tape of
      24-byte nodes that `Tape::verify` re-checks;
    - lazy, allocation-free reads;
    - one strict string decoder, with an offset map;
    - the kernel's one encoder, whose bytes equal `serde_json`'s;
    - integer readers with range checks;
    - errors and `Debug` output carry no input bytes;
    - one dependency, `memchr`.
  - **Tests:** grammar (each error's kind and offset), properties, a differential against
    `serde_json` read strictly, property fuzzing, and no payload in `Debug`. A one-off
    20,000-document differential found 0 disagreements; 13 numbers outside the f64 range were
    accepted by the tape only, which is the known divergence.
  - **Seeded violations:** `arch-json-io-dependency` and fourteen `json-*` cases: one per
    fail-closed rule, one for the oracle, five for the fingerprinted duplicate check and one for
    its run scratch's bound.
  - **Duplicate keys are fingerprinted.**
    - Each key is fingerprinted over its **decoded** bytes as it is read, so an escaped and an
      unescaped spelling of a key always share a fingerprint.
    - When an object closes, objects of up to 8 members compare fingerprints pairwise, and
      larger ones sort them. Only members that share a fingerprint are compared exactly.
    - A collision costs an exact comparison, never a wrong answer. In a run of shared
      fingerprints each escaped key is decoded once and keys are compared as bytes, so keys
      crafted offline to collide (the fingerprint has no key and can be run backwards) cost
      1.4–1.6 times a control of the same shape, not the 12–15 times the V1 review measured
      before the fix.
    - A test pins a real colliding pair; unit tests prove the word-at-a-time and byte-at-a-time
      fingerprints agree at every length and craft 2,000 colliding keys; a nested property
      checks every spelling against an exact oracle.
    - The control-byte check runs branch-free over each run of string bytes.
    - The side stack takes 8 bytes per key of the open objects, at most 8 MiB.
  - **The V1 review** (`docs/reviews/WP3.A2-json.md`): 0 High, 4 Medium, 9 Low, and a scoped
    second round over the fixes, 0 High, 2 Medium, 4 Low, all resolved there. Beyond the collisions: a repeat is found when its object closes, now stated and
    pinned; the offset map and the decoded text are reserved exactly; the node limit no longer
    hides a grammar error; `decode`, `decode_mapped` and `encode_str` return `OutOfMemory`
    instead of aborting, so `encode_str` now returns a `Result`.
  - **Measured** on the reference machine, recorded in the contract's §10:
    - parse p95 is **1.853–1.868 ms over 5 runs** at 1.70 MB, or 0.91 GB/s: within the 2 ms
      stage budget, with 7% headroom on this machine only. The first version measured 2.187 ms,
      9% over; the fix stayed within the stage;
    - one object of a million members now parses in about 53 ms instead of 166 ms;
    - the tape takes 384 KiB for that body;
    - every adversarial input is bounded, and `tests/adversarial.rs` asserts each outcome.
  - **First coverage-guided run:** 10,872,985 runs of `parse` and 79,948,806 of `decode` in
    30 minutes each, with 0 crashes.
  - **Contract first:** `docs/adr/appendix/0014-uaos-json-tape.md` covers:
    - a one-pass, fail-closed RFC 8259 grammar (a byte-order mark refused, duplicate keys
      compared after decoding, numbers grammar-only);
    - limits of 32 MiB, depth 128 and 2^20 nodes;
    - a 24-byte node with eight structural invariants;
    - memory bounds (at most 24 MiB of tape at the defaults; about 384 KiB for a 1.7 MB
      transcript);
    - its proof obligations.
  - **`arch.toml`:** declares the crate with no workspace edge and bans async, network, TLS and
    storage crates and `serde_json`, which is its differential oracle and a dev-dependency only.
    `uaos-redact`, `uaos-module-api` and `uaos-runtime` may depend on it.
  - **D-30 (coverage-guided fuzzing)** is in the decision register.
  - **Fuzzing (D-30):**
    - `fuzz/` is a cargo-fuzz workspace of its own, excluded from the UAOS workspace, never
      shipped, with its own lockfile. It has two targets: `parse` (arbitrary bytes; every tape
      must pass `Tape::verify` and decode everywhere) and `decode` (the decoder and the tape
      agree, the offset map keeps its rules, encoding round-trips).
    - The nightly lane runs each target for 30 minutes on Linux under a pinned nightly
      toolchain, with generated seeds; the tape's heap bound is asserted on every input, and
      single allocations over 64 MB fail the run. It first checks the fuzz workspace's supply
      chain against `deny.toml`.
    - `deny.toml` allows NCSA for `libfuzzer-sys` alone, which vendors LLVM's libFuzzer.
      Without the exception that workspace fails its licence check; the UAOS workspace never
      contains the crate.
    - The nightly lane also runs the tape's property fuzzing at 1,000,000 cases per property
      and its differential at 100,000, and adds `uaos-json` to mutation testing.
    - `.github/CODEOWNERS` covers `/fuzz/`.
- Maintainer decisions of 2026-10-15:
  - **Accepted ADRs:** ADR-0010 (as revised), ADR-0011, ADR-0013, ADR-0014 (as revised, after
    the WP3.0c spike), ADR-0018 and ADR-0019 (with Amendment 1). ADR-0011's code merged a day
    before its acceptance; that is recorded as a deviation.
  - **Ruleset:** the ADR-0019 ruleset is applied to `main` (id 25183857). It requires PRs with
    rebase-only merges, linear history, the checks `merge-gate` and `codeql`, and code scanning,
    with no bypass actors (PD-17).
  - **Threat model:** v1 is signed by the maintainer as the single signer (PD-10). This closes P2.
  - **Decision register:**
    - D-19, D-20, D-21, D-22 and D-26 are decided;
    - D-29 (when to ask providers for an uncompressed stream) is registered as open.
  - **New files:**
    - `docs/release/signing-and-identity.md`: the steps for code signing (D-19) and the
      repository move (D-22), and who does each;
    - `.github/workflows/live.yml`: the live-provider lane (D-21). It runs only on the schedule
      and on dispatch from `main`, in the protected `live-providers` environment, which fork
      PRs never reach. For now it proves its wiring at zero token cost.
- P3 Move 1, Gate 0 records (plan v2 PD-08, PD-10, PD-17):
  - **`merge-gate` CI job.** It `needs` every other `ci.yml` job, runs even when one failed or
    was skipped, and fails unless all succeeded.
  - **Ruleset narrowed (ADR-0019 Amendment 1).** The required checks in
    `docs/adr/appendix/0019-main-ruleset.json` are now `merge-gate` and `codeql`, so adding a
    job never needs another settings change.
  - **New registry checks in `cargo xtask gates`.** The merge gate's `needs` must equal the
    workflow's other jobs, and the ruleset must require exactly those two checks. Every active
    merge-lane gate must be covered by a required check.
  - **Phase check.** `gates.toml` gains `[project] phase`. The README status heading and the
    roadmap's "Current phase" line must name it, which makes the phase-line check that PD-08
    promised real.
  - **Seeded negatives:** `merge-gate-missing-job`, `docs-phase-line-stale`.
  - **Threat model v1.** Statuses reflect P1 and P2; scoped-credential assets are added; the
    in-process-module and CI trust boundaries are added; rows T14 to T19 are added (T18: module
    misbehaviour; T19: parser differential and decoding bombs). It awaits the maintainer's
    single-signer sign-off (PD-10).
  - **Privacy data flow v1.** It lists OS certificate checks (OCSP, CRL, AIA) triggered by TLS
    to the provider, and the machine metadata Claude Code puts in its own requests (CAP-3, CAP-8,
    CAP-10). The P3 in-process design is marked as not yet built.
  - **Claims registry.** It gains the scoped-credential claim that the README states.
  - **ADR-0010 Revision 1** (still Proposed; revised before the decision):
    - the typestate follows ADR-0002's full order;
    - execution starts at the door;
    - balanced-mode recovery settles open reservations at full cost and never releases them on
      a missing `op.executing`;
    - module effects are child Operations authorized by a `GrantRef`, and modules hold no I/O
      handles;
    - CPU stages run off the async workers;
    - the panic boundary has owners.
  - **ADR-0014 Revision 1** (still Proposed; ready for a decision):
    - a `system_message` role for mid-conversation `role: "system"` messages (CAP-6);
    - an exact definition of the newest human turn;
    - the evidence from the WP3.0c splice spike (`docs/adr/appendix/0014-splice-spike-2026-10-15.md`).
      Over 10,000 simulated turns under random client reformatting the values stayed stable,
      and both design counterfactuals broke them.
    - Decision item 6 states what the spike taught:
      - transforms are pinned per chunk value, keyed with the detector version and the
        transform configuration;
      - chunk digests exclude volatile members;
      - replayed edits are their own class;
      - the selector set is closed;
      - numbers are grammar-only.
- `uaos-egress`, the one outbound door (P3 Move 1, PR-5; ADR-0013, threat T5).
  - **Destinations.** Only declared upstreams, named by DNS names. Address literals are refused
    in every spelling.
  - **DNS.** The door resolves names itself, within a timeout, classifies every answer, and
    dials the classified address, at most four per attempt. It refuses every special-purpose
    range, including IPv4 embedded in IPv4-mapped, NAT64 and 6to4 forms, and Teredo; a
    well-known NAT64 address of a public IPv4 address is public, so IPv6-only networks reach
    IPv4-only providers through DNS64. An upstream
    declared private may also reach loopback, private and unique-local addresses, never
    link-local (the metadata service). Plain HTTP is dialled only at pinned local addresses and
    never resolved.
  - **TLS.** On aws-lc-rs, HTTP/1.1, against the system's root certificates read locally and
    verified by rustls: a handshake fetches nothing, so a server's certificate cannot make UAOS
    contact an address of its choosing. Revocation is not checked (ADR-0013 Amendment 1,
    accepted 2026-10-16).
  - **Requests.**
    - Redirects are returned, never followed, and nothing is retried.
    - The URI comes from the upstream's declaration; the path must start with `/`.
    - Only GET, HEAD, POST, PUT, PATCH, DELETE and OPTIONS are sent. TRACE, which would echo
      the credential back to the caller, CONNECT and extension methods are refused before
      contact.
    - A `101 Switching Protocols` answer, and any `transfer-encoding` but one field whose
      value is `chunked`, are errors. A `content-length` sent beside `transfer-encoding` is
      dropped, a `204` keeps none, and otherwise it is forwarded as one value when all its
      values are the same digits (hyper checks it only where it reads a body).
    - Hop-by-hop headers, `host` and `content-length` are stripped and no UAOS header is added.
    - A request carrying one of the listed credential-bearing headers (`authorization`,
      `cookie`, provider key headers and others) is refused, before anything is stripped.
    - The provider credential is inserted last; its value is never printed.
    - Errors say whether the request may have reached the provider: `Unreachable` and
      `Timeout` mean nothing was sent (retryable), also when the connection fails while hyper
      sets it up; new codes `EGRESS_INTERRUPTED` (cut off or unanswered after the request was
      sent) and `EGRESS_UNUSABLE_RESPONSE` (answered in a form the door does not pass on, or
      could not parse) are not retryable and say the provider may have billed it. A response
      timeout that runs out before the request reached a connection is `Timeout`. `Door::new`
      refuses a response timeout that does not exceed the connect phase, and an idle timeout
      over a day.
    - One send per Operation; a request bound to another Operation is refused.
    - A circuit breaker per upstream counts transport failures and lets one probe through
      after its cooldown; a probe whose caller gives up lets the next attempt probe, and a
      probe that settles after the circuit moved on changes nothing unless it answered. A
      transport failure counts only if its attempt was admitted since the circuit last closed
      after an outage. While a probe is in flight, `retry_after` is a 1 s hint.
    - IPv6 forms that embed a local IPv4 address are never treated as local, and the IPv6
      cloud metadata endpoints are refused.
  - **Connection tasks** run on an executor the runtime provides.
  - **Error codes** `UAOS-EGRESS-0001` to `0007`: blocked, unreachable, timeout, circuit open,
    refused, interrupted, unusable response.
- Reachability rules for the door (ADR-0010).
  - **`clippy.toml`.** Outbound connects (std and tokio, `TcpSocket` included, Unix streams
    and datagrams, Windows named-pipe clients), name resolution (`lookup_host`,
    `to_socket_addrs`, hyper-util's `GaiResolver`), UDP and building another HTTP client are
    banned outside the door; listening (`TcpListener::bind`, `TcpSocket::listen`, Unix
    listeners, Windows pipe servers) outside the API crate; every std file-system, `Path`,
    link and ownership call outside `uaos-platform` (a Windows UNC path reaches the network),
    and every `getrandom` entry point; `OsFs` refuses UNC and device paths in every prefix
    spelling (the NT `\??\` one included), any path starting with two separators, and a bare
    volume (`\\?\C:`); task and
    thread spawning,
    and the `JoinSet`, `LocalSet` and hyper-util `TokioExecutor` types, outside the runtime;
    `Door::new` outside its one owner.
  - **`cargo xtask clippy`** is the clippy gate: clippy with warnings denied, in plain text,
    failing also on a `clippy.toml` ban whose path resolves to nothing (clippy itself only
    warns). **Ban canaries** (`crates/uaos-egress/tests/bans.rs`) call every banned item under
    `#[expect]` on the systems where it exists, so a ban that stops firing fails clippy there.
    The negative runner skips a case written for another operating system without counting it
    as skipped. **`cargo xtask allow-audit`** also fails on a ban without a canary and on lint
    switches outside attributes: a nested `clippy.toml`, a member's own `[lints]`, a workspace
    lint table not denying a guarded lint, Cargo configuration naming `CLIPPY_CONF_DIR` or lint
    flags; it reads every mention of a guarded lint in code (macro-built attributes, lint
    groups, old names), refuses `#[path]` and `include!` outside owners, allows only `[alias]`
    in Cargo configuration (names in any case), refuses build scripts (every one `cargo
    metadata` lists) that name one of clippy's variables or keep code in another file, and path
    build-dependencies, reads `.rs` files in any case, and checks each canary's shape: its item
    spelled by the item's own path, and no other ban of the same lint spelled by its full path in
    its function. `cargo
    xtask clippy` neutralises the
    environment of the clippy it runs (compiler flags, wrapper, clippy's arguments) and pins
    clippy's configuration to the workspace root.
  - **`arch.toml`.** The bin's allow list is now explicit and leaves out the door; the bin
    reaches it only through the runtime. `uaos-module-api` and every Ring 1 crate are banned,
    transitively, from network, TLS and async-I/O crates (new `[ring1] ban`, enforced by
    `cargo xtask arch-check`).
  - **`deny.toml`** bans `ring`.
  - **Seeded violations (57):** `egress-dials-private-range`, `egress-numeric-host`,
    `egress-private-reaches-link-local`, `egress-plaintext-resolved`,
    `egress-breaker-admits-after-cooldown`, `egress-probe-stuck-on-cancel`,
    `egress-embedded-local`, `egress-sends-trace`, `egress-forwards-switching-protocols`,
    `egress-forwards-contradicting-length`, `egress-forwards-unknown-transfer-coding`,
    `egress-forwards-repeated-length`, `egress-forwards-bodiless-length`,
    `egress-delivered-reported-unsent`, `egress-timeout-reported-unsent`,
    `egress-unsent-reported-delivered`, `egress-unassigned-timeout-reported-delivered`,
    `egress-canceled-reported-delivered`, `egress-ctor-outside-root`,
    `net-dns-outside-egress`,
    `net-resolver-outside-egress`, `net-connect-outside-egress`, `net-udp-outside-egress`,
    `net-listen-outside-api`, `net-socket-listen-outside-api`, `spawn-outside-supervisor`,
    `spawn-through-tokio-executor`, `clippy-ban-path-unresolved`, `clippy-ban-silenced`,
    `clippy-config-nested`, `lints-not-inherited`, `cargo-config-clippy-override`,
    `clippy-ban-without-canary`, `allow-audit-lint-group`, `allow-audit-macro-attribute`,
    `allow-audit-path-module`, `allow-audit-nested-target`, `workspace-lints-group-allowed`,
    `clippy-config-case`, `cargo-config-not-alias`, `build-script-clippy-env`,
    `build-script-declared-path`, `canary-malformed`, `canary-calls-another-item`,
    `canary-copied-from-sibling`, `canary-setup-calls-another-ban`, `build-script-module`,
    `build-dependency-path`, `build-script-include-in-owner`,
    `arch-ring1-depends-on-hyper`; on Unix only `net-unix-connect-outside-egress`,
    `net-unix-connect-addr-outside-egress`, `net-tokio-unix-connect-outside-egress`,
    `net-unix-socket-connect-outside-egress`; on Windows only (not run in CI)
    `net-named-pipe-outside-egress`, `osfs-doubled-separator-unc` and `osfs-bare-volume`.
  - **Review:** `docs/reviews/WP3.A5-egress.md`, eighteen rounds, all resolved: 2 High,
    4 Medium, 9 Low; then 1 High, 2 Medium, 7 Low; then 1 Medium, 5 Low; then 1 Medium, 5 Low;
    then 2 Medium, 4 Low; then 2 Medium, 2 Low; then 1 High, 2 Medium, 3 Low; then 1 Medium,
    7 Low; then 4 Low; then 2 Low; then 3 Low; then 2 Low; then 1 Medium, 2 Low; then 2 Low;
    then 2 Low; then 1 Medium; then 5 Low; then 4 Low. Two fixes rest on ADR-0013 Amendment 1,
    accepted by
    the
    maintainer on 2026-10-16.
- Dependencies for the ADR-0013 stack: tokio, hyper 1, hyper-util, http, rustls 0.23
  (aws-lc-rs only), tokio-rustls, rustls-native-certs, and rcgen for tests only.
  - 48 cargo-vet exemptions, each with a written reason (the unnoted baseline is unchanged);
    21 of them are lockfile-only crates that compile for no target.
  - cargo-vet 0.10 ignores the newer Bytecode Alliance audits for this stack, so they are not
    imported yet.

- ADR-0018 balanced chunk durability (P3 Move 1, PR-1).
  - `ChunkStore::open_with(…, ChunkDurability::Balanced)`: puts hand chunks to the OS, unflushed.
  - `Journal::open_with_payloads`: every journal flush makes the pending chunks durable before
    the segment, and records the durable point in `journal/FLUSHED`.
  - `Journal::lost_payloads()`.
  - Kernel event type `chunk.lost`: a `chunk.lost` or `chunk.shredded` record names its chunk
    in metadata key `chunk`.
  - `Fs::write_unsynced` and `Fs::sync_file` on both filesystems.
- **Tests and harness:**
  - `uaos-state/tests/durability.rs`: flush ordering under every injected flush fault, random
    crash and power-loss schedules, rotation durability, torn-chunk rewrite and the S-6
    interleaving.
  - **Kill harness:** the writer now stores a payload before each intent, and the harness
    reads every acknowledged record's payload back.
  - **New seeded violations for `journal-durability`:** `chunk-flushed-before-sync`,
    `intent-before-chunk-write`, `chunk-put-pair-race`, `chunk-put-shared-temp`.
- `journal-ack-bench` gains `chunk-put-balanced` and `group-flush-chunks`. The reference-machine
  numbers are in `docs/adr/appendix/0018-chunk-put-2026-10-15.md`: ADR-0018's p99 ≤ 0.5 ms
  balanced-put target is **not met** on Windows (1.55 ms after the first review's fixes,
  `fc4b5a8`; not re-measured after later rounds), where file
  creation dominates. Until the state actor (WP3.3), the request whose append finds the flush
  window due pays for the flush.
- Gate `journal-durability` gains thirty-six more seeded violations, one per class found by
  the WP3.A1 review rounds (every round but the eighth, which added a property test) and the
  extended property tests (forty for ADR-0018 with the four above, forty-one in the
  gate). The nightly lane runs both chunk-durability properties at 20,000 schedules each per
  OS; merges run 64. Their oracles require, after a process crash, the payload of every
  acknowledged record no failed flush could have dropped, and a clean recovery to leave
  nothing refusing work and a journal that reads back whole; their failed appends tear the
  segment, as a full disk does, and the simulated OS writes back on its own, so a record can
  survive a power loss without its payload.
- A payload flush failure no longer replaces the writer's out-of-space or write failure, so
  `recover` always leaves a segment that may end in a torn line; before, it could return `Ok`
  and append after the torn bytes, and the journal then failed to open (WP3.A1 eleventh round,
  H1, present since the first round's fixes). A loss already waiting to be journaled is not
  queued twice.
- A chunk store that a journal coordinates refuses `recover_pending`, `take_lost` and
  `verify_and_sync` from callers (`ChunkError::LossesThroughJournal`; `take_lost` now returns a
  `Result`), and `Journal::recover` recovers a poisoned store whatever state the writer is in.
- `cargo xtask negative` refuses a seed anchor that occurs more than once in its file: the
  first match could be another site, and the case would then prove nothing.
- `uaos-state`'s `tampering_is_detected` flips the last byte of the tag instead of writing 0:
  the nonce is OS-random, so the byte was already 0 one run in 256 and the test then failed
  (a flake since P1, found while verifying the ninth WP3.A1 review).
- Gate `policy-semantics` (active), proven by three seeded violations: slicing that drops
  unconstrained policies, an engine that skips an erroring policy, and a grant that overrides a
  forbid.

- `docs/decisions.md`: a register of open decisions with class, default and deadline. Decisions
  the next release depends on carry markers, so `xtask decisions --release` sees them.
- `docs/roadmap.md` (public roadmap), `docs/rfcs/` (process and template), `MAINTAINERS.md` (with
  the single-maintainer risk stated), `docs/research/name-check.md`.

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

- `docs/research/beachhead-facts.md` (plan v2 WP3.0a). It records the gateway requirements of
  Claude Code (16 facts) and Codex (6 facts), each with its source, date and consequence. Codex's
  Responses-only wire API is confirmed from the official configuration reference. What
  documentation cannot settle (Responses storage and encrypted reasoning as actually sent, the
  exact endpoint inventory) is listed as open until a traffic capture, which waits for the
  maintainer's go-ahead.

- P2 WP2.4: `uaos-identity`, scoped credentials (ADR-0011, proposed; cells C-07, C-08, C-09).
  - **Format:** `uaos_sk_` + 52 Crockford-base32 characters + a CRC-32 checksum. Parsing is
    strict, and look-alikes are rejected without a lookup. UAOS's own redaction class for the
    format follows in WP2.4b.
  - **Storage:** only an HMAC-SHA-256 digest under an identity key kept in the OS keychain. The
    secret is shown once and never journaled. A missing or malformed key while credentials exist
    is reported as lost (`UAOS-IDENTITY-0011`), never silently replaced.
  - **Hierarchy:** master → sub → child, at most four credentials per chain, at most 4,096 live
    credentials and 256 live children per parent. A scope is exact-or-prefix patterns over
    actions and resources, plus pockets, pools and an expiry. child ⊆ parent is checked at
    issuance; records are immutable. Issuing under a chain that is not live, or with an expired
    scope, is refused. A request that omits a dimension the scope restricts is denied.
  - **Revocation:**
    - revoking one credential, or bumping an epoch to revoke a whole subtree;
    - both are critical journal entries recorded before they return; the revocation counter in
      the OS keychain is raised afterwards.
  - **Restore guard:**
    - a keychain counter *ahead* of the journal means a restored data directory: verification
      and every write fail closed (`UAOS-IDENTITY-0005`) until one atomic `restore_recovered`
      entry revokes every live master;
    - *one behind* is an interrupted keychain write, repaired on open;
    - *further behind* or implausibly large fails closed (`UAOS-IDENTITY-0012`).
  - **Recording failures:** like the ledger, a failed recording poisons the writer until it is
    replayed from the journal. Request mistakes are user errors (`UAOS-IDENTITY-0013`), not
    internal failures.
  - **Tests:** random hierarchies with revocations and epoch bumps are checked against an
    independent model, with an independent coverage oracle: anything a credential covers, every
    ancestor covers. They run 256 times per merge and 10,000 nightly, with an anti-vacuity
    check. Regression tests cover each finding of the adversarial review
    (`docs/reviews/WP2.4.md`).
  - **Gate self-test:** a seeded verification that ignores an ancestor's epoch fails the
    property (`identity-epoch-check-skipped`).
- Contract (new): `uaos.credential/1` (draft until RC-1), new kernel event type `identity.entry`,
  and error codes `UAOS-IDENTITY-0003` to `0014`.
- `uaos-contracts::limits`: `MAX_SCOPE_ITEMS`, `MAX_CREDENTIAL_DEPTH`, `MAX_CREDENTIAL_TOKEN`,
  `MAX_LABEL_CHARS`, `MAX_LIVE_CREDENTIALS` and `MAX_LIVE_CHILDREN`. The validated-string serde
  macro is now shared between contracts.

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
- P2 WP2.2 — `uaos-ledger`: pools, reservations, settlement and transfers in integer nano-USD
  (float arithmetic denied).
  - **What the cap guarantees:** a reservation or outgoing transfer beyond the pool's available
    balance is refused before anything is recorded. Spend above a reservation (provider usage
    above the estimate) is recorded truthfully as an overrun, can take a pool negative, and is
    an S1 condition; the clamp and pricing reconciliation of P3 keep it rare.
  - **Typestate:** reservations are typestate tokens. `Held` can be released; once `begin` makes
    it `InFlight` it can only be settled (releasing it does not compile). A reservation id is
    single-use, so no duplicate token can exist.
  - **Recording:** every entry is recorded (journal `budget.entry`, critical) before it takes
    effect. It survives a process kill; within the power-loss window W it can be lost
    (ADR-0003). A recording failure poisons the ledger until it is replayed from the journal.
  - **Recovery:** settles open reservations at full cost, marked estimated, and never releases
    them; it also completes partial settlements and half-recorded transfers.
  - **`budget-concurrency` gate, active:** a randomized simulation against a reference model runs
    256 schedules per merge and 100,000 nightly (16.7 s locally), covering crashes and recording
    failures before and after the write. Contended threads and the journal round trip are also
    tested. A seeded ledger that skips the cap check proves the gate bites. Required behavior
    `budget-double-spend` is active.
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

### Fixed

- Redaction (ADR-0009 Amendment 2): a URL password that starts with `//`
  (`https://u://pw@host`) was missed by detection and by the final scan. CI found it on PR
  #41's Windows run (seed 4814893562051029426).
  - **Fix:** after a plain user, the anchor at that `://` continues the password. Each anchor
    still reads its own URL, so a chain only adds. The scan stays linear.
  - **Narrowed:** a broader first version, any `://` in a password, was narrowed after three
    review rounds to the shape CI found. Every other `://` in a password stays a stated
    limit.
  - **Generator:** the corpus generator now leaves out every stated miss a random password can
    reach, the older `host:port/path` and template shapes included. A stress run had drawn
    one (seed 3677357430622100055).
  - **Corpus:** a new negative family, `url-glued`.
  - **Tests:** the CI seed is a fixed case, with unit tests for the shape, for `host:port`
    URLs before another URL, and for URL lists and glued URLs.
  - **Across rounds:** a redacted `//` password's placeholder does not count toward the window's
    bound, so it never pushes the rest of its URL out of reach.
  - **Negatives:** four seeded violations, `redact-url-separator-ends-userinfo`,
    `redact-url-chain-any-user`, `redact-url-chain-blocks-next-url` and
    `redact-url-placeholder-counts-toward-bound`.

- **`WallTime::from_unix_nanos` no longer panics on far out-of-range values.**
  - For nanoseconds far outside jiff's range (for example `u64::MAX` milliseconds as nanoseconds),
    jiff 0.2.38 reached an internal assertion instead of returning its error.
  - The range is now checked first, and such values return `WallTimeError::Range`.
  - Found by PR-4b's wire property, which converts a "never expires" `u64::MAX` grant.
  - Test: `out_of_range_nanos_are_refused_without_a_panic`.
- **A crash during the journal's very first open no longer bricks the data directory.** A writer
  killed between creating the first segment and storing the manifest left an empty segment and
  no manifest, and every later open refused it ("refusing to start a new history"), so the
  directory could never be opened again. No acknowledged record was ever at risk (nothing is
  acknowledged before open completes); the directory's availability was. Found by the kill
  harness's new kills during boot (nightly 39330543607, macOS).
  - **Now** segment files that are all empty, with no marker naming a record, are set aside as
    orphans and the history starts. One byte in any segment, or a `FLUSHED` marker that names a
    record, is still refused: a new history must never hide a lost one (T12).
  - **Proof:** tests for a crashed first open, for a torn byte, for a real history whose first
    segment is empty, and for a recorded durable point; seeded violations
    `journal-first-open-bricks`, `journal-new-history-over-records`,
    `journal-new-history-checks-first-segment-only` and `journal-new-history-over-a-marker`.
  - **A merge-lane cut harness** (`crates/uaos-state/tests/boot_cuts.rs`, from the fix's V1
    review): every boot is cut before each filesystem step, then crashed or powered off and
    reopened twice; no cut may leave a directory unopenable or lose a record it must keep.
    Review record: `docs/reviews/S0a-journal-first-open.md`.

### Changed

- **Maintainer decisions of 2026-10-20.**
  - **D-31, review convergence:** the rule goes into `GOVERNANCE.md`.
  - **D-32, chunk storage:** prepared pack segments before the RC-1 freeze, through an
    ADR-0018 and ADR-0007 amendment owed before PR-6. Windows CI stays over budget.
  - **D-34:** booking the external audit and the legal review, and searching for a second
    reviewer.
  - D-31 and D-32 were decided inside their 48 h window; the register records this as a
    deviation.

- **Seven locales above a language-neutral kernel (ADR-0020, Proposed; D-36).**
  - CLAUDE.md now names seven GA locales: EN, TR, DE, FR, ES, IT and AR (right-to-left). It
    replaces "TR/EN initial".
  - Two new architectural invariants:
    - **Language neutrality.** The kernel treats content as bytes: no Unicode normalization,
      no case folding outside ASCII, no bidi reordering, no split code points. No Ring 0 or
      Ring 1 type names a locale.
    - **Prefix-stable rendering.** Injected text is rendered once, in the locale pinned for its
      Operation, and replayed as journaled bytes.
  - Two new merge blockers, both registered as pending:
    - `language-neutrality` (P3), which activates with PR-4's seven-locale corpus;
    - `locale-catalog` (P4).
  - The forbidden-claims lint also refuses "faultless" and "flawless" (red line 6).

- **Re-baselined on 2026-10-19.**
  - The roadmap's P3 row says what is built (the network door, chunk durability), what is in
    review (`uaos-json`), what comes next, and that no request flows through UAOS yet.
  - The RC-1 target moves from "2026-11-12 at the earliest" to an estimate from the measured
    pace: build exit in early to mid December 2026, go/no-go at least two weeks later. Gates
    decide; no threshold moved.
  - README lists `uaos-egress` as built but not yet in any request path; it was still under
    "does not exist yet".
  - Four open decisions join the register: D-31 review convergence, D-32 the chunk storage
    format before the freeze, D-33 which machine judges stage budgets, and D-34 booking the
    external audit and legal review.
- **The nightly kill lane fits its time again, with the same proof.** After payloads joined the
  kill harness (PR-1), one job of 10,000 kills overran GitHub's 6 h cap on Windows (run
  39219569263, cancelled; macOS took 3.5 h). On CI runners the cost is the writer itself, now
  that every record carries a payload: its puts and its recovery at boot (serially, 10,000
  Windows kills take about 6.8 h). On the reference machine, reading payloads back costs more
  (about 12 ms for the first read of a freshly written chunk, from its file-system filters).
  - **Sharded:** the nightly runs 8 shards of 1,250 kills per OS with distinct seeds: the same
    10,000 kills and the same checks after each, in parallel, each shard under a 100 min timeout,
    so a slowdown fails loudly instead of being cancelled.
  - **Payload sweeps (`UAOS_CRASH_SWEEP`):** the merge lane still reads every payload back after
    every kill. The nightly lane (`rotation`) reads back, after each kill, the payloads
    acknowledged since the last writer that finished its open, and every payload of a directory
    before it is retired. A loss never heals in the harness, so the same losses are caught; only
    the iteration that reports one can differ.
  - **New kill point:** about one kill in six is aimed before the writer prints `start`, at a
    random point of a boot as long as the last one, during store open and journal recovery
    (15–20% of kills landed there locally). Before, every kill waited for the open to finish.
  - **Bounded disk:** a directory is deleted as soon as it is retired. Before, a 10,000-kill run
    kept about 4 million files until it ended.
  - **Phase timings:** each run prints where its time went (boot, run, journal verification,
    store opens, payload reads, retiring), so the next slowdown names its cost centre.
  - **New seeded violation** `recovery-drops-old-payload`: a recovery that deletes a payload
    acknowledged several runs earlier is caught by the sweep before retirement, with the harness
    in its nightly configuration.
- README and roadmap describe the real state. The phase is P3. Scoped credentials exist. The
  numbers are current: corpus v2 and policy p99 688 µs. The ledger claim is worded as the
  WP2.2 review required: a refusal before recording, and a randomized simulation against a
  reference model.
- The nightly mutation lane also covers `uaos-identity`.
- `uaos-policy` decisions slice by exact resource within an action, and grants are indexed. The
  bench measures three mixes:
  - 1,000 mixed policies: p99 688 µs;
  - 1,000 policies on one action: p99 514 µs, down from 1.7 ms;
  - 10,000 grants: p99 226 µs, down from 19 ms.
- `docs/claims.md`: the authorization, ledger and redaction rows now state exactly what their
  gates prove, as narrowed by the retroactive reviews.

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

