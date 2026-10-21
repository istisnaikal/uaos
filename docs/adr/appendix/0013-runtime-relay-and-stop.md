# ADR-0013 contract: the runtime's relay, stop and admission

**Status:** normative for the crate `uaos-runtime` as far as P3 Move 1 PR-6a (WP3.A6a) builds
it. It was written before the code. A change to anything below changes the contract, so it lands
in the same pull request as the code and is recorded in the CHANGELOG. Draft until RC-1, like
every kernel contract.

**Builds on:**
- ADR-0013 (accepted) Decisions 1 and 2: tokio, bounded; hyper 1 directly; bodies relayed frame
  by frame with a byte bound; the supervisor is the only spawner. Amendment 1 B: the runtime
  builds the door.
- ADR-0010 Decision 7 (the supervisor) and ADR-0002 (reservations before execution).
- The module socket contract, `0010-module-socket.md` (PR-4, #32), §2 and §7: `DialectCodec`,
  `SseEvent`, `FrameKind`, `UsageReport`. Frames reach a codec as the provider sent them.
- CLAUDE.md §3: language neutrality and prefix-stable rendering.
- Cells C-25, C-28, C-45, C-47, C-48. Threat rows T6, T11, T19. Red lines 3, 6 and 9.

## 1. What PR-6a builds, and what it does not

The approved PR-6 row (Move 1 plan §7) is the runtime spine. This PR is its first half, so each
half stays small enough to review (D-31). It also brings forward the relay core from PR-7,
because the maintainer's brief of 2026-10-21 asks for the relay first. Both are reversible
reorders inside Train A.

**Built:** the crate `uaos-runtime` with
- the **stop**, the kernel's kill switch (§3);
- **admission** by bytes in flight (§4);
- the **configuration snapshot** with the pinned locale (§5);
- **declared pricing** (§6);
- the **relay**, metered against the Operation's reservation (§7);
- a minimal **supervisor** (§8).

**Not built here:**
- **PR-6b:** the state actor and durability coordinator (D-5), the bus (D-9), boot recovery
  with the configuration drift check, the one-record intent (D-6), the CPU pool and simulated
  executor (D-7), and the DST harness. It also journals the stop record built here.
- **PR-7:** the typestate pipeline, wiring the door and the relay, the dialect's error frame on
  a cut, the E2E stop drill at 8 concurrent Operations, and the overload test.
- **M2:** the dialect codecs (WP3.4), the pre-request clamp, `uaos.pricing/1` (WP3.5,
  ADR-0016), and rehydration (ADR-0017), which will splice the relay's output.
- **M3:** resuming a stopped kernel, which needs presence (I-13, ADR-0012).
- **@devam and @resume:** a module (C-14). Its paper module comes in PR-10; the product module
  comes after RC-1 (WIP limit).

## 2. The brief, mapped

| Asked | Built here | Corrected, and why |
|---|---|---|
| A streaming splice proxy over hyper 1 and tokio channels: p95 ≤ 1 ms, duplicate-key overhead under 2 ms, never a full object in heap memory | The relay is a hyper `Body` that the client's connection pulls (§7). It uses no task and no channel, holds at most one incomplete event, and forwards each event's exact bytes | **No channel.** A pull body gets backpressure from the client's socket. A channel would add a copy and a buffer that stop must drain. **The request is still read whole,** under admission's byte bound: redaction and the final scan see every byte before anything leaves (CLAUDE.md request flow, I-05). Only the response path streams. **Duplicate keys:** every object-shaped event parses with `uaos-json`, which refuses them. The 2 ms ceiling is PR-2's, for a 1.7 MB request (met: p95 1.86 ms) |
| Ring 2 state sync: ledger budget rules tied to the egress stream. Any single-token overrun mid-stream fires an instantaneous fail-closed kill switch, with no leaked downstream buffer and no grace period | The relay's ceiling is the Operation's reservation (`Reservation<InFlight>::amount`). It prices every usage report, and the first one over the ceiling cuts the stream (one nano-USD over is enough). That report is never forwarded. The upstream is dropped at once, the kernel stop engages (`budget_overrun`), and the client sees an error, never a clean end (§7.4) | **Rings.** The runtime and the ledger are Ring 0; Ring 2 is entitlement and the Hub (`arch.toml`). Nothing changes ring. **Physics.** The kernel learns token counts only when the provider reports them: Anthropic in `message_start` and `message_delta`, OpenAI's Responses API in its final event. Content between reports carries no count the kernel can trust. So **the hard cap is the reservation taken before the request,** sized at the clamped `max_tokens` (WP3.5), past which the provider cannot generate. The mid-stream cut is the second line, for a wrong price or a wrong clamp. **Honesty (red line 3).** Bytes already forwarded cannot be recalled. Tokens the provider generated after its last report or before it saw the disconnect are billed but uncounted, so a stream that did not finish settles the full reservation (§7.5); nothing claims a rollback. **Buffers.** The over-ceiling event is never queued, and the relay keeps no downstream buffer of its own |
| @devam and @resume in seven languages (EN, TR, DE, FR, ES, IT, AR) across every rehydration boundary, with every recovery prefix-stable and byte-identical | The configuration snapshot carries the locale as an opaque tag, pinned per Operation. A published change reaches the next pin only (§5). The relay is byte-exact for any chunking, proven over the seven-locale corpus (§12) | **No locale matrix in Ring 0.** CLAUDE.md (language neutrality) and ADR-0020 (Proposed, D-36) keep the list above the kernel, so an eighth language never breaks a contract. **@devam is a module** (C-14). Replaying journaled injected bytes is proven with the state actor (PR-6b); rehydration with ADR-0017 (M2) |

## 3. The stop

1. **One atomic flag.** Engaging the stop sets the flag before anything else. Admission checks
   it first and refuses with `RUNTIME_STOPPED`, whatever engaged the stop, and `retry-after`
   120 s. That is over 60 s, after which Claude Code stops retrying (v2 §2.5).
2. **Fan-out.** Each admitted Operation holds a watch on the stop. Admission subscribes, then
   checks the flag, so no Operation is admitted without seeing a stop that comes later. A live
   relay cuts at its next poll, and from then on no further upstream byte is read or forwarded.
3. **It restricts, so it acts before its record.** The stop is not a side effect: it takes effect
   before its record is written, and it never waits on the state actor. The record is
   `kernel.stopped`: critical durability, an inline payload `{"reason": <code>}`.
   - Whoever engages the stop need not journal it: a relay has no journal.
   - `Stop::unrecorded` returns the engaged stop until `Stop::recorded` says its record is
     in the journal. PR-6b's state actor journals `Engaged::draft` and then calls
     `recorded`. While the process runs, a failed write is therefore retried.
   - **The window.** A restart before the record is durable boots running: a kill, a crash, a
     power loss, or a write that keeps failing (a `disk_full` stop on a full disk) followed
     by a restart. Rule 3 accepts that window by acting before the record. PR-6b's DST bounds
     it, and the explanation of such a boot says a stop may have been lost.
   - This PR builds the record and the hand-off, and reads the record at boot.
   - A record that fails to write leaves the stop engaged, so it fails closed.
4. **Persisted.** At boot, the last `kernel.stopped` or `kernel.resumed` decides. A stop whose
   reason the reader does not know still boots stopped. Only a human resumes: a
   `kernel.resumed` whose actor is not `human` is ignored.
5. **The first reason wins.** Engaging again changes nothing and says so (`Engaged::first`).
6. **Reasons:** `operator`, `budget_overrun`, `payload_flush_failed`, `disk_full`, `canary_hit`.
   - This PR wires `budget_overrun`, from the relay.
   - The others are wired where their sources live: journal health in PR-6b, the canary in
     PR-3 and PR-7.
7. **Resume** needs presence (I-13, ADR-0012) and arrives in M3. Until then, a stopped kernel
   stays stopped across restarts.

Rule 3 is the ADR-0010 amendment that plan part two names. It is **proposed, not accepted**
(D-37).

## 4. Admission

- **What it counts.** Operations, and bytes in flight. An Operation is admitted with the bytes
  it declares, and its permit charges more as copies are made: the body, the tape and the
  splice. Dropping the permit releases both.
- **Refusals:**
  - over either bound: `RUNTIME_OVERLOAD`, with a short `retry-after` (1 s);
  - stopped: `RUNTIME_STOPPED` (§3).
- **Defaults** `[CONSCIOUS ASSUMPTION]`:
  - 64 Operations and 256 MiB in flight;
  - at about four copies of a 1.7 MB body each, the bytes bound binds first, at about 39
    such Operations. Smaller bodies reach the Operations bound.

  Measured under the overload test (PR-7) and the soak (M4).

## 5. The configuration snapshot and the pinned locale

- **`ConfigSnapshot`** holds a `ConfigVersion` and a `LocaleTag`.
  - `ConfigCell::publish` refuses a version that is not newer.
  - `ConfigCell::pin` returns the snapshot an Operation keeps to its end. A publish never
    changes a pinned snapshot.
- **`LocaleTag`** is opaque.
  - It is an ASCII tag shaped like BCP 47, at most 35 bytes: a primary subtag of 2–3 or 5–8
    letters, then subtags of 1–8 letters or digits, separated by `-`.
  - It is kept exactly as given, never case-folded and never matched against a list in Ring 0.
  - The seven GA tags pass, and so does any other well-formed tag. The list lives in the
    surface layer (ADR-0020 rule 3).
- **Text injected into a request** is rendered once, in the pinned locale, and journaled as
  bytes (CLAUDE.md). This PR provides the pin. PR-6b's actor journals the bytes and proves that
  replay never renders them again.

## 6. Declared pricing

- The relay prices a `UsageReport` through the `Price` trait.
- `DeclaredPrice` is the user-declared flat form ADR-0016 permits (D-11): nano-USD per unit, per
  dimension.
- It refuses:
  - a dimension it has no price for (`BUDGET_UNKNOWN_PRICING`);
  - a product or sum that overflows.
- The published price table, `uaos.pricing/1`, is ADR-0016's (M2).

## 7. The relay

### 7.1 Shape

`Relay::new(codec, price, &reservation, stop, limits)` builds a relay. `.terminal(frame)` sets the
frame a cut ends in. `.sse(upstream, &headers)` returns a body for the client and a receiver for
its report; `.bytes(upstream)` does the same for a body that is not an event stream.

- **One relay per reservation.** `Relay` is not `Clone`. A second relay over the same reservation
  would meter against the whole ceiling again, so PR-7 builds exactly one per Operation and owes
  a typestate that enforces it.
- **The client pulls.** The body is pulled by the client's connection. No task runs it, and no
  channel feeds it.
- **Bounded memory.** It holds:
  - at most one incomplete event (at most `max_event_bytes`, default 1 MiB);
  - the upstream frame it is splitting;
  - the finished segments of that frame not yet forwarded.

  A finished event copied from earlier frames can sit next to a new incomplete one, so the bound
  is about twice `max_event_bytes` plus one upstream frame. Reading an event for usage adds a
  transient tape of at most 65,536 nodes (about 1.5 MiB at 24 bytes a node), freed before the
  next event; admission does not count it.
- **Exact bytes.** It forwards each event's exact bytes. When an event lies inside one upstream
  frame, it forwards a slice of that frame without copying. The stream's first bytes are always
  copied once, until three have arrived to tell a byte-order mark.
- **Uncompressed only.** A `content-encoding` other than `identity` is refused before any byte,
  since the stream must be observed to be metered (D-29: the request then asks for `identity`).
- **Bytes mode** relays frames untouched, under the same bounds and the same stop. It does not
  meter: usage in a body that is not a stream arrives at its end, after the bytes. It ignores a
  terminal frame, so a cut always ends it in an error: an event appended to a partial body would
  read as more body. PR-7 settles such a body as §7.5 says for a stream with no final report.
- **Idle.** `idle_timeout` (default 600 s, `[CONSCIOUS ASSUMPTION]` until WP3.0d measures real
  gaps) counts from when the relay starts waiting on the upstream. A slow client never causes an
  idle cut, and every upstream frame starts the next wait afresh. A timeout too large to add to
  the clock disables the cut.
- **Before rehydration.** The relay forwards what the provider sent. Rehydration (ADR-0017, M2)
  becomes a splice over the relay's output.

### 7.2 Events: the protocol, not the dialect

The relay follows the WHATWG event-stream format:
- a line ends in CRLF, LF or CR, and a CRLF split across two upstream frames is one line ending;
- an event ends at a blank line;
- a leading byte-order mark is skipped for parsing and forwarded with the bytes;
- `data` lines join with LF;
- a comment, or an event without data, is forwarded unclassified;
- an empty event name is the default type, as no name, so the codec sees none;
- the event name must be UTF-8, or the stream is malformed.

At a clean end, a trailing event with no blank line after it is classified, metered and then
forwarded, because a lenient client may act on it.

### 7.3 Metering

- **Every event is classified** with `codec.frame`.
- **Every event but a ping is read for usage, whatever its kind** (review M2). A dialect may
  report usage on its last frame, as the `OpenAI` Responses API does.
  - Data shaped like a JSON object must parse with `uaos-json` as one document, which also
    refuses duplicate keys (T19), within `max_event_bytes`, 128 levels and 65,536 nodes.
    Otherwise the stream is cut: a broken object never slips past metering while a client
    reads it.
  - `[CONSCIOUS ASSUMPTION]` Every dialect's event data is JSON, or not shaped like an
    object. A dialect with text events that may begin with `{` needs a codec declaration
    first. WP3.0d counts rejects on real streams; an `OpenAI`-compatible local server (C-01)
    is where a false cut would show.
  - It is shown to the codec with nothing masked, and the codec reads it with `codec.usage`.
  - A report that names no dimension is no report (scoped round M-a), so a provider that renames
    or empties its usage never settles a final cost of zero.
  - A frame the codec classifies as `Usage` must yield a report.
  - A report is checked against `codec.dimensions()`.
- **Reports merge per dimension, keeping the highest count.** `[CONSCIOUS ASSUMPTION]` RC-1's
  dialects report running totals: Anthropic's `message_delta` usage is cumulative, and OpenAI
  reports once, at the end. WP3.0d and ADR-0016 confirm it. A dialect that reports increments
  needs a codec contract change before it ships.
- **Priced after every report.** A cost over the ceiling cuts (`budget_overrun`). A cost equal
  to the ceiling is within budget. A dimension priced at zero is free whatever its count.
- **Metering fails closed.** Any of these cuts:
  - object-shaped data that is not one JSON document;
  - a usage frame with no report;
  - an undeclared dimension;
  - an unknown price;
  - a cost past nano-USD's range (`cost_out_of_range`, which engages the stop like an overrun).

  The merged usage and its cost change together, only once a report is priced, so a cut for
  `unpriced` or `cost_out_of_range` reports the last usage and cost that were priced.

### 7.4 Cuts

| Reason | Code | Also |
|---|---|---|
| `budget_overrun` | `BUDGET_STREAM_OVERRUN` (new, S1) | engages the kernel stop |
| `cost_out_of_range` | `BUDGET_STREAM_OVERRUN` | engages the kernel stop; the report keeps the last cost in range |
| `stopped` | `RUNTIME_STOPPED` (new), whatever engaged the stop | — |
| `unpriced` | `BUDGET_UNKNOWN_PRICING` | — |
| `unreadable_usage`, `malformed`, `event_too_large`, `body_too_large` | `EGRESS_UNUSABLE_RESPONSE` | — |
| `idle`, `upstream_failed` | `EGRESS_INTERRUPTED` | — |

Only the stream that overran carries `BUDGET_STREAM_OVERRUN`. Every other stream the resulting
stop cuts, and every request refused after it, carries `RUNTIME_STOPPED` (review M1).

On every cut:
1. nothing more of the upstream is forwarded: not the event that caused it, nothing after it,
   and not the segments still queued from the same upstream frame. The same holds once the
   kernel stop is engaged, for every relay, the one that engaged it included. A stream that
   completed but still had segments queued when the stop engaged becomes a cut, never a clean
   end;
2. the upstream body is dropped before the client's body yields again, so hyper closes the
   connection;
3. with a terminal frame from the caller (the dialect's error event, PR-7), an event stream
   yields it and ends. Without one, and always in bytes mode, the body ends in an error, so a
   client never takes a cut for a complete answer (red line 9);
4. the report says what was forwarded, the last priced usage and the reason.

When the client goes away and its body is dropped, the upstream is dropped with it, and the
report says `client_gone`, also when the upstream had completed but segments were still
queued for the client.

### 7.5 Report and settlement

`RelayReport` carries:
- how the stream ended;
- forwarded bytes and segments;
- the merged usage, its cost and the ceiling;
- `usage_final`: the stream completed, and the dialect's end (`FrameKind::End`) came at or
  after its last usage report.

A cost that is not final is a running total, a lower bound on what the provider bills (review
H1). `RelayReport::settlement` is the rule PR-7 applies through PR-6b's actor:
- a final cost: `Usage::Reported(cost)`;
- a cost past the reservation: `Usage::Reported(cost)`. The provider billed at least that much,
  and the ledger records the overrun (`Settlement::overrun`, S1). The ledger's `Usage` has no
  lower-bound form, so it records this spend as not estimated; PR-7's explanation says it is a
  lower bound. A lower-bound settlement in the ledger would need an ADR (scoped round L-b);
- anything else, a cut, a client that left, or a stream that ended without the dialect's end:
  `Usage::Unknown`, the full reservation, estimated. Tokens generated after the last report or
  before the disconnect are billed but uncounted. The clamp bounds them at `max_tokens`, which
  the reservation covers. A `cost_out_of_range` cut settles here too: its overrun shows in the
  cut reason and the kernel stop, not in the ledger, since no cost in range exists to record.

### 7.6 Budgets

- **Per event:** p95 ≤ 1 ms of kernel overhead, the brief's figure. The overall local overhead
  of p95 ≤ 25 ms (CLAUDE.md) stands. Measured by `cargo bench -p uaos-runtime --bench relay`
  over content and usage events on the reference machine, and labelled by environment (D-33).
- **Memory:** as §7.1.

## 8. The supervisor

- **The only spawner in the runtime.** `crates/uaos-runtime/src/supervisor.rs` is the
  allow-audit owner for spawning. Its live tasks are bounded, and it refuses one past the bound.
- **The door's executor.** It implements hyper's `Executor`, so the door's connection tasks run
  under it (ADR-0013 Amendment 1 B). PR-7 wires it in.
- **Unbounded channels (PD-19).** `tokio::sync::mpsc::unbounded_channel` and
  `std::sync::mpsc::channel` are banned across the workspace, each with a canary in
  `crates/uaos-egress/tests/bans.rs`. A file `arch.toml`'s allow-audit list names as an owner
  of `clippy::disallowed_methods` could allow one; none does, and review of each `allow`
  covers it.

## 9. Contract changes (all additive)

- **Event types** `kernel.stopped` and `kernel.resumed`, with the inline payload
  `{"reason": <code>}`. `types::ALL` goes from 13 to 15.
- **Error codes:**
  - `RUNTIME_STOPPED` (Runtime 3, S2, retryable);
  - `BUDGET_STREAM_OVERRUN` (Budget 8, S1).
- **No schema change.** Event types and codes are strings in `uaos.event/1` and `uaos.error/1`.

## 10. Threat and privacy note

- **T6, budget runaway:**
  - the cut and the kernel stop;
  - a cost that is not final never settles below the reservation.

  An overrun the relay can price is recorded in the ledger. One past nano-USD's range shows in
  the cut reason and the kernel stop. Neither is hidden.
- **T11, local DoS:**
  - admission by bytes;
  - bounded events and bodies, and a node bound on reading an event;
  - an idle timeout;
  - bounded tasks;
  - no channels on the relay path.
- **T19, parser differential:** usage is parsed by `uaos-json`, which refuses duplicate keys, and
  object-shaped data must parse. A repeated usage key or a broken object therefore cannot make
  UAOS meter less than a client reads.
- **Privacy:**
  - frames are never logged;
  - reports and errors carry counts and codes only (I-11);
  - every `Debug` over content prints lengths.
- **Red lines:**
  - 3: a cut never claims a rollback;
  - 9: a cut is never silent to the client.

## 11. Observability

- **`RelayReport`:** the end reason, forwarded bytes and segments, usage, cost, ceiling and
  whether the usage is final.
- **Admission refusals** by reason.
- **`Stop::reason`.**

PR-6b exports these through the bus as metrics, with the ids of CLAUDE.md §4.

## 12. Proof obligations (PR-6a)

**Tests:**
- **The stop:**
  - a stopped kernel admits nothing;
  - every refusal under a stop says `RUNTIME_STOPPED`;
  - the first reason wins;
  - the record is handed out until it is journaled;
  - a stop reaches every live permit;
  - a journaled stop survives a restart (a real journal), and an unknown reason boots stopped;
  - a `kernel.resumed` boots running only from a human.
- **Admission:**
  - bytes in flight are counted, not requests;
  - a permit's extra charge is refused past the bound;
  - dropping a permit releases both bounds.
- **Configuration:**
  - versions only grow;
  - a pin survives a publish;
  - the seven GA tags and other well-formed tags validate, and malformed ones do not.
- **Pricing:**
  - per-dimension cost;
  - an unknown dimension and an overflow are refused;
  - a free dimension is free whatever its count.
- **Events:**
  - a property over random event streams and random chunking: CR, LF and CRLF split across
    frames; the byte-order mark; comments; multi-line data; empty event names; the seven-locale
    corpus. The bytes forwarded equal the bytes received, and the events seen equal a reference
    parser run over the whole body;
  - an empty event name reaches the codec as no name.
- **Metering and cuts:**
  - a report one nano-USD over the ceiling is never forwarded, and one equal to it is;
  - an empty usage report is no report: on a usage frame it cuts, and on an end frame the
    stream settles the full reservation;
  - a report after the dialect's end is not final;
  - an event past the node bound cuts;
  - a cut for `unpriced` or `cost_out_of_range` reports usage and cost that agree;
  - usage on an end frame, or on a frame the codec calls content, is metered;
  - an overrun engages the kernel stop and settles at least its cost;
  - a cost out of range cuts and stops;
  - a stream that did not finish settles the full reservation, and a final cost settles as
    reported;
  - a stop cuts a stream that is waiting on its upstream, and that stream says `RUNTIME_STOPPED`;
  - a cut drops the upstream at once;
  - a cut without a terminal frame ends in an error, and one with a terminal frame ends with it;
  - the following each cut:
    - an event past its bound;
    - a body past its bound;
    - an idle upstream;
    - a compressed body;
    - a duplicate usage key;
    - a broken JSON object;
    - an undeclared dimension;
    - an unknown price;
  - upstream activity resets the idle deadline, and a slow client never causes an idle cut;
  - a dropped client body drops the upstream;
  - a failed upstream cuts;
  - a stop engaged before the relay starts forwards nothing;
  - bytes mode relays untouched, does not meter, obeys the stop and ignores a terminal frame;
  - streams shaped like the Anthropic Messages stream and the `OpenAI` Responses and chat
    streams are relayed byte for byte and metered;
  - the report counts what was forwarded.
- **Supervisor:**
  - it refuses past its bound;
  - a finished task frees its slot;
  - it runs hyper's executor tasks.

**Seeded violations** (`cargo xtask negative`, 20):

| id | Seed | Caught by |
|---|---|---|
| `stop-admits-new-op` | admission skips the stop | `a_stopped_kernel_admits_nothing` |
| `stop-not-persisted` | boot ignores `kernel.stopped` | `a_journaled_stop_survives_a_restart` |
| `stop-code-is-the-overrun` | a refusal under an overrun's stop carries the overrun's code | `every_stopped_refusal_says_stopped` |
| `stop-record-handed-out-once` | the record is handed out once, before it is journaled | `the_record_is_handed_out_until_it_is_journaled` |
| `boot-honours-any-resume` | boot honours a resume from any actor | `an_unknown_stop_reason_still_boots_stopped_and_a_resume_boots_running` |
| `admission-counts-requests` | admission ignores bytes | `admission_counts_bytes_in_flight` |
| `relay-forwards-over-ceiling` | the ceiling comparison lets one nano-USD through | `one_nano_usd_over_the_ceiling_is_never_forwarded` |
| `relay-overrun-keeps-kernel-running` | an overrun cuts the stream but leaves the kernel running | `an_overrun_stops_the_kernel` |
| `relay-meters-usage-frames-only` | only frames classified `Usage` are read | `usage_on_an_end_frame_is_metered` |
| `relay-settles-running-total` | every cost counts as final | `a_stream_that_does_not_finish_settles_the_full_reservation` |
| `relay-ignores-stop` | the relay never looks at the stop | `a_stop_cuts_a_waiting_stream` |
| `relay-keeps-upstream-after-cut` | a cut keeps the upstream body | `a_cut_drops_the_upstream_at_once` |
| `relay-cut-ends-clean` | a cut without a terminal frame ends cleanly | `a_cut_without_a_terminal_frame_ends_in_an_error` |
| `relay-event-unbounded` | the event bound is never checked | `an_event_past_its_bound_cuts` |
| `relay-idle-deadline-never-resets` | the idle deadline is set once, at the first wait | `upstream_activity_resets_the_idle_deadline` |
| `sse-split-crlf-twice` | a CRLF split across frames counts as two line endings | `any_chunking_relays_the_same_bytes_and_events` |
| `sse-empty-event-name-kept` | an empty event name reaches the codec as a name | `an_empty_event_name_is_no_name` |
| `relay-empty-usage-report-counts` | a report naming no dimension counts as a report | `an_empty_usage_report_is_no_report` |
| `relay-report-after-end-final` | a report after the dialect's end keeps the usage final | `a_report_after_the_end_is_not_final` |
| `unbounded-channel` | an unbounded channel in the runtime | `cargo xtask clippy` |

**Bench:** `cargo bench -p uaos-runtime --bench relay`: per-event p50, p95, p99 and the maximum,
for content and usage events, with the environment label (§13).

**Owed elsewhere:** a panic in a codec unwinds through the body, and the report then says
`client_gone`. The client still sees a reset, not a clean end. The panic boundary (D-8) is PR-9's,
and it reports such a cut as its own reason.

## 13. Measured, and open decisions

- **Measured** (`cargo bench -p uaos-runtime --bench relay`, reference machine, Windows x86-64,
  2026-10-21, three runs):
  - **The setup:** 2,000 events per round, 20 rounds after 5 warm-up rounds, every 20th event a
    usage report.
  - **Attribution:** one event per chunk, so each timed poll is one event's work (review L5). One
    chunk in four ends mid-event.
  - **What is timed:** every event is parsed and read for usage.
  - **Resolution:** the timer resolves about 100 ns here.

  | Events | n | p50 | p95 | p99 | max |
  |---|---|---|---|---|---|
  | content | 38,000 | 0.6 µs | 0.7 µs | 0.8–1.1 µs | 19–100 µs |
  | usage (parse, read, price, compare) | 2,000 | 0.7 µs | 0.8 µs | 0.9–1.3 µs | 1.6–98 µs |

  - **Throughput:** about 230 MB/s through the relay.
  - **Budget:** the per-event budget of p95 ≤ 1 ms holds on this machine.
  - **Scope:** this is the kernel's own work over an always-ready upstream; network time is the
    provider's.
  - **CI runners:** reported once the bench joins the nightly lane (WP3.8).
- **Property strength:** `any_chunking_relays_the_same_bytes_and_events` runs 256 cases per
  merge; it passed 20,000 cases once locally (2026-10-21).
- **D-37 (E, open):** the ADR-0010 amendment for §3 rule 3. The stop restricts, takes effect
  before its record, and never waits on the state actor, so I-02 holds. Recommendation: accept.
  It is needed before PR-6b journals the record.
