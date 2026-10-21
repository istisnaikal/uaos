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
| A streaming splice proxy over hyper 1 and tokio channels: p95 ≤ 1 ms, duplicate-key overhead under 2 ms, never a full object in heap memory | The relay is a hyper `Body` that the client's connection pulls (§7). It uses no task and no channel, holds at most one event, and forwards each event's exact bytes | **No channel.** A pull body gets backpressure from the client's socket. A channel would add a copy and a buffer that stop must drain. **The request is still read whole,** under admission's byte bound: redaction and the final scan see every byte before anything leaves (CLAUDE.md request flow, I-05). Only the response path streams. **Duplicate keys:** usage frames parse with `uaos-json`, which refuses them. The 2 ms ceiling is PR-2's, for a 1.7 MB request (met: p95 1.86 ms) |
| Ring 2 state sync: ledger budget rules tied to the egress stream. Any single-token overrun mid-stream fires an instantaneous fail-closed kill switch, with no leaked downstream buffer and no grace period | The relay's ceiling is the Operation's reservation (`Reservation<InFlight>::amount`). It prices every usage report, and the first one over the ceiling cuts the stream (one nano-USD over is enough). That report is never forwarded. The upstream is dropped at once, the kernel stop engages (`budget_overrun`), and the client sees an error, never a clean end (§7.4) | **Rings.** The runtime and the ledger are Ring 0; Ring 2 is entitlement and the Hub (`arch.toml`). Nothing changes ring. **Physics.** The kernel learns token counts only when the provider reports them: Anthropic in `message_start` and `message_delta`, OpenAI's Responses API in its final event. Content between reports carries no count the kernel can trust. So **the hard cap is the reservation taken before the request,** sized at the clamped `max_tokens` (WP3.5), past which the provider cannot generate. The mid-stream cut is the second line, for a wrong price or a wrong clamp. **Honesty (red line 3).** Bytes already forwarded cannot be recalled. Tokens the provider generated before it saw the disconnect are billed, and settlement records them as spent; nothing claims a rollback. **Buffers.** The over-ceiling event is never queued, and the relay keeps no downstream buffer of its own |
| @devam and @resume in seven languages (EN, TR, DE, FR, ES, IT, AR) across every rehydration boundary, with every recovery prefix-stable and byte-identical | The configuration snapshot carries the locale as an opaque tag, pinned per Operation. A published change reaches the next pin only (§5). The relay is byte-exact for any chunking, proven over the seven-locale corpus (§12) | **No locale matrix in Ring 0.** CLAUDE.md (language neutrality) and ADR-0020 (Proposed, D-36) keep the list above the kernel, so an eighth language never breaks a contract. **@devam is a module** (C-14). Replaying journaled injected bytes is proven with the state actor (PR-6b); rehydration with ADR-0017 (M2) |

## 3. The stop

1. **One atomic flag.** Engaging the stop sets the flag before anything else. Admission checks
   it first and refuses with `RUNTIME_STOPPED`, `retry-after` 120 s. That is over 60 s, after
   which Claude Code stops retrying (v2 §2.5).
2. **Fan-out.** Each admitted Operation holds a watch on the stop. Admission subscribes, then
   checks the flag, so no Operation is admitted without seeing a stop that comes later. A live
   relay cuts at its next poll, and from then on no further upstream byte is read or forwarded.
3. **It restricts, so it acts before its record.** The stop is not a side effect: it takes effect
   before its record is written, and it never waits on the state actor. The record is
   `kernel.stopped`: critical durability, an inline payload `{"reason": <code>}`.
   - Whoever engages the stop need not journal it: a relay has no journal. `Stop::unrecorded`
     hands the record out exactly once per engagement, and PR-6b's state actor takes it and
     journals `Engaged::draft`.
   - This PR builds the record and the hand-off, and reads the record at boot.
   - A record that fails to write leaves the stop engaged, so it fails closed.
4. **Persisted.** At boot, the last `kernel.stopped` or `kernel.resumed` decides. A stop whose
   reason the reader does not know still boots stopped.
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
  - about four copies of a 1.7 MB body each, for 64 bodies.

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

`Relay::sse(upstream, &headers, codec, price, &reservation, stop, limits)` returns a body for
the client and a receiver for its report. `Relay::bytes(...)` does the same for a body that is
not an event stream.

- **The client pulls.** The body is pulled by the client's connection. No task runs it, and no
  channel feeds it.
- **Bounded memory.** It holds at most one incomplete event (at most `max_event_bytes`, default
  1 MiB), plus the upstream frame it is splitting.
- **Exact bytes.** It forwards each event's exact bytes. When an event lies inside one upstream
  frame, it forwards a slice of that frame without copying.
- **Uncompressed only.** A `content-encoding` other than `identity` is refused before any byte,
  since the stream must be observed to be metered (D-29: the request then asks for `identity`).
- **Bytes mode** relays frames untouched, under the same bounds and the same stop. It does not
  meter: usage in a body that is not a stream arrives at its end, after the bytes. PR-7 settles
  such a body from its usage when it ends, or estimates it at the full reservation.
- **Before rehydration.** The relay forwards what the provider sent. Rehydration (ADR-0017, M2)
  becomes a splice over the relay's output.

### 7.2 Events: the protocol, not the dialect

The relay follows the WHATWG event-stream format:
- a line ends in CRLF, LF or CR, and a CRLF split across two upstream frames is one line ending;
- an event ends at a blank line;
- a leading byte-order mark is skipped for parsing and forwarded with the bytes;
- `data` lines join with LF;
- a comment, or an event without data, is forwarded unclassified;
- the event name must be UTF-8, or the stream is malformed.

At a clean end, a trailing event with no blank line after it is classified, metered and then
forwarded, because a lenient client may act on it.

### 7.3 Metering

- **Every event is classified** with `codec.frame`.
- **A usage frame is read:**
  - its data is parsed with `uaos-json`, which refuses duplicate keys (T19);
  - it is shown to the codec with nothing masked;
  - the codec reads it with `codec.usage`;
  - the report is checked against `codec.dimensions()`.
- **Reports merge per dimension, keeping the highest count.** `[CONSCIOUS ASSUMPTION]` RC-1's
  dialects report running totals: Anthropic's `message_delta` usage is cumulative, and OpenAI
  reports once, at the end. WP3.0d and ADR-0016 confirm it. A dialect that reports increments
  needs a codec contract change before it ships.
- **Priced after every report.** A cost over the ceiling cuts (`budget_overrun`). A cost equal
  to the ceiling is within budget.
- **Metering fails closed.** Any of these cuts:
  - data that is not JSON;
  - a usage frame with no report;
  - an undeclared dimension;
  - an unknown price;
  - an overflow.

### 7.4 Cuts

| Reason | Code | Also |
|---|---|---|
| `budget_overrun` | `BUDGET_STREAM_OVERRUN` (new, S1) | engages the kernel stop |
| `stopped` | `RUNTIME_STOPPED` (new) | — |
| `unpriced` | `BUDGET_UNKNOWN_PRICING` | — |
| `unreadable_usage`, `malformed`, `event_too_large`, `body_too_large` | `EGRESS_UNUSABLE_RESPONSE` | — |
| `idle`, `upstream_failed` | `EGRESS_INTERRUPTED` | — |

On every cut:
1. nothing more of the upstream is forwarded: not the event that caused it, nothing after it,
   and not the segments still queued from the same upstream frame. The same holds once the
   kernel stop is engaged, for every relay, the one that engaged it included. A stream that
   completed but still had segments queued when the stop engaged becomes a cut, never a clean
   end;
2. the upstream body is dropped before the client's body yields again, so hyper closes the
   connection;
3. with a terminal frame from the caller (the dialect's error event, PR-7), the body yields it
   and ends. Without one it ends in an error, so a client never takes a cut for a complete
   answer (red line 9);
4. the report says what was forwarded (bytes and events), the last priced usage and the reason.

When the client goes away and its body is dropped, the upstream is dropped with it, and the
report says `client_gone`, also when the upstream had completed but segments were still
queued for the client.

### 7.5 Report and settlement

`RelayReport` carries:
- how the stream ended;
- forwarded bytes and events;
- the merged usage and its cost.

Settlement is PR-7's, through PR-6b's actor:
- `Usage::Reported(cost)` when a report was priced;
- otherwise `Usage::Unknown`: the full reservation, estimated.

An overrun is settled truthfully: the ledger records spend past the reservation
(`Settlement::overrun`, S1).

### 7.6 Budgets

- **Per event:** p95 ≤ 1 ms of kernel overhead, the brief's figure. The overall local overhead
  of p95 ≤ 25 ms (CLAUDE.md) stands. Measured by `cargo bench -p uaos-runtime --bench relay`
  over content and usage events on the reference machine, and labelled by environment (D-33).
- **Memory:** one incomplete event and one upstream frame per stream.

## 8. The supervisor

- **The only spawner in the runtime.** `crates/uaos-runtime/src/supervisor.rs` is the
  allow-audit owner for spawning. Its live tasks are bounded, and it refuses one past the bound.
- **The door's executor.** It implements hyper's `Executor`, so the door's connection tasks run
  under it (ADR-0013 Amendment 1 B). PR-7 wires it in.
- **No unbounded channel (PD-19).** `tokio::sync::mpsc::unbounded_channel` is banned across the
  workspace, with a canary in `crates/uaos-egress/tests/bans.rs`.

## 9. Contract changes (all additive)

- **Event types** `kernel.stopped` and `kernel.resumed`, with the inline payload
  `{"reason": <code>}`. `types::ALL` goes from 13 to 15.
- **Error codes:**
  - `RUNTIME_STOPPED` (Runtime 3, S2, retryable);
  - `BUDGET_STREAM_OVERRUN` (Budget 8, S1).
- **No schema change.** Event types and codes are strings in `uaos.event/1` and `uaos.error/1`.

## 10. Threat and privacy note

- **T6, budget runaway:** the cut and the kernel stop. An overrun is recorded truthfully, never
  hidden.
- **T11, local DoS:**
  - admission by bytes;
  - bounded events and bodies;
  - an idle timeout;
  - bounded tasks;
  - no channels on the relay path.
- **T19, parser differential:** usage is parsed by `uaos-json`, which refuses duplicate keys. A
  repeated usage key therefore cannot make UAOS meter less than a client reads.
- **Privacy:**
  - frames are never logged;
  - reports and errors carry counts and codes only (I-11);
  - every `Debug` prints lengths.
- **Red lines:**
  - 3: a cut never claims a rollback;
  - 9: a cut is never silent to the client.

## 11. Observability

- **`RelayReport`:** the end reason, forwarded bytes and events, usage and cost.
- **Admission refusals** by reason.
- **`Stop::reason`.**

PR-6b exports these through the bus as metrics, with the ids of CLAUDE.md §4.

## 12. Proof obligations (PR-6a)

**Tests:**
- **The stop:**
  - a stopped kernel admits nothing;
  - the first reason wins;
  - the record is handed out once;
  - a stop reaches every live permit;
  - a journaled stop survives a restart (a real journal), and an unknown reason boots
    stopped;
  - a later `kernel.resumed` boots running.
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
  - an unknown dimension and an overflow are refused.
- **Events:**
  - a property over random event streams and random chunking (CR, LF, CRLF split across
    frames, BOM, comments, multi-line data, the seven-locale corpus): the bytes forwarded equal
    the bytes received, and the events seen equal a reference parser run over the whole body.
- **Metering and cuts:**
  - a usage report one nano-USD over the ceiling is never forwarded, and one equal to it is;
  - an overrun engages the kernel stop;
  - a stop cuts a stream that is waiting on its upstream;
  - a cut drops the upstream at once;
  - a cut without a terminal frame ends in an error, and one with a terminal frame ends with
    it;
  - an event past its bound, a body past its bound, an idle upstream, a compressed body, a
    duplicate usage key, an undeclared dimension and an unknown price each cut;
  - a dropped client body drops the upstream;
  - a failed upstream cuts;
  - a stop engaged before the relay starts forwards nothing;
  - bytes mode relays untouched, does not meter, and obeys the stop;
  - streams shaped like the Anthropic Messages stream and the `OpenAI` Responses and chat
    streams are relayed byte for byte and metered;
  - the report counts what was forwarded.
- **Supervisor:**
  - it refuses past its bound;
  - a finished task frees its slot;
  - it runs hyper's executor tasks.

**Seeded violations** (`cargo xtask negative`):

| id | Seed | Caught by |
|---|---|---|
| `stop-admits-new-op` | admission skips the stop | `a_stopped_kernel_admits_nothing` |
| `stop-not-persisted` | boot ignores `kernel.stopped` | `a_journaled_stop_survives_a_restart` |
| `admission-counts-requests` | admission ignores bytes | `admission_counts_bytes_in_flight` |
| `relay-forwards-over-ceiling` | the ceiling comparison lets one unit through | `one_unit_over_the_ceiling_is_never_forwarded` |
| `relay-overrun-keeps-kernel-running` | an overrun cuts the stream but leaves the kernel running | `an_overrun_stops_the_kernel` |
| `relay-ignores-stop` | the relay never looks at the stop | `a_stop_cuts_a_waiting_stream` |
| `relay-keeps-upstream-after-cut` | a cut keeps the upstream body | `a_cut_drops_the_upstream_at_once` |
| `relay-cut-ends-clean` | a cut without a terminal frame ends cleanly | `a_cut_without_a_terminal_frame_ends_in_an_error` |
| `relay-event-unbounded` | the event bound is never checked | `an_event_past_its_bound_cuts` |
| `sse-split-crlf-twice` | a CRLF split across frames counts as two line endings | `any_chunking_relays_the_same_bytes_and_events` |
| `unbounded-channel` | an unbounded channel in the runtime | `cargo xtask clippy` |

**Bench:** `cargo bench -p uaos-runtime --bench relay`: per-event p50, p95 and p99 for content and
usage events, with the environment label. The numbers go into §13 once measured.

## 13. Measured, and open decisions

- **Measured** (`cargo bench -p uaos-runtime --bench relay`, reference machine, Windows x86-64,
  2026-10-21; 2,000 events per round, 20 rounds after 5 warm-up rounds; every 20th event a
  usage report; chunks of one to three events, one in four ending mid-event). Timer
  resolution here is about 100 ns.

  | Events | n | p50 | p95 | p99 | max |
  |---|---|---|---|---|---|
  | content | 38,000 | 0.1 µs | 0.3 µs | 0.9 µs | 14.2 µs |
  | usage (parse, read, price, compare) | 2,000 | 0.8 µs | 1.1 µs | 1.4 µs | 19.0 µs |

  About 650 MB/s through the relay. The per-event budget of p95 ≤ 1 ms holds on this
  machine. This is the kernel's own work over an always-ready upstream; network time is the
  provider's. The CI runners are reported once the bench joins the nightly lane (WP3.8).
- **Property strength:** `any_chunking_relays_the_same_bytes_and_events` runs 256 cases per
  merge; it passed 20,000 cases once locally (2026-10-21).
- **D-37 (E, open):** the ADR-0010 amendment for §3 rule 3. The stop restricts, takes effect
  before its record, and never waits on the state actor, so I-02 holds. Recommendation: accept.
  It is needed before PR-6b journals the record.
