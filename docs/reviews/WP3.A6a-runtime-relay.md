# Review: P3 Move 1 PR-6a, the runtime's relay, stop and admission (WP3.A6a)

Contract: `docs/adr/appendix/0013-runtime-relay-and-stop.md`. Review rule D-31: a fresh full
review, fixes, one scoped round, then a final fresh full review before the PR leaves draft.

## V1, fresh full review

**Reviewed:** `9a05b29..7a84931`, by a fresh-context agent reading only (no cargo), 2026-10-21.
**Result:** 1 High · 2 Medium · 13 Low.
**Verified:**
- **Relay state machine:**
  - no forward after a cut or a stop;
  - no clean end after a cut;
  - no completed future polled again;
  - no lost waker;
  - exactly one report on every path, `Drop` included.
- **The splitter against WHATWG:**
  - CR, LF and CRLF, split across chunks;
  - the byte-order mark, split and short;
  - `max_event` at all three sites;
  - no segment spanning two events.
- **Metering:** the max-merge, `>` against the ceiling, duplicate keys.
- **The stop and admission:** subscribe-then-check, the flag inside `send_if_modified`, poisoned
  locks.
- **The supervisor:** the bound.
- **Seeds:** all 11 anchors unique, and each caught with its message.
- **The ban:** the path resolves, and the canary is well formed.

| | Finding | Fix |
|---|---|---|
| H1 | §7.5 settled `Reported(cost)` whenever a report was priced, but a cost before the stream's end is a running total. A client leaving after `message_start` would settle about one token while the provider bills thousands, releasing money already spent (T6). | `RelayReport::usage_final` (completed, and the dialect's end at or after the last report) and `RelayReport::settlement`. A final cost, or a cost past the reservation, settles as reported; anything else settles the full reservation, estimated. §2 and §7.5 corrected. Negative `relay-settles-running-total`. |
| M1 | An overrun's stop gave every later refusal and every other cut stream `BUDGET_STREAM_OVERRUN` (S1, not retryable), against §3 and §7.4: an alert storm with a false message. | `RUNTIME_STOPPED` for every refusal and cut under a stop; only the stream that overran carries the overrun's code. Negative `stop-code-is-the-overrun`. |
| M2 | Only frames classified `Usage` were metered. A codec calling the `OpenAI` Responses API's `response.completed` an `End` would leave it unmetered. | Every event but a ping is read for usage, whatever its kind. A `Usage` frame must yield a report, and object-shaped data must parse. Negative `relay-meters-usage-frames-only`. |
| L1 | An overflow was reported as `budget_overrun` with a stale cost. A zero-priced dimension with a huge count overflowed. | Its own reason, `cost_out_of_range`, which keeps the last cost in range and settles the reservation. A free dimension is skipped. |
| L2 | Bytes mode yielded a terminal frame and ended cleanly, appending an event to a partial body. | Bytes mode ignores the terminal frame and always ends a cut in an error. |
| L3 | An empty `event:` reached the codec as `Some("")`, not the default type; the reference parser shared the error. | It reaches the codec as no name; the property generates empty names, and the reference reads them as none. Negative `sse-empty-event-name-kept`. |
| L4 | The idle reset was untested; `Instant + timeout` could panic; the 120 s default was unverified; the deadline ran from the last frame, so a slow client could cause an idle cut. | The deadline runs from each wait; `checked_add` (too far disables the cut); default 600 s as a conscious assumption until WP3.0d; tests for activity and for a slow client. Negative `relay-idle-deadline-never-resets`. |
| L5 | The bench charged a chunk's work to its first event, skewing the content and usage rows. | One event per chunk; numbers re-measured (§13). |
| L6 | "One nano-USD over" was tested only at 1,000 over. | A test with the reservation one nano-USD short; the seed now lets one nano-USD through. |
| L7 | The admission defaults' arithmetic was wrong. | Corrected: the bytes bound binds first, at about 39 Operations of 1.7 MB. |
| L8 | `std::sync::mpsc::channel` (unbounded) was not banned; the wording overclaimed. | Banned, with a canary; §8 says which files could allow one. |
| L9 | Three crate-private types derived `Debug` over content. | Length-only `Debug`. |
| L10 | §7.1's signature, the zero-copy and memory wording, the CHANGELOG's cut sentence and `segments` in bytes mode drifted from the code. | Corrected. |
| L11 | `Relay` was `Clone`, so several relays could each meter one reservation's full ceiling. | Not `Clone`; one relay per reservation, and PR-7 owes the typestate. |
| L12 | `boot_state` honoured a `kernel.resumed` from any actor; `unrecorded` handed the record out once, so a failed write lost it. | Only a human's resume counts. The record is offered until `Stop::recorded`. Negatives `boot-honours-any-resume` and `stop-record-handed-out-once`. |
| L13 | A codec panic unwinds through the body, and the report says `client_gone`. | **Owed to PR-9** (D-8, the panic boundary), recorded in §12. The client still sees a reset, not a clean end. |

## Scoped round (D-31)

**Reviewed:** `7a84931..9ae2206`, plus the invariants and callers it touches, by a
fresh-context agent reading only, 2026-10-21.
**Result:** 0 High · 2 Medium · 8 Low.
**Verified:**
- **H1:** `usage_final` holds in all three orders: a report on the end, a report after it, an
  end with no report. `settlement` is right for every end and cost.
- **M1:** no caller of the removed `StopReason::error_code` is left.
- **M2:** only pings are skipped.
- **L4:** no lost wake, the deadline cannot be skipped, and a slow client cannot run it.
- **L8:** nothing uses `std::sync::mpsc`.
- **Seeds:** all eight new or retargeted ones are caught with their message.

| | Finding | Fix |
|---|---|---|
| M-a | A report naming no dimension counted as a report. A codec that adds only the fields it finds, facing `"usage":{}` or a renamed field, would settle every completed stream at a final cost of zero (T6). | `read` treats it as no report: on a usage frame the stream cuts, and on any other frame it reports nothing. Test `an_empty_usage_report_is_no_report`; negative `relay-empty-usage-report-counts`. |
| M-b | "A restart never boots running for want of a record" overclaimed; rule 3 accepts a window by acting before the record. | §3 and `Stop::unrecorded` state the window, a restart before the record is durable boots running, and say PR-6b's DST bounds it. |
| L-a | No test sent a report after the end, so the "at or after" half of H1 was untested. | `a_report_after_the_end_is_not_final`; negative `relay-report-after-end-final`. |
| L-b | An overrun settles as non-estimated in the ledger though the cost is a lower bound. | §7.5 says so: PR-7's explanation carries the lower bound, and a ledger form for it needs an ADR. |
| L-c | On an `unpriced` or `cost_out_of_range` cut, the report's usage held a count that cost did not price. | The merge is kept only once priced; §7.5 says `cost_out_of_range` settles the reservation, with its overrun in the reason and the stop. Tests assert usage and cost agree. |
| L-d | Reading every event under `Limits::DEFAULT` let a 1 MiB event build about 12 MiB of tape. | At most 128 levels and 65,536 nodes (about 1.5 MiB), within `max_event_bytes`; stated in §7.1 and T11. Test `an_event_past_the_node_bound_cuts`. |
| L-e | The strict parse now gates content frames with no recorded assumption. | A conscious assumption in §7.3, for WP3.0d to count. |
| L-f | The property no longer read object-shaped events. | A one-line JSON event in all seven locales under any chunking, nothing cut. The serializer keeps a blank line after a CR a blank line, so events never merge into one that is not a document. 20,000 cases pass. |
| L-g | Two tests could stall instead of failing on a regression. | `tokio::time::timeout` on both, with the exact cut reason. |
| L-h | Doc drift in `lib.rs`, §2 and §8. | Corrected. |

## Final full review (D-31)

**Reviewed:** `9a05b29..33193f0`, the whole PR, by a fresh-context agent reading only, 2026-10-21.
The agent formed its view before reading this record.
**Result:** 0 High · 2 Medium · 7 Low.
**Verified:**
- **Stop paths:** no byte forwarded after a cut or a stop.
- **Wakers:** no lost waker; no completed future polled again.
- **Reports:** exactly one report on every path.
- **Settlement:** correct for every end and cost.
- **Splitter:** against WHATWG.
- **Stop, admission and supervisor:** all three hold.
- **Seeds:** all 20 bite with their messages.

| | Finding | Fix |
|---|---|---|
| M1 | The splitter queued every segment of a frame twice, in a reused scratch vector and in the forward queue, and neither shrank. One 400 KB frame of blank lines held about 36 MiB per stream, outside the stated bound and outside admission. | Each event is metered as the splitter finds it, and one frame clears at most two pieces: the event completed from earlier frames, then one slice of the frame's own events. Test `one_upstream_frame_is_forwarded_in_at_most_two_pieces` (10,000 blank lines). |
| M2 | The 1 MiB event bound and the strict parse of every object-shaped event cut legitimate streams: a server tool's whole result, a `response.completed` with `top_logprobs` or echoing the request, and, found while fixing, a lone surrogate escape from an emoji split across two text deltas, which `uaos-json` refuses. | Only usage, end and error frames, and kinds added later, are read; content, other and ping frames are forwarded unread. The event bound is the door's request bound, 32 MiB, and a read frame may hold 2^20 nodes. The per-stream memory bound is stated; charging it to the Operation's permit is **owed by PR-7** with the overload test. Test `a_content_frame_is_forwarded_unread`; negative `relay-reads-content-frames`. |
| L1 | `checked_add` guarded the deadline, but tokio's timer adds to it again and could panic. | A timeout over a year disables the cut. Test `a_huge_idle_timeout_disables_the_cut_without_a_panic`. |
| L2 | `a_stop_reaches_every_live_permit` never polled the watch before the stop. | The watch is polled and waiting before the stop engages. |
| L3 | The event-bound seed was caught only through the cut reason, never by the splitter's bound alone. | The test sends data that is not object-shaped, in an event no blank line ends, and asserts nothing is forwarded. |
| L4 | `SseEvent`'s doc promised JSON data, which `[DONE]` is not. | The doc says data is as sent and need not be JSON. |
| L5 | Red line 9's error end holds only for chunked or length-delimited responses. | §7.4 states the precondition; a close-delimited client is **owed by PR-7**. |
| L6 | A request that can never fit was told to retry in 1 s, forever. | `INGRESS_TOO_LARGE`, not retryable, `retry-after` zero, for an admission or a charge. Negative `admission-tells-a-misfit-to-retry`. |
| L7 | The first frame was copied whole, not just its first three bytes. | A first frame of three bytes or more is told for a byte-order mark in place. |
