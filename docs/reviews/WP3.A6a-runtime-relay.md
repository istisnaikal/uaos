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
