# Spike WP3.0c: splice round trip over a structural tape, results (2026-10-15)

**Question (plan P3 Move 1, the kill-spike for ADR-0014).** Can these three pieces together
keep every value the provider checks identical from turn to turn, even when the client
re-serializes its whole history differently each turn?
- a kernel-owned structural tape;
- declarative role selectors;
- kernel-performed splices.

**Run:**
```
cargo run --release -- 200 50
```
This was the reference machine: Windows 10, Ryzen 5600X, release build, single thread.

## Verdict: PASS. ADR-0014's design survives, with three additions it must state

| # | Criterion | Result |
|---|---|---|
| A | **Value-prefix stability.** 200 seeds × 50 turns with transforms on: toy secret detector, tag strip and append-only injection. Each turn the client re-serializes everything in a random style (shuffled keys, pretty or compact, `\/`, `\uXXXX` for non-ASCII, and some ASCII letters escaped too) | **10,000 / 10,000 turns stable**: 277,127 kernel edits, 27,183 chunks transformed, 817,847 replayed. **0 secret leaks** |
| A′ | **Design negatives.** The same run with one element switched off | Without per-chunk pinning, stability **breaks**. With `cache_control` included in chunk digests, stability **breaks**. Both elements are load-bearing |
| B | **Identity.** Transforms off | **5,000 / 5,000 requests byte-identical** |
| C | **Role violations.** Edits inside a thinking block, `system[0]`, `system[1]` (non-secret), a mid-conversation system message (non-secret), `metadata` (opaque) or an assistant turn; tag strip or append in an older user turn | **8 / 8 refused**. Parser: duplicate keys (also after `\u` decoding), lone high/low surrogates, depth 129, trailing data, leading zero, raw control character: **8 / 8 rejected**. Depth 128 accepted |
| D | **Differential against serde_json:** 20,000 random documents, half mutated | 11,728 accepted by both **with equal decoded values**, 8,264 rejected by both, **0 value mismatches, 0 unexplained**. 8 numbers beyond f64 range (`1E9661`) are accepted only by the tape: RFC 8259 sets no range, and the tape forwards number text unchanged |

## Throughput: 1.70 MB request, 573 turns, 12,280 nodes

| Stage | p50 | p95 | Plan v2 §2.4 stage budget |
|---|---|---|---|
| UTF-8 check (inside parse) | 0.82 ms | 0.88 ms | — |
| Tape parse (memchr runs) | **1.70 ms** (≈ 1 GB/s) | 1.87 ms | decode 2 ms ✓ |
| Role resolution | 0.52 ms | 0.57 ms | (part of decode / hooks) |
| Chunk value digests (volatile excluded, SipHash stand-in) | **2.08 ms** | 2.21 ms | digests 2 ms ✗ **over by 4%** |
| Full path, cold (every chunk new) | 7.59 ms | 8.13 ms | first turn of a session only |
| **Full path, warm** (history pinned) | **5.93 ms** | **6.21 ms** | decode + digests + splice = 6 ms: at the edge |

A plain byte loop for string runs gave 858 MB/s. `memchr2` plus a vectorizable control-byte check
gave about 1 GB/s.

## What the spike taught: requirements ADR-0014 must state before acceptance

1. **Transforms are pinned per chunk value and replayed on history.**
   - A tag strip or injection applies only to the newest human turn. On the next turn the same
     message is history, and the client resends its original, unstripped version.
   - Only replaying the recorded transform keeps the values the provider bound. The
     counterfactual fails.
   - Pinning also makes "detect new chunks only" structurally true: replayed chunks skip
     detection.
2. **Chunk digests exclude volatile members.** The client moves its `cache_control`
   breakpoint every turn, and a digest that includes it misses every pin. The counterfactual
   fails.
3. **The pin key must include the detector version and the transform configuration.**
   - Otherwise a detector upgrade mid-session would change values the provider already bound.
   - This was not exercised here (one version); it follows from 1 and ADR-0005 item 3.
4. **Replayed edits need their own class (`Pinned`).**
   - **Allowed** outside the newest turn: they reproduce values already sent.
   - **Still forbidden** in `signed`, `opaque`, `system[0]` and provider-produced content.
5. **A small selector set suffices for every Messages role,** including ADR-0014 Revision 1's
   newest human turn and `system_message`:
   - `Key`, `Each` and `Deep(key)`;
   - the predicates `Is`, `IsNot` and `StrOrAny(nested)`;
   - a `last` modifier.
6. **Numbers are grammar-only.** The kernel parses a numeric field it must read (for example
   `max_tokens`) with an explicit range check. It never re-serializes numbers.

## Over budget, and what fixes it in that stage

**Digests (2.08 ms against 2 ms).** The fix stays within the stage:
- a raw-bytes fast path: compute the canonical value digest only for chunks whose raw bytes
  differ from the previous turn's;
- measure SHA-256 on aws-lc (hardware SHA) in place of the SipHash stand-in.

Both are inputs to Train A PR-2 (`uaos-json`) and WP3.4. The parse stage has headroom through a
SIMD UTF-8 validator, but that would be a new dependency, so it is measured before it is
proposed.

## What this spike does not show

- **Synthetic transcripts only.** No fresh real-client capture was approved. Real clients may
  produce shapes the generator does not.
- **One dialect.** Anthropic Messages only; OpenAI Responses (encrypted reasoning items) is not
  covered.
- **No streams.** No SSE, no rehydration, no real detector (a toy canary pattern stands in for
  `uaos-redact`), and no concurrency.
- **One platform.** Windows only, one machine.
- **The hash is a stand-in.** It is SipHash, not SHA-256.
- **Number text is assumed stable.** The simulated client writes numbers identically every
  turn.

The live lane with the provider's own binding oracle (D-21, WP3.8) is the real proof.
