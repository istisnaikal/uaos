# ADR-0014 contract: the `uaos-json` tape

**Status:** normative for the crate `uaos-json` (WP3.A2, P3 Move 1 PR-2). It was written before the
code. A change to anything below changes the contract, so it lands in the same pull request as
the code and is recorded in the CHANGELOG.

**Builds on:**
- ADR-0014 Decision 1 (Revision 1): one Ring 0 tokenizer with raw spans, key paths and decoded
  strings; duplicate keys rejected; bounded limits; grammar-only numbers;
- the WP3.0c spike ([evidence](0014-splice-spike-2026-10-15.md));
- threat rows T14 and T19.

## 1. What the crate is

A pure library. It makes one forward pass over a **complete, already-buffered** input and
produces a flat, pre-order tape of the document's values. It also provides:
- a strict string decoder, with an optional map from decoded offsets back to raw offsets;
- the kernel's one string encoder;
- integer readers with explicit range checks;
- `Tape::verify`, which re-checks every invariant in §5.

**Why one pass over a complete input, not an incremental parser:**
- Ingress bodies are buffered whole and capped. The door's `max_request_body` defaults to
  32 MiB, and the final scan needs the exact outbound bytes anyway.
- Each SSE event's `data` field is a complete document, so the relay buffers one event and parses
  it whole.
- A parser that resumes across chunks carries state mid-escape, mid-number and inside a UTF-8
  sequence. Each of those is another state, a wider parser differential and more to fuzz.
- With complete input, every span is absolute and the tape borrows the input without copying it.

**Out of scope, and where it lands instead:**
- selectors, roles and `StructuralView`: PR-4;
- the canonical value digest: chunking;
- splice-plan validation: PR-7;
- redaction on the tape: PR-3. Until then `uaos-redact` keeps its own tokenizer, and the
  FinalScanner stays independent of this crate in every PR (ADR-0009, D-4, T14);
- the journal-reader fuzz target: the next micro-step;
- error codes in `uaos-contracts`. This crate has no workspace edge, so callers map `ErrorKind`
  to unified codes.

## 2. Dependencies

The `arch.toml` entry is `allow = []`. Its ban list covers the async, network, TLS and storage
crates, plus `serde_json`.
- The one product dependency is `memchr`, which is already vetted for `uaos-redact`.
- `serde_json` is the differential oracle. It is a dev-dependency only, and the ban keeps it out
  of the product graph, so the oracle stays independent of the code it checks.
- The crate sets `#![forbid(unsafe_code)]` and `#![deny(clippy::indexing_slicing,
  clippy::float_arithmetic)]` on top of the workspace lints, which deny `as` conversions. The
  float ban keeps numbers grammar-only.

## 3. Limits

| Limit | Default | Ceiling | Error |
|---|---|---|---|
| Input bytes | 32 MiB (matches the door) | 1 GiB | `TooLarge` |
| Nesting depth (containers open at once) | 128 | 1,024 | `DepthExceeded` |
| Nodes (values on the tape) | 2^20 = 1,048,576 | 2^24 | `TooManyNodes` |
| Raw key length (between the quotes) | 65,535 | fixed by the layout | `KeyTooLong` |

- `Limits::new` refuses a zero value or one above its ceiling.
- Depth 128 is accepted and 129 refused.
- A document with exactly `max_nodes` nodes is accepted, and one more is refused.

`[CONSCIOUS ASSUMPTION]` **The node default:**
- It is 85 times the 1.70 MB reference transcript, which has 12,280 nodes, and at most 24 MiB of
  tape.
- A body holding about a million values (a huge token-id array, say) is refused fail-closed. Such
  a body can raise the limit up to the ceiling.
- Revisit with real captures.

## 4. Grammar: RFC 8259, fail-closed

Checks run in this order: size, then byte-order mark, then UTF-8, then structure. Each error
carries one `ErrorKind` and one byte offset; §7 defines where the offset points.

| Input | Rule | `ErrorKind` |
|---|---|---|
| More than `max_bytes` | refused before anything is read | `TooLarge` |
| `EF BB BF` at byte 0 | **refused**. RFC 8259 lets a parser ignore it, but stripping it would move every span off the bytes that are forwarded | `ByteOrderMark` |
| Invalid UTF-8, overlong forms, encoded surrogates | refused; the whole input is validated (`str::from_utf8`) | `InvalidUtf8` |
| Empty, or whitespace only | refused | `Empty` |
| Whitespace | exactly space, tab, line feed and carriage return | `ExpectedValue` for anything else |
| Raw byte below 0x20 inside a string | refused (0x7F is allowed) | `ControlCharacter` |
| Escapes | `\" \\ \/ \b \f \n \r \t` and `\uXXXX` (hex digits in either case) only | `InvalidEscape`, `InvalidUnicodeEscape` |
| Surrogates | a high surrogate escape must be followed at once by an escaped low one; a lone low surrogate is refused. `\u0000` and noncharacters are allowed | `LoneSurrogate` |
| Numbers | `-?(0\|[1-9][0-9]*)(\.[0-9]+)?([eE][+-]?[0-9]+)?`. No range check, never converted and never re-serialized. `01`, `-`, `1.`, `1e`, `+1`, `.5`, `NaN` and `Infinity` are refused | `InvalidNumber`, `ExpectedValue` |
| Literals | lowercase `true`, `false` and `null` only | `InvalidLiteral` |
| Top level | any one value; anything but whitespace after it is refused | `TrailingData` |
| Duplicate keys | refused, compared **after decoding**, so `"a"` and the same key spelled as a `\u` escape collide; exact code points, no normalization. Found when the object closes (§7) | `DuplicateKey` |
| Structure | a missing key, colon, comma or closing bracket, a trailing comma, a mismatched closer, or the input ending early | `ExpectedKey`, `ExpectedColon`, `ExpectedCommaOrClose`, `ExpectedValue`, `UnexpectedEnd`, `UnterminatedString` |
| Memory | an allocation the system refuses is returned as an error, never an abort | `OutOfMemory` |

**The one known divergence from serde_json:** a number outside the f64 range, such as `1E9661`, is
valid grammar, so the tape accepts it; serde_json refuses it. The differential test counts these
cases and asserts that they are the only disagreement. serde_json's own depth limit is pinned by a
test and is not this crate's limit.

## 5. Tape layout and invariants

**Each node is a private 24-byte record**, checked at compile time (`size_of == 24`,
`align_of == 4`):

| Field | Type | Meaning |
|---|---|---|
| `start`, `end` | u32 | the value's raw byte span `start..end`; a string's span includes its quotes |
| `parent` | u32 | the parent's index, `u32::MAX` for the root |
| `after` | u32 | one past the last node of this value's subtree (`index + 1` for a scalar) |
| `key_start` | u32 | the offset of the member key's opening quote, for a member of an object |
| `key_len` | u16 | the raw key length, quotes excluded |
| `kind` | u8 | Object, Array, String, Number, True, False or Null |
| `flags` | u8 | `HAS_KEY`, `KEY_ESCAPED`, `STR_ESCAPED`; the other bits are zero |

**Why these fields:**
- **`parent`** makes ancestor checks O(depth). PR-7 needs them for forbidden roles, and key paths
  come from them.
- **`after`** gives a subtree as an index range. That serves the any-depth key selector, sibling
  steps and span containment.
- **No sibling index.** `each` and `system_entry(n)` count while iterating, and `last` is
  O(children). A side table is added only if PR-4 measures a need.
- The layout is private, so it can change without breaking the API. The invariants below cannot.

**Invariants**, checked by `Tape::verify`, the tests and the fuzz targets:
1. **Pre-order.** Node 0 is the root and has no parent, and `parent(i) < i` for every other node.
2. **Subtrees.** `i < after(i) <= after(parent(i))`, and `after(i) == i + 1` for a scalar.
   A container `p`'s children are `p + 1`, then `after` of the previous child, and so on, until
   `after(p)`.
3. **Spans.** `start < end <= input length`. A child's span lies inside its parent's, and
   siblings' spans are ordered and disjoint.
4. **Kinds match bytes.** An object spans `{…}`, an array `[…]` and a string `"…"`. A number
   starts with `-` or a digit, and a literal spans its exact text.
5. **Keys.** A node has `HAS_KEY` exactly when its parent is an object. The key's quoted span lies
   inside the parent's span and ends before the value starts.
6. **Flags.** `STR_ESCAPED` appears only on strings, and exactly when the content holds a
   backslash; `KEY_ESCAPED` follows the same rule for keys. No unknown bit is set.
7. **Unique keys.** No two members of one object have equal decoded keys.
8. **Bounds.** The node count is at most `max_nodes`, and the deepest nesting is at most
   `max_depth`.

## 6. Memory and time bounds

| Item | Bound | At the 1.70 MB reference (12,280 nodes) | At the defaults, worst case |
|---|---|---|---|
| Tape | 24 B × capacity. The first reserve is `clamp((len / 128 + 1).next_power_of_two(), 16, max_nodes)`, and it grows with `try_reserve_exact` to `min(2 × capacity, max_nodes)` | 384 KiB reserved (288 KiB used) | 24 MiB steady; at most 36 MiB while the last growth copies |
| Depth stack | 4 B × `max_depth`, reserved up front | 512 B | 512 B |
| Duplicate-key side stack | 8 B per member key of the objects still open: a 32-bit fingerprint of the decoded key and the member's node id. It grows like the tape, to at most `max_nodes` entries. Object marks: 4 B × `max_depth`, reserved up front | under 1 KiB | 8 MiB steady; at most 12 MiB while the last growth copies |
| Run scratch | only for members that share a fingerprint, reused for every run: 12 B per member of the largest run, plus that run's escaped keys decoded, which is at most their raw length | 0 (no collisions) | 12 MiB, plus at most the input's length |
| String decode | lazy: borrowed when the string has no escape, otherwise the decoded length, reserved exactly | 0 until asked | caller-driven |
| Offset map | 4 B × (decoded length + 1), reserved exactly, half of `uaos-redact`'s 8 B per byte | on demand | caller-driven |

- **Per parse,** at the defaults: at most 24 MiB + 8 MiB + 1 KiB steady when no keys share a
  fingerprint. A run of shared fingerprints, which takes keys crafted to collide, adds at most
  12 MiB plus the input's length. The input belongs to the caller.
- **Eight concurrent Operations:** about 3 MiB at the reference size; at most 8 × 33 MiB without
  collisions, and 8 × 77 MiB with crafted ones.
- **Time.**
  - The scan is O(n) and nothing recurses.
  - Each object adds an O(m log m) duplicate check.
    - **When a key is read,** while its bytes are hot, it is fingerprinted over its **decoded**
      bytes, so an escaped and an unescaped spelling of the same key always share a fingerprint.
      Keys without escapes are hashed eight bytes at a time; escaped keys are streamed through
      the decoder, with no allocation.
    - **When the object closes,** objects with fewer than two members are skipped. Objects of up
      to 8 members compare their fingerprints pairwise, at most 28 integer comparisons; larger
      ones sort them. Only members that share a fingerprint are compared exactly.
    - **A fingerprint collision costs an exact comparison, never a wrong answer.** The members of
      a run of shared fingerprints are compared as bytes: keys without escapes in place, escaped
      keys decoded **once** into the run scratch. So even an object whose keys all collide costs
      one decode per key plus O(m log m) byte comparisons.
    - **Collisions can be crafted.** The fingerprint has no key, and every step of it can be run
      backwards, so keys sharing one fingerprint can be computed offline (the V1 review crafted
      16,000 in 0.4 s). That costs time, never correctness; §10 measures it against a control of
      the same shape.
- **Adversarial inputs.** The bench measures each of these. `tests/adversarial.rs` and the unit
  tests in `src/tape.rs` assert each outcome:
  - 32 MiB of `[0,0,…]`: `TooManyNodes`, with 24 MiB of tape, at most 36 MiB while its last
    growth copies;
  - one object with about a million members;
  - keys sharing a long prefix;
  - 129 levels of nesting;
  - a 32 MiB string of escapes;
  - 32 MiB of number text;
  - 32 MiB of whitespace;
  - keys crafted to share one fingerprint, accepted, and a repeat among them found where it
    starts.
- **Stage budget:** parse p95 ≤ 2 ms at 1.7 MB on the reference machine (master plan v2 per-stage
  table), that is at least 0.85 GB/s. It is recorded by `benches/tape.rs` and not CI-gated:
  `perf-smoke` stays pending until WP3.8. A stage over budget is fixed in that stage, never by
  borrowing from another.

## 7. Errors and observability

- **`JsonError` holds an `ErrorKind` and a u32 byte offset, nothing else.** It never holds input
  bytes (I-11). `Display` reads `json: <reason> at byte <offset>`, and `ErrorKind::code()` gives a
  stable snake_case label (`duplicate_key`, `depth_exceeded`, …) for the runtime's metrics.
- **Where the offset points:** at the first byte that cannot continue a valid document, except:
  - `TooLarge`: at `max_bytes`;
  - `Empty`: at the input length;
  - `InvalidUtf8`: at the first invalid byte;
  - `UnterminatedString`: at its opening quote;
  - `InvalidNumber`: at the number's first byte;
  - `InvalidLiteral`: at the literal's first byte;
  - `InvalidEscape`, `InvalidUnicodeEscape` and `LoneSurrogate`: at the backslash of the escape;
  - `KeyTooLong`: at the key's opening quote;
  - `DuplicateKey`: at the later key's opening quote;
  - `DepthExceeded`: at the bracket that opens one level too many;
  - `TooManyNodes`: at the first byte of the value that would exceed the limit. Only a byte that
    starts a value counts: any other byte is the grammar error it is, whatever the node count.
- **A repeated key is found when its object closes,** not where the repeat is read. The error
  names the first object that closes with a repeat, at its earliest second occurrence; an
  object inside a repeated member closes first, so its repeat is the one reported. An error the
  parser meets before that close, such as a missing key or the end of the input, is reported
  instead. Every such input is refused either way; only the reported kind and offset follow this
  rule. `a_duplicate_is_reported_when_its_object_closes` pins it.
- **`Debug` is written by hand** for `Tape`, `Node`, `Decoded` and the iterators. It shows
  lengths, indices, kinds and spans only.
- **No logging, counters or clock.** The crate is pure. `Tape::stats()` returns the node count,
  the deepest nesting, the input length and the bytes of heap held, for callers to report.

## 8. Decoding, encoding and numbers

- **`decode(content)`** decodes a string's content (between its quotes) under exactly the string
  grammar of §4. On top of that it refuses a raw `"` (`UnescapedQuote`). It returns borrowed text
  when there is no escape. It never substitutes U+FFFD and never falls back silently.
- **`decode_mapped(content)`** also returns the offset map. It holds one entry per decoded byte:
  a byte copied from the content maps to its own offset, and a byte an escape produced maps to
  the escape's backslash. A final entry equals the content length. There is no map when the
  content has no escape. This is `uaos-redact`'s rule, so PR-3 can move onto it.
- **`encode_str`** is the kernel's one encoder for splice replacements:
  - `"` and `\` are escaped;
  - U+0008, U+000C, U+000A, U+000D and U+0009 become `\b \f \n \r \t`;
  - the other characters below U+0020 become `\u00xx` in lowercase hex;
  - everything else is written as is, `/`, U+007F, U+2028 and non-ASCII included.

  Its output is byte-identical to `serde_json::to_string` for every string, and a test proves
  that.
- **Memory outside `parse`.** `decode`, `decode_mapped` and `encode_str` reserve the exact length
  they will write before writing it, and return `OutOfMemory` instead of aborting when it is
  refused; `encode_str` then leaves its output unchanged.
- **`parse_u64` and `parse_i64`** read integer number text with checked arithmetic. Fraction,
  exponent, `-0` and out-of-range values return `None`. Every other number stays text (ADR-0014
  Decision 6).

## 9. Proof obligations (the merge gate of WP3.A2)

**Tests:**
- One grammar test per row of §4, checking both the kind and the offset.
- Exact limit boundaries, including a 1,024-deep document on a thread with a 64 KiB stack, which
  proves there is no recursion.
- **Properties:**
  - `verify` holds on every tape that parses;
  - `encode_str` then `decode` gives back the input, with serde_json's bytes;
  - the decoder and the tape accept the same strings;
  - the offset map's own rules hold;
  - heap stays within the bound of §6;
  - duplicate keys, in nested documents and five spellings, are found exactly where §7 says,
    against an oracle the generator builds; distinct keys, objects of more than 8 members and
    keys sharing a fingerprint included, are accepted.
- **Fingerprint:** the word-at-a-time path equals the byte-at-a-time one at every length from 0 to
  40, and every escaped spelling of a key gets the raw key's fingerprint.
- **Crafted collisions:** 2,000 keys computed to share one fingerprint are accepted, and a repeat
  among them is found where it starts.
- **Adversarial outcomes** of §6, and the side stack's capacity against the node limit.
- **Differential against serde_json:** an edge-case corpus plus generated documents in the
  spike's styles.
  - Accept and reject must agree, decoded strings must be equal, and every node's span must
    re-parse to the oracle's subtree.
  - Out-of-range numbers are the only, counted, divergence.
  - A one-off run covers at least 20,000 documents with 0 unexplained disagreements.
- **No payload in `Debug`:** a canary's bytes never appear in any type's output.

**Fuzzing.**
- **On every merge:** property fuzzing (proptest, 256 cases, fixed seed) over arbitrary bytes and
  mutated documents. Nothing may panic, every tape passes `verify` and decodes fully, and every
  error offset lies within the input.
- **Nightly:** the same with a million cases, seeded by the run ID.
- **Coverage-guided** (D-30 in `docs/decisions.md`):
  - cargo-fuzz in an isolated `fuzz/` workspace. It is not a workspace member, never ships and has
    its own lockfile.
  - It runs only in the nightly lane, on Linux, with a pinned nightly toolchain.
  - Targets: `parse` (arbitrary bytes, then `verify`, then decode every string, then the heap
    bound of §6 on that input) and `decode`.
  - Each target runs for 30 minutes under AddressSanitizer with `-max_len=65536`. Seeds are
    generated, and nothing captured is committed.
  - The memory bound is asserted per input, not read from the process. The first nightly run
    (2026-10-18) used `-rss_limit_mb=256` and stopped after about 176,000 runs at 277 MB. The
    live heap was 25 MB, nearly all of it libFuzzer's own; ASan's quarantine held 160 MB. The
    process limits are therefore coarse: libFuzzer's default of 2048 MB of resident memory, and
    64 MB for any single allocation.
  - `libfuzzer-sys` is licensed `(MIT OR Apache-2.0) AND NCSA`. NCSA is allowed for that crate
    alone, through a scoped exception in `deny.toml`. The nightly job also runs `cargo deny` on the
    fuzz workspace.

**Seeded violations** (`cargo xtask negative`):
- `arch-json-io-dependency`: the arch gate;
- 13 `json-*` cases for the test gate:
  - one per fail-closed rule: `json-duplicate-key-unchecked`,
    `json-escaped-duplicate-compared-raw`, `json-depth-off-by-one`,
    `json-lone-surrogate-accepted`, `json-trailing-data-accepted`, `json-bom-stripped` and
    `json-leading-zero-accepted`;
  - one for the oracle, `json-decode-escape-wrong`, which proves that serde_json bites;
  - five for the fingerprinted check: `json-fingerprint-raw-bytes`,
    `json-fingerprint-collision-accepts`, `json-fingerprint-collision-rejects`,
    `json-fingerprint-word-order` and `json-pairwise-skips-shared-fingerprint`.

**Bench:** `benches/tape.rs` at about 1.70 MB records p50, p95 and p99, the UTF-8 stage alone,
throughput, heap, and the adversarial rows of §6.

## 10. Measured

**Environment:** the reference machine (AMD Ryzen 5 5600X, Windows 10 Pro), single thread,
2026-10-18. Release build (`codegen-units = 1`, thin LTO), run with
`cargo bench -p uaos-json --bench tape`.

**Stage.** The input is a deterministic agent-session body of 1,700,659 bytes:
- 3 system blocks, 29 tools, and alternating turns with text, tool calls and tool results;
- escapes and non-ASCII throughout;
- 9,459 nodes, depth 6.

| Stage | p50 | p95 | p99 | GB/s at p95 |
|---|---|---|---|---|
| parse, first version (`ab6d92f`) | 2.158 ms | 2.187 ms | 2.259 ms | 0.78 |
| parse, after the V1 review fixes: 5 runs on a quiet machine (2026-10-20) | 1.823–1.831 ms | **1.853–1.868 ms** | 1.895–2.060 ms | 0.91–0.92 |
| UTF-8 check alone, the same 5 runs | 0.505–0.515 ms | 0.527–0.532 ms | 0.539–0.554 ms | 3.20–3.23 |

**Within budget, after a fix in place.** The budget is parse p95 ≤ 2 ms at 1.7 MB, that is at
least 0.85 GB/s.
- **The first version measured 2.187 ms, about 9% over.** The master plan fixes a stage in place,
  never by borrowing another stage's budget, and Train B could not start before the fix.
- **Now 1.853–1.868 ms over 5 runs: 7% headroom, on this machine only.** The V1 review measured
  one run of 2.163 ms among five, while other builds ran on the same machine; the five runs above
  were taken with nothing else running. No CI runner judges this stage yet; which machine does
  is open decision D-33, and `perf-smoke` stays pending until WP3.8.
- **Where the time went.** Bisected with stubs that were measurements only, never committed:
  - the old check cost about 0.3 ms, spent per object rather than in sorting large ones;
  - with fingerprints, sorting objects of two to four members still cost about 0.26 ms;
  - taking the fingerprints costs about 0.035 ms.
- **What fixed it, in order:**
  1. Fingerprints over decoded keys, taken as keys are read (§6), with objects of up to 8
     members compared pairwise on fingerprints alone: p95 1.975 ms.
  2. The control-byte check branch-free over each run of string bytes, so it vectorizes:
     p95 1.882–1.888 ms.
- **Tried and not kept:**
  - the first version's pair-by-pair check of up to 8 members' **keys** saved only 0.02 ms,
    because comparing keys reads the input again;
  - a plain multiply as the fingerprint collided about 200 times the ideal rate on `key-N` keys.
    The kept mixer (multiply, fold the high bits down, murmur3's `fmix64`) is within 11% of
    ideal on six structured key sets of up to a million keys each.
- The spike's 1.87 ms p95 was measured on its own transcript and does not compare directly.

**Memory.**
- That body reserves its tape once: 16,384 node slots, 384 KiB, of which 9,459 slots are used.
- A single-scalar body just under 32 MiB, as the bench builds it, reserves 6 MiB of tape for one
  node; at exactly 32 MiB, which is accepted, the power-of-two rounding of the first reserve gives
  12 MiB. The first reserve assumes about one node per 128 bytes. That is inside the §6 bound, but
  wasteful for scalar-heavy input.

**Adversarial inputs** (p50 of 5 timings per run; first version, then the range over the 5 runs
of 2026-10-20):

| Input | Size | p50, first version | p50 now | Outcome |
|---|---|---|---|---|
| `[0,0,…]` to the size limit | 33.6 MB | 16.7 ms | 16.1–16.6 ms | refused: `too_many_nodes` |
| one object of 1,000,001 members | 11.9 MB | 166.1 ms | 52.0–54.2 ms | accepted, 24 MiB of tape |
| 4,001 keys sharing a 4 KiB prefix | 16.4 MB | 16.1 ms | 3.5–3.7 ms | accepted, 3 MiB |
| 129 levels | — | under 0.1 ms | under 0.1 ms | refused: `depth_exceeded` |
| a string of escapes to the size limit | 33.6 MB | 131.7 ms | 123.0–123.6 ms | accepted, one node |
| number text to the size limit | 33.6 MB | 15.9 ms | 8.5–8.6 ms | accepted, one node |
| whitespace around one value, to the size limit | 33.6 MB | 16.1 ms | 15.9–16.2 ms | accepted, one node |
| 16,000 keys crafted to share one fingerprint (320 escaped bytes + 8 each) | 31.6 MB | — | 126.9–127.3 ms | accepted |
| the same shape, keys that do not collide (control) | 31.6 MB | — | 88.7–89.2 ms | accepted |
| 100,000 keys crafted to share one fingerprint (40 escaped bytes + 8 each) | 29.7 MB | — | 139.9–140.7 ms | accepted |
| the same shape, keys that do not collide (control) | 29.7 MB | — | 86.3–86.9 ms | accepted |

**Crafted collisions** (review WP3.A2 M1). Before the fix, every exact comparison in a run decoded
both escaped keys again; the review measured 1,009.9 ms and 1,297.8 ms for these two shapes, 12
and 15 times their controls. With each escaped key decoded once into the run scratch, a crafted
body costs 1.4 and 1.6 times its control. The bench crafts its keys with a copy of the fingerprint run backwards;
it checks that copy against the pair the crate's unit tests pin, and asserts that every crafted
key collides before it measures.

**Coverage-guided fuzzing.** Nightly run 39146599664 on `316513d`, ubuntu-latest, with
AddressSanitizer:

| Target | Runs in 30 minutes | Coverage edges | Corpus | Crashes |
|---|---|---|---|---|
| `parse` | 10,872,985 | 1,091 | 1,613 inputs | 0 |
| `decode` | 79,948,806 | 461 | 499 inputs | 0 |

- The heap bound held on every input `parse` parsed.
- Peak resident memory was 608 MB and 627 MB, AddressSanitizer included.
- The first run, 39146269561, stopped on the 256 MB process cap described in §9.

**Differential.** The one-off release run of 20,000 documents found:
- 5,952 accepted by both;
- 14,035 refused by both;
- 13 numbers outside the f64 range, accepted by the tape only (the known divergence);
- 0 disagreements.
