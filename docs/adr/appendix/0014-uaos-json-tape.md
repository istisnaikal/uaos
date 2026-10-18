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
| Duplicate keys | refused, compared **after decoding**, so `"a"` and `"a"` collide; exact code points, no normalization | `DuplicateKey` |
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
| Duplicate-key scratch | one `Vec<u32>` of member indices, reused for every object | under 1 KiB | 4 MiB |
| String decode | lazy: borrowed when the string has no escape, otherwise at most the content's length | 0 until asked | caller-driven |
| Offset map | 4 B × (decoded length + 1), half of `uaos-redact`'s 8 B per byte | on demand | caller-driven |

- **Per parse,** at the defaults: at most 24 MiB + 4 MiB + 512 B steady. The input belongs to the
  caller.
- **Eight concurrent Operations:** about 3 MiB at the reference size, and at most 8 × 28.5 MiB.
- **Time.**
  - The scan is O(n) and nothing recurses.
  - Each object adds an O(m log m) duplicate check: member indices are sorted and neighbours
    compared. Keys without escapes are compared as bytes. Escaped keys are streamed through the
    decoder, with no allocation.
- **Adversarial inputs.** The bench measures each of these, and the tests assert the outcome:
  - 32 MiB of `[0,0,…]`: `TooManyNodes`, with at most 24 MiB allocated;
  - one object with about a million members;
  - keys sharing a long prefix;
  - 129 levels of nesting;
  - a 32 MiB string of escapes;
  - 32 MiB of number text;
  - 32 MiB of whitespace.
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
  - `LoneSurrogate`: at the backslash of the escape;
  - `DuplicateKey`: at the later key's opening quote;
  - `DepthExceeded`: at the bracket that opens one level too many;
  - `TooManyNodes`: at the first byte of the value that would exceed the limit.
- **`Debug` is written by hand** for `Tape`, `Node`, `Decoded` and the iterators. It shows
  lengths, indices, kinds and spans only.
- **No logging, counters or clock.** The crate is pure. `Tape::stats()` returns the node count,
  the deepest nesting, the input length and the bytes of heap held, for callers to report.

## 8. Decoding, encoding and numbers

- **`decode(content)`** decodes a string's content (between its quotes) under exactly the string
  grammar of §4. On top of that it refuses a raw `"` (`UnescapedQuote`). It returns borrowed text
  when there is no escape. It never substitutes U+FFFD and never falls back silently.
- **`decode_mapped(content)`** also returns the offset map. It holds one entry per decoded byte,
  giving the content offset of the character or escape that produced it, plus a final entry
  equal to the content length. There is no map when the content has no escape. This is
  `uaos-redact`'s rule, so PR-3 can move onto it.
- **`encode_str`** is the kernel's one encoder for splice replacements:
  - `"` and `\` are escaped;
  - U+0008, U+000C, U+000A, U+000D and U+0009 become `\b \f \n \r \t`;
  - the other characters below U+0020 become `\u00xx` in lowercase hex;
  - everything else is written as is, `/`, U+007F, U+2028 and non-ASCII included.

  Its output is byte-identical to `serde_json::to_string` for every string, and a test proves
  that.
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
  - heap stays within the bound of §6.
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
  - Targets: `parse` (arbitrary bytes, then `verify`, then decode every string) and `decode`.
  - Each target runs for 30 minutes with `-rss_limit_mb=256` and `-max_len=65536`. Seeds are
    generated, and nothing captured is committed.
  - `libfuzzer-sys` is licensed `(MIT OR Apache-2.0) AND NCSA`. NCSA is allowed for that crate
    alone, through a scoped exception in `deny.toml`. The nightly job also runs `cargo deny` on the
    fuzz workspace.

**Seeded violations** (`cargo xtask negative`):
- `arch-json-io-dependency`: the arch gate;
- `json-duplicate-key-unchecked`, `json-escaped-duplicate-compared-raw`, `json-depth-off-by-one`,
  `json-lone-surrogate-accepted`, `json-trailing-data-accepted`, `json-bom-stripped`,
  `json-leading-zero-accepted` and `json-decode-escape-wrong`: the test gate. The last one proves
  that the serde_json oracle bites.

**Bench:** `benches/tape.rs` at about 1.70 MB records p50, p95 and p99, the UTF-8 stage alone,
throughput, heap, and the adversarial rows of §6.

## 10. Measured

Not measured yet. This section is filled from `benches/tape.rs` before the pull request leaves
draft. Until then, the only numbers are the spike's, recorded in its appendix.
