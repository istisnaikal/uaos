# ADR-0014: Codec framework: a kernel-owned structural view and declarative selectors

**Status:** Proposed (opened 2026-10-13; earliest decision 2026-10-15, 48 h) · **Plan refs:** v2 I-06, §2.5 beachhead facts, C-01, C-24 · **Builds on:** ADR-0005, ADR-0009 · **Amends:** ADR-0001 (adds Ring 0 crate `uaos-json`)

**Revision 1 (2026-10-15, before the decision).** The Claude Code capture (CAP-6,
`docs/research/beachhead-facts.md`) shows `role: "system"` messages in the middle of
`messages`. The role table did not cover them, so a codec could not mark them and the kernel
could not protect them. Revision 1:
- adds the `system_message` role;
- defines the newest human turn precisely;
- keeps the role check fail-closed for both.

The decision waits for the WP3.0c splice spike (plan P3 Move 1), which can still change this
design.

## Context

ADR-0005 requires byte-preserving codecs: unknown fields and signed blocks pass through
untouched, and transforms are prefix-stable. Plan v2 §2.5 recorded what the providers actually
check:
- The preserved-thinking check covers the **values** of `system`, `tools` and earlier `messages`
  ("JSON formatting and key order don't matter; the values do").
- A rewritten `system` array defeats the positional attribution strip.
- Gateways must forward every `anthropic-*` header and body field as an open list.

Two designs were possible:
- **Each codec splices bytes itself.** That means n implementations of a safety property.
- **The kernel performs every edit, and codecs only describe where things are.**

The tokenizer that exists today (`uaos-redact/src/json.rs`) finds and decodes JSON strings with
raw offsets. It has no nesting or key paths, and there is no fuzz target for it.

## Decision

1. **`uaos-json`, a new Ring 0 pure crate.**
   - It holds a structural tokenizer: objects, arrays, strings, numbers and literals, with raw
     byte spans, key paths and decoded string values. Duplicate keys are rejected and limits are
     bounded.
   - Its arch rules: `allow = []`, and I/O and async crates are banned.
   - `uaos-redact` uses it in place of its private tokenizer.
   - It is fuzzed from WP3.1 (PD-21).
2. **`uaos-module-api` exposes a structural view, never bytes.** A codec gets a read-only
   `StructuralView` of the request and responds with **selectors** that assign roles:

   | Role | Meaning | Kernel behaviour |
   |---|---|---|
   | `signed` | Thinking or reasoning blocks, signatures, encrypted reasoning | never edited, never rehydrated |
   | `opaque` | Fields to forward untouched | never edited |
   | `volatile` | Values that change between turns without changing meaning (e.g. `cache_control`) | excluded from lineage digests (ADR-0015) |
   | `newest_human_turn` | Where tags are read and injections are appended | tag strip and append-only injections happen only here |
   | `provider_produced` | Assistant turns and `tool_use` inputs | detectors never run; only the inverse rehydration map applies (ADR-0017) |
   | `system_entry(n)` | Entries of the `system` array | never added, removed, reordered or merged; entry 0 never touched; only the deterministic secret splice inside entries ≥ 1 |
   | `system_message` | A `role: "system"` message inside `messages` (CAP-6; Revision 1) | never added, removed, moved or merged; never treated as a human turn; only the deterministic secret splice inside it |

   **The newest human turn** is the last `messages` element with `role: "user"` that carries at
   least one block other than a tool result. A user message holding only tool results is tool
   output, so tags in it are never read (T1). A codec that cannot find such a turn marks none.
   The kernel then reads no tags and appends nothing; it never guesses.

   A codec also declares its dialect's endpoints with their class (governed, metadata or
   denied; plan v2 D-28) and its billing dimensions.
3. **The kernel resolves selectors and performs every edit.**
   - Edits are span splices on the original bytes; unedited bytes are forwarded unchanged.
   - Every edit is checked against the roles. An edit is a kernel error that fails the request,
     and is never forwarded, when it lands inside `signed` or `opaque`, at a forbidden `system`
     position, or inside a `system_message` other than the secret splice.
4. **Selectors cannot reduce redaction coverage.** Detection stays schema-agnostic over every
   JSON string (ADR-0009). Roles only *restrict* edits; they never exempt content from the final
   scan.
5. **Prefix stability is checked over values.** For each request the kernel compares the values
   of `system`, `tools` and earlier `messages` against what it sent on the previous turn of the
   same Session, as recorded in the chunk manifest. A difference that UAOS caused is an S2 event
   and counts toward the binding-mismatch SLI (B-37).

## Alternatives rejected

- **Full DOM parse and re-serialize:** it drops unknown fields, reorders keys and breaks the
  attribution strip; every new provider feature becomes a break.
- **Codecs computing byte offsets themselves:** a safety property implemented n times, by
  module authors.
- **Keeping the tokenizer private to `uaos-redact`:** codecs and redaction would then disagree
  about structure.

## Consequences

- A thirteenth Ring 0 crate. ADR-0001's crate map is amended, and `arch.toml` declares it before
  its first code.
- The module API grows by one view type and one selector language, and both freeze at RC-1.

## Threat and privacy note

- **I-06:** prefix stability by construction plus a check.
- **B-22/B-37:** signature breaks are prevented, and the ones that happen anyway are counted.
- **T2:** coverage is never reduced by codecs.
- **T1:** tags are read only from the newest human turn.

## Verification (WP3.1, WP3.4)

- Fuzz `uaos-json`: no panic, bounded memory, and spans always within the input.
- Property: a splice outside forbidden roles leaves every other byte unchanged, and a splice
  inside a forbidden role is rejected.
- Golden transcripts (sanitized) for both RC-1 dialects: an identity transform is byte-identical,
  and tag strip and placeholders are value-stable across turns.
- Live lane: zero binding mismatches by the provider's own oracle (plan v2 §2.5).
