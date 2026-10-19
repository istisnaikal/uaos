# Adversarial review: WP3.A2 `uaos-json`, the bounded tape (P3 Move 1, PR-2, ADR-0014)

**Reviewer:** a fresh-context review agent (plan v2 §4.2, V1), read-only on the branch, probing a
scratchpad copy on Windows 10 with its own scratch tests. **Reviewed:** `cc8f7ba` (`p3/a2-json`),
2026-10-19, the whole crate with the fingerprinted duplicate check hardest.
**Result:** 0 High · 4 Medium · 9 Low. No input got a duplicate key accepted, and no panic was
reachable.
**Resolution:** every Medium fixed, each with a regression test and, where a seeded bug can show
the test bites, a seeded violation. Every Low fixed or, where it is documentation by nature,
written into the contract. A scoped second round over the fixes (`cc8f7ba..97f16e3`) found 0 High,
2 Medium and 4 Low, resolved below; those fixes have not been reviewed again.

## Findings as reported

### Medium

**M1. Crafted fingerprint collisions made the duplicate check about 12 to 15 times slower.**
The fingerprint has no key, and every step of it can be run backwards. The reviewer fixed a
target fingerprint, ran the 2^32 low halves backwards to suffix words and kept the printable ones:
16,000 colliding keys in 0.38 s. Inside a run of shared fingerprints, each exact comparison
decoded both escaped keys again, about m·log m times. Measured: 1,009.9 ms on 30.9 MB (control
83.4 ms) and 1,297.8 ms on 30.4 MB (control 88.5 ms), all accepted. Still O(m log m) comparisons,
so the contract's wording held, but about ten times its worst adversarial row; §6 and the bench
had no colliding row, and the shared-prefix row no longer reached an exact comparison.

**M2. The word-at-a-time fingerprint had no merge-gate test.** An object is accepted when its
members' fingerprints differ, so `fingerprint` (raw keys, a word at a time) must equal
`fingerprint_decoded` (escaped keys, a byte at a time) for every key. Every escaped-duplicate test
decoded to fewer than 8 bytes. The mutant `from_le_bytes` → `from_be_bytes` passed the whole
committed suite and accepted `{"abcdefgh":1,…}` with the second key escaped; only the nightly
fuzzer's `verify` could have caught it.

**M3. A duplicate key is reported late, or not at all.** Duplicates are found when an object
closes, but the rustdoc said "the first rule the input breaks" and §7 "the first byte that cannot
continue". Observed: `{"a":1,"a":{"b":1,"b":2}}` gives `DuplicateKey` at 18, not 7;
`{"a":1,"a":2,]` gives `ExpectedKey`; an unclosed object gives `UnexpectedEnd`. Everything was
still refused; the kind and offset differed from the contract.

**M4. The offset map reserved up to 6 times its contract bound.** `map.reserve(bytes.len() + 1)`
sized it by raw length: 600,000 bytes of escapes gave a map of 100,001 entries with capacity
600,001 (2.4 MB) against §6's bound of 4 B × (decoded length + 1), 400 KB.

### Low

- **L1.** The node limit hid grammar errors: with `max_nodes = 2`, `[1,]` gave `TooManyNodes` at a
  byte that starts no value.
- **L2.** §7's offset exceptions were incomplete: `InvalidEscape`, `InvalidUnicodeEscape` (at the
  backslash), `InvalidLiteral` (at its start) and `KeyTooLong` (at the opening quote).
- **L3.** Two numbers were not quite right: a single scalar of exactly 32 MiB reserves 12 MiB of
  tape, not 6 MiB (6 MiB holds for the bench's 32 MiB − 16 bytes); the `[0,0,…]` row said "at most
  24 MiB allocated" while the last growth peaks at 36 MiB.
- **L4.** Proof inventories were stale: §9 listed 8 `json-*` cases, `gates.toml` had 12; threat
  row T19 said 9, there were 13.
- **L5.** The side stack's bound was never tested (only the tape's heap is observable), and no
  test asserted the outcomes of the adversarial inputs §6 said the tests assert.
- **L6.** `verify()` did not check the root's key fields; it cannot check node counts against the
  limits a tape was parsed under; its key decoding shares `unescape_at` with the parser
  (common mode, T14), mitigated by the serde_json differential.
- **L7.** The budget headroom was within noise: of five runs, one measured p95 2.163 ms, over
  budget.
- **L8.** `decode`, `decode_mapped` and `encode_str` aborted on a refused allocation;
  `OutOfMemory` without an abort held only inside `parse`.
- **L9.** No merge test accepted an object of more than 8 members against an oracle.

**Checked and sound** (the reviewer's list): `remember_key`'s assumption that the next pushed node
is the member; the `keys`/`marks` segmentation across nesting and empty objects; `member_id`
packing; the sort comparator's total order; duplicate offsets within one object; a 20,000-case
nested duplicate property with a close-order oracle; 100,000 fresh-seed cases of the differential
and fuzz tests; every grammar row, limit, BOM, UTF-8, number and surrogate case; no reachable
panic; no payload in `Debug`, `Display`, errors or violations; the number readers; every
`json-*` seeded violation caught by its named test for its stated reason; the nightly
environment variables taking effect; the bench's rows matching §10.

## Resolution

| Finding | What changed | Proof |
|---|---|---|
| M1 | One exact path for every run of shared fingerprints: keys without escapes are read in place, each escaped key is decoded **once** into a run scratch reused across objects, and positions are sorted by those bytes. `compare_keys` and its per-comparison decoding are gone. The scratch is 12 B per member of the largest run plus that run's escaped keys decoded, at most their raw length (§6). §6 now says collisions can be crafted, and that they cost time, never correctness | `crafted_collisions_are_compared_exactly` (unit test: 2,000 escaped keys computed by running the real fingerprint backwards, each asserted to collide, accepted; a repeat among them found where it starts). Bench rows against controls of the same shape: 126.9–127.3 ms against 88.7–89.2 ms and 139.9–140.7 ms against 86.3–86.9 ms, 1.4 and 1.6 times (§10). Negatives `json-escaped-duplicate-compared-raw` (re-anchored on the new path) and `json-fingerprint-collision-rejects` (re-anchored) **PROVEN** |
| M2 | Unit tests on the fingerprint itself; the duplicate property's alphabet gains keys of 0, 7, 8, 9, 16 and 17 bytes, `tool_use_id` and `cache_control` | `the_word_path_equals_the_byte_path` (every length 0–40, 64 inputs each), `escaped_spellings_share_the_raw_fingerprint` (four spellings, every length 0–40); new negative `json-fingerprint-word-order` (the reviewer's mutant) **PROVEN** |
| M3 | The close-time rule is stated in §7 and in `parse`'s rustdoc: the first object to close with a repeat is reported at its earliest second occurrence, unless the parser meets another error before that close | `a_duplicate_is_reported_when_its_object_closes` pins the reviewer's four inputs; the duplicate property, now the reviewer's nested version with a close-order oracle, checks it on generated documents |
| M4 | The first escape sizes the owned text and the map exactly from the decoded length, counted once, and reserves them with `try_reserve_exact` | The map's rules property and the fuzz targets still hold; the reservation is exact by construction (decoded length + 1 entries) |
| L1 | A byte that cannot start a value is `ExpectedValue` before the node limit is consulted | `the_node_limit_never_hides_a_grammar_error` |
| L2 | §7 lists every offset exception | Contract text |
| L3 | §10 states both reservations; §6's `[0,0,…]` line gives 24 MiB of tape and 36 MiB during the last growth | Contract text, from the reviewer's measurement |
| L4 | §9 lists all 13 `json-*` cases plus the arch case; T19 says 14 | `cargo xtask gates` checks every listed case exists |
| L5 | `tests/adversarial.rs` asserts each §6 outcome; a unit test runs the parser on a million-member object and on a 1,000-node limit and asserts the side stack's capacity never passes the node limit | `adversarial.rs` (5 tests), `the_side_stack_never_outgrows_the_node_limit` |
| L6 | `verify` also checks that the root carries no key start, length or escape flag. The limits a tape was parsed under are not kept on the tape, so `verify` checks the hard ceilings only, as stated; the common-mode decode stays mitigated by the serde_json differential | Existing `verify` properties; contract text |
| L7 | §10 reports 5 runs on a quiet machine: p95 1.853–1.868 ms, 7% headroom. The reviewer's over-budget run was taken while other builds ran on the same machine. Which machine judges stage budgets is open decision D-33 | §10 |
| L8 | `decode` and `decode_mapped` reserve exactly and return `OutOfMemory`; `encode_str` reserves the exact encoded length first and now returns `Result<(), JsonError>`, leaving its output unchanged when refused | API change before any caller exists; the fuzz target and the round-trip property updated |
| L9 | The nested property draws objects of up to 19 members from 30 distinct keys, so objects of more than 8 members without a repeat occur and must be accepted | `duplicates_are_found_exactly_after_decoding` |

**Re-verified after the fixes** (reference machine, 2026-10-20):
- the crate's tests: 5 unit, 5 adversarial, 25 grammar, 8 properties, plus the debug,
  differential and fuzz suites;
- 100,000 cases per property and fuzz test;
- the one-off 20,000-document differential (0 disagreements; the 13 known out-of-range numbers);
- all 14 seeded violations of the crate PROVEN;
- `cargo xtask clippy` clean.

## Second round, scoped to the fixes (2026-10-20)

**Reviewer:** a fresh-context agent, read-only on `97f16e3`, scoped to the diff `cc8f7ba..97f16e3`
and every invariant and caller it touches, probing a scratchpad copy. **Result:** 0 High ·
2 Medium · 4 Low. No fail-open, no reachable panic, no wrong kind or offset.

| Finding | What was wrong | What changed | Proof |
|---|---|---|---|
| M1 | The run scratch reserved per escaped key with `try_reserve`, which doubles, so it could hold about twice its decoded keys and keep that across runs: 56.66 MiB on a 29.39 MiB crafted input against §6's 12 MiB plus the input. Plain repeats and natural collisions also form runs, which §6 did not say | One exact reservation per run after `clear`, sized from the run's escaped keys; `spans` and `order` reserved exactly too. §6 says when a run forms | `the_run_scratch_stays_within_its_bound` (33 crafted keys of 4 KiB, first byte escaped: capacity at most the escaped keys' raw length); new negative `json-run-scratch-doubles` restores the doubling, measured at 264,256 bytes against 135,937, **PROVEN** |
| M2 | The bench's drift guard compared its fingerprint copy with itself, so it could not fail; the crafted rows could silently become a second control | The copy moved to `benches/support/fingerprint_copy.rs`, which the crate also compiles into its unit tests; the crate's own crafted-collision test now crafts with the copy | `the_bench_copy_is_the_fingerprint` (every length 0–40), and `crafted_collisions_are_compared_exactly` asserts every key crafted with the copy collides under the real fingerprint |
| L1 | Nothing failed if decoding at every comparison came back | A test-only count of the bytes `Unescape` produces | `crafted_collisions_are_compared_exactly` asserts a crafted run of 2,000 keys decodes at most three times its keys' bytes; once per comparison would be about eleven |
| L2 | The exact-size count walked the rest of the string a byte at a time before decoding | Counted with `memchr` over plain runs, escapes by their UTF-8 length, stopping where decoding stops | The decode properties, the map property and the 100,000-case fuzz run |
| L3 | Stale text: "no allocation", the decode module doc, "exact length" for `encode_str`, no `OutOfMemory` offset in §7, §10's row labels | All corrected | Contract and doc text |
| L4 | `IN_DECODED` (bit 31) relied on the input ceiling staying below 2^31 without a check | A compile-time assertion | `const _: () = assert!(Limits::MAX_BYTES_CEILING < IN_DECODED, …)` |
