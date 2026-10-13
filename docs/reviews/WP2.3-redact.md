# Retroactive adversarial review: WP2.3 uaos-redact

**Why retroactive:** WP2.3 merged without the V1 review that plan v2 now requires (PD-16).
**Reviewer:** a fresh-context review agent with the fixed checklist, read-only. It used probes
on a scratchpad export of `main` (release build). **Reviewed:** `main` at `3ed983f`, 2026-10-13.
**Result:** 0 Critical · 3 High · 4 Medium · 6 Low. **Verdict as reported:** "not yet fit to
serve as the C-53 fail-closed boundary". The crate's own tests, the corpus gate and clippy all
pass. **Status:** every finding is fixed or explicitly accepted (see Resolution).

## Findings as reported

### High

**H1. `FinalScanner`'s `Debug` output leaks the vault secrets.** The scanner derives `Debug` over
an `AhoCorasick` automaton. The printed DFA transitions and byte classes let a probe reconstruct
a known vault secret exactly, although a plain substring search finds nothing. The workspace lint
`missing_debug_implementations` would spread the leak to any struct that contains the scanner.
This breaks red line 2 and ADR-0009.

**H2. A URL password containing `/`, `#`, `?` or `'` passes all three paths** (text, JSON and the
final scan). The cause is the userinfo break set. About 40% of
`openssl rand -base64 24` passwords contain `/`. The corpus password alphabet leaves out exactly
these bytes.

**H3. The boundary and length validators fail open on vendor-prefixed keys.** These all leak:
- `${ANTHROPIC_API_KEY:-sk-ant-…}`, `_ghp_…_`, `STRIPE_KEY_sk_live_…`;
- a key immediately followed by more word characters;
- runs longer than the `max` bound.

### Medium

- **M1. JSON inside a JSON string is decoded only one level.** Tool `arguments`, `partial_json`
  and tool results take exactly this shape.
- **M2. `check_bytes` ignores encodings.** Form-encoded DSNs and PEM headers pass, and so does
  JSONL with `\u` escapes.
- **M3. Repeated PEM headers cause a quadratic slowdown.** 1 MB of repeated
  `-----BEGIN RSA PRIVATE KEY-----` takes 860 ms. Because the final scan covers the full history,
  one poisoned tool result slows every later turn.
- **M4. The corpus gate is circular.** Positives are generated at the validators' exact shapes.
  The false-positive rate is diluted across all 100k negatives instead of being counted per
  family. The seeded failure is coarse, and there is no fuzzing with real anchors.

### Low

- **L1. Claim wording.** The text claims no `Debug` leaks, "linear" scanning and "AWS keys" (only
  the key id is covered), and the ADR's list of limits is incomplete.
- **L2. A PEM key is lost when another anchor overlaps its header.**
- **L3. Placeholder recognition is loose, and placeholders are unauthenticated.**
- **L4. Copies of secrets are not zeroized,** and crate-private types derive `Debug` over raw
  content.
- **L5. Known-secret handling is all-or-nothing with only a length floor,** and encoded vault
  secrets are not matched.
- **L6. A lone surrogate in history wedges the session.** Failing closed is correct here, but
  there is no quarantine path.

## Resolution

| Finding | Status | What changed | Proof |
|---|---|---|---|
| H1 | **Fixed** (this change) | `FinalScanner`, `DetectorSet` and the crate-private `Strings` and `Decoded` have manual `Debug` implementations that show only the version, counts and lengths. No secret-derived structure (automaton, raw or decoded content) reaches `Debug` | `debug_output_carries_no_secret_material`: a canary vault secret leaves no 4-byte window in `{:?}` or `{:#?}`. Against the original derived `Debug` the test fails with "Debug output is unexpectedly large: 7741 bytes" |
| L4 (the `Debug` part) | **Fixed** (this change) | as above | as above |
| H2 | **Fixed** (hardening II) | The userinfo window ends only at hard stops (whitespace, control, `"`, `<`, `>`, `\`, backtick) or the next `://`. The user ends at the first `:`, and a `/`, `?` or `#` before it means there is no userinfo. The password ends at the last `@` that a host follows. `host:port/path@x` (a host-like user, digits, then a path) is not userinfo | `url_passwords_with_any_printable_byte_are_redacted` (all four paths); `urls_without_userinfo_are_not_passwords`; corpus v2 passwords use every printable URL byte; seeded negative `redact-url-password-stops-at-slash` |
| H3 | **Fixed** (hardening II) | Left glue counts only for alphanumeric bytes. Every format's body is the whole run of its characters, with a minimum and no maximum; the exact-length rules and the right-boundary checks are gone. A longer or glued run is covered whole (fail closed) | `glued_and_overlong_keys_are_redacted`; `separators_on_the_left_are_not_glue`; `runs_longer_than_the_format_are_covered_whole`; corpus v2 glued form |
| M1 | **Fixed** (hardening II) | Each string is scanned in 3 views: decoded, then one and two further levels of JSON and percent escapes, decoded leniently. A finding maps back through every view to whole escapes in the raw bytes. The final scan checks the same views, so it never passes what redaction would replace and never blocks what redaction leaves | `secrets_nested_in_json_strings_are_redacted` (tool arguments, `partial_json`, inner JSON stays valid); corpus v2 nested and double-nested forms; `nested_levels_decode_leniently_and_map_back` |
| M2 | **Fixed** (hardening II) | `check_bytes` scans the same 3 views, which covers percent-encoded bodies and `\u`-escaped JSON Lines | `encoded_secrets_in_raw_bytes_are_found`; corpus v2 checks the raw text through `check_bytes` for every positive |
| M3 | **Fixed** (hardening II) | Anchors inside a run, private-key block or userinfo window already examined reuse that work; `memchr::memmem` replaces the naive search | `adversarial_inputs_are_scanned_in_linear_work`: 11 adversarial inputs of 256 KiB, bytes examined ≤ 8 × input + 64 KiB |
| M4 | **Fixed** (hardening II) | Corpus v2: five evasion forms; an oracle independent of the crate (`serde_json` + percent-decoding); false positives counted per family (38 families); a second, one-byte seeded regression; a property that fuzzes with real anchors. cargo-fuzz targets stay with PD-21 (WP3.1) | Corpus v2 is all green. Against the pre-fix detectors it measures recall of 24.8–64.7 % per class. Both seeded negatives are PROVEN |
| L1 | **Fixed** (hardening II) | Crate docs and ADR-0009 now say "AWS access key ids", state the linear-work bound with its proof, and list the remaining limits | review of the text |
| L2 | **Fixed** (hardening II) | The search restarts one byte after each match, so an anchor overlapping another's literal is found | `an_anchor_overlapping_another_anchor_is_still_found` |
| L3 | **Fixed** (grammar) / **accepted** (authentication) | A placeholder is recognised only as `[REDACTED:<known class>:<16 lowercase hex>]`. Placeholders stay unauthenticated by design: rehydration (ADR-0017) restores only values recorded at redaction time, so a placeholder the user types never rehydrates to anything | `placeholders_are_recognised_exactly`; corpus v2 `placeholder` family |
| L4 (copies) | **Accepted** | Decoded views and round buffers that hold a secret are dropped without zeroizing. The request body itself, which the caller owns, holds the same bytes, so wiping the copies gains little until P3 owns the request buffers (they will be zeroized there, plan §2.4) | — |
| L5 | **Fixed** (encodings) / **scheduled** (incremental) | Known vault secrets are matched in all 3 views. Adding secrets one at a time arrives with the per-session known-secret matcher (ADR-0017, WP3.4) | `known_secrets_are_matched_through_encodings` |
| L6 | **Accepted** | A lone surrogate blocks the request, which is the correct fail-closed outcome. The way out arrives in P3, where the runtime's error names the message, and in P6A, where @devam can drop it from the next request | — |
