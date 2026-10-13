# Retroactive adversarial review: WP2.3 uaos-redact

**Why retroactive:** WP2.3 merged without the V1 review that plan v2 now requires (PD-16).
**Reviewer:** a fresh-context review agent with the fixed checklist, read-only. It used probes
on a scratchpad export of `main` (release build). **Reviewed:** `main` at `3ed983f`, 2026-10-13.
**Result:** 0 Critical · 3 High · 4 Medium · 6 Low. **Verdict as reported:** "not yet fit to
serve as the C-53 fail-closed boundary". The crate's own tests, the corpus gate and clippy all
pass.

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
| H2, H3, M1–M4, L1–L3, L5, L6 | **Open, next change (WP2.3 hardening II)**: the URL-password break set, fail-open glue and length bounds, nested JSON decoding, encodings in `check_bytes`, the PEM slowdown, an independent corpus with per-family false-positive counts, exact placeholder grammar, and incremental known-secret handling. Until then, `docs/claims.md` lists these gaps as known limitations | — | — |
