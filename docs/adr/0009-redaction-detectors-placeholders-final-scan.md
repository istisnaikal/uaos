# ADR-0009: Redaction: detector sets, placeholders and the final scan

**Status:** Accepted (2026-10-13) · **Plan refs:** §2.5 DETECT/TRANSFORM/FINAL, D7, D20, T2, B-22 · **Builds on:** ADR-0005, ADR-0007

## Context

Red line 2 says secrets are never logged raw and high-risk redaction is fail-closed. CLAUDE.md sets
recall ≥ 99.9 % and false positives ≤ 0.5 %. Two constraints from ADR-0005 shape everything here:

- **Prefix stability.** Turn N+1 must re-send exactly the bytes turn N sent, or provider caches
  and signed reasoning blocks break.
- **Byte preservation.** Content we do not change must pass through byte for byte.

Three properties follow:

1. A placeholder must be a pure function of the pocket and the secret.
2. The rules must not change under a running session.
3. Redacting already-redacted text must change nothing.

## Decision

`uaos-redact` (Ring 0; depends only on `uaos-contracts` and `uaos-platform`, performs no I/O, never
logs).

1. **Detector sets are versioned as a whole and pinned per session.** `DetectorVersion::V1` is the
   only set. An unknown version is an error, never a silent fallback. Changing any rule, anchor or
   bound means a new version.
2. **Detection** is a single leftmost-first Aho–Corasick pass over anchor literals, followed by a
   per-format validator. Boundaries are checked on both sides, so a format inside a longer token
   is not reported. Overlapping detections merge into one span; the merged span takes the most
   specific class, by `DataClass` declaration order.
3. **Classes claimed by v1** (11):

   | Class | Format confirmed |
   |---|---|
   | `private_key` | PEM `-----BEGIN … PRIVATE KEY-----` through the matching END line. Without an END line, everything to the end of the string is covered (fail closed) |
   | `jwt` | `eyJ…` header `.` `eyJ…` payload `.` signature of at least 16 base64url chars |
   | `anthropic_api_key` | `sk-ant-` + ≥ 32 token chars |
   | `openai_api_key` | `sk-proj-` / `sk-svcacct-` / `sk-admin-` + ≥ 40, or `sk-` + ≥ 40 containing `T3BlbkFJ` |
   | `github_token` | `gh[pousr]_` + exactly 36 alphanumerics; `github_pat_` + 70–120 |
   | `gitlab_token` | `glpat-` / `glrt-` / `gldt-` + ≥ 20 (dotted segments allowed) |
   | `slack_token` | `xox[bpares]-` + ≥ 20; incoming-webhook path after `hooks.slack.com/services/` |
   | `stripe_key` | `sk_`/`rk_` + `live_`/`test_` + 24–247 alphanumerics |
   | `google_api_key` | `AIza` + exactly 35 token chars |
   | `aws_access_key_id` | `AKIA`/`ASIA`/`ABIA`/`ACCA` + exactly 16 `[A-Z0-9]` |
   | `url_credentials` | the password in `scheme://user:password@host`, ending at the **last** `@` of the authority |

4. **Schema-agnostic JSON.** Every string is scanned after its escapes are decoded: keys and
   values, known and unknown fields, at any depth. A decoded→raw offset map splices each
   placeholder into the original bytes. Strings without a finding are never copied; a body with
   no finding is returned borrowed. Malformed strings, invalid UTF-8 and lone surrogates are
   errors.
5. **Placeholders.** The format is `[REDACTED:<class>:<tag>]`. The tag is the first 64 bits of
   HMAC-SHA-256 under the pocket's placeholder key, computed over a domain-separated class and
   secret. The same secret yields the same placeholder on every turn and after every restart, and
   a different one in another pocket. Without the key, a placeholder reveals nothing about the
   secret.
   - **Collisions** between distinct secrets are detected, and the content is blocked.
   - **Format freeze:** the placeholder format is frozen with detector set v1, because changing it
     would break the prefix stability of existing sessions.
   - **Key provisioning:** the key comes from the pocket keyring (ADR-0007) and is passed in by the
     runtime (P3).
6. **Fixpoint.** After replacement, each string is scanned again, up to 4 rounds; if it still has
   findings, the content is blocked. The output therefore contains no detection, so
   `redact(redact(x)) == redact(x)`. No detector matches a placeholder; the URL rule explicitly
   skips placeholder passwords.
7. **Final scan.** `FinalScanner` checks the exact outbound bytes:
   - every detector over every decoded string;
   - every detector over the raw bytes between strings, so text outside quotes in a malformed body
     is covered too;
   - the exact bytes of every known vault secret in both. A known secret must be at least 8 bytes.

   Any hit, malformed input or scanner failure blocks. `Blocked` carries classes only, never
   content.
8. **Errors fail closed.** Every `RedactError` maps to `UAOS-REDACT-0002` (detector failure) and
   must block the content. A detection at the final scan maps to `UAOS-REDACT-0001`.
9. **Secrets in memory.** A `Replacement` keeps the secret in `Zeroizing<String>` for rehydration
   toward the originating client (P3). No type in the crate prints content or secrets in `Debug`
   output.

## Measured

**Corpus v1.** Synthetic, generated at test time from seed `0x55414F5352440001`, so no
secret-shaped string is committed.
- **Positives:** 3,000 per class (33,000 in all), across 26 contexts: shell, env files, headers,
  JSON, YAML, URLs, markdown, prose, and Turkish text.
- **Detection criterion:** a positive counts as detected only if all three paths hold. Text
  redaction removes it. JSON redaction removes it from a chat message and from an unknown nested
  field, and the output passes the final scan. The final scan blocks the unredacted body, naming
  the class.
- **Negatives:** 100,000 hard negatives:
  - near-misses of every format (lengths, prefixes, casing, publishable Stripe keys, public PEM
    objects, two-part JWTs, URLs without passwords);
  - hashes, UUIDs, base64;
  - code;
  - prose;
  - printable noise.

| Measure | Result | Threshold |
|---|---|---|
| Recall, every class | 3,000 / 3,000 (0 missed) | ≥ 99.9 % |
| False positives, every class | 0 / 100,000 | ≤ 0.5 % |
| Class labelled correctly | 3,000 / 3,000 | ≥ 99.9 % |

Zero misses in 3,000 bounds recall above 99.9 % at 95 % confidence (the rule of three). Five
further seeds gave the same result. A nightly job runs a fresh seed each night.

**Cost.** A 1.70 MB chat body (about 400k tokens) with 19 secrets, release build, founder
workstation:

| Operation | p50 | p99 |
|---|---|---|
| Redacting the whole body | 4.7 ms | 5.0 ms |
| Final scan of the whole body | 4.7 ms | 4.7 ms |

In the pipeline, chunk-digest caching (D20) limits redaction to new content. The final scan is
paid in full on every request.

## Limits, stated plainly

- **Corpus-bound recall.** Recall is measured against the formats listed above, on a synthetic
  corpus built from those formats. It is not a measurement of real-world traffic.
- **Not detected:**
  - secrets outside these formats: free-form passwords not in URL userinfo, AWS secret access
    keys, provider keys of other vendors;
  - secrets deliberately encoded, for example base64 or reversed.
- **Exposed history.** Secrets already sent before a session pinned v1 are not retro-redacted;
  P3 raises "already exposed — rotate" (plan §2.5).
- **Deferred to P3.**
  - The chunk-digest result cache arrives with chunk-aware transforms, because it needs the chunk
    boundaries the codec produces.
  - Rehydration and the `redact.exposed_secret` event arrive with the stream relay.

## Consequences

- New direct dependencies: `aho-corasick` and `memchr`. Both already shipped through `regex` (via
  Cedar), so the dependency tree is unchanged.
- A new format needs a new detector set version, a corpus generator for it, and the gate's
  thresholds met before the session default moves.

## Verification

- **Gate `redaction-corpus`** (active): `crates/uaos-redact/tests/corpus.rs`. It is proven to bite
  by a seeded detector set that drops the `ASIA` prefix.
- **Behaviour and properties:** `crates/uaos-redact/tests/redact.rs`.
  - Stable per-pocket placeholders.
  - A clean body is returned borrowed, byte for byte; only the secret's bytes change.
  - `\u`-escaped secrets are caught; a PEM key with escaped newlines is replaced whole.
  - Keys, unknown fields and 100 levels of nesting are scanned.
  - Malformed input fails closed; the final scan blocks known vault secrets and unquoted content.
  - Unknown versions are refused; `Debug` output carries no secrets.
  - Properties: every secret is removed and redaction is a fixpoint. JSON redaction equals text
    redaction of every string and passes the final scan. Arbitrary bytes never panic, and refusals
    never pass the final scan.
- **Benchmark:** `cargo bench -p uaos-redact --bench redact`.
