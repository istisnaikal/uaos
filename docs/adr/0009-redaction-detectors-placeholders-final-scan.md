# ADR-0009: Redaction: detector sets, placeholders and the final scan

**Status:** Accepted (2026-10-13); amended 2026-10-13 by the retroactive review (see "Amendment 1") and 2026-10-22 (see "Amendment 2") · **Plan refs:** §2.5 DETECT/TRANSFORM/FINAL, D7, D20, T2, B-22 · **Builds on:** ADR-0005, ADR-0007

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
   only set. An unknown version is an error, never a silent fallback. Once a release has shipped a
   set, changing any rule, anchor or bound means a new version. **The freeze starts at RC-1:**
   before it, no session outside development has pinned v1, so v1 was corrected in place by
   Amendment 1.
2. **Detection** is a leftmost-first Aho–Corasick search over anchor literals that restarts one
   byte after each match, so an anchor overlapping another anchor's literal is still found. A
   per-format validator then confirms each candidate. Boundaries fail closed:
   - an anchor glued on its left to an **alphanumeric** byte sits inside a longer token and is
     not reported; any other left neighbour (`_`, `-`, `$`, `:` …) is a separator, and so is the
     tail of an escape still encoded in that view (the `n` of `\n`, the `0` of `%20`);
   - a format's body is the **whole** run of its characters, at least the format's minimum. A
     longer run, or one glued to more of the same characters, is covered whole.

   Overlapping detections merge into one span; the merged span takes the most specific class, by
   `DataClass` declaration order. Anchors inside a run, private-key block or userinfo window
   already examined reuse that work: every run computed is indexed by its end, per character
   class. A scan is therefore linear in its input; a unit test bounds the bytes examined on 16
   adversarial shapes, each with 3 tails, including the JWT header thrash the V1 review found.
3. **Classes claimed by v1** (11):

   | Class | Format confirmed |
   |---|---|
   | `private_key` | PEM `-----BEGIN … PRIVATE KEY-----` through the matching END line. Without an END line, everything to the end of the string is covered (fail closed) |
   | `jwt` | `eyJ…` header `.` `eyJ…` payload `.` signature of at least 16 base64url chars |
   | `anthropic_api_key` | `sk-ant-` + ≥ 32 token chars |
   | `openai_api_key` | `sk-proj-` / `sk-svcacct-` / `sk-admin-` + ≥ 40, or `sk-` + ≥ 40 containing `T3BlbkFJ` |
   | `github_token` | `gh[pousr]_` + ≥ 36 alphanumerics; `github_pat_` + ≥ 70 word chars |
   | `gitlab_token` | `glpat-` / `glrt-` / `gldt-` + ≥ 20 (dotted segments allowed) |
   | `slack_token` | `xox[bpares]-` + ≥ 20; incoming-webhook path after `hooks.slack.com/services/` |
   | `stripe_key` | `sk_`/`rk_` + `live_`/`test_` + ≥ 24 alphanumerics |
   | `google_api_key` | `AIza` + ≥ 35 token chars |
   | `aws_access_key_id` | `AKIA`/`ASIA`/`ABIA`/`ACCA` + ≥ 16 `[A-Z0-9]` (the key **id**; secret access keys are not claimed) |
   | `url_credentials` | the password in `scheme://user:password@host`, within 512 bytes of the `://`, its `@` and the host's first byte included. The user ends at the first `:` (no `/`, `?`, `#` before it; placeholders inside it are skipped whole). The password ends at the **last** `@` that a host follows, before a hard stop (whitespace, control, `"`, `<`, `>`, backtick) or the next `://`. So `/`, `#`, `?`, `'`, `\` and `@` inside a password are covered. Not a password: an authority starting with an IPv6 literal; `host:port/path@x`, when the password starts with a port number and `/`, `?` or `#`, and either the user is host-like (dotted, contains `@`, `localhost`) or the rest is a lowercase path; an scp-style path after an email-like user; a template reference (`${NAME}`, `$NAME`, `%(name)s`, `{{name}}`) |

4. **Schema-agnostic JSON.** Every string is scanned after its escapes are decoded: keys and
   values, known and unknown fields, at any depth. A decoded→raw offset map splices each
   placeholder into the original bytes. Strings without a finding are never copied; a body with
   no finding is returned borrowed. Malformed strings, invalid UTF-8 and lone surrogates are
   errors.
   - **Views.** Each string, and each plain text, is scanned in 4 views, outermost first:
     1. as decoded;
     2. with JSON escapes and ASCII percent escapes decoded once more;
     3. with form encoding decoded (`%XX` and `+` for a space), for text that has both;
     4. view 2 decoded once more.

     This covers JSON inside a tool call's arguments, a double-escaped `partial_json`, and
     percent- or form-encoded bodies. Decoding is lenient: an invalid escape stays as it is, so
     ordinary text is scanned, never refused. A finding in a nested view maps back through every
     view to whole escapes in the raw bytes.
5. **Placeholders.** The format is exactly `[REDACTED:<class>:<tag>]`, with a class this build
   knows and a tag of 16 lowercase hex digits; nothing looser is treated as a placeholder. The
   tag is the first 64 bits of
   HMAC-SHA-256 under the pocket's placeholder key, computed over a domain-separated class and
   secret. The same secret yields the same placeholder on every turn and after every restart, and
   a different one in another pocket. Without the key, a placeholder reveals nothing about the
   secret.
   - **Collisions** between distinct secrets are detected, and the content is blocked.
   - **Format freeze:** the placeholder format is frozen with detector set v1, because changing it
     would break the prefix stability of existing sessions.
   - **Key provisioning:** the key comes from the pocket keyring (ADR-0007) and is passed in by the
     runtime (P3).
6. **Fixpoint.** After replacement, each string is scanned again in every view, up to 8 rounds
   (one round handles one view). Content that still has findings after 8 rounds is crafted to
   chain replacements; it is replaced **whole** by one placeholder, which fails closed without
   wedging every later request that carries it. The output therefore contains no detection, so
   `redact(redact(x)) == redact(x)`. No detector matches a placeholder; the URL rule explicitly
   skips placeholder passwords.
7. **Final scan.** `FinalScanner` checks the exact outbound bytes:
   - every detector over every decoded string;
   - every detector over the raw bytes between strings, so text outside quotes in a malformed body
     is covered too;
   - the exact bytes of every known vault secret in both. A known secret must be at least 8 bytes;
   - each of these in the same 4 views the redactor scans (§4), so the final scan never passes
     what redaction would have replaced, and never blocks what it would have left. `check_bytes`
     (non-JSON bodies, headers, JSON Lines) uses the same views.

   Any hit, malformed input or scanner failure blocks. `Blocked` carries classes only, never
   content.
8. **Errors fail closed.** Every `RedactError` maps to `UAOS-REDACT-0002` (detector failure) and
   must block the content. A detection at the final scan maps to `UAOS-REDACT-0001`.
9. **Secrets in memory.** A `Replacement` keeps the secret in `Zeroizing<String>` for rehydration
   toward the originating client (P3). Every type in the crate that holds content, secrets or
   structure derived from them has a manual `Debug` that shows versions, counts and lengths only;
   a canary test proves it for the known-secret automaton.

## Measured

**Corpus v2** (Amendment 1). Synthetic, generated at test time from seed `0x55414F5352440002`,
so no secret-shaped string is committed.
- **Positives:** 3,000 per class (33,000 in all). Each is presented in one of five forms:
  - plain, in one of 26 contexts (shell, env files, headers, JSON, YAML, URLs, markdown, prose,
    Turkish text);
  - glued: separator glue on the left (`${KEY:-…}`, `KEY_…`), word glue on the right;
  - nested: inside a tool call's JSON arguments, with the secret's characters `\u`-escaped at
    that inner level;
  - double-nested: that document again inside a `partial_json` string;
  - percent-encoded, or form-encoded with `+` for a space;
  - slash-escaped, as PHP's `json_encode` writes `/`.

  URL passwords draw from every printable byte an unencoded URL can carry, the backslash
  included.
- **Detection criterion:** a positive counts as detected only if all four paths hold.
  - Text redaction removes it from everything a reader can recover. An oracle independent of the
    crate decides that: `serde_json` at any depth plus percent-decoding.
  - JSON redaction removes it from a chat message and from an unknown nested field, and the
    output passes the final scan.
  - The final scan blocks the unredacted JSON body, naming the class.
  - The final scan blocks the unredacted raw text, naming the class.
- **Negatives:** 100,000 hard negatives in 41 named families. False positives are counted per
  class **and per family**, so a family cannot hide in the total. The families include:
  - near-misses of every format, including runs that break before the minimum length;
  - URLs without a password, `host:port/path@…` on dotted and single-label service hosts,
    scp-style git URLs, and templated passwords;
  - two URLs glued by a byte that is not a scheme byte, the second with a user and no password
    (`url-glued`, Amendment 2);
  - JSON-escaped and percent-encoded text without a secret;
  - exact placeholders;
  - hashes, UUIDs, base64, code, prose and printable noise.

| Measure | Result | Threshold |
|---|---|---|
| Recall, every class | 3,000 / 3,000 (0 missed) | ≥ 99.9 % |
| False positives, every class | 0 / 100,000 | ≤ 0.5 % |
| False positives, every family | 0 in each of 41 | ≤ 0.5 % |
| Class labelled correctly | 3,000 / 3,000 | ≥ 99.9 % |

Zero misses in 3,000 bounds recall above 99.9 % at 95 % confidence (the rule of three). Against
the detector code before Amendment 1, the same corpus measures recall between 24.8 % (URL
passwords) and 64.7 % per class. A nightly job runs a fresh seed each night.

**Cost.** Release build, founder workstation, whole body each time:

| Body | Operation | p50 | p99 |
|---|---|---|---|
| 1.70 MB of prose messages (about 400k tokens), 19 secrets | Redacting the whole body | 5.2 ms | 8.2 ms |
| | Final scan of the whole body | 5.2 ms | 5.3 ms |
| 1.81 MB, every message carried as a tool call's JSON arguments, so every string has a nested view | Redacting the whole body | 9.5 ms | 9.7 ms |
| | Final scan of the whole body | 8.3 ms | 8.6 ms |

In the pipeline, chunk-digest caching (D20) limits redaction to new content. The final scan is
paid in full on every request. On the nested worst case it exceeds the 6 ms the plan's per-stage
budget assumes for this stage (plan v2 §2.4, a hypothesis). That number is an input to WP3.8's
overhead measurement and to D-24 (a chunk-cached final scan, allowed only with a proof that it
equals the full scan).

## Limits, stated plainly

- **Corpus-bound recall.** Recall is measured against the formats listed above, on a synthetic
  corpus built from those formats. It is not a measurement of real-world traffic.
- **Not detected:**
  - secrets outside these formats: free-form passwords not in URL userinfo, AWS secret access
    keys, provider keys of other vendors;
  - secrets deliberately encoded beyond the 3 views, for example base64, reversed, or escaped
    three or more times;
  - a secret split across strings (`"sk-ant-" + rest`) or across stream deltas; the stream relay
    handles deltas in P3;
  - an anchor glued on its left to an alphanumeric byte (`xAKIA…`): by design it reads as part
    of a longer token;
  - URL passwords:
    - containing an unencoded `"`, `<`, `>`, backtick or `://`, which end a URL in text;
    - starting with `//`, where the user's `:` and the `//` read as `://` (Amendment 2);
    - with userinfo of 511 bytes or more: its `@` and the host's first byte must fall within the
      512 bytes after the `://` (Amendment 2);
    - that start with a port number and `/`, `?` or `#` after a host-like user, or continue as a
      lowercase path;
    - that look like an scp path after an email-like user;
    - that are template references.

    Each reads as something else, as URL parsers would read it.
- **Over-redaction.** A URL whose path contains `@` after a password is redacted up to that
  `@`, host and path included; a key glued to more of its own characters is redacted with them.
  Both fail closed.
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

- **Gate `redaction-corpus`** (active): `crates/uaos-redact/tests/corpus.rs`. Three seeded
  negative cases prove it bites:
  - `redact-detector-drops-a-format`: a coarse one, which drops the `ASIA` prefix;
  - `redact-url-password-stops-at-slash`: a subtle one, one byte wide; it brings back review
    H2;
  - `redact-generator-draws-slash-password` (Amendment 2): the corpus generator draws a stated
    miss again, and CI seed 4814893562051029426's fixed case fails.
- **Behaviour and properties:** `crates/uaos-redact/tests/redact.rs`.
  - Stable per-pocket placeholders.
  - A clean body is returned borrowed, byte for byte; only the secret's bytes change.
  - `\u`-escaped secrets are caught; a PEM key with escaped newlines is replaced whole.
  - Keys, unknown fields and 100 levels of nesting are scanned.
  - Malformed input fails closed; the final scan blocks known vault secrets and unquoted content.
  - Unknown versions are refused; `Debug` output carries no secrets (canary test).
  - One test per review finding: URL passwords with any printable byte, glued and over-long
    keys, overlapping anchors, nested JSON at two depths, encodings in raw bytes, exact
    placeholders, and vault secrets through encodings.
  - One test per finding of the V1 review of hardening II: a redacted user does not hide the
    password, form-encoded keys, escaped left neighbours, a crafted cascade, service URLs and
    templates, and a backslash inside a password. A further unit test proves the whole-content
    fallback with a one-round budget.
  - The generator leaves out every stated miss, checked against the redactor sample by sample,
    and CI seed 4814893562051029426 is a fixed case (Amendment 2).
  - Linear work: a unit test bounds the bytes examined on 16 adversarial shapes of 256 KiB,
    each with 3 tails.
  - Fuzzing with real anchors: a property over random concatenations of anchors, separators,
    escapes and placeholders. Redaction reaches a clean fixpoint, and JSON and text redaction
    agree.
  - Properties: every secret is removed and redaction is a fixpoint. JSON redaction equals text
    redaction of every string and passes the final scan. Arbitrary bytes never panic, and refusals
    never pass the final scan.
- **Benchmark:** `cargo bench -p uaos-redact --bench redact`.

## Amendment 1 (2026-10-13): the retroactive review

The retroactive review (`docs/reviews/WP2.3-redact.md`) found three High findings and four
Medium ones in v1 as first merged. A second fresh-context review of the fixes (the V1 review of
hardening II, recorded in the same file) found two High and three Medium findings in them, and
those are fixed here too. The first review's findings were:
- a vault secret recoverable from `Debug`;
- URL passwords containing `/#?'` passed;
- fail-open glue and length bounds;
- one-level JSON decoding;
- encodings ignored by the byte check;
- a quadratic PEM slowdown;
- a circular corpus.

**Decision.** Detector set **v1 is corrected in place** rather than superseded by v2.
- **Why:** no released build has shipped v1 and no session outside development has pinned it.
  Keeping a set that is known to leak, only to version the fix, would protect nothing.
- **Freeze:** from RC-1 on, §1 holds without exception.

**Changes.**
- The rules in §2 and §3.
- The nested views in §4.
- The exact placeholder grammar in §5.
- 8 fixpoint rounds in §6.
- The final scan's views in §7.
- Corpus v2 and the costs under "Measured".
- The stated limits.

The placeholder format, the HMAC tag and the class names are unchanged, so placeholders already
produced stay valid.

## Amendment 2 (2026-10-22): the corpus generator leaves out every stated miss

**Context.** Two property-test failures were draws of stated misses that the corpus generator did
not leave out, not detector regressions:
- CI seed 4814893562051029426 (PR #41's Windows run) drew a URL password starting with `//`
  (`https://u://…@10.0.0.5`). The user's `:` and the `//` read as `://`, which ends a URL
  password, so detection and the final scan missed it.
- Stress seed 3677357430622100055 drew `amqp://svc2:3/#5pi.m@mq.example.org`. `3/#5pi.m` reads as
  `host:port/path`, a miss stated since Amendment 1. It has one shape with clean text such as
  `web:8000/?email=a@b.c`, so the detector cannot tell them apart.

**Decision.** Detector set v1 is unchanged.
- A password starting with `//` is stated as a miss.
- The generator leaves out every stated miss a random password can reach
  (`tests/common::stated_miss`): a `://` in the password or at its start, `host:port/path`, and a
  template reference. Its verdicts are a superset of the misses: it reads the password as written,
  so a `host:port/path` password whose path holds a percent escape is left out although the nested
  view finds it.
- The Limits state the window exactly. The `@` and the host's first byte must fall within the 512
  bytes after the `://`, so userinfo of 511 bytes or more is missed; they said "longer than 512
  bytes".

**Withdrawn: reading a `//` password after a plain user.** A detector extension did that: PR #43,
through five D-31 rounds, and its follow-up PR #45, through three. It continued the userinfo at
the inner `://`, and measured the window from the end of a placeholder that starts a password.
#45's final review found a High: a regression against the base detector across decoded views.
- A round replaces the findings of the outermost view that has any (`Redactor::round`). The
  extension adds outer-view findings the base never makes, and applying one can remove the `://`
  that a deeper view's URL needs.
- Witness: `smtp://ci+bot://me@corp.com:pa\nss%40mail.corp.com`, where `\n` is the two bytes `\`
  and `n`. The base redacts `pa\nss` in the form view. The extension first redacts `//me` in the
  outer view; the password is then read in no view, and the final scan passes.
- Measured on the review's Python port: 3 of 400,000 general fuzz texts lost bytes against the
  base with #45, and 632 of 50,000 texts of a targeted template with #43 alone.

Fixing it means changing the round policy. Taking every view's findings in each round removed the
losses in the review's trial (70,000 texts). But it changes the redactor's semantics and cost, and
by construction it can move a deeper finding's placeholder a round earlier and push a later
password past the window the base still reaches. The extension gained one rare shape, and a
regression against the base is not acceptable for it (red line 2). It is withdrawn; a future
attempt starts from the round policy. The `url-glued` corpus family it added stays, with 0 false
positives on detector v1.

**Seeded violation** (gate `redaction-corpus`): `redact-generator-draws-slash-password` lets the
generator draw a password starting with `//` again, and
`the_ci_seed_that_drew_a_stated_miss_is_redacted` then fails.

**Tests.** `the_ci_seed_that_drew_a_stated_miss_is_redacted` keeps the CI input as a fixed case.
`the_generator_leaves_out_the_stated_misses` checks the generator's verdict against the redactor on
each of its samples. The samples are synthetic, and a failure names the case without printing one:
CodeQL had flagged a version whose message printed it.
