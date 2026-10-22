# ADR-0009: Redaction: detector sets, placeholders and the final scan

**Status:** Accepted (2026-10-13); amended 2026-10-13 by the retroactive review (see "Amendment 1") and 2026-10-21 (see "Amendment 2") · **Plan refs:** §2.5 DETECT/TRANSFORM/FINAL, D7, D20, T2, B-22 · **Builds on:** ADR-0005, ADR-0007

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
   Amendments 1 and 2.
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
   | `url_credentials` | the password in `scheme://user:password@host`, within 512 bytes of the `://`, measured from the end of a placeholder that starts the password (a password that starts with `//` runs up to 512 bytes past it, Amendment 2). The user ends at the first `:` (no `/`, `?`, `#` before it; placeholders inside it are skipped whole). The password ends at the **last** `@` that a host follows, before a hard stop (whitespace, control, `"`, `<`, `>`, backtick) or the next `://`. So `/`, `#`, `?`, `'`, `\` and `@` inside a password are covered. Not a password: an authority starting with an IPv6 literal; `host:port/path@x`, when the password starts with a port number and `/`, `?` or `#`, and either the user is host-like (dotted, contains `@`, `localhost`) or the rest is a lowercase path; an scp-style path after an email-like user; a template reference (`${NAME}`, `$NAME`, `%(name)s`, `{{name}}`) |

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
    - containing an unencoded `"`, `<`, `>` or backtick, which end a URL in text;
    - containing `://`, which reads as another URL starting there. A password that starts with
      `//`, where the user's `:` and the `//` read as `://`, is covered after a plain user
      (Amendment 2);
    - starting with `//` after a user holding a byte other than letters, digits, `+`, `.`, `-`,
      `_` or an earlier placeholder (`smtp://o'brien://pw@h`), which reads as glue between two
      URLs;
    - with userinfo longer than 512 bytes, measured from the end of a placeholder that starts the
      password; the userinfo of a password starting with `//` spans two such windows;
    - that start with a port number and `/`, `?` or `#` after a host-like user, or continue as a
      lowercase path;
    - that look like an scp path after an email-like user;
    - that are template references.

    Each reads as something else, as URL parsers would read it.
- **Over-redaction.** A URL whose path contains `@` after a password is redacted up to that
  `@`, host and path included; a key glued to more of its own characters is redacted with them;
  a doubled scheme (`https://https://jdoe@host`), or a bare host glued to the next URL with no
  glue, a scheme byte or `_` (`http://mirror.example.comhttps://git@host`), reads as a plain user
  before a password starting with `//` (`//jdoe`, `//git`), which is redacted. A merged span
  keeps the lowest class of what it covers, so such a span over a token reports that token's
  class, not `url_credentials`. All fail closed.
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

- **Gate `redaction-corpus`** (active): `crates/uaos-redact/tests/corpus.rs`, with the URL
  rule's unit tests. Eight seeded negative cases prove it bites; the six of Amendment 2 are
  listed there. The first two:
  - `redact-detector-drops-a-format`: a coarse one, which drops the `ASIA` prefix;
  - `redact-url-password-stops-at-slash`: a subtle one, one byte wide; it brings back review
    H2.
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

## Amendment 2 (2026-10-21): a password may start with `//`

**Found by:** CI. On PR #41's Windows run, `text_redaction_removes_every_secret_and_is_a_fixpoint`
drew seed 4814893562051029426, and a URL password starting with `//` survived redaction and the
final scan: `https://u://…@10.0.0.5`. The user's `:` and the password's `//` read as a `://`. The
userinfo window ended at it, and neither anchor found the password.

**Decision, as narrowed by its final review:**
- **Each anchor reads its own URL** in a window that ends at the next `://`, as before, except
  that the window's bound is measured from the end of a placeholder that starts the password.
- **One shape runs past that `://`:** a password that starts with `//` after a plain user
  (letters, digits, `+`, `.`, `-`, `_` or an earlier placeholder).
  - The anchor at that `://` continues it, to the last `@` a host follows in its own window.
  - A chain only adds to what each anchor finds, spans two windows at most, and never carries
    further.
  - A chained anchor may open its own: `x://u://v://pw@h` reaches `//pw`.
- **Every other `://` in a password ends it**, as before this amendment. This is a stated limit.
- **The scan stays linear.** Each window is read a constant number of times
  (`adversarial_inputs_are_scanned_in_linear_work`, which drives the chained path).
- **The corpus generator** leaves out passwords holding `://`, the stated limit, so the property
  claims what the rule does. The CI seed is kept as a fixed case.

**How it was narrowed.** The first version let a userinfo run on past any `://` that did not look
like another URL starting. Three review rounds kept finding shapes at that boundary:
- a chain from `host:port/…` hid the next URL's password (V1 H1);
- glued URLs, a `host:port` with no path, and colon-joined schemes gave new false positives (V1
  and scoped M1);
- a placeholder in the user, and a chain reaching the length bound, missed shapes stated as
  covered (scoped M2, final M1 and M2);
- a templated password or an image tag before a glued URL ran on into it (final M3).

The first, V1's H1, was a regression from the base, fixed before the next round. The others were
not regressions, but each made a claim false. The final review's fixes would
have added more rules at the same boundary. The rule was narrowed instead to the shape CI found,
which none of these shapes touch.

**Precision:**
- Two URLs a comma separates stay two passwords.
- None of these is a password:
  - a URL list;
  - a redirect parameter;
  - a `host:port` URL before another URL;
  - a URL glued to another by a byte that is not a scheme byte or `_`, the second with a user
    and no password, a templated password or an image tag before it included.
- These are tested (`another_url_after_a_list_byte_stays_another_url`,
  `a_host_and_port_never_hide_the_next_urls_password`) and seeded.
- The corpus's `url-glued` family measures it.
- A doubled scheme, or a bare host glued to the next URL by a scheme byte, `_` or nothing, is
  over-redacted, as the Limits state (round 4 M1, round 5 L1).
- **Across redaction rounds:** the bound is measured from the end of a placeholder that starts a
  password, a redacted `//` password's among them, so neither the placeholder nor the user and
  its `:` count. A whole placeholder right before `://` stands for its scheme, so a secret glued
  to the scheme (`ghp_…https://`) does not leave its URL unreadable in the next round (#45 V1 M1:
  `a_secret_glued_to_the_scheme_keeps_its_url_readable`, seeded). With both, redacting a
  password does not push the rest of its URL out of reach in a later round, by the bound or by
  the scheme. The cost is fail-closed: in a later round the bound reaches one user and one
  placeholder further, so a path `@` that far is redacted with it. This is round 4 M2, and the
  follow-up to round 5 M1:
  `a_redacted_password_never_pushes_its_url_out_of_reach`, with a 300-byte user at the old
  boundary, seeded.

**Seeded violations** (gate `redaction-corpus`):

| id | Seed | Caught by |
|---|---|---|
| `redact-url-separator-ends-userinfo` | the user is looked for only before the cut | `url_passwords_may_hold_a_scheme_separator` |
| `redact-url-chain-any-user` | any user owns a password starting with `//` | `another_url_after_a_list_byte_stays_another_url` |
| `redact-url-chain-blocks-next-url` | a chained anchor does not open its own | `url_passwords_may_hold_a_scheme_separator` |
| `redact-url-placeholder-counts-toward-bound` | an earlier round's placeholder counts toward the bound (round 4 M2) | `a_redacted_password_never_pushes_its_url_out_of_reach` |
| `redact-url-bound-counts-the-user` | the bound counts the user and its `:` (#43 round 5 M1, its follow-up) | `a_redacted_password_never_pushes_its_url_out_of_reach` |
| `redact-url-placeholder-not-a-scheme` | a placeholder before `://` does not stand for its scheme (#45 V1 M1) | `a_secret_glued_to_the_scheme_keeps_its_url_readable` |

**The reviews' Lows:**
- The length bound is stated as it is.
- The status line and the Verification section are updated.
- The corpus is re-measured with its 41st family ("Measured").
- `LIST_BYTES` and its `]` went with the broader rule.
- Round 4: the bound's wording (`USERINFO_MAX`), the linear-work test drives the chained path
  (`a://u://p@h`), and the comments no longer speak of list bytes.
- **The generator leaves out every stated miss a random password can reach.** These are a `://`
  in the password, `host:port/path` (`port_then_path`) and a template reference. The test
  `the_generator_leaves_out_exactly_the_stated_misses` checks it against the redactor.
  - Stress seed 3677357430622100055 had drawn `svc2:3/#5pi.m`, a `host:port/path` miss stated
    since Amendment 1, which the generator did not leave out: about three runs in 10,000
    could fail on a documented limit.
  - The detector is unchanged here. `web:8000/?email=a@b.c` (clean) and `svc2:3/#5pi.m@host`
    (a secret) have one shape, and narrowing the exclusion would trade it for false positives.
  - CodeQL flagged the test's synthetic fixtures, with 8 `rust/hard-coded-cryptographic-value`
    alerts and 1 `rust/cleartext-logging` alert. `stated_miss` took them as a parameter named
    `password`, and the failure message printed one. They are named `candidate` now, and the
    message names the case instead of printing it.

**Cost:** re-measured against the base detector on the same machine, with the broader rule of the
scoped round. The p50s agree within about 1% on all four rows of the cost table:

| Row | This rule | Base (`ceadeb0`) |
|---|---|---|
| Redacting the prose body | 5.24 and 5.26 ms | 5.22 and 5.26 ms |
| Its final scan | 5.27 ms | 5.28 and 5.29 ms |
| Redacting the nested body | 9.59 and 9.62 ms | 9.62 and 9.68 ms |
| Its final scan | 8.31 ms | 8.30 and 8.35 ms |

The p99s varied between runs on both builds by up to twice, under other load on the machine. The
narrowed rule does less than the one measured, so the table's figures stand.

**D-31 round 5, the last round** (`222bda4`): 0 High · 1 Medium · 3 Low.
- **M1, split to a follow-up as D-31 requires.** Round 4's fix keeps the placeholder from
  counting toward the bound, but the user and its `:` still count. So in one unbroken run of
  about 450 bytes or more, a password the base redacts in a later round can be missed. This PR
  narrows its claims and states the residual in the Limits. The follow-up measures the bound
  from the placeholder's end, with boundary tests and the seed re-anchored, and gets its own V1
  review.
- **L1:** `_` as glue is named under Over-redaction.
- **L2:** the bound's exception for a leading placeholder is stated in the rule table, the
  Limits and the Decision.
- **L3:** "read a constant number of times".
- **Verified clean by round 5:**
  - no regression within one scan;
  - every stated-covered shape is found;
  - the generator mirrors the detector exactly: 0 of 10,889 URL secrets survive a property
    sweep, and 0 are kept but missed in a biased 300,000-password sweep;
  - `url-glued` is clean;
  - the scan is linear;
  - all six seeds bite.

**The follow-up to round 5 M1** (a separate PR, as D-31 requires): the bound is measured from
the end of a placeholder that starts the password, so the user and its `:` no longer shrink a
URL's reach in a later round. The test covers the old boundary, a 452-byte tail with a 1-byte
and a 300-byte user. The window stays bounded, at one user and one placeholder past 512 bytes, so
the scan stays linear. The Limits' residual is removed.

**#45's V1 review** (0 High · 1 Medium · 3 Low):
- **M1.** A secret glued to the scheme (`ghp_…https://u://p@h…`) is redacted in the same
  round as the `//` password. The next round's only `://` then follows `]`, and no anchor read
  the URL, where the base did.
  - **Fix:** a whole placeholder before `://` stands for its scheme (`placeholder_ends_at`,
    which looks back at most one placeholder's length).
  - **Proof:** tested on the review's witness and on the round-5 shape with the token glued;
    seeded.
- **L1:** the CHANGELOG lists every seed.
- **L2:** the `USERINFO_MAX` doc and the Limits no longer bound the chained userinfo at twice
  512 bytes. Each window can add a user and a placeholder.
- **L3:** the bound's fail-closed over-redaction in a later round is stated in Precision.
