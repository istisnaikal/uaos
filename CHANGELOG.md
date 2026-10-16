# Changelog

All notable changes are recorded here. Format: [Keep a Changelog](https://keepachangelog.com/en/1.1.0/);
versions follow [Semantic Versioning](https://semver.org). Contract (schema) changes must appear
here in the same change that alters `schemas/` (docs-with-contract gate).

## [Unreleased]

### Security

- `uaos-policy` hardening after the retroactive review (`docs/reviews/WP2.1-policy.md`; ADR-0008
  Amendment 1):
  - **Crafted policy text aborted the process** (about 80 nested parentheses overflowed Cedar's
    parser). Text is now bounded before Cedar sees it: 8 nested brackets, 16 `if`s, 256 operators
    (brackets included) and 16 KiB per policy, and 4 MiB in all. The scanner skips comments
    exactly as Cedar's lexer does. The bounds were measured against the actual overflow
    points.
  - **Approvals could never complete.** A grant is now the approval:
    - it satisfies the `@effect("ask")` policies it lists, and allows on its own;
    - it covers nothing riskier than approved (risk tier, data classes);
    - a forbid still wins over it.

    Grants are matched natively, and a property proves this equals compiling them to permits.
  - **The proofs behind the slicing and fail-closed claims did not hold.** Slicing is now
    checked against the complete loaded set. The fail-closed property always has an erroring
    forbid and a permit both apply.
  - **Also:**
    - action groups are honoured by slicing;
    - `@id`s are plain (they cannot pose as explanations);
    - templates are refused;
    - a provider name with `/` fails closed;
    - a request clock running more than 5 s backwards is refused;
    - `@reason` texts are returned.

- Ledger hardening after the retroactive adversarial review (`docs/reviews/WP2.2-ledger.md`),
  which found two overspend paths in merged code:
  - **H1:** a ledger rebuilt from the journal accepted reservations before recovery had charged
    an unclosed overrun. A rebuilt ledger now refuses all new work until `recover()` has run, and
    the cap subtracts any overrun not yet closed.
  - **H2:** caller idempotency keys could collide with keys the ledger derives itself, leaving a
    transfer half-applied and recovery failing permanently. Reserved key forms are refused, a
    transfer checks both keys before its first entry, and recovery reports a stuck item (S2)
    while still closing the rest.
  - **Also:**
    - `recover()` is boot-only;
    - `release` and `settle` hand the token back when refused before recording;
    - stricter per-entry validation in `uaos.budget_tx/1` (fields only where they mean something,
      no hold below zero, releases close);
    - transfers cannot create pools;
    - replay refuses refunds and unattached adjustments, which have no producer;
    - a retry must match every field;
    - distinct error codes `UAOS-BUDGET-0005` to `0007`;
    - overruns are journaled at the highest risk tier.
  - **Accepted, with a reason:** the journal does not yet mark when execution began. That
    arrives with the runtime (WP3.3).

- `uaos-redact`: `FinalScanner`'s derived `Debug` printed its known-secret automaton, from which
  a vault secret could be reconstructed exactly. This was found by the retroactive review
  (`docs/reviews/WP2.3-redact.md`, H1) and breaks red line 2. `FinalScanner`, `DetectorSet` and
  the crate-private JSON scanners now have manual `Debug` implementations that show only the
  version, counts and lengths. A canary test proves no 4-byte window of a vault secret reaches
  `{:?}` or `{:#?}`; against the old code it fails on a 7,741-byte dump.
- `uaos-redact` hardening II closes the rest of the retroactive review (ADR-0009 Amendment 1;
  detector set v1 corrected in place, because no release has shipped it):
  - **URL passwords** containing `/`, `#`, `?`, `'` or `@` were not redacted (H2). The password
    now ends at the last `@` that a host follows, before a hard stop.
  - **Keys glued to separators** (`${KEY:-sk-ant-…}`, `_ghp_…`, `KEY_sk_live_…`), keys followed by
    more word characters, and runs longer than a format allowed all leaked (H3). They are now
    covered whole.
  - **Nested encodings** (M1, M2): JSON inside a JSON string (tool arguments, `partial_json`) and
    percent-encoded text are scanned in three views by redaction, by `check_json` and by
    `check_bytes`.
  - **Smaller fixes:** overlapping anchors are found (L2), scanning is linear, with a test bound
    on adversarial inputs (M3), and placeholders follow an exact grammar (L3).
  - **Gate `redaction-corpus` now measures corpus v2** (M4): six evasion forms, every printable
    URL password byte, an independent oracle, and false positives per family (40 families). It
    reports 0 misses and 0 false positives. The pre-fix detectors scored 24.8–64.7 % recall per
    class on it. The new negative case `redact-url-password-stops-at-slash` proves the gate
    catches a one-byte regression.
  - **A second fresh-context review of these fixes** found 2 High, 3 Medium and 3 Low findings.
    All are fixed:
    - JWT scanning went quadratic;
    - a redacted user hid its password;
    - form-encoded keys passed;
    - service URLs and templated passwords were flagged;
    - an escaped left neighbour hid keys;
    - a crafted cascade wedged the session (such content is now replaced whole).
  - **Cost** on a 1.8 MB history where every message is a tool call's JSON arguments: final scan
    p50 8.3 ms. That is above the plan's 6 ms per-stage hypothesis, and is recorded as a WP3.8
    input.

### Added

- Maintainer decisions of 2026-10-15:
  - **Accepted ADRs:** ADR-0010 (as revised), ADR-0011, ADR-0013, ADR-0014 (as revised, after
    the WP3.0c spike), ADR-0018 and ADR-0019 (with Amendment 1). ADR-0011's code merged a day
    before its acceptance; that is recorded as a deviation.
  - **Ruleset:** the ADR-0019 ruleset is applied to `main` (id 25183857). It requires PRs with
    rebase-only merges, linear history, the checks `merge-gate` and `codeql`, and code scanning,
    with no bypass actors (PD-17).
  - **Threat model:** v1 is signed by the maintainer as the single signer (PD-10). This closes P2.
  - **Decision register:**
    - D-19, D-20, D-21, D-22 and D-26 are decided;
    - D-29 (when to ask providers for an uncompressed stream) is registered as open.
  - **New files:**
    - `docs/release/signing-and-identity.md`: the steps for code signing (D-19) and the
      repository move (D-22), and who does each;
    - `.github/workflows/live.yml`: the live-provider lane (D-21). It runs only on the schedule
      and on dispatch from `main`, in the protected `live-providers` environment, which fork
      PRs never reach. For now it proves its wiring at zero token cost.
- P3 Move 1, Gate 0 records (plan v2 PD-08, PD-10, PD-17):
  - **`merge-gate` CI job.** It `needs` every other `ci.yml` job, runs even when one failed or
    was skipped, and fails unless all succeeded.
  - **Ruleset narrowed (ADR-0019 Amendment 1).** The required checks in
    `docs/adr/appendix/0019-main-ruleset.json` are now `merge-gate` and `codeql`, so adding a
    job never needs another settings change.
  - **New registry checks in `cargo xtask gates`.** The merge gate's `needs` must equal the
    workflow's other jobs, and the ruleset must require exactly those two checks. Every active
    merge-lane gate must be covered by a required check.
  - **Phase check.** `gates.toml` gains `[project] phase`. The README status heading and the
    roadmap's "Current phase" line must name it, which makes the phase-line check that PD-08
    promised real.
  - **Seeded negatives:** `merge-gate-missing-job`, `docs-phase-line-stale`.
  - **Threat model v1.** Statuses reflect P1 and P2; scoped-credential assets are added; the
    in-process-module and CI trust boundaries are added; rows T14 to T19 are added (T18: module
    misbehaviour; T19: parser differential and decoding bombs). It awaits the maintainer's
    single-signer sign-off (PD-10).
  - **Privacy data flow v1.** It lists OS certificate checks (OCSP, CRL, AIA) triggered by TLS
    to the provider, and the machine metadata Claude Code puts in its own requests (CAP-3, CAP-8,
    CAP-10). The P3 in-process design is marked as not yet built.
  - **Claims registry.** It gains the scoped-credential claim that the README states.
  - **ADR-0010 Revision 1** (still Proposed; revised before the decision):
    - the typestate follows ADR-0002's full order;
    - execution starts at the door;
    - balanced-mode recovery settles open reservations at full cost and never releases them on
      a missing `op.executing`;
    - module effects are child Operations authorized by a `GrantRef`, and modules hold no I/O
      handles;
    - CPU stages run off the async workers;
    - the panic boundary has owners.
  - **ADR-0014 Revision 1** (still Proposed; ready for a decision):
    - a `system_message` role for mid-conversation `role: "system"` messages (CAP-6);
    - an exact definition of the newest human turn;
    - the evidence from the WP3.0c splice spike (`docs/adr/appendix/0014-splice-spike-2026-10-15.md`).
      Over 10,000 simulated turns under random client reformatting the values stayed stable,
      and both design counterfactuals broke them.
    - Decision item 6 states what the spike taught:
      - transforms are pinned per chunk value, keyed with the detector version and the
        transform configuration;
      - chunk digests exclude volatile members;
      - replayed edits are their own class;
      - the selector set is closed;
      - numbers are grammar-only.
- `uaos-egress`, the one outbound door (P3 Move 1, PR-5; ADR-0013, threat T5).
  - **Destinations.** Only declared upstreams, named by DNS names. Address literals are refused
    in every spelling.
  - **DNS.** The door resolves names itself, within a timeout, classifies every answer, and
    dials the classified address, at most four per attempt. It refuses every special-purpose
    range, including IPv4 embedded in IPv4-mapped, NAT64 and 6to4 forms, and Teredo; a
    well-known NAT64 address of a public IPv4 address is public, so IPv6-only networks reach
    IPv4-only providers through DNS64. An upstream
    declared private may also reach loopback, private and unique-local addresses, never
    link-local (the metadata service). Plain HTTP is dialled only at pinned local addresses and
    never resolved.
  - **TLS.** On aws-lc-rs, HTTP/1.1, against the system's root certificates read locally and
    verified by rustls: a handshake fetches nothing, so a server's certificate cannot make UAOS
    contact an address of its choosing. Revocation is not checked (ADR-0013 Amendment 1,
    accepted 2026-10-16).
  - **Requests.**
    - Redirects are returned, never followed, and nothing is retried.
    - The URI comes from the upstream's declaration; the path must start with `/`.
    - Hop-by-hop headers, `host` and `content-length` are stripped and no UAOS header is added.
    - A request carrying one of the listed credential-bearing headers (`authorization`,
      `cookie`, provider key headers and others) is refused, before anything is stripped.
    - The provider credential is inserted last; its value is never printed.
    - One send per Operation; a request bound to another Operation is refused.
    - A circuit breaker per upstream counts transport failures and lets one probe through
      after its cooldown; a probe whose caller gives up lets the next attempt probe, and a
      probe that settles after the circuit moved on changes nothing unless it answered. While a
      probe is in flight, `retry_after` is a 1 s hint.
    - IPv6 forms that embed a local IPv4 address are never treated as local, and the IPv6
      cloud metadata endpoints are refused.
  - **Connection tasks** run on an executor the runtime provides.
  - **Error codes** `UAOS-EGRESS-0001` to `0005`: blocked, unreachable, timeout, circuit open,
    refused.
- Reachability rules for the door (ADR-0010).
  - **`clippy.toml`.** Outbound connects (std and tokio, `TcpSocket` included, Unix sockets
    and Windows named pipes), name resolution (`lookup_host`, `to_socket_addrs`, hyper-util's
    `GaiResolver`), UDP and building another HTTP client are banned outside the door; listening
    (`TcpListener::bind`, `TcpSocket::listen`) outside the API crate; task and thread spawning,
    and the `JoinSet` and `LocalSet` types, outside the runtime; `Door::new` outside its one
    owner.
  - **`arch.toml`.** The bin's allow list is now explicit and leaves out the door; the bin
    reaches it only through the runtime. `uaos-module-api` and every Ring 1 crate are banned,
    transitively, from network, TLS and async-I/O crates (new `[ring1] ban`, enforced by
    `cargo xtask arch-check`).
  - **`deny.toml`** bans `ring`.
  - **Seeded violations (17):** `egress-dials-private-range`, `egress-numeric-host`,
    `egress-private-reaches-link-local`, `egress-plaintext-resolved`,
    `egress-breaker-admits-after-cooldown`, `egress-probe-stuck-on-cancel`,
    `egress-embedded-local`, `egress-ctor-outside-root`, `net-dns-outside-egress`,
    `net-resolver-outside-egress`, `net-connect-outside-egress`, `net-udp-outside-egress`,
    `net-listen-outside-api`, `net-socket-listen-outside-api`,
    `net-unix-connect-outside-egress` (Unix only), `spawn-outside-supervisor`,
    `arch-ring1-depends-on-hyper`.
  - **Review:** `docs/reviews/WP3.A5-egress.md`, three rounds, all resolved: 2 High, 4 Medium,
    9 Low; then 1 High, 2 Medium, 7 Low; then 1 Medium, 5 Low. Two fixes rest on ADR-0013
    Amendment 1, accepted by the maintainer on 2026-10-16.
- Dependencies for the ADR-0013 stack: tokio, hyper 1, hyper-util, http, rustls 0.23
  (aws-lc-rs only), tokio-rustls, rustls-native-certs, and rcgen for tests only.
  - 48 cargo-vet exemptions, each with a written reason (the unnoted baseline is unchanged);
    21 of them are lockfile-only crates that compile for no target.
  - cargo-vet 0.10 ignores the newer Bytecode Alliance audits for this stack, so they are not
    imported yet.

- Gate `policy-semantics` (active), proven by three seeded violations: slicing that drops
  unconstrained policies, an engine that skips an erroring policy, and a grant that overrides a
  forbid.

- `docs/decisions.md`: a register of open decisions with class, default and deadline. Decisions
  the next release depends on carry markers, so `xtask decisions --release` sees them.
- `docs/roadmap.md` (public roadmap), `docs/rfcs/` (process and template), `MAINTAINERS.md` (with
  the single-maintainer risk stated), `docs/research/name-check.md`.

- Proposed ADRs (48 h review windows open):
  - **ADR-0011:** scoped credentials (`uaos_sk_`), a hierarchy with decidable scope containment,
    epoch revocation and a guard against restoring an older data directory.
  - **ADR-0012:** approvals need an OS presence ceremony; peer-credential and containment checks
    are defence in depth; the first `unsafe` code comes with obligations.
  - **ADR-0019:** merge integrity with one maintainer: a ruleset with no bypass, an adversarial
    review per work package, and a selective 24 h cool-off.

- `journal-ack-bench` (uaos-testkit) and a nightly `ack-latency` job on Linux, macOS and Windows.
  They measure the production journal's acknowledgement latency (balanced, strict, group flush)
  and the chunk store's per-chunk write (plan v2 PD-01), and the table goes to the run summary.
  First local run (Windows 10, entry-level NVMe):

  | Series | p99 | Other |
  |---|---|---|
  | Balanced ack | 29 µs | |
  | Strict ack | 0.91 ms | |
  | Group flush | 0.68 ms | |
  | New 4 KiB chunk | 3.5 ms | p99.9 11.9 ms |

  The chunk path is the evidence behind PD-18 / ADR-0018: per-chunk flushes do not fit the
  overhead budget. First CI run on all three OSes, recorded in
  `docs/adr/appendix/0003-ack-latency-2026-10-13.md`:
  - balanced-ack p99 is 7.2 µs on Linux, 12.2 µs on macOS and 13.8 µs on Windows (H1 holds);
  - the slowest group flush is 29.5 ms (p99.9), so W = 50 ms stands;
  - a new chunk costs **28.5 ms at p99 on macOS**, more than the entire 25 ms overhead SLO.

- Three merge gates, each proven to bite by seeded violations (plan v2 PD-06, PD-19, V6):
  - **`allow-audit`** finds every `#[allow]`/`#[expect]` of `unsafe_code`,
    `clippy::disallowed_methods` or `clippy::disallowed_types`, including multi-line and
    `cfg_attr` forms, and skipping literals and comments. It fails unless the file is under an
    owner path in `arch.toml [allow_audit]`. Today 17 allows exist, all owned; `unsafe_code` has
    no owner.
  - **`vet-ratchet`**: cargo-vet exemptions without a `notes` reason may not grow past the
    baseline (233). When the count drops, the baseline must be lowered in the same change.
  - **`claims-lint`**: forbidden claim words ("perfect", "zero loss", "tamper-proof",
    "unobtainable", ...) fail in public documents unless quoted, negated or explicitly exempted
    with a reason.
- `docs/claims.md`: the registry of public claims and the gates behind them.

- Proposed ADRs for P3 (48 h review windows open):
  - **ADR-0010:** kernel tokens: a pipeline typestate in a private runtime module, plus
    reachability enforced by `arch.toml`, a `surface` check and a Ring 1 closure ban.
  - **ADR-0013:** tokio with hyper and rustls directly; no reqwest or axum; egress owns name
    resolution.
  - **ADR-0014:** codecs describe structure with declarative selectors over a kernel-owned
    view, and the kernel performs every edit; new Ring 0 crate `uaos-json`.
  - **ADR-0017:** rehydration is a policy-gated action with a recorded round trip and a
    per-session known-secret matcher.
  - **ADR-0018:** chunks join the journal's durability classes. One new chunk costs 28.5 ms
    at p99 on a macOS runner today.

- `cargo xtask evidence [--candidate <rev>] [--streak N] [--max-age-hours H]` (plan v2 V5). It
  checks the nightly runs on `main`. The newest must be green, at most 48 h old, and ran on
  code identical to the candidate in `crates/`, `xtask/`, the manifests and the toolchain file.
  `--streak N` requires N consecutive such nights (counted by date, not by run). No evidence
  is an error, never a pass. It is listed in RELEASING.md with `--streak 7`.
- `cargo xtask quick` (PD-22): fmt, clippy, unit tests (`--lib --bins`, without the long
  simulations) and the local structural checks; about 10 s on a warm cache.
- Nightly `mutants` job (V4): cargo-mutants 27.1.0 on uaos-policy, uaos-ledger, uaos-redact and
  uaos-state, with caught, missed and timed-out counts and the missed list in the run summary.
  It is report-only until a per-crate baseline exists; a failing unmutated baseline still fails
  the job.

- `docs/research/beachhead-facts.md` (plan v2 WP3.0a). It records the gateway requirements of
  Claude Code (16 facts) and Codex (6 facts), each with its source, date and consequence. Codex's
  Responses-only wire API is confirmed from the official configuration reference. What
  documentation cannot settle (Responses storage and encrypted reasoning as actually sent, the
  exact endpoint inventory) is listed as open until a traffic capture, which waits for the
  maintainer's go-ahead.

- P2 WP2.4: `uaos-identity`, scoped credentials (ADR-0011, proposed; cells C-07, C-08, C-09).
  - **Format:** `uaos_sk_` + 52 Crockford-base32 characters + a CRC-32 checksum. Parsing is
    strict, and look-alikes are rejected without a lookup. UAOS's own redaction class for the
    format follows in WP2.4b.
  - **Storage:** only an HMAC-SHA-256 digest under an identity key kept in the OS keychain. The
    secret is shown once and never journaled. A missing or malformed key while credentials exist
    is reported as lost (`UAOS-IDENTITY-0011`), never silently replaced.
  - **Hierarchy:** master → sub → child, at most four credentials per chain, at most 4,096 live
    credentials and 256 live children per parent. A scope is exact-or-prefix patterns over
    actions and resources, plus pockets, pools and an expiry. child ⊆ parent is checked at
    issuance; records are immutable. Issuing under a chain that is not live, or with an expired
    scope, is refused. A request that omits a dimension the scope restricts is denied.
  - **Revocation:**
    - revoking one credential, or bumping an epoch to revoke a whole subtree;
    - both are critical journal entries recorded before they return; the revocation counter in
      the OS keychain is raised afterwards.
  - **Restore guard:**
    - a keychain counter *ahead* of the journal means a restored data directory: verification
      and every write fail closed (`UAOS-IDENTITY-0005`) until one atomic `restore_recovered`
      entry revokes every live master;
    - *one behind* is an interrupted keychain write, repaired on open;
    - *further behind* or implausibly large fails closed (`UAOS-IDENTITY-0012`).
  - **Recording failures:** like the ledger, a failed recording poisons the writer until it is
    replayed from the journal. Request mistakes are user errors (`UAOS-IDENTITY-0013`), not
    internal failures.
  - **Tests:** random hierarchies with revocations and epoch bumps are checked against an
    independent model, with an independent coverage oracle: anything a credential covers, every
    ancestor covers. They run 256 times per merge and 10,000 nightly, with an anti-vacuity
    check. Regression tests cover each finding of the adversarial review
    (`docs/reviews/WP2.4.md`).
  - **Gate self-test:** a seeded verification that ignores an ancestor's epoch fails the
    property (`identity-epoch-check-skipped`).
- Contract (new): `uaos.credential/1` (draft until RC-1), new kernel event type `identity.entry`,
  and error codes `UAOS-IDENTITY-0003` to `0014`.
- `uaos-contracts::limits`: `MAX_SCOPE_ITEMS`, `MAX_CREDENTIAL_DEPTH`, `MAX_CREDENTIAL_TOKEN`,
  `MAX_LABEL_CHARS`, `MAX_LIVE_CREDENTIALS` and `MAX_LIVE_CHILDREN`. The validated-string serde
  macro is now shared between contracts.

- P2 WP2.3 — `uaos-redact` (ADR-0009): schema-agnostic secret detection and redaction with a
  fail-closed final scan. Detector set v1 covers 11 high-risk classes:
  - private keys, JWTs;
  - Anthropic, OpenAI, Google and AWS keys;
  - GitHub, GitLab and Slack tokens, Slack webhooks;
  - Stripe keys;
  - URL passwords.

  Detector sets are versioned and pinned per session. Every JSON string (keys, unknown fields,
  any depth) is scanned after decoding escapes, and placeholders are spliced into the original
  bytes; clean content passes byte for byte. Placeholders `[REDACTED:<class>:<hmac tag>]` are
  stable per pocket across turns and restarts. Redaction is a fixpoint (`redact∘redact = redact`).
  `FinalScanner` blocks on any detection, any known vault secret or any scanner failure.
  `redaction-corpus` gate **active**: synthetic corpus v1 (3,000 positives per class, 100,000 hard
  negatives, generated at test time) shows 0 misses and 0 false positives. Recall is bound to the
  claimed formats and this corpus; it is not a real-world rate. The gate is proven to bite by a
  detector set that drops one AWS prefix. Measured on 1.7 MB (about 400k tokens): full-body
  redaction p50 4.7 ms, final scan p50 4.7 ms.
- P2 WP2.2 — `uaos-ledger`: pools, reservations, settlement and transfers in integer nano-USD
  (float arithmetic denied).
  - **What the cap guarantees:** a reservation or outgoing transfer beyond the pool's available
    balance is refused before anything is recorded. Spend above a reservation (provider usage
    above the estimate) is recorded truthfully as an overrun, can take a pool negative, and is
    an S1 condition; the clamp and pricing reconciliation of P3 keep it rare.
  - **Typestate:** reservations are typestate tokens. `Held` can be released; once `begin` makes
    it `InFlight` it can only be settled (releasing it does not compile). A reservation id is
    single-use, so no duplicate token can exist.
  - **Recording:** every entry is recorded (journal `budget.entry`, critical) before it takes
    effect. It survives a process kill; within the power-loss window W it can be lost
    (ADR-0003). A recording failure poisons the ledger until it is replayed from the journal.
  - **Recovery:** settles open reservations at full cost, marked estimated, and never releases
    them; it also completes partial settlements and half-recorded transfers.
  - **`budget-concurrency` gate, active:** a randomized simulation against a reference model runs
    256 schedules per merge and 100,000 nightly (16.7 s locally), covering crashes and recording
    failures before and after the write. Contended threads and the journal round trip are also
    tested. A seeded ledger that skips the cap check proves the gate bites. Required behavior
    `budget-double-spend` is active.
- Contract (non-breaking): `uaos.budget_tx/1` gains optional `counterparty_pool`, required by
  `validate()` for `transfer_out`/`transfer_in` (`BudgetTxError::MissingCounterparty`), so recovery
  can complete a half-recorded transfer. New kernel event type `budget.entry`.
- P2 WP2.1 — `uaos-policy`: the reference monitor over Cedar (ADR-0008). Default deny; fail
  closed on any evaluation, request or entity validation error (Cedar alone would skip an erroring
  forbid); `Deny > Ask > Allow` via a validated `@effect("ask")`; strict loading (unique `@id`,
  known annotations only, strict schema validation against `uaos.cedarschema`); time-bounded
  grants compiled into scoped permits; per-action slicing proven decision-preserving; explanations
  for every decision. 1,000 policies: p99 662 µs.
- P1 WP1.6 — `journal-durability` gate **active**: `uaos-testkit` (dev-only) kills the production
  journal in a real process at random acknowledgement counts and random times, and verifies every
  acknowledged record by sequence and hash. 40 kills per OS per merge, 10,000 per OS nightly
  (new `nightly` workflow, which also runs the 20,000-scenario crash simulation). The gate is
  proven to bite by a seeded journal that acknowledges without writing. Required behavior
  `disk-full` is active.
- P1 WP1.5 — OS keychain (ADR-0007): `uaos-platform::keychain` (`OsKeychain` over keyring-core with
  an explicitly passed native store — Windows Credential Manager, macOS Keychain, Secret Service
  over pure-Rust zbus — and a fault-injecting `SimKeychain`); `KeychainKeyring`, the production
  `PocketKeyring`, with crash-safe rotation/retirement ordering and an in-memory key cache.
  Conformance suites run against simulated and (on Windows/macOS CI) real keychains.
  **Not yet implemented:** the headless passphrase vault of ADR-0007 §3; until it lands, hosts
  without a keychain fail loudly with `UAOS-STORE-0003`.
- P1 WP1.4 — `uaos-state::projection`: SQLite (bundled, WAL) projections of the journal —
  event index, operation states, cursor — holding metadata only. `catch_up` continues from the
  cursor and rebuilds automatically when the cursor no longer matches the journal (another
  journal, rewritten history, damaged cache). Queries: operation state, correlation trace,
  open intents (the input of crash recovery). Property test: incremental maintenance across
  journal crashes equals a rebuild from scratch, compared by canonical dump.
- P1 WP1.3 — `uaos-state::chunks`: encrypted, content-addressed chunk store. References are
  `HMAC-SHA-256(pocket key, content)` (deduplicated per pocket, unlinkable across pockets);
  every chunk has a random AES-256-GCM data key, context-bound to pocket and reference, wrapped
  by a versioned pocket KEK. Writes are atomic and durable before acknowledgement. Shredding
  rotates the KEK first, deletes, re-wraps survivors and destroys old versions, so restored
  backups of a shredded key are useless; an interrupted rotation is finished on open.
  `PocketKeyring` interface with an in-memory double (OS keychain in WP1.5).
- `uaos-platform::crypto`: `SecretKey` (zeroized, never printed), HMAC-SHA-256, AES-256-GCM.
- Error registry: `STORE` domain (`UAOS-STORE-0001..0003`).
- `SimFs::fail_sync_after(n)` to aim a flush fault at a specific step.
- P1 WP1.2 — `uaos-state` journal core: append-only `uaos.event/1` segments chained over exact
  line bytes from a per-journal genesis; atomic manifest with sealed/suspect/active segments;
  one-daemon-per-data-directory lock; crash recovery that verifies the whole chain, flushes
  before sealing, quarantines orphan segments and never appends after a torn tail; balanced
  (W = 50 ms) and strict flush policies; failed flushes rewritten to a fresh segment, never
  retried in place; disk-full and write failures fail closed until `recover()`; explicit
  `JournalHealth`. Deterministic simulation (crash, power loss, failed flush, disk full) runs
  256 scenarios per merge and 20,000 per policy in a deep sweep, all passing.
- `uaos-platform::crypto`: SHA-256 via aws-lc-rs (ADR-0006: prebuilt NASM objects on Windows).
- P1 WP1.1 — `uaos-platform::fs`: the filesystem boundary for durable stores (append-only
  files, atomic replace, rename, remove, directory sync, exclusive lock). `OsFs` wraps `std::fs`
  (lock via `File::try_lock`, released by the OS if the holder dies); `SimFs` models process
  crash vs power loss, torn writes on disk-full, and failed flushes that drop unflushed bytes.
  One conformance scenario runs against both.
- P0 Bedrock: workspace, pinned toolchain (1.98.1), lint policy (clippy pedantic + restriction
  set, architecture bans in `clippy.toml`), supply-chain policy (`deny.toml`, cargo-vet with
  imported audit sets).
- `uaos-contracts`: typed UUIDv7 identifiers with entity prefixes; canonical decimal-string
  64-bit wire integers; integer nano-USD money; RFC 3339 UTC time; algorithm-tagged digests
  (`sha256:`, `hmac-sha256:`); the Operation lifecycle state machine (non-compensable effects can
  never be reported as compensated; `Indeterminate` only via crash recovery); the unified error
  registry; bounded event envelope.
- Contract schemas: `uaos.event/1`, `uaos.error/1`, `uaos.budget_tx/1` (draft until RC-1),
  `uaos.operation/1`.
- `uaos-platform`: `Clock`, `Rng` and `IdSource` with real and deterministic-simulation
  implementations.
- `xtask`: `ci`, `arch-check`, `schemas`, `schema-check` (drift and breaking-change detection),
  `headers`, `gates`, `decisions`, `dco`, `docs-sync`, and `negative` (gate self-test).
- Governance: LICENSE (Apache-2.0), NOTICE, README, CONTRIBUTING, SECURITY, CODE_OF_CONDUCT
  (Contributor Covenant 2.1), GOVERNANCE, RELEASING, ADR-0001–0005, threat model v0, privacy
  data flow v0, vision traceability matrix.

### Changed

- README and roadmap describe the real state. The phase is P3. Scoped credentials exist. The
  numbers are current: corpus v2 and policy p99 688 µs. The ledger claim is worded as the
  WP2.2 review required: a refusal before recording, and a randomized simulation against a
  reference model.
- The nightly mutation lane also covers `uaos-identity`.
- `uaos-policy` decisions slice by exact resource within an action, and grants are indexed. The
  bench measures three mixes:
  - 1,000 mixed policies: p99 688 µs;
  - 1,000 policies on one action: p99 514 µs, down from 1.7 ms;
  - 10,000 grants: p99 226 µs, down from 19 ms.
- `docs/claims.md`: the authorization, ledger and redaction rows now state exactly what their
  gates prove, as narrowed by the retroactive reviews.

- `dco` gate: merge commits whose combined diff is empty (GitHub's "Update branch", conflict-free
  `git merge`) add no content and are exempt. A merge that resolves a conflict with new content
  still needs a sign-off. This is proven by the new negative case `dco-unsigned-content-merge`.
  The rule was missing; that is why PR #10 failed on an "Update branch" commit.
- CI: `dco` and `docs-sync` now run on pushes to `main` and on merge queues as well as on pull
  requests. Before this, a direct push skipped both (plan v2 PD-17). A missing base commit fails
  the job instead of guessing a range.

- Phase-debt records sweep (plan v2 PD-03, -04, -07, -08, -09, -15, -23):
  - **ADR-0003** now records the measured Windows spike numbers. It states that the Linux, macOS
    and production-journal numbers are owed (PD-01). The spike report moved to
    `docs/adr/appendix/`.
  - **ADR-0002** is amended: the `kernel-tokens` gate activates in P3, not P2, because the tokens
    bind policy, ledger and egress, which first meet in the runtime. `gates.toml` follows.
  - **CODEOWNERS** now covers every Ring 0 crate, the build inputs (`Cargo.toml`/`.lock`,
    toolchain, `.cargo/`), the ADRs, the threat model, the privacy docs and CODEOWNERS itself.
  - **README** describes the real state (P2) and names the gate behind each claim.

