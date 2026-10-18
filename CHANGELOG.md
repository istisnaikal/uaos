# Changelog

All notable changes are recorded here. Format: [Keep a Changelog](https://keepachangelog.com/en/1.1.0/);
versions follow [Semantic Versioning](https://semver.org). Contract (schema) changes must appear
here in the same change that alters `schemas/` (docs-with-contract gate).

## [Unreleased]

### Security

- `deny.toml` takes its first advisory exceptions: RUSTSEC-2026-0370, -0371 and -0372
  (`zvariant`, `zbus_names`, `zvariant_derive` unmaintained, merged into zbus 6.0.0). They reach
  the build only through the Linux keyring store (`zbus-secret-service-keyring-store` 1.0.1 →
  `secret-service` 5.2.0 → zbus 5), which has no zbus 6 release yet. They are not
  vulnerabilities; the exceptions end when the keyring store moves to zbus 6.

- P3 Move 1, PR-1: chunk durability joins the journal's durability classes (ADR-0018), and a
  latent chunk race (S-6) in P1 code is fixed.
  - **Race (S-6).** Two concurrent puts of the same content could tear one shared temporary file
    or pair one writer's data file with the other's key, which reads back as `Corrupt`. It was
    harmless while single-threaded, but parallel subagents sharing `system` and `tools` content
    would make it the common case.
  - **The fix:**
    - every atomic write now uses its own temporary;
    - every operation on a chunk (put, flush, recovery, shred) holds that chunk's slot;
    - a shred cannot destroy the key a concurrent put is wrapping under;
    - a chunk left by an earlier process is read back and rewritten, flushed, before it is
      trusted, and a rewrite keeps the chunk's data key.
  - **Proof:** deterministic interleaving tests and seeded violations.
- Payload before record (I-02). A journal opened with its chunk store refuses a record whose
  `payload_ref` is not stored (`JournalError::PayloadNotStored`, new code
  `JOURNAL_PAYLOAD_NOT_STORED`).
- Payload losses are journaled before the records they affect become durable, in simulation
  (`docs/claims.md` gives the exact conditions).
  - **On open:** the journal reads back the payloads of every record after its durable point
    (the whole journal if the marker is missing), rewrites the readable ones, and journals each
    unreadable one as `chunk.lost` before the durable point moves. Unreadable chunks are
    quarantined, never deleted. A keychain that lost the pocket's keys fails closed instead.
  - **After a failed payload flush,** anywhere in the store: the store refuses work and the
    writer stops until `recover` has rewritten what it can read and journaled the rest. Nothing
    is flushed in place a second time, because after a writeback error a second flush can report
    success without writing anything.
  - **A journal that coordinates a store cannot be opened without it.**
  - **Open no longer flushes the previous run's journal segment again.** It moves the records
    after the durable point to a fresh segment, and one flush covers them together with any loss
    records open appends for them. This also closes a latent P1 gap: a failed flush during open
    could drop records the OS still held.
  - **A shred the journal recorded but a crash interrupted is completed when the journal
    opens**; before, the store's startup re-wrapped the leftover key and the content stayed
    readable (pre-existing).
  - **`Journal::shred`** records a shred, flushes the record, rotates the KEK and removes the
    chunk while no other record can be appended, and returns a `PendingRewrap` that re-wraps the
    pocket's other keys once the writer is free (or when dropped); a store a journal coordinates
    refuses a direct shred. The store marks the chunk before the record is appended and neither
    vouches for it nor serves it until a put of the content succeeds or the shred completes; at
    most 4,096 failed shreds stay marked (`ChunkError::ShredBacklog` beyond).
  - **A journal flush is not acknowledged across a poisoning** of the store while it ran, and the
    first open with a store invalidates a plain journal's marker before it records the store.
  - **A KEK rotation writes every readable key file again before destroying old versions**, so a
    re-wrap whose directory flush failed cannot leave a key file only a destroyed KEK opens
    (found by the extended crash schedules; it predates this PR).
  - **Every journal keeps a durable-point marker**, so restarts copy only the records after it;
    a `PAYLOADS` flag file now records that a journal coordinates a store.
  - **Review:** `docs/reviews/WP3.A1-chunk-durability.md` (4 High, 7 Medium, 7 Low, four defects
    found by the extended property test after the fixes, a second round: 1 High, 1 Medium,
    6 Low, a third: 1 High, 3 Medium, 5 Low, a fourth: 2 Medium, 4 Low, a fifth: 2 Medium,
    3 Low, a sixth: 4 Low, a seventh: 1 Medium, 2 Low, an eighth: 1 Low, a ninth: 4 Low, a
    tenth: 4 Low, an eleventh: 1 High, 3 Low, a twelfth: 3 Low, a thirteenth: 4 Low, and a
    fourteenth: 1 Medium, 4 Low).
    New codes `STORE_PAYLOAD_LOST` (lost content reads back as lost, `ChunkError::Lost`, through
    a marker every loss leaves in the pocket's quarantine and a shred removes) and
    `STORE_PAYLOAD_FLUSH_FAILED`. ADR-0003 §3 and §5 carry amendment
    notes pointing to ADR-0018.

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

- P3 Move 1, PR-2 (WP3.A2): `uaos-json`, the one structural tokenizer (ADR-0014). Nothing calls
  it yet; `uaos-redact` and its final scan are untouched.
  - **The crate:**
    - one forward pass over a complete buffered body, with no recursion, into a flat tape of
      24-byte nodes that `Tape::verify` re-checks;
    - lazy, allocation-free reads;
    - one strict string decoder, with an offset map;
    - the kernel's one encoder, whose bytes equal `serde_json`'s;
    - integer readers with range checks;
    - errors and `Debug` output carry no input bytes;
    - one dependency, `memchr`.
  - **Tests:** grammar (each error's kind and offset), properties, a differential against
    `serde_json` read strictly, property fuzzing, and no payload in `Debug`. A one-off
    20,000-document differential found 0 disagreements; 13 numbers outside the f64 range were
    accepted by the tape only, which is the known divergence.
  - **Seeded violations:** `arch-json-io-dependency` and eight `json-*` cases, one per
    fail-closed rule and one for the oracle.
  - **Measured** on the reference machine, recorded in the contract's §10:
    - parse p95 is 2.187 ms at 1.70 MB, or 0.78 GB/s. That is **over the 2 ms stage budget by
      about 9%**. The duplicate-key check costs about 0.3 ms of it, and the fix is owed in this
      stage before Train B;
    - the tape takes 384 KiB for that body;
    - every adversarial input is bounded.
  - **First coverage-guided run:** 10,872,985 runs of `parse` and 79,948,806 of `decode` in
    30 minutes each, with 0 crashes.
  - **Contract first:** `docs/adr/appendix/0014-uaos-json-tape.md` covers:
    - a one-pass, fail-closed RFC 8259 grammar (a byte-order mark refused, duplicate keys
      compared after decoding, numbers grammar-only);
    - limits of 32 MiB, depth 128 and 2^20 nodes;
    - a 24-byte node with eight structural invariants;
    - memory bounds (at most 24 MiB of tape at the defaults; about 384 KiB for a 1.7 MB
      transcript);
    - its proof obligations.
  - **`arch.toml`:** declares the crate with no workspace edge and bans async, network, TLS and
    storage crates and `serde_json`, which is its differential oracle and a dev-dependency only.
    `uaos-redact`, `uaos-module-api` and `uaos-runtime` may depend on it.
  - **D-30 (coverage-guided fuzzing)** is in the decision register.
  - **Fuzzing (D-30):**
    - `fuzz/` is a cargo-fuzz workspace of its own, excluded from the UAOS workspace, never
      shipped, with its own lockfile. It has two targets: `parse` (arbitrary bytes; every tape
      must pass `Tape::verify` and decode everywhere) and `decode` (the decoder and the tape
      agree, the offset map keeps its rules, encoding round-trips).
    - The nightly lane runs each target for 30 minutes on Linux under a pinned nightly
      toolchain, with generated seeds; the tape's heap bound is asserted on every input, and
      single allocations over 64 MB fail the run. It first checks the fuzz workspace's supply
      chain against `deny.toml`.
    - `deny.toml` allows NCSA for `libfuzzer-sys` alone, which vendors LLVM's libFuzzer.
      Without the exception that workspace fails its licence check; the UAOS workspace never
      contains the crate.
    - The nightly lane also runs the tape's property fuzzing at 1,000,000 cases per property
      and its differential at 100,000, and adds `uaos-json` to mutation testing.
    - `.github/CODEOWNERS` covers `/fuzz/`.
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
    - Only GET, HEAD, POST, PUT, PATCH, DELETE and OPTIONS are sent. TRACE, which would echo
      the credential back to the caller, CONNECT and extension methods are refused before
      contact.
    - A `101 Switching Protocols` answer, and any `transfer-encoding` but one field whose
      value is `chunked`, are errors. A `content-length` sent beside `transfer-encoding` is
      dropped, a `204` keeps none, and otherwise it is forwarded as one value when all its
      values are the same digits (hyper checks it only where it reads a body).
    - Hop-by-hop headers, `host` and `content-length` are stripped and no UAOS header is added.
    - A request carrying one of the listed credential-bearing headers (`authorization`,
      `cookie`, provider key headers and others) is refused, before anything is stripped.
    - The provider credential is inserted last; its value is never printed.
    - Errors say whether the request may have reached the provider: `Unreachable` and
      `Timeout` mean nothing was sent (retryable), also when the connection fails while hyper
      sets it up; new codes `EGRESS_INTERRUPTED` (cut off or unanswered after the request was
      sent) and `EGRESS_UNUSABLE_RESPONSE` (answered in a form the door does not pass on, or
      could not parse) are not retryable and say the provider may have billed it. A response
      timeout that runs out before the request reached a connection is `Timeout`. `Door::new`
      refuses a response timeout that does not exceed the connect phase, and an idle timeout
      over a day.
    - One send per Operation; a request bound to another Operation is refused.
    - A circuit breaker per upstream counts transport failures and lets one probe through
      after its cooldown; a probe whose caller gives up lets the next attempt probe, and a
      probe that settles after the circuit moved on changes nothing unless it answered. A
      transport failure counts only if its attempt was admitted since the circuit last closed
      after an outage. While a probe is in flight, `retry_after` is a 1 s hint.
    - IPv6 forms that embed a local IPv4 address are never treated as local, and the IPv6
      cloud metadata endpoints are refused.
  - **Connection tasks** run on an executor the runtime provides.
  - **Error codes** `UAOS-EGRESS-0001` to `0007`: blocked, unreachable, timeout, circuit open,
    refused, interrupted, unusable response.
- Reachability rules for the door (ADR-0010).
  - **`clippy.toml`.** Outbound connects (std and tokio, `TcpSocket` included, Unix streams
    and datagrams, Windows named-pipe clients), name resolution (`lookup_host`,
    `to_socket_addrs`, hyper-util's `GaiResolver`), UDP and building another HTTP client are
    banned outside the door; listening (`TcpListener::bind`, `TcpSocket::listen`, Unix
    listeners, Windows pipe servers) outside the API crate; every std file-system, `Path`,
    link and ownership call outside `uaos-platform` (a Windows UNC path reaches the network),
    and every `getrandom` entry point; `OsFs` refuses UNC and device paths in every prefix
    spelling (the NT `\??\` one included), any path starting with two separators, and a bare
    volume (`\\?\C:`); task and
    thread spawning,
    and the `JoinSet`, `LocalSet` and hyper-util `TokioExecutor` types, outside the runtime;
    `Door::new` outside its one owner.
  - **`cargo xtask clippy`** is the clippy gate: clippy with warnings denied, in plain text,
    failing also on a `clippy.toml` ban whose path resolves to nothing (clippy itself only
    warns). **Ban canaries** (`crates/uaos-egress/tests/bans.rs`) call every banned item under
    `#[expect]` on the systems where it exists, so a ban that stops firing fails clippy there.
    The negative runner skips a case written for another operating system without counting it
    as skipped. **`cargo xtask allow-audit`** also fails on a ban without a canary and on lint
    switches outside attributes: a nested `clippy.toml`, a member's own `[lints]`, a workspace
    lint table not denying a guarded lint, Cargo configuration naming `CLIPPY_CONF_DIR` or lint
    flags; it reads every mention of a guarded lint in code (macro-built attributes, lint
    groups, old names), refuses `#[path]` and `include!` outside owners, allows only `[alias]`
    in Cargo configuration (names in any case), refuses build scripts (every one `cargo
    metadata` lists) that name one of clippy's variables or keep code in another file, and path
    build-dependencies, reads `.rs` files in any case, and checks each canary's shape: its item
    spelled by the item's own path, and no other ban of the same lint spelled by its full path in
    its function. `cargo
    xtask clippy` neutralises the
    environment of the clippy it runs (compiler flags, wrapper, clippy's arguments) and pins
    clippy's configuration to the workspace root.
  - **`arch.toml`.** The bin's allow list is now explicit and leaves out the door; the bin
    reaches it only through the runtime. `uaos-module-api` and every Ring 1 crate are banned,
    transitively, from network, TLS and async-I/O crates (new `[ring1] ban`, enforced by
    `cargo xtask arch-check`).
  - **`deny.toml`** bans `ring`.
  - **Seeded violations (57):** `egress-dials-private-range`, `egress-numeric-host`,
    `egress-private-reaches-link-local`, `egress-plaintext-resolved`,
    `egress-breaker-admits-after-cooldown`, `egress-probe-stuck-on-cancel`,
    `egress-embedded-local`, `egress-sends-trace`, `egress-forwards-switching-protocols`,
    `egress-forwards-contradicting-length`, `egress-forwards-unknown-transfer-coding`,
    `egress-forwards-repeated-length`, `egress-forwards-bodiless-length`,
    `egress-delivered-reported-unsent`, `egress-timeout-reported-unsent`,
    `egress-unsent-reported-delivered`, `egress-unassigned-timeout-reported-delivered`,
    `egress-canceled-reported-delivered`, `egress-ctor-outside-root`,
    `net-dns-outside-egress`,
    `net-resolver-outside-egress`, `net-connect-outside-egress`, `net-udp-outside-egress`,
    `net-listen-outside-api`, `net-socket-listen-outside-api`, `spawn-outside-supervisor`,
    `spawn-through-tokio-executor`, `clippy-ban-path-unresolved`, `clippy-ban-silenced`,
    `clippy-config-nested`, `lints-not-inherited`, `cargo-config-clippy-override`,
    `clippy-ban-without-canary`, `allow-audit-lint-group`, `allow-audit-macro-attribute`,
    `allow-audit-path-module`, `allow-audit-nested-target`, `workspace-lints-group-allowed`,
    `clippy-config-case`, `cargo-config-not-alias`, `build-script-clippy-env`,
    `build-script-declared-path`, `canary-malformed`, `canary-calls-another-item`,
    `canary-copied-from-sibling`, `canary-setup-calls-another-ban`, `build-script-module`,
    `build-dependency-path`, `build-script-include-in-owner`,
    `arch-ring1-depends-on-hyper`; on Unix only `net-unix-connect-outside-egress`,
    `net-unix-connect-addr-outside-egress`, `net-tokio-unix-connect-outside-egress`,
    `net-unix-socket-connect-outside-egress`; on Windows only (not run in CI)
    `net-named-pipe-outside-egress`, `osfs-doubled-separator-unc` and `osfs-bare-volume`.
  - **Review:** `docs/reviews/WP3.A5-egress.md`, eighteen rounds, all resolved: 2 High,
    4 Medium, 9 Low; then 1 High, 2 Medium, 7 Low; then 1 Medium, 5 Low; then 1 Medium, 5 Low;
    then 2 Medium, 4 Low; then 2 Medium, 2 Low; then 1 High, 2 Medium, 3 Low; then 1 Medium,
    7 Low; then 4 Low; then 2 Low; then 3 Low; then 2 Low; then 1 Medium, 2 Low; then 2 Low;
    then 2 Low; then 1 Medium; then 5 Low; then 4 Low. Two fixes rest on ADR-0013 Amendment 1,
    accepted by
    the
    maintainer on 2026-10-16.
- Dependencies for the ADR-0013 stack: tokio, hyper 1, hyper-util, http, rustls 0.23
  (aws-lc-rs only), tokio-rustls, rustls-native-certs, and rcgen for tests only.
  - 48 cargo-vet exemptions, each with a written reason (the unnoted baseline is unchanged);
    21 of them are lockfile-only crates that compile for no target.
  - cargo-vet 0.10 ignores the newer Bytecode Alliance audits for this stack, so they are not
    imported yet.

- ADR-0018 balanced chunk durability (P3 Move 1, PR-1).
  - `ChunkStore::open_with(…, ChunkDurability::Balanced)`: puts hand chunks to the OS, unflushed.
  - `Journal::open_with_payloads`: every journal flush makes the pending chunks durable before
    the segment, and records the durable point in `journal/FLUSHED`.
  - `Journal::lost_payloads()`.
  - Kernel event type `chunk.lost`: a `chunk.lost` or `chunk.shredded` record names its chunk
    in metadata key `chunk`.
  - `Fs::write_unsynced` and `Fs::sync_file` on both filesystems.
- **Tests and harness:**
  - `uaos-state/tests/durability.rs`: flush ordering under every injected flush fault, random
    crash and power-loss schedules, rotation durability, torn-chunk rewrite and the S-6
    interleaving.
  - **Kill harness:** the writer now stores a payload before each intent, and the harness
    reads every acknowledged record's payload back.
  - **New seeded violations for `journal-durability`:** `chunk-flushed-before-sync`,
    `intent-before-chunk-write`, `chunk-put-pair-race`, `chunk-put-shared-temp`.
- `journal-ack-bench` gains `chunk-put-balanced` and `group-flush-chunks`. The reference-machine
  numbers are in `docs/adr/appendix/0018-chunk-put-2026-10-15.md`: ADR-0018's p99 ≤ 0.5 ms
  balanced-put target is **not met** on Windows (1.55 ms after the first review's fixes,
  `fc4b5a8`; not re-measured after later rounds), where file
  creation dominates. Until the state actor (WP3.3), the request whose append finds the flush
  window due pays for the flush.
- Gate `journal-durability` gains thirty-six more seeded violations, one per class found by
  the WP3.A1 review rounds (every round but the eighth, which added a property test) and the
  extended property tests (forty for ADR-0018 with the four above, forty-one in the
  gate). The nightly lane runs both chunk-durability properties at 20,000 schedules each per
  OS; merges run 64. Their oracles require, after a process crash, the payload of every
  acknowledged record no failed flush could have dropped, and a clean recovery to leave
  nothing refusing work and a journal that reads back whole; their failed appends tear the
  segment, as a full disk does, and the simulated OS writes back on its own, so a record can
  survive a power loss without its payload.
- A payload flush failure no longer replaces the writer's out-of-space or write failure, so
  `recover` always leaves a segment that may end in a torn line; before, it could return `Ok`
  and append after the torn bytes, and the journal then failed to open (WP3.A1 eleventh round,
  H1, present since the first round's fixes). A loss already waiting to be journaled is not
  queued twice.
- A chunk store that a journal coordinates refuses `recover_pending`, `take_lost` and
  `verify_and_sync` from callers (`ChunkError::LossesThroughJournal`; `take_lost` now returns a
  `Result`), and `Journal::recover` recovers a poisoned store whatever state the writer is in.
- `cargo xtask negative` refuses a seed anchor that occurs more than once in its file: the
  first match could be another site, and the case would then prove nothing.
- `uaos-state`'s `tampering_is_detected` flips the last byte of the tag instead of writing 0:
  the nonce is OS-random, so the byte was already 0 one run in 256 and the test then failed
  (a flake since P1, found while verifying the ninth WP3.A1 review).
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

- **Re-baselined on 2026-10-19.**
  - The roadmap's P3 row says what is built (the network door, chunk durability), what is in
    review (`uaos-json`), what comes next, and that no request flows through UAOS yet.
  - The RC-1 target moves from "2026-11-12 at the earliest" to an estimate from the measured
    pace: build exit in early to mid December 2026, go/no-go at least two weeks later. Gates
    decide; no threshold moved.
  - README lists `uaos-egress` as built but not yet in any request path; it was still under
    "does not exist yet".
  - Four open decisions join the register: D-31 review convergence, D-32 the chunk storage
    format before the freeze, D-33 which machine judges stage budgets, and D-34 booking the
    external audit and legal review.
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

