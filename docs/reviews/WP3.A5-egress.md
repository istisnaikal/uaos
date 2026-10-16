# Adversarial review: WP3.A5 the egress door (P3 Move 1, PR-5, ADR-0013)

**Reviewer:** a fresh-context review agent with the fixed V1 checklist (plan v2 §4.2), read-only,
probing a scratchpad export of the branch on Windows 10. **Reviewed:** `b69e23b`
(`p3/a5-egress`), 2026-10-15.
**Result:** 0 Critical · 2 High · 4 Medium · 9 Low. Both High findings were T5 paths the door's
own documentation said were closed. They blocked merge.
**Resolution:** every High and Medium finding fixed with a regression test or a seeded violation;
Low findings fixed or accepted with a reason. Two fixes change accepted decisions and are written
as ADR-0013 Amendment 1, which the maintainer accepted on 2026-10-16. A second V1 review of the
fixes found 1 High, 2 Medium and 7 Low findings, a third 1 Medium and 5 Low, a fourth
1 Medium and 5 Low, a fifth 2 Medium and 4 Low, a sixth 2 Medium and 2 Low, a seventh
1 High, 2 Medium and 3 Low, and an eighth 1 Medium and 7 Low, all resolved below. The PR stays a draft until a review comes back clean.

## Findings as reported

### High

**H1. Under the default trust, the TLS peer can make Windows fetch URLs of its choosing,
outside the door.** `Trust::Platform` used `rustls-platform-verifier`, which calls
`CertGetCertificateChain` with revocation checking and a 10 s URL-retrieval timeout. CryptoAPI
fetches the issuer, OCSP and CRL URLs named in the server's certificate while it is still
building the chain. The repro presented a leaf from an untrusted authority whose URLs pointed at a
local listener: the door reported a failed handshake, but the listener had already received
`GET /latest/meta-data/ca-issuers` from `Microsoft-CryptoAPI/10.0`. Any peer of a declared
upstream, including a DNS attacker who answers with a public address of their own, could probe
the metadata service and the LAN or leak data through name lookups, unclassified and uncounted.

**H2. A plain-HTTP "private" upstream dialled public addresses and any LAN answer.**
`validate()` checked only the flag, and the connector accepted every answer once
`allow_private` was set, of every class (metadata, `0.0.0.0`, multicast). A local model server
declared by name (`ollama.lan`) would send prompts and credentials in clear text to whoever
answered: LAN DNS spoofing, NXDOMAIN rewriting, LLMNR or mDNS poisoning. With a public answer the
request left the LAN.

### Medium

- **M1.** `arch.toml` banned `uaos-egress` from the bin transitively, so the intended wiring
  (bin → runtime → egress) failed the gate, and ADR-0010 had the bin both build the door and not
  depend on its crate.
- **M2.** The clippy bans covered five entry points. DNS through `to_socket_addrs` (std, no
  dependency at all), `TcpSocket::connect`, tokio UDP, a full hyper-util client and spawning on a
  runtime handle all passed `-D warnings`.
- **M3.** `Credential`'s derived `Debug` printed the provider key; it was marked sensitive only
  inside `send`.
- **M4.** The breaker had no half-open state: after the cooldown every concurrent attempt went
  through, and door-local refusals counted as failures.

### Low

- **L1.** The URI was built by string formatting, and the connector routed by the URI's host to
  any declared upstream. A lone `*` path consumed the Operation and was not counted as refused.
- **L2.** A caller's `content-length` truncated the body.
- **L3.** `3fff::/20` (RFC 9637) was public; the local-use NAT64 prefix was decoded with the
  wrong layout; residuals undocumented.
- **L4.** hyper-util's transparent retry contradicted "no retries".
- **L5.** The counters misreported: open circuits and URI failures not counted as refused;
  `sent` counted before connecting.
- **L6.** Resolution had no timeout of its own and the answer list was unbounded; "pool size
  limited" overclaimed.
- **L7.** Only the credential's own header was refused; a client's `authorization` (its UAOS
  sub-key), cookies and other provider key headers passed through.
- **L8.** "No ring" was true but unenforced; some vet notes were inaccurate.
- **L9.** Test and documentation gaps.

## Resolution

Tests are in `crates/uaos-egress/tests/door.rs` and the `addr` unit tests. Negatives run with
`cargo xtask negative <id>`.

| Finding | What changed | Proof |
|---|---|---|
| H1 | **ADR-0013 Amendment 1A (accepted 2026-10-16).** The default trust is `Trust::System`: the OS root store read locally when the door is built (`rustls-native-certs`), chains verified by rustls itself, so a handshake fetches nothing. `rustls-platform-verifier` and 11 crates leave the lockfile. Revocation is not checked; that residual, and Windows' on-demand roots, are written into the amendment | `the_system_trust_fetches_nothing_a_certificate_names`: a leaf naming issuer, OCSP and CRL URLs on a local listener; the handshake fails and the listener receives nothing, on every CI OS. No negative: the fetching verifier is gone from the dependency graph |
| H2 | Plain HTTP requires pinned addresses, all loopback, private or unique-local, and is never resolved. `allow_private` admits only those three ranges, pinned or resolved; link-local (metadata), unspecified, multicast and the rest stay refused. Defence in depth: the dial path refuses a public address for plain HTTP even if validation were bypassed | `plain_http_is_declared_only_toward_pinned_local_addresses`, `a_private_upstream_never_reaches_link_local_or_special_ranges`, `plain_http_reaches_a_pinned_local_server_without_resolving`; negatives `egress-private-reaches-link-local`, `egress-plaintext-resolved` **PROVEN** |
| M1 | **ADR-0013 Amendment 1B (accepted 2026-10-16).** The bin's allow list leaves `uaos-egress` out, the transitive ban is gone, and the runtime builds the door in one private module from declarations the bin passes in runtime types. That module becomes the `Door::new` owner in PR-6 | `cargo xtask arch-check` passes; `arch-bin-depends-on-egress` waits for the bin crate (M3) |
| M2 | Banned outside their owners: `ToSocketAddrs::to_socket_addrs`, `TcpSocket::connect`, tokio `UdpSocket::bind`, hyper-util `HttpConnector::new` and `build_http`, `spawn_local`, `JoinSet::spawn`, `Handle`/`Runtime` spawns, `std::thread::Builder::spawn`. The new ban found three real uses in the policy tests, now allowed at file level with a reason inside an owner path. The crate docs now say the bans cover the listed entry points | negatives `net-dns-outside-egress`, `net-connect-outside-egress`, `net-udp-outside-egress`, `spawn-outside-supervisor` **PROVEN** |
| M3 | `Credential` fields are private; `Credential::new` marks the value sensitive; `Debug` prints only the header name | `the_credential_is_never_printed` |
| M4 | A three-state breaker: closed, open until a monotonic instant, probing. After the cooldown exactly one probe goes; the rest get `CircuitOpen`. Only unreachable and timed-out attempts count; a probe that never reached the upstream lets the next attempt probe | `after_the_cooldown_exactly_one_probe_goes_through` (one connect for four concurrent sends, three refusals counted, reopened after the failed probe); negative `egress-breaker-admits-after-cooldown` **PROVEN** |
| L1 | The URI is built with `Uri::builder` from the upstream's name and port; a path must start with `/`, checked before the Operation is consumed. The authority comes only from the declaration, so the connector can only reach the request's own upstream | `a_path_without_a_leading_slash_is_refused_before_contact` |
| L2 | `content-length` is stripped; the door frames the body | `a_caller_content_length_is_dropped` |
| L3 | `3fff::/20` is Documentation; the local-use NAT64 prefix is refused whole instead of decoded; the residuals (network-specific NAT64 prefixes, cloud host endpoints on public unicast) are documented in `addr` and ADR-0013 | `addr` unit tests; property tests over IPv6 |
| L4 | `retry_canceled_requests(false)` | Configuration only; no test observes it (corrected in round 2: the single-probe test does not cover it) |
| L5 | `CircuitOpen` and every pre-contact refusal bump `refused`; `sent` is documented as "handed to the client once every check passed" | the single-probe test counts refusals |
| L6 | Resolution runs within the connect timeout; at most four addresses are tried per attempt (`MAX_ADDRESSES_TRIED`); `DoorLimits` states what the runtime bounds (concurrency, response bodies) | `a_connection_attempt_tries_a_bounded_number_of_addresses` |
| L7 | A request carrying `authorization`, `proxy-authorization`, `cookie`, `x-api-key`, `api-key`, `x-goog-api-key` or `openai-organization` is refused, whatever credential is injected | `credential_bearing_headers_from_the_caller_are_refused` |
| L8 | `deny.toml` bans `ring`. The vet notes of the 21 lockfile-only crates now say they compile for no target; the 9 exemptions for crates that left the lockfile are removed (vet-ratchet 290 → 281, notes-less baseline unchanged) | `cargo deny check bans`, `cargo vet --locked` |
| L9 | Tests added for the oversized body, a wrong name from the trusted authority, the breaker, plain HTTP toward public addresses and IPv6 classification. ADR-0013's "before any byte" now reads "no request received". The T5 row of the threat model and the privacy data flow (both v1, from #24) are updated after the rebase onto it: the door's controls and residuals in T5, and certificate checks now listed as never happening | `an_oversized_body_and_a_wrong_name_are_refused`, the `addr` property tests |

## Maintainer decision

- **ADR-0013 Amendment 1** (A: trust and revocation; B: where the door is built) was accepted by
  the maintainer on 2026-10-16. Merging still waits for a clean second review and for #24.

## Second review (2026-10-16)

**Reviewed:** `ec45bb4..586114d` (rebased onto `e5b0ec8`) by a fresh-context agent with the same
checklist, in a scratch export. **Result:** 1 High · 2 Medium · 7 Low. The round-1 fixes for
H1, H2, M1 and M3 held; the M4 fix introduced the High.

| Finding | What it was | What changed | Proof |
|---|---|---|---|
| H1 | A probe whose caller dropped the future (client disconnect, deadline, `select!`) left the circuit `Probing` forever: every later send was refused, with no further attempt | Every admitted attempt is an `Admitted` guard, settled exactly once; on drop it is settled as not attempted, so the next attempt probes. The breaker is its own type (`Breakers`) with a unit-tested state machine | `a_cancelled_probe_lets_the_next_attempt_probe`, `the_breaker_lets_one_probe_through_and_settles_it`; negative `egress-probe-stuck-on-cancel` **PROVEN** |
| M1 | IPv6 forms that only embed a local IPv4 address (6to4, NAT64, IPv4-compatible) counted as the local network, so plain HTTP pinned at them passed validation while its traffic left the machine | "Local" is decided on the address (`addr::is_local_network`): embedding forms are never local, IPv4-mapped forms follow their IPv4 address; `classify` still reports the inner range | `plaintext_is_refused_toward_embedded_forms_and_ipv6_metadata`, the property test `embedding_forms_are_never_local`; negative `egress-embedded-local` **PROVEN** |
| M2 | `TcpListener::bind` (std and tokio) was not banned; `bind` with a name resolves it, a DNS leak with no dependency, and it opens a network handle | Both are banned, owner the API crate | negative `net-listen-outside-api` **PROVEN** |
| L1 | Other entry points were unbanned (`HttpConnector::new_with_resolver`, `std::thread::scope`, `JoinSet::{spawn_blocking, spawn_on, spawn_local}`, `LocalSet::spawn_local`, Unix-socket connects); allow-audit is per lint | All banned (Unix paths marked valid only where they exist). The ledger's contention test now allows `thread::scope` with a reason. The per-lint granularity is written into `clippy.toml` and ADR-0013 | workspace clippy `-D warnings` |
| L2 | The IPv6 metadata endpoints `fd00:ec2::254` and `fd20:ce::254` sit in `fc00::/7` and were admitted as unique-local | Refused as `CloudMetadata` and never local | `cloud_metadata_on_ipv6_is_refused_and_never_local` |
| L3 | The system root store can be replaced by `SSL_CERT_FILE`/`SSL_CERT_DIR`, load errors were dropped, Windows' Disallowed store is not consulted, and an empty `Roots` was accepted | An empty `Roots` is refused at build time. The rest is written into ADR-0013 Amendment 1A as residuals, with `uaos doctor` (M3) to show the override | `an_upstream_with_no_root_to_trust_is_refused` |
| L4 | `lookup_host` runs `getaddrinfo` on tokio's blocking pool, outside the supervisor | **Accepted, stated:** written into ADR-0013 as the known exception; moving it onto the supervisor's pool is PR-6 work | — |
| L5 | Five fixes were pinned by no test (the dial path's own plain-HTTP refusal, two credential headers, a not-attempted probe, the outcome mapping, the retry switch) | Unit tests for the dial path (`the_dial_path_refuses_public_addresses_over_plaintext`), every listed credential header, the outcome mapping and the breaker states. **Accepted:** the retry switch has no observable test; the round-1 proof text is corrected | `credential_bearing_headers_from_the_caller_are_refused` (all nine), `only_transport_failures_count_against_an_upstream` |
| L6 | The credential list misses other headers and the query string | `x-amz-security-token` and `ocp-apim-subscription-key` added; the check runs before stripping, so `proxy-authorization` is refused, not dropped. The claim now says "the listed headers"; query-string credentials are a stated residual | the credential-header test |
| L7 | cargo-vet notes still described the platform verifier | Rewritten | `cargo vet --locked` |

## Third review (2026-10-16)

**Reviewed:** `b15abff` (on `555494b`) by a fresh-context agent with the same checklist, in a
scratch export. **Result:** 0 High · 1 Medium · 5 Low. The round-2 fixes held: no path reached
an address the door should refuse, and no path let a caller's credential reach a provider.

| Finding | What it was | What changed | Proof |
|---|---|---|---|
| M1 | T5 said resolve and listen entry points were banned; hyper-util's `GaiResolver::new` (a lookup on the blocking pool, a DNS exfiltration channel) and `TcpSocket::listen` passed clippy in any crate that may depend on hyper-util | Both banned (owners: the door, the API crate). T5 now names "the entry points listed in `clippy.toml`" and states the residual: entry points not on the lists are kept out by `arch.toml` and supply-chain review | negatives `net-resolver-outside-egress`, `net-socket-listen-outside-api` **PROVEN** |
| L1 | A probe's late settlement overwrote newer state: after another attempt closed the circuit, a cancelled probe reopened it as probe-only, and with two probes in flight a third could be admitted | Each probe carries a generation (`Breaker::Probing { generation }`, `Admitted` holds it). A settlement whose generation is no longer in flight changes nothing unless it answered | `a_stale_probe_cannot_reopen_a_closed_circuit`, `a_late_probe_settlement_does_not_admit_a_second_probe` (the reviewer's repros A and B); negative `egress-breaker-admits-after-cooldown` re-anchored, **PROVEN** |
| L2 | While a probe was in flight, `retry_after` was the full cooldown, whatever the probe did | It is `PROBE_RECHECK` (1 s, capped by the cooldown) and documented as a hint; while open it is still the time left | `the_breaker_lets_one_probe_through_and_settles_it` |
| L3 | The spawn and IPC bans were narrower than ADR-0013 said: `JoinSet::{spawn_local_on, spawn_blocking_on}`, spawning through `collect` and `extend`, `UnixSocket::connect`, std `UnixStream::connect_addr` and Windows named pipes passed; no negative showed the Unix-only bans resolve | Those methods banned; the `JoinSet` and `LocalSet` types banned outright (`disallowed-types`), since no method ban can name `collect` or `extend`. A Unix-only negative seeds `std::os::unix::net::UnixStream::connect`; it is skipped on other systems and runs in the CI negative job, which is on Linux | workspace clippy `-D warnings`; negative `net-unix-connect-outside-egress` (Linux CI) |
| L4 | NAT64 well-known answers of public addresses were refused, so IPv4-only providers were unreachable from IPv6-only networks with DNS64; fake-IP proxies in `198.18.0.0/15` were refused unstated | A well-known NAT64 address gets its IPv4 address's verdict (RFC 6052 §3.1 forbids non-global inner addresses there); private inners and the local-use prefix stay refused. Fake-IP proxies stay refused and are written into ADR-0013 and T5 with the error a user sees | `nat64_well_known_follows_its_ipv4_address` (property), the reviewer's repro D in `ipv6_forms_that_embed_a_private_ipv4_address_are_refused` |
| L5 | The CHANGELOG listed 11 of 14 negatives and only the first review; ADR-0013 said `uaos-module-api` was banned from rustls while `arch.toml` did not list it | `rustls` and `tokio-rustls` added to the module-api ban; the CHANGELOG lists all 17 negatives and the three rounds | `cargo xtask arch-check`; review of the text |

The reviewer could not build for Linux; the Unix paths in L3 were read from tokio and std. The
new Unix-only negative turns that reading into a check on the Linux runner.

## Fourth review (2026-10-16)

**Reviewed:** `b4fbfc2` (on `555494b`) by a fresh-context agent with the same checklist, in a
scratch export. **Result:** 0 High · 1 Medium · 5 Low. The round-3 fixes held: no interleaving
left the breaker stuck, no path reached an address the door should refuse, and every round-3 ban
that resolves on Windows fired.

| Finding | What it was | What changed | Proof |
|---|---|---|---|
| M1 | A `clippy.toml` path that resolves to nothing is only a warning that `-D warnings` does not make fatal, so a typo or an item moving upstream would switch a ban off with CI green; the `allow-invalid` bans added in round 3 had no negative, and the docs said the one Unix negative proved them all | The gate runs as `cargo xtask clippy`, which fails on clippy's unresolved-path warning (CI's clippy job, `xtask ci` and `xtask quick`). Each `allow-invalid` ban has a negative on the system where it exists; the runner reports a case for another system as "not here" instead of skipped. The named-pipe negative runs only when the negatives run on Windows, not in CI, and the docs say so | negative `clippy-ban-path-unresolved` **PROVEN**; `net-named-pipe-outside-egress` **PROVEN** on Windows; `net-unix-connect-addr-outside-egress`, `net-tokio-unix-connect-outside-egress`, `net-unix-socket-connect-outside-egress` run in the Linux CI job |
| L1 | hyper-util's `TokioExecutor` spawns with `tokio::spawn` and was on no list, so any crate with hyper-util could spawn outside the supervisor | `hyper_util::rt::TokioExecutor` is a disallowed type (owner: the runtime); test harnesses own `disallowed_types` like `disallowed_methods` | negative `spawn-through-tokio-executor` **PROVEN** |
| L2 | Attempts sent during an outage that failed after a probe had closed the circuit reopened it for another cooldown | Every admission carries a `Ticket`: an ordinary attempt in the circuit's current epoch, or a probe's generation. Closing after an outage begins a new epoch; a transport failure counts only from the current epoch. The counter wraps instead of saturating | `failures_sent_during_an_outage_do_not_reopen_the_circuit_a_probe_closed` (the reviewer's repro, plus failures in the new epoch still opening it) |
| L3 | Half of round 3's stale-probe rule (a stale probe's transport failure) was pinned by no test | A test for it | `a_stale_probe_failure_cannot_reopen_a_closed_circuit` |
| L4 | The property "nothing outside 2000::/3 is public" became false with round 3's NAT64 change and passed only because random draws never hit `64:ff9b::/96` | The property excludes well-known NAT64 addresses, which have their own property and deterministic cases; ADR-0013 is corrected | `nothing_outside_global_unicast_is_public`, `nat64_well_known_follows_its_ipv4_address` |
| L5 | The data-flow document said the zero-egress capture confirmed no certificate fetches, though that capture is owed; this record's status line was stale | The data flow cites the test that proves it today and marks I-14 as owed; the status line is current | review of the text |

## Fifth review (2026-10-16)

**Reviewed:** `959a4e0` (on `555494b`) by a fresh-context agent with the same checklist, in a
scratch export. **Result:** 0 High · 2 Medium · 4 Low. Every arm of the breaker was walked with
no stuck state, no second probe and no stale evidence counted.

| Finding | What it was | What changed | Proof |
|---|---|---|---|
| M1 | `cargo xtask clippy` missed unresolved bans whenever cargo coloured its output, and CI sets `CARGO_TERM_COLOR: always`: the coloured header never starts with `warning:`, so the gate passed on the seeded typo and the CI negative would have reported it broken | The gate asks cargo for plain text (`--color never`) and strips colour codes anyway; a note with no warning above it fails the gate | `a_coloured_unresolved_ban_is_found` (the reviewer's captured output), `a_note_without_its_warning_fails_closed`; negative `clippy-ban-path-unresolved` **PROVEN** with `CARGO_TERM_COLOR=always`, as in CI |
| M2 | Local-IPC and listen entry points were on no list: tokio's `UnixStream::connect_addr`, std's and tokio's Unix datagram sockets (std's need no dependency, so any crate could use them), Unix listeners and Windows pipe servers | All banned: the connects and datagrams outside the door, the listeners outside the API crate; T5 and the CHANGELOG corrected | the canaries below, on each system where the items exist |
| L1 | Two properties the epoch fix rests on were pinned by no test: a close by a late ordinary answer must begin a new epoch, and an answer while closed must keep it | Two tests | `a_close_by_a_late_answer_begins_a_new_epoch`, `failures_after_an_answer_in_the_same_epoch_still_count` |
| L2 | "The gate fails if a listed path resolves to nothing" claimed too much: a first segment naming no crate draws no warning, and `allow-invalid` entries are silent everywhere | Every ban has a canary in `crates/uaos-egress/tests/bans.rs` (and `uaos-platform`'s for `getrandom`): a call under `#[expect]`, compiled where the item exists, so a ban that stops firing fails clippy in the CI clippy job on all three systems; a test fails if a ban has no canary. On Windows every canary that applies is fulfilled; the Unix ones are proven by the Linux and macOS clippy jobs | negative `clippy-ban-silenced` **PROVEN** (a removed ban fails clippy through its canary); `every_ban_has_a_canary` |
| L3 | `crates/*/tests/` owning `clippy::disallowed_types` let every crate's tests use `HashMap`, including seed-reproducible simulations | The owner is `crates/uaos-egress/tests/` only | `cargo xtask allow-audit` |
| L4 | `CONTRIBUTING.md` named raw `cargo clippy` as the lint gate | It names `cargo xtask clippy` | review of the text |

## Sixth review (2026-10-16)

**Reviewed:** `7986f52` (on `555494b`) by a fresh-context agent with the same checklist, in a
scratch export. **Result:** 0 High · 2 Medium · 2 Low. Round five's changes held: the coloured
output is handled, each canary holds one banned call, all 22 Unix canaries were fulfilled for
Linux, and every count matched.

| Finding | What it was | What changed | Proof |
|---|---|---|---|
| M1 | std file-system calls not on the list (`fs::metadata`, `read_dir`, `copy`, `Path::exists` and others) reach the network on Windows through a UNC path: the reviewer's probe opened an SMB session to `127.0.0.1:445` from a crate banned from every network crate | Every std file-system and `Path` call that reads, writes or queries the file system is banned outside `uaos-platform`, each with a canary. **Residual, stated:** the platform's `Fs` does not refuse a UNC or device path, so a data directory on a network share would work; refusing it belongs to the configuration the bin reads (M3). ADR-0013 and T5 say so | the canaries (clippy on Windows); `cargo xtask allow-audit` (every ban has one) |
| M2 | A crate-local `clippy.toml` replaces the root's bans for that crate, and a member's own `[lints]` replaces the workspace's; every gate stayed green | `cargo xtask allow-audit` fails on a `clippy.toml` below the root, a member whose `[lints]` is not exactly `workspace = true`, a workspace lint table that does not deny `disallowed_methods`, `disallowed_types` or `unsafe_code`, and Cargo configuration naming `CLIPPY_CONF_DIR` or lint flags | negatives `clippy-config-nested`, `lints-not-inherited`, `cargo-config-clippy-override` **PROVEN** |
| L1 | tokio's Unix datagrams from `pair()` (`try_send_to`, `poll_send_to`, `from_std`) and FIFOs (`unix::pipe::OpenOptions`) were unbanned | Banned, with Unix canaries, cross-checked for Linux | the cross-check: all 28 Unix canaries fulfilled |
| L2 | The canary completeness test matched `path = "` text, so a compact layout or a second entry on a line could add a ban without a canary | `cargo xtask allow-audit` reads `clippy.toml` as TOML (strings or tables, any spacing) and fails on a ban without a `// canary:` marker; the test in `bans.rs` is gone | `every_ban_layout_needs_a_canary`; negative `clippy-ban-without-canary` **PROVEN** (a compact entry) |

## Seventh review (2026-10-16)

**Reviewed:** `b95205f` (on `555494b`) by a fresh-context agent with the same checklist, in a
scratch export. **Result:** 1 High · 2 Medium · 3 Low. The reviewer's session was cut short;
everything reported came from gate runs that had finished or from reading code.

| Finding | What it was | What changed | Proof |
|---|---|---|---|
| H1 | `allow-audit` read only attributes naming a guarded lint by its current name: `#[allow(clippy::style)]` or `clippy::all`, the old name `disallowed_method`, an attribute a macro builds from its arguments, a `#[path]` module or `include!` of a file under an owner path, and a nested folder named `target` all switched the bans off unseen. The scanner predates the PR, but round six cited it | Every mention of a guarded lint, its old name or a group holding it, anywhere in code, counts (`deny` and `forbid` excepted); `#[path]` and `include!` outside the owners fail; only the root's `target`, `.git` and `node_modules` are skipped | negatives `allow-audit-lint-group`, `allow-audit-macro-attribute`, `allow-audit-path-module`, `allow-audit-nested-target` **PROVEN**; unit tests for the scanner |
| M1 | The configuration checks had gaps: a group allowed in the workspace lint table, `CLIPPY_ARGS` or `rustflags` in Cargo configuration, a `Clippy.toml` (read on Windows and macOS, never compared there by the Linux job), compiler-flag variables in CI | Groups holding a guarded lint must not be allowed in the workspace table; Cargo configuration may hold only `[alias]`, names in any case; `clippy.toml` names match in any case; CI workflows may not set flag, wrapper or clippy variables; `cargo xtask clippy` refuses such an environment; members come from `cargo metadata` | negatives `workspace-lints-group-allowed`, `cargo-config-not-alias`, `clippy-config-case`, `workflow-overriding-env` **PROVEN**; `an_overriding_environment_is_refused` |
| M2 | Link and ownership calls (`soft_link`, Windows `symlink_file`/`symlink_dir`, Unix `symlink`, `chown`, `lchown`, `chroot`) were unbanned, and any crate could build `OsFs` and read a UNC path | Those calls are banned with canaries; `OsFs` refuses UNC and device paths before any call. The residual is restated: rusqlite opens the SQLite file by path outside `OsFs`, and macOS automount paths look local | `network_and_device_paths_are_refused` (Windows); the canaries, cross-checked for Linux |
| L1 | A `// canary:` comment anywhere satisfied the completeness check | A canary must be the marker at the top of a function whose only `#[expect]` names a disallowed lint, with the banned item within three lines, under `cfg(unix)`, `cfg(windows)` or none | `a_canary_must_be_well_formed`; negative `canary-malformed` **PROVEN** |
| L2 | The round-six checks were partly unpinned, and members were found by a path pattern | The negatives above; members from `cargo metadata` | as above |
| L3 | `getrandom`'s `fill_uninit`, `u32`, `u64` and `SysRng` were unbanned | Banned, with canaries in `uaos-platform`'s tests | `cargo xtask clippy` |

**Stated plainly, in ADR-0013:** these gates catch drift, mistakes and careless overrides and make
exceptions visible in review. A contributor with write access could edit the gates themselves;
the boundary there is review, CODEOWNERS and the `main` ruleset, which is not applied yet (PD-17).

## Eighth review (2026-10-17)

**Reviewed:** `0cbbafd` (on `555494b`) by a fresh-context agent with the same checklist, in a
scratch export, judged against ADR-0013's statement that these gates stop drift and careless
overrides, not a contributor who edits the gates. **Result:** 0 High · 1 Medium · 7 Low. Round
seven's scanner, configuration checks and canaries held; only `clippy::style` and `clippy::all`
among the lint groups switch the bans off, and both are caught.

| Finding | What it was | What changed | Proof |
|---|---|---|---|
| M1 | `OsFs` refused `\\?\GLOBALROOT\...` but not the NT spelling `\??\...`, which std does not parse as a prefix yet hands to the system unchanged: `\??\GLOBALROOT\Device\Null` was read, and `\??\UNC\host\share` would reach SMB | A path starting with `\??\` (or `/??/`) is refused too. The residuals are completed: mapped drive letters, links or junctions to shares in the data directory, a UNC current directory | `network_and_device_paths_are_refused`: every `Fs` method, seven refused spellings (the NT ones included), local paths accepted |
| L1 | `cargo xtask clippy` refused variables by exact name, so lowercase `rustflags` (honoured on Windows) passed, configuration outside the repository was unchecked, and `sccache` users could not run it | The clippy it runs gets an empty `CARGO_ENCODED_RUSTFLAGS` (above every other flag source), an empty `RUSTC_WRAPPER`, and no `CLIPPY_ARGS` or `CLIPPY_CONF_DIR`, whatever their case. Configuration outside the repository is stated as the machine's | `the_child_environment_is_neutralised`; a seeded `Instant::now` with lowercase `rustflags` and `clippy_args` set to allow the lint still fails the gate (run by hand) |
| L2 | `.RS` sources compiled on Windows and macOS were skipped by `allow-audit` and `headers` | Extensions compare in any case | by reading; `.rs` handling unchanged otherwise |
| L3 | The canary shape check accepted a canary calling a different ban whose name contains its own (`try_send_to` for `send_to`) | The item must appear as a whole word | `a_canary_must_call_its_own_item` |
| L4 | The workflow text check failed on any `RUSTFLAGS`, comments included, and would block a sanitizer job | Removed: the clippy job is covered by the neutralised environment, and other jobs do not judge lints; its negative is replaced by `build-script-clippy-env` | as L1 |
| L5 | Most `OsFs` refusals and the build-script check were unpinned | A table test over every method; a unit test and a negative for build scripts (names in any case) | `network_and_device_paths_are_refused`, `a_build_script_naming_clippy_is_found`; negative `build-script-clippy-env` **PROVEN** |
| L6 | The walker now scanned nested build output (`fuzz/target`) | Folders holding Cargo's `CACHEDIR.TAG` are skipped | by reading |
| L7 | ADR-0013's list of negatives missed round seven's, the `allow-invalid` wording was wrong, and round seven's commit said "34 Unix canaries" where the Linux cross-check counts 32 (34 `allow-invalid` entries, two of them Windows symlinks) | Corrected here and in ADR-0013 | review of the text |
