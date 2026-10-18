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
1 High, 2 Medium and 3 Low, an eighth 1 Medium and 7 Low, a ninth 4 Low, a tenth 2 Low, an eleventh 3 Low, a twelfth 2 Low, a thirteenth 1 Medium and 2 Low, a fourteenth 2 Low, a fifteenth 2 Low, a sixteenth 1 Medium, a seventeenth 5 Low, and an eighteenth 4 Low, all resolved below. The
eighteenth round's fixes have not been reviewed again.

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

## Eighth review (2026-10-16)

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

## Ninth review (2026-10-16)

**Reviewed:** `821b6e6` (on `555494b`) by a fresh-context agent with the same checklist, in a
scratch export, judged against ADR-0013's statement that these gates stop drift and careless
overrides, not a contributor who edits the gates. **Result:** 0 High · 0 Medium · 4 Low, and one
overclaim in the text.

| Finding | What it was | What changed | Proof |
|---|---|---|---|
| L1 | The door sent any method. An upstream that answers `TRACE` as RFC 9110 §9.3.8 describes (Apache httpd's default) echoes the request it received, so the provider credential the door inserted came back to the caller | The door sends only GET, HEAD, POST, PUT, PATCH, DELETE and OPTIONS. TRACE, CONNECT and extension methods are refused before contact, without consuming the Operation | `methods_the_door_does_not_send_are_refused_before_contact`; negative `egress-sends-trace` **PROVEN** |
| L2 | The canary shape check matched only the banned item's last segment: a copy-pasted canary calling another ban with the same name (`std::fs::File::create` under the marker for the named-pipe `ServerOptions::create`) passed `allow-audit`, and kept clippy green while its own ban resolved to nothing | The item's type or module must be named too, as a whole word in code (comments and strings masked, the marker included), in the function's signature or the three lines after the marker (incomplete: the tenth review, L1) | `a_canary_must_name_its_type_or_module`; negative `canary-calls-another-item` **PROVEN**; every real canary passes |
| L3 | The build-script check refused any build script that mentioned clippy (a comment, a lint attribute) and missed one declared as `build = "build/main.rs"` | Build scripts are taken from `cargo metadata` (targets of kind `custom-build`), and only setting a clippy variable for the compiler counts (`rustc-env=CLIPPY…`, in any case, `cargo:` or `cargo::`) (narrowed too far: the tenth review, L2) | `a_build_script_setting_clippy_env_is_found`; negatives `build-script-clippy-env` and `build-script-declared-path` **PROVEN** |
| L4 | `cargo xtask clippy` removed `CLIPPY_CONF_DIR`, so a machine's Cargo `[env]` without `force` could still set it for clippy; the eighth section's heading carried the wrong date | The clippy it runs gets `CLIPPY_CONF_DIR` set to the workspace root, which `[env]` without `force` does not override (with `force` it does; that configuration is the machine's, as ADR-0013 states). The heading carries the commit date | `the_child_environment_is_neutralised`; by reading |
| Text | ADR-0013 said `OsFs` refused network and device paths "in every spelling", but DOS device names in a last component (`C:\data\NUL`) pass it | ADR-0013 and the test now say "every prefix spelling" and state the gap: every file UAOS opens has a name UAOS chooses, and the data directory, which configuration names, is owed with M3 | review of the text |

**Verified locally (Windows, dedicated target directory):** 25 xtask tests; 24 egress unit and
22 integration tests; 24 platform tests; `cargo xtask clippy`, `allow-audit`, `arch-check`,
`gates`, `claims` and `headers`; all 40 egress negatives, of which 36 PROVEN here and the four
Unix ones left to Linux CI. The ban list and canaries did not change, so the round-eight Linux
cross-check of the Unix canaries stands.

## Tenth review (2026-10-16)

**Reviewed:** `81ebb39` (on `555494b`) by a fresh-context agent with the same checklist, in a
scratch export. **Result:** 0 High · 0 Medium · 2 Low, both gaps in the ninth round's gate
fixes; nothing new in the door. The method allowlist sits before the breaker and the send record,
so a refused method consumes nothing; `CLIPPY_CONF_DIR` pinned to the root still reads the root's
bans with a nested `clippy.toml` and an outer `CLIPPY_CONF_DIR` set (checked by a seeded
violation); `cargo metadata` lists every build script the workspace has; the counts held.

| Finding | What it was | What changed | Proof |
|---|---|---|---|
| L1 | Requiring the owner's name was not enough. std and tokio share eleven type-and-method pairs (`TcpStream::connect`, `UnixDatagram::bind`, …), the std Unix canaries reached their types through an import, and sibling canaries share modules (`tokio::task::spawn_blocking` and the `JoinSet` canaries). A canary calling std's item under tokio's marker, or a sibling's under its own, passed `allow-audit` and kept clippy green while its own ban resolved to nothing (shown on Windows, and for an `allow-invalid` Unix ban in the Linux cross-check) | A canary spells its item by its own path in code: a method its type's full path, an item in a module its whole path, in the signature or the three lines after the marker. The std Unix and Windows named-pipe canaries now use full paths instead of imports | `a_canary_must_spell_its_own_path` (import, same name in another crate, sibling, comment); negatives `canary-calls-another-item` (now std's `TcpStream::connect` under tokio's marker) and `canary-copied-from-sibling` **PROVEN**; every real canary passes; the Linux cross-check of the Unix canaries is clean, and fails with a ban removed |
| L2 | The ninth round narrowed the build-script check to the literal `rustc-env=CLIPPY`, so a script emitting through a helper (`emit("CLIPPY_ARGS", "-A…")`) passed and switched the bans off for its crate | A build script that names one of clippy's variables (`CLIPPY_` in any case) in its code or strings is refused; comments, lint paths (`clippy::`) and prose are not | `a_build_script_naming_a_clippy_variable_is_found`; negative `build-script-clippy-env` now seeds the helper form, in lowercase, and `build-script-declared-path` the direct form, both **PROVEN** |

**Verified locally (Windows, dedicated target directory):** 25 xtask tests; `cargo xtask clippy`,
`allow-audit`; the Linux cross-check of the Unix canaries; all 41 egress negatives, of which 37
PROVEN here and the four Unix ones left to Linux CI. The door's code did not change this round.

## Eleventh review (2026-10-16)

**Reviewed:** `7756686` (on `555494b`) by a fresh-context agent with the same checklist, in a
scratch export. **Result:** 0 High · 0 Medium · 3 Low, two of them gate gaps with a plausible
accidental path (a setup line; a build script split into modules) and one test gap; nothing new
in the door. Every real canary passed the tenth round's rule, including UFCS and turbofish forms,
CRLF, char literals and lifetimes; the round-10 negatives pin their fixes.

| Finding | What it was | What changed | Proof |
|---|---|---|---|
| L1 | The shape check proved that the item's path and name appear, not that the canary's only banned call is its own. A setup line calling another ban of the same lint (`UnixDatagram::unbound()` to get a socket for the `connect` canary, `Path::canonicalize` before `is_file`), or a second call past the third line, kept the shared `#[expect]` fulfilled while the canary's own ban was dead (shown on Windows, and on Linux for a wrong-kind `allow-invalid` entry). The docs also said "never through an import", while the `to_socket_addrs` canary imports its trait inside the function | The whole canary function, up to its closing brace, may spell no other ban of the same lint by the test its own item passes (a ban of the other lint, such as a banned type in a method canary's signature, is allowed: it fulfils a different expectation). The docs say a module-level import does not count | `a_canary_uses_no_other_ban_of_its_lint` (a setup call, a call past the third line, a comment, a type of the other lint); negative `canary-setup-calls-another-ban` **PROVEN**; every real canary passes |
| L2 | The build-script check read only the build script's own file: the tenth round's helper moved into `mod build_env;` passed `allow-audit` and switched the bans off for its crate. A path build-dependency's code runs in the build script unread too | A build script that declares a module in another file is refused (`#[path]` and `include!` already were), and so is any path build-dependency (in owner crates `#[path]` and `include!` were not: the twelfth review, L1) | `a_build_script_module_in_another_file_is_found`; negatives `build-script-module` and `build-dependency-path` **PROVEN** |
| L3 | `path_occurs`'s boundary rule was pinned by no test: a plain substring match passed every test | Tests for a longer identifier (`FileType`, `PathBuf`, `spawn_blocking`) and a longer path | `a_path_occurs_only_whole` |

Also from verifying: `cargo xtask negative` now refuses a seed anchor that occurs more than once in
its file (found on PR-1, where a new function made an older anchor match two sites; every anchor
here was already unique).

**Verified locally (Windows, dedicated target directory):** 28 xtask tests; `cargo xtask clippy`,
`allow-audit`; all 44 egress negatives, of which 40 PROVEN here and the four Unix ones left to
Linux CI. The door's code did not change this round.

## Twelfth review (2026-10-16)

**Reviewed:** `ff6da7d` (on `555494b`) by a fresh-context agent with the same checklist, in a
scratch export. **Result:** 0 High · 0 Medium · 2 Low, both in the gate tooling; nothing new in
the door. `function_code`'s brace matching held against braces in char literals, strings, raw
strings and comments, closures, nested blocks and labels; `declares_file_module` handled
visibility, attributes and comments; every one of the 72 seeds that needs no network applies with
each anchor matching once.

| Finding | What it was | What changed | Proof |
|---|---|---|---|
| L1 | The eleventh round's one-file rule leaned on the `#[path]` and `include!` check, which allows both in the owners of `clippy::disallowed_methods` (`xtask`, `uaos-testkit`). A build script there that `include!`d the helper setting `CLIPPY_ARGS` passed `allow-audit`, and `cargo xtask clippy` then passed a seeded `HashMap` and `unsafe` block in that crate | A build script may use no other file, in any crate: a `mod` in another file, a `#[path]` attribute, `include!`, `include_str!` and `include_bytes!` are refused | `a_build_script_using_another_file_is_found`; negative `build-script-include-in-owner` (the reviewer's repro, in `uaos-testkit`) **PROVEN** |
| L2 | ADR-0013, `tests/bans.rs` and the CHANGELOG said a canary's function may hold "no other ban of the same lint"; the check sees only bans spelled by their full path, so one reached through a module-level import or a shortened path is not seen (it matters only for an `allow-invalid` ban, which the unresolved-path check does not cover) | Stated as such in all three | review of the text |

Also: the seed-anchor uniqueness rule has a unit test (`a_seed_anchor_must_occur_exactly_once`).

**Verified locally (Windows, dedicated target directory):** 29 xtask tests; `cargo xtask clippy`,
`allow-audit`; all 45 egress negatives, of which 41 PROVEN here and the four Unix ones left to
Linux CI. The door's code did not change this round.

## Thirteenth review (2026-10-16)

**Reviewed:** `7924f8a` (on `555494b`) by a fresh-context agent with the same checklist, in a
scratch export, asked to spend at least half its effort on the door after four rounds on the
gates. **Result:** 0 High · 1 Medium · 2 Low, all in the door and the platform's file system;
the twelfth round's gate change held. Address classification was checked against the IANA
registries; DNS, TLS, credentials, the breaker and the absence of retries and redirects held.

| Finding | What it was | What changed | Proof |
|---|---|---|---|
| M1 | `OsFs` let UNC paths through when written with a doubled separator: std parses `\\nas\\share\x`, `//nas//share/x` and `\/nas\\share\x` as a root directory and plain components (it needs a non-empty server and share), while Windows collapses the separator and opens `\\nas\share\x`. Over loopback SMB, `OsFs.read(r"\\127.0.0.1\\C$\Windows\win.ini")` returned the file. A data directory written with doubled backslashes in configuration would reach a host over SMB with the user's NTLM identity (red line 1). Nothing configuration-supplied reaches `OsFs` yet (M3) | On Windows, a path that starts with two separators, in any mix of `\` and `/`, is refused unless std parses it as a verbatim disk path. ADR-0013, T5, the CHANGELOG and `OsFs`'s doc say so | `network_and_device_paths_are_refused` with four doubled spellings, every `Fs` method; negative `osfs-doubled-separator-unc` **PROVEN** (Windows only, like the named-pipe ban) |
| L1 | An upstream answering `101 Switching Protocols` (the door strips `upgrade`, so it asked for nothing) reached the caller as a final response, with the upgraded connection lost; a relay copying the status would switch its own client's connection | A 1xx status from the client is an error (`the upstream switched protocols unasked`); the breaker counts it as answered | `a_switching_protocols_answer_is_an_error`; negative `egress-forwards-switching-protocols` **PROVEN** |
| L2 | A response with `transfer-encoding: chunked` and a contradicting `content-length` reached the caller with the `content-length` kept and the body decoded; relayed as is, the client got no response | A `content-length` beside `transfer-encoding` is dropped (RFC 9112 §6.3) | `a_content_length_beside_transfer_encoding_is_dropped`; negative `egress-forwards-contradicting-length` **PROVEN** |

Also: ADR-0013 says hyper writes `host` and frames the body, and the CHANGELOG's review bullet no
longer breaks a line in four.

**Verified locally (Windows, dedicated target directory):** 24 egress unit and 24 integration
tests; 24 platform tests; 29 xtask tests; `cargo xtask clippy`, `allow-audit`; all 48 egress
negatives, of which 44 PROVEN here and the four Unix ones left to Linux CI.

## Fourteenth review (2026-10-16)

**Reviewed:** `601d164` (on `555494b`) by a fresh-context agent with the same checklist, in a
scratch export, again weighted toward the door and `OsFs`. **Result:** 0 High · 0 Medium · 2 Low.
Nothing reaches an address the door should refuse, leaks a credential, bypasses TLS, retries,
follows a redirect, or lets `OsFs` reach the network. The round-13 fixes were checked by applying
their seeds by hand; an endless run of 100s ends at `response_timeout`; trailers, early closes and
non-UTF-8 `connection` values were checked; every Windows path spelling that reaches the network
is refused.

| Finding | What it was | What changed | Proof |
|---|---|---|---|
| L1 | `OsFs` admitted `\\?\C:`, a verbatim disk prefix with nothing after it, which names the raw volume: a device. Unelevated, every open of it fails; an elevated process could have read or written the volume through `read`, `open_append` or the lock | A verbatim disk path is admitted only with a root directory after the prefix (`\\?\C:\` and below) | `network_and_device_paths_are_refused` with `\\?\C:`, every `Fs` method; `\\?\C:\data` still passes; negative `osfs-bare-volume` **PROVEN** (Windows only) |
| L2 | The round-13 sentence "the caller receives the decoded body" held only for `chunked`: hyper removes only that layer, so `transfer-encoding: gzip, chunked` reached the caller coded with the header stripped, and a list-form or repeated `content-length` passed as is | A transfer coding other than `chunked` is an error (the door asks for none); a repeated `content-length` is forwarded once; ADR-0013, the CHANGELOG and the doc comment say the relay frames the body it forwards | `a_transfer_coding_other_than_chunked_is_an_error`, `a_repeated_content_length_is_forwarded_once`; negatives `egress-forwards-unknown-transfer-coding` and `egress-forwards-repeated-length` **PROVEN** |

Noted, not a finding: when the `osfs-doubled-separator-unc` negative's seed takes effect, Windows
tries to resolve the canary name `uaos-canary.invalid` (DNS, LLMNR, NetBIOS); the case runs only by
hand on Windows, and `.invalid` never resolves.

**Verified locally (Windows, dedicated target directory):** 24 egress unit and 26 integration
tests; 24 platform tests; 29 xtask tests; `cargo xtask clippy`, `allow-audit`; all 51 egress
negatives, of which 47 PROVEN here and the four Unix ones left to Linux CI.

## Fifteenth review (2026-10-16)

**Reviewed:** `88eb134` (on `555494b`) by a fresh-context agent with the same checklist, in a
scratch export, weighted toward the door and `OsFs`. **Result:** 0 High · 0 Medium · 2 Low, both in
the fourteenth round's `frame_for_caller`. `OsFs` held against every spelling tried (device
namespaces, volume GUIDs, `\\?\` with forward slashes and lowercase `unc`, drive-relative paths,
alternate data streams, trailing dots and spaces), and nothing in the door reaches a refused
address, leaks a credential, gets past TLS, retries or redirects.

| Finding | What it was | What changed | Proof |
|---|---|---|---|
| L1 | The fourteenth round's "only `chunked`" check read the codings differently from hyper, which looks only at the last element of the last field: `transfer-encoding: chunked,` (an empty last element), `chunked` followed by an empty second field, and `chunked, chunked` passed the door while hyper left the body framed, so the caller got chunked framing as the body with both framing headers stripped | `transfer-encoding` must be exactly what hyper decodes: one field whose trimmed value is `chunked`, in any case; anything else is the existing error | `a_transfer_coding_other_than_chunked_is_an_error` with all four spellings; checked to fail with the fourteenth round's reading put back; negative `egress-forwards-unknown-transfer-coding` **PROVEN** |
| L2 | The doc said a repeated `content-length` passes only when all are equal, but hyper checks it only where it reads a body: for a HEAD request, a `204` or a `304` it passed unchecked (`5, 7`, `100` on a `204`, `abc, 9`, non-UTF-8 bytes) | A `204` keeps no `content-length`; otherwise it is forwarded as one value only when all its values are the same digits, and dropped when not; the doc comment, ADR-0013 and the CHANGELOG say so. The T5 row's wording is fixed | `content_length_on_answers_without_a_body`; negative `egress-forwards-bodiless-length` **PROVEN** |

Also found while verifying: the round-13 and round-14 negatives' seed anchors moved with the code
(one now matched two sites, one none); the anchor-uniqueness check caught both, and each names its
own site again.

**Verified locally (Windows, dedicated target directory):** 24 egress unit and 27 integration
tests; 24 platform tests; 29 xtask tests; `cargo xtask clippy`, `allow-audit`; all 52 egress
negatives, of which 48 PROVEN here and the four Unix ones left to Linux CI.

## Sixteenth review (2026-10-16)

**Reviewed:** `e97b29a` (on `555494b`) by a fresh-context agent with the same checklist, in a
scratch export. **Result:** 0 High · 1 Medium · 0 Low. The fifteenth round's framing held against
hyper 1.12's client decoder on eleven raw responses (whenever the door accepts, hyper removed
exactly one `chunked` layer or read no body), and what it now refuses no real provider or local
server sends. `OsFs` held against nineteen more spellings over loopback SMB.

| Finding | What it was | What changed | Proof |
|---|---|---|---|
| M1 | Requests the upstream received, or even answered, came back as `EGRESS_UNREACHABLE`: "could not be reached", retryable. An answer the door does not pass on (a `101`, a transfer coding) and a connection cut after the request was written were indistinguishable from a connection that never opened, so the runtime (PR-6) could not tell "nothing left" from "maybe delivered" from "delivered and answered" when settling a reservation (ADR-0002, T6), and a retry would be a new billed call that gets the same answer | Errors split by delivery: `Unreachable` and `Timeout` mean nothing was sent (hyper's canceled-unsent request included) and stay retryable; `Interrupted` (`EGRESS_INTERRUPTED`) covers a connection cut, or no answer within the response timeout, after the request was sent; `Unusable` (`EGRESS_UNUSABLE_RESPONSE`) covers an answer the door does not pass on. Both new codes are not retryable and say the provider may have billed the request; the texts of `EGRESS_UNREACHABLE` and `EGRESS_TIMEOUT` say nothing was sent | `errors_say_whether_the_request_may_have_reached_the_provider` (an unusable answer, a connection cut after the request, a closed port); negative `egress-delivered-reported-unsent` **PROVEN** |

**Verified locally (Windows, dedicated target directory):** 24 egress unit and 28 integration
tests; 43 contracts tests (the registry's own checks); 24 platform tests; 29 xtask tests;
`cargo xtask clippy`, `allow-audit`; all 53 egress negatives, of which 49 PROVEN here and the four
Unix ones left to Linux CI.

## Seventeenth review (2026-10-16)

**Reviewed:** `42f6cd8` (on `555494b`) by a fresh-context agent with the same checklist, in a
scratch export. **Result:** 0 High · 0 Medium · 5 Low. No path reports "nothing was sent" for a
request that may have been delivered: in hyper 1.12's HTTP/1 client every "canceled" hands the
request back unsent, and once the dispatcher took it every error is final. The sixteenth round's
split erred the other way in places. `OsFs` held against eighteen more spellings (NT roots, `..`
inside verbatim paths, look-alike separators) over loopback SMB.

| Finding | What it was | What changed | Proof |
|---|---|---|---|
| L1 | A connection that failed while hyper set it up, before it took the request (the upstream speaks first, or accepts and closes at once), came back as `Interrupted`, "after the request was sent", though the upstream received nothing (23 of 40 runs with the stock executor) | hyper-util attaches connection info only to errors from sending on a connection it holds, so an error without it is "nothing sent": `Unreachable`, retryable | `a_connection_lost_before_the_request_left_is_unreachable` (a server that speaks first counts 0 bytes; one that closes at once), 20 of 20 repeats; negative `egress-unsent-reported-delivered` **PROVEN** |
| L2 | The response timeout also runs through the connect phase; set shorter than it, a request that never left read as `Interrupted` | `Door::new` refuses (`Limits`, `CONFIG_INVALID`) a response timeout that does not exceed resolution, `MAX_ADDRESSES_TRIED` connects and the handshake; `DoorLimits` says the timeout runs from handing the request to the client | `a_response_timeout_inside_the_connect_phase_is_refused` |
| L3 | Two verdicts had no test: no answer within the response timeout (the dangerous direction: changed to `Timeout`, it reads "nothing sent, retryable") and the canceled-unsent branch | Tests for both; the canceled branch's test did not in fact reach it (eighteenth round, L3) | `no_answer_within_the_response_timeout_is_interrupted` and the L1 test; negative `egress-timeout-reported-unsent` **PROVEN** |
| L4 | An answer hyper could not parse (`content-length: abc`, a four-digit status, not HTTP) came back as `Interrupted`, "the connection failed", and counted against the breaker, while an answer the door refuses after the headers counts as answered | hyper's parse errors are `Unusable`, "could not be parsed", and the breaker counts every `Unusable` as answered | `an_unparsable_answer_is_unusable` (three answers); the breaker's unit test |
| L5 | The delivery contract stopped at `send`'s result; `Timeout`'s text said a connect timeout gives `Timeout` (it gives `Unreachable` after the last address); the breaker docs still said "unreachable or timed out" | `EgressResponse` and ADR-0013 say a body that fails mid-stream is an answer cut short and a `send` dropped after the hand-over may have been delivered; the `Timeout` doc and `EGRESS_TIMEOUT` text name resolution and the handshake; the breaker docs name interrupted requests | review of the text |

**Verified locally (Windows, dedicated target directory):** 24 egress unit and 32 integration
tests; 43 contracts tests; 24 platform tests; 29 xtask tests; `cargo xtask clippy`, `allow-audit`;
all 55 egress negatives, of which 51 PROVEN here and the four Unix ones left to Linux CI.

## Eighteenth review (2026-10-16)

**Reviewed:** `543c2c5` (on `555494b`) by a fresh-context agent with the same checklist, in a
scratch export. **Result:** 0 High · 0 Medium · 4 Low. No path in hyper 1.12.0 or hyper-util
0.1.21 reports a sent request as "nothing sent": every error hyper-util builds without connection
info comes before the request is sent, and every client-side "canceled" in hyper hands the
request back unsent. `OsFs` refused sixteen more spellings at runtime; `\\?\C:/x` passes the
check, but Windows reads `C:/` as one object name and the open fails.

| Finding | What it was | What changed | Proof |
|---|---|---|---|
| L1 | The response timeout could run out while hyper-util still waited for the executor to run the connection task, before the request left: the door said `Interrupted` ("may have been received") though the upstream received 0 bytes, and ADR-0013 said that timeout always meant the request was handed over. The error leaned the safe way (settled as possibly billed) and needs a badly delayed executor | The door attaches hyper-util's `capture_connection` to the request: a timeout before a connection was assigned is `Timeout` (nothing sent, retryable), after it `Interrupted` | `a_timeout_before_the_request_was_handed_over_is_not_interrupted` (a late executor; the upstream counts 0 bytes); negative `egress-unassigned-timeout-reported-delivered` **PROVEN** |
| L2 | `DoorLimits::idle_timeout` was not checked: `Duration::MAX` panicked hyper-util's idle task (`Instant` overflow) once the first connection went idle | `Door::new` refuses an idle timeout over a day (`Limits`) | `a_response_timeout_inside_the_connect_phase_is_refused` also checks `Duration::MAX` (refused) and a day (accepted) |
| L3 | The canceled-unsent branch had no test, though the seventeenth round's record said it had: that test reached only the no-connection-info path, and removing the branch left every test green | A test whose executor delays the connection task's second poll, so the upstream's greeting arrives while the request is still queued and hyper hands it back canceled, with connection info; the seventeenth round's row corrected | `a_queued_request_handed_back_is_unreachable` (0 bytes received); negative `egress-canceled-reported-delivered` **PROVEN** |
| L4 | The CHANGELOG listed error codes 0001 to 0005, though 0006 and 0007 exist; `EGRESS_UNUSABLE_RESPONSE`'s message named only a protocol switch or a transfer coding and said a retry gets the same answer, though it also covers answers that could not be parsed | The CHANGELOG lists 0001 to 0007; the message names malformed answers and says a retry sends the request again | review of the text |

**Verified locally (Windows, dedicated target directory):** 24 egress unit and 34 integration
tests; 43 contracts tests; 24 platform tests; 29 xtask tests; `cargo xtask clippy`, `allow-audit`;
all 57 egress negatives, of which 53 PROVEN here and the four Unix ones left to Linux CI.
