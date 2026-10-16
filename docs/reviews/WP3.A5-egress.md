# Adversarial review: WP3.A5 the egress door (P3 Move 1, PR-5, ADR-0013)

**Reviewer:** a fresh-context review agent with the fixed V1 checklist (plan v2 §4.2), read-only,
probing a scratchpad export of the branch on Windows 10. **Reviewed:** `b69e23b`
(`p3/a5-egress`), 2026-10-15.
**Result:** 0 Critical · 2 High · 4 Medium · 9 Low. Both High findings were T5 paths the door's
own documentation said were closed. They blocked merge.
**Resolution:** every High and Medium finding fixed with a regression test or a seeded violation;
Low findings fixed or accepted with a reason. Two fixes change accepted decisions and are written
as ADR-0013 Amendment 1, which the maintainer accepted on 2026-10-16. A second V1 review of the
fixes is pending; the PR stays a draft until it is clean.

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
| L4 | `retry_canceled_requests(false)` | Configuration; covered by the single-probe test's connect count |
| L5 | `CircuitOpen` and every pre-contact refusal bump `refused`; `sent` is documented as "handed to the client once every check passed" | the single-probe test counts refusals |
| L6 | Resolution runs within the connect timeout; at most four addresses are tried per attempt (`MAX_ADDRESSES_TRIED`); `DoorLimits` states what the runtime bounds (concurrency, response bodies) | `a_connection_attempt_tries_a_bounded_number_of_addresses` |
| L7 | A request carrying `authorization`, `proxy-authorization`, `cookie`, `x-api-key`, `api-key`, `x-goog-api-key` or `openai-organization` is refused, whatever credential is injected | `credential_bearing_headers_from_the_caller_are_refused` |
| L8 | `deny.toml` bans `ring`. The vet notes of the 21 lockfile-only crates now say they compile for no target; the 9 exemptions for crates that left the lockfile are removed (vet-ratchet 290 → 281, notes-less baseline unchanged) | `cargo deny check bans`, `cargo vet --locked` |
| L9 | Tests added for the oversized body, a wrong name from the trusted authority, the breaker, plain HTTP toward public addresses and IPv6 classification. ADR-0013's "before any byte" now reads "no request received". The T5 row of the threat model and the privacy data flow (both v1, from #24) are updated after the rebase onto it: the door's controls and residuals in T5, and certificate checks now listed as never happening | `an_oversized_body_and_a_wrong_name_are_refused`, the `addr` property tests |

## Maintainer decision

- **ADR-0013 Amendment 1** (A: trust and revocation; B: where the door is built) was accepted by
  the maintainer on 2026-10-16. Merging still waits for a clean second review and for #24.
