# ADR-0013: Async runtime and HTTP stack

**Status:** Accepted by the maintainer on 2026-10-15, at the end of its 48 h window (opened 2026-10-13); decides D-26 · **Plan refs:** v1 D2, v2 D-26, I-07, I-14, §2.5 · **Builds on:** ADR-0005, ADR-0010

## Context

P3 adds the first network code:
- an ingress server for the client dialects;
- a control API (REST and SSE);
- the egress client toward providers.

Three requirements constrain the choice:
1. **Byte-exact ingress.** Codecs splice the original request bytes in place (ADR-0005). A
   framework that parses and re-serializes bodies would break that.
2. **One door.** Egress must resolve, verify and pin addresses itself, and must never follow
   redirects on its own (SSRF, T5).
3. **A small dependency surface.** There are already 233 unaudited exemptions (PD-06), and every
   new crate adds review load.

## Decision

1. **tokio, bounded.**
   - A multi-thread runtime. Every channel is bounded and sized to the admission limit.
   - The runtime supervisor is the only spawner: `tokio::spawn` is banned elsewhere (ADR-0010).
2. **hyper 1 and hyper-util directly**, for ingress, the control API and egress. Bodies are
   collected with an explicit size limit into owned bytes for the codecs. Response streams are
   relayed frame by frame with a byte bound.
3. **TLS through rustls**, with the `aws-lc-rs` provider (already the crypto family, D18) and
   `rustls-platform-verifier`, so corporate interception roots in the OS trust store work.
4. **Egress owns name resolution.** It resolves, rejects private, link-local and metadata
   ranges, pins the verified address, sets SNI to the original host, and never follows
   redirects automatically.
5. **Revocation traffic is disclosed.** Platform verifiers may trigger OS-level certificate
   checks (OCSP, CRL, AIA fetches). They are caused by the user's own provider connection, but
   they are still external contact, so they are classified in the I-14 network-capture test and
   documented in the privacy data flow.
6. **No reqwest and no axum at RC-1.** The control API has about ten routes and uses a small
   internal router; this choice is re-evaluated at P4 for the panel.

## Alternatives rejected

- **reqwest:** convenient, but its redirect following and connection pooling act on the network
  on their own, which defeats the door's resolve-verify-pin and redirect checks.
- **axum:** its convenience does not pay for its extra crates at this size, and its extractors
  invite parsing bodies before the codec sees the original bytes.
- **async-std:** unmaintained.
- **A thread-per-core runtime on io_uring:** Linux-only.

## Consequences

- There is more boilerplate (routing, body limits) in exchange for control over every byte and
  every connection.
- tokio, hyper, rustls and their dependencies enter cargo-vet. Imported audits (Google, Mozilla,
  Bytecode Alliance) are preferred, and new exemptions carry notes (`vet-ratchet`).

## Threat and privacy note

- **T5:** redirects and DNS rebinding are handled at the door.
- **I-14:** zero egress in the default configuration, with revocation fetches disclosed.
- **T11 (local DoS):** bounded bodies, bounded channels, admission control.

## Evidence so far

Spike WP3.0b (branch `spike/wp3.0b-passthrough`, `spikes/passthrough/RESULTS.md`, 2026-10-13)
measured this shape: collect under a limit, a pooled hyper client, frame-wise relay. With
1.7 MB bodies the passthrough overhead at p95 was:
- sequential: 0.75–2.16 ms on all three runner OSes and the reference machine;
- 8 concurrent clients: at most 8.15 ms.

That is under the 12.5 ms passthrough budget. Concurrency, not body size, dominates, so the P3
overhead bench must include a concurrent scenario.

## Verification (WP3.0b, WP3.2)

- Passthrough spike: p95 ≤ 12.5 ms against the mock provider (half the overhead budget).
- SSRF suite: private, link-local and metadata ranges; DNS rebinding; redirects; IPv6 and decimal
  IP forms.
- Default-config network capture: no egress before a user request, and revocation fetches
  classified.
- Slow-client test: 1 KB/s for 1 h with bounded RSS.

## Amendment 1 (accepted by the maintainer on 2026-10-16)

The V1 review of the first implementation ([WP3.A5](../reviews/WP3.A5-egress.md)) showed that
Decision 3's verifier breaks Decision 4 and red line 1. The maintainer accepted this amendment
on 2026-10-16, both parts, as an explicit instruction in the working session; it is implemented
on the PR-5 branch.

**A. TLS trust: system roots, verified by rustls, nothing fetched (amends Decisions 3 and 5).**
- **Finding (H1).** `rustls-platform-verifier` hands the server's chain to the operating system.
  On Windows, `CertGetCertificateChain` then fetches the issuer, OCSP and CRL URLs named in the
  server's certificate while it is still *building* the chain, before anything is trusted.
  Any TLS peer of a declared upstream can therefore make the machine send HTTP requests to
  addresses of its choosing (the metadata service, the LAN), outside the door, unclassified and
  uncounted. Reproduced on Windows 10; macOS behaves the same way by default, not reproduced.
- **Decision.** The default trust is the operating system's root store, read locally when the
  door is built (`rustls-native-certs`), and chains are verified by rustls's own verifier. A
  handshake fetches nothing. `rustls-platform-verifier` is removed, with 11 crates from the
  lockfile.
- **Revocation is not checked at RC-1.** That is the cost: a provider certificate revoked
  before it expires would still be accepted. Public TLS certificates issued since March 2026
  last at most 200 days, falling to 47 days by March 2029 (CA/Browser Forum ballot SC-081), which
  bounds that window. A revocation source that needs no
  fetch at handshake time (a CRL bundle shipped with releases) can be added later without
  reopening this channel.
- **Second residual.** Windows downloads some roots on demand. A root that has never been
  downloaded on this machine is absent from the local store, so a provider whose chain ends in
  it fails to verify until it is present. `uaos doctor` must diagnose this (M3).
- **Further residuals of the root store** (review round 2, L3):
  - `rustls-native-certs` lets the environment variables `SSL_CERT_FILE` and `SSL_CERT_DIR`
    replace the operating system's store on every platform. That is an ambient input the
    project otherwise bans; `uaos doctor` must show when it is in effect (M3).
  - Certificates in the store that fail to parse are skipped; a partly read store is used.
  - On Windows the loader takes the roots without consulting the Disallowed store or partial
    distrust dates, so a root the OS distrusts only in part is trusted fully.
  - An upstream that declares its own roots must declare at least one; an empty list is
    refused when the door is built.
- **Alternative rejected.** Keeping the platform verifier as an explicit opt-in, documented as
  a residual. It keeps a channel any peer can drive, for a check that only matters when a
  certificate is revoked early.
- **Decision 5** therefore no longer applies to the default configuration: there are no
  revocation fetches to disclose.

**B. Where the door is built (amends ADR-0010 Decision 2).**
- **Finding (M1).** ADR-0010 had the composition root call `Door::new` while also leaving
  `uaos-egress` out of the bin's dependencies, and `arch.toml` banned the egress crate from the
  bin *transitively*, so the intended wiring (bin → runtime → egress) failed the gate.
- **Decision.** The bin never names the egress crate: its allow list is explicit and leaves it
  out, and the transitive ban is gone, since the bin reaches egress through the runtime by
  design. The runtime builds the door, in one private module, from the upstream declarations the
  composition root passes in the runtime's own configuration types, and never exposes egress
  types (ADR-0010 Decision 3). That module becomes the `allow_audit` owner of the `Door::new`
  ban when the runtime crate exists (PR-6).

## Implementation: the egress door (P3 Move 1, PR-5, 2026-10-15; revised 2026-10-16)

**What is built.** `crates/uaos-egress`, the one outbound path:
- `addr::classify` refuses every special-purpose range in the IANA registries, `3fff::/20`
  included. It looks through IPv4-mapped, IPv4-compatible, NAT64 well-known and 6to4 forms, and
  refuses Teredo and the local-use NAT64 prefix whole. Network-specific NAT64 prefixes and cloud
  host endpoints on public unicast (such as `168.63.129.16`) cannot be told apart by address;
  they are reachable only over HTTPS with a verified certificate for the declared name.
- `HostName` refuses address literals in every spelling: decimal, hexadecimal, octal,
  shortened and bracketed.
- **The connector.**
  - It resolves each name itself, within the connect timeout, and classifies every answer.
  - It dials the classified address itself, so there is no second lookup a rebinding attacker
    could answer.
  - It tries at most four addresses per attempt.
  - It runs TLS with the upstream's own name, on aws-lc-rs, against the system's roots or the
    declared ones (Amendment 1A).
- **Private upstreams.** They must be declared (`allow_private`), and then reach only loopback,
  private (RFC 1918) and unique-local addresses, never link-local or another special range. An
  IPv6 form that only embeds a local IPv4 address (IPv4-compatible, NAT64, 6to4) is never
  local, because its traffic leaves the machine, and the IPv6 metadata endpoints inside
  `fc00::/7` (`fd00:ec2::254`, `fd20:ce::254`) are refused as such. Plain HTTP is dialled only
  at pinned local addresses and is never resolved.
- **`Door::send`.**
  - **Refusals before any contact:** a request bound to another Operation, an undeclared
    upstream, an oversized body, a path that does not start with `/`, any of the listed
    credential-bearing headers from the caller (`CREDENTIAL_HEADERS`: `authorization`,
    `cookie`, provider key headers and others; checked before anything is stripped; credentials
    elsewhere, such as in the query string, are not caught here), an open circuit,
    and a second send for the same Operation (a bounded replay window). Only the last consumes
    the Operation.
  - **Headers:** it builds the URI from the upstream's name and port, so the path cannot change
    the destination. It strips hop-by-hop headers, `host` and `content-length` (it frames the
    body itself), and adds nothing except the credential, inserted last.
  - **No hidden behaviour:** it returns redirects without following them, and hyper-util's
    transparent retry is switched off.
  - **Breaker:** each upstream has a circuit that counts only transport failures and, after its
    cooldown, lets exactly one probe through. Every admitted attempt is settled exactly once,
    also when its caller drops the request: a cancelled probe lets the next attempt probe.
- **The credential's value** is marked sensitive when the `Credential` is built and never
  appears in its `Debug` output.
- **Connection tasks.** They run on an executor the caller passes in. The runtime passes its
  supervisor's, so the supervisor stays the only spawner.
- **HTTP version.** HTTP/1.1 only (ALPN `http/1.1`); HTTP/2 is not enabled at RC-1.

**How it is enforced.**
- **`clippy.toml`.** These are banned outside `uaos-egress/src/{connect,resolve}.rs`:
  - outbound connections: `connect` (std and tokio, `TcpSocket` included);
  - name resolution: `lookup_host` and `ToSocketAddrs::to_socket_addrs`, which needs no
    dependency at all;
  - UDP: `UdpSocket::bind` (std and tokio);
  - another HTTP client: hyper-util's `HttpConnector::new`, `new_with_resolver` and
    `build_http`;
  - Unix-socket connects (std and tokio; these paths exist only on Unix);
  - listening: `TcpListener::bind` (std and tokio), whose owner will be the API crate, because
    binding opens a network handle and `bind` with a name resolves it.

  Spawning (`tokio::task::{spawn, spawn_blocking, spawn_local}`, the `JoinSet` and `LocalSet`
  spawns, `Handle`/`Runtime` spawns, `std::thread::{spawn, Builder::spawn, scope}`) is banned
  outside the runtime, and `Door::new` everywhere but its one owner. These bans cover the
  listed entry points. A dependency that opens sockets itself is kept out by `arch.toml` and
  supply-chain review. `cargo xtask allow-audit` checks owners per lint, not per method, so a
  file that owns one disallowed method could allow another; review of each `allow` covers that.
  **Known exception:** the system resolver (`tokio::net::lookup_host`) runs `getaddrinfo` on
  tokio's blocking pool, outside the supervisor; the resolution timeout stops the wait, not the
  thread. Moving resolution onto the supervisor's pool is runtime work (PR-6).
- **`arch.toml`.**
  - The bin's allow list is explicit and leaves out `uaos-egress` (Amendment 1B).
  - `uaos-module-api` and every Ring 1 crate are banned, transitively, from tokio, hyper,
    hyper-util, mio, socket2, rustls and the door.
- **`deny.toml`.** `ring` is banned, so TLS stays on aws-lc-rs.
- **Seeded violations:**
  - for the door's behaviour: `egress-dials-private-range`, `egress-numeric-host`,
    `egress-private-reaches-link-local`, `egress-plaintext-resolved`,
    `egress-breaker-admits-after-cooldown`, `egress-probe-stuck-on-cancel` and
    `egress-embedded-local`;
  - for the clippy bans: `egress-ctor-outside-root`, `net-dns-outside-egress`,
    `net-connect-outside-egress`, `net-udp-outside-egress`, `net-listen-outside-api` and
    `spawn-outside-supervisor`;
  - for the arch rules: `arch-ring1-depends-on-hyper`.

**Verified.**
- **17 unit tests**, including six property tests, the breaker's state machine and the
  dial path's own refusals:
  - IPv4-mapped addresses follow their IPv4 verdict;
  - nothing outside 2000::/3 is public;
  - every embedding form is refused whatever its inner address;
  - the local network is exactly loopback, private and unique-local, and no embedding form
    is ever local;
  - nothing the standard library calls special is ever allowed.
- **21 integration tests** against loopback mocks. They read what the mock received and the
  door's own counters, and cover:
  - the header policy;
  - op binding and replay;
  - credential-bearing headers refused;
  - a redirect not followed;
  - private answers never dialled;
  - a private upstream never reaching link-local;
  - plain HTTP only to pinned local addresses, unresolved;
  - zero contact at construction;
  - the breaker opening, its single probe, and a cancelled probe;
  - an upstream that declares no root, refused when the door is built;
  - a stranger's certificate, and a trusted authority's certificate for another name, both
    refused with no request received;
  - an oversized body refused with no connection;
  - a caller's `content-length` dropped;
  - a path without a leading `/` refused without consuming the Operation;
  - the address cap;
  - the credential never printed;
  - **a certificate naming issuer, OCSP and CRL URLs on a local listener: the handshake fails
    and the listener receives nothing**, on every CI operating system.

**Not yet verified or built, stated plainly.**
- The default-configuration network capture (I-14) is still owed. The door's own counters prove
  it makes no contact at construction; the OS-level capture belongs to the bin (M3).
- The 1 KB/s slow-client test belongs to the runtime's relay (WP3.3).
- The negative `arch-bin-depends-on-egress` waits for the bin crate (M3); the rule is the bin's
  explicit allow list.
- There is no "redirect followed" negative. No code path follows redirects, so there is nothing
  to seed; the integration test pins the behaviour.
- The Ring 1 third-party allowlist arrives with the first module (PR-7). This PR adds the Ring 1
  ban list.
- **Supply chain.**
  - 48 new cargo-vet exemptions, each with a written reason. 21 of them cover crates that are in
    the lockfile only and compile for no target, and their notes say so.
  - cargo-vet 0.10, the version CI pins, ignores 80 newer Bytecode Alliance audits that cover
    much of this stack; upgrading the tool is its own change.
