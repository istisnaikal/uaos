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

## Implementation: the egress door (P3 Move 1, PR-5, 2026-10-15)

**What is built.** `crates/uaos-egress`, the one outbound path:
- `addr::classify` refuses every special-purpose range in the IANA registries. That includes
  IPv4 addresses embedded in IPv4-mapped, IPv4-compatible, NAT64 and 6to4 forms, and Teredo.
- `HostName` refuses address literals in every spelling: decimal, hexadecimal, octal,
  shortened and bracketed.
- The connector resolves each name itself, classifies every answer, and dials the classified
  address, so there is no second lookup a rebinding attacker could answer. It then runs TLS with
  the upstream's own name, on aws-lc-rs, with the platform verifier or declared roots.
- `Door::send` behaves as follows:
  - it refuses a request bound to another Operation, a second send for the same Operation (a
    bounded replay window), an undeclared upstream, an oversized body, and a request that
    already carries the credential's header;
  - it strips hop-by-hop headers and `host`, and adds nothing except the credential, inserted
    last and marked sensitive;
  - it returns redirects without following them;
  - it keeps a circuit breaker per upstream.
- **Private upstreams.** They must be declared (`allow_private`); plain HTTP requires that
  declaration.
- **Connection tasks.** They run on an executor the caller passes in. The runtime passes its
  supervisor's, so the supervisor stays the only spawner.
- **HTTP version.** HTTP/1.1 only (ALPN `http/1.1`); HTTP/2 is not enabled at RC-1.

**How it is enforced.**
- `clippy.toml`: outbound `connect` (std and tokio), `lookup_host` and `UdpSocket::bind` are
  banned outside `uaos-egress/src/{connect,resolve}.rs`. `tokio::task::spawn` and
  `spawn_blocking` are banned outside the runtime. `Door::new` is banned outside the
  composition root.
- `arch.toml`:
  - the bin's allow list is explicit and leaves out `uaos-egress` (ADR-0010);
  - `uaos-module-api` and every Ring 1 crate are banned, transitively, from tokio, hyper,
    hyper-util, mio, socket2, rustls and the door.
- **Seeded violations:** `egress-dials-private-range`, `egress-numeric-host`,
  `egress-ctor-outside-root` and `arch-ring1-depends-on-hyper`.

**Verified.**
- 8 unit tests, including two property tests: an IPv4-mapped address always gets its IPv4
  verdict, and nothing the standard library calls special is ever allowed.
- 8 integration tests against a loopback TLS mock with a throwaway authority. They cover:
  - the header policy, read from what the mock received;
  - op binding and replay;
  - credential collision;
  - a redirect not followed;
  - private answers never dialled (0 connects);
  - zero contact at construction;
  - the breaker opening with no further contact;
  - a stranger's certificate refused before any byte, credential included, is sent.

**Not yet verified or built, stated plainly.**
- The default-configuration network capture (I-14) is still owed. The door's own counters prove
  it makes no contact at construction, but the OS-level capture with revocation fetches belongs
  to the bin (M3).
- The 1 KB/s slow-client test belongs to the runtime's relay (WP3.3).
- The negative `arch-bin-depends-on-egress` waits for the bin crate (M3); the rule is already
  in `arch.toml`.
- There is no "redirect followed" negative. No code path follows redirects, so there is nothing
  to seed; the integration test pins the behaviour.
- The Ring 1 third-party allowlist arrives with the first module (PR-7). This PR adds the Ring 1
  ban list.
- **Supply chain.**
  - 57 new cargo-vet exemptions, each with a written reason.
  - cargo-vet 0.10, the version CI pins, ignores 80 newer Bytecode Alliance audits that cover
    much of this stack; upgrading the tool is its own change.
  - `ring` appears in `Cargo.lock` only as an optional dependency and compiles for no target.
