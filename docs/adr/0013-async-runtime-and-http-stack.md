# ADR-0013: Async runtime and HTTP stack

**Status:** Proposed (opened 2026-10-13; earliest decision 2026-10-15, 48 h) · **Plan refs:** v1 D2, v2 D-26, I-07, I-14, §2.5 · **Builds on:** ADR-0005, ADR-0010

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

## Verification (WP3.0b, WP3.2)

- Passthrough spike: p95 ≤ 12.5 ms against the mock provider (half the overhead budget).
- SSRF suite: private, link-local and metadata ranges; DNS rebinding; redirects; IPv6 and decimal
  IP forms.
- Default-config network capture: no egress before a user request, and revocation fetches
  classified.
- Slow-client test: 1 KB/s for 1 h with bounded RSS.
