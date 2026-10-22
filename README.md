# UAOS — Universal Agentic OS

> Engineering name `UAOS`; product brand to be decided (final work package). Repository norm: `uaos`.

UAOS is a local, single-binary Rust kernel that sits between AI agents and the models and tools
they use. Every model call, tool call and state change becomes an **Operation** that is
authenticated, authorized, priced against a hard budget, redacted, journaled (write-ahead,
hash-chained) and explained. Product features attach to that lifecycle through versioned
contracts; they are never compiled into it.

## Status: P3 (Flow), pre-alpha, no runnable binary yet

The kernel is being built from its foundations up: truth (journal) first, then control (identity,
policy, ledger, redaction), now flow (runtime, network door, proxy, CLI). Nothing user-facing
runs yet. Everything below is a library with tests, and each claim names the gate that proves it
([`docs/claims.md`](docs/claims.md) holds the exact conditions).

| Exists now | Proof (gate in [`gates.toml`](gates.toml)) |
|---|---|
| Canonical contracts (`uaos-contracts`): typed IDs, event envelope, Operation lifecycle, error registry, money, budget entries | unit and property tests; JSON Schemas in [`schemas/`](schemas/) (`schema-compat`) |
| Hash-chained journal, encrypted content-addressed chunks with crypto-shredding, rebuildable SQLite projections, OS keychain (`uaos-state`, `uaos-platform`) | `journal-durability`: the real journal is killed at random points (40 kills per OS per merge, 10,000 nightly) and no acknowledged record may be lost |
| Scoped credentials (`uaos-identity`): `uaos_sk_` keys stored only as keyed digests, a child's scope within its parent's, revocation and epoch bumps journaled before they return, a guard against restoring an old data directory | `test`: random hierarchies checked against an independent model, 256 per merge and 10,000 nightly; seeded negative `identity-epoch-check-skipped` |
| Fail-closed authorization over Cedar (`uaos-policy`): default deny, any evaluation error denies, Deny > Ask > Allow, a grant never beats a forbid | `policy-semantics`; p99 688 µs at 1,000 mixed policies on the reference machine ([ADR-0008](docs/adr/0008-authorization-semantics-over-cedar.md)) |
| Budget ledger (`uaos-ledger`): a reservation or outgoing transfer beyond the available balance is refused before anything is recorded; spend above a reservation is recorded as an S1 overrun | `budget-concurrency`: randomized simulation against a reference model, 256 schedules per merge and 100,000 nightly |
| The one outbound door (`uaos-egress`): only declared upstreams, by DNS name; the door resolves names itself and refuses private, link-local and metadata addresses in every spelling; TLS on aws-lc-rs against the system's roots, fetching nothing; redirects returned, never followed; the credential inserted last; errors say whether the request may have reached the provider. Built, not yet in any request path | `test` and `clippy`: an SSRF and header suite, bans on every other network path outside the door, each proven by a seeded negative |
| Secret redaction with a fail-closed final scan, 11 high-risk formats (`uaos-redact`) | `redaction-corpus`: synthetic corpus v2 (six evasion forms, 41 negative families). Recall is bound to the claimed formats and this corpus; it is not a real-world rate ([ADR-0009](docs/adr/0009-redaction-detectors-placeholders-final-scan.md)) |
| Merge gates: fmt, clippy (pedantic + restriction set), tests, architecture direction and guarded-lint owners, schema compatibility, SPDX headers, claim wording, cargo-deny, cargo-vet with an exemption ratchet, secret scan, DCO, docs-with-contract, CodeQL | every gate is proven to **fail** on a seeded violation: `cargo xtask negative` |

What does **not** exist yet: the runtime, the module socket, the proxy, the CLI, the panel and
every product module. No request flows through UAOS yet. Their gates are listed as pending in [`gates.toml`](gates.toml) and block a
release until they are active. The path ahead is in [`docs/roadmap.md`](docs/roadmap.md).

## Principles you can hold us to

- **Local first.** Data stays on your machine; every external contact is opt-in and visible.
- **Honest side effects.** If something cannot be undone, UAOS says so instead of claiming a rollback.
- **Fail closed where it matters.** Secret redaction, authorization, budget reservation and the
  journal never degrade silently; they refuse.
- **No paywall on safety.** Security, privacy, journal, basic budget, basic panel and basic
  adapters are Apache-2.0 and stay that way ([GOVERNANCE.md](GOVERNANCE.md)).
- **Measured claims only.** Every public claim links to the test, corpus and date behind it.

## Building

See [CONTRIBUTING.md](CONTRIBUTING.md) for setup. In short:

```sh
cargo xtask ci         # the full local merge fast lane
cargo xtask negative   # prove every gate bites
```

## Documents

- Architecture decisions: [`docs/adr/`](docs/adr/)
- Threat model: [`docs/threat-model/`](docs/threat-model/) · Privacy data flow: [`docs/privacy/`](docs/privacy/)
- Vision-to-cell traceability: [`docs/traceability.md`](docs/traceability.md) · Roadmap: [`docs/roadmap.md`](docs/roadmap.md) · Open decisions: [`docs/decisions.md`](docs/decisions.md)
- Security reporting: [SECURITY.md](SECURITY.md) · Conduct: [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md)

## License

Apache License 2.0 — see [LICENSE](LICENSE) and [NOTICE](NOTICE).
