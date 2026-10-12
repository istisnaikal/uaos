# UAOS — Universal Agentic OS

> Engineering name `UAOS`; product brand to be decided (final work package). Repository norm: `uaos`.

UAOS is a local, single-binary Rust kernel that sits between AI agents and the models and tools
they use. Every model call, tool call and state change becomes an **Operation** that is
authenticated, authorized, priced against a hard budget, redacted, journaled (write-ahead,
hash-chained) and explained. Product features attach to that lifecycle through versioned
contracts; they are never compiled into it.

## Status: P0 — Bedrock (pre-alpha, nothing to run yet)

This repository is at the very start of its plan. What exists today:

| Exists now | Proof |
|---|---|
| Canonical contracts (`uaos-contracts`): typed IDs, event envelope, Operation lifecycle, error registry, money, budget entries | unit + property tests; JSON Schemas in [`schemas/`](schemas/) |
| Platform boundary (`uaos-platform`): clocks and randomness with deterministic simulation twins | seed-reproducibility property tests |
| Merge gates: fmt, clippy (pedantic + restriction set), tests, architecture direction, schema compatibility, SPDX headers, cargo-deny, cargo-vet, secret scan, DCO, docs-with-contract | every gate is proven to **fail** on a seeded violation: `cargo xtask negative` |

What does **not** exist yet: the journal, policy engine, ledger, redaction, proxy, CLI, panel
and every product module. Pending gates for them are listed in [`gates.toml`](gates.toml) and
block any release until they are active. No claim in this README goes beyond what CI proves.

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
- Vision-to-cell traceability: [`docs/traceability.md`](docs/traceability.md)
- Security reporting: [SECURITY.md](SECURITY.md) · Conduct: [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md)

## License

Apache License 2.0 — see [LICENSE](LICENSE) and [NOTICE](NOTICE).
