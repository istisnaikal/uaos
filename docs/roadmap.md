# Roadmap

Where the UAOS kernel is going, in what order, and which gate proves each step. The order is
foundations first: nothing is built on a layer whose proofs are still missing. Dates are targets;
**gates decide**. A missed proof moves a date. It never lowers a threshold.

Each phase has two exits:
- **Build exit:** code, tests, decisions and docs are merged, and the phase's gates are active.
- **Evidence exit:** proof that needs time has accumulated: nightly streaks, per-OS numbers,
  live-provider runs, pilots, reviews. Evidence counts only if it was produced by the exact code
  being released.

## Where we are

**Current phase:** P3

| Phase | What it builds | State |
|---|---|---|
| P0 Bedrock | Contracts, platform boundary, merge gates that are proven to bite | built |
| P1 Truth | Hash-chained journal, encrypted chunks, projections, OS keychain | built. Owed: the passphrase vault for hosts without a keychain; chunk durability joining the journal's flush schedule (ADR-0018) |
| P2 Control | Scoped credentials, Cedar authorization, budget ledger, secret redaction | built. Owed: the signed threat-model review that closes the phase |
| P3 Flow → **Kernel RC-1** | Runtime, the one network door, the module socket, proxy for Anthropic Messages and OpenAI Responses clients, CLI, pricing, release pipeline | **in progress.** First move: the module socket and the first governed Operation, end to end against a local mock provider |

Work owed by finished phases is tracked as `phase-debt` and must be repaid before RC-1. The
current phase above is checked against [`gates.toml`](../gates.toml) and the README on every
merge.

## Kernel RC-1

**Target:** a release-candidate go/no-go on **2026-11-12 at the earliest**, preceded by a two-week
evidence window in which only fixes land, no features.

**What RC-1 means.** Unmodified coding agents that use API keys point at UAOS with a base URL, or
run under `uaos run --`. Every request that passes through UAOS is then:
- journaled (no acknowledged record lost to `kill -9`);
- redacted (fail-closed for the claimed secret formats);
- hard-capped (overspend 0, pricing reconciled);
- policy-checked (default deny) and explained.

**Bars RC-1 has to clear:**
- zero UAOS-caused signature, cache or recovery regressions against a live provider;
- local overhead p95 ≤ 25 ms at 400k-token histories;
- install to first value in ≤ 3 minutes.

**Not in RC-1:**
- the panel;
- running tools through UAOS (denied until the sandbox exists);
- the feature modules;
- OpenAI Chat Completions (RC-2);
- subscription logins (pending a terms-of-service review).

## After RC-1

| Phase | Builds |
|---|---|
| RC-2 | Chat Completions dialect, more build targets, power-loss testing, reproducible builds |
| P4 Surface | Localhost control panel, profiles with conflict-safe import, accessibility, keyboard-first flows |
| P5 Containment | Per-OS sandbox, terminal and git tools, MCP valves, signed packages |
| P6 Capability modules | Context repair and checkpoints, notes and pockets, routing, loop breaking, assertions, anchors |
| P7 Evaluation | Refinement, local benchmarks, model changes with canary and rollback, community hub client |
| P8 Launch hardening | Soak and chaos campaigns, external security audit, accessibility audit, legal review, signed installers |

GA is set by these gates, not by a date. Every one of the 61 product cells is either GA, with
its proof, or deferred in writing.

## How to follow along

- Gates and their status: [`gates.toml`](../gates.toml)
- Decisions and their deadlines: [`docs/decisions.md`](decisions.md)
- Why things are the way they are: [`docs/adr/`](adr/)
- What we defend against: [`docs/threat-model/`](threat-model/)
