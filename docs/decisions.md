# Decision register

Open decisions, their class, their default and their deadline. A decision that the next release
depends on carries a pending-decision marker, the token `cargo xtask decisions` searches for. That
command lists the markers on every merge, and `--release` makes it fail while any remain.
Decisions due in later phases are listed without a marker; it is added when their phase starts.

**Classes**
- **R, reversible:** decided within 24 hours. If unanswered by its deadline, it takes the recorded
  default, which is logged as a conscious assumption with a way back.
- **E, expensive:** 48 hours, an ADR, a threat/privacy note and a test plan. Never defaults.
- **RL, red line, money, external identity or external contact:** the maintainer's alone. Never
  defaults, and nothing is bought, created, moved or spent without an explicit decision.

Merges, publishing, spending and repository-setting changes never default, whatever the class.

## Due before the RC-1 release

| ID | Class | Decision | Recommended default | Deadline | Marker |
|---|---|---|---|---|---|
| D-08 | RL | Dedicated conduct address | A project mailbox once a legal entity or organisation exists | overdue (week 1) | in `GOVERNANCE.md` |
| D-19 | RL | Code-signing path | OV/EV certificate and Apple Developer ID, as an individual, started now. Without them RC-1 ships unsigned, with attestations and checksums and the friction documented | overdue (week 1) | PENDING-DECISION(D-19) |
| D-20 | R | Merge review rule with one maintainer | Every work package gets an adversarial review; the maintainer merges after reading it; a 24 h cool-off applies to crypto, `unsafe`, sandbox, contract freezes and gate removals. Applied as a conscious assumption; formalized by ADR-0019 | ADR-0019 window | PENDING-DECISION(D-20) |
| D-21 | RL | Live-provider evidence lane | Both providers, CI-only keys with provider-side spend caps, a protected environment. **Without it the RC-1 tag is blocked**, because live prefix stability is an RC-1 threshold | before WP3.0d | PENDING-DECISION(D-21) |
| D-22 | RL | Repository owner before release attestations | Move to an organisation before the RC-1 release work (WP3.9); attestations bind provenance to `owner/repo` | 2026-10-26 | PENDING-DECISION(D-22) |
| D-06 | E | Ingress from containers and WSL | Off; a Unix socket or named pipe first | P3 | PENDING-DECISION(D-06) |
| D-15 | R | Pricing updates | Manual; automatic updates opt-in | P3 (WP3.5) | PENDING-DECISION(D-15) |
| D-24 | E | Final-scan caching | Scan every byte; caching only with an equivalence proof and under budget pressure | WP3.8 | PENDING-DECISION(D-24) |
| D-26 | E | HTTP stack | hyper directly, no reqwest or axum (ADR-0013) | before WP3.2 | PENDING-DECISION(D-26) |
| D-27 | R | Default pocket for `uaos run` | Project root; budget pools bound explicitly, never by pocket inference | WP3.7 | PENDING-DECISION(D-27) |
| D-28 | E | Endpoint handling | Three classes, governed / metadata / denied, from a captured inventory | 72 h gate | PENDING-DECISION(D-28) |

## Later phases (no marker yet)

| ID | Class | Decision | Recommended default | Phase |
|---|---|---|---|---|
| D-17′ | RL | Subscription pass-through: the client keeps its own login and UAOS only forwards it | Off and legal-gated. A focused terms-of-service review runs in the RC-1 evidence window. RC-1 ships with it off, so RC-1 does not depend on it | ToS review |
| D-05 | R | Panel framework | Svelte + TypeScript, re-checked against the dependency-audit burden | P4 |
| D-11 | R | Telemetry | Opt-in, with a preview of the exact payload | P4 |
| D-04 | E | Windows exec before its sandbox backend is proven | Human-approved with user presence, never autonomous; WSL2 documented | P5 |
| D-02 | E | Encrypted search for notes and Obsidian | A bounded in-memory index rebuilt at unlock | P6A |
| D-10 | R | Tag identifiers | ASCII canonical IDs with Turkish and English aliases | P6 |
| D-07 | RL | Commercial modules at GA | They trail GA | before P7 |
| D-16 | E | Default trust mode | Same-user with honest claims; hardened mode as a GA option | P7 |
| D-13 | RL | Several keys of one provider | Rejected for evading limits; it would also break account-bound reasoning | GA legal gate |

## Decided

| ID | Decision | Where |
|---|---|---|
| D-01 | RC-1 dialects: Anthropic Messages and OpenAI Responses (stateless); Chat Completions in RC-2 | ADR-0005 |
| D-03 | Pipeline order: detect, route over permitted candidates, authorize, reserve, transform, final scan | ADR-0002 |
| D-09 | The private vision document stays out of the public repository; the traceability matrix is public | `docs/traceability.md` |
| D-12 | The repository path keeps its space; CI builds from a path with spaces and non-ASCII characters | `paths` gate |
| D-14 | Policy engine: Cedar with evaluation errors denied | ADR-0008 |
| D-18 | Default durability mode: balanced, W = 50 ms | ADR-0003 |
| D-25 | `kernel-tokens` gate moves from P2 to P3 | ADR-0002 amendment, ADR-0010 |
