> This file is the project's working memory and reflex surface. Not an encyclopedia; it carries decisions, boundaries, actions, and verification.

## 1. Heart

**Project name:** `[WHIRLWIND T]`  
**Engineering name:** `UAOS` — Universal Agentic OS  
**Repo norm:** `uaos`

UAOS is a universal agentic operating layer that manages the context pollution, token/budget chaos, tool/environment fragmentation, error/loop crises, privacy stress, and interface complexity developers experience while working with AI agents, inside an open-source Rust infrastructure core that runs locally, has a transactional context journal, performs autonomous model/budget routing, is capability-based secure, and offers a keyboard-first localhost control room.

Category: Agentic Infrastructure OS.  
Launch standard: full power, production quality, measurable claim.  
Brand/slogan is the final work package; technical norm is `UAOS`.  
Prices are commercial parameters; the entitlement matrix is an architectural norm.

### Red lines

1. Data stays local; external contact is opt-in, minimized, and transparent.
2. Secrets are never logged raw anywhere; high-risk redaction operates fail-closed.
3. If there is an irreversible side effect, the system does not say “I rolled it back”; it gives an honest warning.
4. Autonomy does not take effect without capability sandbox + audit + policy/approval.
5. Security, privacy, journal, basic budget, basic panel, basic adapter are outside the paywall.
6. Claims are carried by metrics, baselines, and tests; “perfect / zero loss / quota-bending” language is forbidden.
7. Legal/ethical review of provider ToS, licensing, user data, and community funding is part of GA.
8. Performance physics is not violated; overhead is measurably minimal, speculative warm-up is permitted.
9. There is no dark pattern: a persistent external-world change cannot be invisible.
10. Unknowns are not fabricated; they are marked as a decision, a conscious assumption, or an option/default.

---

## 2. Nervous System

### Work start

1. Read this file.
2. Scan the phase, open decisions, risks, and gaps.
3. Propose the 1-3 highest-leverage moves.
4. Ask clearly about the point requiring critical approval.
5. If code is to be written, first define the contract, test path, security boundary, and observability point.

### Decision reflex

- Reversible decision: decide within 24 hours, no extension.
- Expensive decision: 48 hours + ADR + threat/privacy note + test plan.
- Red line: if no proof/control, veto; generate alternative.
- Ambiguity: at most 3 questions. If an assumption is required, mark `[CONSCIOUS ASSUMPTION]`.
- Do not change user intent; if there is a stronger path, propose it respectfully and with justification.
- Objection format: no / won’t do → proof → risk → alternative → decision request.

### Priority filter

Every task must pass at least four of these six questions:

- Which pain does it cut?
- Which metric moves?
- Which artery does it cement?
- Which risk does it close?
- Which contract does it test?
- Does it serve launch proof, or only motion?

### Freedom boundary

No micromanagement: if the goal, boundary, and quality threshold are defined, implementation choice is left to engineering intuition. Freedom is courage with a clear direction.

### Rhythm and recognition

- Daily: working output, blocker, moving metric.
- Weekly: is the user losing less context, burning less money, feeling less unsafe?
- Biweekly: what are we killing, what are we narrowing, which assumption is still up in the air?
- Recognition is only at a proven threshold and is a single sentence. Not ornament, but a seal.

---

## 3. Skeleton

### Architectural invariants

- 11 product layers + horizontal assurance spine; 61 GA cells.
- “Default off” = policy-gated; it does not mean absent.
- Main arteries:
  - Context: C-12, C-13, C-14, C-15, C-16, C-17, C-18, C-53
  - Economy: C-25, C-26, C-27, C-28, C-29, C-30, C-52
  - Security-Autonomy: C-09, C-35, C-37, C-38, C-39, C-40, C-41, C-43, C-44, C-45, C-48, C-61
- Core domain: Session, Pocket, Event, Request, BudgetPool, BudgetTransaction, Policy, Adapter, Tool, Anchor, Error, Profile, License, Package.
- Storage:
  - Transactional state: SQLite WAL
  - Append-only journal: JSONL + content-addressed blob + hash chain
  - Local search: SQLite FTS + optional local embedding
  - Sensitive data: encrypted at rest
- Provider:
  - OpenAI-compatible GA contract
  - Streaming, tool-call normalization, capability negotiation, unified error model
  - Drop-in is not magic; it is a contract.
- Identity:
  - BYOK
  - Master/sub key hierarchy
  - Scoped credentials
  - OS keychain/vault
  - No plaintext keys.
- Extension:
  - In-process trait: hot path
  - Out-of-process sidecar/MCP: tools, adapters, isolation
  - Optional WASM: portable plugins
  - Does not create a kernel source-patch requirement.
- Dependency direction: upper layers bind to lower contracts; lower layers do not depend on product decisions.
- Unsafe Rust is forbidden by default; exception requires ADR + owner + sanitizer/Miri + security review.
- Local model/embedding/index jobs carry CPU/GPU/RAM/disk/thermal quotas; under pressure, adaptive degradation, no crashes.

### Canonical contracts

- **Event:** id, session/pocket/request/correlation/parent ids, timestamp, actor, type, payload_ref, cost_estimate, compensable, side_effect_class, risk_tier, hash/prev_hash, metadata.
- **Adapter:** protocol, supports_streaming/tools/json/reasoning, max_context, pricing, error_codes, tool_schema_dialect, health_probe, compliance.
- **Policy:** subject, action, resource, condition, effect, max_amount, ttl, audit_level, compensable.
- **BudgetTx:** idempotency_key, pool/agent/session, type, amount, balance_before/after, reason_code, related_event, settled.
- **Profile:** schema_version, models, hyperparameters, tools allowlists/scopes, budget caps, privacy, ui keybindings/panels.
- **Package:** semver, publisher, signature, checksum, capabilities, resource limits, validated tool descriptions, SBOM, license, changelog.
- **Anchor:** stable id, surface, component path, lifecycle, auth scope, idempotent signal schema, fallback.
- **Error:** unified code, class, severity, sanitized user message, actionable agent message, remediation, secret_leak_risk, audit id.
- **Eval:** workload, category, sanitized/synthetic inputs, golden/rubric, quality/latency/cost/tool/privacy metrics, reproducibility, anti-cheat.

### Main flows

1. **Request:** ingress/auth → intent/risk → context load → redaction → budget precheck/reserve → policy → routing explain → adapter → execution/stream monitor → journal commit → settlement → panel/trace.
2. **@devam:** detect dirty event; warn if side-effect is not compensable; isolate context; prompt stitch; write repair event.
3. **@yenipen:** extract summary/decision log; show retained/dropped/summarized diff; hydrate new window; archive old; leave rollback point.
4. **Tool/Git/Terminal:** policy allow/deny/approval → sandbox profile → dry-run/diff if risky → isolated process → sanitized artifact → compensable flag → supervisor cleanup.
5. **Memory/Obsidian/Cross-project:** scoped consent → encrypted local index → redaction → provenance → injection policy auto/ask/never → journal trace.
6. **Crisis/Loop:** repeat/stagnation/error detect → break/fallback → explain → budget reserve close → assertion quarantine if needed → audit.
7. **Budget transfer:** idle/priority/cap policy → idempotency key → atomic ledger → explain event → retry safe.
8. **Model throne:** local eval → constraints → shadow → canary → promote/rollback.
9. **Panel NL:** intent → dry-run diff → approval → transactional config → audit/rollback.
10. **Release:** GA gates → signed build/SBOM → canary → SLO watch → promote/kill switch → docs/changelog.

### Feature map and scope contract

All cells are GA. Common completion: contract, unit/integration test, threat/privacy note, observability, documentation, rollback/kill switch, default state, explainability. The following lines carry only cell-specific boundary/proof.

#### Layer 1 — Integration

- C-01 Drop-in: migration via base_url/master_api; OpenAI-compatible conformance + migration guide.
- C-02 BYOK: local vault/keychain; secret scan CI + log redaction proof.
- C-03 Source-Agnostic: adapter ABI + capability negotiation; plugin isolation tests.
- C-04 Profile portability: versioned TOML/JSON + migrator; secret-free export.
- C-05 Open-core/freemium: Apache-2.0 boundary; build-from-source + license matrix.
- C-06 Rust kernel: single async binary; extension host + soak tests; no source-patch ecosystem.

#### Layer 2 — Identity/entitlement

- C-07 Master clustering: key hierarchy + revocation propagation tests.
- C-08 Sub-master derivation: TTL/rotation/scope enforcement; child key leak drills.
- C-09 Scoped keys: policy grammar + denial proofs; no implicit privilege.
- C-10 License guard/entitlement: plan matrix + hot-upgrade state tests; security never paid.
- C-11 Offline lock: signed blob + monotonic counter + grace; crypto threat model; optional proprietary.

#### Layer 3 — Context/memory

- C-12 Session memory: durable session_id; kill -9 critical event loss 0.
- C-13 Context Journal: append-only hash chain; redaction/compaction/replay tests.
- C-14 @devam: text/context repair; honest side-effect warning; compensable registry.
- C-15 @yenipen: lossy checkpoint allowed; visible diff + restore previous window.
- C-16 @notal: pocket-scoped notes; injection policy + PII redaction.
- C-17 Reminder: reminder scoring/decay/snooze; precision tests.
- C-18 Pockets: isolation + controlled hydration; leakage tests.
- C-19 Blueprint: assumptions/risks/open questions/confidence; human approval gate.

#### Layer 4 — Intent/tag

- C-20 Fuzzy tags: risk-tiered; dangerous tags exact/approval.
- C-21 IntelliSense: local index + context ranking; latency SLO + privacy.
- C-22 Keyboard-first: Cmd+K/Vim/cross-platform keymap; a11y tests.
- C-23 NL intent: allowlisted actions; confirmation + injection tests.
- C-24 Tag registry/payload cleanser: canonical tags + metadata strip; @pring local reformatter.

#### Layer 5 — Economy

- C-25 Liquid pool: pool accounting/reservation; concurrency proofs.
- C-26 Credit transfer: default off/policy-gated; idempotent transfer + reason codes.
- C-27 Cost metering: pricing normalization + local resource model; metering corpus.
- C-28 Caps: soft warn/hard stop 100%; emergency stop drills.
- C-29 Budget ledger: append-only audit/settlement/refund; tamper evidence.
- C-30 Spending UI: real-time pools/credits/health; information hierarchy review.

#### Layer 6 — Routing/reasoning

- C-31 Model swap: turn-boundary default; stream continuity proofs.
- C-32 Routing policy: DSL + explainability + conflict detection.
- C-33 @oyung: profile policy; dependency graph + apply/rollback; distinct from @uyg.
- C-34 Hyperparam calibration: conservative presets + confidence threshold + override audit.
- C-35 Live hooks: default off; allowlist, sanitize, TTL, SSRF/injection tests.
- C-36 Jev/System-2: `[CONSCIOUS ASSUMPTION]` ReasoningOrchestrator abstraction; no quota bending; compliance/cache coherence tests.

#### Layer 7 — Environment/tools

- C-37 @zeminle: signed packages, quotas, provisioning audit, rollback.
- C-38 @git/: no hooks default, sandbox, approval, submodule RCE tests.
- C-39 Isolated terminal: supervisor/no-exec default; platform escape tests + zombie cleanup.
- C-40 MCP valves: schema validation + description linting + tool output injection tests.
- C-41 Skill injection: signed manifest/version pinning/capability grants; malicious package tests.
- C-42 @uyg: deterministic environment bundle; diff view + reproducible apply/rollback.
- C-43 Obsidian: scoped opt-in, encrypted index, redaction, export/delete.
- C-44 @chatt cross-project: provenance, PII scrub, wrong-project leakage tests.

#### Layer 8 — Parallelism/reflex

- C-45 @heart: visible task ledger, quotas, kill switch; zombie/budget tests.
- C-46 Anchors: registry, auth signals, stale detection; idempotent delivery.
- C-47 Reflexes: event bus priority/backpressure/focus safety; p95/p99 SLO.

#### Layer 9 — Crisis/security

- C-48 Capability sandbox: default-deny, egress control, audit; threat model + escape tests.
- C-49 Error translator: sanitized actionable messages; no secret/path leak proofs.
- C-50 Context assertions: DSL, fail-closed high-risk, false-positive policy.
- C-51 Loop breaker: detection catalog, precision/recall targets, explain/override.
- C-52 Pre-flight: capped probes, circuit breaker, fallback validation; probe budget.
- C-53 @api masking: bidirectional redaction, canary, fail-closed; recall ≥99.9, FP ≤0.5.
- C-54 Custom errors: local/private free; public/log sanitized; harassment/secret filtering.

#### Layer 10 — Ecosystem/evaluation

- C-55 /hap: diagnostics/dry-run/supervised apply; coverage gate + mutation/rollback.
- C-56 Benchmark: local eval first; reproducible workload + anti-cheat; public opt-in.
- C-57 Throne change: shadow/canary/rollback; migration validation proofs.
- C-58 Open-core evolution: DCO/CODEOWNERS/security review/SBOM/signed releases.
- C-59 Hub/voting/priority bets: separate ledger, anti-astroturfing, transparent reports; not runtime budget.

#### Layer 11 — Control room

- C-60 Localhost panel: 127.0.0.1 bind, token auth, CSP, timeline/budget/valves/errors; pen test + WCAG 2.2 AA.
- C-61 AI panel editor: read-only/dry-run default, diff approval, rollback, permission scopes; prompt injection tests.

---

## 4. Muscle and Reflex

### Security and privacy

Bulletproofing does not mean the threat never arrives. If it arrives, it is contained, leaves a trace, raises an alarm, and does not kill the system.

- Default-deny: exec, network, write, secret, spend, config-change.
- Capability grants: fs read/write/delete, network domain/any, exec/thread, secret access/override, model/tool/MCP call, budget spend/transfer, UI config, cross-project/Obsidian read.
- Every grant carries TTL, scope, approval, audit, compensable flag.
- Threat model must stay current: prompt injection, secret leak, supply chain, local privilege escalation, SSRF/exfil, budget race, panel takeover, license tamper, context poisoning, autonomous destruction.
- Privacy: data-flow diagram, minimization, opt-in telemetry/benchmark, scoped consent, encrypted local index, retention, export/delete, PIA for high-risk cells.
- Crypto: modern audited primitives; no custom crypto; license signed blob + monotonic counter + revocation; local index/export encryption.
- Dependencies: cargo deny, audit, SBOM, reproducible builds, signed artifacts, malicious package quarantine.

### Performance and reliability

- Install to first value ≤ 3 min.
- Local overhead p95 ≤ 25 ms, p99 ≤ 75 ms excluding provider/network.
- Policy/routing decision p99 ≤ 1 ms excluding I/O.
- Journal durability: kill -9 critical event loss 0.
- Redaction: recall ≥ 99.9%, false positive ≤ 0.5%, high-risk fail-closed.
- Budget hard cap: 100% pre-request stop.
- Loop breaker: real loop recall ≥ 90%, useful iteration precision ≥ 92%.
- Crash-free session ≥ 99.95%.
- Panel interaction p95 ≤ 100 ms; realtime update ≤ 250 ms; anchor signal p95 ≤ 10 ms.
- Stream backpressure bounded; no memory blowup.
- Local model resource ceiling with adaptive degradation.
- Error budget per SLO; breach triggers freeze/harden/rollback, not feature acceleration.

### Test gates

CI merge blocker:

- fmt/clippy/test
- secret scan
- cargo deny
- adapter conformance
- journal durability
- budget concurrency
- redaction corpus
- sandbox escape
- panel auth/CSRF
- profile migration
- a11y critical flows
- perf smoke
- docs-changed-with-contract

Required behaviors:

- @devam side-effect honesty
- @yenipen diff/restore
- budget double-spend
- prompt injection via tool/live hook/skill
- cross-project consent
- /hap dry-run without coverage cannot apply
- malicious package
- disk full
- pricing reconciliation
- fuzzy dangerous tag
- sync conflict
- benchmark privacy

Test types:

- Property-based: ledger, policy, hash chain, fuzzy
- Fuzz: adapters, manifests, payloads, panel API
- Chaos: provider, disk, clock, permission, malicious, loop, race
- Soak: 24-72h
- Mutation testing: /hap, ledger, policy, redaction

### Observability

- Every request carries correlation/request/session/pocket/agent/tool/provider/budget/policy ids.
- Structured redacted logs.
- OpenTelemetry-compatible traces.
- Metrics: overhead, cost, errors, loop breaks, redaction, journal latency, panel interaction.
- `uaos doctor`: port, permissions, sandbox, keys, disk, provider health, clock, license.
- Alerts:
  - S1: secret leak, RCE, data loss, budget runaway
  - S2: durability/crash/provider cascade
  - S3: UX/perf degradation
- Incident: kill switch, feature flag rollback, signed hotfix, disclosure, postmortem.

### Developer experience and documentation

- Single binary.
- Installers: brew, deb/rpm, exe/msi, cargo, tarball.
- Commands: init, doctor, serve, profile, test.
- Docs: architecture handbook, API/event/policy/profile/package/anchor/error/eval references, security whitepaper, privacy data-flow, troubleshooting, migration notes, ADR log, contributor guide.
- Examples runnable, secret-free, cover real pain:
  - @devam recovery
  - secret masking
  - budget cap
  - sandboxed git
  - keyboard flow
- Accessibility: keyboard-only, screen reader, focus order, contrast, reduced motion; WCAG 2.2 AA critical flows.
- i18n: TR/EN initial; local keymaps.

### Open-source discipline

- Core Apache-2.0; SPDX; no security/privacy paywall.
- DCO required; CLA only with legal review.
- CODEOWNERS critical modules.
- Architecture changes via RFC + ADR.
- PR answers: pain, cell, risk, proof, docs, breaking/migration.
- Security disclosure channel, embargo, CVE/advisory, S1 escalation.
- Releases semver, signed, SBOM, reproducible, changelog, migration notes.
- Extensions/packages signed manifest, capability grants, version pinning, checksum, publisher trust, moderation.
- Priority bets/community funding separate ledger, legal/finance policy, transparent reports.

---

## 5. Gate

### Definition of Done

A task is done if:

- Behavior implemented and proven by tests.
- Contract/event/policy/API/doc updated.
- Threat/privacy impact assessed.
- Performance budget checked.
- Observability and explainability added.
- Rollback/kill switch/feature flag, if any, specified.
- License/open-source compatibility checked.
- Example/demo flow updated.
- Unknowns marked as question/assumption.
- No side effect contrary to the vision was left.

### Release readiness

Go/no-go:

- Stable signed release, SBOM, dependency audit, reproducible build.
- Migration plan and rollback tested.
- Threat model, privacy data-flow, security scan current.
- Perf/soak/chaos/accessibility gates passed.
- Dashboards, alerts, runbooks, support/incident process ready.
- Docs/examples/changelog/known limitations transparent.
- 0 critical security incidents, 0 secret leaks.
- Pilot retention/value targets met; launch assets reproducible.
- All 61 cells GA sign-off or explicitly deferred with written rationale.

### Anti-patterns

- Deferring critical gaps to “later”.
- Postponing security, licensing, documentation, testing.
- Logging secrets, scanning data without authorization, exposing the panel to remote access.
- Enabling autonomous action without audit/approval.
- Misleading language such as “quota-bending”, “zero loss”, “perfect”, “we rewound time”.
- Applying refactor without test/rollback.
- Saying it works and treating it as done.
- Producing ornate terms, empty manifestos, repeated slogans.
- Optimizing without measuring, hiding complexity, losing the whole while dividing it into parts.

### Final word

This file does not answer; it gives direction.  
Every brilliance that oversteps the boundary is debt.  
Every speed backed by proof is valuable.