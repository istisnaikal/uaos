# Threat model — v0 (P0)

Living document; re-reviewed at every phase gate. "Proof" names the gate or suite that must
exist before the control can be claimed. Until a control's gate is active, the threat is
**open** and no claim is made about it.

## Assets

| Asset | Where | Why it matters |
|---|---|---|
| Provider API keys | OS keychain (or hardened-mode vault) | spend and account takeover |
| Prompts, outputs, tool payloads | encrypted chunks referenced from the journal | user code and data, may embed secrets |
| Journal and ledger | data directory | audit trail, budget truth |
| UAOS-issued scoped keys | hashed in state; plaintext only at issuance | agent identity |
| Configuration and policies | profile + config snapshots | what the agent is allowed to do |

## Trust boundaries

1. **Agent process ↔ UAOS ingress** (loopback). The agent is untrusted: prompt injection can turn
   any agent hostile (ADR-0004).
2. **UAOS ↔ model providers** (TLS). Contacted only to fulfil the user's own requests.
3. **UAOS ↔ tools, live hooks, remote MCP** (P5+). Outputs are untrusted data.
4. **UAOS ↔ local OS** (same user by default). Same-user processes are not isolated from the
   user's keychain; hardened mode adds an OS-user boundary.
5. **Panel browser ↔ control API** (loopback, P4+). Browsers are exposed to hostile web origins.

## Threats

| # | Threat | Planned control | Proof (gate) | Phase | Status |
|---|---|---|---|---|---|
| T1 | Prompt injection via tool output, documents, live hooks, skill/MCP descriptions, memory | provenance labels; tags only from the newest human turn; tool output is data; approvals for dangerous actions; capability blast radius | injection corpus (`prompt-injection-tool-hook-skill`) | P5–P6 | open |
| T2 | Secret leakage to providers, logs or exports | schema-agnostic detection + exact-bytes final scan, fail-closed; keys never sent to agents; payloads never logged; encrypted chunks; canaries | `redaction-corpus`, canary suite | P2–P3 | **detection and final scan active** (P2, ADR-0009: 11 classes, corpus v2 with evasion forms; retroactive review fixed); wiring into egress, canaries and rehydration P3 |
| T3 | Supply chain (dependencies, CI, releases) | cargo-deny, cargo-vet with imported audits, pinned toolchain, SHA-pinned Actions, least-privilege workflow tokens, signed artifacts, SBOM | `cargo-deny`, `cargo-vet`, `secret-scan` | P0 | **controls active** (release signing P3) |
| T4 | Local privilege escalation | runs as the user, never elevated; data dir owner-only; authenticated IPC | install tests | P1–P3 | open |
| T5 | SSRF and exfiltration | single egress path; resolve→verify→pin; private/link-local/metadata ranges blocked; redirects re-checked | SSRF suite | P3–P5 | open |
| T6 | Budget double-spend or undercount | single daemon per data dir; single-writer ledger; idempotency; InFlight never released; reconciler; full billing dimensions | `budget-concurrency`, `pricing-reconciliation` | P1–P3 | **ledger controls active** (P2: hard cap, single-use reservations, InFlight never released, crash recovery); periodic reconciler and pricing P3 |
| T7 | Panel takeover (DNS rebinding, CSRF, XSS) | loopback, Host allowlist, Origin check, one-time code → cookie, CSRF token, strict CSP | `panel-auth-csrf` | P4 | open |
| T8 | License tampering | Ring 2 only; cannot affect safety by construction | entitlement tests | P7 | open |
| T9 | Context poisoning | injection policy, provenance, pocket isolation, assertions | leakage tests | P6 | open |
| T10 | Autonomous destruction | default-deny exec/write/delete; compensable classes; dry-run; approvals; sandbox; global stop | `sandbox-escape`, approval tests | P5 | open |
| T11 | Local DoS by runaway agents | per-principal rate limits, admission control | chaos | P3 | open |
| T12 | Journal rewrite by a local attacker | exact-bytes hash chain; optional signed checkpoints anchored externally | tamper tests | P1 | open — **tamper-evident only** |
| T13 | The agent process itself (same user): reads keychain, forges approvals, edits config | user-presence approvals; peer-credential refusal for `uaos run` trees; config drift detection; hardened mode | approval-forgery suite | P2, P7 | open |

## P0 controls in force

- Lint wall: `unsafe` denied, panics denied, ambient clock/randomness/fs/process/env banned
  outside their owner crate (proven by seeded violations).
- Dependency policy: license allowlist, crates.io-only sources, banned crates, audit coverage.
- Secret scanning of the full git history on every merge.
- Contract integrity: any breaking schema change without a major bump fails the merge.

## Residual risks stated now

- Same-user mode cannot stop a determined local agent from reading the user's keychain (T13).
- Tools that a harness executes itself are only observable/vetoable in transit, not contained.
- The hash chain is tamper-evident, not tamper-proof, without external anchoring (T12).
