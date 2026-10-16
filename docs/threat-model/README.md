# Threat model — v1 (P2 exit, P3 entry)

Living document; re-reviewed at every phase gate. "Proof" names the gate or suite that must
exist before the control can be claimed. Until a control's gate is active, the threat is
**open** and no claim is made about it.

**What changed from v0 (P0):**
- Statuses now reflect what P1 and P2 actually built.
- The scoped-credential assets are added.
- Two trust boundaries are added: in-process modules and the CI pipeline.
- Rows T14 to T19 are added. T14 to T17 come from plan v2. T18 and T19 come from the design
  review of the first P3 move (ADR-0010 Revision 1, ADR-0013, ADR-0014).

## Assets

| Asset | Where | Why it matters |
|---|---|---|
| Provider API keys | OS keychain (or hardened-mode vault) | spend and account takeover |
| Prompts, outputs, tool payloads | encrypted chunks referenced from the journal | user code and data, may embed secrets |
| Journal and ledger | data directory | audit trail, budget truth |
| UAOS-issued scoped keys | only their HMAC digests in state; plaintext shown once at issuance | agent identity |
| Identity key and revocation counter | OS keychain (ADR-0011) | forging or resurrecting credentials |
| Per-pocket placeholder key (P3) | next to the pocket's keys; shredded with the pocket | linking placeholders back to secrets |
| Configuration and policies | profile + config snapshots | what the agent is allowed to do |

## Trust boundaries

1. **Agent process ↔ UAOS ingress** (loopback). The agent is untrusted: prompt injection can turn
   any agent hostile (ADR-0004).
2. **UAOS ↔ model providers** (TLS). Contacted only to fulfil the user's own requests.
3. **UAOS ↔ tools, live hooks, remote MCP** (P5+). Outputs are untrusted data.
4. **UAOS ↔ local OS** (same user by default). Same-user processes are not isolated from the
   user's keychain; hardened mode adds an OS-user boundary.
5. **Panel browser ↔ control API** (loopback, P4+). Browsers are exposed to hostile web origins.
6. **Kernel ↔ in-process modules** (Ring 1, P3). Modules are **trusted code with minimized
   authority**, not contained code.
   - They get no network, file or process handle; every effect is a child Operation
     (ADR-0010 Revision 1).
   - A hostile in-process module is out of scope for containment. Untrusted code waits for
     sidecars (P5).
7. **Repository ↔ CI and release pipeline.** Merges, live-provider keys (T15) and release
   signing pass through GitHub Actions.

## Threats

| # | Threat | Planned control | Proof (gate) | Phase | Status |
|---|---|---|---|---|---|
| T1 | Prompt injection via tool output, documents, live hooks, skill/MCP descriptions, memory | provenance labels; tags only from the newest human turn (a codec role, ADR-0014); tool output is data; approvals for dangerous actions; capability blast radius | injection corpus (`prompt-injection-tool-hook-skill`) | P3–P6 | open |
| T2 | Secret leakage to providers, logs or exports | schema-agnostic detection + exact-bytes final scan, fail-closed; the provider key injected only after the final scan, at the door; keys never sent to agents; payloads never logged; encrypted chunks; canaries | `redaction-corpus`, canary suite, end-to-end canary (P3) | P2–P3 | **detection and final scan active** (P2: 11 classes, corpus v2, retroactive review closed). In the request path from the first P3 move |
| T3 | Supply chain (dependencies, CI, releases) | cargo-deny, cargo-vet with an exemption ratchet, pinned toolchain, SHA-pinned Actions, least-privilege workflow tokens, signed artifacts, SBOM, platform-enforced merges (ADR-0019) | `cargo-deny`, `cargo-vet`, `vet-ratchet`, `secret-scan`, `codeql`, `merge-gate` | P0–P3 | **controls active.** Merge enforcement holds only while the ADR-0019 ruleset is applied (check: `gh api repos/<owner>/<repo>/rules/branches/main`). Release signing: WP3.9 |
| T4 | Local privilege escalation | runs as the user, never elevated; data dir owner-only; authenticated IPC | install tests | P1–P3 | open |
| T5 | SSRF and exfiltration | one egress door that owns DNS: resolve → verify against blocked ranges (private, link-local, metadata, IPv4-compatible IPv6, 6to4, Teredo, the local-use NAT64 prefix, `3fff::/20`, decimal/octal forms; IPv4-mapped and well-known NAT64 addresses get their IPv4 address's verdict) → pin; no redirects and no retries; plain HTTP only to pinned local addresses, never resolved; a declared private upstream reaches loopback, private and unique-local addresses, never link-local, IPv6 metadata endpoints or IPv6 forms that embed an IPv4 address; TLS verified by rustls against local roots, so a server's certificate cannot trigger fetches (ADR-0013 Amendment 1A); caller credential headers refused, and methods other than GET, HEAD, POST, PUT, PATCH, DELETE and OPTIONS (TRACE would echo the credential back); only the runtime reaches the door; modules have no network or TLS crate; the resolve, connect, local-IPC, listen, UDP, HTTP-client, file-system (a UNC path reaches the network) and spawn entry points listed in `clippy.toml` banned outside their owners, each with a canary that fails clippy on every CI system where its ban stops firing, and no lint override outside the root configuration (`cargo xtask allow-audit`) | egress SSRF suite, `arch-check` and clippy-ban negatives, zero-egress capture (owed, M3) | P3–P5 | open: **controls built** in PR-5 (not yet merged); residuals: network-specific NAT64 prefixes and cloud host endpoints on public unicast (reachable only over HTTPS with a verified certificate), no revocation checking at RC-1, a root store that `SSL_CERT_FILE`/`SSL_CERT_DIR` can replace, credentials in the query string, entry points in third-party crates that are not on the ban lists (kept out by `arch.toml`, the enabled features and supply-chain review); network locations that look local or bypass the platform's `Fs` (the SQLite file, which rusqlite opens by path; mapped drive letters; links or junctions to shares inside the data directory; a UNC current directory; macOS automount paths): `OsFs` refuses UNC and device paths in every prefix spelling (DOS device names in a last component pass; UAOS names the files it opens), and refusing network locations for the data directory belongs to the configuration the bin reads (M3); Cargo configuration outside the repository; a contributor with write access, who could edit the gates themselves (the boundary there is review, CODEOWNERS and the `main` ruleset, PD-17); fake-IP proxies answering in `198.18.0.0/15` are refused |
| T6 | Budget double-spend or undercount | single daemon per data dir; single-writer ledger; idempotency; InFlight never released; one critical record for reserve + intent; reconciler; full billing dimensions | `budget-concurrency`, `pricing-reconciliation` | P1–P3 | **ledger controls active** (P2: cap on reservations and outgoing transfers, single-use reservations, crash recovery that settles at full cost). After a crash in balanced mode, an open reservation is settled at full cost, never released, because a power loss can lose the record that execution began. Pricing and reconciler: P3 |
| T7 | Panel takeover (DNS rebinding, CSRF, XSS) | loopback, Host allowlist, Origin check, one-time code → cookie, CSRF token, strict CSP | `panel-auth-csrf` | P4 | open |
| T8 | License tampering | Ring 2 only; cannot affect safety by construction | entitlement tests | P7 | open |
| T9 | Context poisoning | injection policy, provenance, pocket isolation, assertions | leakage tests | P6 | open |
| T10 | Autonomous destruction | default-deny exec/write/delete; compensable classes; dry-run; approvals; sandbox; global stop | `sandbox-escape`, approval tests | P5 | open. Tool execution through UAOS is denied until the sandbox exists |
| T11 | Local DoS by runaway agents or modules | per-principal rate limits, admission control with a bounded queue, bounded CPU pool with deadlines | chaos; DST with stalled modules | P3 | open: controls being built in the first P3 move |
| T12 | Journal rewrite by a local attacker | exact-bytes hash chain; optional signed checkpoints anchored externally | tamper tests | P1, P4 | open — **tamper-evident only** |
| T13 | The agent process itself (same user): reads keychain, forges approvals, edits config | scoped credentials (built, P2); user-presence approvals (ADR-0012); peer credentials and containment as defence in depth; config drift detection; hardened mode | approval-forgery suite | P2, P3, P7 | open. Scoped credentials are active; presence approvals arrive in WP3.6 |
| T14 | **Common-mode verification failure:** tests share the code's assumptions (AI-written code and tests) | fresh-context adversarial review per work package; independent oracles (reference models, gitleaks rules, the provider's binding check); mutation testing; an independent corpus; the final scan kept independent of the shared tokenizer; external audit | V1 reports in `docs/reviews/`, nightly mutants, differential tests | P2–P8 | **partial**: reviews and nightly mutants run; independent corpus (PD-11) and external audit owed |
| T15 | **CI as an attack surface for live keys** | CI-only keys with provider-side spend caps; a protected environment that only `main`'s schedule and manual dispatch reach, never fork pull requests; monthly rotation; a canary scan over job logs | workflow review; log canary | P3 | open: the lane is defined; keys are created by the maintainer |
| T16 | **Keyless hosts** (no OS keychain) | a loud failure today; a passphrase vault with an honest, weaker shred guarantee, shown in a banner and in `doctor` (PD-05) | vault tests on a headless Linux runner | P3 | open (PD-05) |
| T17 | **Exfiltration through rehydration:** an injected instruction makes the model put a placeholder into a network-reaching tool call, and rehydration would turn it into the plaintext secret | `secret.rehydrate` policy: text and declared file-edit tools only by default (ADR-0017); the recorded inverse map; a per-session known-secret matcher in the final scan; journaling | `rehydration-exfil` behavior | P3 | open (second P3 move) |
| T18 | **In-process module misbehaviour:** a stall, a panic, a flood of declarations, payload smuggled out through veto reasons or labels, runaway child Operations | no I/O handles (effects only as child Operations); declarations use manifest-declared codes, never free text; CPU stages and hooks on a bounded pool with deadlines, strikes and quarantine; degradation to modules-off; panic containment with a hook that never prints the message; child depth ≤ 2 and per-module quotas | negatives `hook-panic-escapes`, `panic-message-logged`, `child-op-depth-exceeded`, `manifest-veto-fail-open-high-risk`; DST with module faults | P3 | open: being built (first P3 move, train B) |
| T19 | **Parser differential and decoding bombs:** UAOS and the provider read the same bytes differently (duplicate keys, deep nesting, number edge cases, lone surrogates, BOM, invalid UTF-8), or a compressed body expands without bound | the structural tokenizer rejects ambiguous input fail-closed; depth and size limits; bounded decompression; the final scan independent of the tokenizer; fuzzing | `uaos-json` fuzz targets (nightly), tape differential against the old tokenizer | P3 | open: being built (first P3 move) |

## Controls in force (P0–P2)

- **Lint wall.** `unsafe` is denied, as are panics, and ambient clock, randomness, filesystem,
  process and environment use is banned outside the owning crate. Each ban is proven by seeded
  violations.
- **Guarded lints.** They may be switched off only under owner paths (`allow-audit`).
- **Dependency policy.** A license allowlist, crates.io-only sources, banned crates, audit
  coverage, and an exemption ratchet.
- **Secret scanning** of the full git history on every merge, plus CodeQL.
- **Contract integrity.** Any breaking schema change without a major bump fails the merge.
- **Journal.** Hash-chained, kill-safe for acknowledged records (`journal-durability`).
- **Authorization.** Fail-closed Cedar evaluation: default deny, deny on error, forbid wins
  over grants (`policy-semantics`).
- **Ledger.** Reservations and outgoing transfers beyond the balance are refused before
  anything is recorded (`budget-concurrency`).
- **Redaction.** 11 classes with a fail-closed final scan (`redaction-corpus`).
- **Scoped credentials.** Digests only, child within parent, journaled revocation, restore
  guard.

## Residual risks stated now

- Same-user mode cannot stop a determined local agent from reading the user's keychain (T13).
- Tools that a harness executes itself are only observable/vetoable in transit, not contained.
- Some client traffic goes directly to the provider by the client's own design (for example
  Claude Code's fast-mode check and WebFetch domain check, CC-11) and never passes through UAOS.
- The hash chain is tamper-evident, not tamper-proof, without external anchoring (T12).
- In-process modules are trusted code; minimizing their authority is not containment (T18).
- Merge integrity rests on one maintainer plus platform rules and adversarial reviews; it is
  weaker than a second human reviewer (ADR-0019).

## Sign-off

v1 was drafted on 2026-10-15 for the P2 exit (plan v2 PD-10) and the P3 entry. The review is
single-signer by design (plan v2 §13.6): the maintainer plus the attached adversarial reviews
(`docs/reviews/WP2.1-policy.md`, `WP2.2-ledger.md`, `WP2.3-redact.md`, `WP2.4.md`).

**Signed:** v1 was signed by the maintainer on 2026-10-15 as the single signer. The sign-off was
given as an explicit instruction in the working session and is recorded here by the assistant on
the maintainer's behalf. It closes plan v2 PD-10, the P2 exit condition. The residual risks
above are accepted as stated. Rows marked open stay open until their gates are active.
