# Vision → cell traceability

Every item of the original 61-item product vision is mapped to the engineering cells of
CLAUDE.md (C-01…C-61). Where the original wording made a claim the red lines forbid, or implied
an action with legal or ethical risk, the item is **reshaped** and the reason is stated. The
vision document itself stays private (plan D-09); this matrix is the public record of intent.

Legend: **mapped** — carried as stated in substance · **reshaped** — carried in a compliant
form · **deferred** — not in GA scope, post-GA RFC candidate · **activity** — launch work, not a cell.

| Vision # | Theme | Disposition | Cell(s) | Note |
|---|---|---|---|---|
| 1 | Drop-in base URL migration | mapped | C-01 | Drop-in is a contract with conformance tests, not magic (ADR-0005) |
| 2 | Bring your own key | mapped | C-02 | Keys stay in the OS keychain; agents receive scoped keys |
| 3 | Source-agnostic ingestion | mapped | C-03 | Byte-preserving dialect codecs |
| 4 | Profile portability | mapped | C-04 | Versioned schema, migrator, secret-free export |
| 5 | Open core | mapped | C-05 | Paid features only as separate modules (ADR-0001) |
| 6 | Ecosystem integration PRs | activity | — | Upstream docs PRs showing UAOS as a base URL (plan §8.5) |
| 7 | Shared budget pool | mapped | C-25 | |
| 8 | Role-based credit distribution | mapped | C-25, C-26 | Transfers default off, policy-gated |
| 9 | Sub-key hierarchy with limits | mapped | C-08, C-09 | |
| 10 | Priority bidding | reshaped | C-59 | Separate ledger, legal review, transparent reports; security never for sale |
| 11 | Community voting | mapped | C-59 | Anti-astroturfing |
| 12 | Session memory | mapped | C-12 | |
| 13 | Note layer | reshaped | C-16 | Injected notes are token-accounted and policy-controlled; no "zero cost" claim |
| 14 | @devam prompt repair | reshaped | C-14 | Honest side-effect warning; nothing is "rewound" |
| 15 | @yenipen window migration | reshaped | C-15 | Lossy by nature; visible diff and restore instead of a "no loss" claim |
| 16 | Tagged memory valves | mapped | C-16, C-18 | |
| 17 | Payload cleanser | mapped | C-24 | Tags stripped deterministically (prefix stability) |
| 18 | Context and quota routing | reshaped | C-31, C-32, C-52 | Context-size routing and cross-provider failover; rotating keys of one provider to evade rate limits is rejected (D-13) |
| 19 | Harness sniffing and emulation | deferred | C-33 | Profile templates instead; reverse-engineering third-party frameworks carries license/ToS risk |
| 20 | Harnesses as MCP servers | deferred | C-03, C-40 | Possible via the sidecar ecosystem after GA |
| 21 | Cross-harness live orchestration | deferred | C-04, C-12 | Journal-based session export/import is the honest substrate |
| 22 | Keep-alive heartbeats | reshaped | — (ADR-0005) | Keep-alive frames toward the local client only; nothing synthetic to providers |
| 23 | Bidirectional secret masking | mapped | C-53 | Fail-closed; rehydration only toward the originating client |
| 24 | Global and project rules | mapped | C-50, C-32 | Layered policy plus assertions |
| 25 | Context shield ("Jev") | reshaped | C-36, C-50 | Reasoning-orchestrator hook; the external reference is unknown, so no claims (A4) |
| 26 | Correction and bypass modes | reshaped | C-50, C-51 | Bypass only for non-red-line shields, with approval and audit; redaction cannot be bypassed |
| 27 | Isolated pockets | mapped | C-18 | |
| 28 | Blueprint generator | reshaped | C-19 | Assumptions, risks and open questions with confidence; no certainty claim |
| 29 | Obsidian knowledge compiler | reshaped | C-43 | Scoped opt-in; no autonomous scanning |
| 30 | @zeminle provisioning | mapped | C-37 | External notifications are policy-gated side effects |
| 31 | @git/ prompt-driven git | reshaped | C-38 | Approval, no hooks, sandbox; no silent background cloning |
| 32 | Live model swapping | mapped | C-31 | Turn-boundary by default |
| 33 | Routing valves | mapped | C-32 | |
| 34 | @oyung profile conditioning | mapped | C-33 | |
| 35 | Hyperparameter calibration | mapped | C-34 | Conservative presets, override audit |
| 36 | Live hooks | mapped | C-35 | Default off; SSRF/injection tests |
| 37 | @heart background tasks | mapped | C-45 | Visible task ledger and kill switch |
| 38 | Distributed anchors | mapped | C-46 | Cooperative surfaces only; not OS-level UI automation |
| 39 | UI reflexes | mapped | C-47 | |
| 40 | Synthetic crisis simulation | reshaped | — (test harness) | A policy-gated "drill" mode over the kernel's fault-injection points |
| 41 | Error translator | mapped | C-49 | Upstream errors stay byte-identical; translation is additive |
| 42 | Semantic breakpoints | mapped | C-50 | |
| 43 | Pre-flight failover | mapped | C-52 | Capped probe budget |
| 44 | Loop breaker | mapped | C-51 | Recall/precision targets, explain and override |
| 45 | Custom error styling | reshaped | C-54 | Local/private only; sanitized wherever output is shared |
| 46 | /hap refinement | reshaped | C-55 | Dry-run by default; apply needs coverage, mutation score and rollback |
| 47 | Benchmark and leaderboard | mapped | C-56 | Local first; publishing opt-in |
| 48 | Model throne swap | reshaped | C-57 | Shadow, canary, rollback; never silent |
| 49 | Hub for profiles and skills | mapped | C-59, C-41 | Signed packages, moderation |
| 50 | Community practices into core | reshaped | C-58 | Through RFC and review, not automatic absorption |
| 51 | Master key clustering | mapped | C-07 | |
| 52 | Sub-master networks | mapped | C-08 | |
| 53 | Hot upgrade between plans | mapped | C-10 | Ring 2; security never paid |
| 54 | Offline lock | mapped | C-11 | Ring 2, optional; deterrence, not DRM over safety |
| 55 | Fuzzy tag matching | mapped | C-20 | Dangerous tags require exact match and approval |
| 56 | IntelliSense and keyboard control | mapped | C-21, C-22 | |
| 57 | @uyg environment conditioning | mapped | C-42 | Diff view, reproducible apply/rollback |
| 58 | Isolated task terminal | mapped | C-39 | |
| 59 | @notal quick notes | mapped | C-16 | |
| 60 | @pring local pre-processing | mapped | C-24 | Local model under resource quotas |
| 61 | Cache double-buffering | reshaped | — (ADR-0005) | Cache-preserving transforms and a measured cache-hit metric; warm-up opt-in and budget-gated; no cost-avoidance claim |

Cells with no single vision item (they serve several): C-06 Rust kernel, C-13 Context Journal,
C-17 Reminder, C-23 NL intent, C-30 Spending UI, C-44 cross-project memory, C-48 capability
sandbox, C-60 localhost panel, C-61 AI panel editor.
