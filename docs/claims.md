# Claims registry

Every public statement about what UAOS does or guarantees is listed here with the gate that
proves it and the conditions it holds under (CLAUDE.md red line 6). A claim that is not in this
table must not appear in the README, the docs or a release note. Forbidden words are rejected
automatically by `cargo xtask claims`.

| Claim | Holds under | Proven by | Since |
|---|---|---|---|
| No acknowledged critical journal record is lost when the process is killed | Process kill (`kill -9`, `TerminateProcess`); not power loss (balanced mode has a window W, ADR-0003) | `journal-durability`: 40 real kills per OS per merge, 10,000 per OS nightly | P1 |
| The journal is tamper-evident | Up to the last externally anchored checkpoint; never "tamper-proof" | chain verification tests (`uaos-state`) | P1 |
| Shredded content cannot be decrypted by UAOS or from a copy of the data directory | Keychain backends, if the OS keychain does not retain deleted entries; weaker with the passphrase vault (ADR-0007 §4) | chunk-store shred tests | P1 |
| Authorization denies by default and on any evaluation error, and a forbid always wins, over a grant too | Policy sets within the text bounds of ADR-0008 Amendment 1; time from the platform clock | `policy-semantics`: an applicable erroring policy always denies; slicing equals the complete set; native grants equal their permits (each proven to bite by a seeded violation) | P2 |
| A reservation or outgoing transfer beyond a pool's available balance is refused before anything is recorded | Prices and usage as reported. Spend above a reservation is recorded truthfully as an S1 overrun and can take a pool negative (`docs/reviews/WP2.2-ledger.md` M6) | `budget-concurrency`: 256 simulated schedules per merge, 100,000 nightly | P2 |
| Secrets of the claimed formats are redacted, and the final scan blocks on any detection | Detector set v1 (11 classes) measured on synthetic corpus v2 (six evasion forms, 40 negative families). **Not** a real-world recall rate. Not detected: free-form passwords outside URL userinfo, AWS secret access keys, encodings beyond the four views, and the URL edges listed in ADR-0009 "Limits" | `redaction-corpus` (two seeded negatives) | P2 |

**Not claimed yet**, because the gate does not exist yet: overhead budgets, drop-in compatibility,
prefix stability, sandboxing, approvals that need user presence. Each of these enters this table
only when its gate is active.
