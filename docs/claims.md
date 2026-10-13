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
| Authorization denies by default and on any evaluation error | The policy set loaded by `uaos-policy` | proptest `evaluation_errors_never_allow`, ADR-0008 | P2 |
| The budget cap cannot be exceeded by the ledger | Prices and usage as reported; estimation error before settlement is shown, not hidden | `budget-concurrency`: 256 simulated schedules per merge, 100,000 nightly | P2 |
| Secrets of the claimed formats are redacted, and the final scan blocks on any detection | Detector set v1 (11 classes) and synthetic corpus v1. **Not** a real-world recall rate; free-form passwords and encoded secrets are not detected (ADR-0009) | `redaction-corpus` | P2 |

**Not claimed yet**, because the gate does not exist yet: overhead budgets, drop-in compatibility,
prefix stability, sandboxing, approvals that need user presence. Each of these enters this table
only when its gate is active.
