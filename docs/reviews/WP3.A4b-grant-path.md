# Adversarial review: WP3.A4b, grants on the wire and cross-pocket consent (P3 Move 1, PR-4b, ADR-0008)

**Reviewer:** a fresh-context review agent (plan v2 §4.2, V1). It read the code only, at the
maintainer's request while the machine's memory was short; every scenario below is derived from
the code. **Reviewed:** `be612e9` (`p3/a4b-grant-path`, #39), 2026-10-21, all three commits.
**Result:** 0 High · 2 Medium · 5 Low.
**Verified clean by the reviewer:**
- **Ordering:** errors deny first, then forbids, then grants.
- **Permits never allow a cross-pocket read alone.** With asks, only a grant that approves every
  ask allows one.
- **A cross-pocket read naming no grant has no grants**, and the named filter only narrows.
- **The clock mark and slicing are untouched.**
- **All five seeds disable what they claim.**

**Resolution:** every finding is fixed, with a test, and three more seeded violations (8 in
all). Under D-31, a scoped round over the fixes follows, then a final fresh full review.

| | Finding | Fix | Proof |
|---|---|---|---|
| M1 | An own-pocket `memory.read` behind an ask could never be approved persistently: the wire refused every own-pocket grant (`InjectionMismatch` without a policy, `SamePocket` with one), so the approve-and-retry flow of ADR-0008 Amendment 1 broke for this action. | `GrantRecord::validate` asks for an injection policy on cross-pocket grants only; `SamePocket` is gone. An own-pocket grant carries none (appendix §2 rules 3 and 5). | `an_own_pocket_read_behind_an_ask_is_approved_by_a_grant`, `an_own_pocket_read_grant_carries_no_injection_policy`; negative `grant-own-pocket-unjournalable` |
| M2 | "Every engine grant has a record and back" was false. `PolicyEngine::load` accepted grants the wire refuses: more than 8 data classes or asks, expiries past year 9999 (`u64::MAX`), `memory.read` without a pocket, asks outside the `@id` grammar. The property's generator never reached them, nor System, Pool, `budget.transfer`, `count_tokens`, 128-byte names, `:`, `/` or uppercase. | `check_grant` holds the wire's rules, and both `PolicyEngine::load` and `grant_record` call it, so the engine never holds a grant it cannot journal. The claim is narrowed to "every grant the engine loads". The property now generates every principal, resource and action, boundary names, providers with `/`, sets past 8 and expiries past 9999. It checks that the engine loads exactly what `check_grant` accepts, and that each of those round-trips. | `every_engine_grant_round_trips_through_the_wire`; negative `engine-loads-unjournalable-grant` |
| L1 | A record whose model provider holds `/` passed `Grant::try_from` and then refused the whole set at load. | `check_grant` refuses a provider with `/`, and `try_from` runs it. | The widened property |
| L2 | Two grants with one id both passed the named filter, so which injection policy applied was ambiguous. | The engine refuses an id twice at load. | `a_grant_id_twice_is_refused` |
| L3 | The schema's `PolicyId` pattern accepted `grant:x`. | `^(?!grant:)[A-Za-z0-9._:-]{1,128}$`. | `xtask schema-check` |
| L4 | Missing tests: the named filter on other actions; a carried cross-pocket grant facing an ask; the System principal; the 128-byte boundary; `PolicyId` against the engine's `@id`; flooring; a seed for the early return. | Tests for each, and negative `grant-unnamed-cross-pocket-allowed`. | `a_named_grant_narrows_other_actions_too`, `a_carried_grant_must_approve_the_asks_of_a_cross_pocket_read`, `policy_ids_agree_with_engine_ids`, `a_finer_expiry_floors_on_reload`; the widened property reaches System and 128-byte names |
| L5 | The engine's module doc still said a permit allows everywhere and the equivalence holds without exception. The appendix claimed `schema-breaking-change` re-proven over `grant.v1.json`. The `0010-module-socket.md` references dangle on main. | The module doc states the cross-pocket exception and the load check. The appendix states what `schema-compat` covers, and that the socket contract is in #32. ADR-0008 Amendment 1 (accepted) is left as written; the appendix carries the exception. | — |

## Also found while fixing

- **`WallTime::from_unix_nanos` could panic.** The widened wire property converts a "never
  expires" `u64::MAX` grant. For nanoseconds that far outside its range, jiff 0.2.38 reached an
  internal assertion instead of returning its error. `uaos-contracts` now checks the range first
  (`out_of_range_nanos_are_refused_without_a_panic`). The wire's maximum is jiff's,
  9999-12-30T22:00Z.

## Scoped round (D-31)

**Reviewed:** `be612e9..d010903`, by a fresh-context agent reading only, 2026-10-21.
**Result:** 0 High · 1 Medium · 5 Low.
**Verified:**
- no consent hole: an own-pocket grant's key names both pockets;
- `check_grant` matches the wire;
- the time bounds;
- the schema pattern;
- all three new seeds.

| | Finding | Fix |
|---|---|---|
| M1 | `slicing_preserves_decisions` drew grants that could share an id, so the new duplicate-id refusal made it fail about 28% of runs. | One grant per id, as in the equivalence property. |
| L1 | The widened property held by construction and rarely reached a round trip, so a `check_grant` that refused too much would pass. | `every_valid_grant_loads_and_round_trips`: grants valid by construction must load, journal and reload. |
| L2 | Docs: a misplaced `GrantKey` comment, the duplicate rule credited to `check_grant`, `load`'s errors, appendix §3. | Corrected. |
| L3 | Stale `grant.rs` docs ("another pocket", "on a pocket only"), carried into the schema. | Reworded; schema regenerated. |
| L4 | A duplicate id refuses the whole set at boot, the boot behaviour is unspecified, and the test was weak. | §3: issuing refuses a known id, and boot keeps the first and alarms (PR-6/PR-8). The test asserts the reason; negative `grant-id-twice-loaded`. |
| L5 | The `(?!` lookahead is not portable across schema validators. | `PolicyId`'s schema is `allOf` a pattern and `not` a `^grant:` pattern. |

## Final full review (D-31)

**Reviewed:** `main..1d1bf8b`, the whole PR, by a fresh-context agent reading only, 2026-10-21.
**Result:** 0 High · 1 Medium · 4 Low.
**Verified:**
- the consent rule;
- the carried grant;
- `check_grant` against the wire;
- the duplicate-id refusal;
- the schema;
- the seeds' anchors.

| | Finding | Fix |
|---|---|---|
| M1 | Seed `grant-wire-drops-provider` was caught only when the wide property loaded a model grant, which it rarely does: about 8% of runs missed it, so the merge-blocking `negative` job would fail at random. | The seed runs `every_valid_grant_loads_and_round_trips`, where a fifth of the grants are model grants; its round trip carries the seed's message. |
| L1 | `GrantPrincipal::Human` and `System` were unit variants, and serde ignores unknown fields on them. | Both are struct variants with no fields, and a field is refused. Test in `humans_and_the_kernel_can_hold_grants`; negative `grant-principal-ignores-fields`. |
| L2 | `any_valid_grant` drew no name with `/`. | Names with `/` for models, tools, configuration keys and data classes; providers keep none (§3). |
| L3 | Stale text: the CHANGELOG's moved-unchanged bullet kept the old injection rule, the seed count said 8, the scoped round was missing; the appendix said "policies" for a property that uses none or a blanket permit. | Corrected. |
| L4 | `GrantRecord.action` said a module action is allowed, though only engine actions reload; `grant.rs` cited the socket contract, which is on #32. | Engine actions only, and boot skips any other with an alarm (§3); the citation names #32. |
