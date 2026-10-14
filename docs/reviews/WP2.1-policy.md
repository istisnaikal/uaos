# Retroactive adversarial review: WP2.1 uaos-policy

**Why retroactive:** WP2.1 merged without the V1 review that plan v2 now requires (PD-16).
**Reviewer:** a fresh-context review agent with the fixed checklist, read-only. It used probes and
mutants on scratch copies (Cedar 4.13.0). **Reviewed:** `main` at `3ed983f`, 2026-10-13.
**Result:** 3 High · 4 Medium · 6 Low. **Verdict as reported:** "no fail-open path in the merged
code today, but the proofs behind the WP2.1 claims do not hold."

## Findings as reported

### High

**H1. The slicing proof cannot detect a dropped policy.** `authorize_unsliced` builds its "full"
set from the union of the slices. Two mutants pass the whole suite:
`ActionConstraint::Any => false`, which silently deletes every action-unconstrained `forbid`, and
`ActionConstraint::In(_) => false`.

**H2. An approval grant can never satisfy an Ask.** Grants compile to plain permits. The Ask check
fires on any matching `@effect("ask")` permit, so the plan's flow ("a retry after approval
succeeds via the new Grant") cannot work.

**H3. Deeply nested policy text aborts the process.** Cedar's parser overflows the stack: about
80 nested parentheses (around 250 bytes) abort on Windows. Module boundaries cannot catch an
abort, so a persisted policy file becomes a crash loop.

### Medium

- **M1. `evaluation_errors_never_allow` is a tautology.** It still passes with the fail-closed
  branch disabled.
- **M2. There is no policy-semantics gate and no seeded violation.**
- **M3. The p99 claim holds only for a favourable mix.**
  - With 1,000 policies on one action, p99 is 1.7 ms.
  - With 10,000 grants on `exec`, load takes 1 s and p99 is 19 ms.
  - Nothing enforces the target.
- **M4. Slicing ignores the action hierarchy.** It is safe today, because the schema has no action
  groups, but it becomes fail-open once modules compose action groups in P3.

### Low

- **L1.** `@id` text can forge explanations, explanation order is unstable, and `@reason` is
  dropped.
- **L2.** Model ids are not injective, because `/` is allowed in names.
- **L3.** Templates bypass strict loading.
- **L4.** One bad grant voids all policy, and is reported with the wrong error kind.
- **L5.** The engine trusts the caller's clock blindly, and the expiry doc is off by its boundary.
- **L6.** The contract annotations `max_amount`, `ttl` and `audit_level` are missing without a
  recorded deferral.

## Resolution

Every finding is fixed or explicitly accepted; ADR-0008 Amendment 1 records the decisions.

| Finding | Status | What changed | Proof |
|---|---|---|---|
| H1 Slicing proof could not detect a dropped policy | **Fixed** | The engine keeps the complete validated set; `authorize_unsliced` evaluates it, never the slices | `an_unconstrained_forbid_applies_to_every_action`, `an_action_list_forbid_applies_to_each_listed_action`; property `slicing_preserves_decisions` (now with resource-pinned policies); seeded negative `policy-slicing-drops-unconstrained` |
| H2 A grant could never satisfy an Ask | **Fixed** (decided by the maintainer) | A matching grant satisfies every matching ask and allows on its own; a forbid still wins. Grants are matched natively | `a_grant_satisfies_an_ask_but_never_a_forbid`; property `native_grants_equal_their_permits`; seeded negative `policy-grant-overrides-forbid` |
| H3 Nested policy text aborted the process | **Fixed** | Text bounds before Cedar parses: 8 brackets, 16 `if`s, 256 operators, 16 KiB per policy, 4 MiB in all; measured limits in ADR-0008 Amendment 1 | `deeply_nested_policy_text_is_refused_not_a_crash` (5 shapes, 1 MiB stack); `a_policy_at_every_bound_never_crashes`; `a_policy_at_every_bound_evaluates` |
| M1 `evaluation_errors_never_allow` was a tautology | **Fixed** | Replaced by a property in which a permit and an erroring forbid always both apply, so plain Cedar would allow | `an_applicable_erroring_policy_always_denies`; seeded negative `policy-error-fails-open` |
| M2 No policy-semantics gate, no seeded violation | **Fixed** | Gate `policy-semantics` (active) with three seeded violations | `cargo xtask negative`: all three PROVEN |
| M3 The p99 claim held only for a favourable mix | **Fixed** (mixes measured) / **scheduled** (gate) | Slicing by exact resource within an action; grants indexed. The bench measures three mixes, all p99 ≤ 1 ms (419 µs on the review's 1,000-on-one-action case, 176 µs with 10,000 grants). An enforcing `perf-smoke` gate is P3 | `cargo bench -p uaos-policy --bench authorize` |
| M4 Slicing ignored the action hierarchy | **Fixed** | `action in [G]` covers every action under `G`, from the schema's action entities | `slicing_follows_action_groups` (unit) |
| L1 Forgeable `@id`, unstable order, `@reason` dropped | **Fixed** | `@id` grammar `[A-Za-z0-9._:-]{1,128}`; policies sorted by `@id`; reasons returned and shown | `ids_are_plain_and_explanations_are_sorted_by_id`; `a_grant_satisfies_an_ask_but_never_a_forbid` (reasons) |
| L2 Model ids not injective | **Fixed** | A provider name containing `/` fails closed | `a_provider_name_with_a_slash_fails_closed` |
| L3 Templates bypassed strict loading | **Fixed** | Templates are refused | `templates_are_refused` |
| L4 One bad grant voided all policy, with the wrong error kind | **Fixed** | Grants are no longer Cedar text; a grant that cannot be named is a `Rule` error naming the grant | covered by `native_grants_equal_their_permits` |
| L5 Blind clock trust; expiry doc off by its boundary | **Fixed** | A request clock more than 5 s behind the latest seen is refused; docs state the exclusive end | `a_clock_running_backwards_is_refused`; `grants_are_scoped_and_expire` |
| L6 Contract annotations missing without a recorded deferral | **Accepted, deferred with owners** | ADR-0008 Amendment 1 §7 names where `max_amount`, `ttl`, `audit_level` and `compensable` live | review of the text |

