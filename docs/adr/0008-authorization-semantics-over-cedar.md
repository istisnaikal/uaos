# ADR-0008: Authorization semantics over Cedar

**Status:** Accepted (2026-10-13); Amendment 1 decided by the maintainer 2026-10-14 · **Plan refs:** D8, §2.5 AUTHZ, T1, T10, T13 · **Builds on:** ADR-0002

## Context

Plan D8 chose Cedar (Apache-2.0, formally specified, schema-validated) over a custom grammar. Cedar
answers Allow or Deny. UAOS needs more than that, and one of Cedar's documented behaviours is
dangerous if taken at face value: **a policy whose evaluation errors is skipped.** An erroring
`forbid` therefore silently stops forbidding, and plain Cedar can answer Allow.

## Decision

`uaos-policy` layers these semantics over Cedar's authorizer; they are part of the kernel contract.

1. **Default deny.** No matching permit means Deny (`Basis::NoMatchingPermit`).
2. **Fail closed.** Any evaluation error, a request that fails schema validation, or an entity set
   that fails validation means **Deny** (`Basis::EvaluationError`), with the errors named by
   policy `@id` and sorted so explanations are deterministic.
3. **`Deny > Ask > Allow`.** A matching permit annotated `@effect("ask")` turns an Allow into an
   approval request; any matching forbid beats both.
4. **Strict loading.** Every policy has a unique `@id`; only `@id`, `@effect("ask")` (on permits) and
   `@reason` annotations are accepted; `grant:` ids are reserved; the set is validated against the
   UAOS schema (`uaos.cedarschema`) in strict mode. One failing policy means nothing loads. A typo
   such as `@efect("ask")` would otherwise silently mean Allow.
5. **Grants are policies.** A grant compiles to
   `permit(principal == P, action == A, resource == R) when { context.pocket == "…" && context.now_ms < expiry }`
   with `@id("grant:<id>")`. Expiry lives inside the policy, so a grant that is never cleaned up
   still stops applying on time. Caller-supplied names are restricted to `[A-Za-z0-9._:/-]`, so they
   cannot alter policy text.
6. **Per-action slicing.** Policies are partitioned by action constraint at load; a decision
   evaluates only its action's slice. A property test proves slicing never changes a decision.
7. **Time is an input.** `now_ms` comes from the caller's clock, keeping decisions deterministic
   under simulation.

## Measured

1,000 policies (permits, conditional forbids, ask-permits, action-unconstrained forbids) on the
founder workstation, release build: load and strict validation in 65 ms; decisions **p50 387 µs,
p99 662 µs, p99.9 803 µs** (plan target: p99 ≤ 1 ms). Per-request entity validation costs about
10 µs and is kept. If real policy sets approach this size, slicing by resource is the next lever.

## Consequences

- Cedar brings 103 crates (some build-time only, e.g. the LALRPOP parser generator); after
  refreshing imported audits the workspace stands at 47 fully audited, 13 partially audited and
  221 exempted crates. Recorded as debt, not hidden.
- Simple TOML rules for profiles (plan §2.7) compile to Cedar in P4; Cedar stays the only
  evaluator.

## Verification

`crates/uaos-policy/tests/policy.rs`: default deny; permit with provider hierarchy; forbid wins;
Ask precedence; an overflowing forbid that Cedar would skip yields Deny; every loading rule;
grant scope and expiry; name-injection refusal; properties: slicing preserves every decision, and
an evaluation error never yields Allow or Ask. Benchmark: `cargo bench -p uaos-policy --bench authorize`.

## Amendment 1 (2026-10-14): the retroactive review

The retroactive review (`docs/reviews/WP2.1-policy.md`) found no fail-open path in the merged
code. It did find that the proofs behind three claims did not hold, that the approval flow could
not work, and that crafted policy text could abort the process. The maintainer decided the
grant semantics on 2026-10-14. Everything below is in force; §1–§7 above stand, except where
this section changes them.

1. **A grant is an approval (changes §3, §5).**
   - **What it does:** a live grant matching the request's principal, action, resource and
     pocket exactly allows on its own (`Basis::Granted`). It also **satisfies every matching
     `@effect("ask")` policy**, because it is the recorded result of the approval those policies
     ask for. **It never overrides a forbid:** `Deny > (Ask unless granted) > Allow`.
   - **Why:** before this, a grant compiled to a plain permit and the ask check fired on any
     matching ask policy. The flow "approve, then the retry succeeds" could never complete.
   - **How grants are evaluated:** they are no longer Cedar policies. They are exact-match
     capabilities in an index (a map lookup per decision). A property proves the result equals
     compiling each grant to the permit of §5 (`native_grants_equal_their_permits`). Loading
     10,000 grants takes 83 ms instead of 1 s.
2. **Bounded policy text (adds to §4).** Cedar's parser recurses without a stack check: about 80
   nested parentheses aborted the process, and a persisted policy file would become a crash loop.
   - **The bounds:** before Cedar sees the text, a scanner that skips strings and comments
     enforces, per policy, at most:
     - 8 nested brackets;
     - 16 `if`s;
     - 256 operators;
     - 16 KiB.

     The whole text is limited to 4 MiB. Anything beyond is a `Rule` error.
   - **Measured:** on a 1 MiB stack, a debug build overflows at 32 nested brackets, 256 nested
     `if`s and 4,096 chained operators. Cedar's evaluator and typechecker check their remaining
     stack (100 KiB) and fail an evaluation instead of overflowing, so the worst case within the
     bounds is a fail-closed Deny.
   - **What fits:** a policy at every bound at once evaluates normally with 1 MiB of stack in a
     release build, and with 8 MiB in a debug build. The runtime's worker threads (ADR-0013) keep
     at least 2 MiB.
3. **Stricter loading (adds to §4).**
   - An `@id` is 1–128 characters of `[A-Za-z0-9._:-]`, so it cannot pose as an explanation.
   - Templates are refused.
   - A provider name containing `/` fails closed, because `provider/model` must stay injective.
4. **Slicing (changes §6).**
   - **What is partitioned:** policies are partitioned by action, following the schema's action
     groups, so `action in [G]` reaches every member of `G`. Within an action they are partitioned
     again by an exact `resource ==` constraint, and a decision evaluates the common set plus the
     resource's set, merging the two Cedar answers.
   - **Proof:** the property that proves slicing never changes a decision now compares against
     the complete set as loaded. Before, the oracle was rebuilt from the slices, so a dropped
     policy vanished from both sides.
5. **Time (changes §7).** `now_ms` must come from the platform clock. A request whose clock is
   more than 5 s behind the latest one seen is refused, because a clock running backwards could
   revive an expired grant. A grant is live while `now_ms < expires_at_ms`.
6. **Explanations.**
   - Determining policies are listed sorted by `@id`; a grant comes first, followed by the ask
     policies it satisfied.
   - Their `@reason` texts are returned and shown.
7. **Contract annotations, deferred with an owner.** CLAUDE.md's Policy contract lists
   `max_amount`, `ttl`, `audit_level` and `compensable`. Their homes:
   - `max_amount`: the budget ledger's caps and the clamp (WP3.5);
   - `ttl`: grant expiry (here) and profile rules (P4);
   - `audit_level`: the journal's per-Operation records (P3);
   - `compensable`: the Operation contract (ADR-0002).

   None is a policy annotation in v1.

**Measured after the amendment** (release build, founder workstation, 20,000 decisions each):

| Set | Load | p50 | p99 |
|---|---|---|---|
| Mixed: 1,000 permits, conditional forbids and asks across actions | 66 ms | 160 µs | 678 µs |
| 1,000 policies all on `exec` (the review's worst case: p99 1.7 ms before) | 61 ms | 369 µs | 419 µs |
| 10,000 grants on `exec` plus the mixed set (before: load 1 s, p99 19 ms) | 83 ms | 154 µs | 176 µs |

The plan target is p99 ≤ 1 ms. These are measurements of these mixes on one machine, not a
gate; the `perf-smoke` gate arrives in P3.

**New gate `policy-semantics`** (active). It is proven to bite by three seeded violations:
- slicing that drops action-unconstrained policies;
- an engine that skips an erroring policy, as plain Cedar does;
- a grant that overrides a forbid.

