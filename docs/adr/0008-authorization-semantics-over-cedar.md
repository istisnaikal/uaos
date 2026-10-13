# ADR-0008: Authorization semantics over Cedar

**Status:** Accepted (2026-10-13) · **Plan refs:** D8, §2.5 AUTHZ, T1, T10, T13 · **Builds on:** ADR-0002

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
