# Governance

## What this project is, structurally

| Ring | Contents | Where | License |
|---|---|---|---|
| 0 — Kernel | contracts, journal, policy, ledger, redaction, runtime, egress, API | this repository, `crates/` | Apache-2.0 |
| 1 — Standard modules | adapters, tags, context repair, routing, tools, panel… | this repository, `modules/` | Apache-2.0 |
| 2 — Commercial modules | entitlement verifier, offline lock, organisation admin | separate repository | separate |
| 3 — Services | Hub, voting/funding ledger, public leaderboard, advisory feed | separate repositories | separate |

Dependency direction is enforced by `cargo xtask arch-check` (ADR-0001).

## The paywall boundary (red line 5)

**Security, privacy, the journal, basic budget, the basic panel and basic adapters are outside
any paywall, permanently.** This is enforced, not promised:

- Paid features exist only as separate Ring 2 modules. Open code is never feature-flagged
  behind a license check, so there is no crippleware to strip in a fork.
- The kernel's entitlement type cannot name a safety capability (it arrives in P7 with tests).
- CI proves the community build, with no Ring 2 code present, passes every security, privacy,
  journal, basic budget, basic panel and basic adapter test.

Because paid code is separate, contributions need only the DCO. **There is no CLA.**

## Roles

| Role | Can | Becomes one by |
|---|---|---|
| Contributor | open issues and PRs | contributing |
| Triager | label, deduplicate, reproduce | sustained helpful triage; nominated by a maintainer |
| Area reviewer | approve PRs in one area | sustained quality contributions in that area |
| Maintainer | merge, release, set direction | nomination + lazy consensus of maintainers |
| Security maintainer | handle embargoed reports; veto on red lines | maintainer + demonstrated security judgement |

Criteria and current holders are listed in `MAINTAINERS.md` once the first external
contributor joins.

## Decisions

- **Reversible decisions** are made by lazy consensus within 24 hours.
- **Expensive decisions** (contracts, architecture, security posture, licensing) need an RFC
  (`docs/rfcs/`), then an ADR (`docs/adr/`) with a threat/privacy note and a test plan, and at
  least 48 hours of review.
- **Red lines** (CLAUDE.md §1) cannot be traded off by vote. Security maintainers can veto a
  change that crosses one; the veto must name the proof that is missing and an alternative.

## Reviews and CODEOWNERS

Critical paths (contracts, state, platform OS/crypto code, identity, policy, ledger, redaction,
egress, API authentication, CI workflows, schemas) require review by a security owner.
With 2–4 maintainers the rule is one security-owner approval plus a mandatory AI review pass; a
second human approval is required for cryptography, `unsafe` code and the sandbox as soon as a
second qualified reviewer exists. A solo maintainer applies a 24-hour cool-off instead, which is
recorded as a residual risk, not presented as an equivalent to a second reviewer.

**Review convergence (D-31).** Every PR goes through four steps:
1. a fresh full review;
2. fixes;
3. one scoped round over the fix diff and every invariant and caller that diff touches;
4. a final fresh full review before the PR leaves draft.

A PR still holding a High or a Medium after round 5 is split. A Low is fixed, or accepted
one at a time into that review's debt table with an owner and a phase.

## Money and community funding

Priority bets and community funding (C-59) run in Ring 3 on a ledger that is separate from any
runtime budget, with quarterly transparent reports. Security fixes and red-line features are
never for sale or open to bidding.

## Conduct

All spaces follow [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md).

**Private conduct channel.** PENDING-DECISION(D-08): a dedicated conduct address. Until it
exists, report privately through the repository's private reporting form
(<https://github.com/istisnaikal/uaos/security/advisories/new>) with the title prefix
`[CONDUCT]`; it reaches maintainers only and is never published. A release cannot be cut while
this marker exists.

## Changing this document

Changes to governance follow the expensive-decision path (RFC + ADR).
