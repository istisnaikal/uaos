# ADR-0019: Merge integrity with one maintainer

**Status:** Proposed (opened 2026-10-13; earliest decision 2026-10-15, 48 h; governance change per GOVERNANCE.md §Changing this document) · **Plan refs:** v2 PD-17, D-20, V0, V1, B-38, T3 · **Amends:** GOVERNANCE.md §Reviews and CODEOWNERS

## Context

Every merge gate is proven to fail on a seeded violation (`cargo xtask negative`). On
2026-10-13 that still did not stop a failing change from reaching `main`:

- PR #10 failed `dco` on a commit made by GitHub's "Update branch" button, and was closed.
- Its content reached `main` by a direct push.
- `main` had no branch protection or ruleset, and `dco` and `docs-sync` ran only on pull
  requests.

The gates *detected* the problem; nothing *prevented* it. (PR #11 defines the DCO rule for
content-free merges and runs those jobs on pushes.)

GOVERNANCE.md assumed 2–4 maintainers, with a 24 h cool-off for a solo maintainer. Execution is
one human plus AI agents. GitHub cannot require an approving review from a second person, and a
sole code owner cannot approve their own pull request, so the cool-off was the only control left,
and it was not applied.

## Decision

1. **Platform-enforced merging.** A repository ruleset on `main` with these rules:
   - changes only through pull requests;
   - every merge-lane job in `gates.toml` is a required status check, plus CodeQL;
   - required checks must pass on the head being merged;
   - linear history; merge method rebase or squash; no merge commits on `main`;
   - force pushes and deletion blocked;
   - **no bypass actors, including repository admins.**

   The ruleset is applied by the maintainer, or with the maintainer's explicit go-ahead, because
   repository settings are not code.
2. **Review rule (D-20).**
   - Every work package's pull request carries an **independent adversarial review**: a
     fresh-context reviewer with a fixed checklist (invariants touched, red lines, whether each
     negative case really bites, claim wording, failure modes, observability, docs).
   - The review is committed as `docs/reviews/<WP>.md`. Every finding is fixed or explicitly
     accepted with a reason before merge.
   - The maintainer merges only after reading it.
3. **Cool-off.** A **24 h cool-off** between the review report and the merge applies to:
   - cryptography (`uaos-platform::crypto` and any new primitive);
   - `unsafe` code;
   - the sandbox;
   - contract freezes;
   - gate removal or weakening.

   Other changes may merge once green and reviewed.
4. **Honesty about the residual.** This is weaker than a second human reviewer, and
   MAINTAINERS.md says so. When a second security reviewer exists (recruited before P5), the
   GOVERNANCE.md rule of one security-owner approval reapplies, and the ruleset adds a required
   code-owner review.

## Alternatives rejected

- **Cool-off on every merge:** it slows execution to about one merge per day per stack. The risk
  it addresses (unreviewed reasoning) is better addressed by the adversarial review, so the
  cool-off is kept where a mistake is hardest to see and undo.
- **Admin bypass kept "for emergencies":** a bypass that exists will be used. Emergencies go
  through a pull request with an expedited review, and the incident is recorded.
- **Only fixing the gates (run on push):** that detects after the fact; it does not prevent.

## Consequences

- The maintainer can no longer push to `main` directly, including for documentation.
- Stacked pull requests should be rebased rather than updated with merge commits; content-free
  merges are DCO-exempt anyway (PR #11).
- Required-check names must track job names; renaming a job requires updating the ruleset in the
  same change.

## Threat and privacy note

- **T3 (supply chain):** closes the path where an unreviewed or failing change reaches the
  release branch.
- No privacy impact.

## Verification

- **After the ruleset is applied:**
  - a direct push to `main` is rejected (tested once, recorded in the PR that adopts this ADR);
  - a pull request with a failing required check cannot be merged;
  - `gh api repos/<owner>/<repo>/rulesets` shows no bypass actors.
- **Release:** the RC-1 go/no-go (plan v2 §8.1 item 9) checks that the tag commit is reachable
  only through gated merges.
