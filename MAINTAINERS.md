# Maintainers

Roles and how to earn them are defined in [GOVERNANCE.md](GOVERNANCE.md) §Roles.

| Name | GitHub | Roles | Areas |
|---|---|---|---|
| Kistisnai Kaide | [@istisnaikal](https://github.com/istisnaikal) | Maintainer, security maintainer | all |

## The single-maintainer risk, stated plainly

The project has one maintainer, who is also its only security owner. GitHub cannot require an
approving review from a second person, and a sole code owner cannot approve their own pull
request. The controls that exist instead:
- every merge-lane gate is proven to fail on a seeded violation (`cargo xtask negative`). Making
  each one a required check on `main`, with no bypass, is pending the maintainer's go-ahead on
  the repository ruleset (plan v2 PD-17). Until then a direct push is possible; `dco` and
  `docs-sync` catch it afterwards, but nothing prevents it;
- every work package gets an independent adversarial review, kept in `docs/reviews/`;
- a 24-hour cool-off applies to cryptography, `unsafe` code, the sandbox, contract freezes and
  gate removals.

These controls are weaker than a second human reviewer, and we say so. A second security
reviewer is recruited before the sandbox work (plan phase P5).
