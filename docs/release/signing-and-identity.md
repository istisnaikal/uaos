# Release signing and repository identity (D-19, D-22)

**Decided by the maintainer on 2026-10-13, reaffirmed on 2026-10-14:**
- Code signing is prepared for an individual: an OV/EV Windows certificate and an Apple
  Developer ID.
- The repository's target identity is frozen as `uaos-project/uaos` before the release work
  (WP3.9) lands.
- The live-provider evidence lane uses CI-only keys with spend caps in a protected environment
  (D-21).

Registration, purchases and the organisation itself are the maintainer's to carry out: they bind
the maintainer's legal identity and money, and no automation does them.

This page lists what each decision needs, who does it, and what is still to verify. Facts about
third-party programmes are written as "verify at purchase": vendors change terms, and this page
does not guess.

## D-22: repository identity `uaos-project/uaos`

| Step | Who | When |
|---|---|---|
| Create the GitHub organization `uaos-project` (free plan). The name was unclaimed on 2026-10-13 (`gh api orgs/uaos-project` and `users/uaos-project` both 404) | Maintainer (GitHub UI; organizations cannot be created through the API for personal accounts) | **As soon as possible**, so the name cannot be taken |
| Enable 2FA enforcement, private vulnerability reporting, secret scanning, push protection and Dependabot on the org and repo | Maintainer | At creation |
| Transfer `istisnaikal/uaos` → `uaos-project/uaos` (Settings → Transfer). GitHub redirects the old URLs, but published attestations name the repository they were made in | Maintainer | **Before WP3.9** (no signed release before the move) |
| Re-apply the ADR-0019 ruleset and the `live-providers` environment after the transfer, and check that both still exist | Maintainer, verified by automation | Right after the transfer |
| Update links: SECURITY.md, CODE_OF_CONDUCT.md, GOVERNANCE.md, CODEOWNERS (`@istisnaikal` → a `security-owners` team once a second owner exists), README badges, `Cargo.toml` `repository` | Automation (one PR) | Right after the transfer |

## D-19: code signing

### Windows (Authenticode)

| Item | Note |
|---|---|
| Certificate type | Code-signing keys must live on hardware (a token or a cloud HSM) under CA/Browser Forum rules. **Verify at purchase** whether the CA issues EV to individuals; EV is generally issued only to organizations. If it is not, choose OV for an individual. |
| Validation | Identity documents of the individual, as the CA requires. |
| CI integration | A cloud-HSM signing service is preferred, because a hardware token cannot be used by GitHub-hosted runners. Credentials go only into a protected environment (`release`) that deploys only from tags on `main`. |
| SmartScreen | Reputation builds over time. **Verify at purchase** what the CA states about SmartScreen for the certificate type. The ≤ 3-minute first-value measurement (WP3.8) records any warning honestly. |

### macOS (Developer ID and notarization)

| Item | Note |
|---|---|
| Programme | Apple Developer Program, individual enrollment, under the maintainer's legal name. **Verify the current fee and terms at enrollment.** |
| Certificates | A "Developer ID Application" certificate for the binary; notarization with `notarytool` and an App Store Connect API key. |
| CI integration | The certificate (`.p12`) and the API key go into the protected `release` environment, and the job signs and notarizes on a macOS runner. |

### Linux and every platform

GitHub artifact attestations (Sigstore-backed), a CycloneDX SBOM, checksums and `cargo auditable`
need no purchase. They arrive with WP3.9 on every target.

## D-21: the live-provider evidence lane

Settings the maintainer applies:
- A `live-providers` environment, deploying only from `main`.
- `ANTHROPIC_API_KEY` and `OPENAI_API_KEY` as environment secrets, set interactively, so the
  values never appear in a terminal transcript.

| Provider | Create | Limit |
|---|---|---|
| Anthropic | A dedicated workspace for CI (for example `uaos-ci`) and an API key inside it | Set the workspace spend limit in the Console |
| OpenAI | A dedicated project (for example `uaos-ci`) and a project API key | Set the project's monthly budget |

The lane (`.github/workflows/live.yml`) runs on a schedule and on `workflow_dispatch` from `main`
only. Until the kernel relays traffic, it proves its wiring at zero token cost by listing each
provider's models. Pull requests, and forks
in particular, never reach the environment. Keys are rotated monthly, and the canary scan covers
the job logs (threat T15).
