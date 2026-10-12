# Contributing to UAOS

Thank you for considering a contribution. UAOS holds itself to a high, measurable bar; this
guide tells you exactly what that bar is so nothing is a surprise at review time.

## Local setup

1. Install [rustup](https://rustup.rs). The toolchain is pinned in `rust-toolchain.toml` and is
   installed automatically on first build.
2. **Windows:** use the MSVC host (`x86_64-pc-windows-msvc`) and install the *Visual Studio
   Build Tools* (C++ workload). Later phases build C dependencies (SQLite, aws-lc) that need a
   C compiler. If your default host is GNU, scope MSVC to this checkout only:
   `rustup override set 1.98.1-x86_64-pc-windows-msvc`.
3. Developer tools (the same versions CI uses are resolved by `taiki-e/install-action`):
   `cargo install --locked cargo-nextest cargo-deny cargo-vet`, and
   [gitleaks](https://github.com/gitleaks/gitleaks) 8.30.1 (verify its release checksum).
4. Run `cargo xtask ci` before every push. It runs exactly the merge fast lane CI runs.

Paths with spaces and non-ASCII characters (`ü`, `ş`, `ı`) are supported and tested in CI.

## The gates

Every merge must pass the active gates in [`gates.toml`](gates.toml). Each active gate is
proven to bite by `cargo xtask negative`, which seeds a violation and checks the gate fails.

| Gate | Command |
|---|---|
| format | `cargo fmt --all -- --check` |
| lint | `cargo clippy --workspace --all-targets --locked -- -D warnings` |
| tests | `cargo nextest run --workspace --locked` and `cargo test --doc` |
| architecture direction | `cargo xtask arch-check` |
| contract schemas | `cargo xtask schema-check` |
| license headers | `cargo xtask headers` |
| gate registry | `cargo xtask gates` |
| dependencies | `cargo deny --locked check` and `cargo vet --locked` |
| secrets | `gitleaks git` |
| DCO / docs-with-contract | `cargo xtask dco <range>` / `cargo xtask docs-sync <range>` |

## Code standard (enforced by tooling, not taste)

- **No `unsafe`.** Denied workspace-wide. The only exception is `uaos-platform::os` (and from P5
  `uaos-sandbox::os`): it requires an ADR, an owner, a `// SAFETY:` comment per block and
  security review.
- **No panics in product code:** `unwrap`, `expect`, `panic!`, `todo!`, `unimplemented!` are denied.
  Errors are typed (`thiserror`) and map into the unified registry in `uaos-contracts::error`.
- **No hidden nondeterminism.** Clocks, randomness, the filesystem, process spawning and env
  reads go through `uaos-platform`; `clippy.toml` bans them elsewhere. `HashMap`/`HashSet` are
  banned in favour of ordered maps unless justified, because random iteration order breaks
  seed-reproducible simulation.
- **No silent failure.** Every `#[allow]` carries a `reason`. An ignored result needs a comment.
- **No magic numbers.** Bounds live in `uaos_contracts::limits` with units and a rationale.
- **Money is integer nano-USD.** Floats never touch money.

## Architecture rules

Dependency direction is a contract in [`arch.toml`](arch.toml). A new crate must declare its
allowed edges there. Ring 1 modules (`modules/`) may depend only on `uaos-contracts` and
`uaos-module-api`. Product features never go into the kernel; see ADR-0001.

## Changing a contract

Contracts live in `uaos-contracts` and are exported to `schemas/`.

1. Change the type, run `cargo xtask schemas`, commit the regenerated schema.
2. Add a `CHANGELOG.md` entry (the docs-with-contract gate enforces this).
3. A **breaking** change (removed or retyped field, new requirement, tightened constraint)
   needs a new major (`uaos.<name>/<major+1>`) and an ADR. The schema gate detects this.

## Dependencies

Every new dependency must be justified in the PR (why it is needed, why not std or an existing
dependency, maintenance and license status). `cargo deny` enforces licenses and sources;
`cargo vet` requires an audit, an imported audit, or an explicit exemption with a reason.

## Pull requests

Answer these in the PR description (the template asks for them):
**pain** cut, **cell** (C-xx) touched, **risk**, **proof** (tests and numbers), **docs**,
**breaking change / migration**. Security-sensitive paths (see `.github/CODEOWNERS`) need a
threat-note update and security-owner review.

## Developer Certificate of Origin (DCO)

All commits must be signed off: `git commit -s`. This certifies the
[Developer Certificate of Origin 1.1](https://developercertificate.org/): you wrote the change or
otherwise have the right to submit it under the project's license. The sign-off must match the
commit author. There is no CLA.

## Reporting security issues

Never in public issues. See [SECURITY.md](SECURITY.md).
