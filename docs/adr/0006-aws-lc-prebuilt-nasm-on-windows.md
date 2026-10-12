# ADR-0006: aws-lc prebuilt NASM objects on Windows

**Status:** Accepted (2026-10-12) · **Plan refs:** D18, §4.2 reproducibility, B-16

## Context

aws-lc-rs (the single crypto family, D18) needs NASM to assemble its x86_64 Windows code. NASM is
not installed on typical Windows developer machines or by default on CI images. Without it the
build fails; requiring it adds a setup step to the ≤ 3-minute contributor path.

## Decision

On Windows targets only, enable aws-lc-rs's `prebuilt-nasm` feature: the build links NASM object
files that AWS publishes **inside the `aws-lc-sys` crate package**. Linux and macOS continue to
assemble from source. The feature is scoped by a `cfg(windows)` dependency entry in
`crates/uaos-platform/Cargo.toml`.

## Why this is acceptable

- The objects arrive in the same crates.io package as the C sources, pinned by `Cargo.lock`
  checksum and covered by `cargo vet` like any other dependency content.
- They come from the upstream maintainer (AWS), not a third party.
- Windows release reproducibility was already scoped as "rebuildable with verified provenance"
  until bit-for-bit is proven (plan §4.2); this decision does not weaken the Linux bit-for-bit goal.

## Revisit when

- Before GA (P8): evaluate assembling with NASM in the Windows release job so release artifacts
  contain no prebuilt objects; keep `prebuilt-nasm` for developer builds if that holds.
- If upstream changes how the objects are produced or distributed.
