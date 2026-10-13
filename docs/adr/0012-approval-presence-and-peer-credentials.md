# ADR-0012: Approval presence and peer credentials

**Status:** Proposed (opened 2026-10-13; earliest decision 2026-10-15, 48 h) · **Plan refs:** v2 §2.8 ADR-0012, I-13, WP3.6, T13, B-21 · **Builds on:** ADR-0004

## Context

ADR-0004 decided that approvals need a user-presence channel the agent cannot drive, with
peer-credential checks as defence in depth. The plan v2 review sharpened two points:

- **Ancestry checks are bypassable.** A process that refuses callers descended from a `uaos run`
  child can be fooled by:
  - double-forking and `setsid` (Unix);
  - `systemd-run --user`, `launchctl submit` and `schtasks /create` (each re-parents the
    payload under a system service);
  - PID reuse on Windows, where parent ids are not reference-counted.

  So an ancestry check cannot be the boundary.
- **The first first-party `unsafe` arrives here.** Windows has no safe API for a named pipe's
  client process or for presence prompts. CLAUDE.md §3 requires an ADR, an owner, sanitizer
  and/or Miri coverage, and a security review before it lands.

## Decision

1. **The boundary is the presence ceremony.** No approval, grant or other privilege-raising
   control operation completes without one. Per OS, through `uaos-platform::os::*` behind a safe
   `Presence` trait with a simulated twin:
   - **Windows:** Windows Hello (`UserConsentVerifier`), falling back to CredUI.
   - **macOS:** LocalAuthentication (`LAContext`, device-owner authentication).
   - **Linux:** polkit with an action requiring `auth_self`.
   - **Panel (P4):** a confirmation behind fresh authentication. It counts only when the panel
     session itself was established with an OS presence ceremony.

   The ceremony shows what is being approved: the operation, its diff or dry run, and its risk
   tier. An agent can *request* an approval (the request fails immediately with an approval
   id, per ADR-0002). It cannot *complete* one.
2. **Defence in depth, not the boundary.**
   - **Peer credentials:** the CLI and control API learn the calling process (Unix: `SO_PEERCRED` /
     `LOCAL_PEERCRED` through `rustix`'s safe API; Windows: `GetNamedPipeClientProcessId`).
   - **Containment set at spawn:** `uaos run` places the agent in a container the agent cannot
     leave, and the check tests membership, not ancestry:
     - Windows: a Job Object with breakaway forbidden;
     - Linux: a dedicated cgroup where the user can write cgroups, otherwise a process group plus
       session marker;
     - macOS: a process group plus the audit session id.
   - A request from inside the container is refused before the ceremony even starts. Re-parenting
     tricks that escape the container are covered by item 1. The forgery suite proves they
     still cannot complete an approval.
3. **`unsafe` policy for this ADR.**
   - Confined to `uaos-platform::os::windows` (and `os::macos` if a safe binding is
     insufficient), with `#[allow(unsafe_code)]` only there, enforced by the `allow-audit`
     gate.
   - Owner: the security maintainer. Every block has a `// SAFETY:` comment, and
     `clippy::undocumented_unsafe_blocks` is denied.
   - Audited `windows-sys` and `objc2` bindings are preferred over hand-written FFI.
   - An **AddressSanitizer job on `x86_64-pc-windows-msvc`** runs the presence and peer-credential
     tests.
   - **Miri does not apply to FFI**, and we state that instead of claiming coverage.
   - The 24 h cool-off applies (D-20).
4. **Headless hosts.** Without a presence-capable session (SSH, CI, containers), approvals are
   **unavailable**. The operation stays denied, with an explanation; it never degrades to a typed
   confirmation. `uaos doctor` reports the presence backend.

## Alternatives rejected

- **Typed confirmation in the CLI:** an agent with a shell can type it.
- **Ancestry as the boundary:** bypassable as described above.
- **A long-lived approval token cached after one ceremony:** it turns one presence into standing
  authority. Grants have explicit TTLs and scopes instead (ADR-0008).

## Consequences

- Approvals are slower than a keystroke by design. Approval fatigue (v1 B-08) is managed with
  risk tiers and TTL grants, not by weakening the ceremony.
- Headless use cannot approve anything. It runs on pre-granted policy or not at all.
- The project gains its first `unsafe` code, with the obligations above.

## Threat and privacy note

- **T13:** an agent process can request but never complete an approval. The residual is a
  compromised OS session where malware can satisfy the ceremony; that is outside UAOS's boundary
  and documented.
- **Privacy:** no biometric or credential data reaches UAOS. The OS returns only a yes or no.

## Verification (WP3.6)

The approval-forgery behavior (pending in `gates.toml`, active in WP3.6). From inside a `uaos run`
container and from re-parented descendants, these must all fail to complete an approval:
- `setsid`, `systemd-run --user`, `launchctl`, `schtasks`;
- direct control-API calls;
- an edited profile file;
- a simulated presence backend that is not injected.

The simulated `Presence` twin lets the logic be tested on every OS. The real backends run on the
matching CI runners where a session allows it, and that limitation is stated per runner. ASan
runs on windows-msvc.
