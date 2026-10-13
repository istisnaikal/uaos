# ADR-0004: Trust model and approvals

**Status:** Accepted (2026-10-12) · **Plan refs:** D11, T13, B-21

## Context

The agent UAOS mediates usually runs **as the same OS user** and often has a shell. Such a
process can, in principle, read that user's keychain (Windows Credential Manager, an unlocked
Secret Service collection), run `uaos approve`, edit the profile file, or kill the daemon. A
design that ignores this would make false claims ("the agent can never obtain the key",
"autonomy is approval-gated").

## Decision

1. **Honest claim:** provider keys are **never sent** to the agent (agents authenticate with
   UAOS-issued scoped keys). We do not claim the key is unobtainable in same-user mode.
2. **Approvals require a user-presence channel the agent cannot drive:** an OS authentication
   prompt (Windows Hello/CredUI, macOS LocalAuthentication, polkit) or a panel confirmation behind
   fresh authentication. As defence in depth, the CLI/control API check peer credentials and
   refuse approval/grant operations from a `uaos run` child process tree.
3. **Configuration drift:** edits to the profile file made outside UAOS are detected by hash and
   do not load without approval (`UAOS-CONFIG-0002`).
4. **Killing the daemon fails closed:** the agent holds no provider key, so it loses model access
   rather than gaining unmediated access.
5. **Hardened mode (GA option):** the daemon runs as a dedicated OS user that owns the vault and
   data directory; the key becomes genuinely unobtainable to the agent's user. <!-- claims-lint: allow (hardened mode only, item 5) -->

## Alternatives rejected

- *Assume the agent is not hostile:* prompt injection makes a benign agent hostile on demand.
- *Hardened mode as the default:* installer complexity and privilege requirements would break
  the ≤ 3-minute first-value target; offered as an explicit option instead.

## Verification

From P2: an approval-forgery suite (the agent's process tree attempts `uaos approve`, edits
config, calls the control API). Claims about key handling pass the forbidden-words lint
("unobtainable key" is banned outside hardened-mode documentation).
