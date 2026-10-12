# ADR-0005: Client dialects and transform invariants

**Status:** Accepted (2026-10-12) · **Plan refs:** D-01, D7, B-04, B-05, B-20, B-22

## Context

The RC-1 beachhead is coding agents that use API keys. Facts verified on 2026-10-12 against
primary sources (vendor docs and source code):

- **Codex CLI speaks only the OpenAI Responses API.** Chat Completions support was deprecated in
  Dec 2025 and removed on 2026-02-03 (openai/codex PR #10157); `wire_api = "chat"` is now an
  error. Codex hard-codes `store: false` and requests `reasoning.encrypted_content`.
- **Claude Code** (Anthropic Messages via `ANTHROPIC_BASE_URL`) requires gateways to forward
  `anthropic-*` headers unchanged, return upstream error bodies unmodified (its recovery logic
  matches wording), forward the `system` array exactly (order matters), not buffer streams and
  not strip SSE `ping` events (idle watchdogs ≈ 180–300 s), and honour `retry-after`
  (> 60 s stops its retries). It calls `/v1/messages`, optionally `/v1/messages/count_tokens`,
  and a `HEAD` warm-up probe.
- **Anthropic thinking blocks are bound to everything sent before them** (system, tools, prior
  messages): a changed *value* returns 400 "bound to a different conversation"; JSON formatting
  and key order do not matter. Within a tool-use turn, thinking blocks must be passed back
  complete and unmodified.
- **OpenAI Responses stores conversations server-side by default** (`store` defaults to true);
  stateless mode uses `store: false` with `encrypted_content` reasoning items. Server-side tools
  (web search, code interpreter, remote MCP) run outside any proxy's view.
- **Subscription logins:** Anthropic does not permit third parties to route requests through
  Free/Pro/Max credentials on behalf of users. Whether a user-run local proxy counts is unclear
  and goes to legal review (D-17); RC-1 supports API keys only.

## Decision

1. **RC-1 dialects: Anthropic Messages and OpenAI Responses (stateless).** OpenAI Chat
   Completions (the CLAUDE.md GA norm) follows in RC-2 and remains a GA requirement.
2. **Byte-preserving codecs.** The model IR is a read-only *view*; edits are in-place splices of
   the original bytes; unknown fields and provider-signed blocks pass through untouched.
3. **Prefix (value) stability.** Turn N+1's transformed request reproduces exactly the content
   sent on turn N: placeholders are keyed per pocket and persisted; detector versions are pinned
   per session; injections are append-only into the newest user turn; history is never rewritten.
4. **No retro-redaction.** A secret found in already-sent history raises
   `UAOS-REDACT-0003` ("rotate it"); unsent high-risk secrets under signed blocks fail closed.
5. **Passthrough discipline.** Forward provider-protocol headers; strip only hop-by-hop headers,
   the client's auth (replaced by the vault key) and a short denylist. Upstream errors are
   byte-identical; UAOS translation is additive (`x-uaos-*` headers, panel text). UAOS-originated
   errors use the dialect's error shape with `Retry-After` ≤ 60 or none.
6. **No proxy retries by default** (clients retry); failover is opt-in policy.
7. **Token-count endpoints are governed** as non-billable Operations (they carry the full prompt).
8. **Responses API runs stateless by policy** (`store=false` enforced).
9. **Keep-alive only toward the local client** (SSE comment frames during long upstream waits);
   nothing synthetic is ever sent to providers.

## Consequences

- The splice/locator machinery per dialect is more work than full normalization, and it is the
  only way to keep signatures, prompt caches and new provider features intact.
- Cross-dialect routing (e.g. Messages client → OpenAI model) loses opaque reasoning; it is an
  explicit, explained route choice, never a silent default.

## Verification

From P3: the `adapter-conformance` and `prefix-stability` gates, including a nightly live
multi-turn replay with signed thinking and tool use against a signature-enforcing provider
(zero UAOS-caused 400s), header and error passthrough tests, and `count_tokens` governance tests.
