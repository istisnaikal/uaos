# Beachhead facts: what the RC-1 clients require of a gateway

**Recorded:** 2026-10-13 (plan v2 WP3.0a). Every fact here has a source and a date. A fact is
re-verified whenever a source changes, and at least before each release; client drift is risk
B-34. Each fact feeds a decision, and the decision names the fact.

**Status:**
- Claude Code: documentation **and a traffic capture** (2026-10-13, approved by the maintainer;
  see "Captured").
- Codex: documentation only. Codex is not installed on the reference machine.

## Claude Code (Anthropic Messages)

Sources:
- [LLM gateway](https://code.claude.com/docs/en/llm-gateway)
- [Gateway compatibility guide](https://code.claude.com/docs/en/llm-gateway-protocol)
- [Preserved thinking](https://platform.claude.com/docs/en/build-with-claude/preserved-thinking)

All read 2026-10-13.

| # | Fact | Consequence for UAOS |
|---|---|---|
| CC-1 | Selected by `ANTHROPIC_BASE_URL`. Endpoints: `POST /v1/messages` (sent as `/v1/messages?beta=true`; match on the path) and `POST /v1/messages/count_tokens` (optional; without it the client falls back to a character estimate) | D-28 "governed" class. `count_tokens` is a non-billable Operation through detection, authorization and the final scan (v1 §2.5) |
| CC-2 | Startup traffic: `HEAD /api/hello` connection-warming probe, which can be rejected without breaking anything | D-28 "metadata" class, answered **locally**: no external contact (I-14) |
| CC-3 | `GET /v1/models?limit=1000` only with `CLAUDE_CODE_ENABLE_GATEWAY_MODEL_DISCOVERY=1`: 3 s timeout, redirects treated as failure, both credential headers sent | "metadata" class; forwarded only when the user enabled discovery |
| CC-4 | Forward `anthropic-version` and `anthropic-beta` **unchanged**, and treat `anthropic-*` headers and body fields as **open lists**; never allowlist beta values | ADR-0005 / D7 byte preservation. The codec never models the body to decide what to forward (ADR-0014) |
| CC-5 | `anthropic-beta` carries an OAuth capability when the user is signed in with claude.ai and no gateway credential is set; stripping it fails with `401` | D-17′ (subscription pass-through) is a documented client path; ToS review pending |
| CC-6 | Consumable headers: `x-claude-code-session-id`, `x-claude-code-agent-id`, `x-claude-code-parent-agent-id`; opt-in hint headers (`x-claude-code-request-class`, `-compaction`, `-context-compacted`, `-prompt-id`, `-prev-tool-durations`) | ADR-0015 session inference uses them as strong hints. The agent id enables per-subagent sub-pools (H7) |
| CC-7 | Response headers: return `text/event-stream`; `retry-after` in integer seconds (> 60 stops client retries); pass `x-should-retry` and `anthropic-ratelimit-unified-*` unchanged; forward error bodies **unmodified** (client recovery matches the wording) | v1 drop-in rules confirmed. UAOS errors use `Retry-After` ≤ 60 |
| CC-8 | The stream must not be buffered. The full event sequence through `message_stop` is required. `ping` events can be the only bytes during long thinking, and stripping or delaying them trips the client's idle watchdog | Frame-wise relay; pings pass immediately; rehydration lookahead is bounded (ADR-0017 §5) |
| CC-9 | The system prompt's first block is an attribution block, stripped **positionally** by the provider. Prepending, reordering, merging or stringifying `system` defeats the strip | Codec invariant: `system` is structurally untouched; entry 0 is never edited (ADR-0014) |
| CC-10 | A rewritten `system`, `tools` or earlier `messages` gets a `400 … bound to a different conversation`. **Claude Code then silently drops earlier thinking and retries** | Prefix defects look like quality loss, not errors (B-37). UAOS counts these 400s itself |
| CC-11 | The fast-mode availability check and the WebFetch domain-safety check call `api.anthropic.com` **directly** | Known limitation: this traffic bypasses UAOS by design |
| CC-12 | Pairing of features: a beta header and its body field travel together; content inspection that rewrites bodies breaks the pairing | Redaction splices string values only and never removes fields; verified by golden transcripts (WP3.4) |
| CC-13 | Preserved-thinking check: "JSON formatting and key order don't matter; the values do" | I-06 is restated over values |
| CC-14 | Thinking blocks are bound to the account that produced them | I-16 session–account affinity |
| CC-15 | Proxies: forward unknown fields and `thinking.block_binding`; return `input_transformations`; never move `role: "system"` messages; disable tools with `tool_choice: none`, never by removing `tools`; "don't hide the 400" | ADR-0014 roles; P5 MCP valves use `tool_addition`/`tool_removal`; @devam uses a branch or `drop_block` (P6A) |
| CC-16 | The `thinking-binding-controls-2026-08-01` beta reports prefix edits in `input_transformations` without enforcing them, when the header is set and the field is unset | An oracle for UAOS's **own** live-lane traffic (D-21). Never injected into user traffic |

## Codex CLI (OpenAI Responses)

Source: the [Codex configuration reference](https://learn.chatgpt.com/docs/config-file/config-reference),
read 2026-10-13 (redirected from `developers.openai.com/codex/config-reference`; no page date
shown).

| # | Fact | Consequence for UAOS |
|---|---|---|
| CX-1 | A custom provider is `[model_providers.<id>]` with `name`, `base_url`, `env_key` (the **name** of an environment variable), `query_params`, `http_headers`, `env_http_headers`, `requires_openai_auth` (default false). The ids `openai`, `ollama` and `lmstudio` are reserved | `uaos run -- codex` uses a launch recipe: a provider entry or override pointing at UAOS, with `env_key` naming the variable that carries the `uaos_sk_` key |
| CX-2 | `wire_api`: "`responses` is the only supported value, and it is the default when omitted" | Confirms D-01: Responses at RC-1; Chat Completions is not needed for Codex |
| CX-3 | `openai_base_url`: base URL override for the built-in `openai` provider | A simpler recipe alternative, chosen in WP3.7 after a capture |
| CX-4 | The client retries by itself: `request_max_retries` default 4, `stream_max_retries` default 5, `stream_idle_timeout_ms` default 300000 | Confirms "no proxy retries by default" (v1 §2.5). Keep-alive frames toward the client stay below the idle timeout |
| CX-5 | `auth.command` can mint bearer tokens and cannot be combined with `env_key` | An option for short-lived `uaos_sk_` child keys (ADR-0011) in a later recipe |
| CX-6 | `--profile <name>` selects `$CODEX_HOME/<name>.config.toml` | A UAOS profile file instead of editing the user's main config: no permanent change to the user's setup (v1 §7) |

## Captured: Claude Code 2.1.296 through a logging proxy (2026-10-13)

**Method:**
- The proxy (`spikes/capture` on branch `spike/wp3.0a-capture`) forwarded to `api.anthropic.com`
  and logged structure only: header names and values with credentials replaced by their length,
  JSON key and type skeletons, and SSE event counts. No prompt text was logged.
- One prompt ran with the maintainer's claude.ai login, with
  `CLAUDE_CODE_GATEWAY_HINT_HEADERS=1` and `CLAUDE_CODE_ENABLE_GATEWAY_MODEL_DISCOVERY=1`.
- A first attempt picked up an API-key variable and was rejected; it is kept because it shows
  the API-key path and the error shape.
- Logs stay on the maintainer's machine.

| # | Observed | Consequence for UAOS |
|---|---|---|
| CAP-1 | `HEAD /api/hello` arrives first, with no credentials and user agent `Bun/…`; the upstream answers 200 | Confirms CC-2: answered locally, no credential required |
| CAP-2 | `GET /v1/models?limit=1000` was sent **only** in the API-key attempt (`x-api-key`); with the OAuth login, discovery was skipped | Confirms CC-3 and the docs. Discovery needs a key credential |
| CAP-3 | `POST /v1/messages?beta=true`, header names: `accept`, `accept-encoding` (gzip, deflate, br, zstd), `anthropic-beta`, `anthropic-dangerous-direct-browser-access`, `anthropic-version`, `authorization` **or** `x-api-key`, `content-type`, `user-agent: claude-cli/2.1.296 (external, sdk-cli)`, `x-app`, `x-claude-code-prompt-id`, `x-claude-code-request-class`, `x-claude-code-session-id`, and eight `x-stainless-*` SDK headers (arch, lang, os, package version, retry count, runtime, runtime version, timeout) | Open-list forwarding (CC-4) must include non-`anthropic-*` client headers. The `x-stainless-*` headers disclose the user's OS and runtime **by the client's choice**; UAOS passes them through unchanged (v1 header rule) and lists them in the privacy data flow |
| CAP-4 | `anthropic-beta` carries 13 values with an API key, and 15 with the claude.ai login (`oauth-2025-04-20` and `extended-cache-ttl-2025-04-11` added) | Confirms CC-5. A codec must never filter beta values |
| CAP-5 | Body keys: `context_management`, `max_tokens` (128000), `messages`, `metadata` (`user_id`, 186 characters), `model` (`claude-opus-5-5`), `output_config` (`effort: xhigh`), `safeguards`, `stream` (true), `system` (3 blocks), `thinking` (`type: adaptive`), `tools` (29) | The affordability clamp (WP3.5) acts on `max_tokens` = 128,000 by default; it must be dialect-aware, since adaptive thinking has no `budget_tokens`. `context_management` performs server-side thinking clears, which the provider documents as not counting as prefix edits |
| CAP-6 | `messages` contains a **`role: "system"` message mid-conversation**, with its own `cache_control` (`ttl: 1h`) and per-message `output_config` | Codec role `system_entry` must also cover mid-conversation system messages. They stay where they are (CC-15); "newest human turn" means the newest `user` message |
| CAP-7 | `system[0]` is a short block (74 characters, the attribution block); the last system block carries `cache_control` (`ttl: 1h`) | Confirms CC-9. Entry 0 is never edited, and `cache_control` passes through |
| CAP-8 | `safeguards` contains client-side environment metadata: the working directory, the home-directory path length, git state and auto-mode policy lists | The client sends these to the provider itself. For UAOS they are request content: detected and redacted like any other string, and **listed in the privacy data flow** as data the client sends |
| CAP-9 | **The streaming response is gzip-compressed:** `content-type: text/event-stream` with `content-encoding: gzip`, because the client advertised gzip, br and zstd | **New design input** (ADR-0014, ADR-0017). With nothing to observe or rewrite, UAOS relays compressed bytes untouched. When it must observe or rewrite the stream (rehydration, binding-mismatch SLI, loop detection), it requests `accept-encoding: identity` upstream; that header is not an `anthropic-*` one, so the change is allowed. Decision D-29 |
| CAP-10 | Subscription responses carry `anthropic-organization-id`, `anthropic-workspace-id` and 12 `anthropic-ratelimit-unified-*` headers (5h and 7d windows, status, utilization, reset, overage status, fallback percentage, representative claim) | D-17′: plan-usage display has real inputs. Organization and workspace ids are account identifiers: journal them only as ids, never in logs or telemetry |
| CAP-11 | A rejected key gets `401`, `x-should-retry: false`, error `authentication_error` ("invalid x-api-key"), and a `request-id` | Confirms CC-7. Upstream error bodies and headers pass through byte-identical |

## Open: not verifiable from documentation

| Item | Why it matters | How to settle |
|---|---|---|
| Codex: `store`, `previous_response_id` and encrypted reasoning (`reasoning.encrypted_content`) as actually sent | ADR-0005 runs Responses **stateless** (`store=false` enforced, encrypted reasoning passed through) | Capture approved; Codex must first be installed and logged in on the reference machine |
| Codex: exact paths beyond `/v1/responses` (model listing, compaction, other) | The D-28 inventory | Traffic capture |
| Claude Code: behaviour across versions | Drift (B-34) | Re-run the capture per client release; pin in golden transcripts (WP3.8) |
| Codex: whether `-c key=value` overrides work for `model_providers` | The launch recipe (WP3.7) | Capture, or a local dry run without network |
