# ADR-0020: Seven locales above a language-neutral kernel

**Status:** Proposed (opened 2026-10-20; earliest decision 2026-10-22, 48 h; D-36) · **Refs:** CLAUDE.md §3 (language neutrality, prefix-stable rendering), §4 (i18n, merge blockers), C-20, C-22, C-24, C-49, C-60 · **Builds on:** ADR-0001, ADR-0005, ADR-0014, ADR-0017

## Context

The maintainer asked on 2026-10-20 for seven locales instead of "TR/EN initial": EN, TR, DE, FR,
ES, IT and AR. The request also asked for continuity across rehydration and checkpoint
boundaries, with no state drift and no data bleed.

Three kinds of text carry language, and each one fails differently:

1. **Content** is what the user and the model write. UAOS forwards it, and its language is not
   UAOS's to choose. Any change made because of language breaks four things:
   - the provider's prompt-cache prefix (ADR-0005);
   - provider signatures over thinking blocks;
   - redaction offsets;
   - the user's bytes.

   These are the classic hazards:
   - Turkish dotted and dotless i: `"İ".to_lowercase()` is two code points, so lengths change;
   - German `ß` against `ẞ` and `ss`;
   - precomposed `é` against `e` plus U+0301. NFC and NFD are different bytes for the same
     text;
   - Arabic combining marks (tashkeel) and bidirectional controls.
2. **Injected text** is what UAOS or a module adds to a request for the model to read. Examples:
   an @devam side-effect warning, `agent_message`, `remediation`. If it is rendered again after
   a locale change, a sent prefix changes, and the cache misses for the rest of the Session.
3. **Surface text** is what UAOS writes for a person: errors, CLI output, the panel, docs. It
   fails in four ways:
   - a missing translation;
   - placeholders that differ between locales;
   - right-to-left layout;
   - shortcuts that a keyboard layout cannot reach.

What main has today:

- The kernel folds case only on ASCII protocol tokens: `chunked`, host names, `jsonl`,
  `localhost`.
- `uaos.error/1` carries a `message_key` (for example `error-budget-unknown-pricing`) next to the
  English `agent_message` and `remediation`.
- The `path-spaces-unicode` gate builds from a path with `ü`, `ş` and `ı`.
- There is no catalog, no locale setting and no multilingual corpus.

## Decision

1. **Seven GA locales:** `en`, `tr`, `de`, `fr`, `es`, `it`, `ar`. `en` is the source locale.
   `ar` is right-to-left.
2. **The kernel is language-neutral.** Rings 0 and 1 treat content as bytes:
   - no Unicode normalization (NFC, NFD, NFKC, NFKD);
   - case folding only on ASCII protocol tokens;
   - bidirectional controls in content are never reordered, inserted or removed;
   - edits happen only at tape node boundaries (ADR-0014), so a code point is never split.

   The locale list is a product decision, so no Ring 0 or Ring 1 type names a locale (CLAUDE.md
   dependency direction). Modules and codecs report with stable ASCII codes (`Code`,
   `ErrorCode`), never with prose meant for a person.
3. **Surface text is a key plus a catalog.** Each user-facing string has a stable key and an
   entry in every GA locale. The catalog lives in the surface layer (the CLI and the panel), in
   one file per locale. The `locale-catalog` gate fails the build when:
   - a key lacks an entry in a GA locale;
   - a key's entries use different placeholders;
   - a catalog holds a key that no registry defines.

   A requested locale outside the seven falls back to `en`. A GA locale never falls back,
   because the gate has already refused the gap.
4. **Injected text is rendered once and replayed as bytes.**
   - The locale is part of the configuration snapshot pinned per Operation (plan, PR-6 and
     PR-7).
   - Text injected into a request is rendered in that locale and journaled as bytes.
   - @devam, @yenipen, rehydration and checkpoint restore replay those bytes. Nothing renders
     them again.
   - A locale change applies only to new injections, from the next turn boundary.
   - `[CONSCIOUS ASSUMPTION]` At RC-1, agent-facing text stays in `en`. This covers
     `agent_message`, `remediation` and module appends. One byte form for every user keeps
     cache prefixes and evaluations comparable. A per-Session agent locale is a later option,
     and it stays bound by this rule.
   - Hooks get the pinned locale through `HookCx::config()` (PR-6) as an opaque, validated
     BCP 47 tag, not a closed enum.
5. **Bidirectional controls.**
   - **In content:** forwarded untouched (rule 2).
   - **In module text (`ModuleText`):** explicit embedding, override and isolate controls are
     refused (U+202A–U+202E, U+2066–U+2069). The implicit marks are accepted (U+200E, U+200F,
     U+061C). A model gains nothing from an override, and a person reading the panel can be
     misled by one (Trojan Source, CVE-2021-42574).
   - **In the panel:** user content is shown in bidi isolation (`dir="auto"`), and explicit
     controls are shown as visible markers.
6. **Keyboard.** Every shortcut is reachable on each GA locale's common layouts and is tested
   per layout (C-22): TR-Q, TR-F, German QWERTZ, French AZERTY, Spanish, Italian, Arabic.
7. **Docs.** `en` is normative. A translated page names the `en` commit it translates, and a
   stale page says that it is stale.
8. **The one opt-in exception is @pring (C-24).** It is the only path that changes the language
   of content:
   - it runs only when the user asks;
   - it shows its diff;
   - it is journaled.

   Rule 4 then keeps the prefix it produced stable.

## Alternatives rejected

- **A closed locale enum in `uaos-contracts` or `uaos-module-api`, checked at compile time.**
  - Ring 0 would depend on a product decision.
  - An eighth language would become a breaking change, both to `module/1` after its freeze
    (D-15) and to every schema that carries the enum. `schema-compat` treats any enum change as
    breaking.

  The compile-time check belongs where the catalog lives (rule 3).
- **Normalizing content to NFC "for consistency."** It changes bytes the user and the model
  wrote. That breaks prefix caches, provider signatures and redaction offsets (ADR-0005).
- **Unicode case folding in detectors or in tag matching.**
  - Lengths change (`İ` becomes `i̇`), so offsets computed on a folded copy do not map back.
  - Dangerous tags stay an exact byte match (C-20), so a look-alike from another script never
    triggers one.
- **Falling back to `en` for a missing entry in a GA locale.** It hides incompleteness, so the
  gate refuses instead.
- **Localizing agent-facing text per user by default at RC-1.** Prefixes and evaluations would
  diverge between users, and the text is read by a model, not a person.

## Consequences

- Each user-facing string costs seven entries. The cost grows with the CLI (M3) and the panel
  (P4).
- Each locale needs a native-speaker reviewer before GA. **Unknown:** who reviews DE, FR, ES, IT
  and AR. Machine drafts are allowed only when marked as drafts (red line 10).
- The panel needs logical CSS properties and an RTL layout. The a11y lane runs its critical
  flows in `ar` as well as `en`.
- `ModuleText` refuses explicit bidi controls, so a module that needs one cannot have it. This is
  accepted because no planned module needs one.
- Egress and durability do not change. Rules 2 and 4 restate what those layers already do with
  bytes.

## Threat and privacy note

- **Display spoofing:**
  - bidi overrides in module text are refused (rule 5);
  - confusable scripts in tags are covered by the exact byte match (C-20).

  On acceptance, the threat model gains a row for these, to be signed by the maintainer.
- **Prefix and signature integrity:** rules 2 and 4 keep content and sent prefixes
  byte-identical.
- **Privacy:**
  - the locale is local configuration. UAOS never sends it upstream and never reports it as
    telemetry;
  - while agent-facing text stays in `en` (rule 4), nothing a provider receives reveals the
    user's UI language.

## Verification

| Gate | Status | Proof |
|---|---|---|
| `language-neutrality` | pending (P3); active from PR-4 | A seven-locale corpus with the hazards above crosses five stages with **0 byte differences**: `uaos-json` parse, the structural view, selectors (exact match, no folding), `ModuleText`, and `ModuleState` checkpoint and restore. The corpus covers dotted and dotless i, `ß` and `ẞ`, NFC against NFD, Arabic with tashkeel and bidi marks, `\u` escapes and astral characters. PR-7 extends it to the pipeline: request in, egress bytes out, outside redacted spans. M2 adds a mid-Session locale change to `prefix-stability`. Negatives: a seeded case fold in selector matching, and a seeded bidi override accepted by `ModuleText` |
| `locale-catalog` | pending (P4) | The rules of Decision 3. Negatives: a missing entry, a mismatched placeholder, a dead key |
| `a11y-critical-flows` | pending (P4) | The same flows, run in `ar` |
