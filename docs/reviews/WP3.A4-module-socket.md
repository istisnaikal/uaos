# Adversarial review: WP3.A4, the module socket (P3 Move 1, PR-4, ADR-0010)

**Reviewer:** a fresh-context review agent (plan v2 §4.2, V1). It was read-only on the branch and
ran the crates' tests on Windows 10.
**Reviewed:** `23450d5` (`p3/a4-module-api`), 2026-10-20: the four commits of PR-4. These are the
contract, `AgentId` and `uaos.grant/1`, the Cedar `Pocket` entity with `memory.read`, and the
`uaos-module-api` crate.
**Result:** 2 High · 8 Medium · 8 Low.
**Verified clean by the reviewer:**
- envelope bytes without `agent_id`;
- schemas matching the Rust types;
- default deny for `memory.read` with no grant, and forbid over grant;
- the bidi ranges `ModuleText` refuses and accepts;
- no normalization or case folding in the view;
- selector document order and `Last`;
- no accessor returning a masked value.

**Resolution:** both Highs, every Medium but M8, and every Low are fixed in this PR, each with a
test and, where a seeded bug can show the test bites, a seeded violation (16 in all). M8 and the
parts of L5 and L8 that belong to the host are assigned to PR-8, with the contract saying so
(§12). The D-31 scoped round over the fixes found 0 High, 2 Medium and 6 Low, resolved below.
A final fresh full review follows before the PR leaves draft.

## Findings and what was done

### High

| | Finding | Fix | Proof |
|---|---|---|---|
| H1 | The redacted view showed object keys and numbers raw. The mask covered only string values, while detection scans keys too, so a token used as a key was readable through `key()` and `AnyDepthKey` (contract §2 rule 5; red line 2). | `Mask` covers values (strings and numbers) and keys. A masked key reads as `Masked`, matches no name and is never found by `member`. A masked number reads as `Masked`. A finding the host cannot place refuses the view (contract §2 rule 5). | `masked_keys_and_numbers_read_as_masked`; negatives `view-masked-key-readable`, `view-masked-key-found-by-name` |
| H2 | Module events took any value name and any child correlation code, so a wrong module could put words from a prompt into journal metadata, which a pocket shred does not remove (contract §2 rule 4; I-11; ADR-0007). | `EventDecl.fields` declares value names (at most 8), and `check_decls` strikes any other name. A value name appears at most once. The correlation tag is a `u16`. The tools and configuration keys a child Operation names must be declared `targets`. | `an_event_carries_only_declared_value_names`, `child_operations_name_only_declared_targets`; negative `module-event-value-undeclared` |

### Medium

| | Finding | Fix | Proof |
|---|---|---|---|
| M1 | A Cedar permit allowed `memory.read` across pockets with no grant: no consent, no injection policy. A blanket permit covered every pocket. | The engine allows `memory.read` only with a live grant. A permit, named or blanket, at most asks (contract §6.2). The grant-equals-permit property states that `memory.read` is outside it by design. | `a_permit_alone_only_asks_for_a_cross_pocket_read`; negative `cedar-cross-pocket-without-grant` |
| M2 | `check_decls` treated a point the module never hooked as observe mode, and accepted `Emit` and `Request` there. | A declaration at an unhooked point is a strike (`not_hooked`). | `nothing_is_declared_at_a_point_the_module_did_not_hook`; negative `module-decls-at-unhooked-point` |
| M3 | Missing load-time refusals: a grant's `why` was not checked against the declared reasons; `act` was accepted at observe-only points; the §10 codes `undeclared_code` and `point_unavailable` did not exist; a deadline over its ceiling reported `deadline`. | `UndeclaredCode` and `ModeUnavailable` (codes `undeclared_code`, `point_unavailable`). `HookPoint::acts` is false for `stream.observe`, `response.post` and `error.translate`; the last has no annotation declaration yet. A deadline over its ceiling is now `bound_exceeded`. §10 lists every code the crate produces. | `a_manifest_is_refused_whole_for_each_reason`, `refusal_codes_are_the_documented_ones`; negative `module-act-at-observe-point` |
| M4 | `ModuleState` was atomic per change but not per call. The paper-module test kept calls that had outgrown the state. | A refused change marks the state `exceeded`. The host procedure, written into contract §5 and the test's `host_call`, runs each call on a copy and keeps it only if the copy is not exceeded and its declarations pass. Otherwise the call is a strike (`state_exceeded`). | `a_call_that_outgrows_its_state_is_struck_whole`, `state_is_bounded_and_unchanged_on_refusal`; negatives `module-state-unbounded`, `module-state-call-kept` |
| M5 | Predicate values and `Rank` had no bounds. A member was decoded once per value. | At most 32 values of at most 256 bytes per predicate, at every nesting level. Keys are at most 256 bytes. The member is decoded once and looked up with `contains`. `Rank` names at most 64 candidates, none twice (`bound_exceeded`). | `a_selector_is_bounded`, `a_ranking_is_bounded_and_names_each_candidate_once`; negative `selector-predicate-unbounded` |
| M6 | `PathPattern` matched a raw string prefix: `/v1/models*` matched `/v1/models-x`, dot segments and percent-encoded forms. | Patterns and paths must be canonical: no percent-encoding, backslash, dot segment or empty segment except a trailing one. A path that is not canonical matches nothing. A final `*` matches whole segments. | `path_patterns_match_canonical_paths_by_segment`; negatives `path-pattern-crosses-segment`, `path-not-canonical` |
| M7 | The §11 proofs were not delivered: no seeded violation was registered; `selector-escapes-view` targeted a check that does not exist; there was no property over generated tapes. | 16 seeded violations, registered under the `test` gate. The two language cases move to `language-neutrality` once ADR-0020's PR registers that gate. `selector-escapes-view` is dropped: resolution starts from the root and steps through the tape only, so there is no check to seed. Its claim is proven instead by `selectors_stay_inside_the_view`, a property over generated tapes. | `selectors_stay_inside_the_view` (256 cases); the 16 negatives |
| M8 | `EventView` cannot support replay (no values, no correlation tag, no subscriptions). | **Assigned to PR-8**, the host that defines replay. `EventView`, `OpMeta` and `Candidate` are now `#[non_exhaustive]` with constructors (contract §9), so adding these is not a break. | Contract §12 |

### Low

| | Finding | What was done |
|---|---|---|
| L1 | §3 specified `ModuleId` `[a-z][a-z0-9-]{1,47}`; the code uses `ModuleName`. | The contract now names `ModuleName`, which the envelope's module actor already uses: `[a-z][a-z0-9-]*`, at most 64 bytes. |
| L2 | Derived `Debug` on selectors and `SseEvent` printed keys, values and the upstream event name. | Manual `Debug` with lengths and counts, checked by `debug_output_carries_no_content`. |
| L3 | "A masked value never matches a predicate" was false for `MemberNotIn` and `StringOrArrayWith`. | The claim is now what holds: no predicate's answer depends on masked text. `a_masked_value_cannot_be_probed` checks all three predicates over three different masked texts. |
| L4 | `GrantRecord::validate` accepted `memory.read` on a model, and a pocket resource on other actions. | `ResourceMismatch`, tested by `memory_reads_and_pockets_go_together`; negative `grant-memory-read-off-a-pocket`. |
| L5 | `PocketCursor::advance` did not check the event's pocket; `ModuleState` carries no pocket. | `advance(pocket, seq)` refuses another pocket's event. Binding a state to its pocket in the host's store is the host's (PR-8, contract §12). |
| L6 | `RoleMap::governing` returned an empty, most permissive set for a node outside the view. | It returns `None` there, and the caller refuses the edit. Tested. |
| L7 | Weak tests: the `agent_id` check was a substring test; the `ModuleText` property was one-directional; `ApiMinorAhead` cannot be reached; the modules-off documentation was misleading. | A golden-bytes test, checked equal to main's own serialization. The property now checks both directions. `ApiMinorAhead` cannot be reached in this crate by construction: a module built against a newer crate carries a newer `CURRENT`. The `KernelOffer` documentation says modules-off never calls `admit`. |
| L8 | Contract drift: §3's `HookDecl.view`, `error.translate`'s annotation, dotted configuration keys, and §7's "placeholder". | §3 and §7 are corrected. `error.translate` observes only in this draft. Dotted keys and the annotation declaration go to PR-8 (contract §12). |

## Also found while fixing

- Contract §9 requires the inputs a module receives to be `#[non_exhaustive]`. `OpMeta`,
  `Candidate` and `EventView` were not. They are now, with constructors.
- A stray `|||||||` conflict marker from an earlier local rebase of this branch was in
  `CHANGELOG.md`. It was removed before the review; it was never on main.

## Second round, scoped to the fixes (D-31)

**Reviewed:** `23450d5..3df85dd` and every invariant and caller it touches, by a fresh-context
agent, 2026-10-20.
**Result:** 0 High · 2 Medium · 6 Low.
**Verified closed:** H1 (every accessor and selector step goes through the mask), H2 and M2, M3
(12 refusal and 8 strike codes, exactly §10's), L4, L6, L7 (the journal writes with the same
serializer the golden test uses), canonical paths, and all 16 seeds.

| | Finding | Fix | Proof |
|---|---|---|---|
| F1 (M) | A hook got `&mut ModuleState`, and `new` and `restore` are public, so a module could replace the whole state. That cleared `exceeded` and raised its bound to 64 KiB, and the host kept the call; the resulting checkpoint could never be restored. The M4 fix had written this hole into §5. | Hooks get a `StateMut` handle, by value and for one call. It offers the bounded changes only, so the module cannot swap the state or keep the handle (§5). | The type: `Module::on_hook` and `on_event` take `StateMut`; `a_call_that_outgrows_its_state_is_struck_whole` runs through it |
| F2 (M) | Nothing said what a path no endpoint matches gets, or which class wins on overlap, so a host could forward unmatched or non-canonical paths without detection. | `classify(endpoints, method, path)`: `denied` when the path is not canonical or nothing matches; the most restrictive class on overlap (§7). | `an_endpoint_s_class_is_the_strictest_match_and_unknown_paths_are_denied`; negative `endpoint-unmatched-not-denied` |
| F3 (L) | The consent rule caught a read of the requesting pocket itself, an approval loop that could never end: a grant for the own pocket is invalid. | Only a read of another pocket needs a grant; the own pocket follows policy (§6.2). | `a_permit_alone_only_asks_for_a_cross_pocket_read`; negative `cedar-own-pocket-read-asks` |
| F4 (L) | The grant property's generator never produced `memory.read`, and its comment presented that gap as a design choice. | The generator produces `memory.read`, on the requests' own pockets and on others. Off-pocket, the property checks that native and compiled deny alike and that only a grant allows. 20,000 cases pass. | `native_grants_equal_their_permits` |
| F5 (L) | `Rank(vec![])` passed and vetoed the route without a reason; ids outside the offer were not mentioned. | An empty ranking is a strike; §4 says the host strikes an id outside the offer. | `an_empty_ranking_is_a_strike`; negative `module-rank-empty-accepted` |
| F6 (L) | `Strip` selectors still carry strings a module may copy from content. | §2 rule 4: the host never journals or explains a selector's keys or values, only counts. The CHANGELOG claim is narrowed. | Contract §2 |
| F7 (L) | Weak tests: `ModeUnavailable` for one point only; refusal codes partly; masked keys under predicates; bounds on targets and grants. | Every point is tried with an acting hook; both §10 code lists are compared exactly; a masked key, even one spelling the predicate's own name, is absent to every predicate; targets and grants are bounded. | `only_acting_points_take_an_acting_hook`, `every_code_is_one_the_contract_lists`, `a_masked_key_cannot_be_probed`, `targets_and_grants_are_bounded` |
| F8 (L) | Docs: the `MAX_CODES` comment, the `grants` bound in §3, and `SseEvent` not `#[non_exhaustive]`. | All three fixed; `SseEvent::new` is the host's constructor. | Contract §3, §9 |

Under D-31, a final fresh full review of the whole PR follows before it leaves draft.
