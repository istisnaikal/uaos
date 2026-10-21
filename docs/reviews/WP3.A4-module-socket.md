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

A final fresh full review of the whole PR followed (round 3, below).

## Final full review (D-31, round 3)

**Reviewed:** the whole PR at `cd5a72e`, by a fresh-context agent, 2026-10-20.
**Result:** 2 High · 6 Medium · 12 Low. The PR stays in draft.
**Verified correct by the reviewer:**
- the schemas and the golden envelope;
- the `memory.read` rules;
- `StateMut` closing F1;
- all 19 seeds.

| | Finding | What was done | Proof |
|---|---|---|---|
| H1 | Frames reached `stream.observe` after forwarding, which is after rehydration (ADR-0017), so a secret masked on the way out could come back to a module. `error.translate` had the same gap. | Contract §2 rule 5 and §4: frames and errors reach a hook as the provider sent them, before rehydration. A PR-8 proof obligation with a seeded violation (§12). | Contract |
| H2 | A replay through `on_event` re-issued declarations: a restart without a checkpoint re-requested every past child Operation, repeating spend. | `EventView::replay` marks a replayed event. Contract §5: the host applies the state changes and discards every declaration. | `a_replay_rebuilds_state_and_declares_nothing`; negative `replay-declares-again` |
| M1 | "As if the module had never stopped" was false: hook-time changes are not journaled, and two concurrent calls in one pocket could lose an update. | §5: the host runs at most one call of a module for one pocket at a time. The resume claim now says that hook changes after the latest checkpoint do not survive a restart, and how a module keeps them. | Contract; PR-8 obligation |
| M2 | The role check walked ancestors only, so a strip of an enclosing node could remove a signed block. No role marked the newest tool result. | `RoleMap::touching` (ancestors plus the whole subtree, as a range of ids) and `RoleMap::may_strip`. A strip must lie inside the point's anchor and touch no forbidden role. New role `NewestToolResult`; `Role::forbids_edit`. | `a_strip_never_encloses_a_forbidden_role`; negative `role-check-ancestors-only` |
| M3 | Nested `AnyDepthKey` walks repeated subtrees (94.6 ms for 16 steps on 16.7 KB). | A step skips nodes inside a subtree it already walked, so it visits each node at most once: O(steps × nodes). | `nested_any_depth_keys_resolve_once_each`, and the property `any_depth_keys_equal_the_naive_walk` against the naive walk. No seeded violation: removing the skip changes the cost, not the answer |
| M4 | The policy engine matches grants without the grant the module carried, and cites the first. | **Open.** It changes the policy engine's `Request`; it waits for the maintainer's choice between this PR and a separate one before PR-8. | — |
| M5 | `uaos.grant/1` is not yet the wire form of `model::Grant`: no provider, `DataClass` cannot hold dots, no human or system principal, no conversions. | **Open**, as M4. | — |
| M6 | Rule 6 claimed pocket isolation as a type rule, though a module's own fields can carry data across pockets. | Rule 6 now states the limit: a module's own fields are outside the guarantee. A Ring 1 rule against interior mutability and statics is owned by PR-10. | Contract |
| L1 | The §11 seed table missed three seeds. | The table lists all 26. | Contract §11 |
| L2 | Stale "a grant or a policy" comments. | Fixed in `model.rs` and the Cedar schema. | — |
| L3 | `CancelOp` passed without `child_operations`; no code for an id outside the module's children or the offer. | `CancelOp` needs the feature; `not_own_child` and `unknown_candidate` are strike codes the host uses. | `cancelling_a_child_needs_child_operations`, `every_code_is_one_the_contract_lists`; negative `module-cancel-without-feature` |
| L4, L5 | `Code`'s `Debug` prints a struck word; module-built ids were journaled unchecked. | §2 rule 4: the host never formats a struck call's declarations, and checks module-built ids before journaling or explaining them. | Contract |
| L6 | Module event naming was unresolved. | §8: the host journals module events as `module.event`, with the module name and the code as fields. | Contract |
| L7 | The view's API named `uaos-json` types that module-api did not re-export. | `Kind`, `NodeId` and `JsonError` are re-exported. | — |
| L8 | `EventDecl`, `GrantDecl`, `EndpointDecl` and `ModuleVersion` were not `#[non_exhaustive]`. | All four now are, with constructors (§9). | The tests build them through the constructors |
| L9 | Weak tests: the selector property ran with an empty mask; case folding was untested for keys; the `chunk.lost` agent was untested. | The property masks random values and keys; `keys_never_fold_case`; `a_lost_payload_record_names_the_agent_of_the_record_it_reports`. | Negative `chunk-lost-drops-agent` |
| L10 | `ModuleText` accepted Unicode tag characters and refused CR. | Tag characters are refused (`TextError::Tag`); CR is accepted. | `module_text_takes_crlf_and_refuses_tag_characters`; negative `module-text-accepts-tag` |
| L11 | `canonical` accepted `;`. | A path parameter is not canonical. | Negative `path-parameter-canonical` |
| L12 | A masked container masked nothing below it; strips were not said to resolve over the masked view; two assumptions had no mechanism behind them. | A masked container masks everything inside it. §2 rule 5 says strips resolve over the masked view. The pool clause is dropped, and note bodies are marked open (§12). | `a_masked_container_masks_everything_inside`; negative `view-masked-container-leaks` |

Under D-31, the PR leaves draft only when no High or Medium remains: M4 and M5 must be fixed here
or split out. A further fresh full review follows the fixes.

## The grant path moves to its own PR (2026-10-21)

M4 and M5 change the policy engine's request and the grant contract. At the maintainer's
choice they leave this PR, and so does the code they change. PR-4b (`p3/a4b-grant-path`, from
main) takes the whole grant path: `uaos.grant/1`, the Cedar `Pocket` entity, `memory.read`
with its consent rule, and their tests and seeded violations. That covers the findings M1 of
round 1, F3 and F4 of round 2, and L4, M4 and M5. PR-4 keeps the module socket, `AgentId`
and the contract text. PR-4b's own reviews are recorded in `docs/reviews/WP3.A4b-grant-path.md`.

## Fresh full review (D-31, round 4)

**Reviewed:** the whole PR at `442c59a` (rebased on main `eab34c6`), by a fresh-context agent
reading only, 2026-10-21. **Result:** 1 High · 5 Medium · 7 Low.
**Verified clean by the reviewer:**
- the golden envelope bytes, and the schema;
- all 23 seeds;
- no probe of masked text;
- `StateMut`;
- unhooked points;
- event value names;
- canonical paths and `classify`;
- both §10 code lists;
- the moved grant path.

| | Finding | Fix | Proof |
|---|---|---|---|
| H1 | `boot_cuts.rs` (from #29, on main) built an `EventDraft` without the new `agent_id` and no longer compiled. | `agent_id: None` (`e607d2a`). | The lane: 524 tests on main `eab34c6` |
| M1 | The host re-read `manifest()` every call, so a module could grow its manifest after admission. | `KernelOffer::admit_module` returns `Admitted`, which keeps the manifest admitted. §2 rule 5 and the host procedures check every call against it. | `a_module_is_checked_against_its_admitted_manifest`; negative `module-manifest-reread` |
| M2 | Every accessor walked ancestors, so cost grew with depth, and strip resolution had no budget. | `Mask::seal` turns masked containers into id ranges, making each check a binary search; an unsealed mask stays correct. A `Visits` budget runs per resolution and, for the host, per call (`MAX_VISITS`). §7 states the cost. | `sealed_and_unsealed_views_agree` (20,000 cases), `a_selector_stops_at_its_budget`; negatives `view-sealed-mask-drifts`, `selector-unbudgeted` |
| M3 | `UsageReport` took undeclared codes and duplicates. | `DialectCodec::dimensions` declares them; `UsageReport::check` refuses others; `dim` refuses a name twice. | `usage_reports_name_declared_dimensions_once`; negative `usage-undeclared-dimension` |
| M4 | A host-side refusal discarded a call's state live, while replay kept it. | §5: only a static strike or `state_exceeded` discards state. A host-side refusal drops the declaration and keeps the state, so replay rebuilds the live state. PR-8 obligation. | Contract |
| M5 | The CHANGELOG claimed as built what is contract text, and miscounted. | Corrected. | — |
| L1 | A strip could remove its anchor itself. | `may_strip` requires the anchor on a proper ancestor. | Negative `strip-removes-anchor` |
| L2 | A masked container's structure stays visible. | Stated in §2 rule 5: structure is not content; findings are strings, numbers and keys. | Contract |
| L3 | Roles failed open under masking. | `may_strip` refuses a strip that touches masked content (`StructuralView::touches_masked`). | Negative `strip-touches-masked` |
| L4 | `ModuleText` let runs of variation selectors through. | A variation selector must follow a base character. | `module_text_refuses_variation_runs`; negative `module-text-accepts-variation-run` |
| L5 | `OnFailure` vs §4. | §4: the point's policy is the floor. `Deny` is refused where nothing is left to deny (`FailureUnavailable`, `point_unavailable`). `OnFailure` is `#[non_exhaustive]`. | `a_failure_cannot_deny_after_the_fact`; negative `failure-deny-after-the-fact` |
| L6 | The `Decls` collector could be swapped. | Hooks get a `DeclsMut` handle by value. | The type |
| L7 | Stale docs; methods. | Docs corrected. `Put`, `Patch` and `Options` added; an unlisted method is denied. | `an_unlisted_method_is_denied` |

Under D-31 this is round 4. A scoped round 5 over these fixes follows; a High or a Medium still
open after it splits the PR.
