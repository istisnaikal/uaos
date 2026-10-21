# Adversarial review: WP3.A4c, the selector cost, `ModuleText` bases, seals and procedure (P3 Move 1, PR-4c, #42)

**Reviewer:** a fresh-context review agent (D-31, V1). It was read-only on the branch and did not
build; it reasoned from the code and checked every `replace` anchor with a script.
**Reviewed:** `6f6d7ff` (`p3/a4c-selector-cost`, base `ceadeb0`), 2026-10-21: the spec commit and
the code commit. Together they amend `docs/adr/appendix/0010-module-socket.md` §2, §5, §7, §11
and §12, and implement the work split from PR-4 under D-31 at round 5.
**Result:** 0 High · 3 Medium · 7 Low.

**Verified clean by the reviewer:**
- **Charging:** every lookup charges each member before it compares, and the per-step work left
  uncharged stays within the visits charged.
- **Key comparison:** it stops at the first difference.
- **The raw bound:** `>` 1,536 bytes, quotes excluded, is the right boundary, and it is checked
  before any decoding. Masked and unmasked strings answer the same.
- **`RoleMap`:** one budget, and a failed assignment assigns nothing.
- **Changed APIs:** none was used outside `uaos-module-api` at the reviewed base. After the
  rebase onto `91288c9`, #41's relay was (scoped round M-a, below).
- **Unicode tables:** the default-ignorable and unified-ideograph tables match Unicode 16.0.
- **Seals:** a key finding on the root or an array element refuses the seal.
- **The procedures:** `call_hook` and `call_event` match §5.
- **Seeds:** all 37 anchors are unique, and the eight new seeds bite. Of the older seeds,
  `module-manifest-reread` no longer did (M1).

**Resolution:**
- **Fixed in this PR:** every Medium, and L1–L5, each with a test or a contract change.
- **Resolved by M2's fix:** L4.
- **L6:** the Mongolian free variation selectors are fixed. The rest is a conscious assumption
  owned by ADR-0020's PR, before PR-8 (contract §12).
- **L7:** the tables now name their sources. An independent check against the UCD is debt,
  owned by WP3.9.

The D-31 scoped round over these fixes follows, then a final fresh full review before the PR
leaves draft.

## Findings and what was done

### Medium

| | Finding | Fix | Proof |
|---|---|---|---|
| M1 | The seed `module-manifest-reread` no longer bit. It rewrites the accessor `Admitted::manifest()`, but the new `call_hook` and `call_event` read the field directly, so the seeded copy checked the same snapshot. The `negative` job, a merge blocker, would have failed. | Both procedures read the admitted snapshot through `self.manifest()`. | The existing seed bites again: `a_module_is_checked_against_its_admitted_manifest` |
| M2 | A seal identified its tape by a fingerprint: start address, length and node count. A `String` cleared and refilled with another document of the same length and node count matched it, so the stale ranges masked the wrong nodes, against §2 rule 5. | `Mask::seal` returns a `Sealed` that borrows the tape and the mask and builds the view itself (`Sealed::view`). A seal therefore cannot be paired with another tape, and the buffer cannot be refilled while it lives: the borrow checker refuses it. `StructuralView::new` is the unsealed view and is `const` again. | `a_sealed_view_reads_its_own_tape_sealed`; `sealed_and_unsealed_views_agree` (256 cases) over `Sealed::view`. The seed `mask-seal-ignores-tape` is retired: no runtime check is left to seed. |
| M3 | The decode bound had no proof that bit. The "one byte past" case could never equal a value, with or without the shortcut, so deleting the check passed every test and every seed. | A test-only decode counter on `ViewNode::text`, as `uaos-redact` counts its work, and a unit test of `in_values`: at the bound the string is decoded and matches; one byte past, it is never decoded. | `a_string_past_the_raw_bound_is_never_decoded`; negative `selector-raw-bound-too-loose` |

### Low

| | Finding | What was done |
|---|---|---|
| L1 | §11 said "the three language cases"; six are registered on `language-neutrality`. The CHANGELOG omitted §11. | §11 lists all six; the CHANGELOG cites §11. |
| L2 | "Each step visits a node at most once" is not true with per-member charging. A node can be examined twice in one step. | §7 and the selector module's doc now say that a step *selects* a node at most once and that the budget counts examinations, not nodes. The bound is unchanged. |
| L3 | "On its own tape the seal still holds" passed with or without the seal, because the node reads masked unsealed too. | `StructuralView::is_sealed()`. The test asserts it is true for the sealed view and false for the unsealed one. |
| L4 | A seal mismatch was silent: the view fell back to O(depth) a visit, with no signal to the host. | Resolved by M2: a mismatch cannot be expressed. `is_sealed()` reports the cost class, and PR-8 owes "a host builds a module's view from the seal" (§12). |
| L5 | §5 claimed that no host can run the procedure differently, but `on_hook`, `on_event`, `StateMut::new` and `DeclsMut::new` are public. | The text now says every host gets the same procedure, and that a module's entry points stay public for tests. PR-8 owes "the host calls a module only through `call_hook` and `call_event`" (§12). |
| L6 | Invisible runs outside the rule are still accepted: the Mongolian free variation selectors U+180B–U+180D and U+180F; runs of ZWSP, ZWNJ, ZWJ, U+2060–U+2064 and the Hangul fillers; and Cf, private-use and noncharacter bases. | **Fixed:** the Mongolian selectors are variation selectors, as Unicode's `Variation_Selector` property says, with tests. **Conscious assumption (§12):** ZWJ and ZWNJ are needed in emoji sequences and in scripts such as Persian and the Indic scripts, so which other invisible characters to refuse belongs to ADR-0020 (D-36). The kernel's final scan stays the backstop. **Owner:** ADR-0020's PR, before PR-8. |
| L7 | The test oracle's tables are hand copies of the code's. | **Fixed:** both name their exact Unicode 16.0 source files, to re-derive from when Unicode is bumped. **Debt:** an independent check against a vendored UCD extract. **Owner:** WP3.9, before RC-1. |

## Debt accepted from this review

| Item | Owner | Phase |
|---|---|---|
| L6: other invisible characters in `ModuleText` | ADR-0020's PR (D-36) | before PR-8 |
| L7: an independent UCD check of the Unicode tables | WP3.9 | before RC-1 |

## D-31 scoped round (over the fixes, `d672a44` and the relay change)

**Reviewer:** a fresh-context agent, read-only. It covered the fix diff and every invariant and
caller the diff touches.
**Result:** 0 High · 1 Medium · 5 Low.

**Verified clean:**
- **M2:** only `Sealed::view` builds a view with ranges, and no public path can pair a seal
  with another tape. The lifetimes are sound: a PR-8 host can hold a `Sealed` across a call.
- **M3:** the decode counter sits after the mask check and before any decode, and the seed
  bites.
- **M1:** both seeds bite.
- **`#[must_use]`:** it fires for `mask.seal(&tape)?;`. The workspace denies `unused_must_use`,
  so the old pattern no longer compiles.
- **Variation selectors:** the set matches Unicode 16.0, and the oracle agrees with the code,
  U+180E included.
- **Registration:** the §11 rows (39 then, before the final review's additions), the gates, and
  every anchor in the module socket and the relay.

| | Finding | What was done |
|---|---|---|
| M-a | After the rebase onto `91288c9`, #41's relay still sealed a mask and built `StructuralView::new` over it. The `Sealed` was dropped, so the relay read unsealed, at O(depth) a visit against §7's O(log ranges). The leftover `mut` failed clippy, so the fix commit's "clippy clean" held for its own base only. | The relay reads through `sealed.view()`. `Sealed` is `#[must_use]`, and the workspace's `unused_must_use = deny` makes a dropped seal a compile error. `cargo xtask ci` passes on the combined tree (623 tests). |
| L-a | The working tree deleted four tracked proptest regression files (`uaos-policy`, `uaos-state`), from a cleanup glob. | Restored from `d672a44` before the commit was replaced; no commit on the branch deletes them. |
| L-b | Nothing proved that `call_event` checks the admitted snapshot: the test module had no `on_event`. | The test module declares in `on_event` too, and `a_module_is_checked_against_its_admitted_manifest` checks an event. Negative `call-event-manifest-reread`. |
| L-c | `MemberNotIn` and `StringOrArrayWith` had no per-member charge test. | `a_lookup_spends_a_visit_per_member` covers all four lookups. |
| L-d | The L6 assumption listed a sample of what `ModuleText` accepts. | It states the rule. |
| L-e | Wording: the review claimed every older seed bit; two `decl.rs` tables did not name `PropList.txt`; `inside_masked`'s doc still spoke of a mask sealed against a tape. | Fixed. The suggested `compile_fail` doctest is not added: it passes on any compile error, so it would prove little beyond the borrow rule itself. |

## D-31 final fresh full review (`2633697`)

**Reviewer:** a fresh-context agent, read-only, over the whole five-commit diff.
**Result:** 0 High · 2 Medium · 8 Low. A second final full review follows these fixes, as D-31
allows up to round 5.

**Verified clean:**
- **Selector cost:** every examination is charged, and the raw-length shortcut is correct and
  leaks nothing.
- **`Sealed`:** sound lifetimes; `Clone` and `Debug` are harmless.
- **The procedures and the relay** match their contracts.
- **Unicode:** the tables match Unicode 16.0. Emoji ZWJ sequences, keycaps, CJK IVS and the
  Mongolian selectors are accepted.
- **Seeds:** all 192 anchors are unique, and every seed bites.

| | Finding | What was done |
|---|---|---|
| M1 | Nothing tested or seeded `call_event`'s state-exceeded strike. | The test module grows its state in `on_event` too. `an_event_that_outgrows_its_state_is_struck_whole` covers the event procedure live and on replay. Negative `call-event-keeps-outgrown-state`. The default `on_event` is checked through a module that has none, by the procedure, not on the real state. |
| M2 | "An unsealed view is as correct" was false: it cannot refuse a finding it cannot place, so such a finding masks nothing. `HookCx::with_view` took any view. | `HookCx::with_view` takes a `Sealed`. Rule 5 and the view's docs say what an unsealed view cannot do. PR-8 owes building every module and codec view from a seal (§12). |
| L1 | §11 had no row for `call-event-manifest-reread`; the counts were off. | The rows are added, with this round's two new seeds. The CHANGELOG counts them. |
| L2 | The `RoleMap` budget equals the parser's node limit, so a node-dense request near it can be refused. | A PR-8 obligation: the Messages codec's `roles()` is measured at the limit (§12). |
| L3 | No seed covered the selectors' masked-key check in `ViewNode::key_is`. | Negative `view-masked-key-matched-by-name`. |
| L4 | Nothing proves a key comparison stops at the first difference. | Debt: it is `uaos-json`'s `Node::key_is`. A work counter there is owed before PR-8 (§12). |
| L5 | §7 overclaimed: `roles()` bounded and a budget never duplicated, while `Visits::new`, `RoleMap::default` and `Selector::resolve` are public. `RoleMap` equality compared the visits spent. | §7 states the bound for a host that follows §5. `RoleMap` equality compares roles only. |
| L6 | The remaining covert channel was not stated: one selector after each visible base. | A conscious assumption in §12, with the numbers. |
| L7 | Subdivision-flag emoji are refused by the tag rule, unrecorded. | A conscious assumption in §12. |
| L8 | Wording: §5's "Otherwise", the L6 ranges (U+2066–U+2069 are refused), format bases, and the CHANGELOG's `ModuleText` line. | Fixed. |
