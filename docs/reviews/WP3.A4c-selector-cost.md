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
- **Changed APIs:** none is used outside `uaos-module-api`.
- **Unicode tables:** the default-ignorable and unified-ideograph tables match Unicode 16.0.
- **Seals:** a key finding on the root or an array element refuses the seal.
- **The procedures:** `call_hook` and `call_event` match §5.
- **Seeds:** all 37 anchors are unique, and the eight new seeds and the older ones bite.

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
