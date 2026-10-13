# Adversarial review: WP2.4 identity (PR #17)

**Reviewer:** a fresh-context review agent with the fixed V1 checklist (plan v2 §4.2), read-only,
probing a scratchpad export of the branch. **Reviewed:** `145a47e`, 2026-10-13.
**Result:** 0 Critical · 2 High · 7 Medium · 5 Low. The High findings blocked merge.
**Resolution:** every High and Medium finding fixed with a regression test, and Low findings fixed
or accepted with a reason (table at the end).

## Findings as reported

### High

**H1. Any revoke or epoch bump on a stale data directory switches the restore guard off.**
- `next_seq` took `max(journal, keychain) + 1`, gaps were allowed, and nothing refused writes
  while the directory was stale.
- Restoring a journal from before revoking X and then revoking an unrelated Y caught the journal's
  counter up with the keychain, and X verified again. `bump_epoch` had the same effect.

**H2. One write to the keychain counter makes revocation impossible.** `saturating_add` together
with "strictly greater": with the counter set to `u64::MAX`, the first revoke succeeded and every
later revoke failed, so a leaked key kept verifying.

### Medium

- **M1. The property is circular and did not catch the seeded negative.**
  - It used `scope_within` as its own oracle.
  - It asserted nothing when verification failed.
  - It had no revocations, pools were always `Any`, and only `Model` resources were generated.
  - The epoch-skip seed failed a unit test, not the property.
- **M2. `scope_covers` failed open** when the request left out a dimension the scope restricted.
- **M3. Missing keychain entries were treated as a first run.**
  - A missing HMAC key was silently recreated, which invalidated every credential without any
    diagnosis.
  - A missing counter read as 0, so a restored directory with a revoked key verified again.
- **M4. A transient keychain failure during a revoke forced re-issuing every credential**, and the
  error message claimed a backup had been restored.
- **M5. User mistakes were reported as internal S2 failures** (`IDENTITY-0010`), and an unknown
  parent as `IDENTITY-0003` with the leak flag set.
- **M6. Docs claimed more than the code delivers.**
  - The doc comments implied a UAOS redaction class that does not exist yet.
  - Scope "re-checked on verify against a narrowed parent" cannot happen, because records are
    immutable.
  - The PR called the self-test PROVEN against the property, which was not true.
- **M7. The identity tables grow without bound** (I-08).

### Low

- **L1. Issuing under a dead chain succeeds.**
  - Issuing under a revoked grandparent, under an epoch-stale chain, or with an already-expired
    scope all succeeded.
  - `bump_epoch` worked on a revoked credential.
- **L2. Copies of key material are left in memory.**
  - A non-zeroized copy of the HMAC key array.
  - The `hmac::Key` state rebuilt on every verify.
  - Secret bytes moved by value.
- **L3. `recover_after_restore` had no precondition.**
- **L4. The schema and the Rust validation disagree.**
  - Label length: the schema counts code points, Rust counted bytes; Rust also rejects C1.
  - There was no `maxItems`.
  - The generated names `ScopeSet2/3/4` are unstable.
  - `ResourceKind::Pool` duplicates the `pools` dimension.
  - The doc said "after this instant", while the code treats the instant itself as expired.
- **L5. Error details leak and one flag is wrong.**
  - `Display` text names ancestor ids.
  - Raw journal errors appear in `Unavailable`.
  - `KEYS_UNAVAILABLE` is marked retryable even for a malformed entry.

## Resolution

| Finding | What changed | Proof |
|---|---|---|
| H1 | Revoke and bump take exactly `journal + 1`. Only `restore_recovered` may jump ahead, and it now revokes every live master **atomically in one entry**, so a crash can never leave a half-recovered directory that looks healthy. Issue, revoke and bump refuse while the counter is stale | `a_restored_data_directory_fails_closed_and_ordinary_writes_cannot_reopen_it`: revoke, bump and issue on a stale directory are refused, nothing is recorded, and recovery is one entry |
| H2 | `checked_add` everywhere. A counter at or above 2^62 (`GUARD_CEILING`) or malformed reads as tampering, and verification and writes fail closed with `IDENTITY-0012` (S1). A revocation is never refused silently: it fails visibly with the counter error | `a_tampered_or_deleted_counter_fails_closed_and_cannot_block_revocation_silently` |
| M1 | The property now checks random hierarchies **with revocations and epoch bumps** against an independent model (valid ⇔ no ancestor-or-self revoked and no strict ancestor bumped). It also checks an independent coverage oracle over a finite request universe (anything a credential covers, every ancestor covers), across all dimensions and both resource kinds. Totals guard against vacuity. The negative case targets the property | `cargo xtask negative identity-epoch-check-skipped` → **PROVEN** against `derivations_match_the_model`. The reviewer's mutation (making `scope_within` always true) is now caught: "a credential covers a request its ancestor does not" |
| M2 | A restricted resource or pocket dimension left out of a request denies it. Pools are the documented exception: a request without a pool spends nothing | `a_restricted_dimension_left_out_of_a_request_is_denied` |
| M3 | `IdentityKeys::open(…, credentials_exist)` creates a key only when no credential exists. Otherwise a missing or malformed key is `KeyLost` (`IDENTITY-0011`). A counter more than one behind the journal fails closed | `the_identity_key_persists_and_a_lost_key_is_not_silently_replaced`, and the deleted-counter case in the H2 test |
| M4 | The order is reversed: **journal first, keychain second**. An interrupted keychain write leaves the counter exactly one behind (`GuardOutcome::Lagging`). Verification keeps working, and `Identity::reconcile` repairs it on open. No re-issue is needed | `an_interrupted_keychain_write_lags_by_one_and_is_repaired` |
| M5 | New codes: `IDENTITY-0013` invalid request (User/Info), `-0014` limit reached. `ScopeTooBroad` maps to `-0008`. An unknown parent is an invalid request | `request_mistakes_are_user_errors_not_internal_failures` |
| M6 | Doc comments say the redaction class arrives in WP2.4b. Containment is "checked at issuance; records are immutable; narrowing means re-issuing", and the verify-time re-check is documented as defence in depth. The PR text and CHANGELOG were corrected. ADR-0011 is amended in #13 to match | review of the text |
| M7 | At most 4,096 live credentials and 256 live children per parent. Revoked entries leave the state through journal compaction (P4), stated in `limits` | `live_children_per_parent_are_bounded` |
| L1 | Issuance requires the parent's chain to be live at `now` and the scope not yet expired. Bumping a revoked credential is refused | `issuing_under_a_dead_chain_or_with_an_expired_scope_is_refused` |
| L2 | **Partly accepted.** The key is read into a zeroizing buffer. One by-value copy into `SecretKey::from_bytes`, and the per-call `hmac::Key`, remain in `uaos-platform::crypto`'s API; changing that is recorded as a platform follow-up (cache a zeroizing HMAC context) | — |
| L3 | Recovery requires a stale directory | `recovery_is_refused_when_nothing_is_stale` |
| L4 | Labels are counted in characters, and the schema pattern excludes C1. `maxItems: 8`. Stable `ScopeSetOf<T>` names. `ResourceKind::Pool` removed. Expiry doc says "from this instant on". Closed enums are kept deliberately while the contract is a draft, and are reviewed at the RC-1 freeze | regenerated `schemas/credential.v1.json` |
| L5 | **Partly accepted.** `IdentityError` documents that `Display` is for the local journal and that callers get the registered generic message (enforced at the API layer, WP3.6). `KEYS_UNAVAILABLE` stays retryable because it now covers only an unreachable or denied keychain; malformed entries map to `-0011` and `-0012`, which are not retryable | — |
