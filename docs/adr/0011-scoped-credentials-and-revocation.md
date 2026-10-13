# ADR-0011: Scoped credentials, hierarchy and revocation

**Status:** Proposed (opened 2026-10-13; earliest decision 2026-10-15, 48 h) · **Plan refs:** v2 §2.8 ADR-0011, WP2.4, C-07/C-08/C-09, T2, T13 · **Builds on:** ADR-0004, ADR-0007, ADR-0008

## Context

Agents must never hold provider keys (ADR-0004). They authenticate to UAOS with credentials that
UAOS issues. Those credentials carry the cells C-07 (master clustering), C-08 (sub-master
derivation) and C-09 (scoped keys).

Five properties are load-bearing:
1. **A leaked credential is recognisable.** Secret scanners, including our own redactor, must
   find it in logs, commits and prompts.
2. **A child can never exceed its parent.** "Exceed" has to be decidable, not a heuristic.
3. **Revocation holds.** It reaches every descendant and takes effect on the next verify.
4. **Revocation survives a restore.** Restoring an old copy of the data directory must not
   resurrect a revoked key.
5. **Verification leaks nothing useful through timing,** and never stores or logs the secret.

## Decision

1. **Format.** `uaos_sk_` + 52 characters of Crockford base32 (32 random bytes from the OS
   CSPRNG) + 7 characters of Crockford base32 encoding a CRC-32 of those bytes.
   - The checksum lets scanners reject random look-alikes without a lookup, which keeps false
     positives low.
   - Detector set v1.1 in `uaos-redact` recognises the format, as a high-risk class (WP2.4).
   - A rule for upstream gitleaks is proposed after RC-1.
2. **Storage.**
   - UAOS stores only `HMAC-SHA-256(identity key, secret)`. The identity key lives in the OS
     keychain (`<installation>/identity/hmac`, ADR-0007 mechanism).
   - Verification computes the HMAC and looks the digest up. Equality of a keyed digest tells an
     attacker nothing about the secret, so no secret-dependent comparison exists.
   - The secret is shown once, at issuance. It is never journaled; the journal holds the digest.
   - A pocket's agent key is kept in the keychain (`<installation>/pocket/<id>/agent-key`) so
     that `uaos run` can inject it again. This adds no exposure beyond ADR-0004's same-user
     residual.
3. **Hierarchy.**
   - `master` (held by the human principal) → `sub` (normally one per pocket) → `child`
     (optional, e.g. per subagent).
   - Depth ≤ 4 (`limits::MAX_CREDENTIAL_DEPTH`).
   - A credential record holds its id (`cred_…`), kind, parent, digest, scope, issue time,
     expiry, `parent_epoch` and its own `epoch`.
4. **Scope.** A scope is a set of dimensions:
   - actions: a subset of the kernel action set plus registered module actions;
   - resource patterns: **exact or prefix only**, e.g. `model:claude-` (no globs or regexes, so
     containment stays decidable);
   - pockets: a set of ids;
   - pools: the budget pools it may reserve from;
   - an expiry.

   **child ⊆ parent** means each dimension is a subset, every child pattern is covered by some
   parent pattern (prefix containment), and the child's expiry is no later than the parent's.
   The check runs at issue. Records are immutable, so narrowing a scope means re-issuing; the
   check is repeated on every verify as defence in depth against a corrupted state. Violations
   return `UAOS-IDENTITY-0002`. *(Amended 2026-10-13, review M6.)*
5. **Authorization.** Verify yields `Principal::Agent(cred_id)` plus its effective scope. An
   Operation is allowed only if the scope covers (action, resource, pocket, pool) **and** the
   Cedar policy allows it (ADR-0008). The scope is an upper bound; deny wins; the explanation
   names the scope as a basis.
6. **Revocation.**
   - **One credential:** set its `revoked` flag, written as a **critical** journal record
     *before* `revoke` returns.
   - **All descendants at once:** bump the parent's `epoch`. A credential is valid only if, at
     every link of its ancestor chain, its stored `parent_epoch` equals the parent's current
     `epoch`.
   - Verify walks at most 4 links in an in-memory table rebuilt from the journal. The next
     verify after a revocation fails with `UAOS-IDENTITY-0001`.
7. **Restore guard.** *(Amended 2026-10-13 after the WP2.4 adversarial review,
   `docs/reviews/WP2.4.md`, findings H1, H2, M3 and M4.)*
   - **Recording.** Every revocation and epoch bump carries a revocation count of exactly the
     journal's count plus one. It is **journaled first**; the counter in the OS keychain
     (`<installation>/identity/revocation-seq`) is raised **afterwards**.
   - **On every verification and write,** the keychain counter is compared with the journal's
     count:
     - **equal:** normal;
     - **one behind:** a keychain write was interrupted; verification continues and the next
       open repairs it;
     - **ahead:** the data directory predates a revocation. Verification **and every write**
       fail closed with `UAOS-IDENTITY-0005`. An ordinary revoke, bump or issue must not be able
       to close this gap, because that would silently un-revoke a key;
     - **further behind, at or above 2^62, or malformed:** the counter was deleted or altered;
       credentials are refused with `UAOS-IDENTITY-0012` (S1).
   - **Restore recovery** is one atomic `restore_recovered` entry. It revokes every live master
     and is the only entry allowed to jump the count to the keychain's. A crash therefore never
     leaves a half-recovered directory that looks healthy. Recovery is refused when nothing is
     stale.
   - **The identity key is created only when no credential exists.** A key that is missing or
     malformed while credentials exist is `UAOS-IDENTITY-0011` and is never silently replaced.
   - This is honest about its boundary: it detects a restored data directory, not a restored
     keychain.
8. **Rotation.** Issue a successor with the same position and scope, then revoke the
   predecessor after an explicit grace period that defaults to 0. Rotation is two journaled
   operations, never an in-place change.
9. **Contracts.**
   - `uaos.credential/1` for the record; secret-free by construction, since the type has no
     field for the secret.
   - `uaos.grant/1`, exported from the policy `Grant`.
   - `uaos.approval/1` is defined here and implemented in WP3.6 (ADR-0012).
   - New error codes: `IDENTITY` 3 unknown credential, 4 expired, 5 data directory older than
     the latest revocation, 6 depth exceeded.

## Alternatives rejected

- **Opaque random tokens without structure:** scanners cannot recognise them, so leaks go
  unnoticed.
- **JWTs:** a parsing and signature-validation surface, claims that bloat every request, and
  revocation that still needs server state.
- **Revocation lists:** they grow without bound (I-08). Epochs revoke a whole subtree in O(1)
  and verify in O(depth).
- **Glob or regex resource patterns:** containment between globs is costly in general and easy to
  get subtly wrong. Exact and prefix patterns cover the real cases (model families, tool
  namespaces).
- **Storing the secret encrypted, so it can be shown again:** it widens what a data-directory
  copy leaks. Re-issuing is cheap.

## Consequences

- Losing the keychain (identity key) invalidates every credential. That is the intended fail
  closed; `uaos doctor` reports it, and recovery is re-issuing.
- A same-user agent can still read its own pocket's agent key from the keychain (ADR-0004
  residual). It gains nothing it doesn't already have, because the key is its own.
- Credential verification adds one HMAC and up to four map lookups per request, well under the
  policy budget.

## Threat and privacy note

- **T2 (secret leakage):** recognisable format, redaction class, digest-only storage, never
  logged.
- **T13 (same-user agent):** the agent cannot widen its scope (⊆ on every verify) or un-revoke
  (critical record plus restore guard). It can read its own key, which is stated.
- **Privacy:** credential records hold no personal data beyond what the maintainer types as a
  label.

## Verification (WP2.4)

- **Property tests:**
  - no derivation produces a child that escapes its parent on any dimension (10k cases);
  - a narrowed parent invalidates children that now exceed it;
  - an epoch bump invalidates every descendant and nothing else;
  - prefix-containment agrees with a brute-force reference.
- **Restore guard:** a journal restored to before a revocation fails closed; a matching journal
  verifies.
- **Format:** checksum round trip; random strings with the right prefix are rejected without a
  lookup; the redactor detects issued keys; a canary key never appears in logs.
- **Durability:** `revoke` returns only after its critical record is acknowledged (reuses the kill
  harness pattern).
- **Negative case for the gate self-test:** a seeded verify that skips the parent-epoch check
  must fail the property suite.
