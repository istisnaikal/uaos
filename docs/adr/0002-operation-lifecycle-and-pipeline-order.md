# ADR-0002: The Operation lifecycle and the pipeline order

**Status:** Accepted (2026-10-12) · **Plan refs:** §2.3–§2.5 · **Deviates from:** CLAUDE.md §3 "Main flows" item 1 (order)

## Context

Model calls, token counts, tool calls, process executions, budget transfers and config changes
all have side effects that must be authorized, priced, journaled and explained. Giving each its
own path multiplies the places where a check can be skipped.

## Decision

1. **One unit of side effect: the `Operation`**, with one state machine
   (`uaos_contracts::operation`). Two honesty rules are enforced in the type, not in review:
   - an Operation that is not compensable can never reach `Compensated` (red line 3);
   - `Indeterminate` is reachable only by crash recovery from `Reserved`/`Executing`, and
     leaves only through evidence (`ResolveCommitted`/`ResolveFailed`).
2. **Approval is non-blocking.** `ApprovalRequired` is terminal for the Operation: the client
   immediately receives its dialect's error carrying the approval ID; a retry after approval is
   a new Operation. Holding a connection open would trip client idle-stream watchdogs.
3. **Pipeline order** for a model call:
   `ingress → DETECT (schema-agnostic, redacted view for hooks) → hooks (tags, context,
   classify) → precheck → ROUTE (over Cedar-permitted candidates) → AUTHZ → RESERVE
   (reserve+intent, one critical record) → TRANSFORM (in-place splice) → FINAL exact-bytes
   scan → EGRESS → stream → COMMIT/SETTLE → EXPLAIN`.

### Why the order deviates from CLAUDE.md

CLAUDE.md lists *redaction → budget reserve → policy → routing*. This ADR uses
*detect → route → authorize → reserve → transform → final scan* because:

1. an **exact** reservation needs the chosen route's price;
2. authorization must see the provider **and** the detected data classes ("PII may not go to X");
3. hooks must never see raw secrets, so detection comes first, while the **last** check covers
   the exact outbound bytes, including fields no codec knows about.

The CLAUDE.md flow's intent (nothing leaves unredacted, unauthorized or unreserved) is kept and
strengthened; only the order changes.

## Alternatives rejected

- *Per-feature pipelines:* duplicate checks, inevitable gaps.
- *Blocking approvals:* break client watchdogs (≈180–300 s) and pin resources.
- *Redact once, early, and trust the rest:* misses content added by later transforms and
  unknown fields.

## Verification

- Property tests in `uaos-contracts::operation` (red line 3, Indeterminate provenance,
  settled-state exits, immutability of facts).
- From P3: `kernel-tokens` gate — egress cannot be called without kernel-issued
  `Authorized{op_id}`, `Reservation{op_id}` and `EgressReady{op_id}` (compile-fail + runtime binding tests).
  *Amended 2026-10-13 (plan v2 PD-04): originally "from P2". The tokens bind policy, ledger and
  egress, which first meet in the runtime (P3), so the gate cannot exist earlier. The design is
  ADR-0010.*
