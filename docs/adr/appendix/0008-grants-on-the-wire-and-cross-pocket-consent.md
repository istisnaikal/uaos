# ADR-0008 appendix: grants on the wire and cross-pocket consent (`uaos.grant/1`, draft), PR-4b

**Status:** draft contract, written before this PR's new code (P3 Move 1, Train A, PR-4b). It
freezes with the other kernel contracts at RC-1.
**Origin:** split from PR-4 (#32) on 2026-10-21, at the maintainer's choice. PR-4's final review
found that the policy engine ignores which grant a request carries (M4) and that `uaos.grant/1`
cannot represent every grant the engine holds (M5). Both change the policy engine and the grant
contract, so the whole grant path left PR-4 for this PR. That covers `uaos.grant/1`, the Cedar
`Pocket` entity, and the `memory.read` action with its consent rule. PR-4's module socket
contract (`0010-module-socket.md` §6.2, §8) still states the rules; this PR builds and proves
them.
**Builds on:** ADR-0008 and its Amendment 1 (grants satisfy asks, never override a forbid);
ADR-0004 (approvals); ADR-0007 (pocket keys); ADR-0010 Decision 6 (child Operations carry
grants).

## 1. What PR-4b builds

- **`uaos.grant/1`** (`uaos-contracts::grant`, `schemas/grant.v1.json`): a grant entry, issued
  or revoked, and the grant record it carries, with its validation. It is moved unchanged from
  PR-4, then aligned by §3.
- **Cedar** (`uaos-policy`): the entity `Pocket`, the action `memory.read` on it, and in the
  model `Action::MemoryRead` and `Resource::Pocket`. Moved unchanged from PR-4.
- **The consent rule** (§2), moved unchanged from PR-4.
- **The carried grant** (M4, §2 rule 4) and **the exact wire form** (M5, §3), both new.

## 2. Rules

1. **Default deny.** A `memory.read` request is denied unless a policy or a grant allows it, like
   every action.
2. **Only consent allows a cross-pocket read.** A read of another pocket than the requesting one
   is allowed only by a live grant. A grant is consent: a human approved it, and it carries the
   injection policy (`auto`, `ask`, `never`). A permit, named or blanket, at most turns the
   answer into an approval request. A forbid still wins over a grant, and an evaluation error
   still denies.
3. **The requesting pocket is not crossed.** A read of the requesting pocket itself follows
   policy as any action does. No grant can name it (`SamePocket`).
4. **A request names the grant it carries** (`Request::grant`, M4).
   - When it names one, only that grant can satisfy it.
   - A cross-pocket read that names none is never allowed.
   - The decision cites the grant that allowed it, so the runtime applies that grant's injection
     policy and no other. With two live grants for the same read (a renewal, say), the one the
     module carried decides.
5. **`memory.read` grants are on a pocket, and only they are** (`ResourceMismatch`). The
   injection policy is present on exactly those grants (`InjectionMismatch`).

## 3. The exact wire form (M5)

`uaos.grant/1` is the journaled form of the engine's `Grant`. A grant journaled when issued must
reload into the engine at boot exactly, so every engine grant has a record and back:

| Engine (`uaos-policy::model`) | Wire (`uaos.grant/1`) |
|---|---|
| `Principal::{Agent, Human, Module, System}` | `GrantPrincipal::{Agent, Human, Module, System}` |
| `Action` | `ActionName`, one of the engine's Cedar action names |
| `Resource::Model { provider, model }` | `GrantResource::Model { provider, name }` |
| `Resource::{Tool, ConfigKey}(Name)` | `GrantResource::{Tool, ConfigKey} { name }` |
| `Resource::Pool(PoolId)`, `Resource::Pocket(PocketId)` | `GrantResource::{Pool, Pocket} { id }` |
| `Name` (`[A-Za-z0-9._:/-]{1,128}`) | `GrantName`, the same grammar |
| data classes (`Name`) | `DataClass`, the same grammar |
| `approves` (policy `@id`s) | `PolicyId`: `[A-Za-z0-9._:-]{1,128}`, never the reserved `grant:` prefix |
| `expires_at_ms` (Unix milliseconds) | `expires_at` (`WallTime`). An expiry finer than a millisecond floors, so a grant ends early, never late |

The conversions live in `uaos-policy` (`wire`), the crate that owns the engine's types:

- `Grant::try_from(&GrantRecord)` reloads a grant at boot;
- `grant_record(&Grant, approval, issued_at, injection)` builds the record to journal.

The fields the engine does not hold (the approval, the issue time, the injection policy) are
the caller's.

## 4. Proof obligations

**Tests:**
- `uaos.grant/1` round-trips, validates, and its schema is exported;
- the Cedar rules of §2:
  - denied without a grant;
  - allowed with a matching grant;
  - denied when the grant names another source pocket or another requesting pocket, or has
    expired;
  - a forbid wins;
  - a permit, named or blanket, only asks;
  - the own pocket follows policy;
- rule 4:
  - only the named grant can allow;
  - the decision cites it;
  - a cross-pocket read naming no grant is never allowed;
  - a property over random grants, policies and named grants compares the engine with the rule;
- §3: a property shows that every engine grant goes to a record and back unchanged, and that the
  name grammars of the two crates accept the same strings.

**Seeded violations** (`cargo xtask negative`, gate `test`):

| id | Seed | Caught by |
|---|---|---|
| `grant-memory-read-off-a-pocket` | the action and resource pairing skipped | `memory_reads_and_pockets_go_together` |
| `cedar-cross-pocket-without-grant` | a permit allows a cross-pocket read without a grant | `a_permit_alone_only_asks_for_a_cross_pocket_read` |
| `cedar-own-pocket-read-asks` | an own-pocket read is treated as cross-pocket | `a_permit_alone_only_asks_for_a_cross_pocket_read` |
| `grant-carried-ignored` | the engine ignores the grant a request names | `only_the_carried_grant_allows_a_cross_pocket_read` |
| `grant-wire-drops-provider` | the conversion drops a model's provider | `every_engine_grant_round_trips_through_the_wire` |

`schema-breaking-change` is re-proven over `grant.v1.json`.
