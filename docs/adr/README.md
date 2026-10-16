# Architecture Decision Records

One decision per file, numbered, never deleted. A superseded ADR stays and points to its
successor. Format (MADR-lite): **Status · Context · Decision · Alternatives rejected ·
Consequences · Verification**.

Expensive decisions (contracts, architecture, security posture, licensing) require an ADR
before their first code is merged (GOVERNANCE.md §Decisions).

| # | Title | Status |
|---|---|---|
| [0001](0001-rings-and-dependency-direction.md) | Rings, crate boundaries and dependency direction | Accepted |
| [0002](0002-operation-lifecycle-and-pipeline-order.md) | The Operation lifecycle and the pipeline order | Accepted |
| [0003](0003-journal-truth-and-durability.md) | Journal as source of truth; durability classes; pending gates | Accepted |
| [0004](0004-trust-model-and-approvals.md) | Trust model and approvals | Accepted |
| [0005](0005-dialects-and-transform-invariants.md) | Client dialects and transform invariants | Accepted |
| [0006](0006-aws-lc-prebuilt-nasm-on-windows.md) | aws-lc prebuilt NASM objects on Windows | Accepted |
| [0007](0007-key-storage-and-shred-guarantees.md) | Where keys live, and what "shredded" honestly means | Accepted |
| [0008](0008-authorization-semantics-over-cedar.md) | Authorization semantics over Cedar | Accepted |
| [0009](0009-redaction-detectors-placeholders-final-scan.md) | Redaction: detector sets, placeholders and the final scan | Accepted |
| [0010](0010-kernel-tokens-and-reachability.md) | Kernel tokens and reachability | Accepted |
| [0011](0011-scoped-credentials-and-revocation.md) | Scoped credentials, hierarchy and revocation | Accepted |
| [0012](0012-approval-presence-and-peer-credentials.md) | Approval presence and peer credentials | Proposed |
| [0013](0013-async-runtime-and-http-stack.md) | Async runtime and HTTP stack | Accepted |
| [0014](0014-codec-framework-structural-view-and-selectors.md) | Codec framework: a kernel-owned structural view and declarative selectors | Accepted |
| [0017](0017-rehydration-policy-and-round-trip.md) | Rehydration: a policy-gated action with a recorded round trip | Proposed |
| [0018](0018-chunk-durability-joins-the-journal-classes.md) | Chunk durability joins the journal's durability classes | Accepted |
| [0019](0019-merge-integrity-with-one-maintainer.md) | Merge integrity with one maintainer | Accepted |

Numbers 0015 and 0016 are reserved for the remaining P3 decisions named in plan v2 §2.8:
session inference and the pricing package. Each is written before its first code.
