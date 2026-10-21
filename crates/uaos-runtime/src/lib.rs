// SPDX-License-Identifier: Apache-2.0

//! # The UAOS runtime: the relay, the stop, admission and boot recovery
//!
//! The contracts are `docs/adr/appendix/0013-runtime-relay-and-stop.md` (P3 Move 1 PR-6a) and
//! `docs/adr/appendix/0013-runtime-boot-recovery.md` (PR-6b). The state actor is PR-6c's, the
//! bus PR-6d's, and the pipeline that joins them to the egress door PR-7's.
//!
//! - [`Stop`] is the kernel's kill switch. It is one atomic flag that admission reads first and
//!   every admitted Operation watches. It acts before its record ([`Engaged::draft`]), and a
//!   journaled stop is honoured at boot ([`boot_state`]).
//! - [`Admission`] counts bytes in flight as well as Operations.
//! - [`ConfigCell`] publishes configuration snapshots. Each Operation pins one, with its locale
//!   as an opaque [`LocaleTag`]. No Ring 0 type names a locale (CLAUDE.md, language neutrality).
//! - [`DeclaredPrice`] prices usage in nano-USD per unit, the user-declared form ADR-0016
//!   permits.
//! - [`Relay`] streams a provider's response to the client. The client's connection pulls it,
//!   it holds at most one incomplete event, and it forwards exact bytes. Every usage report the
//!   codec finds is priced against the Operation's reservation, and the first one past it cuts
//!   the stream, drops the upstream and engages the stop.
//! - [`Supervisor`] is the runtime's only spawner.
//! - [`boot`] recovers the kernel from its journal: it refuses a configuration older than the
//!   journal's, restores the stop, recovers the ledger, makes every open intent `Indeterminate`
//!   once, and explains the boot (contract `0013-runtime-boot-recovery.md`).
//!
//! **Honest limits.** The hard cap is the reservation taken before the request. The relay sees
//! token counts only when the provider reports them, so content between reports is forwarded
//! unmetered. Bytes already forwarded cannot be recalled, and a cut never claims a rollback (red
//! line 3).

#![forbid(unsafe_code)]
#![deny(missing_docs)]

mod admission;
mod boot;
mod config;
mod price;
mod relay;
mod sse;
mod stop;
mod supervisor;

pub use admission::{Admission, AdmissionLimits, Permit, Refusal, RefusalReason};
pub use boot::{BootError, BootReport, Booted, CRASH_RECOVERY, boot};
pub use config::{ConfigCell, ConfigError, ConfigSnapshot, LocaleError, LocaleTag, MAX_LOCALE_TAG};
pub use price::{DeclaredPrice, Price, PriceError};
pub use relay::{CutReason, Relay, RelayBody, RelayEnd, RelayError, RelayLimits, RelayReport};
pub use stop::{BootState, Engaged, Stop, StopReason, StopWatch, boot_state};
pub use supervisor::{SpawnError, Supervisor, SupervisorLimits};
