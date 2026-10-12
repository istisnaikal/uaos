// SPDX-License-Identifier: Apache-2.0

//! The journal: append-only, hash-chained, crash-recovering (ADR-0003).
//!
//! Layout inside the data directory:
//!
//! ```text
//! uaos.lock                       exclusive lock: one daemon per data directory
//! journal/MANIFEST                segment list (replaced atomically on rotation)
//! journal/seg-<first seq>-<gen>.jsonl   one uaos.event/1 record per line
//! ```

mod error;
pub mod manifest;
mod scan;
mod writer;

pub use error::JournalError;
pub use scan::{VerifiedRecord, VerifyReport, genesis_hash, read_verified, verify};
pub use writer::{Appended, EventDraft, FlushPolicy, JOURNAL_DIR, Journal, JournalHealth, LOCK_FILE};
