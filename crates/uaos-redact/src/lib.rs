// SPDX-License-Identifier: Apache-2.0

//! # UAOS redaction
//!
//! Detection and redaction of high-risk secrets before content leaves the machine (plan §2.5
//! DETECT, TRANSFORM and FINAL; C-53; red line 2):
//!
//! * **schema-agnostic**: every JSON string is scanned (keys and values, at any depth, known
//!   and unknown fields), after decoding escapes, so `\u`-escaped secrets are found;
//! * **nested**: each string and text is scanned in four views (as decoded, two further levels
//!   of JSON and percent escapes, and form encoding), so a secret in a tool call's JSON
//!   arguments, a double-escaped `partial_json` or a form body is found;
//! * **boundaries fail closed**: a key glued to separators, or longer than its format, is still
//!   covered whole;
//! * **byte-preserving**: placeholders are spliced into the original bytes; content without a
//!   detection is returned borrowed, byte for byte;
//! * **stable placeholders**: `[REDACTED:<class>:<tag>]`, where the tag is HMAC-SHA-256 under the
//!   pocket's placeholder key. The same secret gets the same placeholder on every turn and after
//!   every restart, a different one in another pocket, and nothing about the secret is revealed;
//! * **idempotent**: output is redacted to a fixpoint, so `redact(redact(x)) == redact(x)`;
//! * **pinned**: a detector set is versioned as a whole and a session keeps its version;
//! * **fail closed**: every error (malformed input, scanner failure, no convergence) is an error
//!   the caller must turn into a block, and [`FinalScanner`] blocks on any detection or known
//!   vault secret in the exact outbound bytes.
//!
//! This crate performs no I/O and never logs, and no type in it shows content or secret-derived
//! structure in `Debug` output. Scanning is linear in the input (a test bounds the work on
//! adversarial inputs). Recall is bound to the formats detector set v1 claims, measured on
//! synthetic corpus v2 (ADR-0009 lists the classes, metrics and limits). Not detected: free-form
//! passwords outside URL userinfo, AWS secret access keys (only key ids), and encodings beyond
//! the four views. Content that would need more than 8 redaction rounds is replaced whole.

#![deny(missing_docs)]
#![deny(clippy::indexing_slicing)]

mod class;
mod detect;
mod json;
mod redactor;
mod scan;

pub use class::DataClass;
pub use detect::{DetectorSet, DetectorVersion, Finding};
pub use redactor::{Redaction, Redactor, Replacement};
pub use scan::{Blocked, FinalScanner, MIN_KNOWN_SECRET_LEN};

use uaos_contracts::error::{ErrorCode, codes};

/// Why content could not be redacted. Every variant means: block the content. Messages never
/// contain content.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum RedactError {
    /// The session pinned a detector set this build does not have.
    #[error("detector set version {0} is not available")]
    UnknownDetectorVersion(u16),
    /// The content is not valid UTF-8.
    #[error("content is not valid UTF-8")]
    InvalidUtf8,
    /// A JSON string could not be decoded.
    #[error("malformed JSON string: {0}")]
    MalformedJson(&'static str),
    /// Redaction kept finding secrets in its own output.
    #[error("redaction did not converge")]
    Unconverged,
    /// Two different secrets produced the same placeholder.
    #[error("two different secrets produced the same placeholder")]
    PlaceholderCollision,
    /// A known secret is too short to scan for.
    #[error("known secrets must be at least {MIN_KNOWN_SECRET_LEN} bytes")]
    KnownSecretTooShort,
    /// The scanner itself failed.
    #[error("detector failure: {0}")]
    DetectorFailure(&'static str),
}

impl RedactError {
    /// Registered error code.
    #[must_use]
    pub fn code(&self) -> ErrorCode {
        codes::REDACT_DETECTOR_FAILURE
    }
}
