// SPDX-License-Identifier: Apache-2.0

//! Admission by bytes in flight (contract §4).
//!
//! A request is admitted with the bytes it declares, and its [`Permit`] charges more as copies
//! are made (the body, the tape, the splice). The stop is checked before either bound.

use std::fmt;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::Duration;

use uaos_contracts::error::{ErrorCode, codes};

use crate::stop::{Stop, StopReason, StopWatch};

/// Admission's bounds.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AdmissionLimits {
    /// Operations in flight at once.
    pub max_operations: u32,
    /// Bytes in flight at once, across every Operation.
    pub max_bytes: u64,
    /// The `retry-after` an overload refusal carries.
    pub overload_retry_after: Duration,
    /// The `retry-after` a stopped kernel's refusal carries: over 60 s, after which Claude Code
    /// stops retrying (v2 §2.5).
    pub stopped_retry_after: Duration,
}

impl Default for AdmissionLimits {
    /// `[CONSCIOUS ASSUMPTION]` 64 Operations and 256 MiB: about four copies of a 1.7 MB body
    /// each. Measured under the overload test (PR-7) and the soak (M4).
    fn default() -> Self {
        Self {
            max_operations: 64,
            max_bytes: 256 * 1024 * 1024,
            overload_retry_after: Duration::from_secs(1),
            stopped_retry_after: Duration::from_secs(120),
        }
    }
}

/// Why admission refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum RefusalReason {
    /// The kernel is stopped.
    Stopped(StopReason),
    /// Too many Operations in flight.
    Operations,
    /// Too many bytes in flight.
    Bytes,
}

/// A refusal, with the code and `retry-after` the client receives.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("not admitted: {reason:?}; retry after {retry_after:?}")]
pub struct Refusal {
    /// Why.
    pub reason: RefusalReason,
    /// The registered code: `RUNTIME_STOPPED` (or the stop's own), or `RUNTIME_OVERLOAD`.
    pub code: ErrorCode,
    /// When to retry.
    pub retry_after: Duration,
}

#[derive(Debug, Default)]
struct Used {
    operations: u32,
    bytes: u64,
}

struct Inner {
    limits: AdmissionLimits,
    stop: Stop,
    used: Mutex<Used>,
}

impl Inner {
    fn used(&self) -> MutexGuard<'_, Used> {
        // The counters stay consistent under a panic: each update is one assignment.
        self.used.lock().unwrap_or_else(PoisonError::into_inner)
    }

    fn stopped(&self) -> Option<Refusal> {
        if !self.stop.is_engaged() {
            return None;
        }
        let reason = self.stop.reason().unwrap_or(StopReason::Unrecognized);
        Some(Refusal {
            reason: RefusalReason::Stopped(reason),
            code: reason.error_code(),
            retry_after: self.limits.stopped_retry_after,
        })
    }

    fn overload(&self, reason: RefusalReason) -> Refusal {
        Refusal {
            reason,
            code: codes::RUNTIME_OVERLOAD,
            retry_after: self.limits.overload_retry_after,
        }
    }
}

/// Admission control. Clones share one set of counters.
#[derive(Clone)]
pub struct Admission {
    inner: Arc<Inner>,
}

impl fmt::Debug for Admission {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let (operations, bytes) = self.in_flight();
        f.debug_struct("Admission")
            .field("limits", &self.inner.limits)
            .field("operations", &operations)
            .field("bytes", &bytes)
            .finish()
    }
}

impl Admission {
    /// Admission under `limits`, refusing everything while `stop` is engaged.
    #[must_use]
    pub fn new(limits: AdmissionLimits, stop: Stop) -> Self {
        Self {
            inner: Arc::new(Inner {
                limits,
                stop,
                used: Mutex::new(Used::default()),
            }),
        }
    }

    /// Admits one Operation that declares `bytes` in flight.
    ///
    /// # Errors
    /// [`Refusal`]: stopped (checked first), or over either bound.
    pub fn admit(&self, bytes: u64) -> Result<Permit, Refusal> {
        // Subscribe, then check: a stop engaged after this line reaches the permit's watch, and
        // one engaged before it is refused here (rule 2).
        let watch = self.inner.stop.watch();
        if let Some(refusal) = self.inner.stopped() {
            return Err(refusal);
        }
        let mut used = self.inner.used();
        if used.operations >= self.inner.limits.max_operations {
            return Err(self.inner.overload(RefusalReason::Operations));
        }
        match used.bytes.checked_add(bytes) {
            Some(total) if total <= self.inner.limits.max_bytes => {
                used.operations += 1;
                used.bytes = total;
            }
            _ => return Err(self.inner.overload(RefusalReason::Bytes)),
        }
        drop(used);
        Ok(Permit {
            inner: Arc::clone(&self.inner),
            bytes,
            watch,
        })
    }

    /// Operations and bytes in flight now.
    #[must_use]
    pub fn in_flight(&self) -> (u32, u64) {
        let used = self.inner.used();
        (used.operations, used.bytes)
    }
}

/// One admitted Operation's share. Dropping it releases both bounds.
pub struct Permit {
    inner: Arc<Inner>,
    bytes: u64,
    watch: StopWatch,
}

impl fmt::Debug for Permit {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Permit")
            .field("bytes", &self.bytes)
            .finish_non_exhaustive()
    }
}

impl Permit {
    /// Charges `more` bytes, for a copy the Operation is about to make.
    ///
    /// # Errors
    /// [`Refusal`] if the kernel stopped or the bytes do not fit; nothing is charged.
    pub fn charge(&mut self, more: u64) -> Result<(), Refusal> {
        if let Some(refusal) = self.inner.stopped() {
            return Err(refusal);
        }
        let mut used = self.inner.used();
        match used.bytes.checked_add(more) {
            Some(total) if total <= self.inner.limits.max_bytes => {
                used.bytes = total;
                self.bytes += more;
                Ok(())
            }
            _ => Err(self.inner.overload(RefusalReason::Bytes)),
        }
    }

    /// The bytes this Operation holds.
    #[must_use]
    pub const fn bytes(&self) -> u64 {
        self.bytes
    }

    /// The stop, as this Operation watches it.
    #[must_use]
    pub const fn stop(&self) -> &StopWatch {
        &self.watch
    }
}

impl Drop for Permit {
    fn drop(&mut self) {
        let mut used = self.inner.used();
        used.operations = used.operations.saturating_sub(1);
        used.bytes = used.bytes.saturating_sub(self.bytes);
    }
}
