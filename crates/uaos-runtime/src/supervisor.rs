// SPDX-License-Identifier: Apache-2.0

//! The supervisor, the runtime's only spawner (ADR-0013 Decision 1, ADR-0010 Decision 7;
//! contract §8). This file is the allow-audit owner for spawning: no other runtime file may
//! spawn.
//!
//! Its live tasks are bounded, and one past the bound is refused. It implements hyper's
//! [`Executor`](hyper::rt::Executor), so the door's connection tasks run under it (ADR-0013
//! Amendment 1 B, wired in PR-7). The CPU pool and the simulated executor (D-7) are PR-6b's.

use std::fmt;
use std::future::Future;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};

use tokio::runtime::Handle;
use tokio::task::JoinHandle;

/// The supervisor's bounds.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SupervisorLimits {
    /// Tasks alive at once.
    pub max_tasks: usize,
}

impl Default for SupervisorLimits {
    /// `[CONSCIOUS ASSUMPTION]` 1,024: admission's 64 Operations with their connection tasks fit
    /// many times over.
    fn default() -> Self {
        Self { max_tasks: 1024 }
    }
}

/// A task the supervisor refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum SpawnError {
    /// The live-task bound is reached.
    #[error("the supervisor's task bound is reached")]
    Full,
}

struct Inner {
    handle: Handle,
    limits: SupervisorLimits,
    live: AtomicUsize,
    refused: AtomicU64,
}

/// The supervisor. Clones share one task bound.
#[derive(Clone)]
pub struct Supervisor {
    inner: Arc<Inner>,
}

impl fmt::Debug for Supervisor {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Supervisor")
            .field("limits", &self.inner.limits)
            .field("live", &self.live())
            .field("refused", &self.refused())
            .finish()
    }
}

/// Holds one task slot; freed when the task ends, however it ends.
struct Slot(Arc<Inner>);

impl Drop for Slot {
    fn drop(&mut self) {
        self.0.live.fetch_sub(1, Ordering::AcqRel);
    }
}

impl Supervisor {
    /// A supervisor spawning on `handle`.
    #[must_use]
    pub fn new(handle: Handle, limits: SupervisorLimits) -> Self {
        Self {
            inner: Arc::new(Inner {
                handle,
                limits,
                live: AtomicUsize::new(0),
                refused: AtomicU64::new(0),
            }),
        }
    }

    /// Spawns `task`.
    ///
    /// # Errors
    /// [`SpawnError::Full`] if the live-task bound is reached; `task` is dropped unrun.
    pub fn spawn<F>(&self, task: F) -> Result<JoinHandle<F::Output>, SpawnError>
    where
        F: Future + Send + 'static,
        F::Output: Send + 'static,
    {
        let taken = self
            .inner
            .live
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |live| {
                (live < self.inner.limits.max_tasks).then_some(live + 1)
            });
        if taken.is_err() {
            self.inner.refused.fetch_add(1, Ordering::Relaxed);
            return Err(SpawnError::Full);
        }
        let slot = Slot(Arc::clone(&self.inner));
        #[allow(
            clippy::disallowed_methods,
            reason = "the supervisor is the runtime's only spawner (ADR-0013 Decision 1)"
        )]
        let handle = self.inner.handle.spawn(async move {
            let _slot = slot;
            task.await
        });
        Ok(handle)
    }

    /// Tasks alive now.
    #[must_use]
    pub fn live(&self) -> usize {
        self.inner.live.load(Ordering::Acquire)
    }

    /// Tasks refused so far, the executor's included.
    #[must_use]
    pub fn refused(&self) -> u64 {
        self.inner.refused.load(Ordering::Relaxed)
    }
}

impl<F> hyper::rt::Executor<F> for Supervisor
where
    F: Future + Send + 'static,
    F::Output: Send + 'static,
{
    /// Runs a connection task. One past the bound is dropped and counted in
    /// [`Supervisor::refused`]; the request on that connection then fails within the door's
    /// timeouts, never silently succeeds.
    fn execute(&self, task: F) {
        // The refusal is counted inside `spawn`.
        let _refused = self.spawn(task);
    }
}
