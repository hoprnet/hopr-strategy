//! Lifecycle guard for background tasks started by integration scenarios.

use std::future::Future;

use tokio::task::JoinHandle;

pub struct StrategyTask<T> {
    handle: Option<JoinHandle<T>>,
}

impl<T: Send + 'static> StrategyTask<T> {
    pub fn spawn<F>(future: F) -> Self
    where
        F: Future<Output = T> + Send + 'static,
    {
        Self {
            handle: Some(tokio::spawn(future)),
        }
    }

    pub fn is_finished(&self) -> bool {
        self.handle.as_ref().is_none_or(JoinHandle::is_finished)
    }

    pub async fn stop(mut self) {
        if let Some(handle) = self.handle.take() {
            handle.abort();
            // A cancelled task resolves to `Err(_)` with `is_cancelled()`, which we
            // ignore; a task that *panicked* is re-raised so the original backtrace
            // surfaces instead of being silently swallowed.
            if let Err(error) = handle.await {
                if error.is_panic() {
                    std::panic::resume_unwind(error.into_panic());
                }
            }
        }
    }
}

impl StrategyTask<()> {
    /// Spawns a strategy `run()` future, logging any error it returns. A strategy
    /// that fails immediately is then surfaced in the test logs, rather than only
    /// showing up later as a misleading poll timeout.
    pub fn spawn_logged<F, E>(future: F) -> Self
    where
        F: Future<Output = Result<(), E>> + Send + 'static,
        E: std::fmt::Debug,
    {
        Self::spawn(async move {
            if let Err(error) = future.await {
                tracing::error!(?error, "strategy task failed");
            }
        })
    }
}

impl<T> Drop for StrategyTask<T> {
    fn drop(&mut self) {
        if let Some(handle) = self.handle.take() {
            handle.abort();
        }
    }
}
