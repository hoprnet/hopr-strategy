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
            let _ = handle.await;
        }
    }
}

impl<T> Drop for StrategyTask<T> {
    fn drop(&mut self) {
        if let Some(handle) = self.handle.take() {
            handle.abort();
        }
    }
}
