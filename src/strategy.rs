//! ## Multi Strategy
//!
//! Runs multiple sub-strategies concurrently. Each sub-strategy manages its own
//! event subscription and internal timers via the `Strategy::run` method.
//!
//! `MultiStrategy` is a pure combinator: it accepts any `Box<dyn Strategy + Send>` —
//! including strategies defined outside this crate — and runs them all concurrently.
//! Sub-strategies are fully isolated: a failure in one is logged and does not affect
//! the others.
use std::fmt::{Debug, Display, Formatter};

use futures::StreamExt as _;
use hopr_utils::runtime::prelude::{AbortHandle, abortable, spawn};

use crate::errors::Result;

/// Shared component health types, retained under their strategy-specific names.
///
/// States default to `Running` and are ordered by increasing severity.
pub use hopr_api::{AtomicComponentState as AtomicStrategyState, ComponentState as StrategyState};

/// A strategy that runs until cancelled or a fatal error occurs.
///
/// Each implementation subscribes to the node's event stream and/or creates internal
/// timers in [`run`](Strategy::run). The trait is trivially object-safe: `run` takes only
/// `&mut self`, so strategies can be held as `Box<dyn Strategy + Send>`.
///
/// Any type implementing this trait can be composed into a [`MultiStrategy`] without
/// any changes to this crate.
#[async_trait::async_trait]
pub trait Strategy: Display + Send {
    /// Run the strategy. Returns only on cancellation or fatal error.
    async fn run(&mut self) -> Result<()>;

    /// Current externally observable state.
    ///
    /// Default: always [`StrategyState::Running`] — a strategy with nothing to say
    /// about its own health should look healthy from the outside, so implementing this
    /// trait never obligates tracking one.
    ///
    /// ```
    /// use std::fmt::{Display, Formatter};
    ///
    /// use hopr_strategy::{
    ///     errors::Result,
    ///     strategy::{Strategy, StrategyState},
    /// };
    ///
    /// struct PassiveStrategy;
    ///
    /// impl Display for PassiveStrategy {
    ///     fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
    ///         write!(f, "passive")
    ///     }
    /// }
    ///
    /// #[async_trait::async_trait]
    /// impl Strategy for PassiveStrategy {
    ///     async fn run(&mut self) -> Result<()> {
    ///         Ok(())
    ///     }
    ///     // No `state` override — reports the trait's default.
    /// }
    ///
    /// assert_eq!(PassiveStrategy.state(), StrategyState::Running);
    /// ```
    fn state(&self) -> StrategyState {
        StrategyState::Running
    }

    /// The shared atomic behind [`state`](Strategy::state), cloned so it can be read while
    /// the strategy runs.
    ///
    /// [`run`](Strategy::run) takes `&mut self` and is usually moved into a spawned task, so
    /// [`state`](Strategy::state) cannot be called while the strategy runs. Clone this handle
    /// *before* running, then `load` it from anywhere — a strategy that tracks its health
    /// returns its own live atomic, so every clone observes the same transitions.
    ///
    /// Default: a fresh atomic pinned to the current [`state`](Strategy::state) — a strategy
    /// with no live health signal has nothing to share, and its state never changes.
    fn state_handle(&self) -> std::sync::Arc<AtomicStrategyState> {
        std::sync::Arc::new(AtomicStrategyState::new(self.state()))
    }
}

/// One strategy's operational state at the time a snapshot was taken.
#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct StrategyStateSnapshot<'a> {
    /// Strategy display name. Names need not be unique.
    pub name: &'a str,
    /// Observed operational state.
    pub state: StrategyState,
}

/// Live observer retained independently of the running strategies.
///
/// Clone this before moving a [`MultiStrategy`] into its task, then call
/// [`snapshot`](Self::snapshot) when building a diagnostic dump. Each state is read
/// independently; the snapshot is not an atomic observation across strategies.
#[derive(Clone)]
pub struct StrategyStateObserver {
    states: Vec<(String, std::sync::Arc<AtomicStrategyState>)>,
}

impl StrategyStateObserver {
    /// Read the current states in construction order, preserving duplicate names.
    pub fn snapshot(&self) -> Vec<StrategyStateSnapshot<'_>> {
        self.states
            .iter()
            .map(|(name, state)| StrategyStateSnapshot {
                name: name.as_str(),
                state: state.load(std::sync::atomic::Ordering::Relaxed),
            })
            .collect()
    }
}

#[cfg(feature = "serde")]
impl hopr_api::StateDump for StrategyStateObserver {
    type Error = std::convert::Infallible;

    /// Collect owned names and live states without consuming observations.
    ///
    /// Entries preserve construction order and duplicate names. Each state is read
    /// independently; polling does not change operational state.
    async fn dump(
        &self,
    ) -> std::result::Result<impl serde::Serialize + serde::de::DeserializeOwned + Send + 'static, Self::Error> {
        #[derive(serde::Serialize, serde::Deserialize)]
        struct Snapshot {
            name: String,
            state: StrategyState,
        }

        Ok(self
            .states
            .iter()
            .map(|(name, state)| Snapshot {
                name: name.clone(),
                state: state.load(std::sync::atomic::Ordering::Relaxed),
            })
            .collect::<Vec<_>>())
    }
}

/// Runs a group of sub-strategies concurrently, each in its own async task.
///
/// `MultiStrategy` is strategy-kind-agnostic: it only knows about
/// `Box<dyn Strategy + Send>`. Any type implementing [`Strategy`] — including
/// ones defined outside this crate — can be composed here.
pub struct MultiStrategy {
    strategies: Vec<Box<dyn Strategy + Send>>,
    state_observer: StrategyStateObserver,
}

impl MultiStrategy {
    /// Creates a new `MultiStrategy` from pre-built strategy objects.
    ///
    /// Strategies are passed in already constructed; `MultiStrategy` does not know or
    /// care about the concrete types. Pass an empty `strategies` vec to get a passive
    /// strategy that blocks forever.
    pub fn new(strategies: Vec<Box<dyn Strategy + Send>>) -> Self {
        let states = strategies.iter().map(|s| (s.to_string(), s.state_handle())).collect();
        Self {
            strategies,
            state_observer: StrategyStateObserver { states },
        }
    }

    /// Obtain a live observer that remains usable after this strategy is spawned.
    pub fn state_observer(&self) -> StrategyStateObserver {
        self.state_observer.clone()
    }
}

impl Debug for MultiStrategy {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "MultiStrategy({} sub-strategies)", self.strategies.len())
    }
}

impl Display for MultiStrategy {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        let names: Vec<String> = self.strategies.iter().map(|s| s.to_string()).collect();
        if names.is_empty() {
            write!(f, "multi_strategy(passive)")
        } else {
            write!(f, "multi_strategy({})", names.join(", "))
        }
    }
}

#[async_trait::async_trait]
impl Strategy for MultiStrategy {
    async fn run(&mut self) -> Result<()> {
        let strategies = std::mem::take(&mut self.strategies);

        if strategies.is_empty() {
            // Passive strategy: block forever until cancelled.
            futures::future::pending::<()>().await;
            return Ok(());
        }

        // Spawn each sub-strategy as an abortable task.
        // Keeping all AbortHandles in a RAII guard ensures every sub-task is cancelled
        // when MultiStrategy is dropped (graceful shutdown).

        let mut join_handles = Vec::new();
        let mut abort_handles: Vec<AbortHandle> = Vec::new();
        for mut s in strategies {
            let proc = hopr_utils::runtime::diagnostics::instrument(
                async move { s.run().await },
                "multi_strategy_sub_task",
                module_path!(),
                file!(),
                line!(),
            );
            let (proc, abort_handle) = abortable(proc);
            join_handles.push(spawn(proc));
            abort_handles.push(abort_handle);
        }

        struct AbortGuard(Vec<AbortHandle>);
        impl Drop for AbortGuard {
            fn drop(&mut self) {
                for h in &self.0 {
                    h.abort();
                }
            }
        }
        let _guard = AbortGuard(abort_handles);

        // Process completions as they arrive. Sub-strategies are fully isolated:
        // a failure in one is logged but does not affect the others.
        let mut pending: futures::stream::FuturesUnordered<_> = join_handles.into_iter().collect();

        while let Some(join_result) = pending.next().await {
            let strategy_result = match join_result {
                Err(e) => Err(crate::errors::StrategyError::Other(e.into())),
                Ok(Ok(result)) => result,
                Ok(Err(_aborted)) => continue, // aborted by the guard — expected during shutdown
            };

            if let Err(e) = strategy_result {
                tracing::warn!(%e, "sub-strategy failed");
            }
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::fmt::{Display, Formatter};

    use super::*;
    use crate::errors::StrategyError;

    struct OkStrategy;
    impl Display for OkStrategy {
        fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
            write!(f, "ok")
        }
    }
    #[async_trait::async_trait]
    impl Strategy for OkStrategy {
        async fn run(&mut self) -> Result<()> {
            Ok(())
        }
    }

    struct FailStrategy;
    impl Display for FailStrategy {
        fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
            write!(f, "fail")
        }
    }
    #[async_trait::async_trait]
    impl Strategy for FailStrategy {
        async fn run(&mut self) -> Result<()> {
            Err(StrategyError::Other(anyhow::anyhow!("error")))
        }
    }

    /// An externally-defined strategy — simulates a plugin or application-defined strategy.
    struct ExternalStrategy {
        ran: bool,
    }
    impl Display for ExternalStrategy {
        fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
            write!(f, "external")
        }
    }
    #[async_trait::async_trait]
    impl Strategy for ExternalStrategy {
        async fn run(&mut self) -> Result<()> {
            self.ran = true;
            Ok(())
        }
    }

    #[tokio::test]
    async fn test_multi_strategy_sub_failure_does_not_propagate() -> anyhow::Result<()> {
        // A failing sub-strategy is isolated: the MultiStrategy still returns Ok.
        let mut ms = MultiStrategy::new(vec![Box::new(FailStrategy), Box::new(OkStrategy)]);
        ms.run().await?;
        Ok(())
    }

    #[tokio::test]
    async fn test_multi_strategy_accepts_external_strategy() -> anyhow::Result<()> {
        // Demonstrates that any impl Strategy can be composed without modifying hopr-strategy.
        let mut ms = MultiStrategy::new(vec![Box::new(OkStrategy), Box::new(ExternalStrategy { ran: false })]);
        ms.run().await?;
        Ok(())
    }

    #[tokio::test]
    async fn test_multi_strategy_empty_is_passive() {
        // An empty MultiStrategy blocks forever — verify it does not complete immediately.
        let mut ms = MultiStrategy::new(vec![]);
        let result =
            futures_time::future::FutureExt::timeout(ms.run(), futures_time::time::Duration::from_millis(50)).await;
        assert!(result.is_err(), "empty MultiStrategy should block (timeout expected)");
    }

    #[tokio::test]
    async fn state_snapshot_survives_run_and_tracks_live_handles() {
        struct Observed(std::sync::Arc<AtomicStrategyState>);
        impl Display for Observed {
            fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
                write!(f, "observed")
            }
        }
        #[async_trait::async_trait]
        impl Strategy for Observed {
            async fn run(&mut self) -> Result<()> {
                self.0
                    .store(StrategyState::Degraded, std::sync::atomic::Ordering::Relaxed);
                Ok(())
            }

            fn state_handle(&self) -> std::sync::Arc<AtomicStrategyState> {
                self.0.clone()
            }
        }
        let state = std::sync::Arc::new(AtomicStrategyState::new(StrategyState::Running));
        let mut strategy = MultiStrategy::new(vec![Box::new(Observed(state)), Box::new(OkStrategy)]);
        let observer = strategy.state_observer();
        assert_eq!(observer.snapshot()[0].state, StrategyState::Running);
        #[cfg(feature = "serde")]
        {
            use hopr_api::StateDump;
            let dump = observer.dump().await.unwrap();
            assert_eq!(serde_json::to_value(dump).unwrap()[0]["state"], "Running");
        }
        strategy.run().await.unwrap();
        drop(strategy);
        let snapshot = observer.snapshot();
        assert_eq!(snapshot[0].state, StrategyState::Degraded);
        assert_eq!(snapshot[1].state, StrategyState::Running);
        #[cfg(feature = "serde")]
        assert_eq!(
            serde_json::to_value(&snapshot).unwrap(),
            serde_json::json!([
                {"name": "observed", "state": "Degraded"},
                {"name": "ok", "state": "Running"}
            ])
        );
        #[cfg(feature = "serde")]
        {
            use hopr_api::StateDump;
            assert_eq!(
                serde_json::to_value(observer.dump().await.unwrap()).unwrap(),
                serde_json::to_value(&snapshot).unwrap()
            );
        }
        assert!(MultiStrategy::new(vec![]).state_observer().snapshot().is_empty());
    }

    #[cfg(feature = "serde")]
    #[tokio::test]
    async fn state_dump_is_owned_non_consuming_and_preserves_entries() -> anyhow::Result<()> {
        use hopr_api::StateDump;

        // Generic collectors can move both the future and the owned result between tasks.
        fn send<T: Send>(value: T) -> T {
            value
        }
        async fn collect(source: &impl StateDump) -> anyhow::Result<impl serde::Serialize + Send + 'static> {
            Ok(send(source.dump()).await?)
        }

        let mut strategy = MultiStrategy::new(vec![Box::new(OkStrategy), Box::new(OkStrategy)]);
        let observer = strategy.state_observer();
        strategy.run().await?;
        drop(strategy);
        let dump = collect(&observer).await?;
        let repeated = collect(&observer).await?;
        drop(observer);
        let expected = serde_json::json!([
            {"name": "ok", "state": "Running"},
            {"name": "ok", "state": "Running"}
        ]);
        assert_eq!(serde_json::to_value(dump)?, expected);
        assert_eq!(serde_json::to_value(repeated)?, expected);
        let empty = MultiStrategy::new(vec![]).state_observer();
        assert_eq!(serde_json::to_value(empty.dump().await?)?, serde_json::json!([]));
        Ok(())
    }

    #[test]
    fn test_multi_strategy_display() {
        let ms = MultiStrategy::new(vec![Box::new(OkStrategy), Box::new(FailStrategy)]);
        assert_eq!(ms.to_string(), "multi_strategy(ok, fail)");
    }

    #[test]
    fn test_multi_strategy_display_passive() {
        let ms = MultiStrategy::new(vec![]);
        assert_eq!(ms.to_string(), "multi_strategy(passive)");
    }

    /// A strategy that never overrides `state()` must still report `Running` — "nothing
    /// to say" reads as healthy, not as an unimplemented status.
    #[test]
    fn state_defaults_to_running_when_unimplemented() {
        let external = ExternalStrategy { ran: false };
        assert_eq!(external.state(), StrategyState::Running);
    }

    /// Increasing order of severity: comparing two observations always keeps the
    /// worse one, so a strategy combining several internal outcomes into one
    /// reported state can do so with a plain `max`.
    #[test]
    fn state_ordering_is_by_severity() {
        assert!(StrategyState::Running < StrategyState::Degraded);
        assert!(StrategyState::Degraded < StrategyState::Failed);
    }

    /// A shared handle observes state transitions made *after* it was taken — the property
    /// that makes it usable while `run` owns (or a task has moved) the strategy.
    #[test]
    fn shared_state_handle_tracks_live_transitions() {
        use std::sync::{Arc, atomic::Ordering};

        let state = Arc::new(AtomicStrategyState::new(StrategyState::Running));
        let handle = Arc::clone(&state);
        assert_eq!(handle.load(Ordering::Relaxed), StrategyState::Running);

        state.store(StrategyState::Degraded, Ordering::Relaxed);
        assert_eq!(
            handle.load(Ordering::Relaxed),
            StrategyState::Degraded,
            "handle must see writes made after it was cloned"
        );
    }

    /// The default `state_handle` mirrors `state` for a strategy that tracks no health.
    #[test]
    fn default_state_handle_mirrors_state() {
        use std::sync::atomic::Ordering;

        let external = ExternalStrategy { ran: false };
        assert_eq!(external.state_handle().load(Ordering::Relaxed), external.state());
        assert_eq!(external.state_handle().load(Ordering::Relaxed), StrategyState::Running);
    }
}
