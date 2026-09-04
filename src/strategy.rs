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

/// Externally observable operational state of a running [`Strategy`].
///
/// Shared across every strategy in this crate — implementing [`Strategy::state`] is
/// optional, and any strategy can report a real state through it, though today only
/// `channel_lifecycle` does. Deliberately strategy-agnostic: what makes a given
/// strategy `Degraded` or `Failed`, and whether it recovers on its own, is up to that
/// strategy to define and document at its own implementation.
///
/// Implementations that track no health signal of their own do not need to implement
/// [`Strategy::state`] at all — the trait's default reports `Running`, so "nothing to
/// say" reads as healthy rather than as a status an operator has to interpret.
///
/// Declared in increasing order of severity, so comparing two observations keeps the
/// worse one:
///
/// ```
/// use hopr_strategy::strategy::StrategyState;
///
/// assert_eq!(StrategyState::default(), StrategyState::Running);
/// assert!(StrategyState::Running < StrategyState::Degraded);
/// assert!(StrategyState::Degraded < StrategyState::Failed);
/// assert_eq!(
///     StrategyState::Running.max(StrategyState::Degraded),
///     StrategyState::Degraded
/// );
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Default)]
#[repr(u8)]
pub enum StrategyState {
    /// Operating normally: everything the strategy currently needs to do, it can do.
    #[default]
    Running = 0,
    /// Can still do some of what it needs to, but not all of it.
    Degraded = 1,
    /// Cannot currently do any of what it needs to.
    Failed = 2,
}

impl StrategyState {
    /// Reconstructs a state from the discriminant `as u8` produces on this fieldless,
    /// `#[repr(u8)]` enum. Exists so a strategy can store this small `Copy` value in an
    /// atomic instead of behind a lock — see `channel_lifecycle`'s
    /// `ChannelLifecycleStrategyInner::state` field for the pattern.
    ///
    /// `value` should be a discriminant this enum actually produced (0, 1, or 2); any
    /// other input maps to `Failed`, the safe-direction fallback, rather than panicking.
    pub(crate) fn from_u8(value: u8) -> Self {
        match value {
            0 => Self::Running,
            1 => Self::Degraded,
            _ => Self::Failed,
        }
    }
}

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
}

/// Runs a group of sub-strategies concurrently, each in its own async task.
///
/// `MultiStrategy` is strategy-kind-agnostic: it only knows about
/// `Box<dyn Strategy + Send>`. Any type implementing [`Strategy`] — including
/// ones defined outside this crate — can be composed here.
pub struct MultiStrategy {
    strategies: Vec<Box<dyn Strategy + Send>>,
}

impl MultiStrategy {
    /// Creates a new `MultiStrategy` from pre-built strategy objects.
    ///
    /// Strategies are passed in already constructed; `MultiStrategy` does not know or
    /// care about the concrete types. Pass an empty `strategies` vec to get a passive
    /// strategy that blocks forever.
    pub fn new(strategies: Vec<Box<dyn Strategy + Send>>) -> Self {
        Self { strategies }
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
}
