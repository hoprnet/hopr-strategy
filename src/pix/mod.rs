//! # PIX strategy
//!
//! ## What the strategy does
//!
//! The strategy — built by [`PixStrategy`](strategy::PixStrategy) — consumes `PixEvent`s from the
//! node and turns them into [`DepositPool`](hopr_api::chain::DepositPool) calls. It owns the
//! policy around those calls; the pool owns the settlement.
//!
//! | event | the strategy | the pool |
//! |---|---|---|
//! | `NewDepositAddress` | prices the quota at `price_per_byte`, refuses anything above `max_ssa_allocation`, narrows the address to `K::Public`, drops duplicates, buffers | `deposit_funds_to`, or `deposit_funds_to_multiple` for a batch |
//! | `DepositAddressReceived` | spawns the returned future and reports the confirmed balance back through the event's notifier | `notify_deposit` |
//! | `PrivateKeyRecovered` | persists the key to the [`recovery_store`], drops duplicate sweeps, buffers | `withdraw_deposit` / `withdraw_multiple_deposits`, always to the node's Safe |
//!
//! Deposits and withdrawals are debounced (`deposit_buffer_period`, `withdrawal_buffer_period`)
//! and flushed together, which is why two rows name both a single- and a multi-address call: the
//! batch form is used whenever more than one event arrived inside the window.
//!
//! ## Where the boundary sits
//!
//! The strategy never retries a pool call. `DepositPool` makes reliability the implementation's
//! job, so an error arriving here means the pool has already spent its budget: the deposit is
//! abandoned for that flush, and a withdrawal keeps its persisted key so a later start can try
//! again. The deposit-tracking deadline is the pool's for the same reason — it is reported
//! through the failure channel of `notify_deposit`'s future.
//!
//! What the strategy keeps is what the pool cannot see: pricing and the allocation cap, the
//! in-flight guards that stop one SSA being funded or swept twice, the debounce windows, and the
//! recovery store — a recovered key is persisted before its sweep is attempted and removed only
//! once funds have moved, so an unfinished sweep is replayed on the next start.
//!
//! ## Choosing a deposit pool
//!
//! [`DepositPool`](hopr_api::chain::DepositPool) is generic over its keypair, and `K::Public` is
//! the deposit address the pool can settle to. That address type has to match the one
//! `HoprPixSpec` produces — which is chosen by a feature on `hopr-crypto-packet`, in a different
//! crate. Two independent axes that must agree, and Cargo cannot express agreement across
//! crates.
//!
//! Each pool therefore gets its own feature *and its own module*, and a consumer pairs the two
//! axes itself:
// Code spans, not intra-doc links: each row names a module that only exists when its own feature
// is on, so linking them makes every single-pool build emit a broken-intra-doc-link warning. Same
// reason in `strategy.rs` for the two builders. Please leave them unlinked.
//! | feature | module | pool | `K::Public` | pair with |
//! |---|---|---|---|---|
//! | `strategy-pix-secp256k1` | `pix::secp256k1` | `NonAnonymousDepositPool` | `Address` | `hopr-lib/pix-secp256k1` |
//! | `strategy-pix-curvy` | `pix::curvy` | `CurvyDepositPool` (**stub**) | `BjjPublicKey` | `hopr-lib/pix-bjj` (default) |
//!
//! Both features may be enabled at once, and enabling both is what `--all-features` does. Nothing
//! is selected *by* the feature graph: each module exports its own `PoolKeypair` / `PoolConfig`
//! and its own builder on [`PixStrategy`](strategy::PixStrategy), so the pool is chosen at the
//! call site rather than by which features happen to be on.
//!
//! That is a deliberate reversal of an earlier design in which the two features were mutually
//! exclusive and a `compile_error!` rejected both. Cargo features are additive and this is a
//! library: the exclusion could be triggered by two *unrelated* consumers in one dependency
//! graph each wanting a different pool, and neither had any way to fix it locally.
//!
//! ## Keeping the pool and the spec in agreement
//!
//! The two axes still have to agree, and a disagreement is not something this crate can catch on
//! its own: `PixDepositAddress` is a runtime enum over *every* scheme, so the strategy's narrowing
//! to `K::Public` is a `TryFrom` it can only fail at runtime — once per event, having deposited
//! nothing. `HoprPixSpec` lives in a crate this one does not depend on, so only the consumer ever
//! holds both types at once.
//!
//! [`DepositAddressOf`] is what lets the consumer state their agreement once. Each builder takes
//! the spec's address type as a witness parameter, so naming it *is* the check:
//!
//! ```text
//! PixStrategy::new(cfg)
//!     .build_non_anonymous::<_, <HoprPixSpec as PixSpec>::DepositAddress>(node, pool_cfg)?
//! ```
//!
//! A build that paired this pool with the wrong `hopr-lib/pix-*` feature stops at that call site
//! with an error naming both the offending type and the feature pairing that fixes it. There is no
//! separate assertion to keep in sync, because the assertion and the choice are the same
//! expression.
//!
//! Enabling `strategy-pix` alone is supported and gives the engine without a pool, for a
//! consumer supplying its own via
//! [`PixStrategy::build_with_pool`](strategy::PixStrategy::build_with_pool).

#[cfg(feature = "strategy-pix-curvy")]
pub mod curvy;
pub mod recovery_store;
#[cfg(feature = "strategy-pix-secp256k1")]
pub mod secp256k1;
pub mod strategy;

/// Witness that `Self` is exactly the deposit address the pool keyed on `P` settles to.
///
/// `A: DepositAddressOf<P>` holds only when `P::Public == A`, so naming the node's
/// `<HoprPixSpec as PixSpec>::DepositAddress` in a builder call *is* the compatibility check
/// between the pool and the node's PIX spec, and a mismatch is a compile error at that call site.
/// See the module documentation for why the check cannot live inside this crate.
///
/// Bounded on `Self` rather than written as a `P: Keypair<Public = A>` projection equality on
/// purpose: the latter normalises `P::Public` to a generic `A` throughout the builder body, which
/// drags every `K::Public` bound of
/// [`build_with_pool`](strategy::PixStrategy::build_with_pool) onto the caller. This keeps the
/// concrete address type visible inside and the assertion at the boundary.
///
/// Implemented once per pool, in that pool's own module, rather than by a blanket
/// `impl<P, A> DepositAddressOf<P> for A where P: Keypair<Public = A>`. The blanket form makes a
/// mismatch resolve as `E0271` (projection mismatch) rather than `E0277` (unimplemented trait),
/// and `on_unimplemented` below only applies to the latter — which would lose the note naming the
/// two features, the half of the fix that is not guessable from a type mismatch. Each per-pool
/// impl is written for `<PoolKeypair as Keypair>::Public` rather than for a named type, so it is
/// derived from the keypair and cannot claim an address its pool does not settle to.
#[diagnostic::on_unimplemented(
    message = "the selected PIX deposit pool cannot settle to `{Self}` deposit addresses",
    label = "the node's PIX spec produces `{Self}`, which is not the address type this pool settles to",
    note = "the `strategy-pix-*` feature and the node's `hopr-lib/pix-*` feature must agree: pair \
            `strategy-pix-secp256k1` with `hopr-lib/pix-secp256k1` (`Address`), or `strategy-pix-curvy` with \
            `hopr-lib/pix-bjj` (`BjjPublicKey`)"
)]
pub trait DepositAddressOf<P> {}
