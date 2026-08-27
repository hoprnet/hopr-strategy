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
//! | `DepositDataRequest` | spawns a task that streams one payload per requested id back through the event's channel | `generate_deposit_data`, once per id |
//! | `NewDepositAddress` | prices the quota at `price_per_byte`, refuses anything above `max_ssa_allocation`, narrows the address to `K::Public`, checks the payload is the pool's and is filed under the event's own id, drops duplicates, buffers | `deposit_funds_to`, or `deposit_funds_to_multiple` for a batch |
//! | `DepositAddressReceived` | spawns the returned future and reports the confirmed balance back through the event's notifier | `notify_deposit` |
//! | `PrivateKeyRecovered` | persists the key to the [`recovery_store`], drops duplicate sweeps, buffers | `withdraw_deposit` / `withdraw_multiple_deposits`, always to the node's Safe |
//!
//! Deposits and withdrawals are debounced (`deposit_buffer_period`, `withdrawal_buffer_period`)
//! and flushed together, which is why two rows name both a single- and a multi-address call: the
//! batch form is used whenever more than one event arrived inside the window.
//!
//! `DepositDataRequest` is *not* debounced: the Exit is blocked on the event's channel before it
//! can send its PIX request at all, so it is answered as it arrives.
//!
//! ## Where the boundary sits
//!
//! The strategy never retries a pool call. `DepositPool` makes reliability the implementation's
//! job, so an error arriving here means the pool has already spent its budget: the deposit is
//! abandoned for that flush, and a withdrawal keeps its persisted key so a later start can try
//! again. The deposit-tracking deadline is the pool's for the same reason — it is reported
//! through the failure channel of `notify_deposit`'s future.
//!
//! The side-channel payload is the pool's too, in both directions: the pool *generates* it
//! (`generate_deposit_data`) and owns its wire form, since `DepositPool::PoolDepositData` must
//! round-trip through `PixDepositData` itself. The strategy neither reads nor constructs those
//! bytes; it only routes them, and rejects a payload whose conversion the pool refuses.
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
//! | `strategy-pix-test` | `pix::secp256k1` | `NonAnonymousDepositPool` | `Address` | `hopr-lib/pix-secp256k1` |
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
#[cfg(feature = "strategy-pix-test")]
pub mod secp256k1;
pub mod strategy;

use hopr_api::{
    node::{PixAddressId, PixDepositData},
    types::primitive::prelude::GeneralError,
};

use crate::errors::StrategyError;

/// [`PoolDepositData`](hopr_api::chain::DepositPool::PoolDepositData) for a pool that carries no
/// PIX side-channel payload.
///
/// A pool with nothing to carry still cannot use `()`: the associated type must round-trip through
/// [`PixDepositData`] in both directions, and `PixDepositData` is a *pair* — an
/// allocation id plus the bytes. Producing one back therefore needs the id, and the conversion is
/// on the payload type rather than on the pool, so this is where the id has to be kept. The bytes
/// are what is empty here; the id never is.
///
/// Shared by both pool modules rather than defined in either, because each is behind its own
/// feature: a `strategy-pix-curvy`-only build cannot reach into `pix::secp256k1`.
///
/// # Examples
///
/// A payload that carries nothing still names the allocation it belongs to, which is what makes it
/// convertible back to the wire form:
///
/// ```
/// use std::num::NonZeroU32;
///
/// use hopr_api::{
///     node::{PixAddressId, PixDepositData},
///     types::{internal::prelude::HoprPseudonym, primitive::prelude::BytesRepresentable},
/// };
/// use hopr_strategy::pix::EmptyDepositData;
///
/// # fn main() -> anyhow::Result<()> {
/// let id = PixAddressId::new(
///     &HoprPseudonym::from([0xaa; HoprPseudonym::SIZE]),
///     NonZeroU32::new(1).expect("non-zero"),
/// );
///
/// let wire: PixDepositData = EmptyDepositData::for_id(id).try_into()?;
/// assert_eq!(wire.id, id);
/// assert!(wire.is_empty());
/// # Ok(()) }
/// ```
///
/// The reverse conversion accepts an empty payload and rejects one carrying bytes, because bytes
/// arriving at a pool that cannot read them mean the two ends disagree about which pool is running:
///
/// ```
/// use std::num::NonZeroU32;
///
/// use hopr_api::{
///     node::{PixAddressId, PixDepositData},
///     types::{internal::prelude::HoprPseudonym, primitive::prelude::BytesRepresentable},
/// };
/// use hopr_strategy::pix::EmptyDepositData;
///
/// # fn main() -> anyhow::Result<()> {
/// let id = PixAddressId::new(
///     &HoprPseudonym::from([0xbb; HoprPseudonym::SIZE]),
///     NonZeroU32::new(1).expect("non-zero"),
/// );
///
/// let empty = PixDepositData {
///     id,
///     data: Box::default(),
/// };
/// assert_eq!(EmptyDepositData::try_from(empty)?.id(), &id);
///
/// let carries_bytes = PixDepositData {
///     id,
///     data: vec![0xde, 0xad].into(),
/// };
/// assert!(EmptyDepositData::try_from(carries_bytes).is_err());
/// # Ok(()) }
/// ```
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct EmptyDepositData(PixAddressId);

impl EmptyDepositData {
    /// The empty payload for the allocation named by `id`.
    ///
    /// # Examples
    ///
    /// ```
    /// # use std::num::NonZeroU32;
    /// # use hopr_api::{
    /// #     node::PixAddressId,
    /// #     types::{internal::prelude::HoprPseudonym, primitive::prelude::BytesRepresentable},
    /// # };
    /// use hopr_strategy::pix::EmptyDepositData;
    ///
    /// # let id = PixAddressId::new(
    /// #     &HoprPseudonym::from([0xcc; HoprPseudonym::SIZE]),
    /// #     NonZeroU32::new(1).expect("non-zero"),
    /// # );
    /// // `id` names some allocation the pool was asked about.
    /// assert_eq!(EmptyDepositData::for_id(id), id.into());
    /// ```
    pub fn for_id(id: PixAddressId) -> Self {
        Self(id)
    }

    /// The allocation this payload belongs to.
    ///
    /// # Examples
    ///
    /// ```
    /// # use std::num::NonZeroU32;
    /// # use hopr_api::{
    /// #     node::PixAddressId,
    /// #     types::{internal::prelude::HoprPseudonym, primitive::prelude::BytesRepresentable},
    /// # };
    /// use hopr_strategy::pix::EmptyDepositData;
    ///
    /// # let id = PixAddressId::new(
    /// #     &HoprPseudonym::from([0xdd; HoprPseudonym::SIZE]),
    /// #     NonZeroU32::new(1).expect("non-zero"),
    /// # );
    /// assert_eq!(EmptyDepositData::for_id(id).id(), &id);
    /// ```
    pub fn id(&self) -> &PixAddressId {
        &self.0
    }
}

impl From<PixAddressId> for EmptyDepositData {
    fn from(id: PixAddressId) -> Self {
        Self::for_id(id)
    }
}

impl TryFrom<PixDepositData> for EmptyDepositData {
    // Pinned to `StrategyError` rather than `GeneralError` because `DepositPool` requires both
    // conversions to fail with the pool's own `Error`, and both pools here use `StrategyError`.
    type Error = StrategyError;

    fn try_from(data: PixDepositData) -> Result<Self, Self::Error> {
        // A non-empty payload is rejected rather than ignored: it means the Entry sent PIX deposit
        // data to an Exit whose pool cannot use it — the two ends disagree about which pool is
        // running. Swallowing it reproduces exactly the failure this module's `curvy` docs
        // describe: no deposits, no diagnostic.
        //
        // An *empty* payload is not the same thing, and is accepted: it is what both pools here
        // generate.
        data.is_empty()
            .then_some(Self(data.id))
            .ok_or(StrategyError::GeneralError(GeneralError::InvalidInput))
    }
}

// Deliberately `TryFrom` and not the infallible `From`, even though it cannot fail. `DepositPool`
// requires `TryInto<PixDepositData, Error = Self::Error>`, and a `From` impl would instead supply
// the blanket `TryFrom` with `Error = Infallible` — which does not satisfy that bound, and which
// coherence forbids overriding. So the fallible form is the only one that can exist here.
impl TryFrom<EmptyDepositData> for PixDepositData {
    type Error = StrategyError;

    fn try_from(value: EmptyDepositData) -> Result<Self, Self::Error> {
        Ok(Self {
            id: value.0,
            data: Box::default(),
        })
    }
}

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
    note = "the `strategy-pix-*` feature and the node's `hopr-lib/pix-*` feature must agree: pair `strategy-pix-test` \
            with `hopr-lib/pix-secp256k1` (`Address`), or `strategy-pix-curvy` with `hopr-lib/pix-bjj` \
            (`BjjPublicKey`)"
)]
pub trait DepositAddressOf<P> {}
