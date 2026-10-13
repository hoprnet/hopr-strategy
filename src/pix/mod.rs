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
//! | `strategy-pix-test` | `pix::pools::plain` | `NonAnonymousDepositPool` | `Address` | `hopr-lib/pix-secp256k1` |
//! | `strategy-pix-curvy` | `pix::pools::curvy` | `CurvyDepositPool` | `BjjPublicKey` | `hopr-lib/pix-bjj` (default) |
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

pub mod pools;
pub mod recovery_store;
pub mod strategy;

use hopr_api::node::{PixAddressId, PixDepositData};

use crate::errors::StrategyError;

/// An example [`PoolDepositData`](hopr_api::chain::DepositPool::PoolDepositData): the allocation id
/// plus an uninterpreted byte string.
///
/// **Not a production type.** It is the payload of `pools::plain::NonAnonymousDepositPool` — itself a
/// development-and-testing pool — and it exists mainly to show what the associated type has to look
/// like. A real pool should define its own, naming the note, commitment or blinding factor it
/// actually carries, so that the wire form is parsed and validated once, at the boundary, into
/// something the rest of that pool can use without re-checking. `ByteDepositData` deliberately does
/// none of that: it hands the bytes on unread.
///
/// The one case where reaching for it is reasonable in a pool of your own is the *empty* one, via
/// [`for_id`](Self::for_id) — a pool with no side-channel payload at all still cannot use `()`. The
/// associated type must round-trip through [`PixDepositData`] in both directions, and
/// `PixDepositData` is a *pair*: an allocation id plus the bytes. Producing one back therefore
/// needs the id, and the conversion is on the payload type rather than on the pool, so the id has
/// to be kept somewhere. `PixDepositData` is not optional on the events either, so "nothing to
/// carry" is spelled as empty bytes rather than as an absent payload.
///
/// What any bytes *mean* is the receiving pool's business, so no meaning is imposed here: a pool
/// that requires a particular payload checks for it itself, where the payload reaches it — see
/// `pools::plain::DEPOSIT_MARKER_PAYLOAD` for what that looks like. A check on this type would instead
/// apply to every pool using it.
///
/// Defined here rather than in either pool module because both use it and each is behind its own
/// feature: a `strategy-pix-curvy`-only build cannot reach into `pix::pools::plain`.
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
/// use hopr_strategy::pix::ByteDepositData;
///
/// # fn main() -> anyhow::Result<()> {
/// let id = PixAddressId::new(
///     &HoprPseudonym::from([0xaa; HoprPseudonym::SIZE]),
///     NonZeroU32::new(1).expect("non-zero"),
/// );
///
/// let wire: PixDepositData = ByteDepositData::for_id(id).try_into()?;
/// assert_eq!(wire.id, id);
/// assert!(wire.is_empty());
/// # Ok(()) }
/// ```
///
/// Bytes survive both conversions unchanged, so what one pool put on the wire is exactly what the
/// peer's pool is handed — and judging it is that pool's job, not this type's:
///
/// ```
/// use std::num::NonZeroU32;
///
/// use hopr_api::{
///     node::{PixAddressId, PixDepositData},
///     types::{internal::prelude::HoprPseudonym, primitive::prelude::BytesRepresentable},
/// };
/// use hopr_strategy::pix::ByteDepositData;
///
/// # fn main() -> anyhow::Result<()> {
/// let id = PixAddressId::new(
///     &HoprPseudonym::from([0xbb; HoprPseudonym::SIZE]),
///     NonZeroU32::new(1).expect("non-zero"),
/// );
///
/// let received = PixDepositData {
///     id,
///     data: vec![0xde, 0xad].into(),
/// };
///
/// let payload = ByteDepositData::try_from(received)?;
/// assert_eq!(payload.id(), &id);
/// assert_eq!(payload.payload(), &[0xde, 0xad]);
///
/// let wire: PixDepositData = payload.try_into()?;
/// assert_eq!(&*wire.data, &[0xde, 0xad]);
/// # Ok(()) }
/// ```
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ByteDepositData(PixAddressId, Box<[u8]>);

impl ByteDepositData {
    /// The empty payload for the allocation named by `id` — nothing to carry.
    ///
    /// This is the one constructor a pool outside this crate has reason to reach for: a pool with
    /// no side-channel payload can use `ByteDepositData` this way instead of defining a type of its
    /// own. A pool that *does* carry something should define that type — see the type documentation.
    ///
    /// # Examples
    ///
    /// ```
    /// # use std::num::NonZeroU32;
    /// # use hopr_api::{
    /// #     node::PixAddressId,
    /// #     types::{internal::prelude::HoprPseudonym, primitive::prelude::BytesRepresentable},
    /// # };
    /// use hopr_strategy::pix::ByteDepositData;
    ///
    /// # let id = PixAddressId::new(
    /// #     &HoprPseudonym::from([0xcc; HoprPseudonym::SIZE]),
    /// #     NonZeroU32::new(1).expect("non-zero"),
    /// # );
    /// // `id` names some allocation the pool was asked about.
    /// assert_eq!(ByteDepositData::for_id(id), id.into());
    /// assert!(ByteDepositData::for_id(id).payload().is_empty());
    /// ```
    pub fn for_id(id: PixAddressId) -> Self {
        Self(id, Box::default())
    }

    /// The payload carrying `data`, for the allocation named by `id`.
    ///
    /// Used by `pools::plain::NonAnonymousDepositPool` to carry its marker. A pool with a real payload
    /// is better served by a type that names it than by an uninterpreted byte string — see the type
    /// documentation.
    ///
    /// # Examples
    ///
    /// ```
    /// # use std::num::NonZeroU32;
    /// # use hopr_api::{
    /// #     node::PixAddressId,
    /// #     types::{internal::prelude::HoprPseudonym, primitive::prelude::BytesRepresentable},
    /// # };
    /// use hopr_strategy::pix::ByteDepositData;
    ///
    /// # let id = PixAddressId::new(
    /// #     &HoprPseudonym::from([0xcc; HoprPseudonym::SIZE]),
    /// #     NonZeroU32::new(1).expect("non-zero"),
    /// # );
    /// let data = ByteDepositData::new(id, [0xde, 0xad]);
    /// assert_eq!(data.payload(), &[0xde, 0xad]);
    ///
    /// // An empty `data` is the same thing as `for_id`.
    /// assert_eq!(ByteDepositData::new(id, []), ByteDepositData::for_id(id));
    /// ```
    pub fn new(id: PixAddressId, data: impl Into<Box<[u8]>>) -> Self {
        Self(id, data.into())
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
    /// use hopr_strategy::pix::ByteDepositData;
    ///
    /// # let id = PixAddressId::new(
    /// #     &HoprPseudonym::from([0xdd; HoprPseudonym::SIZE]),
    /// #     NonZeroU32::new(1).expect("non-zero"),
    /// # );
    /// assert_eq!(ByteDepositData::for_id(id).id(), &id);
    /// ```
    pub fn id(&self) -> &PixAddressId {
        &self.0
    }

    /// The bytes travelling alongside the deposit, empty when there are none.
    ///
    /// What they mean is the receiving pool's business — see the type documentation.
    pub fn payload(&self) -> &[u8] {
        &self.1
    }
}

impl From<PixAddressId> for ByteDepositData {
    fn from(id: PixAddressId) -> Self {
        Self::for_id(id)
    }
}

impl TryFrom<PixDepositData> for ByteDepositData {
    // Pinned to `StrategyError` rather than `GeneralError` because `DepositPool` requires both
    // conversions to fail with the pool's own `Error`, and both pools here use `StrategyError`.
    // Nothing here can actually fail — see the note on the reverse conversion for why the
    // fallible form is still the only one that can exist.
    type Error = StrategyError;

    fn try_from(data: PixDepositData) -> Result<Self, Self::Error> {
        // Total on purpose: whether a given payload is acceptable depends on which pool is
        // receiving it, and this conversion is shared by every pool. A pool that only reads one
        // shape of payload rejects the others where it is handed them — see
        // `pools::plain::check_deposit_payload`.
        Ok(Self(data.id, data.data))
    }
}

// Deliberately `TryFrom` and not the infallible `From`, even though it cannot fail. `DepositPool`
// requires `TryInto<PixDepositData, Error = Self::Error>`, and a `From` impl would instead supply
// the blanket `TryFrom` with `Error = Infallible` — which does not satisfy that bound, and which
// coherence forbids overriding. So the fallible form is the only one that can exist here.
impl TryFrom<ByteDepositData> for PixDepositData {
    type Error = StrategyError;

    fn try_from(value: ByteDepositData) -> Result<Self, Self::Error> {
        Ok(Self {
            id: value.0,
            data: value.1,
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
