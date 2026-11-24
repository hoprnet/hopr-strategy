//! The Safe's wxHOPR one strategy sets aside from the others on the same node.

use std::sync::{Arc, Mutex, PoisonError};

use hopr_api::types::primitive::prelude::HoprBalance;

/// What the PIX strategy currently claims from the Safe for its next pool refill.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Reservation {
    /// Safe wxHOPR the channel lifecycle strategy must not spend.
    pub reserved: HoprBalance,
    /// The pool is low enough that channels should be closed to cover `reserved`.
    pub reclaim: bool,
}

/// A [`Reservation`] shared between the strategies of one node: the PIX strategy writes it, the
/// channel lifecycle strategy spends only the Safe above it and, under `reclaim`, closes its worst
/// channels to cover it. The default reserves nothing.
///
/// Coordination needs clones of one handle; separate handles silently reserve nothing:
///
/// ```text
/// let reserve = SafeReserve::default();
/// let channels = ChannelLifecycleStrategy::new(lifecycle_cfg).with_safe_reserve(reserve.clone());
/// let pix = PixStrategy::new(pix_cfg).with_safe_reserve(reserve);
/// ```
///
/// ```
/// use hopr_api::types::primitive::prelude::HoprBalance;
/// use hopr_strategy::safe_reserve::{Reservation, SafeReserve};
///
/// let reserve = SafeReserve::default();
/// let seen_by_channels = reserve.clone();
/// reserve.set(Reservation {
///     reserved: HoprBalance::new_base(35),
///     reclaim: true,
/// });
/// assert_eq!(seen_by_channels.get().reserved, HoprBalance::new_base(35));
/// ```
#[derive(Clone, Debug, Default)]
pub struct SafeReserve(Arc<Mutex<Reservation>>);

impl SafeReserve {
    /// The current reservation.
    pub fn get(&self) -> Reservation {
        *self.0.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Replaces the reservation every clone of this handle sees.
    pub fn set(&self, reservation: Reservation) {
        *self.0.lock().unwrap_or_else(PoisonError::into_inner) = reservation;
    }
}
