//! The Safe's wxHOPR one strategy sets aside from the others on the same node.

use std::sync::Arc;

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
#[derive(Clone, Debug, Default)]
pub struct SafeReserve(Arc<parking_lot::Mutex<Reservation>>);

impl SafeReserve {
    pub fn get(&self) -> Reservation {
        *self.0.lock()
    }

    pub fn set(&self, reservation: Reservation) {
        *self.0.lock() = reservation;
    }
}
