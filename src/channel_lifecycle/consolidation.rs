//! Stranded-stake consolidation (hopr-strategy#85).
//!
//! When the Safe cannot top channels up to funding value, stake ends up spread
//! across more channels than it can keep usable: every channel sits below one
//! winning-ticket face value, so none can fund a relay ticket and path-finding
//! filters them all out, even when the node's total stake is several times the
//! face value. This module decides which under-funded channels to close so the
//! reclaimed stake lifts as many of the survivors as possible back to face value.

use hopr_api::types::{
    internal::prelude::ChannelId,
    primitive::prelude::{HoprBalance, U256},
};

/// An open, under-funded channel (balance `< face_value`) considered for
/// consolidation. Healthy channels (`>= face_value`) are never passed in, the
/// caller filters them out, and they are never closed to consolidate.
pub(crate) struct ConsolidationCandidate {
    pub id: ChannelId,
    pub balance: HoprBalance,
    /// Selector rank of the channel's peer, in `[0, 1]`; the lowest-ranked are
    /// closed first so the best peers are the ones kept.
    pub rank: f64,
}

/// Chooses the under-funded channels to close so the stake they return lifts as
/// many of the remaining under-funded channels as possible to `face_value`,
/// returning their ids worst-ranked first.
///
/// The count of channels that can be made usable from the pooled stake is
///
/// ```text
/// achievable = floor( (safe_remaining + Σ under-funded balances) / face_value )
/// ```
///
/// independent of which channels are kept: keeping `k` channels and topping each
/// to `face_value` costs `k·face_value − Σ_kept balances`, funded from
/// `safe_remaining + Σ_closed balances`; the kept/closed balances cancel and this
/// reduces to `k ≤ pool / face_value`. So the best `achievable` channels are kept
/// and the rest are closed, worst-ranked first.
///
/// Returns an empty set when nothing can be improved by closing:
///
/// * `face_value` is zero (economics unavailable), or there are no candidates;
/// * `achievable == 0`, not even one channel can be sustained, so closing would only strand the stake in the Safe and
///   invite open/close thrash;
/// * `achievable >= len`, the pool already covers every under-funded channel, so the ordinary fund pass suffices and no
///   closure is needed.
pub(crate) fn consolidation_closes(
    underfunded: &[ConsolidationCandidate],
    safe_remaining: HoprBalance,
    face_value: HoprBalance,
) -> Vec<ChannelId> {
    if face_value.amount().is_zero() || underfunded.is_empty() {
        return Vec::new();
    }

    let pool = underfunded
        .iter()
        .fold(safe_remaining.amount(), |acc, c| acc + c.balance.amount());
    let achievable = pool / face_value.amount();

    // Cannot sustain even one usable channel (closing would only strand the
    // stake in the Safe and invite thrash), or the pool already covers every
    // channel (the ordinary fund pass handles it), either way, close nothing.
    if achievable.is_zero() || achievable >= U256::from(underfunded.len()) {
        return Vec::new();
    }
    // `achievable < len` here, so the cast cannot truncate.
    let close_count = underfunded.len() - achievable.as_usize();

    let mut ranked: Vec<&ConsolidationCandidate> = underfunded.iter().collect();
    // Worst-ranked first; a stable sort keeps input order for equal ranks, so
    // the result is deterministic without a secondary key.
    ranked.sort_by(|a, b| a.rank.partial_cmp(&b.rank).unwrap_or(std::cmp::Ordering::Equal));
    ranked.into_iter().take(close_count).map(|c| c.id).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A balance of `wei` raw units. Consolidation divides raw amounts, so the
    /// unit is irrelevant, small integers keep the arithmetic exact and the
    /// ratios legible. The issue's live figures (stake 5.0, face 7.5) appear
    /// here scaled ×2 (stake 10, face 15) to stay on whole units.
    fn bal(wei: u128) -> HoprBalance {
        HoprBalance::from(U256::from(wei))
    }

    fn candidate(seed: u8, balance: HoprBalance, rank: f64) -> ConsolidationCandidate {
        ConsolidationCandidate {
            id: ChannelId::create(&[&[seed]]),
            balance,
            rank,
        }
    }

    /// Ids of `count` channels all staked `balance`, ranks ascending by seed so
    /// seed `0` is the worst peer.
    fn uniform(count: u8, balance: HoprBalance) -> Vec<ConsolidationCandidate> {
        (0..count)
            .map(|i| candidate(i, balance, f64::from(i) / f64::from(count)))
            .collect()
    }

    /// The reported case: 7 relays at stake 10, face 15, empty Safe. Pool is 70,
    /// so `floor(70/15) = 4` can be kept usable and the 3 worst are closed.
    #[test]
    fn closes_the_excess_so_the_pool_funds_the_rest() {
        let channels = uniform(7, bal(10));
        let closes = consolidation_closes(&channels, bal(0), bal(15));
        assert_eq!(closes.len(), 3, "7 channels, pool 70, face 15 → keep 4, close 3");
    }

    /// Closes exactly the lowest-ranked, so the best peers are the survivors.
    #[test]
    fn closes_the_worst_ranked_first() {
        let channels = uniform(7, bal(10));
        let closes = consolidation_closes(&channels, bal(0), bal(15));
        // Seeds 0..7 have ascending rank; the three worst are seeds 0, 1, 2.
        let expected: Vec<ChannelId> = (0u8..3).map(|i| ChannelId::create(&[&[i]])).collect();
        let closes_set: std::collections::HashSet<_> = closes.iter().map(|id| id.as_ref().to_vec()).collect();
        let expected_set: std::collections::HashSet<_> = expected.iter().map(|id| id.as_ref().to_vec()).collect();
        assert_eq!(closes_set, expected_set, "the three worst-ranked must be closed");
    }

    /// An exact multiple of `face_value` funds exactly that many, no partial
    /// channel: pool 60, face 15 → keep 4, close 2.
    #[test]
    fn exact_multiple_funds_whole_channels_only() {
        let channels = uniform(6, bal(10));
        let closes = consolidation_closes(&channels, bal(0), bal(15));
        assert_eq!(closes.len(), 2, "pool 60, face 15 → keep 4, close 2");
    }

    /// When the whole pool cannot sustain even one usable channel, close
    /// nothing, closing would only strand the stake in the Safe and the open
    /// pass would churn it straight back into sub-threshold channels.
    #[test]
    fn unachievable_pool_closes_nothing() {
        let channels = uniform(2, bal(5)); // pool 10 < face 15
        let closes = consolidation_closes(&channels, bal(0), bal(15));
        assert!(closes.is_empty(), "pool below one face value must not close anything");
    }

    /// When the Safe already covers every channel, consolidation stays out of
    /// the way, the ordinary fund pass will top them all up.
    #[test]
    fn safe_covers_all_closes_nothing() {
        let channels = uniform(2, bal(10));
        let closes = consolidation_closes(&channels, bal(100), bal(15));
        assert!(closes.is_empty(), "a pool covering every channel needs no closure");
    }

    /// Reclaimable stake adds to the Safe balance when deciding how many fit:
    /// safe 15 + two under-funded at 10 = pool 35, face 15 → keep 2, close 0.
    #[test]
    fn safe_plus_reclaimable_decides_the_count() {
        let channels = uniform(2, bal(10));
        let closes = consolidation_closes(&channels, bal(15), bal(15));
        assert!(closes.is_empty(), "pool 35 keeps both (floor(35/15)=2)");
    }

    /// A zero face value (economics unavailable) must never be divided by.
    #[test]
    fn zero_face_value_closes_nothing() {
        let channels = uniform(3, bal(10));
        let closes = consolidation_closes(&channels, bal(0), bal(0));
        assert!(closes.is_empty());
    }
}
