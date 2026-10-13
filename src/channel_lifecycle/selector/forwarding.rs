//! Per-peer funded-outgoing-channel count: the "forwarding capability" signal.
//!
//! A peer with no funded outgoing channels can only ever be the *last* hop of a
//! path — it can never be an intermediate relay, so it cannot carry the 2- and
//! 3-hop paths the strategy builds, nor route return traffic that earns us
//! tickets.  Every selector uses this count via
//! [`partition_by_forwarding`](super::partition_by_forwarding) to make such
//! peers a last resort, never to bar them.  Populated only when
//! `eligibility.demote_non_forwarding_peers` is set.

use std::collections::HashMap;

use hopr_api::types::primitive::prelude::Address;

/// Per-peer count of funded (`Open`) outgoing channels to distinct third
/// parties.  Peers not present count `0`.
pub struct ForwardingView {
    counts: HashMap<Address, u32>,
}

impl ForwardingView {
    pub fn empty() -> Self {
        Self { counts: HashMap::new() }
    }

    pub fn from_counts(counts: HashMap<Address, u32>) -> Self {
        Self { counts }
    }

    /// Funded `Open` outgoing channels the peer sources to distinct third
    /// parties, or `0` if unknown.
    ///
    /// Unlike probe data, absence here is a *measured* fact: the channel graph is
    /// globally observable on-chain, so a peer missing from the map genuinely has
    /// no outgoing channels and is correctly treated as a ticket sink — this is
    /// not the self-sealing "never measured" case that
    /// [`PeerEdgeInfo::UNMEASURED`](super::PeerEdgeInfo::UNMEASURED) guards
    /// against.
    pub fn outgoing_channels(&self, addr: &Address) -> u32 {
        self.counts.get(addr).copied().unwrap_or(0)
    }
}
