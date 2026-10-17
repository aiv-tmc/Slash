//! Inbound connection budgets: the node-wide inbound cap and the
//! per-subnet caps.
//!
//! Slots are charged when an inbound connection establishes and released
//! when it closes, keyed by peer through a reverse map. Establishment is
//! the earliest point where both the peer identity and the remote
//! address are known, so charging anywhere earlier cannot be attributed
//! to a peer and leaks slots from dials that never complete. Outbound
//! dials never touch the inbound budgets.

use super::limits::{MAX_CONNECTIONS_PER_SUBNET, MAX_INBOUND_CONNECTIONS};
use super::util::subnet_of;
use libp2p::core::ConnectedPoint;
use libp2p::{Multiaddr, PeerId};
use std::collections::HashMap;

/// The established-connection budgets of the node.
#[derive(Default)]
pub(crate) struct ConnectionBudgets {
    /// Established inbound connections, node-wide.
    inbound: usize,
    /// Established inbound connections per subnet. A subnet entry is
    /// removed when its last connection closes, so the map tracks live
    /// subnets only.
    subnets: HashMap<String, usize>,
    /// Reverse map from an established inbound peer to the subnets of
    /// its inbound connections, one entry per connection. A close event
    /// pops one entry and releases exactly the slots the matching open
    /// charged, so churn cannot permanently exhaust a subnet and the
    /// node-wide count cannot drift on connections this table never saw.
    peer_subnets: HashMap<PeerId, Vec<String>>,
}

impl ConnectionBudgets {
    /// Whether an inbound dial fits the node-wide and per-subnet caps.
    /// The dial has no peer identity yet, so the check is read-only and
    /// the slots are charged later, at establishment; the verdict only
    /// informs the admission decision of the caller.
    pub(crate) fn admit(&self, send_back: &Multiaddr) -> bool {
        if self.inbound >= MAX_INBOUND_CONNECTIONS {
            return false;
        }
        match subnet_of(send_back) {
            Some(subnet) => {
                self.subnets.get(&subnet).copied().unwrap_or(0) < MAX_CONNECTIONS_PER_SUBNET
            }
            // Address families without a subnet notion (DNS names) are
            // bounded by the node-wide cap alone.
            None => true,
        }
    }

    /// Charge the budgets for an established connection. An inbound
    /// endpoint consumes one node-wide slot and one slot of its subnet;
    /// an outbound dial consumes nothing.
    pub(crate) fn on_established(&mut self, peer: PeerId, endpoint: &ConnectedPoint) {
        let send_back = match endpoint {
            ConnectedPoint::Listener { send_back_addr, .. } => send_back_addr,
            ConnectedPoint::Dialer { .. } => return,
        };
        self.inbound += 1;
        if let Some(subnet) = subnet_of(send_back) {
            *self.subnets.entry(subnet.clone()).or_insert(0) += 1;
            self.peer_subnets.entry(peer).or_default().push(subnet);
        }
    }

    /// Release the slots one established inbound connection charged.
    /// Connections the table never tracked — every outbound dial —
    /// release nothing.
    pub(crate) fn on_closed(&mut self, peer: &PeerId) {
        let mut forget_peer = false;
        if let Some(subnets) = self.peer_subnets.get_mut(peer) {
            if let Some(subnet) = subnets.pop() {
                self.inbound = self.inbound.saturating_sub(1);
                if let Some(count) = self.subnets.get_mut(&subnet) {
                    *count = count.saturating_sub(1);
                    if *count == 0 {
                        self.subnets.remove(&subnet);
                    }
                }
            }
            forget_peer = subnets.is_empty();
        }
        if forget_peer {
            self.peer_subnets.remove(peer);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// An established inbound connection from the given remote address.
    fn listen_endpoint(addr: &str) -> ConnectedPoint {
        ConnectedPoint::Listener {
            local_addr: "/ip4/0.0.0.0/tcp/30333".parse().unwrap(),
            send_back_addr: addr.parse().unwrap(),
        }
    }

    #[test]
    fn inbound_slots_release_when_the_connection_closes() {
        // An established inbound connection charges one node-wide slot
        // and one subnet slot; closing it releases both, so churn from
        // one subnet cannot permanently exhaust its budget.
        let mut budgets = ConnectionBudgets::default();
        let peer = PeerId::random();
        budgets.on_established(peer, &listen_endpoint("/ip4/203.0.113.7/tcp/40001"));
        assert_eq!(budgets.inbound, 1);
        assert_eq!(budgets.subnets.get("203.0.113.0/24"), Some(&1));
        budgets.on_closed(&peer);
        assert_eq!(budgets.inbound, 0);
        assert!(budgets.subnets.is_empty());
        assert!(budgets.peer_subnets.is_empty());
    }

    #[test]
    fn subnet_cap_blocks_further_inbound_until_a_slot_releases() {
        // The per-subnet cap admits exactly MAX_CONNECTIONS_PER_SUBNET
        // established connections from one subnet, refuses the next
        // dial, keeps admitting other subnets, and reopens the capped
        // subnet as soon as one of its connections closes.
        let mut budgets = ConnectionBudgets::default();
        let mut peers = Vec::new();
        for i in 0..MAX_CONNECTIONS_PER_SUBNET {
            let peer = PeerId::random();
            budgets.on_established(
                peer,
                &listen_endpoint(&format!("/ip4/203.0.113.{}/tcp/40001", 10 + i)),
            );
            peers.push(peer);
        }
        assert_eq!(budgets.inbound, MAX_CONNECTIONS_PER_SUBNET);
        let full_subnet: Multiaddr = "/ip4/203.0.113.99/tcp/40001".parse().unwrap();
        assert!(!budgets.admit(&full_subnet));
        let other_subnet: Multiaddr = "/ip4/198.51.100.5/tcp/40001".parse().unwrap();
        assert!(budgets.admit(&other_subnet));
        budgets.on_closed(&peers[0]);
        assert!(budgets.admit(&full_subnet));
    }

    #[test]
    fn node_wide_cap_counts_all_subnets_together() {
        // The node-wide inbound cap is shared across subnets: filling it
        // refuses dials from any subnet until a connection closes.
        let mut budgets = ConnectionBudgets::default();
        let mut peers = Vec::new();
        for i in 0..MAX_INBOUND_CONNECTIONS {
            let peer = PeerId::random();
            budgets.on_established(
                peer,
                &listen_endpoint(&format!("/ip4/198.51.100.{}/tcp/40001", 10 + (i % 200))),
            );
            peers.push(peer);
        }
        let fresh_subnet: Multiaddr = "/ip4/203.0.113.5/tcp/40001".parse().unwrap();
        assert!(!budgets.admit(&fresh_subnet));
        budgets.on_closed(&peers[0]);
        assert!(budgets.admit(&fresh_subnet));
    }

    #[test]
    fn outbound_dials_never_consume_inbound_budget() {
        // Outbound connections are not inbound load: they charge no
        // slot, and their close events release nothing.
        let mut budgets = ConnectionBudgets::default();
        let peer = PeerId::random();
        budgets.on_established(
            peer,
            &ConnectedPoint::Dialer {
                address: "/ip4/203.0.113.7/tcp/30333".parse().unwrap(),
                role_override: libp2p::core::Endpoint::Dialer,
                port_use: libp2p::core::transport::PortUse::New,
            },
        );
        assert_eq!(budgets.inbound, 0);
        assert!(budgets.subnets.is_empty());
        budgets.on_closed(&peer);
        assert_eq!(budgets.inbound, 0);
        assert!(budgets.subnets.is_empty());
    }

    #[test]
    fn repeated_inbound_from_one_peer_release_one_slot_per_close() {
        // A peer may hold several inbound connections; each close
        // releases exactly one slot pair.
        let mut budgets = ConnectionBudgets::default();
        let peer = PeerId::random();
        budgets.on_established(peer, &listen_endpoint("/ip4/203.0.113.7/tcp/40001"));
        budgets.on_established(peer, &listen_endpoint("/ip4/203.0.113.7/tcp/40002"));
        assert_eq!(budgets.inbound, 2);
        assert_eq!(budgets.subnets.get("203.0.113.0/24"), Some(&2));
        budgets.on_closed(&peer);
        assert_eq!(budgets.inbound, 1);
        assert_eq!(budgets.subnets.get("203.0.113.0/24"), Some(&1));
        budgets.on_closed(&peer);
        assert_eq!(budgets.inbound, 0);
        assert!(budgets.subnets.is_empty());
    }
}
