//! Connection lifecycle and node key material.
//!
//! Inbound dials are gated against the connection budgets, slots are
//! charged at establishment and released at close, misbehavior
//! accumulates strikes into exponential bans, and the node's Ed25519
//! identity and X25519 onion key are loaded or created on disk.

use super::node::Node;
use libp2p::{identity, Multiaddr, PeerId};
use std::time::{Duration, Instant};

impl Node {
    /// Gate an inbound dial against the node-wide and per-subnet budgets.
    /// The dial has not identified its peer yet, so no slot is charged
    /// here; the admission verdict is enforced when the connection
    /// establishes, since the incoming event cannot refuse the dial
    /// itself — an over-budget address is remembered and its connection
    /// is closed at establishment time before any traffic flows.
    pub(crate) fn on_incoming_connection(&mut self, send_back: Multiaddr) {
        if !self.budgets.admit(&send_back) {
            self.rejected_inbound.insert(send_back);
        }
    }

    /// Release the connection budgets and the onion routing entries when
    /// a connection closes. Only connections the budget table tracked as
    /// inbound release a slot; outbound dials release nothing.
    pub(crate) fn on_connection_closed(&mut self, peer: PeerId) {
        self.budgets.on_closed(&peer);
        self.onion_keys.remove(&peer);
        if let Some(key) = self
            .onion_key_to_peer
            .iter()
            .find(|(_, p)| **p == peer)
            .map(|(k, _)| *k)
        {
            self.onion_key_to_peer.remove(&key);
        }
    }

    /// Charge the inbound budgets for an established connection. The
    /// endpoint identifies whether the connection is inbound and carries
    /// the remote address for the subnet attribution. An inbound
    /// connection whose address was over budget at admission time is
    /// disconnected immediately, enforcing the node-wide and per-subnet
    /// caps against floods.
    pub(crate) fn on_connection_established(
        &mut self,
        peer: PeerId,
        endpoint: libp2p::core::ConnectedPoint,
    ) {
        self.budgets.on_established(peer, &endpoint);
        if let libp2p::core::ConnectedPoint::Listener { send_back_addr, .. } = &endpoint {
            if self.rejected_inbound.remove(send_back_addr) {
                let _ = self.swarm.disconnect_peer_id(peer);
            }
        }
    }

    /// Record a misbehavior strike and ban the peer at the threshold;
    /// every further strike doubles the ban up to the maximum.
    pub(crate) fn record_strike(&mut self, peer: PeerId) {
        let strikes = self.strikes.entry(peer).or_insert(0);
        *strikes += 1;
        if let Some(duration) = super::util::ban_duration_secs(*strikes) {
            self.banned_until
                .insert(peer, Instant::now() + Duration::from_secs(duration));
        }
    }

    /// Whether the peer is currently banned.
    pub(crate) fn is_banned(&self, peer: &PeerId) -> bool {
        self.banned_until
            .get(peer)
            .is_some_and(|until| *until > Instant::now())
    }

    /// The 32-byte seed of the node identity; used to sign onion-key
    /// attestations.
    pub(crate) fn node_secret(&self) -> [u8; 32] {
        if let Ok(bytes) = std::fs::read("node_key.bin") {
            if let Ok(sk) = bincode::deserialize::<[u8; 32]>(&bytes) {
                return sk;
            }
        }
        let (sk, _) = crate::crypto::generate_keypair();
        if let Ok(encoded) = bincode::serialize(&sk) {
            let _ = crate::storage::atomic_write("node_key.bin", &encoded);
        }
        sk
    }

    /// The X25519 onion secret, persisted as `x25519.bin`.
    pub(crate) fn onion_secret(&self) -> [u8; 32] {
        load_or_create_onion_key()
    }

    /// The X25519 onion public key derived from the persisted onion secret.
    pub(crate) fn onion_public(&self) -> [u8; 32] {
        use x25519_dalek::{PublicKey, StaticSecret};
        let secret = StaticSecret::from(self.onion_secret());
        *PublicKey::from(&secret).as_bytes()
    }

    /// Resolve every DNS seed into dialable TCP multiaddresses and merge
    /// them into the known-addresses table.
    pub(crate) async fn resolve_dns_seeds(&mut self) {
        for seed in super::util::dns_seeds() {
            if let Ok(lookup) = tokio::net::lookup_host(format!("{}:30333", seed)).await {
                for ip in lookup {
                    let addr = format!("/ip4/{}/tcp/30333", ip.ip())
                        .parse()
                        .expect("seed addr");
                    self.add_known_addr(addr);
                }
            }
        }
    }

    /// Merge a bootstrap file's multiaddresses into the known-addresses
    /// table; a missing or corrupt file is not an error.
    pub(crate) fn load_bootstrap_file(&mut self, path: &str) {
        let Ok(contents) = std::fs::read_to_string(path) else {
            return;
        };
        let Ok(addrs) = serde_json::from_str::<Vec<String>>(&contents) else {
            return;
        };
        for addr in addrs {
            if let Ok(multi) = addr.parse::<Multiaddr>() {
                self.add_known_addr(multi);
            }
        }
    }
}

/// Load or create the node's Ed25519 identity, persisted as a bincode
/// 32-byte secret in `node_key.bin`. A corrupt file is ignored and a fresh
/// key is generated; the peer id changing costs only a reconnect.
pub(super) fn load_or_create_node_key() -> identity::Keypair {
    if let Ok(bytes) = std::fs::read("node_key.bin") {
        if let Ok(sk) = bincode::deserialize::<[u8; 32]>(&bytes) {
            if let Ok(keypair) = identity::ed25519::Keypair::try_from_bytes(&mut sk.clone()) {
                return identity::Keypair::from(keypair);
            }
        }
    }
    let keypair = identity::ed25519::Keypair::generate();
    let secret: [u8; 32] = keypair.to_bytes()[..32]
        .try_into()
        .expect("ed25519 key material is 64 bytes");
    if let Ok(encoded) = bincode::serialize(&secret) {
        let _ = crate::storage::atomic_write("node_key.bin", &encoded);
    }
    identity::Keypair::from(keypair)
}

/// Load or create the node's X25519 onion secret, persisted as a bincode
/// 32-byte secret in `x25519.bin`.
fn load_or_create_onion_key() -> [u8; 32] {
    if let Ok(bytes) = std::fs::read("x25519.bin") {
        if let Ok(sk) = bincode::deserialize::<[u8; 32]>(&bytes) {
            return sk;
        }
    }
    let sk = crate::crypto::generate_x25519_secret();
    if let Ok(encoded) = bincode::serialize(&sk) {
        let _ = crate::storage::atomic_write("x25519.bin", &encoded);
    }
    sk
}
