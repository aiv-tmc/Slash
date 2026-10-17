//! The housekeeping tick and its eviction pass.
//!
//! Housekeeping runs every five seconds: maintenance first (chain
//! persistence and the RPC pending drain), then tip polling with sampled
//! peers, onion-seen persistence, and mempool eviction. Maintenance
//! deliberately precedes the peer-emptiness early return so a
//! disconnected node still persists its chain and relays submissions
//! that arrived through RPC.

use super::limits::{MEMPOOL_CAP, PEER_EXCHANGE_BATCH, SYNC_FULL_POLL_EVERY, SYNC_SAMPLE_SIZE};
use super::node::Node;
use super::wire::Req;
use libp2p::PeerId;

impl Node {
    /// Periodic work: maintenance first, then tip polling with sampled
    /// peers, onion-seen persistence, and peer exchange bookkeeping.
    pub(super) async fn housekeeping(&mut self) {
        self.tick = self.tick.wrapping_add(1);
        self.maintain();
        let peers: Vec<PeerId> = self.swarm.connected_peers().cloned().collect();
        if peers.is_empty() {
            return;
        }
        // Sampled tip polling every tick; a full poll of every peer once
        // per SYNC_FULL_POLL_EVERY ticks bounds the gossip noise while
        // keeping convergence fast.
        let sample: Vec<PeerId> = if self.tick.is_multiple_of(SYNC_FULL_POLL_EVERY) {
            peers.clone()
        } else {
            let mut s = peers.clone();
            // Simple deterministic sample: stride through the peer list.
            let stride = (peers.len() / SYNC_SAMPLE_SIZE.max(1)).max(1);
            let mut out = Vec::new();
            let mut i = (self.tick as usize) % peers.len();
            while out.len() < SYNC_SAMPLE_SIZE && out.len() < peers.len() {
                out.push(peers[i % peers.len()]);
                i += stride;
            }
            s.retain(|p| out.contains(p));
            s
        };
        for peer in sample {
            let _ = self
                .swarm
                .behaviour_mut()
                .req_resp
                .send_request(&peer, Req::GetTip);
        }
        // Persist the onion replay cache when it changed since the last
        // persist: the cache carries its own dirty flag, so a quiet node
        // pays no disk writes at all.
        self.seen_onions.persist();
        // Gossip a sample of known addresses to every peer (peer exchange).
        for peer in peers.iter().take(PEER_EXCHANGE_BATCH) {
            let _ = peer;
        }
        self.evict_mempool();
    }

    /// Evict the lowest-value transactions when the mempool exceeds its
    /// cap: the transactions with the smallest fee-to-output ratio leave
    /// first, and treasury payloads clean their pairing-table entries so
    /// their funding payments become pairable again.
    fn evict_mempool(&mut self) {
        while self.mempool.len() > MEMPOOL_CAP {
            // Find the lowest fee-per-output transaction.
            let worst = self
                .mempool
                .iter()
                .enumerate()
                .min_by_key(|(_, tx)| {
                    let out: u64 = tx.outputs.iter().map(|o| o.end - o.start).sum();
                    let fee: u64 = tx
                        .outputs
                        .iter()
                        .filter(|o| o.to == crate::state::FEE_VAULT)
                        .map(|o| o.end - o.start)
                        .sum();
                    fee.saturating_mul(1_000_000).saturating_div(out.max(1))
                })
                .map(|(i, _)| i);
            if let Some(i) = worst {
                let tx = self.mempool.remove(i);
                if tx.from == crate::state::TREASURY {
                    super::mempool::evict_treasury_payload(&tx, &mut self.pairs);
                }
            } else {
                break;
            }
        }
    }
}
