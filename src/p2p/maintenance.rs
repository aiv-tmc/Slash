//! Periodic node maintenance: chain persistence and the RPC pending
//! drain. The housekeeping tick calls `maintain` before any
//! peer-dependent work so a node without a single connection still
//! persists its chain and relays submissions that arrived through RPC.
//! Everything here touches crate-internal node state.

use super::mempool::admit_treasury_payload;
use super::node::Node;
use libp2p::gossipsub::IdentTopic;

/// Housekeeping ticks between two full chain snapshots. One tick is
/// five seconds, so the chain is snapshotted at most once per minute;
/// between snapshots a restart re-syncs blocks from peers, which the
/// header-first sync path handles from the persisted base height.
const PERSIST_EVERY_TICKS: u64 = 12;

impl Node {
    /// One maintenance pass per housekeeping tick: drain the RPC pending
    /// buffer into the mempool every tick, and persist the chain every
    /// PERSIST_EVERY_TICKS ticks.
    pub(super) fn maintain(&mut self) {
        self.drain_pending();
        if self.tick.is_multiple_of(PERSIST_EVERY_TICKS) {
            self.persist_chain();
        }
    }

    /// Move every transaction the RPC layer queued into the mempool and
    /// gossip it to the mesh, so a submission relays even when it
    /// arrived while the node was busy. Treasury payloads go through the
    /// pairing admission, priced against a running curve position that
    /// starts at the tip's total_sold and advances in arrival order,
    /// exactly as the gossip admission path computes it. Ordinary
    /// transactions are validated against the tip and deduplicated by
    /// signature against the mempool.
    fn drain_pending(&mut self) {
        let mut running_total = self.chain.state.total_sold;
        for tx in crate::drain_pending_txs() {
            let admitted = if tx.from == crate::state::TREASURY {
                admit_treasury_payload(
                    &self.chain,
                    &tx,
                    &self.mempool,
                    &mut self.pairs,
                    &mut running_total,
                )
            } else {
                self.chain.validate_tx(&tx) && !self.mempool.iter().any(|t| t.sig == tx.sig)
            };
            if !admitted {
                continue;
            }
            let bytes = bincode::serialize(&tx).unwrap_or_default();
            let _ = self
                .swarm
                .behaviour_mut()
                .gossipsub
                .publish(IdentTopic::new(super::behaviour::TOPIC_TXS), bytes);
            self.mempool.push(tx);
        }
    }

    /// Write the full chain snapshot through the manifest machinery so
    /// the state, the block vector, and the metadata land as one atomic
    /// triple, then truncate the crash-recovery journal: replaying from
    /// the journal after a consistent snapshot would only duplicate
    /// work the snapshot already records.
    fn persist_chain(&mut self) {
        crate::save(&self.chain);
        let _ = crate::storage::journal_truncate();
    }
}
