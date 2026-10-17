//! Gossip admission for the three broadcast topics: transactions, blocks,
//! and onion envelopes. Every handler returns a three-way verdict so the
//! caller can distinguish honest network noise — a duplicate delivery
//! from an overlapping mesh, an out-of-order block waiting for its
//! parent, an envelope whose next relay left the routing table — from
//! semantically invalid content: only invalid content costs the sender a
//! strike. Admission runs under the sender's token buckets; the onion
//! exit path decrypts the peeled remainder, not the original envelope, so
//! the last layer must come off before inner decryption. The replay
//! cache records only envelopes that authenticated successfully: garbage
//! never occupies a cache slot and cannot evict honest entries.

use super::super::node::Node;
use super::super::wire::Req;
use libp2p::gossipsub::IdentTopic;
use libp2p::PeerId;

use crate::chain::{subsidy_at, Block, BlockError, Tx};
use crate::p2p::mempool::tx_id;

/// The admission verdict of a gossip handler, mapped onto the gossipsub
/// validation report by the caller: `Accept` propagates the message,
/// `Ignore` drops it without any consequence for the sender, and `Reject`
/// scores the propagation source down and — through the caller's strike
/// mapping — penalizes the sender. Honest network noise (duplicates,
/// orphans, missing routes, rate-limit refusals) is `Ignore`; only
/// malformed or semantically invalid content is `Reject`.
pub(super) enum GossipVerdict {
    Accept,
    Ignore,
    Reject,
}

impl Node {
    /// Transaction admission: structural policy through
    /// `Chain::validate_tx`, treasury-pairing admission for treasury
    /// payloads against the running curve total, deduplication by
    /// content-based transaction id, and mempool insertion. An already
    /// known transaction is honest mesh redundancy and returns `Ignore`;
    /// a transaction refused by policy is semantically invalid and
    /// returns `Reject`.
    pub(super) async fn handle_tx(&mut self, peer: PeerId, tx: Tx) -> GossipVerdict {
        if self.is_banned(&peer) {
            return GossipVerdict::Ignore;
        }
        if self.mempool.iter().any(|t| tx_id(t) == tx_id(&tx)) {
            return GossipVerdict::Ignore;
        }
        let admitted = if tx.from == crate::state::TREASURY {
            let mut running_total = self.chain.state.total_sold;
            super::super::mempool::admit_treasury_payload(
                &self.chain,
                &tx,
                &self.mempool,
                &mut self.pairs,
                &mut running_total,
            )
        } else {
            self.chain.validate_tx(&tx)
        };
        if admitted {
            self.mempool.push(tx);
            GossipVerdict::Accept
        } else {
            GossipVerdict::Reject
        }
    }

    /// Block gossip admission: feed the ordinary block pipeline. On
    /// success the block is rebroadcast and included transactions leave
    /// the mempool; on a reorg the disconnected transactions are
    /// re-validated into the mempool. A duplicate or parentless block is
    /// ordinary network ordering and returns `Ignore`; a block refused
    /// by validation is `Reject`.
    pub(super) async fn handle_block(&mut self, peer: PeerId, block: Block) -> GossipVerdict {
        if self.is_banned(&peer) {
            return GossipVerdict::Ignore;
        }
        match self.chain.process_block(block.clone()) {
            Ok(_) => {
                if !self.chain.reorg_disconnected.is_empty() {
                    let disconnected: Vec<Block> =
                        std::mem::take(&mut self.chain.reorg_disconnected);
                    for b in disconnected {
                        // Position 0 is the coinbase only while the
                        // subsidy is positive; it is a consensus
                        // construction that never re-enters the mempool.
                        // From era 9 onward position 0 carries an ordinary
                        // user transaction and re-enters the mempool like
                        // any other, so the skip mirrors the execution
                        // rule exactly.
                        let skip = if subsidy_at(b.height) > 0 { 1 } else { 0 };
                        for tx in b.txs.into_iter().skip(skip) {
                            let _ = self.handle_tx(peer, tx).await;
                        }
                    }
                }
                // Drop the included transactions by content-based id: a
                // signature-equality purge would match every unsigned
                // transaction in the mempool at once, because the coinbase
                // and the treasury payloads all carry an empty signature,
                // and would cost a scan of the block for every entry.
                let included: std::collections::HashSet<Vec<u8>> =
                    block.txs.iter().map(tx_id).collect();
                self.mempool.retain(|t| !included.contains(&tx_id(t)));
                let gossip = bincode::serialize(&block).unwrap_or_default();
                let _ = self.swarm.behaviour_mut().gossipsub.publish(
                    IdentTopic::new(super::super::behaviour::TOPIC_BLOCKS),
                    gossip,
                );
                GossipVerdict::Accept
            }
            Err(BlockError::Duplicate) | Err(BlockError::Orphan) => GossipVerdict::Ignore,
            Err(_) => GossipVerdict::Reject,
        }
    }

    /// Onion envelope relay: replay-cache check, then peel. An envelope
    /// with hops remaining is forwarded to the next relay by unicast; an
    /// exit envelope is decrypted and the inner transaction is admitted
    /// exactly like plaintext gossip, so an onion transaction and a
    /// plaintext transaction follow identical consensus rules. A replayed
    /// envelope and an envelope whose next relay is no longer in the
    /// routing table are honest network churn and return `Ignore`; an
    /// undecryptable or malformed envelope is `Reject`.
    ///
    /// The replay cache records an identifier only after the envelope
    /// has proven itself — deserialized, peeled or decrypted, and either
    /// forwarded or admitted. Garbage envelopes therefore never consume a
    /// cache slot, and an attacker streaming unique malformed envelopes
    /// cannot rotate honest entries out of the FIFO window.
    pub(super) async fn handle_onion(&mut self, peer: PeerId, data: &[u8]) -> GossipVerdict {
        if self.is_banned(&peer) {
            return GossipVerdict::Ignore;
        }
        let id = *blake3::hash(data).as_bytes();
        if self.seen_onions.contains(id) {
            return GossipVerdict::Ignore;
        }
        let Ok(onion) = bincode::deserialize::<crate::onion::OnionTx>(data) else {
            return GossipVerdict::Reject;
        };
        let secret = self.onion_secret();
        let Some(result) = crate::onion::peel(&onion, &secret) else {
            return GossipVerdict::Reject;
        };
        if result.next_relay == [0u8; 32] {
            // Exit relay: decrypt the inner transaction from the peeled
            // remainder — the layer that was just removed is gone from it,
            // which is exactly the shape `decrypt_inner` requires — and
            // admit it through the ordinary transaction path. The cache
            // records the envelope only when the inner transaction was
            // admitted.
            let Some(tx) = crate::onion::decrypt_inner(&result.remaining, &secret) else {
                return GossipVerdict::Reject;
            };
            let verdict = self.handle_tx(peer, tx).await;
            if matches!(verdict, GossipVerdict::Accept) {
                self.seen_onions.insert(id);
            }
            verdict
        } else {
            // Forwarding relay: send the remaining envelope to the next
            // relay by unicast so the transport never broadcasts onion
            // traffic. A next relay that is absent from the routing table
            // is ordinary relay churn, not misbehavior, and costs the
            // sender nothing. The cache records the envelope only when
            // the forward was handed to the transport.
            let bytes = bincode::serialize(&result.remaining).unwrap_or_default();
            if let Some(next) = self.onion_key_to_peer.get(&result.next_relay).copied() {
                let _ = self
                    .swarm
                    .behaviour_mut()
                    .req_resp
                    .send_request(&next, Req::ForwardOnion(bytes));
                self.seen_onions.insert(id);
                GossipVerdict::Accept
            } else {
                GossipVerdict::Ignore
            }
        }
    }
}
