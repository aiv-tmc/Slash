//! Block production: the mining command handler.
//!
//! One mining command assembles a candidate block from the mempool with
//! the running treasury pricing, builds the coinbase with the dev-fund
//! share while the rule is active, sweeps unlocked fee-vault cells into
//! fee claims, and grinds the nonce through the parallel RandomX miner
//! with cooperative cancellation. The candidate set is capped to the
//! block budget before assembly, and invalid candidates are evicted one
//! at a time with a loop bounded by the template size, so a poisoned
//! mempool can delay but never permanently stall mining. A stale search
//! is cancelled when a new one starts, so worker threads of an old
//! search never compete with the current one for CPU.

use super::behaviour::TOPIC_BLOCKS;
use super::mempool::{assemble_block_txs, build_fee_claims, evict_treasury_payload, tx_id};
use super::node::Node;
use libp2p::gossipsub::IdentTopic;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

impl Node {
    /// Mine one block: assemble transactions from the mempool with running
    /// treasury pricing, build the coinbase with the dev-fund share while
    /// the rule is active, claim unlocked fees, grind the nonce, validate
    /// the full block, and gossip it. The candidate set is capped to the
    /// block budget before assembly, and the retry loop is bounded by the
    /// template size, so a poisoned mempool can delay mining but never
    /// stall it permanently.
    pub(crate) async fn mine(&mut self) {
        let Some(miner_sk) = self.miner_key else {
            return;
        };
        let miner = crate::crypto::public_from_secret(&miner_sk);
        let height = self.chain.tip_height() + 1;
        // The miner routes the configured basis-point share of the subsidy
        // to the dev fund while the DevFund rule is active, exactly
        // mirroring the consensus-side coinbase check.
        let rules = crate::governance::active_rules(&self.chain.version_bits.deployments, height);
        let subsidy = crate::chain::subsidy_at(height);
        let dev_share = if rules
            .iter()
            .any(|r| matches!(r, crate::governance::Rule::DevFund))
        {
            subsidy.saturating_mul(self.chain.state.mine_fee_bps) / 10_000
        } else {
            0
        };
        // Block version follows the active rule set: version 2 once the
        // version-2 deployment activates, version 1 before that.
        let block_version = if rules
            .iter()
            .any(|r| matches!(r, crate::governance::Rule::RequireBlockVersion2))
        {
            2
        } else {
            1
        };
        let coinbase =
            crate::chain::Chain::build_coinbase(&self.chain.state, miner, height, dev_share);
        let has_coinbase = coinbase.is_some();
        let mut block = crate::chain::Block {
            version: block_version,
            prev: self.chain.tip_hash(),
            time: chrono::Utc::now().timestamp() as u64,
            height,
            nonce: 0,
            miner,
            mined_cell: 0,
            txs: Vec::new(),
            fee_claims: Vec::new(),
            difficulty: self.chain.next_difficulty(),
            page_roots: Default::default(),
        };
        if let Some(cb) = coinbase {
            block.txs.push(cb);
        }
        // Assemble at most the block transaction budget: the cap is
        // applied to the candidate set before the first validation pass,
        // so a mempool deeper than the block can hold never yields an
        // oversized template whose only recovery would be one-by-one
        // eviction.
        let tx_budget = crate::chain::MAX_TX_PER_BLOCK.saturating_sub(block.txs.len());
        let capped = &self.mempool[..self.mempool.len().min(tx_budget)];
        block.txs.extend(assemble_block_txs(
            &Some(&self.chain),
            capped,
            height,
            &self.pairs,
        ));
        // Sweep the accumulated fee vault into the block. The sweep
        // selector returns state-level outputs; convert them into the
        // block-level form the block carries.
        block.fee_claims = build_fee_claims(&self.chain.state, miner, height)
            .iter()
            .map(|o| crate::chain::Output {
                start: o.start,
                end: o.end,
                to: o.to,
                lock: o.lock,
            })
            .collect();
        block = self.chain.prepare_block(block);
        // Retry loop: evict the first candidate transaction (after the
        // coinbase position while one exists) until the template
        // validates or no removable transaction remains. The loop is
        // bounded by the template size rather than a fixed round count:
        // every iteration shrinks the candidate set by exactly one, so a
        // poisoned mempool can delay but never permanently stall mining,
        // and can never loop forever. Offenders leave the mempool
        // together with their treasury pairing entries, so a poisoned
        // payload cannot wedge reassembly either.
        let first_candidate = usize::from(has_coinbase);
        while block.txs.len() > first_candidate && !self.chain.validate_block(&block) {
            let offender = block.txs.remove(first_candidate);
            if offender.from == crate::state::TREASURY {
                evict_treasury_payload(&offender, &mut self.pairs);
            }
            self.mempool.retain(|t| tx_id(t) != tx_id(&offender));
            block = self.chain.prepare_block(block);
        }
        // The loop exhausted the candidate set without producing a valid
        // template (the sole remaining transaction, if any, is the
        // offender itself): nothing mineable remains in this attempt.
        if !self.chain.validate_block(&block) {
            return;
        }
        // Parallel nonce search with cooperative cancellation. Replacing
        // the slot cancels a search started by an earlier command so worker
        // threads of a stale search never compete with the current one for
        // CPU.
        let cancel = Arc::new(AtomicBool::new(false));
        if let Some(previous) = self.mine_cancel.replace(cancel.clone()) {
            previous.store(true, Ordering::SeqCst);
        }
        let found = crate::mining::mine_block(
            block.prev,
            block.time,
            block.height,
            block.miner,
            block.difficulty,
            cancel,
        );
        if let Some((nonce, cell)) = found {
            block.nonce = nonce;
            block.mined_cell = cell;
            block = self.chain.prepare_block(block);
            if self.chain.validate_block(&block) && self.chain.apply(block.clone()).is_ok() {
                let included: std::collections::HashSet<Vec<u8>> =
                    block.txs.iter().map(tx_id).collect();
                self.mempool.retain(|t| !included.contains(&tx_id(t)));
                let data = bincode::serialize(&block).unwrap_or_default();
                let _ = self
                    .swarm
                    .behaviour_mut()
                    .gossipsub
                    .publish(IdentTopic::new(TOPIC_BLOCKS), data);
            }
        }
    }
}
