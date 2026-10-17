//! src/chain/execution/mod.rs — the block execution pipeline.
//!
//! One speculative `State` clone runs the whole block: the proof-of-work
//! slot mint and coinbase (in `meta`), every transaction with the treasury
//! pairing gates on both sides of the bonding curve (in `txs`), governance
//! close/execute, the miner's fee claims, and finally the page-root
//! recomputation against the block's commitments. Only a fully passing
//! speculative state is ever committed, so a failing block leaves the live
//! chain untouched.
//!
//! Layout:
//! - `meta` — header/slot validation and the coinbase mint
//! - `txs` — the transaction list, pairing gates, and fee-claim sweep

mod meta;
mod txs;

use super::chain::Chain;
use super::types::{Block, BlockError, Output};
use crate::state;

impl Chain {
    /// Execute a block against a state and return the post-state, running
    /// every consensus rule in order: coinbase shape, proof-of-work slot
    /// assignment, transaction execution with treasury pairing, fee
    /// claims, governance tally and execution, and finally the page-root
    /// recomputation against the block's commitments.
    pub fn execute_block_state(
        &self,
        state: &crate::state::State,
        block: &Block,
    ) -> Result<crate::state::State, BlockError> {
        let mut temp = state.clone();
        self.execute_block_meta_inner(&mut temp, block)?;
        self.execute_block_txs(&mut temp, block)?;
        // After all transactions, close any proposals whose voting period
        // ends at this height, execute proposals whose scheduled height
        // has arrived, and persist the resulting governance state.
        let mut dao = std::mem::replace(&mut temp.dao, crate::dao::DaoState::genesis());
        dao.close_due(&temp, block.height);
        dao.execute_due(&mut temp, block.height);
        temp.dao = dao;
        // Recompute every dirty-page Merkle root and compare it with the
        // block's commitment. A mismatch means the block's recorded state
        // transition is not the one the local engine executed, so the
        // block is rejected before any external observer can rely on it.
        for (&page_id, page) in &temp.pages {
            let expected = page.merkle_root();
            match block.page_roots.get(&page_id) {
                Some(&root) if root == expected => {}
                _ => return Err(BlockError::InvalidPageRoot),
            }
        }
        // The commitment map must not reference pages the engine did not
        // dirty: an extra root would claim a transition that never ran.
        for &page_id in block.page_roots.keys() {
            if !temp.pages.contains_key(&page_id) {
                return Err(BlockError::InvalidPageRoot);
            }
        }
        Ok(temp)
    }

    /// Header-level validation on a speculative copy of the tip state.
    /// Validates metadata first so a structurally malformed block never
    /// reaches the state engine, then delegates to execute_block_state.
    pub fn execute_block_meta(&self, block: &Block) -> Result<(), BlockError> {
        self.check_block_meta(block)?;
        let mut temp = self.state.clone();
        self.execute_block_meta_inner(&mut temp, block)?;
        self.execute_block_txs(&mut temp, block)?;
        // Close and execute due governance work exactly as
        // execute_block_state does for the committed path.
        let mut dao = std::mem::replace(&mut temp.dao, crate::dao::DaoState::genesis());
        dao.close_due(&temp, block.height);
        dao.execute_due(&mut temp, block.height);
        temp.dao = dao;
        Ok(())
    }

    /// Prepare a candidate block for validation: execute it speculatively
    /// against the tip state and record the resulting dirty-page Merkle
    /// roots into the block's page-root commitment map. Mining calls this
    /// after filling transactions, fee claims, nonce, and slot cell so
    /// the template carries the roots validation will recompute and
    /// compare.
    ///
    /// The speculative run deliberately skips the page-root comparison:
    /// a candidate cannot carry roots before they are computed, so
    /// checking them here would reject every fresh block. The header,
    /// slot, coinbase, transaction, pairing, governance, and fee-claim
    /// gates all still run, and the map is filled from the resulting
    /// pages, so a template that fails any gate keeps its previous roots
    /// and fails validation downstream exactly as before.
    pub fn prepare_block(&self, mut block: Block) -> Block {
        let mut temp = self.state.clone();
        let executed = self
            .execute_block_meta_inner(&mut temp, &block)
            .and_then(|()| self.execute_block_txs(&mut temp, &block))
            .is_ok();
        if executed {
            // Close and execute due governance work exactly as
            // execute_block_state does for the committed path.
            let mut dao = std::mem::replace(&mut temp.dao, crate::dao::DaoState::genesis());
            dao.close_due(&temp, block.height);
            dao.execute_due(&mut temp, block.height);
            temp.dao = dao;
            // Record the recomputed dirty-page roots into the template so
            // validation recomputes and compares exactly these commitments.
            for (&page_id, page) in &temp.pages {
                block.page_roots.insert(page_id, page.merkle_root());
            }
        }
        block
    }

    /// Convert chain-level transaction outputs into the state-level output
    /// type. The two `Output` structs carry identical fields; the state
    /// engine owns the canonical form because every signature hash is
    /// computed over it.
    pub(crate) fn to_state_outputs(outputs: &[Output]) -> Vec<state::Output> {
        outputs
            .iter()
            .map(|o| state::Output {
                start: o.start,
                end: o.end,
                to: o.to,
                lock: o.lock,
            })
            .collect()
    }
}
