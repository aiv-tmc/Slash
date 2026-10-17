//! Header and slot validation plus the coinbase mint, executed against a
//! speculative state. Metadata checks re-run here because the function is
//! also reached through fork validation where the block does not target
//! the local tip.

use super::super::chain::Chain;
use super::super::pow::verify_pow;
use super::super::subsidy::subsidy_at;
use super::super::types::{Block, BlockError};

impl Chain {
    /// Header and slot validation plus treasury/coinbase minting, executed
    /// against a speculative state. The coinbase is validated against the
    /// executing state, not the chain tip, because this entry point also
    /// serves fork validation, where the block's parent state is the fork
    /// base and the tip state is the wrong basis for the canonical input
    /// selection.
    pub(super) fn execute_block_meta_inner(
        &self,
        temp: &mut crate::state::State,
        block: &Block,
    ) -> Result<(), BlockError> {
        // Active soft-fork rules bind every execution path — main-chain
        // extension, fork validation, and recovery replay — because they
        // are enforced inside this single header-execution entry point
        // rather than in a main-path-only wrapper. The InvalidTx variant
        // carries rule rejections because the error set has no dedicated
        // rule code and this path is fail-closed regardless of the label.
        let rules = crate::governance::active_rules(&self.version_bits.deployments, block.height);
        if !crate::governance::validate_block_rules(block, &rules) {
            return Err(BlockError::InvalidTx);
        }
        // Reject zero-difficulty headers defensively; verify_pow fails
        // closed on its own, and the difficulty-equality rule in
        // check_block_meta is the primary guard.
        if block.difficulty == 0 {
            return Err(BlockError::InvalidDifficulty);
        }
        // Verify the proof-of-work and pin the slot cell to the hash
        // output. The nonce commits to the same input as the search, so
        // the verification recomputes the exact hash the miner ground.
        let cell = verify_pow(
            block.prev,
            block.time,
            block.height,
            block.miner,
            block.nonce,
            block.difficulty,
        )
        .ok_or(BlockError::InvalidPow)?;
        if cell != block.mined_cell {
            return Err(BlockError::InvalidPow);
        }
        // Validate the coinbase shape against the declared subsidy and
        // the executing state before any mutation: the canonical input
        // range is selected on the parent state, and the slot mint below
        // reassigns one treasury cell to the miner, which would shift
        // that selection if the validation ran afterwards.
        self.validate_coinbase(temp, block)?;
        // The PoW slot mint reports success as a boolean: the slot cell
        // must be treasury-owned and unclaimed, otherwise the header is
        // invalid.
        if !temp.mint_slot(block.mined_cell, block.miner, block.height) {
            return Err(BlockError::InvalidTx);
        }
        // Mint the coinbase only while the subsidy is positive: position
        // 0 is the coinbase in eras 0-8 and `validate_coinbase` has
        // already proven it present and treasury-shaped. From era 9
        // onward the subsidy is zero, the coinbase is omitted by rule,
        // and position 0 may carry an ordinary user transaction, which
        // the transaction execution stage handles — minting it here
        // would debit the treasury for cells it does not own.
        if subsidy_at(block.height) > 0 {
            let cb = &block.txs[0];
            // The coinbase mint debits the canonical treasury range and
            // credits the miner (and the dev fund share while the rule is
            // active) through the ordinary mint primitive, which packs
            // outputs exactly over the inputs.
            if !temp.mint(
                &cb.inputs,
                &Self::to_state_outputs(&cb.outputs),
                block.height,
            ) {
                return Err(BlockError::InvalidCoinbase);
            }
        }
        Ok(())
    }
}
