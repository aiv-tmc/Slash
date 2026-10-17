//! Block application entry points.
//!
//! `apply` is the commit path for a block that extends the tip: metadata,
//! speculative execution, commit, history record, version-bit update.
//! `apply_recovered` is the journal-replay path used at startup, which
//! skips the expensive metadata checks because every journaled block was
//! fully validated before it was written.

use super::chain::Chain;
use super::types::{Block, BlockError};

impl Chain {
    /// Apply a fully valid block to the chain: metadata checks, full
    /// speculative execution, commit of the post-state, push, history
    /// record, and version-bit update. The block must extend the current
    /// tip; fork handling lives in `process_block`.
    pub fn apply(&mut self, block: Block) -> Result<(), BlockError> {
        self.check_block_meta(&block)?;
        let temp = self.execute_block_state(&self.state, &block)?;
        self.blocks.push(block.clone());
        self.state = temp;
        self.record_history(block.height);
        // Count this block's version bits and advance every deployment's
        // lifecycle. The borrow of the applied block keeps the chain
        // borrow disjoint while the deployment table is mutated.
        self.update_version_bits(&block);
        Ok(())
    }

    /// Feed a recovered block (from the crash-recovery journal) into the
    /// chain without re-checking metadata: linkage to the current tip must
    /// hold, and the block executes through the ordinary speculative
    /// pipeline. Recovery replays committed blocks only, so a linkage
    /// break means the journal is ahead of the manifest and replay stops
    /// at the first gap.
    pub fn apply_recovered(&mut self, block: Block) -> Result<(), BlockError> {
        if block.height != self.tip_height() + 1 || block.prev != self.tip_hash() {
            return Err(BlockError::InvalidPrevHash);
        }
        let temp = self.execute_block_state(&self.state, &block)?;
        self.blocks.push(block.clone());
        self.state = temp;
        self.record_history(block.height);
        self.update_version_bits(&block);
        Ok(())
    }
}
