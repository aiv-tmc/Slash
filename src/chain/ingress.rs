//! Block ingress: the single dispatch entry for inbound blocks.
//!
//! `process_block` routes every inbound block to exactly one of three
//! destinations: the main-chain extension path, the fork-competition
//! path, or the orphan pool. The routing decision is made from height and
//! parent linkage alone, so every node dispatches identical blocks
//! identically and the three pools never overlap.

use super::chain::Chain;
use super::params::MAX_SIDE_FORKS;
use super::reorg::fork_heavier_than_main;
use super::types::{Block, BlockError, BlockProcessResult};

impl Chain {
    /// The single entry point for incoming blocks. Blocks that continue
    /// the tip apply immediately; blocks at or below the tip, and blocks
    /// that extend a retained side fork, enter the fork-competition path;
    /// blocks whose parent is unknown to both the main chain and the
    /// side-fork pool wait in the orphan pool. Routing a side-fork
    /// extension into the competition (rather than into the orphan pool)
    /// is what lets a competing branch keep growing: the fork walk inside
    /// `validate_fork_chain` follows side-fork parents, and a branch that
    /// accumulates strictly more work than the main chain over the
    /// contested span is adopted through `reorg_to_fork`.
    pub fn process_block(&mut self, block: Block) -> Result<BlockProcessResult, BlockError> {
        let height = block.height;
        let tip = self.tip_height();
        let hash = self.block_hash(&block);
        if self.is_known_block(hash, height, tip) {
            return Err(BlockError::Duplicate);
        }
        if height == tip + 1 && block.prev == self.tip_hash() {
            // Main-chain extension: the common case.
            if !self.validate_block(&block) {
                return Err(BlockError::InvalidTx);
            }
            self.apply(block)?;
            self.process_orphans();
            return Ok(BlockProcessResult::ExtendedMain);
        }
        if height <= tip || self.side_forks.contains_key(&block.prev) {
            // Competing branch: a block inside the retained window, or an
            // extension of a retained side fork. Both validate through
            // the same cursor walk, so an extending block simply
            // lengthens the branch it builds on.
            if !self.validate_side_fork_entry(&block) {
                return Err(BlockError::InvalidTx);
            }
            match self.validate_fork_chain(&block) {
                Ok(fork) if fork_heavier_than_main(&fork, &self.blocks) => {
                    let disconnected: Vec<u64> = (fork[0].height..=tip).collect();
                    self.reorg_to_fork(&fork)?;
                    return Ok(BlockProcessResult::Reorged {
                        disconnected,
                        connected: fork.iter().map(|b| b.height).collect(),
                    });
                }
                Ok(_fork) => {
                    // Not heavier: retain as a side fork for a possible
                    // future reorg, evicting the oldest entry past the cap.
                    if self.side_forks.len() >= MAX_SIDE_FORKS {
                        if let Some(oldest) = self.side_forks.keys().next().copied() {
                            self.side_forks.remove(&oldest);
                        }
                    }
                    self.side_forks.insert(hash, block);
                    return Ok(BlockProcessResult::SideFork);
                }
                Err(e) => return Err(e),
            }
        }
        // Unknown parent on the main chain and outside the side-fork
        // pool: park in the orphan pool; process_orphans retries parked
        // blocks whenever the tip advances. The pool is bounded at four
        // times the side-fork cap so a flood of parentless blocks cannot
        // exhaust memory.
        if self.orphan_blocks.len() >= MAX_SIDE_FORKS * 4 {
            if let Some(oldest) = self.orphan_blocks.keys().next().copied() {
                self.orphan_blocks.remove(&oldest);
            }
        }
        self.orphan_blocks.insert(hash, block);
        Ok(BlockProcessResult::Orphan)
    }

    /// Duplicate detection across the main vector and both pools. The
    /// main vector holds blocks strictly above `base_height` (the block
    /// at height `h` sits at index `h - base_height - 1`), so the index
    /// is computed with `checked_sub` and the lookup is skipped at or
    /// below the base: a block there cannot duplicate retained history,
    /// and the subtraction can never underflow.
    fn is_known_block(&self, hash: [u8; 32], height: u64, tip: u64) -> bool {
        if height > self.base_height && height <= tip {
            if let Some(index) = height
                .checked_sub(self.base_height)
                .and_then(|offset| offset.checked_sub(1))
            {
                if self
                    .blocks
                    .get(index as usize)
                    .is_some_and(|b| self.block_hash(b) == hash)
                {
                    return true;
                }
            }
        }
        self.side_forks.contains_key(&hash) || self.orphan_blocks.contains_key(&hash)
    }

    /// Structural gate for side-fork entries: reject garbage heights,
    /// difficulties, and sizes before any expensive validation work. A
    /// block one above the tip is admitted only when it extends a
    /// retained side fork; anything higher waits for its parent instead
    /// of entering the competition early.
    pub(crate) fn validate_side_fork_entry(&self, block: &Block) -> bool {
        if block.height == 0 {
            return false;
        }
        if block.height > self.tip_height() && !self.side_forks.contains_key(&block.prev) {
            return false;
        }
        if block.difficulty == 0 {
            return false;
        }
        if bincode::serialize(block)
            .map(|b| b.len())
            .unwrap_or(usize::MAX)
            > super::params::MAX_BLOCK_SIZE_BYTES
        {
            return false;
        }
        true
    }
}
