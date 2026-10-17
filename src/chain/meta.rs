//! Header-level block metadata: hashing, timestamp rules, checkpoints, and
//! the `check_block_meta` gate every candidate block passes first.
//!
//! These checks are stateless with respect to transactions: they only need
//! the retained block window and the checkpoint table. They run before any
//! speculative execution so a structurally malformed block never reaches
//! the state engine.

use super::chain::Chain;
use super::params::CHECKPOINT_TRUST_DEPTH;
use super::types::{Block, BlockError, BlockHeader};
use blake3::Hasher;

impl Chain {
    /// The canonical block hash: blake3 over version, prev, time, height,
    /// nonce, miner, mined cell, difficulty, and the body hash. Miner and
    /// verifier construct identical inputs, which keeps the proof-of-work
    /// game and its verification in consensus.
    pub fn block_hash(&self, block: &Block) -> [u8; 32] {
        let header = BlockHeader::from_block(block);
        let mut h = Hasher::new();
        h.update(&header.version.to_le_bytes());
        h.update(&header.prev);
        h.update(&header.time.to_le_bytes());
        h.update(&header.height.to_le_bytes());
        h.update(&header.nonce.to_le_bytes());
        h.update(&header.miner);
        h.update(&header.mined_cell.to_le_bytes());
        h.update(&header.difficulty.to_le_bytes());
        h.update(&header.body_hash);
        *h.finalize().as_bytes()
    }

    /// Look up a block by absolute height, if it is inside the retained
    /// window above the base height. Height 0 (the implicit genesis) and
    /// pruned heights report None.
    pub fn get_block(&self, height: u64) -> Option<&Block> {
        if height < self.base_height || height == 0 {
            return None;
        }
        self.blocks.get((height - self.base_height - 1) as usize)
    }

    /// Median timestamp over the last up-to-eleven blocks, the value the
    /// header time rule compares against. An empty chain has no history
    /// and reports zero.
    pub fn median_timestamp(&self) -> u64 {
        let mut times: Vec<u64> = self.blocks.iter().rev().take(11).map(|b| b.time).collect();
        times.sort_unstable();
        times.get(times.len() / 2).copied().unwrap_or(0)
    }

    /// Validate a single light header exactly like a one-element batch
    /// against the current tip.
    pub fn validate_header(&self, header: &BlockHeader) -> bool {
        self.validate_headers_batch(std::slice::from_ref(header))
    }

    /// Check the header-level metadata of a block that targets the current
    /// tip: height continuity, prev hash, the median-time rule over the
    /// last 11 blocks, and the retargeted difficulty. Checkpoints short-
    /// circuit everything: a block at or below a checkpointed height with a
    /// matching hash is accepted on the spot, and a mismatch is a permanent
    /// rejection.
    pub(crate) fn check_block_meta(&self, block: &Block) -> Result<(), BlockError> {
        let tip = self.tip_height();
        if block.height != tip + 1 {
            return Err(BlockError::InvalidHeight);
        }
        if block.prev != self.tip_hash() {
            return Err(BlockError::InvalidPrevHash);
        }
        // Checkpoint short-circuit: trusted blocks below the checkpoint
        // trust depth skip the expensive checks entirely. Within the trust
        // depth the checkpoint at or below the block height applies; deeper
        // in the chain the highest checkpoint applies. A matching hash is
        // accepted outright, a mismatch is a permanent rejection.
        if tip < CHECKPOINT_TRUST_DEPTH {
            if let Some((&h, &cp)) = self.checkpoints.range(..=block.height).next_back() {
                if block.height <= h {
                    let hash = self.block_hash(block);
                    return if hash == cp {
                        Ok(())
                    } else {
                        Err(BlockError::CheckpointViolation)
                    };
                }
            }
        } else if let Some((&h, &cp)) = self.checkpoints.iter().next_back() {
            if block.height <= h {
                let hash = self.block_hash(block);
                return if hash == cp {
                    Ok(())
                } else {
                    Err(BlockError::CheckpointViolation)
                };
            }
        }
        // Median time over the last 11 blocks must be strictly exceeded.
        let mut times: Vec<u64> = self.blocks.iter().rev().take(11).map(|b| b.time).collect();
        if times.is_empty() {
            times.push(0);
        }
        times.sort_unstable();
        let median = times[times.len() / 2];
        if block.time <= median {
            return Err(BlockError::InvalidTimestamp);
        }
        // A block may not be more than two hours ahead of the local clock.
        let now = chrono::Utc::now().timestamp() as u64;
        if block.time > now.saturating_add(7200) {
            return Err(BlockError::InvalidTimestamp);
        }
        if block.difficulty != self.difficulty_for_height(block.height) {
            return Err(BlockError::InvalidDifficulty);
        }
        Ok(())
    }
}
