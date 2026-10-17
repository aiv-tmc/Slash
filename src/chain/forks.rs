//! Competing-branch validation and retention.
//!
//! A competing branch is validated end to end against a cursor chain
//! that carries the main-chain prefix and the fork-point state, and
//! retained in the bounded side-fork pool until it accumulates strictly
//! more work than the main chain over the contested span. Adoption
//! itself lives in `reorg.rs`, ingress dispatch in `ingress.rs`, and
//! the orphan pool in `orphans.rs`.

use super::chain::Chain;
use super::types::{Block, BlockError};

impl Chain {
    /// Validate a retained or inbound competing branch end to end and
    /// return it as an ascending block vector. The walk starts at the
    /// branch tip and follows parent hashes through the retained
    /// side-fork pool until a block whose parent sits on the main chain
    /// is reached, so a branch of any depth — including one that extends
    /// past the tip — resolves to a single contiguous fork. The
    /// validation cursor carries the main-chain prefix up to the fork
    /// point, so header checks (height sequence, linkage, median time,
    /// retargeted difficulty, checkpoints) run through exactly the same
    /// code as the main chain. Coinbase validation and proof-of-work
    /// verification run inside the ordinary speculative execution, so
    /// the branch is checked by a single code path and cannot drift from
    /// main-chain rules.
    pub(crate) fn validate_fork_chain(&self, fork_tip: &Block) -> Result<Vec<Block>, BlockError> {
        // Walk the fork backwards from its tip through the retained pool
        // until the block that extends the main chain is reached.
        let mut fork = vec![fork_tip.clone()];
        loop {
            let head = fork.last().expect("the fork always has a head");
            let connects_main = head.height > self.base_height
                && self
                    .get_block(head.height - 1)
                    .map(|b| self.block_hash(b) == head.prev)
                    .unwrap_or(false);
            if connects_main {
                break;
            }
            let parent = self
                .side_forks
                .get(&head.prev)
                .cloned()
                .ok_or(BlockError::Orphan)?;
            fork.push(parent);
        }
        fork.reverse();
        let fork_point = fork
            .first()
            .map(|b| b.height.saturating_sub(1))
            .ok_or(BlockError::InvalidHeight)?;
        if fork_point < self.base_height {
            return Err(BlockError::CannotReorgBeyondHistory);
        }
        // The retained vector holds the blocks ABOVE the base height, with
        // the block at height h sitting at index h - base - 1, so the
        // prefix through the fork point holds exactly fork_point - base
        // blocks: the cursor tip must be the fork point itself, making
        // the first fork block the cursor's tip-plus-one.
        let prefix_len = (fork_point - self.base_height) as usize;
        let fork_point_state = self
            .state_history
            .get(&fork_point)
            .cloned()
            .ok_or(BlockError::CannotReorgBeyondHistory)?;
        let mut cursor = Chain {
            blocks: self.blocks[..prefix_len.min(self.blocks.len())].to_vec(),
            base_height: self.base_height,
            state: fork_point_state,
            state_history: std::collections::HashMap::new(),
            deployments_history: std::collections::HashMap::new(),
            checkpoints: self.checkpoints.clone(),
            side_forks: std::collections::HashMap::new(),
            orphan_blocks: std::collections::HashMap::new(),
            reorg_disconnected: Vec::new(),
            version_bits: self.version_bits.clone(),
            chain_id: self.chain_id.clone(),
            testnet: self.testnet,
        };
        for b in &fork {
            // Header validation against the cursor: height sequence,
            // previous-hash linkage, median time over the cursor's last
            // eleven blocks, and the retargeted difficulty schedule.
            cursor.check_block_meta(b)?;
            // Speculative execution enforces coinbase shape, treasury
            // pairing, transaction validity, governance rules, and PoW.
            let temp = cursor.execute_block_state(&cursor.state, b)?;
            cursor.blocks.push(b.clone());
            cursor.state = temp;
        }
        Ok(fork)
    }
}
