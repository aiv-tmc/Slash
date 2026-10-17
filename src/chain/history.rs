//! Rollback support: the bounded state/deployment histories.
//!
//! Every applied block records its post-state and the active deployment
//! table as one pair, so a reorg can restore the exact rule set that was
//! in force at the fork point and replay the competing branch from
//! there. Recording the pair together is what makes reorgs safe for
//! soft-fork politics: the replayed fork re-counts signaling against the
//! restored table, so orphaned signaling cannot leak into the main
//! chain. The deployment lifecycle advance itself lives in
//! `deployments.rs`.

use super::chain::Chain;
use super::params::{HISTORY_REBUILD_MAX_REPLAY, MAX_REORG_DEPTH};
use super::types::BlockError;

impl Chain {
    /// Record the tip state and the active deployment table at `height`.
    /// A later reorg restores the pair together, so the replayed fork
    /// always re-evaluates signaling against the exact rule set that was
    /// active at the fork point.
    pub(crate) fn record_history(&mut self, height: u64) {
        self.state_history.insert(height, self.state.clone());
        self.deployments_history
            .insert(height, self.version_bits.deployments.clone());
        // Keep both histories bounded to the reorg window: older entries
        // can never be restored and only consume memory.
        let cutoff = height.saturating_sub(MAX_REORG_DEPTH);
        self.state_history.retain(|&h, _| h >= cutoff);
        self.deployments_history.retain(|&h, _| h >= cutoff);
    }

    /// Rebuild the bounded state history by replaying retained blocks
    /// from an exact anchor state. Every replayed transition goes through
    /// the same speculative execution used by validation, so the rebuilt
    /// states are identical to the ones the live chain recorded. The
    /// replay refuses to proceed beyond the configured bound and reports
    /// an error instead of fabricating history, so a restart after
    /// corruption fails closed: reorgs are rejected until enough new
    /// blocks extend the window.
    pub fn rebuild_state_history(
        &mut self,
        anchor_state: crate::state::State,
        anchor_height: u64,
    ) -> Result<(), BlockError> {
        let tip = self.tip_height();
        if anchor_height > tip {
            return Err(BlockError::InvalidHeight);
        }
        self.state_history.clear();
        let mut temp = anchor_state;
        self.state_history.insert(anchor_height, temp.clone());
        for block in &self.blocks {
            if block.height <= anchor_height {
                continue;
            }
            if block.height.saturating_sub(anchor_height) > HISTORY_REBUILD_MAX_REPLAY {
                return Err(BlockError::CannotReorgBeyondHistory);
            }
            temp = self.execute_block_state(&temp, block)?;
            self.state_history.insert(block.height, temp.clone());
        }
        // Keep only the states inside the reorg window: older entries can
        // never be restored and only consume memory.
        let cutoff = tip.saturating_sub(MAX_REORG_DEPTH);
        self.state_history.retain(|&h, _| h >= cutoff);
        Ok(())
    }
}
