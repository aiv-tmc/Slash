//! Difficulty retargeting: one windowed rescale feeds both the main chain
//! and the header-batch schedule, with the four-fold clamp and the
//! minimum-difficulty floor.

use super::params::{DIFFICULTY_ADJUSTMENT_INTERVAL, TARGET_BLOCK_TIME_SECS};

impl super::chain::Chain {
    /// The retargeted difficulty for an absolute height. The retarget
    /// runs only when `height - 1` opens a new retarget interval; inside
    /// an interval the difficulty is inherited from the previous block.
    /// The rescale compares the measured window time against the target
    /// interval time and clamps the result to a four-fold change per
    /// interval, never below the minimum difficulty of one.
    pub fn difficulty_for_height(&self, height: u64) -> u64 {
        let base = self.base_height.max(1);
        if height <= base || self.blocks.is_empty() {
            return 1;
        }
        let idx = height.saturating_sub(self.base_height) as usize;
        if (height - 1).is_multiple_of(DIFFICULTY_ADJUSTMENT_INTERVAL)
            && idx > 0
            && idx <= self.blocks.len()
        {
            // Measure over the window that ends at the block before
            // `height`: up to DIFFICULTY_ADJUSTMENT_INTERVAL blocks.
            let window_end = idx;
            let start_idx = window_end.saturating_sub(DIFFICULTY_ADJUSTMENT_INTERVAL as usize);
            let start_time = self.blocks[start_idx].time;
            let end_time = self.blocks[window_end - 1].time;
            let actual = end_time.saturating_sub(start_time).max(1);
            let target = DIFFICULTY_ADJUSTMENT_INTERVAL * TARGET_BLOCK_TIME_SECS;
            let last_diff = self.blocks[window_end - 1].difficulty;
            let mut new_diff = (last_diff as u128)
                .saturating_mul(target as u128)
                .saturating_div(actual as u128) as u64;
            let max_diff = last_diff.saturating_mul(4);
            let min_diff = last_diff.saturating_div(4).max(1);
            if new_diff > max_diff {
                new_diff = max_diff;
            }
            if new_diff < min_diff {
                new_diff = min_diff;
            }
            return new_diff;
        }
        if let Some(b) = self.blocks[..idx.min(self.blocks.len())].iter().next_back() {
            return b.difficulty;
        }
        1
    }

    /// The difficulty the next block must declare: the retargeted value
    /// for the next height.
    pub fn next_difficulty(&self) -> u64 {
        self.difficulty_for_height(self.tip_height() + 1)
    }
}
