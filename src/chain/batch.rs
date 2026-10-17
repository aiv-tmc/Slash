//! Header-batch validation for header-first sync: linkage, median time,
//! retargeted difficulty, and the proof-of-work slot over a run of
//! headers validated before their bodies arrive. The trailing schedule
//! of the batch walks a deque so every step of a long batch costs O(1).

use super::chain::Chain;
use super::params::{DIFFICULTY_ADJUSTMENT_INTERVAL, TARGET_BLOCK_TIME_SECS};
use super::pow::verify_pow;
use super::types::{Block, BlockHeader};
use blake3::Hasher;
use std::collections::VecDeque;

impl Chain {
    /// The stored block at absolute height `h`, if the window retains it.
    /// The block vector holds every height strictly above `base_height`,
    /// so the vector index of height `h` is `h - base_height - 1`; the
    /// genesis block at `base_height == 0` is implicit and never stored.
    fn block_at_height(&self, h: u64) -> Option<&Block> {
        let idx = h.checked_sub(self.base_height)?.checked_sub(1)? as usize;
        self.blocks.get(idx)
    }

    /// Verify a batch of block headers for header-first sync: height
    /// sequence, hash linkage, median time over the trailing window, the
    /// retargeted difficulty, and the proof-of-work slot of every header.
    pub fn validate_headers_batch(&self, headers: &[BlockHeader]) -> bool {
        if headers.is_empty() {
            return true;
        }
        let first_height = headers[0].height;
        let mut expected_height = first_height;
        // The parent of the first header links the batch to the retained
        // window. Height 1 continues the implicit genesis, whose parent
        // hash is the all-zero marker (the same value `tip_hash` reports
        // for an empty chain); without the special case a from-genesis
        // sync batch would be rejected before its first header. When the
        // parent is neither the genesis marker nor a retained block the
        // linkage cannot be established and the batch is rejected instead
        // of being validated against a zeroed parent.
        let mut prev_hash = match first_height.saturating_sub(1) {
            0 => [0u8; 32],
            parent_height => match self.block_at_height(parent_height) {
                Some(parent) => self.block_hash(parent),
                None => return false,
            },
        };
        // The schedule starts from the retained window before the first
        // header so the median-time and retarget windows are full. It is a
        // deque: entries are appended at the back and evicted at the
        // front, so every step of a long batch costs O(1) regardless of
        // the window size.
        let mut schedule: VecDeque<(u64, u64)> = VecDeque::new();
        let window_start = first_height.saturating_sub(DIFFICULTY_ADJUSTMENT_INTERVAL);
        for h in window_start..first_height {
            if let Some(b) = self.block_at_height(h) {
                schedule.push_back((b.time, b.difficulty));
            }
        }
        for header in headers {
            if header.height != expected_height {
                return false;
            }
            // Recompute the header hash from its fields and compare both
            // the linkage and the proof-of-work slot against it.
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
            let hash = *h.finalize().as_bytes();
            if header.prev != prev_hash {
                return false;
            }
            // Median time over the trailing schedule. The current header
            // is deliberately excluded: the rule mirrors the per-header
            // `check_block_meta` semantics (a timestamp must exceed the
            // median of the blocks before it), and an empty or short
            // window degenerates to a median of zero, so a from-genesis
            // batch validates its early headers instead of failing against
            // its own timestamps.
            let window: Vec<u64> = schedule.iter().rev().take(11).map(|(t, _)| *t).collect();
            let mut sorted = window.clone();
            sorted.sort_unstable();
            let median = sorted.get(sorted.len() / 2).copied().unwrap_or(0);
            if header.time <= median {
                return false;
            }
            // Difficulty mirrors `difficulty_for_height` exactly: inside a
            // retarget interval the schedule's last entry is inherited;
            // at an interval boundary the windowed rescale runs over the
            // trailing schedule. Rescaling on a short early window instead
            // would demand difficulties the per-header rule never
            // produces, and honest early sync batches would be rejected.
            let expected_diff = self.batch_difficulty(&schedule, header.height);
            if header.difficulty != expected_diff {
                return false;
            }
            let cell = verify_pow(
                header.prev,
                header.time,
                header.height,
                header.miner,
                header.nonce,
                header.difficulty,
            );
            if cell != Some(header.mined_cell) {
                return false;
            }
            schedule.push_back((header.time, header.difficulty));
            // Keep the schedule bounded to the retarget window plus the
            // median-time lookahead, dropping the oldest entry.
            if schedule.len() > (DIFFICULTY_ADJUSTMENT_INTERVAL + 1) as usize {
                schedule.pop_front();
            }
            prev_hash = hash;
            expected_height += 1;
        }
        true
    }

    /// The difficulty a batch header at `height` must declare, mirroring
    /// `difficulty_for_height` over the trailing schedule: inherit the
    /// last entry inside an interval; run the windowed rescale only when
    /// `height - 1` opens a new interval and the schedule covers it.
    fn batch_difficulty(&self, schedule: &VecDeque<(u64, u64)>, height: u64) -> u64 {
        if schedule.len() < 2 {
            return schedule.back().map(|(_, d)| *d).unwrap_or(1);
        }
        if height > 1 && (height - 1).is_multiple_of(DIFFICULTY_ADJUSTMENT_INTERVAL) {
            self.retarget_from_schedule(schedule)
        } else {
            schedule.back().map(|(_, d)| *d).unwrap_or(1)
        }
    }

    /// The header-sync retarget from a (time, difficulty) schedule: the
    /// same windowed rescale and four-fold clamp as the main-chain
    /// retarget, evaluated against a schedule instead of stored blocks so
    /// headers can be validated before bodies arrive.
    fn retarget_from_schedule(&self, schedule: &VecDeque<(u64, u64)>) -> u64 {
        if schedule.len() < 2 {
            return schedule.back().map(|(_, d)| *d).unwrap_or(1);
        }
        // The window is the newest retarget-interval entries in
        // newest-first order: the first element is the most recent
        // header, the last element is the oldest header of the window.
        let window: Vec<(u64, u64)> = schedule
            .iter()
            .rev()
            .take(DIFFICULTY_ADJUSTMENT_INTERVAL as usize)
            .copied()
            .collect();
        let start_time = window.last().map(|(t, _)| *t).unwrap_or(0);
        let end_time = window.first().map(|(t, _)| *t).unwrap_or(0);
        let actual = end_time.saturating_sub(start_time).max(1);
        let target = DIFFICULTY_ADJUSTMENT_INTERVAL * TARGET_BLOCK_TIME_SECS;
        let last_diff = window.first().map(|(_, d)| *d).unwrap_or(1);
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
        new_diff
    }
}
