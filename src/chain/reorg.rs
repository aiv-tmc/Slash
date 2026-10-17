//! Reorganization: swapping the main chain to a validated fork.
//!
//! Adoption rehearses the entire swap on a scratch copy of the chain —
//! rewind the state and the version-bit deployment table to the fork
//! point, disconnect the main-chain suffix into the recovery buffer, and
//! replay the fork through the ordinary application path — and only then
//! commits in one assignment, so a fork that fails at any step leaves
//! the main chain bit-identical. Restoring the deployment table together
//! with the state is what keeps soft-fork politics consistent: the
//! replayed fork re-counts signaling against the exact rule set that was
//! in force at the fork point, and activations reached only on an
//! abandoned suffix do not persist.

use super::chain::Chain;
use super::params::MAX_REORG_DEPTH;
use super::types::{Block, BlockError};
use std::collections::HashSet;

impl Chain {
    /// Reorganize the main chain to a previously validated fork. The
    /// whole operation runs on a rehearsed copy first: the main chain is
    /// never mutated until the fork has been fully replayed, which makes
    /// the reorg transactional — any failure returns an error and leaves
    /// the node on its previous main chain, exactly as before the call.
    pub(crate) fn reorg_to_fork(&mut self, fork: &[Block]) -> Result<(), BlockError> {
        let fork_point = fork
            .first()
            .map(|b| b.height.saturating_sub(1))
            .ok_or(BlockError::InvalidHeight)?;
        if self.tip_height().saturating_sub(fork_point) > MAX_REORG_DEPTH {
            return Err(BlockError::CannotReorgBeyondHistory);
        }
        let mut replay = self.clone();
        // Restore the state at the fork point. Both the state and the
        // deployment table are restored as one pair: they were recorded
        // as one pair, and the replay below re-derives both from the
        // fork-point snapshot.
        replay.state = self
            .state_history
            .get(&fork_point)
            .cloned()
            .ok_or(BlockError::CannotReorgBeyondHistory)?;
        replay.version_bits.deployments = self
            .deployments_history
            .get(&fork_point)
            .cloned()
            .ok_or(BlockError::CannotReorgBeyondHistory)?;
        // Disconnect the main suffix into the recovery buffer, oldest
        // first, so the node can return its transactions to the mempool.
        // History entries above the fork point drop from both histories:
        // the replay re-records them as the fork applies. A suffix that
        // cannot be popped means the chain is corrupted, and the
        // rehearsal aborts without touching the real chain.
        let mut popped = Vec::new();
        while replay.tip_height() > fork_point {
            let Some(b) = replay.blocks.pop() else {
                return Err(BlockError::CannotReorgBeyondHistory);
            };
            replay.state_history.remove(&b.height);
            replay.deployments_history.remove(&b.height);
            popped.push(b);
        }
        popped.reverse();
        replay.reorg_disconnected = popped;
        // Replay the fork through the ordinary apply path on the
        // rehearsal copy; a failure here aborts the whole reorg with the
        // main chain untouched.
        for b in fork {
            replay.apply(b.clone())?;
        }
        // Fork blocks that are now main-chain history leave the pool.
        let adopted: HashSet<[u8; 32]> = fork.iter().map(|b| replay.block_hash(b)).collect();
        replay.side_forks.retain(|h, _| !adopted.contains(h));
        // Every step succeeded: commit the rehearsed chain in one swap.
        *self = replay;
        Ok(())
    }
}

/// Compare a validated fork against the main chain: the fork wins when
/// the sum of difficulties over its blocks exceeds the main chain's work
/// over the same height range. The sums use 128-bit accumulators so long
/// chains cannot overflow.
pub(crate) fn fork_heavier_than_main(fork: &[Block], main: &[Block]) -> bool {
    let Some(first) = fork.first() else {
        return false;
    };
    let fork_work: u128 = fork.iter().map(|b| b.difficulty as u128).sum();
    let main_work: u128 = main
        .iter()
        .filter(|b| b.height >= first.height)
        .map(|b| b.difficulty as u128)
        .sum();
    fork_work > main_work
}
