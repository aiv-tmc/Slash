//! The orphan pool: blocks whose parents are unknown.
//!
//! Orphans park here until the tip advances enough for their parent to
//! become known; every main-chain extension triggers one retry pass. The
//! pool is bounded by ingress, and each pass adopts at most
//! `MAX_ORPHAN_ADOPTION` blocks so a large pool cannot monopolize the
//! event loop.

use super::chain::Chain;
use super::params::MAX_ORPHAN_ADOPTION;

impl Chain {
    /// Retry parked orphan blocks whose parents are now known. Each pass
    /// adopts at most MAX_ORPHAN_ADOPTION blocks; processed orphans leave
    /// the pool regardless of outcome, so a permanently invalid block
    /// cannot retry forever.
    pub(crate) fn process_orphans(&mut self) -> usize {
        let mut adopted = 0usize;
        let keys: Vec<[u8; 32]> = self.orphan_blocks.keys().copied().collect();
        for key in keys {
            if adopted >= MAX_ORPHAN_ADOPTION {
                break;
            }
            let Some(block) = self.orphan_blocks.remove(&key) else {
                continue;
            };
            if self.process_block(block).is_ok() {
                adopted += 1;
            }
        }
        adopted
    }
}
