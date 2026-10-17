//! src/state/locks.rs — lock maintenance.
//!
//! Expired lock registrations are dead weight in the maps: they no
//! longer bind spending, no longer count against the global lock cap,
//! and no longer carry governance weight. Pruning retires them exactly
//! when the executing height reaches their expiry, never earlier, and
//! always removes the expiry and the creation entry together so the two
//! maps stay one-to-one mirrors of each other.

use super::state::State;

impl State {
    /// Retire every lock whose expiry is at or below `height`. The two
    /// lock maps carry one entry per locked cell, so a retired cell
    /// leaves both maps in the same pass; a cell present in only one map
    /// never happens through the transfer engine and is removed here
    /// just the same, keeping the maps consistent for every reader.
    pub fn prune_locks(&mut self, height: u64) {
        let expired: Vec<u64> = self
            .locks
            .iter()
            .filter(|(_, &expiry)| expiry <= height)
            .map(|(&cell, _)| cell)
            .collect();
        for cell in expired {
            self.locks.remove(&cell);
            self.lock_created.remove(&cell);
        }
    }
}
