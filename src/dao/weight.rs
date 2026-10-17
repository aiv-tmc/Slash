//! Locked-weight scans and the quorum/majority outcome math. Weight is
//! the supply locked at or past the snapshot horizon by a lock that
//! already existed at the snapshot height; the outcome of a closed
//! proposal is a pure function of its snapshot denominators, so weight
//! earned or burned inside the voting window cannot move an open
//! proposal.

use super::types::{
    Proposal, ProposalStatus, DAO_EXEC_DELAY, DAO_LOCK_MIN, DAO_QUORUM_BPS, DAO_THRESHOLD_BPS,
};

/// Whether the lock on `cell` carries governance weight at a proposal
/// snapshot: the expiry must reach the weight horizon
/// (`snapshot + DAO_LOCK_MIN`) and the creation height must not be above
/// the snapshot, so a lock registered inside the voting window buys no
/// influence on the proposal already open. Both lock maps must agree on
/// the cell — the expiry and its creation height are written and removed
/// together — so a cell present in only one map is never counted.
fn weight_holds(state: &crate::state::State, cell: u64, snapshot_height: u64) -> bool {
    let Some(&until) = state.locks.get(&cell) else {
        return false;
    };
    if until < snapshot_height.saturating_add(DAO_LOCK_MIN) {
        return false;
    }
    state
        .lock_created
        .get(&cell)
        .is_some_and(|&created| created <= snapshot_height)
}

/// Voting weight of one address at a snapshot height: every cell the
/// address owns whose lock existed at the snapshot and expires at or past
/// the governance horizon (`snapshot + DAO_LOCK_MIN`) counts one weight
/// unit. Cells whose locks fall short of the horizon are operational
/// locks, not governance commitments, and carry no weight; cells locked
/// after the snapshot belong to a later governance epoch and carry no
/// weight on this proposal.
pub fn locked_weight(state: &crate::state::State, owner: [u8; 32], snapshot_height: u64) -> u64 {
    let mut weight = 0u64;
    for (pid, page) in &state.pages {
        let base = *pid as u64 * crate::state::PAGE_SIZE;
        for (&start, r) in &page.ranges {
            if r.o != owner {
                continue;
            }
            let seg_start = base + start;
            let seg_end = base + r.e;
            for cell in seg_start..seg_end {
                if weight_holds(state, cell, snapshot_height) {
                    weight = weight.saturating_add(1);
                }
            }
        }
    }
    weight
}

/// Total locked supply at a snapshot height: the quorum denominator for
/// every proposal whose snapshot height equals the argument. The scan
/// covers every materialized range cell against both lock maps, so the
/// denominator is an exact function of the state at the snapshot:
/// denominator growth inside the voting window is impossible, and no
/// voter can raise the quorum bar for anyone else's proposal by locking
/// fresh supply.
pub fn total_locked_weight(state: &crate::state::State, snapshot_height: u64) -> u64 {
    let mut weight = 0u64;
    for (pid, page) in &state.pages {
        let base = *pid as u64 * crate::state::PAGE_SIZE;
        for (&start, r) in &page.ranges {
            let seg_start = base + start;
            let seg_end = base + r.e;
            for cell in seg_start..seg_end {
                if weight_holds(state, cell, snapshot_height) {
                    weight = weight.saturating_add(1);
                }
            }
        }
    }
    weight
}

/// Resolve the terminal status of a proposal whose voting window has ended.
/// Passing requires the quorum share of the supplied total locked weight
/// and a strict majority of the cast weight; failing either condition
/// rejects the proposal. Passed proposals receive their executable height.
pub fn close_outcome(p: &Proposal, total_locked_weight: u64) -> (ProposalStatus, u64) {
    let cast = p.yes_weight.saturating_add(p.no_weight);
    let quorum_met = total_locked_weight > 0
        && cast.saturating_mul(10_000) >= total_locked_weight.saturating_mul(DAO_QUORUM_BPS);
    let majority_met = p
        .yes_weight
        .saturating_mul(10_000)
        .gt(&(cast.saturating_mul(DAO_THRESHOLD_BPS).saturating_sub(1)))
        && p.yes_weight > p.no_weight;
    if quorum_met && majority_met {
        (
            ProposalStatus::Passed,
            p.end_height.saturating_add(DAO_EXEC_DELAY),
        )
    } else {
        (ProposalStatus::Rejected, 0)
    }
}
