//! Canonical selection.
//!
//! Selection answers "which exact cells does a consensus rule move": the
//! coinbase mint range, treasury pairing ranges, and fee-claim sweeps all
//! need an answer every node reproduces identically from identical state.
//! `select_single` prefers dirty-page ranges in ascending order and falls
//! back to pristine pages for the treasury, skipping any range that
//! intersects the lock map so a canonical funding range is always
//! spendable by its owner; `select_unlocked` splits owner ranges around
//! locked runs, consulting the lock map in global coordinates on every
//! page.

use super::params::{page_size, PAGE_COUNT, PAGE_SIZE, TREASURY};
use super::state::State;

impl State {
    /// The canonical single contiguous range of `amount` cells owned by
    /// `who`. Dirty pages are scanned first in ascending page order,
    /// ranges in ascending offset order; a range qualifies only when it
    /// alone covers the whole amount, so the returned range never spans
    /// foreign cells, and only when no lock intersects it, so the owner
    /// can actually spend it. For the treasury, pristine pages are the
    /// fallback: a pristine page is one full treasury range, so the first
    /// pristine page that fits the amount wins. Pristine pages carry no
    /// locks by construction, so the lock probe only runs on dirty pages.
    pub fn select_single(&self, who: [u8; 32], amount: u64) -> Option<(u64, u64)> {
        // A zero-width selection has no canonical answer: every range
        // would qualify and the first one would win by accident, so the
        // empty request is refused outright.
        if amount == 0 {
            return None;
        }
        // Dirty pages first, in id order.
        for (&id, page) in &self.pages {
            let base = id as u64 * PAGE_SIZE;
            for (&s, r) in &page.ranges {
                if r.o == who && r.e - s >= amount {
                    let start = base + s;
                    let end = start + amount;
                    // A lock inside the candidate range blocks spending,
                    // and the transfer engine rejects mints over locked
                    // spans, so a locked range is not a usable funding
                    // answer: skip it and keep scanning. The lock map is
                    // keyed by global cell index, so the probe runs in
                    // global coordinates.
                    if self.locks.range(start..end).next().is_some() {
                        continue;
                    }
                    return Some((start, end));
                }
            }
        }
        // Pristine pages: a single treasury range covers the whole page.
        // A pristine page has never been materialized, so no lock can
        // exist on any of its cells.
        if who == TREASURY {
            for id in 0..PAGE_COUNT as u16 {
                if self.pages.contains_key(&id) {
                    continue;
                }
                let size = page_size(id);
                if size >= amount {
                    return Some((id as u64 * PAGE_SIZE, id as u64 * PAGE_SIZE + amount));
                }
            }
        }
        None
    }

    /// Unlocked sweep selection for the fee-claim path: collect up to
    /// `amount` cells owned by `who`, skipping cells locked beyond
    /// `height`, splitting owner ranges around locked runs in canonical
    /// order. The lock map is keyed by global cell index, so every lookup
    /// translates page-local offsets into global coordinates first;
    /// querying local offsets against global keys would miss every lock
    /// on pages after page 0 and match unrelated page-0 locks instead.
    pub fn select_unlocked(&self, who: [u8; 32], amount: u64, height: u64) -> Vec<(u64, u64)> {
        let mut out = Vec::new();
        let mut collected = 0u64;
        for (&id, page) in &self.pages {
            if collected >= amount {
                break;
            }
            let base = id as u64 * PAGE_SIZE;
            for (&s, r) in &page.ranges {
                if collected >= amount {
                    break;
                }
                if r.o != who {
                    continue;
                }
                let mut seg_start = s;
                let seg_end = r.e;
                while seg_start < seg_end && collected < amount {
                    let g_start = base + seg_start;
                    let g_end = base + seg_end;
                    // Walk the locks of this segment in global coordinates
                    // and stop at the first lock that is still active at
                    // `height`. Expired locks never block: every cell from
                    // the segment start up to the first active lock is
                    // claimable again, so the claimable span always starts
                    // at `g_start` regardless of how many expired locks
                    // precede the active one.
                    let mut next_active: Option<u64> = None;
                    for (&locked, &until) in self.locks.range(g_start..g_end) {
                        if until > height {
                            next_active = Some(locked);
                            break;
                        }
                    }
                    match next_active {
                        Some(locked) => {
                            let take = (locked - g_start).min(amount - collected);
                            if take > 0 {
                                out.push((g_start, g_start + take));
                                collected += take;
                            }
                            if collected >= amount {
                                break;
                            }
                            // Resume strictly after the locked cell. The
                            // map stores global indices, so the next local
                            // offset is the global lock index minus the
                            // page base.
                            seg_start = locked + 1 - base;
                        }
                        None => {
                            // No active lock in the remainder of the
                            // segment: the whole span from `g_start` is
                            // claimable. Zero-width results are never
                            // pushed, so downstream claim builders never
                            // see an empty range.
                            let take = (g_end - g_start).min(amount - collected);
                            if take > 0 {
                                out.push((g_start, g_start + take));
                                collected += take;
                            }
                            seg_start = seg_end;
                        }
                    }
                }
            }
        }
        out
    }
}
