//! The coinbase emission schedule.
//!
//! The subsidy starts at 500 cells per block and halves every
//! `HALVING_INTERVAL` blocks, flooring at zero from era 9 onward. The
//! schedule is consensus: the total emitted amount across eras 0-8 is
//! 417,957,120 cells, and every node must agree on `subsidy_at` for every
//! height or coinbase validation diverges.

use super::params::{EMISSION_END_ERA, HALVING_INTERVAL, SUBSIDY_INITIAL};

/// Compute the coinbase subsidy at an absolute block height. The subsidy
/// starts at 500 cells and halves every 420,480 blocks, flooring at zero
/// from era 9 onward. The schedule is consensus: the total emitted amount
/// across eras 0-8 is 417,957,120 cells.
pub fn subsidy_at(height: u64) -> u64 {
    let era = height / HALVING_INTERVAL;
    if era >= EMISSION_END_ERA {
        0
    } else {
        SUBSIDY_INITIAL >> era
    }
}
