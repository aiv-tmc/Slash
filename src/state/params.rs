//! Ledger parameters of the state engine.
//!
//! Every constant in this file is part of the consensus rules: changing
//! any value is a protocol change and must go through the soft-fork or
//! era process described in the project documentation. Nothing here is a
//! tuning knob.

/// The well-known treasury address: the zero key owns every unissued cell
/// and funds the coinbase subsidy and the treasury-sale mints.
pub const TREASURY: [u8; 32] = [0u8; 32];

/// The fee vault collects the mandatory transaction fee; miners claim
/// from this address without a signature.
pub const FEE_VAULT: [u8; 32] = [1u8; 32];

/// The treasury vault collects payments for treasury purchases and funds
/// the sell payouts.
pub const TREASURY_VAULT: [u8; 32] = [2u8; 32];

/// The dev fund collects the dev-fund share of transfers and of the
/// coinbase while the rule is active.
pub const DEV_FUND: [u8; 32] = [3u8; 32];

/// The total ledger supply in cells.
pub const N: u64 = 1_000_000_000;

/// Cells per page.
pub const PAGE_SIZE: u64 = 65_536;

/// Number of pages covering the full supply (the last page is short).
pub const PAGE_COUNT: u64 = N.div_ceil(PAGE_SIZE);

/// Minimum cells per transaction.
pub const MIN: u64 = 50;

/// The fee denominator: the mandatory fee is at least total_out / 200.
pub const MIN_FEE_DENOMINATOR: u64 = 200;

/// The global bound on simultaneously locked cells.
pub const MAX_LOCKED_CELLS: u64 = 1_000_000;

/// The page id (index) of a global cell.
pub fn page_id(cell: u64) -> u16 {
    (cell / PAGE_SIZE) as u16
}

/// The page-local offset of a global cell.
pub fn page_offset(cell: u64) -> u64 {
    cell % PAGE_SIZE
}

/// The number of cells a page holds (the final page is short).
pub fn page_size(page_id: u16) -> u64 {
    let start = page_id as u64 * PAGE_SIZE;
    PAGE_SIZE.min(N.saturating_sub(start))
}

/// The number of pages in the ledger.
pub fn page_count() -> u16 {
    PAGE_COUNT as u16
}
