//! State: the paged multi-input ledger engine (PMIS).
//!
//! The global ledger of one billion cells is partitioned into pages of
//! 65,536 cells. Dirty pages are materialized as sorted range maps;
//! clean pages are reconstructed lazily as a single treasury-owned
//! range, and a page that returns to pristine form is evicted
//! automatically. On top of the page map the engine keeps the lock map,
//! the incremental balance cache, the bonding-curve counters, and the
//! governance bookkeeping, and implements every state transition
//! consensus needs: user transfers, treasury mints and vault payouts,
//! the proof-of-work slot mint, fee claims, and canonical selection.
//!
//! Layout:
//! - `params` — ledger constants and page arithmetic
//! - `page` — the range-map page, its Merkle tree, and page proofs
//! - `state` — the `State` aggregate, its constructors and accessors
//! - `minting` — the consensus mint primitives (slot, mint, payout)
//! - `locks` — lock-map maintenance
//! - `transfer` — the user/treasury transfer pipeline
//! - `fees` — the miner fee-claim sweep
//! - `selection` — canonical unlocked-range selection
//! - `tests` — unit tests (test-only)
//! - `lock_range_tests` — full-range lock registration regressions (test-only)
//!
//! This root file declares the submodules and re-exports their public
//! items so that downstream code keeps addressing everything through
//! `crate::state::…` regardless of which file physically defines it.

mod fees;
#[cfg(test)]
mod lock_range_tests;
mod locks;
mod minting;
mod page;
mod params;
mod selection;
// The `state` submodule holds the `State` aggregate itself; the inception
// lint fires on the file naming convention, which the project keeps so
// every submodule addresses its subject directly.
#[allow(clippy::module_inception)]
mod state;
#[cfg(test)]
mod tests;
mod transfer;

pub use page::*;
pub use params::*;
pub use state::*;
