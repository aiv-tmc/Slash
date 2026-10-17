//! The fee-claim sweep.
//!
//! Miners claim accumulated fee-vault cells in their blocks. Every claim
//! must come from the vault, must be unlocked at the executing height,
//! must pay the block miner exactly, and an empty claim set is a valid
//! no-op — a block may carry no fee claims at all. All amount arithmetic
//! is checked: a malformed claim width fails the sweep instead of
//! wrapping.

use super::params::FEE_VAULT;
use super::state::State;

impl State {
    /// Claim fee-vault outputs for the miner of the block. The empty
    /// claim set is valid and leaves the vault untouched. Every claim
    /// must pay the block miner exactly, and each claimed range must be
    /// unlocked and vault-owned at the executing height.
    pub fn claim_fees(&mut self, miner: [u8; 32], claims: &[Output], height: u64) -> bool {
        if claims.is_empty() {
            return true;
        }
        if claims.iter().any(|c| c.to != miner) {
            return false;
        }
        for claim in claims {
            // A malformed range width, or a zero-width range, is not a
            // claim and fails the sweep instead of wrapping into a bogus
            // balance credit.
            let Some(width) = claim.end.checked_sub(claim.start) else {
                return false;
            };
            if width == 0 {
                return false;
            }
            if !self.remove_for_spend(FEE_VAULT, claim.start, claim.end, height) {
                return false;
            }
            self.get_page_mut(page_id(claim.start)).insert_output(
                page_offset(claim.start),
                page_offset(claim.start) + width,
                claim.to,
            );
            // A claim paying the fee vault itself returns the cells to
            // the vault: the ownership map is unchanged by the round
            // trip, and the balance cache records the sweep debit only.
            if claim.to != FEE_VAULT {
                // The cache credit is bounded by the number of cells N, so
                // the addition cannot overflow in any reachable state; the
                // checked form keeps the invariant local to the line that
                // relies on it.
                let Some(credited) = self
                    .balance_cache
                    .get(&claim.to)
                    .copied()
                    .unwrap_or(0)
                    .checked_add(width)
                else {
                    return false;
                };
                self.balance_cache.insert(claim.to, credited);
            }
        }
        true
    }
}

use super::page::Output;
use super::params::{page_id, page_offset};
