//! Fee-claim sweep tests: the sweep routes around locked spans in global
//! coordinates on every page, drains exactly the unlocked balance, and
//! yields no claims for an empty vault.

use super::super::mempool::build_fee_claims;

#[test]
fn fee_claims_skip_locked_vault_cells() {
    // The sweep routes around a locked run inside the vault: the locked
    // span is skipped and the unlocked cells on both sides are claimed in
    // canonical order; executing the claims at the current height leaves
    // exactly the locked cells in the vault.
    let miner = [9u8; 32];
    let mut state = crate::state::State::genesis();
    for cell in 0..100 {
        state.mine(cell, crate::state::FEE_VAULT, 0);
    }
    for cell in 40..60 {
        state.locks.insert(cell, 1000);
    }

    let claims = build_fee_claims(&state, miner, 10);
    let ranges: Vec<(u64, u64)> = claims.iter().map(|o| (o.start, o.end)).collect();
    assert_eq!(ranges, vec![(0, 40), (60, 100)]);
    assert!(claims.iter().all(|o| o.to == miner));

    // The sweep executes at the current height and drains exactly the
    // unlocked balance, leaving the locked span in the vault.
    assert!(state.claim_fees(miner, &claims, 10));
    assert_eq!(state.balance(crate::state::FEE_VAULT), 20);
    assert_eq!(state.balance(miner), 80);
    for cell in 40..60 {
        assert_eq!(state.locks.get(&cell), Some(&1000));
    }

    // After expiry the previously locked cells become the next sweep.
    let later = build_fee_claims(&state, miner, 1000);
    let ranges: Vec<(u64, u64)> = later.iter().map(|o| (o.start, o.end)).collect();
    assert_eq!(ranges, vec![(40, 60)]);
}

#[test]
fn fee_claims_skip_locked_cells_on_pages_after_page_zero() {
    // Locks are keyed by global cell index. A sweep over a page after
    // page 0 must route around locked runs in global coordinates; with
    // page-local keys the locked run would be invisible, the claims
    // would include locked cells, and the block would be rejected.
    let miner = [9u8; 32];
    let mut state = crate::state::State::genesis();
    // PAGE_SIZE is a u64 constant: page 1 starts at its value in global
    // cell coordinates.
    let base = crate::state::PAGE_SIZE;
    for i in 0..100 {
        state.mine(base + i, crate::state::FEE_VAULT, 0);
    }
    for i in 40..60 {
        state.locks.insert(base + i, 1000);
    }
    let claims = build_fee_claims(&state, miner, 10);
    let ranges: Vec<(u64, u64)> = claims.iter().map(|o| (o.start, o.end)).collect();
    assert_eq!(ranges, vec![(base, base + 40), (base + 60, base + 100)]);
    assert!(claims.iter().all(|o| o.to == miner));
    assert!(state.claim_fees(miner, &claims, 10));
    assert_eq!(state.balance(crate::state::FEE_VAULT), 20);
}

#[test]
fn fee_claims_empty_vault_yields_no_claims() {
    // A pristine chain has an empty vault and therefore an empty claim
    // set; claim construction must not synthesize ranges for a zero
    // balance.
    let state = crate::state::State::genesis();
    assert!(build_fee_claims(&state, [9u8; 32], 0).is_empty());
}
