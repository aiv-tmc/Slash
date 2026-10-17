//! The PoW slot mint and the single-page mining rules: the backfill
//! primitive touches exactly one page, the balance cache tracks bulk
//! mints, the slot mint refuses user-owned cells, and the test/simulation
//! backfill refuses to move cells that already belong to a user.

use super::*;

#[test]
fn mine_changes_only_one_page() {
    let mut state = State::genesis();
    state.mine(1337, [1u8; 32], 0);
    assert_eq!(state.pages.len(), 1);
    assert_eq!(state.balance([1u8; 32]), 1);
    assert_eq!(state.balance(TREASURY), N - 1);
}

#[test]
fn balance_cache_correct_after_1000_ops() {
    let mut state = State::genesis();
    let owner = [1u8; 32];
    for i in 0..1000 {
        state.mine(i, owner, 0);
    }
    assert_eq!(state.balance(owner), 1000);
    assert_eq!(state.balance(TREASURY), N - 1000);
}

#[test]
fn mint_slot_refuses_non_treasury_cells() {
    // The consensus PoW slot must never move a cell owned by a user.
    let mut state = State::genesis();
    let owner = [1u8; 32];
    for i in 50..100 {
        state.mine(i, owner, 0);
    }
    let before = state.clone();
    assert!(!state.mint_slot(60, [2u8; 32], 0));
    assert_eq!(state.pages, before.pages);
    // Treasury-owned cells mint fine.
    assert!(state.mint_slot(200, [2u8; 32], 0));
    assert_eq!(state.balance([2u8; 32]), 1);
}

#[test]
fn mine_refuses_user_owned_cells() {
    // The backfill primitive must never move a cell that already belongs
    // to a user, even though it silently skips instead of reporting an
    // error. Consensus uses mint_slot(); this test pins the identical
    // ownership rule for the test and simulation path.
    let mut state = State::genesis();
    let owner = [1u8; 32];
    for i in 50..100 {
        state.mine(i, owner, 0);
    }
    let before = state.clone();
    // Cell 60 belongs to `owner`; claiming it for someone else is a no-op.
    state.mine(60, [2u8; 32], 0);
    assert_eq!(state.pages, before.pages);
    assert_eq!(state.balance(owner), 50);
    assert_eq!(state.balance([2u8; 32]), 0);
    // Unissued cells still seed normally.
    state.mine(200, [2u8; 32], 0);
    assert_eq!(state.balance([2u8; 32]), 1);
}
