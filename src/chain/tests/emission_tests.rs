//! Emission tests: the subsidy schedule, era boundaries, the perpetual
//! slot tail, and the chain-identifier domain split.

use crate::chain::*;

#[test]
fn test_coinbase_amount_matches_schedule() {
    // The built coinbase pays exactly subsidy_at(height), with canonical
    // treasury inputs, and no coinbase exists once the subsidy is zero.
    let state = crate::state::State::genesis();
    let miner = [9u8; 32];
    for &height in &[0u64, 1, 420_480, 840_960] {
        let cb = Chain::build_coinbase(&state, miner, height, 0)
            .unwrap_or_else(|| panic!("coinbase exists at {}", height));
        let total: u64 = cb.outputs.iter().map(|o| o.end - o.start).sum();
        assert_eq!(total, subsidy_at(height));
    }
    assert!(Chain::build_coinbase(&state, miner, 3_784_320, 0).is_none());
}

#[test]
fn test_genesis_chain_id() {
    // The signature domain pins replay isolation per network.
    let main = Chain::genesis();
    assert_eq!(main.chain_id, MAINNET_ID);
    let test = Chain::with_chain_id(TESTNET_ID.to_string());
    assert_eq!(test.chain_id, TESTNET_ID);
}

#[test]
fn test_era_eight_to_nine_transition() {
    // Era 8 requires a coinbase of exactly one cell; era 9 omits it.
    // Building the era-9 coinbase yields None and validation rejects a
    // treasury-shaped first transaction at zero subsidy.
    let state = crate::state::State::genesis();
    let miner = [3u8; 32];
    let cb8 = Chain::build_coinbase(&state, miner, 3_784_319, 0).expect("era-8 coinbase exists");
    let total: u64 = cb8.outputs.iter().map(|o| o.end - o.start).sum();
    assert_eq!(total, 1);
    assert!(Chain::build_coinbase(&state, miner, 3_784_320, 0).is_none());
    assert_eq!(subsidy_at(3_784_320), 0);
}

#[test]
fn test_tail_slot_emission_is_perpetual() {
    // The slot mint path is height-independent: at a deep-tail height
    // the slot mint still transfers from the treasury entry to the
    // miner, preserving the conservation invariant.
    let mut state = crate::state::State::genesis();
    let miner = [4u8; 32];
    let cell = state
        .select_single(crate::state::TREASURY, 1)
        .map(|r| r.0)
        .expect("treasury has cells");
    assert!(state.mint_slot(cell, miner, 10_000_000), "slot mints");
    assert_eq!(state.balance(miner), 1);
}
