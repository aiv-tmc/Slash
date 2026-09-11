//! End-to-end tests for the bonding-curve treasury:
//! buy, sell, price arithmetic, VRF-based cell selection,
//! and reserve depletion edge cases.

use slash::*;

mod common;
use common::*;

#[test]
fn test_treasury_buy_cells() {
    let _tmp = setup_test_dir("treasury_buy");
    reset_testnet();
    let mut chain = chain::Chain::genesis();
    let buyer = [1u8; 32];

    let outputs = vec![state::Output {
        start: 0,
        end: 100,
        to: buyer,
        lock: None,
    }];
    let tx = chain::Tx {
        from: state::TREASURY,
        inputs: vec![(0, 100)],
        outputs,
        sig: vec![],
        scheme: 0,
    };

    // The block is mined by the treasury so no reward cell can land inside
    // the purchased range and invalidate the buy transaction.
    let b = mine_next_block(&mut chain, state::TREASURY, vec![tx]);
    chain.apply(b).unwrap();

    assert_eq!(chain.state.balance(buyer), 100);
}

#[test]
fn test_treasury_sell_cells() {
    let _tmp = setup_test_dir("treasury_sell");
    reset_testnet();
    let mut chain = chain::Chain::genesis();
    // The seller is the public key matching the signing secret used below.
    let (sk, pk) = crypto::generate_keypair();
    let seller = pk;

    let out = state::Output {
        start: 0,
        end: 50,
        to: seller,
        lock: None,
    };
    let tx1 = chain::Tx {
        from: state::TREASURY,
        inputs: vec![(0, 50)],
        outputs: vec![out],
        sig: vec![],
        scheme: 0,
    };
    // Both blocks are mined by the treasury: mining a treasury-owned cell is
    // a no-op, so no reward cell can interfere with the traded range and the
    // treasury balance below stays exact.
    let b1 = mine_next_block(&mut chain, state::TREASURY, vec![tx1]);
    chain.apply(b1).unwrap();

    let sell_outputs = vec![state::Output {
        start: 0,
        end: 50,
        to: state::TREASURY,
        lock: None,
    }];
    let hash = chain::tx_signature_hash(&seller, &[(0, 50)], &sell_outputs, &chain.chain_id, 0);
    let sig = crypto::sign(&sk, &hash);
    let tx2 = chain::Tx {
        from: seller,
        inputs: vec![(0, 50)],
        outputs: sell_outputs,
        sig,
        scheme: 0,
    };
    let b2 = mine_next_block(&mut chain, state::TREASURY, vec![tx2]);
    chain.apply(b2).unwrap();

    // Selling the cells back exactly cancels the buy, and the treasury-mined
    // blocks moved no reward cells, so the treasury again owns the full supply.
    assert_eq!(chain.state.balance(state::TREASURY), state::N);
}

#[test]
fn test_treasury_buy_price_curve() {
    // Operate near the curve steepness parameter K so that the linear term is
    // visible despite integer division in the buy_price formula.
    let mut ts = treasury::TreasuryState {
        reserve_fiat: 1_000_000,
        total_sold: treasury::K - 50,
        total_bought_back: 0,
        vrf_public: [0u8; 32],
        signer_public: [0u8; 32],
        onion_public: [0u8; 32],
    };

    let p1 = ts.buy_price(1);
    ts.total_sold += 1;
    let p2 = ts.buy_price(1);
    assert!(p2 >= p1);

    // Bulk purchase must cost more than buying the first unit a hundred
    // times, because the per-cell price rises as total_sold grows.
    let bulk = ts.buy_price(100);
    assert!(bulk > p1 * 100);
}

#[test]
fn test_treasury_sell_price_spread() {
    let ts = treasury::TreasuryState {
        reserve_fiat: 1_000_000,
        total_sold: 1000,
        total_bought_back: 0,
        vrf_public: [0u8; 32],
        signer_public: [0u8; 32],
        onion_public: [0u8; 32],
    };

    let buy = ts.buy_price(100);
    let sell = ts.sell_price(100);
    assert!(sell < buy);
    assert_eq!(sell, (buy as u128 * 98 / 100) as u64);
}

#[test]
fn test_treasury_insufficient_reserve() {
    let ts = treasury::TreasuryState {
        reserve_fiat: 10,
        total_sold: 1000,
        total_bought_back: 0,
        vrf_public: [0u8; 32],
        signer_public: [0u8; 32],
        onion_public: [0u8; 32],
    };

    // The refund for 100 cells exceeds the entire reserve, which is exactly
    // the depletion edge case the treasury must handle gracefully.
    let refund = ts.sell_price(100);
    assert!(refund > ts.reserve_fiat);
}

#[test]
fn test_treasury_vrf_selection() {
    let _tmp = setup_test_dir("treasury_vrf");
    reset_testnet();
    let chain = chain::Chain::genesis();

    // Hashing many seeds must eventually select at least one cell that is
    // still treasury-owned, since the vast majority of the ledger is unissued.
    let mut found = 0;
    for counter in 0u64..1000 {
        let mut seed = Vec::new();
        seed.extend_from_slice(b"test_seed");
        seed.extend_from_slice(&counter.to_le_bytes());
        let (output, _proof) = vrf::prove(&[0u8; 32], &seed);
        let idx = u64::from_le_bytes(output[..8].try_into().unwrap()) % state::N;
        if let Some((_s, _e, owner)) = chain.state.get(idx) {
            if owner == state::TREASURY {
                found += 1;
            }
        }
    }
    assert!(found > 0);
}

#[test]
fn test_treasury_buy_price_zero_amount() {
    let ts = treasury::TreasuryState {
        reserve_fiat: 1_000_000,
        total_sold: 100,
        total_bought_back: 0,
        vrf_public: [0u8; 32],
        signer_public: [0u8; 32],
        onion_public: [0u8; 32],
    };

    assert_eq!(ts.buy_price(0), 0);
}

#[test]
fn test_treasury_state_save_and_load() {
    let _tmp = setup_test_dir("treasury_persist");
    reset_testnet();

    let ts = treasury::TreasuryState {
        reserve_fiat: 5000,
        total_sold: 100,
        total_bought_back: 10,
        vrf_public: [1u8; 32],
        signer_public: [2u8; 32],
        onion_public: [3u8; 32],
    };
    ts.save();

    let loaded = treasury::TreasuryState::load().unwrap();
    assert_eq!(loaded.reserve_fiat, 5000);
    assert_eq!(loaded.total_sold, 100);
    assert_eq!(loaded.total_bought_back, 10);
    assert_eq!(loaded.vrf_public, [1u8; 32]);
}
