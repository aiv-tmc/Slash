//! Treasury signer enforcement: a missing configured signer refuses every
//! treasury transaction (the zero key is a valid curve point, so the
//! signature check alone is no barrier), unsigned and wrong-signer
//! payloads are rejected even when every structural rule holds, mints
//! debit the unissued supply, and fee claims move cells to the miner only.

use super::engine::{sign_treasury, with_signer};
use super::*;

#[test]
fn unsigned_treasury_tx_is_rejected() {
    // A treasury transaction without a valid signer signature must fail
    // even when every structural rule holds. This is the regression guard
    // for the unlimited-mint vulnerability.
    let mut state = State::genesis();
    let _sk = with_signer(&mut state);
    let outputs = vec![Output {
        start: 0,
        end: 50,
        to: [2u8; 32],
        lock: None,
    }];
    let before = state.clone();
    assert!(!state.tx(
        TREASURY,
        &[(0, 50)],
        &outputs,
        &[],
        0,
        crate::chain::MAINNET_ID.as_bytes(),
        0,
        &None
    ));
    assert_eq!(state.pages, before.pages);
}

#[test]
fn treasury_tx_with_wrong_signer_is_rejected() {
    // A signature made by any key other than the configured treasury
    // signer is invalid for a treasury transaction.
    let mut state = State::genesis();
    let _deploy_sk = with_signer(&mut state);
    let (attacker_sk, _attacker_pk) = crate::crypto::generate_keypair();
    let outputs = vec![Output {
        start: 0,
        end: 50,
        to: [2u8; 32],
        lock: None,
    }];
    let hash = crate::chain::Chain::tx_signature_hash(
        &TREASURY,
        &[(0, 50)],
        &outputs,
        crate::chain::MAINNET_ID.as_bytes(),
        0,
        &None,
    );
    let attacker_sig = crate::crypto::sign(&attacker_sk, &hash);
    assert!(!state.tx(
        TREASURY,
        &[(0, 50)],
        &outputs,
        &attacker_sig,
        0,
        crate::chain::MAINNET_ID.as_bytes(),
        0,
        &None
    ));
}

#[test]
fn treasury_tx_rejected_without_configured_signer() {
    // The genesis state ships with an all-zero treasury signer, meaning
    // that no treasury key is configured. Even a structurally perfect
    // treasury transaction must be refused in that state, because the
    // zero public key is a valid small-order curve point and signature
    // verification alone is not a sufficient barrier.
    let mut state = State::genesis();
    let (sk, _pk) = crate::crypto::generate_keypair();
    let outputs = vec![Output {
        start: 0,
        end: 50,
        to: [2u8; 32],
        lock: None,
    }];
    let hash = crate::chain::Chain::tx_signature_hash(
        &TREASURY,
        &[(0, 50)],
        &outputs,
        crate::chain::MAINNET_ID.as_bytes(),
        0,
        &None,
    );
    let sig = crate::crypto::sign(&sk, &hash);
    let before = state.clone();
    assert!(!state.tx(
        TREASURY,
        &[(0, 50)],
        &outputs,
        &sig,
        0,
        crate::chain::MAINNET_ID.as_bytes(),
        0,
        &None
    ));
    assert_eq!(state.pages, before.pages);
    // No mutation ran, so the treasury balance entry was never created:
    // the cache is filled lazily and reports zero for untouched addresses.
    assert_eq!(state.balance(TREASURY), 0);
}

#[test]
fn fee_claims_move_cells_to_miner() {
    let mut state = State::genesis();
    let sk = with_signer(&mut state);
    // Seed FEE_VAULT with 50 cells from treasury via a signed mint.
    let out = Output {
        start: 0,
        end: 50,
        to: FEE_VAULT,
        lock: None,
    };
    let sig = sign_treasury(&sk, &[(0, 50)], std::slice::from_ref(&out));
    assert!(state.tx(
        TREASURY,
        &[(0, 50)],
        &[out],
        &sig,
        0,
        crate::chain::MAINNET_ID.as_bytes(),
        0,
        &None
    ));
    // Miner claims 25 cells.
    let claims = vec![Output {
        start: 0,
        end: 25,
        to: [3u8; 32],
        lock: None,
    }];
    assert!(state.claim_fees([3u8; 32], &claims, 0));
    assert_eq!(state.balance(FEE_VAULT), 25);
    assert_eq!(state.balance([3u8; 32]), 25);
}

#[test]
fn treasury_mint_without_prior_mine_uses_unissued_supply() {
    // Regression guard for the balance-cache wraparound: a treasury mint
    // on a pristine state must debit the unissued supply N, not zero.
    // After minting the full emission cap in page-sized chunks, the
    // treasury balance is exactly N - EMISSION_CAP and the ledger-wide
    // conservation invariant holds.
    let mut state = State::genesis();
    let miner = [5u8; 32];
    let emission_cap = 417_957_120u64;
    let mut remaining = emission_cap;
    while remaining > 0 {
        let chunk = remaining.min(PAGE_SIZE);
        let range = state
            .select_single(TREASURY, chunk)
            .expect("pristine pages always fund the emission schedule");
        let out = Output {
            start: range.0,
            end: range.1,
            to: miner,
            lock: None,
        };
        assert!(state.mint(&[range], &[out], 0));
        remaining -= chunk;
    }
    assert_eq!(state.balance(miner), emission_cap);
    assert_eq!(state.balance(TREASURY), N - emission_cap);
    let supply: u64 = state.balance_cache.values().sum();
    assert_eq!(supply, N);
}
