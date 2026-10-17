//! Lock-map semantics: mining respects live and expired locks, the global
//! cap rejects oversized lock outputs before any mutation, and late
//! rejection stages leave no partial mutation.

use super::engine::{sign_treasury, with_signer};
use super::*;

#[test]
fn locked_cells_cannot_be_mined() {
    let mut state = State::genesis();
    // The locking transaction is signed, so the owner must be the public
    // key corresponding to the signing secret.
    let (sk, pk) = crate::crypto::generate_keypair();
    let owner = pk;
    // Mine 50 contiguous cells for the owner.
    for i in 50..100 {
        state.mine(i, owner, 0);
    }
    // Lock cells 50..99 until height 10 and pay the one-cell fee from cell 99.
    let outputs = vec![
        Output {
            start: 50,
            end: 99,
            to: owner,
            lock: Some(10),
        },
        Output {
            start: 99,
            end: 100,
            to: FEE_VAULT,
            lock: None,
        },
    ];
    let hash = crate::chain::Chain::tx_signature_hash(
        &owner,
        &[(50, 100)],
        &outputs,
        crate::chain::MAINNET_ID.as_bytes(),
        0,
        &None,
    );
    let sig = crate::crypto::sign(&sk, &hash);
    assert!(state.tx(
        owner,
        &[(50, 100)],
        &outputs,
        &sig,
        0,
        crate::chain::MAINNET_ID.as_bytes(),
        0,
        &None
    ));
    // Mining at height 5 should fail because the cells are still locked.
    state.mine(50, [2u8; 32], 5);
    assert_eq!(state.balance(owner), 49);
    // Mining at height 10 should succeed because the lock has expired.
    state.mine(50, [2u8; 32], 10);
    assert_eq!(state.balance([2u8; 32]), 1);
    // The remaining 48 locked cells plus the spent change are still owned by the original owner.
    assert_eq!(state.balance(owner), 48);
}

#[test]
fn lock_cap_is_enforced() {
    // A transfer whose lock outputs would push the global lock map past
    // MAX_LOCKED_CELLS is rejected before any mutation, on every
    // consensus path that executes apply_transfer.
    let mut state = State::genesis();
    let sk = with_signer(&mut state);
    let span = MAX_LOCKED_CELLS + 1;
    let outputs = vec![Output {
        start: 0,
        end: span,
        to: [2u8; 32],
        lock: Some(1000),
    }];
    let sig = sign_treasury(&sk, &[(0, span)], &outputs);
    let before = state.clone();
    assert!(!state.tx(
        TREASURY,
        &[(0, span)],
        &outputs,
        &sig,
        0,
        crate::chain::MAINNET_ID.as_bytes(),
        0,
        &None
    ));
    assert_eq!(state.pages, before.pages);
    assert!(state.locks.is_empty());
}

#[test]
fn rejection_leaves_no_partial_mutation() {
    // Every late rejection stage inside apply_transfer runs before any
    // mutation, and the removal loop restores the touched page
    // snapshots if a removal ever fails mid-transfer; this test pins
    // the observable half of that contract. The per-page balance check
    // and the rollback branch are unreachable on a consistent state by
    // construction (exact packing forces per-page sums to agree, and
    // the ownership walk reads the same range map the removal walks),
    // so the stages exercised here are the ones a caller can actually
    // trigger.
    let mut state = State::genesis();
    let sk = with_signer(&mut state);

    // Stage 1: an output-packing violation (a gap between outputs) is
    // rejected after ownership has been established.
    let inputs = vec![(0u64, 100u64)];
    let gapped = vec![
        Output {
            start: 0,
            end: 50,
            to: [4u8; 32],
            lock: None,
        },
        Output {
            start: 51,
            end: 100,
            to: [5u8; 32],
            lock: None,
        },
    ];
    let sig = sign_treasury(&sk, &inputs, &gapped);
    let pages_before = state.pages.clone();
    let locks_before = state.locks.clone();
    let cache_before = state.balance_cache.clone();
    assert!(!state.tx(
        TREASURY,
        &inputs,
        &gapped,
        &sig,
        0,
        crate::chain::MAINNET_ID.as_bytes(),
        0,
        &None
    ));
    assert_eq!(state.pages, pages_before);
    assert_eq!(state.locks, locks_before);
    assert_eq!(state.balance_cache, cache_before);

    // Stage 2: a lock-cap violation is rejected after packing passed.
    let mut state2 = State::genesis();
    let sk2 = with_signer(&mut state2);
    let span = MAX_LOCKED_CELLS + 1;
    let over_cap = vec![Output {
        start: 0,
        end: span,
        to: [4u8; 32],
        lock: Some(10_000),
    }];
    let sig2 = sign_treasury(&sk2, &[(0, span)], &over_cap);
    let pages_before = state2.pages.clone();
    assert!(!state2.tx(
        TREASURY,
        &[(0, span)],
        &over_cap,
        &sig2,
        0,
        crate::chain::MAINNET_ID.as_bytes(),
        0,
        &None
    ));
    assert_eq!(state2.pages, pages_before);
    assert!(state2.locks.is_empty());
}
