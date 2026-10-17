//! Ownership, overspend, and cross-page balance rules: a live lock blocks
//! the covered spend, declared inputs beyond the owned balance fail
//! conservation even with a valid signature and a paid fee, and a
//! transaction spending ranges on both sides of a page boundary must
//! balance each page independently.

use super::*;

#[test]
fn transfer_updates_balances() {
    let mut state = State::genesis();
    // The signature is verified against the owner address, so the owner
    // must be the public key matching the signing secret.
    let (sk, pk) = crate::crypto::generate_keypair();
    let owner = pk;
    let recipient = [2u8; 32];
    for i in 100..150 {
        state.mine(i, owner, 0);
    }
    let outputs = vec![
        Output {
            start: 100,
            end: 125,
            to: recipient,
            lock: None,
        },
        Output {
            start: 125,
            end: 149,
            to: owner,
            lock: None,
        },
        Output {
            start: 149,
            end: 150,
            to: FEE_VAULT,
            lock: None,
        },
    ];
    let hash = crate::chain::Chain::tx_signature_hash(
        &owner,
        &[(100, 150)],
        &outputs,
        crate::chain::MAINNET_ID.as_bytes(),
        0,
        &None,
    );
    let sig = crate::crypto::sign(&sk, &hash);
    assert!(state.tx(
        owner,
        &[(100, 150)],
        &outputs,
        &sig,
        0,
        crate::chain::MAINNET_ID.as_bytes(),
        0,
        &None
    ));
    assert_eq!(state.balance(recipient), 25);
    assert_eq!(state.balance(owner), 24);
    assert_eq!(state.balance(FEE_VAULT), 1);
}

#[test]
fn tx_rejects_bad_signature() {
    let mut state = State::genesis();
    let owner = [1u8; 32];
    // Mine 50 contiguous cells so the transaction is otherwise valid.
    for i in 50..100 {
        state.mine(i, owner, 0);
    }
    let outputs = vec![
        Output {
            start: 50,
            end: 99,
            to: [2u8; 32],
            lock: None,
        },
        Output {
            start: 99,
            end: 100,
            to: FEE_VAULT,
            lock: None,
        },
    ];
    let before = state.clone();
    assert!(!state.tx(
        owner,
        &[(50, 100)],
        &outputs,
        &[0u8; 64],
        0,
        crate::chain::MAINNET_ID.as_bytes(),
        0,
        &None
    ));
    assert_eq!(state.pages, before.pages);
}

#[test]
fn multi_input_cross_page() {
    let mut state = State::genesis();
    // The signature is verified against the owner address, so the owner
    // must be the public key matching the signing secret.
    let (sk, pk) = crate::crypto::generate_keypair();
    let owner = pk;
    let recipient = [2u8; 32];
    // Mine 25 cells near the end of page 0 and 25 at the start of page 1.
    let cell0 = PAGE_SIZE - 25;
    let cell1 = PAGE_SIZE;
    for i in 0..25 {
        state.mine(cell0 + i, owner, 0);
        state.mine(cell1 + i, owner, 0);
    }
    // Spend both ranges in one transaction, paying a one-cell fee from
    // the page-0 portion so that each page still balances independently.
    let inputs = vec![(cell0, cell0 + 25), (cell1, cell1 + 25)];
    let outputs = vec![
        Output {
            start: cell0,
            end: cell0 + 24,
            to: FEE_VAULT,
            lock: None,
        },
        Output {
            start: cell0 + 24,
            end: cell0 + 25,
            to: recipient,
            lock: None,
        },
        Output {
            start: cell1,
            end: cell1 + 25,
            to: owner,
            lock: None,
        },
    ];
    let hash = crate::chain::Chain::tx_signature_hash(
        &owner,
        &inputs,
        &outputs,
        crate::chain::MAINNET_ID.as_bytes(),
        0,
        &None,
    );
    let sig = crate::crypto::sign(&sk, &hash);
    assert!(state.tx(
        owner,
        &inputs,
        &outputs,
        &sig,
        0,
        crate::chain::MAINNET_ID.as_bytes(),
        0,
        &None
    ));
    assert_eq!(state.balance(recipient), 1);
    assert_eq!(state.balance(owner), 25);
    assert_eq!(state.balance(FEE_VAULT), 24);
}

#[test]
fn lock_prevents_spending() {
    let mut state = State::genesis();
    let (sk, pk) = crate::crypto::generate_keypair();
    let recipient = [2u8; 32];
    for i in 0..200 {
        state.mine(i, pk, 0);
    }
    // Lock cells 0..100 until height 10, paying cell 199 as the fee.
    let outputs = vec![
        Output {
            start: 0,
            end: 100,
            to: pk,
            lock: Some(10),
        },
        Output {
            start: 100,
            end: 199,
            to: recipient,
            lock: None,
        },
        Output {
            start: 199,
            end: 200,
            to: FEE_VAULT,
            lock: None,
        },
    ];
    let hash = crate::chain::Chain::tx_signature_hash(
        &pk,
        &[(0, 200)],
        &outputs,
        crate::chain::MAINNET_ID.as_bytes(),
        0,
        &None,
    );
    let sig = crate::crypto::sign(&sk, &hash);
    assert!(state.tx(
        pk,
        &[(0, 200)],
        &outputs,
        &sig,
        0,
        crate::chain::MAINNET_ID.as_bytes(),
        0,
        &None
    ));
    // Spending the locked range at height 5 must fail.
    let outputs2 = vec![
        Output {
            start: 0,
            end: 99,
            to: recipient,
            lock: None,
        },
        Output {
            start: 99,
            end: 100,
            to: FEE_VAULT,
            lock: None,
        },
    ];
    let hash2 = crate::chain::Chain::tx_signature_hash(
        &pk,
        &[(0, 100)],
        &outputs2,
        crate::chain::MAINNET_ID.as_bytes(),
        0,
        &None,
    );
    let sig2 = crate::crypto::sign(&sk, &hash2);
    assert!(!state.tx(
        pk,
        &[(0, 100)],
        &outputs2,
        &sig2,
        5,
        crate::chain::MAINNET_ID.as_bytes(),
        0,
        &None
    ));
    // After the lock expires the spend succeeds.
    assert!(state.tx(
        pk,
        &[(0, 100)],
        &outputs2,
        &sig2,
        10,
        crate::chain::MAINNET_ID.as_bytes(),
        0,
        &None
    ));
}

#[test]
fn tx_rejects_overspend() {
    let mut state = State::genesis();
    let (sk, pk) = crate::crypto::generate_keypair();
    for i in 0..4 {
        state.mine(i, pk, 0);
    }
    // Declared inputs of 60 cells exceed the owned 4 cells; conservation
    // must fail even though the signature is valid and the fee is paid.
    let outputs = vec![
        Output {
            start: 0,
            end: 2,
            to: [2u8; 32],
            lock: None,
        },
        Output {
            start: 2,
            end: 3,
            to: FEE_VAULT,
            lock: None,
        },
        Output {
            start: 3,
            end: 4,
            to: pk,
            lock: None,
        },
    ];
    let hash = crate::chain::Chain::tx_signature_hash(
        &pk,
        &[(0, 60)],
        &outputs,
        crate::chain::MAINNET_ID.as_bytes(),
        0,
        &None,
    );
    let sig = crate::crypto::sign(&sk, &hash);
    assert!(!state.tx(
        pk,
        &[(0, 60)],
        &outputs,
        &sig,
        0,
        crate::chain::MAINNET_ID.as_bytes(),
        0,
        &None
    ));
}
