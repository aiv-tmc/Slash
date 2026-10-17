//! Unit tests of the network layer.
//!
//! The suite pins the wire-independent policy pieces: mempool assembly
//! order and treasury-payload admission (this module), fee-claim sweep
//! routing around locks in global coordinates (`fees`), subnet masking,
//! ban escalation, the onion replay cache semantics and persistence, and
//! the peer-id key extraction the onion attestation relies on (`net`).
//! Tests run without a swarm or network I/O.

mod fees;
mod net;

use super::mempool::{assemble_block_txs, tx_id};
use std::collections::HashMap;

/// Build a minimal ordinary transaction with the given signature bytes so
/// tests can construct mempool fixtures without a wallet.
fn dummy_tx(from: [u8; 32], sig: u8) -> crate::chain::Tx {
    crate::chain::Tx {
        from,
        inputs: vec![(0, 50)],
        outputs: vec![
            crate::chain::Output {
                start: 0,
                end: 49,
                to: [2u8; 32],
                lock: None,
            },
            crate::chain::Output {
                start: 49,
                end: 50,
                to: crate::state::TREASURY_VAULT,
                lock: None,
            },
        ],
        sig: vec![sig; 64],
        scheme: 0,
        memo: None,
    }
}

/// Build a treasury payload paying a third party with the given signature
/// bytes; ownership classification only reads inputs and outputs.
fn treasury_tx(sig: u8) -> crate::chain::Tx {
    crate::chain::Tx {
        from: crate::state::TREASURY,
        inputs: vec![(0, 50)],
        outputs: vec![crate::chain::Output {
            start: 0,
            end: 50,
            to: [3u8; 32],
            lock: None,
        }],
        sig: vec![sig; 64],
        scheme: 0,
        memo: None,
    }
}

#[test]
fn assemble_without_chain_pairing_order() {
    // Without a chain the assembler orders each payload right after its
    // funding payment via the pairing table, then appends every
    // unpaired transaction in admission order. Consensus execution sees
    // each funding payment before its payload.
    let mempool = vec![
        dummy_tx([1u8; 32], 1),
        treasury_tx(9),
        dummy_tx([2u8; 32], 2),
        treasury_tx(10),
    ];
    let mut pairs: HashMap<Vec<u8>, (Vec<u8>, usize)> = HashMap::new();
    pairs.insert(tx_id(&mempool[1]), (tx_id(&mempool[0]), 0));
    pairs.insert(tx_id(&mempool[3]), (tx_id(&mempool[2]), 2));

    let txs = assemble_block_txs(&None, &mempool, 0, &pairs);
    assert_eq!(txs.len(), 4);
    assert_eq!(tx_id(&txs[0]), tx_id(&mempool[0]));
    assert_eq!(tx_id(&txs[1]), tx_id(&mempool[1]));
    assert_eq!(tx_id(&txs[2]), tx_id(&mempool[2]));
    assert_eq!(tx_id(&txs[3]), tx_id(&mempool[3]));
}

#[test]
fn admit_treasury_payload_pairs_with_pending_sell() {
    // A payout payload is admitted only when it carries a valid treasury
    // signer signature and an earlier ordinary transaction returns
    // exactly the sold amount to the treasury at the current curve price;
    // the payment is consumed so a second payout cannot reuse it. The
    // seller and the vault are funded from disjoint ranges: consensus
    // classifies a treasury payload by the ownership of its inputs, so
    // the sell spends seller-owned cells while the payout reads vault
    // funds.
    let mut chain = crate::chain::Chain::genesis();
    // Configure a treasury signer and sign every payload with its key:
    // admission authenticates the payload against the configured signer
    // before any pairing logic runs.
    let (treasury_sk, treasury_pk) = crate::crypto::generate_keypair();
    chain.state.treasury_signer = treasury_pk;
    for i in 0..50 {
        chain.state.mine(100 + i, [1u8; 32], 0);
    }
    for i in 0..48 {
        chain.state.mine(i, crate::state::TREASURY_VAULT, 0);
    }
    let mut pairs: HashMap<Vec<u8>, (Vec<u8>, usize)> = HashMap::new();
    let mut running_total = 0u64;
    // sell_price(49, 0) = floor(49 * 1 * 0.98) = 48.
    let sell = crate::chain::Tx {
        from: [1u8; 32],
        inputs: vec![(100, 150)],
        outputs: vec![
            crate::chain::Output {
                start: 100,
                end: 149,
                to: crate::state::TREASURY,
                lock: None,
            },
            crate::chain::Output {
                start: 149,
                end: 150,
                to: crate::state::FEE_VAULT,
                lock: None,
            },
        ],
        sig: vec![1u8; 64],
        scheme: 0,
        memo: None,
    };
    let mempool = vec![sell];
    // Sign the payout exactly like the consensus engine hashes it:
    // sender, inputs, outputs, chain identifier, scheme, and memo.
    let payout_hash = crate::chain::Chain::tx_signature_hash(
        &crate::state::TREASURY,
        &[(0, 48)],
        &[crate::state::Output {
            start: 0,
            end: 48,
            to: [1u8; 32],
            lock: None,
        }],
        chain.chain_id.as_bytes(),
        0,
        &None,
    );
    let payout_sig = crate::crypto::sign(&treasury_sk, &payout_hash);
    let payout = crate::chain::Tx {
        from: crate::state::TREASURY,
        inputs: vec![(0, 48)],
        outputs: vec![crate::chain::Output {
            start: 0,
            end: 48,
            to: [1u8; 32],
            lock: None,
        }],
        sig: payout_sig,
        scheme: 0,
        memo: None,
    };
    assert!(super::mempool::admit_treasury_payload(
        &chain,
        &payout,
        &mempool,
        &mut pairs,
        &mut running_total
    ));
    // The payment is consumed: a second identical payout — signed, but
    // with its funding sell already spent — is refused.
    let payout2 = crate::chain::Tx {
        sig: crate::crypto::sign(&treasury_sk, &payout_hash),
        ..payout.clone()
    };
    assert!(!super::mempool::admit_treasury_payload(
        &chain,
        &payout2,
        &mempool,
        &mut pairs,
        &mut running_total
    ));
}
