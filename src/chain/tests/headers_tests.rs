//! Header-batch and signature-domain tests: header-first sync walks the
//! full trailing window, and the chain identifier pins the signature
//! domain per network.

use crate::chain::*;
use std::collections::BTreeMap;

#[test]
fn validate_headers_batch_walks_the_full_window() {
    // Fill the retained window with synthetic blocks, then validate a
    // short header batch on top. The trailing schedule exceeds the
    // window cap on the second batch header, so the eviction path runs
    // on every subsequent step and the median-time and retarget windows
    // stay full across the whole walk.
    let mut chain = Chain::genesis();
    let miner = [8u8; 32];
    let base_time = 1_700_000_000u64;
    // Push a full window of synthetic blocks directly: the batch
    // validator reads retained headers only, so no proof-of-work
    // context is allocated for the window itself.
    for h in 1..=(DIFFICULTY_ADJUSTMENT_INTERVAL + 2) {
        chain.blocks.push(Block {
            version: 1,
            prev: [0u8; 32],
            time: base_time + h * TARGET_BLOCK_TIME_SECS,
            height: h,
            nonce: 0,
            miner,
            mined_cell: 999_999_999,
            txs: Vec::new(),
            fee_claims: Vec::new(),
            difficulty: 1,
            page_roots: BTreeMap::new(),
        });
    }
    let mut batch = Vec::new();
    let mut prev_hash = chain.block_hash(chain.blocks.last().unwrap());
    let first_height = chain.tip_height() + 1;
    for h in first_height..first_height + 5 {
        let time = base_time + h * TARGET_BLOCK_TIME_SECS;
        let difficulty = chain.difficulty_for_height(h);
        // The declared slot cell must equal the proof output, so the
        // nonce is searched for this exact header at difficulty 1.
        let cell = verify_pow(prev_hash, time, h, miner, 0, difficulty)
            .expect("difficulty 1 always yields a slot cell");
        let header = BlockHeader {
            version: 1,
            prev: prev_hash,
            time,
            height: h,
            nonce: 0,
            miner,
            mined_cell: cell,
            difficulty,
            body_hash: [0u8; 32],
        };
        // The linkage of the next header commits to this header's
        // hash, recomputed exactly as the batch validator derives it.
        let mut hh = blake3::Hasher::new();
        hh.update(&header.version.to_le_bytes());
        hh.update(&header.prev);
        hh.update(&header.time.to_le_bytes());
        hh.update(&header.height.to_le_bytes());
        hh.update(&header.nonce.to_le_bytes());
        hh.update(&header.miner);
        hh.update(&header.mined_cell.to_le_bytes());
        hh.update(&header.difficulty.to_le_bytes());
        hh.update(&header.body_hash);
        prev_hash = *hh.finalize().as_bytes();
        batch.push(header);
    }
    assert!(chain.validate_headers_batch(&batch));
    // A header whose declared difficulty diverges from the retargeted
    // schedule is rejected: the batch fails closed exactly at the
    // tampered entry.
    batch[3].difficulty = 2;
    assert!(!chain.validate_headers_batch(&batch));
}

#[test]
fn chain_identifier_pins_signature_domain() {
    // The same transaction parts hash differently under the mainnet
    // and testnet identifiers, so a signature made on one network
    // never verifies on the other.
    let main = Chain::with_chain_id(MAINNET_ID.to_string());
    let test = Chain::with_chain_id(TESTNET_ID.to_string());
    let from = [1u8; 32];
    let inputs = vec![(0u64, 50u64)];
    let outputs = vec![crate::state::Output {
        start: 0,
        end: 50,
        to: [2u8; 32],
        lock: None,
    }];
    let hash_main =
        Chain::tx_signature_hash(&from, &inputs, &outputs, main.chain_id.as_bytes(), 0, &None);
    let hash_test =
        Chain::tx_signature_hash(&from, &inputs, &outputs, test.chain_id.as_bytes(), 0, &None);
    assert_ne!(hash_main, hash_test);
}
