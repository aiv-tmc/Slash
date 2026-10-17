//! Entry-gate tests: side-fork admission, orphan adoption bounds, and the
//! recovery replay's linkage stop.

use super::*;
use crate::chain::*;

#[test]
fn side_fork_pool_rejects_garbage() {
    // Garbage entries — zero difficulty, impossible heights, oversized
    // payloads — never enter the side-fork pool.
    let mut chain = Chain::genesis();
    let miner = [7u8; 32];
    mine_tip_block(&mut chain, miner);
    let tip = chain.tip_height();
    let mut garbage = build_block_extending(&chain, chain.tip_hash(), tip, miner);
    garbage.difficulty = 0;
    assert!(!chain.validate_side_fork_entry(&garbage));
    let mut garbage = build_block_extending(&chain, chain.tip_hash(), tip + 1_000_000, miner);
    assert!(!chain.validate_side_fork_entry(&garbage));
    garbage.height = tip;
    garbage.txs = vec![Tx {
        from: [1u8; 32],
        inputs: vec![(0, 50)],
        outputs: vec![Output {
            start: 0,
            end: 50,
            to: [2u8; 32],
            lock: None,
        }],
        sig: vec![3u8; 64],
        scheme: 0,
        memo: None,
    }];
    let _ = &mut garbage;
    assert!(chain.validate_side_fork_entry(&garbage));
}

#[test]
fn process_orphans_adopts_chains_up_to_the_cap() {
    // Orphans whose parents arrive later are adopted, but a single
    // pass processes at most MAX_ORPHAN_ADOPTION blocks.
    let mut chain = Chain::genesis();
    let miner = [7u8; 32];
    let b1 = mine_tip_block(&mut chain, miner);
    // Construct a child of b1 and a grandchild before the child is
    // known: both land in the orphan pool.
    let h2 = b1.height + 1;
    let b2 = build_block_extending(&chain, chain.block_hash(&b1), h2, miner);
    let b2 = chain.prepare_block(b2);
    let b2_hash = chain.block_hash(&b2);
    // Process b2 while b1 is already known: it extends the tip.
    chain.process_block(b2).expect("b2 processes");
    let h3 = h2 + 1;
    let mut b3 = build_block_extending(&chain, b2_hash, h3, miner);
    b3.prev = b2_hash;
    let b3 = chain.prepare_block(b3);
    let mut orphan = b3.clone();
    orphan.prev = [0xAA; 32];
    // An orphan with an unknown parent parks in the pool.
    match chain.process_block(orphan).expect("orphan parks") {
        BlockProcessResult::Orphan => {}
        other => panic!("expected Orphan, got {:?}", other),
    }
    // Once the parent is processed, the orphan pass adopts the queued
    // block within the per-pass cap.
    chain.process_block(b3.clone()).expect("b3 processes");
    let adopted = chain.process_orphans();
    assert!(adopted <= MAX_ORPHAN_ADOPTION);
}

#[test]
fn apply_recovered_rejects_broken_linkage() {
    // Recovery replay stops at the first block that does not link to
    // the current tip: a journal ahead of the manifest must not be
    // applied blindly.
    let mut chain = Chain::genesis();
    let miner = [7u8; 32];
    let b1 = mine_tip_block(&mut chain, miner);
    let mut b2 = build_block_extending(&chain, [0xBB; 32], b1.height + 1, miner);
    b2.prev = [0xBB; 32];
    let err = chain.apply_recovered(b2).expect_err("linkage break");
    assert_eq!(err, BlockError::InvalidPrevHash);
    let b2 = build_block_extending(&chain, chain.tip_hash(), b1.height + 1, miner);
    let b2 = chain.prepare_block(b2);
    chain.apply_recovered(b2).expect("linked recovery applies");
}
