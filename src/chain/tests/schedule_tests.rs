//! Difficulty-schedule tests: retarget cadence, the four-fold clamp, and
//! the zero-difficulty failure mode.

use crate::chain::*;
use std::collections::BTreeMap;

#[test]
fn test_difficulty_retargets_every_interval() {
    // The retarget only changes at interval boundaries; inside an
    // interval the difficulty is inherited from the last block, and a
    // window spaced at exactly the target interval rescales to one.
    // Headers are pushed directly because the schedule reads headers
    // only, which keeps the test free of proof-of-work context
    // allocation entirely.
    let mut chain = Chain::genesis();
    let miner = [7u8; 32];
    let base_time = 1_700_000_000u64;
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
    let tip = chain.tip_height();
    assert_eq!(chain.difficulty_for_height(tip + 1), 1);
    assert_eq!(chain.next_difficulty(), 1);
}

#[test]
fn test_verify_pow_rejects_zero_difficulty() {
    // A zero difficulty target must never validate, whatever the
    // nonce: verification fails closed before the hash is even run.
    let prev = [1u8; 32];
    let miner = [2u8; 32];
    assert!(verify_pow(prev, 100, 1, miner, 0, 0).is_none());
    assert!(verify_pow(prev, 100, 1, miner, 42, 0).is_none());
}

#[test]
fn retarget_boundary_applies_clamp() {
    // Feed the difficulty schedule a synthetic history with one-second
    // spacing: the raw retarget would explode, so the upward clamp
    // must bound the boundary difficulty at exactly four times the
    // previous value. Headers are pushed directly because the
    // schedule reads headers only.
    let mut chain = Chain::genesis();
    let miner = [3u8; 32];
    let base_time = 1_700_000_000u64;
    for h in 1..=(2 * DIFFICULTY_ADJUSTMENT_INTERVAL) {
        chain.blocks.push(Block {
            version: 1,
            prev: [0u8; 32],
            time: base_time + h,
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
    // Inside the first window the schedule keeps the initial
    // difficulty; from the first block after the boundary the
    // clamped retarget applies.
    assert_eq!(chain.difficulty_for_height(1), 1);
    assert_eq!(
        chain.difficulty_for_height(DIFFICULTY_ADJUSTMENT_INTERVAL),
        1
    );
    assert_eq!(
        chain.difficulty_for_height(DIFFICULTY_ADJUSTMENT_INTERVAL + 1),
        4
    );
}
