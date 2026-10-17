//! Coinbase preparation benchmarks on a realistically dirty state: the
//! treasury selection scans the dirty page map, and `prepare_block`
//! executes the full speculative block transition on a state clone.

use criterion::{black_box, Criterion};
use std::collections::BTreeMap;

/// Benchmark coinbase preparation on a realistically dirty state: the
/// treasury selection (select_single) scans the dirty page map, and
/// prepare_block executes the full speculative block transition (slot mint,
/// coinbase mint, page Merkle roots) on a clone of the live state.
pub fn bench_coinbase_preparation(c: &mut Criterion) {
    let mut chain = slash::chain::Chain::genesis();
    let miner = [9u8; 32];

    // Dirty ten thousand cells across the lowest pages so that the
    // canonical treasury selection has real work to do instead of reading
    // the pristine shortcut.
    for i in 0..10_000u64 {
        chain.state.mine(i, miner, 0);
    }

    c.bench_function("build_coinbase", |b| {
        b.iter(|| {
            black_box(slash::chain::Chain::build_coinbase(
                &chain.state,
                miner,
                1,
                0,
            ));
        });
    });

    let coinbase = slash::chain::Chain::build_coinbase(&chain.state, miner, 1, 0).unwrap();
    let block = slash::chain::Block {
        version: 1,
        prev: chain.tip_hash(),
        time: 1,
        height: 1,
        nonce: 0,
        miner,
        mined_cell: 1_000_000,
        txs: vec![coinbase],
        fee_claims: vec![],
        difficulty: 1,
        page_roots: BTreeMap::new(),
    };

    c.bench_function("prepare_block_coinbase_only", |b| {
        b.iter(|| {
            black_box(chain.prepare_block(block.clone()));
        });
    });
}
