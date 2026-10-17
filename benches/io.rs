//! Serialization and hashing micro-benchmarks: the block wire codec and
//! the per-page Merkle root over a dense range map.

use criterion::{black_box, Criterion};
use std::collections::BTreeMap;

/// Benchmark full block serialization and deserialization via bincode.
pub fn bench_serialize_block(c: &mut Criterion) {
    let block = slash::chain::Block {
        version: 1,
        prev: [0u8; 32],
        time: 1,
        height: 1,
        nonce: 0,
        miner: [1u8; 32],
        mined_cell: 0,
        txs: vec![],
        fee_claims: vec![],
        difficulty: 1000,
        page_roots: BTreeMap::new(),
    };

    c.bench_function("serialize_block", |b| {
        b.iter(|| {
            let bytes = bincode::serialize(&block).unwrap();
            black_box(bincode::deserialize::<slash::chain::Block>(&bytes).unwrap());
        });
    });
}

/// Benchmark Merkle root computation for a page containing one hundred ranges.
pub fn bench_page_merkle_root(c: &mut Criterion) {
    let mut page = slash::state::Page {
        ranges: BTreeMap::new(),
    };
    for i in 0..100 {
        page.ranges.insert(
            i * 10,
            slash::state::R {
                e: i * 10 + 5,
                o: [1u8; 32],
            },
        );
    }

    c.bench_function("page_merkle_root_100_ranges", |b| {
        b.iter(|| {
            black_box(page.merkle_root());
        });
    });
}
