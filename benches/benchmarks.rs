use criterion::{black_box, criterion_group, criterion_main, Criterion};
use std::collections::BTreeMap;

/// Benchmark a small multi-input transaction that spends ten individual cells.
/// The state is cloned on every iteration so that each run starts from the
/// same pre-mined ledger and the transaction can be applied repeatedly.
fn bench_state_tx_small(c: &mut Criterion) {
    let mut state = slash::state::State::genesis();
    let owner = [1u8; 32];
    let recipient = [2u8; 32];

    // Mine ten distinct cells so that the transaction has real inputs to spend.
    for i in 0..10 {
        state.mine(i, owner, 0);
    }

    let inputs: Vec<(u64, u64)> = (0..10).map(|i| (i, i + 1)).collect();
    let outputs: Vec<slash::state::Output> = (0..10)
        .map(|i| slash::state::Output {
            start: i,
            end: i + 1,
            to: recipient,
            lock: None,
        })
        .collect();

    let chain_id = b"/slash/0.2.0";
    let hash = slash::chain::tx_signature_hash(&owner, &inputs, &outputs, chain_id, 0);
    let (sk, _pk) = slash::crypto::generate_keypair();
    let sig = slash::crypto::sign(&sk, &hash);

    c.bench_function("state_tx_10_inputs", |b| {
        b.iter(|| {
            let mut test_state = state.clone();
            black_box(test_state.tx(owner, &inputs, &outputs, &sig, 0, chain_id, 0));
        });
    });
}

/// Benchmark a cross-page multi-input transaction that spends one hundred cells
/// spanning the boundary between page 0 and page 1.
fn bench_state_tx_cross_page(c: &mut Criterion) {
    let mut state = slash::state::State::genesis();
    let owner = [1u8; 32];
    let recipient = [2u8; 32];
    let page_size = slash::state::PAGE_SIZE;

    // Mine cells near the end of page 0 and the start of page 1.
    for i in (page_size - 50)..(page_size + 50) {
        state.mine(i, owner, 0);
    }

    let inputs: Vec<(u64, u64)> = ((page_size - 50)..(page_size + 50))
        .map(|i| (i, i + 1))
        .collect();
    let outputs: Vec<slash::state::Output> = ((page_size - 50)..(page_size + 50))
        .map(|i| slash::state::Output {
            start: i,
            end: i + 1,
            to: recipient,
            lock: None,
        })
        .collect();

    let chain_id = b"/slash/0.2.0";
    let hash = slash::chain::tx_signature_hash(&owner, &inputs, &outputs, chain_id, 0);
    let (sk, _pk) = slash::crypto::generate_keypair();
    let sig = slash::crypto::sign(&sk, &hash);

    c.bench_function("state_tx_cross_page_100", |b| {
        b.iter(|| {
            let mut test_state = state.clone();
            black_box(test_state.tx(owner, &inputs, &outputs, &sig, 0, chain_id, 0));
        });
    });
}

/// Benchmark RandomX proof-of-work verification with a fixed nonce.
/// This measures the cost of the hash-and-check operation that underpins consensus.
fn bench_verify_pow(c: &mut Criterion) {
    let prev = [0u8; 32];
    let time = 1_700_000_000u64;
    let height = 100u64;
    let miner = [1u8; 32];
    let nonce = 42u64;
    let difficulty = 1000u64;

    c.bench_function("verify_pow", |b| {
        b.iter(|| {
            black_box(slash::chain::verify_pow(
                prev, time, height, miner, nonce, difficulty,
            ));
        });
    });
}

/// Benchmark full block serialization and deserialization via bincode.
fn bench_serialize_block(c: &mut Criterion) {
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
fn bench_page_merkle_root(c: &mut Criterion) {
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

criterion_group!(
    benches,
    bench_state_tx_small,
    bench_state_tx_cross_page,
    bench_verify_pow,
    bench_serialize_block,
    bench_page_merkle_root
);
criterion_main!(benches);
