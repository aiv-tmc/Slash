//! State-transition benchmarks: a single-range payment and a cross-page
//! multi-input transaction, both fully consensus-valid so the measured
//! time is the cost of a real `apply_transfer`, not of a rejection.

use criterion::{black_box, Criterion};

/// Benchmark a single-input transaction that spends one contiguous range of
/// 60 cells in a real state transition. The transaction satisfies every
/// consensus rule (conservation, minimum output, mandatory fee, exact
/// packing, valid signature), so the measured time is the cost of an actual
/// apply_transfer rather than the cost of rejecting an undersized one.
pub fn bench_state_tx_small(c: &mut Criterion) {
    let mut state = slash::state::State::genesis();
    // The signer must own the spent cells: signing with an unrelated key
    // makes tx() reject at signature verification and the benchmark would
    // measure a rejection instead of a real state transition.
    let (sk, owner) = slash::crypto::generate_keypair();
    let recipient = [2u8; 32];

    // Mine one contiguous range of 60 cells owned by the sender.
    for i in 0..60 {
        state.mine(i, owner, 0);
    }

    // Outputs pack exactly over the input: a 50-cell payment, a 5-cell
    // mandatory fee (5 * 200 >= 60), and 5 cells of change.
    let inputs: Vec<(u64, u64)> = vec![(0, 60)];
    let outputs: Vec<slash::state::Output> = vec![
        slash::state::Output {
            start: 0,
            end: 50,
            to: recipient,
            lock: None,
        },
        slash::state::Output {
            start: 50,
            end: 55,
            to: slash::state::FEE_VAULT,
            lock: None,
        },
        slash::state::Output {
            start: 55,
            end: 60,
            to: owner,
            lock: None,
        },
    ];

    // Use the canonical mainnet chain identifier for replay protection.
    let chain_id = slash::chain::MAINNET_ID.as_bytes();
    let hash =
        slash::chain::Chain::tx_signature_hash(&owner, &inputs, &outputs, chain_id, 0, &None);
    let sig = slash::crypto::sign(&sk, &hash);

    c.bench_function("state_tx_60_cells", |b| {
        b.iter(|| {
            let mut test_state = state.clone();
            black_box(test_state.tx(owner, &inputs, &outputs, &sig, 0, chain_id, 0, &None));
        });
    });
}

/// Benchmark a cross-page multi-input transaction that spends one hundred cells
/// spanning the boundary between page 0 and page 1. The mandatory fee is paid
/// with the last cell so the transaction satisfies the fee rule while still
/// exercising page splitting, per-page balance, and speculative rollback.
pub fn bench_state_tx_cross_page(c: &mut Criterion) {
    let mut state = slash::state::State::genesis();
    let (sk, owner) = slash::crypto::generate_keypair();
    let recipient = [2u8; 32];
    let page_size = slash::state::PAGE_SIZE;

    // Mine cells near the end of page 0 and the start of page 1.
    for i in (page_size - 50)..(page_size + 50) {
        state.mine(i, owner, 0);
    }

    let inputs: Vec<(u64, u64)> = ((page_size - 50)..(page_size + 50))
        .map(|i| (i, i + 1))
        .collect();
    // 99 single-cell payments plus a one-cell mandatory fee output; the fee
    // satisfies fee * 200 >= total_out (200 >= 100).
    let mut outputs: Vec<slash::state::Output> = ((page_size - 50)..(page_size + 49))
        .map(|i| slash::state::Output {
            start: i,
            end: i + 1,
            to: recipient,
            lock: None,
        })
        .collect();
    outputs.push(slash::state::Output {
        start: page_size + 49,
        end: page_size + 50,
        to: slash::state::FEE_VAULT,
        lock: None,
    });

    // Use the canonical mainnet chain identifier for replay protection.
    let chain_id = slash::chain::MAINNET_ID.as_bytes();
    let hash =
        slash::chain::Chain::tx_signature_hash(&owner, &inputs, &outputs, chain_id, 0, &None);
    let sig = slash::crypto::sign(&sk, &hash);

    c.bench_function("state_tx_cross_page_100", |b| {
        b.iter(|| {
            let mut test_state = state.clone();
            black_box(test_state.tx(owner, &inputs, &outputs, &sig, 0, chain_id, 0, &None));
        });
    });
}
