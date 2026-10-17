//! Mempool admission benchmark: ten thousand structurally distinct, fully
//! valid transactions validated against the same chain state.

use super::wire_outputs;
use criterion::{black_box, Criterion};

/// Benchmark mempool admission throughput: ten thousand structurally
/// distinct, fully valid transactions validated against the same chain
/// state. The transactions share one input range (mempool admission checks
/// ownership against the tip state and does not track in-mempool double
/// spends; that bookkeeping lives in the mempool itself), while each
/// transaction carries a unique recipient and signature so the measured
/// cost covers hashing, signature verification, ownership walks, and the
/// structural checks of tx_structure_valid.
pub fn bench_mempool_validation_10k(c: &mut Criterion) {
    let mut chain = slash::chain::Chain::genesis();
    // The mempool admission path verifies the signature against tx.from, so
    // the signer key must own the mined input range.
    let (sk, owner) = slash::crypto::generate_keypair();
    for i in 0..60 {
        chain.state.mine(i, owner, 0);
    }

    let inputs = vec![(0u64, 60u64)];
    let mut txs = Vec::with_capacity(10_000);
    for i in 0..10_000u64 {
        // A unique recipient per transaction keeps the signature hash and
        // the txid distinct across the whole corpus.
        let recipient = [((i >> 8) as u8).wrapping_add(1); 32];
        let outputs = vec![
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
        let hash = slash::chain::Chain::tx_signature_hash(
            &owner,
            &inputs,
            &outputs,
            chain.chain_id.as_bytes(),
            0,
            &None,
        );
        let sig = slash::crypto::sign(&sk, &hash);
        txs.push(slash::chain::Tx {
            from: owner,
            inputs: inputs.clone(),
            outputs: wire_outputs(&outputs),
            sig,
            scheme: 0,
            memo: None,
        });
    }

    // Admission succeeds for every generated transaction; assert once so a
    // regression in the fixture itself fails loudly instead of benchmarking
    // ten thousand silent rejections.
    assert!(chain.validate_tx(&txs[0]));

    c.bench_function("mempool_validate_tx_10k", |b| {
        b.iter(|| {
            for tx in &txs {
                black_box(chain.validate_tx(tx));
            }
        });
    });
}
