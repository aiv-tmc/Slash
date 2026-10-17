//! Proof-of-work verification benchmarks: the steady-state hash with a
//! warm light context versus a cold context that must be created per
//! distinct previous hash.

use criterion::{black_box, Criterion};

/// Benchmark RandomX proof-of-work verification with a warm context cache:
/// every iteration reuses the same prev hash, so the RandomX light context
/// is built once and the measured time is the steady-state hash-and-check
/// operation that dominates consensus verification.
pub fn bench_verify_pow_cache_hit(c: &mut Criterion) {
    let prev = [0u8; 32];
    let time = 1_700_000_000u64;
    let height = 100u64;
    let miner = [1u8; 32];
    let nonce = 42u64;
    let difficulty = 1000u64;

    c.bench_function("verify_pow_cache_hit", |b| {
        b.iter(|| {
            black_box(slash::chain::verify_pow(
                prev, time, height, miner, nonce, difficulty,
            ));
        });
    });
}

/// Benchmark RandomX proof-of-work verification with a cold context cache:
/// each iteration rotates through a pool of distinct prev hashes, so the
/// light verification context must be created from scratch before hashing.
/// Context creation is the dominant cost of a cache miss, which is why the
/// node caches contexts by prev hash with a bounded TTL.
pub fn bench_verify_pow_cache_miss(c: &mut Criterion) {
    // Sixteen distinct prev hashes force sixteen context creations; the
    // small sample size keeps the total runtime acceptable because a light
    // RandomX context costs orders of magnitude more than a single hash.
    let prevs: Vec<[u8; 32]> = (0u8..16).map(|i| [i; 32]).collect();
    let time = 1_700_000_000u64;
    let height = 100u64;
    let miner = [1u8; 32];
    let nonce = 42u64;
    let difficulty = 1000u64;

    let mut idx = 0usize;
    c.bench_function("verify_pow_cache_miss", |b| {
        b.iter(|| {
            let prev = prevs[idx % prevs.len()];
            idx += 1;
            black_box(slash::chain::verify_pow(
                prev, time, height, miner, nonce, difficulty,
            ));
        });
    });
}
