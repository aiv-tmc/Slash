//! Benchmark runner: wires every measurement module into the Criterion
//! groups. The measurements live in sibling modules so each file stays
//! small enough to read whole; this entry point only converts output
//! representations and registers the benchmark functions.

mod coinbase;
mod io;
mod mempool;
mod pow_bench;
mod roots;
mod state_tx;
mod treasury;

use criterion::{criterion_group, criterion_main};

/// Convert engine-level outputs into wire-level outputs for a `Tx`
/// literal. The two output types carry the identical four fields; the
/// conversion is a pure field copy.
pub fn wire_outputs(engine: &[slash::state::Output]) -> Vec<slash::chain::Output> {
    engine
        .iter()
        .map(|o| slash::chain::Output {
            start: o.start,
            end: o.end,
            to: o.to,
            lock: o.lock,
        })
        .collect()
}

/// Convert wire-level outputs into engine-level outputs for direct
/// `State` calls (`tx`, `mint`). The conversion is a pure field copy.
pub fn engine_outputs(wire: &[slash::chain::Output]) -> Vec<slash::state::Output> {
    wire.iter()
        .map(|o| slash::state::Output {
            start: o.start,
            end: o.end,
            to: o.to,
            lock: o.lock,
        })
        .collect()
}

criterion_group!(
    benches,
    state_tx::bench_state_tx_small,
    state_tx::bench_state_tx_cross_page,
    pow_bench::bench_verify_pow_cache_hit,
    pow_bench::bench_verify_pow_cache_miss,
    io::bench_serialize_block,
    io::bench_page_merkle_root,
    coinbase::bench_coinbase_preparation,
    treasury::bench_treasury_pairing_scan,
    roots::bench_global_root,
    roots::bench_global_root_incremental,
    mempool::bench_mempool_validation_10k
);
criterion_main!(benches);
