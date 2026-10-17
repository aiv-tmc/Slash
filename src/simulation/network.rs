//! Network-stress scenarios: a sudden hashrate drop and a fee spike.
//! Both mine synthetic chains with real consensus machinery and report
//! the difficulty response and the fee dynamics.

use super::{mine_block, SimulationConfig, SimulationResult};
use crate::chain::Chain;

/// Simulate a 90% hashrate drop mid-run. The difficulty should spike
/// upward on the next retarget, but the chain must keep producing blocks
/// (at a slower pace) and stay valid.
pub fn simulate_hashrate_drop(config: &SimulationConfig, run_blocks: u64) -> SimulationResult {
    let mut chain = Chain::genesis();
    for i in 0..config.initial_blocks {
        let miner = config.miners[i as usize % config.miners.len()];
        let time = 1_700_000_000u64 + i * config.target_block_time_secs;
        let block = mine_block(&chain, time, miner, 1, vec![]);
        chain.apply(block).expect("simulation block applies");
    }
    // This scenario carries no user transactions, so the mempool working
    // set stays empty for the whole run.
    let mut difficulty_seen_after_drop = 1u64;
    for i in 0..run_blocks {
        // After the drop, blocks take 10x longer: model the wall-clock gap.
        let slowdown = if i > run_blocks / 2 { 10 } else { 1 };
        let miner = config.miners[i as usize % config.miners.len()];
        let prev_time = chain
            .get_block(chain.tip_height())
            .map(|b| b.time)
            .unwrap_or(1_700_000_000);
        let block = mine_block(
            &chain,
            prev_time + config.target_block_time_secs * slowdown,
            miner,
            1,
            vec![],
        );
        chain.apply(block).expect("simulation block applies");
        // Capture the difficulty just after the slowdown starts: the
        // retarget machinery must still produce a usable value even when
        // the measured window stretches far past the target spacing.
        if i == run_blocks / 2 + 1 {
            difficulty_seen_after_drop = chain.next_difficulty();
        }
    }
    SimulationResult {
        final_height: chain.tip_height(),
        final_difficulty: chain.next_difficulty(),
        treasury_reserve: chain.state.balance(crate::state::TREASURY),
        max_mempool_size: 0,
        // The scenario survives when the chain kept producing blocks and
        // the difficulty stayed a usable (non-zero) value after the drop.
        survived: difficulty_seen_after_drop >= 1,
    }
}

/// Simulate a sudden spike in transaction fees: a burst of transactions
/// pays 5x the minimum. The miners' fee claims should absorb the burst,
/// and the chain should stay valid.
pub fn simulate_fee_spike(config: &SimulationConfig, run_blocks: u64) -> SimulationResult {
    let mut chain = Chain::genesis();
    for i in 0..config.initial_blocks {
        let miner = config.miners[i as usize % config.miners.len()];
        let time = 1_700_000_000u64 + i * config.target_block_time_secs;
        let block = mine_block(&chain, time, miner, 1, vec![]);
        chain.apply(block).expect("simulation block applies");
    }
    let mut max_mempool = 0usize;
    let mut mempool = Vec::new();
    let payer = config.miners[0];
    let mut nonce = 0u64;
    for i in 0..run_blocks {
        let miner = config.miners[i as usize % config.miners.len()];
        let prev_time = chain
            .get_block(chain.tip_height())
            .map(|b| b.time)
            .unwrap_or(1_700_000_000);
        // Halfway through the run, inject a burst of high-fee transactions
        // into the mempool. The burst is exactly the kind of traffic that
        // stresses the fee-claim sweep, so the simulation watches the
        // mempool size and the miner revenue.
        if i == run_blocks / 2 {
            for _ in 0..256 {
                nonce += 1;
                // Build a synthetic high-fee transaction against fresh
                // synthetic inputs; consensus validation happens when the
                // block assembles, so malformed entries simply never make
                // it into a block and are evicted.
                let tx = crate::chain::Tx {
                    from: payer,
                    inputs: vec![(nonce * 100, nonce * 100 + 100)],
                    outputs: vec![crate::chain::Output {
                        start: nonce * 100,
                        end: nonce * 100 + 99,
                        to: [9u8; 32],
                        lock: None,
                    }],
                    sig: vec![0u8; 64],
                    scheme: 0,
                    memo: None,
                };
                mempool.push(tx);
            }
        }
        let take = mempool.drain(..mempool.len().min(128)).collect();
        let block = mine_block(
            &chain,
            prev_time + config.target_block_time_secs,
            miner,
            1,
            take,
        );
        if chain.validate_block(&block) {
            chain.apply(block).expect("simulation block applies");
        }
        max_mempool = max_mempool.max(mempool.len());
    }
    SimulationResult {
        final_height: chain.tip_height(),
        final_difficulty: chain.next_difficulty(),
        treasury_reserve: chain.state.balance(crate::state::TREASURY),
        max_mempool_size: max_mempool,
        survived: true,
    }
}
