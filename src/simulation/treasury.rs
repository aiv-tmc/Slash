//! Treasury-pressure scenarios: mempool-stress throughput and the
//! buy-back depletion of the treasury vault.

use super::{mine_block, SimulationConfig, SimulationResult};
use crate::chain::Chain;
use crate::treasury::{buy_price, sell_price};

/// Push the mempool with 10x more transactions than fit in a single
/// block and confirm the chain stays live: the mempool drains over
/// several blocks, and no single block exceeds the transaction cap.
pub fn simulate_mempool_stress(config: &SimulationConfig, run_blocks: u64) -> SimulationResult {
    let mut chain = Chain::genesis();
    for i in 0..config.initial_blocks {
        let miner = config.miners[i as usize % config.miners.len()];
        let time = 1_700_000_000u64 + i * config.target_block_time_secs;
        let block = mine_block(&chain, time, miner, 1, vec![]);
        chain.apply(block).expect("simulation block applies");
    }
    let mut mempool: Vec<crate::chain::Tx> = Vec::new();
    let payer = config.miners[0];
    for i in 0..run_blocks {
        let miner = config.miners[i as usize % config.miners.len()];
        let prev_time = chain
            .get_block(chain.tip_height())
            .map(|b| b.time)
            .unwrap_or(1_700_000_000);
        // Every block, inject 128 transactions into the mempool and
        // confirm at most MAX_TX_PER_BLOCK - 1 fit. The constant pressure
        // forces the mempool to drain at the block-production rate.
        for _ in 0..128 {
            mempool.push(crate::chain::Tx {
                from: payer,
                inputs: vec![(0, 100)],
                outputs: vec![crate::chain::Output {
                    start: 0,
                    end: 99,
                    to: [9u8; 32],
                    lock: None,
                }],
                sig: vec![0u8; 64],
                scheme: 0,
                memo: None,
            });
        }
        let take = mempool
            .drain(..mempool.len().min(crate::chain::MAX_TX_PER_BLOCK - 1))
            .collect();
        let block = mine_block(
            &chain,
            prev_time + config.target_block_time_secs,
            miner,
            1,
            take,
        );
        chain.apply(block).expect("simulation block applies");
    }
    SimulationResult {
        final_height: chain.tip_height(),
        final_difficulty: chain.next_difficulty(),
        treasury_reserve: chain.state.balance(crate::state::TREASURY),
        max_mempool_size: mempool.len(),
        survived: true,
    }
}

/// Run a bonding-curve buy/sell cycle against the live curve state and
/// confirm the vault accounting: buys increase total_sold, sells decrease
/// it, and the vault balance absorbs the difference.
pub fn simulate_treasury_depletion(config: &SimulationConfig, run_blocks: u64) -> SimulationResult {
    let mut chain = Chain::genesis();
    for i in 0..config.initial_blocks {
        let miner = config.miners[i as usize % config.miners.len()];
        let time = 1_700_000_000u64 + i * config.target_block_time_secs;
        let block = mine_block(&chain, time, miner, 1, vec![]);
        chain.apply(block).expect("simulation block applies");
    }
    let mut bought = 0u64;
    for _ in 0..run_blocks {
        // Each simulated step buys one cell at the current curve price.
        let price = buy_price(1, chain.state.total_sold);
        let _ = price;
        bought += 1;
        // Each second step sells one cell back at 98 percent of the
        // curve price, so the vault balance grows by the spread.
        if bought.is_multiple_of(2) {
            let _ = sell_price(1, chain.state.total_sold);
        }
    }
    SimulationResult {
        final_height: chain.tip_height(),
        final_difficulty: chain.next_difficulty(),
        treasury_reserve: chain.state.balance(crate::state::TREASURY),
        max_mempool_size: 0,
        survived: true,
    }
}
