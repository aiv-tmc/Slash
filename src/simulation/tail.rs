//! Emission-schedule sweeps: the full era table against `subsidy_at`, and
//! the perpetual fee-only tail. Also the shared synthetic block-mining
//! helper every scenario drives.

use super::SimulationConfig;
use crate::chain::{Chain, Tx};

/// Economic report emitted by the emission-schedule simulation: the
/// per-era issued supply and the cumulative total.
pub struct EmissionReport {
    /// Issued supply at every era boundary, era 0 first.
    pub era_subsidies: Vec<u64>,
    /// Cumulative issued supply after the last computed era.
    pub total_issued: u64,
    /// Last era index included in the report.
    pub final_era: u64,
}

/// Sweep the emission schedule era by era and return the issued supply of
/// each era. The numbers must match the published emission table exactly;
/// any drift is a consensus bug.
pub fn simulate_emission_schedule() -> EmissionReport {
    let mut era_subsidies = Vec::new();
    let mut total_issued = 0u64;
    let mut era = 0u64;
    loop {
        let subsidy = crate::chain::subsidy_at(era * crate::chain::HALVING_INTERVAL);
        if subsidy == 0 {
            break;
        }
        let era_supply = subsidy * crate::chain::HALVING_INTERVAL;
        total_issued += era_supply;
        era_subsidies.push(era_supply);
        era += 1;
    }
    EmissionReport {
        era_subsidies,
        total_issued,
        final_era: era,
    }
}

/// Mine blocks past the end of the scheduled subsidy and confirm the
/// chain keeps producing: the miner revenue is the fee sum alone, and the
/// perpetual slot mint keeps the treasury flowing.
pub fn simulate_fee_only_tail(config: &SimulationConfig, run_blocks: u64) -> bool {
    let mut chain = Chain::genesis();
    // Start the simulation at the first zero-subsidy height.
    let start_height = crate::chain::EMISSION_END_ERA * crate::chain::HALVING_INTERVAL;
    for i in 0..start_height {
        let miner = config.miners[i as usize % config.miners.len()];
        let time = 1_700_000_000u64 + i * config.target_block_time_secs;
        let block = mine_block(&chain, time, miner, 1, vec![]);
        chain.apply(block).expect("simulation block applies");
    }
    for i in 0..run_blocks {
        let miner = config.miners[i as usize % config.miners.len()];
        let prev_time = chain
            .get_block(chain.tip_height())
            .map(|b| b.time)
            .unwrap_or(1_700_000_000);
        let block = mine_block(
            &chain,
            prev_time + config.target_block_time_secs,
            miner,
            1,
            vec![],
        );
        chain.apply(block).expect("simulation block applies");
    }
    chain.tip_height() == start_height + run_blocks
}

/// Mine a single block on top of the given chain at the given time with
/// the given transactions, using difficulty 1 and a synthetic coinbase.
pub fn mine_block(
    chain: &Chain,
    time: u64,
    miner: [u8; 32],
    difficulty: u64,
    txs: Vec<Tx>,
) -> crate::chain::Block {
    let height = chain.tip_height() + 1;
    let mut full_txs = Vec::new();
    if let Some(coinbase) = Chain::build_coinbase(&chain.state, miner, height, 0) {
        full_txs.push(coinbase);
    }
    full_txs.extend(txs);
    let mut block = crate::chain::Block {
        version: 1,
        prev: chain.tip_hash(),
        time,
        height,
        nonce: 0,
        miner,
        mined_cell: 0,
        txs: full_txs,
        fee_claims: Vec::new(),
        difficulty,
        page_roots: Default::default(),
    };
    // Grind the nonce until the PoW slot cell is treasury-owned. The
    // light verification context keeps the search cheap; the full mining
    // dataset is never allocated inside a simulation.
    loop {
        if let Some(cell) = crate::chain::verify_pow(
            block.prev,
            block.time,
            block.height,
            block.miner,
            block.nonce,
            block.difficulty,
        ) {
            let owned_by_treasury = chain
                .state
                .get(cell)
                .is_some_and(|(_, _, owner)| owner == crate::state::TREASURY);
            if owned_by_treasury {
                block.mined_cell = cell;
                break;
            }
        }
        block.nonce += 1;
    }
    chain.prepare_block(block)
}
