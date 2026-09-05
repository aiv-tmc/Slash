use crate::chain::{Block, Chain};
use crate::state::{Output, FEE_VAULT};
use crate::treasury::TreasuryState;
use std::collections::BTreeMap;

/// Configuration shared by all simulation scenarios.
pub struct SimulationConfig {
    /// Number of blocks to mine with normal parameters before the stress event.
    pub initial_blocks: u64,
    /// Target interval between blocks in seconds.
    pub target_block_time_secs: u64,
    /// List of miner addresses used during the simulation.
    pub miners: Vec<[u8; 32]>,
}

/// Aggregated outcome of a simulation run.
pub struct SimulationResult {
    /// Absolute height of the chain tip when the simulation ends.
    pub final_height: u64,
    /// Difficulty target computed after the stress period.
    pub final_difficulty: u64,
    /// Remaining fiat reserve in the treasury (cents).
    pub treasury_reserve: u64,
    /// Peak number of transactions held in the simulated mempool.
    pub max_mempool_size: usize,
    /// True when the network remained fully operational.
    pub survived: bool,
}

/// Simulate a sudden 90% hash-rate drop.
/// Blocks are mined with ten times the target interval during one full
/// difficulty adjustment window so that the retarget logic is stressed.
pub fn simulate_hashrate_drop(config: &SimulationConfig) -> SimulationResult {
    let mut chain = Chain::genesis();
    let miner = config.miners[0];

    // Establish baseline difficulty with normal block times.
    for h in 1..=config.initial_blocks {
        let mut b = mine_block(&chain, h, miner, 1);
        b.time = h * config.target_block_time_secs;
        let b = chain.prepare_block(b);
        chain.apply(b).unwrap();
    }

    let baseline_diff = chain.next_difficulty();

    // Simulate 90% hashrate drop: each block takes 10x the target time.
    let stress_start = config.initial_blocks + 1;
    let stress_end = config.initial_blocks + crate::chain::DIFFICULTY_ADJUSTMENT_INTERVAL;
    for h in stress_start..=stress_end {
        let mut b = mine_block(&chain, h, miner, chain.next_difficulty());
        b.time = h * config.target_block_time_secs * 10;
        let b = chain.prepare_block(b);
        chain.apply(b).unwrap();
    }

    let final_diff = chain.next_difficulty();
    let survived = final_diff <= baseline_diff.saturating_mul(4)
        && final_diff >= baseline_diff.saturating_div(4).max(1);

    SimulationResult {
        final_height: chain.blocks.len() as u64 + chain.base_height - 1,
        final_difficulty: final_diff,
        treasury_reserve: 0,
        max_mempool_size: 0,
        survived,
    }
}

/// Simulate a fee-spike event.
/// The mempool is flooded with transactions carrying progressively higher
/// fees until the capacity limit is reached and eviction begins.
pub fn simulate_fee_spike(_config: &SimulationConfig) -> SimulationResult {
    let mut chain = Chain::genesis();
    let owner = [1u8; 32];
    let mut mempool: Vec<crate::chain::Tx> = Vec::new();
    let mut mempool_spent: std::collections::BTreeMap<u64, Vec<u8>> = std::collections::BTreeMap::new();

    // Mine an initial supply so that inputs exist for the spam transactions.
    for h in 1..=50 {
        let b = mine_block(&chain, h, owner, 1);
        let b = chain.prepare_block(b);
        chain.apply(b).unwrap();
    }

    let (sk, _pk) = crate::crypto::generate_keypair();
    let mut max_mempool = 0;
    let mempool_cap: usize = 10_000;

    // Flood the mempool with transactions.
    for i in 0..15_000 {
        let cell = i % 50;
        let inputs = vec![(cell, cell + 1)];
        let fee = i as u64;
        let outputs = vec![
            Output {
                start: cell,
                end: cell + 1,
                to: [2u8; 32],
                lock: None,
            },
            Output {
                start: cell + 1,
                end: cell + 1 + fee,
                to: FEE_VAULT,
                lock: None,
            },
        ];
        let hash = crate::chain::tx_signature_hash(&owner, &inputs, &outputs, &chain.chain_id, 0);
        let sig = crate::crypto::sign(&sk, &hash);

        let tx = crate::chain::Tx {
            from: owner,
            inputs,
            outputs,
            sig,
            scheme: 0,
        };

        // Evict the lowest-fee transaction when capacity is exceeded.
        if mempool.len() >= mempool_cap {
            if let Some((idx, _)) = mempool.iter().enumerate().min_by_key(|(_, t)| {
                t.outputs
                    .iter()
                    .filter(|o| o.to == FEE_VAULT)
                    .map(|o| o.end - o.start)
                    .sum::<u64>()
            }) {
                let evicted = mempool.remove(idx);
                for (s, e) in &evicted.inputs {
                    for c in *s..*e {
                        mempool_spent.remove(&c);
                    }
                }
            }
        }

        // Reject the transaction if any input cell is already claimed.
        let mut collision = false;
        for (s, e) in &tx.inputs {
            for c in *s..*e {
                if mempool_spent.contains_key(&c) {
                    collision = true;
                    break;
                }
            }
        }

        if !collision {
            let id = blake3::hash(&tx.sig).as_bytes().to_vec();
            for (s, e) in &tx.inputs {
                for c in *s..*e {
                    mempool_spent.insert(c, id.clone());
                }
            }
            mempool.push(tx);
        }

        if mempool.len() > max_mempool {
            max_mempool = mempool.len();
        }
    }

    SimulationResult {
        final_height: chain.blocks.len() as u64 + chain.base_height - 1,
        final_difficulty: chain.next_difficulty(),
        treasury_reserve: 0,
        max_mempool_size: max_mempool,
        survived: max_mempool <= mempool_cap,
    }
}

/// Simulate sustained sell pressure on the treasury.
/// Cells are sold back until the fiat reserve is depleted or the bonding
/// curve can no longer fund the requested refund.
pub fn simulate_treasury_depletion(_config: &SimulationConfig) -> SimulationResult {
    let mut ts = TreasuryState {
        reserve_fiat: 1_000_000,
        total_sold: 1_000_000,
        total_bought_back: 0,
        vrf_public: [0u8; 32],
        signer_public: [0u8; 32],
        onion_public: [0u8; 32],
    };

    let mut total_bought_back = 0u64;
    let mut survived = true;

    while ts.reserve_fiat > 0 {
        let amount = 1000u64;
        let refund = ts.sell_price(amount);

        if refund == 0 || refund > ts.reserve_fiat {
            break;
        }

        ts.reserve_fiat -= refund;
        ts.total_bought_back += amount;
        total_bought_back += amount;
    }

    if ts.reserve_fiat > 0 && total_bought_back < 1000 {
        survived = false;
    }

    SimulationResult {
        final_height: 0,
        final_difficulty: 0,
        treasury_reserve: ts.reserve_fiat,
        max_mempool_size: 0,
        survived,
    }
}

/// Helper: mine a valid block with the given difficulty using brute-force
/// nonce search. This is deterministic enough for difficulty 1.
fn mine_block(chain: &Chain, height: u64, miner: [u8; 32], diff: u64) -> Block {
    let prev = chain.tip_hash();
    let time = chrono::Utc::now().timestamp() as u64;
    let mut nonce = 0u64;
    loop {
        // `verify_pow` is a free function in the `chain` module, not an associated function of `Chain`.
        if let Some(cell) = crate::chain::verify_pow(prev, time, height, miner, nonce, diff) {
            return Block {
                version: 1,
                prev,
                time,
                height,
                nonce,
                miner,
                mined_cell: cell,
                txs: vec![],
                fee_claims: vec![],
                difficulty: diff,
                page_roots: BTreeMap::new(),
            };
        }
        nonce += 1;
    }
}
