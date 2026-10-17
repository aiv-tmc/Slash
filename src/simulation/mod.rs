//! src/simulation/mod.rs — economic stress tests: emission schedule
//! verification, treasury depletion, mempool pressure, and mining
//! behavior under adverse conditions. Each simulation returns a report
//! the caller can assert against in CI.
//!
//! Layout:
//! - `network` — hashrate-drop and fee-spike scenarios
//! - `treasury` — mempool-stress and treasury-depletion scenarios
//! - `tail` — the emission-schedule and fee-only-tail sweeps, and the
//!   shared block-mining helper

mod network;
mod tail;
mod treasury;

pub(super) use tail::mine_block;

pub use network::{simulate_fee_spike, simulate_hashrate_drop};
pub use tail::{simulate_emission_schedule, simulate_fee_only_tail, EmissionReport};
pub use treasury::{simulate_mempool_stress, simulate_treasury_depletion};

/// Configuration for an economic simulation run.
pub struct SimulationConfig {
    /// Miner identities cycling through the blocks of the scenario.
    pub miners: Vec<[u8; 32]>,
    /// Wall-clock seconds the scenario pretends one block takes; drives
    /// the synthetic timestamps.
    pub target_block_time_secs: u64,
    /// Blocks pre-mined before the scenario starts.
    pub initial_blocks: u64,
}

/// Aggregated outcome of a simulation run.
pub struct SimulationResult {
    /// Height the chain reached when the scenario ended.
    pub final_height: u64,
    /// Difficulty at the final height.
    pub final_difficulty: u64,
    /// Unissued treasury balance at the end.
    pub treasury_reserve: u64,
    /// Largest mempool size observed during the run.
    pub max_mempool_size: usize,
    /// Whether the chain remained valid for the whole scenario.
    pub survived: bool,
}
