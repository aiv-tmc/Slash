//! Consensus parameters of the chain layer.
//!
//! Every constant in this file is part of the consensus rules: changing
//! any value is a protocol change and must go through the soft-fork or
//! era process described in the project documentation. Nothing here is a
//! tuning knob.

/// The mainnet network identifier. Part of every transaction signature
/// hash: a signature made under one identifier never verifies under the
/// other, which is the replay isolation between networks.
pub const MAINNET_ID: &str = "/slash/0.4.14";

/// The testnet network identifier, distinct from the mainnet identifier
/// for the same replay-isolation reason.
pub const TESTNET_ID: &str = "/slash/test/0.4.14";

/// Initial coinbase subsidy at genesis height (era 0), in cells.
pub const SUBSIDY_INITIAL: u64 = 500;

/// Blocks per halving era; nine eras take the subsidy to zero.
pub const HALVING_INTERVAL: u64 = 420_480;

/// First era with a zero coinbase subsidy. From this era on the miner
/// revenue is the perpetual one-cell proof-of-work slot plus fees.
pub const EMISSION_END_ERA: u64 = 9;

/// Retarget period in blocks; the same window length counts version-bit
/// signaling, so difficulty and soft-fork politics share one cadence.
pub const DIFFICULTY_ADJUSTMENT_INTERVAL: u64 = 2016;

/// Target spacing in seconds used by the retarget formula.
pub const TARGET_BLOCK_TIME_SECS: u64 = 300;

/// Serialized block size limit enforced before transaction execution.
pub const MAX_BLOCK_SIZE_BYTES: usize = 1_048_576;

/// Maximum number of transactions in one block, coinbase included.
pub const MAX_TX_PER_BLOCK: usize = 1000;

/// Maximum total number of input and output ranges in a single
/// transaction. Every range drives page-map work in the transfer engine,
/// and a dense run of one-cell ranges forces a split or merge of the
/// page range map per range, so an unbounded range count is a quadratic
/// amplification against the validating node. Real transactions carry a
/// handful of ranges; the cap leaves three orders of magnitude of headroom
/// and bounds the worst case at a small constant of map operations.
pub const MAX_RANGES_PER_TX: usize = 4096;

/// Maximum number of distinct pages a single transaction may touch.
/// Each touched page is materialized in the staging map and re-committed
/// to the live map, so a transaction fanning out across the whole ledger
/// would make every validator pay a full dirty-page walk for a single
/// payment. Real transactions touch one or two pages.
pub const MAX_PAGES_PER_TX: usize = 64;

/// Maximum depth of a chain reorganization; deeper fork attempts are
/// refused so an attacker cannot force unbounded re-validation work.
pub const MAX_REORG_DEPTH: u64 = 100;

/// Maximum retained side forks; the oldest fork is evicted past the cap.
pub const MAX_SIDE_FORKS: usize = 100;

/// Maximum number of orphan adoptions per pass through the orphan pool so
/// a large pool cannot monopolize the event loop.
pub const MAX_ORPHAN_ADOPTION: usize = 128;

/// Maximum number of blocks a pruned recovery may replay to rebuild state
/// above the retained history window.
pub const HISTORY_REBUILD_MAX_REPLAY: u64 = 10_000;

/// Checkpoint grace: blocks within this distance below the tip that match
/// an existing checkpoint hash short-circuit the expensive header checks.
pub const CHECKPOINT_TRUST_DEPTH: u64 = 100;
