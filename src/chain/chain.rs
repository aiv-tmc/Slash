//! The chain aggregate: data layout and constructors.
//!
//! `Chain` bundles everything the node needs to answer "is this block
//! next": the retained block window, the materialized tip state, the
//! bounded histories that make reorgs correct, checkpoints, the side-fork
//! and orphan pools, and the version-bit deployment table. Methods live in
//! the sibling files grouped by responsibility; this file owns the struct
//! and the genesis constructors only.

use super::params::{MAINNET_ID, TESTNET_ID};
use super::types::Block;
use super::version_bits::{Deployment, VersionBits};
use std::collections::{BTreeMap, HashMap};

/// The chain: an ordered vector of blocks above `base_height`, the
/// materialized state at the tip, a bounded history of states for reorgs,
/// checkpoints, side forks, orphans, and the version-bit deployments.
#[derive(Clone)]
pub struct Chain {
    pub blocks: Vec<Block>,
    pub base_height: u64,
    pub state: crate::state::State,
    pub state_history: HashMap<u64, crate::state::State>,
    pub deployments_history: HashMap<u64, Vec<Deployment>>,
    pub checkpoints: BTreeMap<u64, [u8; 32]>,
    pub side_forks: HashMap<[u8; 32], Block>,
    pub orphan_blocks: HashMap<[u8; 32], Block>,
    /// Blocks disconnected by the most recent reorg, oldest first, so the
    /// node can return their transactions to the mempool.
    pub reorg_disconnected: Vec<Block>,
    pub version_bits: VersionBits,
    pub chain_id: String,
    pub testnet: bool,
}

impl Chain {
    /// Build the genesis chain: the genesis block is implicit (height 0
    /// with an all-zero prev), so the block vector starts empty and the
    /// state starts from the treasury-owned genesis state. The genesis
    /// subsidy of 500 cells is credited inside the initial state.
    pub fn genesis() -> Self {
        Self::with_chain_id(MAINNET_ID.to_string())
    }

    /// Build a genesis chain with an explicit network identifier. The
    /// identifier pins the signature domain for every transaction.
    pub fn with_chain_id(chain_id: String) -> Self {
        let testnet = chain_id == TESTNET_ID;
        let mut state = crate::state::State::genesis();
        // The genesis coinbase is executed directly into the initial state
        // so that height 0 already carries the first era-0 subsidy; the
        // implicit genesis block itself never appears in the block vector.
        let miner = crate::state::TREASURY;
        let coinbase = Self::build_coinbase(&state, miner, 0, 0).expect("genesis coinbase");
        // The genesis coinbase debits the canonical treasury range through
        // the ordinary mint primitive, which packs outputs exactly over the
        // inputs. A failure here is a construction bug and panics.
        assert!(
            state.mint(
                &coinbase.inputs,
                &Self::to_state_outputs(&coinbase.outputs),
                0
            ),
            "genesis mint"
        );
        let mut state_history = HashMap::new();
        state_history.insert(0, state.clone());
        let mut chain = Self {
            blocks: Vec::new(),
            base_height: 0,
            state,
            state_history,
            // The deployment history starts empty here and receives the
            // genesis deployment table below, so a reorg back to the
            // genesis height can restore the initial rule set.
            deployments_history: HashMap::new(),
            checkpoints: BTreeMap::new(),
            side_forks: HashMap::new(),
            orphan_blocks: HashMap::new(),
            reorg_disconnected: Vec::new(),
            version_bits: VersionBits::new(),
            chain_id,
            testnet,
        };
        chain
            .deployments_history
            .insert(0, chain.version_bits.deployments.clone());
        chain
    }

    /// Build the genesis chain for the testnet identifier: the same
    /// construction as the mainnet genesis under the testnet chain id.
    pub fn testnet_genesis() -> Self {
        Self::with_chain_id(TESTNET_ID.to_string())
    }

    /// Switch the signature domain between mainnet and testnet. Changing
    /// the identifier invalidates every existing signature, which is
    /// exactly the replay isolation the flag exists for.
    pub fn set_testnet(&mut self, testnet: bool) {
        self.testnet = testnet;
        self.chain_id = if testnet {
            TESTNET_ID.to_string()
        } else {
            MAINNET_ID.to_string()
        };
    }

    /// Absolute height of the current tip; the implicit genesis is height 0.
    pub fn tip_height(&self) -> u64 {
        self.blocks.len() as u64 + self.base_height
    }

    /// Hash of the current tip; the implicit genesis hashes to all zeros.
    pub fn tip_hash(&self) -> [u8; 32] {
        self.blocks
            .last()
            .map(|b| self.block_hash(b))
            .unwrap_or([0u8; 32])
    }
}
