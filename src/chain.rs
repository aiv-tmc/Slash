use serde::{Serialize, Deserialize};
use std::collections::{BTreeMap, HashMap};
use blake3::Hasher;
use rust_randomx::Hasher as RandomXHasher;

/// Maximum transactions allowed inside a single block.
pub const MAX_TX_PER_BLOCK: usize = 1000;
/// Maximum serialized block size in bytes (hard consensus limit).
pub const MAX_BLOCK_SIZE_BYTES: usize = 1_048_576;
/// Number of blocks between difficulty retargets.
pub const DIFFICULTY_ADJUSTMENT_INTERVAL: u64 = 2016;
/// Target spacing between blocks in seconds.
pub const TARGET_BLOCK_TIME_SECS: u64 = 120;
/// How many blocks of state history are kept to support reorgs.
pub const MAX_REORG_DEPTH: u64 = 100;

/// A full block including header fields, transactions, and post-execution page roots.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Block {
    pub version: u32,
    pub prev: [u8; 32],
    pub time: u64,
    pub height: u64,
    pub nonce: u64,
    pub miner: [u8; 32],
    pub mined_cell: u64,
    pub txs: Vec<Tx>,
    pub fee_claims: Vec<crate::state::Output>,
    pub difficulty: u64,
    pub page_roots: BTreeMap<u16, [u8; 32]>,
}

/// Light header containing everything needed for PoW and sync verification.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct BlockHeader {
    pub version: u32,
    pub prev: [u8; 32],
    pub time: u64,
    pub height: u64,
    pub nonce: u64,
    pub miner: [u8; 32],
    pub mined_cell: u64,
    pub difficulty: u64,
    pub page_roots: BTreeMap<u16, [u8; 32]>,
}

impl BlockHeader {
    /// Derive a light header from a full block by copying all header-relevant fields.
    pub fn from_block(block: &Block) -> Self {
        Self {
            version: block.version,
            prev: block.prev,
            time: block.time,
            height: block.height,
            nonce: block.nonce,
            miner: block.miner,
            mined_cell: block.mined_cell,
            difficulty: block.difficulty,
            page_roots: block.page_roots.clone(),
        }
    }
}

/// A single transfer or mint transaction.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct Tx {
    pub from: [u8; 32],
    pub inputs: Vec<(u64, u64)>,
    pub outputs: Vec<crate::state::Output>,
    pub sig: Vec<u8>,
    pub scheme: u8,
}

/// Soft-fork deployment tracked by version bits.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Deployment {
    pub name: String,
    pub bit: u8,
    pub start_height: u64,
    pub timeout_height: u64,
    pub threshold: u32,
    pub status: DeploymentStatus,
    pub activation_height: Option<u64>,
    /// Running tally of signalling blocks observed since the deployment entered the Started state.
    pub signals: u32,
}

/// Lifecycle states of a BIP-9 style deployment.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum DeploymentStatus {
    Defined,
    Started,
    LockedIn,
    Active,
    Failed,
}

/// Container for all in-flight soft-fork deployments.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct VersionBits {
    pub deployments: Vec<Deployment>,
}

/// Errors that can occur while processing a block.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum BlockError {
    InvalidPow,
    InvalidDifficulty,
    InvalidTimestamp,
    InvalidHeight,
    InvalidTx,
    InvalidPageRoot,
    Orphan,
    CheckpointViolation,
}

/// Outcome of attempting to add a block to the chain.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum BlockProcessResult {
    ExtendedMain,
    Orphan,
    Duplicate,
    Reorged { disconnected: Vec<u64>, connected: Vec<u64> },
    /// The block extends a known side fork that is not yet heavier than the main chain.
    SideFork,
}

/// The blockchain itself: an ordered list of blocks, the current state,
/// reorg history, checkpoints, and version-bit deployments.
#[derive(Clone, Debug)]
pub struct Chain {
    pub blocks: Vec<Block>,
    pub base_height: u64,
    pub state: crate::state::State,
    pub state_history: BTreeMap<u64, crate::state::State>,
    pub checkpoints: BTreeMap<u64, [u8; 32]>,
    pub version_bits: VersionBits,
    pub chain_id: Vec<u8>,
    /// Blocks whose parent is not yet known, keyed by their header hash.
    /// Kept in memory so they can be reconsidered as soon as the parent arrives.
    pub orphan_blocks: HashMap<[u8; 32], Block>,
    /// Blocks that extend a known side fork but do not (yet) trigger a reorg.
    pub side_forks: HashMap<[u8; 32], Block>,
}

impl Chain {
    /// Build a mainnet genesis chain. The genesis block has height 0,
    /// prev hash all-zeroes, and difficulty 1.
    pub fn genesis() -> Self {
        let state = crate::state::State::genesis();
        let genesis_block = Block {
            version: 1,
            prev: [0u8; 32],
            time: 0,
            height: 0,
            nonce: 0,
            miner: [0u8; 32],
            mined_cell: 0,
            txs: vec![],
            fee_claims: vec![],
            difficulty: 1000,
            page_roots: BTreeMap::new(),
        };
        let mut chain = Self {
            blocks: vec![genesis_block],
            base_height: 0,
            state,
            state_history: BTreeMap::new(),
            checkpoints: BTreeMap::new(),
            version_bits: VersionBits { deployments: Vec::new() },
            chain_id: b"/slash/0.2.0".to_vec(),
            orphan_blocks: HashMap::new(),
            side_forks: HashMap::new(),
        };
        chain.state_history.insert(0, chain.state.clone());
        chain
    }

    /// Build a testnet genesis chain with a distinct chain identifier.
    pub fn testnet_genesis() -> Self {
        let mut chain = Self::genesis();
        chain.chain_id = b"/slash/test/0.2.0".to_vec();
        chain
    }

    /// Compute the blake3 hash of the current tip block header.
    pub fn tip_hash(&self) -> [u8; 32] {
        match self.blocks.last() {
            Some(b) => self.block_hash(b),
            None => [0u8; 32],
        }
    }

    /// Deterministically hash a block header for chaining and checkpointing.
    /// The hash now commits to the block body as well so that two blocks with
    /// identical header fields but different transactions cannot share the same hash.
    pub fn block_hash(&self, block: &Block) -> [u8; 32] {
        let mut h = Hasher::new();
        h.update(&block.version.to_le_bytes());
        h.update(&block.prev);
        h.update(&block.time.to_le_bytes());
        h.update(&block.height.to_le_bytes());
        h.update(&block.nonce.to_le_bytes());
        h.update(&block.miner);
        h.update(&block.mined_cell.to_le_bytes());
        h.update(&block.difficulty.to_le_bytes());
        h.update(&self.body_hash(block));
        *h.finalize().as_bytes()
    }

    /// Compute a blake3 hash over all transactions and fee claims in the block.
    /// This binds the header hash to the exact body content, preventing light-client
    /// confusion when two blocks share the same header fields but carry different payloads.
    fn body_hash(&self, block: &Block) -> [u8; 32] {
        let mut h = Hasher::new();
        for tx in &block.txs {
            h.update(&tx.from);
            h.update(&bincode::serialize(&tx.inputs).unwrap_or_default());
            h.update(&bincode::serialize(&tx.outputs).unwrap_or_default());
            h.update(&tx.sig);
            h.update(&[tx.scheme]);
        }
        for claim in &block.fee_claims {
            h.update(&claim.start.to_le_bytes());
            h.update(&claim.end.to_le_bytes());
            h.update(&claim.to);
            if let Some(lock) = claim.lock {
                h.update(&lock.to_le_bytes());
            }
        }
        *h.finalize().as_bytes()
    }

    /// Return the difficulty target expected for the next block.
    /// Retargets every DIFFICULTY_ADJUSTMENT_INTERVAL blocks using the
    /// standard clamped formula: new = old * target_time / actual_time,
    /// bounded by 4x increase or 4x decrease.
    pub fn next_difficulty(&self) -> u64 {
        let len = self.blocks.len() as u64;
        if len < 2 {
            return self.blocks.last().map_or(1, |b| b.difficulty);
        }
        let tip_height = len - 1 + self.base_height;
        if tip_height % DIFFICULTY_ADJUSTMENT_INTERVAL != 0 {
            return self.blocks.last().unwrap().difficulty;
        }
        let start_idx = len.saturating_sub(DIFFICULTY_ADJUSTMENT_INTERVAL) as usize;
        let start_block = &self.blocks[start_idx];
        let end_block = self.blocks.last().unwrap();
        let actual_time = end_block.time.saturating_sub(start_block.time).max(1);
        let target_time = DIFFICULTY_ADJUSTMENT_INTERVAL * TARGET_BLOCK_TIME_SECS;
        let last_diff = end_block.difficulty;
        let mut new_diff = (last_diff as u128)
            .saturating_mul(target_time as u128)
            .saturating_div(actual_time as u128) as u64;
        let max_diff = last_diff.saturating_mul(4);
        let min_diff = last_diff.saturating_div(4).max(1);
        if new_diff > max_diff { new_diff = max_diff; }
        if new_diff < min_diff { new_diff = min_diff; }
        new_diff
    }

    /// Median timestamp of the last 11 blocks (or fewer at the start).
    /// Used to enforce monotonic time rules.
    pub fn median_timestamp(&self) -> u64 {
        let mut times: Vec<u64> = self.blocks.iter().map(|b| b.time).collect();
        if times.is_empty() { return 0; }
        let start = times.len().saturating_sub(11);
        let slice = &mut times[start..];
        slice.sort_unstable();
        let mid = slice.len() / 2;
        if slice.len() % 2 == 1 {
            slice[mid]
        } else {
            (slice[mid - 1] + slice[mid]) / 2
        }
    }

    /// Validate only the header fields and PoW, without executing transactions.
    /// Used during header-first synchronization.
    pub fn validate_header(&self, header: &BlockHeader) -> bool {
        let expected_height = self.blocks.len() as u64 + self.base_height;
        if header.height != expected_height {
            return false;
        }
        if header.prev != self.tip_hash() {
            return false;
        }
        let now = chrono::Utc::now().timestamp() as u64;
        if header.time > now + 7200 {
            return false;
        }
        if header.time <= self.median_timestamp() {
            return false;
        }
        if header.difficulty != self.next_difficulty() {
            return false;
        }
        verify_pow(header.prev, header.time, header.height, header.miner, header.nonce, header.difficulty).is_some()
    }

    /// Fully validate a block: structure, size, PoW, timestamps, governance rules, and state transition.
    pub fn validate_block(&self, block: &Block) -> bool {
        if block.height != self.blocks.len() as u64 + self.base_height {
            return false;
        }
        if block.prev != self.tip_hash() {
            return false;
        }
        let now = chrono::Utc::now().timestamp() as u64;
        if block.time > now + 7200 {
            return false;
        }
        if block.time <= self.median_timestamp() {
            return false;
        }
        if block.txs.len() > MAX_TX_PER_BLOCK {
            return false;
        }
        // Size check uses bincode, which is the same format used for all on-disk
        // and P2P serialization, guaranteeing that the limit is checked against
        // the actual bytes that would be transmitted or stored.
        let size = bincode::serialize(block).map_or(0, |v| v.len());
        if size > MAX_BLOCK_SIZE_BYTES {
            return false;
        }
        if verify_pow(block.prev, block.time, block.height, block.miner, block.nonce, block.difficulty).is_none() {
            return false;
        }
        if block.difficulty != self.next_difficulty() {
            return false;
        }

        // Enforce any active soft-fork rules against the block header and every transaction.
        let rules = crate::governance::active_rules(&self.version_bits.deployments, block.height);
        if !crate::governance::validate_block_rules(block, &rules) {
            return false;
        }
        for tx in &block.txs {
            if !crate::governance::validate_tx_rules(tx, &rules) {
                return false;
            }
        }

        // Replay the block on a temporary clone of the current state.
        let mut temp = self.state.clone();
        temp.mine(block.mined_cell, block.miner, block.height);
        if !temp.claim_fees(block.miner, &block.fee_claims, block.height) {
            return false;
        }
        // Validate every transaction against the temporary state. Treasury and user
        // transactions share the same validation path because State::tx already
        // skips the signature check for the treasury address.
        for tx in &block.txs {
            if !temp.tx(tx.from, &tx.inputs, &tx.outputs, &tx.sig, block.height, &self.chain_id, tx.scheme) {
                return false;
            }
        }
        // Verify that the miner-supplied page roots match the recomputed roots.
        for (&page_id, page) in &temp.pages {
            let expected = page.merkle_root();
            if block.page_roots.get(&page_id) != Some(&expected) {
                return false;
            }
        }
        true
    }

    /// Compute page Merkle roots for a block without mutating the chain.
    /// Call this after mining a block and before validation/application.
    pub fn prepare_block(&self, mut block: Block) -> Block {
        let mut temp = self.state.clone();
        temp.mine(block.mined_cell, block.miner, block.height);
        let _ = temp.claim_fees(block.miner, &block.fee_claims, block.height);
        for tx in &block.txs {
            let _ = temp.tx(tx.from, &tx.inputs, &tx.outputs, &tx.sig, block.height, &self.chain_id, tx.scheme);
        }
        let mut roots = BTreeMap::new();
        for (&page_id, page) in &temp.pages {
            roots.insert(page_id, page.merkle_root());
        }
        block.page_roots = roots;
        block
    }

    /// Atomically append a validated block to the chain, update state history,
    /// and advance version-bit signaling.
    pub fn apply(&mut self, block: Block) -> Result<(), BlockError> {
        if !self.validate_block(&block) {
            return Err(BlockError::InvalidTx);
        }
        self.state.mine(block.mined_cell, block.miner, block.height);
        if !self.state.claim_fees(block.miner, &block.fee_claims, block.height) {
            return Err(BlockError::InvalidTx);
        }
        for tx in &block.txs {
            if !self.state.tx(tx.from, &tx.inputs, &tx.outputs, &tx.sig, block.height, &self.chain_id, tx.scheme) {
                return Err(BlockError::InvalidTx);
            }
        }
        self.blocks.push(block.clone());
        let height = block.height;
        self.state_history.insert(height, self.state.clone());
        // Prune old history to keep memory bounded.
        let prune_below = height.saturating_sub(MAX_REORG_DEPTH);
        self.state_history.retain(|&h, _| h >= prune_below);
        // Update version bits.
        self.update_version_bits(&block);
        Ok(())
    }

    /// Attempt to add a block that may extend the main chain, a side fork,
    /// or arrive as an orphan. Triggers reorganization when a fork becomes heavier.
    pub fn process_block(&mut self, block: Block) -> Result<BlockProcessResult, BlockError> {
        let hash = self.block_hash(&block);
        // Checkpoint enforcement: blocks at or below the highest checkpoint
        // must match the checkpoint hash exactly.
        if let Some((&max_cp_height, _)) = self.checkpoints.iter().next_back() {
            if block.height <= max_cp_height {
                if let Some(expected) = self.checkpoints.get(&block.height) {
                    if hash != *expected {
                        return Err(BlockError::CheckpointViolation);
                    }
                }
            }
        }
        // Duplicate detection across both the main chain and the orphan pool.
        for b in &self.blocks {
            if self.block_hash(b) == hash {
                return Ok(BlockProcessResult::Duplicate);
            }
        }
        if self.orphan_blocks.contains_key(&hash) {
            return Ok(BlockProcessResult::Duplicate);
        }
        if self.side_forks.contains_key(&hash) {
            return Ok(BlockProcessResult::Duplicate);
        }
        let expected_main = self.blocks.len() as u64 + self.base_height;
        // Direct extension of the main chain.
        if block.prev == self.tip_hash() && block.height == expected_main {
            self.apply(block)?;
            self.process_orphans()?;
            return Ok(BlockProcessResult::ExtendedMain);
        }
        // Search for the parent inside the existing chain.
        let parent_known = self.blocks.iter().any(|b| self.block_hash(b) == block.prev);
        if parent_known {
            // Side fork: compare lengths to decide reorg.
            let fork_common_height = block.height - 1;
            let main_len_after_common = expected_main - 1 - fork_common_height;
            let fork_len = 1; // This block starts the visible fork tail.
            if fork_len > main_len_after_common {
                let mut disconnected = Vec::new();
                let mut connected = Vec::new();
                // Roll back to common ancestor.
                while self.blocks.len() as u64 + self.base_height > block.height {
                    if let Some(b) = self.blocks.pop() {
                        disconnected.push(b.height);
                    }
                }
                // Restore state at common ancestor.
                if let Some(st) = self.state_history.get(&fork_common_height) {
                    self.state = st.clone();
                }
                // Apply the new fork block.
                self.apply(block.clone())?;
                self.process_orphans()?;
                connected.push(block.height);
                return Ok(BlockProcessResult::Reorged { disconnected, connected });
            } else {
                // Short fork: retain the block so it is not lost.
                self.side_forks.insert(hash, block);
                return Ok(BlockProcessResult::SideFork);
            }
        }
        // Parent unknown: store the block in the orphan pool so it can be
        // reconsidered immediately when the parent finally arrives.
        self.orphan_blocks.insert(hash, block);
        // Prevent unbounded memory growth by capping the orphan pool.
        if self.orphan_blocks.len() > 1000 {
            let first_key = *self.orphan_blocks.keys().next().unwrap();
            self.orphan_blocks.remove(&first_key);
        }
        Ok(BlockProcessResult::Orphan)
    }

    /// Scan the orphan pool for blocks whose parent hash matches the current tip.
    /// Apply every matching orphan recursively so that a chain of orphans can be
    /// adopted as soon as its ancestor appears on the main chain.
    fn process_orphans(&mut self) -> Result<(), BlockError> {
        loop {
            let tip = self.tip_hash();
            let mut next_orphan_hash = None;
            for (hash, orphan) in &self.orphan_blocks {
                if orphan.prev == tip {
                    next_orphan_hash = Some(*hash);
                    break;
                }
            }
            let Some(hash) = next_orphan_hash else { break; };
            if let Some(block) = self.orphan_blocks.remove(&hash) {
                if self.apply(block).is_err() {
                    // Invalid orphan: drop it and continue trying others.
                    continue;
                }
            }
        }
        Ok(())
    }

    /// Roll the chain back to a specific common ancestor height and replay
    /// a sequence of fork blocks. Used explicitly in checkpoint tests.
    pub fn reorg_to_fork(&mut self, common_ancestor_height: u64, _fork_blocks: &[Block]) -> Result<(), BlockError> {
        if let Some((&max_cp, _)) = self.checkpoints.iter().next_back() {
            if common_ancestor_height < max_cp {
                return Err(BlockError::CheckpointViolation);
            }
        }
        while self.blocks.len() as u64 + self.base_height > common_ancestor_height + 1 {
            self.blocks.pop();
        }
        if let Some(st) = self.state_history.get(&common_ancestor_height) {
            self.state = st.clone();
        }
        Ok(())
    }

    /// Update version-bit deployments based on the version field of the accepted block.
    /// Counts signals cumulatively and only transitions to LockedIn once the real
    /// threshold is reached. The Active transition is deferred to the scheduled
    /// activation height.
    fn update_version_bits(&mut self, block: &Block) {
        for d in &mut self.version_bits.deployments {
            if block.height < d.start_height {
                continue;
            }
            if block.height > d.timeout_height && d.status != DeploymentStatus::LockedIn && d.status != DeploymentStatus::Active {
                d.status = DeploymentStatus::Failed;
                continue;
            }
            if d.status == DeploymentStatus::Defined {
                d.status = DeploymentStatus::Started;
            }
            if d.status == DeploymentStatus::Started {
                let signal = (block.version >> d.bit) & 1 == 1;
                if signal {
                    d.signals += 1;
                    if d.signals >= d.threshold {
                        d.status = DeploymentStatus::LockedIn;
                        d.activation_height = Some(block.height + DIFFICULTY_ADJUSTMENT_INTERVAL);
                    }
                }
            }
            if d.status == DeploymentStatus::LockedIn {
                if let Some(act) = d.activation_height {
                    if block.height >= act {
                        d.status = DeploymentStatus::Active;
                    }
                }
            }
        }
    }

    /// Validate a single transaction against the current chain state.
    /// Checks structure, signature, ownership, locks, and active governance rules.
    pub fn validate_tx(&self, tx: &Tx) -> bool {
        if tx.inputs.is_empty() {
            return false;
        }
        let total_in: u64 = tx.inputs.iter().map(|(s, e)| e - s).sum();
        let total_out: u64 = tx.outputs.iter().map(|o| o.end - o.start).sum();
        if total_in != total_out {
            return false;
        }
        if total_out < crate::state::MIN {
            return false;
        }
        // Reject scheme identifiers outside the known set (0 and 1).
        if tx.scheme != 0 && tx.scheme != 1 {
            return false;
        }

        if tx.from != crate::state::TREASURY {
            let hash = tx_signature_hash(&tx.from, &tx.inputs, &tx.outputs, &self.chain_id, tx.scheme);
            if !crate::crypto::verify(&tx.from, &hash, &tx.sig) {
                return false;
            }
        }

        let current_height = self.blocks.len() as u64 + self.base_height;
        for (s, e) in &tx.inputs {
            let mut cur = *s;
            while cur < *e {
                let (_, en, owner) = match self.state.get(cur) {
                    Some(x) => x,
                    None => return false,
                };
                if owner != tx.from {
                    return false;
                }
                if let Some(&until) = self.state.locks.get(&cur) {
                    if until > current_height {
                        return false;
                    }
                }
                cur = en;
            }
        }

        // Enforce active soft-fork rules against the transaction.
        let rules = crate::governance::active_rules(&self.version_bits.deployments, current_height);
        if !crate::governance::validate_tx_rules(tx, &rules) {
            return false;
        }
        // Scheme 1 is only permitted when the AllowScheme1 soft-fork is active.
        if tx.scheme == 1 && !rules.iter().any(|r| matches!(r, crate::governance::Rule::AllowScheme1)) {
            return false;
        }
        true
    }
}

/// Compute the blake3 digest that a transaction must sign.
/// Includes the sender, every input and output, the chain identifier,
/// and the scheme byte to prevent replay across networks and future schemes.
pub fn tx_signature_hash(from: &[u8; 32], inputs: &[(u64, u64)], outputs: &[crate::state::Output], chain_id: &[u8], scheme: u8) -> Vec<u8> {
    let mut h = Hasher::new();
    h.update(from);
    for (s, e) in inputs {
        h.update(&s.to_le_bytes());
        h.update(&e.to_le_bytes());
    }
    for o in outputs {
        h.update(&o.start.to_le_bytes());
        h.update(&o.end.to_le_bytes());
        h.update(&o.to);
        if let Some(lock) = o.lock {
            h.update(&lock.to_le_bytes());
        }
    }
    h.update(chain_id);
    h.update(&[scheme]);
    h.finalize().as_bytes().to_vec()
}

/// Verify RandomX proof-of-work for a block header.
/// Uses the globally cached RandomX VM context so that repeated checks for the
/// same prev hash do not pay the context-creation penalty. The hash input is
/// identical to the one constructed by the miner in mining.rs, guaranteeing
/// consensus between production and validation.
pub fn verify_pow(prev: [u8; 32], time: u64, height: u64, miner: [u8; 32], nonce: u64, difficulty: u64) -> Option<u64> {
    let ctx = crate::mining::get_context(&prev, false);
    let hasher = RandomXHasher::new(ctx);
    let mut inp = Vec::new();
    inp.extend_from_slice(&prev);
    inp.extend_from_slice(&time.to_le_bytes());
    inp.extend_from_slice(&height.to_le_bytes());
    inp.extend_from_slice(&nonce.to_le_bytes());
    inp.extend_from_slice(&miner);
    let out = hasher.hash(&inp);
    let h = out.as_ref();
    let value = u64::from_le_bytes(h[..8].try_into().unwrap());
    if difficulty == 0 {
        return Some(value % crate::state::N);
    }
    if value % difficulty == 0 {
        Some(value % crate::state::N)
    } else {
        None
    }
}
