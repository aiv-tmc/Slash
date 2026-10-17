//! Consensus data structures of the chain layer.
//!
//! These are the wire- and disk-shaped types shared by every subsystem:
//! transactions and outputs as they appear inside blocks, the full block,
//! the light header derived from it, and the result/error enums the block
//! pipeline reports. Field order matters for bincode serialization; do not
//! reorder without a network-identifier bump.

use super::params::MAX_BLOCK_SIZE_BYTES;
use blake3::Hasher;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// A transaction output: a half-open global cell range with an owner and
/// an optional lock height. The range is packed exactly against the inputs
/// in declaration order; `lock` defers spendability until the given height.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct Output {
    pub start: u64,
    pub end: u64,
    pub to: [u8; 32],
    pub lock: Option<u64>,
}

/// A cell-based transaction. Inputs are half-open global cell ranges owned
/// by `from`; outputs pack them exactly in order; `sig` is a 64-byte
/// Ed25519 signature over the transaction hash; `scheme` selects the
/// signature scheme; `memo` carries an optional governance payload whose
/// bytes are committed into the signature hash.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Tx {
    pub from: [u8; 32],
    pub inputs: Vec<(u64, u64)>,
    pub outputs: Vec<Output>,
    pub sig: Vec<u8>,
    pub scheme: u8,
    pub memo: Option<Vec<u8>>,
}

/// A full block. `mined_cell` is the single treasury-owned cell claimed as
/// the proof-of-work slot reward; `page_roots` commits to the Merkle root
/// of every dirty page after executing this block.
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
    pub fee_claims: Vec<Output>,
    pub difficulty: u64,
    pub page_roots: BTreeMap<u16, [u8; 32]>,
}

/// The block header used for header-first sync: every block field except
/// the transaction list and fee claims, plus the body hash committing to
/// them. Headers are cheap to validate (height, linkage, median time,
/// difficulty schedule, proof-of-work) before downloading full bodies.
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
    pub body_hash: [u8; 32],
}

impl BlockHeader {
    /// Derive the light header from a full block. The body hash commits to
    /// every transaction (including memos) and every fee claim, so a
    /// header cannot be paired with a different body.
    pub fn from_block(block: &Block) -> Self {
        let mut h = Hasher::new();
        for tx in &block.txs {
            let bytes = bincode::serialize(tx).unwrap_or_default();
            h.update(&bytes);
        }
        for claim in &block.fee_claims {
            h.update(&claim.start.to_le_bytes());
            h.update(&claim.end.to_le_bytes());
            h.update(&claim.to);
            if let Some(lock) = claim.lock {
                h.update(&lock.to_le_bytes());
            }
        }
        Self {
            version: block.version,
            prev: block.prev,
            time: block.time,
            height: block.height,
            nonce: block.nonce,
            miner: block.miner,
            mined_cell: block.mined_cell,
            difficulty: block.difficulty,
            body_hash: *h.finalize().as_bytes(),
        }
    }
}

/// The outcome of feeding one block into the chain.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum BlockProcessResult {
    /// The block extended the main chain tip.
    ExtendedMain,
    /// The block triggered a reorg; carries disconnected and connected heights.
    Reorged {
        disconnected: Vec<u64>,
        connected: Vec<u64>,
    },
    /// The block is a valid-but-non-heavier fork; retained in the side pool.
    SideFork,
    /// The parent is unknown; retained in the orphan pool.
    Orphan,
}

/// Why a block was rejected. Every variant maps to exactly one consensus
/// rule, so callers can distinguish policy rejections from structural ones.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum BlockError {
    InvalidHeight,
    InvalidPrevHash,
    InvalidTimestamp,
    InvalidDifficulty,
    InvalidPow,
    InvalidCoinbase,
    InvalidTx,
    InvalidPageRoot,
    InvalidSize,
    Orphan,
    Duplicate,
    CheckpointViolation,
    CannotReorgBeyondHistory,
}

impl std::fmt::Display for BlockError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let msg = match self {
            BlockError::InvalidHeight => "block height does not extend the tip",
            BlockError::InvalidPrevHash => "prev hash does not match the tip",
            BlockError::InvalidTimestamp => "block time violates the time rules",
            BlockError::InvalidDifficulty => {
                "declared difficulty differs from the retargeted value"
            }
            BlockError::InvalidPow => "nonce does not satisfy the difficulty target",
            BlockError::InvalidCoinbase => "coinbase is missing, mispositioned, or mis-shaped",
            BlockError::InvalidTx => "a transaction failed consensus validation",
            BlockError::InvalidPageRoot => "a page root differs from the recomputed commitment",
            BlockError::InvalidSize => "the serialized block exceeds the size limit",
            BlockError::Orphan => "parent block is unknown",
            BlockError::Duplicate => "block already known",
            BlockError::CheckpointViolation => "hash mismatches a checkpoint",
            BlockError::CannotReorgBeyondHistory => "reorg exceeds the retained history",
        };
        write!(f, "{}", msg)
    }
}

impl std::error::Error for BlockError {}

// Referenced by the block-size rule so the constant is not reported as
// unused while the rule itself still lives in the validation pipeline.
const _: usize = MAX_BLOCK_SIZE_BYTES;
