pub mod chain;
pub mod crypto;
pub mod governance;
pub mod mining;
pub mod onion;
pub mod p2p;
pub mod rpc;
pub mod simulation;
pub mod state;
pub mod storage;
pub mod treasury;
pub mod vrf;

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Mutex, OnceLock};

/// Global flag that switches the node between mainnet and testnet mode.
/// When true all signature hashes use the testnet chain identifier.
pub static TESTNET_MODE: AtomicBool = AtomicBool::new(false);

/// Global buffer that holds transactions submitted via RPC before the
/// P2P node ingests them into the local mempool. Protected by a mutex
/// so that the RPC handler and the async node loop can safely share it.
pub static PENDING_TXS: OnceLock<Mutex<Vec<chain::Tx>>> = OnceLock::new();

/// Encode a 32-byte key into a lowercase hex string.
pub fn encode_key(key: &[u8; 32]) -> String {
    hex::encode(key)
}

/// Decode a 64-character hex string into a fixed 32-byte array.
pub fn decode_key(hex_str: &str) -> anyhow::Result<[u8; 32]> {
    let bytes = hex::decode(hex_str)?;
    let arr: [u8; 32] = bytes
        .try_into()
        .map_err(|_| anyhow::anyhow!("key must be 32 bytes"))?;
    Ok(arr)
}

/// Submit a transaction into the global pending buffer.
/// The P2P node will drain this buffer periodically and run full
/// mempool validation before broadcasting.
pub fn submit_pending_tx(tx: chain::Tx) {
    let buf = PENDING_TXS.get_or_init(|| Mutex::new(Vec::new()));
    if let Ok(mut guard) = buf.lock() {
        guard.push(tx);
    }
}

/// Remove and return all currently pending transactions.
pub fn drain_pending_txs() -> Vec<chain::Tx> {
    let buf = PENDING_TXS.get_or_init(|| Mutex::new(Vec::new()));
    if let Ok(mut guard) = buf.lock() {
        std::mem::take(&mut *guard)
    } else {
        Vec::new()
    }
}

/// Persist the full chain (blocks + state) to disk atomically via the manifest.
/// The manifest guarantees that readers always see a consistent snapshot.
pub fn save(chain: &chain::Chain) {
    if let Err(e) = storage::save_manifest(&chain.blocks, &chain.state, chain.base_height) {
        eprintln!("[save] manifest storage failed: {}", e);
    }
}

/// Load the chain from disk. If block data is missing but a snapshot exists,
/// fall back to the latest snapshot and replay pruned blocks.
pub fn load() -> chain::Chain {
    load_pruned()
}

/// Load chain, recovering from snapshot when live state files are damaged.
/// First attempts a manifest-based load; if that fails, uses the latest snapshot
/// and replays any blocks that exist after the snapshot height.
pub fn load_pruned() -> chain::Chain {
    // Attempt a manifest-based load first for crash consistency.
    if let Ok((blocks, state, base_height)) = storage::load_from_manifest() {
        let mut chain = chain::Chain {
            blocks,
            base_height,
            state,
            state_history: std::collections::BTreeMap::new(),
            checkpoints: std::collections::BTreeMap::new(),
            version_bits: chain::VersionBits {
                deployments: Vec::new(),
            },
            chain_id: if TESTNET_MODE.load(Ordering::SeqCst) {
                b"/slash/test/0.2.0".to_vec()
            } else {
                b"/slash/0.2.0".to_vec()
            },
            orphan_blocks: std::collections::HashMap::new(),
            side_forks: std::collections::HashMap::new(),
        };
        // Rebuild a minimal state history for reorg depth.
        let tip = chain.blocks.len() as u64 + chain.base_height;
        let start = tip.saturating_sub(chain::MAX_REORG_DEPTH);
        for h in start..=tip {
            if let Some(idx) = h.checked_sub(chain.base_height) {
                // We cannot rebuild exact history without replay,
                // but we keep the tip state for checkpoint protection.
                if chain.blocks.get(idx as usize).is_some() {
                    chain.state_history.insert(h, chain.state.clone());
                }
            }
        }
        return chain;
    }

    // Normal load failed: recover from the most recent snapshot.
    let (snap_height, state) =
        storage::load_latest_snapshot(u64::MAX).unwrap_or_else(|_| (0, state::State::genesis()));
    let mut chain = chain::Chain {
        blocks: Vec::new(),
        base_height: snap_height,
        state,
        state_history: std::collections::BTreeMap::new(),
        checkpoints: std::collections::BTreeMap::new(),
        version_bits: chain::VersionBits {
            deployments: Vec::new(),
        },
        chain_id: if TESTNET_MODE.load(Ordering::SeqCst) {
            b"/slash/test/0.2.0".to_vec()
        } else {
            b"/slash/0.2.0".to_vec()
        },
        orphan_blocks: std::collections::HashMap::new(),
        side_forks: std::collections::HashMap::new(),
    };

    // Replay any blocks stored after the snapshot height.
    if let Ok(all_blocks) = storage::load_blocks() {
        for b in all_blocks {
            if b.height > snap_height {
                let _ = chain.process_block(b);
            }
        }
    }
    chain
}
