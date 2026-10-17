//! src/lib.rs — crate root for the Slash node library.
//!
//! The library exposes the consensus engine (chain + state), the treasury
//! curve, governance, networking, storage, and the FFI/RPC surfaces. The
//! process-wide [`TESTNET_MODE`] selector pins the signature domain for
//! the whole process; every component reads it when a chain identifier is
//! required, so a node can never mix mainnet and testnet semantics.
//!
//! Persistence goes through a single manifest snapshot plus a
//! crash-recovery journal: [`save`] writes the consistent triple (blocks,
//! state, governance metadata) and the journal replays blocks committed
//! after the last manifest, so a crash leaves either the previous or the
//! next consistent state, never a torn one.
//!
//! Layout:
//! - `load` — the startup recovery path: manifest load, snapshot
//!   fallback, journal replay, history rebuild, and the replay-domain
//!   gates, with its unit tests inline (test-only)

pub mod chain;
pub mod crypto;
pub mod dao;
pub mod ffi;
pub mod global_root;
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

#[cfg(any(test, feature = "test-utils"))]
pub mod test_fixtures;

mod load;

pub use load::{load_pruned, prune};

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, OnceLock, RwLock};

/// Process-wide network selector. `false` pins every signature hash to the
/// mainnet chain identifier; `true` switches the whole process to the
/// testnet domain. Every component reads this flag when a chain identifier
/// is required, so the two replay domains can never mix inside one
/// process.
pub static TESTNET_MODE: AtomicBool = AtomicBool::new(false);

/// The cached chain triple: manifest key, manifest length, shared chain.
type CachedChain = Option<(String, u64, Arc<chain::Chain>)>;

/// In-memory chain cache shared by RPC handlers and the FFI layer.
/// Repeated queries reuse the same [`Arc`] instead of re-reading and
/// re-validating the manifest from disk on every call.
static CHAIN_CACHE: OnceLock<RwLock<CachedChain>> = OnceLock::new();

/// Global pending-transaction buffer drained by the P2P node on its
/// periodic tick. RPC submissions land here; the network layer validates
/// and gossips them. The capacity is double the mempool cap so bursts
/// between ticks are smoothed without unbounded growth.
static PENDING_TXS: OnceLock<Mutex<Vec<chain::Tx>>> = OnceLock::new();

/// Build the cache key for the in-memory chain cache. The key is the
/// manifest's content identity — file length plus a short content digest —
/// so any on-disk change invalidates the cached chain without an mtime
/// race. Returns `None` when no manifest exists yet.
fn manifest_key() -> Option<(String, u64)> {
    let path = std::path::Path::new("manifest.bin");
    let md = std::fs::metadata(path).ok()?;
    let len = md.len();
    let content = std::fs::read(path).ok()?;
    let digest = blake3::hash(&content);
    let mut key = String::with_capacity(16);
    for b in digest.as_bytes()[..8].iter() {
        key.push_str(&format!("{:02x}", b));
    }
    Some((key, len))
}

/// Hex-decode a 32-byte key from its string form. Malformed hex and
/// wrong-length input are rejected; every caller maps the error to the
/// same generic rejection, so the error carries no extra detail.
fn decode_key(s: &str) -> anyhow::Result<[u8; 32]> {
    let bytes = hex::decode(s)?;
    bytes
        .as_slice()
        .try_into()
        .map_err(|_| anyhow::anyhow!("key must decode to exactly 32 bytes"))
}

/// The pending buffer capacity: twice the mempool cap the network layer
/// accepts. The P2P node drains the buffer into the mempool on its
/// periodic tick, so the bound only smooths bursts between ticks.
const PENDING_CAP: usize = crate::p2p::MEMPOOL_CAP * 2;

/// Submit a transaction into the global pending buffer. Returns false when
/// the buffer is full, so a submission flood cannot grow the queue without
/// bound and the caller can surface a structured rejection instead of a
/// silent drop. The P2P node drains this buffer periodically and runs full
/// mempool validation before broadcasting.
pub fn submit_pending_tx(tx: chain::Tx) -> bool {
    let buf = PENDING_TXS.get_or_init(|| Mutex::new(Vec::new()));
    match buf.lock() {
        Ok(mut guard) if guard.len() < PENDING_CAP => {
            guard.push(tx);
            true
        }
        _ => false,
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

/// Select the chain identifier that matches the global network mode.
/// Keeping this in one place guarantees that a loaded chain never mixes
/// identifiers between mainnet and testnet semantics.
fn active_chain_id() -> Vec<u8> {
    if TESTNET_MODE.load(Ordering::SeqCst) {
        chain::TESTNET_ID.as_bytes().to_vec()
    } else {
        chain::MAINNET_ID.as_bytes().to_vec()
    }
}

/// Load the chain through the in-memory cache. Returns a shared reference so
/// that repeated RPC and FFI queries do not touch disk or duplicate memory.
/// The cache is invalidated whenever the manifest content changes on disk.
pub fn cached_load() -> Arc<chain::Chain> {
    let cache = CHAIN_CACHE.get_or_init(|| RwLock::new(None));
    let key = manifest_key();
    if let Ok(guard) = cache.read() {
        if let Some((k, len, chain)) = &*guard {
            if key
                .as_ref()
                .is_some_and(|(key_string, key_len)| key_string == k && *key_len == *len)
            {
                return Arc::clone(chain);
            }
        }
    }
    let chain = Arc::new(load());
    if let Ok(mut guard) = cache.write() {
        match key {
            Some((k, len)) => *guard = Some((k, len, Arc::clone(&chain))),
            // Without a manifest there is no stable key; keep the cache empty.
            None => *guard = None,
        }
    }
    Arc::clone(&chain)
}

/// Persist the full chain (blocks + state + governance metadata) to disk
/// atomically via the manifest. The manifest guarantees that readers always
/// see a consistent snapshot. Checkpoints, version-bit deployments, and the
/// chain identifier are written with the blocks so a restart restores the
/// identical validation rules and replay domain; without them soft-fork
/// gates would silently vanish.
/// After a successful manifest write the crash-recovery journal is truncated
/// because the manifest now covers every journaled block.
pub fn save(chain: &chain::Chain) {
    match storage::save_manifest(
        &chain.blocks,
        &chain.state,
        chain.base_height,
        &chain.checkpoints,
        &chain.version_bits.deployments,
        chain.chain_id.as_bytes(),
    ) {
        Ok(()) => {
            if let Err(e) = storage::journal_truncate() {
                eprintln!("[save] journal truncate failed: {}", e);
            }
        }
        Err(e) => eprintln!("[save] manifest storage failed: {}", e),
    }
}

/// Load the chain from disk. If block data is missing but a snapshot exists,
/// fall back to the latest snapshot and replay pruned blocks.
pub fn load() -> chain::Chain {
    load::load_pruned()
}
