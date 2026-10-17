// `mine_parallel` takes one parameter per mining input (header fields,
// difficulty, cancellation flag, worker count, and the slot predicate).
// The arity mirrors the consensus-mandated hash inputs; grouping would hide
// the field list at call sites, so the arity lint is allowed deliberately
// at module scope.
#![allow(clippy::too_many_arguments)]

//! RandomX proof-of-work mining with parallel nonce search.
//!
//! The miner constructs hash inputs identically to `verify_pow` in chain.rs,
//! so a nonce that satisfies the difficulty target is valid consensus-wide.

use rust_randomx::{Context, Hasher as RandomXHasher};
use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, OnceLock};
use std::time::{Duration, Instant};

/// One cache entry: the RandomX context plus the timestamp of its last use.
struct CachedContext {
    context: Arc<Context>,
    last_used: Instant,
}

/// Global cache of RandomX contexts keyed by the block's `prev` hash.
/// Context creation is expensive, so mining and verification reuse contexts
/// across attempts that share the same `prev`.
static CONTEXT_CACHE: OnceLock<std::sync::Mutex<HashMap<[u8; 32], CachedContext>>> =
    OnceLock::new();

/// How long a cached context stays alive after its last use.
const CONTEXT_CACHE_TTL: Duration = Duration::from_secs(600);
/// Maximum number of cached RandomX contexts. Each context pins a large
/// memory allocation, so the count is bounded in addition to the TTL: a peer
/// streaming headers with random prev hashes must not be able to exhaust
/// node memory by forcing the creation of unbounded contexts.
const MAX_CONTEXT_CACHE_ENTRIES: usize = 8;

/// Retrieve a cached RandomX Context for the given prev hash.
/// Creates a new Context if none exists, and evicts entries older than 10 minutes.
/// `full_mem` must be true for mining and may be false for verification.
pub fn get_context(prev: &[u8; 32], full_mem: bool) -> Arc<Context> {
    let key = blake3::hash(prev).into();
    let now = Instant::now();

    // Refresh and return a live entry when one exists. A light entry cannot
    // serve a mining request, so full requests miss on light entries and
    // recreate them with the full dataset.
    let cache = CONTEXT_CACHE.get_or_init(|| std::sync::Mutex::new(HashMap::new()));
    if let Some(entry) = cache.lock().unwrap().get_mut(&key) {
        let full_enough = !full_mem;
        if full_enough && now.duration_since(entry.last_used) <= CONTEXT_CACHE_TTL {
            entry.last_used = now;
            return Arc::clone(&entry.context);
        }
    }

    // Create a fresh context. Light contexts are preferred for verification
    // because they use far less memory; mining always needs the full dataset.
    let ctx = Arc::new(Context::new(prev, full_mem));

    let mut cache = cache.lock().unwrap();
    // Enforce the entry-count bound before inserting: evict the least
    // recently used context so the cache never grows past the constant.
    if cache.len() >= MAX_CONTEXT_CACHE_ENTRIES {
        if let Some(oldest) = cache
            .iter()
            .min_by_key(|(_, v)| v.last_used)
            .map(|(k, _)| *k)
        {
            cache.remove(&oldest);
        }
    }
    cache.insert(
        key,
        CachedContext {
            context: Arc::clone(&ctx),
            last_used: now,
        },
    );
    ctx
}

/// A candidate block assembled by the miner but not yet validated.
pub struct MinerBlock {
    pub nonce: u64,
    pub value: u64,
}

/// Search for a valid nonce in parallel across all available cores.
///
/// Each worker strides nonces by the worker count so no two workers evaluate
/// the same candidate. The search stops as soon as any worker satisfies the
/// difficulty target, finds a treasury-owned proof-of-work slot, or observes
/// the cooperative cancellation flag.
pub fn mine_parallel(
    prev: [u8; 32],
    time: u64,
    height: u64,
    miner: [u8; 32],
    diff: u64,
    cancel: Arc<AtomicBool>,
    threads: usize,
    slot_check: impl Fn(u64) -> bool + Send + Sync + 'static,
) -> Option<MinerBlock> {
    let slot_check = Arc::new(slot_check);
    let ctx = get_context(&prev, true);
    let found = Arc::new(AtomicBool::new(false));
    let (tx, rx) = std::sync::mpsc::channel::<MinerBlock>();
    for i in 0..threads {
        let tx = tx.clone();
        let cancel = cancel.clone();
        let found = found.clone();
        let ctx = Arc::clone(&ctx);
        let slot_check = Arc::clone(&slot_check);
        std::thread::spawn(move || {
            let hasher = RandomXHasher::new(ctx);
            let mut nonce = i as u64;
            while !cancel.load(Ordering::Relaxed) && !found.load(Ordering::Relaxed) {
                let mut inp = Vec::with_capacity(88);
                inp.extend_from_slice(&prev);
                inp.extend_from_slice(&time.to_le_bytes());
                inp.extend_from_slice(&height.to_le_bytes());
                inp.extend_from_slice(&nonce.to_le_bytes());
                inp.extend_from_slice(&miner);
                let out = hasher.hash(&inp);
                let h = out.as_ref();
                let u = u64::from_le_bytes(h[..8].try_into().unwrap());
                let slot = u % crate::state::N;
                if u % diff == 0 && slot_check(slot) {
                    // Publish the winning block, signal the other workers,
                    // and exit. The receiver may already have returned, in
                    // which case the send result is ignored.
                    found.store(true, Ordering::Relaxed);
                    let _ = tx.send(MinerBlock { nonce, value: u });
                    break;
                }
                nonce = nonce.wrapping_add(threads as u64);
            }
        });
    }
    drop(tx);
    rx.recv().ok()
}

/// Synchronous single-threaded mining used by tests and the miner RPC path.
/// `slot_check` lets the caller reject proof-of-work slots that target
/// non-treasury cells without invalidating the whole search.
pub fn mine(
    prev: [u8; 32],
    time: u64,
    height: u64,
    miner: [u8; 32],
    diff: u64,
    cancel: Arc<AtomicBool>,
    slot_check: impl Fn(u64) -> bool,
) -> Option<MinerBlock> {
    let ctx = get_context(&prev, true);
    let hasher = RandomXHasher::new(ctx);
    let mut nonce = 0u64;
    while !cancel.load(Ordering::Relaxed) {
        let mut inp = Vec::with_capacity(88);
        inp.extend_from_slice(&prev);
        inp.extend_from_slice(&time.to_le_bytes());
        inp.extend_from_slice(&height.to_le_bytes());
        inp.extend_from_slice(&nonce.to_le_bytes());
        inp.extend_from_slice(&miner);
        let out = hasher.hash(&inp);
        let h = out.as_ref();
        let u = u64::from_le_bytes(h[..8].try_into().unwrap());
        let slot = u % crate::state::N;
        if u % diff == 0 && slot_check(slot) {
            return Some(MinerBlock { nonce, value: u });
        }
        nonce = nonce.wrapping_add(1);
    }
    None
}

/// Header-only nonce search used by the P2P mining loop. Unlike `mine` and
/// `mine_parallel` it accepts any proof-of-work slot cell because the block
/// template's slot is validated against the treasury ownership table later,
/// during full block validation. Returns the winning nonce together with
/// the slot cell derived from the hash output, or None on cancellation.
pub fn mine_block(
    prev: [u8; 32],
    time: u64,
    height: u64,
    miner: [u8; 32],
    diff: u64,
    cancel: Arc<AtomicBool>,
) -> Option<(u64, u64)> {
    let found = mine(prev, time, height, miner, diff, cancel, |_| true)?;
    Some((found.nonce, found.value % crate::state::N))
}

/// Mining facade used by the P2P node. The node runs this blocking search on
/// the thread-pool via `spawn_blocking` and receives a fully assembled block
/// template whose transaction list and fee claims it fills in afterwards.
pub struct Miner;

impl Miner {
    /// Run the single-threaded nonce search and package the result into a
    /// block template. `cancel` and `slot_check` are optional conveniences:
    /// mining proceeds without cancellation, and without a slot predicate
    /// every treasury-range solution is accepted. The block timestamp is the
    /// wall clock at search start, matching the median-time and future-time
    /// rules enforced during validation.
    pub fn mine(
        prev: [u8; 32],
        height: u64,
        miner: [u8; 32],
        diff: u64,
        cancel: Option<Arc<AtomicBool>>,
        slot_check: Option<Arc<dyn Fn(u64) -> bool + Send + Sync>>,
    ) -> Option<crate::chain::Block> {
        let time = chrono::Utc::now().timestamp() as u64;
        let cancel = cancel.unwrap_or_else(|| Arc::new(AtomicBool::new(false)));
        let slot_check = slot_check.unwrap_or_else(|| Arc::new(|_| true));
        let found = mine(prev, time, height, miner, diff, cancel, move |slot: u64| {
            slot_check(slot)
        })?;
        Some(crate::chain::Block {
            version: 1,
            prev,
            time,
            height,
            nonce: found.nonce,
            miner,
            mined_cell: found.value % crate::state::N,
            txs: vec![],
            fee_claims: vec![],
            difficulty: diff,
            page_roots: std::collections::BTreeMap::new(),
        })
    }
}
