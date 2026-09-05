use std::collections::BTreeMap;
use std::sync::{Arc, Mutex, OnceLock, atomic::{AtomicBool, Ordering}};
use std::collections::HashMap;
use std::time::{Duration, Instant};
use rust_randomx::{Context, Hasher};
use crate::chain::Block;

/// Cached RandomX context together with the timestamp of its last use.
struct CachedContext {
    context: Arc<Context>,
    last_used: Instant,
}

/// Global cache: (prev hash, full_mem flag) -> cached context.
/// The boolean distinguishes mining contexts (full memory) from verification
/// contexts (light memory) so that a light context never shadows a full one.
static CONTEXT_CACHE: OnceLock<Mutex<HashMap<([u8; 32], bool), CachedContext>>> = OnceLock::new();

fn get_context_cache() -> &'static Mutex<HashMap<([u8; 32], bool), CachedContext>> {
    CONTEXT_CACHE.get_or_init(|| Mutex::new(HashMap::new()))
}

/// Retrieve a cached RandomX Context for the given prev hash.
/// Creates a new Context if none exists, and evicts entries older than 10 minutes.
/// `full_mem` must be true for mining and may be false for verification.
pub fn get_context(prev: &[u8; 32], full_mem: bool) -> Arc<Context> {
    let mut cache = get_context_cache().lock().unwrap();
    let now = Instant::now();
    // Evict stale entries to prevent unbounded growth.
    cache.retain(|_, v| now.duration_since(v.last_used) < Duration::from_secs(600));
    let key = (*prev, full_mem);
    if let Some(entry) = cache.get_mut(&key) {
        entry.last_used = now;
        return Arc::clone(&entry.context);
    }
    let ctx = Arc::new(Context::new(prev, full_mem));
    cache.insert(key, CachedContext {
        context: Arc::clone(&ctx),
        last_used: now,
    });
    ctx
}

pub struct Miner;

impl Miner {
    /// Perform CPU-bound RandomX mining until the difficulty target is met.
    /// Automatically uses all available CPU cores via extranonce threading.
    /// Accepts an optional cancellation flag; when the flag becomes true all
    /// workers stop searching immediately so the event loop never stalls.
    pub fn mine(prev: [u8; 32], height: u64, miner: [u8; 32], diff: u64, cancel: Option<Arc<AtomicBool>>) -> Option<Block> {
        let threads = std::thread::available_parallelism()
            .map(|n| n.get())
            .unwrap_or(1);
        Self::mine_parallel(prev, height, miner, diff, threads, cancel)
    }

    /// Parallel RandomX mining with extranonce distribution.
    /// Each worker thread searches a disjoint nonce sub-space (thread_id, thread_id + threads, ...).
    /// The first thread to find a valid hash sends the block back and all workers terminate.
    /// If the cancellation flag is set before a solution is found, every worker exits
    /// and None is returned.
    pub fn mine_parallel(prev: [u8; 32], height: u64, miner: [u8; 32], diff: u64, threads: usize, cancel: Option<Arc<AtomicBool>>) -> Option<Block> {
        let threads = threads.max(1);
        let ctx = get_context(&prev, true);
        let time = chrono::Utc::now().timestamp() as u64;
        let (tx, rx) = std::sync::mpsc::channel();

        for tid in 0..threads {
            let ctx = Arc::clone(&ctx);
            let tx = tx.clone();
            let cancel = cancel.clone();
            std::thread::spawn(move || {
                // Each thread gets its own Hasher instance because RandomX VMs are not thread-safe.
                let hasher = Hasher::new(ctx);
                let mut nonce = tid as u64;
                loop {
                    // Poll the cancellation flag once per nonce iteration.
                    if let Some(ref c) = cancel {
                        if c.load(Ordering::Relaxed) {
                            break;
                        }
                    }
                    let mut inp = Vec::new();
                    inp.extend_from_slice(&prev);
                    inp.extend_from_slice(&time.to_le_bytes());
                    inp.extend_from_slice(&height.to_le_bytes());
                    inp.extend_from_slice(&nonce.to_le_bytes());
                    inp.extend_from_slice(&miner);
                    let out = hasher.hash(&inp);
                    let h = out.as_ref();
                    let u = u64::from_le_bytes(h[..8].try_into().unwrap());
                    if u % diff == 0 {
                        let cell = u % crate::state::N;
                        let block = Block {
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
                        // Send the winning block back to the coordinator.
                        let _ = tx.send(block);
                        break;
                    }
                    // Strided increment ensures no two threads scan the same nonce.
                    nonce += threads as u64;
                }
            });
        }

        // Drop the original sender so recv() unblocks as soon as any thread finishes.
        drop(tx);
        // If cancellation fires before a solution arrives, recv() returns Err.
        match rx.recv() {
            Ok(block) => Some(block),
            Err(_) => None,
        }
    }
}
