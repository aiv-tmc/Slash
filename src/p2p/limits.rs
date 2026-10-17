//! Resource limits of the network layer.
//!
//! Every constant here is a DoS boundary: frame caps bound allocations,
//! token buckets bound per-peer message rates, connection caps bound
//! inbound floods, strike tables bound ban bookkeeping, and the replay
//! cache bounds the onion-seen set. None of them is a tuning knob.
//! Constants used from sibling submodules are crate-visible; the two
//! limits other crates read (mempool capacity, pruned retention) are
//! public.

/// Maximum serialized request-response frame; larger frames are rejected
/// before deserialization so a malicious peer cannot force giant
/// allocations.
pub(crate) const MAX_FRAME: usize = 10 * 1024 * 1024;

/// Number of blocks retained in pruned mode.
pub const PRUNED_KEEP_BLOCKS: u64 = 10_000;

/// Mempool capacity in transactions. Admission evicts the lowest-fee
/// transaction first, so the pool always keeps the most valuable backlog.
pub const MEMPOOL_CAP: usize = 10_000;

/// Maximum open inbound connections node-wide; excess inbound dials are
/// refused so a connection flood cannot starve outbound slots.
pub(crate) const MAX_INBOUND_CONNECTIONS: usize = 64;

/// Maximum connections accepted from one IPv4 /24 or IPv6 /64 subnet. A
/// Sybil cluster behind one subnet key shares one budget, which is the
/// primary defense against cheap multi-identity floods.
pub(crate) const MAX_CONNECTIONS_PER_SUBNET: usize = 8;

/// Peer misbehavior strikes before a ban activates.
pub(crate) const PEER_BAN_STRIKES: u32 = 3;
/// Base ban duration in seconds at the strike threshold.
pub(crate) const PEER_BAN_BASE_SECS: u64 = 60;
/// Maximum ban duration in seconds; the exponential backoff saturates here.
pub(crate) const PEER_BAN_MAX_SECS: u64 = 3600;

/// Tip polling: how many peers are sampled per sync tick, and how many
/// ticks pass between full polls of every peer.
pub(crate) const SYNC_SAMPLE_SIZE: usize = 8;
pub(crate) const SYNC_FULL_POLL_EVERY: u64 = 12;

/// Peer exchange: batch size and the cap of the known-addresses table.
pub(crate) const PEER_EXCHANGE_BATCH: usize = 8;
pub(crate) const KNOWN_ADDRS_CAP: usize = 4096;

/// Onion replay cache capacity. Identifiers evict oldest-first (FIFO), and
/// the cache persists to disk so a restart cannot reopen the replay
/// window.
pub(crate) const ONION_REPLAY_CACHE: usize = 10_000;

/// Refill rates and burst capacities of the per-peer token buckets. One
/// bucket per message class stops a single peer from flooding any single
/// subsystem while leaving other classes usable.
pub(crate) const TX_BUCKET_REFILL_PER_SEC: f64 = 2.0;
pub(crate) const TX_BUCKET_BURST: f64 = 8.0;
pub(crate) const BLOCK_BUCKET_REFILL_PER_SEC: f64 = 0.2;
pub(crate) const BLOCK_BUCKET_BURST: f64 = 2.0;
pub(crate) const ONION_BUCKET_REFILL_PER_SEC: f64 = 0.5;
pub(crate) const ONION_BUCKET_BURST: f64 = 4.0;

/// How far ahead of the local tip an advertised tip is trusted enough to
/// start a header sync. Honest peers advertise at most a bounded window
/// ahead; claims beyond the bound are ignored until the chain approaches
/// them.
pub(crate) const SYNC_MAX_TIP_AHEAD: u64 = 20_160;

/// The serving cap for one GetBlocks response. The sync loop requests
/// the next chunk immediately after a full one, so this constant doubles
/// as the loop's chunk detector.
pub(crate) const SYNC_BLOCKS_PER_RESPONSE: usize = 64;

/// A token bucket for one message class of one peer. Tokens refill
/// linearly up to a burst cap; a take succeeds only when enough tokens
/// are available and consumes them immediately. Every bucket starts with
/// one full token so the first message a freshly connected peer sends is
/// admitted at once: connection startup is never itself a punishable
/// event, and a rate-limit refusal stays an honest drop rather than the
/// first entry in a strike record.
pub(crate) struct RateBucket {
    tokens: f64,
    last: std::time::Instant,
}

impl RateBucket {
    fn new() -> Self {
        Self {
            tokens: 1.0,
            last: std::time::Instant::now(),
        }
    }

    /// Try to consume `cost` tokens, refilling linearly since the last
    /// take. Returns true when the take succeeded; the bucket never goes
    /// negative, so a refused flood costs the caller nothing.
    fn take(&mut self, cost: f64, refill_per_sec: f64, burst: f64) -> bool {
        let now = std::time::Instant::now();
        let elapsed = now.duration_since(self.last).as_secs_f64();
        self.last = now;
        self.tokens = (self.tokens + elapsed * refill_per_sec).min(burst);
        if self.tokens >= cost {
            self.tokens -= cost;
            true
        } else {
            false
        }
    }
}

/// The three per-peer token buckets: one for transactions, one for blocks,
/// one for onion relays. A peer flooding a single class is throttled in
/// that class alone. Fields are crate-visible because the gossip handler
/// consumes them directly.
pub(crate) struct PeerBuckets {
    pub(crate) tx: RateBucket,
    pub(crate) block: RateBucket,
    pub(crate) onion: RateBucket,
}

impl PeerBuckets {
    pub(crate) fn new() -> Self {
        Self {
            tx: RateBucket::new(),
            block: RateBucket::new(),
            onion: RateBucket::new(),
        }
    }

    /// Admit one transaction message under the transaction bucket.
    pub(crate) fn take_tx(&mut self) -> bool {
        self.tx.take(1.0, TX_BUCKET_REFILL_PER_SEC, TX_BUCKET_BURST)
    }

    /// Admit one block message under the block bucket.
    pub(crate) fn take_block(&mut self) -> bool {
        self.block
            .take(1.0, BLOCK_BUCKET_REFILL_PER_SEC, BLOCK_BUCKET_BURST)
    }

    /// Admit one onion relay under the onion bucket.
    pub(crate) fn take_onion(&mut self) -> bool {
        self.onion
            .take(1.0, ONION_BUCKET_REFILL_PER_SEC, ONION_BUCKET_BURST)
    }
}

impl Default for PeerBuckets {
    fn default() -> Self {
        Self::new()
    }
}
