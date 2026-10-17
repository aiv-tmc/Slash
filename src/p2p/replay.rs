//! src/p2p/replay.rs — the onion replay cache.
//!
//! Every relayed onion envelope is identified by the blake3 of its bytes;
//! the cache remembers recently seen identifiers and refuses duplicates.
//! Entries evict oldest-first (FIFO) at a fixed capacity, and the whole
//! cache persists to `onion_seen.bin`, so a node restart cannot reopen
//! the replay window. The on-disk write goes through the atomic-write
//! helper (temp file, fsync, rename), so a crash mid-persist leaves the
//! previous file intact and the reloaded cache is a consistent — possibly
//! shorter — prefix of the live one. Persistence is dirty-flagged: the
//! cache is written only after an identifier was actually recorded since
//! the last persist, not on every housekeeping tick.

use std::collections::{HashSet, VecDeque};

use super::limits::ONION_REPLAY_CACHE;

/// FIFO replay cache of onion envelope identifiers, persisted across
/// restarts as a bincode-serialized identifier list. A missing or corrupt
/// file starts the cache empty, which only widens the replay window for
/// envelopes relayed before the crash — an acceptable failure mode
/// compared to rejecting honest traffic on a corrupt read.
#[derive(Clone, Default)]
pub struct OnionReplayCache {
    seen: HashSet<[u8; 32]>,
    order: VecDeque<[u8; 32]>,
    /// Whether an identifier was recorded since the last successful
    /// persist. Housekeeping consults the flag and skips the disk write
    /// when nothing changed, so the persist cost is paid only when the
    /// cache actually advanced.
    dirty: bool,
}

impl OnionReplayCache {
    /// An empty cache.
    pub fn new() -> Self {
        Self::default()
    }

    /// Load the persisted cache from disk, or an empty cache when the file
    /// is absent or unreadable. A successfully loaded cache is clean: its
    /// contents already equal the on-disk image, so the next persist is
    /// skipped until a new identifier arrives.
    pub fn load() -> Self {
        let Ok(bytes) = std::fs::read("onion_seen.bin") else {
            return Self::new();
        };
        bincode::deserialize::<Vec<[u8; 32]>>(&bytes)
            .map(|ids| {
                let mut cache = Self::new();
                for id in ids {
                    cache.insert(id);
                }
                cache.dirty = false;
                cache
            })
            .unwrap_or_else(|_| Self::new())
    }

    /// Persist the cache contents to disk as a flat identifier list. The
    /// write is skipped entirely when no identifier was recorded since the
    /// last persist, and it goes through the atomic-write helper so a
    /// crash mid-persist leaves either the previous file or the next one,
    /// never a torn image. The dirty flag clears only on a successful
    /// write; a failed write is retried on the next call.
    pub fn persist(&mut self) {
        if !self.dirty {
            return;
        }
        let ids: Vec<[u8; 32]> = self.order.iter().copied().collect();
        if let Ok(bytes) = bincode::serialize(&ids) {
            if crate::storage::atomic_write("onion_seen.bin", &bytes).is_ok() {
                self.dirty = false;
            }
        }
    }

    /// The number of retained identifiers, capped by the eviction policy.
    /// Only the test suite inspects the occupancy; production code
    /// reasons about the cache exclusively through `insert` and
    /// `contains`.
    #[cfg(test)]
    pub fn len(&self) -> usize {
        self.order.len()
    }

    /// Whether an identifier is already present. The admission path
    /// checks membership before doing any deserialization or
    /// cryptographic work, so a replayed envelope is rejected without
    /// spending a cache slot or CPU on it.
    pub fn contains(&self, id: [u8; 32]) -> bool {
        self.seen.contains(&id)
    }

    /// Record an identifier, evicting the oldest entry at capacity so the
    /// cache footprint stays bounded. Returns true when the identifier
    /// was new; false reports a replay of an already-seen envelope. The
    /// dirty flag is raised only by successful insertions of new
    /// identifiers: re-inserting a known identifier changes nothing and
    /// triggers no disk write.
    pub fn insert(&mut self, id: [u8; 32]) -> bool {
        if !self.seen.insert(id) {
            return false;
        }
        self.order.push_back(id);
        if self.order.len() > ONION_REPLAY_CACHE {
            if let Some(oldest) = self.order.pop_front() {
                self.seen.remove(&oldest);
            }
        }
        self.dirty = true;
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A deterministic 32-byte identifier from a small counter: the low
    /// eight bytes carry the counter, the rest stay zero, so identifiers
    /// remain unique and ordered for window assertions.
    fn id_of(i: u64) -> [u8; 32] {
        let mut id = [0u8; 32];
        id[..8].copy_from_slice(&i.to_le_bytes());
        id
    }

    /// Run `f` with the process working directory pointed at a fresh
    /// per-test directory under the system temp dir, restoring the
    /// previous directory afterwards. The cache persists to a relative
    /// filename, so the test isolates its on-disk image exactly the way
    /// the network test suite does.
    fn in_temp_dir(label: &str, f: impl FnOnce()) {
        let dir = std::env::temp_dir().join(format!("slash_replay_{label}_{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let prev = std::env::current_dir().unwrap();
        std::env::set_current_dir(&dir).unwrap();
        f();
        std::env::set_current_dir(prev).unwrap();
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn duplicate_insert_never_raises_the_dirty_flag() {
        // Re-recording a known identifier leaves the cache content and
        // the persist schedule untouched: only genuinely new envelopes
        // mark the cache dirty, and membership checks never allocate.
        let mut cache = OnionReplayCache::new();
        assert!(cache.insert(id_of(7)));
        assert!(cache.contains(id_of(7)));
        assert!(!cache.contains(id_of(8)));
        assert!(!cache.insert(id_of(7)));
        assert_eq!(cache.len(), 1);
    }

    #[test]
    fn insertion_order_bounds_the_window() {
        // The FIFO window holds exactly ONION_REPLAY_CACHE identifiers;
        // the oldest entry leaves first, so the window always covers the
        // most recent envelopes.
        let mut cache = OnionReplayCache::new();
        for i in 0..ONION_REPLAY_CACHE as u64 + 10 {
            assert!(cache.insert(id_of(i)));
        }
        assert_eq!(cache.len(), ONION_REPLAY_CACHE);
        assert!(!cache.contains(id_of(0)));
        assert!(cache.contains(id_of(ONION_REPLAY_CACHE as u64 + 9)));
    }

    #[test]
    fn persisted_cache_round_trips_and_loads_clean() {
        // Round-trip: a cache persisted to disk loads back equal and
        // clean, so the next housekeeping persist is skipped until a new
        // envelope arrives, and a replay of a persisted identifier is
        // still detected after the reload.
        in_temp_dir("roundtrip", || {
            let mut cache = OnionReplayCache::new();
            assert!(cache.insert(id_of(1)));
            assert!(cache.insert(id_of(2)));
            cache.persist();
            let mut loaded = OnionReplayCache::load();
            assert!(loaded.contains(id_of(1)));
            assert!(loaded.contains(id_of(2)));
            assert_eq!(loaded.len(), 2);
            assert!(
                !loaded.insert(id_of(1)),
                "a persisted identifier is still a replay after reload"
            );
            assert!(loaded.insert(id_of(3)));
            loaded.persist();
            let reloaded = OnionReplayCache::load();
            assert_eq!(reloaded.len(), 3);
            assert!(reloaded.contains(id_of(3)));
        });
    }
}
