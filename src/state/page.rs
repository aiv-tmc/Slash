//! The materialized page: a gapless, sorted range map with its Merkle tree.
//!
//! A page stores ownership as a map from range start offset to the range
//! data (exclusive end and owner). The invariants — non-empty map, sorted
//! gapless non-overlapping ranges, eager merging of same-owner neighbours —
//! are enforced by every mutation path, so the Merkle commitment over the
//! range leaves always reflects a well-formed ownership function.

use super::params::TREASURY;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// One ownership range inside a page. Field names are single letters to
/// keep the bincode storage format compact; the range start is the map key.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct R {
    /// Exclusive end offset within the page.
    pub e: u64,
    /// Owner of every cell in [start, end).
    pub o: [u8; 32],
}

/// An output assigns a global cell range to a recipient, optionally locked
/// until a height. Field names are short for the same storage-format reason
/// as R.
#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct Output {
    /// Global start cell index (inclusive).
    pub start: u64,
    /// Global end cell index (exclusive).
    pub end: u64,
    /// Recipient address.
    pub to: [u8; 32],
    /// Optional lock height: the cells are unspendable until this absolute
    /// height. None means immediately spendable.
    pub lock: Option<u64>,
}

/// A materialized page with its ownership ranges. Invariants, enforced by
/// every mutation path:
/// - the range map is non-empty for a materialized page
/// - keys are sorted; ranges are gapless and non-overlapping
/// - adjacent ranges always have different owners (eager merge)
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Page {
    /// Map from range start offset to range data. The end offset lives in
    /// the value so bincode keeps the on-disk form compact.
    pub ranges: BTreeMap<u64, R>,
}

impl Page {
    /// The Merkle root of a page's implicit pristine state: a single range
    /// [0, size) owned by the treasury. This is exactly the commitment that
    /// materializing the page and hashing it through `merkle_root` would
    /// produce, so dirty-page eviction restores the identical root without
    /// storing anything on disk, and the global root can commit to pristine
    /// pages at zero storage cost.
    pub fn pristine_root(size: u64) -> [u8; 32] {
        let mut h = blake3::Hasher::new();
        h.update(&0u64.to_le_bytes());
        h.update(&size.to_le_bytes());
        h.update(&TREASURY);
        *h.finalize().as_bytes()
    }

    /// Hash one leaf of the page tree: blake3(start || end || owner).
    fn leaf_hash(start: u64, end: u64, owner: &[u8; 32]) -> [u8; 32] {
        let mut h = blake3::Hasher::new();
        h.update(&start.to_le_bytes());
        h.update(&end.to_le_bytes());
        h.update(owner);
        *h.finalize().as_bytes()
    }

    /// The Merkle root of this page's range leaves. Panics on an empty
    /// range map: a materialized page must always carry at least one range,
    /// and hashing an empty map would silently root a wrong implicit page.
    pub fn merkle_root(&self) -> [u8; 32] {
        if self.ranges.is_empty() {
            panic!("merkle_root of an empty page");
        }
        let leaves: Vec<[u8; 32]> = self
            .ranges
            .iter()
            .map(|(&s, r)| Self::leaf_hash(s, r.e, &r.o))
            .collect();
        Self::merkle_root_of_leaves(&leaves)
    }

    /// Compute the Merkle root from a pre-hashed leaf list, duplicating the
    /// final leaf whenever a level has odd length so the tree shape is fully
    /// determined by the leaf count alone.
    fn merkle_root_of_leaves(leaves: &[[u8; 32]]) -> [u8; 32] {
        if leaves.is_empty() {
            panic!("merkle_root of an empty leaf list");
        }
        if leaves.len() == 1 {
            return leaves[0];
        }
        let mut level: Vec<[u8; 32]> = leaves.to_vec();
        while level.len() > 1 {
            let mut next = Vec::with_capacity(level.len().div_ceil(2));
            for chunk in level.chunks(2) {
                let mut h = blake3::Hasher::new();
                h.update(&chunk[0]);
                if chunk.len() == 2 {
                    h.update(&chunk[1]);
                } else {
                    h.update(&chunk[0]);
                }
                next.push(*h.finalize().as_bytes());
            }
            level = next;
        }
        level[0]
    }

    /// Build a Merkle proof for the range containing the given page-local
    /// offset. Returns None when the offset is outside every range, which
    /// for the final page also covers offsets beyond its shortened span.
    pub fn merkle_proof(&self, offset: u64) -> Option<PageProof> {
        let (&range_start, range) = self.ranges.range(..=offset).next_back()?;
        if offset >= range.e {
            return None;
        }
        let leaf_index = self
            .ranges
            .keys()
            .position(|k| *k == range_start)
            .expect("range came from the map");
        let leaves: Vec<[u8; 32]> = self
            .ranges
            .iter()
            .map(|(&s, r)| Self::leaf_hash(s, r.e, &r.o))
            .collect();
        // Recompute the leaf hash explicitly so the proof is self-contained
        // even if the leaf list construction ever changes.
        let mut leaf_hasher = blake3::Hasher::new();
        leaf_hasher.update(&range_start.to_le_bytes());
        leaf_hasher.update(&range.e.to_le_bytes());
        leaf_hasher.update(&range.o);
        let leaf_hash = *leaf_hasher.finalize().as_bytes();
        let mut siblings = Vec::new();
        let mut idx = leaf_index;
        let mut level: Vec<[u8; 32]> = leaves;
        while level.len() > 1 {
            let sibling = if idx.is_multiple_of(2) {
                // Even index: sibling is the right neighbour, or the leaf
                // itself when the level has an odd length (duplicated
                // leaf); the last leaf of an odd level has no right
                // neighbour in the vector.
                *level.get(idx + 1).unwrap_or(&level[idx])
            } else {
                level[idx - 1]
            };
            siblings.push(sibling);
            let mut next = Vec::with_capacity(level.len().div_ceil(2));
            for chunk in level.chunks(2) {
                let mut h = blake3::Hasher::new();
                h.update(&chunk[0]);
                if chunk.len() == 2 {
                    h.update(&chunk[1]);
                } else {
                    h.update(&chunk[0]);
                }
                next.push(*h.finalize().as_bytes());
            }
            idx /= 2;
            level = next;
        }
        Some(PageProof {
            leaf_hash,
            siblings,
            leaf_index,
        })
    }

    /// Insert [start, end) owned by `owner`, merging with adjacent ranges of
    /// the same owner. The caller guarantees the span is currently free, so
    /// the insert can never create an overlap.
    pub fn insert_output(&mut self, start: u64, end: u64, owner: [u8; 32]) {
        self.ranges.insert(start, R { e: end, o: owner });
        self.merge_at(start);
    }

    /// Merge the range at `at` with same-owner neighbours on both sides.
    /// Keeps the map gapless with distinct adjacent owners; called after
    /// every insert so merges stay local and cheap.
    fn merge_at(&mut self, at: u64) {
        // Merge left.
        if let Some((&ps, pr)) = self.ranges.range(..at).next_back() {
            if pr.o == self.ranges[&at].o && pr.e == at {
                let end = self.ranges[&at].e;
                self.ranges.insert(ps, R { e: end, o: pr.o });
                self.ranges.remove(&at);
            }
        }
        // Merge right, locating the current key again because a left merge
        // may have re-keyed it.
        let cur = *self.ranges.range(..=at).next_back().unwrap().0;
        if let Some((&ns, nr)) = self.ranges.range(cur..).nth(1) {
            if nr.o == self.ranges[&cur].o && ns == self.ranges[&cur].e {
                let end = nr.e;
                self.ranges.insert(cur, R { e: end, o: nr.o });
                self.ranges.remove(&ns);
            }
        }
    }

    /// Owner of the range containing the page-local offset, if any.
    pub fn owner_of(&self, offset: u64) -> Option<[u8; 32]> {
        let (_, r) = self.ranges.range(..=offset).next_back()?;
        if offset < r.e {
            Some(r.o)
        } else {
            None
        }
    }

    /// Remove [start, end) from the range map. Every crossed range must be
    /// owned by the same party; the caller verifies ownership before
    /// invoking this through remove_for_spend. Boundary ranges keep their
    /// surviving head and tail, with the tail re-keyed at the removal end,
    /// so the map stays gapless. Returns false — leaving the map untouched —
    /// when the span is not covered by one contiguous run of ranges.
    pub fn remove_range(&mut self, start: u64, end: u64) -> bool {
        // Snapshot every overlapped range so a refusal restores exact keys.
        let mut affected: Vec<(u64, R)> = Vec::new();
        for (&s, r) in self.ranges.range(..end) {
            if r.e > start {
                affected.push((s, r.clone()));
            }
        }
        if affected.is_empty() {
            return false;
        }
        // Contiguity: the first overlapped range must begin at or before
        // `start`, each following range must begin exactly where the
        // previous ended, and the last must reach at least `end`.
        if affected[0].0 > start {
            return false;
        }
        for w in affected.windows(2) {
            if w[1].0 != w[0].1.e {
                return false;
            }
        }
        let last = affected.last().unwrap().clone();
        if last.1.e < end {
            return false;
        }
        for &(s, _) in &affected {
            self.ranges.remove(&s);
        }
        let head_owner = affected[0].1.o;
        if affected[0].0 < start {
            self.ranges.insert(
                affected[0].0,
                R {
                    e: start,
                    o: head_owner,
                },
            );
        }
        if last.1.e > end {
            self.ranges.insert(
                end,
                R {
                    e: last.1.e,
                    o: last.1.o,
                },
            );
        }
        true
    }
}

/// A Merkle proof for one leaf of a page tree.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PageProof {
    /// Leaf hash: blake3(start || end || owner).
    pub leaf_hash: [u8; 32],
    /// Sibling hashes from the leaf up to the root.
    pub siblings: Vec<[u8; 32]>,
    /// Position of the leaf in the sorted range list.
    pub leaf_index: usize,
}

/// Verify a page proof against a claimed root. Each step orders the pair by
/// the running index parity, exactly mirroring how the tree was built.
pub fn verify_page_proof(root: &[u8; 32], proof: &PageProof) -> bool {
    let mut hash = proof.leaf_hash;
    let mut idx = proof.leaf_index;
    for sibling in &proof.siblings {
        let mut h = blake3::Hasher::new();
        if idx.is_multiple_of(2) {
            h.update(&hash);
            h.update(sibling);
        } else {
            h.update(sibling);
            h.update(&hash);
        }
        hash = *h.finalize().as_bytes();
        idx /= 2;
    }
    hash == *root
}
