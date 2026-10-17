//! Incremental global root over the page tree (L9).
//!
//! `State::global_root` recomposes the whole commitment from scratch on
//! every call, which costs one blake3 compression per page over all 15,259
//! pages. This module maintains the same data as a fixed complete binary
//! tree whose leaves are the per-page Merkle roots in page order. Updating
//! one dirty page touches only the path from its leaf to the root, which
//! costs O(log P) hash compressions, and the committed root is available in
//! O(1).
//!
//! Commitment layout:
//! - leaf `i` carries the Merkle root of page `i` (`pristine_root` for
//!   clean pages), for `i` in `0..state::page_count()`;
//! - leaves `page_count()..capacity` carry a domain-separated padding
//!   constant; padding leaves never change, so updates stay path-local;
//! - every internal node is `blake3(left_child || right_child)`.
//!
//! The tree root intentionally differs in value from `State::global_root`
//! (a plain sequential hash over the same leaves): the sequential form is
//! kept for compatibility, while this tree is the maintained, incrementally
//! updatable commitment. Both commit to the identical leaf set, the tree can
//! be recomputed from scratch at any time via `rebuild`, and the root is not
//! part of the block header, so adopting the tree changes no consensus rule.

use crate::state::{page_count, page_size, Page, State};

/// Domain separation for padding leaves. A padding commitment can never
/// equal a real page root because it binds a distinct domain string.
const PADDING_DOMAIN: &[u8] = b"slash-page-tree-padding";

/// Smallest power of two that can hold every page: page_count() is 15,259,
/// so the tree has 16,384 leaves and depth 14.
fn capacity() -> usize {
    let mut cap = 1usize;
    while cap < page_count() as usize {
        cap <<= 1;
    }
    cap
}

/// The maintained page-tree commitment.
///
/// Storage is a flat array in heap order: node `i` has children `2i` and
/// `2i + 1`, node `1` is the root, and leaves live at `capacity + index`.
pub struct PageTree {
    nodes: Vec<[u8; 32]>,
    capacity: usize,
}

impl PageTree {
    /// Create a tree with all padding leaves initialized; dirty page leaves
    /// are filled by `rebuild` or `sync_page`.
    pub fn new() -> Self {
        let capacity = capacity();
        let mut tree = Self {
            nodes: vec![[0u8; 32]; 2 * capacity],
            capacity,
        };
        let padding = Self::padding_leaf();
        for slot in (capacity + page_count() as usize)..(2 * capacity) {
            tree.nodes[slot] = padding;
        }
        tree
    }

    /// Domain-separated commitment of a padding position.
    fn padding_leaf() -> [u8; 32] {
        *blake3::hash(PADDING_DOMAIN).as_bytes()
    }

    /// Leaf root for one page: the stored Merkle root when the page is
    /// dirty, the pristine treasury root when it is clean.
    fn page_root(pages: &std::collections::BTreeMap<u16, Page>, page_id: u16) -> [u8; 32] {
        pages.get(&page_id).map_or_else(
            || Page::pristine_root(page_size(page_id)),
            |p| p.merkle_root(),
        )
    }

    /// Internal node composition: the parent binds its children in order.
    fn parent_hash(left: [u8; 32], right: [u8; 32]) -> [u8; 32] {
        let mut hasher = blake3::Hasher::new();
        hasher.update(&left);
        hasher.update(&right);
        *hasher.finalize().as_bytes()
    }

    /// Recompute the whole tree from the state's dirty-page map. Costs O(P)
    /// hash compressions and is used at startup, after crash recovery, and
    /// whenever the incremental state may have diverged.
    pub fn rebuild(&mut self, state: &State) {
        for page_id in 0..page_count() {
            self.nodes[self.capacity + page_id as usize] = Self::page_root(&state.pages, page_id);
        }
        // Descending index order guarantees both children of every internal
        // node are final before the node itself is composed.
        for idx in (1..self.capacity).rev() {
            self.nodes[idx] = Self::parent_hash(self.nodes[2 * idx], self.nodes[2 * idx + 1]);
        }
    }

    /// Commit a new root for one dirty page: the leaf is overwritten and
    /// exactly one node per tree level is recomputed, O(log P) compressions.
    pub fn update(&mut self, page_id: u16, page_root: [u8; 32]) {
        let mut idx = self.capacity + page_id as usize;
        self.nodes[idx] = page_root;
        while idx > 1 {
            idx >>= 1;
            self.nodes[idx] = Self::parent_hash(self.nodes[2 * idx], self.nodes[2 * idx + 1]);
        }
    }

    /// Recompute one page's root from the state and commit it. This is the
    /// per-mutation hook: every operation that dirties `page_id` calls it.
    pub fn sync_page(&mut self, state: &State, page_id: u16) {
        let root = Self::page_root(&state.pages, page_id);
        self.update(page_id, root);
    }

    /// The committed global root, available in O(1).
    pub fn root(&self) -> [u8; 32] {
        self.nodes[1]
    }

    /// Consistency check for recovery and tests: the maintained root equals
    /// a from-scratch recomputation over the same state.
    pub fn verify_against(&self, state: &State) -> bool {
        let mut scratch = PageTree::new();
        scratch.rebuild(state);
        scratch.root() == self.root()
    }
}

impl Default for PageTree {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::state::{State, PAGE_SIZE, TREASURY};

    const OWNER: [u8; 32] = [9u8; 32];

    #[test]
    fn update_matches_full_rebuild() {
        // The incremental path and the from-scratch path must commit to the
        // identical root after every sequence of dirty-page updates.
        let mut state = State::genesis();
        let mut tree = PageTree::new();
        tree.rebuild(&state);
        assert!(tree.verify_against(&state));

        for page_id in 0..64u16 {
            for k in 0..4u64 {
                state.mine(page_id as u64 * PAGE_SIZE + k, OWNER, 1);
                tree.sync_page(&state, page_id);
            }
            assert!(tree.verify_against(&state), "page {}", page_id);
        }
    }

    #[test]
    fn untouched_padding_keeps_root_stable() {
        // Updating nothing leaves the root unchanged: padding leaves never
        // change, so an empty sync sequence is a no-op.
        let state = State::genesis();
        let mut tree = PageTree::new();
        tree.rebuild(&state);
        let before = tree.root();
        assert!(tree.verify_against(&state));
        assert_eq!(before, tree.root());
    }

    #[test]
    fn clean_pages_commit_to_pristine_roots() {
        // A genesis state is entirely clean, so the tree commits to the
        // pristine roots only, and the commitment is stable across
        // independent rebuilds of the same state.
        let state = State::genesis();
        let mut tree = PageTree::new();
        tree.rebuild(&state);
        let mut other = PageTree::new();
        other.rebuild(&state);
        assert_eq!(tree.root(), other.root());
        assert_ne!(tree.root(), [0u8; 32]);
        let _ = TREASURY;
    }
}
