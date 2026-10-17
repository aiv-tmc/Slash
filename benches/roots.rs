//! Global-root benchmarks: the full recomputation over a dirty ledger and
//! the incremental page-tree update against the sequential recomposition
//! over an identical mutation pattern.

use criterion::{black_box, Criterion};

/// Benchmark the global root over a ledger with 1024 dirty pages. The root
/// commits to every page in index order (Merkle roots for dirty pages,
/// pristine constants for clean pages) and is the reference composition for
/// full-state verification.
pub fn bench_global_root(c: &mut Criterion) {
    let mut state = slash::state::State::genesis();
    let owner = [1u8; 32];

    // Dirty 1024 distinct pages, one cell each, scattered across the ledger.
    for i in 0..1024u64 {
        state.mine(i * slash::state::PAGE_SIZE, owner, 0);
    }

    c.bench_function("global_root_1024_dirty_pages", |b| {
        b.iter(|| {
            black_box(state.global_root());
        });
    });
}

/// Benchmark the incremental page-tree commitment (L9) against the full
/// sequential recomposition over an identical mutation pattern. Both paths
/// dirty exactly one fresh cell per iteration in a rotating page, so the
/// comparison isolates the commitment update strategy: O(log P) hash
/// compressions along one root-to-leaf path versus an O(P) recomposition
/// over every page in the ledger.
pub fn bench_global_root_incremental(c: &mut Criterion) {
    let owner = [1u8; 32];

    // Dirty 1024 distinct pages up front, matching the working set of the
    // full-recomposition benchmark above.
    let mut state = slash::state::State::genesis();
    for i in 0..1024u64 {
        state.mine(i * slash::state::PAGE_SIZE, owner, 0);
    }

    let mut tree = slash::global_root::PageTree::new();
    tree.rebuild(&state);
    // The maintained tree must commit to the identical root as a
    // from-scratch recomputation before any measured mutation happens.
    assert!(tree.verify_against(&state));

    // Each iteration mines one fresh cell in a rotating page and commits the
    // page's new root through the tree, so every update walks a full
    // leaf-to-root path over the 14 tree levels.
    let mut i: u64 = 0;
    c.bench_function("page_tree_update_per_dirty_page", |b| {
        b.iter(|| {
            let page_id = ((i / 8) % 1024) as u16;
            let cell = page_id as u64 * slash::state::PAGE_SIZE + 8 + (i % 8);
            state.mine(cell, owner, 0);
            tree.sync_page(&state, page_id);
            black_box(tree.root());
            i += 1;
        });
    });

    // Full sequential recomposition over the same mutation pattern, kept in
    // a separate state clone so the two benches do not interfere.
    let mut full_state = state.clone();
    let mut j: u64 = 0;
    c.bench_function("sequential_recompose_per_dirty_page", |b| {
        b.iter(|| {
            let page_id = ((j / 8) % 1024) as u16;
            let cell = page_id as u64 * slash::state::PAGE_SIZE + 8 + (j % 8);
            full_state.mine(cell, owner, 0);
            black_box(full_state.global_root());
            j += 1;
        });
    });
}
