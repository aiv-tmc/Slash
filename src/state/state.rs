//! The `State` aggregate: layout, construction, and read-only accessors.
//!
//! Everything the state engine needs to answer "who owns this cell, and
//! may it move" lives here: the dirty-page map with lazy pristine
//! reconstruction, the two lock maps, the incremental balance cache, and
//! the economic parameters consensus reads on every block. The lock maps
//! are one-to-one mirrors — the expiry map records until when a lock
//! binds spending, and the creation map records at which height the lock
//! was registered, so governance can weigh only the locks that already
//! existed at a proposal's snapshot height. The mutation primitives live
//! in the sibling files: minting in `minting.rs`, lock maintenance in
//! `locks.rs`, the transfer pipeline in `transfer.rs`, fee sweeps in
//! `fees.rs`, and canonical selection in `selection.rs`.

use super::page::{Page, R};
use super::params::{page_id, page_offset, page_size, PAGE_SIZE, TREASURY};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashMap};

/// The full ledger state: dirty pages, the lock maps, the incremental
/// balance cache, and the economic parameters that consensus reads on
/// every block.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct State {
    /// Materialized (dirty) pages keyed by page id. Pristine pages are
    /// absent and are reconstructed as a single treasury range on demand.
    pub pages: BTreeMap<u16, Page>,
    /// Locked cells keyed by global index; the value is the first height
    /// at which the cell becomes spendable again. A sorted map so the
    /// unlocked selection can jump over locked runs in one step.
    pub locks: BTreeMap<u64, u64>,
    /// Lock creation heights keyed by global index, mirroring the expiry
    /// map one entry per locked cell. Governance weight counts a locked
    /// cell only when its creation height is not above the proposal
    /// snapshot, which pins voting weight to the state at proposal
    /// submission: cells locked inside the voting window buy no influence
    /// on the proposal already open.
    pub lock_created: BTreeMap<u64, u64>,
    /// Incremental balance cache: owner to total cells. The std HashMap
    /// is deliberate: storage.rs Header carries the same type, and both
    /// are serialized with bincode, so the in-memory and on-disk layouts
    /// agree.
    pub balance_cache: HashMap<[u8; 32], u64>,
    /// Ed25519 public key of the treasury signer. Every non-coinbase
    /// treasury transaction must verify against this key; an all-zero
    /// key disables treasury spending entirely.
    pub treasury_signer: [u8; 32],
    /// Total cells sold by the treasury on the bonding curve.
    pub total_sold: u64,
    /// Total cells bought back by the treasury.
    pub total_bought_back: u64,
    /// Ed25519 public key of the dev fund signer. Spends from DEV_FUND
    /// must verify against this key; an all-zero key disables dev fund
    /// spending.
    pub dev_fund_signer: [u8; 32],
    /// Dev-fund share of user transaction outputs, in basis points. Zero
    /// means the requirement is switched off entirely; positive values
    /// are enforced only while the DevFund deployment is active.
    pub dev_fee_bps: u64,
    /// Dev-fund share of the coinbase subsidy, in basis points.
    pub mine_fee_bps: u64,
    /// On-chain governance bookkeeping: proposals, votes, and schedules.
    pub dao: crate::dao::DaoState,
}

impl State {
    /// A fresh ledger: no materialized pages, no locks, and an empty
    /// balance cache. The cache is filled lazily — the first mint,
    /// transfer, or fee claim creates its entries — and an untouched
    /// address, including the treasury, reports a zero balance. Signer
    /// keys are zero so that neither treasury nor dev-fund spending is
    /// possible until keys are configured, and the dev-fund shares start
    /// at zero so nothing is required before governance activates the
    /// rule.
    pub fn genesis() -> Self {
        Self {
            pages: BTreeMap::new(),
            locks: BTreeMap::new(),
            lock_created: BTreeMap::new(),
            balance_cache: HashMap::new(),
            treasury_signer: [0u8; 32],
            total_sold: 0,
            total_bought_back: 0,
            dev_fund_signer: [0u8; 32],
            dev_fee_bps: 0,
            mine_fee_bps: 100,
            dao: crate::dao::DaoState::genesis(),
        }
    }

    /// Read the owner of the range containing the global cell index.
    /// Returns (page_id, offset_within_page, owner), reconstructing
    /// pristine pages as a single treasury range.
    pub fn get(&self, cell: u64) -> Option<(u16, u64, [u8; 32])> {
        let id = page_id(cell);
        let off = page_offset(cell);
        if let Some(page) = self.pages.get(&id) {
            let r = page.ranges.range(..=off).next_back()?;
            if off < r.1.e {
                return Some((id, off, r.1.o));
            }
            None
        } else if off < page_size(id) {
            Some((id, off, TREASURY))
        } else {
            None
        }
    }

    /// Ownership and lock check over a global half-open span. Returns
    /// true only when every cell in `[start, end)` is owned by `owner`
    /// and no cell in the span is locked beyond `height`.
    ///
    /// The lock scan covers the entire queried span on every ownership
    /// segment, not just the segment entry point: the ownership map
    /// compacts adjacent ranges through merging, and a lock registered in
    /// the interior of a merged range must still block a spend that
    /// covers it.
    pub(crate) fn owns(&self, owner: [u8; 32], start: u64, end: u64, height: u64) -> bool {
        let mut cur = start;
        while cur < end {
            let Some((id, off, o)) = self.get(cur) else {
                return false;
            };
            if o != owner {
                return false;
            }
            // Advance to the exclusive end of the range that contains
            // `cur`.
            let range_end = match self.pages.get(&id) {
                Some(page) => {
                    let r = page
                        .ranges
                        .range(..=off)
                        .next_back()
                        .map(|(_, r)| r.e)
                        .unwrap_or(off + 1);
                    id as u64 * PAGE_SIZE + r
                }
                None => (id as u64 + 1) * PAGE_SIZE,
            };
            // Inspect every lock inside this ownership segment, capped at
            // the query end. A single live lock anywhere in the segment
            // rejects the spend, no matter where the lock sits relative
            // to merged range boundaries; expired locks never block.
            let seg_end = range_end.min(end);
            for (_, &until) in self.locks.range(cur..seg_end) {
                if until > height {
                    return false;
                }
            }
            cur = seg_end.max(cur + 1);
        }
        true
    }

    /// Materialize a page (pristine reconstruction when absent) and
    /// return an owned copy. The page is NOT inserted into the dirty map.
    pub fn get_page(&self, id: u16) -> Page {
        if let Some(p) = self.pages.get(&id) {
            p.clone()
        } else {
            let mut p = Page {
                ranges: BTreeMap::new(),
            };
            p.ranges.insert(
                0,
                R {
                    e: page_size(id),
                    o: TREASURY,
                },
            );
            p
        }
    }

    /// Materialize and insert a page into the dirty map, returning a
    /// mutable reference. Every mutation path goes through here so a
    /// dirty page always exists before any range surgery.
    pub fn get_page_mut(&mut self, id: u16) -> &mut Page {
        self.pages.entry(id).or_insert_with(|| {
            let mut p = Page {
                ranges: BTreeMap::new(),
            };
            p.ranges.insert(
                0,
                R {
                    e: page_size(id),
                    o: TREASURY,
                },
            );
            p
        })
    }

    /// Drop a dirty page that has returned to a single pristine treasury
    /// range; the implicit state carries the identical commitment, so
    /// the page no longer needs storage.
    pub fn evict_if_pristine(&mut self, id: u16) {
        if let Some(page) = self.pages.get(&id) {
            if page.ranges.len() == 1 {
                if let Some((&s, r)) = page.ranges.iter().next() {
                    if s == 0 && r.o == TREASURY && r.e == page_size(id) {
                        self.pages.remove(&id);
                    }
                }
            }
        }
    }

    /// Balance of an address from the incremental cache. Untouched
    /// addresses report zero; the cache is updated by the same commit
    /// that publishes staged pages, so a balance always matches the page
    /// map exactly.
    pub fn balance(&self, who: [u8; 32]) -> u64 {
        self.balance_cache.get(&who).copied().unwrap_or(0)
    }

    /// The global root: blake3 over every page id paired with its root,
    /// with pristine pages contributing their implicit commitment. The
    /// iteration order of the BTreeMap is deterministic, so the root is a
    /// pure function of the state.
    pub fn global_root(&self) -> [u8; 32] {
        let mut h = blake3::Hasher::new();
        for id in 0..super::params::page_count() {
            let root = match self.pages.get(&id) {
                Some(page) => page.merkle_root(),
                None => Page::pristine_root(page_size(id)),
            };
            h.update(&id.to_le_bytes());
            h.update(&root);
        }
        *h.finalize().as_bytes()
    }
}
