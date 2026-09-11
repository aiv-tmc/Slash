use std::collections::{BTreeMap, HashMap};

/// Number of cells per page. Must be a power of two for cheap division.
pub const PAGE_SIZE: u64 = 65_536; // 2^16
/// Total cells in the global ledger.
pub const N: u64 = 1_000_000_000;
/// Minimum cells that must move in one transaction.
pub const MIN: u64 = 50;
/// The treasury owns all unissued cells.
pub const TREASURY: [u8; 32] = [0; 32];
/// Address that collects priority fees for miners to claim in blocks.
pub const FEE_VAULT: [u8; 32] = [1u8; 32];

/// One contiguous range inside a single page.
/// PartialEq and Eq are derived so that Page structures can be compared
/// in tests and assertions that verify atomic rollback behaviour.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
pub struct R {
    /// Exclusive end offset inside the page.
    pub e: u64,
    /// Owner public key.
    pub o: [u8; 32],
}

/// A page holds all dirty ranges for one 64-KiB slice of the global state.
/// PartialEq and Eq are required because State stores pages in a BTreeMap
/// that is compared with assert_eq! during transaction rollback tests.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
pub struct Page {
    pub ranges: BTreeMap<u64, R>,
}

/// Global transaction output.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
pub struct Output {
    pub start: u64,
    pub end: u64,
    pub to: [u8; 32],
    /// If set, every cell in this output is locked until the given block height.
    pub lock: Option<u64>,
}

/// Proof that a specific cell belongs to a page with the given Merkle root.
/// The light client walks from the leaf hash up to the root using the sibling path.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct PageProof {
    /// Blake3 hash of the leaf range (start || end || owner).
    pub leaf_hash: [u8; 32],
    /// Sibling hashes from the leaf level up to the root.
    pub siblings: Vec<[u8; 32]>,
    /// Zero-based index of the leaf among all ranges in the page.
    pub leaf_index: usize,
}

/// Paged Multi-Input State.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct State {
    /// Only dirty pages are stored here. Clean pages are lazily treated as fully treasury-owned.
    pub pages: BTreeMap<u16, Page>,
    /// Cell -> block height at which the lock expires.
    pub locks: BTreeMap<u64, u64>,
    /// O(1) balance cache. Updated incrementally by mine() and tx().
    pub balance_cache: HashMap<[u8; 32], u64>,
}

/// Inputs and outputs of a transaction grouped by page, in page-local coordinates.
type PageOps = BTreeMap<u16, (Vec<(u64, u64)>, Vec<Output>)>;

/// Compute the blake3 hash of a single leaf range.
fn leaf_hash(start: u64, end: u64, owner: &[u8; 32]) -> [u8; 32] {
    let mut h = blake3::Hasher::new();
    h.update(&start.to_le_bytes());
    h.update(&end.to_le_bytes());
    h.update(owner);
    *h.finalize().as_bytes()
}

/// Verify a PageProof against a claimed Merkle root.
/// Reconstructs the root by hashing the leaf with its siblings level by level.
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

impl Page {
    /// Look up the local range containing offset `i`.
    fn get(&self, i: u64) -> Option<(u64, u64, [u8; 32])> {
        let (&s, r) = self.ranges.range(..=i).next_back()?;
        if i < r.e {
            Some((s, r.e, r.o))
        } else {
            None
        }
    }

    /// Claim one cell inside this page for `owner`.
    fn mine(&mut self, i: u64, owner: [u8; 32]) {
        let (s, e, old_owner) = self.get(i).unwrap();
        if old_owner == owner {
            return;
        }
        self.ranges.remove(&s);
        if s < i {
            self.ranges.insert(s, R { e: i, o: old_owner });
        }
        self.ranges.insert(i, R { e: i + 1, o: owner });
        if i + 1 < e {
            self.ranges.insert(i + 1, R { e, o: old_owner });
        }
        self.merge(s);
        self.merge(i);
        self.merge(i + 1);
    }

    /// Merge neighbours of `s` when they share the same owner.
    fn merge(&mut self, s: u64) {
        let ra = self.ranges.get(&s).cloned();
        if let Some(ra) = ra {
            if let Some((&b, rb)) = self.ranges.range(..s).next_back() {
                if rb.o == ra.o && rb.e == s {
                    self.ranges.remove(&s);
                    self.ranges.insert(b, R { e: ra.e, o: ra.o });
                }
            }
        }
        let ra2 = self.ranges.get(&s).cloned();
        if let Some(ra2) = ra2 {
            if let Some((&c, rc)) = self.ranges.range(s + 1..).next() {
                if ra2.o == rc.o && ra2.e == c {
                    let rc_e = rc.e;
                    self.ranges.remove(&c);
                    self.ranges.insert(s, R { e: rc_e, o: ra2.o });
                }
            }
        }
    }

    /// Remove a sub-range [start, end) from this page, verifying that every touched cell belongs to `owner`.
    /// Left-over fragments on both sides are returned to `owner`.
    fn remove_range(&mut self, start: u64, end: u64, owner: [u8; 32]) -> bool {
        if start >= end {
            return false;
        }
        let mut affected = Vec::new();
        let mut cur = start;
        while cur < end {
            let (s, e, o) = match self.get(cur) {
                Some(x) => x,
                None => return false,
            };
            if o != owner {
                return false;
            }
            affected.push((s, e));
            cur = e;
        }
        for (s, _) in &affected {
            self.ranges.remove(s);
        }
        let first = affected[0].0;
        let last = affected[affected.len() - 1].1;
        if first < start {
            self.ranges.insert(first, R { e: start, o: owner });
        }
        if end < last {
            self.ranges.insert(end, R { e: last, o: owner });
        }
        true
    }

    /// Insert outputs (page-local coordinates) and merge neighbours.
    fn insert_outputs(&mut self, outputs: &[Output]) {
        for o in outputs {
            self.ranges.insert(o.start, R { e: o.end, o: o.to });
        }
        for o in outputs {
            self.merge(o.start);
            self.merge(o.end);
        }
    }

    /// Returns true when the page consists of exactly one range [0, page_size)
    /// owned by the treasury. Such a page is identical to the lazy default
    /// and does not need to be stored in memory or on disk.
    fn is_pristine(&self, page_size: u64) -> bool {
        if self.ranges.len() != 1 {
            return false;
        }
        let (start, r) = self.ranges.iter().next().unwrap();
        *start == 0 && r.e == page_size && r.o == TREASURY
    }

    /// Compute the Merkle root of all ranges in this page.
    /// Each leaf is the blake3 hash of (start || end || owner).
    /// The tree is built bottom-up with blake3(left || right).
    /// If there is an odd number of leaves at any level, the last leaf is duplicated.
    pub fn merkle_root(&self) -> [u8; 32] {
        if self.ranges.is_empty() {
            return [0u8; 32];
        }
        let mut leaves: Vec<[u8; 32]> = self
            .ranges
            .iter()
            .map(|(s, r)| leaf_hash(*s, r.e, &r.o))
            .collect();
        while leaves.len() > 1 {
            let mut next = Vec::new();
            for chunk in leaves.chunks(2) {
                let mut h = blake3::Hasher::new();
                h.update(&chunk[0]);
                if chunk.len() == 2 {
                    h.update(&chunk[1]);
                } else {
                    h.update(&chunk[0]);
                }
                next.push(*h.finalize().as_bytes());
            }
            leaves = next;
        }
        leaves[0]
    }

    /// Build a Merkle proof for the range that contains `offset`.
    /// Returns None if `offset` is outside every range in the page.
    pub fn merkle_proof(&self, offset: u64) -> Option<PageProof> {
        let ranges_vec: Vec<(u64, &R)> = self.ranges.iter().map(|(s, r)| (*s, r)).collect();
        let mut leaf_idx = None;
        for (i, (s, r)) in ranges_vec.iter().enumerate() {
            if offset >= *s && offset < r.e {
                leaf_idx = Some(i);
                break;
            }
        }
        let leaf_idx = leaf_idx?;
        let mut leaves: Vec<[u8; 32]> = ranges_vec
            .iter()
            .map(|(s, r)| leaf_hash(*s, r.e, &r.o))
            .collect();
        let mut siblings = Vec::new();
        let mut idx = leaf_idx;
        while leaves.len() > 1 {
            let mut next = Vec::new();
            // Hash pairs of leaves to form the next level of the tree.
            // When there is an odd number of leaves the last one is duplicated,
            // matching the construction used by `merkle_root`.
            for chunk in leaves.chunks(2) {
                let mut h = blake3::Hasher::new();
                h.update(&chunk[0]);
                if chunk.len() == 2 {
                    h.update(&chunk[1]);
                } else {
                    h.update(&chunk[0]);
                }
                next.push(*h.finalize().as_bytes());
            }
            // Determine the sibling of the target leaf at the current level.
            // If the target is the last element and the level length is odd,
            // the sibling is itself (the leaf is promoted with a self-hash).
            let sibling_idx = if idx % 2 == 0 {
                if idx + 1 < leaves.len() {
                    idx + 1
                } else {
                    idx
                }
            } else {
                idx - 1
            };
            siblings.push(leaves[sibling_idx]);
            idx /= 2;
            leaves = next;
        }
        let (s, r) = ranges_vec[leaf_idx];
        Some(PageProof {
            leaf_hash: leaf_hash(s, r.e, &r.o),
            siblings,
            leaf_index: leaf_idx,
        })
    }

    /// Compute the Merkle root of a pristine page consisting of a single range [0, page_size)
    /// owned by the treasury. This is a constant for any given page size.
    pub fn pristine_root(page_size: u64) -> [u8; 32] {
        leaf_hash(0, page_size, &TREASURY)
    }
}

impl State {
    /// Number of pages required to cover N cells.
    pub fn page_count() -> u64 {
        N.div_ceil(PAGE_SIZE)
    }

    /// Size of a specific page (the last page may be smaller than PAGE_SIZE).
    pub fn page_size(page_id: u16) -> u64 {
        let start = page_id as u64 * PAGE_SIZE;
        let end = ((page_id as u64 + 1) * PAGE_SIZE).min(N);
        end.saturating_sub(start)
    }

    /// Genesis state: page 0 is fully treasury-owned; balance cache reflects the full supply.
    pub fn genesis() -> Self {
        let mut pages = BTreeMap::new();
        let mut ranges = BTreeMap::new();
        ranges.insert(
            0,
            R {
                e: Self::page_size(0),
                o: TREASURY,
            },
        );
        pages.insert(0, Page { ranges });
        let mut balance_cache = HashMap::new();
        balance_cache.insert(TREASURY, N);
        Self {
            pages,
            locks: BTreeMap::new(),
            balance_cache,
        }
    }

    /// Return a clone of the requested page. If the page has never been dirtied, materialise it as fully treasury-owned.
    pub fn get_page(&self, page_id: u16) -> Page {
        self.pages.get(&page_id).cloned().unwrap_or_else(|| {
            let size = Self::page_size(page_id);
            let mut ranges = BTreeMap::new();
            if size > 0 {
                ranges.insert(
                    0,
                    R {
                        e: size,
                        o: TREASURY,
                    },
                );
            }
            Page { ranges }
        })
    }

    /// Mutable access to a page, materialising it first if it is still lazy.
    fn get_page_mut(&mut self, page_id: u16) -> &mut Page {
        self.pages.entry(page_id).or_insert_with(|| {
            let size = Self::page_size(page_id);
            let mut ranges = BTreeMap::new();
            if size > 0 {
                ranges.insert(
                    0,
                    R {
                        e: size,
                        o: TREASURY,
                    },
                );
            }
            Page { ranges }
        })
    }

    /// Remove a page from the dirty map if every cell in it is owned by the treasury.
    /// Pristine pages are reconstructed on demand, so evicting them saves memory and disk.
    fn evict_if_pristine(&mut self, page_id: u16) {
        if let Some(page) = self.pages.get(&page_id) {
            if page.is_pristine(Self::page_size(page_id)) {
                self.pages.remove(&page_id);
            }
        }
    }

    /// Look up the global range that contains cell `i`.
    pub fn get(&self, i: u64) -> Option<(u64, u64, [u8; 32])> {
        if i >= N {
            return None;
        }
        let page_id = (i / PAGE_SIZE) as u16;
        let offset = i % PAGE_SIZE;
        let page = self.get_page(page_id);
        let (s, e, o) = page.get(offset)?;
        let base = page_id as u64 * PAGE_SIZE;
        Some((s + base, e + base, o))
    }

    /// Claim a single cell for `owner`, respecting height-based locks.
    /// If the cell is locked beyond `height`, the operation is a no-op.
    pub fn mine(&mut self, cell: u64, owner: [u8; 32], height: u64) {
        if cell >= N {
            return;
        }
        // Reject the mining attempt if the target cell is still locked.
        if let Some(&until) = self.locks.get(&cell) {
            if until > height {
                return;
            }
        }
        let page_id = (cell / PAGE_SIZE) as u16;
        let offset = cell % PAGE_SIZE;

        // Determine the previous owner using an immutable clone so that
        // the mutable borrow of self.pages does not conflict with the
        // subsequent update of self.balance_cache.
        let old_owner = {
            let page = self.get_page(page_id);
            match page.get(offset) {
                Some((_, _, o)) => o,
                None => return,
            }
        };
        if old_owner == owner {
            return;
        }

        // Mutate the page and record whether it reverted to pristine state.
        let became_pristine = {
            let page = self.get_page_mut(page_id);
            page.mine(offset, owner);
            page.is_pristine(Self::page_size(page_id))
        };

        *self.balance_cache.entry(old_owner).or_insert(0) -= 1;
        *self.balance_cache.entry(owner).or_insert(0) += 1;

        if became_pristine {
            self.pages.remove(&page_id);
        }
    }

    /// Atomically validate and apply a multi-input transaction at the given block height.
    /// All checks run before any mutation. If any page fails, the whole transaction is rejected.
    /// The signature is verified against a hash that includes chain_id and scheme.
    // The seven validation parameters mirror the consensus transaction structure,
    // so the arity is inherent to the protocol rather than a design choice.
    #[allow(clippy::too_many_arguments)]
    pub fn tx(
        &mut self,
        from: [u8; 32],
        inputs: &[(u64, u64)],
        outputs: &[Output],
        sig: &[u8],
        height: u64,
        chain_id: &[u8],
        scheme: u8,
    ) -> bool {
        if inputs.is_empty() {
            return false;
        }
        let total_in: u64 = inputs.iter().map(|(s, e)| e - s).sum();
        let total_out: u64 = outputs.iter().map(|o| o.end - o.start).sum();
        if total_in != total_out {
            return false;
        }
        if total_out < MIN {
            return false;
        }

        // Signature verification (treasury transactions are unsigned).
        if from != TREASURY {
            let mut h = blake3::Hasher::new();
            h.update(&from);
            for (s, e) in inputs {
                h.update(&s.to_le_bytes());
                h.update(&e.to_le_bytes());
            }
            for o in outputs {
                h.update(&o.start.to_le_bytes());
                h.update(&o.end.to_le_bytes());
                h.update(&o.to);
                if let Some(lock) = o.lock {
                    h.update(&lock.to_le_bytes());
                }
            }
            // Include the chain identifier and scheme byte in the signed payload
            // to enforce replay protection between networks and future signature upgrades.
            h.update(chain_id);
            h.update(&[scheme]);
            if !crate::crypto::verify(&from, h.finalize().as_bytes(), sig) {
                return false;
            }
        }

        // Verify ownership and lock status of every input cell without mutating state.
        for (s, e) in inputs {
            let mut cur = *s;
            while cur < *e {
                let (_, en, owner) = match self.get(cur) {
                    Some(x) => x,
                    None => return false,
                };
                if owner != from {
                    return false;
                }
                // Reject the transaction if any input cell is locked beyond the current height.
                if let Some(&until) = self.locks.get(&cur) {
                    if until > height {
                        return false;
                    }
                }
                cur = en;
            }
        }

        // Outputs must exactly pack into the inputs in declaration order.
        let mut out_idx = 0usize;
        for (in_start, in_end) in inputs {
            let mut covered = 0u64;
            while covered < in_end - in_start {
                if out_idx >= outputs.len() {
                    return false;
                }
                let o = &outputs[out_idx];
                if o.start != in_start + covered {
                    return false;
                }
                covered += o.end - o.start;
                out_idx += 1;
            }
        }
        if out_idx != outputs.len() {
            return false;
        }

        // Group inputs and outputs by page, splitting at page boundaries.
        let mut page_ops: PageOps = BTreeMap::new();
        for (s, e) in inputs {
            let mut cur = *s;
            while cur < *e {
                let page_id = (cur / PAGE_SIZE) as u16;
                let page_end = ((page_id as u64 + 1) * PAGE_SIZE).min(*e);
                let local_start = cur - page_id as u64 * PAGE_SIZE;
                let local_end = page_end - page_id as u64 * PAGE_SIZE;
                page_ops
                    .entry(page_id)
                    .or_default()
                    .0
                    .push((local_start, local_end));
                cur = page_end;
            }
        }
        for o in outputs {
            let mut cur = o.start;
            while cur < o.end {
                let page_id = (cur / PAGE_SIZE) as u16;
                let page_end = ((page_id as u64 + 1) * PAGE_SIZE).min(o.end);
                let local_start = cur - page_id as u64 * PAGE_SIZE;
                let local_end = page_end - page_id as u64 * PAGE_SIZE;
                page_ops.entry(page_id).or_default().1.push(Output {
                    start: local_start,
                    end: local_end,
                    to: o.to,
                    lock: o.lock,
                });
                cur = page_end;
            }
        }

        // Every page must balance independently.
        for (ins, outs) in page_ops.values() {
            let in_sum: u64 = ins.iter().map(|(s, e)| e - s).sum();
            let out_sum: u64 = outs.iter().map(|o| o.end - o.start).sum();
            if in_sum != out_sum {
                return false;
            }
        }

        // Clone affected pages and apply changes speculatively.
        let mut cloned: BTreeMap<u16, Page> = BTreeMap::new();
        for page_id in page_ops.keys() {
            cloned.insert(*page_id, self.get_page(*page_id));
        }
        for (page_id, (ins, outs)) in &page_ops {
            let page = cloned.get_mut(page_id).unwrap();
            for (s, e) in ins {
                if !page.remove_range(*s, *e, from) {
                    return false;
                }
            }
            page.insert_outputs(outs);
        }

        // Commit the speculatively validated pages to the authoritative state.
        for (page_id, page) in cloned {
            self.pages.insert(page_id, page);
        }

        // Drop any pages that have returned to a single treasury-owned range.
        // This prevents unbounded growth of the dirty page set.
        for &page_id in page_ops.keys() {
            self.evict_if_pristine(page_id);
        }

        // Record any height locks declared by the outputs.
        for o in outputs {
            if let Some(until) = o.lock {
                for cell in o.start..o.end {
                    self.locks.insert(cell, until);
                }
            }
        }

        // Incremental balance update.
        *self.balance_cache.entry(from).or_insert(0) -= total_in;
        for o in outputs {
            let amount = o.end - o.start;
            *self.balance_cache.entry(o.to).or_insert(0) += amount;
        }
        true
    }

    /// O(1) balance lookup via the cache.
    pub fn balance(&self, owner: [u8; 32]) -> u64 {
        self.balance_cache.get(&owner).copied().unwrap_or(0)
    }

    /// Atomically transfer cells from FEE_VAULT to the miner as block rewards.
    /// Each claim must reference cells currently owned by FEE_VAULT and not locked.
    pub fn claim_fees(&mut self, miner: [u8; 32], claims: &[Output], height: u64) -> bool {
        if claims.is_empty() {
            return true;
        }
        // Verify every claimed cell is owned by FEE_VAULT and not locked.
        for claim in claims {
            let mut cur = claim.start;
            while cur < claim.end {
                let (_, en, owner) = match self.get(cur) {
                    Some(x) => x,
                    None => return false,
                };
                if owner != FEE_VAULT {
                    return false;
                }
                if let Some(&until) = self.locks.get(&cur) {
                    if until > height {
                        return false;
                    }
                }
                cur = en;
            }
        }
        // Group by page and apply exactly like a treasury transaction without signature.
        let mut page_ops: PageOps = BTreeMap::new();
        for claim in claims {
            let mut cur = claim.start;
            while cur < claim.end {
                let page_id = (cur / PAGE_SIZE) as u16;
                let page_end = ((page_id as u64 + 1) * PAGE_SIZE).min(claim.end);
                let local_start = cur - page_id as u64 * PAGE_SIZE;
                let local_end = page_end - page_id as u64 * PAGE_SIZE;
                page_ops
                    .entry(page_id)
                    .or_default()
                    .0
                    .push((local_start, local_end));
                cur = page_end;
            }
            let mut cur = claim.start;
            while cur < claim.end {
                let page_id = (cur / PAGE_SIZE) as u16;
                let page_end = ((page_id as u64 + 1) * PAGE_SIZE).min(claim.end);
                let local_start = cur - page_id as u64 * PAGE_SIZE;
                let local_end = page_end - page_id as u64 * PAGE_SIZE;
                page_ops.entry(page_id).or_default().1.push(Output {
                    start: local_start,
                    end: local_end,
                    to: miner,
                    lock: None,
                });
                cur = page_end;
            }
        }
        for (ins, outs) in page_ops.values() {
            let in_sum: u64 = ins.iter().map(|(s, e)| e - s).sum();
            let out_sum: u64 = outs.iter().map(|o| o.end - o.start).sum();
            if in_sum != out_sum {
                return false;
            }
        }
        let mut cloned: BTreeMap<u16, Page> = BTreeMap::new();
        for page_id in page_ops.keys() {
            cloned.insert(*page_id, self.get_page(*page_id));
        }
        for (page_id, (ins, outs)) in &page_ops {
            let page = cloned.get_mut(page_id).unwrap();
            for (s, e) in ins {
                if !page.remove_range(*s, *e, FEE_VAULT) {
                    return false;
                }
            }
            page.insert_outputs(outs);
        }
        for (page_id, page) in cloned {
            self.pages.insert(page_id, page);
        }

        // Evict any pages that returned to fully treasury-owned state.
        for &page_id in page_ops.keys() {
            self.evict_if_pristine(page_id);
        }

        let total: u64 = claims.iter().map(|c| c.end - c.start).sum();
        *self.balance_cache.entry(FEE_VAULT).or_insert(0) -= total;
        *self.balance_cache.entry(miner).or_insert(0) += total;
        true
    }

    /// Select enough fragments to cover `need` cells, possibly spanning multiple ranges and pages.
    pub fn select(&self, owner: [u8; 32], need: u64) -> Option<Vec<(u64, u64)>> {
        let mut out = Vec::new();
        let mut got = 0u64;
        // Scan materialised pages.
        for (&page_id, page) in &self.pages {
            let base = page_id as u64 * PAGE_SIZE;
            for (&s, r) in &page.ranges {
                if r.o == owner {
                    let avail = r.e - s;
                    let take = (need - got).min(avail);
                    out.push((base + s, base + s + take));
                    got += take;
                    if got >= need {
                        return Some(out);
                    }
                }
            }
        }
        // For the treasury also scan lazy pages.
        if owner == TREASURY {
            let dirty: std::collections::HashSet<u16> = self.pages.keys().cloned().collect();
            for page_id in 0..Self::page_count() as u16 {
                if dirty.contains(&page_id) {
                    continue;
                }
                let base = page_id as u64 * PAGE_SIZE;
                let size = Self::page_size(page_id);
                let take = (need - got).min(size);
                out.push((base, base + take));
                got += take;
                if got >= need {
                    return Some(out);
                }
            }
        }
        None
    }

    /// Select a single contiguous range that contains at least `need` cells.
    pub fn select_single(&self, owner: [u8; 32], need: u64) -> Option<(u64, u64)> {
        for (&page_id, page) in &self.pages {
            let base = page_id as u64 * PAGE_SIZE;
            for (&s, r) in &page.ranges {
                if r.o == owner {
                    let avail = r.e - s;
                    if avail >= need {
                        return Some((base + s, base + s + need));
                    }
                }
            }
        }
        if owner == TREASURY {
            let dirty: std::collections::HashSet<u16> = self.pages.keys().cloned().collect();
            for page_id in 0..Self::page_count() as u16 {
                if dirty.contains(&page_id) {
                    continue;
                }
                let base = page_id as u64 * PAGE_SIZE;
                let size = Self::page_size(page_id);
                if size >= need {
                    return Some((base, base + need));
                }
            }
        }
        None
    }

    /// Compute a global root that commits to every page in the ledger.
    /// For each page (dirty or clean) the hash concatenates page_id and page_root.
    pub fn global_root(&self) -> [u8; 32] {
        let mut h = blake3::Hasher::new();
        for page_id in 0..Self::page_count() as u16 {
            h.update(&page_id.to_le_bytes());
            if let Some(page) = self.pages.get(&page_id) {
                h.update(&page.merkle_root());
            } else {
                h.update(&Page::pristine_root(Self::page_size(page_id)));
            }
        }
        *h.finalize().as_bytes()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tx_rollback_on_invalid_outputs() {
        let mut state = State::genesis();
        let outputs = vec![
            Output {
                start: 0,
                end: 1,
                to: [2u8; 32],
                lock: None,
            },
            Output {
                start: 2,
                end: 3,
                to: [2u8; 32],
                lock: None,
            }, // gap at 1
        ];
        let before = state.clone();
        assert!(!state.tx(TREASURY, &[(0, 3)], &outputs, &[], 0, b"/slash/0.2.0", 0));
        assert_eq!(state.pages, before.pages);
    }

    #[test]
    fn tx_atomic_success() {
        let mut state = State::genesis();
        // The owner address must be the public half of the signing keypair,
        // because State::tx verifies the Ed25519 signature against `from`.
        let (sk, pk) = crate::crypto::generate_keypair();
        let owner = pk;
        let recipient = [2u8; 32];
        // Mine 50 contiguous cells so the transaction meets the minimum output rule.
        for i in 100..150 {
            state.mine(i, owner, 0);
        }
        let outputs = vec![
            Output {
                start: 100,
                end: 125,
                to: recipient,
                lock: None,
            },
            Output {
                start: 125,
                end: 150,
                to: owner,
                lock: None,
            },
        ];
        let mut h = blake3::Hasher::new();
        h.update(&owner);
        h.update(&100u64.to_le_bytes());
        h.update(&150u64.to_le_bytes());
        for o in &outputs {
            h.update(&o.start.to_le_bytes());
            h.update(&o.end.to_le_bytes());
            h.update(&o.to);
        }
        h.update(b"/slash/0.2.0");
        h.update(&[0u8]);
        let sig = crate::crypto::sign(&sk, h.finalize().as_bytes());
        assert!(state.tx(owner, &[(100, 150)], &outputs, &sig, 0, b"/slash/0.2.0", 0));
        assert_eq!(state.balance(recipient), 25);
        assert_eq!(state.balance(owner), 25);
    }

    #[test]
    fn tx_rejects_bad_signature() {
        let mut state = State::genesis();
        let owner = [1u8; 32];
        // Mine 50 contiguous cells so the transaction is otherwise valid.
        for i in 50..100 {
            state.mine(i, owner, 0);
        }
        let outputs = vec![Output {
            start: 50,
            end: 100,
            to: [2u8; 32],
            lock: None,
        }];
        let before = state.clone();
        assert!(!state.tx(
            owner,
            &[(50, 100)],
            &outputs,
            &[0u8; 64],
            0,
            b"/slash/0.2.0",
            0
        ));
        assert_eq!(state.pages, before.pages);
    }

    #[test]
    fn mine_changes_only_one_page() {
        let mut state = State::genesis();
        state.mine(1337, [1u8; 32], 0);
        assert_eq!(state.pages.len(), 1);
        assert_eq!(state.balance([1u8; 32]), 1);
        assert_eq!(state.balance(TREASURY), N - 1);
    }

    #[test]
    fn balance_cache_correct_after_1000_ops() {
        let mut state = State::genesis();
        let owner = [1u8; 32];
        for i in 0..1000 {
            state.mine(i, owner, 0);
        }
        assert_eq!(state.balance(owner), 1000);
        assert_eq!(state.balance(TREASURY), N - 1000);
    }

    #[test]
    fn multi_input_cross_page() {
        let mut state = State::genesis();
        // The signature is verified against the owner address, so the owner
        // must be the public key matching the signing secret.
        let (sk, pk) = crate::crypto::generate_keypair();
        let owner = pk;
        let recipient = [2u8; 32];
        // Mine 25 cells near the end of page 0 and 25 at the start of page 1.
        let cell0 = PAGE_SIZE - 25;
        let cell1 = PAGE_SIZE;
        for i in 0..25 {
            state.mine(cell0 + i, owner, 0);
            state.mine(cell1 + i, owner, 0);
        }
        // Spend both ranges in one transaction.
        let inputs = vec![(cell0, cell0 + 25), (cell1, cell1 + 25)];
        let outputs = vec![
            Output {
                start: cell0,
                end: cell0 + 25,
                to: recipient,
                lock: None,
            },
            Output {
                start: cell1,
                end: cell1 + 25,
                to: owner,
                lock: None,
            },
        ];
        let mut h = blake3::Hasher::new();
        h.update(&owner);
        for (s, e) in &inputs {
            h.update(&s.to_le_bytes());
            h.update(&e.to_le_bytes());
        }
        for o in &outputs {
            h.update(&o.start.to_le_bytes());
            h.update(&o.end.to_le_bytes());
            h.update(&o.to);
        }
        h.update(b"/slash/0.2.0");
        h.update(&[0u8]);
        let sig = crate::crypto::sign(&sk, h.finalize().as_bytes());
        assert!(state.tx(owner, &inputs, &outputs, &sig, 0, b"/slash/0.2.0", 0));
        assert_eq!(state.balance(recipient), 25);
        assert_eq!(state.balance(owner), 25);
    }

    #[test]
    fn locked_cells_cannot_be_mined() {
        let mut state = State::genesis();
        // The locking transaction is signed, so the owner must be the public
        // key corresponding to the signing secret.
        let (sk, pk) = crate::crypto::generate_keypair();
        let owner = pk;
        // Mine 50 contiguous cells for the owner.
        for i in 50..100 {
            state.mine(i, owner, 0);
        }
        // Lock cells 50..100 until height 10.
        let outputs = vec![Output {
            start: 50,
            end: 100,
            to: owner,
            lock: Some(10),
        }];
        let mut h = blake3::Hasher::new();
        h.update(&owner);
        h.update(&50u64.to_le_bytes());
        h.update(&100u64.to_le_bytes());
        for o in &outputs {
            h.update(&o.start.to_le_bytes());
            h.update(&o.end.to_le_bytes());
            h.update(&o.to);
            if let Some(lock) = o.lock {
                h.update(&lock.to_le_bytes());
            }
        }
        h.update(b"/slash/0.2.0");
        h.update(&[0u8]);
        let sig = crate::crypto::sign(&sk, h.finalize().as_bytes());
        assert!(state.tx(owner, &[(50, 100)], &outputs, &sig, 0, b"/slash/0.2.0", 0));
        // Mining at height 5 should fail because the cells are still locked.
        state.mine(50, [2u8; 32], 5);
        assert_eq!(state.balance(owner), 50);
        // Mining at height 10 should succeed because the lock has expired.
        state.mine(50, [2u8; 32], 10);
        assert_eq!(state.balance([2u8; 32]), 1);
        // The remaining 49 cells are still owned by the original owner.
        assert_eq!(state.balance(owner), 49);
    }

    #[test]
    fn fee_claims_move_cells_to_miner() {
        let mut state = State::genesis();
        // Seed FEE_VAULT with 50 cells from treasury.
        let out = Output {
            start: 0,
            end: 50,
            to: FEE_VAULT,
            lock: None,
        };
        assert!(state.tx(TREASURY, &[(0, 50)], &[out], &[], 0, b"/slash/0.2.0", 0));
        // Miner claims 25 cells.
        let claims = vec![Output {
            start: 0,
            end: 25,
            to: [3u8; 32],
            lock: None,
        }];
        assert!(state.claim_fees([3u8; 32], &claims, 0));
        assert_eq!(state.balance(FEE_VAULT), 25);
        assert_eq!(state.balance([3u8; 32]), 25);
    }

    #[test]
    fn pristine_page_eviction_reduces_dirty_set() {
        let mut state = State::genesis();
        // The spend transaction is signed, so the owner must be the public
        // key corresponding to the signing secret.
        let (sk, pk) = crate::crypto::generate_keypair();
        let owner = pk;
        // Mine 50 cells so page 0 becomes dirty.
        for i in 10..60 {
            state.mine(i, owner, 0);
        }
        assert!(state.pages.contains_key(&0));
        // Transfer the cells back to the treasury.
        let outputs = vec![Output {
            start: 10,
            end: 60,
            to: TREASURY,
            lock: None,
        }];
        let mut h = blake3::Hasher::new();
        h.update(&owner);
        h.update(&10u64.to_le_bytes());
        h.update(&60u64.to_le_bytes());
        for o in &outputs {
            h.update(&o.start.to_le_bytes());
            h.update(&o.end.to_le_bytes());
            h.update(&o.to);
        }
        h.update(b"/slash/0.2.0");
        h.update(&[0u8]);
        let sig = crate::crypto::sign(&sk, h.finalize().as_bytes());
        assert!(state.tx(owner, &[(10, 60)], &outputs, &sig, 0, b"/slash/0.2.0", 0));
        // Page 0 should now be evicted because it is fully treasury-owned again.
        assert!(!state.pages.contains_key(&0));
    }

    #[test]
    fn merkle_root_and_proof() {
        let mut page = Page {
            ranges: BTreeMap::new(),
        };
        page.ranges.insert(
            0,
            R {
                e: 10,
                o: [1u8; 32],
            },
        );
        page.ranges.insert(
            10,
            R {
                e: 20,
                o: [2u8; 32],
            },
        );
        page.ranges.insert(
            20,
            R {
                e: 30,
                o: [3u8; 32],
            },
        );

        let root = page.merkle_root();
        let proof = page.merkle_proof(5).unwrap();
        assert!(verify_page_proof(&root, &proof));

        let proof2 = page.merkle_proof(15).unwrap();
        assert!(verify_page_proof(&root, &proof2));

        let proof3 = page.merkle_proof(25).unwrap();
        assert!(verify_page_proof(&root, &proof3));
    }

    #[test]
    fn global_root_is_deterministic() {
        let state = State::genesis();
        let r1 = state.global_root();
        let r2 = state.global_root();
        assert_eq!(r1, r2);
    }
}
